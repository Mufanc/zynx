use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use anyhow::{Result, anyhow};
use inotify::{Inotify, WatchMask};
use log::{debug, error, info, warn};
use nix::unistd::{Gid, Uid};
use once_cell::sync::Lazy;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard};
use std::ops::Deref;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::task::JoinHandle;

use crate::android::packages::{PackageInfo, parse_package_list};

pub type PackageInfoLocked<'a> = MappedRwLockReadGuard<'a, [PackageInfo]>;

static PACKAGE_INFO_SERVICE: OnceLock<PackageInfoService> = OnceLock::new();

#[allow(unused)]
pub struct EmbryoCheckArgsFast<'a> {
    pub uid: Uid,
    pub gid: Gid,
    pub is_system_server: bool,
    pub is_child_zygote: bool,
    pub package_info: Option<PackageInfoLocked<'a>>,
}

#[allow(unused)]
pub struct EmbryoCheckArgsSlow<'a> {
    fast_args: EmbryoCheckArgsFast<'a>,
    pub nice_name: Option<String>,
    pub app_data_dir: Option<String>,
}

impl<'a> Deref for EmbryoCheckArgsSlow<'a> {
    type Target = EmbryoCheckArgsFast<'a>;

    fn deref(&self) -> &Self::Target {
        &self.fast_args
    }
}

pub enum EmbryoCheckArgs<'a> {
    Fast(EmbryoCheckArgsFast<'a>),
    Slow(EmbryoCheckArgsSlow<'a>),
}

impl<'a> EmbryoCheckArgs<'a> {
    pub fn new_fast(
        uid: Uid,
        gid: Gid,
        is_system_server: bool,
        is_child_zygote: bool,
        package_info: Option<PackageInfoLocked<'a>>,
    ) -> Self {
        EmbryoCheckArgs::Fast(EmbryoCheckArgsFast {
            uid,
            gid,
            is_system_server,
            is_child_zygote,
            package_info,
        })
    }

    pub fn into_slow(self, nice_name: Option<String>, app_data_dir: Option<String>) -> Self {
        EmbryoCheckArgs::Slow(EmbryoCheckArgsSlow {
            fast_args: match self {
                EmbryoCheckArgs::Fast(args) => args,
                EmbryoCheckArgs::Slow(args) => {
                    warn!("into_slow called on already slow args, ignoring conversion");
                    return Self::Slow(args);
                }
            },
            nice_name,
            app_data_dir,
        })
    }

    pub fn is_fast(&self) -> bool {
        matches!(self, EmbryoCheckArgs::Fast(_))
    }

    pub fn is_slow(&self) -> bool {
        !self.is_fast()
    }
}

// === Library Info & Policy Decision ===

/// Library info (represents additional modules only, Bridge is handled separately)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryInfo {
    pub path: PathBuf,
}

/// Policy decision result
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Allow injection with library list
    Allow(Vec<LibraryInfo>),
    /// Insufficient info, requires slow-path
    MoreInfo,
    /// Deny this provider's handling (does not affect other providers)
    Deny,
}

/// Collection of policy decisions
#[derive(Debug)]
pub struct PolicyDecisions {
    pub decisions: Vec<PolicyDecision>,
    pub more_info: bool,
}

/// Policy provider trait
pub trait PolicyProvider: Send + Sync {
    fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecision;
}

// === PolicyProviderManager ===

static POLICY_PROVIDER_MANAGER: Lazy<PolicyProviderManager> = Lazy::new(|| PolicyProviderManager {
    providers: vec![
        Box::new(SystemPolicyProvider),
        // Todo: provider for /data/local/tmp/zynx
    ],
});

pub struct PolicyProviderManager {
    providers: Vec<Box<dyn PolicyProvider>>,
}

impl PolicyProviderManager {
    pub fn instance() -> &'static Self {
        &POLICY_PROVIDER_MANAGER
    }

    pub fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecisions {
        let mut decisions = Vec::with_capacity(self.providers.len());
        let mut more_info = false;

        for provider in &self.providers {
            let decision = provider.check(args);

            if matches!(decision, PolicyDecision::MoreInfo) {
                more_info = true;
            }

            decisions.push(decision);
        }

        PolicyDecisions { decisions, more_info }
    }

    pub fn recheck_slow(&self, args: &EmbryoCheckArgs<'_>, result: &mut PolicyDecisions) {
        result.more_info = false;

        for (index, decision) in result.decisions.iter_mut().enumerate() {
            if matches!(decision, PolicyDecision::MoreInfo) {
                let new_decision = self.providers[index].check(args);

                if matches!(new_decision, PolicyDecision::MoreInfo) {
                    warn!("provider {} returned MoreInfo in slow path, treating as Deny", index);
                    *decision = PolicyDecision::Deny;
                } else {
                    *decision = new_decision;
                }
            }
        }
    }

    /// Aggregate decisions from all policy providers.
    /// Returns None if all denied, Some(libs) if injection allowed (Bridge + extra libs).
    pub fn aggregate(&self, decisions: &[PolicyDecision]) -> Option<Vec<LibraryInfo>> {
        let mut has_allow = false;
        let mut inject_libs = Vec::new();

        for decision in decisions {
            if let PolicyDecision::Allow(libs) = decision {
                has_allow = true;

                for lib in libs {
                    if !inject_libs.contains(lib) {
                        inject_libs.push(lib.clone());
                    }
                }
            }
        }

        if has_allow {
            Some(inject_libs)
        } else {
            None
        }
    }
}

// === SystemPolicyProvider (debug only) ===

pub struct SystemPolicyProvider;

impl PolicyProvider for SystemPolicyProvider {
    fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecision {
        match args {
            EmbryoCheckArgs::Fast(fast) => {
                if let Some(info) = &fast.package_info {
                    debug!("package info: {:?}", info);
                }
                PolicyDecision::MoreInfo
            }
            EmbryoCheckArgs::Slow(slow) => {
                debug!("nice name = {:?}", slow.nice_name);

                if slow.is_system_server {
                    PolicyDecision::Allow(vec![])
                } else {
                    PolicyDecision::Deny
                }
            }
        }
    }
}

// === PackageInfoService ===

pub struct PackageInfoService {
    data: Arc<RwLock<HashMap<Uid, Vec<PackageInfo>>>>,
    _watch_task: JoinHandle<()>,
}

impl PackageInfoService {
    pub async fn init_once() -> Result<()> {
        let packages = parse_package_list()?;
        let map = Self::build_map(packages);

        info!(
            "parsed {} packages from packages.list",
            map.values().map(|v| v.len()).sum::<usize>()
        );

        let inotify = Inotify::init()?;
        inotify.watches().add("/data/system", WatchMask::MOVED_TO)?;

        let data = Arc::new(RwLock::new(map));

        let watch_task = Self::spawn_watch_task(inotify, Arc::clone(&data));

        let service = PackageInfoService {
            data,
            _watch_task: watch_task,
        };

        PACKAGE_INFO_SERVICE
            .set(service)
            .map_err(|_| anyhow!("PackageInfoService already initialized"))?;

        Ok(())
    }

    pub fn instance() -> &'static Self {
        PACKAGE_INFO_SERVICE
            .get()
            .expect("PackageInfoService not initialized")
    }

    pub fn query(&self, uid: Uid) -> Option<PackageInfoLocked<'_>> {
        let lock = self.data.read();
        RwLockReadGuard::try_map(lock, |map| map.get(&uid).map(|v| v.as_slice())).ok()
    }

    fn build_map(packages: Vec<PackageInfo>) -> HashMap<Uid, Vec<PackageInfo>> {
        let mut map: HashMap<Uid, Vec<PackageInfo>> = HashMap::new();
        for info in packages {
            map.entry(info.uid).or_default().push(info);
        }
        map
    }

    fn spawn_watch_task(
        inotify: Inotify,
        data: Arc<RwLock<HashMap<Uid, Vec<PackageInfo>>>>,
    ) -> JoinHandle<()> {
        tokio::task::spawn(async move {
            if let Err(e) = Self::watch_loop(inotify, data).await {
                error!("inotify watch loop exited with error: {e:?}");
            }
        })
    }

    async fn watch_loop(
        mut inotify: Inotify,
        data: Arc<RwLock<HashMap<Uid, Vec<PackageInfo>>>>,
    ) -> Result<()> {
        let async_fd = AsyncFd::with_interest(inotify.as_raw_fd(), Interest::READABLE)?;

        let mut buffer = [0u8; 4096];

        loop {
            let mut lock = async_fd.readable().await?;

            let events = inotify.read_events(&mut buffer)?;
            for event in events {
                if event.name.is_some_and(|name| name == "packages.list") {
                    debug!("detected packages.list update, reloading...");
                    Self::reload_packages(&data);
                }
            }

            lock.clear_ready();
        }
    }

    fn reload_packages(data: &RwLock<HashMap<Uid, Vec<PackageInfo>>>) {
        match parse_package_list() {
            Ok(packages) => {
                let new_map = Self::build_map(packages);
                let count: usize = new_map.values().map(|v| v.len()).sum();

                let mut data = data.write();
                *data = new_map;
                drop(data);

                info!("reloaded {} packages from packages.list", count);
            }
            Err(err) => {
                warn!("failed to reload packages.list: {err:?}, keeping old data");
            }
        }
    }
}
