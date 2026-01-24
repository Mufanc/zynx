use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::sync::{Arc, OnceLock};

use anyhow::{Result, anyhow};
use inotify::{Inotify, WatchMask};
use log::{debug, error, info, warn};
use nix::unistd::{Gid, Uid};
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

pub enum EmbryoCheckResult {
    Deny,
    Allow,
    MoreInfo,
}

pub struct InjectorPolicy {}

impl InjectorPolicy {
    pub fn check_embryo(args: &EmbryoCheckArgs<'_>) -> EmbryoCheckResult {
        match args {
            EmbryoCheckArgs::Fast(fast) => {
                if let Some(info) = &fast.package_info {
                    debug!("package info: {:?}", info);
                }

                EmbryoCheckResult::MoreInfo
            }
            EmbryoCheckArgs::Slow(slow) => {
                debug!("nice name = {:?}", slow.nice_name);

                if slow.is_system_server {
                    EmbryoCheckResult::Allow
                } else {
                    EmbryoCheckResult::Deny
                }
            }
        }
    }
}

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
