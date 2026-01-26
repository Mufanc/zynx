mod debug;

use std::collections::HashSet;
use std::fmt::Debug;
use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use anyhow::Result;
use log::warn;
use nix::unistd::{Gid, Uid};
use once_cell::sync::Lazy;
use std::ops::Deref;
use std::path::PathBuf;

use crate::android::packages::PackageInfoLocked;
use crate::injector::app::policy::debug::SystemPolicyProvider;

static POLICY_PROVIDER_MANAGER: Lazy<PolicyProviderManager> = Lazy::new(|| PolicyProviderManager {
    providers: vec![
        Box::new(SystemPolicyProvider),
        // Todo: provider for /data/local/tmp/zynx
    ],
});

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

pub trait LibraryInfo: Debug + AsRawFd {
    fn id(&self) -> &str;
}

#[derive(Debug)]
pub struct LibraryFile {
    id: String,
    file: File,
}

impl AsRawFd for LibraryFile {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl LibraryInfo for LibraryFile {
    fn id(&self) -> &str {
        &self.id
    }
}

impl LibraryFile {
    fn new<P: Into<PathBuf>>(path: P) -> Result<Self> {
        let path = path.into();

        Ok(Self {
            id: format!("file:{}", path.display()),
            file: File::open(&path)?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum PolicyDecision {
    Allow(Vec<Arc<dyn LibraryInfo>>),
    MoreInfo,
    Deny,
}

#[derive(Debug)]
pub struct PolicyDecisions {
    pub decisions: Vec<PolicyDecision>,
    pub more_info: bool,
}

pub trait PolicyProvider: Send + Sync {
    fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecision;
}

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

        PolicyDecisions {
            decisions,
            more_info,
        }
    }

    pub fn recheck_slow(&self, args: &EmbryoCheckArgs<'_>, result: &mut PolicyDecisions) {
        result.more_info = false;

        for (index, decision) in result.decisions.iter_mut().enumerate() {
            if matches!(decision, PolicyDecision::MoreInfo) {
                let new_decision = self.providers[index].check(args);

                if matches!(new_decision, PolicyDecision::MoreInfo) {
                    warn!(
                        "provider {} returned MoreInfo in slow path, treating as Deny",
                        index
                    );
                    *decision = PolicyDecision::Deny;
                } else {
                    *decision = new_decision;
                }
            }
        }
    }

    /// Aggregate decisions from all policy providers.
    /// Returns None if all denied, Some(libs) if injection allowed (bridge + extra libs).
    pub fn aggregate(&self, decisions: &[PolicyDecision]) -> Option<Vec<Arc<dyn LibraryInfo>>> {
        let mut has_allow = false;

        let mut visited: HashSet<&str> = HashSet::new();
        let mut inject_libs = Vec::new();

        for decision in decisions {
            if let PolicyDecision::Allow(libs) = decision {
                has_allow = true;

                for lib in libs {
                    let id = lib.id();
                    if !visited.contains(id) {
                        visited.insert(id);
                        inject_libs.push(lib.clone());
                    }
                }
            }
        }

        if has_allow { Some(inject_libs) } else { None }
    }
}
