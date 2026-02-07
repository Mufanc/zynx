mod liteloader;
#[cfg(feature = "zygisk")]
mod zygisk;

use crate::android::packages::PackageInfoLocked;
use crate::injector::app::policy::liteloader::LiteLoaderPolicyProvider;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use log::warn;
use memfd::{FileSeal, Memfd, MemfdOptions};
use nix::unistd::{Gid, Uid};
use std::collections::HashSet;
use std::fmt::{Debug, Display};
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::ops::Deref;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use zynx_bridge_types::zygote::LibraryProvider;

static POLICY_PROVIDER_MANAGER: OnceLock<PolicyProviderManager> = OnceLock::new();

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

impl<'a> Deref for EmbryoCheckArgs<'a> {
    type Target = EmbryoCheckArgsFast<'a>;

    fn deref(&self) -> &Self::Target {
        match self {
            EmbryoCheckArgs::Fast(args) => args,
            EmbryoCheckArgs::Slow(args) => &args.fast_args,
        }
    }
}

#[derive(Debug)]
pub struct InjectLibrary {
    name: String,
    fd: Memfd,
}

impl InjectLibrary {
    pub fn new<P: AsRef<Path>, N: Display>(path: P, name: &N) -> Result<Self> {
        let path = path.as_ref();
        let name = format!("zynx-inject::{name}");

        let fd = MemfdOptions::default().allow_sealing(true).create(&name)?;

        let mut file = fd.as_file();

        file.write_all(&fs::read(path)?)?;
        file.sync_data()?;
        file.seek(SeekFrom::Start(0))?;

        fd.add_seals(&[
            FileSeal::SealGrow,
            FileSeal::SealShrink,
            FileSeal::SealWrite,
            FileSeal::SealSeal,
        ])?;

        // Todo: setfilecon

        Ok(Self { name, fd })
    }
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        Self::new(path, &path.display())
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl AsRawFd for InjectLibrary {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[derive(Debug, Clone)]
pub enum PolicyDecision {
    Allow(Vec<Arc<InjectLibrary>>),
    MoreInfo,
    Deny,
}

#[derive(Debug)]
pub struct PolicyDecisions {
    pub decisions: Vec<PolicyDecision>,
    pub more_info: bool,
}

#[async_trait]
pub trait PolicyProvider: Send + Sync {
    async fn init(&self) -> Result<()> {
        Ok(())
    }

    fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecision;
}

pub struct PolicyProviderManager {
    providers: Vec<Box<dyn PolicyProvider>>,
}

impl PolicyProviderManager {
    pub async fn init() -> Result<()> {
        let providers: Vec<Box<dyn PolicyProvider>> =
            vec![Box::new(LiteLoaderPolicyProvider::default())];

        for provider in &providers {
            provider.init().await?;
        }

        POLICY_PROVIDER_MANAGER
            .set(Self { providers })
            .map_err(|_| anyhow!("duplicate called"))?;

        Ok(())
    }

    pub fn instance() -> &'static Self {
        POLICY_PROVIDER_MANAGER.wait()
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
                    warn!("provider {index} returned MoreInfo in slow path, treating as Deny");
                    *decision = PolicyDecision::Deny;
                } else {
                    *decision = new_decision;
                }
            }
        }
    }

    /// Aggregate decisions from all policy providers.
    /// Returns None if all denied, Some(libs) if injection allowed (bridge + extra libs).
    pub fn aggregate(&self, decisions: &[PolicyDecision]) -> Option<Vec<Arc<InjectLibrary>>> {
        let mut has_allow = false;

        let mut visited: HashSet<&str> = HashSet::new();
        let mut inject_libs = Vec::new();

        for decision in decisions {
            if let PolicyDecision::Allow(libs) = decision {
                has_allow = true;

                for lib in libs {
                    let id = lib.name();
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
