mod liteloader;
#[cfg(feature = "zygisk")]
mod zygisk;

use crate::android::packages::PackageInfoListLocked;
use crate::injector::app::policy::liteloader::LiteLoaderPolicyProvider;
use crate::injector::app::policy::zygisk::ZygiskPolicyProvider;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use futures::future;
use log::warn;
use memfd::{FileSeal, Memfd, MemfdOptions};
use nix::unistd::{Gid, Uid};
use std::any::Any;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::io::{Seek, SeekFrom, Write};
use std::ops::Deref;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::{fmt, fs, mem};
use uds::UnixSeqpacketConn;
use zynx_bridge_types::zygote::{IpcPayload, IpcSegment, ProviderType};

static POLICY_PROVIDER_MANAGER: OnceLock<PolicyProviderManager> = OnceLock::new();

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/zynx_policy.rs"));
}

#[allow(unused)]
pub struct EmbryoCheckArgsFast<'a> {
    pub uid: Uid,
    pub gid: Gid,
    pub is_system_server: bool,
    pub is_child_zygote: bool,
    pub package_info: Option<PackageInfoListLocked<'a>>,
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
        package_info: Option<PackageInfoListLocked<'a>>,
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

    // pub fn is_fast(&self) -> bool {
    //     matches!(self, EmbryoCheckArgs::Fast(_))
    // }
    //
    // pub fn is_slow(&self) -> bool {
    //     !self.is_fast()
    // }

    pub fn assume_fast(&self) -> &EmbryoCheckArgsFast<'a> {
        if let EmbryoCheckArgs::Fast(args) = self {
            return args;
        }

        panic!("unexpected check args: expected `fast` but got `slow`");
    }

    pub fn assume_slow(&self) -> &EmbryoCheckArgsSlow<'a> {
        if let EmbryoCheckArgs::Slow(args) = self {
            return args;
        }

        panic!("unexpected check args: expected `slow` but got `fast`");
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
    provider_type: ProviderType,
}

impl InjectLibrary {
    pub fn new<P: AsRef<Path>, N: Display>(
        path: P,
        name: &N,
        provider_type: ProviderType,
    ) -> Result<Self> {
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

        Ok(Self {
            name,
            fd,
            provider_type,
        })
    }
    pub fn from_file<P: AsRef<Path>>(path: P, provider_type: ProviderType) -> Result<Self> {
        let path = path.as_ref();

        Self::new(path, &path.display(), provider_type)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn provider_type(&self) -> ProviderType {
        self.provider_type
    }
}

impl AsRawFd for InjectLibrary {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

pub enum PolicyDecision {
    Allow {
        libs: Vec<Arc<InjectLibrary>>,
        data: Option<(ProviderType, Vec<u8>)>,
    },
    MoreInfo(Option<Box<dyn Any + Send + Sync>>),
    Deny,
}

impl Debug for PolicyDecision {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PolicyDecision::Allow { libs, data } => fmt
                .debug_struct("Allow")
                .field("libs", libs)
                .field("data", &data.as_ref().map(|(t, d)| (t, d.len())))
                .finish(),
            PolicyDecision::MoreInfo(_) => fmt.write_str("MoreInfo(...)"),
            PolicyDecision::Deny => fmt.write_str("Deny"),
        }
    }
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

    async fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecision;

    async fn recheck(
        &self,
        args: &EmbryoCheckArgs<'_>,
        _state: Box<dyn Any + Send + Sync>,
    ) -> PolicyDecision {
        self.check(args).await
    }
}

pub struct InjectPayload {
    libs: Vec<Arc<InjectLibrary>>,
    payload: IpcPayload,
}

impl InjectPayload {
    pub fn is_empty(&self) -> bool {
        self.payload.segments.is_empty()
    }

    pub fn send_to(self, conn_fd: OwnedFd) -> Result<()> {
        let fds: Vec<RawFd> = self.libs.iter().map(|lib| lib.as_raw_fd()).collect();
        let data = wincode::serialize(&self.payload)?;

        let conn = unsafe { UnixSeqpacketConn::from_raw_fd(conn_fd.into_raw_fd()) };

        conn.send(bytemuck::bytes_of(&[data.len(), fds.len()]))?;
        conn.send_fds(&data, &fds)?;

        Ok(())
    }
}

#[derive(Default)]
pub struct PolicyProviderManager {
    providers: Vec<Box<dyn PolicyProvider>>,
}

impl PolicyProviderManager {
    pub async fn init() -> Result<()> {
        let mut instance = Self::default();

        instance.register::<LiteLoaderPolicyProvider>().await?;

        #[cfg(feature = "zygisk")]
        instance.register::<ZygiskPolicyProvider>().await?;

        POLICY_PROVIDER_MANAGER
            .set(instance)
            .map_err(|_| anyhow!("duplicate called"))?;

        Ok(())
    }

    pub async fn register<P: PolicyProvider + Default + 'static>(&mut self) -> Result<()> {
        let provider = P::default();

        provider.init().await?;
        self.providers.push(Box::new(provider));

        Ok(())
    }

    pub fn instance() -> &'static Self {
        POLICY_PROVIDER_MANAGER.wait()
    }

    /// Run fast check on all providers concurrently.
    pub async fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecisions {
        let futures: Vec<_> = self.providers.iter().map(|p| p.check(args)).collect();

        let decisions = future::join_all(futures).await;
        let more_info = decisions
            .iter()
            .any(|it| matches!(it, PolicyDecision::MoreInfo(_)));

        PolicyDecisions {
            decisions,
            more_info,
        }
    }

    /// Re-check providers that returned MoreInfo with slow (full) args.
    /// Cached state from the fast check is forwarded to `recheck` when available.
    pub async fn recheck_slow(&self, args: &EmbryoCheckArgs<'_>, result: &mut PolicyDecisions) {
        result.more_info = false;

        // Extract MoreInfo decisions along with their cached state,
        // replacing them with Deny as placeholders.
        let mut recheck_items = Vec::new();
        let decisions = mem::take(&mut result.decisions);

        result.decisions = decisions
            .into_iter()
            .enumerate()
            .map(|(i, it)| match it {
                PolicyDecision::MoreInfo(state) => {
                    recheck_items.push((i, state));
                    PolicyDecision::Deny
                }
                other => other,
            })
            .collect();

        // Re-check concurrently: use `recheck` if state is available, otherwise `check`.
        let futures: Vec<_> = recheck_items
            .into_iter()
            .map(|(i, state)| async move {
                let decision = match state {
                    Some(s) => self.providers[i].recheck(args, s).await,
                    None => self.providers[i].check(args).await,
                };
                (i, decision)
            })
            .collect();

        let new_decisions = future::join_all(futures).await;

        // Apply new decisions; MoreInfo in slow path is not allowed.
        for (index, new_decision) in new_decisions {
            if matches!(new_decision, PolicyDecision::MoreInfo(_)) {
                warn!("provider {index} returned MoreInfo in slow path, treating as Deny");
                result.decisions[index] = PolicyDecision::Deny;
            } else {
                result.decisions[index] = new_decision;
            }
        }
    }

    /// Aggregate decisions from all policy providers.
    /// Returns None if all denied, Some(payload) if injection allowed.
    pub fn aggregate(&self, decisions: &[PolicyDecision]) -> Option<InjectPayload> {
        let mut has_allow = false;
        let mut visited: HashSet<&str> = HashSet::new();
        let mut libs = Vec::new();
        let mut segments = Vec::new();

        for decision in decisions {
            if let PolicyDecision::Allow {
                libs: decision_libs,
                data,
            } = decision
            {
                has_allow = true;

                for lib in decision_libs {
                    let id = lib.name();
                    if !visited.contains(id) {
                        visited.insert(id);
                        segments.push(IpcSegment {
                            provider_type: lib.provider_type(),
                            names: Some(vec![lib.name().into()]),
                            data: None,
                            fds_count: 1,
                        });
                        libs.push(lib.clone());
                    }
                }

                if let Some((provider_type, bytes)) = data {
                    segments.push(IpcSegment {
                        provider_type: *provider_type,
                        names: None,
                        data: Some(bytes.clone()),
                        fds_count: 0,
                    });
                }
            }
        }

        if has_allow {
            let payload = IpcPayload { segments };
            Some(InjectPayload { libs, payload })
        } else {
            None
        }
    }
}
