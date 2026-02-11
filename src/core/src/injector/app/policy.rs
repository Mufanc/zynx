mod debugger;
mod liteloader;
#[cfg(feature = "zygisk")]
mod zygisk;

use crate::android::packages::PackageInfoListLocked;
use crate::injector::app::policy::debugger::DebuggerPolicyProvider;
use crate::injector::app::policy::liteloader::LiteLoaderPolicyProvider;
use crate::injector::app::policy::zygisk::ZygiskPolicyProvider;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use futures::future;
use log::warn;
use memfd::{FileSeal, Memfd, MemfdOptions};
use nix::unistd::{Gid, Uid};
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::io::{Seek, SeekFrom, Write};
use std::ops::Deref;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::{fmt, fs, mem};
use zynx_bridge_shared::zygote::{
    IpcPayload, IpcSegment, LibraryDescriptor, LibraryType, ProviderType,
};
use zynx_misc::selinux::FileExt;

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
    lib_type: LibraryType,
}

impl InjectLibrary {
    fn new_internal<P: AsRef<Path>, N: Display>(
        path: P,
        name: &N,
        lib_type: LibraryType,
    ) -> Result<Self> {
        let path = path.as_ref();
        let name = format!("zynx-inject::{name}");

        let fd = MemfdOptions::default().allow_sealing(true).create(&name)?;

        let mut file = fd.as_file();

        file.write_all(&fs::read(path)?)?;
        file.sync_data()?;
        file.seek(SeekFrom::Start(0))?;
        file.mark_as_magisk_file();

        fd.add_seals(&[
            FileSeal::SealGrow,
            FileSeal::SealShrink,
            FileSeal::SealWrite,
            FileSeal::SealSeal,
        ])?;

        Ok(Self { name, fd, lib_type })
    }

    pub fn new<P: AsRef<Path>, N: Display>(path: P, name: &N) -> Result<Self> {
        Self::new_internal(path, name, LibraryType::Native)
    }

    pub fn new_java<P: AsRef<Path>, N: Display>(path: P, name: &N) -> Result<Self> {
        Self::new_internal(path, name, LibraryType::Java)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        Self::new(path, &path.display())
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn lib_type(&self) -> LibraryType {
        self.lib_type
    }
}

impl AsRawFd for InjectLibrary {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for InjectLibrary {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_file().as_fd()
    }
}

pub enum PolicyDecision {
    Allow {
        libs: Vec<Arc<InjectLibrary>>,
        data: Option<Vec<u8>>,
    },
    MoreInfo(Option<Box<dyn Any + Send + Sync>>),
    Deny,
}

impl PolicyDecision {
    pub fn allow() -> Self {
        PolicyDecision::Allow {
            libs: vec![],
            data: None,
        }
    }

    pub fn allow_with_libs(libs: Vec<Arc<InjectLibrary>>) -> Self {
        PolicyDecision::Allow { libs, data: None }
    }

    pub fn allow_with_data(data: Vec<u8>) -> Self {
        PolicyDecision::Allow {
            libs: vec![],
            data: Some(data),
        }
    }
}

impl Debug for PolicyDecision {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PolicyDecision::Allow { libs, data } => fmt
                .debug_struct("Allow")
                .field("libs", libs)
                .field("data", &data.as_ref().map(|d| d.len()))
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
    fn provider_type(&self) -> ProviderType;

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
        self.payload
            .send_to(conn_fd, self.libs.iter().map(|lib| lib.as_fd()))
    }
}

#[derive(Default)]
pub struct PolicyProviderManager {
    providers: Vec<Box<dyn PolicyProvider>>,
}

impl PolicyProviderManager {
    pub async fn init() -> Result<()> {
        let mut instance = Self::default();

        instance.register::<DebuggerPolicyProvider>().await?;
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
        struct GroupedEntry {
            libs: Vec<Arc<InjectLibrary>>,
            data: Option<Vec<u8>>,
            visited: HashSet<String>,
        }

        let mut groups: HashMap<ProviderType, GroupedEntry> = HashMap::new();

        // Phase 1: Group libraries and data by ProviderType.
        // decisions[i] corresponds to self.providers[i] (order preserved by join_all).
        for (i, decision) in decisions.iter().enumerate() {
            if let PolicyDecision::Allow {
                libs: decision_libs,
                data,
            } = decision
            {
                let provider_type = self.providers[i].provider_type();
                let entry = groups.entry(provider_type).or_insert_with(|| GroupedEntry {
                    libs: Vec::new(),
                    data: None,
                    visited: HashSet::new(),
                });

                // Deduplicate libraries by name within each provider group
                for lib in decision_libs {
                    if entry.visited.insert(lib.name().to_string()) {
                        entry.libs.push(lib.clone());
                    }
                }

                if let Some(bytes) = data {
                    entry.data = Some(bytes.clone());
                }
            }
        }

        // Phase 2: Build IpcSegments and the flat libs list.
        // The order of `all_libs` must align with segments: each segment's
        // `fds_count` tells the receiver how many consecutive fds belong to it.
        let mut all_libs = Vec::new();
        let mut segments = Vec::new();

        for (provider_type, entry) in groups {
            let libraries: Vec<LibraryDescriptor> = entry
                .libs
                .iter()
                .map(|lib| LibraryDescriptor {
                    name: lib.name().into(),
                    lib_type: lib.lib_type(),
                })
                .collect();

            segments.push(IpcSegment {
                provider_type,
                libraries: if libraries.is_empty() {
                    None
                } else {
                    Some(libraries)
                },
                data: entry.data,
            });
            all_libs.extend(entry.libs);
        }

        if segments.is_empty() {
            None
        } else {
            let payload = IpcPayload { segments };
            Some(InjectPayload {
                libs: all_libs,
                payload,
            })
        }
    }
}
