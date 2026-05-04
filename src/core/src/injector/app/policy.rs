mod debugger;
mod liteloader;
#[cfg(feature = "zygisk")]
mod zygisk;

use crate::android::packages::PackageInfoListLocked;
use crate::injector::app::policy::debugger::DebuggerPolicyProvider;
use crate::injector::app::policy::liteloader::LiteLoaderPolicyProvider;
#[cfg(feature = "zygisk")]
use crate::injector::app::policy::zygisk::ZygiskPolicyProvider;
use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use futures::future;
use log::warn;
use nix::unistd::{Gid, Uid};
use std::any::Any;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use std::os::fd::OwnedFd;
use std::sync::{Arc, OnceLock};
use std::{fmt, mem};
use zynx_bridge_shared::zygote::ProviderType;

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

#[derive(Debug, Clone)]
pub struct Attachment {
    pub fd: Option<Arc<OwnedFd>>,
    pub data: Option<Vec<u8>>,
}

impl Attachment {
    pub fn with_fd(fd: Arc<OwnedFd>) -> Self {
        Self {
            fd: Some(fd),
            data: None,
        }
    }

    pub fn with_data(data: Vec<u8>) -> Self {
        Self {
            fd: None,
            data: Some(data),
        }
    }

    pub fn with_both(fd: Arc<OwnedFd>, data: Vec<u8>) -> Self {
        Self {
            fd: Some(fd),
            data: Some(data),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProviderBundle {
    pub ty: ProviderType,
    pub attachments: Vec<Attachment>,
    pub data: Option<Vec<u8>>,
}

pub enum PolicyDecision {
    Allow {
        data: Option<Vec<u8>>,
        attachments: Option<Vec<Attachment>>,
    },
    MoreInfo(Option<Box<dyn Any + Send + Sync>>),
    Deny,
}

impl PolicyDecision {
    pub fn allow() -> Self {
        PolicyDecision::Allow {
            data: None,
            attachments: None,
        }
    }

    pub fn allow_with_attachments(attachments: Vec<Attachment>) -> Self {
        PolicyDecision::Allow {
            data: None,
            attachments: Some(attachments),
        }
    }

    pub fn allow_with_data(data: Vec<u8>) -> Self {
        PolicyDecision::Allow {
            data: Some(data),
            attachments: None,
        }
    }
}

impl Debug for PolicyDecision {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PolicyDecision::Allow { data, attachments } => fmt
                .debug_struct("Allow")
                .field("attachments", &attachments.as_ref().map(|a| a.len()))
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
    /// Returns None if all denied, Some(bundles) if injection allowed.
    pub fn aggregate(&self, decisions: &[PolicyDecision]) -> Option<Vec<ProviderBundle>> {
        let mut providers: HashMap<ProviderType, ProviderBundle> = HashMap::new();

        for (i, decision) in decisions.iter().enumerate() {
            if let PolicyDecision::Allow { data, attachments } = decision {
                let ty = self.providers[i].provider_type();
                let entry = providers.entry(ty).or_insert_with(|| ProviderBundle {
                    ty,
                    attachments: Vec::new(),
                    data: None,
                });
                if let Some(attachments) = attachments {
                    entry.attachments.extend(attachments.iter().cloned());
                }
                if let Some(data) = data {
                    entry.data = Some(data.clone());
                }
            }
        }

        if providers.is_empty() {
            None
        } else {
            Some(providers.into_values().collect())
        }
    }
}
