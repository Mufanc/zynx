mod debugger;
#[cfg(not(feature = "standalone"))]
mod filter;
mod liteloader;
#[cfg(feature = "zygisk")]
mod zygisk;
#[cfg(not(feature = "standalone"))]
mod zynx;

use crate::android::packages::PackageInfo;
use crate::cli::FeatureFlags;
use crate::config::ZynxConfigs;
use crate::injector::app::policy::debugger::DebuggerPolicyProvider;
use crate::injector::app::policy::liteloader::LiteLoaderPolicyProvider;
#[cfg(not(feature = "standalone"))]
use crate::injector::app::policy::zynx::ZynxPolicyProvider;
use async_trait::async_trait;
use futures::future;
use nix::unistd::{Gid, Uid};
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::os::fd::OwnedFd;
use std::sync::Arc;
use zynx_bridge_shared::zygote::ProviderType;

#[cfg(not(feature = "standalone"))]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/zynx_policy.rs"));
}

#[derive(Debug)]
pub struct ProcessInfo {
    pub uid: Uid,
    pub gid: Gid,
    pub is_system_server: bool,
    pub is_child_zygote: bool,
    pub package_info: Option<Arc<[PackageInfo]>>,
    pub nice_name: Option<String>,
    pub app_data_dir: Option<String>,
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
    Deny,
}

impl PolicyDecision {
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
            PolicyDecision::Deny => fmt.write_str("Deny"),
        }
    }
}

#[async_trait]
pub trait PolicyProvider: Send + Sync {
    fn provider_type(&self) -> ProviderType;

    async fn init(&self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn check(&self, args: &ProcessInfo) -> PolicyDecision;
}

#[derive(Default)]
pub struct PolicyProviderManager {
    providers: Vec<Box<dyn PolicyProvider>>,
}

impl PolicyProviderManager {
    pub async fn new(config: &ZynxConfigs) -> anyhow::Result<Self> {
        let mut instance = Self::default();

        if config.features.contains(FeatureFlags::DEBUGGER) {
            instance.register::<DebuggerPolicyProvider>().await?;
        }

        if config.features.contains(FeatureFlags::LITELOADER) {
            instance.register::<LiteLoaderPolicyProvider>().await?;
        }

        #[cfg(not(feature = "standalone"))]
        {
            #[cfg(feature = "zygisk")]
            let zygisk_enabled = config.features.contains(FeatureFlags::ZYGISK);
            #[cfg(not(feature = "zygisk"))]
            let zygisk_enabled = false;
            let zynx = ZynxPolicyProvider::new(zygisk_enabled);

            zynx.init().await?;

            #[cfg(feature = "zygisk")]
            if config.features.contains(FeatureFlags::ZYGISK) {
                instance.providers.push(Box::new(zynx.zygisk_provider()));
            }

            instance.providers.push(Box::new(zynx));
        }

        Ok(instance)
    }

    pub async fn register<P: PolicyProvider + Default + 'static>(&mut self) -> anyhow::Result<()> {
        let provider = P::default();

        provider.init().await?;
        self.providers.push(Box::new(provider));

        Ok(())
    }

    /// Check all providers concurrently using complete process information.
    pub async fn check(&self, args: &ProcessInfo) -> Vec<PolicyDecision> {
        let checks = self.providers.iter().map(|provider| provider.check(args));

        future::join_all(checks).await
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
