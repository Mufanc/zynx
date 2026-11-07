mod debugger;
#[cfg(not(feature = "standalone"))]
mod filter;
mod liteloader;
#[cfg(not(feature = "standalone"))]
mod module;
#[cfg(feature = "zygisk")]
mod zygisk;

use crate::android::packages::PackageInfo;
use crate::cli::FeatureFlags;
use crate::config::ZynxConfigs;
use crate::injector::app::policy::debugger::DebuggerPolicyProvider;
use crate::injector::app::policy::liteloader::LiteLoaderPolicyProvider;
#[cfg(not(feature = "standalone"))]
use crate::injector::app::policy::module::ModulePolicyProvider;
use async_trait::async_trait;
use futures::future;
use nix::unistd::{Gid, Uid};
use std::os::fd::OwnedFd;
use std::sync::Arc;

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

pub type Action = zynx_bridge_api::action::Action<Arc<OwnedFd>>;

#[derive(Debug)]
pub enum PolicyDecision {
    Allow(Vec<Action>),
    Deny,
}

#[async_trait]
pub trait PolicyProvider: Send + Sync {
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
            let module_provider = ModulePolicyProvider::new(zygisk_enabled);

            module_provider.init().await?;

            #[cfg(feature = "zygisk")]
            if config.features.contains(FeatureFlags::ZYGISK) {
                instance
                    .providers
                    .push(Box::new(module_provider.zygisk_provider()));
            }

            instance.providers.push(Box::new(module_provider));
        }

        Ok(instance)
    }

    pub async fn register<P: PolicyProvider + Default + 'static>(&mut self) -> anyhow::Result<()> {
        let provider = P::default();

        provider.init().await?;
        self.providers.push(Box::new(provider));

        Ok(())
    }

    /// Check all providers concurrently and retain their registration order.
    pub async fn check(&self, args: &ProcessInfo) -> Vec<Action> {
        let checks = self.providers.iter().map(|provider| provider.check(args));

        future::join_all(checks)
            .await
            .into_iter()
            .flat_map(|decision| match decision {
                PolicyDecision::Allow(actions) => actions,
                PolicyDecision::Deny => Vec::new(),
            })
            .collect()
    }
}
