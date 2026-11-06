use super::app::SpecializeCommonConfig;
use super::app::policy::PolicyProviderManager;
use super::bridge::Bridge;
use crate::android::packages::PackageInfoService;
use crate::config::ZynxConfigs;
use log::info;

pub struct ZynxContext {
    pub bridge: Bridge,
    pub package_index: PackageInfoService,
    pub policy: PolicyProviderManager,
    pub specialize_abi: SpecializeCommonConfig,
}

impl ZynxContext {
    pub async fn new(config: &ZynxConfigs) -> anyhow::Result<Self> {
        #[cfg(feature = "standalone")]
        let bridge = Bridge::new()?;
        #[cfg(not(feature = "standalone"))]
        let bridge = Bridge::new(&config.bridge_file)?;
        let specialize = SpecializeCommonConfig::resolve()?;

        info!("SpecializeCommon config: {specialize:?}");

        Ok(Self {
            bridge,
            package_index: PackageInfoService::new()?,
            policy: PolicyProviderManager::new(config).await?,
            specialize_abi: specialize,
        })
    }
}
