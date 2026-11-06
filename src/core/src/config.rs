use crate::cli::{CfgOptions, FeatureFlags};
#[cfg(not(feature = "standalone"))]
use std::path::PathBuf;

#[derive(Debug)]
pub struct ZynxConfigs {
    #[cfg(not(feature = "standalone"))]
    pub bridge_file: PathBuf,
    pub features: FeatureFlags,
}

impl ZynxConfigs {
    pub fn new(config: &CfgOptions) -> Self {
        Self {
            #[cfg(not(feature = "standalone"))]
            bridge_file: config.bridge.clone(),
            features: config.features.unwrap_or_default(),
        }
    }
}
