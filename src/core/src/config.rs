use crate::cli::CfgOptions;
use anyhow::{Result, bail};
use std::path::PathBuf;

#[derive(Debug)]
pub struct ZynxConfigs {
    pub bridge_file: Option<PathBuf>,
    pub enable_debugger: bool,
    pub enable_zygisk: bool,
    pub enable_liteloader: bool,
}

impl ZynxConfigs {
    pub fn new(config: &CfgOptions) -> Result<Self> {
        if !cfg!(feature = "embedded-bridge") && config.cfg_bridge_file.is_none() {
            bail!("--cfg-bridge-file is required when built without embedded-bridge")
        }

        Ok(Self {
            bridge_file: config.cfg_bridge_file.clone(),
            enable_debugger: config.cfg_enable_debugger,
            enable_zygisk: config.cfg_enable_zygisk,
            enable_liteloader: config.cfg_enable_liteloader,
        })
    }
}
