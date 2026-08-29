use crate::cli::CfgOptions;
use anyhow::{Result, anyhow, bail};
use std::path::PathBuf;
use std::sync::OnceLock;

static INSTANCE: OnceLock<ZynxConfigs> = OnceLock::new();

#[derive(Debug)]
pub struct ZynxConfigs {
    pub bridge_file: Option<PathBuf>,
    pub enable_debugger: bool,
    pub enable_zygisk: bool,
    pub enable_liteloader: bool,
}

impl ZynxConfigs {
    pub fn init(config: &CfgOptions) -> Result<()> {
        if !cfg!(feature = "embedded-bridge") && config.cfg_bridge_file.is_none() {
            bail!("--cfg-bridge-file is required when built without embedded-bridge")
        }

        let instance = Self {
            bridge_file: config.cfg_bridge_file.clone(),
            enable_debugger: config.cfg_enable_debugger,
            enable_zygisk: config.cfg_enable_zygisk,
            enable_liteloader: config.cfg_enable_liteloader,
        };

        INSTANCE
            .set(instance)
            .map_err(|_| anyhow!("duplicate called"))?;

        Ok(())
    }

    pub fn instance() -> &'static Self {
        INSTANCE.get().expect("configs not initialized")
    }
}
