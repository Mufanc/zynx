use crate::cli::Cli;
use anyhow::{Result, anyhow};
use std::sync::OnceLock;

static INSTANCE: OnceLock<ZynxConfigs> = OnceLock::new();

#[derive(Debug)]
pub struct ZynxConfigs {
    pub enable_debugger: bool,
    pub enable_zygisk: bool,
}

impl ZynxConfigs {
    pub fn init(cli: &Cli) -> Result<()> {
        let config = Self::from_cli(cli);

        INSTANCE
            .set(config)
            .map_err(|_| anyhow!("duplicate called"))?;

        Ok(())
    }

    pub fn instance() -> &'static Self {
        INSTANCE.get().expect("configs not initialized")
    }

    fn from_cli(cli: &Cli) -> Self {
        Self {
            enable_debugger: cli.cfg_enable_debugger,
            enable_zygisk: cli.cfg_enable_zygisk,
        }
    }
}
