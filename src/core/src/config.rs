use std::sync::OnceLock;

use anyhow::{Result, anyhow};

use crate::cli::Cli;

static INSTANCE: OnceLock<ZynxConfigs> = OnceLock::new();

#[derive(Debug)]
pub struct ZynxConfigs {
    pub disable_debugger: bool,
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
            disable_debugger: cli.cfg_disable_debugger,
        }
    }
}
