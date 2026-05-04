use crate::zygote::ProviderBundle;
use anyhow::Result;
use zynx_bridge_shared::zygote::{ProviderType, SpecializeArgs};

pub trait ProviderHandler: Send + Sync + 'static {
    const TYPE: ProviderType;

    fn on_specialize_pre(_args: &mut SpecializeArgs, _bundle: &mut ProviderBundle) -> Result<()> {
        Ok(())
    }

    fn on_specialize_post(_args: &SpecializeArgs, _bundle: &mut ProviderBundle) -> Result<()> {
        Ok(())
    }
}
