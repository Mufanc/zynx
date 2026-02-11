use anyhow::Result;
use zynx_bridge_shared::dlfcn::Libraries;
use zynx_bridge_shared::injector::ProviderHandler;
use zynx_bridge_shared::zygote::{ProviderType, SpecializeArgs};

pub struct LiteLoaderProviderHandler;

impl ProviderHandler for LiteLoaderProviderHandler {
    const TYPE: ProviderType = ProviderType::LiteLoader;

    fn on_specialize_pre(
        _args: &mut SpecializeArgs,
        _libs: Libraries,
        _data: Option<Vec<u8>>,
    ) -> Result<()> {
        Ok(())
    }

    fn on_specialize_post(_args: &SpecializeArgs) -> Result<()> {
        Ok(())
    }
}
