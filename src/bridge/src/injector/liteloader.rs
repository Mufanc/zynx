use anyhow::Result;
use zynx_bridge_types::dlfcn::Library;
use zynx_bridge_types::injector::ProviderHandler;
use zynx_bridge_types::zygote::{ProviderType, SpecializeArgs};

pub struct LiteLoaderProviderHandler;

impl ProviderHandler for LiteLoaderProviderHandler {
    const TYPE: ProviderType = ProviderType::LiteLoader;

    fn on_specialize_pre(
        _args: &mut SpecializeArgs,
        _libs: Vec<Library>,
        _data: Option<Vec<u8>>,
    ) -> Result<()> {
        Ok(())
    }

    fn on_specialize_post(_args: &SpecializeArgs) -> Result<()> {
        Ok(())
    }
}
