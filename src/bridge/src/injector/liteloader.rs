use anyhow::Result;
use zynx_bridge_shared::dlfcn::Libraries;
use zynx_bridge_shared::injector::ProviderHandler;
use zynx_bridge_shared::zygote::{ProviderType, SpecializeArgs};
use zynx_misc::ext::ResultExt;

pub struct LiteLoaderProviderHandler;

impl ProviderHandler for LiteLoaderProviderHandler {
    const TYPE: ProviderType = ProviderType::LiteLoader;

    fn on_specialize_post(
        _args: &SpecializeArgs,
        libs: &mut Libraries,
        _data: &mut Option<Vec<u8>>,
    ) -> Result<()> {
        for lib in &mut libs.native {
            let _ = lib.open().inspect_log_error();
        }

        Ok(())
    }
}
