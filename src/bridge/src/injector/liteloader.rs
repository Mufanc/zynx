use anyhow::Result;
use zynx_bridge_shared::injector::ProviderHandler;
use zynx_bridge_shared::remote_lib::Libraries;
use zynx_bridge_shared::zygote::{ProviderType, SpecializeArgs};
use zynx_misc::ext::ResultExt;

pub struct LiteLoaderProviderHandler;

impl ProviderHandler for LiteLoaderProviderHandler {
    const TYPE: ProviderType = ProviderType::LiteLoader;

    fn on_specialize_post(
        args: &SpecializeArgs,
        libs: &mut Libraries,
        _data: &mut Option<Vec<u8>>,
    ) -> Result<()> {
        for lib in &mut libs.native {
            lib.open().log_if_error();
        }

        for lib in &mut libs.java {
            lib.load(args.env).log_if_error();
        }

        Ok(())
    }
}
