use anyhow::Result;
use log::warn;
use zynx_bridge_api::injector::ProviderHandler;
use zynx_bridge_api::zygote::ProviderBundle;
use zynx_bridge_shared::policy::zynx::ZynxParams;
use zynx_bridge_shared::remote_lib::NativeLibrary;
use zynx_bridge_shared::zygote::{ProviderType, SpecializeArgs};
use zynx_misc::ext::ResultExt;

pub struct ZynxProviderHandler;

impl ProviderHandler for ZynxProviderHandler {
    const TYPE: ProviderType = ProviderType::Zynx;

    fn on_specialize_post(_args: &SpecializeArgs, bundle: &mut ProviderBundle) -> Result<()> {
        for attachment in &mut bundle.attachments {
            let Some(fd) = attachment.fd.take() else {
                continue;
            };
            let Some(params) = attachment
                .data
                .as_ref()
                .and_then(|data| wincode::deserialize::<ZynxParams>(data).ok())
            else {
                warn!("failed to deserialize ZynxParams");
                continue;
            };

            let mut library = NativeLibrary::new(params.module_name, fd);
            library.open().log_if_error();
        }

        Ok(())
    }
}
