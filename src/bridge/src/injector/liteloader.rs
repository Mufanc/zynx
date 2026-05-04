use anyhow::Result;
use log::warn;
use zynx_bridge_api::injector::ProviderHandler;
use zynx_bridge_api::zygote::ProviderBundle;
use zynx_bridge_shared::policy::liteloader::{LibraryKind, LiteLoaderParams};
use zynx_bridge_shared::remote_lib::{JavaLibrary, NativeLibrary};
use zynx_bridge_shared::zygote::{ProviderType, SpecializeArgs};
use zynx_misc::ext::ResultExt;

pub struct LiteLoaderProviderHandler;

impl ProviderHandler for LiteLoaderProviderHandler {
    const TYPE: ProviderType = ProviderType::LiteLoader;

    fn on_specialize_post(args: &SpecializeArgs, bundle: &mut ProviderBundle) -> Result<()> {
        for attachment in bundle.attachments.iter_mut() {
            if let Some(fd) = attachment.fd.take() {
                let params: LiteLoaderParams = match attachment
                    .data
                    .as_ref()
                    .and_then(|data| wincode::deserialize(data).ok())
                {
                    Some(params) => params,
                    None => {
                        warn!("failed to deserialize LiteLoaderParams");
                        continue;
                    }
                };

                match params.kind {
                    LibraryKind::Native => {
                        let mut lib = NativeLibrary::new(params.lib_name, fd);
                        lib.open().log_if_error();
                    }
                    LibraryKind::Java => {
                        let mut lib = JavaLibrary::new(params.lib_name, fd);
                        lib.load(args.env).log_if_error();
                    }
                }
            }
        }

        Ok(())
    }
}
