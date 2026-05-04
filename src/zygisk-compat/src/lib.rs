use crate::module::{PinnedZygiskModule, ZygiskModule};
use anyhow::Result;
use std::cell::RefCell;
use zynx_bridge_api::injector::ProviderHandler;
use zynx_bridge_api::zygote::ProviderBundle;
use zynx_bridge_shared::policy::zygisk::ZygiskParams;
use zynx_bridge_shared::remote_lib::NativeLibrary;
use zynx_bridge_shared::zygote::{ProviderType, SpecializeArgs};
use zynx_misc::ext::ResultExt;

mod abi;
mod module;

pub struct ZygiskProviderHandler;

thread_local! {
    static G_MODULES: RefCell<Vec<PinnedZygiskModule>> = RefCell::default();
}

impl ProviderHandler for ZygiskProviderHandler {
    const TYPE: ProviderType = ProviderType::Zygisk;

    fn on_specialize_pre(args: &mut SpecializeArgs, bundle: &mut ProviderBundle) -> Result<()> {
        let mut modules = Vec::new();

        for attachment in bundle.attachments.iter_mut() {
            if let Some(fd) = attachment.fd.take() {
                let params: ZygiskParams = match attachment
                    .data
                    .as_ref()
                    .and_then(|data| wincode::deserialize(data).ok())
                {
                    Some(params) => params,
                    None => {
                        log::warn!("failed to deserialize ZygiskParams");
                        continue;
                    }
                };

                let mut lib = NativeLibrary::new(params.module_name, fd);

                let Ok(()) = lib.open().inspect_log_error() else {
                    continue;
                };

                let Ok(module) = ZygiskModule::new(lib).inspect_log_error() else {
                    continue;
                };

                if module.call_entry(args.env) {
                    modules.push(module);
                }
            }
        }

        modules
            .iter()
            .for_each(|module| module.call_specialize_pre(args));

        G_MODULES.with(|cell| {
            cell.borrow_mut().extend(modules);
        });

        Ok(())
    }

    fn on_specialize_post(args: &SpecializeArgs, _bundle: &mut ProviderBundle) -> Result<()> {
        G_MODULES.with(|cell| {
            let modules = cell.take();
            modules
                .iter()
                .for_each(|module| module.call_specialize_post(args));
        });

        Ok(())
    }
}
