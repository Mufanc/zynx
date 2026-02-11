use crate::module::{PinnedZygiskModule, ZygiskModule};
use anyhow::Result;
use std::cell::RefCell;
use zynx_bridge_shared::dlfcn::Libraries;
use zynx_bridge_shared::injector::ProviderHandler;
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

    fn on_specialize_pre(
        args: &mut SpecializeArgs,
        libs: &mut Libraries,
        _data: &mut Option<Vec<u8>>,
    ) -> Result<()> {
        let mut modules = Vec::new();

        for mut lib in libs.native.drain(..) {
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

        modules
            .iter()
            .for_each(|module| module.call_specialize_pre(args));

        G_MODULES.with(|cell| {
            cell.borrow_mut().extend(modules);
        });

        Ok(())
    }

    fn on_specialize_post(
        args: &SpecializeArgs,
        _libs: &mut Libraries,
        _data: &mut Option<Vec<u8>>,
    ) -> Result<()> {
        G_MODULES.with(|cell| {
            let modules = cell.take();
            modules
                .iter()
                .for_each(|module| module.call_specialize_post(args));
        });

        Ok(())
    }
}
