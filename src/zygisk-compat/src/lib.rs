use crate::module::{PinnedZygiskModule, ZygiskModule};
use anyhow::Result;
use std::cell::RefCell;
use zynx_bridge_shared::dlfcn::Library;
use zynx_bridge_shared::injector::ProviderHandler;
use zynx_bridge_shared::zygote::{ProviderType, SpecializeArgs};

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
        libs: Vec<Library>,
        _data: Option<Vec<u8>>,
    ) -> Result<()> {
        let mut modules = Vec::new();

        for lib in libs {
            let module = ZygiskModule::new(lib)?;

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

    fn on_specialize_post(args: &SpecializeArgs) -> Result<()> {
        G_MODULES.with(|cell| {
            let modules = cell.take();
            modules
                .iter()
                .for_each(|module| module.call_specialize_post(args));
        });

        Ok(())
    }
}
