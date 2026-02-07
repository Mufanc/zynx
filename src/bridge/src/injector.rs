mod liteloader;

use crate::injector::liteloader::LiteLoaderProviderHandler;
use anyhow::Result;
use log::error;
use std::collections::HashMap;
use zynx_bridge_types::dlfcn::Library;
use zynx_bridge_types::injector::ProviderHandler;
use zynx_bridge_types::zygote::{ProviderType, SpecializeArgs};
use zynx_zygisk_compat::ZygiskProviderHandler;

#[allow(clippy::type_complexity)]
struct Handler {
    hook_pre: Box<dyn Fn(&mut SpecializeArgs, Vec<Library>) -> Result<()>>,
    hook_post: Box<dyn Fn(&SpecializeArgs) -> Result<()>>,
}

#[derive(Default)]
pub struct ProviderHandlerRegistry {
    handlers: HashMap<ProviderType, Handler>,
}

impl ProviderHandlerRegistry {
    pub fn new() -> Self {
        let mut instance = Self::default();

        instance.register(LiteLoaderProviderHandler);

        #[cfg(feature = "zygisk")]
        instance.register(ZygiskProviderHandler);

        instance
    }

    fn register<P: ProviderHandler>(&mut self, _: P) {
        self.handlers.insert(
            P::TYPE,
            Handler {
                hook_pre: Box::new(P::on_specialize_pre),
                hook_post: Box::new(P::on_specialize_post),
            },
        );
    }

    pub fn dispatch_pre(&self, args: &mut SpecializeArgs, mut libs: Vec<Library>) {
        for (provider_type, handler) in &self.handlers {
            let mut i = 0;
            let mut matched_libs = Vec::new();

            while i < libs.len() {
                if libs[i].provider_type() == *provider_type {
                    matched_libs.push(libs.swap_remove(i));
                } else {
                    i += 1;
                }
            }

            if let Err(err) = (handler.hook_pre)(args, matched_libs) {
                error!("failed to dispatch pre hook for provider type {provider_type:?}: {err:?}");
            }
        }
    }

    pub fn dispatch_post(&self, args: &SpecializeArgs) {
        for (provider_type, handler) in &self.handlers {
            if let Err(err) = (handler.hook_post)(args) {
                error!("failed to dispatch post hook for provider type {provider_type:?}: {err:?}");
            }
        }
    }
}
