mod liteloader;

use crate::injector::liteloader::LiteLoaderProviderHandler;
use anyhow::Result;
use log::error;
use std::collections::HashMap;
use zynx_bridge_shared::dlfcn::Library;
use zynx_bridge_shared::injector::ProviderHandler;
use zynx_bridge_shared::zygote::{ProviderType, SpecializeArgs};
use zynx_zygisk_compat::ZygiskProviderHandler;

#[allow(clippy::type_complexity)]
struct Handler {
    on_specialize_pre:
        Box<dyn Fn(&mut SpecializeArgs, Vec<Library>, Option<Vec<u8>>) -> Result<()>>,
    on_specialize_post: Box<dyn Fn(&SpecializeArgs) -> Result<()>>,
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
                on_specialize_pre: Box::new(P::on_specialize_pre),
                on_specialize_post: Box::new(P::on_specialize_post),
            },
        );
    }

    pub fn dispatch_pre(
        &self,
        args: &mut SpecializeArgs,
        mut groups: HashMap<ProviderType, (Vec<Library>, Option<Vec<u8>>)>,
    ) {
        for (provider_type, handler) in &self.handlers {
            let (libs, data) = groups.remove(provider_type).unwrap_or_default();
            if let Err(err) = (handler.on_specialize_pre)(args, libs, data) {
                error!("failed to dispatch pre hook for provider type {provider_type:?}: {err:?}");
            }
        }
    }

    pub fn dispatch_post(&self, args: &SpecializeArgs) {
        for (provider_type, handler) in &self.handlers {
            if let Err(err) = (handler.on_specialize_post)(args) {
                error!("failed to dispatch post hook for provider type {provider_type:?}: {err:?}");
            }
        }
    }
}
