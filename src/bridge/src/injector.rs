mod debugger;
mod liteloader;

use crate::injector::debugger::DebuggerProviderHandler;
use crate::injector::liteloader::LiteLoaderProviderHandler;
use anyhow::Result;
use log::error;
use std::collections::HashMap;
use zynx_bridge_shared::injector::ProviderHandler;
use zynx_bridge_shared::remote_lib::Libraries;
use zynx_bridge_shared::zygote::{ProviderType, SpecializeArgs};
use zynx_zygisk_compat::ZygiskProviderHandler;

#[allow(clippy::type_complexity)]
struct Handler {
    on_specialize_pre:
        Box<dyn Fn(&mut SpecializeArgs, &mut Libraries, &mut Option<Vec<u8>>) -> Result<()>>,
    on_specialize_post:
        Box<dyn Fn(&SpecializeArgs, &mut Libraries, &mut Option<Vec<u8>>) -> Result<()>>,
}

#[derive(Default)]
pub struct ProviderHandlerRegistry {
    handlers: HashMap<ProviderType, Handler>,
}

impl ProviderHandlerRegistry {
    pub fn new() -> Self {
        let mut instance = Self::default();

        instance.register(DebuggerProviderHandler);
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
        groups: &mut HashMap<ProviderType, (Libraries, Option<Vec<u8>>)>,
    ) {
        for (provider_type, handler) in &self.handlers {
            if let Some((libs, data)) = groups.get_mut(provider_type)
                && let Err(err) = (handler.on_specialize_pre)(args, libs, data)
            {
                error!("failed to dispatch pre hook for provider type {provider_type:?}: {err:?}");
            }
        }
    }

    pub fn dispatch_post(
        &self,
        args: &SpecializeArgs,
        groups: &mut HashMap<ProviderType, (Libraries, Option<Vec<u8>>)>,
    ) {
        for (provider_type, handler) in &self.handlers {
            if let Some((libs, data)) = groups.get_mut(provider_type)
                && let Err(err) = (handler.on_specialize_post)(args, libs, data)
            {
                error!("failed to dispatch post hook for provider type {provider_type:?}: {err:?}");
            }
        }
    }
}
