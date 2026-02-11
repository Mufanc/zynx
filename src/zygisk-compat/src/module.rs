use crate::abi::api::ApiAbi;
use crate::abi::args::app::AppSpecializeArgs;
use crate::abi::args::server::ServerSpecializeArgs;
use crate::abi::flags::ZygiskOption;
use crate::abi::module::ModuleAbi;
use anyhow::Result;
use jni::sys::JNIEnv;
use log::warn;
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::{mem, ptr};
use zynx_bridge_shared::remote_lib::NativeLibrary;
use zynx_bridge_shared::zygote::SpecializeArgs;

pub type PinnedZygiskModule = Pin<Box<ZygiskModule>>;

pub struct ZygiskModule {
    pub library: NativeLibrary,
    pub entry_fn: extern "C" fn(*const ApiAbi, JNIEnv),
    pub api: ApiAbi,
    pub module: *const ModuleAbi,
    pub options: [bool; ZygiskOption::MAX_INDEX + 1],
    _pin: PhantomPinned,
}

impl ZygiskModule {
    pub fn new(library: NativeLibrary) -> Result<PinnedZygiskModule> {
        let entry_fn: extern "C" fn(*const ApiAbi, JNIEnv) =
            unsafe { mem::transmute(library.dlsym("zygisk_module_entry")?) };

        let mut instance = Box::pin(Self {
            library,
            entry_fn,
            api: ApiAbi::new(),
            module: ptr::null(),
            options: [false; ZygiskOption::MAX_INDEX + 1],
            _pin: Default::default(),
        });

        unsafe {
            let pin = instance.as_mut().get_unchecked_mut();
            pin.api.base.local_impl = pin as _
        }

        Ok(instance)
    }

    pub fn call_entry(&self, env: JNIEnv) -> bool {
        (self.entry_fn)(&self.api, env);
        self.api.ready
    }

    pub fn call_specialize_pre(&self, args: &mut SpecializeArgs) {
        let module = unsafe { &*self.module };

        if args.is_system_server {
            let args = ServerSpecializeArgs::new(args, module.version);
            (module.server_pre)(module.remote_impl, &args);
        } else {
            let args = AppSpecializeArgs::new(args, module.version);
            (module.app_pre)(module.remote_impl, &args);
        }
    }

    pub fn call_specialize_post(&self, args: &SpecializeArgs) {
        let args = &mut args.clone();
        let module = unsafe { &*self.module };

        if args.is_system_server {
            let args = ServerSpecializeArgs::new(args, module.version);
            (module.server_pos)(module.remote_impl, &args);
        } else {
            let args = AppSpecializeArgs::new(args, module.version);
            (module.app_pos)(module.remote_impl, &args);
        }
    }
}

impl Drop for ZygiskModule {
    fn drop(&mut self) {
        if self.options[ZygiskOption::DlcloseModuleLibrary.index()] {
            self.library.auto_close_on_drop();
        }

        if self.options[ZygiskOption::ForceDenylistUnmount.index()] {
            warn!(
                "[{}] the FORCE_DENYLIST_UNMOUNT option is unsupported by zynx, modules should NOT inject into processes they don't care about!",
                self.library.name()
            );
            self.library.auto_close_on_drop();
        }
    }
}
