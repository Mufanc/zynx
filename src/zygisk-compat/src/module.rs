use crate::abi::api::ApiAbi;
use crate::abi::flags::ZygiskOption;
use crate::abi::module::ModuleAbi;
use anyhow::Result;
use jni_sys::JNIEnv;
use log::warn;
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::{mem, ptr};
use zynx_bridge_types::dlfcn::Library;

pub type PinnedZygiskModule = Pin<Box<ZygiskModule>>;

pub struct ZygiskModule {
    pub library: Library,
    pub entry_fn: extern "C" fn(*const ApiAbi, JNIEnv),
    pub api: ApiAbi,
    pub module: *const ModuleAbi,
    pub options: [bool; ZygiskOption::MAX_INDEX + 1],
    _pin: PhantomPinned,
}

impl ZygiskModule {
    pub fn new(library: Library) -> Result<PinnedZygiskModule> {
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
