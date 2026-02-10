use crate::abi::flags::ZygiskOption;
use crate::abi::module::ModuleAbi;
use crate::module::ZygiskModule;
use jni::sys::{JNIEnv, JNINativeMethod};
use log::warn;
use nix::libc::{c_char, c_int, c_long, dev_t, ino_t};
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::ptr;

#[repr(C)]
pub struct ApiAbiBase {
    pub local_impl: *mut ZygiskModule,
    pub register_module: extern "C" fn(*mut ApiAbi, *const ModuleAbi) -> bool,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ApiAbiV4 {
    pub hook_jni_native_methods:
        MaybeUninit<extern "C" fn(*const JNIEnv, *const c_char, *const JNINativeMethod, c_int)>,
    pub plt_hook_register:
        MaybeUninit<extern "C" fn(dev_t, ino_t, *const c_char, *const c_void, *const *mut c_void)>,
    pub exempt_fd: MaybeUninit<extern "C" fn(c_int) -> bool>,
    pub plt_hook_commit: MaybeUninit<extern "C" fn() -> bool>,
    pub connect_companion: MaybeUninit<extern "C" fn(*mut ZygiskModule) -> c_int>,
    pub set_option: MaybeUninit<extern "C" fn(*mut ZygiskModule, ZygiskOption)>,
    pub get_module_dir: MaybeUninit<extern "C" fn(*mut ZygiskModule) -> c_int>,
    pub get_flags: MaybeUninit<extern "C" fn(*mut ZygiskModule) -> u32>,
}

impl ApiAbiV4 {
    extern "C" fn set_option(module: *mut ZygiskModule, option: ZygiskOption) {
        unsafe { (*module).options[option.index()] = true }
    }
}

pub type ApiAbiV5 = ApiAbiV4;

#[repr(C)]
pub union ApiAbiSpec {
    pub v4: ApiAbiV4,
    pub v5: ApiAbiV5,
}

impl ApiAbiSpec {
    fn new(version: c_long) -> Self {
        match version {
            4 | 5 => ApiAbiSpec {
                v4: ApiAbiV4 {
                    hook_jni_native_methods: MaybeUninit::zeroed(),
                    plt_hook_register: MaybeUninit::zeroed(),
                    exempt_fd: MaybeUninit::zeroed(),
                    plt_hook_commit: MaybeUninit::zeroed(),
                    connect_companion: MaybeUninit::zeroed(),
                    set_option: MaybeUninit::new(ApiAbiV4::set_option),
                    get_module_dir: MaybeUninit::zeroed(),
                    get_flags: MaybeUninit::zeroed(),
                },
            },
            _ => unreachable!(),
        }
    }
}

#[repr(C)]
pub struct ApiAbi {
    pub base: ApiAbiBase,
    pub spec: MaybeUninit<ApiAbiSpec>,
    pub ready: bool,
}

impl ApiAbi {
    pub fn new() -> Self {
        Self {
            base: ApiAbiBase {
                local_impl: ptr::null_mut(),
                register_module: ApiAbi::register,
            },
            spec: MaybeUninit::zeroed(),
            ready: false,
        }
    }

    extern "C" fn register(api_abi: *mut ApiAbi, module_abi: *const ModuleAbi) -> bool {
        let Some(api) = (unsafe { api_abi.as_mut() }) else {
            return false;
        };

        let Some(module) = (unsafe { module_abi.as_ref() }) else {
            return false;
        };

        if let Some(err) = module.verify() {
            warn!("module verify failed: {err:?}");
            return false;
        }

        unsafe {
            (*api.base.local_impl).module = module;
        }

        api.spec = MaybeUninit::new(ApiAbiSpec::new(module.version));
        api.ready = true;

        true
    }
}
