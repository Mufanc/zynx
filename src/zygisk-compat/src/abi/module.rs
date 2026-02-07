use crate::abi::args::app::AppSpecializeArgs;
use crate::abi::args::server::ServerSpecializeArgs;
use crate::abi::{MAX_ZYGISK_API_VER, MIN_ZYGISK_API_VER};
use nix::libc::c_long;
use std::ffi::c_void;

pub type RemoteImpl = c_void;

pub struct ModuleAbi {
    pub version: c_long,
    pub remote_impl: *const RemoteImpl,
    pub app_pre: extern "C" fn(*const RemoteImpl, *const AppSpecializeArgs),
    pub app_pos: extern "C" fn(*const RemoteImpl, *const AppSpecializeArgs),
    pub server_pre: extern "C" fn(*const RemoteImpl, *const ServerSpecializeArgs),
    pub server_pos: extern "C" fn(*const RemoteImpl, *const ServerSpecializeArgs),
}

impl ModuleAbi {
    pub fn verify(&self) -> Option<String> {
        if self.version < MIN_ZYGISK_API_VER || self.version > MAX_ZYGISK_API_VER {
            return Some(format!("unsupported api version: {}", self.version));
        }

        macro_rules! verify_ptr {
            ($name: ident) => {
                if self.$name as usize == 0 {
                    return Some(format!("{} is null", stringify!($name)));
                }
            };
        }

        verify_ptr!(remote_impl);
        verify_ptr!(app_pre);
        verify_ptr!(app_pos);
        verify_ptr!(server_pre);
        verify_ptr!(server_pos);

        None
    }
}
