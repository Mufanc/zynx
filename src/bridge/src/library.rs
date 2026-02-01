use anyhow::{Result, anyhow};
use log::info;
use nix::libc::{RTLD_NOW, c_char, c_int};
use std::ffi::{CStr, c_void};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use zynx_bridge_common::dlfcn::DlextInfo;

unsafe extern "C" {
    fn android_dlopen_ext(
        filename: *const c_char,
        flag: c_int,
        extinfo: *const DlextInfo,
    ) -> *const c_void;

    fn dlerror() -> *const c_char;
}

pub struct Library {
    id: String,
    handle: *const c_void,
}

impl Library {
    pub fn new(name: &str, fd: OwnedFd) -> Result<Self> {
        info!("dlopen library: {}, fd = {}", name, fd.as_raw_fd());

        let info = unsafe { DlextInfo::from_raw_fd(fd.as_raw_fd()) };
        let handle = unsafe { android_dlopen_ext(c"jit-cache".as_ptr(), RTLD_NOW, &info) };

        if handle.is_null() {
            let error = unsafe { CStr::from_ptr(dlerror()) };
            return Err(anyhow!(
                "dlopen library {} failed: {}",
                name,
                error.to_string_lossy()
            ));
        }

        Ok(Self {
            id: name.into(),
            handle,
        })
    }
}
