use crate::zygote::ProviderType;
use anyhow::{Error, Result, anyhow};
use log::info;
use nix::libc::{RTLD_NOW, c_int, off64_t, size_t};
use std::ffi::{CStr, CString, c_void};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

mod system {
    use crate::dlfcn::DlextInfo;
    use nix::libc::{c_char, c_int};
    use std::ffi::c_void;

    unsafe extern "C" {
        pub fn android_dlopen_ext(
            filename: *const c_char,
            flag: c_int,
            extinfo: *const DlextInfo,
        ) -> *const c_void;

        pub fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;

        pub fn dlerror() -> *const c_char;

        pub fn dlclose(handle: *mut c_void) -> c_int;
    }
}

fn dlerror() -> Error {
    let error = unsafe { CStr::from_ptr(system::dlerror()).to_string_lossy() };
    anyhow!("{error:?}")
}

#[repr(C)]
pub struct DlextInfo {
    pub flags: u64,
    pub reserved_addr: *const c_void,
    pub reserved_size: size_t,
    pub relro_fd: c_int,
    pub library_fd: c_int,
    pub library_fd_offset: off64_t,
    pub library_namespace: *const c_void,
}

impl FromRawFd for DlextInfo {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self {
            flags: 0x10, // ANDROID_DLEXT_USE_LIBRARY_FD
            reserved_addr: ptr::null(),
            reserved_size: 0,
            relro_fd: 0,
            library_fd: fd,
            library_fd_offset: 0,
            library_namespace: ptr::null(),
        }
    }
}

pub struct Library {
    name: String,
    handle: *const c_void,
    auto_close: bool,
    provider_type: ProviderType,
}

impl Library {
    pub fn open(name: String, fd: OwnedFd, provider_type: ProviderType) -> Result<Self> {
        info!("dlopen library: {}, fd = {}", name, fd.as_raw_fd());

        let info = unsafe { DlextInfo::from_raw_fd(fd.as_raw_fd()) };
        let handle = unsafe { system::android_dlopen_ext(c"jit-cache".as_ptr(), RTLD_NOW, &info) };

        if handle.is_null() {
            return Err(anyhow!("dlopen library {} failed: {:?}", name, dlerror()));
        }

        Ok(Self {
            name,
            handle,
            auto_close: false,
            provider_type,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn provider_type(&self) -> ProviderType {
        self.provider_type
    }

    pub fn dlsym(&self, symbol: &str) -> Result<*const c_void> {
        let symbol = CString::new(symbol)?;

        unsafe {
            let address = system::dlsym(self.handle as _, symbol.as_ptr());

            if address.is_null() {
                return Err(dlerror());
            }

            Ok(address)
        }
    }

    pub fn dlclose(mut self) {
        unsafe {
            system::dlclose(self.handle as _);
            self.auto_close = false;
        }
    }

    pub fn auto_close_on_drop(&mut self) {
        self.auto_close = true
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        if self.auto_close {
            unsafe {
                system::dlclose(self.handle as _);
            }
        }
    }
}
