use nix::libc::{c_int, off64_t, size_t};
use std::ffi::c_void;
use std::os::fd::{FromRawFd, RawFd};
use std::ptr;

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
