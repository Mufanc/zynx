use nix::libc::{c_int, off64_t, size_t};
use std::ffi::c_void;

#[repr(C)]
pub struct DlopenExtInfo {
    pub flags: u64,
    pub reserved_addr: *const c_void,
    pub reserved_size: size_t,
    pub relro_fd: c_int,
    pub library_fd: c_int,
    pub library_fd_offset: off64_t,
    pub library_namespace: *const c_void,
}

pub type DlopenExtFn = fn(*const u8, i32, *const DlopenExtInfo) -> *const c_void;
pub type DlsymFn = fn(*const c_void, sym: *const u8) -> *const c_void;
