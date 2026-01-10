use crate::dlfcn::DlopenExtInfo;
use crate::dlfcn::{DlopenExtFn, DlsymFn};
use nix::libc::RTLD_NOW;
use proc_macros::inline_bytes;
use std::{mem, ptr};
use zynx_bridge_common::EmbryoTrampolineArgs;

fn dlopen_bridge(args: &EmbryoTrampolineArgs) {
    let dlopen: DlopenExtFn = unsafe { mem::transmute(args.fn_ptrs.dlopen) };
    let dlsym: DlsymFn = unsafe { mem::transmute(args.fn_ptrs.dlsym) };

    let info = DlopenExtInfo {
        flags: 0x10, // ANDROID_DLEXT_USE_LIBRARY_FD
        reserved_addr: ptr::null(),
        reserved_size: 0,
        relro_fd: 0,
        library_fd: args.bridge_library_fd,
        library_fd_offset: 0,
        library_namespace: ptr::null(),
    };

    let library_name = inline_bytes!("zynx::bridge");
    let handle = dlopen(library_name.as_ptr(), RTLD_NOW, &info as _);

    let entry_name = inline_bytes!("embryo_entry");
    let entry_fn: fn(*const EmbryoTrampolineArgs) =
        unsafe { mem::transmute(dlsym(handle, entry_name.as_ptr())) };

    entry_fn(args);
}

#[unsafe(no_mangle)]
fn embryo_trampoline_entry(args: *const EmbryoTrampolineArgs) {
    let args = unsafe { &*args };
    dlopen_bridge(args)
}
