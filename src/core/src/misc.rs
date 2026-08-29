use anyhow::Result;
use memfd::{FileSeal, MemfdOptions};
use nix::libc;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::{panic, slice};
use zynx_misc::selinux::fsetcon;

const SYSTEM_LIB_FILE_CONTEXT: &str = "u:object_r:system_lib_file:s0";

pub fn create_sealed_memfd(name: &str, data: &[u8]) -> Result<OwnedFd> {
    let fd = MemfdOptions::default().allow_sealing(true).create(name)?;

    let mut file = fd.as_file();
    file.write_all(data)?;
    file.sync_data()?;
    file.seek(SeekFrom::Start(0))?;

    fd.add_seals(&[
        FileSeal::SealGrow,
        FileSeal::SealShrink,
        FileSeal::SealWrite,
        FileSeal::SealSeal,
    ])?;

    let path = format!("/proc/self/fd/{}", fd.as_file().as_raw_fd());
    let readonly: OwnedFd = File::open(path)?.into();
    drop(fd);

    fsetcon(&readonly, SYSTEM_LIB_FILE_CONTEXT)?;
    Ok(readonly)
}

pub fn inject_panic_handler() {
    let original = panic::take_hook();

    panic::set_hook(Box::new(move |info| {
        // dump tombstone on panic
        // https://cs.android.com/android/platform/superproject/+/android14-release:bionic/libc/platform/bionic/reserved_signals.h;l=41
        unsafe {
            libc::raise(35 /* BIONIC_SIGNAL_DEBUGGER */);
        }

        original(info);
    }))
}

pub fn as_byte_slice<T: ?Sized>(value: &T) -> &[u8] {
    unsafe { slice::from_raw_parts(value as *const _ as *const u8, size_of_val(value)) }
}

pub fn as_byte_slice_mut<T: ?Sized>(value: &mut T) -> &mut [u8] {
    unsafe { slice::from_raw_parts_mut(value as *mut _ as *mut u8, size_of_val(value)) }
}
