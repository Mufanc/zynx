use nix::libc;
use std::{panic, slice};

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
