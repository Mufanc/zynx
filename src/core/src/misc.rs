pub mod ext;

use nix::libc;
use std::panic;

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
