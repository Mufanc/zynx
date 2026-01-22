use crate::init_logger;
use log::info;
use nix::libc::c_long;
use std::slice;

#[unsafe(no_mangle)]
extern "C" fn specialize_pre(args: *mut c_long, args_count: usize) {
    let args = unsafe { slice::from_raw_parts_mut(args, args_count) };

    init_logger();

    info!("specialize args: {args:?}");
}

#[unsafe(no_mangle)]
extern "C" fn specialize_post() {
    info!("post specialize");
}
