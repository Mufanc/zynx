use nix::libc::c_long;

pub mod api;
pub mod args;
pub mod flags;
pub mod module;

pub const MIN_ZYGISK_API_VER: c_long = 4;
pub const MAX_ZYGISK_API_VER: c_long = 5;
