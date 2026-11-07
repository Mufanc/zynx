use anyhow::Result;
use jni::sys::JNIEnv;
use std::os::fd::OwnedFd;
use zynx_bridge_shared::remote_lib::NativeLibrary;

pub use crate::module::{PinnedZygiskModule, ZygiskModule};

mod abi;
mod module;

pub fn load(name: String, fd: OwnedFd, env: JNIEnv) -> Result<Option<PinnedZygiskModule>> {
    let mut library = NativeLibrary::new(name, fd);

    library.dlopen()?;

    let module = ZygiskModule::new(library)?;

    Ok(module.call_entry(env).then_some(module))
}
