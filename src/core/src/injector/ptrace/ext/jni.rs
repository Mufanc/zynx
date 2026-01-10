use crate::build_args;
use crate::injector::ptrace::RemoteProcess;
use crate::injector::ptrace::ext::remote_call::PtraceRemoteCallExt;
use anyhow::Result;
use jni_sys::{JNIEnv, jchar, jstring};
use nix::libc::c_long;
use scopeguard::defer;
use std::fmt::Display;
use std::ops::Deref;
use zynx_common::ext::ResultExt;

#[macro_export]
macro_rules! jni_fn {
    ($func: ident) => {
        std::mem::offset_of!(jni_sys::JNINativeInterface__1_6, $func)
    };
}

pub trait PtraceJniExt {
    fn call_remote_jni(&self, env: JNIEnv, fn_offset: usize, args: &[c_long]) -> Result<c_long>;
    fn read_jstring(&self, env: JNIEnv, str: jstring) -> Result<Option<String>>;
}

impl<T> PtraceJniExt for T
where
    T: Deref<Target = RemoteProcess> + PtraceRemoteCallExt + Display,
{
    fn call_remote_jni(&self, env: JNIEnv, fn_offset: usize, args: &[c_long]) -> Result<c_long> {
        let table = self.peek(env as _)? as usize;
        let fn_ptr = self.peek(table + fn_offset)? as usize;

        self.call_remote_auto(fn_ptr, args)
    }

    fn read_jstring(&self, env: JNIEnv, str: jstring) -> Result<Option<String>> {
        if str.is_null() {
            return Ok(None);
        }

        // https://cs.android.com/android/platform/superproject/+/android-latest-release:art/runtime/jni/jni_internal.cc;l=2236;drc=c372dbb5668ee2347702050964ce042f3dcd175a
        let length =
            self.call_remote_jni(env, jni_fn!(GetStringLength), build_args!(env, str))? as usize;
        let ptr = self.call_remote_jni(env, jni_fn!(GetStringCritical), build_args!(env, str, 0))?
            as usize;

        defer! {
            self.call_remote_jni(env, jni_fn!(ReleaseStringCritical), build_args!(env, str, ptr)).log_if_error();
        }

        let mut buffer: Vec<jchar> = vec![0; length];
        let buffer_slice = unsafe {
            let slice = buffer.as_mut_slice();
            std::slice::from_raw_parts_mut(slice as *mut _ as *mut u8, size_of_val(slice))
        };

        self.peek_data(ptr, buffer_slice)?;

        Ok(Some(String::from_utf16_lossy(&buffer)))
    }
}
