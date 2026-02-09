use crate::injector::ptrace::RemoteProcess;
use crate::injector::ptrace::ext::remote_call::PtraceRemoteCallExt;
use crate::{build_args, misc};
use anyhow::Result;
use jni_sys::{JNIEnv, jchar, jstring};
use nix::libc::c_long;
use scopeguard::defer;
use std::fmt::Display;
use std::ops::Deref;
use zynx_misc::ext::ResultExt;

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

        self.peek_data(ptr, misc::as_byte_slice_mut(buffer.as_mut_slice()))?;

        Ok(Some(String::from_utf16_lossy(&buffer)))
    }
}
