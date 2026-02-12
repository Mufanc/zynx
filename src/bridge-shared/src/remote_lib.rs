use anyhow::{Context, Error, Result, anyhow, bail};
use jni::JNIEnv;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::strings::JavaStr;
use log::{info, warn};
use nix::libc::{RTLD_NOW, c_int, off64_t, size_t, PROT_READ, MAP_PRIVATE, MAP_FAILED};
use std::ffi::{CStr, CString, c_void};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use nix::libc;

mod system {
    use crate::remote_lib::DlextInfo;
    use nix::libc::{c_char, c_int};
    use std::ffi::c_void;

    unsafe extern "C" {
        pub fn android_dlopen_ext(
            filename: *const c_char,
            flag: c_int,
            extinfo: *const DlextInfo,
        ) -> *const c_void;

        pub fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;

        pub fn dlerror() -> *const c_char;

        pub fn dlclose(handle: *mut c_void) -> c_int;
    }
}

fn dlerror() -> Error {
    let error = unsafe { CStr::from_ptr(system::dlerror()).to_string_lossy() };
    anyhow!("{error:?}")
}

#[repr(C)]
pub struct DlextInfo {
    pub flags: u64,
    pub reserved_addr: *const c_void,
    pub reserved_size: size_t,
    pub relro_fd: c_int,
    pub library_fd: c_int,
    pub library_fd_offset: off64_t,
    pub library_namespace: *const c_void,
}

impl FromRawFd for DlextInfo {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self {
            flags: 0x10, // ANDROID_DLEXT_USE_LIBRARY_FD
            reserved_addr: ptr::null(),
            reserved_size: 0,
            relro_fd: 0,
            library_fd: fd,
            library_fd_offset: 0,
            library_namespace: ptr::null(),
        }
    }
}

pub struct NativeLibrary {
    name: String,
    fd: Option<OwnedFd>,
    handle: Option<*const c_void>,
    auto_close: bool,
}

impl NativeLibrary {
    pub fn new(name: String, fd: OwnedFd) -> Self {
        Self {
            name,
            fd: Some(fd),
            handle: None,
            auto_close: false,
        }
    }

    pub fn open(&mut self) -> Result<()> {
        let fd = self
            .fd
            .take()
            .ok_or_else(|| anyhow!("already opened or fd consumed"))?;

        info!("dlopen library: {}, fd = {}", self.name, fd.as_raw_fd());

        let info = unsafe { DlextInfo::from_raw_fd(fd.as_raw_fd()) };
        let handle = unsafe { system::android_dlopen_ext(c"jit-cache".as_ptr(), RTLD_NOW, &info) };

        if handle.is_null() {
            return Err(anyhow!(
                "dlopen library {} failed: {:?}",
                self.name,
                dlerror()
            ));
        }

        self.handle = Some(handle);
        Ok(())
    }

    pub fn is_opened(&self) -> bool {
        self.handle.is_some()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn dlsym(&self, symbol: &str) -> Result<*const c_void> {
        let handle = self.handle.ok_or_else(|| anyhow!("library not opened"))?;

        let symbol = CString::new(symbol)?;

        unsafe {
            let address = system::dlsym(handle as _, symbol.as_ptr());

            if address.is_null() {
                return Err(dlerror());
            }

            Ok(address)
        }
    }

    pub fn dlclose(mut self) {
        if let Some(handle) = self.handle.take() {
            unsafe {
                system::dlclose(handle as _);
            }
        }
        self.auto_close = false;
    }

    pub fn auto_close_on_drop(&mut self) {
        self.auto_close = true
    }
}

impl Drop for NativeLibrary {
    fn drop(&mut self) {
        if self.auto_close
            && let Some(handle) = self.handle
        {
            unsafe {
                system::dlclose(handle as _);
            }
        }
    }
}

pub struct JavaLibrary {
    name: String,
    fd: Option<OwnedFd>,
    class_loader: Option<GlobalRef>,
}

impl JavaLibrary {
    pub fn new(name: String, fd: OwnedFd) -> Self {
        Self {
            name,
            fd: Some(fd),
            class_loader: None,
        }
    }

    pub fn load(&mut self, env: jni::sys::JNIEnv) -> Result<()> {
        // Read dex content from fd using mmap to avoid race conditions
        let fd = self.fd.take().context("duplicate called")?;
        let file: File = fd.into();

        info!("loading java library: {}, fd = {}", self.name, file.as_raw_fd());

        let file_size = file.metadata()?.len() as usize;
        let mut file_data = vec![0; file_size];

        unsafe {
            let addr = libc::mmap(
                ptr::null_mut(),
                file_size,
                PROT_READ,
                MAP_PRIVATE,
                file.as_raw_fd(),
                0
            );

            if addr == MAP_FAILED {
                bail!("failed to mmap file")
            }

            ptr::copy_nonoverlapping(addr as _, file_data.as_mut_ptr(), file_size);

            libc::munmap(addr, file_size);
        };

        let mut env = unsafe { JNIEnv::from_raw(env as _) }?;

        // Create InMemoryDexClassLoader with system classloader as parent
        let class_loader_class = env.find_class("java/lang/ClassLoader")?;
        let system_class_loader = env.call_static_method(
            class_loader_class,
            "getSystemClassLoader",
            "()Ljava/lang/ClassLoader;",
            &[],
        )?;

        let inmem_class_loader_class = env.find_class("dalvik/system/InMemoryDexClassLoader")?;

        let buffer =
            unsafe { env.new_direct_byte_buffer(file_data.as_mut_ptr(), file_data.len())? };

        let class_loader = env.new_object(
            inmem_class_loader_class,
            "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",
            &[JValue::Object(&buffer), system_class_loader.borrow()],
        )?;

        self.class_loader = Some(env.new_global_ref(&class_loader)?);
        env.delete_local_ref(buffer)?;

        // Load entry class via ClassLoader.loadClass (env.find_class uses system classloader)
        let class_name = env.new_string("xyz.mufanc.zynx.Main")?;
        let main_class = env.call_method(
            &class_loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&class_name)],
        )?;
        let main_class: JClass = main_class.l()?.into();

        // Invoke Main.main(String[]) with empty args
        let empty_args = env.new_object_array(0, "java/lang/String", &JObject::null())?;

        env.call_static_method(
            main_class,
            "main",
            "([Ljava/lang/String;)V",
            &[JValue::Object(&empty_args)],
        )?;

        let exception = env.exception_occurred()?;

        if !exception.is_null() {
            let message = env.call_method(exception, "toString", "()Ljava/lang/String;", &[])?;
            let message = message.l()?.into();
            let message = JavaStr::from_env(&env, &message)?;

            warn!("failed to call entry: {:?}", message.to_string_lossy());

            env.exception_clear()?;
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct Libraries {
    pub native: Vec<NativeLibrary>,
    pub java: Vec<JavaLibrary>,
}
