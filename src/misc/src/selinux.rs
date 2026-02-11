use crate::debug_on;
use crate::ext::ResultExt;
use anyhow::{Result, bail};
use log::debug;
use nix::libc;
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const SELINUX_XATTR: &CStr = c"security.selinux";
const MAGISK_FILE_CONTEXT: &str = "u:object_r:magisk_file:s0";

pub trait FileExt {
    fn mark_as_magisk_file(&self);
}

impl<F: AsFd> FileExt for F {
    fn mark_as_magisk_file(&self) {
        fsetcon(self.as_fd(), MAGISK_FILE_CONTEXT).log_if_error();
    }
}

pub fn getcon<P: AsRef<Path>>(path: P) -> Result<String> {
    let path = CString::new(path.as_ref().as_os_str().as_bytes())?;
    let mut buffer = [0u8; 128];

    let res = unsafe {
        libc::getxattr(
            path.as_ptr(),
            SELINUX_XATTR.as_ptr(),
            buffer.as_mut_ptr() as _,
            buffer.len(),
        )
    };

    if res < 0 {
        bail!("failed to get context")
    }

    Ok(CStr::from_bytes_until_nul(&buffer)?
        .to_string_lossy()
        .into())
}

pub fn fgetcon<F: AsFd>(file: F) -> Result<String> {
    let mut buffer = [0u8; 128];
    let res = unsafe {
        libc::fgetxattr(
            file.as_fd().as_raw_fd(),
            SELINUX_XATTR.as_ptr(),
            buffer.as_mut_ptr() as _,
            buffer.len(),
        )
    };

    if res < 0 {
        bail!("failed to get context")
    }

    Ok(CStr::from_bytes_until_nul(&buffer)?
        .to_string_lossy()
        .into())
}

pub fn fsetcon<F: AsFd>(file: F, context: &str) -> Result<()> {
    let before: Cow<str> = if debug_on!("selinux") {
        fgetcon(&file)
            .map(Cow::Owned)
            .unwrap_or(Cow::Borrowed("(unknown)"))
    } else {
        Cow::Borrowed("(dummy)")
    };

    let context = CString::new(context)?;
    let res = unsafe {
        libc::fsetxattr(
            file.as_fd().as_raw_fd(),
            SELINUX_XATTR.as_ptr(),
            context.as_ptr() as _,
            context.as_bytes_with_nul().len(),
            0,
        )
    };

    if res < 0 {
        bail!("fsetcon failed")
    }

    if debug_on!("selinux") {
        let after = fgetcon(&file)
            .map(Cow::Owned)
            .unwrap_or(Cow::Borrowed("(unknown)"));
        debug!(
            "fsetcon: fd = {}, {} -> {}",
            file.as_fd().as_raw_fd(),
            before,
            after
        )
    }

    Ok(())
}
