use anyhow::{Context, Result, ensure};
use memfd::{FileSeal, MemfdOptions};
use nix::libc;
use rustix::fs::{Mode, OFlags, ResolveFlags};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::Path;
use std::{panic, slice};
use zynx_misc::selinux::fsetcon;

const SYSTEM_LIB_FILE_CONTEXT: &str = "u:object_r:system_lib_file:s0";

/// Opens a regular file read-only beneath `dir`, allowing internal symlinks but no magic links.
/// Requires kernel support for `openat2`; errors are returned without a fallback.
pub fn open_file_beneath(dir: impl AsFd, path: &Path) -> anyhow::Result<File> {
    let fd = rustix::fs::openat2(
        dir,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
    )
    .with_context(|| format!("failed to open file beneath directory: {}", path.display()))?;
    let file = File::from(fd);

    ensure!(
        file.metadata()?.is_file(),
        "not a regular file: {}",
        path.display()
    );

    Ok(file)
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs as unix_fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::{env, fs};

    #[test]
    fn opens_only_regular_files_beneath_directory() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("zynx-openat2-{}-{unique}", std::process::id()));

        fs::create_dir(&root).unwrap();

        let result = (|| -> anyhow::Result<()> {
            let base = root.join("base");
            fs::create_dir(&base)?;
            fs::write(base.join("file"), b"contents")?;
            fs::write(root.join("outside"), b"outside")?;
            unix_fs::symlink("file", base.join("inside"))?;
            unix_fs::symlink("../outside", base.join("escape"))?;
            let dir = rustix::fs::open(
                &base,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )?;

            for path in ["file", "inside"] {
                let mut bytes = Vec::new();
                open_file_beneath(&dir, Path::new(path))?.read_to_end(&mut bytes)?;
                ensure!(bytes == b"contents");
            }
            for path in [
                Path::new("../outside"),
                Path::new("escape"),
                Path::new("."),
                &base.join("file"),
            ] {
                ensure!(
                    open_file_beneath(&dir, path).is_err(),
                    "accepted: {}",
                    path.display()
                );
            }
            Ok(())
        })();

        fs::remove_dir_all(&root).unwrap();
        result.unwrap();
    }
}
