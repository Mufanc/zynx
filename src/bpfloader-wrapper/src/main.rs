use rustix::fd::OwnedFd;
use rustix::fs::{self, CWD, Mode, OFlags, XattrFlags};
use rustix::mount::{self, MoveMountFlags, OpenTreeFlags, UnmountFlags};
use rustix::net::sockopt::Timeout;
use rustix::net::{self, AddressFamily, RecvFlags, SocketAddrUnix, SocketFlags, SocketType};
use std::env;
use std::ffi::{CStr, OsStr};
use std::fs::File;
use std::io;
use std::process::Command;
use std::time::Duration;

const BPFLOADER_PATH: &str = "/system/bin/bpfloader";
const WRAPPER_PATH: &str = "/dev/.zynx-bpfloader";
const ZYNX_SOCKET_NAME: &[u8] = b"zynx-bpfloader-sock";
const ZYNX_TIMEOUT: Duration = Duration::from_secs(10);
const SELINUX_XATTR: &CStr = c"security.selinux";

fn copy_selinux_context(source: &CStr, target: &OwnedFd) -> io::Result<()> {
    let size = fs::getxattr(source, SELINUX_XATTR, &mut [0_u8; 0])?;
    let mut context = vec![0_u8; size];
    let size = fs::getxattr(source, SELINUX_XATTR, &mut context)?;

    Ok(fs::fsetxattr(
        target,
        SELINUX_XATTR,
        &context[..size],
        XattrFlags::empty(),
    )?)
}

fn stage_wrapper() -> io::Result<OwnedFd> {
    let mut source = File::open("/proc/self/exe")?;
    let mut target = File::options()
        .write(true)
        .create_new(true)
        .open(WRAPPER_PATH)?;

    fs::fchmod(&target, Mode::from_raw_mode(0o755))?;
    io::copy(&mut source, &mut target)?;

    Ok(target.into())
}

fn mount_wrapper() -> Result<(), Box<dyn std::error::Error>> {
    match fs::unlink(WRAPPER_PATH) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(error.into()),
    }

    let attach_result = (|| -> io::Result<()> {
        let wrapper = stage_wrapper()?;

        copy_selinux_context(c"/system/bin/bpfloader", &wrapper)?;

        let tree = mount::open_tree(
            CWD,
            WRAPPER_PATH,
            OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
        )?;
        let target = fs::open(
            BPFLOADER_PATH,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
        )?;

        Ok(mount::move_mount(
            &tree,
            "",
            &target,
            "",
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
        )?)
    })();

    let unlink_result = fs::unlink(WRAPPER_PATH);
    attach_result?;
    unlink_result?;

    Ok(())
}

fn notify_zynx() -> io::Result<()> {
    let socket = net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    let address = SocketAddrUnix::new_abstract_name(ZYNX_SOCKET_NAME)?;

    net::connect(&socket, &address)?;
    net::sockopt::set_socket_timeout(&socket, Timeout::Recv, Some(ZYNX_TIMEOUT))?;

    let mut ready = [0_u8];
    let (_, received) = net::recv(&socket, &mut ready[..], RecvFlags::empty())?;

    if received != ready.len() || ready[0] != 1 {
        return Err(io::Error::other("invalid Zynx readiness response"));
    }

    Ok(())
}

fn run_bpfloader() -> Result<(), Box<dyn std::error::Error>> {
    mount::unmount(BPFLOADER_PATH, UnmountFlags::DETACH)?;

    let status = Command::new(BPFLOADER_PATH)
        .args(env::args_os().skip(1))
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("bpfloader failed: {status}")).into());
    }

    if let Err(error) = notify_zynx() {
        eprintln!("failed to notify Zynx: {error}");
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().nth(1).as_deref() == Some(OsStr::new("mount")) {
        mount_wrapper()
    } else {
        run_bpfloader()
    }
}
