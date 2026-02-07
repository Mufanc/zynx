use crate::init_logger;
use anyhow::Result;
use log::{debug, info};
use nix::libc::c_long;
use std::os::fd::{FromRawFd, OwnedFd};
use std::slice;
use uds::UnixSeqpacketConn;
use zynx_bridge_types::dlfcn::Library;
use zynx_bridge_types::zygote::{ArchivedLibraryList, BridgeArgs};
use zynx_utils::ext::ResultExt;

#[cfg(feature = "zygisk")]
mod zygisk {
    pub use zynx_zygisk_compat::*;
}

fn on_specialize_pre(args: &mut [c_long], bridge_args: &BridgeArgs) -> Result<()> {
    if bridge_args.conn_fd >= 0 {
        info!("connection fd: {}", bridge_args.conn_fd);

        let conn = unsafe { UnixSeqpacketConn::from_raw_fd(bridge_args.conn_fd) };
        let mut buffer = [0u8; 16];

        conn.recv(&mut buffer)?;

        let pair: &[usize; 2] = bytemuck::from_bytes(&buffer);
        let (buffer_len, fds_len) = (pair[0], pair[1]);

        debug!("buffer_len = {buffer_len}, fds_len = {fds_len}");

        let mut buffer: Vec<_> = vec![0; buffer_len];
        let mut fds: Vec<_> = vec![0; fds_len];

        conn.recv_fds(&mut buffer, &mut fds)?;

        let library_list = rkyv::access::<ArchivedLibraryList, rkyv::rancor::Error>(&buffer)?;
        let library_list: Vec<_> = library_list
            .names
            .iter()
            .zip(fds)
            .map(|(name, fd)| Library::open(name, unsafe { OwnedFd::from_raw_fd(fd) }))
            .collect();

        drop(library_list); // Todo: zygisk compatible api?
    }

    Ok(())
}

fn on_specialize_post() -> Result<()> {
    Ok(())
}

#[unsafe(no_mangle)]
extern "C" fn specialize_pre(args: *mut c_long, args_count: usize, bridge_args: *const BridgeArgs) {
    let args = unsafe { slice::from_raw_parts_mut(args, args_count) };
    let bridge_args = unsafe { &*bridge_args };

    init_logger();
    info!("specialize args: {args:?}");

    on_specialize_pre(args, bridge_args).log_if_error()
}

#[unsafe(no_mangle)]
extern "C" fn specialize_post() {
    info!("post specialize");

    on_specialize_post().log_if_error()
}
