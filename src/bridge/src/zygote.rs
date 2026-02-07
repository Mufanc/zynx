use crate::init_logger;
use crate::injector::ProviderHandlerRegistry;
use anyhow::Result;
use log::{debug, info};
use nix::libc::c_long;
use std::cell::RefCell;
use std::os::fd::{FromRawFd, OwnedFd};
use std::slice;
use uds::UnixSeqpacketConn;
use zynx_bridge_types::dlfcn::Library;
use zynx_bridge_types::zygote::{BridgeArgs, LibraryList, SpecializeArgs};
use zynx_utils::ext::ResultExt;

thread_local! {
    static G_ARGS: RefCell<Option<SpecializeArgs>> = RefCell::default();
    static G_HANDLER: RefCell<Option<ProviderHandlerRegistry>> = RefCell::default();
}

fn on_specialize_pre(args: &mut [c_long], bridge_args: &BridgeArgs) -> Result<()> {
    let mut args_struct = SpecializeArgs::new(&mut *args, bridge_args.specialize_version);

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

        let library_list: LibraryList = wincode::deserialize(&buffer)?;
        let library_list: Vec<_> = library_list
            .info
            .into_iter()
            .zip(fds)
            .flat_map(|((name, provider_type), fd)| {
                Library::open(name, unsafe { OwnedFd::from_raw_fd(fd) }, provider_type)
                    .inspect_log_error()
            })
            .collect();

        let handler = ProviderHandlerRegistry::new();

        handler.dispatch_pre(&mut args_struct, library_list);

        G_HANDLER.with(|cell| {
            *cell.borrow_mut() = Some(handler);
        });
    }

    args_struct.write_back_to_slice(args);

    G_ARGS.with(|cell| {
        *cell.borrow_mut() = Some(args_struct);
    });

    Ok(())
}

fn on_specialize_post() -> Result<()> {
    G_ARGS.with(|args| {
        G_HANDLER.with(|handler| {
            if let (Some(args), Some(handler)) = (args.take(), handler.take()) {
                handler.dispatch_post(&args)
            }
        });
    });

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
