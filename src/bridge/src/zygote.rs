use crate::init_logger;
use crate::injector::ProviderHandlerRegistry;
use anyhow::Result;
use log::info;
use nix::libc::c_long;
use std::cell::RefCell;
use std::collections::HashMap;
use std::os::fd::{FromRawFd, OwnedFd};
use std::slice;
use zynx_bridge_types::dlfcn::Library;
use zynx_bridge_types::zygote::{BridgeArgs, IpcPayload, ProviderType, SpecializeArgs};
use zynx_utils::ext::ResultExt;

thread_local! {
    static G_ARGS: RefCell<Option<SpecializeArgs>> = RefCell::default();
    static G_HANDLER: RefCell<Option<ProviderHandlerRegistry>> = RefCell::default();
}

fn on_specialize_pre(args: &mut [c_long], bridge_args: &BridgeArgs) -> Result<()> {
    let mut args_struct = SpecializeArgs::new(&mut *args, bridge_args.specialize_version);

    if bridge_args.conn_fd >= 0 {
        info!("connection fd: {}", bridge_args.conn_fd);

        let (payload, fds) =
            IpcPayload::recv_from(unsafe { OwnedFd::from_raw_fd(bridge_args.conn_fd) })?;

        let mut fds = fds.into_iter();
        let mut groups: HashMap<ProviderType, (Vec<Library>, Option<Vec<u8>>)> = HashMap::new();

        for segment in payload.segments {
            let mut libs = Vec::new();

            if let Some(names) = segment.names {
                for (name, fd) in names.into_iter().zip(fds.by_ref()) {
                    if let Ok(lib) = Library::open(name, fd).inspect_log_error() {
                        libs.push(lib);
                    }
                }
            }

            groups.insert(segment.provider_type, (libs, segment.data));
        }

        let handler = ProviderHandlerRegistry::new();
        handler.dispatch_pre(&mut args_struct, groups);

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
