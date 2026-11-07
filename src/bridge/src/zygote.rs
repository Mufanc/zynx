use crate::init_logger;
use crate::injector::ActionExecutor;
use anyhow::Result;
use log::{debug, info};
use nix::libc::c_long;
use std::cell::RefCell;
use std::os::fd::{FromRawFd, OwnedFd};
use std::slice;
use zynx_bridge_api::action::Action;
use zynx_bridge_shared::zygote::{BridgeArgs, IpcPayload, SpecializeArgs};
use zynx_misc::ext::ResultExt;

struct SpecializeContext {
    args: SpecializeArgs,
    executor: ActionExecutor,
}

thread_local! {
    static G_CONTEXT: RefCell<Option<SpecializeContext>> = RefCell::default();
}

fn on_specialize_pre(args: &mut [c_long], bridge_args: &BridgeArgs) -> Result<()> {
    let mut args_struct = SpecializeArgs::new(&mut *args, bridge_args.specialize_version);

    info!("specialize args: {args_struct:?}");

    if bridge_args.conn_fd >= 0 {
        debug!("connection fd: {}", bridge_args.conn_fd);

        let (payload, fds) =
            IpcPayload::recv_from(unsafe { OwnedFd::from_raw_fd(bridge_args.conn_fd) })?;

        let mut fds = fds.into_iter();
        let actions = payload
            .actions
            .into_iter()
            .map(|wire| Action {
                fd: if wire.has_fd { fds.next() } else { None },
                data: wire.data,
            })
            .collect();
        let mut executor = ActionExecutor::new(actions)?;

        executor.specialize_pre(&mut args_struct);

        G_CONTEXT.with(|cell| {
            *cell.borrow_mut() = Some(SpecializeContext {
                args: args_struct.clone(),
                executor,
            });
        });
    }

    args_struct.write_back_to_slice(args);
    Ok(())
}

fn on_specialize_post() -> Result<()> {
    G_CONTEXT.with(|cell| {
        if let Some(ctx) = cell.borrow_mut().take() {
            ctx.executor.specialize_post(&ctx.args);
        }
    });

    Ok(())
}

#[unsafe(no_mangle)]
extern "C" fn specialize_pre(args: *mut c_long, args_count: usize, bridge_args: *const BridgeArgs) {
    let args = unsafe { slice::from_raw_parts_mut(args, args_count) };
    let bridge_args = unsafe { &*bridge_args };

    init_logger();
    debug!("specialize args: {args:?}");

    on_specialize_pre(args, bridge_args).log_if_error()
}

#[unsafe(no_mangle)]
extern "C" fn specialize_post() {
    debug!("post specialize");

    on_specialize_post().log_if_error()
}
