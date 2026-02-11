use crate::init_logger;
use crate::injector::ProviderHandlerRegistry;
use anyhow::Result;
use log::info;
use nix::libc::c_long;
use std::cell::RefCell;
use std::collections::HashMap;
use std::os::fd::{FromRawFd, OwnedFd};
use std::slice;
use zynx_bridge_shared::dlfcn::{JavaLibrary, Libraries, NativeLibrary};
use zynx_bridge_shared::zygote::{
    BridgeArgs, IpcPayload, LibraryType, ProviderType, SpecializeArgs,
};
use zynx_misc::ext::ResultExt;

struct SpecializeContext {
    args: SpecializeArgs,
    handler: ProviderHandlerRegistry,
    groups: HashMap<ProviderType, (Libraries, Option<Vec<u8>>)>,
}

thread_local! {
    static G_CONTEXT: RefCell<Option<SpecializeContext>> = RefCell::default();
}

fn on_specialize_pre(args: &mut [c_long], bridge_args: &BridgeArgs) -> Result<()> {
    let mut args_struct = SpecializeArgs::new(&mut *args, bridge_args.specialize_version);

    if bridge_args.conn_fd >= 0 {
        info!("connection fd: {}", bridge_args.conn_fd);

        let (payload, fds) =
            IpcPayload::recv_from(unsafe { OwnedFd::from_raw_fd(bridge_args.conn_fd) })?;

        let mut fds = fds.into_iter();
        let mut groups: HashMap<ProviderType, (Libraries, Option<Vec<u8>>)> = HashMap::new();

        for segment in payload.segments {
            let mut libs = Libraries::default();

            if let Some(descriptors) = segment.libraries {
                for (desc, fd) in descriptors.into_iter().zip(fds.by_ref()) {
                    match desc.lib_type {
                        LibraryType::Native => {
                            libs.native.push(NativeLibrary::new(desc.name, fd));
                        }
                        LibraryType::Java => {
                            libs.java.push(JavaLibrary::new(desc.name, fd));
                        }
                    }
                }
            }

            groups.insert(segment.provider_type, (libs, segment.data));
        }

        let handler = ProviderHandlerRegistry::new();
        handler.dispatch_pre(&mut args_struct, &mut groups);

        G_CONTEXT.with(|cell| {
            *cell.borrow_mut() = Some(SpecializeContext {
                args: args_struct.clone(),
                handler,
                groups,
            });
        });
    }

    args_struct.write_back_to_slice(args);
    Ok(())
}

fn on_specialize_post() -> Result<()> {
    G_CONTEXT.with(|cell| {
        if let Some(mut ctx) = cell.borrow_mut().take() {
            ctx.handler.dispatch_post(&ctx.args, &mut ctx.groups);
        }
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
