use jni::sys::{jint, jintArray, jlong};
use nix::libc::c_long;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use zynx_bridge_shared::zygote::SpecializeArgs;

#[repr(C)]
#[derive(Clone)]
pub struct ServerSpecializeArgsV4 {
    // required
    uid: *mut jint,
    gid: *mut jint,
    gids: *mut jintArray,
    runtime_flags: *mut jint,
    permitted_capabilities: *mut jlong,
    effective_capabilities: *mut jlong,
}

pub type ServerSpecializeArgsV5 = ServerSpecializeArgsV4;

#[repr(C)]
pub union ServerSpecializeArgs<'a> {
    v4: ManuallyDrop<ServerSpecializeArgsV4>,
    v5: ManuallyDrop<ServerSpecializeArgsV5>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> ServerSpecializeArgs<'a> {
    #[allow(unused_variables)]
    pub fn new(args: &'a mut SpecializeArgs, version: c_long) -> Self {
        macro_rules! as_ptr {
            ($name: ident) => {
                &mut args.$name as *mut _
            };
        }

        match version {
            4 | 5 => Self {
                v4: ManuallyDrop::new(ServerSpecializeArgsV4 {
                    uid: as_ptr!(uid),
                    gid: as_ptr!(gid),
                    gids: as_ptr!(gids),
                    runtime_flags: as_ptr!(runtime_flags),
                    permitted_capabilities: as_ptr!(permitted_capabilities),
                    effective_capabilities: as_ptr!(effective_capabilities),
                }),
            },
            _ => unreachable!(),
        }
    }
}
