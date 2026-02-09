use jni_sys::{jboolean, jint, jintArray, jobjectArray, jstring};
use nix::libc::c_long;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ptr;
use zynx_bridge_shared::zygote::SpecializeArgs;

#[repr(C)]
#[derive(Clone)]
pub struct AppSpecializeArgsV4 {
    // required
    uid: *mut jint,
    gid: *mut jint,
    gids: *mut jintArray,
    runtime_flags: *mut jint,
    rlimits: *mut jobjectArray,
    mount_external: *mut jint,
    se_info: *mut jstring,
    nice_name: *mut jstring,
    instruction_set: *mut jstring,
    app_data_dir: *mut jstring,

    // optional
    fds_to_ignore: *mut jintArray,
    is_child_zygote: *mut jboolean,
    is_top_app: *mut jboolean,
    pkg_data_info_list: *mut jobjectArray,
    whitelisted_data_info_list: *mut jobjectArray,
    mount_data_dirs: *mut jboolean,
    mount_storage_dirs: *mut jboolean,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AppSpecializeArgsV5 {
    // required
    uid: *mut jint,
    gid: *mut jint,
    gids: *mut jintArray,
    runtime_flags: *mut jint,
    rlimits: *mut jobjectArray,
    mount_external: *mut jint,
    se_info: *mut jstring,
    nice_name: *mut jstring,
    instruction_set: *mut jstring,
    app_data_dir: *mut jstring,

    // optional
    fds_to_ignore: *mut jintArray,
    is_child_zygote: *mut jboolean,
    is_top_app: *mut jboolean,
    pkg_data_info_list: *mut jobjectArray,
    whitelisted_data_info_list: *mut jobjectArray,
    mount_data_dirs: *mut jboolean,
    mount_storage_dirs: *mut jboolean,
    mount_sysprop_overrides: *mut jboolean,
}

#[repr(C)]
pub union AppSpecializeArgs<'a> {
    pub v4: ManuallyDrop<AppSpecializeArgsV4>,
    pub v5: ManuallyDrop<AppSpecializeArgsV5>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> AppSpecializeArgs<'a> {
    #[allow(unused_variables)]
    pub fn new(args: &'a mut SpecializeArgs, version: c_long) -> Self {
        macro_rules! as_ptr {
            ($name: ident) => {
                &mut args.$name as *mut _
            };
        }

        match version {
            4 => Self {
                v4: ManuallyDrop::new(AppSpecializeArgsV4 {
                    uid: as_ptr!(uid),
                    gid: as_ptr!(gid),
                    gids: as_ptr!(gids),
                    runtime_flags: as_ptr!(runtime_flags),
                    rlimits: as_ptr!(rlimits),
                    mount_external: as_ptr!(mount_external),
                    se_info: as_ptr!(managed_se_info),
                    nice_name: as_ptr!(managed_nice_name),
                    instruction_set: as_ptr!(managed_instruction_set),
                    app_data_dir: as_ptr!(managed_app_data_dir),
                    fds_to_ignore: ptr::null_mut(), // zynx does not support this
                    is_child_zygote: as_ptr!(is_child_zygote),
                    is_top_app: as_ptr!(is_top_app),
                    pkg_data_info_list: as_ptr!(pkg_data_info_list),
                    whitelisted_data_info_list: as_ptr!(allowlisted_data_info_list),
                    mount_data_dirs: as_ptr!(mount_data_dirs),
                    mount_storage_dirs: as_ptr!(mount_storage_dirs),
                }),
            },
            5 => Self {
                v5: ManuallyDrop::new(AppSpecializeArgsV5 {
                    uid: as_ptr!(uid),
                    gid: as_ptr!(gid),
                    gids: as_ptr!(gids),
                    runtime_flags: as_ptr!(runtime_flags),
                    rlimits: as_ptr!(rlimits),
                    mount_external: as_ptr!(mount_external),
                    se_info: as_ptr!(managed_se_info),
                    nice_name: as_ptr!(managed_nice_name),
                    instruction_set: as_ptr!(managed_instruction_set),
                    app_data_dir: as_ptr!(managed_app_data_dir),
                    fds_to_ignore: ptr::null_mut(), // zynx does not support this
                    is_child_zygote: as_ptr!(is_child_zygote),
                    is_top_app: as_ptr!(is_top_app),
                    pkg_data_info_list: as_ptr!(pkg_data_info_list),
                    whitelisted_data_info_list: as_ptr!(allowlisted_data_info_list),
                    mount_data_dirs: as_ptr!(mount_data_dirs),
                    mount_storage_dirs: as_ptr!(mount_storage_dirs),
                    mount_sysprop_overrides: as_ptr!(mount_sysprop_overrides),
                }),
            },
            _ => unreachable!(),
        }
    }
}
