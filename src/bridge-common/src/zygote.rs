use jni_sys::{JNIEnv, jint, jintArray, jlong, jobjectArray, jstring};
use nix::libc::c_long;
use strum_macros::{AsRefStr, EnumIter};

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq, AsRefStr, EnumIter)]
#[repr(u8)]
pub enum SpecializeVersion {
    #[strum(
        serialize = "_ZN12_GLOBAL__N_116SpecializeCommonEP7_JNIEnvjjP10_jintArrayiP13_jobjectArraylliP8_jstringS7_bbS7_S7_bS5_S5_bb"
    )]
    R = 30,
    #[strum(
        serialize = "_ZN12_GLOBAL__N_116SpecializeCommonEP7_JNIEnvjjP10_jintArrayiP13_jobjectArrayllliP8_jstringS7_bbS7_S7_bS5_S5_bbb"
    )]
    V = 35,
}

#[derive(Debug, Clone)]
pub struct SpecializeArgs {
    pub version: SpecializeVersion,
    pub env: JNIEnv,
    pub uid: jint,
    pub gid: jint,
    pub gids: jintArray,
    pub runtime_flags: jint,
    pub rlimits: jobjectArray,
    pub permitted_capabilities: jlong,
    pub effective_capabilities: jlong,
    pub bounding_capabilities: jlong,
    pub mount_external: jint,
    pub managed_se_info: jstring,
    pub managed_nice_name: jstring,
    pub is_system_server: bool,
    pub is_child_zygote: bool,
    pub managed_instruction_set: jstring,
    pub managed_app_data_dir: jstring,
    pub is_top_app: bool,
    pub pkg_data_info_list: jobjectArray,
    pub allowlisted_data_info_list: jobjectArray,
    pub mount_data_dirs: bool,
    pub mount_storage_dirs: bool,
    pub mount_sysprop_overrides: bool,
}

impl SpecializeArgs {
    #[allow(unused_mut)]
    #[allow(unused_variables)]
    pub fn new<T: AsRef<[c_long]>>(args: T, version: SpecializeVersion) -> Self {
        let args = args.as_ref().as_ptr();
        let mut index = 0;

        macro_rules! iota {
            () => {
                unsafe {
                    index += 1;
                    *(args.add(index - 1) as *const _)
                }
            };
        }

        macro_rules! require {
            ($version: ident) => {
                if version >= crate::zygote::SpecializeVersion::$version {
                    iota!()
                } else {
                    unsafe { std::mem::zeroed() }
                }
            };
        }

        Self {
            version,
            env: iota!(),
            uid: iota!(),
            gid: iota!(),
            gids: iota!(),
            runtime_flags: iota!(),
            rlimits: iota!(),
            permitted_capabilities: iota!(),
            effective_capabilities: iota!(),
            bounding_capabilities: iota!(),
            mount_external: require!(V),
            managed_se_info: iota!(),
            managed_nice_name: iota!(),
            is_system_server: iota!(),
            is_child_zygote: iota!(),
            managed_instruction_set: iota!(),
            managed_app_data_dir: iota!(),
            is_top_app: iota!(),
            pkg_data_info_list: iota!(),
            allowlisted_data_info_list: iota!(),
            mount_data_dirs: iota!(),
            mount_storage_dirs: iota!(),
            mount_sysprop_overrides: require!(V),
        }
    }
}
