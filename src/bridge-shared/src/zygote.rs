use std::mem::size_of;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use anyhow::{Result, bail};
use jni::sys::{JNIEnv, jint, jintArray, jlong, jobjectArray, jstring};
use nix::libc::{c_int, c_long};
use strum_macros::{AsRefStr, EnumIter};
use uds::UnixSeqpacketConn;
use wincode::{SchemaRead, SchemaWrite};

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

    #[allow(unused_mut)]
    #[allow(unused_variables)]
    #[allow(unused_assignments)]
    pub fn write_back_to_slice(&self, args: &mut [c_long]) {
        let mut index = 0;

        macro_rules! put {
            ($member: ident) => {{
                args[index] = self.$member as _;
                index += 1;
            }};
            ($member: ident, $version: ident) => {
                if self.version >= crate::zygote::SpecializeVersion::$version {
                    put!($member)
                }
            };
        }

        put!(env);
        put!(uid);
        put!(gid);
        put!(gids);
        put!(runtime_flags);
        put!(rlimits);
        put!(permitted_capabilities);
        put!(effective_capabilities);
        put!(bounding_capabilities);
        put!(mount_external, V);
        put!(managed_se_info);
        put!(managed_nice_name);
        put!(is_system_server);
        put!(is_child_zygote);
        put!(managed_instruction_set);
        put!(managed_app_data_dir);
        put!(is_top_app);
        put!(pkg_data_info_list);
        put!(allowlisted_data_info_list);
        put!(mount_data_dirs);
        put!(mount_storage_dirs);
        put!(mount_sysprop_overrides, V);
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, SchemaRead, SchemaWrite)]
pub enum ProviderType {
    Debugger,
    LiteLoader,
    #[cfg(feature = "zygisk")]
    Zygisk,
}

#[derive(Debug, SchemaRead, SchemaWrite)]
pub struct IpcPayload {
    pub segments: Vec<IpcSegment>,
}

#[derive(Debug, SchemaRead, SchemaWrite)]
pub struct IpcSegment {
    pub provider_type: ProviderType,
    pub names: Option<Vec<String>>,
    pub data: Option<Vec<u8>>,
}

impl IpcPayload {
    pub fn send_to<'fd>(
        &self,
        conn_fd: OwnedFd,
        fds: impl IntoIterator<Item = BorrowedFd<'fd>>,
    ) -> Result<()> {
        const SCM_MAX_FD: usize = 253;

        let raw_fds: Vec<RawFd> = fds.into_iter().map(|fd| fd.as_raw_fd()).collect();
        let data = wincode::serialize(self)?;

        assert!(
            raw_fds.len() <= SCM_MAX_FD,
            "too many fds to send: {} (max {SCM_MAX_FD})",
            raw_fds.len()
        );

        let conn = unsafe { UnixSeqpacketConn::from_raw_fd(conn_fd.into_raw_fd()) };

        conn.send(bytemuck::bytes_of(&[data.len(), raw_fds.len()]))?;
        conn.send_fds(&data, &raw_fds)?;

        Ok(())
    }

    pub fn recv_from(conn_fd: OwnedFd) -> Result<(Self, Vec<OwnedFd>)> {
        let conn = unsafe { UnixSeqpacketConn::from_raw_fd(conn_fd.into_raw_fd()) };
        let mut buffer = [0u8; size_of::<[usize; 2]>()];

        let received = conn.recv(&mut buffer)?;
        if received != size_of::<[usize; 2]>() {
            bail!(
                "incomplete IPC header: expected {} bytes, got {received}",
                size_of::<[usize; 2]>()
            );
        }

        let pair: &[usize; 2] = bytemuck::from_bytes(&buffer);
        let (buffer_len, fds_len) = (pair[0], pair[1]);

        let mut buffer: Vec<_> = vec![0; buffer_len];
        let mut raw_fds: Vec<RawFd> = vec![0; fds_len];

        let (bytes_received, truncated, fds_received) = conn.recv_fds(&mut buffer, &mut raw_fds)?;

        if truncated {
            bail!("IPC payload was truncated");
        }

        if bytes_received != buffer_len {
            bail!("incomplete IPC payload: expected {buffer_len} bytes, got {bytes_received}");
        }

        if fds_received != fds_len {
            bail!("incomplete IPC fds: expected {fds_len} fds, got {fds_received}");
        }

        let payload: IpcPayload = wincode::deserialize(&buffer)?;
        let fds = raw_fds
            .into_iter()
            .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
            .collect();

        Ok((payload, fds))
    }
}

#[repr(C)]
pub struct BridgeArgs {
    pub conn_fd: c_int,
    pub specialize_version: SpecializeVersion,
}
