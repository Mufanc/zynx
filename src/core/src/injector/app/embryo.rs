use crate::build_args;
use crate::injector::app::zygote::{SwbpConfig, ZygoteMaps};
use crate::injector::app::{API_LEVEL, PAGE_SIZE, ResumeGuard, SC_CONFIG};
use crate::injector::ptrace::RemoteProcess;
use crate::injector::ptrace::ext::{
    PtraceExt, PtraceRemoteCallExt, RemoteLibraryResolver, WaitStatusExt,
};
use crate::misc::ext::ResultExt;
use anyhow::{Context, Result, bail};
use jni_sys::{JNIEnv, jint, jintArray, jlong, jobjectArray, jstring};
use log::{debug, warn};
use nix::libc::MADV_DONTNEED;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use std::ffi::c_long;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::fmt;

#[derive(Debug, Clone)]
pub struct SpecializeArgs {
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
    pub fn new<T: AsRef<[c_long]>>(args: T, api_level: i32) -> Self {
        let args = args.as_ref().as_ptr();
        let mut index = 0;

        macro_rules! next_arg {
            () => {
                unsafe {
                    index += 1;
                    *(args.add(index - 1) as *const _)
                }
            };
        }

        macro_rules! require {
            ($minapi: literal) => {
                if api_level >= $minapi {
                    next_arg!()
                } else {
                    unsafe { std::mem::zeroed() }
                }
            };
        }

        Self {
            env: next_arg!(),
            uid: next_arg!(),
            gid: next_arg!(),
            gids: next_arg!(),
            runtime_flags: next_arg!(),
            rlimits: next_arg!(),
            permitted_capabilities: next_arg!(),
            effective_capabilities: next_arg!(),
            bounding_capabilities: next_arg!(),
            mount_external: require!(35),
            managed_se_info: next_arg!(),
            managed_nice_name: next_arg!(),
            is_system_server: next_arg!(),
            is_child_zygote: next_arg!(),
            managed_instruction_set: next_arg!(),
            managed_app_data_dir: next_arg!(),
            is_top_app: next_arg!(),
            pkg_data_info_list: next_arg!(),
            allowlisted_data_info_list: next_arg!(),
            mount_data_dirs: next_arg!(),
            mount_storage_dirs: next_arg!(),
            mount_sysprop_overrides: require!(35),
        }
    }
}

pub struct EmbryoInjector {
    pid: Pid,
    tracee: RemoteProcess,
    maps: ZygoteMaps,
    swbp: SwbpConfig,
}

impl RemoteLibraryResolver for EmbryoInjector {
    fn find_library_base(&self, library: &str) -> Result<usize> {
        self.maps
            .find_library_base_by_name(library)
            .context(format!("failed to resolve library: {library}"))
    }
}

impl EmbryoInjector {
    pub fn new(pid: Pid, maps: ZygoteMaps, swbp: SwbpConfig) -> Self {
        Self {
            pid,
            tracee: RemoteProcess::new(pid),
            maps,
            swbp,
        }
    }

    pub fn on_specialize(&self) -> Result<()> {
        let _dontdrop = ResumeGuard::new(self.pid);

        self.seize()?;
        self.kill(Signal::SIGCONT)?;

        loop {
            let status = self.wait()?;

            debug!("{self} status = {status:?}");

            match status {
                WaitStatus::Exited(_, code) => {
                    warn!("embryo exited with code: {code}");
                    break;
                }
                WaitStatus::Signaled(_, sig, _) => {
                    warn!("embryo killed by {sig}");
                    break;
                }
                WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                    let regs = self.get_regs()?;
                    let mut args = vec![0; SC_CONFIG.args_cnt];

                    self.get_args(&mut args)?;
                    self.restore_swbp()?;

                    let _ = self.check_process(&args);

                    self.set_regs(&regs)?;

                    break;
                }
                _ => {}
            }

            self.cont(status.sig())?;
        }

        Ok(())
    }

    fn restore_swbp(&self) -> Result<()> {
        let swbp = &self.swbp;

        debug!("{self} restore swbp: {swbp:?}");

        // note: no writeback is required because MADV_DONTNEED immediately unmaps the memory,
        // subsequent accesses to this region will trigger page faults and reload data from the file.
        // self.poke_data_ignore_perm(swbp.addr(), swbp.backup())?;

        #[rustfmt::skip]
        let result = self.call_remote_auto(
            ("libc", "madvise"),
            build_args!(swbp.page_addr(), *PAGE_SIZE, MADV_DONTNEED)
        )?;

        if result == -1 {
            bail!("failed to restore swbp");
        }

        Ok(())
    }

    fn check_process(&self, args: &[c_long]) -> Result<bool> {
        let args = SpecializeArgs::new(args, *API_LEVEL);

        debug!("{self} specialize args: {args:?}");

        // Todo: quick check with uid/gid
        // Todo: slow check with se_info/nice_name/app_data_dir

        Ok(false)
    }
}

impl Deref for EmbryoInjector {
    type Target = RemoteProcess;

    fn deref(&self) -> &Self::Target {
        &self.tracee
    }
}

impl Drop for EmbryoInjector {
    fn drop(&mut self) {
        if self.tracee.detach(None).ok_or_warn().is_some() {
            debug!("detached from: {}", self.tracee)
        }
    }
}

impl Display for EmbryoInjector {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.tracee, fmt)
    }
}
