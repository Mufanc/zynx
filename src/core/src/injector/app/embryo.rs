use crate::injector::app::zygote::{SwbpConfig, ZygoteMaps};
use crate::injector::app::{API_LEVEL, ResumeGuard, SC_CONFIG};
use crate::injector::policy::{EmbryoCheckArgs, EmbryoCheckResult, InjectorPolicy};
use crate::injector::ptrace::{RegSet, RemoteProcess};
use crate::injector::ptrace::ext::WaitStatusExt;
use crate::injector::ptrace::ext::base::PtraceExt;
use crate::injector::ptrace::ext::ipc::{MmapOptions, PtraceIpcExt};
use crate::injector::ptrace::ext::jni::PtraceJniExt;
use crate::injector::ptrace::ext::remote_call::{PtraceRemoteCallExt, RemoteLibraryResolver};
use crate::injector::trampoline::Bridge;
use crate::injector::{PAGE_SIZE, misc};
use crate::build_args;
use anyhow::{Context, Result, bail};
use jni_sys::{JNIEnv, jint, jintArray, jlong, jobjectArray, jstring};
use log::{debug, warn};
use nix::libc::{
    MADV_DONTNEED, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, c_long,
};
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::{Gid, Pid, Uid};
use scopeguard::defer;
use std::{fmt, slice};
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::os::fd::{AsFd, AsRawFd};
use once_cell::sync::Lazy;
use zynx_bridge_common::{EmbryoTrampolineArgs, EmbryoTrampolineFnPtrs, MemoryRegion, SpecializeHookInfo};
use zynx_common::ext::ResultExt;

static BUFFER_SIZE: Lazy<usize> = Lazy::new(|| {
    let buffer_size = *PAGE_SIZE;
    assert!(size_of::<EmbryoTrampolineArgs>() <= buffer_size);
    buffer_size
});

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
    pub fn new<T: AsRef<[c_long]>>(args: &T, api_level: i32) -> Self {
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

        defer! {
            self.detach(None).log_if_error();
        }

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
                    let mut raw_args = vec![0; SC_CONFIG.args_cnt];

                    self.get_args(&mut raw_args)?;
                    self.restore_swbp()?;

                    let args = SpecializeArgs::new(&raw_args, *API_LEVEL);

                    debug!("{self} specialize args: {args:?}");

                    if self.check_process(&args)? {
                        self.do_inject(&regs, &raw_args)?;
                    } else {
                        self.set_regs(&regs)?;
                    }

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
            build_args!(misc::floor_to_page_size(swbp.addr()), *PAGE_SIZE, MADV_DONTNEED)
        )?;

        if result == -1 {
            bail!("failed to restore swbp");
        }

        Ok(())
    }

    fn check_process(&self, args: &SpecializeArgs) -> Result<bool> {
        let fast_args = EmbryoCheckArgs::new_fast(
            Uid::from_raw(args.uid as _),
            Gid::from_raw(args.gid as _),
            args.is_system_server,
            args.is_child_zygote,
        );

        self.check_process_with_structured_args(args, fast_args)
    }

    fn check_process_with_structured_args(
        &self,
        specialize_args: &SpecializeArgs,
        check_args: EmbryoCheckArgs,
    ) -> Result<bool> {
        Ok(match InjectorPolicy::check_embryo(&check_args) {
            EmbryoCheckResult::Deny => false,
            EmbryoCheckResult::Allow => true,
            EmbryoCheckResult::MoreInfo => {
                if check_args.is_slow() {
                    warn!("recursive check detected, denying process");
                    return Ok(false);
                }

                let slow_args = check_args.into_slow(
                    self.read_jstring(specialize_args.env, specialize_args.managed_nice_name)?,
                    self.read_jstring(specialize_args.env, specialize_args.managed_app_data_dir)?,
                );

                self.check_process_with_structured_args(specialize_args, slow_args)?
            }
        })
    }

    fn do_inject(&self, regs: &RegSet, raw_args: &[c_long]) -> Result<()> {
        let buffer_addr = self.mmap_ex(
            MmapOptions::new(
                *BUFFER_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
            )
            .name("zynx::buffer"),
        )?;
        let conn = self.connect(buffer_addr)?;

        let bridge = Bridge::instance();
        let bridge_fd = self.install_fd(buffer_addr, &conn, bridge.as_fd())?;

        debug!("{self} bridge fd: {bridge_fd:?}");

        let bridge_fd_num = bridge_fd.as_raw_fd();

        let trampoline_addr = self.mmap_ex(
            MmapOptions::new(bridge.trampoline_size(), PROT_READ | PROT_EXEC, MAP_PRIVATE).fd(&bridge_fd),
        )?;

        bridge_fd.forget();
        conn.close(self)?;

        let offset = bridge.resolve("embryo_trampoline_entry")?;
        let args = EmbryoTrampolineArgs {
            bridge_library_fd: bridge_fd_num,
            fn_ptrs: EmbryoTrampolineFnPtrs {
                dlopen: self.resolve_fn(("libdl", "android_dlopen_ext"))?,
                dlsym: self.resolve_fn(("libdl", "dlsym"))?
            },
            trampoline_region: MemoryRegion {
                base: trampoline_addr,
                size: misc::ceil_to_page_size(bridge.trampoline_size()),
            },
            buffer_region: MemoryRegion {
                base: buffer_addr,
                size: misc::ceil_to_page_size(*BUFFER_SIZE),
            },
            specialize_hook: SpecializeHookInfo {
                specialize_fn: self.swbp.addr(),
                specialize_args: {
                    let mut args = [0; _];
                    args[..raw_args.len()].copy_from_slice(raw_args);
                    args
                },
                specialize_args_count: raw_args.len(),
                return_sp: regs.get_sp(),
                return_fp: regs.get_fp(),
                return_lr: regs.get_lr(),
                callee_saves: regs.callee_saves(),
            },
        };

        let args_slice = unsafe {
            slice::from_raw_parts(&args as *const _ as *const u8, size_of_val(&args))
        };

        self.poke_data(buffer_addr, args_slice)?;
        self.call_remote_auto_nowait(
            trampoline_addr + offset,
            0, /* embryo will never return from this call */
            build_args!(buffer_addr),
        )?;

        Ok(())
    }
}

impl Deref for EmbryoInjector {
    type Target = RemoteProcess;

    fn deref(&self) -> &Self::Target {
        &self.tracee
    }
}

impl Display for EmbryoInjector {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.tracee, fmt)
    }
}
