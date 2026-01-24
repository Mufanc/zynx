use crate::injector::app::zygote::ZygoteMaps;
use crate::injector::app::{SC_BRK, SC_CONFIG};
use crate::injector::app::policy::{EmbryoCheckArgs, EmbryoCheckResult, InjectorPolicy};
use crate::injector::ptrace::ext::WaitStatusExt;
use crate::injector::ptrace::ext::base::PtraceExt;
use crate::injector::ptrace::ext::ipc::{MmapOptions, PtraceIpcExt};
use crate::injector::ptrace::ext::jni::PtraceJniExt;
use crate::injector::ptrace::ext::remote_call::{PtraceRemoteCallExt, RemoteLibraryResolver};
use crate::injector::ptrace::{RegSet, RemoteProcess};
use crate::injector::trampoline::Bridge;
use crate::injector::{PAGE_SIZE, misc};
use crate::{build_args, dynasm};
use anyhow::{Context, Result, bail};
use dynasmrt::VecAssembler;
use dynasmrt::aarch64::Aarch64Relocation;
use log::{debug, info, trace, warn};
use nix::libc::{
    MADV_DONTNEED, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, RTLD_NOW, c_int,
    c_long, off64_t, size_t,
};
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::{Gid, Pid, Uid};
use once_cell::sync::Lazy;
use scopeguard::defer;
use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::os::fd::{AsFd, AsRawFd};
use std::{fmt, ptr};
use syscalls::Sysno;
use zynx_bridge_common::zygote::SpecializeArgs;
use zynx_common::ext::ResultExt;

static TRAMPOLINE_SIZE: Lazy<usize> = Lazy::new(|| *PAGE_SIZE);

#[repr(C)]
pub struct DlextInfo {
    pub flags: u64,
    pub reserved_addr: *const c_void,
    pub reserved_size: size_t,
    pub relro_fd: c_int,
    pub library_fd: c_int,
    pub library_fd_offset: off64_t,
    pub library_namespace: *const c_void,
}

pub struct EmbryoInjector {
    tracee: RemoteProcess,
    maps: ZygoteMaps,
    specialize_fn: usize,
}

impl RemoteLibraryResolver for EmbryoInjector {
    fn find_library_base(&self, library: &str) -> Result<usize> {
        self.maps
            .find_library_base_by_name(library)
            .context(format!("failed to resolve library: {library}"))
    }
}

impl EmbryoInjector {
    pub fn new(pid: Pid, maps: ZygoteMaps, specialize_fn: usize) -> Self {
        Self {
            tracee: RemoteProcess::new(pid),
            maps,
            specialize_fn,
        }
    }

    pub fn start(&self) -> Result<()> {
        // install swbp
        self.poke_data_ignore_perm(self.specialize_fn, &SC_BRK)?;

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

                    let args = SpecializeArgs::new(&raw_args, SC_CONFIG.ver);

                    debug!("{self} specialize args: {args:?}");

                    if self.check_process(&args)? {
                        self.do_inject(regs, &raw_args)?;
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
        debug!("{self} restore swbp: {}", self.specialize_fn);

        // note: no writeback is required because MADV_DONTNEED immediately unmaps the memory,
        // subsequent accesses to this region will trigger page faults and reload data from the file.
        // self.poke_data_ignore_perm(swbp.addr(), swbp.backup())?;

        #[rustfmt::skip]
        let result = self.call_remote_auto(
            ("libc", "madvise"),
            build_args!(misc::floor_to_page_size(self.specialize_fn), *PAGE_SIZE, MADV_DONTNEED)
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

    fn do_inject(&self, mut regs: RegSet, raw_args: &[c_long]) -> Result<()> {
        info!("injecting process: {self}, raw_args = {raw_args:?}");

        let trampoline_addr = self.mmap_ex(
            MmapOptions::new(
                *TRAMPOLINE_SIZE,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
            )
            .name("zynx::trampoline"),
        )?;
        let conn = self.connect(trampoline_addr)?;

        let bridge = Bridge::instance();
        let bridge_fd = self.install_fd(trampoline_addr, &conn, bridge.as_fd())?;

        debug!("{self} bridge fd: {bridge_fd:?}");

        let bridge_fd_num = bridge_fd.as_raw_fd();

        bridge_fd.forget();
        conn.close(self)?;

        // Todo: serve for module fds

        let mut ops: VecAssembler<Aarch64Relocation> = VecAssembler::new(0);

        let info = DlextInfo {
            flags: 0x10, // ANDROID_DLEXT_USE_LIBRARY_FD
            reserved_addr: ptr::null(),
            reserved_size: 0,
            relro_fd: 0,
            library_fd: bridge_fd_num,
            library_fd_offset: 0,
            library_namespace: ptr::null(),
        };

        dynasm!(ops
            // save args on register
            ; stp x6, x7, [sp, #-16]!
            ; stp x4, x5, [sp, #-16]!
            ; stp x2, x3, [sp, #-16]!
            ; stp x0, x1, [sp, #-16]!

            // dlopen
            ; stp fp, lr, [sp, #-16]!
            ; ldr ip, >dlopen
            ; adr x0, >lib_name
            ; mov x1, RTLD_NOW as _
            ; adr x2, >lib_info
            ; blr ip
            ; ldp fp, lr, [sp], #16

            // close
            ; stp x0, xzr, [sp, #-16]!
            ; mov x8, Sysno::close as _
            ; mov x0, bridge_fd_num as _
            ; svc #0
            ; ldp x0, xzr, [sp], #16

            // dlsym post-hook
            ; stp fp, lr, [sp, #-16]!
            ; stp x0, x1, [sp, #-16]!
            ; ldr ip, >dlsym
            ; adr x1, >post_hook_sym
            ; blr ip
            ; adr x1, >post_hook_addr
            ; str x0, [x1]
            ; ldp x0, x1, [sp], #16
            ; ldp fp, lr, [sp], #16

            // dlsym pre-hook
            ; stp fp, lr, [sp, #-16]!
            ; ldr ip, >dlsym
            ; adr x1, >pre_hook_sym
            ; blr ip
            ; ldp fp, lr, [sp], #16

            // call pre-hook
            ; stp fp, lr, [sp, #-16]!
            ; mov ip, x0
            ; add x0, sp, 16
            ; mov x1, SC_CONFIG.args_cnt as _
            ; blr ip
            ; ldp fp, lr, [sp], #16

            // replace lr
            ; adr x0, >specialize_lr
            ; str lr, [x0]
            ; adr lr, >trampoline

            // restore args from stack
            ; ldp x0, x1, [sp], #16
            ; ldp x2, x3, [sp], #16
            ; ldp x4, x5, [sp], #16
            ; ldp x6, x7, [sp], #16

            // call SpecializeCommon
            ; ldr ip, >specialize
            ; br ip

            // call post-hook
            ; trampoline:
            ; stp fp, lr, [sp, #-16]!
            ; ldr ip, >post_hook_addr
            ; blr ip
            ; ldp fp, lr, [sp], #16

            // tail call munmap
            ; ldr lr, >specialize_lr
            ; ldr ip, >munmap
            ; ldr x0, >trampoline_addr
            ; mov x1, *TRAMPOLINE_SIZE as _
            ; br ip

            // for specialize
            ; .align 8
            ; specialize:
            ;; ops.push_u64(self.specialize_fn as _)

            ; .align 8
            ; specialize_lr:
            ;; ops.push_u64(0xfee1deadfee1dead)

            // for dlopen
            ; .align 8
            ; dlopen:
            ;; ops.push_u64(self.resolve_fn(("libdl", "android_dlopen_ext"))? as _)

            ; .align 8
            ; dlsym:
            ;; ops.push_u64(self.resolve_fn(("libdl", "dlsym"))? as _)

            ; .align 8
            ; lib_name:
            ;; ops.extend(c"zynx::bridge".to_bytes_with_nul())

            ; .align align_of::<DlextInfo>()
            ; lib_info:
            ;; ops.extend(crate::misc::as_byte_slice(&info))

            // for hooks
            ; .align 8
            ; pre_hook_sym:
            ;; ops.extend(c"specialize_pre".to_bytes_with_nul())

            ; .align 8
            ; post_hook_sym:
            ;; ops.extend(c"specialize_post".to_bytes_with_nul())

            ; .align 8
            ; post_hook_addr:
            ;; ops.push_u64(0xfee1deadfee1dead)

            // for unmap
            ; .align 8
            ; munmap:
            ;; ops.push_u64(self.resolve_fn(("libc", "munmap"))? as _)

            ; .align 8
            ; trampoline_addr:
            ;; ops.push_u64(trampoline_addr as _)
        );

        let bytecode = ops.finalize()?;

        trace!("dynasm bytecode: {bytecode:?}");

        self.poke_data(trampoline_addr, &bytecode)?;

        regs.set_pc(trampoline_addr);
        self.set_regs(&regs)?;

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
