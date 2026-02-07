use crate::android::packages::PackageInfoService;
use crate::injector::app::policy::{EmbryoCheckArgs, InjectLibrary, PolicyProviderManager};
use crate::injector::app::zygote::ZygoteMaps;
use crate::injector::app::{SC_BRK, SC_CONFIG};
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
    MADV_DONTNEED, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, RTLD_NOW, c_long,
};
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::{Gid, Pid, Uid};
use once_cell::sync::Lazy;
use scopeguard::defer;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::Arc;
use syscalls::Sysno;
use uds::UnixSeqpacketConn;
use zynx_bridge_types::dlext::DlextInfo;
use zynx_bridge_types::zygote::{BridgeArgs, LibraryList, SpecializeArgs};
use zynx_utils::ext::ResultExt;

static TRAMPOLINE_SIZE: Lazy<usize> = Lazy::new(|| *PAGE_SIZE * 16);

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

            trace!("{self} status = {status:?}");

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

                    let inject_libs = self.check_process(&args)?;

                    if let Some(libs) = inject_libs {
                        self.do_inject(regs, &raw_args, &libs)?;
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

    fn check_process(&self, args: &SpecializeArgs) -> Result<Option<Vec<Arc<InjectLibrary>>>> {
        let uid = Uid::from_raw(args.uid as _);
        let package_info = PackageInfoService::instance().query(uid);
        let fast_args = EmbryoCheckArgs::new_fast(
            uid,
            Gid::from_raw(args.gid as _),
            args.is_system_server,
            args.is_child_zygote,
            package_info,
        );

        let manager = PolicyProviderManager::instance();
        let mut result = manager.check(&fast_args);

        if result.more_info {
            let slow_args = fast_args.into_slow(
                self.read_jstring(args.env, args.managed_nice_name)?,
                self.read_jstring(args.env, args.managed_app_data_dir)?,
            );
            manager.recheck_slow(&slow_args, &mut result);
        }

        Ok(manager.aggregate(&result.decisions))
    }

    fn do_inject(
        &self,
        mut regs: RegSet,
        raw_args: &[c_long],
        libs: &[Arc<InjectLibrary>],
    ) -> Result<()> {
        info!(
            "injecting process: {self}, raw_args = {raw_args:?}, libs count = {}",
            libs.len()
        );

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

        let bridge_fd = bridge_fd.forget();

        let (conn_fd_local, conn_fd_remote) = if !libs.is_empty() {
            let (local, remote) = conn.forget();
            (Some(local), Some(remote))
        } else {
            conn.close(self)?;
            (None, None)
        };

        let mut ops: VecAssembler<Aarch64Relocation> = VecAssembler::new(0);

        let info = unsafe { DlextInfo::from_raw_fd(bridge_fd) };

        let bridge_args = BridgeArgs {
            conn_fd: conn_fd_remote.unwrap_or(-1),
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
            ; mov x0, bridge_fd as _
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
            ; adr x2, >bridge_args
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
            ; .align align_of::<BridgeArgs>()
            ; bridge_args:
            ;; ops.extend(crate::misc::as_byte_slice(&bridge_args))

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
        self.detach(None)?;

        if let Some(conn_fd) = conn_fd_local {
            self.send_inject_libs(conn_fd, libs)?;
        }

        Ok(())
    }

    fn send_inject_libs(&self, conn_fd: OwnedFd, libs: &[Arc<InjectLibrary>]) -> Result<()> {
        info!(
            "send inject libs: connection fd = {conn_fd:?}, libs count = {}",
            libs.len()
        );

        let conn = unsafe { UnixSeqpacketConn::from_raw_fd(conn_fd.into_raw_fd()) };

        let library_list = LibraryList {
            names: libs.iter().map(|lib| lib.name().into()).collect(),
        };
        let data = rkyv::to_bytes::<rkyv::rancor::Error>(&library_list)?;

        let library_fds: Vec<_> = libs.iter().map(|lib| lib.as_raw_fd()).collect();

        conn.send(bytemuck::bytes_of(&[data.len(), library_fds.len()]))?;
        conn.send_fds(&data, &library_fds)?;

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
