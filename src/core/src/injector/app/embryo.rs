use crate::binary::library::SystemLibraryResolver;
use crate::dynasm;
use crate::injector::app::policy::{Action, ProcessInfo};
use crate::injector::app::zygote::ZygoteMaps;
use crate::injector::app::{SC_BRK, ipc};
use crate::injector::context::ZynxContext;
use crate::injector::process;
use crate::injector::{PAGE_SIZE, misc};
use anyhow::{Context, bail};
use dynasmrt::VecAssembler;
use dynasmrt::aarch64::Aarch64Relocation;
use log::{debug, info, trace, warn};
use nix::errno::Errno;
use nix::libc::{
    MADV_DONTNEED, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PR_SET_VMA, PR_SET_VMA_ANON_NAME,
    PROT_EXEC, PROT_READ, PROT_WRITE, RTLD_NOW, c_long,
};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::WaitStatus;
use nix::unistd::{Gid, Pid, Uid};
use once_cell::sync::Lazy;
use procfs::process::MMPermissions;
use ptrace_kit::memory;
use ptrace_kit::{RegSet, RemoteAddress, Tracee, TraceeWithTimeout};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::sync::Arc;
use std::time::Duration;
use syscalls::Sysno;
use tokio::runtime::Handle;
use zynx_bridge_shared::remote_lib::DlextInfo;
use zynx_bridge_shared::zygote::{BridgeArgs, SpecializeArgs};

static TRAMPOLINE_SIZE: Lazy<usize> = Lazy::new(|| *PAGE_SIZE * 16);

/// Handles injection into a newly forked process (embryo) before it specializes
/// into a specific app. Works by:
/// 1. Installing a software breakpoint at the specialize function
/// 2. Waiting for the embryo to hit the breakpoint (SIGTRAP)
/// 3. Checking policy to decide whether injection is needed
/// 4. If yes, assembling and deploying a trampoline that loads the bridge
///    library, calls pre/post hooks around the original specialize function,
///    and cleans itself up afterwards
pub struct EmbryoInjector {
    context: Arc<ZynxContext>,
    tracee: TraceeWithTimeout,
    maps: ZygoteMaps,
    /// Address of the SpecializeCommon function in the remote process
    specialize_fn: RemoteAddress,
    /// Non-executable libc base used to trap remote function returns.
    return_address: RemoteAddress,
}

impl EmbryoInjector {
    pub fn new(
        context: Arc<ZynxContext>,
        pid: Pid,
        maps: ZygoteMaps,
        specialize_fn: RemoteAddress,
    ) -> anyhow::Result<Self> {
        let return_address = maps
            .find_library_base_by_name("libc")
            .context("failed to find libc base for remote returns")?;
        let vma = maps
            .find_vma(return_address)
            .context("libc base memory region not found")?;

        if vma.perms.contains(MMPermissions::EXECUTE) {
            bail!("libc base memory region is executable");
        }

        memory::process_mem_write_all(pid, specialize_fn, &SC_BRK)?;

        let tracee = Tracee::seize(pid)?.with_timeout(Duration::from_secs(5));

        Ok(Self {
            context,
            tracee,
            maps,
            specialize_fn,
            return_address,
        })
    }

    pub fn start(mut self) -> anyhow::Result<()> {
        signal::kill(self.tracee.tid(), Signal::SIGCONT)?;

        loop {
            let status = self.tracee.wait_blocking()?;

            trace!("{self} status = {status:?}");

            match status {
                WaitStatus::Exited(_, code) => {
                    warn!("embryo exited with code: {code}");
                    return Ok(());
                }
                WaitStatus::Signaled(_, sig, _) => {
                    warn!("embryo killed by {sig}");
                    return Ok(());
                }
                WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                    let regs = self.tracee.read_regs()?;
                    let raw_args = self.read_args(&regs)?;

                    self.restore_swbp()?;

                    let args = SpecializeArgs::new(&raw_args, self.context.specialize_abi.ver);

                    debug!("{self} specialize args: {args:?}");

                    let handle = Handle::current();

                    if let Some(actions) = handle.block_on(self.check_process(&args))? {
                        self.do_inject(regs, &raw_args, actions)?;
                    } else {
                        self.tracee.write_regs(&regs)?;
                        self.tracee.detach(None)?;
                    }

                    return Ok(());
                }
                WaitStatus::Stopped(_, sig) | WaitStatus::PtraceEvent(_, sig, _) => {
                    self.tracee.resume(Some(sig))?;
                }
                _ => self.tracee.resume(None)?,
            }
        }
    }

    fn read_args(&self, regs: &RegSet) -> anyhow::Result<Vec<c_long>> {
        (0..self.context.specialize_abi.args_count)
            .map(|index| {
                if index < 8 {
                    Ok(regs.register(index)? as c_long)
                } else {
                    Ok(self.tracee.read_u64(regs.sp() + 8 * (index - 8))? as c_long)
                }
            })
            .collect()
    }

    fn resolve_fn(&self, library: &str, symbol: &str) -> anyhow::Result<RemoteAddress> {
        let base = self
            .maps
            .find_library_base_by_name(library)
            .with_context(|| format!("failed to resolve library: {library}"))?;

        Ok(base
            + SystemLibraryResolver::instance()
                .resolve(library, symbol)?
                .addr)
    }

    fn call_remote(&mut self, library: &str, symbol: &str, args: &[u64]) -> anyhow::Result<u64> {
        let function = self.resolve_fn(library, symbol)?;

        // The target is stopped; the validated libc base faults on instruction fetch.
        Ok(unsafe {
            self.tracee.call_remote(
                function,
                args,
                self.return_address,
                Some(&mut process::remote_stop),
            )
        }?)
    }

    fn restore_swbp(&mut self) -> anyhow::Result<()> {
        debug!("{self} restore swbp: {}", self.specialize_fn);

        // MADV_DONTNEED reloads the original instructions from the file-backed mapping.
        let result = self.call_remote(
            "libc",
            "madvise",
            &[
                misc::floor_to_page_size(self.specialize_fn) as u64,
                *PAGE_SIZE as u64,
                MADV_DONTNEED as u64,
            ],
        )?;

        if result as i64 == -1 {
            bail!("failed to restore swbp");
        }

        Ok(())
    }

    async fn check_process(
        &mut self,
        args: &SpecializeArgs,
    ) -> anyhow::Result<Option<Vec<Action>>> {
        // Todo: selinux check execmem?

        let uid = Uid::from_raw(args.uid as _);
        let package_info = self.context.package_index.query(uid);
        // JNIEnv and jstring references belong to this stopped specialize call.
        let (nice_name, app_data_dir) = unsafe {
            (
                self.tracee.read_jstring(
                    args.env as RemoteAddress,
                    args.managed_nice_name as RemoteAddress,
                    self.return_address,
                    Some(&mut process::remote_stop),
                )?,
                self.tracee.read_jstring(
                    args.env as RemoteAddress,
                    args.managed_app_data_dir as RemoteAddress,
                    self.return_address,
                    Some(&mut process::remote_stop),
                )?,
            )
        };
        let process = ProcessInfo {
            uid,
            gid: Gid::from_raw(args.gid as _),
            is_system_server: args.is_system_server,
            is_child_zygote: args.is_child_zygote,
            package_info,
            nice_name,
            app_data_dir,
        };
        let manager = &self.context.policy;
        let actions = manager.check(&process).await;

        Ok((!actions.is_empty()).then_some(actions))
    }

    /// Core injection routine. Assembles an AArch64 trampoline in the remote
    /// process that performs the following steps:
    ///
    /// 1. Save the original specialize args (x0-x7) on the stack
    /// 2. Load the bridge library via android_dlopen_ext (using a memfd)
    /// 3. Close the bridge fd (no longer needed after dlopen)
    /// 4. Resolve `specialize_pre` and `specialize_post` hook symbols via dlsym
    /// 5. Call the pre-hook with the saved args and bridge configuration
    /// 6. Replace LR so that SpecializeCommon returns to our trampoline
    /// 7. Restore args and tail-call the original SpecializeCommon
    /// 8. On return (via trampoline): call the post-hook
    /// 9. Clean up by munmap-ing the trampoline and returning to the real caller
    fn do_inject(
        &mut self,
        mut regs: RegSet,
        raw_args: &[c_long],
        actions: Vec<Action>,
    ) -> anyhow::Result<()> {
        info!("injecting process: {self}, raw_args = {raw_args:?}");

        let trampoline_addr = self.call_remote(
            "libc",
            "mmap",
            &[
                0,
                *TRAMPOLINE_SIZE as u64,
                (PROT_READ | PROT_WRITE | PROT_EXEC) as u64,
                (MAP_PRIVATE | MAP_ANONYMOUS) as u64,
                u64::MAX,
                0,
            ],
        )? as RemoteAddress;

        if trampoline_addr == MAP_FAILED as RemoteAddress {
            let errno_ptr = self.call_remote("libc", "__errno", &[])? as RemoteAddress;
            let errno = Errno::from_raw(self.tracee.read_u64(errno_ptr)? as i32);

            bail!("failed to allocate trampoline: {errno}");
        }

        self.tracee
            .write_all(trampoline_addr, c"zynx::trampoline".to_bytes_with_nul())?;
        self.call_remote(
            "libc",
            "prctl",
            &[
                PR_SET_VMA as u64,
                PR_SET_VMA_ANON_NAME as u64,
                trampoline_addr as u64,
                *TRAMPOLINE_SIZE as u64,
                trampoline_addr as u64,
            ],
        )?;

        // The target is stopped at specialize; libc and its stack remain available for IPC setup.
        let mut channel = unsafe {
            self.tracee
                .create_channel(self.return_address, Some(&mut process::remote_stop))
        }?;
        let bridge_fd = unsafe {
            self.tracee.install_fd(
                &mut channel,
                self.context.bridge.as_fd(),
                self.return_address,
                Some(&mut process::remote_stop),
            )
        }?;
        let (local_fd, remote_fd) = channel.into_parts().map_err(|(_, error)| error)?;
        let bytecode = self.assemble_trampoline(
            trampoline_addr,
            bridge_fd.as_raw_fd(),
            remote_fd.as_raw_fd(),
        )?;

        self.tracee.write_all(trampoline_addr, &bytecode)?;
        regs.set_pc(trampoline_addr);
        self.tracee.write_regs(&regs)?;
        self.tracee.detach(None)?;

        // The trampoline and bridge own the remote descriptors after detach.
        let _ = bridge_fd.into_raw_fd();
        let _ = remote_fd.into_raw_fd();

        ipc::transfer_data(local_fd, actions)
    }

    fn assemble_trampoline(
        &self,
        trampoline_addr: RemoteAddress,
        bridge_fd: RawFd,
        remote_fd: RawFd,
    ) -> anyhow::Result<Vec<u8>> {
        // Assemble the AArch64 trampoline code using dynasm
        let mut ops: VecAssembler<Aarch64Relocation> = VecAssembler::new(0);

        // Prepare dlopen info: load bridge library from the installed fd
        let info = unsafe { DlextInfo::from_raw_fd(bridge_fd) };

        // Arguments passed to the bridge's pre-hook function
        let bridge_args = BridgeArgs {
            conn_fd: remote_fd,
            specialize_version: self.context.specialize_abi.ver,
        };

        dynasm!(ops
            // Step 1: Save specialize args (x0-x7) onto the stack
            ; stp x6, x7, [sp, #-16]!
            ; stp x4, x5, [sp, #-16]!
            ; stp x2, x3, [sp, #-16]!
            ; stp x0, x1, [sp, #-16]!

            // Step 2: Load the bridge library via android_dlopen_ext
            //   x0 = library name ("zynx::bridge"), x1 = RTLD_NOW, x2 = DlextInfo
            ; stp fp, lr, [sp, #-16]!
            ; ldr ip, >dlopen
            ; adr x0, >lib_name
            ; mov x1, RTLD_NOW as _
            ; adr x2, >lib_info
            ; blr ip
            ; ldp fp, lr, [sp], #16

            // Step 3: Close the bridge fd via syscall (no longer needed after dlopen)
            //   x0 = dlopen handle (saved/restored around the syscall)
            ; stp x0, xzr, [sp, #-16]!
            ; mov x8, Sysno::close as _
            ; mov x0, bridge_fd as _
            ; svc #0
            ; ldp x0, xzr, [sp], #16

            // Step 4a: Resolve the post-hook symbol and store its address
            //   dlsym(handle, "specialize_post") -> post_hook_addr
            ; stp fp, lr, [sp, #-16]!
            ; stp x0, x1, [sp, #-16]!
            ; ldr ip, >dlsym
            ; adr x1, >post_hook_sym
            ; blr ip
            ; adr x1, >post_hook_addr
            ; str x0, [x1]
            ; ldp x0, x1, [sp], #16
            ; ldp fp, lr, [sp], #16

            // Step 4b: Resolve the pre-hook symbol
            //   dlsym(handle, "specialize_pre") -> x0
            ; stp fp, lr, [sp, #-16]!
            ; ldr ip, >dlsym
            ; adr x1, >pre_hook_sym
            ; blr ip
            ; ldp fp, lr, [sp], #16

            // Step 5: Call the pre-hook
            //   pre_hook(args_on_stack, args_count, &bridge_args)
            ; stp fp, lr, [sp, #-16]!
            ; mov ip, x0
            ; add x0, sp, 16
            ; mov x1, self.context.specialize_abi.args_count as _
            ; adr x2, >bridge_args
            ; blr ip
            ; ldp fp, lr, [sp], #16

            // Step 6: Hijack LR so SpecializeCommon returns to our trampoline
            //   Save the real LR, then set LR to the trampoline label
            ; adr x0, >specialize_lr
            ; str lr, [x0]
            ; adr lr, >trampoline

            // Step 7: Restore original specialize args and jump to SpecializeCommon
            ; ldp x0, x1, [sp], #16
            ; ldp x2, x3, [sp], #16
            ; ldp x4, x5, [sp], #16
            ; ldp x6, x7, [sp], #16

            // Tail-call into the real SpecializeCommon
            ; ldr ip, >specialize
            ; br ip

            // Step 8: Post-hook trampoline (SpecializeCommon returns here)
            ; trampoline:
            ; stp fp, lr, [sp, #-16]!
            ; ldr ip, >post_hook_addr
            ; blr ip
            ; ldp fp, lr, [sp], #16

            // Step 9: Self-cleanup via munmap, then return to the real caller
            //   Restore original LR, then tail-call munmap(trampoline_addr, size)
            ; ldr lr, >specialize_lr
            ; ldr ip, >munmap
            ; ldr x0, >trampoline_addr
            ; mov x1, *TRAMPOLINE_SIZE as _
            ; br ip

            // ---- Data section ----

            // Address of the original SpecializeCommon function
            ; .align 8
            ; specialize:
            ;; ops.push_u64(self.specialize_fn as u64)

            // Slot to save/restore the original return address
            ; .align 8
            ; specialize_lr:
            ;; ops.push_u64(0xfee1deadfee1dead)

            // Resolved addresses of dlopen and dlsym
            ; .align 8
            ; dlopen:
            ;; ops.push_u64(self.resolve_fn("libdl", "android_dlopen_ext")? as u64)

            ; .align 8
            ; dlsym:
            ;; ops.push_u64(self.resolve_fn("libdl", "dlsym")? as u64)

            // Bridge library name (used by android_dlopen_ext)
            ; .align 8
            ; lib_name:
            ;; ops.extend(c"zynx::bridge".to_bytes_with_nul())

            // DlextInfo struct (tells dlopen to load from fd)
            ; .align align_of::<DlextInfo>()
            ; lib_info:
            ;; ops.extend(crate::misc::as_bytes(&info))

            // BridgeArgs struct passed to the pre-hook
            ; .align align_of::<BridgeArgs>()
            ; bridge_args:
            ;; ops.extend(crate::misc::as_bytes(&bridge_args))

            // Hook symbol name strings
            ; .align 8
            ; pre_hook_sym:
            ;; ops.extend(c"specialize_pre".to_bytes_with_nul())

            ; .align 8
            ; post_hook_sym:
            ;; ops.extend(c"specialize_post".to_bytes_with_nul())

            // Slot to store the resolved post-hook function pointer
            ; .align 8
            ; post_hook_addr:
            ;; ops.push_u64(0xfee1deadfee1dead)

            // Resolved address of munmap (for self-cleanup)
            ; .align 8
            ; munmap:
            ;; ops.push_u64(self.resolve_fn("libc", "munmap")? as u64)

            // Base address of this trampoline (passed to munmap)
            ; .align 8
            ; trampoline_addr:
            ;; ops.push_u64(trampoline_addr as u64)
        );

        // Finalize the assembled bytecode and write it into the trampoline region
        let bytecode = ops.finalize()?;

        trace!("dynasm bytecode: {bytecode:?}");

        Ok(bytecode)
    }
}

impl Display for EmbryoInjector {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        write!(fmt, "Remote({})", self.tracee.tid())
    }
}
