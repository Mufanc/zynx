use crate::android::packages::PackageInfoService;
use crate::injector::app::policy::{EmbryoCheckArgs, InjectPayload, PolicyProviderManager};
use crate::injector::app::zygote::ZygoteMaps;
use crate::injector::app::{SC_BRK, SC_CONFIG};
use crate::injector::bridge::Bridge;
use crate::injector::ptrace::ext::WaitStatusExt;
use crate::injector::ptrace::ext::base::PtraceExt;
use crate::injector::ptrace::ext::ipc::{MmapOptions, PtraceIpcExt};
use crate::injector::ptrace::ext::jni::PtraceJniExt;
use crate::injector::ptrace::ext::remote_call::{PtraceRemoteCallExt, RemoteLibraryResolver};
use crate::injector::ptrace::{RegSet, RemoteProcess};
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
use std::os::fd::{AsFd, FromRawFd};
use syscalls::Sysno;
use tokio::runtime::Handle;
use zynx_bridge_types::dlfcn::DlextInfo;
use zynx_bridge_types::zygote::{BridgeArgs, SpecializeArgs};
use zynx_utils::ext::ResultExt;

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
    tracee: RemoteProcess,
    maps: ZygoteMaps,
    /// Address of the SpecializeCommon function in the remote process
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

    /// Main entry point: installs a breakpoint, waits for it to be hit,
    /// then decides whether to inject into the embryo process.
    pub fn start(&self) -> Result<()> {
        // Install a software breakpoint at the specialize function entry
        self.poke_data_ignore_perm(self.specialize_fn, &SC_BRK)?;

        // Attach to the process via PTRACE_SEIZE and resume it
        self.seize()?;
        self.kill(Signal::SIGCONT)?;

        defer! {
            self.detach(None).log_if_error();
        }

        // Event loop: wait for the breakpoint or process termination
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
                // SIGTRAP means the breakpoint was hit (specialize function called)
                WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                    // Capture registers and read the specialize function arguments
                    let regs = self.get_regs()?;
                    let mut raw_args = vec![0; SC_CONFIG.args_cnt];

                    self.get_args(&mut raw_args)?;
                    // Restore the original code at the breakpoint site
                    self.restore_swbp()?;

                    // Parse the raw args into a structured form
                    let args = SpecializeArgs::new(&raw_args, SC_CONFIG.ver);

                    debug!("{self} specialize args: {args:?}");

                    // Query policy providers to determine if injection is needed
                    let handle = Handle::current();
                    let inject_payload = handle.block_on(self.check_process(&args))?;

                    if let Some(payload) = inject_payload {
                        // Injection required: deploy trampoline and inject libraries
                        self.do_inject(regs, &raw_args, payload)?;
                    } else {
                        // No injection needed: just restore registers and let it continue
                        self.set_regs(&regs)?;
                    }

                    break;
                }
                _ => {}
            }

            // Forward any pending signals and continue the tracee
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

    async fn check_process(&self, args: &SpecializeArgs) -> Result<Option<InjectPayload>> {
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
        let mut result = manager.check(&fast_args).await;

        if result.more_info {
            let slow_args = fast_args.into_slow(
                self.read_jstring(args.env, args.managed_nice_name)?,
                self.read_jstring(args.env, args.managed_app_data_dir)?,
            );
            manager.recheck_slow(&slow_args, &mut result).await;
        }

        Ok(manager.aggregate(&result.decisions))
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
        &self,
        mut regs: RegSet,
        raw_args: &[c_long],
        payload: InjectPayload,
    ) -> Result<()> {
        info!("injecting process: {self}, raw_args = {raw_args:?}");

        // Todo: selinux check execmem

        // Allocate RWX memory in the remote process for the trampoline code
        let trampoline_addr = self.mmap_ex(
            MmapOptions::new(
                *TRAMPOLINE_SIZE,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
            )
            .name("zynx::trampoline"),
        )?;

        // Fixme: defer munmap trampoline if failed

        // Establish a unix socket connection with the remote process for IPC
        let conn = self.connect(trampoline_addr)?;

        // Install the bridge library fd into the remote process
        let bridge = Bridge::instance();
        let bridge_fd = self.install_fd(trampoline_addr, &conn, bridge.as_fd())?;

        debug!("{self} bridge fd: {bridge_fd:?}");

        let bridge_fd = bridge_fd.forget();

        // If there are segments to inject, keep the socket open for sending
        // payload later; otherwise close it immediately
        let (conn_fd_local, conn_fd_remote) = if !payload.is_empty() {
            let (local, remote) = conn.forget();
            (Some(local), Some(remote))
        } else {
            conn.close(self)?;
            (None, None)
        };

        // Assemble the AArch64 trampoline code using dynasm
        let mut ops: VecAssembler<Aarch64Relocation> = VecAssembler::new(0);

        // Prepare dlopen info: load bridge library from the installed fd
        let info = unsafe { DlextInfo::from_raw_fd(bridge_fd) };

        // Arguments passed to the bridge's pre-hook function
        let bridge_args = BridgeArgs {
            conn_fd: conn_fd_remote.unwrap_or(-1),
            specialize_version: SC_CONFIG.ver,
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
            //   pre_hook(args_on_stack, args_cnt, &bridge_args)
            ; stp fp, lr, [sp, #-16]!
            ; mov ip, x0
            ; add x0, sp, 16
            ; mov x1, SC_CONFIG.args_cnt as _
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
            ;; ops.push_u64(self.specialize_fn as _)

            // Slot to save/restore the original return address
            ; .align 8
            ; specialize_lr:
            ;; ops.push_u64(0xfee1deadfee1dead)

            // Resolved addresses of dlopen and dlsym
            ; .align 8
            ; dlopen:
            ;; ops.push_u64(self.resolve_fn(("libdl", "android_dlopen_ext"))? as _)

            ; .align 8
            ; dlsym:
            ;; ops.push_u64(self.resolve_fn(("libdl", "dlsym"))? as _)

            // Bridge library name (used by android_dlopen_ext)
            ; .align 8
            ; lib_name:
            ;; ops.extend(c"zynx::bridge".to_bytes_with_nul())

            // DlextInfo struct (tells dlopen to load from fd)
            ; .align align_of::<DlextInfo>()
            ; lib_info:
            ;; ops.extend(crate::misc::as_byte_slice(&info))

            // BridgeArgs struct passed to the pre-hook
            ; .align align_of::<BridgeArgs>()
            ; bridge_args:
            ;; ops.extend(crate::misc::as_byte_slice(&bridge_args))

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
            ;; ops.push_u64(self.resolve_fn(("libc", "munmap"))? as _)

            // Base address of this trampoline (passed to munmap)
            ; .align 8
            ; trampoline_addr:
            ;; ops.push_u64(trampoline_addr as _)
        );

        // Finalize the assembled bytecode and write it into the trampoline region
        let bytecode = ops.finalize()?;

        trace!("dynasm bytecode: {bytecode:?}");

        self.poke_data(trampoline_addr, &bytecode)?;

        // Redirect execution to the trampoline and release the process
        regs.set_pc(trampoline_addr);

        self.set_regs(&regs)?;
        self.detach(None)?;

        // Send payload over the socket so the bridge can load libraries
        if let Some(conn_fd) = conn_fd_local {
            payload.send_to(conn_fd)?;
        }

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
