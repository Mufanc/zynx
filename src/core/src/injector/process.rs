use anyhow::bail;
use log::debug;
use nix::errno::Errno;
use nix::sys::signal;
use nix::sys::wait::{self, WaitPidFlag};
use nix::unistd::Pid;
use procfs::ProcError;
use procfs::process::{ProcState, Process};
use ptrace_kit::remote::StopAction;
use ptrace_kit::{Signal, WaitStatus};
use std::thread;
use std::time::{Duration, Instant};

pub fn remote_stop(status: WaitStatus) -> StopAction {
    match status {
        WaitStatus::Stopped(_, signal @ (Signal::SIGCHLD | Signal::SIGCONT)) => {
            StopAction::Resume(Some(signal))
        }
        _ => StopAction::Abort,
    }
}

pub fn terminate(pid: Pid) -> anyhow::Result<()> {
    match signal::kill(pid, Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(error) => return Err(error.into()),
    }

    let deadline = Instant::now() + Duration::from_secs(5);

    loop {
        match wait::waitpid(pid, Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) | Err(Errno::ECHILD) => {
                return Ok(());
            }
            Ok(_) | Err(Errno::EINTR) => {}
            Err(error) => return Err(error.into()),
        }

        if Instant::now() >= deadline {
            bail!("timed out waiting for embryo {pid} to exit");
        }

        thread::sleep(Duration::from_millis(1));
    }
}

pub fn spin_wait(pid: Pid) -> anyhow::Result<()> {
    let mut count = 0;
    let sleep_duration = Duration::from_millis(10);

    loop {
        let proc = Process::new(pid.as_raw())?;

        match proc.stat().and_then(|stat| stat.state()) {
            Ok(ProcState::Stopped) => break,
            Ok(_) => {}
            Err(ProcError::NotFound(_)) => {}
            Err(err) => bail!(err),
        }

        count += 1;
        thread::sleep(sleep_duration);
    }

    debug!("process {pid} stopped, yield {count} times");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ptrace_kit::{RemoteAddress, Tracee};
    use ptrace_kit::remote::{CallOptions, Recovery, RemoteCallError};

    #[test]
    fn forwards_only_expected_remote_call_signals() {
        let pid = Pid::from_raw(123);
        for signal in [Signal::SIGCHLD, Signal::SIGCONT] {
            assert!(matches!(remote_stop(WaitStatus::Stopped(pid, signal)),
                StopAction::Resume(Some(forwarded)) if forwarded == signal));
        }
        for status in [
            WaitStatus::Stopped(pid, Signal::SIGTRAP),
            WaitStatus::Stopped(pid, Signal::SIGUSR1),
            WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, 128),
            WaitStatus::Exited(pid, 0),
        ] {
            assert!(matches!(remote_stop(status), StopAction::Abort));
        }
    }

    struct Child(Pid);

    impl Child {
        fn paused() -> Self {
            // The fork child only uses async-signal-safe calls and never returns to Rust.
            let pid = unsafe { nix::libc::fork() };
            if pid == 0 {
                loop {
                    unsafe {
                        nix::libc::pause();
                    }
                }
            }
            assert!(pid > 0);
            Self(Pid::from_raw(pid))
        }
    }

    impl Drop for Child {
        fn drop(&mut self) {
            let _ = signal::kill(self.0, Signal::SIGKILL);
            while let Err(Errno::EINTR) = wait::waitpid(self.0, None) {}
        }
    }

    #[test]
    fn terminates_and_reaps_before_attach() {
        let child = Child::paused();
        terminate(child.0).unwrap();
        assert_eq!(wait::waitpid(child.0, None), Err(Errno::ECHILD));
    }

    #[test]
    fn terminates_after_recoverable_and_timed_out_calls() {
        use std::arch::naked_asm;

        #[unsafe(naked)]
        unsafe extern "C" fn spin() -> u64 {
            naked_asm!("2: b 2b");
        }

        #[unsafe(naked)]
        unsafe extern "C" fn fault() -> u64 {
            naked_asm!("mov x9, #0", "ldr x0, [x9]", "ret");
        }

        for (function, restored) in [
            (fault as *const () as RemoteAddress, true),
            (spin as *const () as RemoteAddress, false),
        ] {
            let child = Child::paused();
            let mut tracee = Tracee::seize(child.0)
                .unwrap()
                .with_timeout(Duration::from_secs(5));
            tracee.interrupt().unwrap();
            tracee.wait().unwrap();
            let return_address = tracee.read_regs().unwrap().sp();
            let error = unsafe {
                Tracee::call_remote(
                    &mut tracee,
                    function,
                    &[],
                    CallOptions {
                        return_address,
                        deadline: Instant::now() + Duration::from_millis(50),
                    },
                    Some(&mut remote_stop),
                )
            }
            .unwrap_err();
            assert_eq!(
                matches!(
                    error,
                    RemoteCallError::Call {
                        recovery: Recovery::Restored,
                        ..
                    }
                ),
                restored
            );
            terminate(child.0).unwrap();
            assert_eq!(wait::waitpid(child.0, None), Err(Errno::ECHILD));
        }
    }
}
