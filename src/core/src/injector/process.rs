use anyhow::{bail, Context, Result};
use log::{debug, trace};
use nix::errno::Errno;
use nix::libc;
use nix::libc::c_int;
use nix::sys::wait;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use procfs::process::{ProcState, Process};
use rustix::process::Pid as RustixPid;
use std::ffi::c_long;
use std::thread;
use std::time::Duration;
use procfs::ProcError;

#[derive(Debug)]
pub struct Tracee {
    pid: Pid,
}

impl Tracee {
    pub fn new(pid: RustixPid) -> Self {
        Self {
            pid: Pid::from_raw(pid.as_raw_pid()),
        }
    }

    fn ptrace_raw(&self, request: c_int, addr: usize, data: usize) -> nix::Result<c_long> {
        Errno::result(unsafe { libc::ptrace(request, self.pid.as_raw(), addr, data) })
    }

    pub fn seize(&self) -> Result<()> {
        self.ptrace_raw(0x4206 /* PTRACE_SEIZE */, 0, 0)
            .context("ptrace::seize")?;
        Ok(())
    }

    pub fn wait(&self) -> Result<WaitStatus> {
        let status = wait::waitpid(self.pid, Some(WaitPidFlag::__WALL)).context("ptrace::wait");
        trace!("{self:?} wait status: {status:?}");
        status
    }
}

pub fn spin_wait(pid: RustixPid) -> Result<()> {
    let mut count = 0;
    let sleep_duration = Duration::from_millis(10);

    loop {
        let proc = Process::new(pid.as_raw_pid())?;

        match proc.stat().and_then(|stat| stat.state()) {
            Ok(ProcState::Stopped) => break,
            Ok(_) => {},
            Err(ProcError::NotFound(_)) => {},
            Err(err) => bail!(err),
        }

        count += 1;
        thread::sleep(sleep_duration);
    }

    debug!("process {pid} stopped, yield {count} times");

    Ok(())
}
