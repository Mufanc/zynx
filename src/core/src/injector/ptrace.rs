pub mod ext;

use anyhow::{Context, Result, bail};
use log::{debug, trace};
use nix::errno::Errno;
use nix::libc;
use nix::libc::{PTRACE_GETREGSET, PTRACE_SETREGSET, c_int, c_long, iovec, user_regs_struct};
use nix::sys::signal::Signal;
use nix::sys::uio::RemoteIoVec;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::sys::{ptrace, signal, uio, wait};
use nix::unistd::Pid;
use procfs::ProcError;
use procfs::process::{ProcState, Process};
use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use std::fs::OpenOptions;
use std::io::{IoSlice, IoSliceMut, Seek, SeekFrom, Write};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::{fmt, thread};

#[derive(Clone)]
pub struct RegSet(user_regs_struct);

impl RegSet {
    const SIZE: usize = size_of::<user_regs_struct>();

    fn new(regs: user_regs_struct) -> Self {
        Self(regs)
    }

    fn as_ptr(&self) -> *const c_void {
        &self.0 as *const user_regs_struct as _
    }

    pub fn get_fp(&self) -> usize {
        self.0.regs[29] as _
    }

    pub fn get_sp(&self) -> usize {
        self.0.sp as _
    }

    pub fn set_sp(&mut self, sp: usize) {
        self.0.sp = sp as _
    }

    pub fn align_sp(&mut self) {
        self.0.sp &= !0xf;
    }

    pub fn get_pc(&self) -> usize {
        self.0.pc as _
    }

    pub fn set_pc(&mut self, pc: usize) {
        self.0.pc = pc as _;
    }

    pub fn get_arg(&self, index: usize) -> c_long {
        if index < 8 {
            self.0.regs[index] as _
        } else {
            unreachable!("up to 8 parameters can be passed through registers")
        }
    }

    pub fn set_arg(&mut self, index: usize, value: c_long) {
        if index < 8 {
            self.0.regs[index] = value as _
        } else {
            unreachable!("up to 8 parameters can be passed through registers")
        }
    }

    pub fn get_lr(&self) -> usize {
        self.0.regs[30] as _
    }

    pub fn set_lr(&mut self, address: usize) {
        self.0.regs[30] = address as _
    }

    pub fn return_value(&self) -> c_long {
        self.0.regs[0] as _
    }

    pub fn callee_saves(&self) -> [usize; 10] {
        let mut regs = [0; 10];

        self.0.regs[19..29].iter().enumerate().for_each(|(i, reg)| {
            regs[i] = *reg as _;
        });

        regs
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct RemoteProcess {
    pid: Pid,
    attached: AtomicBool,
}

impl RemoteProcess {
    pub fn new(pid: Pid) -> Self {
        Self {
            pid: Pid::from_raw(pid.as_raw()),
            attached: AtomicBool::new(false),
        }
    }

    fn ptrace_raw(&self, request: c_int, addr: usize, data: usize) -> nix::Result<c_long> {
        Errno::result(unsafe { libc::ptrace(request, self.pid.as_raw(), addr, data) })
    }

    pub fn seize(&self) -> Result<()> {
        self.ptrace_raw(0x4206 /* PTRACE_SEIZE */, 0, 0)
            .context("ptrace::seize")?;
        debug!("attached to {self}");
        self.attached.store(true, Ordering::Release);
        Ok(())
    }

    pub fn wait(&self) -> Result<WaitStatus> {
        let status = wait::waitpid(self.pid, Some(WaitPidFlag::__WALL)).context("ptrace::wait");
        trace!("{self} wait status: {status:?}");
        status
    }

    pub fn cont<T: Into<Option<Signal>>>(&self, sig: T) -> Result<()> {
        ptrace::cont(self.pid, sig).context("ptrace::cont")?;
        Ok(())
    }

    pub fn kill<T: Into<Option<Signal>>>(&self, sig: T) -> Result<()> {
        signal::kill(self.pid, sig).context("signal::kill")?;
        Ok(())
    }

    pub fn peek(&self, addr: usize) -> Result<c_long> {
        Ok(ptrace::read(self.pid, addr as _)?)
    }

    pub fn peek_data(&self, addr: usize, data: &mut [u8]) -> Result<()> {
        let iov_remote = RemoteIoVec {
            base: addr,
            len: data.len(),
        };
        let iov_local = IoSliceMut::new(data);

        uio::process_vm_readv(self.pid, &mut [iov_local], &[iov_remote])
            .context("failed to read memory")?;

        Ok(())
    }

    pub fn poke(&self, addr: usize, data: c_long) -> Result<()> {
        ptrace::write(self.pid, addr as _, data as _)?;
        Ok(())
    }

    pub fn poke_data(&self, addr: usize, data: &[u8]) -> Result<()> {
        let iov_remote = RemoteIoVec {
            base: addr,
            len: data.len(),
        };
        let iov_local = IoSlice::new(data);

        uio::process_vm_writev(self.pid, &[iov_local], &[iov_remote])
            .context("failed to write memory")?;

        Ok(())
    }

    pub fn poke_data_ignore_perm(&self, addr: usize, data: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .open(format!("/proc/{}/mem", self.pid))?;

        file.seek(SeekFrom::Start(addr as _))?;
        file.write_all(data)?;
        file.flush()?;

        Ok(())
    }

    pub fn get_regs(&self) -> Result<RegSet> {
        let mut regs: MaybeUninit<user_regs_struct> = MaybeUninit::uninit();
        let iov = iovec {
            iov_base: regs.as_mut_ptr() as _,
            iov_len: RegSet::SIZE,
        };

        self.ptrace_raw(
            PTRACE_GETREGSET,
            1, /* NT_PRSTATUS */
            &iov as *const _ as _,
        )?;

        Ok(RegSet::new(unsafe { regs.assume_init() }))
    }

    pub fn set_regs(&self, regs: &RegSet) -> Result<()> {
        let iov = iovec {
            iov_base: regs.as_ptr() as _,
            iov_len: RegSet::SIZE,
        };

        self.ptrace_raw(
            PTRACE_SETREGSET,
            1, /* NT_PRSTATUS */
            &iov as *const _ as _,
        )?;

        Ok(())
    }

    pub fn detach<T: Into<Option<Signal>>>(&self, sig: T) -> Result<()> {
        if self.attached.load(Ordering::Acquire) {
            ptrace::detach(self.pid, sig)?;
            self.attached.store(false, Ordering::Release);
            debug!("detached from {self}");
        }

        Ok(())
    }
}

impl Display for RemoteProcess {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        write!(fmt, "Remote({})", self.pid)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub fn spin_wait(pid: Pid) -> Result<()> {
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
