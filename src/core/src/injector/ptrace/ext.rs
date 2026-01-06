use crate::injector::ptrace::{RegSet, Tracee};
use anyhow::{Result, bail};
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use std::ffi::c_long;

#[macro_export]
macro_rules! build_args {
    ($($args: expr),*) => {
        &[ $(($args) as _),* ]
    };
}

pub trait WaitStatusExt {
    fn sig(&self) -> Option<Signal>;
}

impl WaitStatusExt for WaitStatus {
    fn sig(&self) -> Option<Signal> {
        match self {
            WaitStatus::Exited(_, _) => None,
            WaitStatus::Signaled(_, sig, _) => Some(*sig),
            WaitStatus::Stopped(_, sig) => Some(*sig),
            WaitStatus::PtraceEvent(_, sig, _) => Some(*sig),
            WaitStatus::PtraceSyscall(_) => None,
            WaitStatus::Continued(_) => None,
            WaitStatus::StillAlive => None,
        }
    }
}

struct RestoreContextGuard<'a> {
    tracee: &'a Tracee,
    regs_backup: RegSet,
}

impl<'a> RestoreContextGuard<'a> {
    fn new(tracee: &'a Tracee, regs: &RegSet) -> Self {
        Self {
            tracee,
            regs_backup: regs.clone(),
        }
    }
}

#[derive(Debug)]
pub enum RemoteFn {
    Absolute(usize),
    Relative(usize, usize),
}

pub trait PtraceExt {
    fn get_arg(&self, index: usize) -> Result<c_long>;
    fn get_args(&self, args: &mut [c_long]) -> Result<()>;
    fn call_remote(&self, func: RemoteFn, args: &[c_long]) -> Result<c_long>;
}

impl PtraceExt for Tracee {
    fn get_arg(&self, index: usize) -> Result<c_long> {
        let regs = self.get_regs()?;
        let arg = if index < 8 {
            regs.get_arg(index)
        } else {
            let n = index - 8;
            self.peek(regs.get_sp() + 8 * n)?
        };

        Ok(arg)
    }

    fn get_args(&self, args: &mut [c_long]) -> Result<()> {
        let regs = self.get_regs()?;

        for (index, arg) in args.iter_mut().enumerate() {
            if index < 8 {
                *arg = regs.get_arg(index);
            } else {
                let n = index - 8;
                *arg = self.peek(regs.get_sp() + 8 * n)?;
            }
        }

        Ok(())
    }

    fn call_remote(&self, func: RemoteFn, args: &[c_long]) -> Result<c_long> {
        if args.len() > 8 {
            bail!("{self} too many args: {} > 8", args.len());
        }

        let mut regs = self.get_regs()?;
        let _dontdrop = RestoreContextGuard::new(self, &regs);

        let token = regs.get_sp();

        regs.align_sp();

        match func {
            RemoteFn::Absolute(addr) => regs.set_pc(addr),
            RemoteFn::Relative(base, offset) => regs.set_pc(base + offset),
        }

        for (i, arg) in args.iter().enumerate() {
            regs.set_arg(i, *arg);
        }

        regs.set_lr(token);
        self.set_regs(&regs)?;
        self.cont(None)?;

        let status = self.wait()?;
        let WaitStatus::Stopped(_, Signal::SIGSEGV) = status else {
            bail!("{self} stopped by {status:?}, expected SIGSEGV");
        };

        regs = self.get_regs()?;

        if regs.get_pc() != token {
            bail!("{self} wrong return address: 0x{:0>12x}", regs.get_pc());
        }

        Ok(regs.return_value())
    }
}
