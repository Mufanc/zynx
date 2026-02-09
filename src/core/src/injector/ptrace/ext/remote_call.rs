use crate::binary::library::SystemLibraryResolver;
use crate::injector::ptrace::RemoteProcess;
use crate::injector::ptrace::ext::WaitStatusExt;
use anyhow::Result;
use anyhow::bail;
use log::trace;
use nix::errno::Errno;
use nix::libc::c_long;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use scopeguard::defer;
use std::fmt::Display;
use std::ops::Deref;
use zynx_misc::ext::ResultExt;

#[derive(Debug)]
pub enum RemoteFn {
    BaseOffset(usize, usize),
    LibraryOffset(&'static str, usize),
    LibrarySymbol(&'static str, &'static str),
    Absolute(usize),
}

impl From<(usize, usize)> for RemoteFn {
    fn from(value: (usize, usize)) -> Self {
        Self::BaseOffset(value.0, value.1)
    }
}

impl From<(&'static str, usize)> for RemoteFn {
    fn from(value: (&'static str, usize)) -> Self {
        Self::LibraryOffset(value.0, value.1)
    }
}

impl From<(&'static str, &'static str)> for RemoteFn {
    fn from(value: (&'static str, &'static str)) -> Self {
        Self::LibrarySymbol(value.0, value.1)
    }
}

impl From<usize> for RemoteFn {
    fn from(value: usize) -> Self {
        Self::Absolute(value)
    }
}

pub trait RemoteLibraryResolver {
    fn find_library_base(&self, library: &str) -> Result<usize>;
}

pub trait PtraceRemoteCallExt {
    fn call_remote(&self, func: usize, args: &[c_long]) -> Result<c_long>;
    fn resolve_fn<F: Into<RemoteFn>>(&self, func: F) -> Result<usize>;
    fn call_remote_auto<F: Into<RemoteFn>>(&self, func: F, args: &[c_long]) -> Result<c_long>;
    fn errno(&self) -> Result<Errno>;
}

impl<T> PtraceRemoteCallExt for T
where
    T: Deref<Target = RemoteProcess> + RemoteLibraryResolver + Display,
{
    fn call_remote(&self, func: usize, args: &[c_long]) -> Result<c_long> {
        if args.len() > 8 {
            bail!("{self} too many args: {} > 8", args.len());
        }

        trace!("call remote with args: {args:?}");

        let regs_backup = self.get_regs()?;

        defer! {
            self.set_regs(&regs_backup).log_if_error();
        }

        let mut regs = regs_backup.clone();

        let token = regs.get_sp();

        regs.align_sp();
        regs.set_pc(func);

        for (i, arg) in args.iter().enumerate() {
            regs.set_arg(i, *arg);
        }

        regs.set_lr(token);
        self.set_regs(&regs)?;
        self.cont(None)?;

        let mut status = self.wait()?;

        loop {
            trace!("status = {status:?}");

            match status {
                WaitStatus::Stopped(_, Signal::SIGSEGV) => break,
                WaitStatus::Stopped(_, Signal::SIGCHLD) => {}
                WaitStatus::Stopped(_, Signal::SIGCONT) => {}
                _ => bail!("{self} stopped by {status:?}, expected SIGSEGV"),
            }

            self.cont(status.sig())?;
            status = self.wait()?;
        }

        regs = self.get_regs()?;

        if regs.get_pc() != token {
            bail!("{self} wrong return address: 0x{:0>12x}", regs.get_pc());
        }

        Ok(regs.return_value())
    }

    fn resolve_fn<F: Into<RemoteFn>>(&self, func: F) -> Result<usize> {
        Ok(match func.into() {
            RemoteFn::BaseOffset(base, offset) => base + offset,
            RemoteFn::LibraryOffset(library, offset) => self.find_library_base(library)? + offset,
            RemoteFn::LibrarySymbol(library, symbol) => {
                let resolver = SystemLibraryResolver::instance();
                self.find_library_base(library)? + resolver.resolve(library, symbol)?.addr
            }
            RemoteFn::Absolute(addr) => addr,
        })
    }

    fn call_remote_auto<F: Into<RemoteFn>>(&self, func: F, args: &[c_long]) -> Result<c_long> {
        self.call_remote(self.resolve_fn(func)?, args)
    }

    fn errno(&self) -> Result<Errno> {
        let ptr = self.call_remote_auto(("libc", "__errno"), &[])?;
        let errno = self.peek(ptr as _)? & 0xffffffff;

        Ok(Errno::from_raw(errno as _))
    }
}
