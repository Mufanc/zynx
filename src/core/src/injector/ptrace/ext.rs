use crate::binary::library::SystemLibraryResolver;
use crate::injector::ptrace::RemoteProcess;
use crate::misc::ext::ResultExt;
use anyhow::{Result, bail};
use log::debug;
use nix::errno::Errno;
use nix::libc::{AT_FDCWD, MAP_ANONYMOUS, MAP_FAILED, PR_SET_VMA, PR_SET_VMA_ANON_NAME};
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use scopeguard::defer;
use std::ffi::{CString, c_int, c_long};
use std::fmt::Display;
use std::ops::Deref;
use std::os::fd::RawFd;
use std::path::Path;

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

////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait PtraceExt {
    fn get_arg(&self, index: usize) -> Result<c_long>;
    fn get_args(&self, args: &mut [c_long]) -> Result<()>;
}

impl PtraceExt for RemoteProcess {
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
}

////////////////////////////////////////////////////////////////////////////////////////////////////

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

        debug!("call remote: {func:0>12x} {args:?}");

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

    fn call_remote_auto<F: Into<RemoteFn>>(&self, func: F, args: &[c_long]) -> Result<c_long> {
        match func.into() {
            RemoteFn::BaseOffset(base, offset) => self.call_remote(base + offset, args),
            RemoteFn::LibraryOffset(library, offset) => {
                self.call_remote(self.find_library_base(library)? + offset, args)
            }
            RemoteFn::LibrarySymbol(library, symbol) => {
                let resolver = SystemLibraryResolver::instance();

                debug!("offset = {}", resolver.resolve(library, symbol)?.addr);

                self.call_remote(
                    self.find_library_base(library)? + resolver.resolve(library, symbol)?.addr,
                    args,
                )
            }
            RemoteFn::Absolute(func) => self.call_remote(func, args),
        }
    }

    fn errno(&self) -> Result<Errno> {
        let ptr = self.call_remote_auto(("libc", "__errno"), &[])?;
        let errno = self.peek(ptr as _)? & 0xffffffff;

        Ok(Errno::from_raw(errno as _))
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

// Todo: leak canary
pub struct RemoteFd {
    fd: RawFd,
}

impl RemoteFd {
    pub fn new(fd: RawFd) -> Self {
        Self { fd }
    }

    pub fn close<T: PtraceRemoteCallExt>(self, tracee: &T) -> Result<()> {
        tracee.call_remote_auto(("libc", "__close"), build_args!(self.fd))?;
        Ok(())
    }
}

pub struct MmapOptions<'a> {
    addr: Option<usize>,
    size: usize,
    prot: c_int,
    flags: c_int,
    fd: Option<&'a RemoteFd>,
    offset: usize,
    name: Option<&'a str>,
}

impl<'a> MmapOptions<'a> {
    pub fn new(size: usize, prot: c_int, flags: c_int) -> Self {
        Self {
            addr: None,
            size,
            prot,
            flags,
            fd: None,
            offset: 0,
            name: None,
        }
    }

    pub fn addr(mut self, addr: usize) -> Self {
        self.addr = Some(addr);
        self
    }

    pub fn fd(mut self, fd: &'a RemoteFd) -> Self {
        self.fd = Some(fd);
        self
    }

    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    pub fn name(mut self, name: &'a str) -> Self {
        self.name = Some(name);
        self
    }
}

pub trait PtraceIpcExt {
    fn open<P: AsRef<Path>>(&self, buffer_addr: usize, path: P, flags: c_int) -> Result<RemoteFd>;

    fn mmap(
        &self,
        addr: usize,
        size: usize,
        prot: c_int,
        flags: c_int,
        fd: Option<&RemoteFd>,
        offset: usize,
    ) -> Result<usize>;

    fn mmap_ex(&self, options: MmapOptions) -> Result<usize>;
}

impl<T> PtraceIpcExt for T
where
    T: Deref<Target = RemoteProcess> + PtraceRemoteCallExt + Display,
{
    fn open<P: AsRef<Path>>(&self, buffer_addr: usize, path: P, flags: c_int) -> Result<RemoteFd> {
        let path = CString::new(path.as_ref().to_string_lossy().as_bytes())?;

        self.poke_data(buffer_addr, path.as_bytes_with_nul())?;

        #[rustfmt::skip]
        let fd = self.call_remote_auto(
            ("libc", "__openat"),
            build_args!(AT_FDCWD, buffer_addr, flags)
        )? as RawFd;

        if fd < 0 {
            bail!("{self} failed to open {path:?}");
        }

        Ok(RemoteFd::new(fd))
    }

    fn mmap(
        &self,
        addr: usize,
        size: usize,
        prot: c_int,
        flags: c_int,
        fd: Option<&RemoteFd>,
        offset: usize,
    ) -> Result<usize> {
        #[rustfmt::skip]
        let result = self.call_remote_auto(
            ("libc", "mmap"),
            build_args!(addr, size, prot, flags, fd.map(|it| it.fd).unwrap_or(-1), offset)
        )?;

        if result == MAP_FAILED as _ {
            bail!("failed to call mmap");
        }

        Ok(result as _)
    }

    fn mmap_ex(&self, options: MmapOptions) -> Result<usize> {
        if (options.flags & MAP_ANONYMOUS == 0) && options.name.is_some() {
            bail!("name provided for non-anonymous mmap")
        }

        let addr = self.mmap(
            options.addr.unwrap_or(0),
            options.size,
            options.prot,
            options.flags,
            options.fd,
            options.offset,
        )?;

        if let Some(name) = options.name {
            let name = CString::new(name.as_bytes())?;

            self.poke_data(addr, name.as_bytes_with_nul())?;

            #[rustfmt::skip]
            self.call_remote_auto(
                ("libc", "prctl"),
                build_args!(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, name.as_bytes_with_nul().len(), addr)
            )?;
        }

        Ok(addr)
    }
}
