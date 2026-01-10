use anyhow::Result;
use std::ffi::{c_int, CString};
use std::fmt::Display;
use std::ops::Deref;
use std::os::fd::RawFd;
use std::path::Path;
use anyhow::bail;
use nix::libc::{AT_FDCWD, MAP_ANONYMOUS, MAP_FAILED, PR_SET_VMA, PR_SET_VMA_ANON_NAME};
use crate::build_args;
use crate::injector::ptrace::ext::remote_call::PtraceRemoteCallExt;
use crate::injector::ptrace::RemoteProcess;

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
