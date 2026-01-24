use crate::injector::ptrace::RemoteProcess;
use crate::injector::ptrace::ext::remote_call::PtraceRemoteCallExt;
use crate::{build_args, misc};
use anyhow::Result;
use anyhow::bail;
use log::warn;
use nix::libc::{
    AF_UNIX, CMSG_DATA, CMSG_FIRSTHDR, CMSG_SPACE, MAP_ANONYMOUS, MAP_FAILED, PR_SET_VMA,
    PR_SET_VMA_ANON_NAME, SOCK_SEQPACKET, c_int, msghdr,
};
use nix::sys::socket;
use nix::sys::socket::{ControlMessage, MsgFlags};
use std::ffi::CString;
use std::fmt::Display;
use std::ops::Deref;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::{mem, ptr};
use syscalls::{Sysno, syscall};

#[derive(Debug)]
pub struct RemoteFd {
    fd: RawFd,
    leak: bool,
}

impl RemoteFd {
    pub fn new(fd: RawFd) -> Self {
        Self { fd, leak: true }
    }

    pub fn close<T: PtraceRemoteCallExt>(mut self, tracee: &T) -> Result<()> {
        tracee.call_remote_auto(("libc", "__close"), build_args!(self.fd))?;
        self.leak = false;
        Ok(())
    }

    pub fn forget(mut self) {
        self.leak = false;
    }
}

impl AsRawFd for RemoteFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for RemoteFd {
    fn drop(&mut self) {
        if self.leak {
            warn!("remote fd leaked: {}", self.fd);
        }
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

#[allow(unused)]
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

pub struct SocketConnection {
    pub local_fd: OwnedFd,
    pub remote_fd: RemoteFd,
}

impl SocketConnection {
    fn new(local_fd: OwnedFd, remote_fd: RemoteFd) -> Self {
        Self {
            local_fd,
            remote_fd,
        }
    }

    pub fn close<T: PtraceRemoteCallExt>(self, tracee: &T) -> Result<()> {
        self.remote_fd.close(tracee)?;
        Ok(())
    }
}

pub trait PtraceIpcExt {
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

    fn take_fd(&self, remote_fd: RawFd) -> Result<OwnedFd>;

    fn install_fd(
        &self,
        buffer_addr: usize,
        conn: &SocketConnection,
        fd: BorrowedFd,
    ) -> Result<RemoteFd>;

    fn connect(&self, buffer_addr: usize) -> Result<SocketConnection>;
}

impl<T> PtraceIpcExt for T
where
    T: Deref<Target = RemoteProcess> + PtraceRemoteCallExt + Display,
{
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
            let errno = self.errno()?;
            bail!("failed to call mmap: {errno}");
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

    fn take_fd(&self, remote_fd: RawFd) -> Result<OwnedFd> {
        unsafe {
            let pfd =
                OwnedFd::from_raw_fd(syscall!(Sysno::pidfd_open, self.pid.as_raw(), 0)? as RawFd);

            Ok(OwnedFd::from_raw_fd(
                syscall!(Sysno::pidfd_getfd, pfd.as_raw_fd(), remote_fd, 0)? as RawFd,
            ))
        }
    }

    fn install_fd(
        &self,
        buffer_addr: usize,
        conn: &SocketConnection,
        fd: BorrowedFd,
    ) -> Result<RemoteFd> {
        let buffer_len = unsafe { CMSG_SPACE(size_of::<i32>() as _) } as usize;

        let mut header = msghdr {
            msg_name: ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: buffer_addr as _,
            msg_controllen: buffer_len as _,
            msg_flags: 0,
        };

        let header_addr = (buffer_addr + buffer_len + 0xf) & !0xf; // align to 16 bytes

        socket::sendmsg::<()>(
            conn.local_fd.as_raw_fd(),
            &[],
            &[ControlMessage::ScmRights(&[fd.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )?;

        self.poke_data(header_addr, misc::as_byte_slice(&header))?;

        #[rustfmt::skip]
        self.call_remote_auto(
            ("libc", "recvmsg"),
            build_args!(conn.remote_fd.as_raw_fd(), header_addr, 0)
        )?;

        if self.peek(header_addr + mem::offset_of!(msghdr, msg_controllen))? == 0 {
            bail!("failed to install fd, please check your sepolicy rules")
        }

        let mut buffer = vec![0; buffer_len];

        self.peek_data(buffer_addr, &mut buffer)?;

        header.msg_control = buffer.as_ptr() as _;

        let cmsg = unsafe { CMSG_FIRSTHDR(&header) };
        let data = unsafe { CMSG_DATA(cmsg) };

        Ok(RemoteFd::new(unsafe { *(data as *const i32) }))
    }

    fn connect(&self, buffer_addr: usize) -> Result<SocketConnection> {
        let result = self.call_remote_auto(
            ("libc", "socketpair"),
            build_args!(AF_UNIX, SOCK_SEQPACKET, 0, buffer_addr),
        )?;

        if result != 0 {
            bail!("{self} failed to call socketpair")
        }

        let pair = self.peek(buffer_addr)?;

        let local_fd_num = (pair & 0xffffffff) as i32;
        let remote_fd_num = (pair >> 32) as i32;

        let local_fd = self.take_fd(local_fd_num)?;

        RemoteFd::new(local_fd_num).close(self)?;

        Ok(SocketConnection::new(
            local_fd,
            RemoteFd::new(remote_fd_num),
        ))
    }
}
