use crate::binary::symbol::CachedFirstResolver;
use crate::injector::PAGE_SIZE;
use anyhow::{Context, Result};
use memfd::{FileSeal, Memfd, MemfdOptions};
use once_cell::sync::Lazy;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsFd, BorrowedFd};

static DATA: &[u8] = include_bytes!(concat!(
    env!("ROOT_DIR"),
    "/target/aarch64-linux-android/",
    env!("PROFILE"),
    "/libzynx_bridge.so"
));

static INSTANCE: Lazy<Bridge> =
    Lazy::new(|| Bridge::new(DATA).expect("failed to load zynx bridge"));

pub struct Bridge<'a> {
    size: usize,
    fd: Memfd,
    resolver: CachedFirstResolver<'a>,
}

impl Bridge<'_> {
    fn new(data: &[u8]) -> Result<Self> {
        let resolver = CachedFirstResolver::from_data(data.to_vec())?;
        let fd = MemfdOptions::default()
            .allow_sealing(true)
            .create("zynx::bridge")?;

        let mut file = fd.as_file();

        file.write_all(data)?;
        file.sync_data()?;
        file.seek(SeekFrom::Start(0))?;

        fd.add_seals(&[
            FileSeal::SealGrow,
            FileSeal::SealShrink,
            FileSeal::SealWrite,
            FileSeal::SealSeal,
        ])?;

        Ok(Self {
            size: data.len(),
            fd,
            resolver,
        })
    }

    pub fn trampoline_size(&self) -> usize {
        self.size
    }

    pub fn resolve(&self, name: &str) -> Result<usize> {
        let sym = self.resolver.resolve(name)?;
        let sec = self.resolver.inner().find_section(sym.section_index)?;

        Ok(sym.addr - sec.addr
            + sec
                .file_offset
                .context(format!("section {} has no file offset", sec.name))?)
    }

    pub fn instance() -> &'static Self {
        &INSTANCE
    }
}

impl AsFd for Bridge<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_file().as_fd()
    }
}
