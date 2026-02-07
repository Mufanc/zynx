use anyhow::Result;
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

pub struct Bridge {
    fd: Memfd,
}

impl Bridge {
    fn new(data: &[u8]) -> Result<Self> {
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

        Ok(Self { fd })
    }

    pub fn instance() -> &'static Self {
        &INSTANCE
    }
}

impl AsFd for Bridge {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_file().as_fd()
    }
}
