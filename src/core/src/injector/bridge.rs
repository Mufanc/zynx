use crate::misc::create_sealed_memfd;
use anyhow::Result;
use memfd::Memfd;
use once_cell::sync::Lazy;
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
        let fd = create_sealed_memfd("zynx::bridge", data)?;
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
