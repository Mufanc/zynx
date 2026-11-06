use crate::misc::create_sealed_memfd;
#[cfg(not(feature = "standalone"))]
use anyhow::Context;
#[cfg(not(feature = "standalone"))]
use std::fs;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
#[cfg(not(feature = "standalone"))]
use std::path::Path;

#[cfg(feature = "standalone")]
static DATA: &[u8] = include_bytes!(concat!(
    env!("ROOT_DIR"),
    "/target/aarch64-linux-android/",
    env!("PROFILE"),
    "/libzynx_bridge.so"
));

pub struct Bridge {
    fd: OwnedFd,
}

impl Bridge {
    pub fn new(#[cfg(not(feature = "standalone"))] bridge_file: &Path) -> anyhow::Result<Self> {
        #[cfg(feature = "standalone")]
        let data = DATA;
        #[cfg(not(feature = "standalone"))]
        let data: &[u8] = &fs::read(bridge_file)
            .with_context(|| format!("failed to read bridge: {}", bridge_file.display()))?;

        Ok(Self {
            fd: create_sealed_memfd("zynx::bridge", data)?,
        })
    }
}

impl AsFd for Bridge {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
