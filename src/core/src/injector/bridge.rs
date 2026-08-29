use crate::misc::create_sealed_memfd;
use anyhow::{Context, Result};
use std::borrow::Cow;
use std::fs;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

#[cfg(feature = "embedded-bridge")]
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
    pub fn new(bridge_file: Option<&Path>) -> Result<Self> {
        let data = if let Some(path) = bridge_file {
            Cow::Owned(
                fs::read(path)
                    .with_context(|| format!("failed to read bridge: {}", path.display()))?,
            )
        } else {
            #[cfg(feature = "embedded-bridge")]
            {
                Cow::Borrowed(DATA)
            }

            #[cfg(not(feature = "embedded-bridge"))]
            anyhow::bail!("bridge path is not configured")
        };

        Ok(Self {
            fd: create_sealed_memfd("zynx::bridge", &data)?,
        })
    }
}

impl AsFd for Bridge {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
