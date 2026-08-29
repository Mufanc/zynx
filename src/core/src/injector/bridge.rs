use crate::config::ZynxConfigs;
use crate::misc::create_sealed_memfd;
use anyhow::{Context, Result, anyhow};
use once_cell::sync::Lazy;
use std::borrow::Cow;
use std::fs;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

#[cfg(feature = "embedded-bridge")]
static DATA: &[u8] = include_bytes!(concat!(
    env!("ROOT_DIR"),
    "/target/aarch64-linux-android/",
    env!("PROFILE"),
    "/libzynx_bridge.so"
));

static INSTANCE: Lazy<Result<Bridge>> = Lazy::new(Bridge::new);

pub struct Bridge {
    fd: OwnedFd,
}

impl Bridge {
    fn new() -> Result<Self> {
        let data = if let Some(path) = &ZynxConfigs::instance().bridge_file {
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

    pub fn instance() -> Result<&'static Self> {
        INSTANCE
            .as_ref()
            .map_err(|err| anyhow!("failed to load zynx bridge: {err:#}"))
    }
}

impl AsFd for Bridge {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
