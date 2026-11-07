use std::os::fd::OwnedFd;
use zynx_bridge_shared::action::ActionData;

#[derive(Debug, Clone)]
pub struct Action<F = OwnedFd> {
    pub fd: Option<F>,
    pub data: Vec<u8>,
}

impl<F> Action<F> {
    pub fn new(fd: Option<F>, data: ActionData) -> anyhow::Result<Self> {
        Ok(Self {
            fd,
            data: wincode::serialize(&data)?,
        })
    }
}
