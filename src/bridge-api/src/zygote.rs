use std::os::fd::OwnedFd;
use zynx_bridge_shared::zygote::ProviderType;

#[derive(Debug)]
pub struct Attachment {
    pub fd: Option<OwnedFd>,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct ProviderBundle {
    pub ty: ProviderType,
    pub attachments: Vec<Attachment>,
    pub data: Option<Vec<u8>>,
}
