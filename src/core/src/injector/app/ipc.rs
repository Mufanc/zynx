use crate::injector::app::policy::ProviderBundle;
use anyhow::Result;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use zynx_bridge_shared::zygote::{AttachmentWire, IpcPayload, ProviderBundleWire};

/// Convert business-layer `ProviderBundle`s into transport-layer `(IpcPayload, fds)`.
///
/// The returned `IpcPayload` is the wire-format struct, and `fds` is a flat list
/// of borrowed file descriptors extracted from attachments in the same order
/// that the receiver expects (matching `has_fd` markers in the wire struct).
pub fn bundles_to_payload(bundles: &[ProviderBundle]) -> (IpcPayload, Vec<BorrowedFd<'_>>) {
    let mut fds = Vec::new();

    let providers: Vec<ProviderBundleWire> = bundles
        .iter()
        .map(|bundle| ProviderBundleWire {
            ty: bundle.ty,
            attachments: bundle
                .attachments
                .iter()
                .map(|attachment| {
                    if let Some(ref fd) = attachment.fd {
                        fds.push(fd.as_fd());
                    }
                    AttachmentWire {
                        has_fd: attachment.fd.is_some(),
                        data: attachment.data.clone(),
                    }
                })
                .collect(),
            data: bundle.data.clone(),
        })
        .collect();

    (IpcPayload { providers }, fds)
}

/// Transfer `ProviderBundle`s over a unix socket via SCM_RIGHTS.
///
/// This is a convenience wrapper around [`bundles_to_payload`] + [`IpcPayload::send_to`].
pub fn transfer_data(conn_fd: OwnedFd, bundles: Vec<ProviderBundle>) -> Result<()> {
    let (payload, fds) = bundles_to_payload(&bundles);
    payload.send_to(conn_fd, fds)
}
