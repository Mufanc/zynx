use crate::injector::app::policy::Action;
use anyhow::Result;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use zynx_bridge_shared::zygote::{ActionWire, IpcPayload};

/// FDs follow the action order, omitting actions without an FD.
pub fn actions_to_payload(actions: &[Action]) -> (IpcPayload, Vec<BorrowedFd<'_>>) {
    let mut fds = Vec::new();
    let actions = actions
        .iter()
        .map(|action| {
            if let Some(fd) = &action.fd {
                fds.push(fd.as_fd());
            }

            ActionWire {
                has_fd: action.fd.is_some(),
                data: action.data.clone(),
            }
        })
        .collect();

    (IpcPayload { actions }, fds)
}

pub fn transfer_data(conn_fd: OwnedFd, actions: Vec<Action>) -> Result<()> {
    let (payload, fds) = actions_to_payload(&actions);
    payload.send_to(conn_fd, fds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::misc;
    use nix::sys::socket::{self, AddressFamily, SockFlag, SockType};
    use std::fs::File;
    use std::io::Read;
    use std::sync::Arc;
    use zynx_bridge_shared::action::ActionData;

    #[test]
    fn transfers_ordered_actions_with_optional_fds() {
        let (sender, receiver) = socket::socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        let first = Arc::new(misc::create_sealed_memfd("first", b"native-first").unwrap());
        let second = Arc::new(misc::create_sealed_memfd("second", b"java-second").unwrap());
        let actions = vec![
            Action::new(
                Some(first),
                ActionData::LoadNative {
                    name: "first".into(),
                },
            )
            .unwrap(),
            Action::new(None, ActionData::EnableDebugger).unwrap(),
            Action::new(
                Some(second),
                ActionData::LoadJava {
                    name: "second".into(),
                },
            )
            .unwrap(),
        ];
        let sender = std::thread::spawn(move || transfer_data(sender, actions).unwrap());
        let (payload, fds) = IpcPayload::recv_from(receiver).unwrap();
        sender.join().unwrap();
        assert_eq!(
            payload
                .actions
                .iter()
                .map(|action| action.has_fd)
                .collect::<Vec<_>>(),
            [true, false, true]
        );
        let data: Vec<ActionData> = payload
            .actions
            .iter()
            .map(|action| wincode::deserialize(&action.data).unwrap())
            .collect();
        assert!(matches!(&data[0], ActionData::LoadNative { name } if name == "first"));
        assert!(matches!(&data[1], ActionData::EnableDebugger));
        assert!(matches!(&data[2], ActionData::LoadJava { name } if name == "second"));
        let contents: Vec<Vec<u8>> = fds
            .into_iter()
            .map(|fd| {
                let mut bytes = Vec::new();
                File::from(fd).read_to_end(&mut bytes).unwrap();
                bytes
            })
            .collect();
        assert_eq!(
            contents,
            [b"native-first".to_vec(), b"java-second".to_vec()]
        );
    }
}
