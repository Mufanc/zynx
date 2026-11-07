use super::ProcessInfo;
use super::proto::{CheckRequest, CheckResponse, PackageInfo, ProcessInfo as ProcessInfoWire};
use anyhow::{Context, bail, ensure};
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType, UnixAddr};
use prost::Message;
use regex_lite::Regex;
use std::fs;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

const FILTER_PROTOCOL_VERSION: u32 = 2;
const IO_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

#[derive(Debug)]
pub(super) enum ExternalFilter {
    Stdio { path: PathBuf, args: Vec<String> },
    SocketFile { path: PathBuf },
    UnixAbstract { prefix: String },
}

impl ExternalFilter {
    pub(super) async fn check(&self, process: &ProcessInfo) -> anyhow::Result<bool> {
        let mut connection = timeout(IO_TIMEOUT, AdapterConnection::connect(self))
            .await
            .context("filter connection timeout")??;
        let request = CheckRequest {
            protocol_version: FILTER_PROTOCOL_VERSION,
            process: Some(build_process_info(process)),
        };
        let decision = connection.query_decision(&request).await;

        connection.close().await;

        decision
    }
}

/// Resolve the latest abstract socket matching `<prefix>_<seq>_<random>`.
/// Returns the socket name as bytes (without the `@` prefix) for use with `UnixAddr::new_abstract`.
fn resolve_abstract_socket(prefix: &str) -> anyhow::Result<Vec<u8>> {
    let pattern = format!(r"^{}_(\d+)_[a-zA-Z0-9-]+$", regex_lite::escape(prefix));
    let re = Regex::new(&pattern)?;

    let content = fs::read_to_string("/proc/net/unix")?;
    let mut best: Option<(u64, &str)> = None;

    for line in content.lines().skip(1) {
        let path = match line.rsplit_once(char::is_whitespace) {
            Some((_, path)) if path.starts_with('@') => &path[1..],
            _ => continue,
        };

        if let Some(caps) = re.captures(path)
            && let Ok(seq) = caps[1].parse::<u64>()
            && best.is_none_or(|(best_seq, _)| seq > best_seq)
        {
            best = Some((seq, path));
        }
    }

    match best {
        Some((_, name)) => Ok(name.as_bytes().to_vec()),
        None => bail!("no abstract socket found with prefix \"{prefix}\""),
    }
}

enum AdapterConnection {
    Socket(UnixStream),
    Stdio {
        child: Child,
        stdin: ChildStdin,
        stdout: ChildStdout,
    },
}

impl AdapterConnection {
    async fn connect(filter: &ExternalFilter) -> anyhow::Result<Self> {
        match filter {
            ExternalFilter::SocketFile { path } => {
                let stream = UnixStream::connect(path).await?;
                Ok(AdapterConnection::Socket(stream))
            }
            ExternalFilter::UnixAbstract { prefix } => {
                let name = resolve_abstract_socket(prefix)?;
                let fd = socket::socket(
                    AddressFamily::Unix,
                    SockType::Stream,
                    SockFlag::SOCK_CLOEXEC,
                    None,
                )?;
                let addr = UnixAddr::new_abstract(&name)?;

                socket::connect(fd.as_raw_fd(), &addr)?;

                let std_stream = std::os::unix::net::UnixStream::from(fd);

                std_stream.set_nonblocking(true)?;

                let stream = UnixStream::from_std(std_stream)?;
                Ok(AdapterConnection::Socket(stream))
            }
            ExternalFilter::Stdio { path, args } => {
                let mut child = Command::new(path)
                    .args(args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .spawn()?;

                let stdin = child.stdin.take().expect("stdin was configured as piped");
                let stdout = child.stdout.take().expect("stdout was configured as piped");

                Ok(AdapterConnection::Stdio {
                    child,
                    stdin,
                    stdout,
                })
            }
        }
    }

    async fn post_message(&mut self, msg: &impl Message) -> anyhow::Result<()> {
        let data = msg.encode_to_vec();
        ensure!(
            data.len() <= MAX_MESSAGE_SIZE,
            "request exceeds {MAX_MESSAGE_SIZE} bytes"
        );

        let len = data.len() as u32;

        match self {
            AdapterConnection::Socket(stream) => {
                stream.write_all(&len.to_le_bytes()).await?;
                stream.write_all(&data).await?;
            }
            AdapterConnection::Stdio { stdin, .. } => {
                stdin.write_all(&len.to_le_bytes()).await?;
                stdin.write_all(&data).await?;
            }
        }

        Ok(())
    }

    async fn recv_data(&mut self, buffer: &mut [u8]) -> anyhow::Result<()> {
        match self {
            AdapterConnection::Socket(stream) => {
                stream.read_exact(buffer).await?;
            }
            AdapterConnection::Stdio { stdout, .. } => {
                stdout.read_exact(buffer).await?;
            }
        }

        Ok(())
    }

    async fn recv_message<T: Message + Default>(&mut self) -> anyhow::Result<T> {
        let mut len_buf = [0u8; 4];

        self.recv_data(&mut len_buf).await?;

        let len = u32::from_le_bytes(len_buf) as usize;

        if len > MAX_MESSAGE_SIZE {
            bail!("message too large: {len} bytes (max {MAX_MESSAGE_SIZE})");
        }

        let mut data = vec![0u8; len];

        self.recv_data(&mut data).await?;

        Ok(T::decode(data.as_slice())?)
    }

    async fn query_decision(&mut self, request: &CheckRequest) -> anyhow::Result<bool> {
        timeout(IO_TIMEOUT, self.post_message(request))
            .await
            .context("filter send timeout")??;

        let response: CheckResponse = timeout(IO_TIMEOUT, self.recv_message())
            .await
            .context("filter receive timeout")??;

        ensure!(
            response.protocol_version == FILTER_PROTOCOL_VERSION,
            "unsupported filter protocol version: {}",
            response.protocol_version
        );

        response
            .allow
            .context("filter response is missing an allow decision")
    }

    async fn close(self) {
        match self {
            AdapterConnection::Socket(stream) => {
                drop(stream);
            }
            AdapterConnection::Stdio { mut child, .. } => {
                let _ = child.kill().await;
            }
        }
    }
}

fn build_process_info(process: &ProcessInfo) -> ProcessInfoWire {
    let packages = process
        .package_info
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|package| PackageInfo {
            package_name: package.name.clone(),
            debuggable: package.debuggable,
            data_dir: package.data_dir.clone(),
            seinfo: package.seinfo.clone(),
            gids: package.gids.iter().map(|gid| gid.as_raw()).collect(),
        })
        .collect();

    ProcessInfoWire {
        uid: process.uid.as_raw(),
        gid: process.gid.as_raw(),
        is_system_server: process.is_system_server,
        is_child_zygote: process.is_child_zygote,
        package_info: packages,
        nice_name: process.nice_name.clone(),
        app_data_dir: process.app_data_dir.clone(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::{Gid, Uid};

    fn process() -> ProcessInfo {
        ProcessInfo {
            uid: Uid::from_raw(10123),
            gid: Gid::from_raw(10123),
            is_system_server: false,
            is_child_zygote: false,
            package_info: Some(std::sync::Arc::from(vec![
                crate::android::packages::PackageInfo {
                    name: "com.example".into(),
                    app_id: 10123,
                    debuggable: true,
                    data_dir: "/data/user/0/com.example".into(),
                    seinfo: "default".into(),
                    gids: vec![Gid::from_raw(3003)],
                },
            ])),
            nice_name: Some("com.example:worker".into()),
            app_data_dir: Some("/data/user/0/com.example".into()),
        }
    }

    fn request() -> CheckRequest {
        CheckRequest {
            protocol_version: FILTER_PROTOCOL_VERSION,
            process: Some(build_process_info(&process())),
        }
    }

    async fn exchange(response: Vec<u8>) -> anyhow::Result<bool> {
        let (client, server) = UnixStream::pair()?;
        let mut client = AdapterConnection::Socket(client);
        let server = tokio::spawn(async move {
            let mut connection = AdapterConnection::Socket(server);
            let request: CheckRequest = connection.recv_message().await.unwrap();
            assert_eq!(request.protocol_version, FILTER_PROTOCOL_VERSION);
            let process = request.process.unwrap();
            assert_eq!(process.uid, 10123);
            assert_eq!(process.nice_name.as_deref(), Some("com.example:worker"));
            assert_eq!(
                process.app_data_dir.as_deref(),
                Some("/data/user/0/com.example")
            );
            assert_eq!(process.package_info[0].gids, vec![3003]);

            let AdapterConnection::Socket(stream) = &mut connection else {
                unreachable!()
            };
            stream
                .write_all(&(response.len() as u32).to_le_bytes())
                .await
                .unwrap();
            stream.write_all(&response).await.unwrap();
        });
        let decision = client.query_decision(&request()).await;
        client.close().await;
        server.await?;

        decision
    }

    #[tokio::test]
    async fn sends_complete_information_once_and_accepts_explicit_decisions() {
        for allow in [true, false] {
            let response = CheckResponse {
                protocol_version: FILTER_PROTOCOL_VERSION,
                allow: Some(allow),
            };
            assert_eq!(exchange(response.encode_to_vec()).await.unwrap(), allow);
        }
    }

    #[tokio::test]
    async fn rejects_old_responses_wrong_versions_and_missing_decisions() {
        // Old ALLOW is the empty proto3 message; DENY and MORE_INFO only set tag 1.
        for bytes in [vec![], vec![8, 1], vec![8, 2]] {
            assert!(exchange(bytes).await.is_err());
        }
        for response in [
            CheckResponse {
                protocol_version: 1,
                allow: Some(true),
            },
            CheckResponse {
                protocol_version: FILTER_PROTOCOL_VERSION,
                allow: None,
            },
        ] {
            assert!(exchange(response.encode_to_vec()).await.is_err());
        }
    }
}
