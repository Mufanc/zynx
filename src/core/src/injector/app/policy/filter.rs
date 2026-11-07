use super::ProcessInfo;
use super::proto::{CheckRequest, CheckResponse, PackageInfo, ProcessInfo as ProcessInfoWire};
use anyhow::{Context, bail, ensure};
use nix::errno::Errno;
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType, UnixAddr};
use prost::Message;
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
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

#[derive(Debug, PartialEq)]
struct AbstractSocketIdentity {
    pid: i32,
    fd: i32,
    sequence: u64,
}

impl AbstractSocketIdentity {
    fn parse(name: &str, prefix: &str) -> Option<Self> {
        let fields = name.strip_prefix(prefix)?.strip_prefix("/v1:")?;
        let mut seen = HashSet::new();
        let (mut pid, mut fd, mut sequence, mut random) = (None, None, None, None);

        for field in fields.split(';') {
            let (key, value) = field.split_once('=')?;

            if key.is_empty() || value.is_empty() || !seen.insert(key) {
                return None;
            }

            match key {
                "p" | "f" | "s" => {
                    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
                        return None;
                    }

                    match key {
                        "p" => pid = Some(value.parse::<i32>().ok()?),
                        "f" => fd = Some(value.parse::<i32>().ok()?),
                        "s" => sequence = Some(value.parse::<u64>().ok()?),
                        _ => unreachable!(),
                    }
                }
                "?" => random = Some(value),
                _ => {}
            }
        }

        let pid = pid.filter(|pid| *pid > 0)?;

        random?;

        Some(Self {
            pid,
            fd: fd?,
            sequence: sequence?,
        })
    }

    fn validate(&self, inode: u64) -> anyhow::Result<()> {
        let path = format!("/proc/{}/fd/{}", self.pid, self.fd);
        let metadata = root_metadata(Path::new(&path))?;

        ensure!(
            metadata.file_type().is_socket(),
            "advertised FD is not a socket"
        );
        ensure!(metadata.ino() == inode, "abstract socket inode mismatch");

        Ok(())
    }
}

fn root_metadata(path: &Path) -> anyhow::Result<fs::Metadata> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("cannot stat filter endpoint {}", path.display()))?;

    ensure!(
        metadata.uid() == 0,
        "filter endpoint must be owned by root: {}",
        path.display()
    );

    Ok(metadata)
}

fn resolve_abstract_socket(prefix: &str) -> anyhow::Result<Vec<u8>> {
    let content = fs::read_to_string("/proc/net/unix")?;
    let mut best: Option<(u64, &str)> = None;

    for line in content.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let [_, _, _, flags, kind, state, inode, name] = fields.as_slice() else {
            continue;
        };

        // Only consider listening stream sockets: SO_ACCEPTCON, SOCK_STREAM, SS_UNCONNECTED.
        if *flags != "00010000" || *kind != "0001" || *state != "01" {
            continue;
        }

        let Some(name) = name.strip_prefix('@') else {
            continue;
        };
        let Some(identity) = AbstractSocketIdentity::parse(name, prefix) else {
            continue;
        };
        let Ok(inode) = inode.parse::<u64>() else {
            continue;
        };

        if best.is_none_or(|(sequence, _)| identity.sequence > sequence)
            && identity.validate(inode).is_ok()
        {
            best = Some((identity.sequence, name));
        }
    }

    best.map(|(_, name)| name.as_bytes().to_vec())
        .with_context(|| {
            format!("no root-owned abstract filter socket found with prefix {prefix:?}")
        })
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
                ensure!(
                    root_metadata(path)?.file_type().is_socket(),
                    "filter endpoint is not a socket"
                );

                let stream = UnixStream::connect(path).await?;
                Self::from_socket(stream)
            }
            ExternalFilter::UnixAbstract { prefix } => {
                let name = resolve_abstract_socket(prefix)?;
                let fd = socket::socket(
                    AddressFamily::Unix,
                    SockType::Stream,
                    SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
                    None,
                )?;
                let addr = UnixAddr::new_abstract(&name)?;

                match socket::connect(fd.as_raw_fd(), &addr) {
                    Ok(()) | Err(Errno::EINPROGRESS) => {}
                    Err(error) => return Err(error.into()),
                }

                let std_stream = std::os::unix::net::UnixStream::from(fd);
                let stream = UnixStream::from_std(std_stream)?;

                stream.writable().await?;

                if let Some(error) = stream.take_error()? {
                    return Err(error.into());
                }

                Self::from_socket(stream)
            }
            ExternalFilter::Stdio { path, args } => {
                ensure!(
                    root_metadata(path)?.is_file(),
                    "stdio filter is not a regular file"
                );

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

    fn from_socket(stream: UnixStream) -> anyhow::Result<Self> {
        ensure!(stream.peer_cred()?.uid() == 0, "filter peer must be root");
        Ok(Self::Socket(stream))
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
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncBufReadExt, BufReader};

    const RANDOM: &str = "random-suffix";

    #[test]
    fn parses_named_abstract_fields_and_rejects_invalid_identities() {
        let name = format!("example/v1:?={RANDOM};s=42;f=0;p=1234;extra=value");
        assert_eq!(
            AbstractSocketIdentity::parse(&name, "example"),
            Some(AbstractSocketIdentity {
                pid: 1234,
                fd: 0,
                sequence: 42,
            })
        );

        for fields in [
            format!("p=0;f=7;s=42;?={RANDOM}"),
            format!("p=1234;f=-1;s=42;?={RANDOM}"),
            format!("p=1234;f=7;s=18446744073709551616;?={RANDOM}"),
            format!("p=1234;f=7;s=42;p=1234;?={RANDOM}"),
            format!("p=1234;s=42;?={RANDOM}"),
            "p=1234;f=7;s=42".into(),
            "p=1234;f=7;s=42;?=".into(),
        ] {
            assert!(
                AbstractSocketIdentity::parse(&format!("example/v1:{fields}"), "example").is_none(),
                "{fields}"
            );
        }

        assert!(AbstractSocketIdentity::parse(&name.replace("/v1:", "/v2:"), "example").is_none());
        assert!(AbstractSocketIdentity::parse(&name, "exam").is_none());
    }

    fn abstract_listener(
        prefix: &str,
        sequence: u64,
        advertised_fd: Option<i32>,
    ) -> std::os::fd::OwnedFd {
        let fd = socket::socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            None,
        )
        .unwrap();
        let name = format!(
            "{prefix}/v1:p={};f={};s={sequence};?={RANDOM}",
            std::process::id(),
            advertised_fd.unwrap_or(fd.as_raw_fd())
        );
        let address = UnixAddr::new_abstract(name.as_bytes()).unwrap();
        socket::bind(fd.as_raw_fd(), &address).unwrap();
        socket::listen(&fd, socket::Backlog::new(1).unwrap()).unwrap();
        fd
    }

    #[tokio::test]
    async fn authenticates_abstract_inode_before_selecting_latest_socket() {
        assert!(
            Uid::effective().is_root(),
            "run endpoint authentication tests as root"
        );
        let prefix = format!("zynx-test-{}", std::process::id());
        let first = abstract_listener(&prefix, 1, None);
        let latest = abstract_listener(&prefix, 2, None);
        let forged = abstract_listener(&prefix, 99, Some(first.as_raw_fd()));
        let untrusted = abstract_listener(&prefix, 100, None);
        nix::unistd::fchown(&untrusted, Some(Uid::from_raw(2000)), None).unwrap();

        let name = resolve_abstract_socket(&prefix).unwrap();
        assert_eq!(
            AbstractSocketIdentity::parse(std::str::from_utf8(&name).unwrap(), &prefix)
                .unwrap()
                .sequence,
            2
        );
        let connection = AdapterConnection::connect(&ExternalFilter::UnixAbstract { prefix })
            .await
            .unwrap();
        let accepted = socket::accept(latest.as_raw_fd()).unwrap();
        nix::unistd::close(accepted).unwrap();
        assert_eq!(socket::accept(first.as_raw_fd()), Err(Errno::EAGAIN));
        assert_eq!(socket::accept(forged.as_raw_fd()), Err(Errno::EAGAIN));
        assert_eq!(socket::accept(untrusted.as_raw_fd()), Err(Errno::EAGAIN));
        connection.close().await;
    }

    #[tokio::test]
    async fn checks_file_owners_and_types_before_using_endpoints() {
        assert!(
            Uid::effective().is_root(),
            "run endpoint authentication tests as root"
        );
        let path = std::env::temp_dir().join(format!("zynx-filter-{}", std::process::id()));
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let filter = ExternalFilter::SocketFile { path: path.clone() };
        let connection = AdapterConnection::connect(&filter).await.unwrap();
        let _accepted = listener.accept().unwrap();
        connection.close().await;
        nix::unistd::chown(&path, Some(Uid::from_raw(2000)), None).unwrap();
        assert!(AdapterConnection::connect(&filter).await.is_err());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        fs::remove_file(&path).unwrap();

        fs::write(&path, "#!/system/bin/sh\nexit 0\n").unwrap();
        assert!(AdapterConnection::connect(&filter).await.is_err());
        let stdio = ExternalFilter::Stdio {
            path: path.clone(),
            args: vec![],
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let connection = AdapterConnection::connect(&stdio).await.unwrap();
        connection.close().await;
        nix::unistd::chown(&path, Some(Uid::from_raw(2000)), None).unwrap();
        assert!(AdapterConnection::connect(&stdio).await.is_err());
        fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn rejects_non_root_peer_on_root_owned_socket() {
        const CHILD_PATH: &str = "ZYNX_FILTER_TEST_PEER_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let _listener = std::os::unix::net::UnixListener::bind(path).unwrap();
            println!("FILTER_PEER_READY");
            std::io::stdout().flush().unwrap();
            let _ = std::io::stdin().read(&mut [0]);
            return;
        }

        assert!(
            Uid::effective().is_root(),
            "run endpoint authentication tests as root"
        );
        let path = std::env::temp_dir().join(format!("zynx-filter-peer-{}", std::process::id()));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "injector::app::policy::filter::tests::rejects_non_root_peer_on_root_owned_socket",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD_PATH, &path)
            .uid(2000)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
        timeout(IO_TIMEOUT, async {
            while let Some(line) = output.next_line().await.unwrap() {
                if line.contains("FILTER_PEER_READY") {
                    return;
                }
            }
            panic!("peer exited before listening");
        })
        .await
        .unwrap();
        nix::unistd::chown(&path, Some(Uid::from_raw(0)), None).unwrap();
        let result =
            AdapterConnection::connect(&ExternalFilter::SocketFile { path: path.clone() }).await;
        assert_eq!(
            result.err().unwrap().to_string(),
            "filter peer must be root"
        );
        child.kill().await.unwrap();
        fs::remove_file(path).unwrap();
    }

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
    async fn rejects_wrong_versions_and_missing_decisions() {
        for response in [
            CheckResponse {
                protocol_version: FILTER_PROTOCOL_VERSION + 1,
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
