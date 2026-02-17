use crate::android::packages::PackageInfoService;
use crate::config::ZynxConfigs;
use crate::injector::app::policy::proto::{
    CheckArgsFast, CheckArgsSlow, CheckResponse, CheckResult, PackageInfo,
};
use crate::injector::app::policy::{
    EmbryoCheckArgs, EmbryoCheckArgsFast, PolicyDecision, PolicyProvider,
};
use anyhow::{Result, bail};
use async_trait::async_trait;
use log::{info, warn};
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType, UnixAddr};
use parking_lot::RwLock;
use prost::Message;
use regex_lite::Regex;
use serde::Deserialize;
use std::any::Any;
use std::fs;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;
use zynx_bridge_shared::zygote::ProviderType;

const MODULES_DIR: &str = "/data/adb/modules"; // Fixme: use MODDIR
const IO_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB

// ============================================================================
// Configuration parsing (from zynx-configs.toml)
// ============================================================================

#[derive(Debug, Deserialize)]
struct ZygiskModuleConfig {
    filter: FilterConfig,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum FilterConfig {
    Stdio {
        path: PathBuf,
        #[serde(default)]
        args: Vec<String>,
    },
    SocketFile {
        path: PathBuf,
    },
    UnixAbstract {
        prefix: String,
    },
}

#[derive(Debug, Clone)]
enum FilterType {
    Stdio(PathBuf, Vec<Box<str>>),
    SocketFile(PathBuf),
    UnixAbstract(String),
}

struct ZygiskAdapter {
    module_id: String,
    filter: FilterType,
}

// ============================================================================
// Connection abstraction for external filter communication
// ============================================================================

/// Resolve the latest abstract socket matching `<prefix>_<seq>_<random>`.
/// Returns the socket name as bytes (without the `@` prefix) for use with `UnixAddr::new_abstract`.
fn resolve_abstract_socket(prefix: &str) -> Result<Vec<u8>> {
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
    async fn connect(filter: &FilterType) -> Result<Self> {
        match filter {
            FilterType::SocketFile(path) => {
                let stream = UnixStream::connect(path).await?;
                Ok(AdapterConnection::Socket(stream))
            }
            FilterType::UnixAbstract(prefix) => {
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
            FilterType::Stdio(path, args) => {
                let mut child = Command::new(path)
                    .args(args.iter().map(|s| s.as_ref()))
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
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

    async fn send_message(&mut self, msg: &impl Message) -> Result<()> {
        let data = msg.encode_to_vec();
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

    async fn recv_data(&mut self, buffer: &mut [u8]) -> Result<()> {
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

    async fn recv_message<T: Message + Default>(&mut self) -> Result<T> {
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

// ============================================================================
// Check state management
// ============================================================================

/// Result of a single adapter's check in the fast phase
enum AdapterCheckResult {
    /// Already decided in fast phase (ALLOW or DENY)
    Decided(CheckResult),
    /// Needs recheck, connection kept alive
    Pending(Box<AdapterConnection>),
    /// Failed to connect or communicate
    Failed,
}

/// State passed between check() and recheck()
struct ZygiskCheckState {
    /// Results for each adapter (indexed by adapter position)
    results: Vec<AdapterCheckResult>,
    /// Module IDs for logging in recheck
    module_ids: Vec<String>,
}

// ============================================================================
// Module scanning
// ============================================================================

fn scan_modules() -> Result<Vec<ZygiskAdapter>> {
    let modules_dir = Path::new(MODULES_DIR);
    if !modules_dir.exists() {
        return Ok(Vec::new());
    }

    let mut adapters = Vec::new();

    for entry in modules_dir.read_dir()?.flatten() {
        let module_dir = entry.path();
        if !module_dir.is_dir() {
            continue;
        }

        let module_id = match module_dir
            .file_name()
            .and_then(|n| n.to_str())
            .map(String::from)
        {
            Some(id) => id,
            None => continue,
        };

        if module_dir.join("disable").exists() {
            info!("skipping disabled module: {module_id}");
            continue;
        }

        let config_path = module_dir.join("zynx-configs.toml");
        if !config_path.exists() {
            continue;
        }

        let config_content = match fs::read_to_string(&config_path) {
            Ok(content) => content,
            Err(err) => {
                warn!("failed to read config for {module_id}: {err}");
                continue;
            }
        };

        let config: ZygiskModuleConfig = match toml::from_str(&config_content) {
            Ok(cfg) => cfg,
            Err(err) => {
                warn!("failed to parse config for {module_id}: {err}");
                continue;
            }
        };

        let filter = match config.filter {
            FilterConfig::Stdio { path, args } => {
                FilterType::Stdio(path, args.into_iter().map(|s| s.into()).collect())
            }
            FilterConfig::SocketFile { path } => FilterType::SocketFile(path),
            FilterConfig::UnixAbstract { prefix } => FilterType::UnixAbstract(prefix),
        };

        info!("loaded module: {module_id}");
        adapters.push(ZygiskAdapter { module_id, filter });
    }

    info!("scan complete: {} modules loaded", adapters.len());
    Ok(adapters)
}

// ============================================================================
// Policy Provider implementation
// ============================================================================

#[derive(Default)]
pub struct ZygiskPolicyProvider {
    adapters: RwLock<Vec<ZygiskAdapter>>,
}

impl ZygiskPolicyProvider {
    /// Check a single adapter in the fast phase
    async fn check_adapter(
        filter: &FilterType,
        module_id: &str,
        fast_args: &CheckArgsFast,
    ) -> AdapterCheckResult {
        // Connect to the external filter
        let mut conn = match timeout(IO_TIMEOUT, AdapterConnection::connect(filter)).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(err)) => {
                warn!("{module_id}: failed to connect: {err}");
                return AdapterCheckResult::Failed;
            }
            Err(_) => {
                warn!("{module_id}: connection timeout");
                return AdapterCheckResult::Failed;
            }
        };

        // Send CheckArgsFast
        if let Err(err) = timeout(IO_TIMEOUT, conn.send_message(fast_args)).await {
            warn!("{module_id}: failed to send fast args: {err}");
            conn.close().await;
            return AdapterCheckResult::Failed;
        }

        // Receive CheckResponse
        let response: CheckResponse = match timeout(IO_TIMEOUT, conn.recv_message()).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(err)) => {
                warn!("{module_id}: failed to receive response: {err}");
                conn.close().await;
                return AdapterCheckResult::Failed;
            }
            Err(_) => {
                warn!("{module_id}: receive timeout");
                conn.close().await;
                return AdapterCheckResult::Failed;
            }
        };

        match CheckResult::try_from(response.result) {
            Ok(CheckResult::Allow) => {
                conn.close().await;
                AdapterCheckResult::Decided(CheckResult::Allow)
            }
            Ok(CheckResult::Deny) => {
                conn.close().await;
                AdapterCheckResult::Decided(CheckResult::Deny)
            }
            Ok(CheckResult::MoreInfo) => {
                // Keep connection alive for recheck
                AdapterCheckResult::Pending(Box::new(conn))
            }
            Err(_) => {
                warn!("{module_id}: invalid check result: {}", response.result);
                conn.close().await;
                AdapterCheckResult::Failed
            }
        }
    }

    /// Recheck a single adapter in the slow phase
    async fn recheck_adapter(
        mut conn: AdapterConnection,
        module_id: &str,
        slow_args: &CheckArgsSlow,
    ) -> CheckResult {
        // Send CheckArgsSlow
        if let Err(err) = timeout(IO_TIMEOUT, conn.send_message(slow_args)).await {
            warn!("{module_id}: failed to send slow args: {err}");
            conn.close().await;
            return CheckResult::Deny;
        }

        // Receive CheckResponse
        let response: CheckResponse = match timeout(IO_TIMEOUT, conn.recv_message()).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(err)) => {
                warn!("{module_id}: failed to receive response: {err}");
                conn.close().await;
                return CheckResult::Deny;
            }
            Err(_) => {
                warn!("{module_id}: receive timeout");
                conn.close().await;
                return CheckResult::Deny;
            }
        };

        conn.close().await;

        match CheckResult::try_from(response.result) {
            Ok(CheckResult::Allow) => CheckResult::Allow,
            Ok(CheckResult::Deny) => CheckResult::Deny,
            Ok(CheckResult::MoreInfo) => {
                warn!("{module_id}: returned MORE_INFO in slow phase, treating as DENY");
                CheckResult::Deny
            }
            Err(_) => {
                warn!("{module_id}: invalid check result: {}", response.result);
                CheckResult::Deny
            }
        }
    }
}

#[async_trait]
impl PolicyProvider for ZygiskPolicyProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Zygisk
    }

    async fn init(&self) -> Result<()> {
        if !ZynxConfigs::instance().enable_zygisk {
            return Ok(());
        }

        let adapters = scan_modules()?;
        *self.adapters.write() = adapters;

        Ok(())
    }

    async fn check(&self, args: &EmbryoCheckArgs<'_>) -> PolicyDecision {
        if !ZynxConfigs::instance().enable_zygisk {
            return PolicyDecision::Deny;
        }

        // Clone adapter data and release lock before any await
        let adapter_data: Vec<_> = {
            let adapters = self.adapters.read();
            if adapters.is_empty() {
                return PolicyDecision::Deny;
            }
            adapters
                .iter()
                .map(|a| (a.filter.clone(), a.module_id.clone()))
                .collect()
        };

        let fast_args = build_fast_args(args.assume_fast());

        // Check all adapters
        let mut results = Vec::with_capacity(adapter_data.len());
        let mut has_pending = false;
        let mut has_allow = false;

        for (filter, module_id) in &adapter_data {
            let result = Self::check_adapter(filter, module_id, &fast_args).await;

            match &result {
                AdapterCheckResult::Decided(CheckResult::Allow) => has_allow = true,
                AdapterCheckResult::Pending(_) => has_pending = true,
                _ => {}
            }

            results.push(result);
        }

        // Determine decision
        if has_pending {
            // Need recheck for some adapters, store module_ids for recheck
            let module_ids: Vec<_> = adapter_data.into_iter().map(|(_, id)| id).collect();
            PolicyDecision::MoreInfo(Some(Box::new(ZygiskCheckState {
                results,
                module_ids,
            })))
        } else if has_allow {
            // All decided, at least one allowed
            PolicyDecision::allow()
        } else {
            // All decided, none allowed
            PolicyDecision::Deny
        }
    }

    async fn recheck(
        &self,
        args: &EmbryoCheckArgs<'_>,
        state: Box<dyn Any + Send + Sync>,
    ) -> PolicyDecision {
        let slow = args.assume_slow();

        let mut check_state = state
            .downcast::<ZygiskCheckState>()
            .expect("failed to downcast ZygiskCheckState");

        // Build slow args
        let slow_args = CheckArgsSlow {
            fast: None, // We don't need to resend fast args
            nice_name: slow.nice_name.clone(),
            app_data_dir: slow.app_data_dir.clone(),
        };

        let mut has_allow = false;

        // Process all results (module_ids are stored in state, no lock needed)
        for (i, result) in check_state.results.drain(..).enumerate() {
            match result {
                AdapterCheckResult::Decided(CheckResult::Allow) => {
                    has_allow = true;
                }
                AdapterCheckResult::Pending(conn) => {
                    let module_id = &check_state.module_ids[i];
                    let final_result = Self::recheck_adapter(*conn, module_id, &slow_args).await;
                    if final_result == CheckResult::Allow {
                        has_allow = true;
                    }
                }
                AdapterCheckResult::Decided(CheckResult::Deny) | AdapterCheckResult::Failed => {
                    // Already denied or failed
                }
                AdapterCheckResult::Decided(CheckResult::MoreInfo) => {
                    // Should not happen, but treat as deny
                }
            }
        }

        if has_allow {
            PolicyDecision::allow()
        } else {
            PolicyDecision::Deny
        }
    }
}

fn build_fast_args(fast: &EmbryoCheckArgsFast) -> CheckArgsFast {
    let packages: Vec<_> = PackageInfoService::instance()
        .query(fast.uid)
        .map(|pkgs| {
            pkgs.iter()
                .map(|pkg| PackageInfo {
                    package_name: pkg.name.clone(),
                    debuggable: pkg.debuggable,
                    data_dir: pkg.data_dir.clone(),
                    seinfo: pkg.seinfo.clone(),
                    gids: vec![],
                })
                .collect()
        })
        .unwrap_or_default();

    CheckArgsFast {
        uid: fast.uid.as_raw(),
        gid: fast.gid.as_raw(),
        is_system_server: fast.is_system_server,
        is_child_zygote: fast.is_child_zygote,
        package_info: packages,
    }
}
