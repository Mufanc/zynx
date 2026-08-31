use anyhow::{Context, Result, bail};
use daemonize::Daemonize;
use log::info;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::sys::socket;
use nix::sys::socket::{AddressFamily, Backlog, MsgFlags, SockFlag, SockType, UnixAddr};
use nix::unistd::Pid;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant};
use std::{env, process};
use tokio::runtime::Builder;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tokio::sync::oneshot;
use tokio::{task, time};
use zynx_misc::ext::ResultExt;

const ENV_LAUNCHER_PID: &str = "ZYNX_LAUNCHER_PID";
const ENV_WAIT_BPFLOADER: &str = "ZYNX_WAIT_BPFLOADER";
const ZYNX_SOCKET_NAME: &[u8] = b"zynx-bpfloader-sock";

static NOTIFY_ONCE: Once = Once::new();
static BPFLOADER_CONNECTION: Mutex<Option<OwnedFd>> = Mutex::new(None);

/// Bridges synchronous `main` to the async launcher.
pub fn launch_daemon(wait_bpfloader: bool) -> Result<()> {
    Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(launch_daemon_async(wait_bpfloader))?;

    Ok(())
}

/// Spawns a commandless child and waits until that child lets the caller continue.
async fn launch_daemon_async(wait_bpfloader: bool) -> Result<()> {
    let mut sig = unix::signal(SignalKind::user_defined1())?;
    let (tx, rx) = oneshot::channel::<()>();

    task::spawn(async move {
        info!("waiting for signal...");
        let _ = sig.recv().await;
        let _ = tx.send(());
    });

    let start = Instant::now();
    let args: Vec<String> = env::args()
        .skip(1)
        .filter(|arg| arg != "daemon" && arg != "--wait-bpfloader")
        .collect();
    let mut command = Command::new(env::current_exe()?);

    command
        .args(&args)
        .env(ENV_LAUNCHER_PID, format!("{}", process::id()));

    if wait_bpfloader {
        command.env(ENV_WAIT_BPFLOADER, "1");
    }

    let _ = command.spawn()?;

    tokio::select! {
        _ = rx => {
            let elapsed = start.elapsed();
            info!("daemon started in {elapsed:.2?}");
            Ok(())
        }
        _ = time::sleep(Duration::from_secs(10)) => bail!("daemon start timeout"),
    }
}

/// Detaches only children marked by the launcher; direct invocations stay foreground.
pub fn daemonize_if_needed() -> Result<()> {
    if env::var(ENV_LAUNCHER_PID).is_err() {
        info!("not in daemon mode, skip daemonize");
        return Ok(());
    }

    let exe = env::current_exe()?; // e.g. /data/adb/modules/zynx/bin/zynx
    let mut dir = PathBuf::from(exe.parent().unwrap());

    while !dir.join("module.prop").exists() {
        dir = PathBuf::from(dir.parent().context("module.prop not found")?)
    }

    Daemonize::new().working_directory(dir).start()?;

    Ok(())
}

/// Blocks module-mode initialization until the wrapper has run the system bpfloader.
pub fn wait_for_bpfloader_if_needed() -> Result<()> {
    if env::var(ENV_WAIT_BPFLOADER).is_err() {
        return Ok(());
    }

    let listener = socket::socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    let address = UnixAddr::new_abstract(ZYNX_SOCKET_NAME)?;

    socket::bind(listener.as_raw_fd(), &address)?;
    socket::listen(&listener, Backlog::new(1)?)?;
    // The boot script can mount the wrapper once the listener cannot miss its connection.
    notify_launcher_if_needed();

    let connection = socket::accept4(listener.as_raw_fd(), SockFlag::SOCK_CLOEXEC)?;
    let connection = unsafe { OwnedFd::from_raw_fd(connection) };
    // Keep the wrapper blocked until Zynx finishes initializing.
    *BPFLOADER_CONNECTION.lock().unwrap() = Some(connection);

    Ok(())
}

/// Releases the wrapper, or the launcher when no wrapper is involved.
pub fn notify_started() {
    if let Some(connection) = BPFLOADER_CONNECTION.lock().unwrap().take() {
        socket::send(connection.as_raw_fd(), &[1], MsgFlags::MSG_NOSIGNAL).log_if_error();
    }

    notify_launcher_if_needed();
}

/// Wakes the launcher once the child is safe to leave unattended.
fn notify_launcher_if_needed() {
    NOTIFY_ONCE.call_once(|| {
        let result: Result<()> = (|| {
            let Ok(pid) = env::var(ENV_LAUNCHER_PID) else {
                info!("not in daemon mode, skip notify");
                return Ok(());
            };

            let pid = Pid::from_raw(pid.parse()?);

            signal::kill(pid, Signal::SIGUSR1)?;
            info!("notifying launcher...");

            Ok(())
        })();

        result.log_if_error();
    })
}
