use anyhow::{Context, Result};
use daemonize::Daemonize;
use log::info;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Once;
use std::time::{Duration, Instant};
use std::{env, process};
use tokio::runtime::Builder;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tokio::sync::oneshot;
use tokio::{task, time};
use zynx_utils::ext::ResultExt;

const ENV_LAUNCHER_PID: &str = "LAUNCHER_PID";

static NOTIFY_ONCE: Once = Once::new();

pub fn launch_daemon() -> Result<()> {
    Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(launch_daemon_async())?;

    Ok(())
}

async fn launch_daemon_async() -> Result<()> {
    let mut sig = unix::signal(SignalKind::user_defined1())?;
    let (tx, rx) = oneshot::channel::<()>();

    task::spawn(async move {
        info!("waiting for signal...");
        let _ = sig.recv().await;
        let _ = tx.send(());
    });

    let start = Instant::now();
    let _ = Command::new(env::current_exe()?)
        .env(ENV_LAUNCHER_PID, format!("{}", process::id()))
        .spawn()?;

    tokio::select! {
        _ = rx => {
            let elapsed = start.elapsed();
            info!("daemon started in {elapsed:.2?}");
            return Ok(())
        }
        _ = time::sleep(Duration::from_secs(5)) => {
            info!("daemon start timeout!");
        }
    }

    Ok(())
}

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

pub fn notify_launcher_if_needed() {
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
