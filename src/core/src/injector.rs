use crate::config::ZynxConfigs;
use crate::injector::context::ZynxContext;
use crate::monitor::{Message, Monitor};
use crate::{daemon, monitor};
use anyhow::{Result, bail};
use app::zygote::ZYGOTE_NAME;
use app::zygote::ZygoteTracer;
use log::{error, info};
use nix::unistd;
use nix::unistd::{Pid, SysconfVar};
use once_cell::sync::Lazy;
use procfs::process::Process;
use std::sync::Arc;

mod app;
mod asm;
mod bridge;
mod context;
mod misc;
mod ptrace;

pub static PAGE_SIZE: Lazy<usize> =
    Lazy::new(|| unistd::sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap() as _);

fn handle_event(context: &Arc<ZynxContext>, event: &Message) -> Result<()> {
    match event {
        Message::PathMatches(pid, path) => {
            // Todo:
            Ok(())
        }
        Message::NameMatches(pid, name) => {
            if name == ZYGOTE_NAME {
                ptrace::spin_wait(*pid)?;

                let args = Process::new(pid.as_raw())?.cmdline()?;

                if args.iter().any(|arg| arg == "--start-system-server") {
                    return ZygoteTracer::create(context.clone(), *pid);
                }

                info!("found `{ZYGOTE_NAME}` without system server argument: {pid} -> {args:?}")
            }

            // Todo:
            Ok(())
        }
        Message::ZygoteFork(pid) => ZygoteTracer::on_fork(*pid),
        Message::ZygoteCrashed(_pid) => ZygoteTracer::reset(),
    }
}

pub async fn run(config: ZynxConfigs) -> Result<()> {
    let monitor_config = monitor::Config {
        target_paths: vec![],
        target_names: vec![ZYGOTE_NAME.into()],
    };

    let context = Arc::new(ZynxContext::new(&config).await?);
    Monitor::init(monitor_config)?;
    daemon::notify_started();

    let monitor = Monitor::instance();

    while let Some(event) = monitor.recv_msg().await {
        if let Err(err) = handle_event(&context, &event) {
            error!("error while handling event {event:?}: {err:?}");
        }
    }

    bail!("monitor exited unexpectedly");
}

pub async fn attach_zygote(pid: i32, config: ZynxConfigs) -> Result<()> {
    let pid = Pid::from_raw(pid);

    // verify that the process is actually zygote64
    let proc = Process::new(pid.as_raw())?;
    let cmdline = proc.cmdline()?;
    if !cmdline.iter().any(|arg| arg == ZYGOTE_NAME) {
        bail!("process {pid} is not zygote64 (cmdline = {cmdline:?})");
    }

    let monitor_config = monitor::Config {
        target_paths: vec![],
        target_names: vec![ZYGOTE_NAME.into()],
    };

    let context = Arc::new(ZynxContext::new(&config).await?);
    Monitor::init(monitor_config)?;

    ZygoteTracer::create_attach(context.clone(), pid)?;

    let monitor = Monitor::instance();

    while let Some(event) = monitor.recv_msg().await {
        match &event {
            Message::ZygoteCrashed(_) => {
                info!("zygote process exited, shutting down");
                return Ok(());
            }
            _ => {
                if let Err(err) = handle_event(&context, &event) {
                    error!("error while handling event {event:?}: {err:?}");
                }
            }
        }
    }

    bail!("monitor exited unexpectedly");
}
