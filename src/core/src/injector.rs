use crate::monitor;
use crate::monitor::{Message, Monitor};
use anyhow::{Result, bail};
use app::zygote::ZYGOTE_NAME;
use app::zygote::ZygoteTracer;
use log::{error, info};
use procfs::process::Process;

mod app;
mod ptrace;
mod policy;

fn handle_event(event: &Message) -> Result<()> {
    match event {
        Message::PathMatches(pid, path) => {
            // Todo:
            Ok(())
        }
        Message::NameMatches(pid, name) => {
            if name == ZYGOTE_NAME {
                ptrace::spin_wait(*pid)?;

                let args = Process::new(pid.as_raw())?.cmdline()?;

                if args.contains(&"--start-system-server".into()) {
                    return ZygoteTracer::create(*pid);
                }

                info!("found `{ZYGOTE_NAME}` without system server argument: {pid} -> {args:?}")
            }

            // Todo:
            Ok(())
        }
        Message::ZygoteFork(pid) => ZygoteTracer::on_fork(*pid),
        Message::ZygoteCrashed(_pid) => ZygoteTracer::reset(),
        Message::EmbryoSpecialize(pid) => ZygoteTracer::on_specialize(*pid),
    }
}

pub async fn serve() -> Result<()> {
    let config = monitor::Config {
        target_paths: vec![],
        target_names: vec![ZYGOTE_NAME.into()],
    };

    monitor::init_once(config).await?;

    let monitor = Monitor::instance();

    while let Some(event) = monitor.recv_msg().await {
        if let Err(err) = handle_event(&event) {
            error!("error while handling event {event:?}: {err:?}");
        }
    }

    bail!("monitor exited unexpectedly");
}
