use crate::monitor;
use crate::monitor::Message;
use anyhow::{Result, bail};
use log::{error, info};
use procfs::process::Process;
use zygote::ZYGOTE_NAME;

mod process;
mod zygote;

fn handle_event(event: &Message) -> Result<()> {
    match event {
        Message::PathMatches(pid, path) => {
            // Todo:
            Ok(())
        }
        Message::NameMatches(pid, name) => {
            if name == ZYGOTE_NAME {
                process::spin_wait(*pid)?;

                let args = Process::new(pid.as_raw_pid())?.cmdline()?;

                if args.contains(&"--start-system-server".into()) {
                    return zygote::handle_zygote(*pid);
                }

                info!("found `{ZYGOTE_NAME}` without system server argument: {pid} -> {args:?}")
            }

            // Todo:
            Ok(())
        }
        Message::ZygoteFork(pid) => zygote::handle_embryo(*pid),
    }
}

pub async fn serve() -> Result<()> {
    let config = monitor::Config {
        target_paths: vec![],
        target_names: vec![ZYGOTE_NAME.into()],
    };

    monitor::init_once(config).await?;

    let monitor = monitor::instance();

    while let Some(event) = monitor.recv_msg().await {
        if let Err(err) = handle_event(&event) {
            error!("error while handling event {event:?}: {err:?}");
        }
    }

    bail!("monitor exited unexpectedly");
}
