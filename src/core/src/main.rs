mod android;
mod binary;
mod cli;
mod config;
mod daemon;
mod injector;
mod misc;
mod monitor;

use crate::cli::{Cli, Command};
use crate::config::ZynxConfigs;
use crate::misc::inject_panic_handler;
use log::LevelFilter;
use std::env;
use tokio::runtime::Builder;

fn init_logger() {
    if env::var("MODDIR").is_ok() {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(if cfg!(debug_assertions) {
                    LevelFilter::Trace
                } else {
                    LevelFilter::Info
                })
                .with_tag("zynx::core"),
        );
    } else {
        env_logger::init();
    }
}

fn main() -> anyhow::Result<()> {
    init_logger();

    let cli = Cli::parse_args();

    let attach_pid = match cli.command {
        Some(Command::Daemon) => return daemon::launch_daemon(),
        Some(Command::AttachZygote { pid }) => Some(pid),
        None => None,
    };

    let config = ZynxConfigs::new(&cli.configs)?;
    if attach_pid.is_none() {
        daemon::daemonize_if_needed()?;
    }

    Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            inject_panic_handler();
            if let Some(pid) = attach_pid {
                injector::attach_zygote(pid, config).await
            } else {
                injector::run(config).await
            }
        })?;

    Ok(())
}
