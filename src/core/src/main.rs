#[cfg(all(feature = "standalone", feature = "zygisk"))]
compile_error!("features `standalone` and `zygisk` are mutually exclusive");

mod android;
mod binary;
mod cli;
mod config;
#[cfg(not(feature = "standalone"))]
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

    #[cfg(not(feature = "standalone"))]
    {
        if let Some(Command::Daemon { wait_bpfloader }) = cli.command {
            // The child re-enters main without a subcommand.
            return daemon::launch_daemon(wait_bpfloader);
        }

        daemon::daemonize_if_needed()?;
        daemon::wait_for_bpfloader_if_needed()?;
    }

    let config = ZynxConfigs::new(&cli.configs);

    Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            inject_panic_handler();

            #[cfg(feature = "standalone")]
            if let Some(Command::AttachZygote { pid }) = cli.command {
                return injector::attach_zygote(pid, config).await;
            }

            injector::run(config).await
        })?;

    Ok(())
}
