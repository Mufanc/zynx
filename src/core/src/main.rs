mod android;
mod binary;
mod cli;
mod daemon;
mod injector;
mod misc;
mod monitor;

use crate::cli::Cli;
use crate::misc::inject_panic_handler;
use anyhow::Result;
use log::LevelFilter;
use std::env;
use tokio::runtime::Builder;

fn init_logger() {
    if env::var("KSU").is_ok() {
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

fn main() -> Result<()> {
    init_logger();

    let args = Cli::parse_args();

    if args.daemon {
        daemon::launch_daemon()?;
        return Ok(());
    }

    daemon::daemonize_if_needed()?;

    Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())?;

    Ok(())
}

async fn async_main() -> Result<()> {
    inject_panic_handler();
    injector::serve().await?;
    Ok(())
}
