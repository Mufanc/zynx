mod injector;
mod misc;
mod monitor;

use crate::misc::inject_panic_handler;
use anyhow::Result;
use log::LevelFilter;
use std::env;

fn init_logger() {
    if env::var("KSU").is_ok() {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(if cfg!(debug_assertions) {
                    LevelFilter::Trace
                } else {
                    LevelFilter::Info
                })
                .with_tag("zynx"),
        );
    } else {
        env_logger::init();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    inject_panic_handler();

    injector::serve().await?;

    Ok(())
}
