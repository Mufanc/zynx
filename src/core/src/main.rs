mod monitor;

use crate::monitor::Monitor;
use anyhow::Result;
use log::LevelFilter;
use std::env;
use tokio::{signal, task};

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

    let config = monitor::Config {
        target_paths: vec![],
        target_names: vec!["zygote64".into()],
    };
    let mut monitor = Monitor::new(config).await?;

    let task = task::spawn(async move { 
        while let Some(event) = monitor.next().await {
            println!("{:?}", event)
        } 
    });

    tokio::select! {
        _ = signal::ctrl_c() => (),
        _ = task => ()
    }

    Ok(())
}
