use android_logger::Config;
use anyhow::Result;
use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use log::{info, warn, LevelFilter};
use rustix::process;
use rustix::process::{Resource, Rlimit};
use std::env;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::{signal, task};

fn init_logger() {
    if env::var("KSU").is_ok() {
        android_logger::init_once(
            Config::default()
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

    process::setrlimit(
        Resource::Memlock,
        Rlimit {
            current: None,
            maximum: None,
        },
    )?;

    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/zynx-ebpf"
    )))?;

    match EbpfLogger::init(&mut ebpf) {
        Ok(logger) => {
            let mut logger = AsyncFd::with_interest(logger, Interest::READABLE)?;

            task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
        Err(err) => {
            warn!("failed to initialize eBPF logger: {err:?}");
        }
    }

    for (name, program) in ebpf.programs_mut() {
        let parts: Vec<_> = name.split("__").collect();

        #[allow(clippy::single_match)]
        match parts[0] {
            "tracepoint" => {
                let program: &mut TracePoint = program.try_into()?;
                let (category, name) = (parts[1], parts[2]);

                program.load()?;
                program.attach(category, name)?;

                info!("attach tracepoint: {category}/{name}");
            }
            _ => ()
        }
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl+C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
