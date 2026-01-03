use anyhow::Result;
use log::info;
use rustix::process::{Pid, Signal, kill_process};

pub const ZYGOTE_NAME: &str = "zygote64";

pub fn handle_zygote(pid: Pid) -> Result<()> {
    info!("found zygote process: {pid}");

    kill_process(pid, Signal::CONT)?;

    Ok(())
}
