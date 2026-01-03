use crate::monitor;
use anyhow::Result;
use log::info;
use rustix::process::{Pid, Signal, kill_process};

pub const ZYGOTE_NAME: &str = "zygote64";

pub fn handle_zygote(pid: Pid) -> Result<()> {
    info!("found zygote process: {pid}");

    monitor::instance().attach_zygote(pid.as_raw_pid())?;
    kill_process(pid, Signal::CONT)?;

    Ok(())
}

pub fn handle_embryo(pid: Pid) -> Result<()> {
    info!("found embryo process: {pid}");

    // Todo: uprobes or brk insn
    kill_process(pid, Signal::CONT)?;

    Ok(())
}
