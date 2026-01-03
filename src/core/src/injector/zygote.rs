use crate::binary::cpp;
use crate::binary::symbol::{Section, Symbol, SymbolResolver};
use crate::monitor;
use anyhow::Result;
use log::{info, warn};
use once_cell::sync::Lazy;
use regex_lite::Regex;
use rustix::process;
use rustix::process::{Pid, Signal};

pub const ZYGOTE_NAME: &str = "zygote64";

////////////////////////////////////////////////////////////////////////////////////////////////////

const SC_LIBRARY_PATH: &str = "/system/lib64/libandroid_runtime.so";

struct SpecializeCommonConfig {
    lib: &'static str,
    sym: Symbol,
    sec: Section,
    args_cnt: usize,
}

impl SpecializeCommonConfig {
    fn resolve() -> Result<Self> {
        let resolver = SymbolResolver::from_file(SC_LIBRARY_PATH)?;
        let sym =
            resolver.find_first(&Regex::new("_ZN12_GLOBAL__N_116SpecializeCommonE.*").unwrap())?;
        let sec = resolver.find_section(sym.section_index)?;
        let args_count = cpp::count_args_for_symbol(&sym.name)?;

        Ok(Self {
            lib: SC_LIBRARY_PATH,
            sym,
            sec,
            args_cnt: args_count,
        })
    }
}

static SC_CONFIG: Lazy<SpecializeCommonConfig> =
    Lazy::new(|| SpecializeCommonConfig::resolve().expect("failed to resolve SpecializeCommon"));

////////////////////////////////////////////////////////////////////////////////////////////////////

pub fn handle_zygote(pid: Pid) -> Result<()> {
    info!("found zygote process: {pid}");

    monitor::instance().attach_zygote(pid.as_raw_pid())?;
    process::kill_process(pid, Signal::CONT)?;

    Ok(())
}

pub fn handle_embryo(pid: Pid) -> Result<()> {
    info!("found embryo process: {pid}");

    let addr =
        SC_CONFIG.sym.addr - SC_CONFIG.sec.addr + SC_CONFIG.sec.file_offset.expect("no offset");
    let target = SC_CONFIG.lib;

    if let Err(err) = monitor::instance().attach_embryo(pid.as_raw_pid(), addr, target) {
        warn!("failed to attach embryo: {err:?}")
    }

    process::kill_process(pid, Signal::CONT)?;

    Ok(())
}
