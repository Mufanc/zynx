use crate::binary::cpp;
use crate::binary::symbol::{Section, Symbol, SymbolResolver};
use crate::monitor;
use anyhow::{Context, Result};
use dynasmrt::dynasm;
use log::{info, warn};
use once_cell::sync::Lazy;
use procfs::process::{MMapPath, Process};
use regex_lite::Regex;
use rustix::fs::{Mode, OFlags};
use rustix::path::Arg;
use rustix::process::{Pid, Signal};
use rustix::{fs, process};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};

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

static SC_SHELLCODE: Lazy<Vec<u8>> = Lazy::new(|| {
    let mut ops = dynasmrt::aarch64::Assembler::new().expect("failed to create assembler");

    dynasm!(ops
        ; .arch aarch64
        ; brk 0x0
    );

    ops.finalize()
        .expect("failed to finalize shellcode")
        .to_vec()
});

////////////////////////////////////////////////////////////////////////////////////////////////////

pub fn handle_zygote(pid: Pid) -> Result<()> {
    info!("found zygote process: {pid}");

    monitor::instance().attach_zygote(pid.as_raw_pid())?;
    process::kill_process(pid, Signal::CONT)?;

    Ok(())
}

struct ResumeGuard(Pid);

impl Drop for ResumeGuard {
    fn drop(&mut self) {
        let _ = process::kill_process(self.0, Signal::CONT);
    }
}

pub fn handle_embryo(pid: Pid) -> Result<()> {
    info!("found embryo process: {pid}");

    let guard = ResumeGuard(pid);

    // uprobe:
    // let addr =
    //     SC_CONFIG.sym.addr - SC_CONFIG.sec.addr + SC_CONFIG.sec.file_offset.expect("no offset");
    // let target = SC_CONFIG.lib;
    //
    // if let Err(err) = monitor::instance().attach_embryo(pid.as_raw_pid(), addr, target) {
    //     warn!("failed to attach embryo: {err:?}")
    // }

    // shellcode:
    let mut ops = dynasmrt::aarch64::Assembler::new()?;

    dynasm!(ops
        ; .arch aarch64
        ; brk 0x0
    );

    let base = Process::new(pid.as_raw_pid())?
        .maps()?
        .into_iter()
        .find_map(|map| {
            if let MMapPath::Path(path) = map.pathname
                && path.to_string_lossy() == SC_CONFIG.lib
            {
                Some(map.address.0)
            } else {
                None
            }
        })
        .context("failed to find libandroid_runtime.so base address")? as usize;
    let addr = base + SC_CONFIG.sym.addr;

    warn!("addr: {addr}");

    // let file = fs::open(format!("/proc/{}/mem", pid.as_raw_pid()), OFlags::WRONLY, Mode::empty())?;
    let mut file = OpenOptions::new()
        .write(true)
        .open(format!("/proc/{pid}/mem"))?;

    file.seek(SeekFrom::Start(addr as _))?;
    file.write_all(&SC_SHELLCODE)?;
    file.flush()?;

    drop(file);

    // process::kill_process(pid, Signal::CONT)?;

    Ok(())
}
