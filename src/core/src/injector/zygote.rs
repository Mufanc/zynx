use crate::binary::cpp;
use crate::binary::library::LibraryCache;
use crate::binary::symbol::{Section, Symbol, SymbolResolver};
use crate::injector::ptrace::Tracee;
use crate::injector::ptrace::ext::{PtraceExt, WaitStatusExt};
use crate::misc::ext::ResultExt;
use crate::monitor;
use anyhow::{Context, Result};
use dynasmrt::dynasm;
use log::{info, warn};
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use once_cell::sync::Lazy;
use regex_lite::Regex;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::sync::{Arc, RwLock};
use tokio::task;

pub const ZYGOTE_NAME: &str = "zygote64";

////////////////////////////////////////////////////////////////////////////////////////////////////

const SC_LIBRARY_PATH: &str = "/system/lib64/libandroid_runtime.so";

#[derive(Debug)]
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

static SC_CONFIG: Lazy<SpecializeCommonConfig> = Lazy::new(|| {
    let config = SpecializeCommonConfig::resolve().expect("failed to resolve SpecializeCommon");
    info!("SpecializeCommon config: {config:?}");
    config
});

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

struct ResumeGuard(Pid);

impl Drop for ResumeGuard {
    fn drop(&mut self) {
        let _ = signal::kill(self.0, Signal::SIGCONT).ok_or_warn();
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

static ZYGOTE_TRACER: Lazy<Arc<RwLock<Option<ZygoteTracer>>>> = Lazy::new(Default::default);

pub struct ZygoteTracer {
    specialize_common: usize,
    library_cache: LibraryCache,
}

impl ZygoteTracer {
    pub fn create(pid: Pid) -> Result<()> {
        info!("found zygote process: {pid}");

        let _dontdrop = ResumeGuard(pid);
        monitor::instance().attach_zygote(pid.as_raw())?;

        let library_cache = LibraryCache::parse(pid)?;
        let library_base = library_cache
            .resolve(SC_CONFIG.lib)
            .context("failed to find libandroid_runtime.so base address")?;

        let specialize_common = library_base + SC_CONFIG.sym.addr;

        let mut tracer = ZYGOTE_TRACER.write().expect("lock poisoned");
        tracer.replace(Self {
            specialize_common,
            library_cache,
        });

        Ok(())
    }

    pub fn reset() -> Result<()> {
        ZYGOTE_TRACER.write().expect("lock poisoned").take();
        Ok(())
    }

    pub fn on_fork(pid: Pid) -> Result<()> {
        let _dontdrop = ResumeGuard(pid);

        let mut ops = dynasmrt::aarch64::Assembler::new()?;

        dynasm!(ops
            ; .arch aarch64
            ; brk 0x0
        );

        let mut file = OpenOptions::new()
            .write(true)
            .open(format!("/proc/{pid}/mem"))?;

        let lock = ZYGOTE_TRACER.read().expect("lock poisoned");
        let tracer = lock.as_ref().context("zygote tracer not initialized")?;

        let specialize_common = tracer.specialize_common;

        drop(lock);

        file.seek(SeekFrom::Start(specialize_common as _))?;
        file.write_all(&SC_SHELLCODE)?;
        file.flush()?;

        drop(file);

        Ok(())
    }

    pub fn on_specialize(pid: Pid) -> Result<()> {
        let lock = ZYGOTE_TRACER.read().expect("lock poisoned");
        let tracer = lock.as_ref().context("zygote tracer not initialized")?;

        let library_cache = tracer.library_cache.clone();

        drop(lock);

        task::spawn_blocking(move || {
            handle_specialize(pid, library_cache).log_if_error();
        });

        Ok(())
    }
}

fn handle_specialize(pid: Pid, library_cache: LibraryCache) -> Result<()> {
    let _dontdrop = ResumeGuard(pid);

    let embryo = Tracee::new(pid);

    embryo.seize()?;
    embryo.kill(Signal::SIGCONT)?;

    loop {
        let status = embryo.wait()?;

        use WaitStatus::*;
        match status {
            Exited(_, code) => {
                warn!("embryo exited with code: {code}");
                break;
            }
            Signaled(_, sig, _) => {
                warn!("embryo killed by {sig}");
                break;
            }
            Stopped(_, Signal::SIGTRAP) => {
                let mut regs = embryo.get_regs()?;
                let mut args = vec![0; SC_CONFIG.args_cnt];

                embryo.get_args(&mut args)?;

                println!("{args:?}");

                let libc_base = library_cache
                    .resolve_name("libc.so")
                    .context("failed to resolve libc.so")?;

                // Todo:
            }
            _ => {}
        }

        embryo.cont(status.sig())?;
    }

    Ok(())
}
