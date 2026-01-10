use crate::android::properties;
use crate::binary::cpp::ArgCounter;
use crate::binary::symbol::{Section, Symbol, SymbolResolver};
use anyhow::Result;
use dynasmrt::dynasm;
use log::info;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use once_cell::sync::Lazy;
use regex_lite::Regex;
use scopeguard::ScopeGuard;
use zynx_common::ext::ResultExt;

mod embryo;
pub mod zygote;

pub static API_LEVEL: Lazy<i32> = Lazy::new(|| {
    properties::get("ro.build.version.sdk")
        .parse()
        .expect("failed to parse api level")
});

pub const SC_LIBRARY_PATH: &str = "/system/lib64/libandroid_runtime.so";

#[derive(Debug)]
pub struct SpecializeCommonConfig {
    pub lib: &'static str,
    pub sym: Symbol,
    pub sec: Section,
    pub args_cnt: usize,
}

impl SpecializeCommonConfig {
    fn resolve() -> Result<Self> {
        let resolver = SymbolResolver::from_file(SC_LIBRARY_PATH)?;
        let sym =
            resolver.find_first(&Regex::new("_ZN12_GLOBAL__N_116SpecializeCommonE.*").unwrap())?;
        let sec = resolver.find_section(sym.section_index)?;
        let args_count = ArgCounter::count_args_for_symbol(&sym.name)?;

        Ok(Self {
            lib: SC_LIBRARY_PATH,
            sym,
            sec,
            args_cnt: args_count,
        })
    }
}

pub static SC_CONFIG: Lazy<SpecializeCommonConfig> = Lazy::new(|| {
    let config = SpecializeCommonConfig::resolve().expect("failed to resolve SpecializeCommon");
    info!("SpecializeCommon config: {config:?}");
    config
});

pub static SC_SHELLCODE: Lazy<Vec<u8>> = Lazy::new(|| {
    let mut ops = dynasmrt::aarch64::Assembler::new().expect("failed to create assembler");

    dynasm!(ops
        ; .arch aarch64
        ; brk 0x0
    );

    let vec = ops
        .finalize()
        .expect("failed to finalize shellcode")
        .to_vec();

    assert_eq!(vec.len(), 4);

    vec
});

pub struct ResumeGuard {
    _dontdrop: ScopeGuard<Pid, fn(Pid)>,
}

impl ResumeGuard {
    pub fn new(pid: Pid) -> Self {
        Self {
            _dontdrop: ScopeGuard::with_strategy(pid, |pid| {
                signal::kill(pid, Signal::SIGCONT).ok_or_warn();
            }),
        }
    }
}
