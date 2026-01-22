use crate::android::properties;
use crate::binary::cpp::ArgCounter;
use crate::binary::symbol::{Section, Symbol, SymbolResolver};
use anyhow::Result;
use log::info;
use once_cell::sync::Lazy;
use regex_lite::Regex;

mod embryo;
pub mod zygote;

pub static API_LEVEL: Lazy<i32> = Lazy::new(|| {
    properties::get("ro.build.version.sdk")
        .parse()
        .expect("failed to parse api level")
});

pub const SC_LIBRARY_PATH: &str = "/system/lib64/libandroid_runtime.so";

#[allow(unused)]
#[derive(Debug)]
pub struct SpecializeCommonConfig {
    pub lib: &'static str,
    pub sym: Symbol,
    pub sec: Section,
    pub args_cnt: usize,
}

// Todo: resolve specific symbol
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

pub static SC_BRK: [u8; 4] = [0x00, 0x00, 0x20, 0xd4]; // brk #0
