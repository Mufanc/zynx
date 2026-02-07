use crate::binary::cpp::ArgCounter;
use crate::binary::symbol::{Section, Symbol, SymbolResolver};
use anyhow::{Context, Result};
use log::info;
use once_cell::sync::Lazy;
use strum::IntoEnumIterator;
use zynx_bridge_types::zygote::SpecializeVersion;

mod embryo;
pub mod policy;
pub mod zygote;

pub const SC_LIBRARY_PATH: &str = "/system/lib64/libandroid_runtime.so";

#[allow(unused)]
#[derive(Debug)]
pub struct SpecializeCommonConfig {
    pub lib: &'static str,
    pub ver: SpecializeVersion,
    pub sym: Symbol,
    pub sec: Section,
    pub args_cnt: usize,
}

impl SpecializeCommonConfig {
    fn resolve() -> Result<Self> {
        let resolver = SymbolResolver::from_file(SC_LIBRARY_PATH)?;

        let (sym, ver) = SpecializeVersion::iter()
            .find_map(|ver| resolver.find_symbol(ver.as_ref()).map(|sym| (sym, ver)))
            .context("no known SpecializeCommon symbol found in libandroid_runtime.so")?;

        let sec = resolver.find_section(sym.section_index)?;
        let args_count = ArgCounter::count_args_for_symbol(&sym.name)?;

        Ok(Self {
            lib: SC_LIBRARY_PATH,
            ver,
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
