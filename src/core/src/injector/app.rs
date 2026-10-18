use anyhow::{Context, Result};
use r3solvr::{BasicResolver, Query, Section, Symbol, SymbolResolver};
use strum::IntoEnumIterator;
use zynx_bridge_shared::zygote::SpecializeVersion;

mod embryo;
pub mod ipc;
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
    pub args_count: usize,
}

impl SpecializeCommonConfig {
    pub fn resolve() -> Result<Self> {
        let resolver = BasicResolver::from_file(SC_LIBRARY_PATH)?;

        let (sym, ver) = SpecializeVersion::iter()
            .find_map(|ver| {
                let name = ver.as_ref();

                resolver
                    .lookup_symbol(Query::new(name).with_prefix(true).with_debugdata(true))
                    .ok()
                    .filter(|sym| matches_symbol_name(&sym.name, name))
                    .map(|sym| (sym, ver))
            })
            .context("no known SpecializeCommon symbol found in libandroid_runtime.so")?;

        let sec = resolver.lookup_section(sym.section_index)?;

        Ok(Self {
            lib: SC_LIBRARY_PATH,
            ver,
            sym,
            sec,
            args_count: ver.args_count(),
        })
    }
}

fn matches_symbol_name(symbol: &str, expected: &str) -> bool {
    let Some((base, hash)) = symbol.rsplit_once(".__uniq.") else {
        return symbol == expected;
    };

    base == expected && !hash.is_empty() && hash.bytes().all(|byte| byte.is_ascii_digit())
}

pub static SC_BRK: [u8; 4] = [0x00, 0x00, 0x20, 0xd4]; // brk #0

#[cfg(test)]
mod tests {
    use super::matches_symbol_name;

    #[test]
    fn unique_symbol_suffix_is_strict() {
        let base = "_ZN12_GLOBAL__N_116SpecializeCommon";

        assert!(matches_symbol_name(base, base));
        assert!(matches_symbol_name(
            "_ZN12_GLOBAL__N_116SpecializeCommon.__uniq.138421450522488007553410587292931815916",
            base
        ));
        assert!(!matches_symbol_name(
            "_ZN12_GLOBAL__N_116SpecializeCommon.__uniq.",
            base
        ));
        assert!(!matches_symbol_name(
            "_ZN12_GLOBAL__N_116SpecializeCommon.__uniq.clone",
            base
        ));
    }
}
