use anyhow::Result;
use cpp_demangle::{DemangleOptions, DemangleWrite, Symbol};
use std::fmt;
use zynx_bridge_shared::zygote::SpecializeVersion;

#[derive(Default)]
struct ArgCounter(usize);

impl ArgCounter {
    fn count_args_for_symbol(symbol_name: &str) -> Result<usize> {
        let sym = Symbol::new(symbol_name)?;
        let options = DemangleOptions::default();
        let mut counter = Self::default();
        sym.structured_demangle(&mut counter, &options)?;

        Ok(counter.0 + 1)
    }
}

impl DemangleWrite for ArgCounter {
    fn write_string(&mut self, token: &str) -> fmt::Result {
        // e.g. (anonymous namespace)::SpecializeCommon(_JNIEnv*, unsigned int, unsigned int, _jintArray*, int, _jobjectArray*, long, long, int, _jstring*, _jstring*, bool, bool, _jstring*, _jstring*, bool, _jobjectArray*, _jobjectArray*, bool, bool)

        match token.trim() {
            "(" => self.0 = 0,
            "," => self.0 += 1,
            _ => (),
        }

        Ok(())
    }
}

#[test]
fn specialize_argument_counts_match_symbols() -> Result<()> {
    for version in [SpecializeVersion::R, SpecializeVersion::V] {
        assert_eq!(
            ArgCounter::count_args_for_symbol(version.as_ref())?,
            version.args_count()
        );
    }

    Ok(())
}
