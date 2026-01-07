use anyhow::Result;
use cpp_demangle::{DemangleOptions, DemangleWrite, Symbol};
use log::debug;
use std::fmt;

#[derive(Default)]
pub struct ArgCounter(usize);

impl ArgCounter {
    fn new() -> Self {
        Self::default()
    }

    fn count(&self) -> usize {
        self.0 + 1
    }

    pub fn count_args_for_symbol(symbol_name: &str) -> Result<usize> {
        let sym = Symbol::new(symbol_name)?;
        let options = DemangleOptions::default();

        debug!("demangle symbol: {} -> {}", symbol_name, sym.demangle()?);

        let mut counter = Self::new();
        sym.structured_demangle(&mut counter, &options)?;

        Ok(counter.count())
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
