use anyhow::Result;
use once_cell::sync::Lazy;
use once_map::OnceMap;
use r3solvr::{CachedResolver, Symbol, SymbolResolver};

static SYSTEM_LIBRARY_RESOLVER: Lazy<SystemLibraryResolver> = Lazy::new(SystemLibraryResolver::new);

pub struct SystemLibraryResolver<'a> {
    resolvers: OnceMap<String, CachedResolver<'a>>,
}

impl SystemLibraryResolver<'_> {
    fn new() -> Self {
        Self {
            resolvers: OnceMap::new(),
        }
    }

    pub fn resolve(&self, library_name: &str, symbol_name: &str) -> Result<Symbol> {
        Ok(self.resolvers.map_try_insert(
            library_name.into(),
            |name| CachedResolver::from_file(format!("/system/lib64/{name}.so")),
            |_, v| v.lookup_symbol(symbol_name),
        )??)
    }

    pub fn instance() -> &'static Self {
        &SYSTEM_LIBRARY_RESOLVER
    }
}
