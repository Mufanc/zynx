use crate::binary::symbol::{CachedSymbolResolver, Symbol};
use anyhow::Result;
use once_cell::sync::Lazy;
use once_map::OnceMap;

static SYSTEM_LIBRARY_RESOLVER: Lazy<SystemLibraryResolver> = Lazy::new(SystemLibraryResolver::new);

pub struct SystemLibraryResolver<'a> {
    resolvers: OnceMap<String, CachedSymbolResolver<'a>>,
}

impl SystemLibraryResolver<'_> {
    fn new() -> Self {
        Self {
            resolvers: OnceMap::new(),
        }
    }

    pub fn resolve(&self, name: &str, pattern: &str) -> Result<Symbol> {
        self.resolvers.map_try_insert(
            name.into(),
            |name| CachedSymbolResolver::from_file(format!("/system/lib64/{name}.so")),
            |_, v| v.resolve(pattern),
        )?
    }

    pub fn instance() -> &'static Self {
        &SYSTEM_LIBRARY_RESOLVER
    }
}
