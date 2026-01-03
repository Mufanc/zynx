use crate::misc::ext::ResultExt;
use anyhow::{Context, Result};
use object::{Object, ObjectSection, ObjectSymbol, SectionIndex};
use once_map::OnceMap;
use regex_lite::Regex;
use std::fmt::Debug;
use std::fs;
use std::marker::PhantomPinned;
use std::mem::MaybeUninit;
use std::path::Path;
use std::pin::Pin;

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub addr: usize,
    pub section_index: usize,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub addr: usize,
    pub file_offset: Option<usize>,
}

pub struct SymbolResolver<'a> {
    data: Vec<u8>,
    file: MaybeUninit<object::File<'a>>,
    _pin: PhantomPinned,
}

impl SymbolResolver<'_> {
    pub fn from_file<P: AsRef<Path>>(file: P) -> Result<Pin<Box<Self>>> {
        Self::from_data(fs::read(file)?)
    }

    pub fn from_data(data: Vec<u8>) -> Result<Pin<Box<Self>>> {
        let mut boxed = Box::pin(Self {
            data,
            file: MaybeUninit::uninit(),
            _pin: PhantomPinned,
        });

        unsafe {
            let ptr = boxed.as_mut().get_unchecked_mut() as *mut SymbolResolver;
            let refr = &mut *ptr;

            refr.file.write(object::File::parse(refr.data.as_slice())?);
        }

        Ok(boxed)
    }

    fn file(&'_ self) -> &'_ object::File<'_> {
        unsafe { self.file.assume_init_ref() }
    }

    pub fn find_symbol(&self, pattern: &Regex) -> Vec<Symbol> {
        let file = self.file();

        let mut symbols: Vec<_> = file
            .dynamic_symbols()
            .chain(file.symbols())
            .filter_map(|sym| {
                sym.name()
                    .ok()
                    .filter(|name| pattern.is_match(name))
                    .and_then(|name| {
                        sym.section_index().map(|index| Symbol {
                            name: name.into(),
                            addr: sym.address() as _,
                            section_index: index.0,
                        })
                    })
            })
            .collect();

        let debug_symbols: Option<Vec<_>> = file
            .section_by_name(".gnu_debugdata")
            .and_then(|sec| sec.data().ok_or_warn())
            .and_then(|mut data| {
                let mut decompressed = Vec::new();
                lzma_rs::xz_decompress(&mut data, &mut decompressed)
                    .ok_or_warn()
                    .map(|_| decompressed)
            })
            .and_then(|data| SymbolResolver::from_data(data).ok_or_warn())
            .map(|resolver| {
                resolver
                    .find_symbol(pattern)
                    .into_iter()
                    .filter_map(|sym| {
                        let Symbol {
                            name,
                            addr,
                            section_index,
                        } = sym;

                        file.section_by_index(SectionIndex(section_index))
                            .and_then(|sec| sec.name())
                            .ok()
                            .and_then(|name| file.section_by_name(name))
                            .map(|sec| Symbol {
                                name,
                                addr,
                                section_index: sec.index().0,
                            })
                    })
                    .collect()
            });

        if let Some(debug_symbols) = debug_symbols {
            symbols.extend(debug_symbols);
        }

        symbols
    }

    pub fn find_first(&self, pattern: &Regex) -> Result<Symbol> {
        self.find_symbol(pattern)
            .into_iter()
            .next()
            .context(format!("cannot resolve symbol by pattern: {pattern}"))
    }

    pub fn find_section(&self, index: usize) -> Result<Section> {
        let section = self
            .file()
            .section_by_index(SectionIndex(index))
            .context(format!("cannot find section with index: {index}"))?;

        Ok(Section {
            name: section.name()?.into(),
            addr: section.address() as _,
            file_offset: section.file_range().map(|(base, _)| base as _),
        })
    }
}

impl Drop for SymbolResolver<'_> {
    fn drop(&mut self) {
        unsafe {
            self.file.assume_init_drop();
        }
    }
}

pub struct CachedFirstResolver<'a> {
    resolver: Pin<Box<SymbolResolver<'a>>>,
    caches: OnceMap<String, Symbol>,
}

impl CachedFirstResolver<'_> {
    pub fn new<P: AsRef<Path>>(file: P) -> Result<Self> {
        let resolver = SymbolResolver::from_file(file)?;

        Ok(Self {
            resolver,
            caches: OnceMap::new(),
        })
    }

    pub fn resolve(&mut self, pattern: &str) -> Result<Symbol> {
        self.caches.map_try_insert(
            pattern.into(),
            |pattern| {
                let pattern_regex = Regex::new(pattern)?;
                let symbol = self
                    .resolver
                    .find_symbol(&pattern_regex)
                    .into_iter()
                    .next()
                    .context(format!("cannot resolve symbol by pattern: {pattern}"))?;

                Ok(symbol)
            },
            |_, v| v.clone(),
        )
    }
}
