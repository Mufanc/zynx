use anyhow::Result;
use nix::fcntl;
use nix::unistd::Pid;
use procfs::process::{MMapPath, Process};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct LibraryCache(Arc<RwLock<HashMap<String, usize>>>);

impl LibraryCache {
    pub fn parse(pid: Pid) -> Result<Self> {
        let mut caches = HashMap::new();

        Process::new(pid.as_raw())?
            .maps()?
            .into_iter()
            .for_each(|map| {
                if let MMapPath::Path(path) = map.pathname {
                    caches
                        .entry(path.to_string_lossy().into())
                        .or_insert(map.address.0 as usize);
                }
            });

        Ok(Self(Arc::new(RwLock::new(caches))))
    }

    pub fn resolve(&self, path: &str) -> Option<usize> {
        let realpath = fcntl::readlink(path);
        let realpath = realpath.as_ref().map(|it| it.to_string_lossy()).unwrap_or(Cow::Borrowed(path));

        let caches = self.0.read().expect("lock poisoned");

        caches.get(&*realpath).copied()
    }

    pub fn resolve_name(&self, name: &str) -> Option<usize> {
        let suffix = format!("/{name}");
        let caches = self.0.read().expect("lock poisoned");

        caches.iter().find_map(|(path, addr)| {
            if path.ends_with(&suffix) {
                Some(*addr)
            } else {
                None
            }
        })
    }
}
