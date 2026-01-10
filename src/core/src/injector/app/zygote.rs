use crate::injector::app::embryo::EmbryoInjector;
use crate::injector::app::{PAGE_SIZE, ResumeGuard, SC_CONFIG, SC_SHELLCODE};
use crate::injector::ptrace::RemoteProcess;
use crate::misc::ext::ResultExt;
use crate::monitor::Monitor;
use anyhow::{Context, Result, bail};
use log::info;
use nix::fcntl;
use nix::unistd::Pid;
use once_cell::sync::Lazy;
use procfs::process::{MMPermissions, MMapPath, MemoryMap, MemoryMaps, Process};
use rustix::path::Arg;
use std::borrow::Cow;
use std::sync::{Arc, RwLock};
use tokio::task;

pub const ZYGOTE_NAME: &str = "zygote64";

static ZYGOTE_TRACER: Lazy<Arc<RwLock<Option<ZygoteTracer>>>> = Lazy::new(Default::default);

#[derive(Clone)]
pub struct ZygoteMaps(Arc<MemoryMaps>);

impl ZygoteMaps {
    pub fn parse(pid: Pid) -> Result<Self> {
        Ok(Self(Arc::new(Process::new(pid.as_raw())?.maps()?)))
    }

    pub fn find_vma(&self, addr: usize) -> Option<&MemoryMap> {
        let addr = addr as u64;
        self.0
            .iter()
            .find(|vma| vma.address.0 <= addr && vma.address.1 > addr)
    }

    pub fn find_library_base(&self, path: &str) -> Option<usize> {
        let realpath = fcntl::readlink(path);
        let realpath = realpath
            .as_ref()
            .map(|it| it.to_string_lossy())
            .unwrap_or(Cow::Borrowed(path));

        self.0.iter().find_map(|vma| {
            if let MMapPath::Path(path) = &vma.pathname
                && path.to_string_lossy() == realpath
            {
                Some(vma.address.0 as _)
            } else {
                None
            }
        })
    }

    pub fn find_library_base_by_name(&self, name: &str) -> Option<usize> {
        let suffix = format!("/{name}.so");

        self.0.iter().find_map(|vma| {
            if let MMapPath::Path(path) = &vma.pathname
                && path.to_string_lossy().ends_with(&suffix)
            {
                Some(vma.address.0 as _)
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct SwbpConfig {
    addr: usize,
    backup: Vec<u8>,
}

impl SwbpConfig {
    pub fn new(addr: usize, backup: Vec<u8>) -> Self {
        Self { addr, backup }
    }

    pub fn addr(&self) -> usize {
        self.addr
    }

    pub fn page_addr(&self) -> usize {
        self.addr & !(*PAGE_SIZE - 1)
    }

    pub fn backup(&self) -> &[u8] {
        &self.backup
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ZygoteTracer {
    maps: ZygoteMaps,
    specialize_common: (usize, SwbpConfig),
}

impl ZygoteTracer {
    pub fn create(pid: Pid) -> Result<()> {
        info!("found zygote process: {pid}");

        let _dontdrop = ResumeGuard::new(pid);
        Monitor::instance().attach_zygote(pid.as_raw())?;

        let maps = ZygoteMaps::parse(pid)?;
        let library_base = maps
            .find_library_base(SC_CONFIG.lib)
            .context("SpecializeCommon: failed to find libandroid_runtime.so base address")?;

        let sc = library_base + SC_CONFIG.sym.addr;
        let Some(sc_vma) = maps.find_vma(sc) else {
            bail!("SpecializeCommon: memory region not found")
        };

        if (sc_vma.perms & MMPermissions::EXECUTE) == MMPermissions::empty() {
            bail!("SpecializeCommon: memory region is not executable")
        }

        if !matches!(sc_vma.pathname, MMapPath::Path(_)) {
            bail!("SpecializeCommon: memory region is not mapped from file")
        }

        info!("SpecializeCommon vma: {sc_vma:?}");

        let swbp = {
            let remote = RemoteProcess::new(pid);
            let mut backup = vec![0u8; SC_SHELLCODE.len()];

            remote.peek_data(sc, &mut backup)?;
            SwbpConfig::new(sc, backup)
        };

        info!("SpecializeCommon swbp: {swbp:?}");

        let mut tracer = ZYGOTE_TRACER.write().expect("lock poisoned");
        tracer.replace(Self {
            specialize_common: (sc, swbp),
            maps,
        });

        Ok(())
    }

    pub fn reset() -> Result<()> {
        ZYGOTE_TRACER.write().expect("lock poisoned").take();
        Ok(())
    }

    pub fn on_fork(pid: Pid) -> Result<()> {
        let _dontdrop = ResumeGuard::new(pid);

        let lock = ZYGOTE_TRACER.read().expect("lock poisoned");
        let tracer = lock.as_ref().context("zygote tracer not initialized")?;

        let (addr, _) = tracer.specialize_common;

        drop(lock);

        RemoteProcess::new(pid).poke_data_ignore_perm(addr, &SC_SHELLCODE)?;

        Ok(())
    }

    pub fn on_specialize(pid: Pid) -> Result<()> {
        let lock = ZYGOTE_TRACER.read().expect("lock poisoned");
        let tracer = lock.as_ref().context("zygote tracer not initialized")?;

        let maps = tracer.maps.clone();
        let (_, swbp) = tracer.specialize_common.clone();

        drop(lock);

        task::spawn_blocking(move || {
            // Todo: timeout check
            EmbryoInjector::new(pid, maps, swbp)
                .on_specialize()
                .log_if_error();
        });

        Ok(())
    }
}
