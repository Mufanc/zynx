use crate::injector::app::embryo::EmbryoInjector;
use crate::injector::app::{ResumeGuard, SC_CONFIG, SC_SHELLCODE};
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
use std::ffi::c_int;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
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

#[derive(Clone)]
pub struct SwbpConfig(MemoryMap, String);

impl SwbpConfig {
    pub fn new(mmap: MemoryMap) -> Self {
        if let MMapPath::Path(path) = &mmap.pathname {
            let path = path.to_string_lossy().into();
            Self(mmap, path)
        } else {
            unreachable!("wtf??")
        }
    }

    pub fn addr(&self) -> usize {
        self.0.address.0 as _
    }

    pub fn length(&self) -> usize {
        (self.0.address.1 - self.0.address.0) as _
    }

    pub fn map_path(&self) -> &str {
        &self.1
    }

    pub fn map_prot(&self) -> c_int {
        (self.0.perms.bits() as c_int) & 0x7
    }

    pub fn map_flags(&self) -> c_int {
        (self.0.perms.bits() as c_int) >> 3
    }

    pub fn map_offset(&self) -> usize {
        self.0.offset as _
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

        let mut tracer = ZYGOTE_TRACER.write().expect("lock poisoned");
        tracer.replace(Self {
            specialize_common: (sc, SwbpConfig::new(sc_vma.clone())),
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

        let mut file = OpenOptions::new()
            .write(true)
            .open(format!("/proc/{pid}/mem"))?;

        let lock = ZYGOTE_TRACER.read().expect("lock poisoned");
        let tracer = lock.as_ref().context("zygote tracer not initialized")?;

        let (address, _) = tracer.specialize_common;

        drop(lock);

        file.seek(SeekFrom::Start(address as _))?;
        file.write_all(&SC_SHELLCODE)?;
        file.flush()?;

        drop(file);

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
