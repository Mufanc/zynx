use crate::injector::app::embryo::EmbryoInjector;
use crate::injector::context::ZynxContext;
use crate::monitor::Monitor;
use anyhow::{Context, Result, bail};
use log::{debug, info};
use nix::fcntl;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use procfs::process::{MMPermissions, MMapPath, MemoryMap, MemoryMaps, Process};
use scopeguard::defer;
use std::sync::Arc;
use std::time::Instant;
use tokio::task;
use zynx_misc::ext::ResultExt;

pub const ZYGOTE_NAME: &str = "zygote64";

static ZYGOTE_TRACER: Lazy<RwLock<Option<ZygoteTracer>>> = Lazy::new(Default::default);

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
            .unwrap_or(path.into());

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

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ZygoteTracer {
    context: Arc<ZynxContext>,
    maps: ZygoteMaps,
    specialize_fn: usize,
}

impl ZygoteTracer {
    pub fn create(context: Arc<ZynxContext>, pid: Pid) -> Result<()> {
        info!("found zygote process: {pid}");

        defer! {
            signal::kill(pid, Signal::SIGCONT).log_if_error()
        }

        Monitor::instance().attach_zygote(pid.as_raw())?;

        let maps = ZygoteMaps::parse(pid)?;
        let library_base = maps
            .find_library_base(context.specialize_abi.lib)
            .context("SpecializeCommon: failed to find libandroid_runtime.so base address")?;

        let sc_addr = library_base + context.specialize_abi.sym.addr;
        let Some(sc_vma) = maps.find_vma(sc_addr) else {
            bail!("SpecializeCommon: memory region not found")
        };

        if (sc_vma.perms & MMPermissions::EXECUTE) == MMPermissions::empty() {
            bail!("SpecializeCommon: memory region is not executable")
        }

        if !matches!(sc_vma.pathname, MMapPath::Path(_)) {
            bail!("SpecializeCommon: memory region is not mapped from file")
        }

        info!("SpecializeCommon vma: {sc_vma:?}, addr: {sc_addr}");

        let mut tracer = ZYGOTE_TRACER.write();
        tracer.replace(Self {
            context,
            specialize_fn: sc_addr,
            maps,
        });

        Ok(())
    }

    pub fn create_attach(context: Arc<ZynxContext>, pid: Pid) -> Result<()> {
        info!("attaching to running zygote process: {pid}");

        // stop zygote to prevent state changes during maps parsing
        signal::kill(pid, Signal::SIGSTOP)?;

        defer! {
            signal::kill(pid, Signal::SIGCONT).log_if_error()
        }

        Monitor::instance().attach_zygote(pid.as_raw())?;

        let maps = ZygoteMaps::parse(pid)?;
        let library_base = maps
            .find_library_base(context.specialize_abi.lib)
            .context("SpecializeCommon: failed to find libandroid_runtime.so base address")?;

        let sc_addr = library_base + context.specialize_abi.sym.addr;
        let Some(sc_vma) = maps.find_vma(sc_addr) else {
            bail!("SpecializeCommon: memory region not found")
        };

        if (sc_vma.perms & MMPermissions::EXECUTE) == MMPermissions::empty() {
            bail!("SpecializeCommon: memory region is not executable")
        }

        if !matches!(sc_vma.pathname, MMapPath::Path(_)) {
            bail!("SpecializeCommon: memory region is not mapped from file")
        }

        info!("SpecializeCommon vma: {sc_vma:?}, addr: {sc_addr}");

        let mut tracer = ZYGOTE_TRACER.write();
        tracer.replace(Self {
            context,
            specialize_fn: sc_addr,
            maps,
        });

        Ok(())
    }

    pub fn reset() -> Result<()> {
        ZYGOTE_TRACER.write().take();
        Ok(())
    }

    pub fn on_fork(pid: Pid) -> Result<()> {
        let lock = ZYGOTE_TRACER.read();
        let tracer = lock.as_ref().context("zygote tracer not initialized")?;

        let specialize_fn = tracer.specialize_fn;
        let maps = tracer.maps.clone();
        let context = tracer.context.clone();

        drop(lock);

        task::spawn_blocking(move || {
            let start = Instant::now();
            EmbryoInjector::new(context, pid, maps, specialize_fn)
                .start()
                .log_if_error();
            let elapsed = start.elapsed();
            debug!("embryo {pid} check/injection completed in {elapsed:.2?}");
        });

        Ok(())
    }
}
