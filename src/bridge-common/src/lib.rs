use std::ffi::c_long;
use std::os::fd::RawFd;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct EmbryoTrampolineFnPtrs {
    pub dlopen: usize,
    pub dlsym: usize,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base: usize,
    pub size: usize,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SpecializeHookInfo {
    pub specialize_fn: usize,
    pub specialize_args: [c_long; 32],
    pub specialize_args_count: usize,
    pub return_sp: usize,
    pub return_fp: usize,
    pub return_lr: usize,
    pub callee_saves: [usize; 10],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct EmbryoTrampolineArgs {
    pub bridge_library_fd: RawFd,
    pub fn_ptrs: EmbryoTrampolineFnPtrs,
    pub trampoline_region: MemoryRegion,
    pub buffer_region: MemoryRegion,
    pub specialize_hook: SpecializeHookInfo,
}
