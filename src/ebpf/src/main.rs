#![no_std]
#![no_main]

use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::{EbpfContext, helpers};
use aya_log_ebpf::info;

////////////////////////////////////////////////////////////////////////////////////////////////////

trait TracePointEvent {
    const EVENT_OFFSET: usize = 8;
    fn from_context(ctx: &TracePointContext) -> &Self;
}

impl<T> TracePointEvent for T {
    fn from_context(ctx: &TracePointContext) -> &Self {
        unsafe { &*(ctx.as_ptr().add(Self::EVENT_OFFSET) as *const _) }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

#[inline(always)]
fn current_pid() -> i32 {
    (helpers::bpf_get_current_pid_tgid() & 0xffffffff) as i32
}

////////////////////////////////////////////////////////////////////////////////////////////////////

#[repr(C)]
struct TaskNewTaskEvent {
    pid: i32,
    _comm: [u8; 16],
    clone_flags: u64,
    _oom_score_adj: i16,
}

#[tracepoint]
pub fn tracepoint_task_task_newtask(ctx: TracePointContext) -> u32 {
    let event = TaskNewTaskEvent::from_context(&ctx);

    let parent_pid = current_pid();
    let child_pid = event.pid;

    info!(&ctx, "process fork: {} -> {}", parent_pid, child_pid);

    0
}

////////////////////////////////////////////////////////////////////////////////////////////////////

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
