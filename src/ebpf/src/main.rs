#![no_std]
#![no_main]
#![allow(static_mut_refs)]
#![allow(non_snake_case)]

use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::{EbpfContext, helpers};
use aya_ebpf::bindings::{BPF_EXIST, BPF_NOEXIST};
use aya_ebpf::maps::{HashMap, RingBuf};
use aya_log_ebpf::{debug, warn};

const DEBUG: bool = option_env!("DEBUG_EBPF").is_some();
const INIT_PID: i32 = 1;
const FIRST_APP_UID: u64 = 10000;

#[map]
static mut TARGET_PATHS: HashMap<[u8; 128], i32> = HashMap::with_max_entries(0x100, 0);

#[map]
static mut TARGET_NAMES: HashMap<[u8; 16], i32> = HashMap::with_max_entries(0x100, 0);

#[map]
static mut MESSAGE_CHANNEL: RingBuf = RingBuf::with_byte_size(0x1000, 0);

#[map]
static mut INIT_CHILDREN: HashMap<i32, u8> = HashMap::with_max_entries(0x1000, 0);

#[map]
static mut ZYGOTE_CHILDREN: HashMap<i32, u8> = HashMap::with_max_entries(0x1000, 0);

#[repr(u8)]
#[derive(Copy, Clone)]
enum ProcessState {
    PostFork,
    PostExec
}

impl From<ProcessState> for u8 {
    fn from(value: ProcessState) -> Self {
        value as u8
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

trait TracePointEvent {
    const OFFSET: usize = 8;
    fn from_context(ctx: &TracePointContext) -> &Self;
}

impl<T> TracePointEvent for T {
    fn from_context(ctx: &TracePointContext) -> &Self {
        unsafe { &*(ctx.as_ptr().add(Self::OFFSET) as *const _) }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

#[inline(always)]
fn current_is_privileged() -> bool {
    helpers::bpf_get_current_uid_gid() & 0xffffffff < FIRST_APP_UID
}

#[inline(always)]
fn current_pid() -> i32 {
    (helpers::bpf_get_current_pid_tgid() & 0xffffffff) as i32
}

#[inline(always)]
fn hashmap_create<K, V>(map: &mut HashMap<K, V>, key: &K, value: &V) -> bool {
    map.insert(key, value, BPF_NOEXIST as _).is_ok()
}

#[inline(always)]
fn hashmap_remove<K, V>(map: &mut HashMap<K, V>, key: &K) -> bool {
    map.remove(key).is_ok()
}

#[inline(always)]
fn hashmap_change<K, V>(map: &mut HashMap<K, V>, key: &K, value: &V) -> bool {
    map.insert(key, value, BPF_EXIST as _).is_ok()
}

#[inline(always)]
fn hashmap_get<'a, K, V>(map: &'a HashMap<K, V>, key: &K) -> Option<&'a V> {
    unsafe { map.get(key) }
}

#[inline(always)]
fn hashmap_contains<K, V>(map: &HashMap<K, V>, key: &K) -> bool {
    map.get_ptr(key).is_some()
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
pub fn tracepoint__task__task_newtask(ctx: TracePointContext) -> u32 {
    let event = TaskNewTaskEvent::from_context(&ctx);

    // skip for threads
    if event.clone_flags & 0x00010000 /* CLONE_THREAD */ != 0 {
        return 0;
    }

    if !current_is_privileged() {
        return 0;
    }

    let parent_pid = current_pid();
    let child_pid = event.pid;

    unsafe {
        if parent_pid == INIT_PID {
            if DEBUG {
                debug!(&ctx, "[init] fork: {}", child_pid)
            }

            if !hashmap_create(&mut INIT_CHILDREN, &child_pid, &ProcessState::PostFork.into()) && DEBUG {
                warn!(&ctx, "[init] failed to record child: {}", child_pid)
            }
        }
    }

    0
}

#[repr(C)]
struct SchedProcessExitEvent {
    _comm: [u8; 16],
    pid: i32,
    _prio: i32,
}

#[tracepoint]
pub fn tracepoint__sched__sched_process_exit(ctx: TracePointContext) -> u32 {
    let event = SchedProcessExitEvent::from_context(&ctx);
    let pid = event.pid;

    unsafe {
        if hashmap_remove(&mut INIT_CHILDREN, &pid) && DEBUG {
            debug!(&ctx, "[init] child exit: {}", pid);
        }
    }

    0
}

////////////////////////////////////////////////////////////////////////////////////////////////////

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
