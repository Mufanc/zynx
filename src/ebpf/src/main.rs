#![no_std]
#![no_main]
#![allow(static_mut_refs)]
#![allow(non_snake_case)]

use aya_ebpf::bindings::{BPF_EXIST, BPF_NOEXIST};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::{HashMap, RingBuf};
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::{EbpfContext, helpers};
use aya_log_ebpf::{debug, info, warn};
use zynx_ebpf_common::Message;

const DEBUG: bool = option_env!("DEBUG_EBPF").is_some();
const EVENT_PARAMS_OFFSET: usize = 8;
const INIT_PID: i32 = 1;
const FIRST_APP_UID: u64 = 10000;

#[map]
static mut TARGET_PATHS: HashMap<[u8; 128], u8> = HashMap::with_max_entries(0x100, 0);

#[map]
static mut TARGET_NAMES: HashMap<[u8; 16], u8> = HashMap::with_max_entries(0x100, 0);

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
    PostExec,
}

impl From<ProcessState> for u8 {
    fn from(value: ProcessState) -> Self {
        value as u8
    }
}

trait TracePointEvent {
    fn from_context(ctx: &TracePointContext) -> &Self;
}

impl<T> TracePointEvent for T {
    fn from_context(ctx: &TracePointContext) -> &Self {
        unsafe { &*(ctx.as_ptr().add(EVENT_PARAMS_OFFSET) as *const _) }
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
fn hashmap_load<'a, K, V>(map: &'a HashMap<K, V>, key: &K) -> Option<&'a V> {
    unsafe { map.get(key) }
}

#[inline(always)]
fn hashmap_contains<K, V>(map: &HashMap<K, V>, key: &K) -> bool {
    map.get_ptr(key).is_some()
}

#[inline(always)]
fn stop_current_proc() {
    unsafe {
        helpers::bpf_send_signal_thread(19 /* SIGSTOP */);
    }
}

#[inline(always)]
fn emit(message: Message) -> bool {
    unsafe {
        let entry = MESSAGE_CHANNEL.reserve::<Message>(0);
        let mut entry = match entry {
            Some(entry) => entry,
            None => return false,
        };

        entry.write(message);
        entry.submit(0);
    }

    true
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
                debug!(&ctx, "init fork: {}", child_pid)
            }

            if !hashmap_create(
                &mut INIT_CHILDREN,
                &child_pid,
                &ProcessState::PostFork.into(),
            ) && DEBUG
            {
                warn!(&ctx, "failed to record init child: {}", child_pid)
            }
        }
    }

    0
}

#[repr(C)]
struct SchedProcessExecEvent {
    filename: (i16, u16), // __data_loc
    pid: i32,
    _old_pid: i32,
}

#[tracepoint]
pub fn tracepoint__sched__sched_process_exec(ctx: TracePointContext) -> u32 {
    if !current_is_privileged() {
        return 0;
    }

    let event = SchedProcessExecEvent::from_context(&ctx);
    let pid = event.pid;

    unsafe {
        if let Some(state) = hashmap_load(&INIT_CHILDREN, &pid) {
            if *state == ProcessState::PostFork.into() {
                let ptr = ctx.as_ptr().add(event.filename.0 as _) as *const u8;
                let mut buffer = [0u8; 128];

                if helpers::bpf_probe_read_kernel_str_bytes(ptr, &mut buffer).is_ok() {
                    let path = core::str::from_utf8_unchecked(&buffer);

                    if DEBUG {
                        debug!(&ctx, "process exec: {} -> {}", pid, path);
                    }

                    if hashmap_contains(&TARGET_PATHS, &buffer) {
                        info!(&ctx, "path matches: {} -> {}", pid, path);
                        hashmap_remove(&mut INIT_CHILDREN, &pid);
                        stop_current_proc();
                        emit(Message::PathMatches(pid, buffer));
                        return 0;
                    }
                }

                hashmap_change(&mut INIT_CHILDREN, &pid, &ProcessState::PostExec.into());

                return 0;
            }

            hashmap_remove(&mut INIT_CHILDREN, &pid);
        }
    }

    0
}

#[repr(C)]
struct TaskRenameEvent {
    pid: i32,
    old_comm: [u8; 16],
    new_comm: [u8; 16],
}

#[tracepoint]
pub fn tracepoint__task__task_rename(ctx: TracePointContext) -> u32 {
    if !current_is_privileged() {
        return 0;
    }

    let event = TaskRenameEvent::from_context(&ctx);
    let pid = event.pid;

    unsafe {
        match hashmap_load(&INIT_CHILDREN, &pid) {
            Some(state) if *state == ProcessState::PostExec.into() => {
                let ptr = ctx
                    .as_ptr()
                    .add(EVENT_PARAMS_OFFSET + core::mem::offset_of!(TaskRenameEvent, new_comm))
                    as *const u8;
                let mut buffer = [0u8; 16];

                if helpers::bpf_probe_read_kernel_str_bytes(ptr, &mut buffer).is_ok() {
                    let name = core::str::from_utf8_unchecked(&buffer);

                    if DEBUG {
                        debug!(&ctx, "process rename: {} -> {}", pid, name);
                    }

                    if hashmap_contains(&TARGET_NAMES, &buffer) {
                        info!(&ctx, "name matches: {} -> {}", pid, name);
                        stop_current_proc();
                        emit(Message::NameMatches(pid, buffer));
                    }
                }

                hashmap_remove(&mut INIT_CHILDREN, &pid);
            }
            _ => (),
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
            debug!(&ctx, "init child exit: {}", pid);
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
