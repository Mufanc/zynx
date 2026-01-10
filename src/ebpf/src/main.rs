#![no_std]
#![no_main]
#![allow(static_mut_refs)]
#![allow(non_snake_case)]

use aya_ebpf::bindings::{BPF_ANY, BPF_EXIST, BPF_NOEXIST};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::{Array, HashMap, RingBuf};
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::{EbpfContext, helpers};
use aya_log_ebpf::{debug, info, warn};
use zynx_ebpf_common::Message;

const DEBUG: bool = option_env!("DEBUG_EBPF").is_some();
const EVENT_PARAMS_OFFSET: usize = 8;
const INIT_PID: i32 = 1;
const FIRST_APP_UID: u64 = 10000;
const SIGSTOP: u32 = 19;
const SIGCONT: u32 = 18;
const SIGTRAP: u32 = 5;

#[map]
static mut TARGET_PATHS: HashMap<[u8; 128], u8> = HashMap::with_max_entries(0x100, 0);

#[map]
static mut TARGET_NAMES: HashMap<[u8; 16], u8> = HashMap::with_max_entries(0x100, 0);

#[map]
static mut MESSAGE_CHANNEL: RingBuf = RingBuf::with_byte_size(0x1000, 0);

#[map]
static mut INIT_CHILDREN: HashMap<i32, u8> = HashMap::with_max_entries(0x1000, 0);

#[map]
static mut ZYGOTE_INFO: Array<i32> = Array::with_max_entries(1, 0);

#[map]
static mut ZYGOTE_CHILDREN: HashMap<i32, u8> = HashMap::with_max_entries(0x1000, 0);

#[repr(u8)]
#[derive(Copy, Clone)]
enum ServiceState {
    PostFork,
    PostExec,
}

impl From<ServiceState> for u8 {
    fn from(value: ServiceState) -> Self {
        value as u8
    }
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum EmbryoState {
    PreFork,
}

impl From<EmbryoState> for u8 {
    fn from(value: EmbryoState) -> Self {
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
fn current_pid() -> i32 {
    (helpers::bpf_get_current_pid_tgid() & 0xffffffff) as i32
}

#[inline(always)]
fn current_is_privileged() -> bool {
    helpers::bpf_get_current_uid_gid() & 0xffffffff < FIRST_APP_UID
}

#[repr(C)]
#[repr(align(16))]
#[derive(Copy, Clone)]
struct TaskStruct {
    thread_info: ThreadInfo,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ThreadInfo {
    flags: aya_ebpf::cty::c_ulong,
}

#[inline(always)]
fn current_is_32bit() -> bool {
    // https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/include/linux/sched.h;l=823-829;drc=0c042cc4273593b3b67bb53e6a9d46c7f51b2193
    // https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/arch/arm64/include/asm/thread_info.h;l=25;drc=0c042cc4273593b3b67bb53e6a9d46c7f51b2193
    // https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/arch/arm64/include/asm/thread_info.h;l=78;drc=0c042cc4273593b3b67bb53e6a9d46c7f51b2193

    let mut is32bit = false;

    unsafe {
        let task = helpers::bpf_get_current_task() as *const TaskStruct;

        if let Ok(thread_info) = helpers::bpf_probe_read_kernel(&(*task).thread_info) {
            let flags = thread_info.flags;
            is32bit = (flags >> 22/* TIF_32BIT */) & 1 != 0
        }
    }

    is32bit
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
fn sigstop() {
    unsafe {
        helpers::bpf_send_signal_thread(SIGSTOP);
    }
}

#[inline(always)]
fn sigcont() {
    unsafe {
        helpers::bpf_send_signal_thread(SIGCONT);
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
                &ServiceState::PostFork.into(),
            ) {
                warn!(&ctx, "failed to record init child: {}", child_pid)
            }
        }

        if ZYGOTE_INFO.get(0) == Some(&parent_pid) {
            if DEBUG {
                debug!(&ctx, "zygote fork: {} -> {}", parent_pid, child_pid);
            }

            if !hashmap_create(
                &mut ZYGOTE_CHILDREN,
                &child_pid,
                &EmbryoState::PreFork.into(),
            ) {
                warn!(&ctx, "failed to record zygote child: {}", child_pid);
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
            if *state == ServiceState::PostFork.into() {
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
                        sigstop();

                        if !emit(Message::PathMatches(pid, buffer)) {
                            warn!(&ctx, "failed to emit path matches message");
                            sigcont();
                        }

                        return 0;
                    }
                }

                hashmap_change(&mut INIT_CHILDREN, &pid, &ServiceState::PostExec.into());

                return 0;
            }

            hashmap_remove(&mut INIT_CHILDREN, &pid);
        }

        // skip process fork-exec from zygote (e.g. idmap2)
        if hashmap_load(&ZYGOTE_CHILDREN, &pid).is_some() {
            hashmap_remove(&mut ZYGOTE_CHILDREN, &pid);
            debug!(&ctx, "skip zygote child: {}", pid);
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
        if let Some(state) = hashmap_load(&INIT_CHILDREN, &pid)
            && *state == ServiceState::PostExec.into()
        {
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

                    sigstop();

                    if !emit(Message::NameMatches(pid, buffer)) {
                        warn!(&ctx, "failed to emit name matches message");
                        sigcont();
                    }
                }
            }

            hashmap_remove(&mut INIT_CHILDREN, &pid);
        }
    }

    0
}

#[repr(C)]
struct SysEnterEvent {
    id: i64,
    args: [u64; 6],
}

#[tracepoint]
pub fn tracepoint__raw_syscalls__sys_enter(ctx: TracePointContext) -> u32 {
    let event = SysEnterEvent::from_context(&ctx);

    // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/jni/com_android_internal_os_Zygote.cpp;l=2506;drc=00e40a9ebff41f5b55b8f1743058a7accb0bad8e
    if event.id != 135 /* rt_sigprocmask */ || event.args[0] != 1
    /* SIG_UNBLOCK */
    {
        return 0;
    }

    if !current_is_privileged() {
        return 0;
    }

    if current_is_32bit() {
        return 0;
    }

    let pid = current_pid();

    unsafe {
        if hashmap_load(&ZYGOTE_CHILDREN, &pid) == Some(&EmbryoState::PreFork.into()) {
            hashmap_remove(&mut ZYGOTE_CHILDREN, &pid);

            if DEBUG {
                debug!(&ctx, "post zygote fork: {}", pid)
            }

            sigstop();

            if !emit(Message::ZygoteFork(pid)) {
                warn!(&ctx, "failed to emit zygote fork message");
                sigcont();
            }
        }
    }

    0
}

#[repr(C)]
struct SignalDeliverEvent {
    sig: i32,
    _errno: i32,
    code: i32,
    _sa_handler: u64,
    _sa_flags: u64,
}

#[tracepoint]
pub fn tracepoint__signal__signal_deliver(ctx: TracePointContext) -> u32 {
    if !DEBUG {
        return 0;
    }

    let event = SignalDeliverEvent::from_context(&ctx);
    let sig = event.sig as u32;

    if sig != SIGSTOP && sig != SIGCONT && sig != SIGTRAP {
        return 0;
    }

    if !current_is_privileged() {
        return 0;
    }

    let pid = current_pid();

    debug!(
        &ctx,
        "signal deliver to process {}: sig={}, code={}", pid, event.sig, event.code
    );

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

        if hashmap_remove(&mut ZYGOTE_CHILDREN, &pid) && DEBUG {
            debug!(&ctx, "zygote child exit: {}", pid);
        }

        if ZYGOTE_INFO.get(0) == Some(&pid) {
            warn!(&ctx, "zygote crashed: {}", pid);

            if !emit(Message::ZygoteCrashed(pid)) {
                warn!(&ctx, "failed to emit zygote crash message");
            }

            if ZYGOTE_INFO.set(0, 0, BPF_ANY as _).is_err() {
                warn!(&ctx, "failed to clear zygote pid")
            }
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
