pub mod remote_call;
pub mod base;
pub mod ipc;
pub mod jni;

use crate::injector::ptrace::ext::remote_call::PtraceRemoteCallExt;
use crate::misc::ext::ResultExt;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use std::fmt::Display;
use std::ops::Deref;

#[macro_export]
macro_rules! build_args {
    ($($args: expr),*) => {
        &[ $(($args) as _),* ]
    };
}

pub trait WaitStatusExt {
    fn sig(&self) -> Option<Signal>;
}

impl WaitStatusExt for WaitStatus {
    fn sig(&self) -> Option<Signal> {
        match self {
            WaitStatus::Exited(_, _) => None,
            WaitStatus::Signaled(_, sig, _) => Some(*sig),
            WaitStatus::Stopped(_, sig) => Some(*sig),
            WaitStatus::PtraceEvent(_, sig, _) => Some(*sig),
            WaitStatus::PtraceSyscall(_) => None,
            WaitStatus::Continued(_) => None,
            WaitStatus::StillAlive => None,
        }
    }
}
