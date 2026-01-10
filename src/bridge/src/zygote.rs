use crate::init_logger;
use log::{error, info};
use nix::libc::c_long;
use nix::sys::mman;
use nix::unistd;
use std::arch::naked_asm;
use std::ptr::NonNull;
use zynx_bridge_common::EmbryoTrampolineArgs;
/*
 *            AArch64 Calling Convention
 *
 * > Arguments 1-8 are passed in registers x0-x7
 * > Arguments beyond the 8th are placed on the stack
 *
 *                     ...
 *               ┌─────────────┐ <-- High Address
 *               │    arg12    │
 *               ├─────────────┤
 *               │    arg11    │
 *               ├─────────────┤
 *               │    arg10    │
 *               ├─────────────┤
 *        sp --> │    arg9     │
 *               └─────────────┘ <-- Low Address
 */

#[allow(unused_variables)]
#[unsafe(naked)]
unsafe extern "C" fn specialize_common(func: usize, args_count: usize, args: *const c_long) {
    naked_asm!(
        // prologue
        "stp x29, x30, [sp, #-16]!",
        "mov x29, sp",
        // save args
        "mov x10, x0", // func -> x10
        "mov x11, x1", // args_count -> x11
        "mov x12, x2", // args -> x12
        // alloc space for arguments
        "sub x0, x11, #8",        // i = args_count - 8
        "sub sp, sp, x0, lsl #3", // sp -= i * 8
        "mov x0, sp",             // i = sp
        "bic x0, x0, #15",        // i &= ~0xf
        "mov sp, x0",             // sp = i
        // pass arguments on the stack
        "mov x0, #8",                // i = 8
        "cmp x0, x11",               // loop {
        "b.eq #24",                  //     if i == args_count: break
        "ldr x8, [x12, x0, lsl #3]", //     x = args[i]
        "sub x1, x0, #8",            //     j = i - 8
        "str x8, [sp, x1, lsl #3]",  //     sp[j] = x
        "add x0, x0, #1",            //     ++i
        "b #-24",                    // }
        // pass arguments in registers
        "ldp x0, x1, [x12]",
        "ldp x2, x3, [x12, #16]",
        "ldp x4, x5, [x12, #32]",
        "ldp x6, x7, [x12, #48]",
        // call real SpecializeCommon
        "blr x10",
        // restore sp
        "mov sp, x29",
        // epilogue
        "ldp x29, x30, [sp], #16",
        "ret",
    )
}

#[allow(unused_variables)]
#[unsafe(naked)]
extern "C" fn long_return(sp: usize, fp: usize, lr: usize, callee_saves: *const usize) {
    naked_asm!(
        "mov x29, x1",
        "mov x30, x2",
        "ldp x19, x20, [x3]",
        "ldp x21, x22, [x3, #16]",
        "ldp x23, x24, [x3, #32]",
        "ldp x25, x26, [x3, #48]",
        "ldp x27, x28, [x3, #64]",
        "mov sp, x0",
        "ret"
    )
}

fn handle_specialize_common(args: &EmbryoTrampolineArgs) -> anyhow::Result<()> {
    unsafe {
        mman::munmap(
            NonNull::new_unchecked(args.buffer_region.base as _),
            args.buffer_region.size,
        )?;
        mman::munmap(
            NonNull::new_unchecked(args.trampoline_region.base as _),
            args.trampoline_region.size,
        )?;
    }

    info!("pre specialize, uid = {}", unistd::getuid());

    let hook = &args.specialize_hook;
    unsafe {
        specialize_common(
            hook.specialize_fn,
            hook.specialize_args_count,
            hook.specialize_args.as_ptr(),
        );
    }

    info!("post specialize, uid = {}", unistd::getuid());

    Ok(())
}

#[unsafe(no_mangle)]
extern "C" fn embryo_entry(args: *const EmbryoTrampolineArgs) {
    let args = unsafe { (*args).clone() }; // copy to stack

    init_logger();

    info!("trampoline args: {args:?}");

    if let Err(err) = handle_specialize_common(&args) {
        error!("failed to handle specialize common: {err:?}")
    }

    let info = args.specialize_hook;
    long_return(
        info.return_sp,
        info.return_fp,
        info.return_lr,
        info.callee_saves.as_ptr(),
    )
}
