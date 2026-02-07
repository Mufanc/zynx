mod abi;
mod module;

use anyhow::Result;
use nix::libc::c_long;

fn on_specialize_pre(args: &mut [c_long]) -> Result<()> {
    Ok(())
}

fn on_specialize_post() -> Result<()> {
    Ok(())
}
