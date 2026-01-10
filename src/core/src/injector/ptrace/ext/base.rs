use crate::injector::ptrace::RemoteProcess;
use anyhow::Result;
use nix::libc::c_long;

pub trait PtraceExt {
    fn get_arg(&self, index: usize) -> Result<c_long>;
    fn get_args(&self, args: &mut [c_long]) -> Result<()>;
}

impl PtraceExt for RemoteProcess {
    fn get_arg(&self, index: usize) -> Result<c_long> {
        let regs = self.get_regs()?;
        let arg = if index < 8 {
            regs.get_arg(index)
        } else {
            let n = index - 8;
            self.peek(regs.get_sp() + 8 * n)?
        };

        Ok(arg)
    }

    fn get_args(&self, args: &mut [c_long]) -> Result<()> {
        let regs = self.get_regs()?;

        for (index, arg) in args.iter_mut().enumerate() {
            if index < 8 {
                *arg = regs.get_arg(index);
            } else {
                let n = index - 8;
                *arg = self.peek(regs.get_sp() + 8 * n)?;
            }
        }

        Ok(())
    }
}
