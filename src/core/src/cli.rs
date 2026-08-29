use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Zynx - an eBPF-based Android process injection framework", version, long_version = concat!(env!("CARGO_PKG_VERSION"), " (commit ", env!("GIT_COMMIT_HASH"), ")"))]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub configs: CfgOptions,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run as daemon (for KernelSU/Magisk module)
    Daemon,
    /// Attach to a running zygote process
    AttachZygote {
        /// PID of the zygote64 process
        pid: i32,
    },
}

#[derive(Args, Clone)]
pub struct CfgOptions {
    #[clap(
        long,
        global = true,
        value_name = "PATH",
        help = "Load the bridge library from PATH instead of the embedded copy"
    )]
    pub cfg_bridge_file: Option<PathBuf>,

    #[clap(
        long,
        global = true,
        help = "Enable debugger (allow force-debuggable for apps)"
    )]
    pub cfg_enable_debugger: bool,

    #[clap(long, global = true, help = "Enable zygisk compat")]
    pub cfg_enable_zygisk: bool,

    #[clap(long, global = true, help = "Enable liteloader")]
    pub cfg_enable_liteloader: bool,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
