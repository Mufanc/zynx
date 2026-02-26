use clap::Parser;

#[derive(Parser)]
#[command(about = "Zynx - an eBPF-based Android process injection framework", version, long_version = concat!(env!("CARGO_PKG_VERSION"), " (commit ", env!("GIT_COMMIT_HASH"), ")"))]
pub struct Cli {
    #[clap(
        long,
        help = "Run Zynx in daemon mode (usually used for KernelSU/Magisk module)"
    )]
    pub daemon: bool,

    #[clap(long, help = "Enable debugger (allow force-debuggable for apps)")]
    pub cfg_enable_debugger: bool,

    #[clap(long, help = "Enable zygisk compat")]
    pub cfg_enable_zygisk: bool,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
