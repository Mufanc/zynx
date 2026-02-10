use clap::Parser;

#[derive(Parser)]
pub struct Cli {
    #[clap(long, help = "run zynx in daemon mode", conflicts_with = "configs")]
    pub daemon: bool,

    #[clap(long, help = "disable debugger", group = "configs")]
    pub cfg_disable_debugger: bool,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
