use clap::Parser;

#[derive(Parser)]
pub struct Cli {
    #[clap(long, help = "run zynx in daemon mode")]
    pub daemon: bool,
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
