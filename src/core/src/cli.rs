use bitflags::bitflags;
use clap::{Args, Parser, Subcommand};
#[cfg(not(feature = "standalone"))]
use std::path::PathBuf;
use std::str::FromStr;

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
    #[cfg(not(feature = "standalone"))]
    Daemon {
        /// Wait for the system BPF loader before initializing
        #[arg(long)]
        wait_bpfloader: bool,
    },
    /// Attach to a running zygote process
    #[cfg(feature = "standalone")]
    AttachZygote {
        /// PID of the zygote64 process
        pid: i32,
    },
}

#[derive(Args, Clone)]
pub struct CfgOptions {
    #[cfg(not(feature = "standalone"))]
    #[arg(long, value_name = "PATH", help = "Load the bridge library from PATH")]
    pub bridge: PathBuf,

    #[arg(
        long,
        global = true,
        value_name = "LIST",
        help = "Enable colon-separated runtime features: debugger, liteloader, zygisk (if built in)"
    )]
    pub features: Option<FeatureFlags>,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct FeatureFlags: u8 {
        const DEBUGGER = 1 << 0;
        const LITELOADER = 1 << 1;
        #[cfg(feature = "zygisk")]
        const ZYGISK = 1 << 2;
    }
}

impl FromStr for FeatureFlags {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut features = Self::empty();

        for name in input.split(':') {
            let feature = match name {
                "debugger" => Self::DEBUGGER,
                "liteloader" => Self::LITELOADER,
                #[cfg(feature = "zygisk")]
                "zygisk" => Self::ZYGISK,
                "" => return Err("empty runtime feature name".into()),
                _ => return Err(format!("unknown runtime feature `{name}`")),
            };

            features.insert(feature);
        }

        Ok(features)
    }
}

impl Cli {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, FeatureFlags};
    use clap::Parser;
    use clap::error::ErrorKind;

    #[test]
    fn parses_runtime_features() {
        assert_eq!(
            "debugger:liteloader".parse(),
            Ok(FeatureFlags::DEBUGGER | FeatureFlags::LITELOADER)
        );
        assert!("debugger::liteloader".parse::<FeatureFlags>().is_err());
        assert!("unknown".parse::<FeatureFlags>().is_err());

        #[cfg(feature = "zygisk")]
        assert_eq!(
            "zygisk:liteloader".parse(),
            Ok(FeatureFlags::ZYGISK | FeatureFlags::LITELOADER)
        );
        #[cfg(not(feature = "zygisk"))]
        assert_eq!(
            "zygisk:liteloader".parse::<FeatureFlags>(),
            Err("unknown runtime feature `zygisk`".into())
        );
    }

    #[cfg(feature = "standalone")]
    #[test]
    fn standalone_only_uses_embedded_bridge() {
        assert!(Cli::try_parse_from(["zynx", "attach-zygote", "123"]).is_ok());

        let Err(error) = Cli::try_parse_from(["zynx", "--bridge", "/tmp/bridge.so"]) else {
            panic!("standalone accepted an external bridge path");
        };
        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[cfg(not(feature = "standalone"))]
    #[test]
    fn module_requires_bridge_path_before_launch() {
        for args in [&["zynx"][..], &["zynx", "daemon", "--wait-bpfloader"][..]] {
            let Err(error) = Cli::try_parse_from(args) else {
                panic!("missing bridge path accepted for {args:?}");
            };
            assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
        }

        assert!(
            Cli::try_parse_from([
                "zynx",
                "--bridge",
                "/module/bin/libzynx_bridge.so",
                "daemon",
                "--wait-bpfloader",
                "--features",
                "liteloader",
            ])
            .is_ok()
        );
    }

    #[cfg(not(feature = "standalone"))]
    #[test]
    fn module_rejects_attach_zygote() {
        let Err(error) = Cli::try_parse_from([
            "zynx",
            "--bridge",
            "/module/bin/libzynx_bridge.so",
            "attach-zygote",
            "123",
        ]) else {
            panic!("module accepted attach-zygote");
        };
        assert_eq!(error.kind(), ErrorKind::InvalidSubcommand);
    }
}
