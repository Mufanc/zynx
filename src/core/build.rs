use aya_build::{Package, Toolchain};
use std::env;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let project_root = env::var("ROOT_DIR")?;
    let ebpf_package = Package {
        name: "zynx-ebpf",
        root_dir: project_root.as_str(),
        ..Default::default()
    };

    aya_build::build_ebpf([ebpf_package], Toolchain::default())?;

    Ok(())
}
