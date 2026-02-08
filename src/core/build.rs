use aya_build::{Package, Toolchain};
use std::env;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    if env::var("PROFILE")? == "debug" {
        unsafe {
            env::set_var("DEBUG_EBPF", "1");
        }
    }

    let project_root = env::var("ROOT_DIR")?;
    let ebpf_package = Package {
        name: "zynx-ebpf",
        root_dir: project_root.as_str(),
        ..Default::default()
    };

    aya_build::build_ebpf([ebpf_package], Toolchain::default())?;

    let proto_src = concat!(env!("CARGO_MANIFEST_DIR"), "/proto");
    let proto_files: Vec<_> = glob::glob(&format!("{proto_src}/*.proto"))?
        .flatten()
        .collect();

    prost_build::compile_protos(&proto_files, &[proto_src])?;

    Ok(())
}
