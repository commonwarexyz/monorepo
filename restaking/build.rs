use std::path::Path;
use std::process::Command;
use std::result::Result;

const MODULES: &[&str] = &["symbiotic"];

fn main() -> Result<(), String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    for elem in MODULES {
        let _ = execute_forge_build(&manifest_dir, elem);
    }
    Ok(())
}

fn execute_forge_build(manifest_dir: &str, module: &str) -> Result<(), String> {
    let module_src = Path::new("src").join(module);
    let artifacts_path = module_src.join("artifacts");
    let current_dir = Path::new(manifest_dir).join(module_src);

    let forge_status = Command::new("forge")
        .arg("build")
        .arg("--root")
        .arg(manifest_dir)
        .arg("--cache-path")
        .arg("forge_cache")
        .arg(".")
        .arg("-o")
        .arg(artifacts_path.to_str().unwrap())
        .current_dir(current_dir.to_str().unwrap())
        .status()
        .expect("Failed to compiler testutils contracts.");

    if !forge_status.success() {
        panic!("Force contracts compilation failed. Check contracts for errors.")
    }
    Ok(())
}
