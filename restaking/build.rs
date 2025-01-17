use std::env;
use std::path::Path;
use std::process::Command;
use std::result::Result;

fn main() -> Result<(), String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let out_dir = env::var("OUT_DIR").unwrap();
    let input_contract_dir = Path::new(&manifest_dir).join("src/solidity_interfaces");
    let output_contract_dir = Path::new(&manifest_dir).join("src/abi");
    let forge_status = Command::new("forge")
        .arg("build")
        .arg(".")
        .arg("-o")
        .arg(format!("{}", output_contract_dir.to_str().unwrap()))
        .current_dir(input_contract_dir)
        .status()
        .expect("Failed to compiler testutils contracts.");

    if !forge_status.success() {
        panic!("Force compilation failed. Check contracts for errors.")
    }

    println!("The build output directory is: {}", out_dir);

    Ok(())
}
