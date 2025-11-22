use commonware_utils::from_hex_formatted;
use std::{
    env,
    fs::File,
    io::{BufReader, Write},
    path::Path,
};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("trusted_setup.bin");
    let mut f_out = File::create(dest_path).unwrap();

    // Note: Cargo only runs build scripts from the crate root, so this helper must live here
    // rather than alongside the KZG module sources.

    // Parse the JSON file manually to avoid adding a dependency
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let setup_path = Path::new(&manifest_dir).join("src/kzg/trusted_setup_4096.json");
    let f_in = File::open(setup_path).expect("trusted setup file not found");
    let reader = BufReader::new(f_in);

    let json: serde_json::Value = serde_json::from_reader(reader).expect("failed to parse json");

    let g1_monomial = json["g1_monomial"].as_array().expect("g1_monomial missing");
    let g2_monomial = json["g2_monomial"].as_array().expect("g2_monomial missing");

    // Write G1 powers
    f_out
        .write_all(&(g1_monomial.len() as u32).to_be_bytes())
        .unwrap();
    for val in g1_monomial {
        let hex_str = val.as_str().expect("g1 value not string");
        let bytes = from_hex_formatted(hex_str).expect("invalid g1 hex");
        f_out.write_all(&bytes).unwrap();
    }

    // Write G2 powers
    f_out
        .write_all(&(g2_monomial.len() as u32).to_be_bytes())
        .unwrap();
    for val in g2_monomial {
        let hex_str = val.as_str().expect("g2 value not string");
        let bytes = from_hex_formatted(hex_str).expect("invalid g2 hex");
        f_out.write_all(&bytes).unwrap();
    }

    println!("cargo:rerun-if-changed=src/kzg/trusted_setup_4096.json");
}
