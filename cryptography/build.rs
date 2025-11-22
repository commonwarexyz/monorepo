use std::env;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("trusted_setup.bin");
    let mut f_out = File::create(dest_path).unwrap();

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
        let bytes = hex::decode(hex_str.trim_start_matches("0x")).expect("invalid hex");
        f_out.write_all(&bytes).unwrap();
    }

    // Write G2 powers
    f_out
        .write_all(&(g2_monomial.len() as u32).to_be_bytes())
        .unwrap();
    for val in g2_monomial {
        let hex_str = val.as_str().expect("g2 value not string");
        let bytes = hex::decode(hex_str.trim_start_matches("0x")).expect("invalid hex");
        f_out.write_all(&bytes).unwrap();
    }

    println!("cargo:rerun-if-changed=src/kzg/trusted_setup_4096.json");
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd length".to_string());
        }
        let mut bytes = Vec::with_capacity(s.len() / 2);
        for i in (0..s.len()).step_by(2) {
            let b = u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())?;
            bytes.push(b);
        }
        Ok(bytes)
    }
}
