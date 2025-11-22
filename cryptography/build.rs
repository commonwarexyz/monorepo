use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=src/kzg/eth_trusted_setup.txt");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("trusted_setup.bin");
    let src_path = "src/kzg/eth_trusted_setup.txt";

    let content = fs::read_to_string(src_path).expect("failed to read trusted setup file");
    let mut lines = content.lines();

    let g1_count: usize = lines.next().unwrap().parse().unwrap();
    let g2_count: usize = lines.next().unwrap().parse().unwrap();

    let mut output = Vec::new();
    output.extend_from_slice(&(g1_count as u32).to_le_bytes());
    output.extend_from_slice(&(g2_count as u32).to_le_bytes());

    // Skip G1 lagrange (same as original code)
    // The original code says: "Skip the lagrange-form G1 powers provided by the c-kzg text format."
    // It skips `g1_count` lines.
    for _ in 0..g1_count {
        lines.next().unwrap();
    }

    // Read G2 monomials
    for _ in 0..g2_count {
        let line = lines.next().unwrap();
        let bytes = parse_hex(line);
        output.extend_from_slice(&bytes);
    }

    // Read G1 monomials
    for _ in 0..g1_count {
        let line = lines.next().unwrap();
        let bytes = parse_hex(line);
        output.extend_from_slice(&bytes);
    }

    fs::write(dest_path, output).expect("failed to write trusted setup bin");
}

fn parse_hex(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    let hex = hex.strip_prefix("0x").unwrap_or(hex);

    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("invalid hex"))
        .collect()
}
