//! Converts JSON trace files (produced by the quint tracing fuzzer) into
//! `.qnt` test files that can be verified with the quint model checker.
//!
//! Usage:
//!   cargo run -p commonware-consensus-fuzz --bin trace_to_quint -- <trace_dir> <output_dir>

use commonware_consensus_fuzz::tracing::{
    data::TraceData,
    encoder::{self, EncoderConfig},
};
use std::{env, fs, path::PathBuf, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: trace_to_quint <trace_dir> <output_dir>");
        process::exit(1);
    }

    let trace_dir = PathBuf::from(&args[1]);
    let output_dir = PathBuf::from(&args[2]);

    if !trace_dir.is_dir() {
        eprintln!("Error: {} is not a directory", trace_dir.display());
        process::exit(1);
    }

    fs::create_dir_all(&output_dir).expect("failed to create output directory");

    let mut converted = 0;
    let mut errors = 0;

    for entry in fs::read_dir(&trace_dir).expect("failed to read trace directory") {
        let entry = entry.expect("failed to read directory entry");
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        let json = match fs::read_to_string(&path) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("Error reading {}: {}", path.display(), e);
                errors += 1;
                continue;
            }
        };

        let trace_data: TraceData = match serde_json::from_str(&json) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Error parsing {}: {}", path.display(), e);
                errors += 1;
                continue;
            }
        };

        let cfg = EncoderConfig {
            n: trace_data.n,
            faults: trace_data.faults,
            epoch: trace_data.epoch,
            max_view: trace_data.max_view,
            required_containers: trace_data.required_containers,
        };

        let qnt = encoder::encode(&trace_data, &cfg);
        let output_path = output_dir.join(format!("trace_{}.qnt", stem));
        fs::write(&output_path, &qnt).expect("failed to write quint test");
        println!("{} -> {}", path.display(), output_path.display());
        converted += 1;
    }

    println!("Converted {} trace(s), {} error(s)", converted, errors);
    if errors > 0 {
        process::exit(1);
    }
}
