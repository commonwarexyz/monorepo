//! Converts canonical `Trace` JSON files into `.qnt` test files that can be
//! verified with the quint model checker.
//!
//! Usage:
//!   cargo run -p commonware-consensus-fuzz --bin trace_to_quint -- <trace_dir> <output_dir>

use commonware_consensus::simplex::replay::Trace;
use commonware_consensus_fuzz::tracing::encoder;
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

        let trace: Trace = match Trace::from_json(&json) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Error parsing {}: {}", path.display(), e);
                errors += 1;
                continue;
            }
        };

        // Derive required_containers from the maximum last_finalized across
        // all recorded nodes; defaults to 0 when the snapshot is empty (the
        // encoder tolerates 0 and just doesn't set a finalizations lower
        // bound).
        let required_containers = trace
            .expected
            .nodes
            .values()
            .map(|n| n.last_finalized.get())
            .max()
            .unwrap_or(0);

        let qnt = encoder::encode_from_trace(&trace, required_containers);
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
