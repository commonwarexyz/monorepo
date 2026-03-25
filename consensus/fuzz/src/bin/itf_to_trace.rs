//! Converts an ITF trace (from `quint run --out-itf`) into a JSON trace file
//! and an expected observable state file for replay and comparison.
//!
//! Usage:
//!   cargo run -p commonware-consensus-fuzz --bin itf_to_trace -- <trace.itf.json> <output_dir> [--n N] [--faults F]

use commonware_consensus_fuzz::tracing::decoder;
use std::{env, fs, path::Path, process};

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut itf_path = None;
    let mut output_dir = None;
    let mut n: usize = 0;
    let mut faults: usize = 0;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--n" => {
                i += 1;
                n = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--faults" => {
                i += 1;
                faults = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            arg if itf_path.is_none() => {
                itf_path = Some(arg.to_string());
            }
            arg if output_dir.is_none() => {
                output_dir = Some(arg.to_string());
            }
            _ => {
                eprintln!("Unexpected argument: {}", args[i]);
                process::exit(1);
            }
        }
        i += 1;
    }

    let Some(itf_path) = itf_path else {
        eprintln!("Usage: itf_to_trace <trace.itf.json> <output_dir> [--n N] [--faults F]");
        process::exit(1);
    };
    let Some(output_dir) = output_dir else {
        eprintln!("Usage: itf_to_trace <trace.itf.json> <output_dir> [--n N] [--faults F]");
        process::exit(1);
    };

    let json = fs::read_to_string(&itf_path).unwrap_or_else(|e| {
        eprintln!("Error reading {itf_path}: {e}");
        process::exit(1);
    });

    let (trace_data, expected_state) = decoder::decode_itf(&json, n, faults).unwrap_or_else(|e| {
        eprintln!("Error decoding ITF trace: {e}");
        process::exit(1);
    });

    println!(
        "Decoded ITF trace: n={}, faults={}, epoch={}, entries={}, max_view={}",
        trace_data.n,
        trace_data.faults,
        trace_data.epoch,
        trace_data.entries.len(),
        trace_data.max_view
    );
    println!(
        "Expected state for {} correct node(s)",
        expected_state.nodes.len()
    );
    for (node, state) in &expected_state.nodes {
        println!(
            "  {node}: notarizations={:?}, nullifications={:?}, finalizations={:?}, last_finalized={}",
            state.notarizations.keys().collect::<Vec<_>>(),
            state.nullifications.iter().collect::<Vec<_>>(),
            state.finalizations.keys().collect::<Vec<_>>(),
            state.last_finalized,
        );
    }

    // Write output files
    let out = Path::new(&output_dir);
    fs::create_dir_all(out).unwrap_or_else(|e| {
        eprintln!("Error creating output directory: {e}");
        process::exit(1);
    });

    let stem = Path::new(&itf_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("trace");

    let trace_out = out.join(format!("{stem}.json"));
    let trace_json = serde_json::to_string_pretty(&trace_data).expect("serialize trace");
    fs::write(&trace_out, trace_json).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {e}", trace_out.display());
        process::exit(1);
    });
    println!("Wrote trace: {}", trace_out.display());

    let expected_out = out.join(format!("{stem}_expected.json"));
    let expected_json =
        serde_json::to_string_pretty(&expected_state).expect("serialize expected state");
    fs::write(&expected_out, expected_json).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {e}", expected_out.display());
        process::exit(1);
    });
    println!("Wrote expected state: {}", expected_out.display());
}
