//! Validates a set of trace corpus directories against `replica.qnt`,
//! embeds the Quint-derived expected state, and writes accepted traces
//! to a destination directory.
//!
//! Usage:
//!   cargo run -p commonware-consensus-fuzz --bin validate_trace_corpus -- \
//!       <dest_dir> <src_dir> [<src_dir> ...]
//!
//! Environment:
//!   * `MODEL_FAULTS` - optional faults override applied before validation
//!   * `APPEND`       - if set, do not clear `<dest_dir>` and skip source
//!                      files whose corresponding output already exists
//!                      (enables incremental/concurrent runs)

use commonware_consensus_fuzz::{
    quint_model, trace_mutator::find_json_files, tracing::data::TraceData,
};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

fn usage() -> ! {
    eprintln!("Usage: validate_trace_corpus <dest_dir> <src_dir> [<src_dir> ...]");
    process::exit(1);
}

fn normalized_dest_prefix(src: &Path) -> String {
    src.file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("source")
        .to_string()
}

fn load_trace(path: &Path, faults_override: Option<usize>) -> Option<TraceData> {
    let json = match fs::read_to_string(path) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("warning: skipping {}: read error: {e}", path.display());
            return None;
        }
    };
    let mut trace = match serde_json::from_str::<TraceData>(&json) {
        Ok(trace) => trace,
        Err(e) => {
            eprintln!("warning: skipping {}: parse error: {e}", path.display());
            return None;
        }
    };
    if trace.entries.is_empty() {
        return None;
    }
    if let Some(faults) = faults_override {
        trace.faults = faults;
    }
    Some(trace)
}

fn write_trace(path: &Path, trace: &TraceData) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("failed to create {}: {e}", parent.display());
            process::exit(1);
        });
    }
    let json = serde_json::to_string_pretty(trace).unwrap_or_else(|e| {
        eprintln!("failed to serialize {}: {e}", path.display());
        process::exit(1);
    });
    fs::write(path, json).unwrap_or_else(|e| {
        eprintln!("failed to write {}: {e}", path.display());
        process::exit(1);
    });
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        usage();
    }

    let dest_dir = PathBuf::from(&args[1]);
    let src_dirs: Vec<PathBuf> = args[2..].iter().map(PathBuf::from).collect();
    let faults_override = env::var("MODEL_FAULTS").ok().and_then(|s| s.parse().ok());
    // When APPEND is set, do not clear the destination, and skip any source
    // file whose corresponding output already exists. This enables
    // incremental/concurrent runs alongside a fuzzer.
    let append = env::var("APPEND").is_ok();

    if src_dirs.iter().any(|src| src == &dest_dir) {
        eprintln!(
            "destination {} must differ from all source dirs",
            dest_dir.display()
        );
        process::exit(1);
    }

    if dest_dir.exists() && !append {
        fs::remove_dir_all(&dest_dir).unwrap_or_else(|e| {
            eprintln!("failed to clear {}: {e}", dest_dir.display());
            process::exit(1);
        });
    }
    fs::create_dir_all(&dest_dir).unwrap_or_else(|e| {
        eprintln!("failed to create {}: {e}", dest_dir.display());
        process::exit(1);
    });

    let mut total = 0usize;
    let mut accepted = 0usize;
    let mut skipped_missing = 0usize;

    for src in &src_dirs {
        if !src.is_dir() {
            eprintln!("warning: skipping missing source dir {}", src.display());
            skipped_missing += 1;
            continue;
        }

        let prefix = normalized_dest_prefix(src);
        let files = find_json_files(src);
        println!(
            "validate_trace_corpus: source {} -> {} candidate files",
            src.display(),
            files.len()
        );

        for (idx, path) in files.iter().enumerate() {
            total += 1;
            if idx == 0 || idx % 10 == 0 || idx + 1 == files.len() {
                println!(
                    "validate_trace_corpus: validating {}/{} from {} (accepted so far {})",
                    idx + 1,
                    files.len(),
                    src.display(),
                    accepted
                );
            }
            let rel = path.strip_prefix(src).unwrap_or(path);
            let out = dest_dir.join(&prefix).join(rel);
            if append && out.exists() {
                continue;
            }
            let Some(trace) = load_trace(path, faults_override) else {
                continue;
            };

            let label = path.display().to_string();
            match quint_model::validate_and_extract_expected(&trace, &label) {
                Ok(expected) => {
                    let mut trace = trace;
                    trace.expected_state = expected;
                    write_trace(&out, &trace);
                    accepted += 1;
                }
                Err(_) => {}
            }

            if files.len() >= 10 && ((idx + 1) % 10 == 0 || idx + 1 == files.len()) {
                println!(
                    "validate_trace_corpus: {} progress {}/{} accepted={}",
                    src.display(),
                    idx + 1,
                    files.len(),
                    accepted
                );
            }
        }
    }

    println!(
        "validate_trace_corpus: accepted {}/{} traces into {}",
        accepted,
        total,
        dest_dir.display()
    );

    // In append mode, an empty pass is fine (no new files to validate).
    if accepted == 0 && !append {
        eprintln!(
            "no model-valid traces found across {} source dirs ({} missing)",
            src_dirs.len(),
            skipped_missing
        );
        process::exit(1);
    }
}
