//! Reads `Trace` JSON from one or more source directories, runs each
//! trace through Quint via
//! [`commonware_consensus_fuzz::quint_model::validate_and_extract_expected`],
//! embeds the Quint-derived `expected` snapshot, and writes accepted
//! traces to a destination directory as JSON.
//!
//! Usage:
//!   cargo run -p commonware-consensus-fuzz --bin validate_trace_corpus -- \
//!       <dest_dir> <src_dir> [<src_dir> ...]
//!
//! Environment:
//!   * `MODEL_FAULTS` - optional faults override applied before validation.
//!   * `APPEND=1`     - if set, do not clear `<dest_dir>`; skip source
//!                      files whose corresponding output already exists.

use commonware_consensus::simplex::replay::Trace;
use commonware_consensus_fuzz::{quint_model, trace_mutator::find_json_files};
use sha1::{Digest as _, Sha1};
use std::{env, fs, path::Path, path::PathBuf, process};

fn usage() -> ! {
    eprintln!(
        "Usage: validate_trace_corpus <dest_dir> <src_dir> [<src_dir> ...]"
    );
    process::exit(1);
}

fn normalized_dest_prefix(src: &Path) -> String {
    src.file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("source")
        .to_string()
}

fn load_trace(path: &Path, faults_override: Option<u32>) -> Option<Trace> {
    let json = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  skip (read error) {}: {e}", path.display());
            return None;
        }
    };
    let mut trace = match Trace::from_json(&json) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("  skip (parse error) {}: {e}", path.display());
            return None;
        }
    };
    if let Some(f) = faults_override {
        trace.topology.faults = f;
    }
    Some(trace)
}

fn output_filename(prefix: &str, src_name: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(prefix.as_bytes());
    hasher.update(b":");
    hasher.update(src_name.as_bytes());
    let hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    format!("{prefix}_{hex}.json")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        usage();
    }
    let dest_dir = PathBuf::from(&args[1]);
    let src_dirs: Vec<PathBuf> = args[2..].iter().map(PathBuf::from).collect();

    let append = env::var("APPEND").is_ok();
    let faults_override: Option<u32> = env::var("MODEL_FAULTS").ok().and_then(|s| s.parse().ok());

    if !append {
        let _ = fs::remove_dir_all(&dest_dir);
    }
    if let Err(e) = fs::create_dir_all(&dest_dir) {
        eprintln!("failed to create {}: {e}", dest_dir.display());
        process::exit(1);
    }

    let mut total_accepted = 0usize;

    for src in &src_dirs {
        if !src.exists() {
            eprintln!("validate_trace_corpus: skipping missing {}", src.display());
            continue;
        }
        let prefix = normalized_dest_prefix(src);
        let candidates = find_json_files(src);
        eprintln!(
            "validate_trace_corpus: source {} -> {} candidate files",
            src.display(),
            candidates.len()
        );

        let mut seen = 0usize;
        for path in &candidates {
            seen += 1;
            let src_name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();

            let out_name = output_filename(&prefix, &src_name);
            let out_path = dest_dir.join(&out_name);
            if append && out_path.exists() {
                continue;
            }
            if seen == 1 || seen == candidates.len() || seen % 10 == 0 {
                eprintln!(
                    "validate_trace_corpus: validating {}/{} from {} (accepted so far {})",
                    seen,
                    candidates.len(),
                    src.display(),
                    total_accepted,
                );
            }

            let Some(mut trace) = load_trace(path, faults_override) else {
                continue;
            };

            let label = out_name.clone();
            let expected = match quint_model::validate_and_extract_expected(&trace, &label)
            {
                Ok(exp) => exp,
                Err(_) => {
                    continue;
                }
            };
            if let Some(exp) = expected {
                trace.expected = exp;
            }

            let json = match trace.to_json() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("  encode error: {e}");
                    continue;
                }
            };
            let tmp = out_path.with_extension("json.tmp");
            if let Err(e) = fs::write(&tmp, &json).and_then(|_| fs::rename(&tmp, &out_path)) {
                eprintln!("  write error {}: {e}", out_path.display());
                continue;
            }
            total_accepted += 1;
        }

        eprintln!(
            "validate_trace_corpus: {} progress {}/{} accepted={}",
            src.display(),
            seen,
            candidates.len(),
            total_accepted,
        );
    }

    eprintln!(
        "validate_trace_corpus: accepted {total_accepted} traces into {}",
        dest_dir.display()
    );
}
