use crate::tracing::{
    data::TraceData,
    encoder::{self, EncoderConfig},
};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

fn fuzz_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn quint_traces_dir() -> PathBuf {
    let dir = fuzz_dir().parent().unwrap().join("quint/traces");
    std::fs::create_dir_all(&dir).ok();
    dir
}

fn encode_trace(json: &str) -> String {
    let trace_data: TraceData = serde_json::from_str(json).expect("failed to parse trace JSON");
    let cfg = EncoderConfig {
        n: trace_data.n,
        faults: trace_data.faults,
        epoch: trace_data.epoch,
        max_view: trace_data.max_view,
        required_containers: trace_data.required_containers,
    };
    encoder::encode(&trace_data, &cfg)
}

fn run_quint_test(qnt_path: &Path) {
    let output = Command::new("quint")
        .args([
            "test",
            "--main=tests",
            "--backend=rust",
            "--max-samples=10",
            "--verbosity=4",
            "--match=traceTest",
        ])
        .arg(qnt_path)
        .env("NODE_OPTIONS", "--max-old-space-size=8192")
        .output()
        .expect("failed to run quint");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "quint test failed (exit={}):\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout,
        stderr,
    );
}

fn units_dir(suite: &str) -> PathBuf {
    fuzz_dir().join(format!("src/tracing/tests/fixtures/{suite}"))
}

fn run_json_roundtrip(json_path: &Path, hash: &str) {
    assert!(
        json_path.exists(),
        "JSON fixture not found: {}",
        json_path.display()
    );

    let json = std::fs::read_to_string(json_path).expect("failed to read trace JSON");
    let qnt = encode_trace(&json);

    let qnt_path = quint_traces_dir().join(format!("trace_{hash}_encoder_test.qnt"));
    std::fs::write(&qnt_path, &qnt).expect("failed to write .qnt file");

    let result = std::panic::catch_unwind(|| run_quint_test(&qnt_path));

    let _ = std::fs::remove_file(&qnt_path);

    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

/// Iterates over all `.json` files in a units sub-directory and runs each
/// through the encoder roundtrip. Collects all failures before panicking.
fn run_all_units(suite: &str) {
    let dir = units_dir(suite);
    assert!(dir.exists(), "units dir not found: {}", dir.display());

    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("failed to read units dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "json"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    assert!(!entries.is_empty(), "no JSON fixtures in {}", dir.display());

    let mut failures: Vec<(String, String)> = Vec::new();
    for entry in &entries {
        let path = entry.path();
        let hash = path.file_stem().unwrap().to_str().unwrap();
        let result = std::panic::catch_unwind(|| {
            run_json_roundtrip(&path, hash);
        });
        if let Err(e) = result {
            let msg = if let Some(s) = e.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = e.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "unknown panic".to_string()
            };
            failures.push((hash.to_string(), msg));
        }
    }

    if !failures.is_empty() {
        let summary: Vec<String> = failures
            .iter()
            .map(|(h, m)| format!("  {h}: {m}"))
            .collect();
        panic!(
            "{} of {} {suite} unit tests failed:\n{}",
            failures.len(),
            entries.len(),
            summary.join("\n")
        );
    }
}

// --- Unit tests: all JSON fixtures per suite ---

#[test]
fn test_units_byzantine() {
    run_all_units("byzantine");
}

#[test]
fn test_units_twins() {
    run_all_units("twins");
}

#[test]
fn test_units_honest() {
    run_all_units("honest");
}
