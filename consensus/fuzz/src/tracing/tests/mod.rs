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

fn fixtures_dir() -> PathBuf {
    fuzz_dir().join("src/tracing/tests/fixtures/regressions")
}

fn generate_json_trace(
    fuzz_target: &str,
    trace_dir: &str,
    corpus_path: &Path,
    hash: &str,
) -> PathBuf {
    let output = Command::new("cargo")
        .args(["+nightly", "fuzz", "run", fuzz_target])
        .arg(corpus_path)
        .env("TRACE_SELECTION_STRATEGY", "smallscope")
        .env("MIN_REQUIRED_CONTAINERS", "3")
        .env("MAX_REQUIRED_CONTAINERS", "10")
        .current_dir(fuzz_dir().parent().unwrap())
        .output()
        .expect("failed to run cargo fuzz");

    assert!(
        output.status.success(),
        "cargo fuzz failed (exit={}):\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    fuzz_dir()
        .join(format!("artifacts/traces/{trace_dir}_smallscope"))
        .join(format!("{hash}.json"))
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
    fuzz_dir().join(format!("src/tracing/tests/fixtures/units/{suite}"))
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

/// Runs the encoder roundtrip from a pre-generated JSON fixture (no fuzz target needed).
fn run_encoder_roundtrip_json(hash: &str) {
    run_json_roundtrip(&fixtures_dir().join(hash), hash);
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

fn run_encoder_roundtrip(hash: &str) {
    run_encoder_roundtrip_impl(
        "simplex_ed25519_quint_byzantine",
        "simplex_ed25519_quint_byzantine",
        hash,
    );
}

fn run_encoder_roundtrip_target(fuzz_target: &str, hash: &str) {
    run_encoder_roundtrip_impl(fuzz_target, fuzz_target, hash);
}

fn run_encoder_roundtrip_impl(fuzz_target: &str, trace_dir: &str, hash: &str) {
    let corpus_path = fixtures_dir().join(hash);
    assert!(
        corpus_path.exists(),
        "corpus fixture not found: {}",
        corpus_path.display()
    );

    let json_path = generate_json_trace(fuzz_target, trace_dir, &corpus_path, hash);
    assert!(
        json_path.exists(),
        "JSON trace not generated: {}",
        json_path.display()
    );

    let json = std::fs::read_to_string(&json_path).expect("failed to read trace JSON");
    let qnt = encode_trace(&json);

    let qnt_path = quint_traces_dir().join(format!("trace_{hash}_encoder_test.qnt"));
    std::fs::write(&qnt_path, &qnt).expect("failed to write .qnt file");

    let result = std::panic::catch_unwind(|| run_quint_test(&qnt_path));

    let _ = std::fs::remove_file(&qnt_path);

    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

#[test]
fn test_encoder_roundtrip_d8bc163602d7759db2b7ea48a17eae663c3ee47c() {
    run_encoder_roundtrip_json("d8bc163602d7759db2b7ea48a17eae663c3ee47c");
}

#[test]
fn test_encoder_roundtrip_449b2497101c43ad3c59f77013977e8bbb9e1340() {
    run_encoder_roundtrip_json("449b2497101c43ad3c59f77013977e8bbb9e1340");
}

#[test]
fn test_encoder_roundtrip_da39a3ee5e6b4b0d3255bfef95601890afd80709() {
    run_encoder_roundtrip_json("da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn test_encoder_roundtrip_b12ca0d39b9286468f2ce0d791750bda4b6d3f37() {
    run_encoder_roundtrip_json("b12ca0d39b9286468f2ce0d791750bda4b6d3f37");
}

#[test]
fn test_encoder_roundtrip_7340e23239ef037c7208177fc9b4c39d05d48eb1() {
    run_encoder_roundtrip_json("7340e23239ef037c7208177fc9b4c39d05d48eb1");
}

#[test]
fn test_encoder_roundtrip_35d8bbc9bac04cc106d4c9e32f8f4c0985186069() {
    run_encoder_roundtrip_json("35d8bbc9bac04cc106d4c9e32f8f4c0985186069");
}

#[test]
fn test_encoder_roundtrip_c72bd2b1346cedb1e287ab6c217fd1c9b1837068() {
    run_encoder_roundtrip_json("c72bd2b1346cedb1e287ab6c217fd1c9b1837068");
}

#[test]
fn test_encoder_roundtrip_57ee33dc4aa3193f0f134235b1e9339f97335735() {
    run_encoder_roundtrip_json("57ee33dc4aa3193f0f134235b1e9339f97335735");
}

#[test]
fn test_encoder_roundtrip_f8e973d05611bcdd590fc791818775e247225159() {
    run_encoder_roundtrip_json("f8e973d05611bcdd590fc791818775e247225159");
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
