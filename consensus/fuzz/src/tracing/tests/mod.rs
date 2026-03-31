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
    fuzz_dir().parent().unwrap().join("quint/traces")
}

fn fixtures_dir() -> PathBuf {
    fuzz_dir().join("src/tracing/tests/fixtures")
}

fn generate_json_trace(fuzz_target: &str, trace_dir: &str, corpus_path: &Path, hash: &str) -> PathBuf {
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

fn run_encoder_roundtrip(hash: &str) {
    run_encoder_roundtrip_impl("simplex_ed25519_quint_twins_disrupter", "simplex_ed25519_quint_twins_disrupter", hash);
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
    run_encoder_roundtrip("d8bc163602d7759db2b7ea48a17eae663c3ee47c");
}

#[test]
fn test_encoder_roundtrip_449b2497101c43ad3c59f77013977e8bbb9e1340() {
    run_encoder_roundtrip("449b2497101c43ad3c59f77013977e8bbb9e1340");
}

#[test]
fn test_encoder_roundtrip_da39a3ee5e6b4b0d3255bfef95601890afd80709() {
    run_encoder_roundtrip_impl(
        "simplex_ed25519_quint_equivocator",
        "simplex_ed25519_quint_byzantine",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    );
}

#[test]
fn test_encoder_roundtrip_b12ca0d39b9286468f2ce0d791750bda4b6d3f37() {
    run_encoder_roundtrip_target(
        "simplex_ed25519_quint_byzantine",
        "b12ca0d39b9286468f2ce0d791750bda4b6d3f37",
    );
}
