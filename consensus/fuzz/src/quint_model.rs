use crate::{
    replayer::compare::{ExpectedNodeState, ExpectedState},
    tracing::{data::TraceData, decoder, encoder},
};
use commonware_consensus::{
    simplex::replay::{
        trace::{CertStateSnapshot, NodeSnapshot, NullStateSnapshot, Snapshot},
        Trace,
    },
    types::View,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_utils::Participant;
use sha1::{Digest, Sha1};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    error::Error,
    fmt::{self, Display},
    fs,
    path::{Path, PathBuf},
    process::{self, Command},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct ModelError {
    message: String,
}

impl ModelError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ModelError {}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn quint_dir() -> PathBuf {
    manifest_dir().join("../quint")
}

fn temp_dir() -> PathBuf {
    quint_dir().join(".mbf_model_tmp")
}

fn unique_stem(label: &str, suffix: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(label.as_bytes());
    hasher.update(suffix.as_bytes());
    hasher.update(process::id().to_string().as_bytes());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_nanos()
        .to_string();
    hasher.update(now.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn normalized_model_trace(trace: &TraceData) -> TraceData {
    let mut model_trace = trace.clone();
    model_trace.required_containers = 0;
    model_trace.reporter_states.clear();
    model_trace.expected_state = None;
    model_trace
}

fn encoder_config(trace: &TraceData) -> encoder::EncoderConfig {
    encoder::EncoderConfig {
        n: trace.n,
        faults: trace.faults,
        epoch: trace.epoch,
        max_view: trace.max_view,
        required_containers: 0,
    }
}

fn run_quint_test_module(
    label: &str,
    suffix: &str,
    qnt_source: &str,
    itf_output: Option<&Path>,
) -> Result<(), ModelError> {
    let temp_dir = temp_dir();
    fs::create_dir_all(&temp_dir)
        .map_err(|e| ModelError::new(format!("failed to create {}: {e}", temp_dir.display())))?;

    let stem = unique_stem(label, suffix);
    let qnt_path = temp_dir.join(format!("{stem}.qnt"));

    fs::write(&qnt_path, qnt_source)
        .map_err(|e| ModelError::new(format!("failed to write {}: {e}", qnt_path.display())))?;

    let mut command = Command::new("quint");
    command
        .current_dir(quint_dir())
        .env("NODE_OPTIONS", "--max-old-space-size=8192")
        .args([
            "test",
            "--main=tests",
            "--backend=rust",
            "--max-samples=1",
            "--match=traceTest",
        ]);
    if let Some(itf_path) = itf_output {
        command.arg(format!(
            "--out-itf={}",
            itf_path.to_str().expect("utf8 itf path")
        ));
    }
    command.arg(qnt_path.to_str().expect("utf8 qnt path"));

    let output = command.output().map_err(|e| {
        ModelError::new(format!(
            "failed to run quint for {} [{}]: {e}",
            label,
            suffix,
        ))
    })?;

    let _ = fs::remove_file(&qnt_path);
    if let Some(itf) = itf_output {
        // ITF cleanup is handled by caller after reading the file
        if !output.status.success() {
            let _ = fs::remove_file(itf);
        }
    }
    let _ = fs::remove_dir(&temp_dir);

    if !output.status.success() {
        let mut message = format!(
            "quint test failed for {} [{}] (exit {})",
            label,
            suffix,
            output.status.code().unwrap_or(-1)
        );
        if !output.stdout.is_empty() {
            message.push_str("\n--- quint stdout ---\n");
            message.push_str(&String::from_utf8_lossy(&output.stdout));
        }
        if !output.stderr.is_empty() {
            message.push_str("\n--- quint stderr ---\n");
            message.push_str(&String::from_utf8_lossy(&output.stderr));
        }
        return Err(ModelError::new(message));
    }
    Ok(())
}

fn validate_replica_trace_with_itf(
    trace: &TraceData,
    label: &str,
    itf_path: &Path,
) -> Result<(), ModelError> {
    let cfg = encoder_config(trace);
    let qnt = encoder::encode(trace, &cfg);
    run_quint_test_module(label, "replica", &qnt, Some(itf_path))
}

/// Validates the trace against `replica.qnt` and extracts expected state
/// from the ITF output.
pub fn validate_and_extract_expected(
    trace: &TraceData,
    label: &str,
) -> Result<Option<ExpectedState>, ModelError> {
    let model_trace = normalized_model_trace(trace);

    // Validate against replica.qnt with ITF output
    let td = temp_dir();
    fs::create_dir_all(&td)
        .map_err(|e| ModelError::new(format!("failed to create {}: {e}", td.display())))?;
    let stem = unique_stem(label, "itf");
    let itf_path = td.join(format!("{stem}.itf.json"));

    validate_replica_trace_with_itf(&model_trace, label, &itf_path)?;

    // Parse the ITF file and extract expected state
    let expected = match fs::read_to_string(&itf_path) {
        Ok(itf_json) => {
            let _ = fs::remove_file(&itf_path);
            let _ = fs::remove_dir(&td);
            parse_itf_expected_state(&itf_json, trace)?
        }
        Err(e) => {
            let _ = fs::remove_file(&itf_path);
            let _ = fs::remove_dir(&td);
            return Err(ModelError::new(format!(
                "failed to read ITF output for {label}: {e}"
            )));
        }
    };

    Ok(Some(expected))
}

fn parse_itf_expected_state(
    itf_json: &str,
    trace: &TraceData,
) -> Result<ExpectedState, ModelError> {
    let itf: serde_json::Value = serde_json::from_str(itf_json)
        .map_err(|e| ModelError::new(format!("failed to parse ITF JSON: {e}")))?;

    let states = itf["states"]
        .as_array()
        .ok_or_else(|| ModelError::new("ITF JSON missing 'states' array".to_string()))?;

    let final_state = states
        .last()
        .ok_or_else(|| ModelError::new("ITF 'states' array is empty".to_string()))?;

    // Build block map: invert encoder::build_block_map to get name -> hex
    let block_pairs = encoder::build_block_map(trace);
    let block_map: HashMap<String, String> = block_pairs
        .into_iter()
        .map(|(hash, name)| (name, hash))
        .collect();

    let correct_nodes = decoder::identify_correct_nodes(final_state);
    Ok(decoder::extract_expected_state(
        final_state,
        &correct_nodes,
        &block_map,
    ))
}

// ---------------------------------------------------------------------------
// Canonical (Trace-native) validation path
// ---------------------------------------------------------------------------

/// Validates a canonical [`Trace`] against `replica.qnt` and extracts
/// expected state from the ITF output as a [`Snapshot`].
///
/// Mirrors [`validate_and_extract_expected`] but takes the canonical
/// [`Trace`] type throughout: encodes via
/// [`encoder::encode_from_trace`], parses the ITF via the shared
/// [`decoder::extract_expected_state`] (which is already TraceData-free),
/// and converts the resulting [`ExpectedState`] into a
/// [`Snapshot`] keyed by [`Participant`].
pub fn validate_and_extract_expected_canonical(
    trace: &Trace,
    label: &str,
) -> Result<Option<Snapshot>, ModelError> {
    let qnt = encoder::encode_from_trace(trace, 0);

    let td = temp_dir();
    fs::create_dir_all(&td)
        .map_err(|e| ModelError::new(format!("failed to create {}: {e}", td.display())))?;
    let stem = unique_stem(label, "itf_canonical");
    let itf_path = td.join(format!("{stem}.itf.json"));

    run_quint_test_module(label, "canonical_replica", &qnt, Some(&itf_path))?;

    let itf_json = match fs::read_to_string(&itf_path) {
        Ok(s) => {
            let _ = fs::remove_file(&itf_path);
            let _ = fs::remove_dir(&td);
            s
        }
        Err(e) => {
            let _ = fs::remove_file(&itf_path);
            let _ = fs::remove_dir(&td);
            return Err(ModelError::new(format!(
                "failed to read ITF output for {label}: {e}"
            )));
        }
    };

    let itf: serde_json::Value = serde_json::from_str(&itf_json)
        .map_err(|e| ModelError::new(format!("failed to parse ITF JSON: {e}")))?;

    let states = itf["states"]
        .as_array()
        .ok_or_else(|| ModelError::new("ITF JSON missing 'states' array".to_string()))?;
    let final_state = states
        .last()
        .ok_or_else(|| ModelError::new("ITF 'states' array is empty".to_string()))?;

    // Build block map: encoder produces (hex, "val_bN") pairs; invert.
    let block_pairs = encoder::build_block_map_from_events(&trace.events);
    let block_map: HashMap<String, String> = block_pairs
        .into_iter()
        .map(|(hash, name)| (name, hash))
        .collect();

    let correct_nodes = decoder::identify_correct_nodes(final_state);
    let expected = decoder::extract_expected_state(final_state, &correct_nodes, &block_map);

    let snapshot = expected_state_to_snapshot(&expected)?;
    Ok(Some(snapshot))
}

/// Converts the Quint-level [`ExpectedState`] (keyed by `"nX"` strings
/// with hex payloads) into a [`Snapshot`] keyed by [`Participant`] with
/// typed payload digests. Returns `ModelError` if any payload hex is
/// malformed or any node ID is not the expected `"nN"` shape.
pub fn expected_state_to_snapshot(es: &ExpectedState) -> Result<Snapshot, ModelError> {
    let mut nodes: BTreeMap<Participant, NodeSnapshot> = BTreeMap::new();
    for (id, ns) in &es.nodes {
        let participant = node_id_to_participant(id)?;
        let snap = node_state_to_node_snapshot(ns)?;
        nodes.insert(participant, snap);
    }
    Ok(Snapshot { nodes })
}

fn node_state_to_node_snapshot(ns: &ExpectedNodeState) -> Result<NodeSnapshot, ModelError> {
    let notarizations = cert_map_to_snapshot(
        &ns.notarizations,
        &ns.notarization_signature_counts,
        "notarization",
    )?;
    let finalizations = cert_map_to_snapshot(
        &ns.finalizations,
        &ns.finalization_signature_counts,
        "finalization",
    )?;
    let nullifications: BTreeMap<View, NullStateSnapshot> = ns
        .nullifications
        .iter()
        .map(|view| {
            let signature_count = ns
                .nullification_signature_counts
                .get(view)
                .copied()
                .flatten()
                .map(|c| c as u32);
            (View::new(*view), NullStateSnapshot { signature_count })
        })
        .collect();
    let certified: BTreeSet<View> = ns.certified.iter().copied().map(View::new).collect();
    let notarize_signers = signer_map_to_snapshot(&ns.notarize_signers)?;
    let nullify_signers = signer_map_to_snapshot(&ns.nullify_signers)?;
    let finalize_signers = signer_map_to_snapshot(&ns.finalize_signers)?;
    Ok(NodeSnapshot {
        notarizations,
        nullifications,
        finalizations,
        certified,
        notarize_signers,
        nullify_signers,
        finalize_signers,
        last_finalized: View::new(ns.last_finalized),
    })
}

fn cert_map_to_snapshot(
    payloads: &BTreeMap<u64, String>,
    sig_counts: &BTreeMap<u64, Option<usize>>,
    kind: &'static str,
) -> Result<BTreeMap<View, CertStateSnapshot>, ModelError> {
    let mut out = BTreeMap::new();
    for (view, hex) in payloads {
        let payload = hex_to_digest(hex).map_err(|e| {
            ModelError::new(format!("invalid {kind} payload hex at view {view}: {e}"))
        })?;
        let signature_count = sig_counts
            .get(view)
            .copied()
            .flatten()
            .map(|c| c as u32);
        out.insert(
            View::new(*view),
            CertStateSnapshot {
                payload,
                signature_count,
            },
        );
    }
    Ok(out)
}

fn signer_map_to_snapshot(
    in_map: &BTreeMap<u64, BTreeSet<String>>,
) -> Result<BTreeMap<View, BTreeSet<Participant>>, ModelError> {
    let mut out: BTreeMap<View, BTreeSet<Participant>> = BTreeMap::new();
    for (view, signers) in in_map {
        let mut set = BTreeSet::new();
        for s in signers {
            set.insert(node_id_to_participant(s)?);
        }
        out.insert(View::new(*view), set);
    }
    Ok(out)
}

fn node_id_to_participant(id: &str) -> Result<Participant, ModelError> {
    let idx_str = id
        .strip_prefix('n')
        .ok_or_else(|| ModelError::new(format!("node id '{id}' missing 'n' prefix")))?;
    let idx: u32 = idx_str
        .parse()
        .map_err(|e| ModelError::new(format!("node id '{id}' not a u32: {e}")))?;
    Ok(Participant::new(idx))
}

const DIGEST_BYTES: usize = 32;

fn hex_to_digest(hex: &str) -> Result<Sha256Digest, String> {
    if hex.len() != DIGEST_BYTES * 2 {
        return Err(format!(
            "expected {} hex chars, got {}",
            DIGEST_BYTES * 2,
            hex.len()
        ));
    }
    let mut bytes = [0u8; DIGEST_BYTES];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let pair = &hex[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|e| format!("invalid hex pair '{pair}' at offset {i}: {e}"))?;
    }
    Ok(Sha256Digest::from(bytes))
}

#[cfg(test)]
mod canonical_validation_tests {
    use super::*;
    use commonware_consensus::simplex::replay::Trace;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("src/simplex/replay/fixtures/strict")
    }

    #[test]
    fn validate_and_extract_expected_canonical_on_honest_fixture() {
        if std::env::var("SKIP_QUINT_TESTS").is_ok() {
            return;
        }
        let dir = fixtures_dir();
        if !dir.exists() {
            // Fixture dir is optional in non-replay builds.
            return;
        }
        let path = dir.join("honest_n4_f0_c3.json");
        if !path.exists() {
            return;
        }
        let json = fs::read_to_string(&path).expect("read fixture");
        let trace = Trace::from_json(&json).expect("parse canonical trace");
        let expected =
            validate_and_extract_expected_canonical(&trace, "canonical_sanity")
                .expect("validate + extract");
        let snap = expected.expect("non-empty snapshot");
        assert!(!snap.nodes.is_empty(), "snapshot should have nodes");
    }
}

