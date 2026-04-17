//! [`Trace`] <-> Quint `replica.qnt` bridge.
//!
//! Given a [`Trace`], encode it as a Quint test module
//! ([`crate::tracing::encoder::encode_from_trace`]), drive `quint test` with
//! ITF output, then parse the resulting ITF final state into a
//! [`Snapshot`] keyed by [`Participant`].

use commonware_consensus::{
    simplex::replay::{
        trace::{CertStateSnapshot, NodeSnapshot, NullStateSnapshot, Snapshot},
        Trace,
    },
    types::View,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_utils::Participant;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

use crate::tracing::encoder;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ExpectedState (decoded ITF view, keyed by Quint node string)
// ---------------------------------------------------------------------------

/// Observable state from the Quint model for a single correct node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedNodeState {
    /// Views that have been notarized, mapped to block hex digest.
    pub notarizations: BTreeMap<u64, String>,
    /// Views that have been nullified.
    pub nullifications: BTreeSet<u64>,
    /// Views that have been finalized, mapped to block hex digest.
    pub finalizations: BTreeMap<u64, String>,
    /// Expected visible certificate signer counts per view.
    #[serde(default)]
    pub notarization_signature_counts: BTreeMap<u64, Option<usize>>,
    #[serde(default)]
    pub nullification_signature_counts: BTreeMap<u64, Option<usize>>,
    #[serde(default)]
    pub finalization_signature_counts: BTreeMap<u64, Option<usize>>,
    /// The last finalized view.
    pub last_finalized: u64,
    /// Views for which the replica observed any certificate.
    #[serde(default)]
    pub certified: BTreeSet<u64>,
    /// Per-view set of node IDs that sent notarize votes to this node.
    #[serde(default)]
    pub notarize_signers: BTreeMap<u64, BTreeSet<String>>,
    /// Per-view set of node IDs that sent nullify votes to this node.
    #[serde(default)]
    pub nullify_signers: BTreeMap<u64, BTreeSet<String>>,
    /// Per-view set of node IDs that sent finalize votes to this node.
    #[serde(default)]
    pub finalize_signers: BTreeMap<u64, BTreeSet<String>>,
}

/// Expected observable state from the Quint model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedState {
    /// Per correct node expected state, keyed by node ID (e.g. "n1", "n2").
    pub nodes: BTreeMap<String, ExpectedNodeState>,
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Quint test driver
// ---------------------------------------------------------------------------

pub fn run_quint_test_module(
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
            label, suffix,
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

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Validates a [`Trace`] against `replica.qnt` and extracts
/// expected state from the ITF output as a [`Snapshot`].
pub fn validate_and_extract_expected(
    trace: &Trace,
    label: &str,
) -> Result<Option<Snapshot>, ModelError> {
    let qnt = encoder::encode_from_trace(trace, 0);

    let td = temp_dir();
    fs::create_dir_all(&td)
        .map_err(|e| ModelError::new(format!("failed to create {}: {e}", td.display())))?;
    let stem = unique_stem(label, "itf");
    let itf_path = td.join(format!("{stem}.itf.json"));

    run_quint_test_module(label, "replica", &qnt, Some(&itf_path))?;

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

    let itf: Value = serde_json::from_str(&itf_json)
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

    let correct_nodes = identify_correct_nodes(final_state);
    let expected = extract_expected_state(final_state, &correct_nodes, &block_map);

    let snapshot = expected_state_to_snapshot(&expected)?;
    Ok(Some(snapshot))
}

// ---------------------------------------------------------------------------
// Snapshot conversion
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ITF parsing helpers
// ---------------------------------------------------------------------------

/// Looks up a state variable by suffix in an ITF state object.
/// ITF variables may be qualified (e.g. `itf_main::r::store_vote`),
/// so we match by the trailing `::suffix` or exact name.
fn get_var<'a>(state: &'a Value, suffix: &str) -> &'a Value {
    if let Value::Object(obj) = state {
        if let Some(v) = obj.get(suffix) {
            return v;
        }
        let pattern = format!("::{suffix}");
        for (key, val) in obj {
            if key.ends_with(&pattern) || key == suffix {
                return val;
            }
        }
    }
    &Value::Null
}

/// Parses an ITF-encoded integer (JSON number or `{"#bigint": "N"}`).
fn parse_int(v: &Value) -> u64 {
    match v {
        Value::Number(n) => n.as_u64().unwrap_or(0),
        Value::Object(obj) => {
            if let Some(s) = obj.get("#bigint").and_then(|v| v.as_str()) {
                s.parse().unwrap_or(0)
            } else {
                0
            }
        }
        _ => 0,
    }
}

/// Parses an ITF-encoded set (`{"#set": [...]}`).
fn parse_set(v: &Value) -> Vec<&Value> {
    match v {
        Value::Object(obj) => obj
            .get("#set")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().collect())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Parses an ITF-encoded map (`{"#map": [[k, v], ...]}`).
fn parse_map(v: &Value) -> Vec<(&Value, &Value)> {
    match v {
        Value::Object(obj) => obj
            .get("#map")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|pair| {
                        let a = pair.as_array()?;
                        if a.len() >= 2 {
                            Some((&a[0], &a[1]))
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Identifies the correct node set from the ITF state.
/// Correct nodes are those with entries in `replica_state`.
pub fn identify_correct_nodes(state: &Value) -> Vec<String> {
    let mut nodes: Vec<String> = parse_map(get_var(state, "replica_state"))
        .iter()
        .filter_map(|(k, _)| k.as_str().map(String::from))
        .collect();
    nodes.sort();
    nodes
}

/// Collects the per-node certificate store from the ITF state.
///
/// Reads the current split name `store_certificates` (plural); also
/// accepts the legacy monolithic name `store_certificate` if a fixture
/// predates the split. Values are already variant-tagged in ITF
/// (`{"tag":"Notarization"|"Nullification"|"Finalization","value":…}`).
fn collect_store_certificate(state: &Value) -> HashMap<String, Vec<Value>> {
    let mut out: HashMap<String, Vec<Value>> = HashMap::new();
    for name in &["store_certificates", "store_certificate"] {
        let map_val = get_var(state, name);
        if map_val.is_null() {
            continue;
        }
        for (k, v) in parse_map(map_val) {
            let Some(node) = k.as_str() else { continue };
            let certs = parse_set(v);
            out.entry(node.to_string())
                .or_default()
                .extend(certs.into_iter().cloned());
        }
    }
    out
}

/// Collects the per-node vote store from the ITF state, keyed by node
/// ID. Reads the current split maps `store_notarize_votes`,
/// `store_nullify_votes`, `store_finalize_votes` (values are untagged
/// votes and get tagged here so downstream code sees the same
/// `{"tag":"Notarize|Nullify|Finalize","value":…}` shape `sent_*`
/// extraction produces); also accepts the legacy monolithic
/// `store_vote` map whose values were already variant-tagged.
fn collect_store_vote(state: &Value) -> HashMap<String, Vec<Value>> {
    let mut out: HashMap<String, Vec<Value>> = HashMap::new();
    // Legacy monolithic map: values are already tagged.
    let legacy = get_var(state, "store_vote");
    if !legacy.is_null() {
        for (k, v) in parse_map(legacy) {
            let Some(node) = k.as_str() else { continue };
            let votes = parse_set(v);
            out.entry(node.to_string())
                .or_default()
                .extend(votes.into_iter().cloned());
        }
    }
    // Split maps: tag each vote with its kind to match the shape
    // `insert_vote_signer` expects.
    for (name, tag) in [
        ("store_notarize_votes", "Notarize"),
        ("store_nullify_votes", "Nullify"),
        ("store_finalize_votes", "Finalize"),
    ] {
        let map_val = get_var(state, name);
        if map_val.is_null() {
            continue;
        }
        for (k, v) in parse_map(map_val) {
            let Some(node) = k.as_str() else { continue };
            let votes = parse_set(v);
            let entry = out.entry(node.to_string()).or_default();
            for vote in votes {
                entry.push(serde_json::json!({ "tag": tag, "value": vote.clone() }));
            }
        }
    }
    out
}

/// Collects the `sent_vote` (or union of `sent_notarize_votes`,
/// `sent_nullify_votes`, `sent_finalize_votes`) as a flat vector of
/// tagged vote values.
fn collect_sent_vote(state: &Value) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    // Legacy monolithic set.
    let legacy = get_var(state, "sent_vote");
    if !legacy.is_null() {
        for v in parse_set(legacy) {
            out.push(v.clone());
        }
    }
    // New split sets. Tag each with its variant so downstream matches
    // the `{"tag": "Notarize", ...}` shape the store uses.
    for (suffix, tag) in [
        ("sent_notarize_votes", "Notarize"),
        ("sent_nullify_votes", "Nullify"),
        ("sent_finalize_votes", "Finalize"),
    ] {
        let set_val = get_var(state, suffix);
        if set_val.is_null() {
            continue;
        }
        for v in parse_set(set_val) {
            out.push(serde_json::json!({ "tag": tag, "value": v.clone() }));
        }
    }
    out
}

/// Extracts expected observable state from the final ITF state.
pub fn extract_expected_state(
    state: &Value,
    correct_nodes: &[String],
    block_map: &HashMap<String, String>,
) -> ExpectedState {
    let store_cert_map = collect_store_certificate(state);
    let store_vote_map = collect_store_vote(state);
    let sent_votes = collect_sent_vote(state);
    let replica_state_entries = parse_map(get_var(state, "replica_state"));

    let mut nodes: BTreeMap<String, ExpectedNodeState> = BTreeMap::new();
    for node in correct_nodes {
        let mut notarizations: BTreeMap<u64, String> = BTreeMap::new();
        let mut notarization_signature_counts: BTreeMap<u64, Option<usize>> = BTreeMap::new();
        let mut nullifications: BTreeSet<u64> = BTreeSet::new();
        let mut nullification_signature_counts: BTreeMap<u64, Option<usize>> = BTreeMap::new();
        let mut finalizations: BTreeMap<u64, String> = BTreeMap::new();
        let mut finalization_signature_counts: BTreeMap<u64, Option<usize>> = BTreeMap::new();

        if let Some(certs) = store_cert_map.get(node) {
            for cert_val in certs {
                let Some(tag) = cert_val.get("tag").and_then(|t| t.as_str()) else {
                    continue;
                };
                let Some(inner) = cert_val.get("value") else {
                    continue;
                };
                match tag {
                    "Notarization" => {
                        let view = parse_int(
                            inner
                                .get("proposal")
                                .map(|proposal| &proposal["view"])
                                .unwrap_or(&inner["view"]),
                        );
                        let block_name = inner
                            .get("proposal")
                            .and_then(|proposal| proposal["payload"].as_str())
                            .or_else(|| inner["block"].as_str())
                            .unwrap_or("");
                        let hex = block_map.get(block_name).cloned().unwrap_or_default();
                        let signature_count = parse_set(&inner["signatures"]).len();
                        notarizations.insert(view, hex);
                        // Multiple notarization certs for the same
                        // view can appear in `store_certificates` under
                        // equivocation or future-Byzantine scenarios.
                        // Pick the MAX signer count as the canonical
                        // representative.
                        let existing = notarization_signature_counts
                            .get(&view)
                            .copied()
                            .flatten()
                            .unwrap_or(0);
                        notarization_signature_counts
                            .insert(view, Some(signature_count.max(existing)));
                    }
                    "Nullification" => {
                        let view = parse_int(&inner["view"]);
                        let signature_count = parse_set(&inner["signatures"]).len();
                        nullifications.insert(view);
                        let existing = nullification_signature_counts
                            .get(&view)
                            .copied()
                            .flatten()
                            .unwrap_or(0);
                        nullification_signature_counts
                            .insert(view, Some(signature_count.max(existing)));
                    }
                    "Finalization" => {
                        let view = parse_int(
                            inner
                                .get("proposal")
                                .map(|proposal| &proposal["view"])
                                .unwrap_or(&inner["view"]),
                        );
                        let block_name = inner
                            .get("proposal")
                            .and_then(|proposal| proposal["payload"].as_str())
                            .or_else(|| inner["block"].as_str())
                            .unwrap_or("");
                        let hex = block_map.get(block_name).cloned().unwrap_or_default();
                        let signature_count = parse_set(&inner["signatures"]).len();
                        finalizations.insert(view, hex);
                        let existing = finalization_signature_counts
                            .get(&view)
                            .copied()
                            .flatten()
                            .unwrap_or(0);
                        finalization_signature_counts
                            .insert(view, Some(signature_count.max(existing)));
                    }
                    _ => {}
                }
            }
        }

        let certified: BTreeSet<u64> = notarizations
            .keys()
            .copied()
            .chain(nullifications.iter().copied())
            .chain(finalizations.keys().copied())
            .collect();

        let last_finalized = replica_state_entries
            .iter()
            .find(|(k, _)| k.as_str() == Some(node.as_str()))
            .map(|(_, v)| parse_int(&v["last_finalized"]))
            .unwrap_or(0);

        // Extract vote signers from store_vote + sent_vote
        let (notarize_signers, nullify_signers, finalize_signers) =
            extract_vote_signers(&store_vote_map, &sent_votes, node);

        nodes.insert(
            node.clone(),
            ExpectedNodeState {
                notarizations,
                notarization_signature_counts,
                nullifications,
                nullification_signature_counts,
                finalizations,
                finalization_signature_counts,
                last_finalized,
                certified,
                notarize_signers,
                nullify_signers,
                finalize_signers,
            },
        );
    }

    ExpectedState { nodes }
}

/// For a given node `nid`, collects the per-view sender sets of notarize,
/// nullify, and finalize votes observed in the node's local `store_vote`
/// plus the global `sent_vote` (votes sent by `nid` itself).
fn extract_vote_signers(
    store_vote_map: &HashMap<String, Vec<Value>>,
    sent_votes: &[Value],
    nid: &str,
) -> (
    BTreeMap<u64, BTreeSet<String>>,
    BTreeMap<u64, BTreeSet<String>>,
    BTreeMap<u64, BTreeSet<String>>,
) {
    let mut notarize: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    let mut nullify: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    let mut finalize: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();

    let empty_store: Vec<Value> = Vec::new();
    let local_store = store_vote_map.get(nid).unwrap_or(&empty_store);
    for vote in local_store {
        insert_vote_signer(vote, &mut notarize, &mut nullify, &mut finalize);
    }

    // The monolithic sent_vote set (if any) contains the sender's own
    // broadcasts. For views where the sender is `nid`, treat the vote as
    // coming from `nid` itself.
    for vote in sent_votes {
        let Some(sig) = vote
            .get("value")
            .and_then(|v| v.get("sig"))
            .and_then(|s| s.as_str())
            .or_else(|| {
                vote.get("value")
                    .and_then(|v| v.get("signature"))
                    .and_then(|s| s.as_str())
            })
        else {
            continue;
        };
        if sig != nid {
            continue;
        }
        insert_vote_signer(vote, &mut notarize, &mut nullify, &mut finalize);
    }
    (notarize, nullify, finalize)
}

fn insert_vote_signer(
    vote: &Value,
    notarize: &mut BTreeMap<u64, BTreeSet<String>>,
    nullify: &mut BTreeMap<u64, BTreeSet<String>>,
    finalize: &mut BTreeMap<u64, BTreeSet<String>>,
) {
    let Some(tag) = vote.get("tag").and_then(|t| t.as_str()) else {
        return;
    };
    let Some(inner) = vote.get("value") else {
        return;
    };
    let Some(sig) = inner
        .get("sig")
        .and_then(|s| s.as_str())
        .or_else(|| inner.get("signature").and_then(|s| s.as_str()))
    else {
        return;
    };
    let sig = sig.to_string();
    match tag {
        "Notarize" => {
            let view = parse_int(
                inner
                    .get("proposal")
                    .map(|proposal| &proposal["view"])
                    .unwrap_or(&inner["view"]),
            );
            notarize.entry(view).or_default().insert(sig);
        }
        "Nullify" => {
            let view = parse_int(&inner["view"]);
            nullify.entry(view).or_default().insert(sig);
        }
        "Finalize" => {
            let view = parse_int(
                inner
                    .get("proposal")
                    .map(|proposal| &proposal["view"])
                    .unwrap_or(&inner["view"]),
            );
            finalize.entry(view).or_default().insert(sig);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod validation_tests {
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
            return;
        }
        let path = dir.join("honest_n4_f0_c3.json");
        if !path.exists() {
            return;
        }
        let json = fs::read_to_string(&path).expect("read fixture");
        let trace = Trace::from_json(&json).expect("parse trace");
        let expected = validate_and_extract_expected(&trace, "sanity")
            .expect("validate + extract");
        let snap = expected.expect("non-empty snapshot");
        assert!(!snap.nodes.is_empty(), "snapshot should have nodes");
    }
}
