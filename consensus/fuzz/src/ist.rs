//! Interactive Symbolic Testing (IST) for Simplex consensus.
//!
//! Uses Apalache's SMT solver to generate transitions on-the-fly, then
//! immediately replays each step's messages into Rust engines and compares
//! observable state against Apalache's expected state.
//!
//! # Interactive Architecture
//!
//! A single loop alternates between:
//! 1. Driving Apalache to pick an enabled transition (blocking HTTP)
//! 2. Extracting new messages from the state diff
//! 3. Injecting messages into Rust engines
//! 4. Comparing observable state against Apalache's expected state
//!
//! Blocking HTTP inside the deterministic runtime is safe because:
//! - The runtime is single-threaded; blocking HTTP blocks the thread
//! - The event loop does not check liveness while a task is polled
//! - Engines are idle during HTTP calls (nothing to process)
//! - Between HTTP calls, `context.sleep()` yields to let engines process

use crate::{
    apalache::{ApalacheClient, TransitionStatus},
    config::ForwardingPolicy,
    invariants,
    quint_model::{extract_expected_state, identify_correct_nodes, ExpectedState},
    types::ReplayedReplicaState,
};
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::{
        config,
        elector::RoundRobin,
        mocks::{application, relay, reporter},
        replay::injected::{self, NullBlocker, NullSender, PendingReceiver},
        scheme::ed25519,
        types::{
            Certificate, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify,
            Proposal, Vote,
        },
        Engine,
    },
    types::{Delta, Epoch as EpochType, Round, View},
};
use commonware_cryptography::{
    certificate::mocks::Fixture,
    ed25519::PublicKey,
    sha256::{Digest as Sha256Digest, Sha256 as Sha256Hasher},
    Hasher, Sha256,
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Clock, IoBuf, Metrics, Runner};
use commonware_utils::{NZUsize, NZU16};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    num::{NonZeroU16, NonZeroUsize},
    process::Command,
    sync::Arc,
    time::Duration,
};

const NAMESPACE: &[u8] = b"consensus_fuzz";
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

type S = ed25519::Scheme;

/// Errors from IST execution.
#[derive(Debug)]
pub enum Error {
    Apalache(crate::apalache::Error),
    Quint(String),
    Setup(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Apalache(e) => write!(f, "apalache: {e}"),
            Error::Quint(e) => write!(f, "quint compile: {e}"),
            Error::Setup(e) => write!(f, "setup: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<crate::apalache::Error> for Error {
    fn from(e: crate::apalache::Error) -> Self {
        Error::Apalache(e)
    }
}

// ---------------------------------------------------------------------------
// ITF decode helpers (inlined from the retired tracing::decoder module)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum TracedVote {
    Notarize {
        view: u64,
        parent: u64,
        sig: String,
        block: String,
    },
    Nullify {
        view: u64,
        #[allow(dead_code)]
        sig: String,
    },
    Finalize {
        view: u64,
        parent: u64,
        sig: String,
        block: String,
    },
}

#[derive(Clone, Debug)]
enum TracedCert {
    Notarization {
        view: u64,
        parent: u64,
        block: String,
        signers: Vec<String>,
        ghost_sender: String,
    },
    Nullification {
        view: u64,
        signers: Vec<String>,
        ghost_sender: String,
    },
    Finalization {
        view: u64,
        parent: u64,
        block: String,
        signers: Vec<String>,
        ghost_sender: String,
    },
}

#[derive(Clone, Debug)]
enum TraceEntry {
    Vote {
        sender: String,
        receiver: String,
        vote: TracedVote,
    },
    Certificate {
        #[allow(dead_code)]
        sender: String,
        receiver: String,
        cert: TracedCert,
    },
}

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

fn block_to_hex(name: &str, map: &mut HashMap<String, String>) -> String {
    if let Some(hex) = map.get(name) {
        return hex.clone();
    }
    let hash = Sha256::hash(name.as_bytes());
    let bytes: &[u8] = hash.as_ref();
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    map.insert(name.to_string(), hex.clone());
    hex
}

fn extract_leader_map(state: &Value) -> BTreeMap<u64, String> {
    let mut map = BTreeMap::new();
    for (k, v) in parse_map(get_var(state, "leader")) {
        let view = parse_int(k);
        if let Some(node) = v.as_str() {
            map.insert(view, node.to_string());
        }
    }
    map
}

fn compute_epoch(leader_map: &BTreeMap<u64, String>, n: usize) -> Result<u64, String> {
    let (&first_view, first_leader) = leader_map
        .iter()
        .find(|(&v, _)| v >= 1)
        .ok_or_else(|| "leader map is not round-robin; cannot compute epoch".to_string())?;
    let leader_idx = first_leader
        .strip_prefix('n')
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| format!("invalid node ID: {first_leader}"))?;
    let n64 = n as u64;
    let epoch = (leader_idx + n64 - (first_view % n64)) % n64;
    for (&view, leader) in leader_map {
        if view == 0 {
            continue;
        }
        let expected_idx = (epoch + view) % n64;
        let expected = format!("n{expected_idx}");
        if leader != &expected {
            return Err("leader map is not round-robin; cannot compute epoch".to_string());
        }
    }
    Ok(epoch)
}

fn count_nodes(state: &Value) -> usize {
    let mut all_nodes: BTreeSet<String> = BTreeSet::new();
    for (_, v) in parse_map(get_var(state, "leader")) {
        if let Some(node) = v.as_str() {
            all_nodes.insert(node.to_string());
        }
    }
    let legacy_store_vote = get_var(state, "store_vote");
    if !legacy_store_vote.is_null() {
        for (k, _) in parse_map(legacy_store_vote) {
            if let Some(node) = k.as_str() {
                all_nodes.insert(node.to_string());
            }
        }
        return all_nodes.len();
    }
    for var_name in [
        "store_notarize_votes",
        "store_nullify_votes",
        "store_finalize_votes",
    ] {
        for (k, _) in parse_map(get_var(state, var_name)) {
            if let Some(node) = k.as_str() {
                all_nodes.insert(node.to_string());
            }
        }
    }
    all_nodes.len()
}

fn wrap_tagged_value(tag: &str, value: &Value) -> Value {
    json!({ "tag": tag, "value": value.clone() })
}

fn collect_typed_vote_store(
    state: &Value,
    var_name: &str,
    tag: &str,
    result: &mut HashMap<String, Vec<Value>>,
) {
    for (k, v) in parse_map(get_var(state, var_name)) {
        if let Some(node) = k.as_str() {
            let votes = result.entry(node.to_string()).or_default();
            votes.extend(
                parse_set(v)
                    .into_iter()
                    .map(|vote| wrap_tagged_value(tag, vote)),
            );
        }
    }
}

fn collect_store_vote(state: &Value) -> HashMap<String, Vec<Value>> {
    let mut result = HashMap::new();
    let legacy_store_vote = get_var(state, "store_vote");
    if !legacy_store_vote.is_null() {
        for (k, v) in parse_map(legacy_store_vote) {
            if let Some(node) = k.as_str() {
                let votes: Vec<Value> = parse_set(v).into_iter().cloned().collect();
                result.insert(node.to_string(), votes);
            }
        }
        return result;
    }
    collect_typed_vote_store(state, "store_notarize_votes", "Notarize", &mut result);
    collect_typed_vote_store(state, "store_nullify_votes", "Nullify", &mut result);
    collect_typed_vote_store(state, "store_finalize_votes", "Finalize", &mut result);
    result
}

fn collect_store_certificate(state: &Value) -> HashMap<String, Vec<Value>> {
    let mut result = HashMap::new();
    let cert_var = if get_var(state, "store_certificates").is_null() {
        "store_certificate"
    } else {
        "store_certificates"
    };
    for (k, v) in parse_map(get_var(state, cert_var)) {
        if let Some(node) = k.as_str() {
            let certs: Vec<Value> = parse_set(v).into_iter().cloned().collect();
            result.insert(node.to_string(), certs);
        }
    }
    result
}

fn parse_itf_vote(v: &Value, block_map: &mut HashMap<String, String>) -> Option<TracedVote> {
    let tag = v.get("tag")?.as_str()?;
    let inner = v.get("value")?;
    match tag {
        "Notarize" => {
            let proposal = inner.get("proposal");
            let view = parse_int(proposal.map(|p| &p["view"]).unwrap_or(&inner["view"]));
            let parent = proposal.map(|p| parse_int(&p["parent"])).unwrap_or(0);
            let sig = inner["sig"].as_str()?.to_string();
            let block_name = proposal
                .and_then(|p| p["payload"].as_str())
                .or_else(|| inner["block"].as_str())?;
            let block = block_to_hex(block_name, block_map);
            Some(TracedVote::Notarize {
                view,
                parent,
                sig,
                block,
            })
        }
        "Nullify" => {
            let view = parse_int(&inner["view"]);
            let sig = inner["sig"].as_str()?.to_string();
            Some(TracedVote::Nullify { view, sig })
        }
        "Finalize" => {
            let proposal = inner.get("proposal");
            let view = parse_int(proposal.map(|p| &p["view"]).unwrap_or(&inner["view"]));
            let parent = proposal.map(|p| parse_int(&p["parent"])).unwrap_or(0);
            let sig = inner["sig"].as_str()?.to_string();
            let block_name = proposal
                .and_then(|p| p["payload"].as_str())
                .or_else(|| inner["block"].as_str())?;
            let block = block_to_hex(block_name, block_map);
            Some(TracedVote::Finalize {
                view,
                parent,
                sig,
                block,
            })
        }
        _ => None,
    }
}

fn parse_itf_cert(v: &Value, block_map: &mut HashMap<String, String>) -> Option<TracedCert> {
    let tag = v.get("tag")?.as_str()?;
    let inner = v.get("value")?;
    match tag {
        "Notarization" => {
            let proposal = inner.get("proposal");
            let view = parse_int(proposal.map(|p| &p["view"]).unwrap_or(&inner["view"]));
            let parent = proposal.map(|p| parse_int(&p["parent"])).unwrap_or(0);
            let block_name = proposal
                .and_then(|p| p["payload"].as_str())
                .or_else(|| inner["block"].as_str())?;
            let block = block_to_hex(block_name, block_map);
            let signers: Vec<String> = parse_set(&inner["signatures"])
                .iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect();
            let ghost_sender = inner["ghost_sender"].as_str()?.to_string();
            Some(TracedCert::Notarization {
                view,
                parent,
                block,
                signers,
                ghost_sender,
            })
        }
        "Nullification" => {
            let view = parse_int(&inner["view"]);
            let signers: Vec<String> = parse_set(&inner["signatures"])
                .iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect();
            let ghost_sender = inner["ghost_sender"].as_str()?.to_string();
            Some(TracedCert::Nullification {
                view,
                signers,
                ghost_sender,
            })
        }
        "Finalization" => {
            let proposal = inner.get("proposal");
            let view = parse_int(proposal.map(|p| &p["view"]).unwrap_or(&inner["view"]));
            let parent = proposal.map(|p| parse_int(&p["parent"])).unwrap_or(0);
            let block_name = proposal
                .and_then(|p| p["payload"].as_str())
                .or_else(|| inner["block"].as_str())?;
            let block = block_to_hex(block_name, block_map);
            let signers: Vec<String> = parse_set(&inner["signatures"])
                .iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect();
            let ghost_sender = inner["ghost_sender"].as_str()?.to_string();
            Some(TracedCert::Finalization {
                view,
                parent,
                block,
                signers,
                ghost_sender,
            })
        }
        _ => None,
    }
}

fn diff_store_vote(
    prev_store: &HashMap<String, Vec<Value>>,
    next_store: &HashMap<String, Vec<Value>>,
    block_map: &mut HashMap<String, String>,
) -> Vec<(String, String, TracedVote)> {
    let mut new_entries = Vec::new();
    for (node, next_votes) in next_store {
        let prev_votes = prev_store.get(node);
        let prev_list = prev_votes.map(|v| v.as_slice()).unwrap_or(&[]);
        for vote_val in next_votes {
            if !prev_list.iter().any(|pv| pv == vote_val) {
                if let Some(vote) = parse_itf_vote(vote_val, block_map) {
                    let sender = match &vote {
                        TracedVote::Notarize { sig, .. }
                        | TracedVote::Nullify { sig, .. }
                        | TracedVote::Finalize { sig, .. } => sig.clone(),
                    };
                    new_entries.push((node.clone(), sender, vote));
                }
            }
        }
    }
    new_entries
}

fn diff_store_certificate(
    prev_store: &HashMap<String, Vec<Value>>,
    next_store: &HashMap<String, Vec<Value>>,
    block_map: &mut HashMap<String, String>,
) -> Vec<(String, String, TracedCert)> {
    let mut new_entries = Vec::new();
    for (node, next_certs) in next_store {
        let prev_certs = prev_store.get(node);
        let prev_list = prev_certs.map(|v| v.as_slice()).unwrap_or(&[]);
        for cert_val in next_certs {
            if !prev_list.iter().any(|pc| pc == cert_val) {
                if let Some(cert) = parse_itf_cert(cert_val, block_map) {
                    let sender = match &cert {
                        TracedCert::Notarization { ghost_sender, .. }
                        | TracedCert::Nullification { ghost_sender, .. }
                        | TracedCert::Finalization { ghost_sender, .. } => ghost_sender.clone(),
                    };
                    new_entries.push((node.clone(), sender, cert));
                }
            }
        }
    }
    new_entries
}

// ---------------------------------------------------------------------------
// Mismatch reporting (inlined from the retired replayer::compare module)
// ---------------------------------------------------------------------------

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
pub enum Mismatch {
    MissingNotarization {
        node: String,
        view: u64,
    },
    ExtraNotarization {
        node: String,
        view: u64,
    },
    NotarizationPayloadMismatch {
        node: String,
        view: u64,
        expected: String,
        actual: String,
    },
    NotarizationSignatureCountMismatch {
        node: String,
        view: u64,
        expected: Option<usize>,
        actual: Option<usize>,
    },
    MissingNullification {
        node: String,
        view: u64,
    },
    ExtraNullification {
        node: String,
        view: u64,
    },
    NullificationSignatureCountMismatch {
        node: String,
        view: u64,
        expected: Option<usize>,
        actual: Option<usize>,
    },
    MissingFinalization {
        node: String,
        view: u64,
    },
    ExtraFinalization {
        node: String,
        view: u64,
    },
    FinalizationPayloadMismatch {
        node: String,
        view: u64,
        expected: String,
        actual: String,
    },
    FinalizationSignatureCountMismatch {
        node: String,
        view: u64,
        expected: Option<usize>,
        actual: Option<usize>,
    },
    LastFinalizedMismatch {
        node: String,
        expected: u64,
        actual: u64,
    },
    CertifiedViewsMismatch {
        node: String,
        expected: BTreeSet<u64>,
        actual: BTreeSet<u64>,
    },
    VoteSignerMismatch {
        node: String,
        view: u64,
        vote_type: &'static str,
        expected: BTreeSet<String>,
        actual: BTreeSet<String>,
    },
}

fn certificate_counts_match(
    expected: Option<usize>,
    actual: Option<usize>,
    quorum: usize,
) -> bool {
    match (expected, actual) {
        (Some(e), Some(a)) if e >= quorum && a >= quorum => true,
        _ => expected == actual,
    }
}

fn compare(
    expected: &ExpectedState,
    states: &[ReplayedReplicaState],
    faults: usize,
) -> Vec<Mismatch> {
    let mut mismatches = Vec::new();
    let n = states.len() + faults;
    let quorum = crate::bounds::quorum(n as u32) as usize;

    for (correct_idx, state) in states.iter().enumerate() {
        let node_idx = correct_idx + faults;
        let node_id = format!("n{node_idx}");
        let Some(expected_node) = expected.nodes.get(&node_id) else {
            continue;
        };

        let actual_views: BTreeSet<u64> = state.notarizations.keys().copied().collect();
        let expected_views: BTreeSet<u64> = expected_node.notarizations.keys().copied().collect();
        for &view in expected_views.difference(&actual_views) {
            mismatches.push(Mismatch::MissingNotarization {
                node: node_id.clone(),
                view,
            });
        }
        for &view in actual_views.difference(&expected_views) {
            mismatches.push(Mismatch::ExtraNotarization {
                node: node_id.clone(),
                view,
            });
        }
        for view in expected_views.intersection(&actual_views) {
            let expected_data = &expected_node.notarizations[view];
            let actual_data = state
                .notarizations
                .get(view)
                .expect("view present in both maps");
            if expected_data != &actual_data.payload.to_string() {
                mismatches.push(Mismatch::NotarizationPayloadMismatch {
                    node: node_id.clone(),
                    view: *view,
                    expected: expected_data.clone(),
                    actual: actual_data.payload.to_string(),
                });
            }
            let expected_count = expected_node
                .notarization_signature_counts
                .get(view)
                .copied()
                .unwrap_or(None);
            if !certificate_counts_match(expected_count, actual_data.signature_count, quorum) {
                mismatches.push(Mismatch::NotarizationSignatureCountMismatch {
                    node: node_id.clone(),
                    view: *view,
                    expected: expected_count,
                    actual: actual_data.signature_count,
                });
            }
        }

        let actual_null_views: BTreeSet<u64> = state.nullifications.keys().copied().collect();
        let expected_null_views: BTreeSet<u64> =
            expected_node.nullifications.iter().copied().collect();
        for &view in expected_null_views.difference(&actual_null_views) {
            mismatches.push(Mismatch::MissingNullification {
                node: node_id.clone(),
                view,
            });
        }
        for &view in actual_null_views.difference(&expected_null_views) {
            mismatches.push(Mismatch::ExtraNullification {
                node: node_id.clone(),
                view,
            });
        }
        for view in expected_null_views.intersection(&actual_null_views) {
            let expected_count = expected_node
                .nullification_signature_counts
                .get(view)
                .copied()
                .unwrap_or(None);
            let actual_count = state
                .nullifications
                .get(view)
                .expect("view present in both maps")
                .signature_count;
            if !certificate_counts_match(expected_count, actual_count, quorum) {
                mismatches.push(Mismatch::NullificationSignatureCountMismatch {
                    node: node_id.clone(),
                    view: *view,
                    expected: expected_count,
                    actual: actual_count,
                });
            }
        }

        let actual_final_views: BTreeSet<u64> = state.finalizations.keys().copied().collect();
        let expected_final_views: BTreeSet<u64> =
            expected_node.finalizations.keys().copied().collect();
        for &view in expected_final_views.difference(&actual_final_views) {
            mismatches.push(Mismatch::MissingFinalization {
                node: node_id.clone(),
                view,
            });
        }
        for &view in actual_final_views.difference(&expected_final_views) {
            mismatches.push(Mismatch::ExtraFinalization {
                node: node_id.clone(),
                view,
            });
        }
        for view in expected_final_views.intersection(&actual_final_views) {
            let expected_data = &expected_node.finalizations[view];
            let actual_data = state
                .finalizations
                .get(view)
                .expect("view present in both maps");
            if expected_data != &actual_data.payload.to_string() {
                mismatches.push(Mismatch::FinalizationPayloadMismatch {
                    node: node_id.clone(),
                    view: *view,
                    expected: expected_data.clone(),
                    actual: actual_data.payload.to_string(),
                });
            }
            let expected_count = expected_node
                .finalization_signature_counts
                .get(view)
                .copied()
                .unwrap_or(None);
            if !certificate_counts_match(expected_count, actual_data.signature_count, quorum) {
                mismatches.push(Mismatch::FinalizationSignatureCountMismatch {
                    node: node_id.clone(),
                    view: *view,
                    expected: expected_count,
                    actual: actual_data.signature_count,
                });
            }
        }

        let actual_last = state.finalizations.keys().max().copied().unwrap_or(0);
        if expected_node.last_finalized != actual_last {
            mismatches.push(Mismatch::LastFinalizedMismatch {
                node: node_id.clone(),
                expected: expected_node.last_finalized,
                actual: actual_last,
            });
        }

        let actual_certified: BTreeSet<u64> = state.certified.iter().copied().collect();
        if expected_node.certified != actual_certified {
            mismatches.push(Mismatch::CertifiedViewsMismatch {
                node: node_id.clone(),
                expected: expected_node.certified.clone(),
                actual: actual_certified,
            });
        }

        compare_signers(
            &mut mismatches,
            &node_id,
            "notarize",
            &expected_node.notarize_signers,
            &state.notarize_signers,
        );
        compare_signers(
            &mut mismatches,
            &node_id,
            "nullify",
            &expected_node.nullify_signers,
            &state.nullify_signers,
        );
        compare_signers(
            &mut mismatches,
            &node_id,
            "finalize",
            &expected_node.finalize_signers,
            &state.finalize_signers,
        );
    }

    mismatches
}

fn compare_signers(
    mismatches: &mut Vec<Mismatch>,
    node: &str,
    vote_type: &'static str,
    expected: &BTreeMap<u64, BTreeSet<String>>,
    actual: &HashMap<u64, BTreeSet<String>>,
) {
    let all_views: BTreeSet<u64> = expected.keys().chain(actual.keys()).copied().collect();
    for view in all_views {
        if view == 0 {
            continue;
        }
        let empty = BTreeSet::new();
        let exp_set = expected.get(&view).unwrap_or(&empty);
        let act_set = actual.get(&view).unwrap_or(&empty);
        if exp_set != act_set {
            mismatches.push(Mismatch::VoteSignerMismatch {
                node: node.to_string(),
                view,
                vote_type,
                expected: exp_set.clone(),
                actual: act_set.clone(),
            });
        }
    }
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mismatch::MissingNotarization { node, view } => {
                write!(f, "{node}: missing notarization for view {view}")
            }
            Mismatch::ExtraNotarization { node, view } => {
                write!(f, "{node}: extra notarization for view {view}")
            }
            Mismatch::NotarizationPayloadMismatch {
                node,
                view,
                expected,
                actual,
            } => write!(
                f,
                "{node}: notarization payload mismatch at view {view}: spec={expected}, impl={actual}"
            ),
            Mismatch::NotarizationSignatureCountMismatch {
                node,
                view,
                expected,
                actual,
            } => write!(
                f,
                "{node}: notarization signature count mismatch at view {view}: spec={expected:?}, impl={actual:?}"
            ),
            Mismatch::MissingNullification { node, view } => {
                write!(f, "{node}: missing nullification for view {view}")
            }
            Mismatch::ExtraNullification { node, view } => {
                write!(f, "{node}: extra nullification for view {view}")
            }
            Mismatch::NullificationSignatureCountMismatch {
                node,
                view,
                expected,
                actual,
            } => write!(
                f,
                "{node}: nullification signature count mismatch at view {view}: spec={expected:?}, impl={actual:?}"
            ),
            Mismatch::MissingFinalization { node, view } => {
                write!(f, "{node}: missing finalization for view {view}")
            }
            Mismatch::ExtraFinalization { node, view } => {
                write!(f, "{node}: extra finalization for view {view}")
            }
            Mismatch::FinalizationPayloadMismatch {
                node,
                view,
                expected,
                actual,
            } => write!(
                f,
                "{node}: finalization payload mismatch at view {view}: spec={expected}, impl={actual}"
            ),
            Mismatch::FinalizationSignatureCountMismatch {
                node,
                view,
                expected,
                actual,
            } => write!(
                f,
                "{node}: finalization signature count mismatch at view {view}: spec={expected:?}, impl={actual:?}"
            ),
            Mismatch::LastFinalizedMismatch {
                node,
                expected,
                actual,
            } => write!(
                f,
                "{node}: last_finalized mismatch: expected {expected}, got {actual}"
            ),
            Mismatch::CertifiedViewsMismatch {
                node,
                expected,
                actual,
            } => write!(
                f,
                "{node}: certified views mismatch: spec={expected:?}, impl={actual:?}"
            ),
            Mismatch::VoteSignerMismatch {
                node,
                view,
                vote_type,
                expected,
                actual,
            } => write!(
                f,
                "{node}: {vote_type} signers mismatch at view {view}: spec={expected:?}, impl={actual:?}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Message construction (inlined from the retired replayer::messages module)
// ---------------------------------------------------------------------------

fn digest_from_hex(hex: &str) -> Sha256Digest {
    assert!(
        hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "block ID must be a 64-char hex string, got: {hex:?}"
    );
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).expect("ascii hex");
        bytes[i] = u8::from_str_radix(s, 16).expect("valid hex pair");
    }
    Sha256Digest::from(bytes)
}

fn parse_node_id(id: &str) -> usize {
    id.strip_prefix('n')
        .and_then(|s| s.parse().ok())
        .expect("invalid node id")
}

fn make_proposal(epoch: u64, view: u64, parent: u64, block: &str) -> Proposal<Sha256Digest> {
    let round = Round::new(EpochType::new(epoch), View::new(view));
    let payload = digest_from_hex(block);
    Proposal::new(round, View::new(parent), payload)
}

struct ConstructedMessage {
    sender_pk: PublicKey,
    payload: IoBuf,
    is_certificate: bool,
}

fn construct_vote(
    sender: &str,
    vote: &TracedVote,
    schemes: &[S],
    participants: &[PublicKey],
    epoch: u64,
) -> ConstructedMessage {
    let signer_idx = match vote {
        TracedVote::Notarize { sig, .. }
        | TracedVote::Nullify { sig, .. }
        | TracedVote::Finalize { sig, .. } => parse_node_id(sig),
    };
    let scheme = &schemes[signer_idx];
    let encoded: IoBuf = match vote {
        TracedVote::Notarize {
            view,
            parent,
            block,
            ..
        } => {
            let proposal = make_proposal(epoch, *view, *parent, block);
            let notarize = Notarize::<S, Sha256Digest>::sign(scheme, proposal)
                .expect("signing must succeed");
            Vote::Notarize(notarize).encode().into()
        }
        TracedVote::Nullify { view, .. } => {
            let round = Round::new(EpochType::new(epoch), View::new(*view));
            let nullify =
                Nullify::<S>::sign::<Sha256Digest>(scheme, round).expect("signing must succeed");
            Vote::<S, Sha256Digest>::Nullify(nullify).encode().into()
        }
        TracedVote::Finalize {
            view,
            parent,
            block,
            ..
        } => {
            let proposal = make_proposal(epoch, *view, *parent, block);
            let finalize = Finalize::<S, Sha256Digest>::sign(scheme, proposal)
                .expect("signing must succeed");
            Vote::Finalize(finalize).encode().into()
        }
    };
    let sender_idx = parse_node_id(sender);
    ConstructedMessage {
        sender_pk: participants[sender_idx].clone(),
        payload: encoded,
        is_certificate: false,
    }
}

fn construct_certificate(
    cert: &TracedCert,
    schemes: &[S],
    participants: &[PublicKey],
    epoch: u64,
) -> ConstructedMessage {
    let strategy = Sequential;
    let (ghost_sender, encoded): (&str, IoBuf) = match cert {
        TracedCert::Notarization {
            view,
            parent,
            block,
            signers,
            ghost_sender,
        } => {
            let proposal = make_proposal(epoch, *view, *parent, block);
            let notarizes: Vec<_> = signers
                .iter()
                .map(|s| {
                    let idx = parse_node_id(s);
                    Notarize::<S, Sha256Digest>::sign(&schemes[idx], proposal.clone())
                        .expect("signing must succeed")
                })
                .collect();
            let notarization =
                Notarization::from_notarizes(&schemes[0], notarizes.iter(), &strategy)
                    .expect("certificate assembly must succeed");
            (
                ghost_sender.as_str(),
                Certificate::Notarization(notarization).encode().into(),
            )
        }
        TracedCert::Nullification {
            view,
            signers,
            ghost_sender,
        } => {
            let round = Round::new(EpochType::new(epoch), View::new(*view));
            let nullifies: Vec<_> = signers
                .iter()
                .map(|s| {
                    let idx = parse_node_id(s);
                    Nullify::<S>::sign::<Sha256Digest>(&schemes[idx], round)
                        .expect("signing must succeed")
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&schemes[0], nullifies.iter(), &strategy)
                    .expect("certificate assembly must succeed");
            (
                ghost_sender.as_str(),
                Certificate::<S, Sha256Digest>::Nullification(nullification)
                    .encode()
                    .into(),
            )
        }
        TracedCert::Finalization {
            view,
            parent,
            block,
            signers,
            ghost_sender,
        } => {
            let proposal = make_proposal(epoch, *view, *parent, block);
            let finalizes: Vec<_> = signers
                .iter()
                .map(|s| {
                    let idx = parse_node_id(s);
                    Finalize::<S, Sha256Digest>::sign(&schemes[idx], proposal.clone())
                        .expect("signing must succeed")
                })
                .collect();
            let finalization =
                Finalization::from_finalizes(&schemes[0], finalizes.iter(), &strategy)
                    .expect("certificate assembly must succeed");
            (
                ghost_sender.as_str(),
                Certificate::Finalization(finalization).encode().into(),
            )
        }
    };
    let sender_idx = parse_node_id(ghost_sender);
    ConstructedMessage {
        sender_pk: participants[sender_idx].clone(),
        payload: encoded,
        is_certificate: true,
    }
}

fn construct_message(
    entry: &TraceEntry,
    schemes: &[S],
    participants: &[PublicKey],
    epoch: u64,
) -> ConstructedMessage {
    match entry {
        TraceEntry::Vote { sender, vote, .. } => {
            construct_vote(sender, vote, schemes, participants, epoch)
        }
        TraceEntry::Certificate { cert, .. } => {
            construct_certificate(cert, schemes, participants, epoch)
        }
    }
}

// ---------------------------------------------------------------------------
// Apalache driver glue
// ---------------------------------------------------------------------------

/// Compiles a Quint spec to TLA+ using `quint compile --target tlaplus`.
pub fn compile_quint_to_tla(spec_path: &str, main: &str) -> Result<String, Error> {
    let output = Command::new("quint")
        .args(["compile", "--target", "tlaplus", "--main", main, spec_path])
        .output()
        .map_err(|e| Error::Quint(format!("failed to run quint: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Quint(format!(
            "quint compile failed ({}): {stderr}",
            output.status
        )));
    }

    let tla = String::from_utf8_lossy(&output.stdout).to_string();
    if tla.trim().is_empty() {
        return Err(Error::Quint("quint compile produced empty output".into()));
    }

    Ok(tla)
}

/// Configuration for an IST run.
pub struct IstConfig {
    pub apalache_url: String,
    pub max_steps: usize,
    pub spec_path: String,
    pub main_module: String,
    pub compact_every: usize,
    pub tla_path: Option<String>,
}

impl Default for IstConfig {
    fn default() -> Self {
        Self {
            apalache_url: "http://localhost:8822/rpc".to_string(),
            max_steps: 100,
            spec_path: String::new(),
            main_module: "itf_main".to_string(),
            compact_every: 20,
            tla_path: None,
        }
    }
}

fn fix_tla_precedence(tla: &str) -> String {
    // Step 1: Replace := with = for standard operator precedence
    let tla = tla.replace(" := ", " = ");

    // Step 2: Parenthesize LET bodies in primed variable assignments.
    let lines: Vec<&str> = tla.lines().collect();
    let mut output: Vec<String> = Vec::with_capacity(lines.len());
    let mut need_close = false;
    let mut bracket_depth: i32 = 0;
    let mut saw_bracket = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if !need_close && trimmed.starts_with("= LET") && i > 0 {
            if lines[i - 1].trim().ends_with('\'') {
                let ws = &line[..line.len() - trimmed.len()];
                output.push(format!("{ws}= (LET{}", &trimmed["= LET".len()..]));
                need_close = true;
                bracket_depth = 0;
                saw_bracket = false;
                continue;
            }
        }

        if need_close {
            for ch in line.chars() {
                if ch == '[' {
                    bracket_depth += 1;
                    saw_bracket = true;
                }
                if ch == ']' {
                    bracket_depth -= 1;
                }
            }

            if saw_bracket && bracket_depth == 0 {
                output.push(format!("{line})"));
                need_close = false;
                continue;
            }
        }

        output.push(line.to_string());
    }

    output.join("\n")
}

fn normalize_state(state: &Value) -> Value {
    let Some(obj) = state.as_object() else {
        return state.clone();
    };
    let mut normalized = serde_json::Map::new();
    for (key, val) in obj {
        let short = key.find("_r_").map(|pos| &key[pos + 3..]).unwrap_or(key);
        normalized.insert(short.to_string(), val.clone());
    }
    Value::Object(normalized)
}

fn last_state_from_trace(trace: &Value) -> Result<(Value, Value), Error> {
    let states = trace["states"]
        .as_array()
        .ok_or(Error::Setup("trace has no states array".into()))?;
    let state = states
        .last()
        .ok_or(Error::Setup("trace states array is empty".into()))?;
    Ok((state.clone(), normalize_state(state)))
}

fn last_two_states_from_trace(trace: &Value) -> Result<(Value, Value), Error> {
    let states = trace["states"]
        .as_array()
        .ok_or(Error::Setup("trace has no states array".into()))?;
    if states.len() < 2 {
        return Err(Error::Setup(
            "trace needs at least 2 states for diffing".into(),
        ));
    }
    let prev = normalize_state(&states[states.len() - 2]);
    let last = normalize_state(&states[states.len() - 1]);
    Ok((prev, last))
}

fn get_tla_source(cfg: &IstConfig) -> Result<String, Error> {
    let tla_source = if let Some(tla_path) = &cfg.tla_path {
        println!("reading pre-compiled TLA+ from {tla_path}...");
        std::fs::read_to_string(tla_path)
            .map_err(|e| Error::Setup(format!("failed to read TLA+ file {tla_path}: {e}")))?
    } else {
        println!("compiling {} to TLA+...", cfg.spec_path);
        compile_quint_to_tla(&cfg.spec_path, &cfg.main_module)?
    };
    let tla_source = fix_tla_precedence(&tla_source);
    println!(
        "TLA+ source: {} bytes (after precedence fixup)",
        tla_source.len()
    );
    Ok(tla_source)
}

fn inject_entry(
    entry: &TraceEntry,
    faults: usize,
    vote_injectors: &[injected::Injector],
    cert_injectors: &[injected::Injector],
    schemes: &[S],
    participants: &[PublicKey],
    epoch: u64,
) {
    // Skip self-votes
    if let TraceEntry::Vote {
        sender, receiver, ..
    } = entry
    {
        if sender == receiver {
            return;
        }
    }

    let receiver_id = match entry {
        TraceEntry::Vote { receiver, .. } => receiver,
        TraceEntry::Certificate { receiver, .. } => receiver,
    };

    let receiver_idx = receiver_id
        .strip_prefix('n')
        .and_then(|s| s.parse::<usize>().ok())
        .expect("invalid receiver id");

    if receiver_idx < faults {
        return;
    }

    let correct_idx = receiver_idx - faults;

    let msg = construct_message(entry, schemes, participants, epoch);

    if msg.is_certificate {
        cert_injectors[correct_idx].inject(msg.sender_pk, msg.payload);
    } else {
        vote_injectors[correct_idx].inject(msg.sender_pk, msg.payload);
    }
}

/// Runs an IST session as a single interactive loop.
pub fn run_ist(cfg: &IstConfig) -> Result<IstReport, Error> {
    let tla_source = get_tla_source(cfg)?;

    let client = ApalacheClient::new(&cfg.apalache_url);
    client.health().map_err(|e| {
        Error::Setup(format!(
            "cannot reach Apalache at {}: {e}\n\
             Start it with: docker run --rm -p 8822:8822 \
             ghcr.io/apalache-mc/apalache:latest server --server-type=explorer",
            cfg.apalache_url
        ))
    })?;
    println!("connected to Apalache");

    use base64::{engine::general_purpose::STANDARD, Engine as B64Engine};
    let source_b64 = STANDARD.encode(&tla_source);

    let session = client.load_spec(&[source_b64], Some("init"), Some("step"), &[])?;
    println!(
        "loaded spec: session={}, init transitions={}, next transitions={}",
        session.id,
        session.init_transitions.len(),
        session.next_transitions.len()
    );

    let init_id = session
        .init_transitions
        .first()
        .ok_or(Error::Setup("no init transitions".into()))?
        .index;

    let assume_result = client.assume_transition(&session.id, init_id, true)?;
    if assume_result.status != TransitionStatus::Enabled {
        let _ = client.dispose_spec(&session.id);
        return Err(Error::Setup("init transition not enabled".into()));
    }
    let next_result = client.next_step(&session.id)?;
    println!("initialized: step={}", next_result.step_no);

    let query_result = client.query(&session.id, &["TRACE"], None)?;
    let trace = query_result
        .trace
        .as_ref()
        .ok_or(Error::Setup("no trace from query".into()))?;
    let (_, init_state) = last_state_from_trace(trace)?;

    let correct_nodes = identify_correct_nodes(&init_state);
    let n = count_nodes(&init_state);
    let faults = n - correct_nodes.len();
    let leader_map = extract_leader_map(&init_state);
    let epoch = compute_epoch(&leader_map, n)
        .map_err(|e| Error::Setup(format!("epoch computation: {e}")))?;

    println!("config: n={n}, faults={faults}, epoch={epoch}, correct={correct_nodes:?}");

    let executor = deterministic::Runner::timed(Duration::from_secs(600));
    let max_steps = cfg.max_steps;

    let report: Result<IstReport, Error> = executor.start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            verifier: _,
            ..
        } = ed25519::fixture(&mut context, NAMESPACE, n as u32);

        let correct_start = faults;
        let mut vote_injectors = Vec::new();
        let mut cert_injectors = Vec::new();
        let mut reporters = Vec::new();

        let relay_inst = Arc::new(relay::Relay::new());
        let elector = RoundRobin::<Sha256Hasher>::default();

        for i in correct_start..n {
            let ctx = context.with_label(&format!("validator_n{i}"));

            let (vote_inj, vote_rx) = injected::channel();
            vote_injectors.push(vote_inj);

            let (cert_inj, cert_rx) = injected::channel();
            cert_injectors.push(cert_inj);

            let resolver_rx = PendingReceiver;

            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: schemes[i].clone(),
                elector: elector.clone(),
            };
            let reporter_inst =
                reporter::Reporter::new(ctx.with_label("reporter"), reporter_cfg);
            reporters.push(reporter_inst.clone());

            let app_cfg = application::Config {
                hasher: Sha256::default(),
                relay: relay_inst.clone(),
                me: participants[i].clone(),
                propose_latency: (1.0, 0.1),
                verify_latency: (1.0, 0.1),
                certify_latency: (1.0, 0.1),
                should_certify: application::Certifier::Always,
            };
            let (actor, application) =
                application::Application::new(ctx.with_label("application"), app_cfg);
            actor.start();

            let engine_cfg = config::Config {
                blocker: NullBlocker,
                scheme: schemes[i].clone(),
                elector: elector.clone(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter_inst.clone(),
                partition: format!("ist_n{i}"),
                mailbox_size: 1024,
                epoch: EpochType::new(epoch),
                leader_timeout: Duration::from_secs(3600),
                certification_timeout: Duration::from_secs(3600),
                timeout_retry: Duration::from_secs(3600),
                fetch_timeout: Duration::from_secs(3600),
                activity_timeout: Delta::new(100),
                skip_timeout: Delta::new(50),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(ctx.with_label("engine"), engine_cfg);
            engine.start(
                (NullSender, vote_rx),
                (NullSender, cert_rx),
                (NullSender, resolver_rx),
            );
        }

        let mut current_snapshot = next_result.snapshot_id;
        let mut steps_completed = 0;
        let mut divergences: Vec<(usize, Vec<Mismatch>)> = Vec::new();

        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let mut transition_indices: Vec<usize> =
            (0..session.next_transitions.len()).collect();

        let mut block_map: HashMap<String, String> = HashMap::new();

        for step in 0..max_steps {
            let mut found_enabled = false;
            let pre_snapshot = current_snapshot;

            transition_indices.shuffle(&mut rng);

            for &ti in &transition_indices {
                let transition = &session.next_transitions[ti];
                let assume_result =
                    client.assume_transition(&session.id, transition.index, true)?;

                match assume_result.status {
                    TransitionStatus::Enabled => {
                        let step_result = client.next_step(&session.id)?;
                        current_snapshot = step_result.snapshot_id;

                        let query_result =
                            client.query(&session.id, &["TRACE"], None)?;
                        let trace_val = query_result
                            .trace
                            .as_ref()
                            .ok_or(Error::Setup("no trace from query".into()))?;
                        let (prev_state, new_state) =
                            last_two_states_from_trace(trace_val)?;

                        let action_name = new_state
                            .get("lastAction")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?");

                        let prev_votes = collect_store_vote(&prev_state);
                        let new_votes = collect_store_vote(&new_state);
                        let prev_certs = collect_store_certificate(&prev_state);
                        let new_certs = collect_store_certificate(&new_state);

                        let vote_entries =
                            diff_store_vote(&prev_votes, &new_votes, &mut block_map);
                        let cert_entries = diff_store_certificate(
                            &prev_certs,
                            &new_certs,
                            &mut block_map,
                        );

                        println!(
                            "step {step}: t{} [{action_name}] -> {} votes, {} certs",
                            transition.index,
                            vote_entries.len(),
                            cert_entries.len(),
                        );

                        let mut step_entries = Vec::new();
                        for (receiver, sender, vote) in vote_entries {
                            println!("  vote: {sender} -> {receiver}: {vote:?}");
                            step_entries.push(TraceEntry::Vote {
                                sender,
                                receiver,
                                vote,
                            });
                        }
                        for (receiver, sender, cert) in cert_entries {
                            println!("  cert: {sender} -> {receiver}: {cert:?}");
                            step_entries.push(TraceEntry::Certificate {
                                sender,
                                receiver,
                                cert,
                            });
                        }

                        for entry in &step_entries {
                            inject_entry(
                                entry,
                                faults,
                                &vote_injectors,
                                &cert_injectors,
                                &schemes,
                                &participants,
                                epoch,
                            );
                            context.sleep(Duration::from_millis(1)).await;
                        }

                        context.sleep(Duration::from_secs(2)).await;

                        let observed = invariants::extract_replayed(&reporters, n);
                        let correct_nodes_now = identify_correct_nodes(&new_state);
                        let expected = extract_expected_state(
                            &new_state,
                            &correct_nodes_now,
                            &block_map,
                        );
                        let mismatches = compare(&expected, &observed, faults);

                        for (ci, impl_state) in observed.iter().enumerate() {
                            let ni = ci + faults;
                            let nid = format!("n{ni}");

                            let i_notar: Vec<u64> =
                                impl_state.notarizations.keys().copied().collect();
                            let i_nulls: Vec<u64> =
                                impl_state.nullifications.keys().copied().collect();
                            let i_finals: Vec<u64> =
                                impl_state.finalizations.keys().copied().collect();
                            let i_last_fin =
                                i_finals.last().copied().unwrap_or(0);

                            let spec_node = expected.nodes.get(&nid);
                            let s_notar: Vec<u64> = spec_node
                                .map(|s| s.notarizations.keys().copied().collect())
                                .unwrap_or_default();
                            let s_nulls: Vec<u64> = spec_node
                                .map(|s| s.nullifications.iter().copied().collect())
                                .unwrap_or_default();
                            let s_finals: Vec<u64> = spec_node
                                .map(|s| s.finalizations.keys().copied().collect())
                                .unwrap_or_default();
                            let s_last_fin = spec_node
                                .map(|s| s.last_finalized)
                                .unwrap_or(0);

                            let has_state = !i_notar.is_empty()
                                || !i_nulls.is_empty()
                                || !i_finals.is_empty()
                                || !s_notar.is_empty()
                                || !s_nulls.is_empty()
                                || !s_finals.is_empty();

                            if has_state {
                                println!(
                                    "  {nid} spec: notarization={s_notar:?} nullification={s_nulls:?} finalization={s_finals:?} last_finalized={s_last_fin}"
                                );
                                println!(
                                    "  {nid} impl: notarization={i_notar:?} nullification={i_nulls:?} finalization={i_finals:?} last_finalized={i_last_fin}"
                                );

                                let s_notar_v = spec_node
                                    .map(|s| &s.notarize_signers)
                                    .cloned()
                                    .unwrap_or_default();
                                let s_null_v = spec_node
                                    .map(|s| &s.nullify_signers)
                                    .cloned()
                                    .unwrap_or_default();
                                let s_fin_v = spec_node
                                    .map(|s| &s.finalize_signers)
                                    .cloned()
                                    .unwrap_or_default();

                                let all_views: BTreeSet<u64> = s_notar_v
                                    .keys()
                                    .chain(impl_state.notarize_signers.keys())
                                    .chain(s_null_v.keys())
                                    .chain(impl_state.nullify_signers.keys())
                                    .chain(s_fin_v.keys())
                                    .chain(impl_state.finalize_signers.keys())
                                    .copied()
                                    .filter(|&v| v > 1)
                                    .collect();

                                let empty = BTreeSet::new();
                                for view in all_views {
                                    let sn = s_notar_v.get(&view).unwrap_or(&empty);
                                    let in_ = impl_state
                                        .notarize_signers
                                        .get(&view)
                                        .unwrap_or(&empty);
                                    let snl = s_null_v.get(&view).unwrap_or(&empty);
                                    let inl = impl_state
                                        .nullify_signers
                                        .get(&view)
                                        .unwrap_or(&empty);
                                    let sf = s_fin_v.get(&view).unwrap_or(&empty);
                                    let if_ = impl_state
                                        .finalize_signers
                                        .get(&view)
                                        .unwrap_or(&empty);

                                    if !sn.is_empty() || !in_.is_empty() {
                                        println!(
                                            "    v{view} notarize: spec={sn:?} impl={in_:?}"
                                        );
                                    }
                                    if !snl.is_empty() || !inl.is_empty() {
                                        println!(
                                            "    v{view} nullify:  spec={snl:?} impl={inl:?}"
                                        );
                                    }
                                    if !sf.is_empty() || !if_.is_empty() {
                                        println!(
                                            "    v{view} finalize: spec={sf:?} impl={if_:?}"
                                        );
                                    }
                                }
                            }
                        }
                        if mismatches.is_empty() {
                            println!("  [OK]");
                        } else {
                            println!(
                                "  [DIVERGENCE] {} mismatches:",
                                mismatches.len()
                            );
                            for m in &mismatches {
                                println!("    {m}");
                            }
                            divergences.push((step, mismatches));
                            steps_completed = step + 1;
                            break;
                        }

                        current_snapshot =
                            client.compact(&session.id, current_snapshot)?;
                        steps_completed = step + 1;
                        found_enabled = true;
                        break;
                    }
                    TransitionStatus::Disabled => {
                        client.rollback(&session.id, pre_snapshot)?;
                        current_snapshot = pre_snapshot;
                    }
                    TransitionStatus::Unknown => {
                        println!(
                            "step {step}: t{} {:?} returned UNKNOWN, skipping",
                            transition.index, transition.labels
                        );
                        client.rollback(&session.id, pre_snapshot)?;
                        current_snapshot = pre_snapshot;
                    }
                }
            }

            if !divergences.is_empty() {
                break;
            }

            if !found_enabled {
                println!("step {step}: no enabled transitions, stopping");
                break;
            }
        }

        let _ = client.dispose_spec(&session.id);

        Ok(IstReport {
            steps_completed,
            divergences,
        })
    });

    report
}

/// Report from an IST run.
pub struct IstReport {
    pub steps_completed: usize,
    pub divergences: Vec<(usize, Vec<Mismatch>)>,
}

impl IstReport {
    pub fn is_ok(&self) -> bool {
        self.divergences.is_empty()
    }
}

impl std::fmt::Display for IstReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IST: {} steps completed, {} divergences",
            self.steps_completed,
            self.divergences.len()
        )?;
        for (step, mismatches) in &self.divergences {
            write!(f, "\n  at step {step}: {} mismatches", mismatches.len())?;
        }
        Ok(())
    }
}
