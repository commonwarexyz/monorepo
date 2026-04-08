//! Decodes ITF (Informal Trace Format) JSON traces produced by
//! `quint run --out-itf` into [`TraceData`] and [`ExpectedState`]
//! for replay against the Rust simplex engine.

use super::{
    data::{ReporterReplicaStateData, TraceData, TraceProposalData},
    sniffer::{TraceEntry, TracedCert, TracedVote},
};
use crate::replayer::compare::{ExpectedNodeState, ExpectedState};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Errors encountered while decoding an ITF trace.
#[derive(Debug)]
pub enum DecodeError {
    /// JSON parsing failed.
    Json(serde_json::Error),
    /// A required field is missing from the ITF JSON.
    MissingField(&'static str),
    /// The trace contains no states.
    EmptyTrace,
    /// The leader map is not compatible with round-robin scheduling.
    NonRoundRobinLeaders,
    /// A node ID could not be parsed.
    InvalidNodeId(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Json(e) => write!(f, "JSON parse error: {e}"),
            DecodeError::MissingField(field) => write!(f, "missing field: {field}"),
            DecodeError::EmptyTrace => write!(f, "trace contains no states"),
            DecodeError::NonRoundRobinLeaders => {
                write!(f, "leader map is not round-robin; cannot compute epoch")
            }
            DecodeError::InvalidNodeId(id) => write!(f, "invalid node ID: {id}"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<serde_json::Error> for DecodeError {
    fn from(e: serde_json::Error) -> Self {
        DecodeError::Json(e)
    }
}

/// Looks up a state variable by suffix in an ITF state object.
/// ITF variables may be qualified (e.g. `itf_main::r::store_vote`),
/// so we match by the trailing `::suffix` or exact name.
pub fn get_var<'a>(state: &'a Value, suffix: &str) -> &'a Value {
    if let Value::Object(obj) = state {
        // Try exact match first
        if let Some(v) = obj.get(suffix) {
            return v;
        }
        // Try suffix match (::suffix)
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
pub fn parse_int(v: &Value) -> u64 {
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
pub fn parse_set(v: &Value) -> Vec<&Value> {
    match v {
        Value::Object(obj) => {
            if let Some(arr) = obj.get("#set").and_then(|v| v.as_array()) {
                arr.iter().collect()
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

/// Parses an ITF-encoded map (`{"#map": [[k, v], ...]}`).
pub fn parse_map(v: &Value) -> Vec<(&Value, &Value)> {
    match v {
        Value::Object(obj) => {
            if let Some(arr) = obj.get("#map").and_then(|v| v.as_array()) {
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
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

/// Parses a Quint option value represented as `None` or `{ tag: "Some", value: ... }`.
pub fn parse_option(v: &Value) -> Option<&Value> {
    match v {
        Value::Object(obj) if obj.get("tag").and_then(|t| t.as_str()) == Some("Some") => {
            obj.get("value")
        }
        _ => None,
    }
}

/// Converts a Quint block name (e.g. "val_b0") to a deterministic full
/// SHA-256 hex digest (64 chars) so ITF conversion and Rust replay use the
/// same payload representation end to end.
pub fn block_to_hex(name: &str, map: &mut HashMap<String, String>) -> String {
    if let Some(hex) = map.get(name) {
        return hex.clone();
    }
    use commonware_cryptography::{Hasher, Sha256};
    let hash = Sha256::hash(name.as_bytes());
    let bytes: &[u8] = hash.as_ref();
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    map.insert(name.to_string(), hex.clone());
    hex
}

/// Extracts the leader map from an ITF state.
pub fn extract_leader_map(state: &Value) -> BTreeMap<u64, String> {
    let mut map = BTreeMap::new();
    for (k, v) in parse_map(get_var(state, "leader")) {
        let view = parse_int(k);
        if let Some(node) = v.as_str() {
            map.insert(view, node.to_string());
        }
    }
    map
}

/// Computes the epoch from a round-robin leader map.
/// Returns an error if the map is not compatible with round-robin.
pub fn compute_epoch(leader_map: &BTreeMap<u64, String>, n: usize) -> Result<u64, DecodeError> {
    let (&first_view, first_leader) = leader_map
        .iter()
        .find(|(&v, _)| v >= 1)
        .ok_or(DecodeError::NonRoundRobinLeaders)?;

    let leader_idx = first_leader
        .strip_prefix('n')
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| DecodeError::InvalidNodeId(first_leader.clone()))?;

    // (epoch + first_view) % n == leader_idx
    let n64 = n as u64;
    let epoch = (leader_idx + n64 - (first_view % n64)) % n64;

    // Verify for all views >= 1
    for (&view, leader) in leader_map {
        if view == 0 {
            continue;
        }
        let expected_idx = (epoch + view) % n64;
        let expected = format!("n{expected_idx}");
        if leader != &expected {
            return Err(DecodeError::NonRoundRobinLeaders);
        }
    }

    Ok(epoch)
}

/// Parses a Quint Vote variant into a [`TracedVote`].
pub fn parse_itf_vote(v: &Value, block_map: &mut HashMap<String, String>) -> Option<TracedVote> {
    let tag = v.get("tag")?.as_str()?;
    let inner = v.get("value")?;
    match tag {
        "Notarize" => {
            let view = parse_int(
                inner
                    .get("proposal")
                    .map(|proposal| &proposal["view"])
                    .unwrap_or(&inner["view"]),
            );
            let sig = inner["sig"].as_str()?.to_string();
            let block_name = inner
                .get("proposal")
                .and_then(|proposal| proposal["payload"].as_str())
                .or_else(|| inner["block"].as_str())?;
            let block = block_to_hex(block_name, block_map);
            Some(TracedVote::Notarize { view, sig, block })
        }
        "Nullify" => {
            let view = parse_int(&inner["view"]);
            let sig = inner["sig"].as_str()?.to_string();
            Some(TracedVote::Nullify { view, sig })
        }
        "Finalize" => {
            let view = parse_int(
                inner
                    .get("proposal")
                    .map(|proposal| &proposal["view"])
                    .unwrap_or(&inner["view"]),
            );
            let sig = inner["sig"].as_str()?.to_string();
            let block_name = inner
                .get("proposal")
                .and_then(|proposal| proposal["payload"].as_str())
                .or_else(|| inner["block"].as_str())?;
            let block = block_to_hex(block_name, block_map);
            Some(TracedVote::Finalize { view, sig, block })
        }
        _ => None,
    }
}

/// Parses a Quint Certificate variant into a [`TracedCert`].
pub fn parse_itf_cert(v: &Value, block_map: &mut HashMap<String, String>) -> Option<TracedCert> {
    let tag = v.get("tag")?.as_str()?;
    let inner = v.get("value")?;
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
                .or_else(|| inner["block"].as_str())?;
            let block = block_to_hex(block_name, block_map);
            let signers: Vec<String> = parse_set(&inner["signatures"])
                .iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect();
            let ghost_sender = inner["ghost_sender"].as_str()?.to_string();
            Some(TracedCert::Notarization {
                view,
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
            let view = parse_int(
                inner
                    .get("proposal")
                    .map(|proposal| &proposal["view"])
                    .unwrap_or(&inner["view"]),
            );
            let block_name = inner
                .get("proposal")
                .and_then(|proposal| proposal["payload"].as_str())
                .or_else(|| inner["block"].as_str())?;
            let block = block_to_hex(block_name, block_map);
            let signers: Vec<String> = parse_set(&inner["signatures"])
                .iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect();
            let ghost_sender = inner["ghost_sender"].as_str()?.to_string();
            Some(TracedCert::Finalization {
                view,
                block,
                signers,
                ghost_sender,
            })
        }
        _ => None,
    }
}

/// Returns the view number from a [`TracedVote`].
fn vote_view(vote: &TracedVote) -> u64 {
    match vote {
        TracedVote::Notarize { view, .. }
        | TracedVote::Nullify { view, .. }
        | TracedVote::Finalize { view, .. } => *view,
    }
}

/// Returns the view number from a [`TracedCert`].
fn cert_view(cert: &TracedCert) -> u64 {
    match cert {
        TracedCert::Notarization { view, .. }
        | TracedCert::Nullification { view, .. }
        | TracedCert::Finalization { view, .. } => *view,
    }
}

fn wrap_tagged_value(tag: &str, value: &Value) -> Value {
    json!({
        "tag": tag,
        "value": value.clone(),
    })
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

/// Collects stored votes for each node from the split Quint vote stores.
/// Falls back to the legacy `store_vote` map when decoding older ITF traces.
pub fn collect_store_vote(state: &Value) -> HashMap<String, Vec<Value>> {
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

/// Collects stored certificates for each node from `store_certificates` in a state.
/// Falls back to the legacy `store_certificate` map when decoding older ITF traces.
pub fn collect_store_certificate(state: &Value) -> HashMap<String, Vec<Value>> {
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

/// Finds new votes delivered between two consecutive states.
/// Returns `(receiver, sender, vote)` triples.
pub fn diff_store_vote(
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

/// Finds new certificates delivered between two consecutive states.
/// Returns `(receiver, sender, cert)` triples.
pub fn diff_store_certificate(
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

/// Collects the global set of sent votes from the split Quint sent-vote sets.
/// Falls back to the legacy `sent_vote` set when decoding older ITF traces.
pub fn collect_sent_vote(state: &Value) -> Vec<Value> {
    let legacy_sent_vote = get_var(state, "sent_vote");
    if !legacy_sent_vote.is_null() {
        return parse_set(legacy_sent_vote).into_iter().cloned().collect();
    }

    let mut votes = Vec::new();
    votes.extend(
        parse_set(get_var(state, "sent_notarize_votes"))
            .into_iter()
            .map(|vote| wrap_tagged_value("Notarize", vote)),
    );
    votes.extend(
        parse_set(get_var(state, "sent_nullify_votes"))
            .into_iter()
            .map(|vote| wrap_tagged_value("Nullify", vote)),
    );
    votes.extend(
        parse_set(get_var(state, "sent_finalize_votes"))
            .into_iter()
            .map(|vote| wrap_tagged_value("Finalize", vote)),
    );
    votes
}

/// Extracts vote signers from the normalized store/sent vote collections for a
/// given node. We union in the node's own sent votes so the result always
/// includes self, matching the Rust Reporter which always records
/// self-constructed votes.
#[allow(clippy::type_complexity)]
fn extract_vote_signers(
    store_vote_map: &HashMap<String, Vec<Value>>,
    sent_votes: &[Value],
    node: &str,
) -> (
    BTreeMap<u64, BTreeSet<String>>,
    BTreeMap<u64, BTreeSet<String>>,
    BTreeMap<u64, BTreeSet<String>>,
) {
    let mut notarize_signers: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    let mut nullify_signers: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    let mut finalize_signers: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();

    // Votes received from the network
    if let Some(votes) = store_vote_map.get(node) {
        for vote_val in votes {
            insert_vote_signer(
                vote_val,
                &mut notarize_signers,
                &mut nullify_signers,
                &mut finalize_signers,
            );
        }
    }

    // Node's own sent votes (self-delivery)
    for vote_val in sent_votes {
        let sig = vote_val.get("value").and_then(|v| v["sig"].as_str());
        if sig == Some(node) {
            insert_vote_signer(
                vote_val,
                &mut notarize_signers,
                &mut nullify_signers,
                &mut finalize_signers,
            );
        }
    }

    (notarize_signers, nullify_signers, finalize_signers)
}

fn insert_vote_signer(
    vote_val: &Value,
    notarize_signers: &mut BTreeMap<u64, BTreeSet<String>>,
    nullify_signers: &mut BTreeMap<u64, BTreeSet<String>>,
    finalize_signers: &mut BTreeMap<u64, BTreeSet<String>>,
) {
    let Some(tag) = vote_val.get("tag").and_then(|t| t.as_str()) else {
        return;
    };
    let Some(inner) = vote_val.get("value") else {
        return;
    };
    let sig = inner["sig"].as_str().unwrap_or("").to_string();
    match tag {
        "Notarize" => {
            let view = parse_int(
                inner
                    .get("proposal")
                    .map(|proposal| &proposal["view"])
                    .unwrap_or(&inner["view"]),
            );
            notarize_signers.entry(view).or_default().insert(sig);
        }
        "Nullify" => {
            let view = parse_int(&inner["view"]);
            nullify_signers.entry(view).or_default().insert(sig);
        }
        "Finalize" => {
            let view = parse_int(
                inner
                    .get("proposal")
                    .map(|proposal| &proposal["view"])
                    .unwrap_or(&inner["view"]),
            );
            finalize_signers.entry(view).or_default().insert(sig);
        }
        _ => {}
    }
}

/// Extracts expected observable state from the final ITF state.
pub fn extract_expected_state(
    state: &Value,
    correct_nodes: &[String],
    block_map: &HashMap<String, String>,
) -> ExpectedState {
    let reporter_states = extract_reporter_states(state, correct_nodes, block_map);
    let nodes = reporter_states
        .into_iter()
        .map(|(node, data)| {
            let committed_entries = parse_map(get_var(state, "ghost_committed_blocks"));
            let last_finalized = parse_map(get_var(state, "replica_state"))
                .iter()
                .find(|(k, _)| k.as_str() == Some(node.as_str()))
                .map(|(_, v)| parse_int(&v["last_finalized"]))
                .unwrap_or(0);

            let committed_sequence = committed_entries
                .iter()
                .find(|(k, _)| k.as_str() == Some(node.as_str()))
                .and_then(|(_, v)| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|entry| {
                            if entry.is_object() {
                                Some(parse_int(&entry["view"]))
                            } else {
                                let block_name = entry.as_str()?;
                                data.finalizations
                                    .iter()
                                    .find(|(_, proposal)| {
                                        proposal.payload
                                            == block_map
                                                .get(block_name)
                                                .cloned()
                                                .unwrap_or_default()
                                    })
                                    .map(|(&v, _)| v)
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            (
                node,
                ExpectedNodeState {
                    notarizations: data
                        .notarizations
                        .iter()
                        .map(|(view, proposal)| (*view, proposal.payload.clone()))
                        .collect(),
                    nullifications: data.nullifications.clone(),
                    finalizations: data
                        .finalizations
                        .iter()
                        .map(|(view, proposal)| (*view, proposal.payload.clone()))
                        .collect(),
                    notarization_signature_counts: data.notarization_signature_counts.clone(),
                    nullification_signature_counts: data.nullification_signature_counts.clone(),
                    finalization_signature_counts: data.finalization_signature_counts.clone(),
                    last_finalized,
                    committed_sequence,
                    certified: data.certified.clone(),
                    successful_certifications: data.successful_certifications.clone(),
                    notarize_signers: data.notarize_signers.clone(),
                    nullify_signers: data.nullify_signers.clone(),
                    finalize_signers: data.finalize_signers.clone(),
                },
            )
        })
        .collect();

    ExpectedState { nodes }
}

/// Extracts reporter-like observable state from the final ITF state so traces
/// converted from Quint keep the same JSON shape as runtime-generated traces.
pub fn extract_reporter_states(
    state: &Value,
    correct_nodes: &[String],
    block_map: &HashMap<String, String>,
) -> BTreeMap<String, ReporterReplicaStateData> {
    let store_cert_map = collect_store_certificate(state);
    let store_vote_map = collect_store_vote(state);
    let sent_votes = collect_sent_vote(state);
    let replica_state_entries = parse_map(get_var(state, "replica_state"));

    let mut nodes = BTreeMap::new();
    for node in correct_nodes {
        let mut notarizations = BTreeMap::new();
        let mut notarization_signature_counts = BTreeMap::new();
        let mut nullifications = BTreeSet::new();
        let mut nullification_signature_counts = BTreeMap::new();
        let mut finalizations = BTreeMap::new();
        let mut finalization_signature_counts = BTreeMap::new();

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
                        let parent = parse_int(
                            inner
                                .get("proposal")
                                .map(|proposal| &proposal["parent"])
                                .unwrap_or(&Value::Null),
                        );
                        let block_name = inner
                            .get("proposal")
                            .and_then(|proposal| proposal["payload"].as_str())
                            .or_else(|| inner["block"].as_str())
                            .unwrap_or("");
                        let hex = block_map.get(block_name).cloned().unwrap_or_default();
                        let signature_count = parse_set(&inner["signatures"]).len();
                        notarizations.insert(
                            view,
                            TraceProposalData {
                                view,
                                parent,
                                payload: hex,
                            },
                        );
                        notarization_signature_counts.insert(view, Some(signature_count));
                    }
                    "Nullification" => {
                        let view = parse_int(&inner["view"]);
                        let signature_count = parse_set(&inner["signatures"]).len();
                        nullifications.insert(view);
                        nullification_signature_counts.insert(view, Some(signature_count));
                    }
                    "Finalization" => {
                        let view = parse_int(
                            inner
                                .get("proposal")
                                .map(|proposal| &proposal["view"])
                                .unwrap_or(&inner["view"]),
                        );
                        let parent = parse_int(
                            inner
                                .get("proposal")
                                .map(|proposal| &proposal["parent"])
                                .unwrap_or(&Value::Null),
                        );
                        let block_name = inner
                            .get("proposal")
                            .and_then(|proposal| proposal["payload"].as_str())
                            .or_else(|| inner["block"].as_str())
                            .unwrap_or("");
                        let hex = block_map.get(block_name).cloned().unwrap_or_default();
                        let signature_count = parse_set(&inner["signatures"]).len();
                        finalizations.insert(
                            view,
                            TraceProposalData {
                                view,
                                parent,
                                payload: hex,
                            },
                        );
                        finalization_signature_counts.insert(view, Some(signature_count));
                    }
                    _ => {}
                }
            }
        }

        let successful_certifications = replica_state_entries
            .iter()
            .find(|(k, _)| k.as_str() == Some(node.as_str()))
            .map(|(_, v)| {
                parse_map(&v["certified"])
                    .into_iter()
                    .filter_map(|(view, value)| parse_option(value).map(|_| parse_int(view)))
                    .collect()
            })
            .unwrap_or_default();

        let certified = notarizations
            .keys()
            .copied()
            .chain(nullifications.iter().copied())
            .chain(finalizations.keys().copied())
            .collect();

        let max_finalized_view = finalizations.keys().copied().max().unwrap_or(0);

        // Extract vote signers from store_vote + sent_vote
        let (notarize_signers, nullify_signers, finalize_signers) =
            extract_vote_signers(&store_vote_map, &sent_votes, node);

        nodes.insert(
            node.clone(),
            ReporterReplicaStateData {
                notarizations,
                notarization_signature_counts,
                nullifications,
                nullification_signature_counts,
                finalizations,
                finalization_signature_counts,
                certified,
                successful_certifications,
                notarize_signers,
                nullify_signers,
                finalize_signers,
                max_finalized_view,
            },
        );
    }

    nodes
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

/// Determines total node count from the leader map (all distinct node IDs).
pub fn count_nodes(state: &Value) -> usize {
    let mut all_nodes: BTreeSet<String> = BTreeSet::new();
    // Collect from leader map
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

/// Decodes an ITF trace JSON string into a [`TraceData`] and [`ExpectedState`].
///
/// If `n` and `faults` are not provided (set to 0), they are inferred from
/// the trace. `n` is the total node count and `faults` = n - correct_count.
pub fn decode_itf(
    json: &str,
    n_override: usize,
    faults_override: usize,
) -> Result<(TraceData, ExpectedState), DecodeError> {
    let itf: Value = serde_json::from_str(json)?;
    let states = itf["states"]
        .as_array()
        .ok_or(DecodeError::MissingField("states"))?;

    if states.is_empty() {
        return Err(DecodeError::EmptyTrace);
    }

    let state0 = &states[0];

    // Identify nodes and configuration
    let correct_nodes = identify_correct_nodes(state0);
    let n = if n_override > 0 {
        n_override
    } else {
        count_nodes(state0)
    };
    let faults = if faults_override > 0 || n_override > 0 {
        if faults_override > 0 {
            faults_override
        } else {
            n - correct_nodes.len()
        }
    } else {
        n - correct_nodes.len()
    };

    // Extract leader map and compute epoch
    let leader_map = extract_leader_map(state0);
    let epoch = compute_epoch(&leader_map, n)?;

    // Block name -> hex digest mapping (populated during parsing)
    let mut block_map: HashMap<String, String> = HashMap::new();

    // Diff consecutive states to extract trace entries
    let mut entries = Vec::new();
    let mut max_view = 0u64;

    let mut prev_votes = collect_store_vote(state0);
    let mut prev_certs = collect_store_certificate(state0);

    for next in states.iter().skip(1) {
        let next_votes = collect_store_vote(next);
        let next_certs = collect_store_certificate(next);

        // Diff votes
        for (receiver, sender, vote) in diff_store_vote(&prev_votes, &next_votes, &mut block_map) {
            max_view = max_view.max(vote_view(&vote));
            entries.push(TraceEntry::Vote {
                sender,
                receiver,
                vote,
            });
        }

        // Diff certificates
        for (receiver, sender, cert) in
            diff_store_certificate(&prev_certs, &next_certs, &mut block_map)
        {
            max_view = max_view.max(cert_view(&cert));
            entries.push(TraceEntry::Certificate {
                sender,
                receiver,
                cert,
            });
        }

        prev_votes = next_votes;
        prev_certs = next_certs;
    }

    // Extract expected state from final state
    let final_state = states.last().unwrap();
    let expected = extract_expected_state(final_state, &correct_nodes, &block_map);
    let reporter_states = extract_reporter_states(final_state, &correct_nodes, &block_map);

    let trace_data = TraceData {
        n,
        faults,
        epoch,
        max_view,
        entries,
        required_containers: 0,
        reporter_states,
    };

    Ok((trace_data, expected))
}

#[cfg(test)]
mod tests {
    use super::{block_to_hex, decode_itf};
    use std::{collections::HashMap, fs};

    #[test]
    fn block_to_hex_returns_full_deterministic_digest() {
        let mut map = HashMap::new();

        let first = block_to_hex("val_b0", &mut map);
        let second = block_to_hex("val_b0", &mut map);
        let other = block_to_hex("val_b1", &mut map);

        assert_eq!(first.len(), 64);
        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn decode_itf_splits_certificate_presence_from_successful_certification() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../quint/itf_traces/trace_roundtrip_test_26ba90da8575272103245a2ed669f37fd98f7597.itf.json"
        );
        let json = fs::read_to_string(path).expect("fixture must exist");

        let (trace, expected) = decode_itf(&json, 0, 0).expect("fixture must decode");

        let reporter_state = trace
            .reporter_states
            .get("n1")
            .expect("n1 reporter state must exist");
        assert_eq!(
            reporter_state.certified,
            [1, 2, 3, 4, 5, 6].into_iter().collect()
        );
        assert_eq!(
            reporter_state.successful_certifications,
            [2, 3, 4, 6].into_iter().collect()
        );

        let expected_node = expected
            .nodes
            .get("n1")
            .expect("n1 expected state must exist");
        assert_eq!(
            expected_node.certified,
            [1, 2, 3, 4, 5, 6].into_iter().collect()
        );
        assert_eq!(
            expected_node.successful_certifications,
            [2, 3, 4, 6].into_iter().collect()
        );
    }
}
