//! Converts an ITF trace (from `quint run --out-itf`) into canonical
//! [`Trace`] JSON for replay against the Rust simplex engine. The
//! expected observable state is embedded as the trace's `expected`
//! [`Snapshot`] field - no sibling `_expected.json` is written.
//!
//! ITF traces only carry identifier strings (`"n0"`, `"val_b0"`) rather
//! than signed bytes, so we materialize the canonical payloads by
//! signing with the deterministic [`Fixture`] rehydrated from the
//! trace's topology. The fixture's namespace + RNG must match the one
//! the replayer will use, otherwise signer indices will not align. We
//! use the same `consensus_fuzz` namespace that the fuzz recording
//! helpers (and `static_honest`) use.
//!
//! Usage:
//!   cargo run -p commonware-consensus-fuzz --bin itf_to_trace -- <trace.itf.json> <output_dir> [--n N] [--faults F]

use commonware_consensus::{
    simplex::{
        replay::{
            trace::{rehydrate_keys, Snapshot, Timing, Topology},
            Event, Trace, Wire,
        },
        scheme::ed25519::Scheme,
        types::{
            Certificate, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify,
            Proposal, Vote,
        },
    },
    types::{Epoch, Round, View},
};
use commonware_consensus_fuzz::quint_model::{
    expected_state_to_snapshot, extract_expected_state, identify_correct_nodes,
};
use commonware_cryptography::{
    certificate::mocks::Fixture,
    sha256::{Digest as Sha256Digest, Sha256},
    Hasher,
};
use commonware_parallel::Sequential;
use commonware_utils::Participant;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    env, fs,
    path::Path,
    process,
};

const NAMESPACE: &[u8] = b"consensus_fuzz";

// ---------------------------------------------------------------------------
// ITF decode helpers (inlined from the retired tracing::decoder module)
// ---------------------------------------------------------------------------

/// Traced vote reconstructed from a Quint ITF state.
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

/// Traced certificate reconstructed from a Quint ITF state.
#[derive(Clone, Debug)]
enum TracedCert {
    Notarization {
        view: u64,
        parent: u64,
        block: String,
        signers: Vec<String>,
        #[allow(dead_code)]
        ghost_sender: String,
    },
    Nullification {
        view: u64,
        signers: Vec<String>,
        #[allow(dead_code)]
        ghost_sender: String,
    },
    Finalization {
        view: u64,
        parent: u64,
        block: String,
        signers: Vec<String>,
        #[allow(dead_code)]
        ghost_sender: String,
    },
}

/// A structured trace entry capturing sender, receiver, and message.
#[derive(Clone, Debug)]
#[allow(dead_code)]
enum TraceEntry {
    Vote {
        sender: String,
        receiver: String,
        vote: TracedVote,
    },
    Certificate {
        sender: String,
        receiver: String,
        cert: TracedCert,
    },
}

/// Looks up a state variable by suffix in an ITF state object.
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

/// Converts a Quint block name (e.g. "val_b0") to a deterministic SHA-256 hex digest.
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

/// Extracts the leader map from an ITF state.
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

/// Computes the epoch from a round-robin leader map.
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

/// Determines total node count from the leader map (all distinct node IDs).
fn count_nodes(state: &Value) -> usize {
    let mut all_nodes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
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

/// Collects stored votes for each node from the split (or legacy) vote stores.
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

/// Collects stored certificates for each node from `store_certificates`.
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

/// Finds new votes delivered between two consecutive states.
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

/// Finds new certificates delivered between two consecutive states.
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
// Canonical signing helpers
// ---------------------------------------------------------------------------

fn node_id_to_idx(id: &str) -> Result<u32, String> {
    let rest = id
        .strip_prefix('n')
        .ok_or_else(|| format!("node id '{id}' missing 'n' prefix"))?;
    rest.parse::<u32>()
        .map_err(|e| format!("node id '{id}' not a u32: {e}"))
}

fn digest_from_hex(hex: &str) -> Result<Sha256Digest, String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        let pair = &hex[i * 2..i * 2 + 2];
        bytes[i] = u8::from_str_radix(pair, 16)
            .map_err(|e| format!("invalid hex pair '{pair}': {e}"))?;
    }
    Ok(Sha256Digest::from(bytes))
}

fn round_for(epoch: u64, view: u64) -> Round {
    Round::new(Epoch::new(epoch), View::new(view))
}

fn make_proposal(
    epoch: u64,
    view: u64,
    parent: u64,
    payload: Sha256Digest,
) -> Proposal<Sha256Digest> {
    Proposal::new(round_for(epoch, view), View::new(parent), payload)
}

fn sign_notarize(
    fixture: &Fixture<Scheme>,
    signer: u32,
    proposal: &Proposal<Sha256Digest>,
) -> Result<Notarize<Scheme, Sha256Digest>, String> {
    Notarize::sign(&fixture.schemes[signer as usize], proposal.clone())
        .ok_or_else(|| format!("notarize sign failed for signer {signer}"))
}

fn sign_finalize(
    fixture: &Fixture<Scheme>,
    signer: u32,
    proposal: &Proposal<Sha256Digest>,
) -> Result<Finalize<Scheme, Sha256Digest>, String> {
    Finalize::sign(&fixture.schemes[signer as usize], proposal.clone())
        .ok_or_else(|| format!("finalize sign failed for signer {signer}"))
}

fn sign_nullify(
    fixture: &Fixture<Scheme>,
    signer: u32,
    round: Round,
) -> Result<Nullify<Scheme>, String> {
    Nullify::sign::<Sha256Digest>(&fixture.schemes[signer as usize], round)
        .ok_or_else(|| format!("nullify sign failed for signer {signer}"))
}

fn notarization_cert(
    fixture: &Fixture<Scheme>,
    signers: &[u32],
    proposal: &Proposal<Sha256Digest>,
) -> Result<Notarization<Scheme, Sha256Digest>, String> {
    let votes: Result<Vec<_>, _> = signers
        .iter()
        .map(|s| sign_notarize(fixture, *s, proposal))
        .collect();
    let votes = votes?;
    Notarization::from_notarizes(&fixture.verifier, votes.iter(), &Sequential)
        .ok_or_else(|| "notarization aggregation failed".to_string())
}

fn finalization_cert(
    fixture: &Fixture<Scheme>,
    signers: &[u32],
    proposal: &Proposal<Sha256Digest>,
) -> Result<Finalization<Scheme, Sha256Digest>, String> {
    let votes: Result<Vec<_>, _> = signers
        .iter()
        .map(|s| sign_finalize(fixture, *s, proposal))
        .collect();
    let votes = votes?;
    Finalization::from_finalizes(&fixture.verifier, votes.iter(), &Sequential)
        .ok_or_else(|| "finalization aggregation failed".to_string())
}

fn nullification_cert(
    fixture: &Fixture<Scheme>,
    signers: &[u32],
    round: Round,
) -> Result<Nullification<Scheme>, String> {
    let votes: Result<Vec<_>, _> = signers
        .iter()
        .map(|s| sign_nullify(fixture, *s, round))
        .collect();
    let votes = votes?;
    Nullification::from_nullifies(&fixture.verifier, votes.iter(), &Sequential)
        .ok_or_else(|| "nullification aggregation failed".to_string())
}

/// Builds the canonical event stream from ITF state transitions.
fn build_events(
    states: &[Value],
    fixture: &Fixture<Scheme>,
    epoch: u64,
    block_hex_to_digest: &mut HashMap<String, Sha256Digest>,
    block_map_names: &mut HashMap<String, String>,
) -> Result<Vec<Event>, String> {
    let mut events: Vec<Event> = Vec::new();
    let mut constructed: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut prev_votes = collect_store_vote(&states[0]);
    let mut prev_certs = collect_store_certificate(&states[0]);

    for next in states.iter().skip(1) {
        let next_votes = collect_store_vote(next);
        let next_certs = collect_store_certificate(next);

        let vote_diffs = diff_store_vote(&prev_votes, &next_votes, block_map_names);
        for (receiver, sender, vote) in vote_diffs {
            let sender_idx = node_id_to_idx(&sender)?;
            let receiver_idx = node_id_to_idx(&receiver)?;

            let (canonical_vote, fingerprint) =
                lift_vote(&vote, fixture, epoch, sender_idx, block_hex_to_digest)?;

            let key = format!("vote:{sender_idx}:{fingerprint}");
            if constructed.insert(key) {
                events.push(Event::Construct {
                    node: Participant::new(sender_idx),
                    vote: canonical_vote.clone(),
                });
            }

            if sender_idx != receiver_idx {
                events.push(Event::Deliver {
                    to: Participant::new(receiver_idx),
                    from: Participant::new(sender_idx),
                    msg: Wire::Vote(canonical_vote),
                });
            }
        }

        let cert_diffs = diff_store_certificate(&prev_certs, &next_certs, block_map_names);
        for (receiver, sender, cert) in cert_diffs {
            let sender_idx = node_id_to_idx(&sender)?;
            let receiver_idx = node_id_to_idx(&receiver)?;

            let canonical_cert = lift_cert(&cert, fixture, epoch, block_hex_to_digest)?;

            events.push(Event::Deliver {
                to: Participant::new(receiver_idx),
                from: Participant::new(sender_idx),
                msg: Wire::Cert(canonical_cert),
            });
        }

        prev_votes = next_votes;
        prev_certs = next_certs;
    }

    Ok(events)
}

fn lift_vote(
    vote: &TracedVote,
    fixture: &Fixture<Scheme>,
    epoch: u64,
    sender_idx: u32,
    block_hex_to_digest: &mut HashMap<String, Sha256Digest>,
) -> Result<(Vote<Scheme, Sha256Digest>, String), String> {
    match vote {
        TracedVote::Notarize {
            view,
            parent,
            block,
            ..
        } => {
            let payload = canonicalize_block(block, block_hex_to_digest)?;
            let proposal = make_proposal(epoch, *view, *parent, payload);
            let n = sign_notarize(fixture, sender_idx, &proposal)?;
            let fingerprint = format!("notarize:{view}:{parent}:{block}");
            Ok((Vote::Notarize(n), fingerprint))
        }
        TracedVote::Finalize {
            view,
            parent,
            block,
            ..
        } => {
            let payload = canonicalize_block(block, block_hex_to_digest)?;
            let proposal = make_proposal(epoch, *view, *parent, payload);
            let f = sign_finalize(fixture, sender_idx, &proposal)?;
            let fingerprint = format!("finalize:{view}:{parent}:{block}");
            Ok((Vote::Finalize(f), fingerprint))
        }
        TracedVote::Nullify { view, .. } => {
            let round = round_for(epoch, *view);
            let n = sign_nullify(fixture, sender_idx, round)?;
            let fingerprint = format!("nullify:{view}");
            Ok((Vote::Nullify(n), fingerprint))
        }
    }
}

fn lift_cert(
    cert: &TracedCert,
    fixture: &Fixture<Scheme>,
    epoch: u64,
    block_hex_to_digest: &mut HashMap<String, Sha256Digest>,
) -> Result<Certificate<Scheme, Sha256Digest>, String> {
    match cert {
        TracedCert::Notarization {
            view,
            parent,
            block,
            signers,
            ..
        } => {
            let payload = canonicalize_block(block, block_hex_to_digest)?;
            let proposal = make_proposal(epoch, *view, *parent, payload);
            let signer_idxs = collect_signer_idxs(signers)?;
            Ok(Certificate::Notarization(notarization_cert(
                fixture,
                &signer_idxs,
                &proposal,
            )?))
        }
        TracedCert::Finalization {
            view,
            parent,
            block,
            signers,
            ..
        } => {
            let payload = canonicalize_block(block, block_hex_to_digest)?;
            let proposal = make_proposal(epoch, *view, *parent, payload);
            let signer_idxs = collect_signer_idxs(signers)?;
            Ok(Certificate::Finalization(finalization_cert(
                fixture,
                &signer_idxs,
                &proposal,
            )?))
        }
        TracedCert::Nullification { view, signers, .. } => {
            let round = round_for(epoch, *view);
            let signer_idxs = collect_signer_idxs(signers)?;
            Ok(Certificate::Nullification(nullification_cert(
                fixture,
                &signer_idxs,
                round,
            )?))
        }
    }
}

fn collect_signer_idxs(signers: &[String]) -> Result<Vec<u32>, String> {
    let mut idxs: Vec<u32> = signers
        .iter()
        .map(|s| node_id_to_idx(s))
        .collect::<Result<Vec<_>, _>>()?;
    idxs.sort();
    idxs.dedup();
    Ok(idxs)
}

fn canonicalize_block(
    hex: &str,
    block_hex_to_digest: &mut HashMap<String, Sha256Digest>,
) -> Result<Sha256Digest, String> {
    if let Some(d) = block_hex_to_digest.get(hex) {
        return Ok(*d);
    }
    let digest = digest_from_hex(hex)?;
    block_hex_to_digest.insert(hex.to_string(), digest);
    Ok(digest)
}

/// Synthesize Propose events for leader proposals observed in the ITF trace.
fn propose_events_from_entries(
    entries: &[TraceEntry],
    _fixture: &Fixture<Scheme>,
    epoch: u64,
    n: u32,
    block_hex_to_digest: &mut HashMap<String, Sha256Digest>,
) -> Vec<Event> {
    let mut by_view: BTreeMap<u64, (u64, String, u32)> = BTreeMap::new();

    for entry in entries {
        if let TraceEntry::Vote {
            vote:
                TracedVote::Notarize {
                    view,
                    parent,
                    sig,
                    block,
                },
            ..
        } = entry
        {
            let leader_idx = ((epoch + view) % (n as u64)) as u32;
            let Ok(sig_idx) = node_id_to_idx(sig) else {
                continue;
            };
            if sig_idx == leader_idx && !by_view.contains_key(view) {
                by_view.insert(*view, (*parent, block.clone(), leader_idx));
            }
        }
    }

    let mut out = Vec::new();
    for (view, (parent, block, leader_idx)) in by_view {
        let Ok(payload) = canonicalize_block(&block, block_hex_to_digest) else {
            continue;
        };
        let proposal = make_proposal(epoch, view, parent, payload);
        out.push(Event::Propose {
            leader: Participant::new(leader_idx),
            proposal,
        });
    }
    out
}

/// Walks ITF states to collect [`TraceEntry`] equivalents for propose synthesis.
fn collect_trace_entries(states: &[Value]) -> Vec<TraceEntry> {
    let mut entries = Vec::new();
    let mut block_map_names: HashMap<String, String> = HashMap::new();
    let mut prev_votes = collect_store_vote(&states[0]);
    let mut prev_certs = collect_store_certificate(&states[0]);
    for next in states.iter().skip(1) {
        let next_votes = collect_store_vote(next);
        let next_certs = collect_store_certificate(next);
        for (receiver, sender, vote) in
            diff_store_vote(&prev_votes, &next_votes, &mut block_map_names)
        {
            entries.push(TraceEntry::Vote {
                sender,
                receiver,
                vote,
            });
        }
        for (receiver, sender, cert) in
            diff_store_certificate(&prev_certs, &next_certs, &mut block_map_names)
        {
            entries.push(TraceEntry::Certificate {
                sender,
                receiver,
                cert,
            });
        }
        prev_votes = next_votes;
        prev_certs = next_certs;
    }
    entries
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut itf_path = None;
    let mut output_dir = None;
    let mut n_override: usize = 0;
    let mut faults_override: usize = 0;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--n" => {
                i += 1;
                n_override = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--faults" => {
                i += 1;
                faults_override = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
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

    let itf: Value = serde_json::from_str(&json).unwrap_or_else(|e| {
        eprintln!("Error parsing ITF JSON: {e}");
        process::exit(1);
    });

    let states = itf["states"].as_array().unwrap_or_else(|| {
        eprintln!("ITF JSON missing 'states' array");
        process::exit(1);
    });

    if states.is_empty() {
        eprintln!("ITF trace contains no states");
        process::exit(1);
    }

    let state0 = &states[0];

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

    let leader_map = extract_leader_map(state0);
    let epoch = compute_epoch(&leader_map, n).unwrap_or_else(|e| {
        eprintln!("Error computing epoch: {e}");
        process::exit(1);
    });

    let topology = Topology {
        n: n as u32,
        faults: faults as u32,
        epoch,
        namespace: NAMESPACE.to_vec(),
        timing: Timing::default(),
    };
    let fixture = rehydrate_keys(&topology);

    let mut block_hex_to_digest: HashMap<String, Sha256Digest> = HashMap::new();
    let mut block_map_names: HashMap<String, String> = HashMap::new();

    // Pre-seed block_map_names by walking all states so canonicalization
    // uses a stable val_b alias ordering.
    for state in states {
        let votes = collect_store_vote(state);
        for node_votes in votes.values() {
            for v in node_votes {
                let Some(inner) = v.get("value") else {
                    continue;
                };
                let Some(name) = inner
                    .get("proposal")
                    .and_then(|p| p["payload"].as_str())
                    .or_else(|| inner["block"].as_str())
                else {
                    continue;
                };
                if !block_map_names.contains_key(name) {
                    let hash = Sha256::hash(name.as_bytes());
                    let hex: String = hash
                        .as_ref()
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    block_map_names.insert(name.to_string(), hex);
                }
            }
        }
    }

    let mut events = build_events(
        states,
        &fixture,
        epoch,
        &mut block_hex_to_digest,
        &mut block_map_names,
    )
    .unwrap_or_else(|e| {
        eprintln!("Error building events: {e}");
        process::exit(1);
    });

    let entries = collect_trace_entries(states);
    let mut propose_events = propose_events_from_entries(
        &entries,
        &fixture,
        epoch,
        n as u32,
        &mut block_hex_to_digest,
    );
    propose_events.extend(events.drain(..));
    events = propose_events;

    let final_state = states.last().unwrap();
    let expected = extract_expected_state(final_state, &correct_nodes, &block_map_names);
    let snapshot: Snapshot = expected_state_to_snapshot(&expected).unwrap_or_else(|e| {
        eprintln!("Error converting expected state: {e}");
        process::exit(1);
    });

    let trace = Trace {
        topology,
        events,
        expected: snapshot,
    };

    println!(
        "Decoded ITF trace: n={}, faults={}, epoch={}, events={}, expected_nodes={}",
        n,
        faults,
        epoch,
        trace.events.len(),
        trace.expected.nodes.len()
    );

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
    let trace_json = trace.to_json().unwrap_or_else(|e| {
        eprintln!("Error serializing trace: {e}");
        process::exit(1);
    });
    fs::write(&trace_out, trace_json).unwrap_or_else(|e| {
        eprintln!("Error writing {}: {e}", trace_out.display());
        process::exit(1);
    });
    println!("Wrote trace: {}", trace_out.display());
}
