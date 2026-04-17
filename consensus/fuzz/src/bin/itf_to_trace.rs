//! Converts an ITF trace (from `quint run --out-itf`) into canonical
//! [`Trace`] JSON for replay against the Rust simplex engine. The
//! expected observable state is embedded as the trace's `expected`
//! [`Snapshot`] field — no sibling `_expected.json` is written.
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
use commonware_consensus_fuzz::{
    quint_model::expected_state_to_snapshot,
    tracing::{
        decoder,
        sniffer::{TraceEntry, TracedCert, TracedVote},
    },
};
use commonware_cryptography::{
    certificate::mocks::Fixture,
    sha256::{Digest as Sha256Digest, Sha256},
    Hasher,
};
use commonware_parallel::Sequential;
use commonware_utils::Participant;
use serde_json::Value;
use std::{collections::HashMap, env, fs, path::Path, process};

const NAMESPACE: &[u8] = b"consensus_fuzz";

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
///
/// For every vote that appears (as a diff between consecutive states)
/// in a receiver's store, we emit:
///   * An `Event::Construct` the first time any node produces that vote.
///   * An `Event::Deliver` for the receiver (unless sender == receiver,
///     in which case `Construct` already represents self-delivery).
///
/// For every certificate that appears in a receiver's store, we emit
/// `Event::Deliver` directly with the synthesized signed certificate.
fn build_events(
    states: &[Value],
    fixture: &Fixture<Scheme>,
    epoch: u64,
    block_hex_to_digest: &mut HashMap<String, Sha256Digest>,
    block_map_names: &mut HashMap<String, String>,
) -> Result<Vec<Event>, String> {
    let mut events: Vec<Event> = Vec::new();
    let mut constructed: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut prev_votes = decoder::collect_store_vote(&states[0]);
    let mut prev_certs = decoder::collect_store_certificate(&states[0]);

    for next in states.iter().skip(1) {
        let next_votes = decoder::collect_store_vote(next);
        let next_certs = decoder::collect_store_certificate(next);

        let vote_diffs = decoder::diff_store_vote(&prev_votes, &next_votes, block_map_names);
        for (receiver, sender, vote) in vote_diffs {
            let sender_idx = node_id_to_idx(&sender)?;
            let receiver_idx = node_id_to_idx(&receiver)?;

            let (canonical_vote, fingerprint) =
                lift_vote(&vote, fixture, epoch, sender_idx, block_hex_to_digest)?;

            // First materialization of a given signed vote -> Construct.
            let key = format!("vote:{sender_idx}:{fingerprint}");
            if constructed.insert(key) {
                events.push(Event::Construct {
                    node: Participant::new(sender_idx),
                    vote: canonical_vote.clone(),
                });
            }

            // If sender and receiver differ, log a delivery too.
            if sender_idx != receiver_idx {
                events.push(Event::Deliver {
                    to: Participant::new(receiver_idx),
                    from: Participant::new(sender_idx),
                    msg: Wire::Vote(canonical_vote),
                });
            }
        }

        let cert_diffs = decoder::diff_store_certificate(&prev_certs, &next_certs, block_map_names);
        for (receiver, sender, cert) in cert_diffs {
            let sender_idx = node_id_to_idx(&sender)?;
            let receiver_idx = node_id_to_idx(&receiver)?;

            let canonical_cert = lift_cert(&cert, fixture, epoch, block_hex_to_digest)?;

            // Delivery event. Certs don't get Construct events in this
            // conversion; the replayer only relies on Deliver for certs.
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

/// Returns a canonical `Vote` and a fingerprint string identifying its
/// identity (kind, view, payload, sig) so we can dedupe `Construct`
/// events.
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

/// Synthesize Propose events for leader proposals observed in the ITF
/// trace. Looks at notarize votes by the view's leader; the first seen
/// for a given view becomes the canonical proposal record.
fn propose_events_from_entries(
    entries: &[TraceEntry],
    _fixture: &Fixture<Scheme>,
    epoch: u64,
    n: u32,
    block_hex_to_digest: &mut HashMap<String, Sha256Digest>,
) -> Vec<Event> {
    use std::collections::BTreeMap;
    let mut by_view: BTreeMap<u64, (u64, String, u32)> = BTreeMap::new();

    for entry in entries {
        if let TraceEntry::Vote {
            vote: TracedVote::Notarize {
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

/// Walks ITF states to collect TraceEntry equivalents (for propose
/// synthesis). Mirrors `decode_itf` but just returns the per-diff
/// entries without the trace_data wrapping.
fn collect_trace_entries(states: &[Value]) -> Vec<TraceEntry> {
    let mut entries = Vec::new();
    let mut block_map_names: HashMap<String, String> = HashMap::new();
    let mut prev_votes = decoder::collect_store_vote(&states[0]);
    let mut prev_certs = decoder::collect_store_certificate(&states[0]);
    for next in states.iter().skip(1) {
        let next_votes = decoder::collect_store_vote(next);
        let next_certs = decoder::collect_store_certificate(next);
        for (receiver, sender, vote) in
            decoder::diff_store_vote(&prev_votes, &next_votes, &mut block_map_names)
        {
            entries.push(TraceEntry::Vote {
                sender,
                receiver,
                vote,
            });
        }
        for (receiver, sender, cert) in
            decoder::diff_store_certificate(&prev_certs, &next_certs, &mut block_map_names)
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

    // Infer topology from state 0 (with optional CLI overrides).
    let correct_nodes = decoder::identify_correct_nodes(state0);
    let n = if n_override > 0 {
        n_override
    } else {
        decoder::count_nodes(state0)
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

    let leader_map = decoder::extract_leader_map(state0);
    let epoch = decoder::compute_epoch(&leader_map, n).unwrap_or_else(|e| {
        eprintln!("Error computing epoch: {e}");
        process::exit(1);
    });

    // Build topology matching the fuzz-fixture convention so replayer
    // keys line up with signer indices.
    let topology = Topology {
        n: n as u32,
        faults: faults as u32,
        epoch,
        namespace: NAMESPACE.to_vec(),
        timing: Timing::default(),
    };
    let fixture = rehydrate_keys(&topology);

    // Walk ITF states. `block_hex_to_digest` maps the quint block
    // identifiers (SHA-256 hex of "val_bN" — already a 64-char hex) to
    // typed digests; `block_map_names` is the decoder-side alias map
    // used by parse_itf_vote/cert to assign val_bN names.
    let mut block_hex_to_digest: HashMap<String, Sha256Digest> = HashMap::new();
    let mut block_map_names: HashMap<String, String> = HashMap::new();

    // Pre-seed block_map_names by walking all states once, so subsequent
    // canonicalization uses a stable val_b alias ordering consistent
    // with the decoder's extract_expected_state.
    for state in states {
        let votes = decoder::collect_store_vote(state);
        for node_votes in votes.values() {
            for v in node_votes {
                if let Some(inner) = v.get("value") {
                    if let Some(name) = inner
                        .get("proposal")
                        .and_then(|p| p["payload"].as_str())
                        .or_else(|| inner["block"].as_str())
                    {
                        if !block_map_names.contains_key(name) {
                            // use the same SHA-256 hex encoding as decoder::block_to_hex
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

    // Prepend Propose events per view (synthesized from first seen
    // notarize by the leader).
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

    // Expected state from the final ITF state, lifted to Snapshot.
    let final_state = states.last().unwrap();
    let expected = decoder::extract_expected_state(final_state, &correct_nodes, &block_map_names);
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
