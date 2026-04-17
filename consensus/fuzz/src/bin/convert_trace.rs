//! Convert a legacy `fuzz::tracing::data::TraceData` JSON file into the
//! new `commonware_consensus::simplex::replay::Trace` format.
//!
//! Usage:
//!   cargo run -p commonware-consensus-fuzz --bin convert_trace -- <in.json> [out.json]
//!
//! If `out.json` is omitted the new trace is written to stdout. Payloads
//! are re-signed from scratch using the canonical `seeded(0)` ed25519
//! fixture so the output is self-contained — no re-use of the original
//! fuzz RNG.

use commonware_consensus::{
    simplex::{
        replay::{
            trace::{
                CertStateSnapshot, Event, NodeSnapshot, NullStateSnapshot, Snapshot, Timing,
                Topology, Trace, Wire,
            },
        },
        scheme::ed25519,
        types::{
            Certificate, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify,
            Proposal, Vote,
        },
    },
    types::{Epoch, Round, View},
};
use commonware_consensus_fuzz::{
    replayer::compare::{ExpectedNodeState, ExpectedState},
    tracing::{
        data::{ReporterReplicaStateData, TraceData},
        sniffer::{TraceEntry, TracedCert, TracedVote},
    },
};
use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{deterministic, Runner};
use commonware_utils::Participant;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    env, fs, process,
};

type Scheme = ed25519::Scheme;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: convert_trace <in.json> [out.json]");
        process::exit(1);
    }
    let in_path = &args[1];
    let out_path = args.get(2).cloned();

    let json = fs::read_to_string(in_path).unwrap_or_else(|e| {
        eprintln!("read {in_path}: {e}");
        process::exit(1);
    });
    let old: TraceData = serde_json::from_str(&json).unwrap_or_else(|e| {
        eprintln!("parse {in_path}: {e}");
        process::exit(1);
    });

    let trace = convert(&old);
    let out_json = trace.to_json().unwrap_or_else(|e| {
        eprintln!("encode: {e}");
        process::exit(1);
    });

    match out_path {
        Some(p) => {
            fs::write(&p, &out_json).unwrap_or_else(|e| {
                eprintln!("write {p}: {e}");
                process::exit(1);
            });
            eprintln!(
                "wrote {} events ({} bytes) to {p}",
                trace.events.len(),
                out_json.len()
            );
        }
        None => println!("{out_json}"),
    }
}

/// Canonical namespace — hardcoded for iteration 1.
const NAMESPACE: &[u8] = b"consensus_fuzz";

fn convert(old: &TraceData) -> Trace {
    let topology = Topology {
        n: old.n as u32,
        faults: old.faults as u32,
        epoch: old.epoch,
        namespace: NAMESPACE.to_vec(),
        timing: Timing::default(),
    };

    // Rehydrate keys using the same procedure the replayer uses so that
    // the re-signed payloads are verifiable against the replayer's own
    // fixture.
    let fixture = rehydrate(&topology);
    let schemes = &fixture.schemes;
    let participants = fixture.participants.clone();

    let events = convert_entries(
        &old.entries,
        old.n as u32,
        old.faults,
        old.epoch,
        schemes,
    );
    // Prefer the Quint-derived expected_state if present — that's the
    // spec-level ground truth. Fall back to the harness's reporter_states
    // only when expected_state is absent (honest-pipeline fixtures never
    // populated it).
    let expected = match old.expected_state.as_ref() {
        Some(exp) => convert_from_expected(exp),
        None => convert_snapshot(&old.reporter_states, old.faults),
    };

    // Sanity check: every participant in the fixture is valid.
    debug_assert_eq!(participants.len(), old.n);

    Trace {
        topology,
        events,
        expected,
    }
}

fn rehydrate(topology: &Topology) -> Fixture<Scheme> {
    let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
    let captured_clone = captured.clone();
    let namespace = topology.namespace.clone();
    let n = topology.n;
    let runner = deterministic::Runner::seeded(0);
    runner.start(|mut ctx| async move {
        let fixture = ed25519::fixture(&mut ctx, &namespace, n);
        *captured_clone.lock().unwrap() = Some(fixture);
    });
    let mut guard = captured.lock().unwrap();
    guard.take().expect("fixture captured")
}

fn convert_entries(
    entries: &[TraceEntry],
    n: u32,
    faults: usize,
    epoch: u64,
    schemes: &[Scheme],
) -> Vec<Event> {
    let mut events = Vec::new();

    // Track proposals we've already emitted a Propose for. Keyed by
    // (view, parent, payload) — the automaton's release is keyed by
    // (view, parent) but different payloads are distinct proposals.
    let mut seen_proposals: HashSet<(u64, u64, String)> = HashSet::new();

    // Track correct-signer Nullify/Finalize votes we've already emitted
    // Construct for.
    let mut emitted_construct_nullify: HashSet<(usize, u64)> = HashSet::new();
    let mut emitted_construct_finalize: HashSet<(usize, u64, u64, String)> = HashSet::new();

    for entry in entries {
        match entry {
            TraceEntry::Vote {
                sender,
                receiver,
                vote,
            } => {
                // If this is a Notarize or Finalize, it references a
                // proposal. Emit Propose once.
                maybe_emit_propose(vote, &mut seen_proposals, &mut events, epoch, n);

                // Build signed vote.
                let signed = sign_vote(vote, schemes, epoch);

                // Construct for correct-signer Nullify/Finalize.
                let sig_idx = match vote {
                    TracedVote::Notarize { sig, .. }
                    | TracedVote::Nullify { sig, .. }
                    | TracedVote::Finalize { sig, .. } => parse_node(sig),
                };
                if sig_idx >= faults {
                    match vote {
                        TracedVote::Nullify { view, .. } => {
                            if emitted_construct_nullify.insert((sig_idx, *view)) {
                                events.push(Event::Construct {
                                    node: Participant::new(sig_idx as u32),
                                    vote: signed.clone(),
                                });
                            }
                        }
                        TracedVote::Finalize {
                            view,
                            parent,
                            block,
                            ..
                        } => {
                            if emitted_construct_finalize.insert((
                                sig_idx,
                                *view,
                                *parent,
                                block.clone(),
                            )) {
                                events.push(Event::Construct {
                                    node: Participant::new(sig_idx as u32),
                                    vote: signed.clone(),
                                });
                            }
                        }
                        TracedVote::Notarize { .. } => {}
                    }
                }

                events.push(Event::Deliver {
                    to: Participant::new(parse_node(receiver) as u32),
                    from: Participant::new(parse_node(sender) as u32),
                    msg: Wire::Vote(signed),
                });
            }
            TraceEntry::Certificate {
                sender,
                receiver,
                cert,
            } => {
                // Propose from cert-carried proposal.
                maybe_emit_propose_from_cert(cert, &mut seen_proposals, &mut events, epoch, n);

                let assembled = assemble_cert(cert, schemes, epoch);
                events.push(Event::Deliver {
                    to: Participant::new(parse_node(receiver) as u32),
                    from: Participant::new(parse_node(sender) as u32),
                    msg: Wire::Cert(assembled),
                });
            }
        }
    }

    events
}

fn maybe_emit_propose(
    vote: &TracedVote,
    seen: &mut HashSet<(u64, u64, String)>,
    out: &mut Vec<Event>,
    epoch: u64,
    n: u32,
) {
    let (view, parent, block) = match vote {
        TracedVote::Notarize {
            view,
            parent,
            block,
            ..
        }
        | TracedVote::Finalize {
            view,
            parent,
            block,
            ..
        } => (*view, *parent, block.clone()),
        TracedVote::Nullify { .. } => return,
    };
    emit_propose(seen, out, epoch, view, parent, &block, n);
}

fn maybe_emit_propose_from_cert(
    cert: &TracedCert,
    seen: &mut HashSet<(u64, u64, String)>,
    out: &mut Vec<Event>,
    epoch: u64,
    n: u32,
) {
    let (view, parent, block) = match cert {
        TracedCert::Notarization {
            view,
            parent,
            block,
            ..
        }
        | TracedCert::Finalization {
            view,
            parent,
            block,
            ..
        } => (*view, *parent, block.clone()),
        TracedCert::Nullification { .. } => return,
    };
    emit_propose(seen, out, epoch, view, parent, &block, n);
}

fn emit_propose(
    seen: &mut HashSet<(u64, u64, String)>,
    out: &mut Vec<Event>,
    epoch: u64,
    view: u64,
    parent: u64,
    block: &str,
    n: u32,
) {
    let key = (view, parent, block.to_string());
    if !seen.insert(key) {
        return;
    }
    let digest = digest_from_hex(block);
    let proposal = Proposal::new(
        Round::new(Epoch::new(epoch), View::new(view)),
        View::new(parent),
        digest,
    );
    let leader_idx = ((epoch + view) % n as u64) as u32;
    out.push(Event::Propose {
        leader: Participant::new(leader_idx),
        proposal,
    });
}

fn sign_vote(vote: &TracedVote, schemes: &[Scheme], epoch: u64) -> Vote<Scheme, Sha256Digest> {
    match vote {
        TracedVote::Notarize {
            view,
            parent,
            sig,
            block,
        } => {
            let signer = parse_node(sig);
            let proposal = Proposal::new(
                Round::new(Epoch::new(epoch), View::new(*view)),
                View::new(*parent),
                digest_from_hex(block),
            );
            let n = Notarize::<Scheme, Sha256Digest>::sign(&schemes[signer], proposal)
                .expect("sign notarize");
            Vote::Notarize(n)
        }
        TracedVote::Nullify { view, sig } => {
            let signer = parse_node(sig);
            let round = Round::new(Epoch::new(epoch), View::new(*view));
            let n = Nullify::<Scheme>::sign::<Sha256Digest>(&schemes[signer], round)
                .expect("sign nullify");
            Vote::Nullify(n)
        }
        TracedVote::Finalize {
            view,
            parent,
            sig,
            block,
        } => {
            let signer = parse_node(sig);
            let proposal = Proposal::new(
                Round::new(Epoch::new(epoch), View::new(*view)),
                View::new(*parent),
                digest_from_hex(block),
            );
            let f = Finalize::<Scheme, Sha256Digest>::sign(&schemes[signer], proposal)
                .expect("sign finalize");
            Vote::Finalize(f)
        }
    }
}

fn assemble_cert(
    cert: &TracedCert,
    schemes: &[Scheme],
    epoch: u64,
) -> Certificate<Scheme, Sha256Digest> {
    let strategy = Sequential;
    match cert {
        TracedCert::Notarization {
            view,
            parent,
            block,
            signers,
            ..
        } => {
            let proposal = Proposal::new(
                Round::new(Epoch::new(epoch), View::new(*view)),
                View::new(*parent),
                digest_from_hex(block),
            );
            let notarizes: Vec<_> = signers
                .iter()
                .map(|s| {
                    let idx = parse_node(s);
                    Notarize::<Scheme, Sha256Digest>::sign(&schemes[idx], proposal.clone())
                        .expect("sign notarize")
                })
                .collect();
            let n = Notarization::from_notarizes(&schemes[0], notarizes.iter(), &strategy)
                .expect("assemble notarization");
            Certificate::Notarization(n)
        }
        TracedCert::Nullification { view, signers, .. } => {
            let round = Round::new(Epoch::new(epoch), View::new(*view));
            let nullifies: Vec<_> = signers
                .iter()
                .map(|s| {
                    let idx = parse_node(s);
                    Nullify::<Scheme>::sign::<Sha256Digest>(&schemes[idx], round)
                        .expect("sign nullify")
                })
                .collect();
            let n = Nullification::from_nullifies(&schemes[0], nullifies.iter(), &strategy)
                .expect("assemble nullification");
            Certificate::Nullification(n)
        }
        TracedCert::Finalization {
            view,
            parent,
            block,
            signers,
            ..
        } => {
            let proposal = Proposal::new(
                Round::new(Epoch::new(epoch), View::new(*view)),
                View::new(*parent),
                digest_from_hex(block),
            );
            let finalizes: Vec<_> = signers
                .iter()
                .map(|s| {
                    let idx = parse_node(s);
                    Finalize::<Scheme, Sha256Digest>::sign(&schemes[idx], proposal.clone())
                        .expect("sign finalize")
                })
                .collect();
            let f = Finalization::from_finalizes(&schemes[0], finalizes.iter(), &strategy)
                .expect("assemble finalization");
            Certificate::Finalization(f)
        }
    }
}

fn convert_snapshot(
    states: &BTreeMap<String, ReporterReplicaStateData>,
    _faults: usize,
) -> Snapshot {
    let mut nodes = BTreeMap::new();
    for (node_id, state) in states {
        let idx = parse_node(node_id) as u32;
        // The converter preserves signer observations verbatim. Past-
        // horizon observations are timing-noisy in both directions
        // (legacy harness misses self-votes; new replay catches them);
        // the replay integration test filters both sides to the stable
        // window for comparison.
        let snap = NodeSnapshot {
            notarizations: state
                .notarizations
                .iter()
                .map(|(view, p)| {
                    (
                        View::new(*view),
                        CertStateSnapshot {
                            payload: digest_from_hex(&p.payload),
                            signature_count: state
                                .notarization_signature_counts
                                .get(view)
                                .copied()
                                .flatten()
                                .map(|n| n as u32),
                        },
                    )
                })
                .collect(),
            nullifications: state
                .nullifications
                .iter()
                .map(|view| {
                    (
                        View::new(*view),
                        NullStateSnapshot {
                            signature_count: state
                                .nullification_signature_counts
                                .get(view)
                                .copied()
                                .flatten()
                                .map(|n| n as u32),
                        },
                    )
                })
                .collect(),
            finalizations: state
                .finalizations
                .iter()
                .map(|(view, p)| {
                    (
                        View::new(*view),
                        CertStateSnapshot {
                            payload: digest_from_hex(&p.payload),
                            signature_count: state
                                .finalization_signature_counts
                                .get(view)
                                .copied()
                                .flatten()
                                .map(|n| n as u32),
                        },
                    )
                })
                .collect(),
            certified: state.certified.iter().map(|v| View::new(*v)).collect(),
            notarize_signers: sig_map(&state.notarize_signers),
            nullify_signers: sig_map(&state.nullify_signers),
            finalize_signers: sig_map(&state.finalize_signers),
            last_finalized: View::new(state.max_finalized_view),
        };
        nodes.insert(Participant::new(idx), snap);
    }
    Snapshot { nodes }
}

fn convert_from_expected(exp: &ExpectedState) -> Snapshot {
    let mut nodes = BTreeMap::new();
    for (node_id, state) in &exp.nodes {
        let idx = parse_node(node_id) as u32;
        let snap = convert_expected_node(state);
        nodes.insert(Participant::new(idx), snap);
    }
    Snapshot { nodes }
}

fn convert_expected_node(state: &ExpectedNodeState) -> NodeSnapshot {
    NodeSnapshot {
        notarizations: state
            .notarizations
            .iter()
            .map(|(view, payload)| {
                (
                    View::new(*view),
                    CertStateSnapshot {
                        payload: digest_from_hex(payload),
                        signature_count: state
                            .notarization_signature_counts
                            .get(view)
                            .copied()
                            .flatten()
                            .map(|n| n as u32),
                    },
                )
            })
            .collect(),
        nullifications: state
            .nullifications
            .iter()
            .map(|view| {
                (
                    View::new(*view),
                    NullStateSnapshot {
                        signature_count: state
                            .nullification_signature_counts
                            .get(view)
                            .copied()
                            .flatten()
                            .map(|n| n as u32),
                    },
                )
            })
            .collect(),
        finalizations: state
            .finalizations
            .iter()
            .map(|(view, payload)| {
                (
                    View::new(*view),
                    CertStateSnapshot {
                        payload: digest_from_hex(payload),
                        signature_count: state
                            .finalization_signature_counts
                            .get(view)
                            .copied()
                            .flatten()
                            .map(|n| n as u32),
                    },
                )
            })
            .collect(),
        certified: state.certified.iter().map(|v| View::new(*v)).collect(),
        notarize_signers: sig_map(&state.notarize_signers),
        nullify_signers: sig_map(&state.nullify_signers),
        finalize_signers: sig_map(&state.finalize_signers),
        last_finalized: View::new(state.last_finalized),
    }
}

fn sig_map(m: &BTreeMap<u64, BTreeSet<String>>) -> BTreeMap<View, BTreeSet<Participant>> {
    m.iter()
        .map(|(view, sigs)| {
            (
                View::new(*view),
                sigs.iter()
                    .map(|s| Participant::new(parse_node(s) as u32))
                    .collect(),
            )
        })
        .collect()
}

fn parse_node(id: &str) -> usize {
    id.strip_prefix('n')
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("invalid node id {id:?}"))
}

fn digest_from_hex(hex: &str) -> Sha256Digest {
    assert_eq!(hex.len(), 64, "digest must be 64 hex chars: {hex:?}");
    let mut bytes = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
            .expect("valid hex pair");
    }
    Sha256Digest::from(bytes)
}
