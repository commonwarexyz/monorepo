//! Encodes a simplex consensus trace into a quint test file.
//!
//! Takes structured [`TraceEntry`] items from the sniffer and produces
//! a complete `.qnt` test module that can be verified with the quint
//! model checker against `replica.qnt`.

use super::sniffer::{TraceEntry, TracedCert, TracedVote};
use std::{
    collections::{HashMap, HashSet},
    fmt::Write,
};

/// Returns true if the node ID (e.g. "n0") is Byzantine (index < faults).
fn is_byzantine_node(node: &str, faults: usize) -> bool {
    if let Some(idx_str) = node.strip_prefix('n') {
        if let Ok(idx) = idx_str.parse::<usize>() {
            return idx < faults;
        }
    }
    false
}

/// Configuration for the quint test encoder.
pub struct EncoderConfig {
    /// Number of validators.
    pub n: usize,
    /// Number of Byzantine (faulty) validators.
    pub faults: usize,
    /// Epoch used by the round-robin elector.
    pub epoch: u64,
    /// Maximum view to include in VIEWS range.
    pub max_view: u64,
    /// Expected finalized containers for each honest node.
    pub required_containers: u64,
}

/// Encodes trace entries into a quint test module.
pub fn encode(entries: &[TraceEntry], cfg: &EncoderConfig) -> String {
    // Filter out entries where the receiver is Byzantine (no state in quint model)
    let correct_entries: Vec<TraceEntry> = entries
        .iter()
        .filter(|e| {
            let receiver = match e {
                TraceEntry::Vote { receiver, .. } => receiver,
                TraceEntry::Certificate { receiver, .. } => receiver,
            };
            !is_byzantine_node(receiver, cfg.faults)
        })
        .cloned()
        .collect();

    let block_map = build_block_map(&correct_entries);
    let leader_map = build_leader_map(cfg);

    let block_names: Vec<&str> = block_map.iter().map(|(_, n)| n.as_str()).collect();
    let f = (cfg.n - 1) / 3;
    let q = cfg.n - f;

    let mut out = String::new();

    // Module header
    writeln!(out, "module tests {{").unwrap();
    writeln!(out, "    import types.* from \"../types\"").unwrap();
    writeln!(out, "    import defs.* from \"../defs\"").unwrap();
    writeln!(out, "    import option.* from \"../option\"").unwrap();

    // Automaton import with certify domain
    write!(out, "    import automaton(\n        CERTIFY_DOMAIN = Set(").unwrap();
    let all_blocks: Vec<String> = block_names.iter().map(|b| format!("\"{}\"", b)).collect();
    write!(out, "{}", all_blocks.join(", ")).unwrap();
    writeln!(out, "),").unwrap();
    writeln!(out, "    ) as app from \"../automaton\"").unwrap();

    // Replica import
    writeln!(out, "    import replica(").unwrap();
    writeln!(out, "        N = {},", cfg.n).unwrap();
    writeln!(out, "        F = {},", f).unwrap();
    writeln!(out, "        Q = {},", q).unwrap();

    // CORRECT / BYZANTINE sets
    let correct: Vec<String> = (cfg.faults..cfg.n).map(|i| format!("\"n{}\"", i)).collect();
    writeln!(out, "        CORRECT = Set({}),", correct.join(", ")).unwrap();
    let byzantine: Vec<String> = (0..cfg.faults).map(|i| format!("\"n{}\"", i)).collect();
    if byzantine.is_empty() {
        writeln!(out, "        BYZANTINE = Set(),").unwrap();
    } else {
        writeln!(out, "        BYZANTINE = Set({}),", byzantine.join(", ")).unwrap();
    }

    // REPLICA_KEYS
    let keys: Vec<String> = (0..cfg.n)
        .map(|i| format!("\"n{}\"->\"n{}\"", i, i))
        .collect();
    writeln!(out, "        REPLICA_KEYS = Map({}),", keys.join(", ")).unwrap();

    writeln!(out, "        VIEWS = 1.to({}),", cfg.max_view).unwrap();

    // VALID_BLOCKS
    write!(out, "        VALID_BLOCKS = Set(").unwrap();
    write!(out, "{}", all_blocks.join(", ")).unwrap();
    writeln!(out, "),").unwrap();
    writeln!(out, "        INVALID_BLOCKS = Set()").unwrap();
    writeln!(out, "    ).* from \"../replica\"").unwrap();
    writeln!(out).unwrap();

    // Certify policy
    writeln!(out, "    pure val CERTIFY_POLICY = Map(").unwrap();
    writeln!(out, "        GENESIS_BLOCK -> true,").unwrap();
    for name in &block_names {
        writeln!(out, "        \"{}\" -> true,", name).unwrap();
    }
    writeln!(out, "    )").unwrap();
    writeln!(
        out,
        "    pure val CERTIFY_CUSTOM = Replicas.mapBy(_ => CERTIFY_POLICY)"
    )
    .unwrap();
    writeln!(out).unwrap();

    // Generate actions with self-vote injection
    let actions = build_actions(&correct_entries, &block_map, cfg);

    // Split actions into chunks of CHUNK_SIZE, emitting trace_part_NN actions
    const CHUNK_SIZE: usize = 25;
    let chunks: Vec<&[String]> = actions.chunks(CHUNK_SIZE).collect();

    let leader_init = {
        let leader_entries: Vec<String> = leader_map
            .iter()
            .map(|(v, id)| format!("{} -> \"{}\"", v, id))
            .collect();
        format!(
            "initWithLeaderAndCertify(\n            Map({}),\n            CERTIFY_CUSTOM\n        )",
            leader_entries.join(", ")
        )
    };

    for (i, chunk) in chunks.iter().enumerate() {
        writeln!(out, "    action trace_part_{:02} =", i).unwrap();
        if i == 0 {
            writeln!(out, "        {}", leader_init).unwrap();
        } else {
            writeln!(out, "        trace_part_{:02}", i - 1).unwrap();
        }
        for action in *chunk {
            writeln!(out, "            .then({})", action).unwrap();
        }
        writeln!(out, "            .expect(all_invariants)").unwrap();
        writeln!(out).unwrap();
    }

    // Final run references the last part
    let last_part = if chunks.is_empty() {
        leader_init
    } else {
        format!("trace_part_{:02}", chunks.len() - 1)
    };
    writeln!(out, "    run traceTest =").unwrap();
    writeln!(out, "        {}", last_part).unwrap();
    writeln!(out, "            .expect(all_invariants)").unwrap();
    // Assert that all correct nodes finalized the expected number of containers
    if cfg.required_containers > 0 {
        for i in cfg.faults..cfg.n {
            writeln!(
                out,
                "            .expect(replica_state.get(\"n{}\").last_finalized >= {})",
                i, cfg.required_containers
            )
            .unwrap();
        }
    }
    writeln!(out).unwrap();

    // Helper actions
    write_helpers(&mut out);

    writeln!(out, "}}").unwrap();
    out
}

/// Identifies a vote type for self-delivery tracking.
#[derive(Hash, Eq, PartialEq)]
enum VoteKey {
    Notarize(String, u64, String), // (node, view, block)
    Nullify(String, u64),          // (node, view)
    Finalize(String, u64, String), // (node, view, block)
}

/// Builds the full action list, injecting self-vote deliveries before
/// cross-node deliveries. In the real implementation each node counts
/// its own vote; the quint model needs this delivered explicitly.
fn build_actions(
    entries: &[TraceEntry],
    block_map: &[(String, String)],
    cfg: &EncoderConfig,
) -> Vec<String> {
    let mut actions = Vec::new();
    let mut self_delivered: HashSet<VoteKey> = HashSet::new();

    // Collect all (signer, view, vote_type) combos from the trace
    // to know which self-deliveries are needed
    #[allow(clippy::type_complexity)]
    let mut all_signers: HashMap<(u64, &str), Vec<(&str, Option<&str>)>> = HashMap::new();
    for entry in entries {
        if let TraceEntry::Vote { vote, .. } = entry {
            match vote {
                TracedVote::Notarize { view, sig, block } => {
                    all_signers
                        .entry((*view, "notarize"))
                        .or_default()
                        .push((sig.as_str(), Some(block.as_str())));
                }
                TracedVote::Nullify { view, sig } => {
                    all_signers
                        .entry((*view, "nullify"))
                        .or_default()
                        .push((sig.as_str(), None));
                }
                TracedVote::Finalize { view, sig, block } => {
                    all_signers
                        .entry((*view, "finalize"))
                        .or_default()
                        .push((sig.as_str(), Some(block.as_str())));
                }
            }
        }
    }

    // Deduplicate signers per (view, type)
    #[allow(clippy::type_complexity)]
    let mut unique_signers: HashMap<(u64, &str), Vec<(String, Option<String>)>> = HashMap::new();
    for ((view, vtype), items) in &all_signers {
        let mut seen = HashSet::new();
        for (sig, block) in items {
            if seen.insert(*sig) {
                unique_signers
                    .entry((*view, vtype))
                    .or_default()
                    .push((sig.to_string(), block.map(|b| b.to_string())));
            }
        }
    }

    for entry in entries {
        match entry {
            TraceEntry::Vote { vote, .. } => {
                // Before delivering a cross-node vote, inject self-deliveries
                // for ALL signers of this (view, type) group
                let (view, vtype) = match vote {
                    TracedVote::Notarize { view, .. } => (*view, "notarize"),
                    TracedVote::Nullify { view, .. } => (*view, "nullify"),
                    TracedVote::Finalize { view, .. } => (*view, "finalize"),
                };

                if let Some(signers) = unique_signers.get(&(view, vtype)) {
                    for (sig, block) in signers {
                        // Skip self-delivery for Byzantine nodes
                        if is_byzantine_node(sig, cfg.faults) {
                            continue;
                        }
                        let key = match vtype {
                            "notarize" => VoteKey::Notarize(
                                sig.clone(),
                                view,
                                block.as_ref().unwrap().clone(),
                            ),
                            "nullify" => VoteKey::Nullify(sig.clone(), view),
                            "finalize" => VoteKey::Finalize(
                                sig.clone(),
                                view,
                                block.as_ref().unwrap().clone(),
                            ),
                            _ => unreachable!(),
                        };
                        if self_delivered.insert(key) {
                            // Inject self-delivery: node receives its own vote
                            let self_action = match vtype {
                                "notarize" => {
                                    let bn = map_block(block.as_ref().unwrap(), block_map);
                                    format!(
                                        "replica_receives_notarize_vote(\"{}\", \"{}\", {}, \"{}\")",
                                        sig, bn, view, sig
                                    )
                                }
                                "nullify" => {
                                    format!(
                                        "replica_receives_nullify_vote(\"{}\", {}, \"{}\")",
                                        sig, view, sig
                                    )
                                }
                                "finalize" => {
                                    let bn = map_block(block.as_ref().unwrap(), block_map);
                                    format!(
                                        "replica_receives_finalize_vote(\"{}\", \"{}\", {}, \"{}\")",
                                        sig, bn, view, sig
                                    )
                                }
                                _ => unreachable!(),
                            };
                            actions.push(self_action);
                        }
                    }
                }

                // Now emit the actual trace entry
                actions.push(encode_entry(entry, block_map));
            }
            TraceEntry::Certificate { .. } => {
                actions.push(encode_entry(entry, block_map));
            }
        }
    }
    // Deduplicate consecutive identical actions
    actions.dedup();
    // Remove self-deliveries that duplicate a following cross-node delivery
    // (e.g., if trace already has "n0 receives from n0")
    let mut deduped = Vec::new();
    let mut seen_actions: HashSet<String> = HashSet::new();
    for action in actions {
        if seen_actions.insert(action.clone()) {
            deduped.push(action);
        }
    }
    deduped
}

/// Maps block hashes to val_b0, val_b1, ... in order of first appearance.
fn build_block_map(entries: &[TraceEntry]) -> Vec<(String, String)> {
    let mut map = Vec::new();
    let mut seen = HashMap::new();
    for entry in entries {
        let hash = match entry {
            TraceEntry::Vote {
                vote: TracedVote::Notarize { block, .. },
                ..
            }
            | TraceEntry::Vote {
                vote: TracedVote::Finalize { block, .. },
                ..
            }
            | TraceEntry::Certificate {
                cert: TracedCert::Notarization { block, .. },
                ..
            }
            | TraceEntry::Certificate {
                cert: TracedCert::Finalization { block, .. },
                ..
            } => Some(block.clone()),
            _ => None,
        };
        if let Some(h) = hash {
            if !seen.contains_key(&h) {
                let name = format!("val_b{}", map.len());
                seen.insert(h.clone(), name.clone());
                map.push((h, name));
            }
        }
    }
    map
}

/// Builds the leader map: view -> replica ID using round-robin.
fn build_leader_map(cfg: &EncoderConfig) -> Vec<(u64, String)> {
    let mut map = Vec::new();
    for view in 0..=cfg.max_view {
        let leader_idx = (cfg.epoch + view) as usize % cfg.n;
        map.push((view, format!("n{}", leader_idx)));
    }
    map
}

/// Converts a block hash to its val_bN name.
fn map_block(hash: &str, block_map: &[(String, String)]) -> String {
    for (h, name) in block_map {
        if h == hash {
            return name.clone();
        }
    }
    hash.to_string()
}

/// Encodes a single trace entry into a quint action call.
fn encode_entry(entry: &TraceEntry, block_map: &[(String, String)]) -> String {
    match entry {
        TraceEntry::Vote { receiver, vote, .. } => match vote {
            TracedVote::Notarize { view, sig, block } => {
                let block_name = map_block(block, block_map);
                format!(
                    "replica_receives_notarize_vote(\"{}\", \"{}\", {}, \"{}\")",
                    receiver, block_name, view, sig
                )
            }
            TracedVote::Nullify { view, sig } => {
                format!(
                    "replica_receives_nullify_vote(\"{}\", {}, \"{}\")",
                    receiver, view, sig
                )
            }
            TracedVote::Finalize { view, sig, block } => {
                let block_name = map_block(block, block_map);
                format!(
                    "replica_receives_finalize_vote(\"{}\", \"{}\", {}, \"{}\")",
                    receiver, block_name, view, sig
                )
            }
        },
        TraceEntry::Certificate { receiver, cert, .. } => {
            let cert_str = encode_cert(cert, block_map);
            format!("on_certificate(\"{}\", {})", receiver, cert_str)
        }
    }
}

/// Encodes a certificate as a quint constructor call.
fn encode_cert(cert: &TracedCert, block_map: &[(String, String)]) -> String {
    match cert {
        TracedCert::Notarization {
            view,
            block,
            signers,
            ghost_sender,
        } => {
            let block_name = map_block(block, block_map);
            let sigs: Vec<String> = signers.iter().map(|s| format!("\"{}\"", s)).collect();
            format!(
                "notarization({}, \"{}\", Set({}), \"{}\")",
                view,
                block_name,
                sigs.join(", "),
                ghost_sender
            )
        }
        TracedCert::Nullification {
            view,
            signers,
            ghost_sender,
        } => {
            let sigs: Vec<String> = signers.iter().map(|s| format!("\"{}\"", s)).collect();
            format!(
                "nullification({}, Set({}), \"{}\")",
                view,
                sigs.join(", "),
                ghost_sender
            )
        }
        TracedCert::Finalization {
            view,
            block,
            signers,
            ghost_sender,
        } => {
            let block_name = map_block(block, block_map);
            let sigs: Vec<String> = signers.iter().map(|s| format!("\"{}\"", s)).collect();
            format!(
                "finalization({}, \"{}\", Set({}), \"{}\")",
                view,
                block_name,
                sigs.join(", "),
                ghost_sender
            )
        }
    }
}

/// Writes the standard helper actions used by test modules.
fn write_helpers(out: &mut String) {
    writeln!(out, "    action replica_receives_notarize_vote(id: ReplicaId, block: Block, view: ViewNumber, src: ReplicaId): bool =").unwrap();
    writeln!(
        out,
        "        on_vote_notarize(id, view, block, Set(notarize(view, src, block)))"
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    action replica_receives_finalize_vote(id: ReplicaId, block: Block, view: ViewNumber, src: ReplicaId): bool =").unwrap();
    writeln!(
        out,
        "        on_vote_finalize(id, view, block, Set(finalize(view, src, block)))"
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    action replica_receives_nullify_vote(id: ReplicaId, view: ViewNumber, src: ReplicaId): bool =").unwrap();
    writeln!(
        out,
        "        on_vote_nullify(id, view, Set(nullify(view, src)))"
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    action unchanged_all = all {{").unwrap();
    writeln!(out, "        sent_proposal' = sent_proposal,").unwrap();
    writeln!(out, "        sent_vote' = sent_vote,").unwrap();
    writeln!(out, "        sent_certificate' = sent_certificate,").unwrap();
    writeln!(out, "        store_vote' = store_vote,").unwrap();
    writeln!(out, "        store_certificate' = store_certificate,").unwrap();
    writeln!(out, "        ghost_proposal' = ghost_proposal,").unwrap();
    writeln!(out, "        parent_refs' = parent_refs,").unwrap();
    writeln!(
        out,
        "        ghost_committed_blocks' = ghost_committed_blocks,"
    )
    .unwrap();
    writeln!(out, "        leader' = leader,").unwrap();
    writeln!(out, "        replica_state' = replica_state,").unwrap();
    writeln!(out, "        certify_policy' = certify_policy,").unwrap();
    writeln!(out, "    }}").unwrap();
}
