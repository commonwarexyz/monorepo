//! Encodes a simplex consensus trace into a quint test file.
//!
//! Takes structured [`TraceEntry`] items from the sniffer and produces
//! a complete `.qnt` test module that can be verified with the quint
//! model checker against `replica.qnt`.

use super::sniffer::{TracedCert, TracedVote, TraceEntry};
use std::collections::{HashMap, HashSet};
use std::fmt::Write;

/// Configuration for the quint test encoder.
pub struct EncoderConfig {
    /// Number of validators.
    pub n: usize,
    /// Epoch used by the round-robin elector.
    pub epoch: u64,
    /// Maximum view to include in VIEWS range.
    pub max_view: u64,
}

/// Encodes trace entries into a quint test module.
pub fn encode(entries: &[TraceEntry], cfg: &EncoderConfig) -> String {
    let block_map = build_block_map(entries);
    let certify_policy = build_certify_policy(entries, &block_map);
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

    // CORRECT set
    let replicas: Vec<String> = (0..cfg.n).map(|i| format!("\"n{}\"", i)).collect();
    writeln!(out, "        CORRECT = Set({}),", replicas.join(", ")).unwrap();
    writeln!(out, "        BYZANTINE = Set(),").unwrap();

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
        let val = certify_policy.get(*name).copied().unwrap_or(true);
        writeln!(out, "        \"{}\" -> {},", name, val).unwrap();
    }
    writeln!(out, "    )").unwrap();
    writeln!(
        out,
        "    pure val CERTIFY_CUSTOM = Replicas.mapBy(_ => CERTIFY_POLICY)"
    )
    .unwrap();
    writeln!(out).unwrap();

    // Test body
    writeln!(out, "    run traceTest = {{").unwrap();

    // Init with leader map
    write!(out, "        initWithLeaderAndCertify(\n            Map(").unwrap();
    let leader_entries: Vec<String> = leader_map
        .iter()
        .map(|(v, id)| format!("{} -> \"{}\"", v, id))
        .collect();
    write!(out, "{}", leader_entries.join(", ")).unwrap();
    writeln!(out, "),").unwrap();
    writeln!(out, "            CERTIFY_CUSTOM").unwrap();
    writeln!(out, "        )").unwrap();

    // Generate actions with self-vote injection
    let actions = build_actions(entries, &block_map, cfg);
    for action in &actions {
        writeln!(out, "            .then({})", action).unwrap();
    }

    writeln!(out, "            .expect(all_invariants)").unwrap();
    writeln!(out, "    }}").unwrap();
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
    _cfg: &EncoderConfig,
) -> Vec<String> {
    let mut actions = Vec::new();
    let mut self_delivered: HashSet<VoteKey> = HashSet::new();

    // Collect all (signer, view, vote_type) combos from the trace
    // to know which self-deliveries are needed
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

/// Returns a HashMap from val_bN -> bool indicating certify policy.
///
/// A block fails certification if it appears in notarize votes for a view
/// but that view also has nullify votes (meaning certification was rejected).
fn build_certify_policy(
    entries: &[TraceEntry],
    block_map: &[(String, String)],
) -> HashMap<String, bool> {
    let hash_to_name: HashMap<&str, &str> = block_map
        .iter()
        .map(|(h, n)| (h.as_str(), n.as_str()))
        .collect();

    // Track which views have notarize blocks and which views have nullify/finalize
    let mut view_block: HashMap<u64, String> = HashMap::new();
    let mut view_has_finalize: HashMap<u64, bool> = HashMap::new();
    let mut view_has_nullify: HashMap<u64, bool> = HashMap::new();

    for entry in entries {
        match entry {
            TraceEntry::Vote {
                vote: TracedVote::Notarize { view, block, .. },
                ..
            } => {
                view_block.entry(*view).or_insert_with(|| block.clone());
            }
            TraceEntry::Vote {
                vote: TracedVote::Finalize { view, .. },
                ..
            } => {
                view_has_finalize.insert(*view, true);
            }
            TraceEntry::Vote {
                vote: TracedVote::Nullify { view, .. },
                ..
            } => {
                // Only count nullify as certification failure if the view also has notarize
                if view_block.contains_key(view) {
                    view_has_nullify.insert(*view, true);
                }
            }
            _ => {}
        }
    }

    let mut policy = HashMap::new();
    for (view, hash) in &view_block {
        if let Some(name) = hash_to_name.get(hash.as_str()) {
            // Block fails certification if the view has nullify but no finalize
            let has_fin = view_has_finalize.get(view).copied().unwrap_or(false);
            let has_null = view_has_nullify.get(view).copied().unwrap_or(false);
            let certify = has_fin || !has_null;
            policy.insert(name.to_string(), certify);
        }
    }
    policy
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
    writeln!(out, "        ghost_committed_blocks' = ghost_committed_blocks,").unwrap();
    writeln!(out, "        leader' = leader,").unwrap();
    writeln!(out, "        replica_state' = replica_state,").unwrap();
    writeln!(out, "        certify_policy' = certify_policy,").unwrap();
    writeln!(out, "    }}").unwrap();
}
