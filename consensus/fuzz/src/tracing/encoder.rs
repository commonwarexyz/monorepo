//! Encodes a simplex consensus trace into a quint test file.
//!
//! Takes structured [`TraceEntry`] items from the sniffer and produces
//! a complete `.qnt` test module that can be verified with the quint
//! model checker against `replica.qnt`.

use super::{
    data::{ReporterReplicaStateData, TraceData, TraceProposalData},
    sniffer::{TraceEntry, TracedCert, TracedVote},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Write,
};

/// Returns true if the block hash is certifiable, matching
/// `Certifier::Sometimes`: `last_byte % 11 < 9`.
fn is_certifiable(block_hash: &str) -> bool {
    if block_hash.len() >= 2 {
        let last_two = &block_hash[block_hash.len() - 2..];
        let last_byte = u8::from_str_radix(last_two, 16).unwrap_or(0);
        (last_byte % 11) < 9
    } else {
        true
    }
}

/// Returns true if the node ID (e.g. "n0") is Byzantine (index < faults).
fn is_byzantine_node(node: &str, faults: usize) -> bool {
    if let Some(idx_str) = node.strip_prefix('n') {
        if let Ok(idx) = idx_str.parse::<usize>() {
            return idx < faults;
        }
    }
    false
}

fn normalize_vote_sig_for_sender(sender: &str, sig: &str, cfg: &EncoderConfig) -> String {
    if !is_byzantine_node(sender, cfg.faults) || cfg.n == 0 {
        return sig.to_string();
    }
    if let Some(idx_str) = sig.strip_prefix('n') {
        if let Ok(idx) = idx_str.parse::<usize>() {
            return format!("n{}", idx % cfg.n);
        }
    }
    sig.to_string()
}

/// Kind of vote delivery action. Used to group votes between barriers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum VoteKind {
    Finalize,
    Nullify,
}

/// Intermediate action representation used during trace encoding.
/// Each vote delivery becomes an individual `on_finalize` or `on_nullify`
/// call with a single vote argument.
#[derive(Clone)]
enum ActionItem {
    /// Non-reorderable action: on_notarize, send_*_vote, on_certificate.
    Barrier(String),
    /// Individual vote delivery rendered as a single `on_*` call.
    VoteDelivery {
        kind: VoteKind,
        receiver: String,
        /// Single vote record, e.g. `{ proposal: proposal_v2_val_b0, sig: "n0" }`.
        vote: String,
    },
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

/// Proposal information reconstructed from trace data.
struct ViewProposal {
    view_parent: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct ProposalKey {
    view: u64,
    block_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum VoteReplayKey {
    Notarize {
        view: u64,
        sig: String,
        block: String,
    },
    Nullify {
        view: u64,
        sig: String,
    },
    Finalize {
        view: u64,
        sig: String,
        block: String,
    },
}

fn vote_replay_key(vote: &TracedVote, sig: String) -> VoteReplayKey {
    match vote {
        TracedVote::Notarize { view, block, .. } => VoteReplayKey::Notarize {
            view: *view,
            sig,
            block: block.clone(),
        },
        TracedVote::Nullify { view, .. } => VoteReplayKey::Nullify { view: *view, sig },
        TracedVote::Finalize { view, block, .. } => VoteReplayKey::Finalize {
            view: *view,
            sig,
            block: block.clone(),
        },
    }
}

fn proposal_key(view: u64, block_name: &str) -> ProposalKey {
    ProposalKey {
        view,
        block_name: block_name.to_string(),
    }
}

fn proposal_var_name(key: &ProposalKey) -> String {
    format!("proposal_v{}_{}", key.view, key.block_name)
}

fn proposal_ref(view: u64, block_name: &str) -> String {
    proposal_var_name(&proposal_key(view, block_name))
}

fn collect_honest_votes(entries: &[TraceEntry], cfg: &EncoderConfig) -> HashSet<VoteReplayKey> {
    entries
        .iter()
        .filter_map(|entry| match entry {
            TraceEntry::Vote { sender, vote, .. } if !is_byzantine_node(sender, cfg.faults) => {
                let sig = match vote {
                    TracedVote::Notarize { sig, .. }
                    | TracedVote::Nullify { sig, .. }
                    | TracedVote::Finalize { sig, .. } => sig.clone(),
                };
                Some(vote_replay_key(vote, sig))
            }
            _ => None,
        })
        .collect()
}

fn filter_invalid_byzantine_votes(
    entries: &[TraceEntry],
    cfg: &EncoderConfig,
    honest_votes: &HashSet<VoteReplayKey>,
) -> Vec<TraceEntry> {
    entries
        .iter()
        .filter(|entry| match entry {
            TraceEntry::Vote { sender, vote, .. } if is_byzantine_node(sender, cfg.faults) => {
                let sig = match vote {
                    TracedVote::Notarize { sig, .. }
                    | TracedVote::Nullify { sig, .. }
                    | TracedVote::Finalize { sig, .. } => {
                        normalize_vote_sig_for_sender(sender, sig, cfg)
                    }
                };
                is_byzantine_node(&sig, cfg.faults)
                    || honest_votes.contains(&vote_replay_key(vote, sig))
            }
            _ => true,
        })
        .cloned()
        .collect()
}

/// Encodes trace entries into a quint test module.
pub fn encode(trace_data: &TraceData, cfg: &EncoderConfig) -> String {
    let entries = &trace_data.entries;
    let honest_votes = collect_honest_votes(entries, cfg);

    // Filter out invalid byzantine votes (forged signer identity).
    // Keep entries with byzantine receivers: `build_actions` needs them to
    // emit `send_*_vote` barriers before certificates that depend on them.
    let filtered_entries = filter_invalid_byzantine_votes(entries, cfg, &honest_votes);

    let block_map = build_block_map(trace_data);
    let leader_map = build_leader_map_to(cfg, cfg.max_view);
    let leader_lookup: HashMap<u64, String> = leader_map.iter().cloned().collect();

    let block_names: Vec<&str> = block_map.iter().map(|(_, n)| n.as_str()).collect();
    let f = (cfg.n - 1) / 3;
    let q = cfg.n - f;

    // Build view proposals from the filtered trace itself. Certificate
    // validity is checked by the Quint model, not by the encoder.
    let proposals = build_view_proposals(&filtered_entries, &block_map, cfg);

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

    // VALID_PAYLOADS
    write!(out, "        VALID_PAYLOADS = Set(").unwrap();
    write!(out, "{}", all_blocks.join(", ")).unwrap();
    writeln!(out, "),").unwrap();
    writeln!(out, "        INVALID_PAYLOADS = Set(),").unwrap();
    writeln!(out, "        ACTIVITY_TIMEOUT = 10").unwrap();
    writeln!(out, "    ).* from \"../replica\"").unwrap();
    writeln!(out).unwrap();

    // Certify policy: derive from block hash using Certifier::Sometimes logic
    let mut certifiable_payloads: Vec<String> = vec!["GENESIS_PAYLOAD".to_string()];
    for (hash, name) in &block_map {
        if is_certifiable(hash) {
            certifiable_payloads.push(format!("\"{}\"", name));
        }
    }
    writeln!(
        out,
        "    pure val CERTIFY_POLICY = Set({})",
        certifiable_payloads.join(", ")
    )
    .unwrap();
    writeln!(
        out,
        "    pure val CERTIFY_CUSTOM = Replicas.mapBy(_ => CERTIFY_POLICY)"
    )
    .unwrap();
    writeln!(out).unwrap();

    // Emit proposal val declarations
    let mut sorted_proposals: Vec<ProposalKey> = proposals.keys().cloned().collect();
    sorted_proposals.sort();
    for key in &sorted_proposals {
        let p = &proposals[key];
        let parent_str = if p.view_parent == 0 {
            "GENESIS_VIEW".to_string()
        } else {
            p.view_parent.to_string()
        };
        writeln!(
            out,
            "    pure val {} = {{ payload: \"{}\", view: {}, parent: {} }}",
            proposal_var_name(key),
            key.block_name,
            key.view,
            parent_str
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    // Generate actions in original trace order, then group vote deliveries.
    // Pass all filtered entries (including byzantine receivers) so that
    // `send_*_vote` barriers are emitted at the earliest occurrence.
    let action_items = build_actions(&filtered_entries, &block_map, cfg, &leader_lookup);

    // Flatten vote deliveries: each finalize/nullify vote becomes its own
    // on_finalize/on_nullify call with a single vote argument.
    let actions = flatten_vote_deliveries(action_items);

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

    // Chunks break the action chain into pieces to avoid deep nesting.
    // Invariants are only checked at the final traceTest step, not at
    // intermediate chunk boundaries, to keep evaluation fast.
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
        writeln!(out, "            .expect(safe_invariants)").unwrap();
        writeln!(out).unwrap();
    }

    // Final run references the last trace chunk or snapshot action.
    let last_part = if chunks.is_empty() {
        leader_init
    } else {
        format!("trace_part_{:02}", chunks.len() - 1)
    };
    let last_action = write_snapshot_expectations(
        &mut out,
        &last_part,
        &trace_data.reporter_states,
        &block_map,
    );
    writeln!(out, "    run traceTest =").unwrap();
    writeln!(out, "        {}", last_action).unwrap();
    writeln!(out, "            .expect(safe_invariants)").unwrap();
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
    write_reporter_helpers(&mut out);

    writeln!(out, "}}").unwrap();
    out
}

/// Builds the full action list, processing entries in original trace order.
///
/// For notarize votes, the trace format does not include explicit proposal
/// events. We therefore reconstruct the missing causal prefix:
/// - when a correct leader is first needed, emit `propose(...)`
/// - when a byzantine leader is first needed, emit `send_notarize_vote(...)`
/// - before replaying an honest non-leader notarize send, ensure that sender
///   has already processed the leader's notarize vote via
///   `on_notarize(sender, leader_vote)`
/// This keeps the current trace format while restoring the protocol's causal
/// order: proposal first, then honest votes that depend on it.
/// Finalize/nullify deliveries emit individual `on_finalize`/`on_nullify`
/// calls, each with a single vote argument.
///
/// Returns structured `ActionItem`s: barriers (non-reorderable) and vote
/// deliveries. The caller runs `flatten_vote_deliveries` to convert them
/// into individual quint action calls.
fn build_actions(
    entries: &[TraceEntry],
    block_map: &[(String, String)],
    cfg: &EncoderConfig,
    leader_lookup: &HashMap<u64, String>,
) -> Vec<ActionItem> {
    let mut actions: Vec<ActionItem> = Vec::new();
    // Keys include block name for notarize/finalize to handle byzantine equivocation
    // (same signer, same view, different blocks).
    let mut sent_votes_emitted: HashSet<(String, u64, String, String)> = HashSet::new();
    let mut self_delivered: HashSet<(String, u64, String)> = HashSet::new();
    let mut leader_vote_introduced: HashSet<ProposalKey> = HashSet::new();
    let mut leader_vote_delivered: HashSet<(String, u64, String)> = HashSet::new();
    // Dedup cert deliveries per receiver. In the Rust execution, each node
    // broadcasts its assembled cert to all peers, producing up to N^2 total
    // deliveries (N senders x N receivers). In the quint model, the first
    // delivery per (receiver, kind, view, block, signers) does all the work;
    // subsequent ones with a different ghost_sender are no-ops because the
    // cert is already in store_certificate. Skipping them avoids redundant
    // state evaluation and dramatically speeds up the quint checker.
    let mut cert_delivered: HashSet<String> = HashSet::new();
    let mut cert_sent: HashSet<String> = HashSet::new();

    for entry in entries {
        match entry {
            TraceEntry::Vote {
                sender,
                receiver,
                vote,
            } => {
                // Byzantine receivers have no state in the quint model, so
                // skip delivery actions for them. `send_*_vote` barriers
                // are still emitted so the global sent-vote set is updated
                // before any certificate that depends on them.
                let byzantine_receiver = is_byzantine_node(receiver, cfg.faults);

                match vote {
                    TracedVote::Notarize { view, sig, block } => {
                        let sig = normalize_vote_sig_for_sender(sender, sig, cfg);
                        let bn = map_block(block, block_map);
                        let proposal = proposal_key(*view, &bn);
                        let leader_id = leader_lookup
                            .get(view)
                            .cloned()
                            .expect("leader must be defined for traced view");
                        let leader_is_byzantine = is_byzantine_node(&leader_id, cfg.faults);
                        let sender_is_correct = !is_byzantine_node(sender, cfg.faults);
                        let is_leader_vote = sig == leader_id;
                        let leader_vote = format!(
                            "{{ proposal: {}, sig: \"{}\" }}",
                            proposal_ref(*view, &bn),
                            leader_id
                        );

                        if sender_is_correct {
                            if leader_vote_introduced.insert(proposal.clone()) {
                                if leader_is_byzantine {
                                    if sent_votes_emitted.insert((
                                        leader_id.clone(),
                                        *view,
                                        "notarize".into(),
                                        bn.clone(),
                                    )) {
                                        actions.push(ActionItem::Barrier(format!(
                                            "send_notarize_vote({})",
                                            leader_vote
                                        )));
                                    }
                                } else {
                                    actions.push(ActionItem::Barrier(format!(
                                        "propose(\"{}\", {}.payload, {}.parent)",
                                        leader_id,
                                        proposal_ref(*view, &bn),
                                        proposal_ref(*view, &bn)
                                    )));
                                }
                            }

                            if sender != &leader_id
                                && leader_vote_delivered.insert((sender.clone(), *view, bn.clone()))
                            {
                                actions.push(ActionItem::Barrier(format!(
                                    "on_notarize(\"{}\", {})",
                                    sender, leader_vote
                                )));
                            }
                        } else if is_byzantine_node(&sig, cfg.faults)
                            && sent_votes_emitted.insert((
                                sig.clone(),
                                *view,
                                "notarize".into(),
                                bn.clone(),
                            ))
                        {
                            actions.push(ActionItem::Barrier(format!(
                                "send_notarize_vote({{ proposal: {}, sig: \"{}\" }})",
                                proposal_ref(*view, &bn),
                                sig
                            )));
                        }

                        if byzantine_receiver {
                            continue;
                        }

                        if is_leader_vote {
                            if receiver != &leader_id
                                && leader_vote_delivered.insert((
                                    receiver.clone(),
                                    *view,
                                    bn.clone(),
                                ))
                            {
                                actions.push(ActionItem::Barrier(format!(
                                    "on_notarize(\"{}\", {})",
                                    receiver, leader_vote
                                )));
                            }
                        } else {
                            actions.push(ActionItem::Barrier(format!(
                                "on_notarize(\"{}\", {{ proposal: {}, sig: \"{}\" }})",
                                receiver,
                                proposal_ref(*view, &bn),
                                sig
                            )));
                        }
                    }
                    TracedVote::Finalize { view, sig, block } => {
                        let sig = normalize_vote_sig_for_sender(sender, sig, cfg);
                        let bn = map_block(block, block_map);

                        if sent_votes_emitted.insert((
                            sig.clone(),
                            *view,
                            "finalize".into(),
                            bn.clone(),
                        )) {
                            actions.push(ActionItem::Barrier(format!(
                                "send_finalize_vote({{ proposal: {}, sig: \"{}\" }})",
                                proposal_ref(*view, &bn),
                                sig
                            )));
                        }

                        if byzantine_receiver {
                            continue;
                        }

                        // Correct finalize: self-delivery (node counts its own finalize)
                        if !is_byzantine_node(&sig, cfg.faults)
                            && self_delivered.insert((sig.clone(), *view, "finalize".into()))
                        {
                            actions.push(ActionItem::VoteDelivery {
                                kind: VoteKind::Finalize,
                                receiver: sig.clone(),
                                vote: format!(
                                    "{{ proposal: {}, sig: \"{}\" }}",
                                    proposal_ref(*view, &bn),
                                    sig
                                ),
                            });
                        }

                        // Deliver vote to receiver
                        actions.push(ActionItem::VoteDelivery {
                            kind: VoteKind::Finalize,
                            receiver: receiver.clone(),
                            vote: format!(
                                "{{ proposal: {}, sig: \"{}\" }}",
                                proposal_ref(*view, &bn),
                                sig
                            ),
                        });
                    }
                    TracedVote::Nullify { view, sig } => {
                        let sig = normalize_vote_sig_for_sender(sender, sig, cfg);
                        if sent_votes_emitted.insert((
                            sig.clone(),
                            *view,
                            "nullify".into(),
                            String::new(),
                        )) {
                            actions.push(ActionItem::Barrier(format!(
                                "send_nullify_vote({{ view: {}, sig: \"{}\" }})",
                                view, sig
                            )));
                        }

                        if byzantine_receiver {
                            continue;
                        }

                        // Correct nullify: inject if it was not already produced by
                        // leader proposal processing for that signer/view.
                        if !is_byzantine_node(&sig, cfg.faults) {
                            // Self-delivery
                            if self_delivered.insert((sig.clone(), *view, "nullify".into())) {
                                actions.push(ActionItem::VoteDelivery {
                                    kind: VoteKind::Nullify,
                                    receiver: sig.clone(),
                                    vote: format!("{{ view: {}, sig: \"{}\" }}", view, sig),
                                });
                            }
                        }

                        // Deliver vote to receiver
                        actions.push(ActionItem::VoteDelivery {
                            kind: VoteKind::Nullify,
                            receiver: receiver.clone(),
                            vote: format!("{{ view: {}, sig: \"{}\" }}", view, sig),
                        });
                    }
                }
            }
            TraceEntry::Certificate { receiver, cert, .. } => {
                let cert_str = encode_cert(cert, block_map);

                // Emit send_certificate once per unique cert (regardless of
                // receiver) so sent_certificates is populated before any
                // on_certificate delivery.
                let cert_send_key = {
                    let mut signers_sorted;
                    match cert {
                        TracedCert::Notarization {
                            view,
                            block,
                            signers,
                            ..
                        } => {
                            signers_sorted = signers.clone();
                            signers_sorted.sort();
                            format!(
                                "N:{}:{}:{}",
                                view,
                                map_block(block, block_map),
                                signers_sorted.join(",")
                            )
                        }
                        TracedCert::Nullification { view, signers, .. } => {
                            signers_sorted = signers.clone();
                            signers_sorted.sort();
                            format!("U:{}:{}", view, signers_sorted.join(","))
                        }
                        TracedCert::Finalization {
                            view,
                            block,
                            signers,
                            ..
                        } => {
                            signers_sorted = signers.clone();
                            signers_sorted.sort();
                            format!(
                                "F:{}:{}:{}",
                                view,
                                map_block(block, block_map),
                                signers_sorted.join(",")
                            )
                        }
                    }
                };
                if cert_sent.insert(cert_send_key) {
                    actions.push(ActionItem::Barrier(format!(
                        "send_certificate({})",
                        cert_str
                    )));
                }

                // Skip delivery to byzantine receivers (no state in quint model).
                if is_byzantine_node(receiver, cfg.faults) {
                    continue;
                }

                // Skip duplicate cert deliveries to the same receiver.
                // A cert is identified by (kind, view, block, signers);
                // the ghost_sender varies but doesn't affect model behavior.
                let cert_dedup_key = format!("{}:{}", receiver, &cert_str);
                if !cert_delivered.insert(cert_dedup_key) {
                    continue;
                }

                // Deliver certificate (barrier: cannot be reordered with votes)
                actions.push(ActionItem::Barrier(format!(
                    "on_certificate(\"{}\", {})",
                    receiver, cert_str
                )));
            }
        }
    }

    actions
}

/// Flattens action items into individual quint calls. Each vote delivery
/// becomes its own `on_finalize` or `on_nullify` call with a single vote.
/// Barriers pass through unchanged.
fn flatten_vote_deliveries(items: Vec<ActionItem>) -> Vec<String> {
    let mut result = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for item in items {
        match item {
            ActionItem::Barrier(s) => result.push(s),
            ActionItem::VoteDelivery {
                kind,
                receiver,
                vote,
            } => {
                let call = match kind {
                    VoteKind::Finalize => {
                        format!("on_finalize(\"{}\", {})", receiver, vote)
                    }
                    VoteKind::Nullify => {
                        format!("on_nullify(\"{}\", {})", receiver, vote)
                    }
                };
                // Dedup identical calls
                if seen.insert((receiver, vote)) {
                    result.push(call);
                }
            }
        }
    }
    result
}

/// Maps block hashes to val_b0, val_b1, ... in order of first appearance.
fn build_block_map(trace_data: &TraceData) -> Vec<(String, String)> {
    let mut map = Vec::new();
    let mut seen = HashMap::new();
    let mut record_hash = |hash: String| {
        if hash == "GENESIS_PAYLOAD" || seen.contains_key(&hash) {
            return;
        }
        let name = format!("val_b{}", map.len());
        seen.insert(hash.clone(), name.clone());
        map.push((hash, name));
    };

    for entry in &trace_data.entries {
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
        if let Some(hash) = hash {
            record_hash(hash);
        }
    }

    for state in trace_data.reporter_states.values() {
        for proposal in state.notarizations.values() {
            record_hash(proposal.payload.clone());
        }
        for proposal in state.finalizations.values() {
            record_hash(proposal.payload.clone());
        }
    }

    map
}

/// Builds the leader map: view -> replica ID using round-robin.
fn build_leader_map_to(cfg: &EncoderConfig, max_view: u64) -> Vec<(u64, String)> {
    let mut map = Vec::new();
    for view in 0..=max_view {
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
                "notarization({}, Set({}), \"{}\")",
                proposal_ref(*view, &block_name),
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
                "finalization({}, Set({}), \"{}\")",
                proposal_ref(*view, &block_name),
                sigs.join(", "),
                ghost_sender
            )
        }
    }
}

/// Builds proposals from block-carrying entries in the trace.
///
/// Twins traces may contain multiple Byzantine proposals in the same view, so
/// proposals are reconstructed per `(view, block)`. All proposals within a
/// given view share the same parent view, and the parent for the next view is
/// chosen from the latest certifiable certificate present in the trace.
fn build_view_proposals(
    entries: &[TraceEntry],
    block_map: &[(String, String)],
    cfg: &EncoderConfig,
) -> HashMap<ProposalKey, ViewProposal> {
    let mut per_view_blocks: HashMap<u64, HashMap<String, (Vec<String>, usize)>> = HashMap::new();
    let mut certified_blocks: HashMap<u64, HashMap<String, usize>> = HashMap::new();

    for (idx, entry) in entries.iter().enumerate() {
        match entry {
            TraceEntry::Vote {
                sender,
                vote: TracedVote::Notarize { view, sig, block },
                ..
            } => {
                let block_name = map_block(block, block_map);
                let block_entry = per_view_blocks
                    .entry(*view)
                    .or_default()
                    .entry(block_name)
                    .or_insert_with(|| (Vec::new(), idx));
                block_entry.1 = idx;

                let sig = normalize_vote_sig_for_sender(sender, sig, cfg);
                if !is_byzantine_node(&sig, cfg.faults) {
                    if !block_entry.0.contains(&sig) {
                        block_entry.0.push(sig);
                    }
                }
            }
            TraceEntry::Vote {
                vote: TracedVote::Finalize { view, block, .. },
                ..
            } => {
                let block_name = map_block(block, block_map);
                let block_entry = per_view_blocks
                    .entry(*view)
                    .or_default()
                    .entry(block_name)
                    .or_insert_with(|| (Vec::new(), idx));
                block_entry.1 = idx;
            }
            TraceEntry::Certificate { cert, .. } => match cert {
                TracedCert::Notarization { view, block, .. }
                | TracedCert::Finalization { view, block, .. } => {
                    let block_name = map_block(block, block_map);
                    per_view_blocks
                        .entry(*view)
                        .or_default()
                        .entry(block_name.clone())
                        .or_insert_with(|| (Vec::new(), idx))
                        .1 = idx;
                    if is_certifiable(block) {
                        certified_blocks
                            .entry(*view)
                            .or_default()
                            .insert(block_name, idx);
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    let mut views: Vec<u64> = per_view_blocks.keys().cloned().collect();
    views.sort();

    let mut last_parent_view: u64 = 0;

    let mut proposals = HashMap::new();
    for &view in &views {
        let mut view_blocks: Vec<(ProposalKey, Vec<String>, usize)> = per_view_blocks[&view]
            .iter()
            .map(|(block_name, (correct_notarizers, last_seen_idx))| {
                (
                    proposal_key(view, block_name),
                    correct_notarizers.clone(),
                    *last_seen_idx,
                )
            })
            .collect();
        view_blocks.sort_by(|a, b| {
            a.2.cmp(&b.2)
                .then_with(|| a.0.block_name.cmp(&b.0.block_name))
        });

        for (key, _correct_notarizers, _) in &view_blocks {
            proposals.insert(
                key.clone(),
                ViewProposal {
                    view_parent: last_parent_view,
                },
            );
        }

        if certified_blocks.contains_key(&view) {
            last_parent_view = view;
        }
    }

    proposals
}

fn encode_reporter_payload_expr(payload: &str, block_map: &[(String, String)]) -> String {
    if payload == "GENESIS_PAYLOAD" {
        "GENESIS_PAYLOAD".to_string()
    } else {
        format!("\"{}\"", map_block(payload, block_map))
    }
}

fn encode_reporter_view_expr(view: u64) -> String {
    if view == 0 {
        "GENESIS_VIEW".to_string()
    } else {
        view.to_string()
    }
}

fn encode_reporter_option_payload_expr(
    proposal: Option<&TraceProposalData>,
    block_map: &[(String, String)],
) -> String {
    match proposal {
        Some(proposal) => format!(
            "Some({})",
            encode_reporter_payload_expr(&proposal.payload, block_map)
        ),
        None => "None".to_string(),
    }
}

fn encode_option_usize_expr(value: Option<usize>) -> String {
    match value {
        Some(value) => format!("Some({value})"),
        None => "None".to_string(),
    }
}

fn encode_signer_set_expr(signers: Option<&BTreeSet<String>>) -> String {
    match signers {
        Some(signers) if !signers.is_empty() => {
            let values: Vec<String> = signers
                .iter()
                .map(|signer| format!("\"{signer}\""))
                .collect();
            format!("Set({})", values.join(", "))
        }
        _ => "Set()".to_string(),
    }
}

fn write_snapshot_expectations(
    out: &mut String,
    base_action: &str,
    reporter_states: &BTreeMap<String, ReporterReplicaStateData>,
    block_map: &[(String, String)],
) -> String {
    let mut previous = base_action.to_string();

    for (replica_id, state) in reporter_states {
        let mut views = BTreeSet::new();
        views.extend(state.notarizations.keys().copied());
        views.extend(state.nullifications.iter().copied());
        views.extend(state.finalizations.keys().copied());
        views.extend(state.certified.iter().copied());

        for view in views {
            let view_expr = encode_reporter_view_expr(view);
            let has_notarization = state.notarizations.contains_key(&view);
            let has_nullification = state.nullifications.contains(&view);
            let has_finalization = state.finalizations.contains_key(&view);
            let is_certified = state.certified.contains(&view);
            let notarization_expr =
                encode_reporter_option_payload_expr(state.notarizations.get(&view), block_map);
            let notarization_count_expr = encode_option_usize_expr(
                state
                    .notarization_signature_counts
                    .get(&view)
                    .copied()
                    .flatten(),
            );
            let nullification_count_expr = encode_option_usize_expr(
                state
                    .nullification_signature_counts
                    .get(&view)
                    .copied()
                    .flatten(),
            );
            let finalization_expr =
                encode_reporter_option_payload_expr(state.finalizations.get(&view), block_map);
            let finalization_count_expr = encode_option_usize_expr(
                state
                    .finalization_signature_counts
                    .get(&view)
                    .copied()
                    .flatten(),
            );
            let action_name = format!("trace_snapshot_id_{}_view_{}", replica_id, view);

            writeln!(out, "    action {} =", action_name).unwrap();
            writeln!(out, "        {}", previous).unwrap();
            writeln!(out, "            .then(all {{").unwrap();
            writeln!(
                out,
                "                assert(replica_has_notarization(\"{}\", {}) == {}),",
                replica_id,
                view_expr,
                if has_notarization { "true" } else { "false" }
            )
            .unwrap();
            writeln!(
                out,
                "                assert(replica_notarization_payload(\"{}\", {}) == {}),",
                replica_id, view_expr, notarization_expr
            )
            .unwrap();
            writeln!(
                out,
                "                assert(replica_notarization_signature_count(\"{}\", {}) == {}),",
                replica_id, view_expr, notarization_count_expr
            )
            .unwrap();
            writeln!(
                out,
                "                assert(replica_has_nullification(\"{}\", {}) == {}),",
                replica_id,
                view_expr,
                if has_nullification { "true" } else { "false" }
            )
            .unwrap();
            writeln!(
                out,
                "                assert(replica_nullification_signature_count(\"{}\", {}) == {}),",
                replica_id, view_expr, nullification_count_expr
            )
            .unwrap();
            if let Some(signers) = state.notarize_signers.get(&view) {
                if !signers.is_empty() {
                    let signers_expr = encode_signer_set_expr(Some(signers));
                    writeln!(
                        out,
                        "                assert(replica_has_notarization(\"{r}\", {v}) or replica_is_certified(\"{r}\", {v}) or replica_observed_notarize_signers(\"{r}\", {v}) == {s}),",
                        r = replica_id, v = view_expr, s = signers_expr
                    )
                    .unwrap();
                }
            }
            if let Some(signers) = state.nullify_signers.get(&view) {
                if !signers.is_empty() {
                    let signers_expr = encode_signer_set_expr(Some(signers));
                    writeln!(
                        out,
                        "                assert(replica_has_nullification(\"{r}\", {v}) or replica_has_finalization(\"{r}\", {v}) or replica_is_certified(\"{r}\", {v}) or replica_observed_nullify_signers(\"{r}\", {v}) == {s}),",
                        r = replica_id, v = view_expr, s = signers_expr
                    )
                    .unwrap();
                }
            }
            if let Some(signers) = state.finalize_signers.get(&view) {
                if !signers.is_empty() {
                    let signers_expr = encode_signer_set_expr(Some(signers));
                    writeln!(
                        out,
                        "                assert(replica_has_finalization(\"{r}\", {v}) or replica_has_nullification(\"{r}\", {v}) or replica_is_certified(\"{r}\", {v}) or replica_observed_finalize_signers(\"{r}\", {v}) == {s}),",
                        r = replica_id, v = view_expr, s = signers_expr
                    )
                    .unwrap();
                }
            }
            writeln!(
                out,
                "                assert(replica_has_finalization(\"{}\", {}) == {}),",
                replica_id,
                view_expr,
                if has_finalization { "true" } else { "false" }
            )
            .unwrap();
            writeln!(
                out,
                "                assert(replica_is_certified(\"{}\", {}) == {}),",
                replica_id,
                view_expr,
                if is_certified { "true" } else { "false" }
            )
            .unwrap();
            writeln!(
                out,
                "                assert(replica_finalization_payload(\"{}\", {}) == {}),",
                replica_id, view_expr, finalization_expr
            )
            .unwrap();
            writeln!(
                out,
                "                assert(replica_finalization_signature_count(\"{}\", {}) == {}),",
                replica_id, view_expr, finalization_count_expr
            )
            .unwrap();
            writeln!(out, "                unchanged_all,").unwrap();
            writeln!(out, "            }})").unwrap();
            writeln!(out).unwrap();

            previous = action_name;
        }

        let action_name = format!("trace_snapshot_id_{}_max_finalized_view", replica_id);
        writeln!(out, "    action {} =", action_name).unwrap();
        writeln!(out, "        {}", previous).unwrap();
        writeln!(out, "            .then(all {{").unwrap();
        writeln!(
            out,
            "                assert(replica_max_finalized_view(\"{}\") >= {}),",
            replica_id,
            encode_reporter_view_expr(state.max_finalized_view)
        )
        .unwrap();
        writeln!(out, "                unchanged_all,").unwrap();
        writeln!(out, "            }})").unwrap();
        writeln!(out).unwrap();
        previous = action_name;
    }

    previous
}

fn write_reporter_helpers(out: &mut String) {
    // replica_has_notarization
    writeln!(
        out,
        "    def replica_has_notarization(id: ReplicaId, view: ViewNumber): bool = {{"
    )
    .unwrap();
    writeln!(
        out,
        "        store_certificates.get(id).exists(c => is_notarization_cert(c) and cert_view(c) == view)"
    )
    .unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_notarization_payload
    writeln!(out, "    def replica_notarization_payload(id: ReplicaId, view: ViewNumber): Option[Payload] = {{").unwrap();
    writeln!(
        out,
        "        store_certificates.get(id).fold(None, (acc, c) =>"
    )
    .unwrap();
    writeln!(out, "            match c {{").unwrap();
    writeln!(out, "                | Notarization(nc) => if (nc.proposal.view == view) Some(nc.proposal.payload) else acc").unwrap();
    writeln!(out, "                | _ => acc").unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "        )").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_notarization_signature_count
    writeln!(out, "    def replica_notarization_signature_count(id: ReplicaId, view: ViewNumber): Option[int] = {{").unwrap();
    writeln!(
        out,
        "        store_certificates.get(id).fold(None, (acc, c) =>"
    )
    .unwrap();
    writeln!(out, "            match c {{").unwrap();
    writeln!(out, "                | Notarization(nc) => if (nc.proposal.view == view) Some(nc.signatures.size()) else acc").unwrap();
    writeln!(out, "                | _ => acc").unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "        )").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_has_nullification
    writeln!(
        out,
        "    def replica_has_nullification(id: ReplicaId, view: ViewNumber): bool = {{"
    )
    .unwrap();
    writeln!(
        out,
        "        store_certificates.get(id).exists(c => is_nullification_cert(c) and cert_view(c) == view)"
    )
    .unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_nullification_signature_count
    writeln!(out, "    def replica_nullification_signature_count(id: ReplicaId, view: ViewNumber): Option[int] = {{").unwrap();
    writeln!(
        out,
        "        store_certificates.get(id).fold(None, (acc, c) =>"
    )
    .unwrap();
    writeln!(out, "            match c {{").unwrap();
    writeln!(out, "                | Nullification(nc) => if (nc.view == view) Some(nc.signatures.size()) else acc").unwrap();
    writeln!(out, "                | _ => acc").unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "        )").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_has_finalization
    writeln!(
        out,
        "    def replica_has_finalization(id: ReplicaId, view: ViewNumber): bool = {{"
    )
    .unwrap();
    writeln!(
        out,
        "        store_certificates.get(id).exists(c => is_finalization_cert(c) and cert_view(c) == view)"
    )
    .unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_finalization_payload
    writeln!(out, "    def replica_finalization_payload(id: ReplicaId, view: ViewNumber): Option[Payload] = {{").unwrap();
    writeln!(
        out,
        "        store_certificates.get(id).fold(None, (acc, c) =>"
    )
    .unwrap();
    writeln!(out, "            match c {{").unwrap();
    writeln!(out, "                | Finalization(fc) => if (fc.proposal.view == view) Some(fc.proposal.payload) else acc").unwrap();
    writeln!(out, "                | _ => acc").unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "        )").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_finalization_signature_count
    writeln!(out, "    def replica_finalization_signature_count(id: ReplicaId, view: ViewNumber): Option[int] = {{").unwrap();
    writeln!(
        out,
        "        store_certificates.get(id).fold(None, (acc, c) =>"
    )
    .unwrap();
    writeln!(out, "            match c {{").unwrap();
    writeln!(out, "                | Finalization(fc) => if (fc.proposal.view == view) Some(fc.signatures.size()) else acc").unwrap();
    writeln!(out, "                | _ => acc").unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "        )").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_observed_notarize_signers (unchanged - uses vote stores)
    writeln!(out, "    def replica_observed_notarize_signers(id: ReplicaId, view: ViewNumber): Set[Signature] = {{").unwrap();
    writeln!(out, "        val stored = store_notarize_votes.get(id).filter(v => v.proposal.view == view).map(v => v.sig)").unwrap();
    writeln!(out, "        val local = sent_notarize_votes.filter(v => and {{ v.sig == sig_of(id), v.proposal.view == view }}).map(v => v.sig)").unwrap();
    writeln!(out, "        stored.union(local)").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_observed_nullify_signers (unchanged - uses vote stores)
    writeln!(out, "    def replica_observed_nullify_signers(id: ReplicaId, view: ViewNumber): Set[Signature] = {{").unwrap();
    writeln!(out, "        val stored = store_nullify_votes.get(id).filter(v => v.view == view).map(v => v.sig)").unwrap();
    writeln!(out, "        val local = sent_nullify_votes.filter(v => and {{ v.sig == sig_of(id), v.view == view }}).map(v => v.sig)").unwrap();
    writeln!(out, "        stored.union(local)").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_observed_finalize_signers (unchanged - uses vote stores)
    writeln!(out, "    def replica_observed_finalize_signers(id: ReplicaId, view: ViewNumber): Set[Signature] = {{").unwrap();
    writeln!(out, "        val stored = store_finalize_votes.get(id).filter(v => v.proposal.view == view).map(v => v.sig)").unwrap();
    writeln!(out, "        val local = sent_finalize_votes.filter(v => and {{ v.sig == sig_of(id), v.proposal.view == view }}).map(v => v.sig)").unwrap();
    writeln!(out, "        stored.union(local)").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_is_certified
    writeln!(
        out,
        "    def replica_is_certified(id: ReplicaId, view: ViewNumber): bool = {{"
    )
    .unwrap();
    writeln!(out, "        or {{").unwrap();
    writeln!(out, "            replica_has_notarization(id, view),").unwrap();
    writeln!(out, "            replica_has_nullification(id, view),").unwrap();
    writeln!(out, "            replica_has_finalization(id, view),").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_max_finalized_view
    writeln!(
        out,
        "    def replica_max_finalized_view(id: ReplicaId): ViewNumber = {{"
    )
    .unwrap();
    writeln!(
        out,
        "        store_certificates.get(id).fold(GENESIS_VIEW, (acc, c) =>"
    )
    .unwrap();
    writeln!(out, "            match c {{").unwrap();
    writeln!(out, "                | Finalization(fc) => if (fc.proposal.view > acc) fc.proposal.view else acc").unwrap();
    writeln!(out, "                | _ => acc").unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "        )").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();
}
/// Writes the standard helper actions used by test modules.
fn write_helpers(out: &mut String) {
    writeln!(out, "    action unchanged_all = all {{").unwrap();
    writeln!(out, "        sent_notarize_votes' = sent_notarize_votes,").unwrap();
    writeln!(out, "        sent_nullify_votes' = sent_nullify_votes,").unwrap();
    writeln!(out, "        sent_finalize_votes' = sent_finalize_votes,").unwrap();
    writeln!(out, "        sent_certificates' = sent_certificates,").unwrap();
    writeln!(out, "        store_notarize_votes' = store_notarize_votes,").unwrap();
    writeln!(out, "        store_nullify_votes' = store_nullify_votes,").unwrap();
    writeln!(out, "        store_finalize_votes' = store_finalize_votes,").unwrap();
    writeln!(out, "        store_certificates' = store_certificates,").unwrap();
    writeln!(
        out,
        "        ghost_committed_blocks' = ghost_committed_blocks,"
    )
    .unwrap();
    writeln!(out, "        leader' = leader,").unwrap();
    writeln!(out, "        replica_state' = replica_state,").unwrap();
    writeln!(out, "        certify_policy' = certify_policy,").unwrap();
    writeln!(out, "        lastAction' = lastAction,").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    action send_notarize_vote(vote: NotarizeVote): bool = all {{"
    )
    .unwrap();
    writeln!(
        out,
        "        sent_notarize_votes' = sent_notarize_votes.union(Set(vote)),"
    )
    .unwrap();
    writeln!(out, "        sent_nullify_votes' = sent_nullify_votes,").unwrap();
    writeln!(out, "        sent_finalize_votes' = sent_finalize_votes,").unwrap();
    writeln!(out, "        sent_certificates' = sent_certificates,").unwrap();
    writeln!(out, "        store_notarize_votes' = store_notarize_votes,").unwrap();
    writeln!(out, "        store_nullify_votes' = store_nullify_votes,").unwrap();
    writeln!(out, "        store_finalize_votes' = store_finalize_votes,").unwrap();
    writeln!(out, "        store_certificates' = store_certificates,").unwrap();
    writeln!(
        out,
        "        ghost_committed_blocks' = ghost_committed_blocks,"
    )
    .unwrap();
    writeln!(out, "        leader' = leader,").unwrap();
    writeln!(out, "        replica_state' = replica_state,").unwrap();
    writeln!(out, "        certify_policy' = certify_policy,").unwrap();
    writeln!(out, "        lastAction' = \"send_notarize_vote\",").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    action send_nullify_vote(vote: NullifyVote): bool = all {{"
    )
    .unwrap();
    writeln!(out, "        sent_notarize_votes' = sent_notarize_votes,").unwrap();
    writeln!(
        out,
        "        sent_nullify_votes' = sent_nullify_votes.union(Set(vote)),"
    )
    .unwrap();
    writeln!(out, "        sent_finalize_votes' = sent_finalize_votes,").unwrap();
    writeln!(out, "        sent_certificates' = sent_certificates,").unwrap();
    writeln!(out, "        store_notarize_votes' = store_notarize_votes,").unwrap();
    writeln!(out, "        store_nullify_votes' = store_nullify_votes,").unwrap();
    writeln!(out, "        store_finalize_votes' = store_finalize_votes,").unwrap();
    writeln!(out, "        store_certificates' = store_certificates,").unwrap();
    writeln!(
        out,
        "        ghost_committed_blocks' = ghost_committed_blocks,"
    )
    .unwrap();
    writeln!(out, "        leader' = leader,").unwrap();
    writeln!(out, "        replica_state' = replica_state,").unwrap();
    writeln!(out, "        certify_policy' = certify_policy,").unwrap();
    writeln!(out, "        lastAction' = \"send_nullify_vote\",").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    action send_finalize_vote(vote: FinalizeVote): bool = all {{"
    )
    .unwrap();
    writeln!(out, "        sent_notarize_votes' = sent_notarize_votes,").unwrap();
    writeln!(out, "        sent_nullify_votes' = sent_nullify_votes,").unwrap();
    writeln!(
        out,
        "        sent_finalize_votes' = sent_finalize_votes.union(Set(vote)),"
    )
    .unwrap();
    writeln!(out, "        sent_certificates' = sent_certificates,").unwrap();
    writeln!(out, "        store_notarize_votes' = store_notarize_votes,").unwrap();
    writeln!(out, "        store_nullify_votes' = store_nullify_votes,").unwrap();
    writeln!(out, "        store_finalize_votes' = store_finalize_votes,").unwrap();
    writeln!(out, "        store_certificates' = store_certificates,").unwrap();
    writeln!(
        out,
        "        ghost_committed_blocks' = ghost_committed_blocks,"
    )
    .unwrap();
    writeln!(out, "        leader' = leader,").unwrap();
    writeln!(out, "        replica_state' = replica_state,").unwrap();
    writeln!(out, "        certify_policy' = certify_policy,").unwrap();
    writeln!(out, "        lastAction' = \"send_finalize_vote\",").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    action send_certificate(cert: Certificate): bool = all {{"
    )
    .unwrap();
    writeln!(out, "        sent_notarize_votes' = sent_notarize_votes,").unwrap();
    writeln!(out, "        sent_nullify_votes' = sent_nullify_votes,").unwrap();
    writeln!(out, "        sent_finalize_votes' = sent_finalize_votes,").unwrap();
    writeln!(
        out,
        "        sent_certificates' = sent_certificates.union(Set(cert)),"
    )
    .unwrap();
    writeln!(out, "        store_notarize_votes' = store_notarize_votes,").unwrap();
    writeln!(out, "        store_nullify_votes' = store_nullify_votes,").unwrap();
    writeln!(out, "        store_finalize_votes' = store_finalize_votes,").unwrap();
    writeln!(out, "        store_certificates' = store_certificates,").unwrap();
    writeln!(
        out,
        "        ghost_committed_blocks' = ghost_committed_blocks,"
    )
    .unwrap();
    writeln!(out, "        leader' = leader,").unwrap();
    writeln!(out, "        replica_state' = replica_state,").unwrap();
    writeln!(out, "        certify_policy' = certify_policy,").unwrap();
    writeln!(out, "        lastAction' = \"send_certificate\",").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "    action inject_vote(vote: Vote): bool = all {{").unwrap();
    writeln!(out, "        match (vote) {{").unwrap();
    writeln!(out, "            | Notarize(v) => all {{").unwrap();
    writeln!(
        out,
        "                sent_notarize_votes' = sent_notarize_votes.union(Set(v)),"
    )
    .unwrap();
    writeln!(
        out,
        "                sent_nullify_votes' = sent_nullify_votes,"
    )
    .unwrap();
    writeln!(
        out,
        "                sent_finalize_votes' = sent_finalize_votes,"
    )
    .unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "            | Nullify(v) => all {{").unwrap();
    writeln!(
        out,
        "                sent_notarize_votes' = sent_notarize_votes,"
    )
    .unwrap();
    writeln!(
        out,
        "                sent_nullify_votes' = sent_nullify_votes.union(Set(v)),"
    )
    .unwrap();
    writeln!(
        out,
        "                sent_finalize_votes' = sent_finalize_votes,"
    )
    .unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "            | Finalize(v) => all {{").unwrap();
    writeln!(
        out,
        "                sent_notarize_votes' = sent_notarize_votes,"
    )
    .unwrap();
    writeln!(
        out,
        "                sent_nullify_votes' = sent_nullify_votes,"
    )
    .unwrap();
    writeln!(
        out,
        "                sent_finalize_votes' = sent_finalize_votes.union(Set(v)),"
    )
    .unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "        }},").unwrap();
    writeln!(out, "        sent_certificates' = sent_certificates,").unwrap();
    writeln!(out, "        store_notarize_votes' = store_notarize_votes,").unwrap();
    writeln!(out, "        store_nullify_votes' = store_nullify_votes,").unwrap();
    writeln!(out, "        store_finalize_votes' = store_finalize_votes,").unwrap();
    writeln!(out, "        store_certificates' = store_certificates,").unwrap();
    writeln!(
        out,
        "        ghost_committed_blocks' = ghost_committed_blocks,"
    )
    .unwrap();
    writeln!(out, "        leader' = leader,").unwrap();
    writeln!(out, "        replica_state' = replica_state,").unwrap();
    writeln!(out, "        certify_policy' = certify_policy,").unwrap();
    writeln!(out, "        lastAction' = \"inject_vote\",").unwrap();
    writeln!(out, "    }}").unwrap();
}
