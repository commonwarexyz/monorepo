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
/// Vote deliveries between barriers can be reordered and merged by
/// (receiver, kind, view, block) into a single `on_vote_*` call with
/// a combined `Set(...)`, reducing the number of quint evaluation steps.
#[derive(Clone)]
enum ActionItem {
    /// Non-reorderable action: on_notarize, inject_vote, on_certificate.
    /// Acts as a barrier for vote grouping.
    Barrier(String),
    /// Vote delivery that can be merged with others sharing the same
    /// (receiver, kind, view, block) key.
    VoteDelivery {
        kind: VoteKind,
        receiver: String,
        view: u64,
        block: String,
        /// Individual vote constructor, e.g. `notarize(proposal_v2_val_b0, "n0")`.
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
    /// Correct nodes that sent notarize votes for this view.
    correct_notarizers: Vec<String>,
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
pub fn encode(entries: &[TraceEntry], cfg: &EncoderConfig) -> String {
    let honest_votes = collect_honest_votes(entries, cfg);

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
    let correct_entries = filter_invalid_byzantine_votes(&correct_entries, cfg, &honest_votes);

    let block_map = build_block_map(&correct_entries);
    let leader_map = build_leader_map_to(cfg, cfg.max_view);
    let leader_lookup: HashMap<u64, String> = leader_map.iter().cloned().collect();

    let block_names: Vec<&str> = block_map.iter().map(|(_, n)| n.as_str()).collect();
    let f = (cfg.n - 1) / 3;
    let q = cfg.n - f;

    let vote_blocks = build_correct_vote_blocks(&correct_entries, &block_map, cfg);

    // Build view proposals from notarize votes and authentic certificates
    let proposals =
        build_view_proposals(&correct_entries, &block_map, &vote_blocks, cfg);

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
    writeln!(out, "        INVALID_PAYLOADS = Set()").unwrap();
    writeln!(out, "    ).* from \"../replica\"").unwrap();
    writeln!(out).unwrap();

    // Certify policy: derive from block hash using Certifier::Sometimes logic
    writeln!(out, "    pure val CERTIFY_POLICY = Map(").unwrap();
    writeln!(out, "        GENESIS_PAYLOAD -> true,").unwrap();
    for (hash, name) in &block_map {
        let certifiable = is_certifiable(hash);
        writeln!(out, "        \"{}\" -> {},", name, certifiable).unwrap();
    }
    writeln!(out, "    )").unwrap();
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

    // Generate actions in original trace order, then group vote deliveries
    let action_items = build_actions(
        &correct_entries,
        &block_map,
        &proposals,
        cfg,
        &leader_lookup,
        &vote_blocks,
    );

    // Group finalize/nullify deliveries between barriers: votes to the same
    // (receiver, kind, view, block) are merged into a single on_* call
    // with a combined Set, reducing quint evaluation steps.
    let grouped = group_vote_deliveries(action_items);

    // Deduplicate while preserving order
    let mut actions = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for action in grouped {
        if seen.insert(action.clone()) {
            actions.push(action);
        }
    }

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

fn is_correct_notarizer_for_view(
    proposals: &HashMap<ProposalKey, ViewProposal>,
    view: u64,
    sig: &str,
) -> bool {
    proposals
        .iter()
        .any(|(key, proposal)| {
            key.view == view && proposal.correct_notarizers.iter().any(|s| s == sig)
        })
}

/// Pre-scans the trace to build a map of blocks that correct nodes actually
/// voted for. Used to filter out forged certificates from byzantine senders.
/// The sniffer captures all network messages including forged certs that the
/// Rust engine rejects via signature verification.
fn build_correct_vote_blocks(
    entries: &[TraceEntry],
    block_map: &[(String, String)],
    cfg: &EncoderConfig,
) -> HashMap<(String, u64, String), HashSet<String>> {
    let mut map: HashMap<(String, u64, String), HashSet<String>> = HashMap::new();
    for entry in entries {
        if let TraceEntry::Vote { sender, vote, .. } = entry {
            match vote {
                TracedVote::Notarize { view, sig, block } => {
                    let sig = normalize_vote_sig_for_sender(sender, sig, cfg);
                    if is_byzantine_node(&sig, cfg.faults) {
                        continue;
                    }
                    let bn = map_block(block, block_map);
                    map.entry((sig, *view, "notarize".into()))
                        .or_default()
                        .insert(bn);
                }
                TracedVote::Finalize { view, sig, block } => {
                    let sig = normalize_vote_sig_for_sender(sender, sig, cfg);
                    if is_byzantine_node(&sig, cfg.faults) {
                        continue;
                    }
                    let bn = map_block(block, block_map);
                    map.entry((sig, *view, "finalize".into()))
                        .or_default()
                        .insert(bn);
                }
                _ => {}
            }
        }
    }
    map
}

/// Returns true if a certificate is authentic: all correct signers actually
/// voted for the cert's block. Certs from correct senders are trusted.
/// Certs from byzantine senders are validated against the vote map.
fn is_authentic_cert(
    cert: &TracedCert,
    vote_blocks: &HashMap<(String, u64, String), HashSet<String>>,
    block_map: &[(String, String)],
    faults: usize,
) -> bool {
    let ghost_sender = match cert {
        TracedCert::Notarization { ghost_sender, .. }
        | TracedCert::Nullification { ghost_sender, .. }
        | TracedCert::Finalization { ghost_sender, .. } => ghost_sender,
    };
    // Certs from correct senders are trusted (they assembled from real votes)
    if !is_byzantine_node(ghost_sender, faults) {
        return true;
    }
    // For byzantine-sourced certs, verify correct signers' votes match the block
    match cert {
        TracedCert::Notarization {
            view,
            block,
            signers,
            ..
        } => {
            let bn = map_block(block, block_map);
            signers.iter().all(|s| {
                is_byzantine_node(s, faults)
                    || vote_blocks
                        .get(&(s.clone(), *view, "notarize".into()))
                        .map_or(false, |blocks| blocks.contains(&bn))
            })
        }
        TracedCert::Nullification { .. } => {
            // Nullify votes don't carry a block, no forgery possible
            true
        }
        TracedCert::Finalization {
            view,
            block,
            signers,
            ..
        } => {
            let bn = map_block(block, block_map);
            signers.iter().all(|s| {
                is_byzantine_node(s, faults)
                    || vote_blocks
                        .get(&(s.clone(), *view, "finalize".into()))
                        .map_or(false, |blocks| blocks.contains(&bn))
            })
        }
    }
}

/// Builds the full action list, processing entries in original trace order.
///
/// For notarize votes, leader proposal handling is driven directly through
/// `on_notarize(receiver, vote)`. The encoder synthesizes a single
/// self-delivery for a correct leader so the leader's own sent/local vote
/// is represented even when the trace only shows network deliveries to
/// other replicas. Byzantine votes are injected via `inject_vote`.
/// Finalize/nullify deliveries continue to use grouped `on_*` calls.
///
/// Returns structured `ActionItem`s: barriers (non-reorderable) and vote
/// deliveries (groupable). The caller runs `group_vote_deliveries` to
/// merge adjacent vote deliveries sharing the same (receiver, kind, view,
/// block) key into single `on_vote_*` calls with combined Sets.
fn build_actions(
    entries: &[TraceEntry],
    block_map: &[(String, String)],
    proposals: &HashMap<ProposalKey, ViewProposal>,
    cfg: &EncoderConfig,
    leader_lookup: &HashMap<u64, String>,
    vote_blocks: &HashMap<(String, u64, String), HashSet<String>>,
) -> Vec<ActionItem> {
    let mut actions: Vec<ActionItem> = Vec::new();
    // Keys include block name for notarize/finalize to handle byzantine equivocation
    // (same signer, same view, different blocks).
    let mut injected_votes: HashSet<(String, u64, String, String)> = HashSet::new();
    let mut self_delivered: HashSet<(String, u64, String)> = HashSet::new();
    let mut leader_self_processed: HashSet<ProposalKey> = HashSet::new();
    // Dedup cert deliveries per receiver. In the Rust execution, each node
    // broadcasts its assembled cert to all peers, producing up to N^2 total
    // deliveries (N senders x N receivers). In the quint model, the first
    // delivery per (receiver, kind, view, block, signers) does all the work;
    // subsequent ones with a different ghost_sender are no-ops because the
    // cert is already in store_certificate. Skipping them avoids redundant
    // state evaluation and dramatically speeds up the quint checker.
    let mut cert_delivered: HashSet<String> = HashSet::new();

    for entry in entries {
        match entry {
            TraceEntry::Vote {
                sender,
                receiver,
                vote,
            } => match vote {
                TracedVote::Notarize { view, sig, block } => {
                    let sig = normalize_vote_sig_for_sender(sender, sig, cfg);
                    let bn = map_block(block, block_map);
                    let proposal = proposal_key(*view, &bn);
                    let is_leader =
                        leader_lookup.get(view).map(|l| l.as_str()) == Some(sig.as_str());

                    // The trace typically does not contain a self-delivery for the
                    // correct leader's own proposal vote, so synthesize one once.
                    if is_leader
                        && !is_byzantine_node(&sig, cfg.faults)
                        && leader_self_processed.insert(proposal.clone())
                    {
                        actions.push(ActionItem::Barrier(format!(
                            "on_notarize(\"{}\", {{ proposal: {}, sig: \"{}\" }})",
                            sig,
                            proposal_var_name(&proposal),
                            sig
                        )));
                    }

                    // Byzantine notarize: inject into sent_vote
                    if is_byzantine_node(&sig, cfg.faults)
                        && injected_votes.insert((
                            sig.clone(),
                            *view,
                            "notarize".into(),
                            bn.clone(),
                        ))
                    {
                        actions.push(ActionItem::Barrier(format!(
                            "inject_vote(notarize({}, \"{}\"))",
                            proposal_ref(*view, &bn),
                            sig
                        )));
                    }

                    // Deliver vote to receiver
                    actions.push(ActionItem::Barrier(format!(
                        "on_notarize(\"{}\", {{ proposal: {}, sig: \"{}\" }})",
                        receiver,
                        proposal_ref(*view, &bn),
                        sig
                    )));
                }
                TracedVote::Finalize { view, sig, block } => {
                    let sig = normalize_vote_sig_for_sender(sender, sig, cfg);
                    let bn = map_block(block, block_map);

                    // Correct finalize: self-delivery (node counts its own finalize)
                    if !is_byzantine_node(&sig, cfg.faults)
                        && self_delivered.insert((sig.clone(), *view, "finalize".into()))
                    {
                        actions.push(ActionItem::VoteDelivery {
                            kind: VoteKind::Finalize,
                            receiver: sig.clone(),
                            view: *view,
                            block: bn.clone(),
                            vote: format!("finalize({}, \"{}\")", proposal_ref(*view, &bn), sig),
                        });
                    }

                    // Byzantine finalize: inject into sent_vote
                    if is_byzantine_node(&sig, cfg.faults)
                        && injected_votes.insert((
                            sig.clone(),
                            *view,
                            "finalize".into(),
                            bn.clone(),
                        ))
                    {
                        actions.push(ActionItem::Barrier(format!(
                            "inject_vote(finalize({}, \"{}\"))",
                            proposal_ref(*view, &bn),
                            sig
                        )));
                    }

                    // Deliver vote to receiver
                    actions.push(ActionItem::VoteDelivery {
                        kind: VoteKind::Finalize,
                        receiver: receiver.clone(),
                        view: *view,
                        block: bn.clone(),
                        vote: format!("finalize({}, \"{}\")", proposal_ref(*view, &bn), sig),
                    });
                }
                TracedVote::Nullify { view, sig } => {
                    let sig = normalize_vote_sig_for_sender(sender, sig, cfg);
                    // Correct nullify: inject if it was not already produced by
                    // leader proposal processing for that signer/view.
                    if !is_byzantine_node(&sig, cfg.faults) {
                        let needs_inject = !is_correct_notarizer_for_view(proposals, *view, &sig);
                        if needs_inject
                            && injected_votes.insert((
                                sig.clone(),
                                *view,
                                "nullify".into(),
                                String::new(),
                            ))
                        {
                            actions.push(ActionItem::Barrier(format!(
                                "inject_vote(nullify({}, \"{}\"))",
                                view, sig
                            )));
                        }
                        // Self-delivery
                        if self_delivered.insert((sig.clone(), *view, "nullify".into())) {
                            actions.push(ActionItem::VoteDelivery {
                                kind: VoteKind::Nullify,
                                receiver: sig.clone(),
                                view: *view,
                                block: String::new(),
                                vote: format!("nullify({}, \"{}\")", view, sig),
                            });
                        }
                    }

                    // Byzantine nullify: inject into sent_vote
                    if is_byzantine_node(&sig, cfg.faults)
                        && injected_votes.insert((
                            sig.clone(),
                            *view,
                            "nullify".into(),
                            String::new(),
                        ))
                    {
                        actions.push(ActionItem::Barrier(format!(
                            "inject_vote(nullify({}, \"{}\"))",
                            view, sig
                        )));
                    }

                    // Deliver vote to receiver
                    actions.push(ActionItem::VoteDelivery {
                        kind: VoteKind::Nullify,
                        receiver: receiver.clone(),
                        view: *view,
                        block: String::new(),
                        vote: format!("nullify({}, \"{}\")", view, sig),
                    });
                }
            },
            TraceEntry::Certificate { receiver, cert, .. } => {
                // Skip forged certificates from byzantine senders.
                // The sniffer captures all network messages including certs
                // that the Rust engine would reject via signature verification.
                if !is_authentic_cert(cert, vote_blocks, block_map, cfg.faults) {
                    continue;
                }

                // Skip duplicate cert deliveries to the same receiver.
                // A cert is identified by (kind, view, block, signers);
                // the ghost_sender varies but doesn't affect model behavior.
                let cert_dedup_key = {
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
                                "{}:N:{}:{}:{}",
                                receiver,
                                view,
                                map_block(block, block_map),
                                signers_sorted.join(",")
                            )
                        }
                        TracedCert::Nullification { view, signers, .. } => {
                            signers_sorted = signers.clone();
                            signers_sorted.sort();
                            format!("{}:U:{}:{}", receiver, view, signers_sorted.join(","))
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
                                "{}:F:{}:{}:{}",
                                receiver,
                                view,
                                map_block(block, block_map),
                                signers_sorted.join(",")
                            )
                        }
                    }
                };
                if !cert_delivered.insert(cert_dedup_key) {
                    continue;
                }

                // Ensure correct nullify signers are injected (for nullification certs)
                if let TracedCert::Nullification { view, signers, .. } = cert {
                    for sig in signers {
                        if !is_byzantine_node(sig, cfg.faults) {
                            let needs_inject = !is_correct_notarizer_for_view(proposals, *view, sig);
                            if needs_inject
                                && injected_votes.insert((
                                    sig.clone(),
                                    *view,
                                    "nullify".into(),
                                    String::new(),
                                ))
                            {
                                actions.push(ActionItem::Barrier(format!(
                                    "inject_vote(nullify({}, \"{}\"))",
                                    view, sig
                                )));
                            }
                        }
                    }
                }

                // Inject byzantine signers' votes for the certificate
                inject_byzantine_cert_votes(
                    cert,
                    &mut injected_votes,
                    &mut actions,
                    block_map,
                    cfg,
                );

                // Deliver certificate (barrier: cannot be reordered with votes)
                let cert_str = encode_cert(cert, block_map);
                actions.push(ActionItem::Barrier(format!(
                    "on_certificate(\"{}\", {})",
                    receiver, cert_str
                )));
            }
        }
    }

    actions
}

/// Merges adjacent vote deliveries that share the same (receiver, kind,
/// view, block) key into single calls with combined Sets. Barriers act
/// as fences: votes on opposite sides of a barrier are never merged.
///
/// For example, 9 individual `on_vote_finalize` calls (3 signers x 3
/// receivers) become 3 calls (one per receiver, each with 3 votes in
/// the Set), reducing quint evaluation steps by ~3x per view.
fn group_vote_deliveries(items: Vec<ActionItem>) -> Vec<String> {
    let mut result = Vec::new();
    let mut pending: Vec<ActionItem> = Vec::new();

    for item in items {
        match &item {
            ActionItem::Barrier(_) => {
                flush_vote_group(&mut pending, &mut result);
                if let ActionItem::Barrier(s) = item {
                    result.push(s);
                }
            }
            ActionItem::VoteDelivery { .. } => {
                pending.push(item);
            }
        }
    }
    flush_vote_group(&mut pending, &mut result);
    result
}

/// Flushes pending vote deliveries by grouping them by (receiver, kind,
/// view, block) and rendering each group as a single `on_*` call.
/// Preserves first-appearance order for deterministic output.
fn flush_vote_group(pending: &mut Vec<ActionItem>, result: &mut Vec<String>) {
    if pending.is_empty() {
        return;
    }

    // Each entry: (receiver, kind, view, block, votes)
    // Preserves insertion order for deterministic output.
    let mut groups: Vec<(String, VoteKind, u64, String, Vec<String>)> = Vec::new();

    for item in pending.drain(..) {
        if let ActionItem::VoteDelivery {
            kind,
            receiver,
            view,
            block,
            vote,
        } = item
        {
            if let Some(g) = groups
                .iter_mut()
                .find(|g| g.0 == receiver && g.1 == kind && g.2 == view && g.3 == block)
            {
                // Dedup individual votes within the group
                if !g.4.contains(&vote) {
                    g.4.push(vote);
                }
            } else {
                groups.push((receiver, kind, view, block, vec![vote]));
            }
        }
    }

    for (receiver, kind, view, block, votes) in groups {
        let vote_set = votes.join(", ");
        let s = match kind {
            VoteKind::Finalize => format!(
                "on_finalize(\"{}\", {}, \"{}\", Set({}))",
                receiver, view, block, vote_set
            ),
            VoteKind::Nullify => format!(
                "on_nullify(\"{}\", {}, Set({}))",
                receiver, view, vote_set
            ),
        };
        result.push(s);
    }
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
/// chosen from the latest authentic certifiable certificate.
fn build_view_proposals(
    entries: &[TraceEntry],
    block_map: &[(String, String)],
    vote_blocks: &HashMap<(String, u64, String), HashSet<String>>,
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
            TraceEntry::Certificate { cert, .. } if is_authentic_cert(
                cert,
                vote_blocks,
                block_map,
                cfg.faults,
            ) =>
            {
                match cert {
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
                }
            }
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
        view_blocks.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.block_name.cmp(&b.0.block_name)));

        for (key, correct_notarizers, _) in &view_blocks {
            proposals.insert(
                key.clone(),
                ViewProposal {
                    view_parent: last_parent_view,
                    correct_notarizers: correct_notarizers.clone(),
                },
            );
        }

        if let Some(view_certified_blocks) = certified_blocks.get(&view) {
            let support = |key: &ProposalKey| {
                per_view_blocks
                    .get(&view)
                    .and_then(|blocks| blocks.get(&key.block_name))
                    .map_or(0, |(correct_notarizers, _)| correct_notarizers.len())
            };

            if view_certified_blocks
                .iter()
                .max_by(|a, b| {
                    support(&proposal_key(view, a.0))
                        .cmp(&support(&proposal_key(view, b.0)))
                        .then_with(|| a.1.cmp(b.1))
                        .then_with(|| a.0.cmp(b.0))
                })
                .is_some()
            {
                last_parent_view = view;
            }
        }
    }

    proposals
}

/// Injects byzantine signers' votes from a certificate into sent_vote.
fn inject_byzantine_cert_votes(
    cert: &TracedCert,
    injected: &mut HashSet<(String, u64, String, String)>,
    actions: &mut Vec<ActionItem>,
    block_map: &[(String, String)],
    cfg: &EncoderConfig,
) {
    match cert {
        TracedCert::Notarization {
            view,
            block,
            signers,
            ..
        } => {
            let bn = map_block(block, block_map);
            for sig in signers {
                if !is_byzantine_node(sig, cfg.faults) {
                    continue;
                }
                if injected.insert((sig.clone(), *view, "notarize".into(), bn.clone())) {
                    actions.push(ActionItem::Barrier(format!(
                        "inject_vote(notarize({}, \"{}\"))",
                        proposal_ref(*view, &bn),
                        sig
                    )));
                }
            }
        }
        TracedCert::Nullification { view, signers, .. } => {
            for sig in signers {
                if !is_byzantine_node(sig, cfg.faults) {
                    continue;
                }
                if injected.insert((sig.clone(), *view, "nullify".into(), String::new())) {
                    actions.push(ActionItem::Barrier(format!(
                        "inject_vote(nullify({}, \"{}\"))",
                        view, sig
                    )));
                }
            }
        }
        TracedCert::Finalization {
            view,
            block,
            signers,
            ..
        } => {
            let bn = map_block(block, block_map);
            for sig in signers {
                if !is_byzantine_node(sig, cfg.faults) {
                    continue;
                }
                if injected.insert((sig.clone(), *view, "finalize".into(), bn.clone())) {
                    actions.push(ActionItem::Barrier(format!(
                        "inject_vote(finalize({}, \"{}\"))",
                        proposal_ref(*view, &bn),
                        sig
                    )));
                }
            }
        }
    }
}

/// Writes the standard helper actions used by test modules.
fn write_helpers(out: &mut String) {
    writeln!(out, "    action inject_vote(vote: Vote): bool = all {{").unwrap();
    writeln!(out, "        sent_vote' = sent_vote.union(Set(vote)),").unwrap();
    writeln!(out, "        sent_proposal' = sent_proposal,").unwrap();
    writeln!(out, "        sent_certificate' = sent_certificate,").unwrap();
    writeln!(out, "        store_vote' = store_vote,").unwrap();
    writeln!(out, "        store_certificate' = store_certificate,").unwrap();
    writeln!(out, "        ghost_proposal' = ghost_proposal,").unwrap();
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
