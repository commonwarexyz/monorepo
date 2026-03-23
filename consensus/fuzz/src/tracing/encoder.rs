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

/// Kind of vote delivery action. Used to group votes between barriers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum VoteKind {
    Notarize,
    Finalize,
    Nullify,
}

/// Intermediate action representation used during trace encoding.
/// Vote deliveries between barriers can be reordered and merged by
/// (receiver, kind, view, block) into a single `on_vote_*` call with
/// a combined `Set(...)`, reducing the number of quint evaluation steps.
#[derive(Clone)]
enum ActionItem {
    /// Non-reorderable action: inject_proposal, on_proposal, inject_vote,
    /// on_certificate. Acts as a barrier for vote grouping.
    Barrier(String),
    /// Vote delivery that can be merged with others sharing the same
    /// (receiver, kind, view, block) key.
    VoteDelivery {
        kind: VoteKind,
        receiver: String,
        view: u64,
        block: String,
        /// Individual vote constructor, e.g. `notarize(2, "n0", "val_b0")`.
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
    block_name: String,
    leader: String,
    view_parent: u64,
    block_parent_name: String,
    /// Correct nodes that sent notarize votes for this view.
    correct_notarizers: Vec<String>,
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
    let leader_map = build_leader_map_to(cfg, cfg.max_view);
    let leader_lookup: HashMap<u64, String> = leader_map.iter().cloned().collect();

    let block_names: Vec<&str> = block_map.iter().map(|(_, n)| n.as_str()).collect();
    let f = (cfg.n - 1) / 3;
    let q = cfg.n - f;

    // Build view proposals from notarize votes
    let proposals = build_view_proposals(&correct_entries, &block_map, &leader_map, cfg);

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

    // Certify policy: derive from block hash using Certifier::Sometimes logic
    writeln!(out, "    pure val CERTIFY_POLICY = Map(").unwrap();
    writeln!(out, "        GENESIS_BLOCK -> true,").unwrap();
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
    let mut sorted_views: Vec<u64> = proposals.keys().cloned().collect();
    sorted_views.sort();
    for &view in &sorted_views {
        let p = &proposals[&view];
        let vp_str = if p.view_parent == 0 {
            "GENESIS_VIEW".to_string()
        } else {
            p.view_parent.to_string()
        };
        let bp_str = if p.view_parent == 0 {
            "GENESIS_BLOCK".to_string()
        } else {
            format!("\"{}\"", p.block_parent_name)
        };
        writeln!(
            out,
            "    pure val proposal_v{} = {{ block: \"{}\", view: {}, view_parent: {}, block_parent: {}, sig: sig_of(\"{}\") }}",
            view, p.block_name, view, vp_str, bp_str, p.leader
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    // Generate actions in original trace order, then group vote deliveries
    let vote_blocks = build_correct_vote_blocks(&correct_entries, &block_map, cfg.faults);
    let action_items = build_actions(
        &correct_entries,
        &block_map,
        &proposals,
        cfg,
        &leader_lookup,
        &vote_blocks,
    );

    // Group vote deliveries between barriers: votes to the same
    // (receiver, kind, view, block) are merged into a single on_vote_*
    // call with a combined Set, reducing quint evaluation steps.
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

/// Emits `inject_proposal` (once per view) and `on_proposal` + notarize
/// self-delivery (once per node+view) if not already done.
fn ensure_proposal_and_on_proposal(
    node: &str,
    view: u64,
    block_name: &str,
    proposal_injected: &mut HashSet<u64>,
    on_proposal_done: &mut HashSet<(String, u64)>,
    self_delivered: &mut HashSet<(String, u64, String)>,
    actions: &mut Vec<ActionItem>,
) {
    if proposal_injected.insert(view) {
        actions.push(ActionItem::Barrier(format!(
            "inject_proposal(proposal_v{})",
            view
        )));
    }
    if on_proposal_done.insert((node.to_string(), view)) {
        actions.push(ActionItem::Barrier(format!(
            "on_proposal(\"{}\", proposal_v{})",
            node, view
        )));
        // Self-delivery: node receives its own notarize vote
        if self_delivered.insert((node.to_string(), view, "notarize".to_string())) {
            actions.push(ActionItem::VoteDelivery {
                kind: VoteKind::Notarize,
                receiver: node.to_string(),
                view,
                block: block_name.to_string(),
                vote: format!("notarize({}, \"{}\", \"{}\")", view, node, block_name),
            });
        }
    }
}

/// Pre-scans the trace to build a map of blocks that correct nodes actually
/// voted for. Used to filter out forged certificates from byzantine senders.
/// The sniffer captures all network messages including forged certs that the
/// Rust engine rejects via signature verification.
fn build_correct_vote_blocks(
    entries: &[TraceEntry],
    block_map: &[(String, String)],
    faults: usize,
) -> HashMap<(String, u64, String), HashSet<String>> {
    let mut map: HashMap<(String, u64, String), HashSet<String>> = HashMap::new();
    for entry in entries {
        if let TraceEntry::Vote { vote, .. } = entry {
            match vote {
                TracedVote::Notarize { view, sig, block } if !is_byzantine_node(sig, faults) => {
                    let bn = map_block(block, block_map);
                    map.entry((sig.clone(), *view, "notarize".into()))
                        .or_default()
                        .insert(bn);
                }
                TracedVote::Finalize { view, sig, block } if !is_byzantine_node(sig, faults) => {
                    let bn = map_block(block, block_map);
                    map.entry((sig.clone(), *view, "finalize".into()))
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
/// For each notarize vote from the leader delivered to a correct node,
/// emits `on_proposal` (which adds the receiver's notarize to `sent_vote`)
/// followed by a notarize self-delivery. For correct non-leader notarize
/// signers, ensures `on_proposal` was called before their vote is used.
/// Byzantine votes are injected via `inject_vote`. All vote deliveries
/// use direct `on_vote_*` calls.
///
/// Returns structured `ActionItem`s: barriers (non-reorderable) and vote
/// deliveries (groupable). The caller runs `group_vote_deliveries` to
/// merge adjacent vote deliveries sharing the same (receiver, kind, view,
/// block) key into single `on_vote_*` calls with combined Sets.
fn build_actions(
    entries: &[TraceEntry],
    block_map: &[(String, String)],
    proposals: &HashMap<u64, ViewProposal>,
    cfg: &EncoderConfig,
    leader_lookup: &HashMap<u64, String>,
    vote_blocks: &HashMap<(String, u64, String), HashSet<String>>,
) -> Vec<ActionItem> {
    let mut actions: Vec<ActionItem> = Vec::new();
    let mut proposal_injected: HashSet<u64> = HashSet::new();
    let mut on_proposal_done: HashSet<(String, u64)> = HashSet::new();
    // Keys include block name for notarize/finalize to handle byzantine equivocation
    // (same signer, same view, different blocks).
    let mut injected_votes: HashSet<(String, u64, String, String)> = HashSet::new();
    let mut self_delivered: HashSet<(String, u64, String)> = HashSet::new();
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
            TraceEntry::Vote { receiver, vote, .. } => match vote {
                TracedVote::Notarize { view, sig, block } => {
                    let bn = map_block(block, block_map);
                    let is_leader =
                        leader_lookup.get(view).map(|l| l.as_str()) == Some(sig.as_str());

                    // Ensure on_proposal for the correct notarize signer (puts their
                    // vote in sent_vote). Triggered when we first see their vote.
                    if !is_byzantine_node(sig, cfg.faults)
                        && proposals
                            .get(view)
                            .map_or(false, |p| p.correct_notarizers.contains(sig))
                    {
                        ensure_proposal_and_on_proposal(
                            sig,
                            *view,
                            &bn,
                            &mut proposal_injected,
                            &mut on_proposal_done,
                            &mut self_delivered,
                            &mut actions,
                        );
                    }

                    // If leader's notarize, also trigger on_proposal for the correct
                    // receiver (the leader's notarize IS the proposal delivery).
                    if is_leader
                        && !is_byzantine_node(receiver, cfg.faults)
                        && proposals
                            .get(view)
                            .map_or(false, |p| p.correct_notarizers.contains(receiver))
                    {
                        ensure_proposal_and_on_proposal(
                            receiver,
                            *view,
                            &bn,
                            &mut proposal_injected,
                            &mut on_proposal_done,
                            &mut self_delivered,
                            &mut actions,
                        );
                    }

                    // Byzantine notarize: inject into sent_vote
                    if is_byzantine_node(sig, cfg.faults)
                        && injected_votes.insert((
                            sig.clone(),
                            *view,
                            "notarize".into(),
                            bn.clone(),
                        ))
                    {
                        actions.push(ActionItem::Barrier(format!(
                            "inject_vote(notarize({}, \"{}\", \"{}\"))",
                            view, sig, bn
                        )));
                    }

                    // Deliver vote to receiver
                    actions.push(ActionItem::VoteDelivery {
                        kind: VoteKind::Notarize,
                        receiver: receiver.clone(),
                        view: *view,
                        block: bn.clone(),
                        vote: format!("notarize({}, \"{}\", \"{}\")", view, sig, bn),
                    });
                }
                TracedVote::Finalize { view, sig, block } => {
                    let bn = map_block(block, block_map);

                    // Correct finalize: self-delivery (node counts its own finalize)
                    if !is_byzantine_node(sig, cfg.faults)
                        && self_delivered.insert((sig.clone(), *view, "finalize".into()))
                    {
                        actions.push(ActionItem::VoteDelivery {
                            kind: VoteKind::Finalize,
                            receiver: sig.clone(),
                            view: *view,
                            block: bn.clone(),
                            vote: format!("finalize({}, \"{}\", \"{}\")", view, sig, bn),
                        });
                    }

                    // Byzantine finalize: inject into sent_vote
                    if is_byzantine_node(sig, cfg.faults)
                        && injected_votes.insert((
                            sig.clone(),
                            *view,
                            "finalize".into(),
                            bn.clone(),
                        ))
                    {
                        actions.push(ActionItem::Barrier(format!(
                            "inject_vote(finalize({}, \"{}\", \"{}\"))",
                            view, sig, bn
                        )));
                    }

                    // Deliver vote to receiver
                    actions.push(ActionItem::VoteDelivery {
                        kind: VoteKind::Finalize,
                        receiver: receiver.clone(),
                        view: *view,
                        block: bn.clone(),
                        vote: format!("finalize({}, \"{}\", \"{}\")", view, sig, bn),
                    });
                }
                TracedVote::Nullify { view, sig } => {
                    // Correct nullify: inject if not produced by on_proposal
                    if !is_byzantine_node(sig, cfg.faults) {
                        let needs_inject = proposals
                            .get(view)
                            .map_or(true, |p| !p.correct_notarizers.contains(sig));
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
                    if is_byzantine_node(sig, cfg.faults)
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
                        TracedCert::Nullification {
                            view, signers, ..
                        } => {
                            signers_sorted = signers.clone();
                            signers_sorted.sort();
                            format!(
                                "{}:U:{}:{}",
                                receiver,
                                view,
                                signers_sorted.join(",")
                            )
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

                // Ensure correct notarize signers have on_proposal (for notarization certs)
                if let TracedCert::Notarization {
                    view,
                    block,
                    signers,
                    ..
                } = cert
                {
                    let bn = map_block(block, block_map);
                    for sig in signers {
                        if !is_byzantine_node(sig, cfg.faults)
                            && proposals
                                .get(view)
                                .map_or(false, |p| p.correct_notarizers.contains(sig))
                        {
                            ensure_proposal_and_on_proposal(
                                sig,
                                *view,
                                &bn,
                                &mut proposal_injected,
                                &mut on_proposal_done,
                                &mut self_delivered,
                                &mut actions,
                            );
                        }
                    }
                }

                // Ensure correct nullify signers are injected (for nullification certs)
                if let TracedCert::Nullification { view, signers, .. } = cert {
                    for sig in signers {
                        if !is_byzantine_node(sig, cfg.faults) {
                            let needs_inject = proposals
                                .get(view)
                                .map_or(true, |p| !p.correct_notarizers.contains(sig));
                            if needs_inject
                                && injected_votes
                                    .insert((sig.clone(), *view, "nullify".into(), String::new()))
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
/// view, block) and rendering each group as a single `on_vote_*` call.
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
            VoteKind::Notarize => format!(
                "on_vote_notarize(\"{}\", {}, \"{}\", Set({}))",
                receiver, view, block, vote_set
            ),
            VoteKind::Finalize => format!(
                "on_vote_finalize(\"{}\", {}, \"{}\", Set({}))",
                receiver, view, block, vote_set
            ),
            VoteKind::Nullify => format!(
                "on_vote_nullify(\"{}\", {}, Set({}))",
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

/// Builds view proposals from notarize votes in the trace.
///
/// For each view with notarize votes, determines the block, leader, parent
/// references, and which correct nodes sent notarize. Parent references form
/// a chain: each view's parent is the most recently notarized (view, block).
fn build_view_proposals(
    entries: &[TraceEntry],
    block_map: &[(String, String)],
    leader_map: &[(u64, String)],
    cfg: &EncoderConfig,
) -> HashMap<u64, ViewProposal> {
    // Collect views with notarize votes from correct nodes
    let mut view_block_hash: HashMap<u64, String> = HashMap::new();
    let mut view_correct_notarizers: HashMap<u64, Vec<String>> = HashMap::new();

    for entry in entries {
        if let TraceEntry::Vote {
            vote: TracedVote::Notarize { view, sig, block },
            ..
        } = entry
        {
            // Only use correct nodes' votes for the block hash to avoid
            // picking a byzantine node's equivocating block.
            if !is_byzantine_node(sig, cfg.faults) {
                view_block_hash
                    .entry(*view)
                    .or_insert_with(|| block.clone());
                let notarizers = view_correct_notarizers.entry(*view).or_default();
                if !notarizers.contains(sig) {
                    notarizers.push(sig.clone());
                }
            }
        }
    }

    // Sort views to build parent chain
    let mut views: Vec<u64> = view_block_hash.keys().cloned().collect();
    views.sort();

    let leader_lookup: HashMap<u64, &str> =
        leader_map.iter().map(|(v, l)| (*v, l.as_str())).collect();

    let mut last_parent_view: u64 = 0;
    let mut last_parent_block_name = String::new();

    let mut proposals = HashMap::new();
    for &view in &views {
        let block_hash = &view_block_hash[&view];
        let block_name = map_block(block_hash, block_map);
        let leader = leader_lookup.get(&view).unwrap_or(&"").to_string();
        let correct_notarizers = view_correct_notarizers
            .get(&view)
            .cloned()
            .unwrap_or_default();

        proposals.insert(
            view,
            ViewProposal {
                block_name: block_name.clone(),
                leader,
                view_parent: last_parent_view,
                block_parent_name: last_parent_block_name.clone(),
                correct_notarizers,
            },
        );

        // Only update parent chain if the block is certifiable.
        // Uncertifiable blocks get nullified and cannot serve as a valid
        // parent (valid_parent requires finalized or notarized+certified).
        if is_certifiable(block_hash) {
            last_parent_view = view;
            last_parent_block_name = block_name;
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
                        "inject_vote(notarize({}, \"{}\", \"{}\"))",
                        view, sig, bn
                    )));
                }
            }
        }
        TracedCert::Nullification {
            view, signers, ..
        } => {
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
                        "inject_vote(finalize({}, \"{}\", \"{}\"))",
                        view, sig, bn
                    )));
                }
            }
        }
    }
}

/// Writes the standard helper actions used by test modules.
fn write_helpers(out: &mut String) {
    writeln!(
        out,
        "    action inject_proposal(proposal: Proposal): bool = all {{"
    )
    .unwrap();
    writeln!(
        out,
        "        sent_proposal' = sent_proposal.union(Set(proposal)),"
    )
    .unwrap();
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
    writeln!(out, "        lastAction' = \"inject_proposal\",").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    action inject_vote(vote: Vote): bool = all {{"
    )
    .unwrap();
    writeln!(
        out,
        "        sent_vote' = sent_vote.union(Set(vote)),"
    )
    .unwrap();
    writeln!(out, "        sent_proposal' = sent_proposal,").unwrap();
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
    writeln!(out, "        lastAction' = \"inject_vote\",").unwrap();
    writeln!(out, "    }}").unwrap();
}
