//! Encodes a simplex consensus trace into a quint test module.
//!
//! Takes structured [`TraceEntry`] items from the sniffer and produces a
//! complete `.qnt` test module that can be verified with the quint model
//! checker against `replica.qnt`. The semantic walk in
//! [`build_action_items`] is shared with the TLA/TLC back-end (see
//! `super::tlc_encoder`), so the two encoders always agree on which events
//! are emitted, in what order, and with what dedup decisions.

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

/// Semantic action item produced by [`build_action_items`].
///
/// Each variant describes one logical action in a target-language-independent
/// form. The Quint and TLA+ renderers consume this list and turn it into the
/// appropriate concrete syntax (quint action calls or JSON action objects).
#[derive(Clone, Debug)]
pub enum ActionItem {
    /// Leader of `parent_view + 1` proposes a new payload.
    Propose {
        leader: String,
        view: u64,
        payload: String,
        parent_view: u64,
    },
    /// `send_notarize_vote(...)` barrier (introduces a vote into the
    /// network without delivering it to a particular receiver).
    SendNotarizeVote {
        view: u64,
        parent_view: u64,
        payload: String,
        sig: String,
    },
    /// `send_nullify_vote(...)` barrier.
    SendNullifyVote { view: u64, sig: String },
    /// `send_finalize_vote(...)` barrier.
    SendFinalizeVote {
        view: u64,
        parent_view: u64,
        payload: String,
        sig: String,
    },
    /// `send_certificate(...)` barrier.
    SendCertificate { cert: CertItem },
    /// `on_notarize(receiver, vote)` delivery.
    OnNotarize {
        receiver: String,
        view: u64,
        parent_view: u64,
        payload: String,
        sig: String,
    },
    /// `on_nullify(receiver, vote)` delivery.
    OnNullify {
        receiver: String,
        view: u64,
        sig: String,
    },
    /// `on_finalize(receiver, vote)` delivery.
    OnFinalize {
        receiver: String,
        view: u64,
        parent_view: u64,
        payload: String,
        sig: String,
    },
    /// `on_certificate(receiver, cert)` delivery.
    OnCertificate { receiver: String, cert: CertItem },
}

/// Semantic certificate value carried by [`ActionItem::SendCertificate`] and
/// [`ActionItem::OnCertificate`]. The `payload` field stores the `val_bN`
/// name (already mapped from the raw block hash), so the renderer never
/// needs the original [`build_block_map`] output. `parent_view` is the parent
/// view of the proposal embedded in the cert; populated from the encoder's
/// proposal map so the JSON renderer can emit a complete `Proposal` record.
#[derive(Clone, Debug)]
pub enum CertItem {
    Notarization {
        view: u64,
        parent_view: u64,
        payload: String,
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
        parent_view: u64,
        payload: String,
        signers: Vec<String>,
        ghost_sender: String,
    },
}

impl CertItem {
    /// Stable dedup key for delivery dedup. Ignores `ghost_sender` so that
    /// multiple deliveries of the "same" logical cert (kind/view/payload/
    /// signers) collapse to one `on_certificate` call per receiver.
    fn dedup_key(&self) -> String {
        match self {
            CertItem::Notarization {
                view,
                parent_view,
                payload,
                signers,
                ..
            } => {
                let mut sorted = signers.clone();
                sorted.sort();
                format!(
                    "N:{}:{}:{}:{}",
                    view,
                    parent_view,
                    payload,
                    sorted.join(",")
                )
            }
            CertItem::Nullification { view, signers, .. } => {
                let mut sorted = signers.clone();
                sorted.sort();
                format!("U:{}:{}", view, sorted.join(","))
            }
            CertItem::Finalization {
                view,
                parent_view,
                payload,
                signers,
                ..
            } => {
                let mut sorted = signers.clone();
                sorted.sort();
                format!(
                    "F:{}:{}:{}:{}",
                    view,
                    parent_view,
                    payload,
                    sorted.join(",")
                )
            }
        }
    }

    /// Returns the cert's `ghost_sender`.
    fn ghost_sender(&self) -> &str {
        match self {
            CertItem::Notarization { ghost_sender, .. }
            | CertItem::Nullification { ghost_sender, .. }
            | CertItem::Finalization { ghost_sender, .. } => ghost_sender,
        }
    }
}

fn cert_to_item(cert: &TracedCert, block_map: &[(String, String)]) -> CertItem {
    match cert {
        TracedCert::Notarization {
            view,
            parent,
            block,
            signers,
            ghost_sender,
        } => {
            let payload = map_block(block, block_map);
            CertItem::Notarization {
                view: *view,
                parent_view: *parent,
                payload,
                signers: signers.clone(),
                ghost_sender: ghost_sender.clone(),
            }
        }
        TracedCert::Nullification {
            view,
            signers,
            ghost_sender,
        } => CertItem::Nullification {
            view: *view,
            signers: signers.clone(),
            ghost_sender: ghost_sender.clone(),
        },
        TracedCert::Finalization {
            view,
            parent,
            block,
            signers,
            ghost_sender,
        } => {
            let payload = map_block(block, block_map);
            CertItem::Finalization {
                view: *view,
                parent_view: *parent,
                payload,
                signers: signers.clone(),
                ghost_sender: ghost_sender.clone(),
            }
        }
    }
}

fn leader_for_view(cfg: &EncoderConfig, view: u64) -> String {
    let n = cfg.n as u64;
    format!("n{}", (cfg.epoch + view) % n)
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

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct ProposalKey {
    view: u64,
    parent: u64,
    block_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum VoteReplayKey {
    Notarize {
        view: u64,
        parent: u64,
        sig: String,
        block: String,
    },
    Nullify {
        view: u64,
        sig: String,
    },
    Finalize {
        view: u64,
        parent: u64,
        sig: String,
        block: String,
    },
}

fn vote_replay_key(vote: &TracedVote, sig: String) -> VoteReplayKey {
    match vote {
        TracedVote::Notarize {
            view,
            parent,
            block,
            ..
        } => VoteReplayKey::Notarize {
            view: *view,
            parent: *parent,
            sig,
            block: block.clone(),
        },
        TracedVote::Nullify { view, .. } => VoteReplayKey::Nullify { view: *view, sig },
        TracedVote::Finalize {
            view,
            parent,
            block,
            ..
        } => VoteReplayKey::Finalize {
            view: *view,
            parent: *parent,
            sig,
            block: block.clone(),
        },
    }
}

fn proposal_key(view: u64, parent: u64, block_name: &str) -> ProposalKey {
    ProposalKey {
        view,
        parent,
        block_name: block_name.to_string(),
    }
}

fn proposal_var_name(key: &ProposalKey) -> String {
    format!("proposal_v{}_p{}_{}", key.view, key.parent, key.block_name)
}

fn proposal_ref(view: u64, parent: u64, block_name: &str) -> String {
    proposal_var_name(&proposal_key(view, parent, block_name))
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
    let mut sorted_proposals: Vec<ProposalKey> = proposals.iter().cloned().collect();
    sorted_proposals.sort();
    for key in &sorted_proposals {
        let parent_str = if key.parent == 0 {
            "GENESIS_VIEW".to_string()
        } else {
            key.parent.to_string()
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

    // Generate semantic action items in original trace order, then render
    // them as quint action call strings. The same `build_actions_internal`
    // walk drives the TLA+ renderer in `tlc::TlcMapper`, so quint and TLC
    // always agree on the action sequence.
    let action_items = build_actions_internal(&filtered_entries, &block_map, cfg);
    let actions = render_quint_actions(&action_items);

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

/// Public entry point: builds the full semantic action sequence for a trace.
///
/// Filters invalid byzantine votes, builds the block map and view-proposal
/// map, then walks the entries via [`build_actions_internal`] to produce a
/// list of [`ActionItem`]s. The caller picks a renderer
/// ([`render_quint_actions`] or [`render_tla_actions`]) to convert the items
/// into the target language.
pub fn build_action_items(trace_data: &TraceData, cfg: &EncoderConfig) -> Vec<ActionItem> {
    let entries = &trace_data.entries;
    let honest_votes = collect_honest_votes(entries, cfg);
    let filtered = filter_invalid_byzantine_votes(entries, cfg, &honest_votes);
    let block_map = build_block_map(trace_data);
    build_actions_internal(&filtered, &block_map, cfg)
}

/// Builds the full action list, processing entries in original trace order.
///
/// For notarize votes, the trace format does not include explicit proposal
/// events. We therefore reconstruct the missing causal prefix:
/// - when a correct leader is first needed, emit `Propose`
/// - when a byzantine leader is first needed, emit `SendNotarizeVote`
/// - before replaying an honest non-leader notarize send, ensure that sender
///   has already processed the leader's notarize vote via `OnNotarize`
///
/// This keeps the current trace format while restoring the protocol's causal
/// order: proposal first, then honest votes that depend on it.
fn build_actions_internal(
    entries: &[TraceEntry],
    block_map: &[(String, String)],
    cfg: &EncoderConfig,
) -> Vec<ActionItem> {
    let mut actions: Vec<ActionItem> = Vec::new();
    // Keys include block name and parent for notarize/finalize to handle
    // byzantine equivocation (same signer, same view, different blocks or parents).
    let mut sent_votes_emitted: HashSet<(String, u64, u64, String, String)> = HashSet::new();
    let mut self_delivered: HashSet<(String, u64, u64, String)> = HashSet::new();
    let mut leader_vote_introduced: HashSet<ProposalKey> = HashSet::new();
    let mut leader_vote_delivered: HashSet<(String, u64, u64, String)> = HashSet::new();
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
                // skip delivery actions for them. `Send*Vote` barriers
                // are still emitted so the global sent-vote set is updated
                // before any certificate that depends on them.
                let byzantine_receiver = is_byzantine_node(receiver, cfg.faults);

                match vote {
                    TracedVote::Notarize {
                        view,
                        parent,
                        sig,
                        block,
                    } => {
                        let sig = normalize_vote_sig_for_sender(sender, sig, cfg);
                        let bn = map_block(block, block_map);
                        let proposal = proposal_key(*view, *parent, &bn);
                        let parent_view = *parent;
                        let leader_id = leader_for_view(cfg, *view);
                        let leader_is_byzantine = is_byzantine_node(&leader_id, cfg.faults);
                        let sender_is_correct = !is_byzantine_node(sender, cfg.faults);
                        let is_leader_vote = sig == leader_id;

                        if sender_is_correct {
                            if leader_vote_introduced.insert(proposal.clone()) {
                                if leader_is_byzantine {
                                    if sent_votes_emitted.insert((
                                        leader_id.clone(),
                                        *view,
                                        parent_view,
                                        "notarize".into(),
                                        bn.clone(),
                                    )) {
                                        actions.push(ActionItem::SendNotarizeVote {
                                            view: *view,
                                            parent_view,
                                            payload: bn.clone(),
                                            sig: leader_id.clone(),
                                        });
                                    }
                                } else {
                                    actions.push(ActionItem::Propose {
                                        leader: leader_id.clone(),
                                        view: *view,
                                        payload: bn.clone(),
                                        parent_view,
                                    });
                                }
                            }

                            if sender != &leader_id
                                && leader_vote_delivered.insert((
                                    sender.clone(),
                                    *view,
                                    parent_view,
                                    bn.clone(),
                                ))
                            {
                                actions.push(ActionItem::OnNotarize {
                                    receiver: sender.clone(),
                                    view: *view,
                                    parent_view,
                                    payload: bn.clone(),
                                    sig: leader_id.clone(),
                                });
                            }
                        } else if is_byzantine_node(&sig, cfg.faults)
                            && sent_votes_emitted.insert((
                                sig.clone(),
                                *view,
                                parent_view,
                                "notarize".into(),
                                bn.clone(),
                            ))
                        {
                            actions.push(ActionItem::SendNotarizeVote {
                                view: *view,
                                parent_view,
                                payload: bn.clone(),
                                sig: sig.clone(),
                            });
                        }

                        if byzantine_receiver {
                            continue;
                        }

                        if is_leader_vote {
                            if receiver != &leader_id
                                && leader_vote_delivered.insert((
                                    receiver.clone(),
                                    *view,
                                    parent_view,
                                    bn.clone(),
                                ))
                            {
                                actions.push(ActionItem::OnNotarize {
                                    receiver: receiver.clone(),
                                    view: *view,
                                    parent_view,
                                    payload: bn.clone(),
                                    sig: leader_id.clone(),
                                });
                            }
                        } else {
                            actions.push(ActionItem::OnNotarize {
                                receiver: receiver.clone(),
                                view: *view,
                                parent_view,
                                payload: bn.clone(),
                                sig,
                            });
                        }
                    }
                    TracedVote::Finalize {
                        view,
                        parent,
                        sig,
                        block,
                    } => {
                        let sig = normalize_vote_sig_for_sender(sender, sig, cfg);
                        let bn = map_block(block, block_map);
                        let parent_view = *parent;

                        if sent_votes_emitted.insert((
                            sig.clone(),
                            *view,
                            parent_view,
                            "finalize".into(),
                            bn.clone(),
                        )) {
                            actions.push(ActionItem::SendFinalizeVote {
                                view: *view,
                                parent_view,
                                payload: bn.clone(),
                                sig: sig.clone(),
                            });
                        }

                        if byzantine_receiver {
                            continue;
                        }

                        // Correct finalize: self-delivery (node counts its own finalize)
                        if !is_byzantine_node(&sig, cfg.faults)
                            && self_delivered.insert((
                                sig.clone(),
                                *view,
                                parent_view,
                                "finalize".into(),
                            ))
                        {
                            actions.push(ActionItem::OnFinalize {
                                receiver: sig.clone(),
                                view: *view,
                                parent_view,
                                payload: bn.clone(),
                                sig: sig.clone(),
                            });
                        }

                        // Deliver vote to receiver
                        actions.push(ActionItem::OnFinalize {
                            receiver: receiver.clone(),
                            view: *view,
                            parent_view,
                            payload: bn.clone(),
                            sig,
                        });
                    }
                    TracedVote::Nullify { view, sig } => {
                        let sig = normalize_vote_sig_for_sender(sender, sig, cfg);
                        if sent_votes_emitted.insert((
                            sig.clone(),
                            *view,
                            0,
                            "nullify".into(),
                            String::new(),
                        )) {
                            actions.push(ActionItem::SendNullifyVote {
                                view: *view,
                                sig: sig.clone(),
                            });
                        }

                        if byzantine_receiver {
                            continue;
                        }

                        // Correct nullify: self-delivery
                        if !is_byzantine_node(&sig, cfg.faults)
                            && self_delivered.insert((sig.clone(), *view, 0, "nullify".into()))
                        {
                            actions.push(ActionItem::OnNullify {
                                receiver: sig.clone(),
                                view: *view,
                                sig: sig.clone(),
                            });
                        }

                        // Deliver vote to receiver
                        actions.push(ActionItem::OnNullify {
                            receiver: receiver.clone(),
                            view: *view,
                            sig,
                        });
                    }
                }
            }
            TraceEntry::Certificate { receiver, cert, .. } => {
                let cert_item = cert_to_item(cert, block_map);
                let cert_key = cert_item.dedup_key();

                // Emit `send_certificate` once per distinct cert, including
                // `ghost_sender` in the dedup key. The model treats certs
                // with different `ghost_sender` as distinct values in
                // `sent_certificates`, so each variant must be sent before
                // it can be delivered via `on_certificate`.
                let cert_send_key = format!("{}:{}", cert_item.ghost_sender(), &cert_key);
                if cert_sent.insert(cert_send_key) {
                    actions.push(ActionItem::SendCertificate {
                        cert: cert_item.clone(),
                    });
                }

                // Skip delivery to byzantine receivers (no state in quint model).
                if is_byzantine_node(receiver, cfg.faults) {
                    continue;
                }

                // Skip duplicate cert deliveries to the same receiver.
                // A cert is identified by (kind, view, block, signers);
                // the ghost_sender varies but doesn't affect model behavior.
                let cert_dedup_key = format!("{}:{}", receiver, &cert_key);
                if !cert_delivered.insert(cert_dedup_key) {
                    continue;
                }

                // Deliver certificate (barrier: cannot be reordered with votes)
                actions.push(ActionItem::OnCertificate {
                    receiver: receiver.clone(),
                    cert: cert_item,
                });
            }
        }
    }

    actions
}

/// Renders semantic action items as quint action call strings.
///
/// Applies a second-pass dedup over `(receiver, vote)` for finalize/nullify
/// deliveries so identical calls produced by multiple distinct trace entries
/// collapse to one quint call (the model's state update is idempotent).
pub fn render_quint_actions(items: &[ActionItem]) -> Vec<String> {
    let mut result = Vec::new();
    let mut delivery_seen: HashSet<(String, String)> = HashSet::new();

    for item in items {
        match item {
            ActionItem::Propose {
                leader,
                view,
                payload,
                parent_view,
            } => {
                let pref = proposal_ref(*view, *parent_view, payload);
                result.push(format!(
                    "propose(\"{}\", {}.payload, {}.parent)",
                    leader, pref, pref
                ));
            }
            ActionItem::SendNotarizeVote {
                view,
                parent_view,
                payload,
                sig,
            } => {
                result.push(format!(
                    "send_notarize_vote({{ proposal: {}, sig: \"{}\" }})",
                    proposal_ref(*view, *parent_view, payload),
                    sig
                ));
            }
            ActionItem::SendNullifyVote { view, sig } => {
                result.push(format!(
                    "send_nullify_vote({{ view: {}, sig: \"{}\" }})",
                    view, sig
                ));
            }
            ActionItem::SendFinalizeVote {
                view,
                parent_view,
                payload,
                sig,
            } => {
                result.push(format!(
                    "send_finalize_vote({{ proposal: {}, sig: \"{}\" }})",
                    proposal_ref(*view, *parent_view, payload),
                    sig
                ));
            }
            ActionItem::SendCertificate { cert } => {
                result.push(format!("send_certificate({})", cert_to_quint(cert)));
            }
            ActionItem::OnNotarize {
                receiver,
                view,
                parent_view,
                payload,
                sig,
            } => {
                result.push(format!(
                    "on_notarize(\"{}\", {{ proposal: {}, sig: \"{}\" }})",
                    receiver,
                    proposal_ref(*view, *parent_view, payload),
                    sig
                ));
            }
            ActionItem::OnNullify {
                receiver,
                view,
                sig,
            } => {
                let vote = format!("{{ view: {}, sig: \"{}\" }}", view, sig);
                if delivery_seen.insert((receiver.clone(), vote.clone())) {
                    result.push(format!("on_nullify(\"{}\", {})", receiver, vote));
                }
            }
            ActionItem::OnFinalize {
                receiver,
                view,
                parent_view,
                payload,
                sig,
            } => {
                let vote = format!(
                    "{{ proposal: {}, sig: \"{}\" }}",
                    proposal_ref(*view, *parent_view, payload),
                    sig
                );
                if delivery_seen.insert((receiver.clone(), vote.clone())) {
                    result.push(format!("on_finalize(\"{}\", {})", receiver, vote));
                }
            }
            ActionItem::OnCertificate { receiver, cert } => {
                result.push(format!(
                    "on_certificate(\"{}\", {})",
                    receiver,
                    cert_to_quint(cert)
                ));
            }
        }
    }

    result
}

fn cert_to_quint(cert: &CertItem) -> String {
    match cert {
        CertItem::Notarization {
            view,
            parent_view,
            payload,
            signers,
            ghost_sender,
        } => {
            let sigs: Vec<String> = signers.iter().map(|s| format!("\"{}\"", s)).collect();
            format!(
                "notarization({}, Set({}), \"{}\")",
                proposal_ref(*view, *parent_view, payload),
                sigs.join(", "),
                ghost_sender
            )
        }
        CertItem::Nullification {
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
        CertItem::Finalization {
            view,
            parent_view,
            payload,
            signers,
            ghost_sender,
        } => {
            let sigs: Vec<String> = signers.iter().map(|s| format!("\"{}\"", s)).collect();
            format!(
                "finalization({}, Set({}), \"{}\")",
                proposal_ref(*view, *parent_view, payload),
                sigs.join(", "),
                ghost_sender
            )
        }
    }
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

/// Builds proposals from block-carrying entries in the trace, using the
/// parent stored directly in each entry rather than inferring it.
fn build_view_proposals(
    entries: &[TraceEntry],
    block_map: &[(String, String)],
    _cfg: &EncoderConfig,
) -> HashSet<ProposalKey> {
    let mut proposals = HashSet::new();
    for entry in entries {
        let (view, parent, block) = match entry {
            TraceEntry::Vote {
                vote:
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
                    },
                ..
            } => (*view, *parent, block.as_str()),
            TraceEntry::Certificate {
                cert:
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
                    },
                ..
            } => (*view, *parent, block.as_str()),
            _ => continue,
        };
        proposals.insert(proposal_key(view, parent, &map_block(block, block_map)));
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
