//! Encodes a canonical simplex consensus [`Trace`] into a Quint test module.
//!
//! Takes the canonical event list produced by the recorder and produces a
//! complete `.qnt` test module that can be verified with the quint model
//! checker against `replica.qnt`. The semantic walk in
//! [`lower_events_to_actions`] is shared with the TLA/TLC back-end (see
//! `super::tlc_encoder`), so the two encoders always agree on which events
//! are emitted, in what order, and with what dedup decisions.

use commonware_consensus::{
    simplex::{
        replay::{Event, Snapshot, Trace, Wire},
        scheme::ed25519::Scheme,
        types::{Attributable, Certificate, Vote},
    },
    types::View,
    Viewable,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Write,
};

// ---------------------------------------------------------------------------
// Semantic action items (shared with tlc_encoder)
// ---------------------------------------------------------------------------

/// Target-language-independent semantic action.
///
/// Each variant describes one logical action produced by the canonical
/// lowering. The Quint and TLA+ renderers consume this list and turn it into
/// the appropriate concrete syntax (quint action calls or JSON action
/// objects).
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
/// needs the original block map. `parent_view` is the parent view of the
/// proposal embedded in the cert; populated from the encoder's proposal map
/// so the JSON renderer can emit a complete `Proposal` record.
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
pub(crate) struct ProposalKey {
    view: u64,
    parent: u64,
    block_name: String,
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn node_id(p: commonware_utils::Participant) -> String {
    format!("n{}", p.get())
}

fn digest_hex(d: &Sha256Digest) -> String {
    d.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
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

/// Builds the leader map: view -> replica ID using round-robin.
fn build_leader_map_to(cfg: &EncoderConfig, max_view: u64) -> Vec<(u64, String)> {
    let mut map = Vec::new();
    for view in 0..=max_view {
        let leader_idx = (cfg.epoch + view) as usize % cfg.n;
        map.push((view, format!("n{}", leader_idx)));
    }
    map
}

// ---------------------------------------------------------------------------
// Snapshot-shaped representation used by the renderer
// ---------------------------------------------------------------------------

/// Minimal Quint-view of a per-replica snapshot used by the renderer's
/// `replica_has_*` assertions. Populated from the canonical
/// [`Snapshot`] via [`snapshot_to_reporter_states`]; not publicly visible
/// outside this module (the rendering helpers consume it directly).
#[derive(Clone, Debug)]
pub(crate) struct ReporterStateData {
    pub notarizations: BTreeMap<u64, ProposalData>,
    pub notarization_signature_counts: BTreeMap<u64, Option<usize>>,
    pub nullifications: BTreeSet<u64>,
    pub nullification_signature_counts: BTreeMap<u64, Option<usize>>,
    pub finalizations: BTreeMap<u64, ProposalData>,
    pub finalization_signature_counts: BTreeMap<u64, Option<usize>>,
    pub certified: BTreeSet<u64>,
    pub notarize_signers: BTreeMap<u64, BTreeSet<String>>,
    pub nullify_signers: BTreeMap<u64, BTreeSet<String>>,
    pub finalize_signers: BTreeMap<u64, BTreeSet<String>>,
    pub max_finalized_view: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ProposalData {
    pub payload: String,
}

// ---------------------------------------------------------------------------
// Canonical event lowering
// ---------------------------------------------------------------------------

/// Build the `(hex, "val_bN")` block map by walking canonical events in
/// order of first appearance.
pub fn build_block_map_from_events(events: &[Event]) -> Vec<(String, String)> {
    let mut map: Vec<(String, String)> = Vec::new();
    let mut seen: HashMap<String, String> = HashMap::new();
    let mut record = |hash: String| {
        if hash == "GENESIS_PAYLOAD" || seen.contains_key(&hash) {
            return;
        }
        let name = format!("val_b{}", map.len());
        seen.insert(hash.clone(), name.clone());
        map.push((hash, name));
    };
    for event in events {
        if let Some(d) = event_digest(event) {
            record(digest_hex(&d));
        }
    }
    map
}

fn event_digest(e: &Event) -> Option<Sha256Digest> {
    match e {
        Event::Propose { proposal, .. } => Some(proposal.payload),
        Event::Construct { vote, .. } => match vote {
            Vote::Notarize(n) => Some(n.proposal.payload),
            Vote::Finalize(f) => Some(f.proposal.payload),
            Vote::Nullify(_) => None,
        },
        Event::Deliver { msg, .. } => match msg {
            Wire::Vote(v) => match v {
                Vote::Notarize(n) => Some(n.proposal.payload),
                Vote::Finalize(f) => Some(f.proposal.payload),
                Vote::Nullify(_) => None,
            },
            Wire::Cert(c) => match c {
                Certificate::Notarization(n) => Some(n.proposal.payload),
                Certificate::Finalization(f) => Some(f.proposal.payload),
                Certificate::Nullification(_) => None,
            },
        },
        Event::Timeout { .. } => None,
    }
}

/// Extract the view an event touches; used to derive `max_view`.
pub fn event_view(e: &Event) -> Option<u64> {
    match e {
        Event::Propose { proposal, .. } => Some(proposal.view().get()),
        Event::Construct { vote, .. } => Some(vote.view().get()),
        Event::Deliver { msg, .. } => Some(match msg {
            Wire::Vote(v) => v.view().get(),
            Wire::Cert(c) => c.view().get(),
        }),
        Event::Timeout { view, .. } => Some(view.get()),
    }
}

/// Walk canonical events into the existing `ProposalKey` set.
pub(crate) fn build_proposals_from_events(
    events: &[Event],
    block_map: &[(String, String)],
) -> HashSet<ProposalKey> {
    let mut out = HashSet::new();
    for event in events {
        let (view, parent, hash) = match event {
            Event::Propose { proposal, .. } => (
                proposal.view().get(),
                proposal.parent.get(),
                digest_hex(&proposal.payload),
            ),
            Event::Construct { vote, .. } => match vote {
                Vote::Notarize(n) => (
                    n.proposal.view().get(),
                    n.proposal.parent.get(),
                    digest_hex(&n.proposal.payload),
                ),
                Vote::Finalize(f) => (
                    f.proposal.view().get(),
                    f.proposal.parent.get(),
                    digest_hex(&f.proposal.payload),
                ),
                Vote::Nullify(_) => continue,
            },
            Event::Deliver { msg, .. } => match msg {
                Wire::Vote(v) => match v {
                    Vote::Notarize(n) => (
                        n.proposal.view().get(),
                        n.proposal.parent.get(),
                        digest_hex(&n.proposal.payload),
                    ),
                    Vote::Finalize(f) => (
                        f.proposal.view().get(),
                        f.proposal.parent.get(),
                        digest_hex(&f.proposal.payload),
                    ),
                    Vote::Nullify(_) => continue,
                },
                Wire::Cert(c) => match c {
                    Certificate::Notarization(n) => (
                        n.proposal.view().get(),
                        n.proposal.parent.get(),
                        digest_hex(&n.proposal.payload),
                    ),
                    Certificate::Finalization(f) => (
                        f.proposal.view().get(),
                        f.proposal.parent.get(),
                        digest_hex(&f.proposal.payload),
                    ),
                    Certificate::Nullification(_) => continue,
                },
            },
            Event::Timeout { .. } => continue,
        };
        out.insert(proposal_key(view, parent, &map_block(&hash, block_map)));
    }
    out
}

/// Lower a canonical event list into semantic [`ActionItem`]s. This is a
/// 1:1 mapping — no causal reconstruction, no dedup, no Byzantine-sig
/// normalization (canonical events carry real signed payloads).
///
/// The only dedup this does is for `send_certificate`: a certificate
/// may be `Deliver`ed multiple times (once per receiver), but the TLC
/// / Quint action set expects `send_certificate` to be emitted once per
/// `(ghost_sender, dedup_key)`. We emit it on the first `Deliver` of
/// that certificate and skip on subsequent ones.
pub fn lower_events_to_actions(
    events: &[Event],
    block_map: &[(String, String)],
) -> Vec<ActionItem> {
    let mut out = Vec::new();
    let mut cert_sent: HashSet<String> = HashSet::new();

    for event in events {
        match event {
            Event::Propose { leader, proposal } => {
                let payload = map_block(&digest_hex(&proposal.payload), block_map);
                out.push(ActionItem::Propose {
                    leader: node_id(*leader),
                    view: proposal.view().get(),
                    parent_view: proposal.parent.get(),
                    payload,
                });
            }
            Event::Construct { node, vote } => {
                // Source of truth for the signer is the signed vote
                // itself (cryptographic identity), not the enclosing
                // `node` field. For honest recorder output the two
                // agree; for malformed or future-Byzantine canonical
                // traces they may diverge — preferring the signed
                // signer keeps Quint lowering consistent with what
                // Rust replay actually ingests. A `debug_assert!`
                // catches mismatches during recorder development.
                match vote {
                    Vote::Notarize(n) => {
                        let signer = n.signer();
                        debug_assert_eq!(
                            signer, *node,
                            "Event::Construct(Notarize) signer mismatch: node={} signer={}",
                            node.get(),
                            signer.get(),
                        );
                        out.push(ActionItem::SendNotarizeVote {
                            view: n.proposal.view().get(),
                            parent_view: n.proposal.parent.get(),
                            payload: map_block(&digest_hex(&n.proposal.payload), block_map),
                            sig: node_id(signer),
                        });
                    }
                    Vote::Nullify(n) => {
                        let signer = n.signer();
                        debug_assert_eq!(
                            signer, *node,
                            "Event::Construct(Nullify) signer mismatch: node={} signer={}",
                            node.get(),
                            signer.get(),
                        );
                        out.push(ActionItem::SendNullifyVote {
                            view: n.view().get(),
                            sig: node_id(signer),
                        });
                    }
                    Vote::Finalize(f) => {
                        let signer = f.signer();
                        debug_assert_eq!(
                            signer, *node,
                            "Event::Construct(Finalize) signer mismatch: node={} signer={}",
                            node.get(),
                            signer.get(),
                        );
                        out.push(ActionItem::SendFinalizeVote {
                            view: f.proposal.view().get(),
                            parent_view: f.proposal.parent.get(),
                            payload: map_block(&digest_hex(&f.proposal.payload), block_map),
                            sig: node_id(signer),
                        });
                    }
                }
            }
            Event::Deliver { to, from, msg } => {
                let receiver = node_id(*to);
                let ghost_sender = node_id(*from);
                match msg {
                    Wire::Vote(Vote::Notarize(n)) => {
                        out.push(ActionItem::OnNotarize {
                            receiver,
                            view: n.proposal.view().get(),
                            parent_view: n.proposal.parent.get(),
                            payload: map_block(&digest_hex(&n.proposal.payload), block_map),
                            sig: node_id(n.signer()),
                        });
                    }
                    Wire::Vote(Vote::Nullify(n)) => {
                        out.push(ActionItem::OnNullify {
                            receiver,
                            view: n.view().get(),
                            sig: node_id(n.signer()),
                        });
                    }
                    Wire::Vote(Vote::Finalize(f)) => {
                        out.push(ActionItem::OnFinalize {
                            receiver,
                            view: f.proposal.view().get(),
                            parent_view: f.proposal.parent.get(),
                            payload: map_block(&digest_hex(&f.proposal.payload), block_map),
                            sig: node_id(f.signer()),
                        });
                    }
                    Wire::Cert(cert) => {
                        let item = cert_to_item_canonical(cert, &ghost_sender, block_map);
                        let key = format!("{}:{}", item.ghost_sender(), item.dedup_key());
                        if cert_sent.insert(key) {
                            out.push(ActionItem::SendCertificate {
                                cert: item.clone(),
                            });
                        }
                        out.push(ActionItem::OnCertificate {
                            receiver,
                            cert: item,
                        });
                    }
                }
            }
            Event::Timeout { .. } => {
                // No ActionItem variant for Timeout. Timeout-induced
                // nullify votes are captured separately as
                // `Event::Construct(Vote::Nullify)`.
            }
        }
    }
    out
}

fn cert_to_item_canonical(
    cert: &Certificate<Scheme, Sha256Digest>,
    ghost_sender: &str,
    block_map: &[(String, String)],
) -> CertItem {
    let signers = |s: &commonware_cryptography::certificate::Signers| -> Vec<String> {
        s.iter().map(node_id).collect()
    };
    match cert {
        Certificate::Notarization(n) => CertItem::Notarization {
            view: n.proposal.view().get(),
            parent_view: n.proposal.parent.get(),
            payload: map_block(&digest_hex(&n.proposal.payload), block_map),
            signers: signers(&n.certificate.signers),
            ghost_sender: ghost_sender.to_string(),
        },
        Certificate::Nullification(n) => CertItem::Nullification {
            view: n.view().get(),
            signers: signers(&n.certificate.signers),
            ghost_sender: ghost_sender.to_string(),
        },
        Certificate::Finalization(f) => CertItem::Finalization {
            view: f.proposal.view().get(),
            parent_view: f.proposal.parent.get(),
            payload: map_block(&digest_hex(&f.proposal.payload), block_map),
            signers: signers(&f.certificate.signers),
            ghost_sender: ghost_sender.to_string(),
        },
    }
}

/// Build a `reporter_states`-shaped view of a canonical [`Snapshot`] so
/// the Quint snapshot-assertion helper can consume it.
pub(crate) fn snapshot_to_reporter_states(
    snapshot: &Snapshot,
) -> BTreeMap<String, ReporterStateData> {
    let mut out = BTreeMap::new();
    for (participant, node) in &snapshot.nodes {
        let node_id_s = format!("n{}", participant.get());
        let notarizations: BTreeMap<u64, ProposalData> = node
            .notarizations
            .iter()
            .map(|(view, cert)| {
                (
                    view.get(),
                    ProposalData {
                        payload: digest_hex(&cert.payload),
                    },
                )
            })
            .collect();
        let notarization_signature_counts: BTreeMap<u64, Option<usize>> = node
            .notarizations
            .iter()
            .map(|(view, cert)| (view.get(), cert.signature_count.map(|c| c as usize)))
            .collect();
        let nullifications: BTreeSet<u64> =
            node.nullifications.keys().map(|v| v.get()).collect();
        let nullification_signature_counts: BTreeMap<u64, Option<usize>> = node
            .nullifications
            .iter()
            .map(|(view, n)| (view.get(), n.signature_count.map(|c| c as usize)))
            .collect();
        let finalizations: BTreeMap<u64, ProposalData> = node
            .finalizations
            .iter()
            .map(|(view, cert)| {
                (
                    view.get(),
                    ProposalData {
                        payload: digest_hex(&cert.payload),
                    },
                )
            })
            .collect();
        let finalization_signature_counts: BTreeMap<u64, Option<usize>> = node
            .finalizations
            .iter()
            .map(|(view, cert)| (view.get(), cert.signature_count.map(|c| c as usize)))
            .collect();
        let certified: BTreeSet<u64> = node.certified.iter().map(|v| v.get()).collect();
        let sig_map = |m: &BTreeMap<View, BTreeSet<commonware_utils::Participant>>|
                      -> BTreeMap<u64, BTreeSet<String>> {
            m.iter()
                .map(|(v, s)| (v.get(), s.iter().map(|p| node_id(*p)).collect()))
                .collect()
        };
        let data = ReporterStateData {
            notarizations,
            notarization_signature_counts,
            nullifications,
            nullification_signature_counts,
            finalizations,
            finalization_signature_counts,
            certified,
            notarize_signers: sig_map(&node.notarize_signers),
            nullify_signers: sig_map(&node.nullify_signers),
            finalize_signers: sig_map(&node.finalize_signers),
            max_finalized_view: node.last_finalized.get(),
        };
        out.insert(node_id_s, data);
    }
    out
}

/// Public entry point: encode a canonical [`Trace`] as a Quint test module.
pub fn encode_from_trace(trace: &Trace, required_containers: u64) -> String {
    let cfg = EncoderConfig {
        n: trace.topology.n as usize,
        faults: trace.topology.faults as usize,
        epoch: trace.topology.epoch,
        max_view: trace
            .events
            .iter()
            .filter_map(event_view)
            .max()
            .unwrap_or(1),
        required_containers,
    };
    let block_map = build_block_map_from_events(&trace.events);
    let proposals = build_proposals_from_events(&trace.events, &block_map);
    let actions = lower_events_to_actions(&trace.events, &block_map);
    let reporter_states = snapshot_to_reporter_states(&trace.expected);
    render_quint_from_actions(&cfg, &block_map, &proposals, &actions, &reporter_states)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Core rendering: given already-prepared inputs, emit the Quint test module.
fn render_quint_from_actions(
    cfg: &EncoderConfig,
    block_map: &[(String, String)],
    proposals: &HashSet<ProposalKey>,
    action_items: &[ActionItem],
    reporter_states: &BTreeMap<String, ReporterStateData>,
) -> String {
    let leader_map = build_leader_map_to(cfg, cfg.max_view);
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
    for (hash, name) in block_map {
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

    // Render semantic action items as quint action call strings.
    let actions = render_quint_actions(action_items);

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
    let last_action = write_snapshot_expectations(&mut out, &last_part, reporter_states, block_map);
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

/// Lowers [`ActionItem`]s into a Quint action call string for each item.
///
/// Applies a second-pass dedup over `(receiver, vote)` for finalize/nullify
/// deliveries so identical calls produced by multiple distinct events
/// collapse to one Quint call (the model's state update is idempotent).
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

// ---------------------------------------------------------------------------
// Renderer-local helpers (snapshot assertions, action definitions)
// ---------------------------------------------------------------------------

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
    proposal: Option<&ProposalData>,
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
    reporter_states: &BTreeMap<String, ReporterStateData>,
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

    // replica_notarization_signature_count — max over matching certs.
    writeln!(out, "    def replica_notarization_signature_count(id: ReplicaId, view: ViewNumber): Option[int] = {{").unwrap();
    writeln!(
        out,
        "        store_certificates.get(id).fold(None, (acc, c) =>"
    )
    .unwrap();
    writeln!(out, "            match c {{").unwrap();
    writeln!(out, "                | Notarization(nc) => if (nc.proposal.view == view)").unwrap();
    writeln!(out, "                    Some(match acc {{ | Some(cur) => if (cur > nc.signatures.size()) cur else nc.signatures.size() | None => nc.signatures.size() }})").unwrap();
    writeln!(out, "                  else acc").unwrap();
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

    // replica_nullification_signature_count — max over matching certs.
    writeln!(out, "    def replica_nullification_signature_count(id: ReplicaId, view: ViewNumber): Option[int] = {{").unwrap();
    writeln!(
        out,
        "        store_certificates.get(id).fold(None, (acc, c) =>"
    )
    .unwrap();
    writeln!(out, "            match c {{").unwrap();
    writeln!(out, "                | Nullification(nc) => if (nc.view == view)").unwrap();
    writeln!(out, "                    Some(match acc {{ | Some(cur) => if (cur > nc.signatures.size()) cur else nc.signatures.size() | None => nc.signatures.size() }})").unwrap();
    writeln!(out, "                  else acc").unwrap();
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

    // replica_finalization_signature_count — max over matching certs.
    writeln!(out, "    def replica_finalization_signature_count(id: ReplicaId, view: ViewNumber): Option[int] = {{").unwrap();
    writeln!(
        out,
        "        store_certificates.get(id).fold(None, (acc, c) =>"
    )
    .unwrap();
    writeln!(out, "            match c {{").unwrap();
    writeln!(out, "                | Finalization(fc) => if (fc.proposal.view == view)").unwrap();
    writeln!(out, "                    Some(match acc {{ | Some(cur) => if (cur > fc.signatures.size()) cur else fc.signatures.size() | None => fc.signatures.size() }})").unwrap();
    writeln!(out, "                  else acc").unwrap();
    writeln!(out, "                | _ => acc").unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "        )").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_observed_notarize_signers
    writeln!(out, "    def replica_observed_notarize_signers(id: ReplicaId, view: ViewNumber): Set[Signature] = {{").unwrap();
    writeln!(out, "        val stored = store_notarize_votes.get(id).filter(v => v.proposal.view == view).map(v => v.sig)").unwrap();
    writeln!(out, "        val local = sent_notarize_votes.filter(v => and {{ v.sig == sig_of(id), v.proposal.view == view }}).map(v => v.sig)").unwrap();
    writeln!(out, "        stored.union(local)").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_observed_nullify_signers
    writeln!(out, "    def replica_observed_nullify_signers(id: ReplicaId, view: ViewNumber): Set[Signature] = {{").unwrap();
    writeln!(out, "        val stored = store_nullify_votes.get(id).filter(v => v.view == view).map(v => v.sig)").unwrap();
    writeln!(out, "        val local = sent_nullify_votes.filter(v => and {{ v.sig == sig_of(id), v.view == view }}).map(v => v.sig)").unwrap();
    writeln!(out, "        stored.union(local)").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // replica_observed_finalize_signers
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod canonical_tests {
    use super::*;
    use commonware_consensus::simplex::replay::{trace::Timing, Topology};

    #[test]
    fn empty_trace_produces_module() {
        let trace = Trace {
            topology: Topology {
                n: 4,
                faults: 0,
                epoch: 333,
                namespace: b"consensus_fuzz".to_vec(),
                timing: Timing::default(),
            },
            events: Vec::new(),
            expected: Snapshot::default(),
        };
        let quint = encode_from_trace(&trace, 0);
        assert!(quint.contains("module tests"));
        assert!(quint.contains("N = 4"));
        assert!(quint.contains("F = 1"));
        assert!(quint.contains("Q = 3"));
        assert!(quint.contains("run traceTest"));
    }

    #[test]
    fn lower_empty_events_is_empty() {
        let block_map: Vec<(String, String)> = Vec::new();
        let items = lower_events_to_actions(&[], &block_map);
        assert!(items.is_empty());
    }
}
