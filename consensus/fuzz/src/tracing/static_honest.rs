//! Analytically-generated small honest `Trace` fixtures.
//!
//! This module synthesizes canonical [`Trace`] values without running a
//! live simplex cluster: it walks a bounded tree of "propose" and
//! "nullify" view extensions, signs votes with the deterministic fuzz
//! fixture, and assembles notarization / nullification / finalization
//! certificates directly via `from_notarizes` / `from_nullifies` /
//! `from_finalizes`.
//!
//! The output [`Trace`] is event-order-equivalent to what
//! [`commonware_consensus::simplex::replay::record_honest`] produces for
//! the equivalent live run: `Propose` before `Construct`, every `Deliver`
//! has a matching `Construct` earlier, certificates land after the last
//! vote that contributed to them.

use commonware_consensus::{
    simplex::{
        replay::{
            trace::{
                rehydrate_keys, CertStateSnapshot, NodeSnapshot, NullStateSnapshot, Snapshot,
                Timing, Topology,
            },
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
use commonware_cryptography::{
    certificate::mocks::Fixture,
    sha256::{Digest as Sha256Digest, Sha256},
    Hasher,
};
use commonware_parallel::Sequential;
use commonware_utils::Participant;
use sha1::{Digest, Sha1};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    sync::LazyLock,
};

const N: u32 = 4;
const FAULTS: u32 = 0;
const Q: usize = 3;
const NAMESPACE: &[u8] = b"consensus_fuzz";

/// Number of distinct payloads cycled through by `payload_for_view`.
const NUM_PAYLOADS: usize = 3;

/// Returns true if the hex digest is certifiable, matching
/// `Certifier::Sometimes`: `last_byte % 11 < 9`. Kept because the
/// encoder's quint output is compared against a model that assumes
/// certifiable payloads, and the existing fixture tests rely on this
/// property.
fn is_certifiable(digest: &Sha256Digest) -> bool {
    let bytes: &[u8] = digest.as_ref();
    let last = *bytes.last().unwrap_or(&0);
    (last % 11) < 9
}

fn alias_digest(name: &str) -> Sha256Digest {
    Sha256::hash(name.as_bytes())
}

/// Canonical payload digests, one per cycled block alias. Computed from
/// "val_b0", "val_b1", "val_b2" via SHA-256.
static PAYLOADS: LazyLock<[Sha256Digest; NUM_PAYLOADS]> = LazyLock::new(|| {
    let digests = std::array::from_fn(|i| alias_digest(&format!("val_b{i}")));
    for (i, d) in digests.iter().enumerate() {
        assert!(
            is_certifiable(d),
            "val_b{i} is not certifiable — update NUM_PAYLOADS or aliases"
        );
    }
    digests
});

/// Deterministic ed25519 fixture shared by all generated traces. Seeded
/// by [`rehydrate_keys`] so signer indices match the replayer's keyset.
static FIXTURE: LazyLock<Fixture<Scheme>> = LazyLock::new(|| {
    rehydrate_keys(&Topology {
        n: N,
        faults: FAULTS,
        epoch: 0,
        namespace: NAMESPACE.to_vec(),
        timing: Timing::default(),
    })
});

#[derive(Clone, Copy, Debug)]
pub struct SmallHonestTraceConfig {
    pub max_views: u64,
    pub max_containers: u64,
    pub epoch: u64,
}

impl Default for SmallHonestTraceConfig {
    fn default() -> Self {
        Self {
            max_views: 4,
            max_containers: 4,
            epoch: 0,
        }
    }
}

fn participant(idx: u32) -> Participant {
    Participant::new(idx)
}

fn all_participants() -> Vec<Participant> {
    (0..N).map(participant).collect()
}

fn leader_for_view(epoch: u64, view: u64) -> u32 {
    ((epoch + view) % (N as u64)) as u32
}

fn payload_for_view(view: u64) -> Sha256Digest {
    PAYLOADS[((view - 1) as usize) % PAYLOADS.len()]
}

fn round_for(epoch: u64, view: u64) -> Round {
    Round::new(Epoch::new(epoch), View::new(view))
}

fn make_proposal(epoch: u64, view: u64, parent: u64, payload: Sha256Digest) -> Proposal<Sha256Digest> {
    Proposal::new(round_for(epoch, view), View::new(parent), payload)
}

fn sign_notarize(signer: u32, proposal: &Proposal<Sha256Digest>) -> Notarize<Scheme, Sha256Digest> {
    Notarize::sign(&FIXTURE.schemes[signer as usize], proposal.clone())
        .expect("notarize sign must succeed")
}

fn sign_finalize(signer: u32, proposal: &Proposal<Sha256Digest>) -> Finalize<Scheme, Sha256Digest> {
    Finalize::sign(&FIXTURE.schemes[signer as usize], proposal.clone())
        .expect("finalize sign must succeed")
}

fn sign_nullify(signer: u32, round: Round) -> Nullify<Scheme> {
    Nullify::sign::<Sha256Digest>(&FIXTURE.schemes[signer as usize], round)
        .expect("nullify sign must succeed")
}

fn notarization_cert(
    signers: &[u32],
    proposal: &Proposal<Sha256Digest>,
) -> Notarization<Scheme, Sha256Digest> {
    let votes: Vec<Notarize<Scheme, Sha256Digest>> =
        signers.iter().map(|s| sign_notarize(*s, proposal)).collect();
    Notarization::from_notarizes(&FIXTURE.verifier, votes.iter(), &Sequential)
        .expect("notarization aggregation must succeed")
}

fn finalization_cert(
    signers: &[u32],
    proposal: &Proposal<Sha256Digest>,
) -> Finalization<Scheme, Sha256Digest> {
    let votes: Vec<Finalize<Scheme, Sha256Digest>> =
        signers.iter().map(|s| sign_finalize(*s, proposal)).collect();
    Finalization::from_finalizes(&FIXTURE.verifier, votes.iter(), &Sequential)
        .expect("finalization aggregation must succeed")
}

fn nullification_cert(signers: &[u32], round: Round) -> Nullification<Scheme> {
    let votes: Vec<Nullify<Scheme>> = signers.iter().map(|s| sign_nullify(*s, round)).collect();
    Nullification::from_nullifies(&FIXTURE.verifier, votes.iter(), &Sequential)
        .expect("nullification aggregation must succeed")
}

fn cert_sender(signers: &[u32]) -> u32 {
    *signers.iter().min().expect("at least one signer")
}

fn broadcast_vote(events: &mut Vec<Event>, sender: u32, vote: Vote<Scheme, Sha256Digest>) {
    for p in 0..N {
        if p == sender {
            continue;
        }
        events.push(Event::Deliver {
            to: participant(p),
            from: participant(sender),
            msg: Wire::Vote(vote.clone()),
        });
    }
}

fn broadcast_cert(events: &mut Vec<Event>, sender: u32, cert: Certificate<Scheme, Sha256Digest>) {
    for p in 0..N {
        if p == sender {
            continue;
        }
        events.push(Event::Deliver {
            to: participant(p),
            from: participant(sender),
            msg: Wire::Cert(cert.clone()),
        });
    }
}

/// Accumulator used while walking the view tree. The snapshot is
/// materialized analytically as events are emitted so the resulting
/// [`Trace::expected`] is exactly what a faithful replay would produce.
#[derive(Clone, Debug)]
struct SearchState {
    next_view: u64,
    latest_parent: u64,
    finalized_containers: u64,
    max_seen_view: u64,
    events: Vec<Event>,
    /// Per-node observable state accumulator. Keyed by participant idx.
    snapshot: BTreeMap<Participant, NodeSnapshot>,
}

impl SearchState {
    fn init() -> Self {
        let mut snapshot = BTreeMap::new();
        for p in all_participants() {
            snapshot.insert(p, NodeSnapshot::default());
        }
        Self {
            next_view: 1,
            latest_parent: 0,
            finalized_containers: 0,
            max_seen_view: 0,
            events: Vec::new(),
            snapshot,
        }
    }
}

#[derive(Clone, Debug)]
struct ViewExtension {
    events: Vec<Event>,
    snapshot_delta: SnapshotDelta,
    next_parent: u64,
    finalized_delta: u64,
    advances_view: bool,
}

/// Per-view contribution to each node's [`NodeSnapshot`]. Applied to the
/// running `SearchState::snapshot` after the corresponding events are
/// committed.
#[derive(Clone, Debug, Default)]
struct SnapshotDelta {
    view: u64,
    // Notarize signers this view (populated for propose; empty for nullify).
    notarize_signers: BTreeSet<Participant>,
    // Finalize signers this view.
    finalize_signers: BTreeSet<Participant>,
    // Nullify signers this view (populated for nullify; empty for propose).
    nullify_signers: BTreeSet<Participant>,
    // Notarization payload + signer count (Some iff reached Q notarizers).
    notarization: Option<(Sha256Digest, u32)>,
    // Finalization payload + signer count (Some iff reached Q notarizers).
    finalization: Option<(Sha256Digest, u32)>,
    // Nullification signer count (Some iff this is a nullify extension).
    nullification: Option<u32>,
    // True iff this view produced a finalization (updates last_finalized
    // for every correct node).
    finalized: bool,
    // True iff any certificate landed for this view.
    certified: bool,
}

fn apply_delta(snapshot: &mut BTreeMap<Participant, NodeSnapshot>, delta: &SnapshotDelta) {
    let view = View::new(delta.view);
    for (_p, node) in snapshot.iter_mut() {
        if !delta.notarize_signers.is_empty() {
            node.notarize_signers
                .insert(view, delta.notarize_signers.clone());
        }
        if !delta.finalize_signers.is_empty() {
            node.finalize_signers
                .insert(view, delta.finalize_signers.clone());
        }
        if !delta.nullify_signers.is_empty() {
            node.nullify_signers
                .insert(view, delta.nullify_signers.clone());
        }
        if let Some((payload, count)) = delta.notarization {
            node.notarizations.insert(
                view,
                CertStateSnapshot {
                    payload,
                    signature_count: Some(count),
                },
            );
        }
        if let Some((payload, count)) = delta.finalization {
            node.finalizations.insert(
                view,
                CertStateSnapshot {
                    payload,
                    signature_count: Some(count),
                },
            );
        }
        if let Some(count) = delta.nullification {
            node.nullifications.insert(
                view,
                NullStateSnapshot {
                    signature_count: Some(count),
                },
            );
        }
        if delta.certified {
            node.certified.insert(view);
        }
        if delta.finalized {
            node.last_finalized = view;
        }
    }
}

fn leader_nullify_extension(epoch: u64, view: u64, parent: u64) -> ViewExtension {
    let mut events = Vec::new();
    let signers: Vec<u32> = (0..N).collect();
    let round = round_for(epoch, view);

    // Every signer constructs + broadcasts their nullify.
    for signer in &signers {
        let nullify = sign_nullify(*signer, round);
        let vote = Vote::Nullify(nullify);
        events.push(Event::Construct {
            node: participant(*signer),
            vote: vote.clone(),
        });
        broadcast_vote(&mut events, *signer, vote);
    }

    // Certificate broadcast from the lowest-index signer.
    let sender = cert_sender(&signers);
    let cert = Certificate::Nullification(nullification_cert(&signers, round));
    broadcast_cert(&mut events, sender, cert);

    let mut delta = SnapshotDelta {
        view,
        ..SnapshotDelta::default()
    };
    for s in &signers {
        delta.nullify_signers.insert(participant(*s));
    }
    // The replay engine locally constructs its cert at quorum, so the
    // observed signer count reflects Q rather than the full broadcast set.
    delta.nullification = Some(Q as u32);
    delta.certified = true;

    ViewExtension {
        events,
        snapshot_delta: delta,
        next_parent: parent,
        finalized_delta: 0,
        advances_view: true,
    }
}

fn propose_extension(
    epoch: u64,
    view: u64,
    parent: u64,
    follower_notarizers_mask: u8,
) -> ViewExtension {
    let leader = leader_for_view(epoch, view);
    let payload = payload_for_view(view);
    let proposal = make_proposal(epoch, view, parent, payload);

    let followers: Vec<u32> = (0..N).filter(|i| *i != leader).collect();
    let mut notarizers: Vec<u32> = vec![leader];

    let mut events = Vec::new();

    // Propose fires the leader's proposal hook; every replayer
    // automaton registers the digest from this.
    events.push(Event::Propose {
        leader: participant(leader),
        proposal: proposal.clone(),
    });

    // Leader's Notarize (construct + broadcast).
    let leader_notarize = sign_notarize(leader, &proposal);
    let leader_vote = Vote::Notarize(leader_notarize);
    events.push(Event::Construct {
        node: participant(leader),
        vote: leader_vote.clone(),
    });
    broadcast_vote(&mut events, leader, leader_vote);

    // Followers selected by the mask notarize next.
    for (idx, follower) in followers.iter().enumerate() {
        if follower_notarizers_mask & (1u8 << idx) == 0 {
            continue;
        }
        notarizers.push(*follower);
        let vote = Vote::Notarize(sign_notarize(*follower, &proposal));
        events.push(Event::Construct {
            node: participant(*follower),
            vote: vote.clone(),
        });
        broadcast_vote(&mut events, *follower, vote);
    }

    let mut delta = SnapshotDelta {
        view,
        ..SnapshotDelta::default()
    };
    for s in &notarizers {
        delta.notarize_signers.insert(participant(*s));
    }

    if notarizers.len() >= Q {
        // Notarization cert broadcast.
        let not_sender = cert_sender(&notarizers);
        let notar = notarization_cert(&notarizers, &proposal);
        broadcast_cert(
            &mut events,
            not_sender,
            Certificate::Notarization(notar.clone()),
        );

        // Finalize votes from every notarizer (construct + broadcast).
        for signer in &notarizers {
            let vote = Vote::Finalize(sign_finalize(*signer, &proposal));
            events.push(Event::Construct {
                node: participant(*signer),
                vote: vote.clone(),
            });
            broadcast_vote(&mut events, *signer, vote);
        }

        // Finalization cert broadcast.
        let fin_sender = cert_sender(&notarizers);
        let fin = finalization_cert(&notarizers, &proposal);
        broadcast_cert(
            &mut events,
            fin_sender,
            Certificate::Finalization(fin.clone()),
        );

        for s in &notarizers {
            delta.finalize_signers.insert(participant(*s));
        }
        // The replay engine locally constructs both certs at quorum, so
        // the observed signer count reflects Q regardless of how many
        // notarizers we include in the event stream.
        delta.notarization = Some((payload, Q as u32));
        delta.finalization = Some((payload, Q as u32));
        delta.certified = true;
        delta.finalized = true;

        return ViewExtension {
            events,
            snapshot_delta: delta,
            next_parent: view,
            finalized_delta: 1,
            advances_view: true,
        };
    }

    // Sub-quorum: no certificates emitted, view does not advance.
    ViewExtension {
        events,
        snapshot_delta: delta,
        next_parent: parent,
        finalized_delta: 0,
        advances_view: false,
    }
}

fn view_extensions(cfg: &SmallHonestTraceConfig, state: &SearchState) -> Vec<ViewExtension> {
    let mut out = Vec::new();
    let view = state.next_view;
    let parent = state.latest_parent;

    out.push(leader_nullify_extension(cfg.epoch, view, parent));
    for follower_mask in 0u8..(1u8 << (N as usize - 1)) {
        out.push(propose_extension(cfg.epoch, view, parent, follower_mask));
    }
    out
}

fn build_trace(state: &SearchState, cfg: &SmallHonestTraceConfig) -> Trace {
    let _ = cfg.max_containers; // used only for search cutoff
    Trace {
        topology: Topology {
            n: N,
            faults: FAULTS,
            epoch: cfg.epoch,
            namespace: NAMESPACE.to_vec(),
            timing: Timing::default(),
        },
        events: state.events.clone(),
        expected: Snapshot {
            nodes: state.snapshot.clone(),
        },
    }
}

fn canonical_key(trace: &Trace) -> String {
    trace.to_json().expect("trace serialization must succeed")
}

fn explore(cfg: &SmallHonestTraceConfig, state: SearchState, seen: &mut BTreeMap<String, Trace>) {
    if state.next_view > cfg.max_views || state.finalized_containers >= cfg.max_containers {
        return;
    }

    for extension in view_extensions(cfg, &state) {
        let finalized = state.finalized_containers + extension.finalized_delta;
        if finalized > cfg.max_containers {
            continue;
        }

        let max_seen_view = state.max_seen_view.max(state.next_view);
        let mut events = state.events.clone();
        events.extend(extension.events);
        let mut snapshot = state.snapshot.clone();
        apply_delta(&mut snapshot, &extension.snapshot_delta);

        let next = SearchState {
            next_view: state.next_view + 1,
            latest_parent: extension.next_parent,
            finalized_containers: finalized,
            max_seen_view,
            events,
            snapshot,
        };

        let trace = build_trace(&next, cfg);
        seen.entry(canonical_key(&trace)).or_insert(trace);

        if extension.advances_view
            && next.next_view <= cfg.max_views
            && next.finalized_containers < cfg.max_containers
        {
            explore(cfg, next, seen);
        }
    }
}

pub fn generate_small_honest_traces(cfg: SmallHonestTraceConfig) -> Vec<Trace> {
    let mut seen = BTreeMap::new();
    explore(&cfg, SearchState::init(), &mut seen);
    seen.into_values().collect()
}

/// Writes generated traces as canonical [`Trace`] JSON (pretty-printed
/// via [`Trace::to_json`]) to `output_dir`. Filenames are `sha1(json)`
/// prefixed with `canonical_` for parity with `generate_canonical_seeds`.
pub fn write_small_honest_traces(
    traces: &[Trace],
    output_dir: &Path,
) -> Result<usize, std::io::Error> {
    fs::create_dir_all(output_dir)?;
    let mut written = 0usize;
    for trace in traces {
        let json = trace.to_json().expect("trace serialization must succeed");
        let digest = Sha1::digest(json.as_bytes());
        let name = format!("canonical_{:x}.json", digest);
        fs::write(output_dir.join(name), json)?;
        written += 1;
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::{generate_small_honest_traces, SmallHonestTraceConfig, N};
    use commonware_consensus::simplex::{
        replay::{replay, Event, Wire},
        types::{Certificate, Vote},
    };
    use std::collections::BTreeSet;

    #[test]
    fn generate_bounded_honest_traces() {
        let cfg = SmallHonestTraceConfig::default();
        let traces = generate_small_honest_traces(cfg);

        assert!(
            !traces.is_empty(),
            "generator must produce at least one trace"
        );

        let mut serialized = BTreeSet::new();
        for trace in &traces {
            assert_eq!(trace.topology.n, N);
            assert_eq!(trace.topology.faults, 0);
            assert_eq!(trace.topology.epoch, 0);

            // Basic structural invariants on the event stream.
            assert!(!trace.events.is_empty());
            for event in &trace.events {
                match event {
                    Event::Deliver { to, from, msg } => {
                        assert_ne!(to, from);
                        match msg {
                            Wire::Vote(v) => match v {
                                Vote::Notarize(n) => {
                                    let view = n.proposal.round.view().get();
                                    assert!(view >= 1 && view <= cfg.max_views);
                                    assert!(n.proposal.parent.get() <= view);
                                }
                                Vote::Finalize(f) => {
                                    let view = f.proposal.round.view().get();
                                    assert!(view >= 1 && view <= cfg.max_views);
                                    assert!(f.proposal.parent.get() <= view);
                                }
                                Vote::Nullify(n) => {
                                    let view = n.round.view().get();
                                    assert!(view >= 1 && view <= cfg.max_views);
                                }
                            },
                            Wire::Cert(c) => match c {
                                Certificate::Notarization(n) => {
                                    let view = n.proposal.round.view().get();
                                    assert!(view >= 1 && view <= cfg.max_views);
                                    assert!(n.proposal.parent.get() <= view);
                                }
                                Certificate::Finalization(f) => {
                                    let view = f.proposal.round.view().get();
                                    assert!(view >= 1 && view <= cfg.max_views);
                                    assert!(f.proposal.parent.get() <= view);
                                }
                                Certificate::Nullification(n) => {
                                    let view = n.round.view().get();
                                    assert!(view >= 1 && view <= cfg.max_views);
                                }
                            },
                        }
                    }
                    Event::Propose { proposal, .. } => {
                        let view = proposal.round.view().get();
                        assert!(view >= 1 && view <= cfg.max_views);
                    }
                    Event::Construct { vote, .. } => match vote {
                        Vote::Notarize(n) => {
                            let view = n.proposal.round.view().get();
                            assert!(view >= 1 && view <= cfg.max_views);
                        }
                        Vote::Finalize(f) => {
                            let view = f.proposal.round.view().get();
                            assert!(view >= 1 && view <= cfg.max_views);
                        }
                        Vote::Nullify(n) => {
                            let view = n.round.view().get();
                            assert!(view >= 1 && view <= cfg.max_views);
                        }
                    },
                    Event::Timeout { .. } => {}
                }
            }

            // JSON must round-trip cleanly.
            let json = trace.to_json().expect("serialize generated trace");
            assert!(serialized.insert(json), "generated traces must be unique");

            // TLC-encoder path must produce a non-empty action list.
            let actions = crate::tracing::tlc_encoder::encode_from_trace(trace);
            assert!(!actions.is_empty(), "encoded action list must be non-empty");
        }
    }

    #[test]
    fn parent_survives_nullified_view_after_finalization() {
        let cfg = SmallHonestTraceConfig {
            max_views: 3,
            max_containers: 2,
            epoch: 0,
        };
        let traces = generate_small_honest_traces(cfg);
        let mut found = false;

        for trace in &traces {
            let finalized_v1 = trace.events.iter().any(|e| match e {
                Event::Deliver {
                    msg: Wire::Cert(Certificate::Finalization(f)),
                    ..
                } => f.proposal.round.view().get() == 1 && f.proposal.parent.get() == 0,
                _ => false,
            });
            let nullified_v2 = trace.events.iter().any(|e| match e {
                Event::Deliver {
                    msg: Wire::Cert(Certificate::Nullification(n)),
                    ..
                } => n.round.view().get() == 2,
                _ => false,
            });
            if !(finalized_v1 && nullified_v2) {
                continue;
            }

            let has_view3_activity = trace.events.iter().any(|e| match e {
                Event::Deliver { msg, .. } => match msg {
                    Wire::Vote(Vote::Notarize(n)) => n.proposal.round.view().get() == 3,
                    Wire::Vote(Vote::Finalize(f)) => f.proposal.round.view().get() == 3,
                    Wire::Cert(Certificate::Notarization(n)) => {
                        n.proposal.round.view().get() == 3
                    }
                    Wire::Cert(Certificate::Finalization(f)) => {
                        f.proposal.round.view().get() == 3
                    }
                    _ => false,
                },
                Event::Construct { vote, .. } => match vote {
                    Vote::Notarize(n) => n.proposal.round.view().get() == 3,
                    Vote::Finalize(f) => f.proposal.round.view().get() == 3,
                    _ => false,
                },
                _ => false,
            });
            if !has_view3_activity {
                continue;
            }
            found = true;

            for event in &trace.events {
                match event {
                    Event::Deliver { msg, .. } => match msg {
                        Wire::Vote(Vote::Notarize(n)) if n.proposal.round.view().get() == 3 => {
                            assert_eq!(n.proposal.parent.get(), 1);
                        }
                        Wire::Vote(Vote::Finalize(f)) if f.proposal.round.view().get() == 3 => {
                            assert_eq!(f.proposal.parent.get(), 1);
                        }
                        Wire::Cert(Certificate::Notarization(n))
                            if n.proposal.round.view().get() == 3 =>
                        {
                            assert_eq!(n.proposal.parent.get(), 1);
                        }
                        Wire::Cert(Certificate::Finalization(f))
                            if f.proposal.round.view().get() == 3 =>
                        {
                            assert_eq!(f.proposal.parent.get(), 1);
                        }
                        _ => {}
                    },
                    Event::Construct { vote, .. } => match vote {
                        Vote::Notarize(n) if n.proposal.round.view().get() == 3 => {
                            assert_eq!(n.proposal.parent.get(), 1);
                        }
                        Vote::Finalize(f) if f.proposal.round.view().get() == 3 => {
                            assert_eq!(f.proposal.parent.get(), 1);
                        }
                        _ => {}
                    },
                    Event::Propose { proposal, .. } if proposal.round.view().get() == 3 => {
                        assert_eq!(proposal.parent.get(), 1);
                    }
                    _ => {}
                }
            }
        }

        assert!(found);
    }

    fn extract_payload_hexes(trace: &commonware_consensus::simplex::replay::Trace) -> Vec<String> {
        let mut out = Vec::new();
        for event in &trace.events {
            let payload = match event {
                Event::Propose { proposal, .. } => Some(proposal.payload),
                Event::Construct { vote, .. } => match vote {
                    Vote::Notarize(n) => Some(n.proposal.payload),
                    Vote::Finalize(f) => Some(f.proposal.payload),
                    Vote::Nullify(_) => None,
                },
                Event::Deliver { msg, .. } => match msg {
                    Wire::Vote(Vote::Notarize(n)) => Some(n.proposal.payload),
                    Wire::Vote(Vote::Finalize(f)) => Some(f.proposal.payload),
                    Wire::Cert(Certificate::Notarization(n)) => Some(n.proposal.payload),
                    Wire::Cert(Certificate::Finalization(f)) => Some(f.proposal.payload),
                    _ => None,
                },
                Event::Timeout { .. } => None,
            };
            if let Some(d) = payload {
                let bytes: &[u8] = d.as_ref();
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                out.push(hex);
            }
        }
        out
    }

    #[test]
    fn static_trace_payloads_are_hex() {
        let cfg = SmallHonestTraceConfig::default();
        let traces = generate_small_honest_traces(cfg);
        assert!(!traces.is_empty());

        for (i, trace) in traces.iter().enumerate() {
            for block in extract_payload_hexes(trace) {
                assert_eq!(
                    block.len(),
                    64,
                    "trace {i}: block ID must be 64 hex chars, got {} chars: {block:?}",
                    block.len()
                );
                assert!(
                    block.bytes().all(|b| b.is_ascii_hexdigit()),
                    "trace {i}: block ID contains non-hex chars: {block:?}"
                );
            }
        }
    }

    #[test]
    fn static_trace_replay_matches_expected() {
        let cfg = SmallHonestTraceConfig {
            max_views: 2,
            max_containers: 2,
            epoch: 0,
        };
        let traces = generate_small_honest_traces(cfg);

        // Pick one trace with at least one finalization to exercise
        // strict equality between the analytic expected snapshot and the
        // live replayer's observed snapshot.
        let trace = traces
            .iter()
            .find(|t| {
                t.events.iter().any(|e| {
                    matches!(
                        e,
                        Event::Deliver {
                            msg: Wire::Cert(Certificate::Finalization(_)),
                            ..
                        }
                    )
                })
            })
            .expect("need at least one trace with a finalization");

        let actual = replay(trace);
        assert_eq!(
            actual, trace.expected,
            "static trace replay snapshot diverged from analytically-derived expected"
        );
    }
}
