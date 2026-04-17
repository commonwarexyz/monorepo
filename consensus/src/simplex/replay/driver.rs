//! Replay a [`Trace`] against a live N-engine simplex cluster.
//!
//! The top-level entry point is [`replay`]: given a typed [`Trace`], spin
//! up N engines in a deterministic runtime, walk every [`Event`], and
//! extract a typed [`Snapshot`] of the resulting reporter state.
//!
//! Ordering guarantees come from [`commonware_runtime::Context::quiesce`]
//! after every step — wall-clock time never advances while events are
//! being dispatched, so timers that belong to the trace only fire when
//! the driver emits an explicit [`Event::Timeout`].

use super::{
    automaton::ReplayAutomaton,
    injected::{channel as inj_channel, NullBlocker, NullSender, PendingReceiver},
    trace::{
        rehydrate_keys, CertStateSnapshot, Event, NodeSnapshot, NullStateSnapshot, Snapshot, Trace,
        Wire,
    },
};
use crate::{
    simplex::{
        config::{Config, ForwardingPolicy},
        elector::RoundRobin,
        mocks::reporter,
        scheme::ed25519::Scheme,
        types::Vote,
        voter, Engine,
    },
    types::{Delta, Epoch as EpochType, View},
    Viewable,
};
use commonware_codec::{Encode, Read};
use commonware_cryptography::{
    certificate,
    ed25519::PublicKey,
    sha256::{Digest as Sha256Digest, Sha256 as Sha256Hasher},
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Metrics, Runner};
use commonware_utils::{NZUsize, NZU16, Participant};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    num::NonZeroU16,
    time::Duration,
};

const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: std::num::NonZeroUsize = NZUsize!(10);

/// Top-level entry point. Runs `trace` to completion and returns the
/// observed [`Snapshot`].
pub fn replay(trace: &Trace) -> Snapshot {
    // We clone into the async closure; Trace is cheap to clone (Vec of
    // events, and all the inner payloads are already-decoded owned values).
    let trace = trace.clone();
    let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
    let captured_clone = captured.clone();

    let runner = deterministic::Runner::timed(Duration::from_secs(120));
    runner.start(|ctx| async move {
        let snapshot = replay_async(ctx, trace).await;
        *captured_clone.lock().unwrap() = Some(snapshot);
    });

    let mut guard = captured.lock().unwrap();
    guard.take().expect("snapshot captured")
}

async fn replay_async(context: deterministic::Context, trace: Trace) -> Snapshot {
    let topology = trace.topology.clone();
    let faults = topology.faults as usize;
    let n = topology.n as usize;

    // Rehydrate keys (fixture seed is deterministic; matches the
    // trace's recorded namespace).
    let fixture = rehydrate_keys(&topology);
    let participants = fixture.participants.clone();
    let schemes = fixture.schemes.clone();

    // One automaton per correct node (replay-specific — each engine
    // holds its own clone; `release` fans out externally).
    let mut automatons = Vec::with_capacity(n - faults);
    let mut vote_injectors = Vec::with_capacity(n - faults);
    let mut cert_injectors = Vec::with_capacity(n - faults);
    let mut voter_mailboxes: Vec<voter::Mailbox<Scheme, Sha256Digest>> =
        Vec::with_capacity(n - faults);
    let mut reporters = Vec::with_capacity(n - faults);

    let elector = RoundRobin::<Sha256Hasher>::default();

    for i in faults..n {
        let ctx = context.with_label(&format!("validator_n{i}"));

        let (vote_inj, vote_rx) = inj_channel();
        vote_injectors.push(vote_inj);
        let (cert_inj, cert_rx) = inj_channel();
        cert_injectors.push(cert_inj);
        let resolver_rx = PendingReceiver;

        let reporter_cfg = reporter::Config {
            participants: participants
                .as_slice()
                .try_into()
                .expect("public keys are unique"),
            scheme: schemes[i].clone(),
            elector: elector.clone(),
        };
        let reporter = reporter::Reporter::new(ctx.with_label("reporter"), reporter_cfg);
        reporters.push(reporter.clone());

        let automaton = ReplayAutomaton::new();
        automatons.push(automaton.clone());

        let engine_cfg = Config {
            blocker: NullBlocker,
            scheme: schemes[i].clone(),
            elector: elector.clone(),
            automaton: automaton.clone(),
            relay: automaton,
            reporter: reporter.clone(),
            partition: format!("replayer_n{i}"),
            mailbox_size: 1024,
            epoch: EpochType::new(topology.epoch),
            leader_timeout: Duration::from_millis(topology.timing.leader_timeout_ms),
            certification_timeout: Duration::from_millis(topology.timing.certification_timeout_ms),
            timeout_retry: Duration::from_millis(topology.timing.timeout_retry_ms),
            fetch_timeout: Duration::from_millis(topology.timing.fetch_timeout_ms),
            activity_timeout: Delta::new(topology.timing.activity_timeout),
            skip_timeout: Delta::new(topology.timing.skip_timeout),
            fetch_concurrent: 1,
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
            forwarding: ForwardingPolicy::Disabled,
        };
        let engine = Engine::new(ctx.with_label("engine"), engine_cfg);
        voter_mailboxes.push(engine.voter_mailbox());
        engine.start(
            (NullSender, vote_rx),
            (NullSender, cert_rx),
            (NullSender, resolver_rx),
        );
    }

    // Lookup: participant index → offset into the correct-node vectors.
    // Byzantine indices (< faults) have no offset and are skipped.
    let correct_offset = |p: Participant| -> Option<usize> {
        let idx = p.get() as usize;
        (idx >= faults && idx < n).then(|| idx - faults)
    };

    // Walk events.
    for event in &trace.events {
        match event {
            Event::Deliver { to, from, msg } => {
                let Some(to_off) = correct_offset(*to) else {
                    continue;
                };
                let from_pk = participants[from.get() as usize].clone();
                match msg {
                    Wire::Vote(v) => {
                        register_payload_digest_from_vote(&automatons, v);
                        let buf = v.encode().into();
                        vote_injectors[to_off].inject(from_pk, buf);
                    }
                    Wire::Cert(c) => {
                        let buf = c.encode().into();
                        cert_injectors[to_off].inject(from_pk, buf);
                    }
                }
            }
            Event::Propose { leader, proposal } => {
                let digest = proposal.payload;
                let view = proposal.view();
                let parent = proposal.parent;
                // Register the digest on every automaton so any follower
                // that calls verify() against it succeeds.
                for auto in &automatons {
                    auto.register(digest);
                }
                // Release only on the leader's automaton — that's the
                // one node whose engine is (or will be) parked on
                // `propose()`. Releasing on every automaton would
                // satisfy wrong-leader traces silently, masking traces
                // that assign a proposal to the wrong leader. If the
                // leader is Byzantine (index < faults) no engine exists
                // and we skip — the trace's downstream Deliver events
                // drive the honest followers.
                if let Some(off) = correct_offset(*leader) {
                    automatons[off].release(view, parent, digest);
                }
            }
            Event::Construct { node, vote } => {
                let Some(off) = correct_offset(*node) else {
                    continue;
                };
                register_payload_digest_from_vote(&automatons, vote);
                voter_mailboxes[off].replayed(vote.clone()).await;
            }
            Event::Timeout { node, view, reason } => {
                let Some(off) = correct_offset(*node) else {
                    continue;
                };
                voter_mailboxes[off].timeout(*view, *reason).await;
            }
        }
        drain(&context).await;
    }

    // Final drain to settle any trailing certificate constructions.
    drain(&context).await;

    // Extract typed snapshot.
    extract_snapshot(&reporters, &participants, faults, n)
}

/// Runs the deterministic runtime's quiesce to drain all pending work.
async fn drain(context: &deterministic::Context) {
    context.quiesce().await;
}

#[cfg(test)]
mod tests {
    use super::super::trace::{Snapshot, Timing, Topology, Trace};
    use super::replay;

    fn topology(n: u32, faults: u32) -> Topology {
        Topology {
            n,
            faults,
            epoch: 333,
            namespace: b"consensus_fuzz".to_vec(),
            timing: Timing::default(),
        }
    }

    #[test]
    fn replay_empty_trace_n4_f0() {
        // No events: start 4 engines, quiesce, extract snapshot.
        // Every node should be present in the snapshot with empty state.
        let trace = Trace {
            topology: topology(4, 0),
            events: Vec::new(),
            expected: Snapshot::default(),
        };
        let snapshot = replay(&trace);
        assert_eq!(snapshot.nodes.len(), 4, "all 4 correct nodes present");
        for (p, node) in &snapshot.nodes {
            assert!(
                node.notarizations.is_empty() && node.finalizations.is_empty(),
                "node {p} should have empty state, got {node:?}"
            );
        }
    }

    #[test]
    fn replay_empty_trace_n4_f1() {
        // 1 Byzantine + 3 correct. Snapshot should have 3 nodes keyed
        // by Participant(1..=3).
        let trace = Trace {
            topology: topology(4, 1),
            events: Vec::new(),
            expected: Snapshot::default(),
        };
        let snapshot = replay(&trace);
        assert_eq!(snapshot.nodes.len(), 3);
        let keys: Vec<u32> = snapshot.nodes.keys().map(|p| p.get()).collect();
        assert_eq!(keys, vec![1, 2, 3]);
    }
}

fn register_payload_digest_from_vote(
    automatons: &[ReplayAutomaton],
    vote: &Vote<Scheme, Sha256Digest>,
) {
    let digest = match vote {
        Vote::Notarize(n) => Some(n.proposal.payload),
        Vote::Finalize(f) => Some(f.proposal.payload),
        Vote::Nullify(_) => None,
    };
    if let Some(d) = digest {
        for auto in automatons {
            auto.register(d);
        }
    }
}

fn extract_snapshot(
    reporters: &[reporter::Reporter<
        deterministic::Context,
        Scheme,
        RoundRobin<Sha256Hasher>,
        Sha256Digest,
    >],
    _participants: &[PublicKey],
    faults: usize,
    _n: usize,
) -> Snapshot {
    let mut nodes = BTreeMap::new();
    for (offset, reporter) in reporters.iter().enumerate() {
        let participant = Participant::new((offset + faults) as u32);

        let notarizations: BTreeMap<View, CertStateSnapshot> = reporter
            .notarizations
            .lock()
            .iter()
            .map(|(view, cert)| {
                (
                    *view,
                    CertStateSnapshot {
                        payload: cert.proposal.payload,
                        signature_count: signature_count(&cert.certificate, reporter.participants.len()),
                    },
                )
            })
            .collect();

        let nullifications: BTreeMap<View, NullStateSnapshot> = reporter
            .nullifications
            .lock()
            .iter()
            .map(|(view, cert)| {
                (
                    *view,
                    NullStateSnapshot {
                        signature_count: signature_count(&cert.certificate, reporter.participants.len()),
                    },
                )
            })
            .collect();

        let finalizations: BTreeMap<View, CertStateSnapshot> = reporter
            .finalizations
            .lock()
            .iter()
            .map(|(view, cert)| {
                (
                    *view,
                    CertStateSnapshot {
                        payload: cert.proposal.payload,
                        signature_count: signature_count(&cert.certificate, reporter.participants.len()),
                    },
                )
            })
            .collect();

        let certified: BTreeSet<View> = reporter.certified.lock().iter().copied().collect();

        let notarize_signers = extract_participation_signers(
            &*reporter.notarizes.lock(),
            &reporter.participants,
        );
        let finalize_signers =
            extract_participation_signers(&*reporter.finalizes.lock(), &reporter.participants);
        let nullify_signers = reporter
            .nullifies
            .lock()
            .iter()
            .map(|(view, pks)| {
                let set: BTreeSet<Participant> = pks
                    .iter()
                    .map(|pk| Participant::new(pk_to_index(pk, &reporter.participants) as u32))
                    .collect();
                (*view, set)
            })
            .collect();

        let last_finalized = finalizations.keys().copied().max().unwrap_or(View::new(0));

        nodes.insert(
            participant,
            NodeSnapshot {
                notarizations,
                nullifications,
                finalizations,
                certified,
                notarize_signers,
                nullify_signers,
                finalize_signers,
                last_finalized,
            },
        );
    }
    Snapshot { nodes }
}

type Participation = HashMap<View, HashMap<Sha256Digest, std::collections::HashSet<PublicKey>>>;

fn extract_participation_signers(
    map: &Participation,
    participants: &commonware_utils::ordered::Set<PublicKey>,
) -> BTreeMap<View, BTreeSet<Participant>> {
    let mut out = BTreeMap::new();
    for (view, payload_map) in map {
        let mut signers = BTreeSet::new();
        for pks in payload_map.values() {
            for pk in pks {
                signers.insert(Participant::new(pk_to_index(pk, participants) as u32));
            }
        }
        out.insert(*view, signers);
    }
    out
}

fn pk_to_index(pk: &PublicKey, participants: &commonware_utils::ordered::Set<PublicKey>) -> usize {
    participants
        .iter()
        .position(|p| p == pk)
        .expect("public key not in participants")
}

fn signature_count(
    certificate: &<Scheme as certificate::Scheme>::Certificate,
    max_participants: usize,
) -> Option<u32> {
    let encoded = certificate.encode();
    let mut cursor = encoded.as_ref();
    let signers = commonware_cryptography::certificate::Signers::read_cfg(
        &mut cursor,
        &max_participants,
    )
    .expect("certificate signers must decode");
    Some(signers.count() as u32)
}

