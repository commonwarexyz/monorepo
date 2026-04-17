//! Canonical honest-session recorder.
//!
//! Runs a 4-node simplex cluster on the simulated p2p network with the
//! [`Recorder`](super::Recorder) wrappers ([`RecordingReceiver`],
//! [`RecordingSender`], [`RecordingApp`]) on every node, drives it to a
//! target number of finalizations, then returns the captured canonical
//! [`Trace`].
//!
//! This is the native-canonical counterpart of the legacy
//! `fuzz::tracing::runtime::run_honest_pipeline`. Unlike the legacy
//! path, there is no sniffing of network bytes and no post-hoc causal
//! reconstruction: the recorder captures events at the engine's
//! semantic boundaries and the returned [`Trace`] is ready to feed back
//! into [`super::replay`] for strict-equality verification.

use super::{
    recorder::{ChannelKind, RecordingApp, RecordingReceiver, RecordingSender, Recorder},
    trace::{
        CertStateSnapshot, NodeSnapshot, NullStateSnapshot, Snapshot, Timing, Topology, Trace,
    },
};
use crate::{
    simplex::{
        config::{Config, ForwardingPolicy},
        elector::RoundRobin,
        mocks::{application, relay, reporter},
        scheme::ed25519::{self, Scheme},
        Engine,
    },
    types::{Delta, Epoch, View},
};
use crate::Monitor;
use commonware_codec::Read;
use commonware_cryptography::{
    certificate,
    ed25519::PublicKey,
    sha256::{Digest as Sha256Digest, Sha256 as Sha256Hasher},
};
use commonware_p2p::simulated::{Config as SimConfig, Link, Network};
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, Metrics, Quota, Runner, Spawner,
};
use commonware_utils::{channel::mpsc::Receiver, NZUsize, NZU16, Participant};
use futures::future::join_all;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    num::{NonZeroU16, NonZeroU32},
    time::Duration,
};

/// Inputs that govern a recorded honest session.
#[derive(Clone, Debug)]
pub struct RecordConfig {
    /// Total participants. Must be ≥ 1.
    pub n: u32,
    /// Target number of finalizations per correct node before stopping.
    pub required_containers: u64,
    /// Namespace passed to the ed25519 fixture (also stored in the
    /// output [`Topology::namespace`] so replay rehydrates matching keys).
    pub namespace: Vec<u8>,
    /// Consensus epoch.
    pub epoch: u64,
    /// Voter timing knobs (written into the returned [`Topology`]).
    pub timing: Timing,
}

impl Default for RecordConfig {
    fn default() -> Self {
        Self {
            n: 4,
            required_containers: 3,
            namespace: b"consensus_fuzz".to_vec(),
            epoch: 333,
            timing: Timing::default(),
        }
    }
}

const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: std::num::NonZeroUsize = NZUsize!(10);
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

/// Record a canonical honest session. Drives a 4-node cluster (or
/// `cfg.n`-node) inside the deterministic runtime until every node
/// has finalized `cfg.required_containers` views, then returns the
/// captured [`Trace`].
pub fn record_honest(cfg: RecordConfig) -> Trace {
    let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
    let cap_clone = captured.clone();

    // Same RNG seed the replayer uses — keeps key material identical
    // across record and replay (see `trace::rehydrate_keys`).
    let runner = deterministic::Runner::timed(Duration::from_secs(300));
    runner.start(|ctx| async move {
        let trace = record_honest_async(ctx, cfg).await;
        *cap_clone.lock().unwrap() = Some(trace);
    });

    let mut guard = captured.lock().unwrap();
    guard.take().expect("recorded trace captured")
}

async fn record_honest_async(context: deterministic::Context, cfg: RecordConfig) -> Trace {
    let n_usize = cfg.n as usize;
    // Recorder requires PublicKeys in canonical sorted order so it can
    // map sender pks to Participant indices; use the same fixture the
    // replayer uses (namespace-keyed, seeded RNG internal to the
    // runner). We start a short nested runner to extract the fixture
    // deterministically — this matches `trace::rehydrate_keys` exactly.
    let fixture = {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
        let cc = captured.clone();
        let ns = cfg.namespace.clone();
        let n = cfg.n;
        let runner = deterministic::Runner::seeded(0);
        runner.start(|mut ctx2| async move {
            let f = ed25519::fixture(&mut ctx2, &ns, n);
            *cc.lock().unwrap() = Some(f);
        });
        let mut g = captured.lock().unwrap();
        g.take().unwrap()
    };
    let participants = fixture.participants.clone();
    let schemes = fixture.schemes.clone();

    // Simulated p2p network.
    let (network, oracle) = Network::new(
        context.with_label("network"),
        SimConfig {
            max_size: MAX_MESSAGE_SIZE,
            disconnect_on_block: false,
            tracked_peer_sets: None,
        },
    );
    network.start();

    // Register each node on three channels: 0=vote, 1=cert, 2=resolver.
    let quota: Quota = Quota::per_second(NonZeroU32::MAX);
    let mut vote_chans = HashMap::new();
    let mut cert_chans = HashMap::new();
    let mut resolver_chans = HashMap::new();
    for pk in &participants {
        let v = oracle.control(pk.clone()).register(0, quota).await.unwrap();
        let c = oracle.control(pk.clone()).register(1, quota).await.unwrap();
        let r = oracle.control(pk.clone()).register(2, quota).await.unwrap();
        vote_chans.insert(pk.clone(), v);
        cert_chans.insert(pk.clone(), c);
        resolver_chans.insert(pk.clone(), r);
    }

    // Fully-connected zero-latency zero-loss network.
    for a in &participants {
        for b in &participants {
            if a == b {
                continue;
            }
            let _ = oracle
                .add_link(
                    a.clone(),
                    b.clone(),
                    Link {
                        latency: Duration::from_millis(5),
                        jitter: Duration::from_millis(0),
                        success_rate: 1.0,
                    },
                )
                .await;
        }
    }

    let recorder = Recorder::new(participants.clone());
    let app_relay = std::sync::Arc::new(relay::Relay::new());
    let elector = RoundRobin::<Sha256Hasher>::default();
    let mut reporters = Vec::with_capacity(n_usize);

    for i in 0..n_usize {
        let me = Participant::new(i as u32);
        let validator = participants[i].clone();
        let ctx = context.with_label(&format!("validator_{validator}"));

        let (vote_sender, vote_receiver) = vote_chans.remove(&validator).unwrap();
        let (cert_sender, cert_receiver) = cert_chans.remove(&validator).unwrap();
        let (resolver_sender, resolver_receiver) = resolver_chans.remove(&validator).unwrap();

        // Reporter stays unwrapped — it exposes the observable state we
        // freeze into `Snapshot` at the end of the session.
        let reporter_cfg = reporter::Config {
            participants: participants
                .as_slice()
                .try_into()
                .expect("public keys unique"),
            scheme: schemes[i].clone(),
            elector: elector.clone(),
        };
        let reporter = reporter::Reporter::new(ctx.with_label("reporter"), reporter_cfg);
        reporters.push(reporter.clone());

        // Mock application — the honest, "certify-sometimes" one.
        let app_cfg = application::Config {
            hasher: Sha256Hasher::default(),
            relay: app_relay.clone(),
            me: validator.clone(),
            propose_latency: (10.0, 5.0),
            verify_latency: (10.0, 5.0),
            certify_latency: (10.0, 5.0),
            should_certify: application::Certifier::Sometimes,
        };
        let (actor, application) =
            application::Application::new(ctx.with_label("application"), app_cfg);
        actor.start();

        // Wrap application with the recording app (captures Propose).
        let rec_app = RecordingApp::new(application.clone(), recorder.clone(), me);

        // Wrap vote receiver (Deliver / Vote channel).
        let rec_vote_rx = RecordingReceiver::new(
            vote_receiver,
            recorder.clone(),
            me,
            ChannelKind::Vote,
            n_usize,
        );
        // Wrap cert receiver (Deliver / Certificate channel).
        let rec_cert_rx = RecordingReceiver::new(
            cert_receiver,
            recorder.clone(),
            me,
            ChannelKind::Certificate,
            n_usize,
        );
        // Wrap vote sender (Construct).
        let rec_vote_tx = RecordingSender::new(vote_sender, recorder.clone(), me);

        let blocker = oracle.control(validator.clone());
        let engine_cfg = Config {
            blocker,
            scheme: schemes[i].clone(),
            elector: elector.clone(),
            automaton: rec_app.clone(),
            relay: rec_app,
            reporter: reporter.clone(),
            partition: validator.to_string(),
            mailbox_size: 1024,
            epoch: Epoch::new(cfg.epoch),
            leader_timeout: Duration::from_millis(cfg.timing.leader_timeout_ms),
            certification_timeout: Duration::from_millis(cfg.timing.certification_timeout_ms),
            timeout_retry: Duration::from_millis(cfg.timing.timeout_retry_ms),
            fetch_timeout: Duration::from_millis(cfg.timing.fetch_timeout_ms),
            activity_timeout: Delta::new(cfg.timing.activity_timeout),
            skip_timeout: Delta::new(cfg.timing.skip_timeout),
            fetch_concurrent: 1,
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
            forwarding: ForwardingPolicy::Disabled,
        };
        let engine = Engine::new(ctx.with_label("engine"), engine_cfg);
        engine.start(
            (rec_vote_tx, rec_vote_rx),
            (cert_sender, rec_cert_rx),
            (resolver_sender, resolver_receiver),
        );
    }

    // Wait until every reporter has observed `required_containers`
    // finalizations. We subscribe before spawning so no early events
    // are missed.
    let mut finalizers = Vec::new();
    let target = cfg.required_containers;
    for reporter in reporters.iter_mut() {
        let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
        finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
            while latest.get() < target {
                latest = monitor.recv().await.expect("finalization stream closed");
            }
        }));
    }
    join_all(finalizers).await;
    context.quiesce().await;

    // Freeze observed state into a canonical Snapshot.
    let snapshot = build_snapshot(&reporters, &participants);

    let topology = Topology {
        n: cfg.n,
        faults: 0,
        epoch: cfg.epoch,
        namespace: cfg.namespace,
        timing: cfg.timing,
    };
    recorder.freeze(topology, snapshot)
}

fn build_snapshot(
    reporters: &[reporter::Reporter<
        deterministic::Context,
        Scheme,
        RoundRobin<Sha256Hasher>,
        Sha256Digest,
    >],
    _participants: &[PublicKey],
) -> Snapshot {
    let mut nodes = BTreeMap::new();
    for (idx, reporter) in reporters.iter().enumerate() {
        let me = Participant::new(idx as u32);
        let n_participants = reporter.participants.len();

        let notarizations: BTreeMap<View, CertStateSnapshot> = reporter
            .notarizations
            .lock()
            .iter()
            .map(|(v, cert)| {
                (
                    *v,
                    CertStateSnapshot {
                        payload: cert.proposal.payload,
                        signature_count: signer_count(&cert.certificate, n_participants),
                    },
                )
            })
            .collect();

        let nullifications: BTreeMap<View, NullStateSnapshot> = reporter
            .nullifications
            .lock()
            .iter()
            .map(|(v, cert)| {
                (
                    *v,
                    NullStateSnapshot {
                        signature_count: signer_count(&cert.certificate, n_participants),
                    },
                )
            })
            .collect();

        let finalizations: BTreeMap<View, CertStateSnapshot> = reporter
            .finalizations
            .lock()
            .iter()
            .map(|(v, cert)| {
                (
                    *v,
                    CertStateSnapshot {
                        payload: cert.proposal.payload,
                        signature_count: signer_count(&cert.certificate, n_participants),
                    },
                )
            })
            .collect();

        let certified: BTreeSet<View> = reporter.certified.lock().iter().copied().collect();
        let last_finalized = finalizations.keys().copied().max().unwrap_or(View::new(0));

        let notarize_signers = participation_to_signers(
            &*reporter.notarizes.lock(),
            &reporter.participants,
        );
        let finalize_signers = participation_to_signers(
            &*reporter.finalizes.lock(),
            &reporter.participants,
        );
        let nullify_signers = reporter
            .nullifies
            .lock()
            .iter()
            .map(|(v, pks)| {
                let set: BTreeSet<Participant> = pks
                    .iter()
                    .map(|pk| Participant::new(pk_index(pk, &reporter.participants) as u32))
                    .collect();
                (*v, set)
            })
            .collect();

        nodes.insert(
            me,
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

type Participation =
    HashMap<View, HashMap<Sha256Digest, std::collections::HashSet<PublicKey>>>;

fn participation_to_signers(
    map: &Participation,
    participants: &commonware_utils::ordered::Set<PublicKey>,
) -> BTreeMap<View, BTreeSet<Participant>> {
    let mut out = BTreeMap::new();
    for (view, payload_map) in map {
        let mut signers = BTreeSet::new();
        for pks in payload_map.values() {
            for pk in pks {
                signers.insert(Participant::new(pk_index(pk, participants) as u32));
            }
        }
        out.insert(*view, signers);
    }
    out
}

fn pk_index(pk: &PublicKey, participants: &commonware_utils::ordered::Set<PublicKey>) -> usize {
    participants
        .iter()
        .position(|p| p == pk)
        .expect("pk in participants")
}

fn signer_count(
    certificate: &<Scheme as certificate::Scheme>::Certificate,
    max_participants: usize,
) -> Option<u32> {
    use commonware_codec::Encode;
    let encoded = certificate.encode();
    let mut cursor = encoded.as_ref();
    let signers = commonware_cryptography::certificate::Signers::read_cfg(
        &mut cursor,
        &max_participants,
    )
    .expect("Signers decode");
    Some(signers.count() as u32)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex::replay::replay;

    #[test]
    fn record_then_replay_strictly_matches() {
        let cfg = RecordConfig {
            n: 4,
            required_containers: 2,
            namespace: b"consensus_fuzz".to_vec(),
            epoch: 333,
            timing: Timing::default(),
        };
        let trace = record_honest(cfg);
        assert!(!trace.events.is_empty(), "recording produced no events");
        let recorded_expected = trace.expected.clone();
        let actual = replay(&trace);
        assert_eq!(
            actual, recorded_expected,
            "replay of recorded trace did not match the recorded snapshot"
        );
    }

    /// Generates the strict-suite honest fixture. Marked `#[ignore]`
    /// because writing to the source tree from a test is unusual — run
    /// on demand with `cargo test ... -- --ignored write_strict_honest_fixture`.
    #[test]
    #[ignore]
    fn write_strict_honest_fixture() {
        let cfg = RecordConfig {
            n: 4,
            required_containers: 3,
            namespace: b"consensus_fuzz".to_vec(),
            epoch: 333,
            timing: Timing::default(),
        };
        let trace = record_honest(cfg);
        let json = trace.to_json().expect("encode");
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/simplex/replay/fixtures/strict/honest_n4_f0_c3.json");
        std::fs::create_dir_all(path.parent().unwrap()).expect("create dir");
        std::fs::write(&path, json).expect("write");
        eprintln!("wrote strict fixture: {}", path.display());
    }
}
