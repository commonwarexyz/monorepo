use crate::{
    disrupter::Disrupter, invariants, simplex, strategy::SmallScopeForTracing, utils::Partition,
    ByzantineActor, FuzzInput, SimplexEd25519, EPOCH, N4F0C4, N4F1C3, PAGE_CACHE_SIZE, PAGE_SIZE,
};
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_consensus::{
    simplex::{
        config::{self, ForwardingPolicy},
        elector::{Config as ElectorConfig, RoundRobin},
        mocks::{
            application, conflicter, equivocator, nuller, nullify_only, outdated, relay, reporter,
            twins::{self, Elector as TwinsElector, Framework, Mode},
        },
        replay::{
            recorder::{ChannelKind, RecordingApp, RecordingReceiver, RecordingSender, Recorder},
            trace::{
                CertStateSnapshot, NodeSnapshot, NullStateSnapshot, Snapshot, Timing, Topology,
                Trace,
            },
        },
        types::{Certificate, Vote},
        Engine,
    },
    types::{Delta, Epoch, View},
    Monitor, Viewable,
};
use commonware_cryptography::{
    certificate::{Scheme, Signers},
    ed25519::PublicKey,
    sha256::{Digest as Sha256Digest, Sha256 as Sha256Hasher},
};
use commonware_p2p::{
    simulated::{SplitOrigin, SplitTarget},
    Recipients,
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, IoBuf, Metrics, Runner, Spawner};
use commonware_utils::{channel::mpsc::Receiver, FuzzRng, NZUsize, Participant};
use futures::future::join_all;
use sha1::Digest;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

const NAMESPACE: &[u8] = b"consensus_fuzz";

/// Derive the ed25519 fixture using `Runner::seeded(0)` — the same RNG
/// source `simplex::replay::trace::rehydrate_keys` uses. This is what
/// makes recorded traces replayable: the fuzz runtime's own RNG is
/// driven by `FuzzRng` (input-dependent), so keys derived from it
/// would not match what `replay(&Trace)` rehydrates.
fn replay_fixture(
    n: u32,
    namespace: &[u8],
) -> commonware_cryptography::certificate::mocks::Fixture<
    commonware_consensus::simplex::scheme::ed25519::Scheme,
> {
    let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
    let cc = captured.clone();
    let ns = namespace.to_vec();
    let runner = deterministic::Runner::seeded(0);
    runner.start(|mut ctx| async move {
        let f = commonware_consensus::simplex::scheme::ed25519::fixture(&mut ctx, &ns, n);
        *cc.lock().unwrap() = Some(f);
    });
    let out = captured.lock().unwrap().take().expect("fixture captured");
    out
}

type Ed25519Scheme = <SimplexEd25519 as simplex::Simplex>::Scheme;

fn timing_for_fuzz() -> Timing {
    Timing {
        leader_timeout_ms: 1_000,
        certification_timeout_ms: 2_000,
        timeout_retry_ms: 10_000,
        fetch_timeout_ms: 1_000,
        activity_timeout: 10,
        skip_timeout: 5,
    }
}

fn timing_for_twins() -> Timing {
    Timing {
        leader_timeout_ms: 1_000,
        certification_timeout_ms: 1_500,
        timeout_retry_ms: 10_000,
        fetch_timeout_ms: 1_000,
        activity_timeout: 10,
        skip_timeout: 5,
    }
}

fn trace_artifacts_dir(base_dir: &str) -> PathBuf {
    let dir_name = format!("{base_dir}_canonical");
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts/traces")
        .join(dir_name)
}

fn persist_trace(base_dir: &str, hash_hex: &str, trace: &Trace) {
    let artifacts_dir = trace_artifacts_dir(base_dir);
    fs::create_dir_all(&artifacts_dir).expect("failed to create artifacts directory");
    let json = trace.to_json().expect("failed to serialize trace");
    let json_path = artifacts_dir.join(format!("{hash_hex}.json"));
    fs::write(&json_path, &json).expect("failed to write trace JSON");
    println!(
        "wrote {} trace events to {}",
        trace.events.len(),
        json_path.display()
    );
}

fn pk_index(pk: &PublicKey, participants: &[PublicKey]) -> Option<usize> {
    participants.iter().position(|p| p == pk)
}

fn participation_to_signers(
    map: &std::collections::HashMap<
        View,
        std::collections::HashMap<Sha256Digest, std::collections::HashSet<PublicKey>>,
    >,
    participants: &[PublicKey],
) -> BTreeMap<View, BTreeSet<Participant>> {
    let mut out = BTreeMap::new();
    for (view, payload_map) in map {
        let mut signers = BTreeSet::new();
        for pks in payload_map.values() {
            for pk in pks {
                if let Some(idx) = pk_index(pk, participants) {
                    signers.insert(Participant::new(idx as u32));
                }
            }
        }
        out.insert(*view, signers);
    }
    out
}

fn nullifies_to_signers(
    map: &std::collections::HashMap<View, std::collections::HashSet<PublicKey>>,
    participants: &[PublicKey],
) -> BTreeMap<View, BTreeSet<Participant>> {
    let mut out = BTreeMap::new();
    for (view, pks) in map {
        let signers: BTreeSet<Participant> = pks
            .iter()
            .filter_map(|pk| pk_index(pk, participants).map(|i| Participant::new(i as u32)))
            .collect();
        out.insert(*view, signers);
    }
    out
}

fn signer_count(
    certificate: &<Ed25519Scheme as Scheme>::Certificate,
    max_participants: usize,
) -> Option<u32> {
    let encoded = certificate.encode();
    let mut cursor = encoded.as_ref();
    let signers = Signers::read_cfg(&mut cursor, &max_participants).expect("Signers decode");
    Some(signers.count() as u32)
}

fn build_snapshot_from_reporters<L>(
    reporters: &[reporter::Reporter<deterministic::Context, Ed25519Scheme, L, Sha256Digest>],
    participants: &[PublicKey],
    faults: usize,
) -> Snapshot
where
    L: ElectorConfig<Ed25519Scheme>,
{
    let mut nodes = BTreeMap::new();
    for (idx, reporter) in reporters.iter().enumerate() {
        let me = Participant::new((faults + idx) as u32);
        let n_participants = participants.len();

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

        let notarize_signers =
            participation_to_signers(&reporter.notarizes.lock(), participants);
        let finalize_signers =
            participation_to_signers(&reporter.finalizes.lock(), participants);
        let nullify_signers = nullifies_to_signers(&reporter.nullifies.lock(), participants);

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

async fn drain_pipeline(context: &deterministic::Context) {
    context.quiesce().await;
}

/// Run consensus with all honest nodes and record a canonical Trace.
pub fn run_quint_honest_recording(input: FuzzInput, corpus_bytes: &[u8]) {
    let hash = sha1::Sha1::digest(corpus_bytes);
    let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    let Some(trace) = run_honest_pipeline(input) else {
        return;
    };
    persist_trace("simplex_ed25519_quint_honest", &hash_hex, &trace);
}

/// Runs the deterministic 4-node honest consensus pipeline and returns the
/// resulting canonical [`Trace`] without persisting it.
///
/// Shared between [`run_quint_honest_recording`] (which then writes the trace
/// to an artifact directory) and the TLC-driven fuzz target (which feeds the
/// trace into the controlled TLC server for coverage feedback).
pub fn run_honest_pipeline(input: FuzzInput) -> Option<Trace> {
    let captured: Arc<std::sync::Mutex<Option<Trace>>> =
        Arc::new(std::sync::Mutex::new(None));
    let captured_clone = captured.clone();

    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|context| async move {
        let trace = build_honest_trace(context, input).await;
        *captured_clone.lock().unwrap() = Some(trace);
    });

    let result = captured.lock().unwrap().take();
    result
}

/// Body of the honest recording pipeline. Sets up the deterministic 4-node
/// network, runs consensus until every reporter has reached the required
/// container count, drains the pipeline, and returns the canonical
/// [`Trace`].
async fn build_honest_trace(mut context: deterministic::Context, input: FuzzInput) -> Trace {
    let tracing_input = FuzzInput {
        raw_bytes: input.raw_bytes.clone(),
        required_containers: input.required_containers,
        degraded_network: false,
        configuration: N4F0C4,
        partition: Partition::Connected,
        strategy: input.strategy,
        byzantine_actor: input.byzantine_actor,
    };

    let fixture = replay_fixture(tracing_input.configuration.n, NAMESPACE);
    let (oracle, participants, schemes, mut registrations) =
        crate::setup_network_with_fixture::<SimplexEd25519>(
            &mut context,
            &tracing_input,
            fixture,
        )
        .await;

    let recorder = Recorder::new(participants.clone());
    let app_relay = Arc::new(relay::Relay::new());
    let elector = RoundRobin::<Sha256Hasher>::default();
    let mut reporters = Vec::new();
    let config = tracing_input.configuration;
    let n_usize = config.n as usize;

    for i in 0..n_usize {
        let validator = participants[i].clone();
        let (vote_network, cert_network, resolver_network) =
            registrations.remove(&validator).unwrap();
        let ctx = context.with_label(&format!("validator_{validator}"));
        let me = Participant::new(i as u32);

        let (vote_sender, vote_receiver) = vote_network;
        let (cert_sender, cert_receiver) = cert_network;
        let (resolver_sender, resolver_receiver) = resolver_network;

        let rec_vote_rx = RecordingReceiver::new(
            vote_receiver,
            recorder.clone(),
            me,
            ChannelKind::Vote,
            n_usize,
        );
        let rec_cert_rx = RecordingReceiver::new(
            cert_receiver,
            recorder.clone(),
            me,
            ChannelKind::Certificate,
            n_usize,
        );
        let rec_vote_tx = RecordingSender::new(vote_sender, recorder.clone(), me);

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

        let rec_app = RecordingApp::new(application.clone(), recorder.clone(), me);

        let blocker = oracle.control(validator.clone());
        let engine_cfg = config::Config {
            blocker,
            scheme: schemes[i].clone(),
            elector: elector.clone(),
            automaton: rec_app.clone(),
            relay: rec_app,
            reporter: reporter.clone(),
            partition: validator.to_string(),
            mailbox_size: 1024,
            epoch: Epoch::new(EPOCH),
            leader_timeout: Duration::from_secs(1),
            certification_timeout: Duration::from_secs(2),
            timeout_retry: Duration::from_secs(10),
            fetch_timeout: Duration::from_secs(1),
            activity_timeout: Delta::new(10),
            skip_timeout: Delta::new(5),
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

    let mut finalizers = Vec::new();
    for reporter in reporters.iter_mut() {
        let required_containers = tracing_input.required_containers;
        let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
        finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
            while latest.get() < required_containers {
                latest = monitor.recv().await.expect("event missing");
            }
        }));
    }
    join_all(finalizers).await;
    drain_pipeline(&context).await;

    let replayed = invariants::extract_replayed(&reporters, config.n as usize);
    let states = invariants::extract(&reporters, config.n as usize);
    invariants::check::<SimplexEd25519>(config.n, &states);
    invariants::check_vote_invariants(&replayed, config.faults as usize);

    let snapshot =
        build_snapshot_from_reporters(&reporters, &participants, config.faults as usize);
    let topology = Topology {
        n: config.n,
        faults: config.faults,
        epoch: EPOCH,
        namespace: NAMESPACE.to_vec(),
        timing: timing_for_fuzz(),
    };
    recorder.freeze(topology, snapshot)
}

/// Thin wrapper: runs the Byzantine pipeline with [`ByzantineActor::Disrupter`].
pub fn run_quint_disrupter_recording(input: FuzzInput, corpus_bytes: &[u8]) {
    run_quint_byzantine_recording(ByzantineActor::Disrupter, input, corpus_bytes);
}

/// Run consensus with a Byzantine actor as node 0 and record a canonical Trace.
pub fn run_quint_byzantine_recording(
    actor: ByzantineActor,
    input: FuzzInput,
    corpus_bytes: &[u8],
) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    let hash = sha1::Sha1::digest(corpus_bytes);
    let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

    executor.start(|mut context| async move {
        let tracing_input = FuzzInput {
            raw_bytes: input.raw_bytes.clone(),
            required_containers: input.required_containers,
            degraded_network: false,
            configuration: N4F1C3,
            partition: Partition::Connected,
            strategy: input.strategy,
            byzantine_actor: input.byzantine_actor,
        };

        let (oracle, participants, schemes, mut registrations) =
            crate::setup_network::<SimplexEd25519>(&mut context, &tracing_input).await;

        let recorder = Recorder::new(participants.clone());
        let app_relay = Arc::new(relay::Relay::new());
        let elector = RoundRobin::<Sha256Hasher>::default();
        let mut reporters = Vec::new();
        let config = tracing_input.configuration;
        let n_usize = config.n as usize;

        {
            let validator = participants[0].clone();
            let (vote_network, cert_network, resolver_network) =
                registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let me = Participant::new(0);

            let (vote_sender, vote_receiver) = vote_network;
            let (cert_sender, cert_receiver) = cert_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let rec_vote_rx = RecordingReceiver::new(
                vote_receiver,
                recorder.clone(),
                me,
                ChannelKind::Vote,
                n_usize,
            );
            let rec_cert_rx = RecordingReceiver::new(
                cert_receiver,
                recorder.clone(),
                me,
                ChannelKind::Certificate,
                n_usize,
            );
            let rec_vote_tx = RecordingSender::new(vote_sender, recorder.clone(), me);

            match actor {
                ByzantineActor::Equivocator => {
                    let cfg = equivocator::Config {
                        scheme: schemes[0].clone(),
                        elector: elector.clone(),
                        epoch: Epoch::new(EPOCH),
                        relay: app_relay.clone(),
                        hasher: Sha256Hasher::default(),
                    };
                    let equivocator =
                        equivocator::Equivocator::new(ctx.with_label("equivocator"), cfg);
                    equivocator.start((rec_vote_tx, rec_vote_rx), (cert_sender, rec_cert_rx));
                }
                ByzantineActor::Conflicter => {
                    let cfg = conflicter::Config {
                        scheme: schemes[0].clone(),
                    };
                    let conflicter = conflicter::Conflicter::<_, _, Sha256Hasher>::new(
                        ctx.with_label("conflicter"),
                        cfg,
                    );
                    conflicter.start((rec_vote_tx, rec_vote_rx));
                }
                ByzantineActor::Nuller => {
                    let cfg = nuller::Config {
                        scheme: schemes[0].clone(),
                    };
                    let nuller =
                        nuller::Nuller::<_, _, Sha256Hasher>::new(ctx.with_label("nuller"), cfg);
                    nuller.start((rec_vote_tx, rec_vote_rx));
                }
                ByzantineActor::NullifyOnly => {
                    let cfg = nullify_only::Config {
                        scheme: schemes[0].clone(),
                    };
                    let nullify_only = nullify_only::NullifyOnly::<_, _, Sha256Hasher>::new(
                        ctx.with_label("nullify_only"),
                        cfg,
                    );
                    nullify_only.start((rec_vote_tx, rec_vote_rx));
                }
                ByzantineActor::Outdated => {
                    let cfg = outdated::Config {
                        scheme: schemes[0].clone(),
                        view_delta: Delta::new(5),
                    };
                    let outdated = outdated::Outdated::<_, _, Sha256Hasher>::new(
                        ctx.with_label("outdated"),
                        cfg,
                    );
                    outdated.start((rec_vote_tx, rec_vote_rx));
                }
                ByzantineActor::Disrupter => {
                    let disrupter = Disrupter::new(
                        ctx.with_label("disrupter"),
                        schemes[0].clone(),
                        SmallScopeForTracing::new(2, 5),
                    );
                    disrupter.start(
                        (rec_vote_tx, rec_vote_rx),
                        (cert_sender, rec_cert_rx),
                        (resolver_sender, resolver_receiver),
                    );
                }
            }
        }

        for i in (config.faults as usize)..n_usize {
            let validator = participants[i].clone();
            let (vote_network, cert_network, resolver_network) =
                registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let me = Participant::new(i as u32);

            let (vote_sender, vote_receiver) = vote_network;
            let (cert_sender, cert_receiver) = cert_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let rec_vote_rx = RecordingReceiver::new(
                vote_receiver,
                recorder.clone(),
                me,
                ChannelKind::Vote,
                n_usize,
            );
            let rec_cert_rx = RecordingReceiver::new(
                cert_receiver,
                recorder.clone(),
                me,
                ChannelKind::Certificate,
                n_usize,
            );
            let rec_vote_tx = RecordingSender::new(vote_sender, recorder.clone(), me);

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

            let rec_app = RecordingApp::new(application.clone(), recorder.clone(), me);

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: schemes[i].clone(),
                elector: elector.clone(),
                automaton: rec_app.clone(),
                relay: rec_app,
                reporter: reporter.clone(),
                partition: validator.to_string(),
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
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

        let mut finalizers = Vec::new();
        for reporter in reporters.iter_mut() {
            let required_containers = tracing_input.required_containers;
            let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
            finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                while latest.get() < required_containers {
                    latest = monitor.recv().await.expect("event missing");
                }
            }));
        }
        join_all(finalizers).await;
        drain_pipeline(&context).await;

        let replayed = invariants::extract_replayed(&reporters, config.n as usize);
        let states = invariants::extract(&reporters, config.n as usize);
        invariants::check::<SimplexEd25519>(config.n, &states);
        invariants::check_vote_invariants(&replayed, config.faults as usize);

        let snapshot =
            build_snapshot_from_reporters(&reporters, &participants, config.faults as usize);
        let topology = Topology {
            n: config.n,
            faults: config.faults,
            epoch: EPOCH,
            namespace: NAMESPACE.to_vec(),
            timing: timing_for_fuzz(),
        };
        let trace = recorder.freeze(topology, snapshot);

        let base_dir = if matches!(actor, ByzantineActor::Disrupter) {
            "simplex_ed25519_quint_disrupter"
        } else {
            "simplex_ed25519_quint_byzantine"
        };
        persist_trace(base_dir, &hash_hex, &trace);
    });
}

/// Run consensus with a Byzantine twin and record a canonical Trace.
pub fn run_quint_twins_recording(input: FuzzInput, corpus_bytes: &[u8]) {
    let mut rng = FuzzRng::new(input.raw_bytes.clone());
    let case = twins::cases(
        &mut rng,
        Framework {
            participants: N4F1C3.n as usize,
            faults: N4F1C3.faults as usize,
            rounds: 1,
            mode: Mode::Sampled,
            max_cases: 1,
        },
    )
    .into_iter()
    .next()
    .expect("should generate at least one case");
    let scenario = case.scenario;

    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    let hash = sha1::Sha1::digest(corpus_bytes);
    let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();

    executor.start(|mut context| async move {
        let tracing_input = FuzzInput {
            raw_bytes: input.raw_bytes.clone(),
            required_containers: input.required_containers,
            degraded_network: false,
            configuration: N4F1C3,
            partition: Partition::Connected,
            strategy: input.strategy,
            byzantine_actor: input.byzantine_actor,
        };

        let (oracle, participants, schemes, mut registrations) =
            crate::setup_network::<SimplexEd25519>(&mut context, &tracing_input).await;
        let participants_arc: Arc<[_]> = participants.clone().into();

        let recorder = Recorder::new(participants.clone());
        let app_relay = Arc::new(relay::Relay::new());
        let config = tracing_input.configuration;
        let n_usize = config.n as usize;
        let elector = TwinsElector::new(
            RoundRobin::<Sha256Hasher>::default(),
            &scenario,
            n_usize,
        );
        let mut reporters = Vec::new();

        {
            let idx = 0;
            let validator = participants[idx].clone();
            let twin_ctx = context.with_label(&format!("twin_{idx}"));
            let scheme = schemes[idx].clone();
            let (vote_network, certificate_network, resolver_network) = registrations
                .remove(&validator)
                .expect("validator should be registered");

            let make_vote_forwarder = || {
                let participants = participants_arc.clone();
                let scenario = scenario.clone();
                move |origin: SplitOrigin, recipients: &Recipients<_>, message: &IoBuf| {
                    let Ok(msg) =
                        Vote::<<SimplexEd25519 as simplex::Simplex>::Scheme, Sha256Digest>::decode(
                            message.clone(),
                        )
                    else {
                        return Some(recipients.clone());
                    };
                    let (primary, secondary) =
                        scenario.partitions(msg.view(), participants.as_ref());
                    match origin {
                        SplitOrigin::Primary => Some(Recipients::Some(primary)),
                        SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                    }
                }
            };
            let make_certificate_forwarder = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants_arc.clone();
                let scenario = scenario.clone();
                move |origin: SplitOrigin, recipients: &Recipients<_>, message: &IoBuf| {
                    let Ok(msg) = Certificate::<
                        <SimplexEd25519 as simplex::Simplex>::Scheme,
                        Sha256Digest,
                    >::decode_cfg(&mut message.as_ref(), &codec) else {
                        return Some(recipients.clone());
                    };
                    let (primary, secondary) =
                        scenario.partitions(msg.view(), participants.as_ref());
                    match origin {
                        SplitOrigin::Primary => Some(Recipients::Some(primary)),
                        SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                    }
                }
            };
            let make_resolver_forwarder = || {
                move |_: SplitOrigin, recipients: &Recipients<_>, _: &IoBuf| {
                    Some(recipients.clone())
                }
            };

            let make_vote_router = || {
                let participants = participants_arc.clone();
                let scenario = scenario.clone();
                move |(sender, message): &(_, IoBuf)| {
                    let Ok(msg) =
                        Vote::<<SimplexEd25519 as simplex::Simplex>::Scheme, Sha256Digest>::decode(
                            message.clone(),
                        )
                    else {
                        return SplitTarget::None;
                    };
                    scenario.route(msg.view(), sender, participants.as_ref())
                }
            };
            let make_certificate_router = || {
                let codec = schemes[idx].certificate_codec_config();
                let participants = participants_arc.clone();
                let scenario = scenario.clone();
                move |(sender, message): &(_, IoBuf)| {
                    let Ok(msg) = Certificate::<
                        <SimplexEd25519 as simplex::Simplex>::Scheme,
                        Sha256Digest,
                    >::decode_cfg(&mut message.as_ref(), &codec) else {
                        return SplitTarget::None;
                    };
                    scenario.route(msg.view(), sender, participants.as_ref())
                }
            };
            let make_resolver_router = || move |(_sender, _message): &(_, IoBuf)| SplitTarget::Both;

            let (vote_sender, vote_receiver) = vote_network;
            let (certificate_sender, certificate_receiver) = certificate_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let (vote_sender_primary, vote_sender_secondary) =
                vote_sender.split_with(make_vote_forwarder());
            let (vote_receiver_primary, vote_receiver_secondary) = vote_receiver.split_with(
                twin_ctx.with_label(&format!("pending_split_{idx}")),
                make_vote_router(),
            );
            let (certificate_sender_primary, certificate_sender_secondary) =
                certificate_sender.split_with(make_certificate_forwarder());
            let (certificate_receiver_primary, certificate_receiver_secondary) =
                certificate_receiver.split_with(
                    twin_ctx.with_label(&format!("recovered_split_{idx}")),
                    make_certificate_router(),
                );
            let (resolver_sender_primary, resolver_sender_secondary) =
                resolver_sender.split_with(make_resolver_forwarder());
            let (resolver_receiver_primary, resolver_receiver_secondary) = resolver_receiver
                .split_with(
                    twin_ctx.with_label(&format!("resolver_split_{idx}")),
                    make_resolver_router(),
                );

            let me = Participant::new(idx as u32);
            let rec_vote_rx_primary = RecordingReceiver::new(
                vote_receiver_primary,
                recorder.clone(),
                me,
                ChannelKind::Vote,
                n_usize,
            );
            let rec_cert_rx_primary = RecordingReceiver::new(
                certificate_receiver_primary,
                recorder.clone(),
                me,
                ChannelKind::Certificate,
                n_usize,
            );
            let rec_vote_tx_primary =
                RecordingSender::new(vote_sender_primary, recorder.clone(), me);

            let primary_label = format!("twin_{idx}_primary");
            let primary_context = twin_ctx.with_label(&primary_label);
            let primary_elector = elector.clone();
            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: scheme.clone(),
                elector: primary_elector.clone(),
            };
            let reporter =
                reporter::Reporter::new(primary_context.with_label("reporter"), reporter_cfg);

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
                application::Application::new(primary_context.with_label("application"), app_cfg);
            actor.start();

            let rec_app_primary =
                RecordingApp::new(application.clone(), recorder.clone(), me);

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: scheme.clone(),
                elector: primary_elector,
                automaton: rec_app_primary.clone(),
                relay: rec_app_primary,
                reporter: reporter.clone(),
                partition: primary_label,
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&primary_context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(primary_context.with_label("engine"), engine_cfg);
            engine.start(
                (rec_vote_tx_primary, rec_vote_rx_primary),
                (certificate_sender_primary, rec_cert_rx_primary),
                (resolver_sender_primary, resolver_receiver_primary),
            );

            let secondary_label = format!("twin_{idx}_secondary");
            let secondary_context = twin_ctx.with_label(&secondary_label);
            let secondary_elector = elector.clone();
            let secondary_reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: scheme.clone(),
                elector: secondary_elector.clone(),
            };
            let secondary_reporter = reporter::Reporter::new(
                secondary_context.with_label("reporter"),
                secondary_reporter_cfg,
            );

            let secondary_app_cfg = application::Config {
                hasher: Sha256Hasher::default(),
                relay: app_relay.clone(),
                me: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: application::Certifier::Sometimes,
            };
            let (secondary_actor, secondary_application) = application::Application::new(
                secondary_context.with_label("application"),
                secondary_app_cfg,
            );
            secondary_actor.start();

            let rec_vote_rx_secondary = RecordingReceiver::new(
                vote_receiver_secondary,
                recorder.clone(),
                me,
                ChannelKind::Vote,
                n_usize,
            );
            let rec_cert_rx_secondary = RecordingReceiver::new(
                certificate_receiver_secondary,
                recorder.clone(),
                me,
                ChannelKind::Certificate,
                n_usize,
            );
            let rec_vote_tx_secondary =
                RecordingSender::new(vote_sender_secondary, recorder.clone(), me);
            let rec_app_secondary =
                RecordingApp::new(secondary_application.clone(), recorder.clone(), me);

            let secondary_blocker = oracle.control(validator.clone());
            let secondary_engine_cfg = config::Config {
                blocker: secondary_blocker,
                scheme: scheme.clone(),
                elector: secondary_elector,
                automaton: rec_app_secondary.clone(),
                relay: rec_app_secondary,
                reporter: secondary_reporter.clone(),
                partition: secondary_label,
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&secondary_context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding: ForwardingPolicy::Disabled,
            };
            let secondary_engine =
                Engine::new(secondary_context.with_label("engine"), secondary_engine_cfg);
            secondary_engine.start(
                (rec_vote_tx_secondary, rec_vote_rx_secondary),
                (certificate_sender_secondary, rec_cert_rx_secondary),
                (resolver_sender_secondary, resolver_receiver_secondary),
            );
        }

        for i in 1..n_usize {
            let validator = participants[i].clone();
            let (vote_network, cert_network, resolver_network) =
                registrations.remove(&validator).unwrap();
            let ctx = context.with_label(&format!("validator_{validator}"));
            let me = Participant::new(i as u32);

            let (vote_sender, vote_receiver) = vote_network;
            let (cert_sender, cert_receiver) = cert_network;
            let (resolver_sender, resolver_receiver) = resolver_network;

            let rec_vote_rx = RecordingReceiver::new(
                vote_receiver,
                recorder.clone(),
                me,
                ChannelKind::Vote,
                n_usize,
            );
            let rec_cert_rx = RecordingReceiver::new(
                cert_receiver,
                recorder.clone(),
                me,
                ChannelKind::Certificate,
                n_usize,
            );
            let rec_vote_tx = RecordingSender::new(vote_sender, recorder.clone(), me);

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

            let rec_app = RecordingApp::new(application.clone(), recorder.clone(), me);

            let blocker = oracle.control(validator.clone());
            let engine_cfg = config::Config {
                blocker,
                scheme: schemes[i].clone(),
                elector: elector.clone(),
                automaton: rec_app.clone(),
                relay: rec_app,
                reporter: reporter.clone(),
                partition: validator.to_string(),
                mailbox_size: 1024,
                epoch: Epoch::new(EPOCH),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout: Delta::new(10),
                skip_timeout: Delta::new(5),
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

        let mut finalizers = Vec::new();
        for reporter in reporters.iter_mut() {
            let required_containers = tracing_input.required_containers;
            let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;
            finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                while latest.get() < required_containers {
                    latest = monitor.recv().await.expect("event missing");
                }
            }));
        }
        join_all(finalizers).await;
        drain_pipeline(&context).await;

        let replayed = invariants::extract_replayed(&reporters, config.n as usize);
        let states = invariants::extract(&reporters, config.n as usize);
        invariants::check::<SimplexEd25519>(config.n, &states);
        invariants::check_vote_invariants(&replayed, config.faults as usize);

        let snapshot =
            build_snapshot_from_reporters(&reporters, &participants, config.faults as usize);
        let topology = Topology {
            n: config.n,
            faults: config.faults,
            epoch: EPOCH,
            namespace: NAMESPACE.to_vec(),
            timing: timing_for_twins(),
        };
        let trace = recorder.freeze(topology, snapshot);
        persist_trace("simplex_ed25519_quint_twins", &hash_hex, &trace);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::StrategyChoice;
    use commonware_consensus::simplex::replay::replay;

    fn minimal_fuzz_input() -> FuzzInput {
        FuzzInput {
            raw_bytes: vec![0u8; 256],
            required_containers: 3,
            degraded_network: false,
            configuration: N4F0C4,
            partition: Partition::Connected,
            strategy: StrategyChoice::SmallScope {
                fault_rounds: 0,
                fault_rounds_bound: 1,
            },
            byzantine_actor: ByzantineActor::Disrupter,
        }
    }

    /// Regression: the fuzz recorder must produce traces that round-trip
    /// through `simplex::replay::replay`. Before the
    /// `replay_fixture`/`setup_network_with_fixture` fix, the fuzz
    /// runtime's FuzzRng-seeded context derived different ed25519 keys
    /// than `rehydrate_keys` uses on the replay side, so signatures
    /// didn't verify and the replay Snapshot never matched the recorded
    /// `expected`.
    #[test]
    fn honest_recording_roundtrips_through_rust_replay() {
        let input = minimal_fuzz_input();
        let trace = run_honest_pipeline(input).expect("honest pipeline captured a Trace");
        let actual = replay(&trace);
        assert_eq!(
            actual, trace.expected,
            "Rust replay must agree with the recorder's embedded expected"
        );
    }
}
