//! Engine configuration derivation, lifecycle, and recovery tests.

use super::{
    CHECKPOINT_INTERVAL, Config, Engine, Overrides, Planes, Readiness, Running, Stopped,
    critical_threads, derive_profile, inflight_application,
};
use crate::{
    Epochable as _,
    multimmit::{
        actors::{
            resolver,
            voter::{VoterLimits, validation_parallelism},
        },
        config::{Error as ConfigError, LeaderSchedule, Profile, Role, Tuning},
        machine::{DischargeKind, Inspection},
        mocks::{
            Committee, MockApplication, NoopReporter,
            cluster::{QUOTA, link_all, start_network},
        },
        storage::{OpenError, Recovered, RecoveryConfig, partitions, recover},
        types::{EpochGenesis, PathLimits, SignedTransactionBlock, ViewProof},
        wire::{CertificateMessage, DataMessage, Envelope, EnvelopeConfig},
    },
    types::{Height, Participant, View},
};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::MinPk, ed25519, sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_traced};
use commonware_p2p::{
    Receiver as _, Recipients, Sender as _,
    simulated::{Oracle, Receiver as SimulatedReceiver, Sender as SimulatedSender},
    utils::mocks::NoopBlocker,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Clock as _, Runner as _, Storage as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic::{self, Runner as DeterministicRunner},
    telemetry::metrics::count_running_tasks,
};
use commonware_utils::{NZU64, NZUsize, channel::oneshot};
use rstest::rstest;
use std::{
    collections::BTreeSet,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

type TestBlocker = NoopBlocker<ed25519::PublicKey>;

type TestPlanes = Planes<
    SimulatedSender<ed25519::PublicKey, deterministic::Context>,
    SimulatedReceiver<ed25519::PublicKey>,
>;

/// Registers `identity`'s four engine planes on channels 0 through 3.
async fn register_planes(
    oracle: &Oracle<ed25519::PublicKey, deterministic::Context>,
    identity: &ed25519::PublicKey,
) -> TestPlanes {
    let control = oracle.control(identity.clone());
    Planes {
        data: control.register(0, QUOTA).await.unwrap(),
        consensus: control.register(1, QUOTA).await.unwrap(),
        certificates: control.register(2, QUOTA).await.unwrap(),
        resolver: control.register(3, QUOTA).await.unwrap(),
    }
}

fn tuning() -> Tuning {
    Tuning {
        production_interval: Duration::from_millis(100),
        ..Tuning::new(Duration::from_millis(500))
    }
}

fn profile(committee: &Committee<MinPk>, role: Role) -> Profile<Sha256Digest> {
    Profile::new::<MinPk>(committee.config.clone(), role, tuning()).unwrap()
}

fn config(
    context: &impl BufferPooler,
    committee: &Committee<MinPk>,
    index: usize,
    prefix: &str,
) -> Config<
    Sha256,
    ed25519::PublicKey,
    MinPk,
    MockApplication,
    MockApplication,
    NoopReporter<MinPk, Sha256Digest>,
    Sequential,
    Sequential,
    TestBlocker,
> {
    let application = MockApplication::new();
    Config {
        scheme: committee.signers[index].clone(),
        genesis: committee.config.genesis().clone(),
        tuning: tuning(),
        automaton: application.clone(),
        relay: application,
        reporter: NoopReporter::default(),
        strategy: Sequential,
        critical_strategy: Sequential,
        blocker: NoopBlocker::default(),
        partition_prefix: format!("{prefix}_{index}"),
        page_cache: CacheRef::from_pooler(context, paged::page_size(4_096), NZUsize!(8)),
        mailbox_size: NonZeroUsize::new(128).unwrap(),
    }
}

fn assert_same_durable_prefix(
    live: &Inspection<Sha256Digest>,
    recovered: &Inspection<Sha256Digest>,
) {
    assert!(live.is_live());
    assert!(!live.is_recovering());
    assert!(!recovered.is_live());
    assert!(recovered.is_recovering());
    // Admission queues and jobs are generation-local service metadata. The fields below are
    // the semantic projection owned by the checkpoint and contiguous journal suffix.
    assert_eq!(recovered.epoch(), live.epoch());
    assert_eq!(recovered.view(), live.view());
    assert_eq!(recovered.generation(), live.generation());
    assert_eq!(recovered.cursor(), live.cursor());
    assert_eq!(recovered.local_artifacts(), live.local_artifacts());
    assert_eq!(recovered.outbox(), live.outbox());
    assert_eq!(recovered.produced_blocks(), live.produced_blocks());
    assert_eq!(recovered.chain_progress(), live.chain_progress());
    assert_eq!(recovered.pools(), live.pools());
    assert_eq!(recovered.finality(), live.finality());
    assert_eq!(
        recovered.retained_artifact_references(),
        live.retained_artifact_references()
    );
    assert_eq!(
        recovered.nullification_suffix(),
        live.nullification_suffix()
    );
    assert_eq!(recovered.retired_view(), live.retired_view());
    assert_eq!(recovered.finality_floor(), live.finality_floor());

    let live_producer = live.producer().expect("validator has producer state");
    let recovered_producer = recovered.producer().expect("producer state recovers");
    assert_eq!(recovered_producer.chain(), live_producer.chain());
    assert_eq!(recovered_producer.produced(), live_producer.produced());
    assert_eq!(recovered_producer.certified(), live_producer.certified());
    assert_eq!(recovered_producer.da_quorum(), live_producer.da_quorum());
    assert_eq!(
        recovered_producer.pipeline_depth(),
        live_producer.pipeline_depth()
    );
}

#[test]
fn skip_timeout_follows_the_tuning() {
    DeterministicRunner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(944, 6).build();
        // Unset, the window is five view timeouts of the tuning it belongs to.
        for (label, skip_timeout, expected) in [
            ("default", None, Duration::from_millis(2500)),
            (
                "explicit",
                Some(Duration::from_secs(3)),
                Duration::from_secs(3),
            ),
        ] {
            let mut config = config(&context, &committee, 0, label);
            config.tuning.skip_timeout = skip_timeout;
            let engine = Engine::open(context.child(label), config)
                .await
                .expect("engine opens");
            assert_eq!(
                engine.actors.voter.skip_timeout(),
                Some(expected),
                "{label}"
            );
        }
    });
}

#[rstest]
#[case(Duration::ZERO)]
#[case(Duration::from_millis(500))]
#[case(Duration::from_secs(1))]
fn skip_timeout_rejects_windows_below_the_retry_ceiling(#[case] window: Duration) {
    DeterministicRunner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(944, 6).build();
        let mut config = config(&context, &committee, 0, "skip_timeout");
        config.tuning.skip_timeout = Some(window);
        let Err(error) = Engine::open(context.child("engine"), config).await else {
            panic!("a skip timeout at or below the retry ceiling opened");
        };
        assert!(matches!(
            error,
            OpenError::Config(ConfigError::SkipTimeoutTooShort { actual, .. }) if actual == window
        ));
        assert!(
            error
                .to_string()
                .contains("skip timeout must exceed the publication retry ceiling")
        );
    });
}

#[test]
fn voter_limits_are_nonzero_and_overflow_safe() {
    let committee = Committee::<MinPk>::builder(77, 6).build();
    for view_timeout in [Duration::from_nanos(1), Duration::MAX] {
        let profile: Profile<Sha256Digest> = Profile::new::<MinPk>(
            committee.config.clone(),
            Role::Observer,
            Tuning {
                production_interval: Duration::from_millis(1),
                ..Tuning::new(view_timeout)
            },
        )
        .unwrap();
        let limits = VoterLimits::from_profile(&profile, CHECKPOINT_INTERVAL);
        assert_eq!(inflight_application(&profile).get(), 12);
        assert!(!limits.retry_initial.is_zero());
        assert!(limits.retry_initial <= limits.retry_ceiling);
        assert!(limits.retry_ceiling <= limits.heartbeat);
        assert_eq!(limits.skip_timeout, view_timeout.checked_mul(5));
    }
}

#[test]
fn the_view_critical_pool_scales_with_the_committee() {
    // One view's view-critical cryptography is bounded by the committee, so the pool that runs it
    // tracks the committee rather than the machine's total crypto slots.
    for (participants, threads) in [(1, 2), (6, 2), (16, 2), (32, 4), (50, 6), (100, 12)] {
        assert_eq!(
            critical_threads(participants).get(),
            threads,
            "participants={participants}"
        );
    }
}

#[test]
fn inflight_application_covers_each_producer_pipeline() {
    for (seed, namespace, participants, producers, expected) in [
        (
            79,
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_ALL_CHAIN_CAPACITY_TEST".as_slice(),
            11,
            11,
            22,
        ),
        (
            80,
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_APPLICATION_CAPACITY_TEST",
            41,
            9,
            18,
        ),
        (
            83,
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_CHAIN_CAPACITY_TEST",
            51,
            10,
            20,
        ),
    ] {
        let committee = Committee::<MinPk>::builder(seed, participants)
            .namespace(namespace)
            .producers((0..producers).map(Participant::new).collect())
            .build();
        let profile = profile(&committee, Role::Observer);
        assert_eq!(
            inflight_application(&profile).get(),
            expected,
            "participants={participants} producers={producers}"
        );
    }
}

#[test]
fn inflight_application_does_not_exceed_retained_artifact_capacity() {
    let producers = (0..100).map(Participant::new).collect();
    let committee = Committee::<MinPk>::builder(89, 100)
        .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_APPLICATION_ARTIFACT_CAP_TEST")
        .producers(producers)
        .limits(PathLimits::new(800, 1).unwrap())
        .build();
    let profile: Profile<Sha256Digest> = Profile::new::<MinPk>(
        committee.config,
        Role::Observer,
        Tuning {
            max_artifact_bytes: NonZeroUsize::new(4 * 1024 * 1024),
            ..Tuning::default()
        },
    )
    .unwrap();
    let uncapped = profile
        .codec()
        .chains()
        .checked_mul(validation_parallelism(&profile))
        .unwrap();

    assert!(uncapped > profile.resources().max_cached_artifacts());
    assert_eq!(
        inflight_application(&profile).get(),
        profile.resources().max_cached_artifacts(),
    );
}

#[test_traced]
fn readiness_wait_survives_cancellation_and_remembers_failure() {
    DeterministicRunner::default().start(|context| async move {
        let (sender, receiver) = oneshot::channel();
        let mut readiness = Readiness::Pending(receiver);
        select! {
            result = readiness.wait() => panic!("pending readiness resolved: {result:?}"),
            () = context.sleep(Duration::from_millis(1)) => {},
        }

        drop(sender);
        assert!(matches!(readiness.wait().await, Err(Stopped)));
        assert!(matches!(readiness.wait().await, Err(Stopped)));

        let (sender, receiver) = oneshot::channel();
        let mut readiness = Readiness::Pending(receiver);
        sender.send(()).unwrap();
        assert!(readiness.wait().await.is_ok());
        assert!(readiness.wait().await.is_ok());
    });
}

#[test_traced]
fn open_spawns_no_task_until_start() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = Committee::<MinPk>::builder(79, 6).build();
        let oracle = start_network(&context, committee.identities.clone(), 4 * 1024 * 1024).await;
        let planes = register_planes(&oracle, &committee.identities[0]).await;
        let engine_context = context.child("split");
        let task_prefix = engine_context.name().label;
        let config = config(&context, &committee, 0, "split");
        let engine = Engine::open(engine_context, config)
            .await
            .expect("engine opens");
        assert_eq!(
            count_running_tasks(&context, &task_prefix),
            0,
            "open spawned a task before start"
        );

        let mut running = engine.start(planes);
        assert!(running.ready().await.is_ok());
        assert!(count_running_tasks(&context, &task_prefix) > 0);
        running.abort();
        assert!(running.join().await.is_err(), "join reports the abort");
        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(count_running_tasks(&context, &task_prefix), 0);
    });
}

#[test_traced]
fn ready_reports_an_engine_stopped_before_readiness() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = Committee::<MinPk>::builder(80, 6).build();
        let oracle = start_network(&context, committee.identities.clone(), 4 * 1024 * 1024).await;
        let planes = register_planes(&oracle, &committee.identities[0]).await;
        let config = config(&context, &committee, 0, "stopped_before_ready");
        let engine = Engine::open(context.child("stopped"), config)
            .await
            .expect("engine opens");
        let mut running = engine.start(planes);
        running.abort();
        assert!(matches!(running.ready().await, Err(Stopped)));
        assert!(running.inspector().inspect().await.is_none());
    });
}

#[test_traced]
fn maximum_timer_durations_do_not_overflow_actor_deadlines() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = Committee::<MinPk>::builder(78, 6).build();
        let oracle = start_network(&context, committee.identities.clone(), 4 * 1024 * 1024).await;
        let planes = register_planes(&oracle, &committee.identities[0]).await;
        let mut config = config(&context, &committee, 0, "maximum_timer_durations");
        config.tuning = Tuning {
            production_interval: Duration::MAX,
            ..Tuning::new(Duration::MAX)
        };

        let engine = Engine::open(context.child("engine"), config)
            .await
            .expect("the voter opens with representable saturated deadlines");
        let _running = engine.start(planes);
    });
}

fn proof_covers_view(proof: &ViewProof<MinPk, Sha256Digest>, requested: View) -> bool {
    match proof {
        ViewProof::Nullification(_) | ViewProof::Vqc(_) => proof.view() == requested,
        ViewProof::Lqc(_) => proof.view() >= requested,
    }
}

/// Returns whether `proofs` serves a proof that crosses `view`.
async fn serves_view(proofs: &resolver::Server<MinPk, Sha256Digest>, view: View) -> bool {
    proofs
        .serve(view)
        .await
        .ok()
        .flatten()
        .is_some_and(|proof| proof_covers_view(&proof, view))
}

#[test]
fn engine_derives_the_protocol_from_the_scheme() {
    let limits = PathLimits::new(2, 1).unwrap();
    let reversed =
        LeaderSchedule::from_order((0..6).rev().map(Participant::new).collect(), 6).unwrap();
    let committee = Committee::<MinPk>::builder(76, 6)
        .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_ENGINE_PROTOCOL_TEST")
        .producers(vec![Participant::new(4), Participant::new(1)])
        .limits(limits)
        .leaders(reversed)
        .build();
    DeterministicRunner::default().start(|context| async move {
        let config = config(&context, &committee, 0, "protocol");
        let profile: Profile<Sha256Digest> = derive_profile(&config).unwrap();

        // The profile shares the scheme's parameters, so the two cannot disagree.
        assert!(Arc::ptr_eq(
            profile.protocol().parameters(),
            config.scheme.parameters()
        ));
        assert_eq!(profile.protocol().genesis(), &config.genesis);
    });
}

#[test]
fn engine_derives_the_role_from_the_scheme() {
    let committee = Committee::<MinPk>::builder(77, 6).build();
    DeterministicRunner::default().start(|context| async move {
        let mut config = config(&context, &committee, 2, "role");
        let validator: Profile<Sha256Digest> = derive_profile(&config).unwrap();
        assert_eq!(validator.role(), Role::Validator(Participant::new(2)));

        config.scheme = committee.verifier.clone();
        let observer: Profile<Sha256Digest> = derive_profile(&config).unwrap();
        assert_eq!(observer.role(), Role::Observer);
    });
}

#[test]
fn invalid_configurations_fail_before_touching_storage() {
    DeterministicRunner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(78, 6).build();
        let other = Committee::<MinPk>::builder(79, 6).build();
        let genesis = other.config.genesis().clone();
        let foreign_genesis = EpochGenesis::new(
            genesis.epoch().next(),
            genesis.leader(),
            genesis.vqc(),
            genesis.lqc(),
            genesis.tips().to_vec(),
        )
        .unwrap();

        for label in ["prefix", "small_artifact", "large_artifact", "genesis"] {
            let mut invalid = config(&context, &committee, 0, label);
            match label {
                "prefix" => invalid.partition_prefix = format!("{label}-hyphenated"),
                "small_artifact" => invalid.tuning.max_artifact_bytes = NonZeroUsize::new(1),
                "large_artifact" => {
                    invalid.tuning.max_artifact_bytes = NonZeroUsize::new(usize::MAX)
                }
                _ => invalid.genesis = foreign_genesis.clone(),
            }
            let partition_prefix = invalid.partition_prefix.clone();
            let Err(OpenError::Config(error)) = Engine::open(context.child(label), invalid).await
            else {
                panic!("{label}: an invalid configuration did not fail validation");
            };
            let expected = match label {
                "prefix" => matches!(error, ConfigError::InvalidPartitionPrefix),
                "small_artifact" => matches!(
                    error,
                    ConfigError::ArtifactByteLimitTooSmall { actual: 1, .. }
                ),
                "large_artifact" => matches!(
                    error,
                    ConfigError::ArtifactByteLimitTooLarge {
                        actual: usize::MAX,
                        ..
                    }
                ),
                _ => matches!(error, ConfigError::GenesisEpoch { .. }),
            };
            assert!(expected, "{label}: {error:?}");
            let partitions = partitions(&partition_prefix);
            for partition in [partitions.journal, partitions.checkpoints] {
                assert!(
                    context
                        .scan(&partition)
                        .await
                        .map_or(true, |blobs| blobs.is_empty()),
                    "{label}: {partition} was created"
                );
            }
        }
    });
}

#[test]
fn an_unset_artifact_byte_limit_resolves_to_the_codec_bound_or_one_mebibyte() {
    DeterministicRunner::default().start(|context| async move {
        for (participants, limits) in [
            (6, PathLimits::new(2, 1).unwrap()),
            (200, PathLimits::new(8, 8).unwrap()),
        ] {
            let committee = Committee::<MinPk>::builder(81, participants)
                .limits(limits)
                .build();
            let config = config(&context, &committee, 0, "resolved");
            let required = committee
                .codec()
                .max_artifact_bytes::<MinPk, Sha256Digest>()
                .unwrap()
                .get();
            let profile: Profile<Sha256Digest> = derive_profile(&config).unwrap();
            assert_eq!(
                profile.resources().max_artifact_bytes(),
                required.max(1024 * 1024),
                "participants={participants}"
            );
        }
    });
}

/// An engine the tests started, with the handle that reads the proofs it serves.
struct Launched {
    running: Running<Sha256Digest>,
    proofs: resolver::Server<MinPk, Sha256Digest>,
}

/// How a test launches validator zero's engine.
struct LaunchOptions<'a> {
    /// Task label of the engine.
    label: &'static str,
    /// Storage partition prefix; the engine stores under `{prefix}_0`.
    prefix: &'a str,
    /// Replayed journal events between machine checkpoints.
    checkpoint_interval: NonZeroU64,
    /// Application the engine builds and verifies with.
    application: MockApplication,
}

impl<'a> LaunchOptions<'a> {
    /// Launches under `label` and `prefix` with the default checkpoint cadence and a fresh
    /// application.
    fn new(label: &'static str, prefix: &'a str) -> Self {
        Self {
            label,
            prefix,
            checkpoint_interval: CHECKPOINT_INTERVAL,
            application: MockApplication::new(),
        }
    }
}

/// Starts validator zero's engine over four freshly registered planes.
async fn launch(
    context: &deterministic::Context,
    oracle: &Oracle<ed25519::PublicKey, deterministic::Context>,
    committee: Committee<MinPk>,
    options: LaunchOptions<'_>,
) -> Launched {
    let LaunchOptions {
        label,
        prefix,
        checkpoint_interval,
        application,
    } = options;
    let planes = register_planes(oracle, &committee.identities[0]).await;
    let mut config = config(context, &committee, 0, prefix);
    config.automaton = application.clone();
    config.relay = application;
    let overrides = Overrides {
        checkpoint_interval,
        ..Overrides::default()
    };
    let engine = Engine::open_with(context.child(label), config, overrides)
        .await
        .expect("engine opens");
    let proofs = engine.proofs();
    Launched {
        running: engine.start(planes),
        proofs,
    }
}

/// Runs validator zero until it produced a block and consumed its persistence barrier, and
/// returns its inspection for an unclean crash at that point.
async fn produce_one_block(
    context: &deterministic::Context,
    seed: u64,
    prefix: &str,
) -> Inspection<Sha256Digest> {
    let committee = Committee::<MinPk>::builder(seed, 6).build();
    let oracle = start_network(context, committee.identities.clone(), 4 * 1024 * 1024).await;
    link_all(&oracle, &committee.identities).await;
    let application = MockApplication::new();
    application.permit_builds(1);
    let mut engine = Box::pin(launch(
        context,
        &oracle,
        committee,
        LaunchOptions {
            application,
            ..LaunchOptions::new("first", prefix)
        },
    ))
    .await;
    assert!(engine.running.ready().await.is_ok());
    // Production is applied before acknowledgement so private work can overlap storage, and is
    // not by itself evidence that recovery can replay it.
    for _ in 0..600 {
        context.sleep(Duration::from_millis(50)).await;
        let inspection = engine
            .running
            .inspector()
            .inspect()
            .await
            .expect("engine runs");
        if inspection.produced_blocks() >= 1
            && inspection.pending_barrier().is_none()
            && inspection.verification_jobs().is_empty()
        {
            return inspection;
        }
    }
    panic!("no block was produced before the crash");
}

/// Recovers validator zero's durable state as `Engine::open` does, without starting actors.
async fn recover_validator(
    context: &deterministic::Context,
    committee: &Committee<MinPk>,
    label: &'static str,
    partition_prefix: &str,
    page_cache: CacheRef,
    checkpoint_interval: NonZeroU64,
    application: &MockApplication,
) -> Result<Recovered<deterministic::Context, Sha256, MinPk>, OpenError> {
    let profile = profile(committee, Role::Validator(Participant::new(0)));
    let inflight_application = inflight_application(&profile);
    let mut store_context = context.child(label);
    Box::pin(recover(
        &mut store_context,
        RecoveryConfig {
            profile,
            partition_prefix,
            scheme: &committee.verifier,
            strategy: &Sequential,
            page_cache,
            checkpoint_interval,
            inflight_application,
        },
        application,
    ))
    .await
}

#[test_traced]
fn recovery_checks_custody_before_compacting_the_suffix() {
    let seed = 73;
    let runner = DeterministicRunner::timed(Duration::from_secs(120));
    let (_, checkpoint) = runner.start_and_recover(|context| async move {
        produce_one_block(&context, seed, "custody").await
    });

    DeterministicRunner::from(checkpoint).start(|context| async move {
        let committee = Committee::<MinPk>::builder(seed, 6).build();
        let page_cache = || CacheRef::from_pooler(&context, paged::page_size(4_096), NZUsize!(8));

        // Compaction is due, but the application no longer holds a recovered payload.
        let failure = recover_validator(
            &context,
            &committee,
            "unverified",
            "custody_0",
            page_cache(),
            NZU64!(1),
            &MockApplication::builder()
                .verify_result(Some(false))
                .build(),
        )
        .await;
        assert!(matches!(
            failure,
            Err(OpenError::RecoveredPayloadUnverified)
        ));

        // The failed fence left the replay suffix in place.
        let recovered = recover_validator(
            &context,
            &committee,
            "verified",
            "custody_0",
            page_cache(),
            CHECKPOINT_INTERVAL,
            &MockApplication::new(),
        )
        .await
        .expect("stores reopen");
        let replayed = recovered.replayed.expect("durable state selects recovery");
        assert!(replayed > 0, "a failed custody fence compacted the suffix");
        drop(recovered);

        // Once custody holds, a due compaction replaces the suffix with a checkpoint that later
        // recoveries restore without replaying anything.
        for label in ["compacting", "compacted"] {
            let recovered = recover_validator(
                &context,
                &committee,
                label,
                "custody_0",
                page_cache(),
                NZU64!(1),
                &MockApplication::new(),
            )
            .await
            .expect("stores recover");
            assert_eq!(recovered.replayed, Some(0));
        }
    });
}

#[test_traced]
fn recovery_verification_precedes_actor_construction_and_dependent_effects() {
    let seed = 72;
    let runner = DeterministicRunner::timed(Duration::from_secs(120));
    let (before, checkpoint) = runner.start_and_recover(|context| async move {
        produce_one_block(&context, seed, "restart").await
    });

    let runner = DeterministicRunner::from(checkpoint);
    runner.start(|context| async move {
        let committee = Committee::<MinPk>::builder(seed, 6).build();
        let oracle = start_network(&context, committee.identities.clone(), 4 * 1024 * 1024).await;
        link_all(&oracle, &committee.identities).await;
        let recovered = recover_validator(
            &context,
            &committee,
            "rebuild",
            "restart_0",
            CacheRef::from_pooler(&context, paged::page_size(4_096), NZUsize!(8)),
            CHECKPOINT_INTERVAL,
            &MockApplication::new(),
        )
        .await
        .expect("stores reopen");
        assert!(
            recovered.replayed.is_some(),
            "durable state must select recovery startup"
        );
        let inspection = recovered.core.machine().inspect();
        assert_same_durable_prefix(&before, &inspection);
        assert!(inspection.is_recovering());
        assert!(!inspection.is_live());
        assert!(
            inspection.produced_blocks() >= 1,
            "recovery restored durable production state"
        );
        assert!(
            !inspection.outbox().is_empty(),
            "recovery restored the outbox"
        );
        let requirements = recovered.core.machine().recovered_payloads();
        assert!(!requirements.is_empty());
        drop(recovered);

        let application = MockApplication::new();
        let mut verification = application.gate_verification();
        application.pause_building();
        let application_log = application.log();
        let mut starting = Box::pin(launch(
            &context,
            &oracle,
            committee,
            LaunchOptions {
                application,
                ..LaunchOptions::new("second", "restart")
            },
        ));
        select! {
            () = verification.wait_started() => {},
            _ = &mut starting => {
                panic!("the recovered engine started before checking application custody");
            },
        }
        assert_eq!(application_log.lock().verifications, requirements);
        assert_eq!(application_log.lock().proposed, 0);
        select! {
            _ = &mut starting => {
                panic!("the recovered engine crossed the pending application custody fence");
            },
            () = context.sleep(Duration::from_millis(100)) => {},
        }
        verification.release();

        let mut engine = starting.await;
        assert!(
            engine.running.ready().await.is_ok(),
            "recovered engine becomes ready"
        );
        let inspection = engine
            .running
            .inspector()
            .inspect()
            .await
            .expect("engine runs");
        assert!(
            inspection.produced_blocks() >= 1,
            "durable production state survived the crash"
        );
        assert!(!inspection.outbox().is_empty(), "the outbox was reissued");
    });
}

#[rstest]
#[case(4_096)]
#[case(16_384)]
#[test_traced]
fn engine_restart_preserves_every_active_publication_family(#[case] physical_page_size: u32) {
    let seed = 75;
    let prefix = "typed_obligation_restart";
    let runner = DeterministicRunner::timed(Duration::from_secs(120));
    let ((first, second), checkpoint) = runner.start_and_recover(|context| async move {
        let fixture = Committee::<MinPk>::builder(seed, 6).build();
        let oracle = start_network(&context, fixture.identities.clone(), 4 * 1024 * 1024).await;
        link_all(&oracle, &fixture.identities).await;

        let peer = fixture.identities[1].clone();
        let (mut data_tx, mut data_rx) = oracle
            .control(peer.clone())
            .register(0, QUOTA)
            .await
            .unwrap();
        let (mut certificates_tx, _) = oracle.control(peer).register(2, QUOTA).await.unwrap();
        let planes = register_planes(&oracle, &fixture.identities[0]).await;
        let application = MockApplication::new();
        application.pause_building();
        application.permit_builds(2);
        let mut engine_config = config(
            &context,
            &Committee::<MinPk>::builder(seed, 6).build(),
            0,
            prefix,
        );
        engine_config.automaton = application.clone();
        engine_config.relay = application;
        engine_config.page_cache =
            CacheRef::from_pooler(&context, paged::page_size(physical_page_size), NZUsize!(2));
        let overrides = Overrides {
            checkpoint_interval: NZU64!(2),
            ..Overrides::default()
        };
        let engine = Engine::open_with(context.child("typed_first"), engine_config, overrides)
            .await
            .expect("engine opens");
        let proofs = engine.proofs();
        let mut engine = engine.start(planes);
        assert!(engine.ready().await.is_ok());

        let mut blocks = Vec::new();
        let deadline = context.current() + Duration::from_secs(5);
        while blocks.len() < 2 {
            select! {
                result = data_rx.recv() => {
                    let (_, bytes) = result.expect("network remains connected");
                    let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                        bytes,
                        &EnvelopeConfig {
                            max_frame_bytes: usize::MAX,
                            epoch: fixture.config.epoch(),
                            payload: fixture.codec(),
                        },
                    )
                    .expect("engine emits canonical data");
                    let DataMessage::Block(block) = envelope.into_payload() else {
                        continue;
                    };
                    if !blocks.iter().any(|existing: &SignedTransactionBlock<_, _>| {
                        existing.header().height() == block.header().height()
                    }) {
                        blocks.push(block);
                        blocks.sort_unstable_by_key(|block| block.header().height());
                    }
                },
                () = context.sleep_until(deadline) => {
                    panic!("engine did not create two active block publications");
                },
            }
        }
        let first = blocks[0].clone();
        let second = blocks[1].clone();
        assert_eq!(first.header().height(), Height::new(1));
        assert_eq!(second.header().height(), Height::new(2));

        // Let the view timeout create the local NoVote/Nullify batch before admitting its
        // exact exit. The two DA blocks remain below the pipeline limit while this happens.
        context.sleep(Duration::from_millis(600)).await;
        let votes = (0..fixture.codec().da_quorum())
            .map(|signer| fixture.da_vote(Participant::from_usize(signer), first.header().clone()))
            .collect::<Vec<_>>();
        let certificate = fixture
            .verifier
            .assemble_da_certificate(&votes, &Sequential)
            .expect("a quorum of valid shares recovers the DA certificate");
        let _ = data_tx.send(
            Recipients::One(fixture.identities[0].clone()),
            Envelope::new(
                fixture.config.epoch(),
                DataMessage::<MinPk, Sha256Digest>::DaCertificate(certificate),
            )
            .encode(),
            false,
        );
        let _ = certificates_tx.send(
            Recipients::One(fixture.identities[0].clone()),
            Envelope::new(
                fixture.config.epoch(),
                CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                    fixture.nullification(View::new(1)),
                ),
            )
            .encode(),
            true,
        );

        let exit_view = View::new(1);
        let deadline = context.current() + Duration::from_secs(10);
        loop {
            let settled = engine
                .inspector()
                .inspect()
                .await
                .is_some_and(|inspection| {
                    inspection.view() >= View::new(2)
                        && inspection
                            .producer()
                            .is_some_and(|producer| producer.certified() >= first.header().height())
                        && inspection.pending_barrier().is_none()
                });
            let view_retained = serves_view(&proofs, exit_view).await;
            if settled && view_retained {
                break;
            }
            assert!(
                context.current() < deadline,
                "typed obligations did not settle"
            );
            context.sleep(Duration::from_millis(25)).await;
        }

        let checkpoint_partition = partitions(&format!("{prefix}_0")).checkpoints;
        let deadline = context.current() + Duration::from_secs(10);
        loop {
            if context
                .scan(&checkpoint_partition)
                .await
                .is_ok_and(|blobs| !blobs.is_empty())
            {
                break;
            }
            assert!(
                context.current() < deadline,
                "checkpoint sync did not complete"
            );
            context.sleep(Duration::from_millis(25)).await;
        }

        // No more application work is permitted and the next view timer is still distant.
        // Give the acknowledged snapshot a quiet interval before the unclean stop.
        context.sleep(Duration::from_millis(100)).await;

        engine.abort();
        assert!(
            engine.join().await.is_err(),
            "the aborted engine reports its abort"
        );
        (first, second)
    });

    DeterministicRunner::from(checkpoint).start(move |context| async move {
        let committee = Committee::<MinPk>::builder(seed, 6).build();
        let recovered = recover_validator(
            &context,
            &committee,
            "typed_stores",
            &format!("{prefix}_0"),
            CacheRef::from_pooler(&context, paged::page_size(physical_page_size), NZUsize!(2)),
            CHECKPOINT_INTERVAL,
            &MockApplication::new(),
        )
        .await
        .expect("stores recover");
        assert!(
            recovered.replayed.is_some(),
            "active typed obligations must select recovery startup"
        );
        let snapshot = recovered.core.machine().live_snapshot_for_test();
        let mut families = BTreeSet::new();
        for entry in snapshot.outbox().values() {
            assert!(!entry.discharges().is_empty());
            for discharge in entry.discharges() {
                match discharge.until() {
                    DischargeKind::BlockCertifiedAtLeast { height, .. } => {
                        assert_eq!(height, second.header().height());
                        families.insert("block");
                    }
                    DischargeKind::VoteCertifiedAtLeast { height, .. } => {
                        assert_eq!(height, second.header().height());
                        families.insert("vote");
                    }
                    DischargeKind::CertificateSupersededAbove { height, .. } => {
                        assert_eq!(height, first.header().height());
                        families.insert("certificate");
                    }
                    DischargeKind::ExitReplacedAfter { view } => {
                        assert_eq!(view, View::new(1));
                        families.insert("exit");
                    }
                    DischargeKind::ViewRetired { .. } => {
                        families.insert("own-message");
                    }
                }
            }
        }
        assert_eq!(
            families,
            BTreeSet::from(["block", "certificate", "exit", "own-message", "vote"])
        );

        drop(recovered);

        let oracle = start_network(&context, committee.identities.clone(), 4 * 1024 * 1024).await;
        link_all(&oracle, &committee.identities).await;
        let mut engine = Box::pin(launch(
            &context,
            &oracle,
            committee,
            LaunchOptions {
                checkpoint_interval: NZU64!(2),
                ..LaunchOptions::new("typed_second", prefix)
            },
        ))
        .await;
        assert!(engine.running.ready().await.is_ok());
        let deadline = context.current() + Duration::from_secs(10);
        loop {
            let exit_view = View::new(1);
            let view_ready = serves_view(&engine.proofs, exit_view).await;
            if view_ready {
                break;
            }
            assert!(
                context.current() < deadline,
                "recovered view proof did not become ready"
            );
            context.sleep(Duration::from_millis(25)).await;
        }
    });
}
