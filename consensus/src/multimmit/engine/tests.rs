//! Engine configuration validation, lifecycle, and restart tests.

use super::{
    ActorLimits, CHECKPOINT_INTERVAL, Config, Engine, Planes, Readiness, Running, Stopped,
    critical_threads, derive_profile,
};
use crate::{
    multimmit::{
        actors::voter::{Observed, VoterLimits},
        config::{Error as ConfigError, Profile, Role, Tuning},
        mocks::{
            Committee, MockApplication, NoopReporter,
            cluster::{
                CERTIFICATE_CHANNEL, CONSENSUS_CHANNEL, Cluster, ClusterOptions, DATA_CHANNEL,
                QUOTA, RESOLVER_CHANNEL, link_all, start_network,
            },
        },
        storage::{OpenError, partitions},
        testing::decode_frame,
        types::{SignedTransactionBlock, VoteUpdate},
        wire::{ConsensusMessage, DataMessage, Plane},
    },
    types::{Participant, View},
};
use commonware_actor::{Feedback, Unreliable};
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::MinPk, ed25519, sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_traced};
use commonware_p2p::{
    Receiver as _,
    simulated::{Oracle, Receiver as SimulatedReceiver, Sender as SimulatedSender},
    utils::mocks::NoopBlocker,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Clock as _, Runner as _, Storage as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic::{self, Runner},
    telemetry::metrics::count_running_tasks,
};
use commonware_utils::{NZU64, NZUsize, channel::oneshot};
use rstest::rstest;
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc, time::Duration};
use tracing::Span;

type TestConfig = Config<
    Sha256,
    ed25519::PublicKey,
    MinPk,
    MockApplication,
    MockApplication,
    NoopReporter<MinPk, Sha256Digest>,
    Sequential,
    Sequential,
    NoopBlocker<ed25519::PublicKey>,
>;

type TestPlanes = Planes<
    SimulatedSender<ed25519::PublicKey, deterministic::Context>,
    SimulatedReceiver<ed25519::PublicKey>,
>;

/// Registers `identity`'s four engine planes.
async fn register_planes(
    oracle: &Oracle<ed25519::PublicKey, deterministic::Context>,
    identity: &ed25519::PublicKey,
) -> TestPlanes {
    let control = oracle.control(identity.clone());
    Planes {
        data: control.register(DATA_CHANNEL, QUOTA).await.unwrap(),
        consensus: control.register(CONSENSUS_CHANNEL, QUOTA).await.unwrap(),
        certificates: control.register(CERTIFICATE_CHANNEL, QUOTA).await.unwrap(),
        resolver: control.register(RESOLVER_CHANNEL, QUOTA).await.unwrap(),
    }
}

fn tuning() -> Tuning {
    Tuning {
        timer_ceiling: Duration::from_secs(5),
        ..Tuning::new()
    }
}

/// Configures participant `index` of `committee` to store under `{prefix}_{index}`.
fn config(
    pooler: &impl BufferPooler,
    committee: &Committee<MinPk>,
    index: usize,
    prefix: &str,
    page_size: u32,
) -> TestConfig {
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
        page_cache: CacheRef::from_pooler(pooler, paged::page_size(page_size), NZUsize!(8)),
        mailbox_size: NonZeroUsize::new(128).unwrap(),
    }
}

#[test]
fn the_view_critical_pool_scales_with_the_committee() {
    for (participants, threads) in [(1, 2), (6, 2), (16, 2), (32, 4), (50, 6), (100, 12)] {
        assert_eq!(
            critical_threads(participants).get(),
            threads,
            "participants={participants}"
        );
    }
}

#[test]
fn voter_limits_are_nonzero_and_overflow_safe() {
    let committee = Committee::<MinPk>::builder(70, 6).build();
    for ceiling in [Duration::from_nanos(1), Duration::MAX] {
        let tuning = Tuning {
            delta_initial: ceiling,
            delta_min: ceiling,
            timer_ceiling: ceiling,
            ..Tuning::new()
        };
        let profile: Profile<Sha256Digest> =
            Profile::new::<MinPk>(committee.config.clone(), Role::Observer, tuning).unwrap();
        let limits = VoterLimits::from_profile(&profile, CHECKPOINT_INTERVAL);
        assert!(!limits.retry_initial.is_zero(), "ceiling={ceiling:?}");
        assert!(
            limits.retry_initial <= limits.retry_ceiling,
            "ceiling={ceiling:?}"
        );
        assert!(
            limits.retry_ceiling <= limits.heartbeat,
            "ceiling={ceiling:?}"
        );
    }
}

#[test]
fn the_engine_derives_its_protocol_and_role_from_the_scheme() {
    let committee = Committee::<MinPk>::builder(71, 6).build();
    Runner::default().start(|context| async move {
        let mut config = config(&context, &committee, 2, "derive", 4_096);
        let validator: Profile<Sha256Digest> = derive_profile(&config).unwrap();
        assert!(Arc::ptr_eq(
            validator.protocol().parameters(),
            config.scheme.parameters()
        ));
        assert_eq!(validator.protocol().genesis(), &config.genesis);
        assert_eq!(validator.role(), Role::Validator(Participant::new(2)));

        config.scheme = committee.verifier.clone();
        let observer: Profile<Sha256Digest> = derive_profile(&config).unwrap();
        assert_eq!(observer.role(), Role::Observer);
    });
}

#[test]
fn invalid_configurations_fail_before_touching_storage() {
    type Invalidate = fn(&mut TestConfig, &Committee<MinPk>);
    type Expect = fn(&ConfigError) -> bool;
    let cases: [(&str, Invalidate, Expect); 5] = [
        (
            "prefix",
            |config, _| config.partition_prefix = "hyphenated-prefix".into(),
            |error| matches!(error, ConfigError::InvalidPartitionPrefix),
        ),
        (
            "genesis",
            |config, other| config.genesis = other.config.genesis().clone(),
            |error| matches!(error, ConfigError::GenesisEpoch { .. }),
        ),
        (
            "small_artifact",
            |config, _| config.tuning.max_artifact_bytes = NonZeroUsize::new(1),
            |error| {
                matches!(
                    error,
                    ConfigError::ArtifactByteLimitTooSmall { actual: 1, .. }
                )
            },
        ),
        (
            "large_artifact",
            |config, _| config.tuning.max_artifact_bytes = NonZeroUsize::new(usize::MAX),
            |error| matches!(error, ConfigError::ArtifactByteLimitTooLarge { .. }),
        ),
        (
            "delay_bounds",
            |config, _| config.tuning.delta_min = config.tuning.timer_ceiling * 2,
            |error| matches!(error, ConfigError::DelayBounds { .. }),
        ),
    ];
    Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(72, 6).build();
        let other = Committee::<MinPk>::builder(73, 6).build();
        for (label, invalidate, expected) in cases {
            let mut invalid = config(&context, &committee, 0, label, 4_096);
            invalidate(&mut invalid, &other);
            let partition_prefix = invalid.partition_prefix.clone();
            let Err(OpenError::Config(error)) = Engine::open(context.child(label), invalid).await
            else {
                panic!("{label}: an invalid configuration opened");
            };
            assert!(expected(&error), "{label}: {error:?}");
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

#[test_traced]
fn readiness_wait_survives_cancellation_and_remembers_failure() {
    Runner::default().start(|context| async move {
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

#[test]
fn the_voter_queues_every_observation_cohort_ingress_may_credit() {
    Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = Committee::<MinPk>::builder(75, 6).build();
        let mut config = config(&context, &committee, 0, "credits", 4_096);
        config.mailbox_size = NonZeroUsize::MIN;
        let profile = derive_profile(&config).expect("the test configuration is valid");
        let capacity = ActorLimits::from_profile::<MinPk, _>(&profile, CHECKPOINT_INTERVAL)
            .observation_capacity
            .get();
        assert!(capacity > config.mailbox_size.get());
        let engine = Engine::open(context.child("engine"), config)
            .await
            .expect("engine opens");

        // Nothing drains the queue before start, so it must hold every cohort ingress may have
        // in flight, however small the configured mailboxes are.
        let observations = &engine.actors.voter_mailbox.observations;
        for _ in 0..capacity {
            let cohort = Observed {
                artifacts: Vec::new(),
                bytes: 0,
                plane: Plane::Consensus,
                span: Span::none(),
                forwarded_at: context.current(),
            };
            assert!(matches!(
                observations.observed(cohort),
                Unreliable::Outcome(Feedback::Ok)
            ));
        }
    });
}

#[test_traced]
fn open_spawns_nothing_until_start_and_join_reports_an_abort() {
    Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = Committee::<MinPk>::builder(74, 6).build();
        let oracle = start_network(&context, committee.identities.clone(), 4 * 1024 * 1024).await;
        let planes = register_planes(&oracle, &committee.identities[0]).await;
        let engine_context = context.child("engine");
        let task_prefix = engine_context.name().label;
        let engine = Engine::open(
            engine_context,
            config(&context, &committee, 0, "split", 4_096),
        )
        .await
        .expect("engine opens");
        assert_eq!(
            count_running_tasks(&context, &task_prefix),
            0,
            "open spawned a task before start"
        );

        let mut running = engine.start(planes);
        assert!(running.ready().await.is_ok());
        assert!(
            running
                .inspector()
                .inspect()
                .await
                .is_some_and(|inspection| inspection.is_live())
        );
        assert!(count_running_tasks(&context, &task_prefix) > 0);
        running.abort();
        assert!(running.join().await.is_err(), "join reports the abort");
        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(count_running_tasks(&context, &task_prefix), 0);
    });
}

#[test_traced]
fn ready_reports_an_engine_stopped_before_readiness() {
    Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = Committee::<MinPk>::builder(75, 6).build();
        let oracle = start_network(&context, committee.identities.clone(), 4 * 1024 * 1024).await;
        let planes = register_planes(&oracle, &committee.identities[0]).await;
        let engine = Engine::open(
            context.child("engine"),
            config(&context, &committee, 0, "stopped", 4_096),
        )
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
    Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = Committee::<MinPk>::builder(76, 6).build();
        let oracle = start_network(&context, committee.identities.clone(), 4 * 1024 * 1024).await;
        let planes = register_planes(&oracle, &committee.identities[0]).await;
        let mut config = config(&context, &committee, 0, "maximum", 4_096);
        config.tuning = Tuning {
            vote_interval: Duration::MAX,
            delta_initial: Duration::MAX,
            theta_initial: Duration::MAX,
            timer_ceiling: Duration::MAX,
            ..Tuning::new()
        };
        let engine = Engine::open(context.child("engine"), config)
            .await
            .expect("saturated timer durations are valid");
        let mut running = engine.start(planes);
        assert!(running.ready().await.is_ok());
        context.sleep(Duration::from_secs(1)).await;
        assert!(
            running
                .inspector()
                .inspect()
                .await
                .is_some_and(|inspection| inspection.is_live())
        );
    });
}

/// What a peer saw participant zero publish: its headers by height, and its vote updates by view
/// and sequence number.
#[derive(Default)]
struct Published {
    headers: BTreeMap<u64, SignedTransactionBlock<MinPk, Sha256Digest>>,
    updates: BTreeMap<(View, u32), VoteUpdate<MinPk, Sha256Digest>>,
}

impl Published {
    /// Receives from participant zero until `done` holds, asserting that no header height and
    /// no update slot is ever published with two contents.
    async fn observe(
        &mut self,
        context: &deterministic::Context,
        committee: &Committee<MinPk>,
        data: &mut SimulatedReceiver<ed25519::PublicKey>,
        consensus: &mut SimulatedReceiver<ed25519::PublicKey>,
        mut done: impl FnMut(&Self) -> bool,
    ) {
        let deadline = context.current() + Duration::from_secs(10);
        while !done(self) {
            select! {
                result = data.recv() => {
                    let DataMessage::Block(block) = decode_frame(committee, result.unwrap().1);
                    let height = block.header().height().get();
                    let previous = self.headers.entry(height).or_insert_with(|| block.clone());
                    assert_eq!(*previous, block, "height {height} was signed twice");
                },
                result = consensus.recv() => {
                    let message: ConsensusMessage<MinPk, Sha256Digest> =
                        decode_frame(committee, result.unwrap().1);
                    if let ConsensusMessage::Update(update) = message {
                        let slot = (update.round().view(), update.seq());
                        let previous = self.updates.entry(slot).or_insert_with(|| update.clone());
                        assert_eq!(*previous, update, "update {slot:?} was signed twice");
                    }
                },
                () = context.sleep_until(deadline) => panic!("publications did not arrive"),
            }
        }
    }
}

/// Starts participant zero of a fixed committee under `label`, permitting `builds` blocks, and
/// returns peer one's data and consensus receivers.
async fn start_participant_zero(
    context: &deterministic::Context,
    label: &'static str,
    page_size: u32,
    builds: u64,
) -> (
    Committee<MinPk>,
    Running<Sha256Digest>,
    SimulatedReceiver<ed25519::PublicKey>,
    SimulatedReceiver<ed25519::PublicKey>,
) {
    let committee = Committee::<MinPk>::builder(77, 6).build();
    let oracle = start_network(context, committee.identities.clone(), 4 * 1024 * 1024).await;
    link_all(&oracle, &committee.identities).await;
    let peer = oracle.control(committee.identities[1].clone());
    let (_, data) = peer.register(DATA_CHANNEL, QUOTA).await.unwrap();
    let (_, consensus) = peer.register(CONSENSUS_CHANNEL, QUOTA).await.unwrap();
    let planes = register_planes(&oracle, &committee.identities[0]).await;
    let config = config(context, &committee, 0, "restart", page_size);
    config.automaton.pause_building();
    config.automaton.permit_builds(builds);
    let engine = Engine::open(context.child(label), config)
        .await
        .expect("engine opens");
    let mut running = engine.start(planes);
    assert!(running.ready().await.is_ok());
    (committee, running, data, consensus)
}

#[rstest]
#[case(4_096)]
#[case(16_384)]
#[test_traced]
fn an_unclean_restart_resumes_owed_publications_without_conflicting_signatures(
    #[case] page_size: u32,
) {
    let runner = Runner::timed(Duration::from_secs(60));
    let (before, checkpoint) = runner.start_and_recover(|context| async move {
        let (committee, running, mut data, mut consensus) =
            start_participant_zero(&context, "first", page_size, 2).await;
        let mut published = Published::default();
        published
            .observe(
                &context,
                &committee,
                &mut data,
                &mut consensus,
                |published| published.headers.len() == 2 && !published.updates.is_empty(),
            )
            .await;
        // Every publication seen was released after its barrier synced, so it survives the cut.
        running.abort();
        let _ = running.join().await;
        published
    });

    Runner::from(checkpoint).start(move |context| async move {
        let (committee, running, mut data, mut consensus) =
            start_participant_zero(&context, "second", page_size, 0).await;
        // Neither header reached its height quorum, so both are owed again and resent
        // identically, and the recovered vote slot continues above every update sent before
        // the cut.
        let last = *before.updates.keys().next_back().unwrap();
        let mut after = Published::default();
        after
            .observe(
                &context,
                &committee,
                &mut data,
                &mut consensus,
                |published| {
                    published.headers.len() == 2
                        && published.updates.keys().any(|slot| *slot > last)
                },
            )
            .await;
        assert_eq!(after.headers, before.headers);
        for (slot, update) in &after.updates {
            if let Some(previous) = before.updates.get(slot) {
                assert_eq!(
                    previous, update,
                    "update {slot:?} was re-signed after recovery"
                );
            }
        }
        let inspection = running.inspector().inspect().await.expect("engine runs");
        assert_eq!(
            inspection
                .producer()
                .map(|producer| producer.produced().get()),
            Some(2)
        );
        assert!(inspection.outbox_len() > 0);
    });
}

#[test_traced]
fn frequent_checkpoints_prune_the_journal_and_survive_a_crash() {
    Runner::timed(Duration::from_secs(600)).start(|context| async move {
        let wait = Duration::from_secs(120);
        let mut cluster = Cluster::<MinPk>::new(&context, ClusterOptions::new(13, 6)).await;
        cluster.set_checkpoint_interval(NZU64!(8));
        cluster.start_all().await;
        cluster.produce();
        let all = cluster.all_nodes();
        cluster.wait_delivered(&all, 50, wait).await;

        // Live checkpoints every few events roll the journal and prune the sections behind them;
        // a section freshly rolled to holds no blob until its first append.
        for &node in &all {
            let sections = cluster.journal_sections(node).await;
            assert!(
                !sections.contains(&0),
                "node {node} still holds its first journal section: {sections:?}"
            );
            assert!(sections.len() <= 2, "node {node} retains {sections:?}");
        }

        // A crashed node recovers from its newest checkpoint and the suffix after it.
        cluster.crash(5).await;
        let rest = [0, 1, 2, 3, 4];
        let target = cluster.deliveries(0).last().map_or(0, |index| index.get()) + 30;
        cluster.wait_delivered(&rest, target, wait).await;
        cluster.restart(5).await;
        cluster.wait_delivered(&all, target + 30, wait).await;
        assert!(cluster.journal_sections(5).await.len() <= 2);
        cluster.assert_resolutions_agree(&all);
        cluster.assert_deliveries_agree(&all);
    });
}
