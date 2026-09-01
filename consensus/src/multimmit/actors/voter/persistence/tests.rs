//! Persistence actor tests: append, sync, and flush scheduling, checkpoint cuts, and metrics.

use super::{metrics::Metrics, *};
use crate::{
    multimmit::{
        config::{Profile, Role, Tuning},
        machine::{
            BatchId, Change, CoreState, Cursor, DomainEvent, DomainEventCodecConfig, Generation,
            PersistJob, Snapshot, SnapshotCodecConfig,
        },
        mocks::Committee,
        storage::{JournalConfig, JournalRecord, SafetyJournal, SnapshotStore},
        testing::SpanRecorder,
        types::{CodecConfig, PathLimits},
    },
    types::{Epoch, Participant, View},
};
use commonware_actor::mailbox;
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
};
use commonware_runtime::{
    BufferPooler, Clock as _, Handle, Metrics as _, Runner as _, Spawner, Storage, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic,
    mocks::{
        DeferredSync, DelayedSyncContext, PendingSyncs, drive_pending_syncs, next_pending_sync,
    },
    telemetry::metrics::metric_sum,
    utils::reschedule,
};
use commonware_storage::Context as StorageContext;
use commonware_utils::{NZU16, NZUsize};
use std::{num::NonZeroUsize, time::Duration};
use tracing::Span;
use tracing_subscriber::prelude::*;

type TestJob = PersistJob<MinPk, Sha256Digest>;
type DelayedContext = DelayedSyncContext<deterministic::Context>;
type Outputs = mailbox::Receiver<Output<MinPk, Sha256Digest>>;

const SEED: u64 = 7;

fn event_codec() -> DomainEventCodecConfig {
    DomainEventCodecConfig::new(
        CodecConfig::new(1, 1, PathLimits::new(1, 0).unwrap()).unwrap(),
        4096,
        16,
        16,
    )
}

fn config(context: &impl BufferPooler, partition: &str, epoch: Epoch) -> JournalConfig {
    JournalConfig {
        partition: partition.to_owned(),
        epoch,
        event_codec: event_codec(),
        max_events_per_record: NZUsize!(4),
        max_record_bytes: NZUsize!(16 * 1024),
        page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8)),
        write_buffer: NZUsize!(16 * 1024),
        replay_buffer: NZUsize!(16 * 1024),
    }
}

fn job(epoch: Epoch, barrier: u64, previous: u64, urgent: bool) -> TestJob {
    let generation = 1;
    PersistJob::new(
        BatchId::new(barrier),
        Generation::new(generation),
        Cursor::new(previous),
        vec![DomainEvent::new(
            epoch,
            Cursor::new(previous + 1),
            Change::GenerationAdvanced(Generation::new(generation + barrier)),
        )],
        urgent,
    )
}

fn profile() -> Profile<Sha256Digest> {
    let committee = Committee::<MinPk>::builder(SEED, 6).build();
    Profile::new::<MinPk>(
        committee.config,
        Role::Validator(Participant::new(0)),
        Tuning::default(),
    )
    .unwrap()
}

/// Returns the cut of a fresh machine, which has nothing staged.
fn cut() -> Snapshot<MinPk, Sha256Digest> {
    CoreState::<Sha256, MinPk>::fresh(profile())
        .unwrap()
        .machine()
        .checkpoint_cut()
        .expect("a fresh machine is quiescent")
}

fn origin() -> CheckpointOrigin {
    CheckpointOrigin {
        epoch: Epoch::new(8),
        view: View::new(1),
        cursor: Cursor::zero(),
        retired_views: View::zero(),
    }
}

async fn open_empty<E>(
    context: &E,
    partition: &str,
    epoch: Epoch,
) -> SafetyJournal<E, MinPk, Sha256Digest>
where
    E: BufferPooler + commonware_runtime::Metrics + Storage + Spawner,
{
    let mut recovery = SafetyJournal::open(
        context.child("open"),
        config(context, partition, epoch),
        Cursor::zero(),
    )
    .await
    .unwrap();
    assert!(recovery.next().await.unwrap().is_none());
    recovery.finish().unwrap()
}

async fn open_checkpoints<E: StorageContext + Spawner>(
    context: &E,
    partition: &str,
) -> SnapshotStore<E, MinPk, Sha256Digest> {
    let (store, snapshot) = SnapshotStore::open(
        context.child("checkpoints"),
        format!("{partition}-checkpoints"),
        SnapshotCodecConfig::from_profile(&profile()),
        Epoch::new(8),
    )
    .await
    .unwrap();
    assert!(snapshot.is_none());
    store
}

/// Stores over a context whose started syncs park until a test releases them.
struct Delayed {
    context: DelayedContext,
    journal: SafetyJournal<DelayedContext, MinPk, Sha256Digest>,
    checkpoints: SnapshotStore<DelayedContext, MinPk, Sha256Digest>,
    pending: PendingSyncs,
    baseline: usize,
}

async fn open_delayed(context: deterministic::Context, partition: &str, epoch: Epoch) -> Delayed {
    let pending = PendingSyncs::default();
    let context = DelayedSyncContext {
        inner: context,
        pending: pending.clone(),
    };
    let journal = drive_pending_syncs(&pending, open_empty(&context, partition, epoch)).await;
    let checkpoints = drive_pending_syncs(&pending, open_checkpoints(&context, partition)).await;
    let baseline = pending.starts();
    Delayed {
        context,
        journal,
        checkpoints,
        pending,
        baseline,
    }
}

/// A started actor and the ends of its mailbox and output.
struct Running<E: StorageContext + Spawner> {
    client: Mailbox<Sha256, MinPk>,
    flusher: Flusher,
    outputs: Outputs,
    metrics: Metrics,
    handle: Handle<()>,
    context: E,
}

fn start<E: StorageContext + Spawner>(
    context: E,
    journal: SafetyJournal<E, MinPk, Sha256Digest>,
    checkpoints: SnapshotStore<E, MinPk, Sha256Digest>,
    capacity: NonZeroUsize,
    gates: TestGates,
) -> Running<E> {
    let (output, outputs) = mailbox::new(context.child("output"), capacity);
    let flushes = Flushes::default();
    let flusher = flushes.flusher();
    let (actor, client) = Actor::new(
        context.child("owner"),
        Config {
            journal,
            checkpoints,
            capacity,
            output,
            snapshot_tasks: context.child("snapshots"),
            flushes,
            hooks: gates,
        },
    );
    let metrics = actor.metrics();
    Running {
        client,
        flusher,
        outputs,
        metrics,
        handle: actor.start(),
        context,
    }
}

impl Delayed {
    fn start(self, capacity: NonZeroUsize, gates: TestGates) -> Running<DelayedContext> {
        start(
            self.context,
            self.journal,
            self.checkpoints,
            capacity,
            gates,
        )
    }
}

/// Receives the next output, which must be a durability.
async fn durable(outputs: &mut Outputs) -> Durable<MinPk, Sha256Digest> {
    match outputs.recv().await {
        Some(Output::Durable(durable)) => durable,
        Some(_) => panic!("expected a durability"),
        None => panic!("the actor stopped"),
    }
}

async fn wait_for_starts(pending: &PendingSyncs, expected: usize) {
    for _ in 0..128 {
        if pending.starts() >= expected {
            return;
        }
        reschedule().await;
    }
    assert_eq!(pending.starts(), expected, "prefix sync did not start");
}

async fn wait_for_pending(metrics: &Metrics, expected: usize) {
    for _ in 0..128 {
        if usize::try_from(metrics.pending_barriers.get()).unwrap() == expected {
            return;
        }
        reschedule().await;
    }
    assert_eq!(
        usize::try_from(metrics.pending_barriers.get()).unwrap(),
        expected,
        "persistence actor did not retain the expected barrier count"
    );
}

async fn release_next(pending: &PendingSyncs) {
    let DeferredSync { release, blocked } = next_pending_sync(pending);
    blocked.await.expect("the sync handle must be polled");
    release.send(Ok(())).expect("the sync is still waiting");
}

async fn finish(running: Running<DelayedContext>, pending: &PendingSyncs) {
    let Running { client, handle, .. } = running;
    drop(client);
    drive_pending_syncs(pending, handle)
        .await
        .expect("persistence actor must stop cleanly");
}

fn assert_histogram(context: &DelayedContext, name: &str, count: u64, sum: f64) {
    let encoded = context.inner.encode();
    assert_eq!(
        metric_sum(&encoded, &format!("{name}_count"), &[]),
        count as f64
    );
    let actual_sum = metric_sum(&encoded, &format!("{name}_sum"), &[]);
    assert!(
        (actual_sum - sum).abs() < 1e-12,
        "expected histogram sum {sum}, got {}",
        actual_sum
    );
}

#[test]
fn processing_spans_begin_at_dequeue() {
    let spans = SpanRecorder::default();
    tracing::subscriber::with_default(tracing_subscriber::registry().with(spans.clone()), || {
        deterministic::Runner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let stores = open_delayed(context, "persistence_tracing", epoch).await;
            let gates = TestGates::default();
            let mut gate = gates.arm_next_append();
            let pending = stores.pending.clone();
            let baseline = stores.baseline;
            let mut running = stores.start(NZUsize!(8), gates);
            let callers = [
                tracing::info_span!("first_persist"),
                tracing::info_span!("second_persist"),
            ];
            running
                .client
                .append(Span::none(), callers[0].clone(), job(epoch, 1, 0, true))
                .unwrap();
            running
                .client
                .append(Span::none(), callers[1].clone(), job(epoch, 2, 1, false))
                .unwrap();
            assert!(
                !spans
                    .spans()
                    .iter()
                    .any(|span| span.name.starts_with("multimmit.voter.journal."))
            );
            gate.wait_entered().await;
            let processing = spans.named("multimmit.voter.journal.append.process");
            assert_eq!(
                processing.len(),
                1,
                "only the dequeued append has a processing child"
            );
            assert_eq!(
                processing[0].parent,
                callers[0].id().map(|id| id.into_u64())
            );
            assert!(!processing[0].closed());
            gate.release();
            wait_for_starts(&pending, baseline + 1).await;
            let processing = spans.named("multimmit.voter.journal.append.process");
            for caller in &callers {
                assert!(
                    processing
                        .iter()
                        .any(|span| span.parent == caller.id().map(|id| id.into_u64())
                            && span.closed()),
                    "append processing ends before its durability wait"
                );
            }
            release_next(&pending).await;
            assert_eq!(
                durable(&mut running.outputs).await.span.id(),
                callers[0].id()
            );
            assert_eq!(
                durable(&mut running.outputs).await.span.id(),
                callers[1].id()
            );
            assert_eq!(pending.starts(), baseline + 1);

            let roll = tracing::info_span!("ready_roll");
            running
                .client
                .checkpoint(cut(), origin(), roll.clone())
                .unwrap();
            let outputs = &mut running.outputs;
            drive_pending_syncs(&pending, async move {
                assert!(matches!(outputs.recv().await, Some(Output::Stored)));
                assert!(matches!(outputs.recv().await, Some(Output::Pruned)));
            })
            .await;
            let first = |name| {
                spans
                    .first(name)
                    .unwrap_or_else(|| panic!("missing span {name}"))
            };
            assert_eq!(
                first("multimmit.voter.journal.roll.process").parent,
                roll.id().map(|id| id.into_u64())
            );
            assert_eq!(first("multimmit.voter.checkpoint.store").parent, None);
            assert_eq!(first("multimmit.voter.checkpoint.prune").parent, None);
            assert_eq!(
                first("multimmit.voter.journal.prune.process").parent,
                Some(first("multimmit.voter.checkpoint.prune").id)
            );
            finish(running, &pending).await;
        });
    });
}

#[test]
fn metrics_names_match_dashboard() {
    deterministic::Runner::default().start(|context| async move {
        let journal = context
            .child("engine")
            .child("voter")
            .child("driver")
            .child("journal");
        let metrics = Metrics::new(&journal);
        metrics.appended_barriers.inc();
        metrics.appended_events.inc();
        metrics.appended_bytes.inc();
        metrics.start_syncs.inc();
        metrics.durable_barriers.inc();
        metrics.prefix_depth.observe(1.0);
        metrics.barrier_latency.observe(0.001);
        metrics.urgent_tail_latency.observe(0.001);

        let encoded = context.encode();
        for name in [
            "engine_voter_driver_journal_appended_barriers_total",
            "engine_voter_driver_journal_appended_events_total",
            "engine_voter_driver_journal_appended_bytes_total",
            "engine_voter_driver_journal_start_syncs_total",
            "engine_voter_driver_journal_durable_barriers_total",
            "engine_voter_driver_journal_prefix_depth_count",
            "engine_voter_driver_journal_prefix_depth_sum",
            "engine_voter_driver_journal_barrier_latency_count",
            "engine_voter_driver_journal_barrier_latency_sum",
            "engine_voter_driver_journal_urgent_tail_latency_count",
            "engine_voter_driver_journal_urgent_tail_latency_sum",
            "engine_voter_driver_journal_pending_barriers",
            "engine_voter_driver_journal_pending_bytes",
            "engine_voter_driver_journal_covered_barriers",
            "engine_voter_driver_journal_uncovered_barriers",
            "engine_voter_driver_journal_uncovered_bytes",
            "engine_voter_driver_journal_sync_in_flight",
            "engine_voter_driver_journal_max_prefix_depth",
            "engine_voter_driver_journal_max_unsynced_bytes",
            "engine_voter_driver_journal_max_unsynced_age_milliseconds",
        ] {
            assert!(
                encoded.lines().any(|line| {
                    line.strip_prefix(name)
                        .is_some_and(|suffix| suffix.starts_with(' ') || suffix.starts_with('{'))
                }),
                "missing exact metric {name}: {encoded}"
            );
        }
        assert!(!encoded.contains("engine_voter_journal_"));
    });
}

#[test]
fn performance_gate_prefix_pipeline() {
    deterministic::Runner::default().start(|context| async move {
        const TAIL_BARRIERS: usize = 8;
        const FIRST_SYNC_LATENCY: Duration = Duration::from_millis(25);
        const TAIL_SYNC_LATENCY: Duration = Duration::from_millis(10);
        const EXPECTED_URGENT_TAIL_DELAY: Duration = Duration::from_millis(22);
        // The actor observes a released sync one scheduler cycle after the release.
        const ACTOR_HOP: Duration = Duration::from_millis(1);

        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-performance-prefix", epoch).await;
        let gates = TestGates::default();
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NZUsize!(16), gates.clone());
        let context = &running.context;
        let metrics = running.metrics.clone();

        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, true))
            .unwrap();
        wait_for_starts(&pending, baseline + 1).await;
        let DeferredSync { release, blocked } = next_pending_sync(&pending);
        let first_release = context
            .child("first_release")
            .spawn(move |context| async move {
                blocked.await.expect("the first sync handle must be polled");
                let started_at = context.current();
                context.sleep(FIRST_SYNC_LATENCY).await;
                let released_at = context.current();
                release.send(Ok(())).expect("the first sync is waiting");
                (started_at, released_at)
            });

        let tail_bytes = (2..=TAIL_BARRIERS as u64 + 1)
            .map(|barrier| {
                JournalRecord::encoded_size(&job(
                    epoch,
                    barrier,
                    barrier - 1,
                    barrier == TAIL_BARRIERS as u64 + 1,
                ))
            })
            .sum::<usize>();
        let mut tail_append_gate = gates.arm_after_append();
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 2, 1, false))
            .unwrap();
        let tail_appended_at = tail_append_gate.wait_entered_at().await;
        tail_append_gate.release();
        for barrier in 3..=TAIL_BARRIERS as u64 {
            running
                .client
                .append(
                    Span::none(),
                    Span::none(),
                    job(epoch, barrier, barrier - 1, false),
                )
                .unwrap();
        }
        let mut urgent_append_gate = gates.arm_after_append();
        running
            .client
            .append(
                Span::none(),
                Span::none(),
                job(epoch, TAIL_BARRIERS as u64 + 1, TAIL_BARRIERS as u64, true),
            )
            .unwrap();
        let _urgent_appended_at = urgent_append_gate.wait_entered_at().await;
        urgent_append_gate.release();
        wait_for_pending(&metrics, TAIL_BARRIERS + 1).await;

        assert_eq!(
            pending.starts(),
            baseline + 1,
            "appends behind a sync must not start a concurrent prefix sync"
        );
        assert_eq!(metrics.start_syncs.get(), 1);
        assert_eq!(metrics.appended_barriers.get(), TAIL_BARRIERS as u64 + 1);
        assert_eq!(
            usize::try_from(metrics.pending_barriers.get()).unwrap(),
            TAIL_BARRIERS + 1
        );
        assert_eq!(
            usize::try_from(metrics.uncovered_barriers.get()).unwrap(),
            TAIL_BARRIERS
        );
        assert_eq!(metrics.covered_barriers.get(), 1);
        assert_eq!(metrics.sync_in_flight.get(), 1);
        assert_eq!(metrics.appended_events.get(), TAIL_BARRIERS as u64 + 1);
        assert_eq!(
            usize::try_from(metrics.appended_bytes.get()).unwrap(),
            JournalRecord::encoded_size(&job(epoch, 1, 0, true)) + tail_bytes
        );
        assert_eq!(metrics.max_prefix_depth.get(), 1);
        assert_histogram(context, "owner_prefix_depth", 1, 1.0);
        assert_histogram(context, "owner_urgent_tail_latency", 0, 0.0);

        let mut tail_start_gate = gates.arm_next_start_sync();
        let (first_sync_started_at, first_released_at) = first_release.await.unwrap();
        assert_eq!(
            first_released_at
                .duration_since(first_sync_started_at)
                .unwrap(),
            FIRST_SYNC_LATENCY
        );
        let tail_sync_started_at = tail_start_gate.wait_entered_at().await;
        // The first prefix is reported before the tail sync begins.
        let Ok(Output::Durable(first)) = running.outputs.try_recv() else {
            panic!("the first prefix is durable");
        };
        assert_eq!(first.ack.barrier(), BatchId::new(1));
        assert!(
            running.outputs.try_recv().is_err(),
            "the tail is not durable yet"
        );
        tail_start_gate.release();
        wait_for_starts(&pending, baseline + 2).await;
        assert_eq!(metrics.start_syncs.get(), 2);
        assert_eq!(
            metrics.durable_barriers.get(),
            1,
            "only the first covered prefix is durable"
        );
        assert_eq!(
            usize::try_from(metrics.covered_barriers.get()).unwrap(),
            TAIL_BARRIERS
        );
        assert_eq!(metrics.uncovered_barriers.get(), 0);
        assert_eq!(metrics.max_prefix_depth.get(), TAIL_BARRIERS as i64);
        assert_eq!(
            usize::try_from(metrics.max_unsynced_bytes.get()).unwrap(),
            tail_bytes
        );
        assert_eq!(
            u128::try_from(metrics.max_unsynced_age_milliseconds.get()).unwrap(),
            tail_sync_started_at
                .duration_since(tail_appended_at)
                .unwrap()
                .as_millis()
        );
        assert_histogram(context, "owner_prefix_depth", 2, (TAIL_BARRIERS + 1) as f64);
        assert_histogram(
            context,
            "owner_urgent_tail_latency",
            1,
            EXPECTED_URGENT_TAIL_DELAY.as_secs_f64(),
        );
        assert_eq!(
            metrics.start_syncs.get() as f64 / metrics.appended_barriers.get() as f64,
            2.0 / (TAIL_BARRIERS as f64 + 1.0),
            "nine appends must require exactly two prefix syncs"
        );

        let DeferredSync { release, blocked } = next_pending_sync(&pending);
        let tail_release = context
            .child("tail_release")
            .spawn(move |context| async move {
                blocked.await.expect("the tail sync handle must be polled");
                let started_at = context.current();
                context.sleep(TAIL_SYNC_LATENCY).await;
                let released_at = context.current();
                release.send(Ok(())).expect("the tail sync is waiting");
                (started_at, released_at)
            });
        let (tail_release_started_at, tail_released_at) = tail_release.await.unwrap();
        assert_eq!(
            tail_released_at
                .duration_since(tail_release_started_at)
                .unwrap(),
            TAIL_SYNC_LATENCY
        );
        for barrier in 2..=TAIL_BARRIERS as u64 + 1 {
            assert_eq!(
                durable(&mut running.outputs).await.ack.barrier(),
                BatchId::new(barrier)
            );
        }
        assert_eq!(metrics.durable_barriers.get(), TAIL_BARRIERS as u64 + 1);
        assert_eq!(metrics.pending_barriers.get(), 0);
        assert_eq!(metrics.pending_bytes.get(), 0);
        assert_eq!(metrics.covered_barriers.get(), 0);
        // Every barrier becomes durable one actor hop after the release of the sync covering it,
        // so the latency sum follows the recorded append and release instants exactly.
        let appended = gates.appended_at();
        assert_eq!(appended.len(), TAIL_BARRIERS + 1);
        let first_durable = first_released_at + ACTOR_HOP;
        let tail_durable = tail_released_at + ACTOR_HOP;
        let expected_latency_sum = first_durable.duration_since(appended[0]).unwrap()
            + appended[1..]
                .iter()
                .map(|appended_at| tail_durable.duration_since(*appended_at).unwrap())
                .sum::<Duration>();
        assert_histogram(
            context,
            "owner_barrier_latency",
            TAIL_BARRIERS as u64 + 1,
            expected_latency_sum.as_secs_f64(),
        );
        finish(running, &pending).await;
    });
}

#[test]
fn performance_gate_response_retention_ceiling() {
    deterministic::Runner::default().start(|context| async move {
        const CAPACITY: usize = 4;

        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-performance-capacity", epoch).await;
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let running = stores.start(NZUsize!(CAPACITY), TestGates::default());

        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, true))
            .unwrap();
        wait_for_starts(&pending, baseline + 1).await;
        for barrier in 2..=CAPACITY as u64 {
            running
                .client
                .append(
                    Span::none(),
                    Span::none(),
                    job(epoch, barrier, barrier - 1, false),
                )
                .unwrap();
        }
        wait_for_pending(&running.metrics, CAPACITY).await;

        for barrier in CAPACITY as u64 + 1..=CAPACITY as u64 * 2 {
            running
                .client
                .append(
                    Span::none(),
                    Span::none(),
                    job(epoch, barrier, barrier - 1, false),
                )
                .unwrap();
        }
        let rejected = running.client.append(
            Span::none(),
            Span::none(),
            job(epoch, CAPACITY as u64 * 2 + 1, CAPACITY as u64 * 2, false),
        );
        assert!(matches!(rejected, Err(Admission::Full(_))));
        assert!(!running.client.has_capacity());
        assert_eq!(running.metrics.appended_barriers.get(), CAPACITY as u64);
        assert_eq!(running.metrics.start_syncs.get(), 1);
        assert_eq!(
            usize::try_from(running.metrics.pending_barriers.get()).unwrap(),
            CAPACITY,
            "the actor must stop consuming before retained appends exceed its limit"
        );
        let expected_pending_bytes = (1..=CAPACITY as u64)
            .map(|barrier| {
                JournalRecord::encoded_size(&job(epoch, barrier, barrier - 1, barrier == 1))
            })
            .sum::<usize>();
        assert_eq!(
            usize::try_from(running.metrics.pending_bytes.get()).unwrap(),
            expected_pending_bytes
        );

        let Running {
            client,
            mut outputs,
            handle,
            ..
        } = running;
        drop(client);
        drive_pending_syncs(&pending, async move {
            for barrier in 1..=CAPACITY as u64 * 2 {
                assert_eq!(
                    durable(&mut outputs).await.ack.barrier(),
                    BatchId::new(barrier)
                );
            }
            handle.await.unwrap();
        })
        .await;
    });
}

#[test]
fn append_continues_behind_sync_and_urgent_tail_syncs_next() {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-pipeline", epoch).await;
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NZUsize!(8), TestGates::default());

        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, true))
            .unwrap();
        wait_for_starts(&pending, baseline + 1).await;
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 2, 1, true))
            .unwrap();

        release_next(&pending).await;
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(1)
        );
        assert!(running.outputs.try_recv().is_err());

        wait_for_starts(&pending, baseline + 2).await;
        release_next(&pending).await;
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(2)
        );
        finish(running, &pending).await;
    });
}

#[test]
fn authorization_and_ready_signature_use_the_minimum_one_sync() {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-minimum-signature-sync", epoch).await;
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NZUsize!(8), TestGates::default());
        let context = &running.context;

        // Both records are ready before the actor runs, so one sync covers the authorization
        // and its signed result in the same contiguous prefix.
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, false))
            .unwrap();
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 2, 1, true))
            .unwrap();
        wait_for_starts(&pending, baseline + 1).await;

        assert_eq!(running.metrics.start_syncs.get(), 1);
        assert_eq!(running.metrics.appended_barriers.get(), 2);
        assert_eq!(running.metrics.covered_barriers.get(), 2);
        assert_eq!(running.metrics.uncovered_barriers.get(), 0);
        assert_histogram(context, "owner_prefix_depth", 1, 2.0);

        release_next(&pending).await;
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(1)
        );
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(2)
        );
        assert_eq!(running.metrics.start_syncs.get(), 1);
        finish(running, &pending).await;
    });
}

#[test]
fn authorization_waits_for_signature_demand() {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-signature-demand", epoch).await;
        let gates = TestGates::default();
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NZUsize!(8), gates.clone());
        let mut appended = gates.arm_after_append();
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, false))
            .unwrap();
        appended.wait_entered_at().await;
        appended.release();
        for _ in 0..8 {
            reschedule().await;
        }
        assert_eq!(running.metrics.start_syncs.get(), 0);
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 2, 1, true))
            .unwrap();
        wait_for_starts(&pending, baseline + 1).await;
        assert_eq!(running.metrics.covered_barriers.get(), 2);
        release_next(&pending).await;
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(1)
        );
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(2)
        );
        assert_eq!(running.metrics.start_syncs.get(), 1);
        finish(running, &pending).await;
    });
}

#[test]
fn ready_urgent_prefix_uses_one_sync() {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-ready-urgent-prefix", epoch).await;
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NZUsize!(8), TestGates::default());

        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, true))
            .unwrap();
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 2, 1, true))
            .unwrap();
        wait_for_starts(&pending, baseline + 1).await;

        assert_eq!(running.metrics.start_syncs.get(), 1);
        assert_eq!(running.metrics.covered_barriers.get(), 2);
        assert_eq!(running.metrics.uncovered_barriers.get(), 0);
        release_next(&pending).await;
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(1)
        );
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(2)
        );
        assert_eq!(running.metrics.start_syncs.get(), 1);
        finish(running, &pending).await;
    });
}

#[test]
fn ready_nonurgent_prefix_uses_one_sync() {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-bytes", epoch).await;
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NZUsize!(8), TestGates::default());
        let context = &running.context;

        for barrier in 1..=3 {
            running
                .client
                .append(
                    Span::none(),
                    Span::none(),
                    job(epoch, barrier, barrier - 1, false),
                )
                .unwrap();
        }
        running.client.flush().unwrap();
        wait_for_starts(&pending, baseline + 1).await;
        assert_eq!(running.metrics.start_syncs.get(), 1);
        assert_eq!(running.metrics.appended_barriers.get(), 3);
        assert_histogram(context, "owner_prefix_depth", 1, 3.0);
        assert_eq!(running.metrics.covered_barriers.get(), 3);
        assert_eq!(running.metrics.uncovered_barriers.get(), 0);
        assert_eq!(running.metrics.uncovered_bytes.get(), 0);

        release_next(&pending).await;
        for barrier in 1..=3 {
            assert_eq!(
                durable(&mut running.outputs).await.ack.barrier(),
                BatchId::new(barrier)
            );
        }
        assert_eq!(pending.starts(), baseline + 1);
        finish(running, &pending).await;
    });
}

#[rstest::rstest]
fn nonurgent_demand_syncs_without_coalescing_delay(#[values(1, 2, 3)] capacity: usize) {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-demand", epoch).await;
        let gates = TestGates::default();
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NonZeroUsize::new(capacity).unwrap(), gates.clone());
        let mut append_gate = gates.arm_after_append();
        let mut start_gate = gates.arm_next_start_sync();
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, false))
            .unwrap();
        let appended_at = append_gate.wait_entered_at().await;
        running.client.flush().unwrap();
        append_gate.release();
        let started_at = start_gate.wait_entered_at().await;
        assert!(started_at.duration_since(appended_at).unwrap() < Duration::from_millis(25));
        start_gate.release();
        wait_for_starts(&pending, baseline + 1).await;
        release_next(&pending).await;
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(1)
        );
        finish(running, &pending).await;
    });
}

#[rstest::rstest]
fn capacity_demand_flushes_small_nonurgent_prefixes(#[values(1, 2, 3, 4)] capacity: usize) {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-capacity-demand", epoch).await;
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NonZeroUsize::new(capacity).unwrap(), TestGates::default());
        for barrier in 1..=capacity as u64 {
            running
                .client
                .append(
                    Span::none(),
                    Span::none(),
                    job(epoch, barrier, barrier - 1, false),
                )
                .unwrap();
        }
        wait_for_starts(&pending, baseline + 1).await;
        assert_eq!(running.metrics.covered_barriers.get(), capacity as i64);
        release_next(&pending).await;
        for barrier in 1..=capacity as u64 {
            assert_eq!(
                durable(&mut running.outputs).await.ack.barrier(),
                BatchId::new(barrier)
            );
        }
        finish(running, &pending).await;
    });
}

#[test]
fn explicit_flush_covers_nonurgent_tail_behind_active_sync() {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-flush-tail", epoch).await;
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NZUsize!(8), TestGates::default());
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, true))
            .unwrap();
        wait_for_starts(&pending, baseline + 1).await;
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 2, 1, false))
            .unwrap();
        running.client.flush().unwrap();
        release_next(&pending).await;
        durable(&mut running.outputs).await;
        wait_for_starts(&pending, baseline + 2).await;
        release_next(&pending).await;
        durable(&mut running.outputs).await;
        assert_eq!(running.metrics.start_syncs.get(), 2);
        finish(running, &pending).await;
    });
}

#[test]
fn flush_requests_never_take_append_capacity() {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-flush-capacity", epoch).await;
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NZUsize!(2), TestGates::default());

        // Without yielding, the actor drains nothing: every request collapses into one flush and
        // both command slots stay free for appends.
        for _ in 0..4 {
            running.client.flush().unwrap();
        }
        for barrier in 1..=2 {
            running
                .client
                .append(
                    Span::none(),
                    Span::none(),
                    job(epoch, barrier, barrier - 1, false),
                )
                .unwrap();
        }
        assert!(!running.client.has_capacity());
        running.client.flush().unwrap();

        wait_for_starts(&pending, baseline + 1).await;
        release_next(&pending).await;
        for barrier in 1..=2 {
            assert_eq!(
                durable(&mut running.outputs).await.ack.barrier(),
                BatchId::new(barrier)
            );
        }

        // A satisfied flush does not linger: the next quiet record waits for its own demand.
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 3, 2, false))
            .unwrap();
        wait_for_pending(&running.metrics, 1).await;
        for _ in 0..8 {
            reschedule().await;
        }
        assert_eq!(pending.starts(), baseline + 1);
        running.client.flush().unwrap();
        wait_for_starts(&pending, baseline + 2).await;
        release_next(&pending).await;
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(3)
        );
        finish(running, &pending).await;
    });
}

#[test]
fn detached_flusher_shares_the_mailbox_flush_slot() {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-detached-flusher", epoch).await;
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NZUsize!(4), TestGates::default());

        // Requests from the mailbox and a detached flusher share one slot, so eight of them
        // demand exactly one sync of the quiet prefix and none lingers after it.
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, false))
            .unwrap();
        for _ in 0..4 {
            running.flusher.flush().unwrap();
            running.client.flush().unwrap();
        }
        wait_for_starts(&pending, baseline + 1).await;
        release_next(&pending).await;
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(1)
        );

        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 2, 1, false))
            .unwrap();
        wait_for_pending(&running.metrics, 1).await;
        for _ in 0..8 {
            reschedule().await;
        }
        assert_eq!(
            pending.starts(),
            baseline + 1,
            "a quiet record waits for its own demand"
        );

        running.flusher.flush().unwrap();
        wait_for_starts(&pending, baseline + 2).await;
        release_next(&pending).await;
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(2)
        );
        finish(running, &pending).await;
    });
}

#[test]
fn flush_behind_a_running_sync_keeps_accepting_appends() {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-flush-running-sync", epoch).await;
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NZUsize!(8), TestGates::default());
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, true))
            .unwrap();
        wait_for_starts(&pending, baseline + 1).await;

        // The flush waits for the running sync without holding up command intake.
        running.client.flush().unwrap();
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 2, 1, false))
            .unwrap();
        wait_for_pending(&running.metrics, 2).await;
        assert_eq!(running.metrics.appended_barriers.get(), 2);
        assert_eq!(pending.starts(), baseline + 1);

        release_next(&pending).await;
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(1)
        );
        wait_for_starts(&pending, baseline + 2).await;
        release_next(&pending).await;
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(2)
        );
        finish(running, &pending).await;
    });
}

#[test]
fn nonurgent_tail_drains_after_close_without_coalescing_delay() {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-closed-tail", epoch).await;
        let gates = TestGates::default();
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let running = stores.start(NZUsize!(4), gates.clone());
        let Running {
            client,
            mut outputs,
            metrics,
            handle,
            context,
            ..
        } = running;
        client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, true))
            .unwrap();
        wait_for_starts(&pending, baseline + 1).await;
        client
            .append(Span::none(), Span::none(), job(epoch, 2, 1, false))
            .unwrap();
        client
            .append(Span::none(), Span::none(), job(epoch, 3, 2, false))
            .unwrap();
        wait_for_pending(&metrics, 3).await;
        assert_eq!(metrics.start_syncs.get(), 1);
        drop(client);
        for _ in 0..8 {
            reschedule().await;
        }
        let mut start_gate = gates.arm_next_start_sync();
        let released_at = context.current();
        release_next(&pending).await;
        assert_eq!(durable(&mut outputs).await.ack.barrier(), BatchId::new(1));
        let started_at = start_gate.wait_entered_at().await;
        assert!(started_at.duration_since(released_at).unwrap() < Duration::from_millis(25));
        start_gate.release();
        wait_for_starts(&pending, baseline + 2).await;
        release_next(&pending).await;
        assert_eq!(durable(&mut outputs).await.ack.barrier(), BatchId::new(2));
        assert_eq!(durable(&mut outputs).await.ack.barrier(), BatchId::new(3));
        handle.await.unwrap();
        assert_eq!(pending.starts(), baseline + 2);
    });
}

#[test]
fn full_admission_returns_untouched_append() {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-full", epoch).await;
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NZUsize!(1), TestGates::default());
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, true))
            .unwrap();
        let expected = job(epoch, 2, 1, true);
        let returned = match running
            .client
            .append(Span::none(), Span::none(), expected.clone())
        {
            Err(Admission::Full(append)) => append,
            _ => panic!("the sole command slot must be full"),
        };
        assert_eq!(returned.job, expected);

        wait_for_starts(&pending, baseline + 1).await;
        release_next(&pending).await;
        durable(&mut running.outputs).await;
        finish(running, &pending).await;
    });
}

#[test]
fn checkpoint_prunes_only_once_no_append_is_pending() {
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-checkpoint", epoch).await;
        let gates = TestGates::default();
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let mut running = stores.start(NZUsize!(8), gates.clone());

        running
            .client
            .checkpoint(cut(), origin(), Span::none())
            .unwrap();
        running
            .client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, true))
            .unwrap();
        wait_for_starts(&pending, baseline + 1).await;
        assert!(
            matches!(running.outputs.recv().await, Some(Output::Stored)),
            "the snapshot write does not wait for later appends"
        );
        for _ in 0..8 {
            reschedule().await;
        }
        assert!(
            running.outputs.try_recv().is_err(),
            "the prune waits for the pending append"
        );

        release_next(&pending).await;
        assert_eq!(
            durable(&mut running.outputs).await.ack.barrier(),
            BatchId::new(1)
        );
        let outputs = &mut running.outputs;
        drive_pending_syncs(&pending, async move {
            assert!(matches!(outputs.recv().await, Some(Output::Pruned)));
        })
        .await;
        finish(running, &pending).await;
    });
}

#[test]
fn checkpoint_with_pending_appends_is_terminal() {
    let _subscriber = tracing::subscriber::set_default(tracing_subscriber::registry());
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-busy-checkpoint", epoch).await;
        let pending = stores.pending.clone();
        let baseline = stores.baseline;
        let running = stores.start(NZUsize!(8), TestGates::default());
        let Running {
            client,
            mut outputs,
            handle,
            ..
        } = running;
        client
            .append(Span::none(), Span::none(), job(epoch, 1, 0, true))
            .unwrap();
        wait_for_starts(&pending, baseline + 1).await;
        let roll = tracing::info_span!("busy_roll");
        client.checkpoint(cut(), origin(), roll.clone()).unwrap();

        let Some(Output::Failed {
            root,
            error: Error::Busy,
        }) = outputs.recv().await
        else {
            panic!("a busy checkpoint is terminal");
        };
        assert!(root.id().is_some());
        assert_eq!(
            root.id(),
            roll.id(),
            "the checkpoint's span owns the failure"
        );
        handle.await.unwrap();
        assert!(
            outputs.recv().await.is_none(),
            "the failed actor reports once"
        );
        assert!(matches!(
            client.append(Span::none(), Span::none(), job(epoch, 2, 1, true)),
            Err(Admission::Closed(_))
        ));
    });
}

#[test]
fn append_failure_is_reported_once() {
    let _subscriber = tracing::subscriber::set_default(tracing_subscriber::registry());
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let journal = open_empty(&context, "voter-journal-append-fail", epoch).await;
        let checkpoints = open_checkpoints(&context, "voter-journal-append-fail").await;
        let Running {
            client,
            mut outputs,
            handle,
            ..
        } = start(
            context,
            journal,
            checkpoints,
            NZUsize!(2),
            TestGates::default(),
        );
        let failing = tracing::info_span!("failing_root");
        client
            .append(failing.clone(), Span::none(), job(epoch, 1, 7, true))
            .unwrap();
        client
            .append(
                tracing::info_span!("later_root"),
                Span::none(),
                job(epoch, 2, 1, true),
            )
            .unwrap();

        let Some(Output::Failed {
            root,
            error: Error::Journal(_),
        }) = outputs.recv().await
        else {
            panic!("the invalid append fails the journal");
        };
        assert!(root.id().is_some());
        assert_eq!(
            root.id(),
            failing.id(),
            "the failed barrier's root owns the failure"
        );
        handle.await.unwrap();
        assert!(outputs.recv().await.is_none());
        drop(client);
    });
}

#[test]
fn sync_failure_is_reported_once() {
    let _subscriber = tracing::subscriber::set_default(tracing_subscriber::registry());
    deterministic::Runner::default().start(|context| async move {
        let epoch = Epoch::new(8);
        let stores = open_delayed(context, "voter-journal-sync-fail", epoch).await;
        stores.pending.arm_fail();
        stores.pending.unblock();
        let running = stores.start(NZUsize!(2), TestGates::default());
        let Running {
            client,
            mut outputs,
            handle,
            ..
        } = running;
        let synced = tracing::info_span!("synced_root");
        client
            .append(synced.clone(), Span::none(), job(epoch, 1, 0, true))
            .unwrap();

        let Some(Output::Failed {
            root,
            error: Error::Sync(_),
        }) = outputs.recv().await
        else {
            panic!("the failed sync is terminal");
        };
        assert!(root.id().is_some());
        assert_eq!(
            root.id(),
            synced.id(),
            "the covered barrier's root owns the failure"
        );
        handle.await.unwrap();
        drop(client);
    });
}
