//! Bounded owner for the voter safety journal.
//!
//! The voter core must remain available while storage appends and syncs are pending. This
//! module moves those waits into one supervised task and keeps the storage object affine: only the
//! owner task can call `append_persist`, `start_sync`, `roll`, or `prune`.
//!
//! ```text
//! core                     journal owner
//!    |                              |
//!    |-- Append(span, job) -------->|
//!    |                              |-- append_persist(job)
//!    |                              |
//!    |<---- response pending -------|-- start_sync(captured prefix)
//!    |                              |       |
//!    |-- Append(next job) --------->|       | append continues behind the sync
//!    |                              |<------+
//!    |<-- Durable(span, job, ack) --| oldest first
//! ```
//!
//! Each admitted command owns a one-shot response allocated before the bounded command send. An
//! append response remains owned by the task until the exact captured prefix is durable, which
//! bounds response storage together with the pending and command limits. The caller should retain
//! append responses in admission order and feed each returned [`BarrierAck`] to the core in
//! that order.
//!
//! A sync captures every append visible when it starts. Later appends continue while that handle
//! runs, but never borrow its durability. There is at most one sync handle. Once it completes, the
//! task acknowledges exactly the captured prefix, then immediately starts another sync if the
//! uncovered tail is urgent, has reached [`MAX_UNSYNCED`], has reached its encoded-byte budget,
//! or passed its coalescing deadline.
//!
//! Byte charging uses the same barrier, generation, previous-cursor, event-count, and encoded
//! event fields as the storage journal record. The storage configuration separately validates the
//! maximum size of one record. Therefore the retained append queue's encoded payload is bounded
//! by `command_capacity * max_record_bytes`, while the explicit byte threshold bounds the
//! non-urgent uncovered tail that can accumulate before a sync starts.
//!
//! Any append, sync-start, sync-handle, or prune error is terminal. The failed journal is never
//! reused, every retained response receives the same fatal error, and queued responses are failed
//! before the task exits.

#[cfg(test)]
use crate::multimmit::machine::{BarrierId, Change, Cursor, EffectId};
use crate::{
    LATENCY,
    multimmit::{
        machine::{BarrierAck, PersistJob},
        storage::{JournalError, SafetyJournal},
    },
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use commonware_runtime::{
    Clock, Error as RuntimeError, Handle, Metrics, Spawner, Storage,
    telemetry::metrics::{
        Counter, Gauge, GaugeExt as _, Histogram, HistogramExt as _, MetricsExt as _,
    },
};
use commonware_utils::channel::{mpsc, oneshot};
#[cfg(test)]
use commonware_utils::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::VecDeque,
    future::{Future, pending as pending_forever},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};
use tracing::{Instrument as _, Span};

/// An admitted append's durable response, or the returned command when the queue is full.
type TryAppend<V, D> = Result<Response<Durable<V, D>>, Admission<Append<V, D>>>;

/// Maximum uncovered barriers allowed before a prefix sync is forced.
pub(super) const MAX_UNSYNCED: usize = 8;

const PREFIX_DEPTH_BUCKETS: [f64; 10] = [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0];

/// Starts one bounded journal owner.
///
/// `command_capacity` bounds both the ready command queue and the task's retained append queue.
/// The task stops receiving commands while the retained queue is full, so a stalled sync cannot
/// turn prompt command consumption into unbounded response retention.
pub(super) fn spawn<E, V, D>(
    context: E,
    journal: SafetyJournal<E, V, D>,
    command_capacity: NonZeroUsize,
    max_unsynced_bytes: NonZeroUsize,
    flush_delay: Duration,
) -> (JournalClient<V, D>, JournalMonitor)
where
    E: Clock + Metrics + Spawner + Storage,
    V: Variant,
    D: Digest,
{
    spawn_inner(
        context,
        journal,
        command_capacity,
        max_unsynced_bytes,
        flush_delay,
        #[cfg(test)]
        TestGates::default(),
    )
}

/// Test-only suspension points immediately before the owner's real storage awaits.
#[cfg(test)]
#[derive(Clone, Default)]
pub(super) struct TestGates {
    append: Arc<Mutex<Option<GateWaiter>>>,
    after_append: Arc<Mutex<Option<GateWaiter>>>,
    start_sync: Arc<Mutex<Option<GateWaiter>>>,
    after_sync: Arc<Mutex<Option<GateWaiter>>>,
    roll: Arc<Mutex<Option<GateWaiter>>>,
    before_prune: Arc<Mutex<Option<GateWaiter>>>,
    after_prune: Arc<Mutex<Option<GateWaiter>>>,
    appends: Arc<Mutex<Vec<JournalPoint>>>,
    append_ordinal: Arc<AtomicU64>,
    sync_ordinal: Arc<AtomicU64>,
    after_sync_ordinal: Arc<AtomicU64>,
    roll_ordinal: Arc<AtomicU64>,
    prune_ordinal: Arc<AtomicU64>,
}

#[cfg(test)]
struct GateWaiter {
    target: GateTarget,
    entered: oneshot::Sender<SystemTime>,
    release: oneshot::Receiver<()>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum GateTarget {
    Coordinate { generation: u64, cursor: Cursor },
    Retires(EffectId),
    Ordinal(u64),
}

/// Content-independent identity of one attempted append.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct JournalPoint {
    pub(super) ordinal: u64,
    pub(super) barrier: BarrierId,
    pub(super) generation: u64,
    pub(super) previous: Cursor,
    pub(super) result: Cursor,
}

/// Controller for one armed storage suspension point.
#[cfg(test)]
pub(super) struct TestGate {
    entered: Option<oneshot::Receiver<SystemTime>>,
    release: Option<oneshot::Sender<()>>,
}

#[cfg(test)]
impl TestGates {
    pub(super) fn appends(&self) -> Vec<JournalPoint> {
        self.appends.lock().clone()
    }

    pub(super) fn arm_append_covering(&self, generation: u64, cursor: Cursor) -> TestGate {
        Self::arm(&self.append, GateTarget::Coordinate { generation, cursor })
    }

    pub(super) fn arm_after_append(&self) -> TestGate {
        Self::arm(
            &self.after_append,
            GateTarget::Ordinal(self.append_ordinal.load(Ordering::SeqCst)),
        )
    }

    pub(super) fn arm_start_sync_covering(&self, generation: u64, cursor: Cursor) -> TestGate {
        Self::arm(
            &self.start_sync,
            GateTarget::Coordinate { generation, cursor },
        )
    }

    pub(super) fn arm_after_sync_covering(&self, generation: u64, cursor: Cursor) -> TestGate {
        Self::arm(
            &self.after_sync,
            GateTarget::Coordinate { generation, cursor },
        )
    }

    pub(super) fn arm_after_sync_retiring(&self, effect: EffectId) -> TestGate {
        Self::arm(&self.after_sync, GateTarget::Retires(effect))
    }

    pub(super) fn arm_next_append(&self) -> TestGate {
        Self::arm(
            &self.append,
            GateTarget::Ordinal(self.append_ordinal.load(Ordering::SeqCst)),
        )
    }

    pub(super) fn arm_next_start_sync(&self) -> TestGate {
        Self::arm(
            &self.start_sync,
            GateTarget::Ordinal(self.sync_ordinal.load(Ordering::SeqCst)),
        )
    }

    pub(super) fn arm_next_after_sync(&self) -> TestGate {
        Self::arm(
            &self.after_sync,
            GateTarget::Ordinal(self.after_sync_ordinal.load(Ordering::SeqCst)),
        )
    }

    pub(super) fn arm_next_roll(&self) -> TestGate {
        Self::arm(
            &self.roll,
            GateTarget::Ordinal(self.roll_ordinal.load(Ordering::SeqCst)),
        )
    }

    pub(super) fn arm_next_before_prune(&self) -> TestGate {
        Self::arm(
            &self.before_prune,
            GateTarget::Ordinal(self.prune_ordinal.load(Ordering::SeqCst)),
        )
    }

    pub(super) fn arm_next_after_prune(&self) -> TestGate {
        Self::arm(
            &self.after_prune,
            GateTarget::Ordinal(self.prune_ordinal.load(Ordering::SeqCst)),
        )
    }

    fn arm(slot: &Mutex<Option<GateWaiter>>, target: GateTarget) -> TestGate {
        let (entered_sender, entered) = oneshot::channel();
        let (release, release_receiver) = oneshot::channel();
        let mut slot = slot.lock();
        assert!(slot.is_none(), "journal test gate is already armed");
        *slot = Some(GateWaiter {
            target,
            entered: entered_sender,
            release: release_receiver,
        });
        TestGate {
            entered: Some(entered),
            release: Some(release),
        }
    }

    fn observe_append<V, D>(&self, job: &PersistJob<V, D>) -> JournalPoint
    where
        V: Variant,
        D: Digest,
    {
        let point = JournalPoint {
            ordinal: self.append_ordinal.fetch_add(1, Ordering::SeqCst),
            barrier: job.id(),
            generation: job.generation(),
            previous: job.previous(),
            result: job.last_cursor(),
        };
        self.appends.lock().push(point);
        let retires = |change: &Change<V, D>, effect| match change {
            Change::DaCertificateAdvanced { retired, .. }
            | Change::ArtifactForwarded { retired, .. }
            | Change::ViewAdvanced { retired, .. } => retired.contains(&effect),
            Change::FinalityFloorAdvanced {
                publication_retired,
                ..
            } => publication_retired.contains(&effect),
            _ => false,
        };
        let mut after_sync = self.after_sync.lock();
        if after_sync.as_ref().is_some_and(|waiter| {
            matches!(waiter.target, GateTarget::Retires(effect)
                if job.events().iter().any(|event| retires(event.change(), effect)))
        }) {
            after_sync.as_mut().expect("checked above").target = GateTarget::Coordinate {
                generation: point.generation,
                cursor: point.result,
            };
        }
        point
    }

    async fn before_append(&self, point: JournalPoint, entered_at: SystemTime) {
        Self::wait(&self.append, point, point.ordinal, true, entered_at).await;
    }

    async fn after_append(&self, point: JournalPoint, entered_at: SystemTime) {
        Self::wait(&self.after_append, point, point.ordinal, true, entered_at).await;
    }

    async fn before_start_sync(&self, point: JournalPoint, entered_at: SystemTime) {
        let ordinal = self.sync_ordinal.fetch_add(1, Ordering::SeqCst);
        Self::wait(&self.start_sync, point, ordinal, false, entered_at).await;
    }

    async fn after_sync(&self, point: JournalPoint, entered_at: SystemTime) {
        let ordinal = self.after_sync_ordinal.fetch_add(1, Ordering::SeqCst);
        Self::wait(&self.after_sync, point, ordinal, false, entered_at).await;
    }

    async fn before_roll(&self, entered_at: SystemTime) {
        let ordinal = self.roll_ordinal.fetch_add(1, Ordering::SeqCst);
        Self::wait_ordinal(&self.roll, ordinal, entered_at).await;
    }

    async fn before_prune(&self, ordinal: u64, entered_at: SystemTime) {
        Self::wait_ordinal(&self.before_prune, ordinal, entered_at).await;
    }

    async fn after_prune(&self, ordinal: u64, entered_at: SystemTime) {
        Self::wait_ordinal(&self.after_prune, ordinal, entered_at).await;
    }

    async fn wait_ordinal(slot: &Mutex<Option<GateWaiter>>, ordinal: u64, entered_at: SystemTime) {
        let waiter = {
            let mut slot = slot.lock();
            if slot.as_ref().is_some_and(
                |waiter| !matches!(waiter.target, GateTarget::Ordinal(target) if target == ordinal),
            ) {
                return;
            }
            slot.take()
        };
        Self::hold(waiter, entered_at).await;
    }

    async fn wait(
        slot: &Mutex<Option<GateWaiter>>,
        point: JournalPoint,
        ordinal: u64,
        append: bool,
        entered_at: SystemTime,
    ) {
        let waiter = {
            let mut slot = slot.lock();
            if let Some(waiter) = slot.as_mut() {
                match waiter.target {
                    GateTarget::Coordinate { generation, cursor }
                        if generation != point.generation
                            || cursor > point.result
                            || (append && cursor <= point.previous) =>
                    {
                        return;
                    }
                    GateTarget::Retires(_) => return,
                    GateTarget::Ordinal(target) if target != ordinal => return,
                    GateTarget::Coordinate { .. } | GateTarget::Ordinal(_) => {}
                }
            }
            slot.take()
        };
        Self::hold(waiter, entered_at).await;
    }

    async fn hold(waiter: Option<GateWaiter>, entered_at: SystemTime) {
        let Some(waiter) = waiter else {
            return;
        };
        let _ = waiter.entered.send(entered_at);
        let _ = waiter.release.await;
    }
}

#[cfg(test)]
impl TestGate {
    pub(super) async fn wait_entered(&mut self) {
        let _ = self
            .entered
            .take()
            .expect("journal test gate is awaited once")
            .await
            .expect("journal owner reaches the armed gate");
    }

    async fn wait_entered_at(&mut self) -> SystemTime {
        self.entered
            .take()
            .expect("journal test gate is awaited once")
            .await
            .expect("journal owner reaches the armed gate")
    }

    pub(super) fn release(mut self) {
        let _ = self
            .release
            .take()
            .expect("journal test gate is released once")
            .send(());
    }
}

/// Starts a journal owner with test-only storage suspension points.
#[cfg(test)]
pub(super) fn spawn_with_gates<E, V, D>(
    context: E,
    journal: SafetyJournal<E, V, D>,
    command_capacity: NonZeroUsize,
    max_unsynced_bytes: NonZeroUsize,
    flush_delay: Duration,
    gates: TestGates,
) -> (JournalClient<V, D>, JournalMonitor)
where
    E: Clock + Metrics + Spawner + Storage,
    V: Variant,
    D: Digest,
{
    spawn_inner(
        context,
        journal,
        command_capacity,
        max_unsynced_bytes,
        flush_delay,
        gates,
    )
}

fn spawn_inner<E, V, D>(
    context: E,
    journal: SafetyJournal<E, V, D>,
    command_capacity: NonZeroUsize,
    max_unsynced_bytes: NonZeroUsize,
    flush_delay: Duration,
    #[cfg(test)] gates: TestGates,
) -> (JournalClient<V, D>, JournalMonitor)
where
    E: Clock + Metrics + Spawner + Storage,
    V: Variant,
    D: Digest,
{
    let (commands, receiver) = mpsc::channel(command_capacity.get());
    let pending_limit = command_capacity.get();
    let metrics = JournalMetrics::new(&context);
    #[cfg(test)]
    let client_metrics = metrics.clone();
    let handle = context.shared(false).spawn(move |context| async move {
        Owner {
            context,
            journal: Some(journal),
            commands: receiver,
            commands_open: true,
            pending: VecDeque::new(),
            pending_bytes: 0,
            pending_limit,
            sync: None,
            max_unsynced_bytes: max_unsynced_bytes.get(),
            flush_delay,
            flush_at: None,
            flush_due: false,
            metrics,
            #[cfg(test)]
            gates,
        }
        .run()
        .await
    });
    (
        JournalClient {
            commands,
            #[cfg(test)]
            metrics: client_metrics,
        },
        JournalMonitor { handle },
    )
}

/// Nonblocking handle to the bounded journal command queue.
pub(super) struct JournalClient<V, D>
where
    V: Variant,
    D: Digest,
{
    commands: mpsc::Sender<Command<V, D>>,
    #[cfg(test)]
    metrics: JournalMetrics,
}

impl<V, D> Clone for JournalClient<V, D>
where
    V: Variant,
    D: Digest,
{
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
            #[cfg(test)]
            metrics: self.metrics.clone(),
        }
    }
}

impl<V, D> JournalClient<V, D>
where
    V: Variant,
    D: Digest,
{
    /// Attempts to admit one exact append without waiting for command capacity.
    ///
    /// On saturation or closure the original span and job are returned, so the caller can retain
    /// the mandatory append without cloning or dropping it.
    pub(super) fn try_append(&self, span: Span, job: PersistJob<V, D>) -> TryAppend<V, D> {
        let append = Append { span, job };
        let (responder, receiver) = oneshot::channel();
        let command = Command::Append { append, responder };
        match self.commands.try_send(command) {
            Ok(()) => Ok(Response { receiver }),
            Err(mpsc::error::TrySendError::Full(Command::Append { append, .. })) => {
                Err(Admission::Full(append))
            }
            Err(mpsc::error::TrySendError::Closed(Command::Append { append, .. })) => {
                Err(Admission::Closed(append))
            }
            Err(_) => unreachable!("try_append constructed an append command"),
        }
    }

    /// Returns whether a command can be admitted without waiting at this instant.
    ///
    /// The voter has one sender, so it can use this check before servicing core work that may
    /// stage a mandatory barrier. [`Self::try_append`] remains authoritative and returns the full
    /// append if capacity changed before admission.
    pub(super) fn has_capacity(&self) -> bool {
        self.capacity() != 0
    }

    /// Returns the bounded command slots currently available to this sender.
    pub(super) fn capacity(&self) -> usize {
        self.commands.capacity()
    }

    #[cfg(test)]
    const fn metrics(&self) -> &JournalMetrics {
        &self.metrics
    }

    /// Waits until one command slot can be reserved, then releases it without sending.
    ///
    /// The voter selects on this only while the queue is full. Releasing the temporary permit
    /// wakes the next control-loop turn, which can reserve the slot for an exact machine effect.
    pub(super) async fn wait_for_capacity(&self) -> Result<(), JournalFailure> {
        let permit = self
            .commands
            .reserve()
            .await
            .map_err(|_| JournalFailure::Closed)?;
        drop(permit);
        Ok(())
    }

    /// Rolls to the section that will follow a fully acknowledged checkpoint snapshot.
    pub(super) fn try_roll(&self) -> Result<Response<()>, Admission<()>> {
        self.try_control(|span, responder| Command::Roll { span, responder })
    }

    /// Prunes journal sections covered by a durable checkpoint.
    pub(super) fn try_prune(&self) -> Result<Response<()>, Admission<()>> {
        self.try_control(|span, responder| Command::Prune { span, responder })
    }

    fn try_control(
        &self,
        make: impl FnOnce(Span, Responder<()>) -> Command<V, D>,
    ) -> Result<Response<()>, Admission<()>> {
        let (responder, receiver) = oneshot::channel();
        match self.commands.try_send(make(Span::current(), responder)) {
            Ok(()) => Ok(Response { receiver }),
            Err(mpsc::error::TrySendError::Full(_)) => Err(Admission::Full(())),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(Admission::Closed(())),
        }
    }
}

/// Original append payload returned when bounded admission cannot accept it.
#[derive(Debug)]
pub(super) struct Append<V, D>
where
    V: Variant,
    D: Digest,
{
    pub(super) span: Span,
    pub(super) job: PersistJob<V, D>,
}

/// Result of a nonblocking command-admission attempt.
#[derive(Debug)]
pub(super) enum Admission<T> {
    /// The bounded command queue has no available slot.
    Full(T),
    /// The journal owner has stopped accepting commands.
    Closed(T),
}

/// Typed response allocated before a command enters the bounded queue.
#[must_use = "journal responses carry mandatory completion or failure"]
pub(super) struct Response<T> {
    receiver: oneshot::Receiver<Result<T, JournalFailure>>,
}

impl<T> Unpin for Response<T> {}

impl<T> Future for Response<T> {
    type Output = Result<T, JournalFailure>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let receiver = &mut self.get_mut().receiver;
        match Pin::new(receiver).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(JournalFailure::ResponseCanceled)),
        }
    }
}

/// Monitor for the supervised journal owner.
///
/// A response cancellation says only that its one-shot sender disappeared. This monitor carries
/// the owner's terminal storage failure or the runtime failure that prevented the task from
/// returning one, so callers can distinguish command cancellation from task failure.
#[must_use = "the journal owner is a mandatory supervised task"]
pub(super) struct JournalMonitor {
    handle: Handle<Result<(), JournalFailure>>,
}

impl Unpin for JournalMonitor {}

impl Future for JournalMonitor {
    type Output = Result<(), JournalFailure>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let handle = &mut self.get_mut().handle;
        match Pin::new(handle).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(error)) => Poll::Ready(Err(JournalFailure::Task(Arc::new(error)))),
        }
    }
}

/// One exact durable barrier, preserving its tracing and bookkeeping context.
pub(super) struct Durable<V, D>
where
    V: Variant,
    D: Digest,
{
    pub(super) span: Span,
    pub(super) job: PersistJob<V, D>,
    pub(super) ack: BarrierAck,
}

/// Fatal journal-owner failure.
///
/// Storage and runtime errors are reference counted so the same cause can be delivered to every
/// append covered by a failed prefix operation.
#[derive(Clone, Debug, thiserror::Error)]
pub(super) enum JournalFailure {
    /// The journal rejected or failed a storage operation.
    #[error("safety journal failed: {0}")]
    Journal(Arc<JournalError>),
    /// A started prefix sync failed in the runtime.
    #[error("safety journal sync failed: {0}")]
    Sync(Arc<RuntimeError>),
    /// The owner or a response channel closed before returning a result.
    #[error("safety journal owner closed")]
    Closed,
    /// A command response sender disappeared before completing the response.
    #[error("safety journal command response was canceled")]
    ResponseCanceled,
    /// The supervised owner task failed before returning its own terminal result.
    #[error("safety journal owner task failed: {0}")]
    Task(Arc<RuntimeError>),
    /// A checkpoint roll raced outstanding journal persistence.
    #[error("safety journal roll requested with persistence outstanding")]
    Busy,
}

type Responder<T> = oneshot::Sender<Result<T, JournalFailure>>;

enum Command<V, D>
where
    V: Variant,
    D: Digest,
{
    Append {
        append: Append<V, D>,
        responder: Responder<Durable<V, D>>,
    },
    Roll {
        span: Span,
        responder: Responder<()>,
    },
    Prune {
        span: Span,
        responder: Responder<()>,
    },
}

impl<V, D> Command<V, D>
where
    V: Variant,
    D: Digest,
{
    fn fail(self, failure: JournalFailure) {
        match self {
            Self::Append { responder, .. } => {
                let _ = responder.send(Err(failure));
            }
            Self::Roll { responder, .. } | Self::Prune { responder, .. } => {
                let _ = responder.send(Err(failure));
            }
        }
    }
}

struct Pending<V, D>
where
    V: Variant,
    D: Digest,
{
    append: Append<V, D>,
    ack: BarrierAck,
    #[cfg(test)]
    point: JournalPoint,
    encoded_size: usize,
    appended_at: SystemTime,
    urgent_behind_sync: bool,
    responder: Responder<Durable<V, D>>,
}

#[derive(Clone)]
struct JournalMetrics {
    appended_barriers: Counter,
    appended_events: Counter,
    appended_bytes: Counter,
    start_syncs: Counter,
    durable_barriers: Counter,
    prefix_depth: Histogram,
    barrier_latency: Histogram,
    urgent_tail_latency: Histogram,
    pending_barriers: Gauge,
    pending_bytes: Gauge,
    covered_barriers: Gauge,
    uncovered_barriers: Gauge,
    uncovered_bytes: Gauge,
    sync_in_flight: Gauge,
    max_prefix_depth: Gauge,
    max_unsynced_bytes: Gauge,
    max_unsynced_age_milliseconds: Gauge,
}

impl JournalMetrics {
    fn new<E: Metrics>(context: &E) -> Self {
        Self {
            appended_barriers: context.counter(
                "appended_barriers",
                "barriers appended to the voter safety journal",
            ),
            appended_events: context.counter(
                "appended_events",
                "events appended to the voter safety journal",
            ),
            appended_bytes: context.counter(
                "appended_bytes",
                "canonical bytes appended to the voter safety journal",
            ),
            start_syncs: context.counter(
                "start_syncs",
                "prefix-covering safety journal syncs started",
            ),
            durable_barriers: context.counter(
                "durable_barriers",
                "barriers acknowledged from durable safety journal prefixes",
            ),
            prefix_depth: context.histogram(
                "prefix_depth",
                "barriers covered by one safety journal prefix sync",
                PREFIX_DEPTH_BUCKETS,
            ),
            barrier_latency: context.histogram(
                "barrier_latency",
                "time from safety journal append to durable acknowledgement",
                LATENCY,
            ),
            urgent_tail_latency: context.histogram(
                "urgent_tail_latency",
                "time from urgent tail append to its prefix sync start",
                LATENCY,
            ),
            pending_barriers: context.gauge(
                "pending_barriers",
                "appended barriers awaiting durable acknowledgement",
            ),
            pending_bytes: context.gauge(
                "pending_bytes",
                "canonical appended bytes awaiting durable acknowledgement",
            ),
            covered_barriers: context.gauge(
                "covered_barriers",
                "barriers covered by the in-flight prefix sync",
            ),
            uncovered_barriers: context.gauge(
                "uncovered_barriers",
                "appended barriers not covered by the in-flight prefix sync",
            ),
            uncovered_bytes: context.gauge(
                "uncovered_bytes",
                "canonical appended bytes not covered by the in-flight prefix sync",
            ),
            sync_in_flight: context.gauge(
                "sync_in_flight",
                "whether one prefix-covering safety journal sync is in flight",
            ),
            max_prefix_depth: context.gauge(
                "max_prefix_depth",
                "maximum barriers covered by one safety journal prefix sync",
            ),
            max_unsynced_bytes: context.gauge(
                "max_unsynced_bytes",
                "maximum canonical bytes captured from one unsynced prefix",
            ),
            max_unsynced_age_milliseconds: context.gauge(
                "max_unsynced_age_milliseconds",
                "maximum age in milliseconds of the oldest barrier when its prefix sync starts",
            ),
        }
    }

    fn observe_prefix(&self, depth: usize, bytes: usize, age: Duration) {
        self.prefix_depth.observe(depth as f64);
        set_max(&self.max_prefix_depth, depth);
        set_max(&self.max_unsynced_bytes, bytes);
        set_max(
            &self.max_unsynced_age_milliseconds,
            usize::try_from(age.as_millis()).unwrap_or(usize::MAX),
        );
    }

    fn update_depths(
        &self,
        pending_barriers: usize,
        pending_bytes: usize,
        covered_barriers: usize,
        covered_bytes: usize,
    ) {
        let _ = self.pending_barriers.try_set(pending_barriers);
        let _ = self.pending_bytes.try_set(pending_bytes);
        let _ = self.covered_barriers.try_set(covered_barriers);
        let _ = self
            .uncovered_barriers
            .try_set(pending_barriers.saturating_sub(covered_barriers));
        let _ = self
            .uncovered_bytes
            .try_set(pending_bytes.saturating_sub(covered_bytes));
    }
}

fn set_max(metric: &Gauge, value: usize) {
    let value = i64::try_from(value).unwrap_or(i64::MAX);
    if value > metric.get() {
        metric.set(value);
    }
}

struct PrefixSync {
    /// Number of entries at the front of `pending` captured by this sync.
    covered: usize,
    /// Canonical bytes at the front of `pending` captured by this sync.
    covered_bytes: usize,
    handle: Handle<()>,
    #[cfg(test)]
    point: JournalPoint,
}

struct Owner<E, V, D>
where
    E: Clock + Metrics + Spawner + Storage,
    V: Variant,
    D: Digest,
{
    context: E,
    journal: Option<SafetyJournal<E, V, D>>,
    commands: mpsc::Receiver<Command<V, D>>,
    commands_open: bool,
    pending: VecDeque<Pending<V, D>>,
    pending_bytes: usize,
    pending_limit: usize,
    sync: Option<PrefixSync>,
    max_unsynced_bytes: usize,
    flush_delay: Duration,
    flush_at: Option<SystemTime>,
    flush_due: bool,
    metrics: JournalMetrics,
    #[cfg(test)]
    gates: TestGates,
}

impl<E, V, D> Owner<E, V, D>
where
    E: Clock + Metrics + Spawner + Storage,
    V: Variant,
    D: Digest,
{
    async fn run(mut self) -> Result<(), JournalFailure> {
        let result = self.serve().await;
        match &result {
            Ok(()) if !self.pending.is_empty() => self.fail_all(JournalFailure::Closed),
            Ok(()) => {}
            Err(failure) => self.fail_all(failure.clone()),
        }
        result
    }

    async fn serve(&mut self) -> Result<(), JournalFailure> {
        loop {
            if !self.commands_open && self.pending.is_empty() {
                return Ok(());
            }

            let receive_commands = self.commands_open && self.pending.len() < self.pending_limit;
            select! {
                _ = self.context.stopped() => return Ok(()),
                result = wait_for_sync(self.sync.as_mut()) => {
                    result.map_err(|error| JournalFailure::Sync(Arc::new(error)))?;
                    self.complete_sync().await?;
                },
                () = wait_for_deadline(&self.context, self.flush_at) => {
                    self.flush_at = None;
                    self.flush_due = true;
                    if self.sync.is_none() {
                        self.drain_ready_commands().await?;
                        self.start_sync().await?;
                    }
                },
                command = receive_command(&mut self.commands, receive_commands) => {
                    let Some(command) = command else {
                        self.commands_open = false;
                        if !self.pending.is_empty() && self.sync.is_none() {
                            self.flush_due = true;
                            self.start_sync().await?;
                        }
                        continue;
                    };
                    self.process(command).await?;
                },
            }
        }
    }

    async fn process(&mut self, command: Command<V, D>) -> Result<(), JournalFailure> {
        match command {
            Command::Append { append, responder } => {
                self.append(append, responder).await?;
                if self.sync.is_none() && self.must_sync_uncovered() {
                    self.drain_ready_commands().await?;
                    self.start_sync().await?;
                }
                Ok(())
            }
            Command::Roll { span, responder } => self.roll(responder).instrument(span).await,
            Command::Prune { span, responder } => self.prune(responder).instrument(span).await,
        }
    }

    /// Appends every command already queued before one required prefix sync starts.
    async fn drain_ready_commands(&mut self) -> Result<(), JournalFailure> {
        while self.pending.len() < self.pending_limit {
            let Ok(command) = self.commands.try_recv() else {
                break;
            };
            match command {
                Command::Append { append, responder } => self.append(append, responder).await?,
                Command::Roll { span, responder } => self.roll(responder).instrument(span).await?,
                Command::Prune { span, responder } => {
                    self.prune(responder).instrument(span).await?
                }
            }
        }
        Ok(())
    }

    async fn append(
        &mut self,
        append: Append<V, D>,
        responder: Responder<Durable<V, D>>,
    ) -> Result<(), JournalFailure> {
        let journal = self.journal.take().ok_or(JournalFailure::Closed)?;
        #[cfg(test)]
        let point = self.gates.observe_append(&append.job);
        #[cfg(test)]
        self.gates
            .before_append(point, self.context.current())
            .await;
        let result = journal
            .append_persist(&append.job)
            .instrument(append.span.clone())
            .await;
        let (journal, ack) = match result {
            Ok(result) => result,
            Err(error) => {
                let failure = JournalFailure::Journal(Arc::new(error));
                let _ = responder.send(Err(failure.clone()));
                return Err(failure);
            }
        };
        self.journal = Some(journal);
        let appended_at = self.context.current();
        #[cfg(test)]
        self.gates.after_append(point, appended_at).await;
        let encoded_size = encoded_size(&append.job);
        let event_count = append.job.events().len();
        let urgent_behind_sync = self.sync.is_some() && append.job.urgent();
        self.pending.push_back(Pending {
            append,
            ack,
            #[cfg(test)]
            point,
            encoded_size,
            appended_at,
            urgent_behind_sync,
            responder,
        });
        self.pending_bytes = self.pending_bytes.saturating_add(encoded_size);
        self.metrics.appended_barriers.inc();
        self.metrics
            .appended_events
            .inc_by(u64::try_from(event_count).unwrap_or(u64::MAX));
        self.metrics
            .appended_bytes
            .inc_by(u64::try_from(encoded_size).unwrap_or(u64::MAX));
        self.update_depth_metrics();

        self.arm_deadline();
        Ok(())
    }

    async fn start_sync(&mut self) -> Result<(), JournalFailure> {
        if self.sync.is_some() || self.pending.is_empty() {
            return Ok(());
        }

        let covered = self.pending.len();
        #[cfg(test)]
        let point = self
            .pending
            .get(covered - 1)
            .expect("a sync covers at least one append")
            .point;
        let covered_bytes = self.pending_bytes;
        let oldest = self
            .pending
            .front()
            .map(|pending| pending.appended_at)
            .ok_or(JournalFailure::Closed)?;
        let now = self.context.current();
        let oldest_urgent = self
            .pending
            .iter()
            .find(|pending| pending.urgent_behind_sync)
            .map(|pending| pending.appended_at);
        let journal = self.journal.take().ok_or(JournalFailure::Closed)?;
        #[cfg(test)]
        self.gates.before_start_sync(point, now).await;
        // The sync serves every covered barrier; the newest one parents the storage spans so
        // fsyncs surface inside the round that paid for them instead of as detached roots.
        let span = self
            .pending
            .back()
            .map(|pending| pending.append.span.clone())
            .unwrap_or_else(Span::none);
        let (journal, handle) = journal
            .start_sync()
            .instrument(span)
            .await
            .map_err(|error| JournalFailure::Journal(Arc::new(error)))?;
        self.journal = Some(journal);
        self.metrics.start_syncs.inc();
        self.metrics.observe_prefix(
            covered,
            covered_bytes,
            now.duration_since(oldest).unwrap_or_default(),
        );
        if let Some(appended_at) = oldest_urgent {
            self.metrics
                .urgent_tail_latency
                .observe_between(appended_at, now);
        }
        self.metrics.sync_in_flight.set(1);
        self.sync = Some(PrefixSync {
            covered,
            covered_bytes,
            handle,
            #[cfg(test)]
            point,
        });
        self.update_depth_metrics();
        self.flush_at = None;
        self.flush_due = false;
        Ok(())
    }

    async fn complete_sync(&mut self) -> Result<(), JournalFailure> {
        let sync = self.sync.take().ok_or(JournalFailure::Closed)?;
        #[cfg(test)]
        self.gates
            .after_sync(sync.point, self.context.current())
            .await;
        self.metrics.sync_in_flight.set(0);
        for _ in 0..sync.covered {
            let Pending {
                append,
                ack,
                #[cfg(test)]
                    point: _,
                encoded_size,
                appended_at,
                urgent_behind_sync: _,
                responder,
            } = self.pending.pop_front().ok_or(JournalFailure::Closed)?;
            self.pending_bytes = self.pending_bytes.saturating_sub(encoded_size);
            self.metrics
                .barrier_latency
                .observe_between(appended_at, self.context.current());
            self.metrics.durable_barriers.inc();
            let durable = Durable {
                span: append.span,
                job: append.job,
                ack,
            };
            let _ = responder.send(Ok(durable));
        }
        self.update_depth_metrics();

        if self.pending.is_empty() {
            self.flush_at = None;
            self.flush_due = false;
            return Ok(());
        }
        if self.must_sync_uncovered() {
            self.drain_ready_commands().await?;
            return self.start_sync().await;
        }
        self.arm_deadline();
        Ok(())
    }

    #[cfg_attr(not(test), allow(clippy::unused_async))]
    async fn roll(&mut self, responder: Responder<()>) -> Result<(), JournalFailure> {
        if !self.pending.is_empty() || self.sync.is_some() {
            let _ = responder.send(Err(JournalFailure::Busy));
            return Ok(());
        }
        let journal = self.journal.take().ok_or(JournalFailure::Closed)?;
        #[cfg(test)]
        self.gates.before_roll(self.context.current()).await;
        self.journal = Some(journal.roll());
        let _ = responder.send(Ok(()));
        Ok(())
    }

    async fn prune(&mut self, responder: Responder<()>) -> Result<(), JournalFailure> {
        if !self.pending.is_empty() || self.sync.is_some() {
            let _ = responder.send(Err(JournalFailure::Busy));
            return Ok(());
        }
        let journal = self.journal.take().ok_or(JournalFailure::Closed)?;
        #[cfg(test)]
        let ordinal = self.gates.prune_ordinal.fetch_add(1, Ordering::SeqCst);
        #[cfg(test)]
        self.gates
            .before_prune(ordinal, self.context.current())
            .await;
        match journal.prune().await {
            Ok(journal) => {
                self.journal = Some(journal);
                #[cfg(test)]
                self.gates
                    .after_prune(ordinal, self.context.current())
                    .await;
                let _ = responder.send(Ok(()));
                Ok(())
            }
            Err(error) => {
                let failure = JournalFailure::Journal(Arc::new(error));
                let _ = responder.send(Err(failure.clone()));
                Err(failure)
            }
        }
    }

    fn must_sync_uncovered(&self) -> bool {
        if self.flush_due {
            return true;
        }
        let covered = self.sync.as_ref().map_or(0, |sync| sync.covered);
        let uncovered = self.pending.len().saturating_sub(covered);
        let uncovered_bytes = self
            .pending
            .iter()
            .skip(covered)
            .fold(0usize, |bytes, pending| {
                bytes.saturating_add(pending.encoded_size)
            });
        uncovered >= MAX_UNSYNCED
            || uncovered_bytes >= self.max_unsynced_bytes
            || self
                .pending
                .iter()
                .skip(covered)
                .any(|pending| pending.append.job.urgent())
    }

    fn arm_deadline(&mut self) {
        if self.flush_at.is_some() || self.must_sync_uncovered() {
            return;
        }
        let covered = self.sync.as_ref().map_or(0, |sync| sync.covered);
        let Some(oldest) = self.pending.get(covered) else {
            return;
        };
        self.flush_at = Some(
            oldest
                .appended_at
                .checked_add(self.flush_delay)
                .unwrap_or(oldest.appended_at),
        );
    }

    fn update_depth_metrics(&self) {
        let (covered_barriers, covered_bytes) = self
            .sync
            .as_ref()
            .map_or((0, 0), |sync| (sync.covered, sync.covered_bytes));
        self.metrics.update_depths(
            self.pending.len(),
            self.pending_bytes,
            covered_barriers,
            covered_bytes,
        );
    }

    fn fail_all(&mut self, failure: JournalFailure) {
        self.commands.close();
        self.sync.take();
        self.metrics.sync_in_flight.set(0);
        while let Some(pending) = self.pending.pop_front() {
            let _ = pending.responder.send(Err(failure.clone()));
        }
        self.pending_bytes = 0;
        self.update_depth_metrics();
        while let Ok(command) = self.commands.try_recv() {
            command.fail(failure.clone());
        }
        self.journal.take();
    }
}

/// Returns the canonical encoded size of one persisted journal record.
///
/// Saturation is conservative: an arithmetic overflow forces an immediate sync. Validated journal
/// records fit in `usize`, so ordinary operation is byte-for-byte identical to
/// `JournalRecord::encode_size`.
fn encoded_size<V: Variant, D: Digest>(job: &PersistJob<V, D>) -> usize {
    let event_bytes = job.events().iter().fold(0usize, |bytes, event| {
        bytes.saturating_add(event.encode_size())
    });
    job.id()
        .get()
        .encode_size()
        .saturating_add(job.generation().encode_size())
        .saturating_add(job.previous().get().encode_size())
        .saturating_add(job.events().len().encode_size())
        .saturating_add(event_bytes)
}

async fn wait_for_sync(sync: Option<&mut PrefixSync>) -> Result<(), RuntimeError> {
    let Some(sync) = sync else {
        return pending_forever().await;
    };
    (&mut sync.handle).await
}

async fn wait_for_deadline<E: Clock>(context: &E, deadline: Option<SystemTime>) {
    let Some(deadline) = deadline else {
        return pending_forever().await;
    };
    context.sleep_until(deadline).await;
}

async fn receive_command<V, D>(
    commands: &mut mpsc::Receiver<Command<V, D>>,
    enabled: bool,
) -> Option<Command<V, D>>
where
    V: Variant,
    D: Digest,
{
    if !enabled {
        return pending_forever().await;
    }
    commands.recv().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            config::{CodecConfig, Limits},
            machine::{BarrierId, Change, Cursor, DomainEvent, DomainEventCodecConfig},
            storage::JournalConfig,
        },
        types::Epoch,
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{
        BufferPooler, Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{
            DeferredSync, DelayedSyncContext, PendingSyncs, drive_pending_syncs, next_pending_sync,
        },
        utils::reschedule,
    };
    use commonware_utils::{NZU16, NZUsize};
    use futures::poll;

    type TestJob = PersistJob<MinPk, Sha256Digest>;
    type DelayedContext = DelayedSyncContext<deterministic::Context>;

    fn event_codec() -> DomainEventCodecConfig {
        DomainEventCodecConfig::new(
            CodecConfig::new(1, 1, Limits::new(1, 0).unwrap()).unwrap(),
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
        }
    }

    fn job(epoch: Epoch, barrier: u64, previous: u64, urgent: bool) -> TestJob {
        let generation = 1;
        PersistJob::new(
            BarrierId::new(barrier),
            generation,
            Cursor::new(previous),
            vec![DomainEvent::new(
                epoch,
                Cursor::new(previous + 1),
                Change::GenerationAdvanced(generation + barrier),
            )],
            urgent,
        )
    }

    async fn open_empty<E>(
        context: &E,
        partition: &str,
        epoch: Epoch,
    ) -> SafetyJournal<E, MinPk, Sha256Digest>
    where
        E: BufferPooler + Metrics + Storage + Spawner,
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

    async fn open_delayed(
        context: deterministic::Context,
        partition: &str,
        epoch: Epoch,
    ) -> (
        DelayedContext,
        SafetyJournal<DelayedContext, MinPk, Sha256Digest>,
        PendingSyncs,
        usize,
    ) {
        let pending = PendingSyncs::default();
        let context = DelayedSyncContext {
            inner: context,
            pending: pending.clone(),
        };
        let journal = drive_pending_syncs(&pending, open_empty(&context, partition, epoch)).await;
        let baseline = pending.starts();
        (context, journal, pending, baseline)
    }

    fn large_byte_budget() -> NonZeroUsize {
        NonZeroUsize::new(usize::MAX).unwrap()
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

    async fn wait_for_pending(client: &JournalClient<MinPk, Sha256Digest>, expected: usize) {
        for _ in 0..128 {
            if usize::try_from(client.metrics().pending_barriers.get()).unwrap() == expected {
                return;
            }
            reschedule().await;
        }
        assert_eq!(
            usize::try_from(client.metrics().pending_barriers.get()).unwrap(),
            expected,
            "journal owner did not retain the expected barrier count"
        );
    }

    async fn release_next(pending: &PendingSyncs) {
        let DeferredSync { release, blocked } = next_pending_sync(pending);
        blocked.await.expect("the sync handle must be polled");
        release.send(Ok(())).expect("the sync is still waiting");
    }

    async fn finish(
        client: JournalClient<MinPk, Sha256Digest>,
        monitor: JournalMonitor,
        pending: &PendingSyncs,
    ) {
        drop(client);
        drive_pending_syncs(pending, monitor)
            .await
            .expect("journal owner must stop cleanly");
    }

    fn metric_sample(encoded: &str, name: &str) -> f64 {
        encoded
            .lines()
            .find_map(|line| {
                let (sample, value) = line.rsplit_once(' ')?;
                (sample == name).then(|| value.parse().unwrap())
            })
            .unwrap_or_else(|| panic!("missing metric sample {name}: {encoded}"))
    }

    fn assert_histogram(context: &DelayedContext, name: &str, count: u64, sum: f64) {
        let encoded = context.inner.encode();
        assert_eq!(
            metric_sample(&encoded, &format!("{name}_count")),
            count as f64
        );
        let actual_sum = metric_sample(&encoded, &format!("{name}_sum"));
        assert!(
            (actual_sum - sum).abs() < 1e-12,
            "expected histogram sum {sum}, got {}",
            actual_sum
        );
    }

    #[test]
    fn metrics_names_match_dashboard() {
        deterministic::Runner::default().start(|context| async move {
            let journal = context
                .child("engine")
                .child("voter")
                .child("driver")
                .child("journal");
            let metrics = JournalMetrics::new(&journal);
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
                        line.strip_prefix(name).is_some_and(|suffix| {
                            suffix.starts_with(' ') || suffix.starts_with('{')
                        })
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
            const FIRST_SYNC_LATENCY: Duration = Duration::from_millis(25);
            const TAIL_SYNC_LATENCY: Duration = Duration::from_millis(10);
            const EXPECTED_URGENT_TAIL_DELAY: Duration = Duration::from_millis(22);
            const EXPECTED_RELEASE_LATENCY_SUM: Duration = Duration::from_millis(322);

            let epoch = Epoch::new(8);
            let (context, journal, pending, baseline) =
                open_delayed(context, "voter-journal-performance-prefix", epoch).await;
            let gates = TestGates::default();
            let (client, monitor) = spawn_with_gates(
                context.child("owner"),
                journal,
                NZUsize!(16),
                large_byte_budget(),
                Duration::from_secs(3600),
                gates.clone(),
            );

            let first = client
                .try_append(Span::none(), job(epoch, 1, 0, true))
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

            let tail_bytes = (2..=MAX_UNSYNCED as u64 + 1)
                .map(|barrier| {
                    encoded_size(&job(
                        epoch,
                        barrier,
                        barrier - 1,
                        barrier == MAX_UNSYNCED as u64 + 1,
                    ))
                })
                .sum::<usize>();
            let mut tail = Vec::with_capacity(MAX_UNSYNCED);
            let mut tail_append_gate = gates.arm_after_append();
            tail.push(
                client
                    .try_append(Span::none(), job(epoch, 2, 1, false))
                    .unwrap(),
            );
            let tail_appended_at = tail_append_gate.wait_entered_at().await;
            tail_append_gate.release();
            for barrier in 3..=MAX_UNSYNCED as u64 {
                tail.push(
                    client
                        .try_append(Span::none(), job(epoch, barrier, barrier - 1, false))
                        .unwrap(),
                );
            }
            let mut urgent_append_gate = gates.arm_after_append();
            tail.push(
                client
                    .try_append(
                        Span::none(),
                        job(epoch, MAX_UNSYNCED as u64 + 1, MAX_UNSYNCED as u64, true),
                    )
                    .unwrap(),
            );
            let _urgent_appended_at = urgent_append_gate.wait_entered_at().await;
            urgent_append_gate.release();
            let busy = client.try_roll().unwrap();
            assert!(matches!(busy.await, Err(JournalFailure::Busy)));

            assert_eq!(
                pending.starts(),
                baseline + 1,
                "appends behind a sync must not start a concurrent prefix sync"
            );
            assert_eq!(client.metrics().start_syncs.get(), 1);
            assert_eq!(
                client.metrics().appended_barriers.get(),
                MAX_UNSYNCED as u64 + 1
            );
            assert_eq!(
                usize::try_from(client.metrics().pending_barriers.get()).unwrap(),
                MAX_UNSYNCED + 1
            );
            assert_eq!(
                usize::try_from(client.metrics().uncovered_barriers.get()).unwrap(),
                MAX_UNSYNCED
            );
            assert_eq!(client.metrics().covered_barriers.get(), 1);
            assert_eq!(client.metrics().sync_in_flight.get(), 1);
            assert_eq!(
                client.metrics().appended_events.get(),
                MAX_UNSYNCED as u64 + 1
            );
            assert_eq!(
                usize::try_from(client.metrics().appended_bytes.get()).unwrap(),
                encoded_size(&job(epoch, 1, 0, true)) + tail_bytes
            );
            assert_eq!(client.metrics().max_prefix_depth.get(), 1);
            assert_histogram(&context, "owner_prefix_depth", 1, 1.0);
            assert_histogram(&context, "owner_urgent_tail_latency", 0, 0.0);

            let mut tail_start_gate = gates.arm_next_start_sync();
            let (first_sync_started_at, first_released_at) = first_release.await.unwrap();
            assert_eq!(
                first_released_at
                    .duration_since(first_sync_started_at)
                    .unwrap(),
                FIRST_SYNC_LATENCY
            );
            assert_eq!(first.await.unwrap().ack.barrier(), BarrierId::new(1));
            for response in &mut tail {
                assert!(poll!(response).is_pending());
            }

            let tail_sync_started_at = tail_start_gate.wait_entered_at().await;
            tail_start_gate.release();
            wait_for_starts(&pending, baseline + 2).await;
            assert_eq!(client.metrics().start_syncs.get(), 2);
            assert_eq!(
                client.metrics().durable_barriers.get(),
                1,
                "only the first covered prefix is durable"
            );
            assert_eq!(
                usize::try_from(client.metrics().covered_barriers.get()).unwrap(),
                MAX_UNSYNCED
            );
            assert_eq!(client.metrics().uncovered_barriers.get(), 0);
            assert_eq!(client.metrics().max_prefix_depth.get(), MAX_UNSYNCED as i64);
            assert_eq!(
                usize::try_from(client.metrics().max_unsynced_bytes.get()).unwrap(),
                tail_bytes
            );
            assert_eq!(
                u128::try_from(client.metrics().max_unsynced_age_milliseconds.get()).unwrap(),
                tail_sync_started_at
                    .duration_since(tail_appended_at)
                    .unwrap()
                    .as_millis()
            );
            assert_histogram(&context, "owner_prefix_depth", 2, (MAX_UNSYNCED + 1) as f64);
            assert_histogram(
                &context,
                "owner_urgent_tail_latency",
                1,
                EXPECTED_URGENT_TAIL_DELAY.as_secs_f64(),
            );
            assert_eq!(
                client.metrics().start_syncs.get() as f64
                    / client.metrics().appended_barriers.get() as f64,
                2.0 / (MAX_UNSYNCED as f64 + 1.0),
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
            for (offset, response) in tail.into_iter().enumerate() {
                assert_eq!(
                    response.await.unwrap().ack.barrier(),
                    BarrierId::new(offset as u64 + 2)
                );
            }
            assert_eq!(
                client.metrics().durable_barriers.get(),
                MAX_UNSYNCED as u64 + 1
            );
            assert_eq!(client.metrics().pending_barriers.get(), 0);
            assert_eq!(client.metrics().pending_bytes.get(), 0);
            assert_eq!(client.metrics().covered_barriers.get(), 0);
            assert_histogram(
                &context,
                "owner_barrier_latency",
                MAX_UNSYNCED as u64 + 1,
                EXPECTED_RELEASE_LATENCY_SUM.as_secs_f64(),
            );
            finish(client, monitor, &pending).await;
        });
    }

    #[test]
    fn performance_gate_response_retention_ceiling() {
        deterministic::Runner::default().start(|context| async move {
            const CAPACITY: usize = 4;

            let epoch = Epoch::new(8);
            let (context, journal, pending, baseline) =
                open_delayed(context, "voter-journal-performance-capacity", epoch).await;
            let (client, monitor) = spawn(
                context.child("owner"),
                journal,
                NZUsize!(CAPACITY),
                large_byte_budget(),
                Duration::from_secs(3600),
            );
            let mut responses = Vec::with_capacity(CAPACITY * 2);

            responses.push(
                client
                    .try_append(Span::none(), job(epoch, 1, 0, true))
                    .unwrap(),
            );
            wait_for_starts(&pending, baseline + 1).await;
            for barrier in 2..=CAPACITY as u64 {
                responses.push(
                    client
                        .try_append(Span::none(), job(epoch, barrier, barrier - 1, false))
                        .unwrap(),
                );
            }
            wait_for_pending(&client, CAPACITY).await;

            for barrier in CAPACITY as u64 + 1..=CAPACITY as u64 * 2 {
                responses.push(
                    client
                        .try_append(Span::none(), job(epoch, barrier, barrier - 1, false))
                        .unwrap(),
                );
            }
            let rejected = client.try_append(
                Span::none(),
                job(epoch, CAPACITY as u64 * 2 + 1, CAPACITY as u64 * 2, false),
            );
            assert!(matches!(rejected, Err(Admission::Full(_))));
            assert_eq!(responses.len(), CAPACITY * 2);
            assert_eq!(client.capacity(), 0);
            assert_eq!(client.metrics().appended_barriers.get(), CAPACITY as u64);
            assert_eq!(client.metrics().start_syncs.get(), 1);
            assert_eq!(
                usize::try_from(client.metrics().pending_barriers.get()).unwrap(),
                CAPACITY,
                "the owner must stop consuming before retained responses exceed its limit"
            );
            let expected_pending_bytes = (1..=CAPACITY as u64)
                .map(|barrier| encoded_size(&job(epoch, barrier, barrier - 1, barrier == 1)))
                .sum::<usize>();
            assert_eq!(
                usize::try_from(client.metrics().pending_bytes.get()).unwrap(),
                expected_pending_bytes
            );

            drop(client);
            drive_pending_syncs(&pending, async move {
                for (offset, response) in responses.into_iter().enumerate() {
                    assert_eq!(
                        response.await.unwrap().ack.barrier(),
                        BarrierId::new(offset as u64 + 1)
                    );
                }
                monitor.await.unwrap();
            })
            .await;
        });
    }

    #[test]
    fn append_continues_behind_sync_and_urgent_tail_syncs_next() {
        deterministic::Runner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let (context, journal, pending, baseline) =
                open_delayed(context, "voter-journal-pipeline", epoch).await;
            let (client, monitor) = spawn(
                context.child("owner"),
                journal,
                NZUsize!(8),
                large_byte_budget(),
                Duration::from_secs(3600),
            );

            let first = client
                .try_append(Span::none(), job(epoch, 1, 0, true))
                .unwrap();
            wait_for_starts(&pending, baseline + 1).await;
            let mut second = client
                .try_append(Span::none(), job(epoch, 2, 1, true))
                .unwrap();
            let busy = client.try_roll().unwrap();
            assert!(matches!(busy.await, Err(JournalFailure::Busy)));

            release_next(&pending).await;
            let first = first.await.unwrap();
            assert_eq!(first.ack.barrier(), BarrierId::new(1));
            assert!(poll!(&mut second).is_pending());

            wait_for_starts(&pending, baseline + 2).await;
            release_next(&pending).await;
            let second = second.await.unwrap();
            assert_eq!(second.ack.barrier(), BarrierId::new(2));
            finish(client, monitor, &pending).await;
        });
    }

    #[test]
    fn authorization_and_ready_signature_use_the_minimum_one_sync() {
        deterministic::Runner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let (context, journal, pending, baseline) =
                open_delayed(context, "voter-journal-minimum-signature-sync", epoch).await;
            let (client, monitor) = spawn(
                context.child("owner"),
                journal,
                NZUsize!(8),
                large_byte_budget(),
                Duration::from_secs(3600),
            );

            // The authorization starts private signing but exposes no signature, so it may wait
            // for the completion. Once the signed result is appended, one sync is both necessary
            // and sufficient to make the entire contiguous safety prefix durable.
            let authorization = client
                .try_append(Span::none(), job(epoch, 1, 0, false))
                .unwrap();
            let signature = client
                .try_append(Span::none(), job(epoch, 2, 1, true))
                .unwrap();
            wait_for_starts(&pending, baseline + 1).await;

            assert_eq!(client.metrics().start_syncs.get(), 1);
            assert_eq!(client.metrics().appended_barriers.get(), 2);
            assert_eq!(client.metrics().covered_barriers.get(), 2);
            assert_eq!(client.metrics().uncovered_barriers.get(), 0);
            assert_histogram(&context, "owner_prefix_depth", 1, 2.0);

            release_next(&pending).await;
            assert_eq!(
                authorization.await.unwrap().ack.barrier(),
                BarrierId::new(1)
            );
            assert_eq!(signature.await.unwrap().ack.barrier(), BarrierId::new(2));
            assert_eq!(client.metrics().start_syncs.get(), 1);
            finish(client, monitor, &pending).await;
        });
    }

    #[test]
    fn ready_urgent_prefix_uses_one_sync() {
        deterministic::Runner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let (context, journal, pending, baseline) =
                open_delayed(context, "voter-journal-ready-urgent-prefix", epoch).await;
            let (client, monitor) = spawn(
                context.child("owner"),
                journal,
                NZUsize!(8),
                large_byte_budget(),
                Duration::from_secs(3600),
            );

            let first = client
                .try_append(Span::none(), job(epoch, 1, 0, true))
                .unwrap();
            let second = client
                .try_append(Span::none(), job(epoch, 2, 1, true))
                .unwrap();
            wait_for_starts(&pending, baseline + 1).await;

            assert_eq!(client.metrics().start_syncs.get(), 1);
            assert_eq!(client.metrics().covered_barriers.get(), 2);
            assert_eq!(client.metrics().uncovered_barriers.get(), 0);
            release_next(&pending).await;
            assert_eq!(first.await.unwrap().ack.barrier(), BarrierId::new(1));
            assert_eq!(second.await.unwrap().ack.barrier(), BarrierId::new(2));
            assert_eq!(client.metrics().start_syncs.get(), 1);
            finish(client, monitor, &pending).await;
        });
    }

    #[test]
    fn byte_flush_coalesces_the_ready_prefix() {
        deterministic::Runner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let first_job = job(epoch, 1, 0, false);
            let second_job = job(epoch, 2, 1, false);
            let threshold = NonZeroUsize::new(
                encoded_size(&first_job).saturating_add(encoded_size(&second_job)),
            )
            .unwrap();
            let (context, journal, pending, baseline) =
                open_delayed(context, "voter-journal-bytes", epoch).await;
            let (client, monitor) = spawn(
                context.child("owner"),
                journal,
                NZUsize!(8),
                threshold,
                Duration::from_secs(3600),
            );

            let first = client.try_append(Span::none(), first_job).unwrap();
            let second = client.try_append(Span::none(), second_job).unwrap();
            let third = client
                .try_append(Span::none(), job(epoch, 3, 2, false))
                .unwrap();
            let busy = client.try_roll().unwrap();
            assert!(matches!(busy.await, Err(JournalFailure::Busy)));
            wait_for_starts(&pending, baseline + 1).await;
            assert_eq!(client.metrics().start_syncs.get(), 1);
            assert_eq!(client.metrics().appended_barriers.get(), 3);
            assert_histogram(&context, "owner_prefix_depth", 1, 3.0);
            assert_eq!(client.metrics().covered_barriers.get(), 3);
            assert_eq!(client.metrics().uncovered_barriers.get(), 0);
            assert_eq!(client.metrics().uncovered_bytes.get(), 0);

            release_next(&pending).await;
            assert_eq!(first.await.unwrap().ack.barrier(), BarrierId::new(1));
            assert_eq!(second.await.unwrap().ack.barrier(), BarrierId::new(2));
            assert_eq!(third.await.unwrap().ack.barrier(), BarrierId::new(3));
            assert_eq!(pending.starts(), baseline + 1);
            finish(client, monitor, &pending).await;
        });
    }

    #[test]
    fn nonurgent_count_flushes_at_eight() {
        deterministic::Runner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let (context, journal, pending, baseline) =
                open_delayed(context, "voter-journal-count", epoch).await;
            let (client, monitor) = spawn(
                context.child("owner"),
                journal,
                NZUsize!(16),
                large_byte_budget(),
                Duration::from_secs(3600),
            );
            let mut responses = Vec::new();
            for barrier in 1..MAX_UNSYNCED as u64 {
                responses.push(
                    client
                        .try_append(Span::none(), job(epoch, barrier, barrier - 1, false))
                        .unwrap(),
                );
            }
            let busy = client.try_roll().unwrap();
            assert!(matches!(busy.await, Err(JournalFailure::Busy)));
            assert_eq!(pending.starts(), baseline);
            assert_eq!(client.metrics().start_syncs.get(), 0);
            assert_eq!(
                client.metrics().appended_barriers.get(),
                MAX_UNSYNCED as u64 - 1
            );
            assert_eq!(
                usize::try_from(client.metrics().uncovered_barriers.get()).unwrap(),
                MAX_UNSYNCED - 1
            );

            responses.push(
                client
                    .try_append(
                        Span::none(),
                        job(epoch, MAX_UNSYNCED as u64, MAX_UNSYNCED as u64 - 1, false),
                    )
                    .unwrap(),
            );
            wait_for_starts(&pending, baseline + 1).await;
            assert_eq!(client.metrics().start_syncs.get(), 1);
            assert_eq!(
                client.metrics().appended_barriers.get(),
                MAX_UNSYNCED as u64
            );
            assert_histogram(&context, "owner_prefix_depth", 1, MAX_UNSYNCED as f64);
            assert_eq!(client.metrics().covered_barriers.get(), MAX_UNSYNCED as i64);
            assert_eq!(client.metrics().uncovered_barriers.get(), 0);
            release_next(&pending).await;
            for (index, response) in responses.into_iter().enumerate() {
                assert_eq!(
                    response.await.unwrap().ack.barrier(),
                    BarrierId::new(index as u64 + 1)
                );
            }
            finish(client, monitor, &pending).await;
        });
    }

    #[test]
    fn nonurgent_age_flushes_without_more_commands() {
        deterministic::Runner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let delay = Duration::from_millis(25);
            let (context, journal, pending, baseline) =
                open_delayed(context, "voter-journal-age", epoch).await;
            let gates = TestGates::default();
            let (client, monitor) = spawn_with_gates(
                context.child("owner"),
                journal,
                NZUsize!(4),
                large_byte_budget(),
                delay,
                gates.clone(),
            );
            let mut append_gate = gates.arm_after_append();
            let response = client
                .try_append(Span::none(), job(epoch, 1, 0, false))
                .unwrap();
            let appended_at = append_gate.wait_entered_at().await;
            append_gate.release();
            let busy = client.try_roll().unwrap();
            assert!(matches!(busy.await, Err(JournalFailure::Busy)));
            assert_eq!(pending.starts(), baseline);
            assert_eq!(client.metrics().start_syncs.get(), 0);
            assert_histogram(&context, "owner_prefix_depth", 0, 0.0);

            let mut start_gate = gates.arm_next_start_sync();
            let started_at = start_gate.wait_entered_at().await;
            start_gate.release();
            wait_for_starts(&pending, baseline + 1).await;
            assert_eq!(
                started_at.duration_since(appended_at).unwrap(),
                delay,
                "the lazy tail must start at its exact coalescing deadline"
            );
            assert_eq!(client.metrics().start_syncs.get(), 1);
            assert_histogram(&context, "owner_prefix_depth", 1, 1.0);
            let DeferredSync { release, blocked } = next_pending_sync(&pending);
            blocked.await.expect("the lazy sync handle must be polled");
            release.send(Ok(())).expect("the lazy sync is waiting");
            assert_eq!(response.await.unwrap().ack.barrier(), BarrierId::new(1));
            finish(client, monitor, &pending).await;
        });
    }

    #[test]
    fn full_admission_returns_untouched_append() {
        deterministic::Runner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let (context, journal, pending, baseline) =
                open_delayed(context, "voter-journal-full", epoch).await;
            let (client, monitor) = spawn(
                context.child("owner"),
                journal,
                NZUsize!(1),
                large_byte_budget(),
                Duration::from_secs(3600),
            );
            let first = client
                .try_append(Span::none(), job(epoch, 1, 0, true))
                .unwrap();
            let expected = job(epoch, 2, 1, true);
            let returned = match client.try_append(Span::none(), expected.clone()) {
                Err(Admission::Full(append)) => append,
                _ => panic!("the sole command slot must be full"),
            };
            assert_eq!(returned.job, expected);

            wait_for_starts(&pending, baseline + 1).await;
            release_next(&pending).await;
            first.await.unwrap();
            finish(client, monitor, &pending).await;
        });
    }

    #[test]
    fn busy_checkpoint_controls_are_recoverable_and_ordered() {
        deterministic::Runner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let (context, journal, pending, baseline) =
                open_delayed(context, "voter-journal-controls", epoch).await;
            let (client, mut monitor) = spawn(
                context.child("owner"),
                journal,
                NZUsize!(8),
                large_byte_budget(),
                Duration::from_secs(3600),
            );
            let first = client
                .try_append(Span::none(), job(epoch, 1, 0, true))
                .unwrap();
            wait_for_starts(&pending, baseline + 1).await;
            let roll = client.try_roll().unwrap();
            let prune = client.try_prune().unwrap();
            assert!(matches!(roll.await, Err(JournalFailure::Busy)));
            assert!(matches!(prune.await, Err(JournalFailure::Busy)));
            assert!(poll!(&mut monitor).is_pending());

            release_next(&pending).await;
            first.await.unwrap();
            let roll = client.try_roll().unwrap();
            let prune = client.try_prune().unwrap();
            roll.await.unwrap();
            prune.await.unwrap();

            let second = client
                .try_append(Span::none(), job(epoch, 2, 1, true))
                .unwrap();
            wait_for_starts(&pending, baseline + 2).await;
            release_next(&pending).await;
            assert_eq!(second.await.unwrap().ack.barrier(), BarrierId::new(2));
            finish(client, monitor, &pending).await;
        });
    }

    #[test]
    fn append_failure_reaches_every_response_and_monitor() {
        deterministic::Runner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let journal = open_empty(&context, "voter-journal-append-fail", epoch).await;
            let (client, monitor) = spawn(
                context.child("owner"),
                journal,
                NZUsize!(2),
                large_byte_budget(),
                Duration::from_secs(3600),
            );
            let first = client
                .try_append(Span::none(), job(epoch, 1, 7, true))
                .unwrap();
            let second = client
                .try_append(Span::none(), job(epoch, 2, 1, true))
                .unwrap();

            assert!(matches!(first.await, Err(JournalFailure::Journal(_))));
            assert!(matches!(second.await, Err(JournalFailure::Journal(_))));
            assert!(matches!(monitor.await, Err(JournalFailure::Journal(_))));
            drop(client);
        });
    }

    #[test]
    fn sync_failure_reaches_response_and_monitor() {
        deterministic::Runner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let (context, journal, pending, _) =
                open_delayed(context, "voter-journal-sync-fail", epoch).await;
            pending.arm_fail();
            pending.unblock();
            let (client, monitor) = spawn(
                context.child("owner"),
                journal,
                NZUsize!(2),
                large_byte_budget(),
                Duration::from_secs(3600),
            );
            let response = client
                .try_append(Span::none(), job(epoch, 1, 0, true))
                .unwrap();

            assert!(matches!(response.await, Err(JournalFailure::Sync(_))));
            assert!(matches!(monitor.await, Err(JournalFailure::Sync(_))));
            drop(client);
        });
    }
}
