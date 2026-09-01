//! The persistence actor's task.

use super::{
    checkpoint_span,
    hooks::{Hooks, NoHooks},
    mailbox::{Append, CheckpointOrigin, Durable, Error, Flushes, Mailbox, Message, Output},
    metrics::Metrics,
};
use crate::multimmit::{
    actors::util::{gated, some_or_pending},
    machine::{BarrierAck, MAX_INFLIGHT_BARRIERS, Snapshot},
    storage::{JournalRecord, SafetyJournal, SnapshotError, SnapshotStore},
};
use commonware_actor::mailbox;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select_loop;
use commonware_runtime::{
    ContextCell, Error as RuntimeError, Handle, Spawner, spawn_cell,
    telemetry::metrics::HistogramExt as _,
};
use commonware_storage::Context as StorageContext;
use commonware_utils::channel::mpsc;
use std::{collections::VecDeque, future::pending, num::NonZeroUsize, time::SystemTime};
use tracing::{Instrument as _, Span};

/// The journal is taken only for the duration of one storage operation, and a failed operation
/// stops the actor.
const JOURNAL_PRESENT: &str = "the journal is present between storage operations";

/// A storage failure and the root span that owns it.
struct Fault {
    root: Span,
    error: Error,
}

/// A finished snapshot write: the returned store, or why the write failed.
type StoreResult<E, V, D> = Result<SnapshotStore<E, V, D>, SnapshotError>;

/// Configuration for the persistence actor.
pub(crate) struct Config<E: StorageContext, H: Hasher, V: Variant, K: Hooks = NoHooks> {
    /// The epoch's safety journal, positioned after recovery.
    pub(crate) journal: SafetyJournal<E, V, H::Digest>,
    /// Durable checkpoint snapshots.
    pub(crate) checkpoints: SnapshotStore<E, V, H::Digest>,
    /// Bound on queued commands and on appends awaiting durability.
    pub(crate) capacity: NonZeroUsize,
    /// Receives every result in the order it was produced.
    pub(crate) output: mailbox::Sender<Output<V, H::Digest>>,
    /// Runs each snapshot write under its `checkpoint` child.
    pub(crate) snapshot_tasks: E,
    /// The flush requests the actor serves.
    pub(crate) flushes: Flushes,
    /// Observes and may pause storage operations.
    pub(crate) hooks: K,
}

/// One appended barrier awaiting a covering sync.
struct Pending<V: Variant, D: Digest, P> {
    append: Append<V, D>,
    ack: BarrierAck,
    point: P,
    encoded_size: usize,
    appended_at: SystemTime,
    urgent_behind_sync: bool,
}

/// The one in-flight sync and the prefix of pending appends it covers.
struct PrefixSync<P> {
    /// Number of entries at the front of the pending queue captured by this sync.
    covered: usize,
    /// Canonical bytes at the front of the pending queue captured by this sync.
    covered_bytes: usize,
    handle: Handle<()>,
    point: P,
}

/// The checkpoint store and the snapshot write that may hold it.
enum Checkpoint<E: StorageContext, V: Variant, D: Digest> {
    /// No snapshot is being written.
    Idle(SnapshotStore<E, V, D>),
    /// A task is writing the snapshot.
    Storing {
        task: Handle<StoreResult<E, V, D>>,
        origin: CheckpointOrigin,
        /// The write's span, which owns its failure.
        span: Span,
    },
    /// The snapshot is durable; the journal prunes once no append is pending.
    Stored {
        store: SnapshotStore<E, V, D>,
        origin: CheckpointOrigin,
    },
}

/// The persistence actor for one epoch.
pub(crate) struct Actor<E, H, V, K = NoHooks>
where
    E: StorageContext + Spawner,
    H: Hasher,
    V: Variant,
    K: Hooks,
{
    context: ContextCell<E>,
    snapshot_tasks: E,
    journal: Option<SafetyJournal<E, V, H::Digest>>,
    checkpoint: Option<Checkpoint<E, V, H::Digest>>,
    commands: mpsc::Receiver<Message<H, V>>,
    commands_open: bool,
    flushes: mpsc::Receiver<()>,
    flush_requested: bool,
    output: mailbox::Sender<Output<V, H::Digest>>,
    pending: VecDeque<Pending<V, H::Digest, K::Point>>,
    pending_bytes: usize,
    pending_limit: usize,
    sync: Option<PrefixSync<K::Point>>,
    metrics: Metrics,
    hooks: K,
}

impl<E, H, V, K> Actor<E, H, V, K>
where
    E: StorageContext + Spawner,
    H: Hasher,
    V: Variant,
    K: Hooks,
{
    /// Creates the actor and its command mailbox.
    ///
    /// `context` labels the actor's metrics and task. The configured capacity bounds both the
    /// queued commands and the appends awaiting durability: the actor stops receiving commands
    /// while that many appends are pending, so a stalled sync cannot turn prompt command intake
    /// into unbounded retention.
    pub(crate) fn new(context: E, config: Config<E, H, V, K>) -> (Self, Mailbox<H, V>) {
        let Config {
            journal,
            checkpoints,
            capacity,
            output,
            snapshot_tasks,
            flushes,
            hooks,
        } = config;
        let (commands, command_receiver) = mpsc::channel(capacity.get());
        let (flusher, flush_receiver) = flushes.split();
        (
            Self {
                metrics: Metrics::new(&context),
                context: ContextCell::new(context),
                snapshot_tasks,
                journal: Some(journal),
                checkpoint: Some(Checkpoint::Idle(checkpoints)),
                commands: command_receiver,
                commands_open: true,
                flushes: flush_receiver,
                flush_requested: false,
                output,
                pending: VecDeque::new(),
                pending_bytes: 0,
                pending_limit: capacity.get(),
                sync: None,
                hooks,
            },
            Mailbox::new(commands, flusher),
        )
    }

    /// Returns a handle to the actor's metrics.
    #[cfg(test)]
    pub(super) fn metrics(&self) -> Metrics {
        self.metrics.clone()
    }

    /// Starts the actor.
    ///
    /// It stops once every mailbox is dropped and its pending appends are durable, when the
    /// runtime stops, or after reporting a failure.
    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        if let Err(fault) = self.serve().await {
            self.fail(fault);
        }
    }

    async fn serve(&mut self) -> Result<(), Fault> {
        select_loop! {
            self.context,
            on_start => {
                if self.demands_sync() {
                    self.drain_ready_commands().await?;
                    self.start_sync().await?;
                }
                if self.flush_requested && self.covered() {
                    self.flush_requested = false;
                }
                if self.idle() && matches!(self.checkpoint, Some(Checkpoint::Stored { .. })) {
                    self.prune().await?;
                }
                if !self.commands_open && self.pending.is_empty() {
                    return Ok(());
                }
                let receive_commands =
                    self.commands_open && self.pending.len() < self.pending_limit;
            },
            on_stopped => {},
            result = wait_for_sync(self.sync.as_mut()) => {
                result.map_err(|error| self.pending_fault(Error::Sync(error)))?;
                self.complete_sync().await;
            },
            stored = wait_for_store(self.checkpoint.as_mut()) => {
                let store = match stored {
                    Ok(Ok(store)) => store,
                    Ok(Err(error)) => return Err(self.store_fault(error.into())),
                    Err(error) => return Err(self.store_fault(Error::StoreTask(error))),
                };
                self.stored(store);
            },
            command = gated(receive_commands, self.commands.recv()) => {
                let Some(command) = command else {
                    self.commands_open = false;
                    continue;
                };
                self.process(command).await?;
            },
            () = some_or_pending(self.flushes.recv()) => {
                self.flush_requested = true;
            },
        }
        Ok(())
    }

    /// Returns whether the pending appends need a sync now.
    fn demands_sync(&self) -> bool {
        self.sync.is_none()
            && !self.pending.is_empty()
            && (!self.commands_open
                || self.flush_requested
                || self.pending.len() >= self.pending_limit.min(MAX_INFLIGHT_BARRIERS)
                || self
                    .pending
                    .iter()
                    .any(|pending| pending.append.job.urgent()))
    }

    /// Returns whether every append admitted so far is durable or covered by the running sync.
    fn covered(&self) -> bool {
        self.commands.is_empty()
            && self.pending.len() == self.sync.as_ref().map_or(0, |sync| sync.covered)
    }

    /// Returns whether no append is pending, the precondition for rolling and pruning.
    fn idle(&self) -> bool {
        self.pending.is_empty() && self.sync.is_none()
    }

    async fn process(&mut self, command: Message<H, V>) -> Result<(), Fault> {
        match command {
            Message::Append(append) => self.append(append).await,
            Message::Checkpoint { cut, origin, span } => {
                let root = span.clone();
                self.roll(cut, origin)
                    .instrument(span)
                    .await
                    .map_err(|error| Fault { root, error })
            }
        }
    }

    /// Returns `error` owned by the oldest pending append, whose acknowledgement the voter awaits
    /// first, or by `fallback` when none is pending.
    fn append_fault(&self, error: Error, fallback: &Span) -> Fault {
        let root = self
            .pending
            .front()
            .map_or(fallback, |pending| &pending.append.root)
            .clone();
        Fault { root, error }
    }

    /// Returns `error` owned by the oldest pending append.
    fn pending_fault(&self, error: Error) -> Fault {
        self.append_fault(error, &Span::none())
    }

    /// Returns `error` owned by the running snapshot write.
    fn store_fault(&self, error: Error) -> Fault {
        let root = match &self.checkpoint {
            Some(Checkpoint::Storing { span, .. }) => span.clone(),
            _ => Span::none(),
        };
        Fault { root, error }
    }

    /// Appends every command already queued before capturing the next prefix for sync.
    async fn drain_ready_commands(&mut self) -> Result<(), Fault> {
        while self.pending.len() < self.pending_limit {
            let Ok(command) = self.commands.try_recv() else {
                break;
            };
            self.process(command).await?;
        }
        Ok(())
    }

    #[tracing::instrument(
        name = "multimmit.voter.journal.append.process",
        level = "info",
        skip_all,
        parent = &append.span,
        fields(barrier = append.job.id().get())
    )]
    async fn append(&mut self, append: Append<V, H::Digest>) -> Result<(), Fault> {
        let journal = self.journal.take().expect(JOURNAL_PRESENT);
        let point = self.hooks.appending(&append.job);
        self.hooks.before_append(point, &*self.context).await;
        let (journal, ack) = journal
            .append_persist(&append.job)
            .await
            .map_err(|error| self.append_fault(error.into(), &append.root))?;
        self.journal = Some(journal);
        let appended_at = self.context.current();
        self.hooks.after_append(point, appended_at).await;
        let encoded_size = JournalRecord::encoded_size(&append.job);
        let event_count = append.job.events().len();
        let urgent_behind_sync = self.sync.is_some() && append.job.urgent();
        self.pending.push_back(Pending {
            append,
            ack,
            point,
            encoded_size,
            appended_at,
            urgent_behind_sync,
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
        Ok(())
    }

    async fn start_sync(&mut self) -> Result<(), Fault> {
        if self.sync.is_some() || self.pending.is_empty() {
            return Ok(());
        }

        let covered = self.pending.len();
        let newest = self
            .pending
            .back()
            .expect("a sync covers at least one append");
        let point = newest.point;
        // The sync serves every covered barrier; the newest one parents the storage spans so
        // fsyncs surface inside the round that paid for them instead of as detached roots.
        let span = newest.append.span.clone();
        let covered_bytes = self.pending_bytes;
        let oldest = self
            .pending
            .front()
            .expect("a sync covers at least one append")
            .appended_at;
        let now = self.context.current();
        let oldest_urgent = self
            .pending
            .iter()
            .find(|pending| pending.urgent_behind_sync)
            .map(|pending| pending.appended_at);
        let journal = self.journal.take().expect(JOURNAL_PRESENT);
        self.hooks.before_start_sync(point, now).await;
        let (journal, handle) = journal
            .start_sync()
            .instrument(span)
            .await
            .map_err(|error| self.pending_fault(error.into()))?;
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
            point,
        });
        self.update_depth_metrics();
        Ok(())
    }

    async fn complete_sync(&mut self) {
        let sync = self.sync.take().expect("a completed sync was in flight");
        self.hooks.after_sync(sync.point, &*self.context).await;
        self.metrics.sync_in_flight.set(0);
        for _ in 0..sync.covered {
            let Pending {
                append: Append { root, span, job },
                ack,
                encoded_size,
                appended_at,
                ..
            } = self
                .pending
                .pop_front()
                .expect("a completed sync covers retained appends");
            self.pending_bytes = self.pending_bytes.saturating_sub(encoded_size);
            self.metrics
                .barrier_latency
                .observe_between(appended_at, self.context.current());
            self.metrics.durable_barriers.inc();
            self.emit(Output::Durable(Durable {
                root,
                span,
                job,
                ack,
            }));
        }
        self.update_depth_metrics();
    }

    /// Rolls the journal to the section that follows `cut`, then writes its snapshot on a task.
    ///
    /// The roll precedes snapshot materialization, and every later append lands in the new
    /// section.
    #[tracing::instrument(
        name = "multimmit.voter.journal.roll.process",
        level = "info",
        skip_all
    )]
    async fn roll(
        &mut self,
        cut: Box<Snapshot<V, H::Digest>>,
        origin: CheckpointOrigin,
    ) -> Result<(), Error> {
        if !self.idle() || !matches!(self.checkpoint, Some(Checkpoint::Idle(_))) {
            return Err(Error::Busy);
        }
        let Some(Checkpoint::Idle(store)) = self.checkpoint.take() else {
            unreachable!("checked above");
        };
        let journal = self.journal.take().expect(JOURNAL_PRESENT);
        self.hooks.before_roll(&*self.context).await;
        self.journal = Some(journal.roll());
        let span = checkpoint_span!(None, "multimmit.voter.checkpoint.store", origin);
        let write = span.clone();
        let task = self
            .snapshot_tasks
            .child("checkpoint")
            .shared(true)
            .spawn(move |_| async move { store.store(*cut).await }.instrument(write));
        self.checkpoint = Some(Checkpoint::Storing { task, origin, span });
        Ok(())
    }

    /// Records a durable snapshot; its prune runs once no append is pending.
    fn stored(&mut self, store: SnapshotStore<E, V, H::Digest>) {
        let Some(Checkpoint::Storing { origin, .. }) = self.checkpoint.take() else {
            unreachable!("only a running snapshot write completes");
        };
        self.checkpoint = Some(Checkpoint::Stored { store, origin });
        self.emit(Output::Stored);
    }

    /// Prunes the journal sections covered by the stored snapshot.
    async fn prune(&mut self) -> Result<(), Fault> {
        let Some(Checkpoint::Stored { store, origin }) = self.checkpoint.take() else {
            unreachable!("only a stored snapshot is pruned behind");
        };
        let span = checkpoint_span!(None, "multimmit.voter.checkpoint.prune", origin);
        let root = span.clone();
        self.prune_journal()
            .instrument(span)
            .await
            .map_err(|error| Fault { root, error })?;
        self.checkpoint = Some(Checkpoint::Idle(store));
        self.emit(Output::Pruned);
        Ok(())
    }

    #[tracing::instrument(
        name = "multimmit.voter.journal.prune.process",
        level = "info",
        skip_all
    )]
    async fn prune_journal(&mut self) -> Result<(), Error> {
        let journal = self.journal.take().expect(JOURNAL_PRESENT);
        let ordinal = self.hooks.before_prune(&*self.context).await;
        let section = journal.section();
        self.journal = Some(journal.prune_before(section).await?);
        self.hooks.after_prune(ordinal, &*self.context).await;
        Ok(())
    }

    fn emit(&self, output: Output<V, H::Digest>) {
        // A closed output means the voter stopped; the actor follows once its mailbox drops.
        let _ = self.output.enqueue(output);
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

    /// Discards all retained work and reports the failure.
    fn fail(&mut self, fault: Fault) {
        self.commands.close();
        self.sync = None;
        self.metrics.sync_in_flight.set(0);
        self.pending.clear();
        self.pending_bytes = 0;
        self.update_depth_metrics();
        self.journal = None;
        let Fault { root, error } = fault;
        self.emit(Output::Failed { root, error });
    }
}

async fn wait_for_sync<P>(sync: Option<&mut PrefixSync<P>>) -> Result<(), RuntimeError> {
    let Some(sync) = sync else {
        return pending().await;
    };
    (&mut sync.handle).await
}

async fn wait_for_store<E, V, D>(
    checkpoint: Option<&mut Checkpoint<E, V, D>>,
) -> Result<StoreResult<E, V, D>, RuntimeError>
where
    E: StorageContext,
    V: Variant,
    D: Digest,
{
    match checkpoint {
        Some(Checkpoint::Storing { task, .. }) => task.await,
        _ => pending().await,
    }
}
