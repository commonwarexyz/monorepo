//! Core sync engine components that are shared across sync clients.
use crate::{
    merkle::{
        Family, Location,
        mem::{self, Mem},
    },
    qmdb::{
        self,
        sync::{
            Database, Error as SyncError, Journal, Metrics, SourceFor, Target,
            database::Config as _,
            error::EngineError,
            requests::{Id as RequestId, Requests},
            source::{Request, Response, Source},
        },
    },
};
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher};
use commonware_macros::{boxed, select};
use commonware_runtime::Supervisor as _;
use commonware_utils::channel::{fallible::AsyncFallibleExt, mpsc};
use futures::future::{Aborted, Either, pending};
use mpsc::error::TryRecvError;
use std::{
    collections::BTreeMap,
    fmt::Debug,
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
    sync::Arc,
};

/// Number of newer updates after which the first escape is replaced. Each replacement doubles it.
const ESCAPE_UPDATES: usize = 2;

/// Most operations a target update derives pinned nodes over. Derivation reads and hashes them on
/// the engine task, which handles no responses or updates meanwhile, so a longer move of the lower
/// bound fetches the boundary instead.
const MAX_DERIVED_OPERATIONS: u64 = 1 << 16;

/// What handling a fetch result leaves the engine to do.
enum Fetched<DB: Database> {
    /// A request for the current target completed, or a request was cancelled.
    Current,
    /// A deferred update's boundary request failed, or its boundary arrived once nothing below its
    /// lower bound was outstanding.
    Unused,
    /// A deferred update's boundary arrived while a request below its lower bound was
    /// outstanding. The update is adopted with the operation and pinned nodes at its lower bound.
    Adopt(Target<DB::Family, DB::Digest>, DB::Op, Vec<DB::Digest>),
}

/// Target updates deferred until the current target is reached.
///
/// It keeps the newest update and an older one, the escape. While they wait behind a request below
/// their lower bounds, the engine also fetches their boundaries, and adopts an update whose
/// boundary arrives while that request is still outstanding. Each newer update replaces the newest
/// one. An escape whose boundary has not arrived after `lifetime` updates is replaced by the
/// previous newest update, and the lifetime doubles, so an escape's boundary request eventually
/// outlives any round trip. Adopting an update resets the lifetime.
enum Deferred<F: Family, D: Digest> {
    /// No update is deferred.
    Empty,
    /// One update is deferred, and it is the escape.
    One(Target<F, D>),
    /// The escape and a newer update are deferred.
    Two {
        escape: Target<F, D>,
        latest: Target<F, D>,
        /// Number of updates deferred since the escape.
        age: usize,
        /// Number of newer updates after which the escape is replaced.
        lifetime: usize,
    },
}

impl<F: Family, D: Digest> Deferred<F, D> {
    /// Returns the newest deferred update.
    const fn latest(&self) -> Option<&Target<F, D>> {
        match self {
            Self::Empty => None,
            Self::One(latest) | Self::Two { latest, .. } => Some(latest),
        }
    }

    /// Returns the escape and the newer update, if deferred.
    const fn kept(&self) -> [Option<&Target<F, D>>; 2] {
        match self {
            Self::Empty => [None, None],
            Self::One(escape) => [Some(escape), None],
            Self::Two { escape, latest, .. } => [Some(escape), Some(latest)],
        }
    }

    /// Defers `update` as the newest update.
    const fn push(&mut self, update: Target<F, D>) {
        *self = match std::mem::replace(self, Self::Empty) {
            Self::Empty => Self::One(update),
            Self::One(escape) => Self::Two {
                escape,
                latest: update,
                age: 1,
                lifetime: ESCAPE_UPDATES,
            },
            // The previous newest update arrived one update ago.
            Self::Two {
                latest,
                age,
                lifetime,
                ..
            } if age + 1 >= lifetime => Self::Two {
                escape: latest,
                latest: update,
                age: 1,
                lifetime: lifetime.saturating_mul(2),
            },
            Self::Two {
                escape,
                age,
                lifetime,
                ..
            } => Self::Two {
                escape,
                latest: update,
                age: age + 1,
                lifetime,
            },
        };
    }

    /// Removes and returns the newest update with lower bound `start`, with every older update.
    fn take_at(&mut self, start: Location<F>) -> Option<Target<F, D>> {
        match std::mem::replace(self, Self::Empty) {
            Self::One(update) | Self::Two { latest: update, .. }
                if update.range.start() == start =>
            {
                Some(update)
            }
            Self::Two { escape, latest, .. } if escape.range.start() == start => {
                *self = Self::One(latest);
                Some(escape)
            }
            unchanged => {
                *self = unchanged;
                None
            }
        }
    }

    /// Removes every update and returns the newest.
    const fn take_latest(&mut self) -> Option<Target<F, D>> {
        match std::mem::replace(self, Self::Empty) {
            Self::Empty => None,
            Self::One(latest) | Self::Two { latest, .. } => Some(latest),
        }
    }
}

/// Type alias for sync engine errors
type Error<DB, S> =
    qmdb::sync::Error<<DB as Database>::Family, <S as Source>::Error, <DB as Database>::Digest>;

/// Whether sync should continue or complete
#[derive(Debug)]
pub(crate) enum NextStep<C, D> {
    /// Sync should continue with the updated client
    Continue(C),
    /// Sync is complete with the final database
    Complete(D),
}

/// Events that can occur during synchronization
#[derive(Debug)]
enum Event<F: Family, Op, D: Digest, E> {
    /// A target update was received
    TargetUpdate(Target<F, D>),
    /// A batch of operations was received, or its request was aborted by a target update
    BatchReceived(Result<IndexedFetchResult<F, Op, D, E>, Aborted>),
    /// The target update channel was closed
    UpdateChannelClosed,
    /// A finish signal was received
    FinishRequested,
    /// The finish signal channel was closed
    FinishChannelClosed,
}

/// Result from a fetch operation, tagged with its request ID.
#[derive(Debug)]
pub(super) struct IndexedFetchResult<F: Family, Op, D: Digest, E> {
    /// Unique ID assigned when the request was scheduled.
    pub id: RequestId,
    /// The result of the fetch operation.
    pub result: Result<Option<Response<F, Op, D>>, E>,
}

/// Verifies one response against the exact request and trusted root that scheduled it.
fn verify_response<F, Op, H>(
    request: Request<F>,
    root: &H::Digest,
    response: &Response<F, Op, H::Digest>,
) -> bool
where
    F: Family,
    Op: Encode,
    H: Hasher,
{
    if response.proof().leaves != request.size() {
        return false;
    }

    let hasher = qmdb::hasher::<H>();
    match (&request, response) {
        (
            Request::Operations {
                size,
                start,
                max_ops,
            },
            Response::Operations { proof, operations },
        ) => {
            // An honest source returns every requested operation that exists at `size`.
            let expected = max_ops.get().min((**size).saturating_sub(**start));
            if expected == 0 || operations.len() as u64 != expected {
                false
            } else {
                let elements = operations.iter().map(Encode::encode).collect::<Vec<_>>();
                proof.verify_range_inclusion(&hasher, &elements, *start, root)
            }
        }
        (
            Request::Boundary { start, .. },
            Response::Boundary {
                proof,
                op,
                pinned_nodes,
            },
        ) => {
            proof.verify_proof_and_pinned_nodes(&hasher, &[op.encode()], *start, pinned_nodes, root)
        }
        _ => false,
    }
}

/// Returns the pinned nodes at `range.end` from the pinned nodes at `range.start` and the
/// operations in `range`, read from `journal` in chunks of at most `chunk` operations.
async fn derive_pinned_nodes<F, H, J>(
    journal: &J,
    pinned_nodes: Vec<H::Digest>,
    range: Range<Location<F>>,
    chunk: NonZeroU64,
) -> Result<Vec<H::Digest>, qmdb::Error<F>>
where
    F: Family,
    H: Hasher,
    J: Journal<F>,
    J::Op: Encode,
{
    let hasher = qmdb::hasher::<H>();
    let mut merkle = Mem::init(mem::Config {
        nodes: Vec::new(),
        pruning_boundary: range.start,
        pinned_nodes,
    })?;

    // Fold each chunk into the structure and prune behind it.
    let mut start = range.start;
    while start < range.end {
        let end = start
            .checked_add(chunk.get())
            .map_or(range.end, |end| end.min(range.end));
        let ops = journal.read_range(start..end).await.map_err(Into::into)?;
        let batch = merkle
            .new_batch()
            .add_many(&hasher, &ops)
            .merkleize(&merkle, &hasher);
        merkle
            .apply_batch(&batch)
            .expect("batch extends the structure");
        merkle
            .prune(end)
            .expect("chunk end is within the structure");
        start = end;
    }
    Ok(merkle.node_digests_to_pin(range.end))
}

/// Wait for the next synchronization event.
/// Returns `None` when there are no outstanding requests and no channels to wait on.
async fn wait_for_event<F: Family, Op: Send, D: Digest, E: Send>(
    update_rx: &mut Option<mpsc::Receiver<Target<F, D>>>,
    finish_rx: &mut Option<mpsc::Receiver<()>>,
    outstanding_requests: &mut Requests<F, Op, D, E>,
) -> Option<Event<F, Op, D, E>> {
    if outstanding_requests.len() == 0 && update_rx.is_none() && finish_rx.is_none() {
        return None;
    }

    let target_update_fut = update_rx.as_mut().map_or_else(
        || Either::Right(pending()),
        |update_rx| Either::Left(update_rx.recv()),
    );
    let finish_fut = finish_rx.as_mut().map_or_else(
        || Either::Right(pending()),
        |finish_rx| Either::Left(finish_rx.recv()),
    );
    let batch_result_fut = outstanding_requests.next_completed();

    select! {
        finish = finish_fut => finish.map_or_else(
            || Some(Event::FinishChannelClosed),
            |_| Some(Event::FinishRequested)
        ),
        target = target_update_fut => target.map_or_else(
            || Some(Event::UpdateChannelClosed),
            |target| Some(Event::TargetUpdate(target))
        ),
        result = batch_result_fut => Some(Event::BatchReceived(result)),
    }
}

/// Configuration for creating a new Engine
pub struct Config<DB, S>
where
    DB: Database,
    S: SourceFor<DB>,
    DB::Op: Encode,
{
    /// Runtime context for creating database components
    pub context: DB::Context,
    /// Source of operations and proofs
    pub source: S,
    /// Trusted sync target (root digest and operation bounds).
    ///
    /// The engine only verifies source data against this commitment and does not select or
    /// authenticate the target.
    pub target: Target<DB::Family, DB::Digest>,
    /// Maximum number of outstanding operations requests. Boundary requests are outstanding beyond
    /// it: one for the current target's pinned nodes and, while updates are deferred, up to two for
    /// deferred updates.
    ///
    /// Sync requests no operations starting `2 * max_outstanding_requests * fetch_batch_size` or
    /// more past the journal tip, which bounds how many fetched operations wait in memory.
    pub max_outstanding_requests: NonZeroUsize,
    /// Maximum operations to fetch per batch
    pub fetch_batch_size: NonZeroU64,
    /// Number of operations read and hashed per batch when the Merkle structure is rebuilt from
    /// the synced journal at the end of sync, and when pinned nodes are derived after the lower
    /// bound moves. Bounds the memory that work uses.
    pub apply_batch_size: NonZeroU64,
    /// Database-specific configuration
    pub db_config: DB::Config,
    /// Channel for receiving sync target updates.
    ///
    /// The caller selects targets before sending updates. The engine adopts only strictly
    /// advancing targets and discards the rest.
    ///
    /// Once every remaining operation is fetched or requested, the engine defers updates until the
    /// current target is reached, then adopts the newest. While deferred updates wait behind a
    /// request below their lower bounds, the engine also fetches the boundaries of the newest and
    /// of one older update, and adopts an update whose boundary arrives while that request is
    /// still outstanding. Each newer update replaces the newest one's request. The older one's
    /// request is replaced after two updates, and each replacement doubles how many updates the
    /// next one is kept for. A failed request for a deferred update's boundary does not fail
    /// sync, and is retried later. Requests below the lower bound of the newest target sent may
    /// never be answered, but the source must keep serving every request at or beyond it.
    pub update_rx: Option<mpsc::Receiver<Target<DB::Family, DB::Digest>>>,
    /// Channel that requests sync completion once the current target is reached. Updates are
    /// still handled after the request, and sync completes at the first target it reaches.
    ///
    /// When `None`, sync completes as soon as the target is reached.
    pub finish_rx: Option<mpsc::Receiver<()>>,
    /// Channel used to notify an observer once the current target is reached.
    /// The engine sends at most one notification for each target it reaches, before it adopts a
    /// later one. A target left for a deferred update whose boundary arrived first is not
    /// reported.
    ///
    /// When `reached_target_tx` is `Some(...)`, this receiver must be actively
    /// drained by the observer. The engine awaits send capacity on this channel before
    /// proceeding, so backpressure can pause progress at target.
    pub reached_target_tx: Option<mpsc::Sender<Target<DB::Family, DB::Digest>>>,
}
/// A shared sync engine that manages the core synchronization state and operations.
pub(crate) struct Engine<DB, S>
where
    DB: Database,
    S: SourceFor<DB>,
    DB::Op: Encode,
{
    /// Tracks outstanding fetch requests and their futures
    outstanding_requests: Requests<DB::Family, DB::Op, DB::Digest, S::Error>,

    /// Operations that have been fetched but not yet applied to the log.
    ///
    /// # Invariant
    ///
    /// The vectors in the map are non-empty.
    fetched_operations: BTreeMap<Location<DB::Family>, Vec<DB::Op>>,

    /// Pinned merkle nodes at `target.range.start()`, used for database construction.
    ///
    /// They are recovered from local Merkle state, extracted from boundary proofs, or derived
    /// across a lower bound move.
    pinned_nodes: Option<Vec<DB::Digest>>,

    /// The current sync target (root digest and operation bounds)
    target: Target<DB::Family, DB::Digest>,

    /// Target updates deferred until the current target is reached.
    deferred: Deferred<DB::Family, DB::Digest>,

    /// Maximum number of parallel outstanding requests
    max_outstanding_requests: NonZeroUsize,

    /// Maximum operations to fetch in a single batch
    fetch_batch_size: NonZeroU64,

    /// Number of operations per batch when rebuilding the Merkle structure at the end of sync or
    /// deriving pinned nodes
    apply_batch_size: NonZeroU64,

    /// Journal that operations are applied to during sync
    journal: DB::Journal,

    /// Source of operations and proofs, shared with in-flight requests
    source: Arc<S>,

    /// Runtime context for database operations
    context: DB::Context,

    /// Configuration for building the final database
    config: DB::Config,

    /// Optional receiver for target updates during sync
    update_rx: Option<mpsc::Receiver<Target<DB::Family, DB::Digest>>>,

    /// Whether the caller has asked the sync to finish at the current target.
    finish_requested: bool,

    /// Channel that requests sync completion once the current target is reached.
    ///
    /// When `None`, sync completes as soon as the target is reached.
    finish_rx: Option<mpsc::Receiver<()>>,

    /// Channel used to notify an observer once the current target is reached.
    /// The engine sends at most one notification for each target it reaches, before it adopts a
    /// later one.
    ///
    /// When `reached_target_tx` is `Some(...)`, this receiver must be actively
    /// drained by the observer. The engine awaits send capacity on this channel before
    /// proceeding, so backpressure can pause progress at target.
    reached_target_tx: Option<mpsc::Sender<Target<DB::Family, DB::Digest>>>,

    /// Progress gauges updated after target updates and batch application.
    metrics: Metrics,

    /// Tracks whether the current target has already been reported as reached.
    reached_current_target_reported: bool,
}

#[cfg(test)]
impl<DB, S> Engine<DB, S>
where
    DB: Database,
    S: SourceFor<DB>,
    DB::Op: Encode,
{
    pub(crate) fn journal(&self) -> &DB::Journal {
        &self.journal
    }
}

impl<DB, S> Engine<DB, S>
where
    DB: Database,
    S: SourceFor<DB>,
    DB::Op: Encode,
{
    pub async fn new(config: Config<DB, S>) -> Result<Self, Error<DB, S>> {
        if !config.target.range.end().is_valid() {
            return Err(SyncError::Engine(EngineError::InvalidTarget {
                lower_bound_pos: config.target.range.start(),
                upper_bound_pos: config.target.range.end(),
            }));
        }

        // Recover the operation prefix that can resume this target.
        let journal = <DB::Journal as Journal<DB::Family>>::new(
            config.context.child("journal"),
            config.db_config.journal_config(),
            config.target.range.clone(),
        )
        .await?;
        let journal_size = journal.size();

        // The sync journal is the source of truth for resume. If it already
        // reaches the target, try to recover the target's pinned nodes from local
        // Merkle state before asking peers for them. Partial journals resume without
        // probing completed database state.
        let pinned_nodes = if journal_size == *config.target.range.end() {
            DB::local_pinned_nodes(
                config.context.child("local_pinned_nodes"),
                &config.db_config,
                &config.target,
                &journal,
            )
            .await?
        } else {
            None
        };

        let sync_context = config.context.child("sync");
        let metrics = Metrics::new(&sync_context);
        let mut engine = Self {
            outstanding_requests: Requests::new(),
            fetched_operations: BTreeMap::new(),
            pinned_nodes,
            target: config.target.clone(),
            deferred: Deferred::Empty,
            max_outstanding_requests: config.max_outstanding_requests,
            fetch_batch_size: config.fetch_batch_size,
            apply_batch_size: config.apply_batch_size,
            journal,
            source: Arc::new(config.source),
            context: config.context,
            config: config.db_config,
            update_rx: config.update_rx,
            finish_requested: false,
            finish_rx: config.finish_rx,
            reached_target_tx: config.reached_target_tx,
            reached_current_target_reported: false,
            metrics,
        };
        engine.schedule_requests();
        engine.record_progress();
        Ok(engine)
    }

    /// Track `request` and spawn its fetch against the shared source, verified against `root`.
    fn spawn_fetch(&mut self, request: Request<DB::Family>, root: DB::Digest) {
        let source = Arc::clone(&self.source);
        self.outstanding_requests
            .insert(request, move |id| async move {
                let result: Result<_, S::Error> = async {
                    let (mut response, mut feedback) = source.serve(request).await?;
                    loop {
                        if verify_response::<DB::Family, DB::Op, DB::Hasher>(
                            request, &root, &response,
                        ) {
                            if let Some(feedback) = feedback {
                                feedback.accept();
                            }
                            return Ok(Some(response));
                        }

                        let Some(current) = feedback else {
                            return Ok(None);
                        };
                        let Some((next_response, next_feedback)) = current.reject().await else {
                            return Ok(None);
                        };
                        response = next_response;
                        feedback = Some(next_feedback);
                    }
                }
                .await;
                IndexedFetchResult { id, result }
            });
    }

    /// Returns the outstanding requests for the current target, in ascending order of start. A
    /// boundary request at any other lower bound belongs to a deferred update.
    fn current_requests(&self) -> impl Iterator<Item = Request<DB::Family>> + '_ {
        let start = self.target.range.start();
        self.outstanding_requests.requests().filter(move |request| {
            !matches!(request, Request::Boundary { .. }) || request.start() == start
        })
    }

    /// Returns the first range of the current target that is neither fetched nor requested.
    fn next_gap(&self) -> Option<Range<Location<DB::Family>>> {
        crate::qmdb::sync::gaps::find_next(
            Location::new(self.journal.size())..self.target.range.end(),
            self.fetched_operations.iter().map(|(&start, operations)| {
                start..start.checked_add(operations.len() as u64).unwrap()
            }),
            self.current_requests().map(|request| {
                let start = request.start();
                start..start.checked_add(request.max_ops().get()).unwrap()
            }),
        )
    }

    /// Schedule new fetch requests for operations in the sync range that we haven't yet fetched.
    ///
    /// Only operations within twice the in-flight capacity of the journal tip are requested, so a
    /// stalled request at the tip bounds how many operations are buffered behind it.
    fn schedule_requests(&mut self) {
        let target_size = self.target.range.end();

        // Schedule a boundary request at the lower sync bound if pinned nodes are still
        // needed and one isn't already in flight. The pinned nodes it returns are what let
        // us rebuild the pruned prefix.
        if !self.pinned_nodes_ready()
            && !self
                .outstanding_requests
                .contains(&self.target.range.start())
        {
            let request = Request::Boundary {
                size: target_size,
                start: self.target.range.start(),
            };
            self.spawn_fetch(request, self.target.root);
        }

        // Calculate the maximum number of requests to make. Boundary requests do not count toward
        // the maximum, so operations keep arriving while one is outstanding.
        let operations = self
            .outstanding_requests
            .requests()
            .filter(|request| matches!(request, Request::Operations { .. }))
            .count();
        let num_requests = self
            .max_outstanding_requests
            .get()
            .saturating_sub(operations);

        let lookahead = (self.max_outstanding_requests.get() as u64)
            .saturating_mul(2)
            .saturating_mul(self.fetch_batch_size.get());
        let lookahead_end = self.journal.size().saturating_add(lookahead);

        for _ in 0..num_requests {
            // Find the next gap in the sync range that needs to be fetched.
            let Some(gap_range) = self.next_gap() else {
                break; // No more gaps to fill
            };
            if *gap_range.start >= lookahead_end {
                break; // The rest waits for the journal to advance
            }

            // Calculate batch size for this gap
            let gap_size = *gap_range.end.checked_sub(*gap_range.start).unwrap();
            let gap_size: NonZeroU64 = gap_size.try_into().unwrap();
            let batch_size = self.fetch_batch_size.min(gap_size);

            // Schedule the request
            let request = Request::Operations {
                size: target_size,
                start: gap_range.start,
                max_ops: batch_size,
            };
            self.spawn_fetch(request, self.target.root);
        }
    }

    /// Returns whether a request of the current target below `start` is outstanding.
    fn blocks(&self, start: Location<DB::Family>) -> bool {
        self.current_requests()
            .next()
            .is_some_and(|request| request.start() < start)
    }

    /// Fetch the boundary of each kept deferred update that waits behind a request below its lower
    /// bound, so it is adopted even if that request never completes.
    ///
    /// Requests are tracked by start location, so an operations request of the current target at
    /// the same location replaces a deferred boundary request, which is issued again once that
    /// request completes. A failed request is issued again once another request completes or an
    /// update is deferred or adopted.
    fn fetch_deferred_boundaries(&mut self) {
        let kept = self.deferred.kept().map(|update| {
            update.map(|update| (update.range.start(), update.range.end(), update.root))
        });
        for (start, size, root) in kept.into_iter().flatten() {
            if self.blocks(start) && !self.outstanding_requests.contains(&start) {
                self.spawn_fetch(Request::Boundary { size, start }, root);
            }
        }
    }

    /// Reset sync state for a target update, given the pinned nodes at a moved lower bound if they
    /// are known.
    ///
    /// Keeps fetched operations. Keeps pinned nodes while the lower bound is unchanged, and
    /// otherwise takes `pinned_nodes`. Keeps outstanding requests, whatever target size they were
    /// issued for, except those below a moved lower bound and, at it, an operations request while
    /// the pinned nodes are unknown or a boundary request once they are known. Each request
    /// verifies against the root it was issued with.
    pub async fn reset_for_target_update(
        mut self,
        new_target: Target<DB::Family, DB::Digest>,
        pinned_nodes: Option<Vec<DB::Digest>>,
    ) -> Result<Self, Error<DB, S>> {
        let start_moved = self.target.range.start() != new_target.range.start();
        self.journal = self.journal.resize(new_target.range.start()).await?;
        if start_moved {
            self.pinned_nodes = pinned_nodes;
        }

        // A source may prune up to the new lower bound, so a request below a moved bound may
        // never be answered. Requests are also tracked by start location, so an operations request
        // kept at the new bound would block the boundary request there, which is only needed while
        // the pinned nodes are unknown.
        let new_start = new_target.range.start();
        let known = self.pinned_nodes.is_some();
        self.outstanding_requests.retain(|request| {
            !start_moved
                || request.start() > new_start
                || (request.start() == new_start
                    && known != matches!(request, Request::Boundary { .. }))
        });

        self.target = new_target;
        self.reached_current_target_reported = false;
        Ok(self)
    }

    /// Drain a pending explicit-finish signal without blocking.
    ///
    /// If a finish signal is present, the finish channel is dropped and the engine
    /// may complete as soon as it is at a target. If the finish channel is
    /// disconnected before a finish request is observed, this returns
    /// [`EngineError::FinishChannelClosed`].
    fn drain_finish_requests(&mut self) -> Result<(), Error<DB, S>> {
        let Some(finish_rx) = self.finish_rx.as_mut() else {
            return Ok(());
        };
        match finish_rx.try_recv() {
            Ok(()) => {
                self.finish_rx = None;
                self.finish_requested = true;
                Ok(())
            }
            Err(TryRecvError::Empty) => Ok(()),
            Err(TryRecvError::Disconnected) => {
                Err(SyncError::Engine(EngineError::FinishChannelClosed))
            }
        }
    }

    /// Notify an observer that the current target has been reached. The notification is sent
    /// at most once per target, guarded by `reached_current_target_reported`.
    ///
    /// This send awaits backpressure. When `reached_target_tx` is `Some(...)`,
    /// the receiver is expected to consume notifications promptly so the engine
    /// can keep making progress. If the receiver side is closed, we drop the
    /// sender and continue syncing without further reached-target notifications.
    async fn report_reached_target(&mut self) {
        if self.reached_current_target_reported {
            return;
        }
        if let Some(sender) = self.reached_target_tx.as_ref()
            && !sender.send_lossy(self.target.clone()).await
        {
            self.reached_target_tx = None;
        }
        self.reached_current_target_reported = true;
    }

    /// Record a progress snapshot in metrics.
    fn record_progress(&mut self) {
        self.metrics.record_target(*self.target.range.end());
        self.metrics.record_synced(self.journal.size());
    }

    /// Store a batch of fetched operations. If the input list is empty, this is a no-op.
    ///
    /// Each start has at most one outstanding request, and gaps skip stored batches, so a batch
    /// never replaces another.
    pub(crate) fn store_operations(
        &mut self,
        start_loc: Location<DB::Family>,
        operations: Vec<DB::Op>,
    ) {
        if operations.is_empty() {
            return;
        }
        self.fetched_operations.insert(start_loc, operations);
    }

    /// Apply fetched operations to the journal if we have them.
    ///
    /// This method finds operations that are contiguous with the current journal tip
    /// and applies them in order. It removes stale batches and handles partial
    /// application of batches when needed.
    pub(crate) async fn apply_operations(mut self) -> Result<Self, Error<DB, S>> {
        let mut next_loc = self.journal.size();

        // Remove any batches of operations with stale data.
        // That is, those whose last operation is before `next_loc`.
        self.fetched_operations.retain(|&start_loc, operations| {
            assert!(!operations.is_empty());
            let end_loc = start_loc.checked_add(operations.len() as u64 - 1).unwrap();
            end_loc >= next_loc
        });

        loop {
            // See if we have the next operation to apply (i.e. at the journal tip).
            // Find the index of the range that contains the next location.
            let range_start_loc =
                self.fetched_operations
                    .iter()
                    .find_map(|(range_start, range_ops)| {
                        assert!(!range_ops.is_empty());
                        let range_end =
                            range_start.checked_add(range_ops.len() as u64 - 1).unwrap();
                        if *range_start <= next_loc && next_loc <= range_end {
                            Some(*range_start)
                        } else {
                            None
                        }
                    });

            let Some(range_start_loc) = range_start_loc else {
                // We don't have the next operation to apply (i.e. at the journal tip)
                break;
            };

            // Remove the batch of operations that contains the next operation to apply.
            let mut operations = self.fetched_operations.remove(&range_start_loc).unwrap();
            assert!(!operations.is_empty());
            // Skip operations that are before the next location. The containment check when
            // selecting the range (`next_loc <= range_end`) guarantees at least one operation
            // at or after it, so the batch is never empty.
            operations.drain(..(next_loc - *range_start_loc) as usize);
            next_loc += operations.len() as u64;
            self.journal = self.journal.append(operations).await?;
        }

        Ok(self)
    }

    /// Check if sync is complete based on the current journal size and target
    fn is_at_target(&self) -> Result<bool, Error<DB, S>> {
        let journal_size = self.journal.size();
        let target_journal_size = self.target.range.end();

        // Check if we've completed sync
        if journal_size >= target_journal_size {
            if journal_size > target_journal_size {
                // This shouldn't happen in normal operation - indicates a bug
                return Err(SyncError::Engine(EngineError::InvalidState));
            }
            return Ok(true);
        }

        Ok(false)
    }

    /// Returns whether this target needs pinned nodes to reconstruct pruned state.
    fn needs_pinned_nodes(&self) -> bool {
        self.target.range.start() > Location::new(0)
    }

    /// Returns whether pinned nodes are present or not needed by this target.
    fn pinned_nodes_ready(&self) -> bool {
        !self.needs_pinned_nodes() || self.pinned_nodes.is_some()
    }

    /// Returns whether the journal and pinned nodes are both ready for completion.
    fn is_ready_to_complete(&self) -> Result<bool, Error<DB, S>> {
        Ok(self.is_at_target()? && self.pinned_nodes_ready())
    }

    /// Returns whether a target update waits for the current target to be reached.
    ///
    /// Updates wait while the current target is not reached, every remaining operation is fetched
    /// or requested, and a request is outstanding to complete it.
    fn defers_updates(&self) -> Result<bool, Error<DB, S>> {
        Ok(!self.is_ready_to_complete()?
            && self.next_gap().is_none()
            && self.current_requests().next().is_some())
    }

    /// Handle the result of a fetch operation.
    fn handle_fetch_result(
        &mut self,
        fetch_result: IndexedFetchResult<DB::Family, DB::Op, DB::Digest, S::Error>,
    ) -> Result<Fetched<DB>, Error<DB, S>> {
        // A target update can retire a request before its completed result is handled.
        let Some(request) = self.outstanding_requests.remove(fetch_result.id) else {
            return Ok(Fetched::Current);
        };

        // A boundary request at another lower bound is for a deferred update. It is speculative,
        // so its failure does not fail sync.
        let start_loc = request.start();
        let speculative =
            matches!(request, Request::Boundary { .. }) && start_loc != self.target.range.start();
        let response = match fetch_result.result {
            Ok(Some(response)) => response,
            Ok(None) | Err(_) if speculative => return Ok(Fetched::Unused),
            Ok(None) => return Err(SyncError::Engine(EngineError::InvalidResponse)),
            Err(err) => return Err(SyncError::Source(err)),
        };

        match response {
            Response::Operations { operations, .. } => {
                self.store_operations(start_loc, operations);
            }
            Response::Boundary {
                op, pinned_nodes, ..
            } => {
                if !speculative {
                    // A fetched batch at the current lower bound already holds its operation.
                    self.pinned_nodes = Some(pinned_nodes);
                    self.fetched_operations
                        .entry(start_loc)
                        .or_insert_with(|| vec![op]);
                } else if self.blocks(start_loc)
                    && let Some(update) = self.deferred.take_at(start_loc)
                {
                    return Ok(Fetched::Adopt(update, op, pinned_nodes));
                } else {
                    return Ok(Fetched::Unused);
                }
            }
        }

        Ok(Fetched::Current)
    }

    /// Returns whether `update` advances `latest`. An advancing update with the same root is
    /// impossible for an append-only log and indicates a caller bug.
    fn admits(
        latest: &Target<DB::Family, DB::Digest>,
        update: &Target<DB::Family, DB::Digest>,
    ) -> Result<bool, Error<DB, S>> {
        if !update.advances(latest) {
            return Ok(false);
        }
        if update.root == latest.root {
            return Err(SyncError::Engine(EngineError::SyncTargetRootUnchanged));
        }
        Ok(true)
    }

    /// Handle a sync event and return the next engine state.
    async fn handle_event(
        mut self,
        event: Event<DB::Family, DB::Op, DB::Digest, S::Error>,
    ) -> Result<NextStep<Self, DB>, Error<DB, S>> {
        match event {
            Event::TargetUpdate(new_target) => {
                // An update that does not advance the latest target, deferred or current, is
                // discarded.
                if !Self::admits(self.deferred.latest().unwrap_or(&self.target), &new_target)? {
                    return Ok(NextStep::Continue(self));
                }

                // A deferred update waits for the current target to be reached. Boundary requests
                // of updates it replaces are cancelled.
                if self.defers_updates()? {
                    self.deferred.push(new_target);
                    let current = self.target.range.start();
                    let kept = self
                        .deferred
                        .kept()
                        .map(|update| update.map(|update| update.range.start()));
                    self.outstanding_requests.retain(|request| {
                        !matches!(request, Request::Boundary { .. })
                            || request.start() == current
                            || kept.contains(&Some(request.start()))
                    });
                    self.fetch_deferred_boundaries();
                    return Ok(NextStep::Continue(self));
                }

                // Deferred updates' boundary requests are at or below the new lower bound, so the
                // reset cancels them or keeps one at it as the new target's.
                self.deferred = Deferred::Empty;

                // Derive the pinned nodes at a lower bound moved within the journal from those at
                // the current bound (none at zero) instead of fetching them.
                let old_start = self.target.range.start();
                let new_start = new_target.range.start();
                let distance = (*new_start).saturating_sub(*old_start);
                let pinned_nodes = if (1..=MAX_DERIVED_OPERATIONS).contains(&distance)
                    && self.journal.size() >= *new_start
                    && self.pinned_nodes_ready()
                {
                    Some(
                        derive_pinned_nodes::<_, DB::Hasher, _>(
                            &self.journal,
                            self.pinned_nodes.take().unwrap_or_default(),
                            old_start..new_start,
                            self.apply_batch_size,
                        )
                        .await?,
                    )
                } else {
                    None
                };
                let mut updated_self = self
                    .reset_for_target_update(new_target, pinned_nodes)
                    .await?;
                updated_self.record_progress();
                updated_self.schedule_requests();
                Ok(NextStep::Continue(updated_self))
            }
            Event::UpdateChannelClosed => {
                self.update_rx = None;
                Ok(NextStep::Continue(self))
            }
            Event::FinishRequested => {
                self.finish_rx = None;
                self.finish_requested = true;
                Ok(NextStep::Continue(self))
            }
            Event::FinishChannelClosed => Err(SyncError::Engine(EngineError::FinishChannelClosed)),
            Event::BatchReceived(fetch_result) => {
                // An aborted request carries no result, but still wakes the loop to reschedule.
                let fetched = match fetch_result {
                    Ok(fetch_result) => self.handle_fetch_result(fetch_result)?,
                    Err(Aborted) => Fetched::Current,
                };

                // Adopt a deferred update now rather than wait on the request below its lower
                // bound, which may never complete. A newer deferred update stays deferred.
                let unused = matches!(fetched, Fetched::Unused);
                if let Fetched::Adopt(update, op, pinned_nodes) = fetched {
                    let start = update.range.start();
                    self = self
                        .reset_for_target_update(update, Some(pinned_nodes))
                        .await?;
                    self.fetched_operations
                        .entry(start)
                        .or_insert_with(|| vec![op]);
                }
                // Schedule after applying. Measured from the journal tip before the apply, the
                // lookahead could leave nothing in flight once the tip request lands, and sync
                // would stall.
                let mut engine = self.apply_operations().await?;
                engine.schedule_requests();
                // An unused deferred boundary request is not issued again here, so a source that
                // fails it at once is not asked in a loop.
                if !unused {
                    engine.fetch_deferred_boundaries();
                }
                engine.record_progress();
                Ok(NextStep::Continue(engine))
            }
        }
    }

    /// Execute one step of the synchronization process.
    ///
    /// This is the main coordination method that:
    /// 1. Checks if sync is complete
    /// 2. Waits for the next synchronization event
    /// 3. Handles different event types (target updates, fetch results)
    /// 4. Coordinates request scheduling and operation application
    ///
    /// Returns `NextStep::Complete(database)` when sync is finished, or
    /// `NextStep::Continue(self)` when more work remains.
    #[boxed]
    pub(crate) async fn step(mut self) -> Result<NextStep<Self, DB>, Error<DB, S>> {
        self.drain_finish_requests()?;

        // Check if sync is complete
        if self.is_ready_to_complete()? {
            self.report_reached_target().await;

            // Take the newest deferred or queued target update before completing at the reached
            // target, unless the caller already asked to finish. Updates that do not advance the
            // newest one taken so far are discarded.
            if !self.finish_requested {
                let mut update = self.deferred.take_latest();
                while let Some(update_rx) = self.update_rx.as_mut() {
                    match update_rx.try_recv() {
                        Ok(new_target) => {
                            if Self::admits(update.as_ref().unwrap_or(&self.target), &new_target)? {
                                update = Some(new_target);
                            }
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => self.update_rx = None,
                    }
                }
                if let Some(target) = update {
                    return self.handle_event(Event::TargetUpdate(target)).await;
                }
            }

            if self.finish_rx.is_some() {
                let event = wait_for_event(
                    &mut self.update_rx,
                    &mut self.finish_rx,
                    &mut self.outstanding_requests,
                )
                .await
                .ok_or(SyncError::Engine(EngineError::SyncStalled))?;
                return self.handle_event(event).await;
            }

            return Ok(NextStep::Complete(self.complete().await?));
        }

        // Wait for the next synchronization event
        let event = wait_for_event(
            &mut self.update_rx,
            &mut self.finish_rx,
            &mut self.outstanding_requests,
        )
        .await
        .ok_or(SyncError::Engine(EngineError::SyncStalled))?;
        self.handle_event(event).await
    }

    /// Build the final database from the completed sync and verify its root against the
    /// target.
    async fn complete(mut self) -> Result<DB, Error<DB, S>> {
        self.journal = self.journal.sync().await?;

        let database = DB::from_sync_result(
            self.context,
            self.config,
            self.journal,
            self.pinned_nodes,
            self.target.range.clone(),
            self.apply_batch_size,
        )
        .await?;

        let got_root = database.root();
        let expected_root = self.target.root;
        if got_root != expected_root {
            return Err(SyncError::Engine(EngineError::RootMismatch {
                expected: expected_root,
                actual: got_root,
            }));
        }

        Ok(database.persist_sync_result().await?)
    }

    /// Run sync to completion, returning the final database when done.
    ///
    /// This method repeatedly calls `step()` until sync is complete. The `step()` method
    /// handles building the final database and verifying the root digest.
    pub async fn sync(mut self) -> Result<DB, Error<DB, S>> {
        // Run sync loop until completion
        loop {
            match self.step().await? {
                NextStep::Continue(new_engine) => self = new_engine,
                NextStep::Complete(database) => return Ok(database),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{
            full,
            mmb::Family as MmbFamily,
            mmr::{Family as MmrFamily, Proof},
        },
        qmdb::sync::{journal::Memory, source},
    };
    use commonware_cryptography::{Sha256, sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, buffer::paged::CacheRef, deterministic};
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range};
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        },
    };

    #[derive(Clone)]
    struct TestConfig {
        journal_size: u64,
        pinned_node_probes: Arc<AtomicUsize>,
    }

    impl crate::qmdb::sync::DatabaseConfig for TestConfig {
        type JournalConfig = u64;

        fn journal_config(&self) -> Self::JournalConfig {
            self.journal_size
        }
    }

    struct TestJournal {
        size: u64,
        /// Number of operations read.
        reads: AtomicU64,
    }

    impl Journal<MmrFamily> for TestJournal {
        type Config = u64;
        type Context = deterministic::Context;
        type Error = crate::journal::Error;
        type Op = i32;

        async fn new(
            _context: Self::Context,
            size: Self::Config,
            _range: commonware_utils::range::NonEmptyRange<Location<MmrFamily>>,
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                size,
                reads: AtomicU64::new(0),
            })
        }

        async fn resize(mut self, start: Location<MmrFamily>) -> Result<Self, Self::Error> {
            self.size = self.size.max(*start);
            Ok(self)
        }

        async fn sync(self) -> Result<Self, Self::Error> {
            Ok(self)
        }

        fn size(&self) -> u64 {
            self.size
        }

        async fn append(mut self, ops: Vec<Self::Op>) -> Result<Self, Self::Error> {
            self.size += ops.len() as u64;
            Ok(self)
        }

        async fn read_range(
            &self,
            range: Range<Location<MmrFamily>>,
        ) -> Result<Vec<Self::Op>, Self::Error> {
            let len = *range.end - *range.start;
            self.reads.fetch_add(len, Ordering::SeqCst);
            Ok(vec![0; len as usize])
        }
    }

    struct TestDb;

    impl Database for TestDb {
        type Config = TestConfig;
        type Context = deterministic::Context;
        type Digest = sha256::Digest;
        type Family = MmrFamily;
        type Hasher = Sha256;
        type Journal = TestJournal;
        type Op = i32;

        async fn from_sync_result(
            _context: Self::Context,
            _config: Self::Config,
            _journal: Self::Journal,
            _pinned_nodes: Option<Vec<Self::Digest>>,
            _range: commonware_utils::range::NonEmptyRange<Location<Self::Family>>,
            _apply_batch_size: NonZeroU64,
        ) -> Result<Self, qmdb::Error<Self::Family>> {
            Ok(Self)
        }

        async fn persist_sync_result(self) -> Result<Self, qmdb::Error<Self::Family>> {
            Ok(self)
        }

        async fn local_pinned_nodes(
            _context: Self::Context,
            config: &Self::Config,
            _target: &Target<Self::Family, Self::Digest>,
            _journal: &Self::Journal,
        ) -> Result<Option<Vec<Self::Digest>>, qmdb::Error<Self::Family>> {
            config.pinned_node_probes.fetch_add(1, Ordering::SeqCst);
            Ok(Some(vec![]))
        }

        fn root(&self) -> Self::Digest {
            sha256::Digest::from([0u8; 32])
        }
    }

    #[derive(Clone)]
    struct TestSource;

    impl Source for TestSource {
        type Digest = sha256::Digest;
        type Error = Infallible;
        type Family = MmrFamily;
        type Op = i32;

        async fn serve(&self, _request: Request<MmrFamily>) -> source::Result<Self> {
            Ok((
                Response::Operations {
                    proof: Proof {
                        leaves: Location::new(0),
                        inactive_peaks: 0,
                        digests: vec![],
                    },
                    operations: vec![],
                },
                None,
            ))
        }
    }

    fn test_engine_config(
        context: deterministic::Context,
        journal_size: u64,
        pinned_node_probes: Arc<AtomicUsize>,
    ) -> Config<TestDb, TestSource> {
        Config {
            context,
            source: TestSource,
            target: Target {
                root: sha256::Digest::from([1u8; 32]),
                range: non_empty_range!(Location::new(5), Location::new(10)),
            },
            max_outstanding_requests: NZUsize!(1),
            fetch_batch_size: NZU64!(1),
            apply_batch_size: NZU64!(1),
            db_config: TestConfig {
                journal_size,
                pinned_node_probes,
            },
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
        }
    }

    fn insert_pending_request(
        engine: &mut Engine<TestDb, TestSource>,
        request: Request<MmrFamily>,
    ) -> RequestId {
        engine
            .outstanding_requests
            .insert(request, |_| std::future::pending())
    }

    fn late_fetch_result(
        id: RequestId,
    ) -> IndexedFetchResult<MmrFamily, i32, sha256::Digest, Infallible> {
        IndexedFetchResult {
            id,
            result: Ok(Some(Response::Operations {
                proof: Proof {
                    leaves: Location::new(10),
                    inactive_peaks: 0,
                    digests: vec![],
                },
                operations: vec![99],
            })),
        }
    }

    /// A boundary response keeps a fetched batch that starts at the lower bound.
    #[test]
    fn boundary_response_keeps_fetched_batch_at_lower_bound() {
        deterministic::Runner::default().start(|context| async move {
            let mut engine = Engine::new(test_engine_config(
                context,
                5,
                Arc::new(AtomicUsize::new(0)),
            ))
            .await
            .unwrap();
            engine
                .fetched_operations
                .insert(Location::new(6), vec![1, 2, 3]);

            // Move the lower bound to the start of the fetched batch.
            let next = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(6), Location::new(12)),
            };
            let mut engine = engine.reset_for_target_update(next, None).await.unwrap();
            assert!(engine.pinned_nodes.is_none());

            // The boundary response sets pinned nodes without replacing the batch.
            let id = insert_pending_request(
                &mut engine,
                Request::Boundary {
                    size: Location::new(12),
                    start: Location::new(6),
                },
            );
            let pinned = vec![sha256::Digest::from([7; 32])];
            engine
                .handle_fetch_result(IndexedFetchResult {
                    id,
                    result: Ok(Some(Response::Boundary {
                        proof: Proof {
                            leaves: Location::new(12),
                            inactive_peaks: 0,
                            digests: vec![],
                        },
                        op: 1,
                        pinned_nodes: pinned.clone(),
                    })),
                })
                .unwrap();
            assert_eq!(engine.pinned_nodes, Some(pinned));
            assert_eq!(
                engine.fetched_operations.get(&Location::new(6)),
                Some(&vec![1, 2, 3])
            );

            // Applying moves the journal past the whole batch.
            let engine = engine.apply_operations().await.unwrap();
            assert_eq!(engine.journal.size(), 9);
        });
    }

    /// Moving the lower bound past an operation request cancels it with the old boundary and
    /// drops its queued result.
    #[test]
    fn target_update_drops_queued_result_of_cancelled_request() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let mut engine = Engine::new(config).await.unwrap();

            // Track the boundary request and an operation request below the next lower bound.
            assert!(engine.outstanding_requests.contains(&Location::new(5)));
            let request = Request::Operations {
                size: Location::new(10),
                start: Location::new(6),
                max_ops: NZU64!(1),
            };
            let old_id = insert_pending_request(&mut engine, request);
            let queued_result = late_fetch_result(old_id);
            assert_eq!(engine.outstanding_requests.len(), 2);

            // Moving the lower bound beyond both starts cancels both requests.
            let new_target = Target {
                root: sha256::Digest::from([2u8; 32]),
                range: non_empty_range!(Location::new(7), Location::new(12)),
            };
            let mut engine = engine
                .reset_for_target_update(new_target, None)
                .await
                .unwrap();
            assert_eq!(engine.outstanding_requests.len(), 0);
            assert!(engine.outstanding_requests.remove(old_id).is_none());

            // The queued result of the cancelled request is ignored.
            engine.handle_fetch_result(queued_result).unwrap();
            assert!(engine.fetched_operations.is_empty());
            assert!(engine.pinned_nodes.is_none());
            assert!(matches!(
                engine.outstanding_requests.next_completed().await,
                Err(Aborted)
            ));
            assert!(matches!(
                engine.outstanding_requests.next_completed().await,
                Err(Aborted)
            ));
            assert_eq!(engine.outstanding_requests.len(), 0);
        });
    }

    /// An operation request at an old size survives any number of target updates while its
    /// start is beyond the lower bound, and its late response is stored. The boundary request
    /// survives updates that keep the lower bound.
    #[test]
    fn target_updates_keep_old_size_request_beyond_floor() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let mut engine = Engine::new(config).await.unwrap();
            engine.outstanding_requests.retain(|_| false);

            // Track a pending boundary request and an operation request at the first target
            // size.
            insert_pending_request(
                &mut engine,
                Request::Boundary {
                    size: Location::new(10),
                    start: Location::new(5),
                },
            );
            let request = Request::Operations {
                size: Location::new(10),
                start: Location::new(8),
                max_ops: NZU64!(1),
            };
            let id = insert_pending_request(&mut engine, request);
            assert_eq!(engine.outstanding_requests.len(), 2);

            // Updates with an unchanged lower bound keep both requests.
            let mut root = 2u8;
            for end in 11..21 {
                let next = Target {
                    root: sha256::Digest::from([root; 32]),
                    range: non_empty_range!(Location::new(5), Location::new(end)),
                };
                root += 1;
                engine = engine.reset_for_target_update(next, None).await.unwrap();
                assert!(engine.outstanding_requests.contains(&Location::new(5)));
                assert!(engine.outstanding_requests.contains(&Location::new(8)));
                assert_eq!(engine.outstanding_requests.len(), 2);
            }

            // Updates that move the lower bound below the request start cancel the boundary
            // and keep the operation request.
            for (start, end) in [(6, 22), (7, 24)] {
                let next = Target {
                    root: sha256::Digest::from([root; 32]),
                    range: non_empty_range!(Location::new(start), Location::new(end)),
                };
                root += 1;
                engine = engine.reset_for_target_update(next, None).await.unwrap();
                assert!(engine.outstanding_requests.contains(&Location::new(8)));
                assert_eq!(engine.outstanding_requests.len(), 1);
            }

            // The late response at the first target size is stored at its start.
            engine.handle_fetch_result(late_fetch_result(id)).unwrap();
            assert_eq!(engine.outstanding_requests.len(), 0);
            assert_eq!(
                engine.fetched_operations.get(&Location::new(8)),
                Some(&vec![99])
            );
        });
    }

    /// Moving the lower bound cancels an operation request whose range ends at the new bound and
    /// keeps one beyond it.
    #[test]
    fn target_update_floor_move_cancels_operations_below_bound() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let mut engine = Engine::new(config).await.unwrap();

            // Track operation requests below and beyond the next lower bound.
            let below = Request::Operations {
                size: Location::new(10),
                start: Location::new(6),
                max_ops: NZU64!(2),
            };
            insert_pending_request(&mut engine, below);
            let beyond = Request::Operations {
                size: Location::new(10),
                start: Location::new(9),
                max_ops: NZU64!(1),
            };
            insert_pending_request(&mut engine, beyond);
            assert_eq!(engine.outstanding_requests.len(), 3);

            // Moving the lower bound to the end of the first request cancels it and the old
            // boundary. The request beyond the bound survives.
            let next = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(8), Location::new(14)),
            };
            let engine = engine.reset_for_target_update(next, None).await.unwrap();
            assert!(!engine.outstanding_requests.contains(&Location::new(5)));
            assert!(!engine.outstanding_requests.contains(&Location::new(6)));
            assert!(engine.outstanding_requests.contains(&Location::new(9)));
            assert_eq!(engine.outstanding_requests.len(), 1);
        });
    }

    /// Moving the lower bound to the start of an operation request cancels it and the old
    /// boundary request, and scheduling issues the boundary request at the new lower bound.
    #[test]
    fn moved_floor_schedules_boundary_without_waiting_for_old_operation() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let mut engine = Engine::new(config).await.unwrap();

            // Track the boundary request and an operation request at the next lower bound.
            let operation_id = insert_pending_request(
                &mut engine,
                Request::Operations {
                    size: Location::new(10),
                    start: Location::new(6),
                    max_ops: NZU64!(1),
                },
            );
            assert!(engine.outstanding_requests.contains(&Location::new(5)));

            // Move the lower bound to the start of the operation request.
            let next = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(6), Location::new(12)),
            };
            let mut engine = engine.reset_for_target_update(next, None).await.unwrap();
            engine.schedule_requests();

            // Both requests are cancelled. Scheduling issues the boundary request at the new lower
            // bound and, beside it, the next operation.
            assert!(engine.outstanding_requests.remove(operation_id).is_none());
            assert!(!engine.outstanding_requests.contains(&Location::new(5)));
            assert!(engine.outstanding_requests.contains(&Location::new(6)));
            assert!(engine.outstanding_requests.contains(&Location::new(7)));
            assert_eq!(engine.outstanding_requests.len(), 2);
        });
    }

    /// Target updates keep fetched operations and keep pinned nodes only while the lower bound is
    /// unchanged. Once the lower bound moves, applying drops batches below it and trims a batch
    /// that straddles it.
    #[test]
    fn target_updates_keep_operations_and_reset_pins_only_when_floor_moves() {
        deterministic::Runner::default().start(|context| async move {
            let mut engine = Engine::new(test_engine_config(
                context,
                5,
                Arc::new(AtomicUsize::new(0)),
            ))
            .await
            .unwrap();

            // Hold pinned nodes and two batches fetched ahead of the journal tip.
            let fetched = BTreeMap::from([
                (Location::new(6), vec![1, 2]),
                (Location::new(8), vec![3, 4]),
            ]);
            engine.fetched_operations = fetched.clone();
            let pinned = vec![sha256::Digest::from([7; 32])];
            engine.pinned_nodes = Some(pinned.clone());

            // An update with an unchanged lower bound keeps operations and pinned nodes.
            let next = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(5), Location::new(12)),
            };
            let engine = engine.reset_for_target_update(next, None).await.unwrap();
            assert_eq!(engine.fetched_operations, fetched);
            assert_eq!(engine.pinned_nodes, Some(pinned));

            // An update that moves the lower bound keeps operations and clears pinned nodes.
            let next = Target {
                root: sha256::Digest::from([3; 32]),
                range: non_empty_range!(Location::new(9), Location::new(14)),
            };
            let engine = engine.reset_for_target_update(next, None).await.unwrap();
            assert_eq!(engine.fetched_operations, fetched);
            assert!(engine.pinned_nodes.is_none());

            // Applying drops the batch below the new lower bound and appends the operation of
            // the straddling batch at it.
            let engine = engine.apply_operations().await.unwrap();
            assert_eq!(engine.journal.size(), 10);
            assert!(engine.fetched_operations.is_empty());
        });
    }

    /// Checks that pinned nodes derived from a journal match those a persisted Merkle structure
    /// serves, for lower bounds at and above zero and several chunk sizes.
    async fn derived_pinned_nodes_match_merkle<F: Family>(context: deterministic::Context) {
        const OPS: u64 = 50;

        // Persist a structure over the encoded operations.
        let hasher = qmdb::hasher::<Sha256>();
        let config = full::Config {
            journal_partition: "derive-journal".into(),
            metadata_partition: "derive-metadata".into(),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: CacheRef::from_pooler(&context, NZU16!(111), NZUsize!(5)),
        };
        let mut merkle =
            full::Merkle::<F, _, sha256::Digest, Sequential>::init(context, &hasher, config)
                .await
                .unwrap();
        let ops = (0..OPS).collect::<Vec<_>>();
        let mut batch = merkle.new_batch();
        for op in &ops {
            batch = batch.add(&hasher, &op.encode());
        }
        let batch = batch.merkleize(merkle.mem(), &hasher);
        merkle = merkle.apply_batch(&batch).unwrap();

        // Derive from each lower bound to each later one and compare with the structure.
        for start in [0, 1, 5, 13] {
            let start = Location::<F>::new(start);
            let range = non_empty_range!(start, Location::new(OPS));
            let journal = <Memory<F, (), u64> as Journal<F>>::new((), (), range)
                .await
                .unwrap();
            let journal = journal
                .append(ops[*start as usize..].to_vec())
                .await
                .unwrap();
            let pinned = merkle.pinned_nodes_at(start).await.unwrap();
            for end in *start + 1..=OPS {
                let end = Location::new(end);
                let expected = merkle.pinned_nodes_at(end).await.unwrap();
                for chunk in [NZU64!(1), NZU64!(4), NZU64!(64)] {
                    let derived = derive_pinned_nodes::<F, Sha256, _>(
                        &journal,
                        pinned.clone(),
                        start..end,
                        chunk,
                    )
                    .await
                    .unwrap();
                    assert_eq!(derived, expected, "start={start} end={end} chunk={chunk}");
                }
            }
        }
        merkle.destroy().await.unwrap();
    }

    #[test]
    fn derived_pinned_nodes_match_merkle_mmr() {
        deterministic::Runner::default().start(derived_pinned_nodes_match_merkle::<MmrFamily>);
    }

    #[test]
    fn derived_pinned_nodes_match_merkle_mmb() {
        deterministic::Runner::default().start(derived_pinned_nodes_match_merkle::<MmbFamily>);
    }

    /// Deriving from pinned nodes of the wrong count fails instead of panicking.
    #[test]
    fn derive_rejects_mismatched_pinned_nodes() {
        deterministic::Runner::default().start(|_context| async move {
            let range = non_empty_range!(Location::<MmrFamily>::new(5), Location::new(10));
            let journal = <Memory<MmrFamily, (), u64> as Journal<MmrFamily>>::new((), (), range)
                .await
                .unwrap();
            let journal = journal.append(vec![5, 6, 7, 8, 9]).await.unwrap();
            let result = derive_pinned_nodes::<MmrFamily, Sha256, _>(
                &journal,
                Vec::new(),
                Location::new(5)..Location::new(8),
                NZU64!(4),
            )
            .await;
            assert!(result.is_err());
        });
    }

    /// Placeholder pinned nodes for a lower bound at `start`.
    fn pinned_at(start: u64) -> Vec<sha256::Digest> {
        let count = MmrFamily::nodes_to_pin(Location::new(start)).count();
        vec![sha256::Digest::from([7; 32]); count]
    }

    /// Handles `update`, which the engine must adopt rather than defer.
    async fn adopt(
        engine: Engine<TestDb, TestSource>,
        update: Target<MmrFamily, sha256::Digest>,
    ) -> Engine<TestDb, TestSource> {
        let NextStep::Continue(engine) = engine
            .handle_event(Event::TargetUpdate(update.clone()))
            .await
            .unwrap()
        else {
            panic!("a target update must not complete sync");
        };
        assert_eq!(engine.target, update);
        engine
    }

    /// An update whose lower bound moves within the journal derives its pinned nodes, keeps the
    /// operations request at the new bound, and requests no boundary.
    #[test]
    fn target_update_derives_pinned_nodes_within_journal() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 8, Arc::new(AtomicUsize::new(0)));
            let mut engine = Engine::new(config).await.unwrap();
            engine.outstanding_requests.retain(|_| false);
            engine.pinned_nodes = Some(pinned_at(5));

            // The request at the journal tip leaves a gap, so the update is not deferred.
            let at_tip = Request::Operations {
                size: Location::new(10),
                start: Location::new(8),
                max_ops: NZU64!(1),
            };
            insert_pending_request(&mut engine, at_tip);
            let engine = adopt(
                engine,
                Target {
                    root: sha256::Digest::from([2; 32]),
                    range: non_empty_range!(Location::new(8), Location::new(14)),
                },
            )
            .await;
            assert_eq!(
                engine.pinned_nodes.map(|nodes| nodes.len()),
                Some(pinned_at(8).len())
            );
            assert_eq!(engine.journal.reads.load(Ordering::SeqCst), 3);
            assert_eq!(
                engine.outstanding_requests.requests().collect::<Vec<_>>(),
                vec![at_tip]
            );
        });
    }

    /// Pinned nodes are derived over at most [`MAX_DERIVED_OPERATIONS`] operations. A longer move
    /// of the lower bound requests the boundary instead.
    #[test]
    fn target_update_derives_pinned_nodes_up_to_limit() {
        deterministic::Runner::default().start(|context| async move {
            for (label, distance) in [
                ("limit", MAX_DERIVED_OPERATIONS),
                ("beyond", MAX_DERIVED_OPERATIONS + 1),
            ] {
                let derived = distance <= MAX_DERIVED_OPERATIONS;
                let new_start = 5 + distance;
                let mut config = test_engine_config(
                    context.child(label),
                    new_start,
                    Arc::new(AtomicUsize::new(0)),
                );
                config.target.range =
                    non_empty_range!(Location::new(5), Location::new(new_start + 1));
                config.apply_batch_size = NZU64!(1 << 16);
                let mut engine = Engine::new(config).await.unwrap();
                engine.outstanding_requests.retain(|_| false);
                engine.pinned_nodes = Some(pinned_at(5));

                let engine = adopt(
                    engine,
                    Target {
                        root: sha256::Digest::from([2; 32]),
                        range: non_empty_range!(
                            Location::new(new_start),
                            Location::new(new_start + 6)
                        ),
                    },
                )
                .await;
                assert_eq!(engine.pinned_nodes.is_some(), derived, "{label}");
                let reads = engine.journal.reads.load(Ordering::SeqCst);
                assert_eq!(reads, if derived { distance } else { 0 }, "{label}");
                let at_start = engine.outstanding_requests.requests().next();
                assert_eq!(
                    matches!(at_start, Some(Request::Boundary { .. })),
                    !derived,
                    "{label}"
                );
            }
        });
    }

    /// An update whose lower bound moves past the journal tip, or away from a bound whose pinned
    /// nodes are unknown, derives nothing and requests the boundary.
    #[test]
    fn target_update_without_derivation_requests_boundary() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let mut engine = Engine::new(config).await.unwrap();
            engine.outstanding_requests.retain(|_| false);
            engine.pinned_nodes = Some(pinned_at(5));

            // A lower bound past the journal tip.
            let mut engine = adopt(
                engine,
                Target {
                    root: sha256::Digest::from([2; 32]),
                    range: non_empty_range!(Location::new(6), Location::new(12)),
                },
            )
            .await;
            assert!(engine.pinned_nodes.is_none());
            assert!(matches!(
                engine.outstanding_requests.requests().next(),
                Some(Request::Boundary { start, .. }) if start == Location::new(6)
            ));

            // A lower bound at the journal tip, moved from one whose pinned nodes are unknown.
            engine.journal.size = 8;
            let engine = adopt(
                engine,
                Target {
                    root: sha256::Digest::from([3; 32]),
                    range: non_empty_range!(Location::new(8), Location::new(14)),
                },
            )
            .await;
            assert!(engine.pinned_nodes.is_none());
            assert!(matches!(
                engine.outstanding_requests.requests().next(),
                Some(Request::Boundary { start, .. }) if start == Location::new(8)
            ));
            assert_eq!(engine.journal.reads.load(Ordering::SeqCst), 0);
        });
    }

    /// A deferred update adopted once the current target is reached derives its pinned nodes and
    /// cancels the boundary request issued while it was deferred.
    #[test]
    fn adopted_deferred_update_derives_pinned_nodes() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let (mut engine, operations) = tail_engine(config, true).await;
            engine.pinned_nodes = Some(pinned_at(5));

            // An update behind the operations request at 5 fetches its boundary at 8.
            let update = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(8), Location::new(14)),
            };
            let NextStep::Continue(mut engine) = engine
                .handle_event(Event::TargetUpdate(update.clone()))
                .await
                .unwrap()
            else {
                panic!("a deferred update must not complete sync");
            };
            assert!(engine.outstanding_requests.contains(&Location::new(8)));

            // The current target is reached, and the next step adopts the update.
            engine
                .handle_fetch_result(IndexedFetchResult {
                    id: operations,
                    result: Ok(Some(Response::Operations {
                        proof: Proof {
                            leaves: Location::new(10),
                            inactive_peaks: 0,
                            digests: vec![],
                        },
                        operations: vec![5, 6, 7, 8, 9],
                    })),
                })
                .unwrap();
            let engine = engine.apply_operations().await.unwrap();
            let NextStep::Continue(engine) = engine.step().await.unwrap() else {
                panic!("engine should adopt the deferred update instead of completing");
            };
            assert_eq!(engine.target, update);
            assert_eq!(
                engine.pinned_nodes.map(|nodes| nodes.len()),
                Some(pinned_at(8).len())
            );
            assert_eq!(engine.journal.reads.load(Ordering::SeqCst), 3);
            let requests = engine.outstanding_requests.requests().collect::<Vec<_>>();
            assert!(matches!(
                requests[..],
                [Request::Operations { start, .. }] if start == Location::new(10)
            ));
        });
    }

    #[test]
    fn new_probes_local_pinned_nodes_when_journal_reaches_target() {
        deterministic::Runner::default().start(|context| async move {
            let pinned_node_probes = Arc::new(AtomicUsize::new(0));
            Engine::new(test_engine_config(context, 10, pinned_node_probes.clone()))
                .await
                .unwrap();

            assert_eq!(pinned_node_probes.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn new_skips_local_pinned_nodes_when_journal_is_partial() {
        deterministic::Runner::default().start(|context| async move {
            let pinned_node_probes = Arc::new(AtomicUsize::new(0));
            Engine::new(test_engine_config(context, 7, pinned_node_probes.clone()))
                .await
                .unwrap();

            assert_eq!(pinned_node_probes.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn new_schedules_operations_after_boundary_request() {
        deterministic::Runner::default().start(|context| async move {
            let mut config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            config.max_outstanding_requests = NZUsize!(2);
            config.fetch_batch_size = NZU64!(5);

            let engine = Engine::new(config).await.unwrap();
            let requests = &engine.outstanding_requests;

            assert_eq!(requests.len(), 2);
            assert!(requests.contains(&Location::new(5)));
            assert!(requests.contains(&Location::new(6)));
        });
    }

    /// A target reached with updates queued is reported before the newest advancing update is
    /// taken.
    #[test]
    fn step_reports_reached_target_before_taking_queued_update() {
        deterministic::Runner::default().start(|context| async move {
            let (update_tx, update_rx) = mpsc::channel(3);
            let (reached_tx, mut reached_rx) = mpsc::channel(1);
            let mut config = test_engine_config(context, 10, Arc::new(AtomicUsize::new(0)));
            let reached = config.target.clone();
            config.update_rx = Some(update_rx);
            config.reached_target_tx = Some(reached_tx);
            // Queue a stale update and two advancing ones. The stale one is discarded and the
            // newest retargets the engine instead of completing.
            let stale = Target {
                root: sha256::Digest::from([2u8; 32]),
                range: non_empty_range!(Location::new(5), Location::new(10)),
            };
            let advancing = Target {
                root: sha256::Digest::from([3u8; 32]),
                range: non_empty_range!(Location::new(5), Location::new(12)),
            };
            let newest = Target {
                root: sha256::Digest::from([4u8; 32]),
                range: non_empty_range!(Location::new(5), Location::new(14)),
            };
            update_tx.send(stale).await.unwrap();
            update_tx.send(advancing).await.unwrap();
            update_tx.send(newest.clone()).await.unwrap();

            let engine = Engine::new(config).await.unwrap();
            let NextStep::Continue(engine) = engine.step().await.unwrap() else {
                panic!("engine should retarget instead of completing");
            };
            assert_eq!(engine.target, newest);
            assert_eq!(reached_rx.try_recv().unwrap(), reached);
        });
    }

    /// An update received with the journal at the target end and the boundary request still
    /// outstanding waits for the current target instead of cancelling the boundary.
    #[test]
    fn update_waits_for_boundary_when_journal_is_complete() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 10, Arc::new(AtomicUsize::new(0)));
            let current = config.target.clone();
            let mut engine = Engine::new(config).await.unwrap();
            engine.pinned_nodes = None;
            insert_pending_request(
                &mut engine,
                Request::Boundary {
                    size: Location::new(10),
                    start: Location::new(5),
                },
            );

            let update = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(7), Location::new(12)),
            };
            let NextStep::Continue(engine) = engine
                .handle_event(Event::TargetUpdate(update))
                .await
                .unwrap()
            else {
                panic!("a deferred update must not complete sync");
            };
            assert_eq!(engine.target, current);
            assert!(engine.outstanding_requests.contains(&Location::new(5)));
        });
    }

    #[test]
    fn step_completes_at_current_target_after_finish() {
        deterministic::Runner::default().start(|context| async move {
            let (update_tx, update_rx) = mpsc::channel(1);
            let (finish_tx, finish_rx) = mpsc::channel(1);
            let mut config = test_engine_config(context, 10, Arc::new(AtomicUsize::new(0)));
            // TestDb's root, so completion's final check passes.
            config.target.root = sha256::Digest::from([0u8; 32]);
            config.update_rx = Some(update_rx);
            config.finish_rx = Some(finish_rx);
            let advancing = Target {
                root: sha256::Digest::from([3u8; 32]),
                range: non_empty_range!(Location::new(5), Location::new(12)),
            };
            update_tx.send(advancing).await.unwrap();
            finish_tx.send(()).await.unwrap();

            let engine = Engine::new(config).await.unwrap();
            let NextStep::Complete(_) = engine.step().await.unwrap() else {
                panic!("a requested finish must win over a queued update");
            };
        });
    }

    /// Returns an engine at target [5, 10) whose pending requests cover every remaining operation,
    /// and the operation request's ID. With `pinned`, pinned nodes are held and the operation
    /// request covers [5, 10). Otherwise a boundary request at 5 is pending and the operation
    /// request covers [6, 10).
    async fn tail_engine(
        config: Config<TestDb, TestSource>,
        pinned: bool,
    ) -> (Engine<TestDb, TestSource>, RequestId) {
        let mut engine = Engine::new(config).await.unwrap();
        engine.outstanding_requests.retain(|_| false);
        let start = if pinned {
            engine.pinned_nodes = Some(Vec::new());
            5
        } else {
            insert_pending_request(
                &mut engine,
                Request::Boundary {
                    size: Location::new(10),
                    start: Location::new(5),
                },
            );
            6
        };
        let id = insert_pending_request(
            &mut engine,
            Request::Operations {
                size: Location::new(10),
                start: Location::new(start),
                max_ops: NonZeroU64::new(10 - start).unwrap(),
            },
        );
        (engine, id)
    }

    /// Updates received while every remaining operation is requested and pinned nodes are held
    /// wait for the current target. The engine reports the reached target, then adopts the
    /// newest update.
    #[test]
    fn tail_defers_newest_update_until_target_is_reported() {
        deterministic::Runner::default().start(|context| async move {
            let (reached_tx, mut reached_rx) = mpsc::channel(1);
            let mut config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let reached = config.target.clone();
            config.reached_target_tx = Some(reached_tx);
            let (engine, id) = tail_engine(config, true).await;

            // An update in the tail waits.
            let first = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(5), Location::new(12)),
            };
            let NextStep::Continue(engine) = engine
                .handle_event(Event::TargetUpdate(first.clone()))
                .await
                .unwrap()
            else {
                panic!("a deferred update must not complete sync");
            };
            assert_eq!(engine.target, reached);
            assert_eq!(engine.deferred.latest(), Some(&first));

            // A newer update waits too, and an older one is discarded.
            let newest = Target {
                root: sha256::Digest::from([3; 32]),
                range: non_empty_range!(Location::new(5), Location::new(14)),
            };
            let NextStep::Continue(engine) = engine
                .handle_event(Event::TargetUpdate(newest.clone()))
                .await
                .unwrap()
            else {
                panic!("a deferred update must not complete sync");
            };
            let NextStep::Continue(mut engine) = engine
                .handle_event(Event::TargetUpdate(first.clone()))
                .await
                .unwrap()
            else {
                panic!("a discarded update must not complete sync");
            };
            assert_eq!(engine.target, reached);
            assert_eq!(engine.deferred.latest(), Some(&newest));
            assert!(reached_rx.try_recv().is_err());

            // The response reaches the current target. The next step reports it, then adopts
            // the newest update.
            engine
                .handle_fetch_result(IndexedFetchResult {
                    id,
                    result: Ok(Some(Response::Operations {
                        proof: Proof {
                            leaves: Location::new(10),
                            inactive_peaks: 0,
                            digests: vec![],
                        },
                        operations: vec![1, 2, 3, 4, 5],
                    })),
                })
                .unwrap();
            let engine = engine.apply_operations().await.unwrap();
            let NextStep::Continue(engine) = engine.step().await.unwrap() else {
                panic!("engine should adopt the deferred update instead of completing");
            };
            assert_eq!(reached_rx.try_recv().unwrap(), reached);
            assert_eq!(engine.target, newest);
            assert!(engine.deferred.latest().is_none());
        });
    }

    /// Updates received while the boundary request is outstanding and every remaining operation is
    /// requested wait for the current target, however far their lower bounds move. The newest and
    /// an older one, the escape, fetch their boundaries. After two updates the escape is replaced
    /// by the previous newest, which is then kept for four. The current boundary is kept, and the
    /// escape's arrival adopts it.
    #[test]
    fn boundary_tail_keeps_boundary_across_updates() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let (mut engine, _) = tail_engine(config, false).await;
            let current = engine.target.clone();
            let update = |n: u64| Target {
                root: sha256::Digest::from([n as u8; 32]),
                range: non_empty_range!(Location::new(n), Location::new(2 * n)),
            };

            // Each update moves the lower bound and waits behind the boundary at 5. The update at
            // 7 is the escape until the one at 9 replaces it with the one at 8.
            for n in 7..=11 {
                let NextStep::Continue(next) = engine
                    .handle_event(Event::TargetUpdate(update(n)))
                    .await
                    .unwrap()
                else {
                    panic!("a deferred update must not complete sync");
                };
                engine = next;
                let escape = if n < 9 { 7 } else { 8 };
                assert_eq!(engine.target, current);
                assert_eq!(engine.deferred.kept()[0], Some(&update(escape)));
                assert_eq!(engine.deferred.latest(), Some(&update(n)));
                for start in 5..=12 {
                    // The current boundary is at 5 and the operations request at 6.
                    let kept = start <= 6 || start == escape || start == n;
                    assert_eq!(
                        engine.outstanding_requests.contains(&Location::new(start)),
                        kept,
                        "boundary at {start} after update {n}"
                    );
                }
            }

            // The boundary at 8 arrives. Its update is adopted and the newest becomes the escape.
            let id = insert_pending_request(
                &mut engine,
                Request::Boundary {
                    size: Location::new(16),
                    start: Location::new(8),
                },
            );
            let NextStep::Continue(engine) = engine
                .handle_event(Event::BatchReceived(Ok(IndexedFetchResult {
                    id,
                    result: Ok(Some(Response::Boundary {
                        proof: Proof {
                            leaves: Location::new(16),
                            inactive_peaks: 0,
                            digests: vec![],
                        },
                        op: 8,
                        pinned_nodes: vec![],
                    })),
                })))
                .await
                .unwrap()
            else {
                panic!("the adopted target is not reached");
            };
            assert_eq!(engine.target, update(8));
            assert_eq!(engine.pinned_nodes, Some(vec![]));
            assert_eq!(engine.deferred.kept()[0], Some(&update(11)));
            assert_eq!(engine.deferred.latest(), Some(&update(11)));
            assert!(!engine.outstanding_requests.contains(&Location::new(5)));

            // The new escape's boundary does not take the adopted target's only request slot.
            assert_eq!(engine.journal.size(), 9);
            assert!(engine.outstanding_requests.contains(&Location::new(9)));
            assert!(engine.outstanding_requests.contains(&Location::new(11)));
        });
    }

    /// A deferred update with no outstanding request below its lower bound fetches no boundary.
    #[test]
    fn deferred_update_without_request_below_floor_fetches_no_boundary() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 7, Arc::new(AtomicUsize::new(0)));
            let mut engine = Engine::new(config).await.unwrap();
            engine.outstanding_requests.retain(|_| false);
            engine.pinned_nodes = Some(Vec::new());
            insert_pending_request(
                &mut engine,
                Request::Operations {
                    size: Location::new(10),
                    start: Location::new(7),
                    max_ops: NZU64!(3),
                },
            );

            let update = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(6), Location::new(12)),
            };
            let NextStep::Continue(engine) = engine
                .handle_event(Event::TargetUpdate(update.clone()))
                .await
                .unwrap()
            else {
                panic!("a deferred update must not complete sync");
            };
            assert_eq!(engine.deferred.latest(), Some(&update));
            assert!(!engine.outstanding_requests.contains(&Location::new(6)));
        });
    }

    /// Adopting a deferred update keeps its boundary request, whose response then supplies the
    /// adopted target's pinned nodes.
    #[test]
    fn adoption_keeps_boundary_at_new_lower_bound() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let (engine, id) = tail_engine(config, true).await;

            // An update behind the operations request at 5 fetches its boundary at 11, past the
            // current target's end.
            let update = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(11), Location::new(14)),
            };
            let NextStep::Continue(mut engine) = engine
                .handle_event(Event::TargetUpdate(update.clone()))
                .await
                .unwrap()
            else {
                panic!("a deferred update must not complete sync");
            };
            let boundary = insert_pending_request(
                &mut engine,
                Request::Boundary {
                    size: Location::new(14),
                    start: Location::new(11),
                },
            );

            // The current target is reached, and the next step adopts the update.
            engine
                .handle_fetch_result(IndexedFetchResult {
                    id,
                    result: Ok(Some(Response::Operations {
                        proof: Proof {
                            leaves: Location::new(10),
                            inactive_peaks: 0,
                            digests: vec![],
                        },
                        operations: vec![1, 2, 3, 4, 5],
                    })),
                })
                .unwrap();
            let engine = engine.apply_operations().await.unwrap();
            let NextStep::Continue(mut engine) = engine.step().await.unwrap() else {
                panic!("engine should adopt the deferred update instead of completing");
            };
            assert_eq!(engine.target, update);
            assert!(engine.pinned_nodes.is_none());

            // The boundary request issued for the deferred update still completes.
            engine
                .handle_fetch_result(IndexedFetchResult {
                    id: boundary,
                    result: Ok(Some(Response::Boundary {
                        proof: Proof {
                            leaves: Location::new(14),
                            inactive_peaks: 0,
                            digests: vec![],
                        },
                        op: 11,
                        pinned_nodes: vec![],
                    })),
                })
                .unwrap();
            assert_eq!(engine.pinned_nodes, Some(vec![]));
        });
    }

    /// An operation request below the lower bound of a deferred update stays outstanding when newer
    /// updates replace the deferred ones.
    #[test]
    fn tail_keeps_request_below_deferred_floor_across_updates() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let (mut engine, _) = tail_engine(config, true).await;
            let current = engine.target.clone();
            for (root, start, end) in [(2u8, 7u64, 12u64), (3, 8, 14), (4, 9, 16)] {
                let update = Target {
                    root: sha256::Digest::from([root; 32]),
                    range: non_empty_range!(Location::new(start), Location::new(end)),
                };
                let NextStep::Continue(next) = engine
                    .handle_event(Event::TargetUpdate(update.clone()))
                    .await
                    .unwrap()
                else {
                    panic!("a deferred update must not complete sync");
                };
                engine = next;
                assert_eq!(engine.target, current);
                assert_eq!(engine.deferred.latest(), Some(&update));
                assert!(engine.outstanding_requests.contains(&Location::new(5)));
            }
        });
    }

    /// A requested finish completes at the reached target and drops the deferred update.
    #[test]
    fn finish_drops_deferred_update() {
        deterministic::Runner::default().start(|context| async move {
            let (finish_tx, finish_rx) = mpsc::channel(1);
            let mut config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));

            // TestDb's root.
            config.target.root = sha256::Digest::from([0u8; 32]);
            config.finish_rx = Some(finish_rx);
            let (engine, id) = tail_engine(config, true).await;

            // An update in the tail waits.
            let update = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(5), Location::new(12)),
            };
            let NextStep::Continue(mut engine) = engine
                .handle_event(Event::TargetUpdate(update.clone()))
                .await
                .unwrap()
            else {
                panic!("a deferred update must not complete sync");
            };
            assert_eq!(engine.deferred.latest(), Some(&update));

            // The caller asks to finish, and the response reaches the current target.
            finish_tx.send(()).await.unwrap();
            engine
                .handle_fetch_result(IndexedFetchResult {
                    id,
                    result: Ok(Some(Response::Operations {
                        proof: Proof {
                            leaves: Location::new(10),
                            inactive_peaks: 0,
                            digests: vec![],
                        },
                        operations: vec![1, 2, 3, 4, 5],
                    })),
                })
                .unwrap();
            let engine = engine.apply_operations().await.unwrap();
            let NextStep::Complete(_) = engine.step().await.unwrap() else {
                panic!("a requested finish must win over a deferred update");
            };
        });
    }

    /// A finish requested before the current target is reached keeps the deferred update and its
    /// boundary request, whose arrival adopts the update.
    #[test]
    fn finish_before_reaching_target_keeps_deferred_boundary() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let (engine, _) = tail_engine(config, false).await;

            // An update behind the boundary at 5 is deferred and fetches its own boundary at 7.
            let deferred = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(7), Location::new(12)),
            };
            let NextStep::Continue(engine) = engine
                .handle_event(Event::TargetUpdate(deferred.clone()))
                .await
                .unwrap()
            else {
                panic!("a deferred update must not complete sync");
            };
            let NextStep::Continue(mut engine) =
                engine.handle_event(Event::FinishRequested).await.unwrap()
            else {
                panic!("the current target is not reached");
            };
            assert_eq!(engine.deferred.kept()[0], Some(&deferred));
            assert!(engine.outstanding_requests.contains(&Location::new(7)));

            // Replace it with a request whose response the test delivers.
            let id = insert_pending_request(
                &mut engine,
                Request::Boundary {
                    size: Location::new(12),
                    start: Location::new(7),
                },
            );
            let NextStep::Continue(engine) = engine
                .handle_event(Event::BatchReceived(Ok(IndexedFetchResult {
                    id,
                    result: Ok(Some(Response::Boundary {
                        proof: Proof {
                            leaves: Location::new(12),
                            inactive_peaks: 0,
                            digests: vec![],
                        },
                        op: 7,
                        pinned_nodes: vec![],
                    })),
                })))
                .await
                .unwrap()
            else {
                panic!("the adopted target is not reached");
            };
            assert_eq!(engine.target, deferred);
            assert!(engine.deferred.latest().is_none());
            assert!(!engine.outstanding_requests.contains(&Location::new(5)));
            assert!(!engine.outstanding_requests.contains(&Location::new(7)));
        });
    }

    /// The escape is replaced by the previous newest update after two updates, then after four,
    /// then after eight.
    #[test]
    fn escape_lifetime_doubles_after_each_replacement() {
        let target = |n: u64| Target::<MmrFamily, sha256::Digest> {
            root: sha256::Digest::from([n as u8; 32]),
            range: non_empty_range!(Location::new(n), Location::new(n + 1)),
        };
        let mut deferred = Deferred::Empty;
        let mut escapes = Vec::new();
        for n in 1..=15 {
            deferred.push(target(n));
            let escape = *deferred.kept()[0].unwrap().range.start();
            if escapes.last().is_none_or(|&(_, last)| last != escape) {
                escapes.push((n, escape));
            }
            assert_eq!(deferred.latest(), Some(&target(n)));
        }
        assert_eq!(escapes, vec![(1, 1), (3, 2), (6, 5), (13, 12)]);

        // The escape's arrival adopts it, the newest update becomes the escape, and the lifetime
        // returns to two.
        assert_eq!(deferred.take_at(Location::new(12)), Some(target(12)));
        assert_eq!(deferred.kept()[0], Some(&target(15)));
        deferred.push(target(16));
        deferred.push(target(17));
        assert_eq!(deferred.kept()[0], Some(&target(16)));
        assert_eq!(deferred.take_latest(), Some(target(17)));
        assert!(deferred.latest().is_none());
    }

    /// When the escape and the newest update share a lower bound, the boundary's arrival adopts the
    /// newest.
    #[test]
    fn take_at_prefers_newest_update_at_lower_bound() {
        let target = |root: u8, end: u64| Target::<MmrFamily, sha256::Digest> {
            root: sha256::Digest::from([root; 32]),
            range: non_empty_range!(Location::new(7), Location::new(end)),
        };
        let mut deferred = Deferred::Empty;
        deferred.push(target(1, 10));
        deferred.push(target(2, 12));
        assert_eq!(deferred.take_at(Location::new(7)), Some(target(2, 12)));
        assert!(deferred.latest().is_none());
    }

    /// A boundary response at `start` for a request at `size`.
    fn boundary_result(
        id: RequestId,
        size: u64,
        start: u64,
    ) -> IndexedFetchResult<MmrFamily, i32, sha256::Digest, Infallible> {
        IndexedFetchResult {
            id,
            result: Ok(Some(Response::Boundary {
                proof: Proof {
                    leaves: Location::new(size),
                    inactive_peaks: 0,
                    digests: vec![],
                },
                op: start as i32,
                pinned_nodes: vec![],
            })),
        }
    }

    /// A deferred update's boundary that arrives once no request below its lower bound is
    /// outstanding is dropped, and the update stays deferred.
    #[test]
    fn deferred_boundary_is_dropped_once_unblocked() {
        deterministic::Runner::default().start(|context| async move {
            let mut config = test_engine_config(context, 15, Arc::new(AtomicUsize::new(0)));
            config.target.range = non_empty_range!(Location::new(5), Location::new(20));
            let mut engine = Engine::new(config).await.unwrap();
            let current = engine.target.clone();
            let boundary = insert_pending_request(
                &mut engine,
                Request::Boundary {
                    size: Location::new(20),
                    start: Location::new(5),
                },
            );
            insert_pending_request(
                &mut engine,
                Request::Operations {
                    size: Location::new(20),
                    start: Location::new(15),
                    max_ops: NZU64!(5),
                },
            );

            // An update behind the boundary at 5 fetches its own boundary at 10.
            let update = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(10), Location::new(30)),
            };
            let NextStep::Continue(engine) = engine
                .handle_event(Event::TargetUpdate(update.clone()))
                .await
                .unwrap()
            else {
                panic!("a deferred update must not complete sync");
            };
            assert!(engine.outstanding_requests.contains(&Location::new(10)));

            // The boundary at 5 arrives, leaving only the request at 15, beyond the update's
            // lower bound. The update's boundary then arrives and is dropped.
            let NextStep::Continue(mut engine) = engine
                .handle_event(Event::BatchReceived(Ok(boundary_result(boundary, 20, 5))))
                .await
                .unwrap()
            else {
                panic!("the current target is not reached");
            };
            let id = insert_pending_request(
                &mut engine,
                Request::Boundary {
                    size: Location::new(30),
                    start: Location::new(10),
                },
            );
            let NextStep::Continue(engine) = engine
                .handle_event(Event::BatchReceived(Ok(boundary_result(id, 30, 10))))
                .await
                .unwrap()
            else {
                panic!("the current target is not reached");
            };
            assert_eq!(engine.target, current);
            assert_eq!(engine.deferred.latest(), Some(&update));
            assert!(!engine.outstanding_requests.contains(&Location::new(10)));
        });
    }

    /// A failed request for a deferred update's boundary does not fail sync. The update stays
    /// deferred, and its boundary is requested again when another update arrives.
    #[test]
    fn failed_deferred_boundary_is_retried_on_next_update() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let (engine, _) = tail_engine(config, false).await;
            let first = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(7), Location::new(12)),
            };
            let NextStep::Continue(mut engine) = engine
                .handle_event(Event::TargetUpdate(first.clone()))
                .await
                .unwrap()
            else {
                panic!("a deferred update must not complete sync");
            };

            // The source has no response for the boundary at 7.
            let id = insert_pending_request(
                &mut engine,
                Request::Boundary {
                    size: Location::new(12),
                    start: Location::new(7),
                },
            );
            let NextStep::Continue(engine) = engine
                .handle_event(Event::BatchReceived(Ok(IndexedFetchResult {
                    id,
                    result: Ok(None),
                })))
                .await
                .unwrap()
            else {
                panic!("the current target is not reached");
            };
            assert_eq!(engine.deferred.latest(), Some(&first));
            assert!(!engine.outstanding_requests.contains(&Location::new(7)));

            // The next update requests both boundaries.
            let next = Target {
                root: sha256::Digest::from([3; 32]),
                range: non_empty_range!(Location::new(8), Location::new(14)),
            };
            let NextStep::Continue(engine) = engine
                .handle_event(Event::TargetUpdate(next))
                .await
                .unwrap()
            else {
                panic!("a deferred update must not complete sync");
            };
            assert!(engine.outstanding_requests.contains(&Location::new(7)));
            assert!(engine.outstanding_requests.contains(&Location::new(8)));
        });
    }

    /// An outstanding boundary request does not count toward the request limit, so with a limit of
    /// one, operations are still requested while the pinned nodes are pending.
    #[test]
    fn boundary_request_leaves_room_for_operations() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let engine = Engine::new(config).await.unwrap();
            let requests = engine.outstanding_requests.requests().collect::<Vec<_>>();
            assert!(matches!(
                requests[..],
                [Request::Boundary { .. }, Request::Operations { .. }]
            ));
        });
    }

    /// A deferred update whose lower bound holds an operations request of the current target
    /// fetches its boundary once that request completes.
    #[test]
    fn deferred_boundary_is_requested_once_its_lower_bound_is_free() {
        deterministic::Runner::default().start(|context| async move {
            let config = test_engine_config(context, 5, Arc::new(AtomicUsize::new(0)));
            let (engine, operations) = tail_engine(config, false).await;
            let update = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(6), Location::new(12)),
            };
            let NextStep::Continue(engine) = engine
                .handle_event(Event::TargetUpdate(update.clone()))
                .await
                .unwrap()
            else {
                panic!("a deferred update must not complete sync");
            };
            assert_eq!(engine.deferred.latest(), Some(&update));

            // The operations request at 6 completes, while the boundary at 5 stays outstanding.
            let NextStep::Continue(engine) = engine
                .handle_event(Event::BatchReceived(Ok(IndexedFetchResult {
                    id: operations,
                    result: Ok(Some(Response::Operations {
                        proof: Proof {
                            leaves: Location::new(10),
                            inactive_peaks: 0,
                            digests: vec![],
                        },
                        operations: vec![6, 7, 8, 9],
                    })),
                })))
                .await
                .unwrap()
            else {
                panic!("the current target is not reached");
            };
            let at_update = engine
                .outstanding_requests
                .requests()
                .find(|request| request.start() == Location::new(6));
            assert!(matches!(at_update, Some(Request::Boundary { .. })));
        });
    }

    /// An operations request of the current target at a deferred update's lower bound replaces
    /// that update's boundary request.
    #[test]
    fn operations_request_replaces_deferred_boundary() {
        deterministic::Runner::default().start(|context| async move {
            let mut config = test_engine_config(context, 9, Arc::new(AtomicUsize::new(0)));
            config.target.range = non_empty_range!(Location::new(8), Location::new(16));
            config.max_outstanding_requests = NZUsize!(4);
            let mut engine = Engine::new(config).await.unwrap();
            engine.outstanding_requests.retain(|_| false);
            engine.pinned_nodes = Some(Vec::new());
            let update = Target {
                root: sha256::Digest::from([2; 32]),
                range: non_empty_range!(Location::new(11), Location::new(22)),
            };
            engine.deferred.push(update.clone());
            insert_pending_request(
                &mut engine,
                Request::Boundary {
                    size: Location::new(22),
                    start: Location::new(11),
                },
            );

            // The deferred boundary does not cover the current target's operation at 11.
            engine.schedule_requests();
            let at_update = engine
                .outstanding_requests
                .requests()
                .find(|request| request.start() == Location::new(11));
            assert!(matches!(at_update, Some(Request::Operations { .. })));
            assert_eq!(engine.deferred.latest(), Some(&update));
        });
    }

    /// A queued update that advances the reached target with an unchanged root fails sync, even
    /// when a later queued update supersedes it.
    #[test]
    fn step_rejects_queued_update_with_unchanged_root() {
        deterministic::Runner::default().start(|context| async move {
            let (update_tx, update_rx) = mpsc::channel(2);
            let mut config = test_engine_config(context, 10, Arc::new(AtomicUsize::new(0)));
            config.update_rx = Some(update_rx);
            let unchanged_root = Target {
                root: config.target.root,
                range: non_empty_range!(Location::new(5), Location::new(12)),
            };
            let later = Target {
                root: sha256::Digest::from([3; 32]),
                range: non_empty_range!(Location::new(5), Location::new(14)),
            };
            update_tx.send(unchanged_root).await.unwrap();
            update_tx.send(later).await.unwrap();

            let engine = Engine::new(config).await.unwrap();
            assert!(matches!(
                engine.step().await,
                Err(SyncError::Engine(EngineError::SyncTargetRootUnchanged))
            ));
        });
    }

    /// A no-op fetch result for testing request tracking.
    fn dummy_result(id: RequestId) -> IndexedFetchResult<MmrFamily, i32, sha256::Digest, ()> {
        IndexedFetchResult {
            id,
            result: Ok(Some(Response::Operations {
                proof: Proof {
                    leaves: Location::new(0),
                    inactive_peaks: 0,
                    digests: vec![],
                },
                operations: vec![],
            })),
        }
    }

    /// Helper to add a request at a given location.
    fn add(requests: &mut Requests<MmrFamily, i32, sha256::Digest, ()>, loc: u64) -> RequestId {
        requests.insert(
            Request::Operations {
                size: Location::new(loc),
                start: Location::new(loc),
                max_ops: NZU64!(1),
            },
            |id| std::future::ready(dummy_result(id)),
        )
    }

    #[test]
    fn test_add_and_remove() {
        let mut requests: Requests<MmrFamily, i32, sha256::Digest, ()> = Requests::new();
        assert_eq!(requests.len(), 0);

        let id = add(&mut requests, 10);
        assert_eq!(requests.len(), 1);
        assert!(requests.contains(&Location::new(10)));

        assert!(requests.remove(id).is_some());
        assert!(!requests.contains(&Location::new(10)));
        assert!(requests.remove(id).is_none());
    }

    #[test]
    fn test_retain_matching() {
        let mut requests: Requests<MmrFamily, i32, sha256::Digest, ()> = Requests::new();

        add(&mut requests, 5);
        add(&mut requests, 10);
        add(&mut requests, 15);
        add(&mut requests, 20);
        assert_eq!(requests.len(), 4);

        requests.retain(|request| request.start() >= Location::new(10));
        assert_eq!(requests.len(), 3);
        assert!(!requests.contains(&Location::new(5)));
        assert!(requests.contains(&Location::new(10)));
        assert!(requests.contains(&Location::new(15)));
        assert!(requests.contains(&Location::new(20)));
    }

    #[test]
    fn test_retain_none() {
        let mut requests: Requests<MmrFamily, i32, sha256::Digest, ()> = Requests::new();

        add(&mut requests, 5);
        add(&mut requests, 10);
        assert_eq!(requests.len(), 2);

        requests.retain(|_| false);
        assert_eq!(requests.len(), 0);
    }

    #[test]
    fn test_retain_empty() {
        let mut requests: Requests<MmrFamily, i32, sha256::Digest, ()> = Requests::new();
        requests.retain(|_| true);
        assert_eq!(requests.len(), 0);
    }

    #[test]
    fn test_retain_all() {
        let mut requests: Requests<MmrFamily, i32, sha256::Digest, ()> = Requests::new();

        add(&mut requests, 10);
        add(&mut requests, 20);
        assert_eq!(requests.len(), 2);

        requests.retain(|_| true);
        assert_eq!(requests.len(), 2);
        assert!(requests.contains(&Location::new(10)));
        assert!(requests.contains(&Location::new(20)));
    }

    #[test]
    fn test_superseded_request() {
        let mut requests: Requests<MmrFamily, i32, sha256::Digest, ()> = Requests::new();

        // Old request at location 10
        let old_id = add(&mut requests, 10);
        assert_eq!(requests.len(), 1);

        // New request supersedes at same location
        let new_id = add(&mut requests, 10);
        assert_eq!(requests.len(), 1);

        // Old ID is no longer tracked (superseded by insert)
        assert!(requests.remove(old_id).is_none());

        // New ID is still tracked and by_location is intact
        assert!(requests.contains(&Location::new(10)));
        assert!(requests.remove(new_id).is_some());
        assert!(!requests.contains(&Location::new(10)));
    }

    #[test]
    fn test_stale_completion_after_retain() {
        let mut requests: Requests<MmrFamily, i32, sha256::Digest, ()> = Requests::new();

        let old_id = add(&mut requests, 5);
        let queued_result = dummy_result(old_id);
        add(&mut requests, 15);
        requests.retain(|request| request.start() >= Location::new(10));

        // The queued completion no longer resolves to a tracked request.
        assert!(requests.remove(queued_result.id).is_none());

        // New request at the same location gets a different ID
        let new_id = add(&mut requests, 5);
        assert_ne!(old_id, new_id);
        assert!(requests.remove(new_id).is_some());
    }

    #[test]
    fn test_retain_aborts_future() {
        deterministic::Runner::default().start(|_context| async move {
            let mut requests: Requests<MmrFamily, i32, sha256::Digest, ()> = Requests::new();
            requests.insert(
                Request::Operations {
                    size: Location::new(5),
                    start: Location::new(5),
                    max_ops: NZU64!(1),
                },
                |_| std::future::pending(),
            );
            requests.retain(|_| false);
            assert!(matches!(requests.next_completed().await, Err(Aborted)));
        });
    }
}
