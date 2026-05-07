//! Core sync engine components that are shared across sync clients.
use crate::{
    merkle::{hasher::Standard as StandardHasher, Family, Location},
    qmdb::{
        self,
        sync::{
            database::Config as _,
            error::EngineError,
            requests::{Id as RequestId, Requests},
            resolver::{FetchResult, Resolver},
            target::validate_update,
            Database, DbResolver, Error as SyncError, Journal, Target,
        },
    },
};
use commonware_codec::Encode;
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_runtime::{
    telemetry::metrics::{Gauge, GaugeExt, MetricsExt},
    Supervisor as _,
};
use commonware_utils::{
    channel::{
        fallible::{AsyncFallibleExt, OneshotExt as _},
        mpsc, oneshot,
    },
    NZU64,
};
use futures::{
    future::{pending, Either},
    StreamExt,
};
use mpsc::error::TryRecvError;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fmt::Debug,
    num::NonZeroU64,
};

/// Type alias for sync engine errors
type Error<DB, R> =
    qmdb::sync::Error<<DB as Database>::Family, <R as Resolver>::Error, <DB as Database>::Digest>;

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
    /// A batch of operations was received
    BatchReceived(IndexedFetchResult<F, Op, D, E>),
    /// The target update channel was closed
    UpdateChannelClosed,
    /// A finish signal was received
    FinishRequested,
    /// The finish signal channel was closed
    FinishChannelClosed,
}

/// Progress gauges updated by the sync engine.
struct ProgressMetrics {
    journal_size: Gauge,
    target_end: Gauge,
}

impl ProgressMetrics {
    /// Register sync progress metrics on the provided context.
    fn new(context: &impl commonware_runtime::Metrics) -> Self {
        let journal_size = context.gauge("journal_size", "Current sync journal size");
        let target_end = context.gauge(
            "target_end",
            "Exclusive target range end, equal to journal size when sync completes",
        );

        Self {
            journal_size,
            target_end,
        }
    }

    /// Update progress gauges from the current engine snapshot.
    fn record(&self, journal_size: u64, target_end: u64) {
        let _ = self.journal_size.try_set(journal_size);
        let _ = self.target_end.try_set(target_end);
    }
}

/// Result from a fetch operation with its request ID and starting location.
#[derive(Debug)]
pub(super) struct IndexedFetchResult<F: Family, Op, D: Digest, E> {
    /// Unique ID assigned when the request was scheduled.
    pub id: RequestId,
    /// The result of the fetch operation.
    pub result: Result<FetchResult<F, Op, D>, E>,
}

/// Wait for the next synchronization event.
/// Returns `None` when there are no outstanding requests and no channels to wait on.
async fn wait_for_event<F: Family, Op, D: Digest, E>(
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
    let batch_result_fut = if outstanding_requests.len() == 0 {
        Either::Right(pending())
    } else {
        Either::Left(outstanding_requests.futures_mut().next())
    };

    select! {
        finish = finish_fut => finish.map_or_else(
            || Some(Event::FinishChannelClosed),
            |_| Some(Event::FinishRequested)
        ),
        target = target_update_fut => target.map_or_else(
            || Some(Event::UpdateChannelClosed),
            |target| Some(Event::TargetUpdate(target))
        ),
        result = batch_result_fut => result.map(|fetch_result| Event::BatchReceived(fetch_result)),
    }
}

/// Configuration for creating a new Engine
pub struct Config<DB, R>
where
    DB: Database,
    R: DbResolver<DB>,
    DB::Op: Encode,
{
    /// Runtime context for creating database components
    pub context: DB::Context,
    /// Network resolver for fetching operations and proofs
    pub resolver: R,
    /// Sync target (root digest and operation bounds)
    pub target: Target<DB::Family, DB::Digest>,
    /// Maximum number of outstanding requests for operation batches
    pub max_outstanding_requests: usize,
    /// Maximum operations to fetch per batch
    pub fetch_batch_size: NonZeroU64,
    /// Number of operations to apply in a single batch
    pub apply_batch_size: usize,
    /// Database-specific configuration
    pub db_config: DB::Config,
    /// Channel for receiving sync target updates
    pub update_rx: Option<mpsc::Receiver<Target<DB::Family, DB::Digest>>>,
    /// Channel that requests sync completion once the current target is reached.
    ///
    /// When `None`, sync completes as soon as the target is reached.
    pub finish_rx: Option<mpsc::Receiver<()>>,
    /// Channel used to notify an observer once the current target is reached.
    /// The engine sends at most one notification for each target.
    ///
    /// When `reached_target_tx` is `Some(...)`, this receiver must be actively
    /// drained by the observer. The engine awaits send capacity on this channel before
    /// proceeding, so backpressure can pause progress at target.
    pub reached_target_tx: Option<mpsc::Sender<Target<DB::Family, DB::Digest>>>,
    /// Maximum number of previous roots to retain for verifying in-flight
    /// requests after target updates. Set to 0 to disable (all retained
    /// requests will be re-fetched).
    pub max_retained_roots: usize,
}
/// A shared sync engine that manages the core synchronization state and operations.
pub(crate) struct Engine<DB, R>
where
    DB: Database,
    R: DbResolver<DB>,
    DB::Op: Encode,
{
    /// Tracks outstanding fetch requests and their futures
    outstanding_requests: Requests<DB::Family, DB::Op, DB::Digest, R::Error>,

    /// Operations that have been fetched but not yet applied to the log.
    ///
    /// # Invariant
    ///
    /// The vectors in the map are non-empty.
    fetched_operations: BTreeMap<Location<DB::Family>, Vec<DB::Op>>,

    /// Pinned merkle nodes extracted from proofs, used for database construction
    pinned_nodes: Option<Vec<DB::Digest>>,

    /// Whether persisted local state already matches the current target and can be
    /// rebuilt without fetching fresh boundary pins.
    local_target_state_available: bool,

    /// Historical roots from previous sync targets, keyed by tree size
    /// (target.range.end()). Each tree size maps to a unique root because
    /// the merkle tree is append-only and validate_update rejects unchanged
    /// roots. When a retained request completes, proof.leaves identifies
    /// which historical root to verify against.
    retained_roots: HashMap<Location<DB::Family>, DB::Digest>,

    /// Tree sizes of retained roots in insertion order (oldest first),
    /// used for FIFO eviction when retained_roots exceeds capacity.
    retained_roots_order: VecDeque<Location<DB::Family>>,

    /// Maximum number of historical roots to retain
    max_retained_roots: usize,

    /// The current sync target (root digest and operation bounds)
    target: Target<DB::Family, DB::Digest>,

    /// Maximum number of parallel outstanding requests
    max_outstanding_requests: usize,

    /// Maximum operations to fetch in a single batch
    fetch_batch_size: NonZeroU64,

    /// Number of operations to apply in a single batch
    apply_batch_size: usize,

    /// Journal that operations are applied to during sync
    journal: DB::Journal,

    /// Resolver for fetching operations and proofs from the sync source
    resolver: R,

    /// Hasher used for proof verification
    hasher: StandardHasher<DB::Hasher>,

    /// Runtime context for database operations
    context: DB::Context,

    /// Configuration for building the final database
    config: DB::Config,

    /// Optional receiver for target updates during sync
    update_rx: Option<mpsc::Receiver<Target<DB::Family, DB::Digest>>>,

    /// Channel that requests sync completion once the current target is reached.
    ///
    /// When `None`, sync completes as soon as the target is reached.
    finish_rx: Option<mpsc::Receiver<()>>,

    /// Channel used to notify an observer once the current target is reached.
    /// The engine sends at most one notification for each target.
    ///
    /// When `reached_target_tx` is `Some(...)`, this receiver must be actively
    /// drained by the observer. The engine awaits send capacity on this channel before
    /// proceeding, so backpressure can pause progress at target.
    reached_target_tx: Option<mpsc::Sender<Target<DB::Family, DB::Digest>>>,

    /// Progress gauges updated after target updates and batch application.
    progress_metrics: ProgressMetrics,

    /// Whether explicit finish has been requested.
    finish_requested: bool,

    /// Tracks whether the current target has already been reported as reached.
    reached_current_target_reported: bool,
}

#[cfg(test)]
impl<DB, R> Engine<DB, R>
where
    DB: Database,
    R: DbResolver<DB>,
    DB::Op: Encode,
{
    pub(crate) fn journal(&self) -> &DB::Journal {
        &self.journal
    }
}

impl<DB, R> Engine<DB, R>
where
    DB: Database,
    R: DbResolver<DB>,
    DB::Op: Encode,
{
    /// Create a new sync engine with the given configuration
    pub async fn new(config: Config<DB, R>) -> Result<Self, Error<DB, R>> {
        if !config.target.range.end().is_valid() {
            return Err(SyncError::Engine(EngineError::InvalidTarget {
                lower_bound_pos: config.target.range.start(),
                upper_bound_pos: config.target.range.end(),
            }));
        }

        // Probe for persisted local state matching the target before opening
        // any engine-owned handles.
        let local_target_state_available = if config.target.range.start() > Location::new(0) {
            DB::has_local_target_state(
                config.context.child("local_target_probe"),
                &config.db_config,
                &config.target,
            )
            .await
        } else {
            false
        };

        // Create journal and verifier using the database's factory methods
        let journal = <DB::Journal as Journal<DB::Family>>::new(
            config.context.child("journal"),
            config.db_config.journal_config(),
            config.target.range.clone(),
        )
        .await?;

        let sync_context = config.context.child("sync");
        let progress_metrics = ProgressMetrics::new(&sync_context);
        let mut engine = Self {
            outstanding_requests: Requests::new(),
            fetched_operations: BTreeMap::new(),
            pinned_nodes: None,
            local_target_state_available,
            retained_roots: HashMap::new(),
            retained_roots_order: VecDeque::new(),
            max_retained_roots: config.max_retained_roots,
            target: config.target.clone(),
            max_outstanding_requests: config.max_outstanding_requests,
            fetch_batch_size: config.fetch_batch_size,
            apply_batch_size: config.apply_batch_size,
            journal,
            resolver: config.resolver.clone(),
            hasher: qmdb::hasher::<DB::Hasher>(),
            context: config.context,
            config: config.db_config,
            update_rx: config.update_rx,
            finish_rx: config.finish_rx,
            reached_target_tx: config.reached_target_tx,
            finish_requested: false,
            reached_current_target_reported: false,
            progress_metrics,
        };
        engine.schedule_requests().await?;
        engine.record_progress().await;
        Ok(engine)
    }

    /// Schedule new fetch requests for operations in the sync range that we haven't yet fetched.
    async fn schedule_requests(&mut self) -> Result<(), Error<DB, R>> {
        let target_size = self.target.range.end();

        // Schedule a pinned-nodes request at the lower sync bound if we don't
        // have boundary state yet and one isn't already in flight.
        if !self.has_boundary_state()
            && !self
                .outstanding_requests
                .contains(&self.target.range.start())
        {
            let start_loc = self.target.range.start();
            let resolver = self.resolver.clone();
            let (cancel_tx, cancel_rx) = oneshot::channel();
            let id = self.outstanding_requests.next_id();
            self.outstanding_requests.insert(
                id,
                start_loc,
                target_size,
                cancel_tx,
                Box::pin(async move {
                    let result = resolver
                        .get_operations(target_size, start_loc, NZU64!(1), true, cancel_rx)
                        .await;
                    IndexedFetchResult { id, result }
                }),
            );
        }

        // Calculate the maximum number of requests to make
        let num_requests = self
            .max_outstanding_requests
            .saturating_sub(self.outstanding_requests.len());

        let log_size = self.journal.size().await;

        for _ in 0..num_requests {
            // Convert fetched operations to operation counts for shared gap detection
            let operation_counts: BTreeMap<Location<DB::Family>, u64> = self
                .fetched_operations
                .iter()
                .map(|(&start_loc, operations)| (start_loc, operations.len() as u64))
                .collect();

            // Find the next gap in the sync range that needs to be fetched.
            let Some(gap_range) = crate::qmdb::sync::gaps::find_next(
                Location::new(log_size)..self.target.range.end(),
                &operation_counts,
                self.outstanding_requests.locations(),
                self.fetch_batch_size,
            ) else {
                break; // No more gaps to fill
            };

            // Calculate batch size for this gap
            let gap_size = *gap_range.end.checked_sub(*gap_range.start).unwrap();
            let gap_size: NonZeroU64 = gap_size.try_into().unwrap();
            let batch_size = self.fetch_batch_size.min(gap_size);

            // Schedule the request
            let resolver = self.resolver.clone();
            let (cancel_tx, cancel_rx) = oneshot::channel();
            let id = self.outstanding_requests.next_id();
            self.outstanding_requests.insert(
                id,
                gap_range.start,
                target_size,
                cancel_tx,
                Box::pin(async move {
                    let result = resolver
                        .get_operations(target_size, gap_range.start, batch_size, false, cancel_rx)
                        .await;
                    IndexedFetchResult { id, result }
                }),
            );
        }

        Ok(())
    }

    /// Reset sync state for a target update.
    ///
    /// Only cancels requests that cover ranges before the new target range
    /// start. Requests at or after the new start are retained; their proofs
    /// will be verified against the saved historical root (see
    /// `retained_roots`) so the fetched operations can still be used.
    pub async fn reset_for_target_update(
        mut self,
        new_target: Target<DB::Family, DB::Digest>,
    ) -> Result<Self, Error<DB, R>> {
        self.journal.resize(new_target.range.start()).await?;
        // Remove requests at or before the new start. The request at start
        // must be re-issued as a pinned-nodes request with the new target size.
        self.outstanding_requests
            .remove_before(new_target.range.start().checked_add(1).unwrap());
        self.fetched_operations.clear();
        self.pinned_nodes = None;
        self.local_target_state_available = false;

        // Save the current root keyed by its tree size for verifying
        // retained requests that were issued against this target.
        if self.max_retained_roots > 0 {
            let old_target_size = self.target.range.end();
            assert!(
                self.retained_roots
                    .insert(old_target_size, self.target.root)
                    .is_none(),
                "duplicate retained root for tree size {old_target_size:?}"
            );
            self.retained_roots_order.push_back(old_target_size);
            while self.retained_roots.len() > self.max_retained_roots {
                if let Some(oldest) = self.retained_roots_order.pop_front() {
                    self.retained_roots.remove(&oldest);
                }
            }
        }

        self.target = new_target;
        self.reached_current_target_reported = false;
        Ok(self)
    }

    /// Drain a pending explicit-finish signal without blocking.
    ///
    /// If a finish signal is present, the engine transitions into "finish requested"
    /// mode via [`Self::accept_finish`]. If the finish channel is disconnected before
    /// a finish request is observed, this returns [`EngineError::FinishChannelClosed`].
    fn drain_finish_requests(&mut self) -> Result<(), Error<DB, R>> {
        let Some(finish_rx) = self.finish_rx.as_mut() else {
            return Ok(());
        };
        match finish_rx.try_recv() {
            Ok(()) => {
                self.accept_finish();
                Ok(())
            }
            Err(TryRecvError::Empty) => Ok(()),
            Err(TryRecvError::Disconnected) => {
                Err(SyncError::Engine(EngineError::FinishChannelClosed))
            }
        }
    }

    /// Mark that explicit finish has been requested and stop listening for more signals.
    ///
    /// This is a one-way transition for the current engine instance. Once set, the
    /// engine may complete as soon as it is at a target (or the next time it reaches one).
    fn accept_finish(&mut self) {
        self.finish_requested = true;
        self.finish_rx = None;
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
        if let Some(sender) = self.reached_target_tx.as_ref() {
            if !sender.send_lossy(self.target.clone()).await {
                self.reached_target_tx = None;
            }
        }
        self.reached_current_target_reported = true;
    }

    /// Record a progress snapshot in metrics.
    async fn record_progress(&self) {
        self.progress_metrics
            .record(self.journal.size().await, *self.target.range.end());
    }

    /// Store a batch of fetched operations. If the input list is empty, this is a no-op.
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
    pub(crate) async fn apply_operations(&mut self) -> Result<(), Error<DB, R>> {
        let mut next_loc = self.journal.size().await;

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
            let operations = self.fetched_operations.remove(&range_start_loc).unwrap();
            assert!(!operations.is_empty());
            // Skip operations that are before the next location.
            let skip_count = (next_loc - *range_start_loc) as usize;
            let operations_count = operations.len() - skip_count;
            let remaining_operations = operations.into_iter().skip(skip_count);
            next_loc += operations_count as u64;
            self.apply_operations_batch(remaining_operations).await?;
        }

        Ok(())
    }

    /// Apply a batch of operations to the journal
    async fn apply_operations_batch<I>(&mut self, operations: I) -> Result<(), Error<DB, R>>
    where
        I: IntoIterator<Item = DB::Op>,
    {
        for op in operations {
            self.journal.append(op).await?;
            // No need to sync here -- the journal will periodically sync its storage
            // and we will also sync when we're done applying all operations.
        }
        Ok(())
    }

    /// Check if sync is complete based on the current journal size and target
    pub async fn is_at_target(&self) -> Result<bool, Error<DB, R>> {
        let journal_size = self.journal.size().await;
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

    /// Returns whether this target needs pinned boundary nodes to reconstruct pruned state.
    fn needs_pinned_boundary(&self) -> bool {
        self.target.range.start() > Location::new(0)
    }

    /// Returns whether the current target has the boundary state needed for completion.
    fn has_boundary_state(&self) -> bool {
        !self.needs_pinned_boundary()
            || self.pinned_nodes.is_some()
            || self.local_target_state_available
    }

    /// Returns whether the journal and boundary state are both ready for completion.
    async fn is_ready_to_complete(&self) -> Result<bool, Error<DB, R>> {
        Ok(self.is_at_target().await? && self.has_boundary_state())
    }

    /// Handle the result of a fetch operation.
    ///
    /// Discards results for requests no longer tracked (removed by
    /// `remove_before` during a target update). For tracked requests,
    /// verifies the proof against the current root first, then falls back
    /// to a matching historical root from `retained_roots` if available.
    fn handle_fetch_result(
        &mut self,
        fetch_result: IndexedFetchResult<DB::Family, DB::Op, DB::Digest, R::Error>,
    ) -> Result<(), Error<DB, R>> {
        // Discard results for stale requests (removed by a target update).
        // Using the request ID prevents a stale future from consuming the
        // tracking entry of a fresh request at the same location.
        let Some(request) = self.outstanding_requests.remove(fetch_result.id) else {
            return Ok(());
        };

        let start_loc = request.start_loc;
        let FetchResult {
            proof,
            operations,
            success_tx,
            pinned_nodes,
        } = fetch_result.result.map_err(SyncError::Resolver)?;

        // Validate batch size
        let operations_len = operations.len() as u64;
        if operations_len == 0 || operations_len > self.fetch_batch_size.get() {
            // Invalid batch size - notify resolver of failure.
            // We will request these operations again when we scan for unfetched operations.
            success_tx.send_lossy(false);
            return Ok(());
        }

        if proof.leaves != request.target_size {
            success_tx.send_lossy(false);
            return Ok(());
        }

        // Look up the root to verify against using the tree size the request
        // asked for. Fresh requests match the current target; retained
        // requests match a historical root that was explicitly retained.
        let is_current_target = request.target_size == self.target.range.end();
        let target_root = if is_current_target {
            &self.target.root
        } else {
            let Some(root) = self.retained_roots.get(&request.target_size) else {
                // No historical root to verify against (evicted or
                // max_retained_roots is 0). Drop the result without
                // penalizing the resolver — the data may be valid.
                return Ok(());
            };
            root
        };

        // Verify the proof. Pinned nodes are only extracted from proofs
        // for the current root because the database needs them for the
        // latest tree size. When local state already satisfies the boundary
        // (pins are available in on-disk metadata), we must not demand
        // pinned nodes from the proof: an empty pinned set would fail
        // `verify_proof_and_pinned_nodes` against the expected
        // `nodes_to_pin(range.start)` count, causing an infinite retry loop
        // whenever a gap request happens to land at `range.start`.
        let need_pinned = is_current_target
            && self.pinned_nodes.is_none()
            && !self.local_target_state_available
            && start_loc == self.target.range.start();
        let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
        let valid = if need_pinned {
            let nodes = pinned_nodes.as_deref().unwrap_or(&[]);
            proof.verify_proof_and_pinned_nodes(
                &self.hasher,
                &elements,
                start_loc,
                nodes,
                target_root,
            )
        } else {
            proof.verify_range_inclusion(&self.hasher, &elements, start_loc, target_root)
        };

        // Report success or failure to the resolver.
        success_tx.send_lossy(valid);

        if !valid {
            if need_pinned {
                tracing::warn!("boundary proof or pinned nodes failed verification, will retry");
            }
            return Ok(());
        }

        // Cache pinned nodes only from current-root-verified proofs.
        if need_pinned {
            if let Some(nodes) = pinned_nodes {
                self.pinned_nodes = Some(nodes);
            }
        }

        // Store operations for later application.
        self.store_operations(start_loc, operations);

        Ok(())
    }

    /// Handle a sync event and return the next engine state.
    async fn handle_event(
        mut self,
        event: Event<DB::Family, DB::Op, DB::Digest, R::Error>,
    ) -> Result<NextStep<Self, DB>, Error<DB, R>> {
        match event {
            Event::TargetUpdate(new_target) => {
                validate_update(&self.target, &new_target)?;

                let mut updated_self = self.reset_for_target_update(new_target).await?;
                updated_self.record_progress().await;
                updated_self.schedule_requests().await?;
                Ok(NextStep::Continue(updated_self))
            }
            Event::UpdateChannelClosed => {
                self.update_rx = None;
                Ok(NextStep::Continue(self))
            }
            Event::FinishRequested => {
                self.accept_finish();
                Ok(NextStep::Continue(self))
            }
            Event::FinishChannelClosed => Err(SyncError::Engine(EngineError::FinishChannelClosed)),
            Event::BatchReceived(fetch_result) => {
                self.handle_fetch_result(fetch_result)?;
                self.schedule_requests().await?;
                self.apply_operations().await?;
                self.record_progress().await;
                Ok(NextStep::Continue(self))
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
    /// Returns `StepResult::Complete(database)` when sync is finished, or
    /// `StepResult::Continue(self)` when more work remains.
    pub(crate) async fn step(mut self) -> Result<NextStep<Self, DB>, Error<DB, R>> {
        self.drain_finish_requests()?;

        // Check if sync is complete
        if self.is_ready_to_complete().await? {
            self.report_reached_target().await;

            if self.finish_rx.is_some() && !self.finish_requested {
                let event = wait_for_event(
                    &mut self.update_rx,
                    &mut self.finish_rx,
                    &mut self.outstanding_requests,
                )
                .await
                .ok_or(SyncError::Engine(EngineError::SyncStalled))?;
                return self.handle_event(event).await;
            }

            self.journal.sync().await?;

            // Build the database from the completed sync
            let database = DB::from_sync_result(
                self.context,
                self.config,
                self.journal,
                self.pinned_nodes,
                self.target.range.clone(),
                self.apply_batch_size,
            )
            .await?;

            // Verify the final root digest matches the final target
            let got_root = database.root();
            let expected_root = self.target.root;
            if got_root != expected_root {
                return Err(SyncError::Engine(EngineError::RootMismatch {
                    expected: expected_root,
                    actual: got_root,
                }));
            }

            return Ok(NextStep::Complete(database));
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

    /// Run sync to completion, returning the final database when done.
    ///
    /// This method repeatedly calls `step()` until sync is complete. The `step()` method
    /// handles building the final database and verifying the root digest.
    pub async fn sync(mut self) -> Result<DB, Error<DB, R>> {
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
        merkle::mmr::{Family as MmrFamily, Proof},
        qmdb::sync::requests::FetchFuture,
    };
    use commonware_cryptography::sha256;
    use commonware_utils::channel::oneshot;

    /// Create a no-op fetch result future for testing request tracking.
    fn dummy_future(id: RequestId) -> FetchFuture<MmrFamily, i32, sha256::Digest, ()> {
        Box::pin(async move {
            IndexedFetchResult {
                id,
                result: Ok(FetchResult {
                    proof: Proof {
                        leaves: Location::new(0),
                        inactive_peaks: 0,
                        digests: vec![],
                    },
                    operations: vec![],
                    success_tx: oneshot::channel().0,
                    pinned_nodes: None,
                }),
            }
        })
    }

    /// Helper to add a request at a given location.
    fn add(requests: &mut Requests<MmrFamily, i32, sha256::Digest, ()>, loc: u64) -> RequestId {
        let id = requests.next_id();
        requests.insert(
            id,
            Location::new(loc),
            Location::new(loc),
            oneshot::channel().0,
            dummy_future(id),
        );
        id
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
    fn test_remove_before() {
        let mut requests: Requests<MmrFamily, i32, sha256::Digest, ()> = Requests::new();

        add(&mut requests, 5);
        add(&mut requests, 10);
        add(&mut requests, 15);
        add(&mut requests, 20);
        assert_eq!(requests.len(), 4);

        requests.remove_before(Location::new(10));
        assert_eq!(requests.len(), 3);
        assert!(!requests.contains(&Location::new(5)));
        assert!(requests.contains(&Location::new(10)));
        assert!(requests.contains(&Location::new(15)));
        assert!(requests.contains(&Location::new(20)));
    }

    #[test]
    fn test_remove_before_all() {
        let mut requests: Requests<MmrFamily, i32, sha256::Digest, ()> = Requests::new();

        add(&mut requests, 5);
        add(&mut requests, 10);
        assert_eq!(requests.len(), 2);

        requests.remove_before(Location::new(100));
        assert_eq!(requests.len(), 0);
    }

    #[test]
    fn test_remove_before_empty() {
        let mut requests: Requests<MmrFamily, i32, sha256::Digest, ()> = Requests::new();
        requests.remove_before(Location::new(10));
        assert_eq!(requests.len(), 0);
    }

    #[test]
    fn test_remove_before_none() {
        let mut requests: Requests<MmrFamily, i32, sha256::Digest, ()> = Requests::new();

        add(&mut requests, 10);
        add(&mut requests, 20);
        assert_eq!(requests.len(), 2);

        requests.remove_before(Location::new(5));
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
    fn test_stale_id_after_remove_before() {
        let mut requests: Requests<MmrFamily, i32, sha256::Digest, ()> = Requests::new();

        let old_id = add(&mut requests, 5);
        add(&mut requests, 15);
        requests.remove_before(Location::new(10));

        // Old ID at location 5 was discarded by remove_before
        assert!(requests.remove(old_id).is_none());

        // New request at the same location gets a different ID
        let new_id = add(&mut requests, 5);
        assert_ne!(old_id, new_id);
        assert!(requests.remove(new_id).is_some());
    }
}
