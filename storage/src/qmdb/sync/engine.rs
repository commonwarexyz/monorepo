//! Core sync engine components that are shared across sync clients.
use crate::{
    merkle::{Family, Location, hasher::Standard as StandardHasher},
    qmdb::{
        self,
        sync::{
            Database, Error as SyncError, Journal, Metrics, SourceFor, Target,
            database::Config as _,
            error::EngineError,
            requests::{Id as RequestId, Requests},
            source::{FeedbackTx, Request, Response, Source},
        },
    },
};
use commonware_codec::Encode;
use commonware_cryptography::Digest;
use commonware_macros::{boxed, select};
use commonware_runtime::Supervisor as _;
use commonware_utils::channel::{
    fallible::{AsyncFallibleExt, OneshotExt as _},
    mpsc,
};
use futures::future::{Aborted, Either, pending};
use mpsc::error::TryRecvError;
use std::{collections::BTreeMap, fmt::Debug, num::NonZeroU64, sync::Arc};

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
    pub result: Result<(Response<F, Op, D>, FeedbackTx), E>,
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
    /// Maximum number of outstanding requests for operation batches
    pub max_outstanding_requests: usize,
    /// Maximum operations to fetch per batch
    pub fetch_batch_size: NonZeroU64,
    /// Number of operations to apply in a single batch
    pub apply_batch_size: NonZeroU64,
    /// Database-specific configuration
    pub db_config: DB::Config,
    /// Channel for receiving sync target updates.
    ///
    /// The caller selects targets before sending updates. The engine adopts only strictly
    /// advancing targets and discards the rest.
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

    /// Pinned merkle nodes extracted from proofs, used for database construction
    pinned_nodes: Option<Vec<DB::Digest>>,

    /// Historical roots from superseded sync targets, keyed by database size
    /// (target.range.end()). Keys strictly increase across target updates
    /// (non-advancing updates are discarded), so each size maps to a unique
    /// root and the smallest key is the oldest. Eviction drops it first.
    /// When a retained request completes, its requested size selects the
    /// historical root to verify against.
    retained_roots: BTreeMap<Location<DB::Family>, DB::Digest>,

    /// Maximum number of historical roots to retain
    max_retained_roots: usize,

    /// The current sync target (root digest and operation bounds)
    target: Target<DB::Family, DB::Digest>,

    /// Maximum number of parallel outstanding requests
    max_outstanding_requests: usize,

    /// Maximum operations to fetch in a single batch
    fetch_batch_size: NonZeroU64,

    /// Number of operations to apply in a single batch
    apply_batch_size: NonZeroU64,

    /// Journal that operations are applied to during sync
    journal: DB::Journal,

    /// Source of operations and proofs, shared with in-flight requests
    source: Arc<S>,

    /// Hasher used for proof verification
    hasher: StandardHasher<DB::Hasher>,

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
    /// The engine sends at most one notification for each target.
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

        // Create journal and verifier using the database's factory methods
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
            retained_roots: BTreeMap::new(),
            max_retained_roots: config.max_retained_roots,
            target: config.target.clone(),
            max_outstanding_requests: config.max_outstanding_requests,
            fetch_batch_size: config.fetch_batch_size,
            apply_batch_size: config.apply_batch_size,
            journal,
            source: Arc::new(config.source),
            hasher: qmdb::hasher::<DB::Hasher>(),
            context: config.context,
            config: config.db_config,
            update_rx: config.update_rx,
            finish_requested: false,
            finish_rx: config.finish_rx,
            reached_target_tx: config.reached_target_tx,
            reached_current_target_reported: false,
            metrics,
        };
        engine.schedule_requests()?;
        engine.record_progress();
        Ok(engine)
    }

    /// Track `request` and spawn its fetch against the shared source.
    fn spawn_fetch(&mut self, request: Request<DB::Family>) {
        let source = Arc::clone(&self.source);
        self.outstanding_requests
            .insert(request, move |id| async move {
                let result = source.serve(request).await;
                IndexedFetchResult { id, result }
            });
    }

    /// Schedule new fetch requests for operations in the sync range that we haven't yet fetched.
    fn schedule_requests(&mut self) -> Result<(), Error<DB, S>> {
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
            self.spawn_fetch(request);
        }

        // Calculate the maximum number of requests to make
        let num_requests = self
            .max_outstanding_requests
            .saturating_sub(self.outstanding_requests.len());

        let log_size = self.journal.size();

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
                self.outstanding_requests.ranges(),
            ) else {
                break; // No more gaps to fill
            };

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
            self.spawn_fetch(request);
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
    ) -> Result<Self, Error<DB, S>> {
        self.journal = self.journal.resize(new_target.range.start()).await?;
        // Remove requests at or before the new start. The request at start
        // must be re-issued as a boundary request with the new target size.
        self.outstanding_requests
            .remove_before(new_target.range.start().checked_add(1).unwrap());
        self.fetched_operations.clear();
        self.pinned_nodes = None;

        // Save the current root keyed by its database size for verifying
        // retained requests that were issued against this target.
        if self.max_retained_roots > 0 {
            self.retained_roots
                .insert(self.target.range.end(), self.target.root);
            while self.retained_roots.len() > self.max_retained_roots {
                self.retained_roots.pop_first();
            }
        }

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
            let operations = self.fetched_operations.remove(&range_start_loc).unwrap();
            assert!(!operations.is_empty());
            // Skip operations that are before the next location. The containment check when
            // selecting the range (`next_loc <= range_end`) guarantees at least one operation
            // at or after it, so the batch is never empty.
            let operations = &operations[(next_loc - *range_start_loc) as usize..];
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

    /// Handle a response that failed validation.
    ///
    /// A source that accepts feedback is told the response failed, and the request is
    /// retried. A source that is not listening cannot change its answer, so the failure
    /// is terminal.
    fn reject_response(feedback_tx: FeedbackTx) -> Result<(), Error<DB, S>> {
        feedback_tx.map_or_else(
            || Err(SyncError::Engine(EngineError::InvalidResponse)),
            |feedback_tx| {
                feedback_tx.send_lossy(false);
                Ok(())
            },
        )
    }

    /// Handle the result of a fetch operation.
    ///
    /// Verifies the proof against the current root first, then falls back
    /// to a matching historical root from `retained_roots` if available.
    fn handle_fetch_result(
        &mut self,
        fetch_result: IndexedFetchResult<DB::Family, DB::Op, DB::Digest, S::Error>,
    ) -> Result<(), Error<DB, S>> {
        // Removal aborts a request's future, so a result for an untracked ID should
        // be unreachable.
        let Some(request) = self.outstanding_requests.remove(fetch_result.id) else {
            return Ok(());
        };

        let (response, feedback_tx) = fetch_result.result.map_err(SyncError::Source)?;

        let start_loc = request.start();
        let size = request.size();

        // The proof must cover exactly the requested size.
        if response.proof().leaves != size {
            return Self::reject_response(feedback_tx);
        }
        // A response must match the shape of its request.
        match (request, response) {
            (Request::Operations { max_ops, .. }, Response::Operations { proof, operations }) => {
                let operations_len = operations.len() as u64;
                if operations_len == 0 || operations_len > max_ops.get() {
                    return Self::reject_response(feedback_tx);
                }
                let Some(root) = self.verification_root(size) else {
                    return Ok(());
                };
                let elements = operations.iter().map(|op| op.encode()).collect::<Vec<_>>();
                if !proof.verify_range_inclusion(&self.hasher, &elements, start_loc, root) {
                    return Self::reject_response(feedback_tx);
                }
                if let Some(feedback_tx) = feedback_tx {
                    feedback_tx.send_lossy(true);
                }
                self.store_operations(start_loc, operations);
            }
            (
                Request::Boundary { .. },
                Response::Boundary {
                    proof,
                    op,
                    pinned_nodes,
                },
            ) => {
                // Use the pinned nodes only if the current target still needs them. Otherwise
                // keep the operation and drop the pinned nodes.
                let need_pinned = size == self.target.range.end()
                    && self.pinned_nodes.is_none()
                    && start_loc == self.target.range.start();
                let element = [op.encode()];
                let valid = if need_pinned {
                    proof.verify_proof_and_pinned_nodes(
                        &self.hasher,
                        &element,
                        start_loc,
                        &pinned_nodes,
                        &self.target.root,
                    )
                } else {
                    let Some(root) = self.verification_root(size) else {
                        return Ok(());
                    };
                    proof.verify_range_inclusion(&self.hasher, &element, start_loc, root)
                };
                if !valid {
                    if need_pinned {
                        tracing::warn!("boundary response failed verification");
                    }
                    return Self::reject_response(feedback_tx);
                }
                if let Some(feedback_tx) = feedback_tx {
                    feedback_tx.send_lossy(true);
                }
                if need_pinned {
                    self.pinned_nodes = Some(pinned_nodes);
                }
                self.store_operations(start_loc, vec![op]);
            }
            _ => return Self::reject_response(feedback_tx),
        }

        Ok(())
    }

    /// The root to verify a response against at a given size.
    fn verification_root(&self, size: Location<DB::Family>) -> Option<&DB::Digest> {
        if size == self.target.range.end() {
            Some(&self.target.root)
        } else {
            self.retained_roots.get(&size)
        }
    }

    /// Handle a sync event and return the next engine state.
    async fn handle_event(
        mut self,
        event: Event<DB::Family, DB::Op, DB::Digest, S::Error>,
    ) -> Result<NextStep<Self, DB>, Error<DB, S>> {
        match event {
            Event::TargetUpdate(new_target) => {
                // A non-advancing update is discarded.
                if !new_target.advances(&self.target) {
                    return Ok(NextStep::Continue(self));
                }
                // A same-root update that advances is impossible for an append-only log and
                // indicates a caller bug.
                if new_target.root == self.target.root {
                    return Err(SyncError::Engine(EngineError::SyncTargetRootUnchanged));
                }

                let mut updated_self = self.reset_for_target_update(new_target).await?;
                updated_self.record_progress();
                updated_self.schedule_requests()?;
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
                if let Ok(fetch_result) = fetch_result {
                    self.handle_fetch_result(fetch_result)?;
                }
                self.schedule_requests()?;
                let mut engine = self.apply_operations().await?;
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
            // Take a queued target update before completing at the old target, unless the
            // caller already asked to finish. Updates that do not advance the target are
            // discarded.
            if !self.finish_requested {
                while let Some(update_rx) = self.update_rx.as_mut() {
                    match update_rx.try_recv() {
                        Ok(new_target) => {
                            if new_target.advances(&self.target) {
                                return self.handle_event(Event::TargetUpdate(new_target)).await;
                            }
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            self.update_rx = None;
                        }
                    }
                }
            }

            self.report_reached_target().await;

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
    use crate::merkle::mmr::{Family as MmrFamily, Proof};
    use commonware_cryptography::{Sha256, sha256};
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{NZU64, non_empty_range};
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
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
            Ok(Self { size })
        }

        async fn resize(mut self, start: Location<MmrFamily>) -> Result<Self, Self::Error> {
            self.size = *start;
            Ok(self)
        }

        async fn sync(self) -> Result<Self, Self::Error> {
            Ok(self)
        }

        fn size(&self) -> u64 {
            self.size
        }

        async fn append(mut self, ops: &[Self::Op]) -> Result<Self, Self::Error> {
            self.size += ops.len() as u64;
            Ok(self)
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

        async fn serve(
            &self,
            _request: Request<MmrFamily>,
        ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, FeedbackTx), Self::Error>
        {
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
            max_outstanding_requests: 1,
            fetch_batch_size: NZU64!(1),
            apply_batch_size: NZU64!(1),
            db_config: TestConfig {
                journal_size,
                pinned_node_probes,
            },
            update_rx: None,
            finish_rx: None,
            reached_target_tx: None,
            max_retained_roots: 0,
        }
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
            config.max_outstanding_requests = 2;
            config.fetch_batch_size = NZU64!(5);

            let engine = Engine::new(config).await.unwrap();
            let requests = &engine.outstanding_requests;

            assert_eq!(requests.len(), 2);
            assert!(requests.contains(&Location::new(5)));
            assert!(requests.contains(&Location::new(6)));
        });
    }

    #[test]
    fn step_takes_queued_update_before_completing() {
        deterministic::Runner::default().start(|context| async move {
            let (update_tx, update_rx) = mpsc::channel(2);
            let mut config = test_engine_config(context, 10, Arc::new(AtomicUsize::new(0)));
            config.update_rx = Some(update_rx);
            // Queue a stale update and an advancing one. The stale one is discarded and
            // the advancing one retargets the engine instead of completing.
            let stale = Target {
                root: sha256::Digest::from([2u8; 32]),
                range: non_empty_range!(Location::new(5), Location::new(10)),
            };
            let advancing = Target {
                root: sha256::Digest::from([3u8; 32]),
                range: non_empty_range!(Location::new(5), Location::new(12)),
            };
            update_tx.send(stale).await.unwrap();
            update_tx.send(advancing.clone()).await.unwrap();

            let engine = Engine::new(config).await.unwrap();
            let NextStep::Continue(engine) = engine.step().await.unwrap() else {
                panic!("engine should retarget instead of completing");
            };
            assert_eq!(engine.target, advancing);
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

    /// A no-op fetch result for testing request tracking.
    fn dummy_result(id: RequestId) -> IndexedFetchResult<MmrFamily, i32, sha256::Digest, ()> {
        IndexedFetchResult {
            id,
            result: Ok((
                Response::Operations {
                    proof: Proof {
                        leaves: Location::new(0),
                        inactive_peaks: 0,
                        digests: vec![],
                    },
                    operations: vec![],
                },
                None,
            )),
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

    #[test]
    fn test_remove_before_aborts_future() {
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
            requests.remove_before(Location::new(10));
            assert!(matches!(requests.next_completed().await, Err(Aborted)));
        });
    }
}
