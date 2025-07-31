//! Core sync engine components that are shared across sync clients.

use crate::mmr::verification::Proof;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_utils::NZU64;
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    stream::FuturesUnordered,
    StreamExt,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    future::Future,
    num::NonZeroU64,
    pin::Pin,
};
use thiserror::Error;

/// Trait for journals that support sync operations
pub trait Journal {
    type Op;
    type Error: std::error::Error + Send + 'static;

    /// Get the current size (number of operations) in the journal
    fn size(&self) -> impl Future<Output = Result<u64, Self::Error>>;

    /// Append an operation to the journal
    fn append(&mut self, op: Self::Op) -> impl Future<Output = Result<(), Self::Error>>;

    /// Resize the journal due to a target update.
    ///
    /// If the last operation is before `lower_bound`, close and reinitialize.
    /// If the last operation is at/after `lower_bound`, prune to `lower_bound`.
    /// If the last operation is at/after `upper_bound`, rewind to `upper_bound`.
    fn resize(
        &mut self,
        lower_bound: u64,
        upper_bound: u64,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

/// Trait for verifying proofs of operation batches
pub trait SyncVerifier<Op, D: Digest> {
    type Error: std::error::Error + Send + 'static;

    /// Verify that a proof is valid for the given operations and target root
    fn verify_proof(
        &mut self,
        proof: &Proof<D>,
        start_loc: u64,
        operations: &[Op],
        target_root: &D,
    ) -> bool;

    /// Extract pinned nodes from a proof if needed for future verifications
    fn extract_pinned_nodes(
        &mut self,
        proof: &Proof<D>,
        start_loc: u64,
        operations_len: u64,
    ) -> Result<Option<Vec<D>>, Self::Error>;
}

/// Trait for building final databases from completed sync journals
pub trait SyncDatabase: Sized {
    // Core associated types - determined by database implementation
    type Op;
    type Journal: Journal<Op = Self::Op>;
    type Verifier: SyncVerifier<Self::Op, Self::Digest>;
    type Error: std::error::Error + Send + 'static;
    type Config;
    type Digest: Digest;
    type Context: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
        + Clone;

    /// Create a journal for syncing with the given bounds
    fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> impl Future<Output = Result<Self::Journal, Self::Error>>;

    /// Create a verifier for proof validation  
    fn create_verifier() -> Self::Verifier;

    /// Build a database from a completed sync journal and configuration
    fn from_sync_result(
        config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        target: SyncTarget<Self::Digest>,
    ) -> impl Future<Output = Result<Self, Self::Error>>;

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;
}

/// Result of executing one sync step
#[derive(Debug)]
pub enum StepResult<C, D> {
    /// Sync should continue with the updated client
    Continue(C),
    /// Sync is complete with the final database
    Complete(D),
}

/// Result of sync completion with journal and pinned nodes
pub struct SyncCompletionResult<J: Journal, D: Digest> {
    pub journal: J,
    pub pinned_nodes: Option<Vec<D>>,
    pub target: SyncTarget<D>,
}

/// Events that can occur during synchronization
#[derive(Debug)]
pub enum SyncEvent<Op, D: Digest, E> {
    /// A target update was received
    TargetUpdate(SyncTarget<D>),
    /// A batch of operations was received
    BatchReceived(IndexedFetchResult<Op, D, E>),
    /// The target update channel was closed
    UpdateChannelClosed,
}

/// Target state to sync to
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncTarget<D: Digest> {
    /// The root digest we're syncing to
    pub root: D,
    /// Lower bound of operations to sync (inclusive)
    pub lower_bound_ops: u64,
    /// Upper bound of operations to sync (inclusive)
    pub upper_bound_ops: u64,
}

impl<D: Digest> Write for SyncTarget<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.lower_bound_ops.write(buf);
        self.upper_bound_ops.write(buf);
    }
}

impl<D: Digest> EncodeSize for SyncTarget<D> {
    fn encode_size(&self) -> usize {
        self.root.encode_size()
            + self.lower_bound_ops.encode_size()
            + self.upper_bound_ops.encode_size()
    }
}

impl<D: Digest> Read for SyncTarget<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let root = D::read(buf)?;
        let lower_bound_ops = u64::read(buf)?;
        let upper_bound_ops = u64::read(buf)?;
        Ok(Self {
            root,
            lower_bound_ops,
            upper_bound_ops,
        })
    }
}

/// Result from a fetch operation with its starting location
#[derive(Debug)]
pub struct IndexedFetchResult<Op, D: Digest, E> {
    /// The location of the first operation in the batch
    pub start_loc: u64,
    /// The result of the fetch operation
    pub result: Result<FetchResult<Op, D>, E>,
}

/// Generic fetch result that works with any operation type
pub struct FetchResult<Op, D: Digest> {
    /// The proof for the operations
    pub proof: Proof<D>,
    /// The operations that were fetched
    pub operations: Vec<Op>,
    /// Channel to report success/failure back to resolver
    pub success_tx: oneshot::Sender<bool>,
}

impl<Op: std::fmt::Debug, D: Digest> std::fmt::Debug for FetchResult<Op, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchResult")
            .field("proof", &self.proof)
            .field("operations", &self.operations)
            .field("success_tx", &"<callback>")
            .finish()
    }
}

/// Manages outstanding fetch requests for any operation type
pub struct OutstandingRequests<Op, D: Digest, E> {
    /// Futures that will resolve to batches of operations
    #[allow(clippy::type_complexity)]
    futures: FuturesUnordered<Pin<Box<dyn Future<Output = IndexedFetchResult<Op, D, E>> + Send>>>,
    /// Start locations of outstanding requests
    /// Each element corresponds to an element in `futures` and vice versa
    locations: BTreeSet<u64>,
}

impl<Op, D: Digest, E> OutstandingRequests<Op, D, E> {
    /// Create a new empty set of outstanding requests
    pub fn new() -> Self {
        Self {
            futures: FuturesUnordered::new(),
            locations: BTreeSet::new(),
        }
    }

    /// Add a new outstanding request
    pub fn add(
        &mut self,
        start_loc: u64,
        future: Pin<Box<dyn Future<Output = IndexedFetchResult<Op, D, E>> + Send>>,
    ) {
        self.locations.insert(start_loc);
        self.futures.push(future);
    }

    /// Remove a request from `self.locations` by its starting location.
    /// Doesn't remove from `self.futures` as it would be expensive.
    pub fn remove(&mut self, start_loc: u64) {
        self.locations.remove(&start_loc);
    }

    /// Get the set of outstanding request locations
    pub fn locations(&self) -> &BTreeSet<u64> {
        &self.locations
    }

    /// Clear all outstanding requests
    pub fn clear(&mut self) {
        self.locations.clear();
        self.futures = FuturesUnordered::new();
    }

    /// Get a mutable reference to the futures stream
    #[allow(clippy::type_complexity)]
    pub fn futures_mut(
        &mut self,
    ) -> &mut FuturesUnordered<Pin<Box<dyn Future<Output = IndexedFetchResult<Op, D, E>> + Send>>>
    {
        &mut self.futures
    }

    /// Check if there are any outstanding requests
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// Get the number of outstanding requests
    pub fn len(&self) -> usize {
        self.locations.len()
    }
}

impl<Op, D: Digest, E> Default for OutstandingRequests<Op, D, E> {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks fetched operations and outstanding operation requests.
pub struct SyncState<Op, D: Digest, E> {
    /// Batches of operations waiting to be applied, indexed by location of first operation
    pub fetched_operations: BTreeMap<u64, Vec<Op>>,
    /// Outstanding fetch requests
    pub outstanding_requests: OutstandingRequests<Op, D, E>,
}

// TODO danlaine: remove unused methods
impl<Op, D: Digest, E> SyncState<Op, D, E> {
    /// Create new sync state
    pub fn new() -> Self {
        Self {
            fetched_operations: BTreeMap::new(),
            outstanding_requests: OutstandingRequests::new(),
        }
    }

    /// Store a verified batch of operations to be applied later
    pub fn store_operations(&mut self, start_loc: u64, operations: Vec<Op>) {
        self.fetched_operations.insert(start_loc, operations);
    }

    /// Get operation counts for gap detection
    pub fn operation_counts(&self) -> BTreeMap<u64, u64> {
        self.fetched_operations
            .iter()
            .map(|(&start_loc, operations)| (start_loc, operations.len() as u64))
            .collect()
    }

    /// Remove stale batches whose last operation is before the given location
    pub fn remove_stale_batches(&mut self, min_loc: u64) {
        self.fetched_operations.retain(|&start_loc, operations| {
            let end_loc = start_loc + operations.len() as u64 - 1;
            end_loc >= min_loc
        });
    }

    /// Find and remove the batch containing the given location
    pub fn remove_batch_containing(&mut self, loc: u64) -> Option<(u64, Vec<Op>)> {
        let range_start_loc =
            self.fetched_operations
                .iter()
                .find_map(|(range_start, range_ops)| {
                    let range_end = range_start + range_ops.len() as u64 - 1;
                    if *range_start <= loc && loc <= range_end {
                        Some(*range_start)
                    } else {
                        None
                    }
                })?;

        let operations = self.fetched_operations.remove(&range_start_loc)?;
        Some((range_start_loc, operations))
    }

    /// Clear all state
    pub fn clear(&mut self) {
        self.fetched_operations.clear();
        self.outstanding_requests.clear();
    }
}

impl<Op, D: Digest, E> Default for SyncState<Op, D, E> {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during target update validation
#[derive(Debug, Error, Clone)]
pub enum TargetUpdateError {
    /// Target bounds are invalid (lower > upper)
    #[error("invalid target bounds: lower_bound {lower_bound} > upper_bound {upper_bound}")]
    InvalidBounds { lower_bound: u64, upper_bound: u64 },
    /// Target moved backward (bounds decreased)
    #[error("sync target moved backward: old bounds [{old_lower}, {old_upper}], new bounds [{new_lower}, {new_upper}]")]
    MovedBackward {
        old_lower: u64,
        old_upper: u64,
        new_lower: u64,
        new_upper: u64,
    },
    /// Target root is unchanged
    #[error("sync target root unchanged")]
    RootUnchanged,
}

/// Validate a target update against the current target
pub fn validate_target_update<D: Digest>(
    old_target: &SyncTarget<D>,
    new_target: &SyncTarget<D>,
) -> Result<(), TargetUpdateError> {
    if new_target.lower_bound_ops > new_target.upper_bound_ops {
        return Err(TargetUpdateError::InvalidBounds {
            lower_bound: new_target.lower_bound_ops,
            upper_bound: new_target.upper_bound_ops,
        });
    }

    if new_target.lower_bound_ops < old_target.lower_bound_ops
        || new_target.upper_bound_ops < old_target.upper_bound_ops
    {
        return Err(TargetUpdateError::MovedBackward {
            old_lower: old_target.lower_bound_ops,
            old_upper: old_target.upper_bound_ops,
            new_lower: new_target.lower_bound_ops,
            new_upper: new_target.upper_bound_ops,
        });
    }

    if new_target.root == old_target.root {
        return Err(TargetUpdateError::RootUnchanged);
    }

    Ok(())
}

/// Type alias for sync target update receivers
pub type SyncTargetUpdateReceiver<D> = mpsc::Receiver<SyncTarget<D>>;

/// Wait for the next synchronization event from either target updates or fetch results.
pub async fn wait_for_event<Op, D, E>(
    update_receiver: &mut Option<SyncTargetUpdateReceiver<D>>,
    outstanding_requests: &mut OutstandingRequests<Op, D, E>,
) -> Result<SyncEvent<Op, D, E>, crate::adb::sync::error::SyncError<E>>
where
    D: Digest,
    E: std::fmt::Debug + std::fmt::Display,
{
    let target_update_fut = match update_receiver {
        Some(update_rx) => Either::Left(update_rx.next()),
        None => Either::Right(futures::future::pending()),
    };

    select! {
        target = target_update_fut => {
            match target {
                Some(target) => Ok(SyncEvent::TargetUpdate(target)),
                None => Ok(SyncEvent::UpdateChannelClosed),
            }
        },
        result = outstanding_requests.futures_mut().next() => {
            let fetch_result = result.ok_or(crate::adb::sync::error::SyncError::<E>::SyncStalled)?;
            Ok(SyncEvent::BatchReceived(fetch_result))
        },
    }
}

/// A shared sync engine that manages the core synchronization state and operations.
///
/// This engine handles the common sync logic that can be reused across different
/// ADB implementations (Any, Immutable, Current).
pub struct SyncEngine<
    DB: SyncDatabase,
    R: crate::adb::sync::resolver::Resolver<Op = DB::Op, Digest = DB::Digest>,
> {
    /// Tracks outstanding fetch requests and their futures
    pub outstanding_requests: OutstandingRequests<DB::Op, DB::Digest, DB::Error>,

    /// Operations that have been fetched but not yet applied to the log
    pub fetched_operations: BTreeMap<u64, Vec<DB::Op>>,

    /// Pinned MMR nodes extracted from proofs, used for database construction
    pub pinned_nodes: Option<Vec<DB::Digest>>,

    /// The current sync target (root digest and operation bounds)
    pub target: SyncTarget<DB::Digest>,

    /// Maximum number of parallel outstanding requests
    pub max_outstanding_requests: usize,

    /// Maximum operations to fetch in a single batch
    pub fetch_batch_size: NonZeroU64,

    /// Journal that operations are applied to during sync
    pub journal: DB::Journal,

    /// Resolver for fetching operations and proofs from the sync source
    pub resolver: R,

    /// Verifier for validating proofs and extracting pinned nodes
    pub verifier: DB::Verifier,

    /// Configuration for building the final database
    pub config: DB::Config,

    /// Optional receiver for target updates during sync
    pub update_receiver: Option<SyncTargetUpdateReceiver<DB::Digest>>,
}

/// Configuration for creating a new SyncEngine
pub struct SyncEngineConfig<
    DB: SyncDatabase,
    R: crate::adb::sync::resolver::Resolver<Op = DB::Op, Digest = DB::Digest>,
> {
    /// Runtime context for creating database components
    pub context: DB::Context,
    /// Network resolver for fetching operations and proofs
    pub resolver: R,
    /// Sync target (root digest and operation bounds)
    pub target: SyncTarget<DB::Digest>,
    /// Maximum number of outstanding requests for operation batches
    pub max_outstanding_requests: usize,
    /// Maximum operations to fetch per batch
    pub fetch_batch_size: NonZeroU64,
    /// Database-specific configuration
    pub db_config: DB::Config,
    /// Channel for receiving sync target updates
    pub update_receiver: Option<SyncTargetUpdateReceiver<DB::Digest>>,
}

impl<DB, R> SyncEngine<DB, R>
where
    DB: SyncDatabase,
    DB::Error: From<<DB::Journal as Journal>::Error>, // TODO: review this
    DB::Error: From<crate::adb::any::sync::Error>,    // TODO: review this
    DB::Op: Clone + Send + 'static,
    DB::Digest: Clone,
    DB::Config: Clone,
    R: crate::adb::sync::resolver::Resolver<Op = DB::Op, Digest = DB::Digest>,
{
    /// Create a new sync engine with the given configuration
    pub async fn new(
        config: SyncEngineConfig<DB, R>,
    ) -> Result<Self, crate::adb::sync::error::SyncError<DB::Error>> {
        // Create journal and verifier using the database's factory methods
        let journal = DB::create_journal(
            config.context,
            &config.db_config,
            config.target.lower_bound_ops,
            config.target.upper_bound_ops,
        )
        .await?;

        let verifier = DB::create_verifier();

        Ok(Self {
            outstanding_requests: OutstandingRequests::new(),
            fetched_operations: BTreeMap::new(),
            pinned_nodes: None,
            target: config.target,
            max_outstanding_requests: config.max_outstanding_requests,
            fetch_batch_size: config.fetch_batch_size,
            journal,
            resolver: config.resolver,
            verifier,
            config: config.db_config,
            update_receiver: config.update_receiver,
        })
    }

    /// Schedule new fetch requests based on gap analysis and request limits.
    ///
    /// This method implements the core request scheduling logic that can be used
    /// across different ADB sync implementations.
    pub async fn schedule_requests(
        &mut self,
    ) -> Result<(), crate::adb::sync::error::SyncError<DB::Error>> {
        let target_size = self.target.upper_bound_ops + 1;

        // Special case: If we don't have pinned nodes, we need to extract them from a proof
        // for the lower sync bound.
        if self.pinned_nodes.is_none() {
            let start_loc = self.target.lower_bound_ops;
            let resolver = self.resolver.clone();
            self.outstanding_requests.add(
                start_loc,
                Box::pin(async move {
                    let result = resolver
                        .get_operations(target_size, start_loc, NZU64!(1))
                        .await
                        .map_err(DB::Error::from);
                    IndexedFetchResult { start_loc, result }
                }),
            );
        }

        // Calculate the maximum number of requests to make
        let num_requests = self
            .max_outstanding_requests
            .saturating_sub(self.outstanding_requests.len());

        // TODO can we do this more cleanly?
        let log_size = self.journal.size().await.map_err(|e| {
            crate::adb::sync::error::SyncError::<DB::Error>::from(DB::Error::from(e))
        })?;

        for _ in 0..num_requests {
            // Convert fetched operations to operation counts for shared gap detection
            let operation_counts: BTreeMap<u64, u64> = self
                .fetched_operations
                .iter()
                .map(|(&start_loc, operations)| (start_loc, operations.len() as u64))
                .collect();

            // Find the next gap in the sync range that needs to be fetched.
            let Some((start_loc, end_loc)) = crate::adb::sync::gaps::find_next_gap(
                log_size,
                self.target.upper_bound_ops,
                &operation_counts,
                self.outstanding_requests.locations(),
                self.fetch_batch_size.get(),
            ) else {
                break; // No more gaps to fill
            };

            // Calculate batch size for this gap
            let gap_size = NZU64!(end_loc - start_loc + 1);
            let batch_size = self.fetch_batch_size.min(gap_size);

            // Schedule the request
            let resolver = self.resolver.clone();
            self.outstanding_requests.add(
                start_loc,
                Box::pin(async move {
                    let result = resolver
                        .get_operations(target_size, start_loc, batch_size)
                        .await
                        .map_err(DB::Error::from);
                    IndexedFetchResult { start_loc, result }
                }),
            );
        }

        Ok(())
    }

    /// Clear all sync state for a target update
    pub async fn reset_for_target_update(
        &mut self,
        new_target: SyncTarget<DB::Digest>,
    ) -> Result<(), crate::adb::sync::error::SyncError<DB::Error>> {
        self.journal
            .resize(new_target.lower_bound_ops, new_target.upper_bound_ops)
            .await
            .map_err(|e| {
                crate::adb::sync::error::SyncError::<DB::Error>::from(DB::Error::from(e))
            })?;
        self.target = new_target;
        self.fetched_operations.clear();
        self.outstanding_requests.clear();
        self.pinned_nodes = None;
        Ok(())
    }

    /// Store a batch of fetched operations
    pub fn store_operations(&mut self, start_loc: u64, operations: Vec<DB::Op>) {
        self.fetched_operations.insert(start_loc, operations);
    }

    /// Check if we have pinned nodes
    pub fn has_pinned_nodes(&self) -> bool {
        self.pinned_nodes.is_some()
    }

    /// Set pinned nodes from a proof
    pub fn set_pinned_nodes(&mut self, nodes: Vec<DB::Digest>) {
        self.pinned_nodes = Some(nodes);
    }

    /// Apply fetched operations to the journal if we have them.
    ///
    /// This method finds operations that are contiguous with the current journal tip
    /// and applies them in order. It removes stale batches and handles partial
    /// application of batches when needed.
    pub async fn apply_operations(
        &mut self,
    ) -> Result<(), crate::adb::sync::error::SyncError<DB::Error>> {
        let mut next_loc = self.journal.size().await.map_err(|e| {
            crate::adb::sync::error::SyncError::<DB::Error>::from(DB::Error::from(e))
        })?;

        // Remove any batches of operations with stale data.
        // That is, those whose last operation is before `next_loc`.
        self.fetched_operations.retain(|&start_loc, operations| {
            let end_loc = start_loc + operations.len() as u64 - 1;
            end_loc >= next_loc
        });

        loop {
            // See if we have the next operation to apply (i.e. at the journal tip).
            // Find the index of the range that contains the next location.
            let range_start_loc =
                self.fetched_operations
                    .iter()
                    .find_map(|(range_start, range_ops)| {
                        let range_end = range_start + range_ops.len() as u64 - 1;
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
            // Skip operations that are before the next location.
            let skip_count = (next_loc - range_start_loc) as usize;
            let operations_count = operations.len() - skip_count;
            let remaining_operations = operations.into_iter().skip(skip_count);
            next_loc += operations_count as u64;
            self.apply_operations_batch(remaining_operations).await?;
        }

        Ok(())
    }

    /// Apply a batch of operations to the journal
    async fn apply_operations_batch<I>(
        &mut self,
        operations: I,
    ) -> Result<(), crate::adb::sync::error::SyncError<DB::Error>>
    where
        I: IntoIterator<Item = DB::Op>,
    {
        for op in operations {
            self.journal.append(op).await.map_err(|e| {
                crate::adb::sync::error::SyncError::<DB::Error>::from(DB::Error::from(e))
            })?;
            // No need to sync here -- the journal will periodically sync its storage
            // and we will also sync when we're done applying all operations.
        }
        Ok(())
    }

    /// Check if sync is complete based on the current journal size and target
    pub async fn is_complete(&self) -> Result<bool, crate::adb::sync::error::SyncError<DB::Error>> {
        let journal_size = self.journal.size().await.map_err(|e| {
            crate::adb::sync::error::SyncError::<DB::Error>::from(DB::Error::from(e))
        })?;

        // Calculate the target journal size (upper bound is inclusive)
        let target_journal_size = self.target.upper_bound_ops + 1;

        // Check if we've completed sync
        if journal_size >= target_journal_size {
            if journal_size > target_journal_size {
                // This shouldn't happen in normal operation - indicates a bug
                return Err(crate::adb::sync::error::SyncError::<DB::Error>::InvalidState);
            }
            return Ok(true);
        }

        Ok(false)
    }

    /// Handle the result of a fetch operation.
    ///
    /// This method processes incoming fetch results by:
    /// 1. Removing the request from outstanding requests
    /// 2. Validating batch size
    /// 3. Verifying proofs using the configured verifier
    /// 4. Extracting pinned nodes if needed
    /// 5. Storing valid operations for later application
    pub fn handle_fetch_result(
        &mut self,
        fetch_result: IndexedFetchResult<DB::Op, DB::Digest, DB::Error>,
    ) -> Result<(), crate::adb::sync::error::SyncError<DB::Error>> {
        // Mark request as complete
        self.outstanding_requests.remove(fetch_result.start_loc);

        let start_loc = fetch_result.start_loc;
        match fetch_result.result {
            Ok(FetchResult {
                proof,
                operations,
                success_tx,
            }) => {
                // Validate batch size
                let operations_len = operations.len() as u64;
                if operations_len == 0 || operations_len > self.fetch_batch_size.get() {
                    // Invalid batch size - notify resolver of failure
                    let _ = success_tx.send(false);
                } else {
                    // Verify the proof
                    let proof_valid = self.verifier.verify_proof(
                        &proof,
                        start_loc,
                        &operations,
                        &self.target.root,
                    );

                    // Report success or failure to the resolver
                    let _ = success_tx.send(proof_valid);

                    if proof_valid {
                        // Extract pinned nodes if we don't have them and this is the first batch
                        if self.pinned_nodes.is_none() && start_loc == self.target.lower_bound_ops {
                            if let Ok(Some(nodes)) = self.verifier.extract_pinned_nodes(
                                &proof,
                                start_loc,
                                operations_len,
                            ) {
                                self.pinned_nodes = Some(nodes);
                            }
                        }

                        // Store operations for later application
                        self.store_operations(start_loc, operations);
                    }
                }
            }
            Err(e) => {
                // Resolver error - propagate it up to fail the sync.
                // TODO: How should we handle a resolver error?
                return Err(crate::adb::sync::error::SyncError::<DB::Error>::from(e));
            }
        }
        Ok(())
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
    pub async fn step(
        mut self,
    ) -> Result<StepResult<Self, DB>, crate::adb::sync::error::SyncError<DB::Error>> {
        // Check if sync is complete
        if self.is_complete().await? {
            // Build the database from the completed sync
            let database = DB::from_sync_result(
                self.config.clone(),
                self.journal,
                self.pinned_nodes,
                self.target.clone(),
            )
            .await?;

            // Verify the final root digest matches the final target
            let got_root = database.root();
            let expected_root = self.target.root;
            if got_root != expected_root {
                return Err(
                    crate::adb::sync::error::SyncError::<DB::Error>::RootMismatch {
                        expected: Box::new(expected_root),
                        actual: Box::new(got_root),
                    },
                );
            }

            return Ok(StepResult::Complete(database));
        }

        // Wait for the next synchronization event
        match wait_for_event(&mut self.update_receiver, &mut self.outstanding_requests)
            .await
            .map_err(|sync_err| match sync_err {
                crate::adb::sync::error::SyncError::SyncStalled => {
                    crate::adb::sync::error::SyncError::<DB::Error>::SyncStalled
                }
                crate::adb::sync::error::SyncError::Database(e) => {
                    crate::adb::sync::error::SyncError::<DB::Error>::from(e)
                }
                crate::adb::sync::error::SyncError::Resolver(e) => {
                    crate::adb::sync::error::SyncError::<DB::Error>::resolver(e)
                }
                _ => crate::adb::sync::error::SyncError::<DB::Error>::InvalidState,
            })? {
            SyncEvent::TargetUpdate(new_target) => {
                // Validate and handle the target update
                crate::adb::sync::engine::validate_target_update(&self.target, &new_target)
                    .map_err(|e| match e {
                        TargetUpdateError::MovedBackward { .. } => {
                            crate::adb::sync::error::SyncError::<DB::Error>::SyncTargetMovedBackward {
                                old: Box::new(self.target.root),
                                new: Box::new(new_target.root),
                            }
                        }
                        TargetUpdateError::InvalidBounds {
                            lower_bound,
                            upper_bound,
                        } => crate::adb::sync::error::SyncError::<DB::Error>::InvalidTarget {
                            lower_bound_pos: lower_bound,
                            upper_bound_pos: upper_bound,
                        },
                        TargetUpdateError::RootUnchanged => {
                            crate::adb::sync::error::SyncError::<DB::Error>::SyncTargetRootUnchanged
                        }
                    })?;

                self.reset_for_target_update(new_target).await?;

                // Schedule new requests for the updated target
                self.schedule_requests().await?;
            }
            SyncEvent::UpdateChannelClosed => {
                self.update_receiver = None;
            }
            SyncEvent::BatchReceived(fetch_result) => {
                // Process the fetch result
                self.handle_fetch_result(fetch_result)?;

                // Request operations in the sync range
                self.schedule_requests().await?;

                // Apply operations that are now contiguous with the current journal
                self.apply_operations().await?;
            }
        }

        Ok(StepResult::Continue(self))
    }

    /// Run sync to completion, returning the final database when done.
    ///
    /// This method repeatedly calls `step()` until sync is complete. The `step()` method
    /// handles building the final database and verifying the root digest.
    pub async fn sync(mut self) -> Result<DB, crate::adb::sync::error::SyncError<DB::Error>> {
        // Run sync loop until completion
        loop {
            match self.step().await? {
                StepResult::Continue(new_engine) => self = new_engine,
                StepResult::Complete(database) => return Ok(database),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256;
    use std::io::Cursor;
    use test_case::test_case;

    #[test]
    fn test_outstanding_requests() {
        let mut requests: OutstandingRequests<i32, sha256::Digest, ()> = OutstandingRequests::new();
        assert!(requests.is_empty());
        assert_eq!(requests.len(), 0);

        // Test adding requests
        let fut = Box::pin(async {
            IndexedFetchResult {
                start_loc: 0,
                result: Ok(FetchResult {
                    proof: Proof {
                        size: 0,
                        digests: vec![],
                    },
                    operations: vec![],
                    success_tx: oneshot::channel().0,
                }),
            }
        });
        requests.add(10, fut);
        assert!(!requests.is_empty());
        assert_eq!(requests.len(), 1);
        assert!(requests.locations().contains(&10));

        // Test removing requests
        requests.remove(10);
        assert!(requests.is_empty());
        assert!(!requests.locations().contains(&10));
    }

    #[test]
    fn test_sync_state() {
        let mut state: SyncState<i32, sha256::Digest, ()> = SyncState::new();

        // Test storing operations
        state.store_operations(0, vec![1, 2, 3]);
        state.store_operations(5, vec![4, 5]);

        let counts = state.operation_counts();
        assert_eq!(counts.get(&0), Some(&3));
        assert_eq!(counts.get(&5), Some(&2));

        // Test removing stale batches
        state.remove_stale_batches(6);
        assert!(!state.fetched_operations.contains_key(&0));
        assert!(state.fetched_operations.contains_key(&5));

        // Test finding batch containing location
        let batch = state.remove_batch_containing(5);
        assert_eq!(batch, Some((5, vec![4, 5])));
        assert!(state.fetched_operations.is_empty());
    }

    #[test_case(
        SyncTarget { root: sha256::Digest::from([0; 32]), lower_bound_ops: 0, upper_bound_ops: 100 },
        SyncTarget { root: sha256::Digest::from([1; 32]), lower_bound_ops: 50, upper_bound_ops: 200 },
        true;
        "valid update"
    )]
    #[test_case(
        SyncTarget { root: sha256::Digest::from([0; 32]), lower_bound_ops: 0, upper_bound_ops: 100 },
        SyncTarget { root: sha256::Digest::from([1; 32]), lower_bound_ops: 200, upper_bound_ops: 100 },
        false;
        "invalid bounds - lower > upper"
    )]
    #[test_case(
        SyncTarget { root: sha256::Digest::from([0; 32]), lower_bound_ops: 0, upper_bound_ops: 100 },
        SyncTarget { root: sha256::Digest::from([1; 32]), lower_bound_ops: 0, upper_bound_ops: 50 },
        false;
        "moves backward"
    )]
    #[test_case(
        SyncTarget { root: sha256::Digest::from([0; 32]), lower_bound_ops: 0, upper_bound_ops: 100 },
        SyncTarget { root: sha256::Digest::from([0; 32]), lower_bound_ops: 50, upper_bound_ops: 200 },
        false;
        "same root"
    )]
    fn test_validate_target_update(
        old_target: SyncTarget<sha256::Digest>,
        new_target: SyncTarget<sha256::Digest>,
        should_succeed: bool,
    ) {
        let result = validate_target_update(&old_target, &new_target);
        if should_succeed {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_sync_target_serialization() {
        let target = SyncTarget {
            root: sha256::Digest::from([42; 32]),
            lower_bound_ops: 100,
            upper_bound_ops: 500,
        };

        // Serialize
        let mut buffer = Vec::new();
        target.write(&mut buffer);

        // Verify encoded size matches actual size
        assert_eq!(buffer.len(), target.encode_size());

        // Deserialize
        let mut cursor = Cursor::new(buffer);
        let deserialized = SyncTarget::read(&mut cursor).unwrap();

        // Verify
        assert_eq!(target, deserialized);
        assert_eq!(target.root, deserialized.root);
        assert_eq!(target.lower_bound_ops, deserialized.lower_bound_ops);
        assert_eq!(target.upper_bound_ops, deserialized.upper_bound_ops);
    }
}
