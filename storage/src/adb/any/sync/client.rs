use crate::{
    adb::{self, any::SyncConfig, operation::Operation},
    journal::fixed::{Config as JConfig, Journal},
    mmr::{self, iterator::leaf_num_to_pos},
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_macros::select;
use commonware_runtime::{
    telemetry::metrics::histogram::{Buckets, Timed},
    Clock, Metrics as MetricsTrait, Storage,
};
use commonware_utils::Array;
use futures::{future, stream::FuturesUnordered, StreamExt};
use prometheus_client::metrics::{counter::Counter, histogram::Histogram};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    marker::PhantomData,
    num::NonZeroU64,
    pin::Pin,
    sync::Arc,
};
use tracing::{debug, info, warn};

use super::{
    resolver::{GetOperationsResult, Resolver},
    Error, SyncTarget, SyncTargetUpdateReceiver,
};

/// Result of executing one sync step
///
/// Generic parameters:
/// - `C`: The client type (for continuation)
/// - `D`: The database type (for completion)
pub enum SyncStepResult<C, D> {
    /// Sync should continue with the updated client
    Continue(C),
    /// Sync is complete with the final database
    Complete(D),
}

/// A stateful sync client that encapsulates all sync state and configuration
///
/// This client uses a functional ownership pattern: each step consumes the client
/// and returns either a new client (to continue) or the final database (when complete).
pub struct SyncClient<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
    config: Config<E, K, V, H, T, R>,
    state: SyncState<E, K, V, H>,
    log: Journal<E, Operation<K, V>>,
    metrics: Metrics<E>,
}

impl<E, K, V, H, T, R> SyncClient<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
    /// Create a new sync client and perform initialization
    ///
    /// This performs the same initialization as the old `initialize_sync` function,
    /// but encapsulates all state within the client.
    pub async fn new(config: Config<E, K, V, H, T, R>) -> Result<Self, Error> {
        // Validate configuration
        config.validate()?;

        // Initialize the operations journal
        let log = Journal::<E, Operation<K, V>>::init_sync(
            config.context.clone().with_label("log"),
            JConfig {
                partition: config.db_config.log_journal_partition.clone(),
                items_per_blob: config.db_config.log_items_per_blob,
                write_buffer: config.db_config.log_write_buffer,
                buffer_pool: config.db_config.buffer_pool.clone(),
            },
            config.target.lower_bound_ops,
            config.target.upper_bound_ops,
        )
        .await
        .map_err(adb::Error::JournalError)
        .map_err(Error::Adb)?;

        // Get current log size to initialize sync state
        let log_size = log
            .size()
            .await
            .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;

        // Assert invariant from Journal::init_sync
        assert!(log_size <= config.target.upper_bound_ops + 1);

        // Initialize sync state
        let state = SyncState::new(log_size);

        // Initialize metrics
        let metrics = Metrics::new(config.context.clone());

        // Create client
        let mut client = Self {
            config,
            state,
            log,
            metrics,
        };

        // Initialize parallel fetching
        client.fill_fetch_queue().await?;

        // Note: We don't check for immediate completion here - let the first step() call handle it.
        // This keeps the initialization logic simple and consistent.

        Ok(client)
    }

    /// Execute one step of the sync process
    ///
    /// This performs one iteration of the main sync loop:
    /// 1. Check if sync is complete  
    /// 2. Wait for and handle the next event (target update or batch completion)
    /// 3. Apply any operations that are now contiguous
    ///
    /// Returns either a new client to continue with, or the final database if complete.
    pub async fn step(
        mut self,
    ) -> Result<SyncStepResult<Self, adb::any::Any<E, K, V, H, T>>, Error> {
        // Check if sync is complete
        if self
            .state
            .is_sync_complete(&self.log, self.config.target.upper_bound_ops)
            .await?
        {
            let database = build_database(
                self.config,
                self.log,
                self.state.pinned_nodes.clone(),
                &self.metrics,
            )
            .await?;
            return Ok(SyncStepResult::Complete(database));
        }

        // Wait for a target update or a batch completion
        select! {
            target_update = async {
                if let Some(ref mut receiver) = self.config.update_receiver {
                    receiver.next().await
                } else {
                    future::pending().await // Never resolves when no receiver
                }
            } => {
                if let Some(new_target) = target_update {
                    self = self.handle_target_update(new_target).await?;
                }
            },
            batch_result = self.state.pending_fetches.next() => {
                if let Some((start_pos, result)) = batch_result {
                    self.handle_batch_completion(start_pos, result).await?;
                }
            },
        }

        // Apply operations that are now contiguous with the current log size
        self.apply_contiguous_batches().await?;

        Ok(SyncStepResult::Continue(self))
    }

    /// Queue batches of operations to be fetched from the resolver
    async fn fill_fetch_queue(&mut self) -> Result<(), Error> {
        let target_size = self.config.target.upper_bound_ops + 1;

        // Special case: If we don't have pinned nodes, we need to extract them
        // from the first operation we actually need to fetch, not always from lower_bound_ops
        if !self.state.has_pinned_nodes() {
            // Find the first gap we need to fetch - this is where we'll extract pinned nodes
            let search_start = std::cmp::max(
                self.config.target.lower_bound_ops,
                self.state.next_apply_pos,
            );
            if let Some((gap_start, gap_end)) = find_next_gap_to_fetch::<K, V>(
                search_start,
                self.config.target.upper_bound_ops,
                &self.state.verified_batches,
                &self.state.outstanding_requests,
                self.config.fetch_batch_size.get(),
            ) {
                // Request from the first gap to extract pinned nodes
                let gap_size = gap_end - gap_start + 1;
                let batch_size = std::cmp::min(self.config.fetch_batch_size.get(), gap_size);
                if let Some(batch_size) = NonZeroU64::new(batch_size) {
                    self.state.add_outstanding_request(gap_start);

                    let resolver = self.config.resolver.clone();
                    let start_pos = gap_start;

                    self.state.pending_fetches.push(Box::pin(async move {
                        let result = resolver
                            .get_operations(target_size, start_pos, batch_size)
                            .await;
                        (start_pos, result)
                    }));
                }
            }
            return Ok(()); // Don't make additional requests until we have pinned nodes
        }

        // Normal case: Fill the fetch queue with multiple concurrent requests
        // Use gap detection to find what actually needs to be fetched
        let requests_to_make = self
            .config
            .max_outstanding_requests
            .saturating_sub(self.state.outstanding_requests.len());

        for _ in 0..requests_to_make {
            // Find the next gap that needs to be fetched
            // For existing databases, start from next_apply_pos instead of lower_bound_ops
            let search_start = std::cmp::max(
                self.config.target.lower_bound_ops,
                self.state.next_apply_pos,
            );
            let Some((gap_start, gap_end)) = find_next_gap_to_fetch::<K, V>(
                search_start,
                self.config.target.upper_bound_ops,
                &self.state.verified_batches,
                &self.state.outstanding_requests,
                self.config.fetch_batch_size.get(),
            ) else {
                break; // No more gaps to fill
            };

            // Calculate how much of this gap to request in this batch
            let gap_size = gap_end - gap_start + 1; // gap_end is inclusive
            let batch_size = std::cmp::min(self.config.fetch_batch_size.get(), gap_size);
            let batch_size =
                NonZeroU64::new(batch_size).expect("batch_size should be > 0 since gap exists");

            self.state.add_outstanding_request(gap_start);

            let resolver = self.config.resolver.clone();
            let start_pos = gap_start;

            self.state.pending_fetches.push(Box::pin(async move {
                let result = resolver
                    .get_operations(target_size, start_pos, batch_size)
                    .await;
                (start_pos, result)
            }));
        }

        Ok(())
    }

    /// Handle completion of a batch fetch
    async fn handle_batch_completion(
        &mut self,
        start_pos: u64,
        result: Result<GetOperationsResult<H::Digest, K, V>, Error>,
    ) -> Result<(), Error> {
        // Remove from outstanding requests
        self.state.remove_outstanding_request(start_pos);

        match result {
            Ok(GetOperationsResult {
                proof,
                operations,
                success_tx,
            }) => {
                let operations_len = operations.len() as u64;

                // Validate batch size
                if operations_len > self.config.fetch_batch_size.get() || operations_len == 0 {
                    debug!(
                        operations_len,
                        batch_size = self.config.fetch_batch_size.get(),
                        start_pos,
                        "received invalid batch size from resolver"
                    );
                    self.metrics.invalid_batches_received.inc();
                    let _ = success_tx.send(false);

                    self.fill_fetch_queue().await?;
                    return Ok(());
                }

                // Verify the proof
                let proof_valid = {
                    let _timer = self.metrics.proof_verification_duration.timer();
                    adb::any::Any::<E, K, V, H, T>::verify_proof(
                        &mut self.config.hasher,
                        &proof,
                        start_pos,
                        &operations,
                        &self.config.target.root,
                    )
                };
                let _ = success_tx.send(proof_valid);

                if !proof_valid {
                    debug!(start_pos, "proof verification failed, retrying");
                    self.metrics.invalid_batches_received.inc();

                    self.fill_fetch_queue().await?;
                    return Ok(());
                }

                // Install pinned nodes on first successful batch (can be from any position)
                if !self.state.has_pinned_nodes() {
                    let start_pos_mmr = leaf_num_to_pos(start_pos);
                    let end_pos_mmr = leaf_num_to_pos(start_pos + operations_len - 1);
                    match proof.extract_pinned_nodes(start_pos_mmr, end_pos_mmr) {
                        Ok(nodes) => {
                            self.state.set_pinned_nodes(nodes);
                        }
                        Err(_) => {
                            warn!(start_pos, "failed to extract pinned nodes, retrying");
                            self.metrics.invalid_batches_received.inc();

                            self.fill_fetch_queue().await?;
                            return Ok(());
                        }
                    }
                }

                // Store verified batch
                self.state.store_batch(start_pos, operations);
                self.metrics.valid_batches_received.inc();
                self.metrics.operations_fetched.inc_by(operations_len);

                // Update highest_received_pos if this batch extends our contiguous coverage
                self.state.update_next_apply_pos(start_pos, operations_len);

                // Fill queue to maintain parallelism
                self.fill_fetch_queue().await?;
            }
            Err(e) => {
                warn!(start_pos, error = ?e, "batch fetch failed, retrying");
                self.fill_fetch_queue().await?;
            }
        }

        Ok(())
    }

    /// Apply contiguous verified batches to the log
    async fn apply_contiguous_batches(&mut self) -> Result<(), Error> {
        let log_size = self
            .log
            .size()
            .await
            .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;

        let mut operations_to_apply = Vec::new();
        let mut current_pos = log_size;

        // Collect contiguous operations starting from current log size
        while let Some(operations) = self.state.take_batch(current_pos) {
            let operations_len = operations.len() as u64;
            operations_to_apply.extend(operations);
            current_pos += operations_len;

            // Apply in batches to avoid memory issues
            if operations_to_apply.len() >= self.config.apply_batch_size {
                self.apply_operations_batch(operations_to_apply).await?;
                operations_to_apply = Vec::new();
            }
        }

        // Apply remaining operations
        if !operations_to_apply.is_empty() {
            self.apply_operations_batch(operations_to_apply).await?;
        }

        Ok(())
    }

    /// Apply a batch of operations to the log (helper method)
    async fn apply_operations_batch(
        &mut self,
        operations: Vec<Operation<K, V>>,
    ) -> Result<(), Error> {
        let _timer = self.metrics.apply_duration.timer();
        for op in operations.into_iter() {
            self.log
                .append(op)
                .await
                .map_err(adb::Error::JournalError)
                .map_err(Error::Adb)?;
            // No need to sync here -- the log will periodically sync its storage
            // and we will also sync when we're done.
        }
        Ok(())
    }

    /// Handle a target update by validating it and reinitializing state
    async fn handle_target_update(
        mut self,
        new_target: SyncTarget<H::Digest>,
    ) -> Result<Self, Error> {
        validate_target_update::<H>(&self.config.target, &new_target)?;

        info!(
            old_target = ?self.config.target,
            new_target = ?new_target,
            "applying target update"
        );

        // Update config target
        self.config.target = new_target;

        // Reinitialize log if needed
        self.log = reinitialize_log_for_target_update(
            self.log,
            self.config.context.clone(),
            &self.config.db_config,
            self.config.target.lower_bound_ops,
            self.config.target.upper_bound_ops,
        )
        .await?;

        // Reset sync state to the new log size
        let new_log_size = self
            .log
            .size()
            .await
            .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;
        self.state.reset(new_log_size);

        // Reinitialize parallel fetching
        self.fill_fetch_queue().await?;

        Ok(self)
    }
}

/// Configuration for the sync client
pub struct Config<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
    /// Context for the database.
    pub context: E,

    /// Channel for receiving target updates.
    pub update_receiver: Option<SyncTargetUpdateReceiver<H::Digest>>,

    /// Database configuration.
    pub db_config: crate::adb::any::Config<T>,

    /// Maximum operations to fetch per batch.
    pub fetch_batch_size: NonZeroU64,

    /// Synchronization target (root digest and operation bounds).
    pub target: SyncTarget<H::Digest>,

    /// Resolves requests for proofs and operations.
    pub resolver: R,

    /// Hasher for root digests.
    pub hasher: mmr::hasher::Standard<H>,

    /// The maximum number of operations to keep in memory
    /// before committing the database while applying operations.
    /// Higher value will cause more memory usage during sync.
    pub apply_batch_size: usize,

    /// Maximum number of outstanding requests for operation batches.
    /// Higher values increase parallelism but also memory usage.
    pub max_outstanding_requests: usize,
}

impl<E, K, V, H, T, R> Config<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
    /// Validate the configuration parameters
    pub fn validate(&self) -> Result<(), Error> {
        // Validate bounds (inclusive)
        if self.target.lower_bound_ops > self.target.upper_bound_ops {
            return Err(Error::InvalidTarget {
                lower_bound_pos: self.target.lower_bound_ops,
                upper_bound_pos: self.target.upper_bound_ops,
            });
        }
        Ok(())
    }
}

/// Prometheus metrics for the sync client.
pub struct Metrics<E: Clock> {
    /// Number of valid batches successfully received and processed.
    valid_batches_received: Counter<u64>,
    /// Number of invalid batches received that failed validation.
    invalid_batches_received: Counter<u64>,
    /// Total number of operations fetched during sync.
    operations_fetched: Counter<u64>,
    /// Total time spent fetching operations from resolver (seconds).
    fetch_duration: Timed<E>,
    /// Total time spent verifying proofs (seconds).
    proof_verification_duration: Timed<E>,
    /// Total time spent applying operations to the log (seconds).
    apply_duration: Timed<E>,
}

impl<E: Clock + MetricsTrait> Metrics<E> {
    /// Register metrics with the provided runtime metrics context and return the struct.
    pub fn new(context: E) -> Self {
        let fetch_histogram = Histogram::new(Buckets::NETWORK.into_iter());
        let proof_verification_histogram = Histogram::new(Buckets::CRYPTOGRAPHY.into_iter());
        let apply_histogram = Histogram::new(Buckets::LOCAL.into_iter());

        let metrics = Self {
            valid_batches_received: Counter::default(),
            invalid_batches_received: Counter::default(),
            operations_fetched: Counter::default(),
            fetch_duration: Timed::new(fetch_histogram.clone(), Arc::new(context.clone())),
            proof_verification_duration: Timed::new(
                proof_verification_histogram.clone(),
                Arc::new(context.clone()),
            ),
            apply_duration: Timed::new(apply_histogram.clone(), Arc::new(context.clone())),
        };

        // Register metrics.
        context.register(
            "valid_batches_received",
            "Number of valid operation batches processed during ADB sync",
            metrics.valid_batches_received.clone(),
        );
        context.register(
            "invalid_batches_received",
            "Number of invalid operation batches encountered during ADB sync",
            metrics.invalid_batches_received.clone(),
        );
        context.register(
            "operations_fetched",
            "Total number of operations fetched during ADB sync",
            metrics.operations_fetched.clone(),
        );
        context.register(
            "fetch_duration_seconds",
            "Histogram of durations spent fetching operation batches during ADB sync",
            fetch_histogram,
        );
        context.register(
            "proof_verification_duration_seconds",
            "Histogram of durations spent verifying proofs during ADB sync",
            proof_verification_histogram,
        );
        context.register(
            "apply_duration_seconds",
            "Histogram of durations spent applying operations during ADB sync",
            apply_histogram,
        );

        metrics
    }
}

/// Find the next gap in operations that needs to be fetched
/// Returns (start, end) inclusive range, or None if no gaps
fn find_next_gap_to_fetch<K: Array, V: Array>(
    lower_bound: u64,
    upper_bound: u64,
    verified_batches: &BTreeMap<u64, Vec<Operation<K, V>>>,
    outstanding_requests: &BTreeSet<u64>,
    fetch_batch_size: u64,
) -> Option<(u64, u64)> {
    if lower_bound > upper_bound {
        return None;
    }

    let mut current_covered_end: Option<u64> = None; // None means nothing covered yet

    // Create iterators for both data structures (already sorted)
    let mut verified_iter = verified_batches
        .iter()
        .filter_map(|(&start_pos, operations)| {
            if operations.is_empty() {
                None
            } else {
                let end_pos = start_pos + operations.len() as u64 - 1;
                Some((start_pos, end_pos))
            }
        })
        .peekable();

    let mut outstanding_iter = outstanding_requests
        .iter()
        .map(|&start_pos| {
            let end_pos = (start_pos + fetch_batch_size - 1).min(upper_bound);
            (start_pos, end_pos)
        })
        .peekable();

    // Merge process both iterators in sorted order
    loop {
        let next_range = match (verified_iter.peek(), outstanding_iter.peek()) {
            (Some(&(v_start, _)), Some(&(o_start, _))) => {
                if v_start <= o_start {
                    verified_iter.next().unwrap()
                } else {
                    outstanding_iter.next().unwrap()
                }
            }
            (Some(_), None) => verified_iter.next().unwrap(),
            (None, Some(_)) => outstanding_iter.next().unwrap(),
            (None, None) => break,
        };

        let (range_start, range_end) = next_range;

        // Check if there's a gap before this range
        match current_covered_end {
            None => {
                // First range - check if there's a gap before it
                if lower_bound < range_start {
                    let gap_end = (range_start - 1).min(upper_bound);
                    return Some((lower_bound, gap_end));
                }
            }
            Some(covered_end) => {
                // Check if there's a gap between current coverage and this range
                if covered_end + 1 < range_start {
                    let gap_start = covered_end + 1;
                    let gap_end = (range_start - 1).min(upper_bound);
                    if gap_start <= gap_end {
                        return Some((gap_start, gap_end));
                    }
                }
            }
        }

        // Update current covered end (merge overlapping ranges)
        current_covered_end = Some(match current_covered_end {
            None => range_end,
            Some(covered_end) => covered_end.max(range_end),
        });

        // Early exit if we've covered everything up to upper_bound
        if current_covered_end.unwrap() >= upper_bound {
            return None;
        }
    }

    // Check if there's a gap after all ranges
    match current_covered_end {
        None => {
            // No ranges at all - entire range is a gap
            Some((lower_bound, upper_bound))
        }
        Some(covered_end) => {
            // Check if there's a gap after the last covered position
            let gap_start = covered_end + 1;
            if gap_start <= upper_bound {
                Some((gap_start, upper_bound))
            } else {
                None
            }
        }
    }
}

/// Manages the state of the sync process
pub struct SyncState<E, K, V, H>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
{
    /// Verified batches waiting to be applied, indexed by start position
    pub verified_batches: BTreeMap<u64, Vec<Operation<K, V>>>,

    /// Set of batch start positions that have outstanding requests
    pub outstanding_requests: BTreeSet<u64>,

    /// The next position to apply to the log
    pub next_apply_pos: u64,

    /// Pending fetch futures
    pub pending_fetches: FuturesUnordered<
        Pin<
            Box<
                dyn Future<Output = (u64, Result<GetOperationsResult<H::Digest, K, V>, Error>)>
                    + Send,
            >,
        >,
    >,

    /// Pinned nodes extracted from the first batch
    pub pinned_nodes: Option<Vec<H::Digest>>,

    /// Phantom marker for the E type parameter
    _phantom: PhantomData<E>,
}

impl<E, K, V, H> SyncState<E, K, V, H>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
{
    /// Create a new sync state
    fn new(initial_log_size: u64) -> Self {
        Self {
            verified_batches: BTreeMap::new(),
            outstanding_requests: BTreeSet::new(),
            next_apply_pos: initial_log_size,

            pending_fetches: FuturesUnordered::new(),
            pinned_nodes: None,
            _phantom: PhantomData,
        }
    }

    /// Reset state for a target update
    fn reset(&mut self, new_log_size: u64) {
        self.verified_batches.clear();
        self.outstanding_requests.clear();
        self.pending_fetches.clear();
        self.pinned_nodes = None;
        self.next_apply_pos = new_log_size;
    }

    /// Check if sync is complete based on the current log size and target
    async fn is_sync_complete(
        &self,
        log: &Journal<E, Operation<K, V>>,
        target_upper_bound: u64,
    ) -> Result<bool, Error> {
        let log_size = log
            .size()
            .await
            .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;

        // Calculate the target log size (upper bound is inclusive)
        let target_log_size = target_upper_bound
            .checked_add(1)
            .ok_or(Error::InvalidState)?;

        // Check if we've completed sync
        if log_size >= target_log_size {
            if log_size > target_log_size {
                warn!(log_size, target_log_size, "log size exceeded sync target");
                return Err(Error::InvalidState);
            }
            return Ok(true);
        }

        Ok(false)
    }

    /// Update the next position to apply to the log
    /// TODO remove extra arg?
    fn update_next_apply_pos(&mut self, start_pos: u64, operations_len: u64) {
        if start_pos == self.next_apply_pos {
            self.next_apply_pos = start_pos + operations_len;
        }
    }

    /// Store a verified batch of operations
    fn store_batch(&mut self, start_pos: u64, operations: Vec<Operation<K, V>>) {
        self.verified_batches.insert(start_pos, operations);
    }

    /// Remove and return the batch of operations starting at the given position
    fn take_batch(&mut self, start_pos: u64) -> Option<Vec<Operation<K, V>>> {
        self.verified_batches.remove(&start_pos)
    }

    /// Add an outstanding request
    fn add_outstanding_request(&mut self, start_pos: u64) {
        self.outstanding_requests.insert(start_pos);
    }

    /// Remove an outstanding request
    fn remove_outstanding_request(&mut self, start_pos: u64) {
        self.outstanding_requests.remove(&start_pos);
    }

    /// Set pinned nodes
    fn set_pinned_nodes(&mut self, nodes: Vec<H::Digest>) {
        self.pinned_nodes = Some(nodes);
    }

    /// Check if we have pinned nodes
    fn has_pinned_nodes(&self) -> bool {
        self.pinned_nodes.is_some()
    }
}

/// Validate a target update against the current target
fn validate_target_update<H: Hasher>(
    old_target: &SyncTarget<H::Digest>,
    new_target: &SyncTarget<H::Digest>,
) -> Result<(), Error> {
    if new_target.lower_bound_ops > new_target.upper_bound_ops {
        return Err(Error::InvalidTarget {
            lower_bound_pos: new_target.lower_bound_ops,
            upper_bound_pos: new_target.upper_bound_ops,
        });
    }
    if new_target.lower_bound_ops < old_target.lower_bound_ops
        || new_target.upper_bound_ops < old_target.upper_bound_ops
    {
        return Err(Error::SyncTargetMovedBackward {
            old: Box::new(old_target.clone()),
            new: Box::new(new_target.clone()),
        });
    }
    if new_target.root == old_target.root {
        return Err(Error::SyncTargetRootUnchanged);
    }
    Ok(())
}

/// Reinitialize the log for a target update
async fn reinitialize_log_for_target_update<E, K, V, T>(
    mut log: Journal<E, Operation<K, V>>,
    context: E,
    db_config: &adb::any::Config<T>,
    lower_bound_ops: u64,
    upper_bound_ops: u64,
) -> Result<Journal<E, Operation<K, V>>, Error>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    T: Translator,
{
    let log_size = log
        .size()
        .await
        .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;

    if log_size <= lower_bound_ops {
        log.close()
            .await
            .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;
        log = Journal::<E, Operation<K, V>>::init_sync(
            context.clone().with_label("log"),
            JConfig {
                partition: db_config.log_journal_partition.clone(),
                items_per_blob: db_config.log_items_per_blob,
                write_buffer: db_config.log_write_buffer,
                buffer_pool: db_config.buffer_pool.clone(),
            },
            lower_bound_ops,
            upper_bound_ops,
        )
        .await
        .map_err(adb::Error::JournalError)
        .map_err(Error::Adb)?;
    } else {
        // Prune the log to the new lower bound
        log.prune(lower_bound_ops)
            .await
            .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;
    }

    Ok(log)
}

/// Build the final database once sync is complete
async fn build_database<E, K, V, H, T, R>(
    config: Config<E, K, V, H, T, R>,
    log: Journal<E, Operation<K, V>>,
    pinned_nodes: Option<Vec<H::Digest>>,
    metrics: &Metrics<E>,
) -> Result<adb::any::Any<E, K, V, H, T>, Error>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
    let log_size = log
        .size()
        .await
        .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;

    // Build the complete database from the log
    let db = adb::any::Any::init_synced(
        config.context.clone(),
        SyncConfig {
            db_config: config.db_config,
            log,
            lower_bound: config.target.lower_bound_ops,
            upper_bound: config.target.upper_bound_ops,
            pinned_nodes,
            apply_batch_size: config.apply_batch_size,
        },
    )
    .await
    .map_err(Error::Adb)?;

    // Verify the final root digest matches the target
    let mut hasher = mmr::hasher::Standard::<H>::new();
    let got_root = db.root(&mut hasher);
    if got_root != config.target.root {
        return Err(Error::RootMismatch {
            expected: Box::new(config.target.root),
            actual: Box::new(got_root),
        });
    }

    info!(
        target_root = ?config.target.root,
        lower_bound_ops = config.target.lower_bound_ops,
        upper_bound_ops = config.target.upper_bound_ops,
        log_size = log_size,
        valid_batches_received = metrics.valid_batches_received.get(),
        invalid_batches_received = metrics.invalid_batches_received.get(),
        "sync completed successfully");

    Ok(db)
}

/// Synchronizes a database by fetching, verifying, and applying operations from a remote source.
///
/// We fetch operations in parallel batches from a Resolver, verify cryptographic proofs,
/// and apply operations to reconstruct the database's operation log.
///
/// When the database's operation log is complete, we reconstruct the database's MMR and snapshot.
///
/// This function creates a SyncClient and runs it to completion using the step-based API.
pub async fn sync<E, K, V, H, T, R>(
    config: Config<E, K, V, H, T, R>,
) -> Result<adb::any::Any<E, K, V, H, T>, Error>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
    info!("starting sync");

    // Create client and initialize all state
    let mut client = SyncClient::new(config).await?;

    // Run sync to completion using step-based API
    loop {
        match client.step().await? {
            SyncStepResult::Continue(new_client) => client = new_client,
            SyncStepResult::Complete(database) => return Ok(database),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        adb::any::{
            sync::{resolver::tests::FailResolver, resolver::AnyResolver, sync},
            test::{apply_ops, create_test_db, create_test_ops},
        },
        translator,
    };
    use commonware_cryptography::{sha256::Digest, Digest as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _};
    use commonware_utils::NZU64;

    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use std::collections::{HashMap, HashSet};
    use test_case::test_case;

    type TestDigest = Sha256;
    type TestTranslator = translator::TwoCap;

    const PAGE_SIZE: usize = 111;
    const PAGE_CACHE_SIZE: usize = 5;

    fn create_test_hasher() -> crate::mmr::hasher::Standard<TestDigest> {
        crate::mmr::hasher::Standard::<TestDigest>::new()
    }

    fn create_test_config(seed: u64) -> adb::any::Config<TestTranslator> {
        adb::any::Config {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: 1024,
            mmr_write_buffer: 64,
            log_journal_partition: format!("log_journal_{seed}"),
            log_items_per_blob: 1024,
            log_write_buffer: 64,
            translator: TestTranslator::default(),
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            pruning_delay: 100,
        }
    }

    #[test_case(1, NZU64!(1); "singleton db with batch size == 1")]
    #[test_case(1, NZU64!(2); "singleton db with batch size > db size")]
    #[test_case(1000, NZU64!(1); "db with batch size 1")]
    #[test_case(1000, NZU64!(3); "db size not evenly divided by batch size")]
    #[test_case(1000, NZU64!(999); "db size not evenly divided by batch size; different batch size")]
    #[test_case(1000, NZU64!(100); "db size divided by batch size")]
    #[test_case(1000, NZU64!(1000); "db size == batch size")]
    #[test_case(1000, NZU64!(1001); "batch size > db size")]
    fn test_sync(target_db_ops: usize, fetch_batch_size: std::num::NonZeroU64) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_db_ops = create_test_ops(target_db_ops);
            apply_ops(&mut target_db, target_db_ops.clone()).await;
            target_db.commit().await.unwrap();
            let target_op_count = target_db.op_count();
            let target_inactivity_floor = target_db.inactivity_floor_loc;
            let target_log_size = target_db.log.size().await.unwrap();
            let mut hasher = create_test_hasher();
            let target_root = target_db.root(&mut hasher);

            // After commit, the database may have pruned early operations
            // Start syncing from the inactivity floor, not 0
            let lower_bound_ops = target_db.inactivity_floor_loc;

            // Capture target database state and deleted keys before moving into config
            let mut expected_kvs = HashMap::new();
            let mut deleted_keys = HashSet::new();
            for op in &target_db_ops {
                match op {
                    Operation::Update(key, _) => {
                        if let Some((value, loc)) = target_db.get_with_loc(key).await.unwrap() {
                            expected_kvs.insert(*key, (value, loc));
                            deleted_keys.remove(key);
                        }
                    }
                    Operation::Deleted(key) => {
                        expected_kvs.remove(key);
                        deleted_keys.insert(*key);
                    }
                    _ => {}
                }
            }

            let db_config = create_test_config(context.next_u64());

            // Wrap target_db in Arc<RwLock> for resolver and continued use
            let target_db_arc = std::sync::Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                db_config: db_config.clone(),
                fetch_batch_size,
                target: SyncTarget {
                    root: target_root,
                    lower_bound_ops,
                    upper_bound_ops: target_op_count - 1, // target_op_count is the count, operations are 0-indexed
                },
                context: context.clone(),
                resolver: AnyResolver::new_from_arc(target_db_arc.clone()),
                hasher,
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let mut got_db = sync(config).await.unwrap();

            // Verify database state
            let mut hasher = create_test_hasher();
            assert_eq!(got_db.op_count(), target_op_count);
            assert_eq!(got_db.inactivity_floor_loc, target_inactivity_floor);
            assert_eq!(got_db.log.size().await.unwrap(), target_log_size);
            assert_eq!(
                got_db.ops.pruned_to_pos(),
                leaf_num_to_pos(target_inactivity_floor)
            );

            // Verify the root digest matches the target
            assert_eq!(got_db.root(&mut hasher), target_root);

            // Verify that the synced database matches the target state
            for (key, &(value, loc)) in &expected_kvs {
                let synced_opt = got_db.get_with_loc(key).await.unwrap();
                assert_eq!(synced_opt, Some((value, loc)));
            }
            // Verify that deleted keys are absent
            for key in &deleted_keys {
                assert!(got_db.get_with_loc(key).await.unwrap().is_none(),);
            }

            // Put more key-value pairs into both databases
            let mut new_ops = Vec::new();
            let mut rng = StdRng::seed_from_u64(42);
            let mut new_kvs = HashMap::new();
            for _ in 0..expected_kvs.len() {
                let key = Digest::random(&mut rng);
                let value = Digest::random(&mut rng);
                new_ops.push(Operation::Update(key, value));
                new_kvs.insert(key, value);
            }
            apply_ops(&mut got_db, new_ops.clone()).await;
            apply_ops(&mut *target_db_arc.write().await, new_ops).await;
            got_db.commit().await.unwrap();
            target_db_arc.write().await.commit().await.unwrap();

            // Verify that the databases match
            for (key, value) in &new_kvs {
                let got_value = got_db.get(key).await.unwrap().unwrap();
                let target_value = target_db_arc.read().await.get(key).await.unwrap().unwrap();
                assert_eq!(got_value, target_value);
                assert_eq!(got_value, *value);
            }

            let final_target_root = target_db_arc.write().await.root(&mut hasher);
            assert_eq!(got_db.root(&mut hasher), final_target_root);

            // Capture the database state before closing
            let final_synced_op_count = got_db.op_count();
            let final_synced_inactivity_floor = got_db.inactivity_floor_loc;
            let final_synced_log_size = got_db.log.size().await.unwrap();
            let final_synced_oldest_retained_loc = got_db.oldest_retained_loc();
            let final_synced_pruned_to_pos = got_db.ops.pruned_to_pos();
            let final_synced_root = got_db.root(&mut hasher);

            // Close the database
            got_db.close().await.unwrap();

            // Reopen the database using the same configuration and verify the state is unchanged
            let reopened_db = adb::any::Any::<_, Digest, Digest, TestDigest, TestTranslator>::init(
                context, db_config,
            )
            .await
            .unwrap();

            // Compare state against the database state before closing
            assert_eq!(reopened_db.op_count(), final_synced_op_count);
            assert_eq!(
                reopened_db.inactivity_floor_loc,
                final_synced_inactivity_floor
            );
            assert_eq!(reopened_db.log.size().await.unwrap(), final_synced_log_size);
            assert_eq!(
                reopened_db.oldest_retained_loc(),
                final_synced_oldest_retained_loc,
            );
            assert_eq!(reopened_db.ops.pruned_to_pos(), final_synced_pruned_to_pos);
            assert_eq!(reopened_db.root(&mut hasher), final_synced_root);

            // Verify that the original key-value pairs are still correct
            for (key, &(value, _loc)) in &expected_kvs {
                let reopened_value = reopened_db.get(key).await.unwrap();
                assert_eq!(reopened_value, Some(value));
            }

            // Verify all new key-value pairs are still correct
            for (key, &value) in &new_kvs {
                let reopened_value = reopened_db.get(key).await.unwrap().unwrap();
                assert_eq!(reopened_value, value);
            }

            // Verify that deleted keys are still absent
            for key in &deleted_keys {
                assert!(reopened_db.get(key).await.unwrap().is_none());
            }

            // Cleanup
            reopened_db.destroy().await.unwrap();
        });
    }

    /// Test that invalid bounds are rejected
    #[test]
    fn test_sync_invalid_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_db = create_test_db(context.clone()).await;

            let config = Config {
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(10),
                target: SyncTarget {
                    root: Digest::from([1u8; 32]),
                    lower_bound_ops: 31, // Invalid: lower > upper
                    upper_bound_ops: 30,
                },
                context,
                resolver: AnyResolver::new(target_db),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };

            let result = sync(config).await;
            match result {
                Err(Error::InvalidTarget {
                    lower_bound_pos: 31,
                    upper_bound_pos: 30,
                }) => {
                    // Expected error
                }
                _ => panic!("expected InvalidTarget error for invalid bounds"),
            }
        });
    }

    /// Test that sync works when target database has operations beyond the requested range
    /// of operations to sync.
    #[test]
    fn test_sync_subset_of_target_database() {
        const TARGET_DB_OPS: usize = 1000;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(TARGET_DB_OPS);
            // Apply all but the last operation
            apply_ops(&mut target_db, target_ops[0..TARGET_DB_OPS - 1].to_vec()).await;
            target_db.commit().await.unwrap();

            let mut hasher = create_test_hasher();
            let upper_bound_ops = target_db.op_count() - 1;
            let root = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;

            // Add another operation after the sync range
            let final_op = &target_ops[TARGET_DB_OPS - 1];
            apply_ops(&mut target_db, vec![final_op.clone()]).await; // TODO: this is wrong
            target_db.commit().await.unwrap();

            // Start of the sync range is after the inactivity floor
            let config = Config {
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(10),
                target: SyncTarget {
                    root,
                    lower_bound_ops,
                    upper_bound_ops,
                },
                context,
                resolver: AnyResolver::new(target_db),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };

            let synced_db = sync(config).await.unwrap();

            // Verify the synced database has the correct range of operations
            assert_eq!(synced_db.inactivity_floor_loc, lower_bound_ops);
            assert_eq!(synced_db.oldest_retained_loc(), Some(lower_bound_ops));
            assert_eq!(
                synced_db.ops.pruned_to_pos(),
                leaf_num_to_pos(lower_bound_ops)
            );
            assert_eq!(synced_db.op_count(), upper_bound_ops + 1);

            // Verify the final root digest matches our target
            assert_eq!(synced_db.root(&mut hasher), root);

            // Verify the synced database doesn't have any operations beyond the sync range.
            assert_eq!(
                synced_db.get(final_op.to_key().unwrap()).await.unwrap(),
                None
            );
        });
    }

    // Test syncing where the sync client has some but not all of the operations in the target
    // database.
    #[test]
    fn test_sync_use_existing_db_partial_match() {
        const ORIGINAL_DB_OPS: usize = 1_000;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let original_ops = create_test_ops(ORIGINAL_DB_OPS);

            // Create two databases
            let mut target_db = create_test_db(context.clone()).await;
            let sync_db_config = create_test_config(1337);
            let mut sync_db = adb::any::Any::init(context.clone(), sync_db_config.clone())
                .await
                .unwrap();

            // Apply the same operations to both databases
            apply_ops(&mut target_db, original_ops.clone()).await;
            apply_ops(&mut sync_db, original_ops.clone()).await;
            target_db.commit().await.unwrap();
            sync_db.commit().await.unwrap();

            let original_db_op_count = target_db.op_count();

            // Close sync_db
            sync_db.close().await.unwrap();

            // Add one more operation and commit the target database
            let last_op = create_test_ops(1);
            apply_ops(&mut target_db, last_op.clone()).await;
            target_db.commit().await.unwrap();
            let mut hasher = create_test_hasher();
            let root = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;
            let upper_bound_ops = target_db.op_count() - 1; // Up to the last operation

            // Reopen the sync database and sync it to the target database
            let target_db = std::sync::Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                db_config: sync_db_config, // Use same config as before
                fetch_batch_size: NZU64!(10),
                target: SyncTarget {
                    root,
                    lower_bound_ops,
                    upper_bound_ops,
                },
                context: context.clone(),
                resolver: AnyResolver::new_from_arc(target_db.clone()),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let sync_db = sync(config).await.unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), upper_bound_ops + 1);
            assert_eq!(
                sync_db.inactivity_floor_loc,
                target_db.read().await.inactivity_floor_loc
            );
            assert_eq!(sync_db.oldest_retained_loc().unwrap(), lower_bound_ops);
            assert_eq!(
                sync_db.log.size().await.unwrap(),
                target_db.read().await.log.size().await.unwrap()
            );
            assert_eq!(
                sync_db.ops.pruned_to_pos(),
                leaf_num_to_pos(lower_bound_ops)
            );
            // Verify the root digest matches the target
            assert_eq!(sync_db.root(&mut hasher), root);

            // Verify that the operations in the overlapping range are present and correct
            for i in lower_bound_ops..original_db_op_count {
                let expected_op = target_db.read().await.log.read(i).await.unwrap();
                let synced_op = sync_db.log.read(i).await.unwrap();
                assert_eq!(expected_op, synced_op);
            }

            for target_op in &original_ops {
                if let Some(key) = target_op.to_key() {
                    let target_value = target_db.read().await.get(key).await.unwrap();
                    let synced_value = sync_db.get(key).await.unwrap();
                    assert_eq!(target_value, synced_value);
                }
            }
            // Verify the last operation is present
            let last_key = last_op[0].to_key().unwrap();
            let last_value = *last_op[0].to_value().unwrap();
            assert_eq!(sync_db.get(last_key).await.unwrap(), Some(last_value));

            sync_db.destroy().await.unwrap();
            std::sync::Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test case where existing database on disk exactly matches the sync target
    #[test]
    fn test_sync_use_existing_db_exact_match() {
        const NUM_OPS: usize = 1_000;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_ops = create_test_ops(NUM_OPS);

            // Create two databases
            let target_config = create_test_config(context.next_u64());
            let mut target_db = adb::any::Any::init(context.clone(), target_config)
                .await
                .unwrap();
            let sync_config = create_test_config(context.next_u64());
            let mut sync_db = adb::any::Any::init(context.clone(), sync_config.clone())
                .await
                .unwrap();

            // Apply the same operations to both databases
            apply_ops(&mut target_db, target_ops.clone()).await;
            apply_ops(&mut sync_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();
            sync_db.commit().await.unwrap();

            target_db.sync().await.unwrap();
            sync_db.sync().await.unwrap();

            // Close sync_db
            sync_db.close().await.unwrap();

            // Reopen sync_db
            let mut hasher = create_test_hasher();
            let root = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;
            let upper_bound_ops = target_db.op_count() - 1;
            // sync_db should never ask the resolver for operations
            // because it is already complete. Use a resolver that always fails
            // to ensure that it's not being used.
            let resolver = FailResolver::<Digest, Digest, Digest>::new();
            let config = Config {
                db_config: sync_config, // Use same config to access same partitions
                fetch_batch_size: NZU64!(10),
                target: SyncTarget {
                    root,
                    lower_bound_ops,
                    upper_bound_ops,
                },
                context: context.clone(),
                resolver,
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let sync_db = sync(config).await.unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), upper_bound_ops + 1);
            assert_eq!(sync_db.op_count(), target_db.op_count());
            assert_eq!(sync_db.oldest_retained_loc().unwrap(), lower_bound_ops);
            assert_eq!(
                sync_db.log.size().await.unwrap(),
                target_db.log.size().await.unwrap()
            );
            assert_eq!(
                sync_db.ops.pruned_to_pos(),
                leaf_num_to_pos(lower_bound_ops)
            );

            // Verify the root digest matches the target
            assert_eq!(sync_db.root(&mut hasher), root);

            // Verify state matches for sample operations
            for target_op in &target_ops {
                if let Some(key) = target_op.to_key() {
                    let target_value = target_db.get(key).await.unwrap();
                    let synced_value = sync_db.get(key).await.unwrap();
                    assert_eq!(target_value, synced_value);
                }
            }

            sync_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Test demonstrating that a synced database can be reopened and retain its state.
    #[test_traced("WARN")]
    fn test_sync_database_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create and populate a simple target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(10);
            apply_ops(&mut target_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture target state
            let mut hasher = create_test_hasher();
            let target_root = target_db.root(&mut hasher);
            let lower_bound = target_db.inactivity_floor_loc;
            let upper_bound = target_db.op_count() - 1;

            // Perform sync
            let db_config = create_test_config(42);
            let context_clone = context.clone();
            let target_db = std::sync::Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                db_config: db_config.clone(),
                fetch_batch_size: NZU64!(5),
                target: SyncTarget {
                    root: target_root,
                    lower_bound_ops: lower_bound,
                    upper_bound_ops: upper_bound,
                },
                context,
                resolver: AnyResolver::new_from_arc(target_db.clone()),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let synced_db = sync(config).await.unwrap();

            // Verify initial sync worked
            let mut hasher = create_test_hasher();
            assert_eq!(synced_db.root(&mut hasher), target_root);

            // Save state before closing
            let expected_root = synced_db.root(&mut hasher);
            let expected_op_count = synced_db.op_count();
            let expected_inactivity_floor_loc = synced_db.inactivity_floor_loc;
            let expected_oldest_retained_loc = synced_db.oldest_retained_loc();
            let expected_pruned_to_pos = synced_db.ops.pruned_to_pos();

            // Close the database
            synced_db.close().await.unwrap();

            // Re-open the database
            let reopened_db = adb::any::Any::<_, Digest, Digest, TestDigest, TestTranslator>::init(
                context_clone,
                db_config,
            )
            .await
            .unwrap();

            // Verify the state is unchanged
            assert_eq!(reopened_db.root(&mut hasher), expected_root);
            assert_eq!(reopened_db.op_count(), expected_op_count);
            assert_eq!(
                reopened_db.inactivity_floor_loc,
                expected_inactivity_floor_loc
            );
            assert_eq!(
                reopened_db.oldest_retained_loc(),
                expected_oldest_retained_loc
            );
            assert_eq!(reopened_db.ops.pruned_to_pos(), expected_pruned_to_pos);

            // Cleanup
            std::sync::Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
            reopened_db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_sync_step_example() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create a simple target database with a few operations
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(5);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit().await.unwrap();

            let mut hasher = create_test_hasher();
            let upper_bound_ops = target_db.op_count() - 1;
            let root = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;

            // Set up sync configuration
            let config = Config {
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(2),
                target: SyncTarget {
                    root,
                    lower_bound_ops,
                    upper_bound_ops,
                },
                context: context.clone(),
                resolver: AnyResolver::new(target_db),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };

            // Create sync client
            let mut client = SyncClient::new(config).await.unwrap();

            // Use client.step() to control sync progression
            let mut step_count = 0;
            let final_db = loop {
                match client.step().await.unwrap() {
                    SyncStepResult::Continue(new_client) => {
                        client = new_client;
                        step_count += 1;
                        // Can inspect client state between steps
                        assert!(step_count < 100, "Too many steps, likely infinite loop");
                    }
                    SyncStepResult::Complete(database) => {
                        break database;
                    }
                }
            };
            assert_eq!(final_db.op_count(), upper_bound_ops + 1);
            assert!(step_count > 0, "Should have taken at least one step");
        });
    }

    #[test]
    fn test_find_next_gap_to_fetch() {
        use crate::adb::operation::Operation;
        use commonware_cryptography::sha256::Digest;

        // Test case 1: Empty state - should return the full range
        let verified_batches: BTreeMap<u64, Vec<Operation<Digest, Digest>>> = BTreeMap::new();
        let outstanding_requests = BTreeSet::new();
        let result = find_next_gap_to_fetch::<Digest, Digest>(
            0,
            10,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, Some((0, 10)));

        // Test case 2: Some verified batches with gaps
        let mut verified_batches = BTreeMap::new();
        verified_batches.insert(
            0,
            vec![Operation::Update(
                Digest::from([1; 32]),
                Digest::from([2; 32]),
            )],
        );
        verified_batches.insert(
            1,
            vec![Operation::Update(
                Digest::from([3; 32]),
                Digest::from([4; 32]),
            )],
        );
        // Gap at positions 2, 3
        verified_batches.insert(
            5,
            vec![Operation::Update(
                Digest::from([5; 32]),
                Digest::from([6; 32]),
            )],
        );

        let outstanding_requests = BTreeSet::new();
        let result = find_next_gap_to_fetch::<Digest, Digest>(
            0,
            10,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, Some((2, 4))); // First gap is positions 2-4

        // Test case 3: Outstanding request covers part of the gap
        let mut outstanding_requests = BTreeSet::new();
        outstanding_requests.insert(2); // Outstanding request starting at 2, covers 2-6 (batch_size=5)

        let result = find_next_gap_to_fetch::<Digest, Digest>(
            0,
            10,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, Some((7, 10))); // Next gap is 7-10

        // Test case 4: No gaps - everything covered
        let mut verified_batches = BTreeMap::new();
        for i in 0..=10 {
            verified_batches.insert(
                i,
                vec![Operation::Update(
                    Digest::from([i as u8; 32]),
                    Digest::from([i as u8 + 1; 32]),
                )],
            );
        }
        let outstanding_requests = BTreeSet::new();
        let result = find_next_gap_to_fetch::<Digest, Digest>(
            0,
            10,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, None);

        // Test case 5: Gap at the end
        let mut verified_batches = BTreeMap::new();
        for i in 0..=7 {
            verified_batches.insert(
                i,
                vec![Operation::Update(
                    Digest::from([i as u8; 32]),
                    Digest::from([i as u8 + 1; 32]),
                )],
            );
        }
        let outstanding_requests = BTreeSet::new();
        let result = find_next_gap_to_fetch::<Digest, Digest>(
            0,
            10,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, Some((8, 10)));

        // Test case 6: Multi-operation batches
        let mut verified_batches = BTreeMap::new();
        verified_batches.insert(
            0,
            vec![
                Operation::Update(Digest::from([1; 32]), Digest::from([2; 32])),
                Operation::Update(Digest::from([3; 32]), Digest::from([4; 32])),
                Operation::Update(Digest::from([5; 32]), Digest::from([6; 32])),
            ],
        ); // Covers positions 0, 1, 2

        let outstanding_requests = BTreeSet::new();
        let result = find_next_gap_to_fetch::<Digest, Digest>(
            0,
            10,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, Some((3, 10))); // Gap starts at position 3

        // Test case 7: Invalid bounds
        let verified_batches: BTreeMap<u64, Vec<Operation<Digest, Digest>>> = BTreeMap::new();
        let outstanding_requests = BTreeSet::new();
        let result = find_next_gap_to_fetch::<Digest, Digest>(
            10,
            5,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, None);

        // Test case 8: User's example - lower_bound=0, upper_bound=10, outstanding at 5, batch 0-2 completed
        let mut verified_batches = BTreeMap::new();
        verified_batches.insert(
            0,
            vec![
                Operation::Update(Digest::from([1; 32]), Digest::from([2; 32])),
                Operation::Update(Digest::from([3; 32]), Digest::from([4; 32])),
                Operation::Update(Digest::from([5; 32]), Digest::from([6; 32])),
            ],
        ); // Covers positions 0, 1, 2

        let mut outstanding_requests = BTreeSet::new();
        outstanding_requests.insert(5); // Outstanding request at 5

        let result = find_next_gap_to_fetch::<Digest, Digest>(
            0,
            10,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, Some((3, 4))); // Should request gap 3-4

        // Test case 9: Adjacent ranges should merge
        let mut verified_batches = BTreeMap::new();
        verified_batches.insert(
            0,
            vec![Operation::Update(
                Digest::from([1; 32]),
                Digest::from([2; 32]),
            )],
        ); // Covers position 0
        verified_batches.insert(
            1,
            vec![Operation::Update(
                Digest::from([3; 32]),
                Digest::from([4; 32]),
            )],
        ); // Covers position 1 (adjacent to position 0)

        let outstanding_requests = BTreeSet::new();
        let result = find_next_gap_to_fetch::<Digest, Digest>(
            0,
            10,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, Some((2, 10))); // Gap should start at 2

        // Test case 10: Overlapping outstanding requests
        let verified_batches: BTreeMap<u64, Vec<Operation<Digest, Digest>>> = BTreeMap::new();
        let mut outstanding_requests = BTreeSet::new();
        outstanding_requests.insert(0); // Covers 0-4 (batch_size=5)
        outstanding_requests.insert(3); // Covers 3-7 (overlaps with first)
        outstanding_requests.insert(8); // Covers 8-10 (gap at positions 5-7 should be covered by second request)

        let result = find_next_gap_to_fetch::<Digest, Digest>(
            0,
            10,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, None); // No gaps - everything covered by overlapping requests

        // Test case 11: Outstanding request goes beyond upper_bound (should be capped)
        let verified_batches: BTreeMap<u64, Vec<Operation<Digest, Digest>>> = BTreeMap::new();
        let mut outstanding_requests = BTreeSet::new();
        outstanding_requests.insert(8); // Would cover 8-12, but upper_bound is 10

        let result = find_next_gap_to_fetch::<Digest, Digest>(
            0,
            10,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, Some((0, 7))); // Gap from 0-7, then 8-10 is covered

        // Test case 12: Zero-length range (lower_bound == upper_bound)
        let verified_batches: BTreeMap<u64, Vec<Operation<Digest, Digest>>> = BTreeMap::new();
        let outstanding_requests = BTreeSet::new();
        let result = find_next_gap_to_fetch::<Digest, Digest>(
            5,
            5,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, Some((5, 5))); // Single position gap

        // Test case 13: Outstanding requests only (no verified batches)
        let verified_batches: BTreeMap<u64, Vec<Operation<Digest, Digest>>> = BTreeMap::new();
        let mut outstanding_requests = BTreeSet::new();
        outstanding_requests.insert(0); // Covers 0-4
        outstanding_requests.insert(7); // Covers 7-10

        let result = find_next_gap_to_fetch::<Digest, Digest>(
            0,
            10,
            &verified_batches,
            &outstanding_requests,
            4,
        );
        assert_eq!(result, Some((4, 6))); // Gap between the two outstanding requests

        // Test case 14: Empty verified batches should be ignored
        let mut verified_batches = BTreeMap::new();
        verified_batches.insert(0, vec![]); // Empty batch should be ignored
        verified_batches.insert(
            2,
            vec![Operation::Update(
                Digest::from([1; 32]),
                Digest::from([2; 32]),
            )],
        );

        let outstanding_requests = BTreeSet::new();
        let result = find_next_gap_to_fetch::<Digest, Digest>(
            0,
            5,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, Some((0, 1))); // Gap at 0-1, empty batch ignored

        // Test case 15: Outstanding request before lower_bound (edge case)
        let verified_batches: BTreeMap<u64, Vec<Operation<Digest, Digest>>> = BTreeMap::new();
        let mut outstanding_requests = BTreeSet::new();
        outstanding_requests.insert(0); // This covers 0-4, but lower_bound is 3

        let result = find_next_gap_to_fetch::<Digest, Digest>(
            3,
            10,
            &verified_batches,
            &outstanding_requests,
            5,
        );
        assert_eq!(result, Some((5, 10))); // Gap after the outstanding request coverage
    }
}
