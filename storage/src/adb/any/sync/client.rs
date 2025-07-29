use super::{
    resolver::{GetOperationsResult, Resolver},
    Error, SyncTarget, SyncTargetUpdateReceiver,
};
use crate::{
    adb::{
        self,
        any::{sync::metrics::Metrics, SyncConfig},
        operation::Fixed,
    },
    journal::fixed::{Config as JConfig, Journal},
    mmr::{self, iterator::leaf_num_to_pos, verification::Proof},
    translator::Translator,
};
use commonware_cryptography::{Digest, Hasher};
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics as MetricsTrait, Storage};
use commonware_utils::{Array, NZU64};
use futures::{future::Either, stream::FuturesUnordered, StreamExt};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    num::NonZeroU64,
    pin::Pin,
};
use tracing::{debug, info, warn};

/// Result of executing one sync step
enum StepResult<C, D> {
    /// Sync should continue with the updated client
    Continue(C),
    /// Sync is complete with the final database
    Complete(D),
}

/// Events that can occur during synchronization
enum SyncEvent<H, K, V>
where
    H: Digest,
    K: Array,
    V: Array,
{
    /// A target update was received
    TargetUpdate(SyncTarget<H>),
    /// A batch of operations was received
    BatchReceived(IndexedFetchResult<H, K, V>),
    /// The target update channel was closed
    UpdateChannelClosed,
}

struct IndexedFetchResult<D, K, V>
where
    D: Digest,
    K: Array,
    V: Array,
{
    /// The location of the first operation in the batch
    start_loc: u64,
    /// The result of the fetch operation
    result: Result<GetOperationsResult<D, K, V>, Error>,
}

/// Manages outstanding fetch requests.
struct OutstandingRequests<D, K, V>
where
    D: Digest,
    K: Array,
    V: Array,
{
    /// Futures that will resolve to batches of operations.
    #[allow(clippy::type_complexity)]
    futures: FuturesUnordered<Pin<Box<dyn Future<Output = IndexedFetchResult<D, K, V>> + Send>>>,
    /// Start locations of outstanding requests.
    /// Each element corresponds to an element in `futures` and vice versa.
    locations: BTreeSet<u64>,
}

impl<D, K, V> OutstandingRequests<D, K, V>
where
    D: Digest,
    K: Array,
    V: Array,
{
    fn new() -> Self {
        Self {
            futures: FuturesUnordered::new(),
            locations: BTreeSet::new(),
        }
    }

    /// Add a new outstanding request.
    fn add(
        &mut self,
        start_loc: u64,
        future: Pin<Box<dyn Future<Output = IndexedFetchResult<D, K, V>> + Send>>,
    ) {
        self.locations.insert(start_loc);
        self.futures.push(future);
    }

    /// Get a mutable reference to the underlying futures.
    #[allow(clippy::type_complexity)]
    fn futures_mut(
        &mut self,
    ) -> &mut FuturesUnordered<Pin<Box<dyn Future<Output = IndexedFetchResult<D, K, V>> + Send>>>
    {
        &mut self.futures
    }

    /// Remove a request from location tracking.
    fn remove(&mut self, start_loc: u64) {
        self.locations.remove(&start_loc);
    }

    /// Clear all outstanding requests.
    fn clear(&mut self) {
        self.futures.clear();
        self.locations.clear();
    }

    /// Get the number of outstanding requests.
    fn len(&self) -> usize {
        self.locations.len()
    }

    /// Get a view of the outstanding request locations.
    fn locations(&self) -> &BTreeSet<u64> {
        &self.locations
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
    /// Higher values increase parallelism.
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

/// Client that syncs an [adb::any::Any] database.
pub(super) struct Client<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
    config: Config<E, K, V, H, T, R>,

    /// Batches of operations waiting to be applied, indexed by location of first operation.
    fetched_operations: BTreeMap<u64, Vec<Fixed<K, V>>>,

    /// Outstanding fetch requests.
    outstanding_requests: OutstandingRequests<H::Digest, K, V>,

    /// Pinned nodes extracted from the batch of operations at the lower sync bound.
    pinned_nodes: Option<Vec<H::Digest>>,

    /// Journal of operations that the sync protocol fills.
    /// When it's completed, we use it to build the database.
    log: Journal<E, Fixed<K, V>>,

    metrics: Metrics<E>,
}

impl<E, K, V, H, T, R> Client<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
    /// Create a new sync client.
    pub(super) async fn new(config: Config<E, K, V, H, T, R>) -> Result<Self, Error> {
        // Validate configuration
        config.validate()?;

        // Initialize the operations journal
        let log = Journal::<E, Fixed<K, V>>::init_sync(
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

        let log_size = log
            .size()
            .await
            .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;
        assert!(log_size <= config.target.upper_bound_ops + 1);

        // Initialize metrics
        let metrics = Metrics::new(config.context.clone());

        // Create client
        let mut client = Self {
            config,
            fetched_operations: BTreeMap::new(),
            outstanding_requests: OutstandingRequests::new(),
            pinned_nodes: None,
            log,
            metrics,
        };

        // Request operations in the sync range
        client.request_operations().await?;

        Ok(client)
    }

    /// Run sync to completion.
    pub(super) async fn sync(mut self) -> Result<adb::any::Any<E, K, V, H, T>, Error> {
        loop {
            match self.step().await? {
                StepResult::Continue(new_client) => self = new_client,
                StepResult::Complete(database) => return Ok(database),
            }
        }
    }

    /// Handle the result of a fetch operation.
    fn handle_fetch_result(
        &mut self,
        fetch_result: IndexedFetchResult<H::Digest, K, V>,
    ) -> Result<(), Error> {
        // Mark request as complete
        self.outstanding_requests.remove(fetch_result.start_loc);

        let start_loc = fetch_result.start_loc;
        match fetch_result.result {
            Ok(GetOperationsResult {
                proof,
                operations,
                success_tx,
            }) => {
                // Validate batch size
                let operations_len = operations.len() as u64;
                if operations_len == 0 || operations_len > self.config.fetch_batch_size.get() {
                    debug!(
                        operations_len,
                        batch_size = self.config.fetch_batch_size.get(),
                        start_loc,
                        "received invalid batch size from resolver"
                    );
                    self.metrics.invalid_batches_received.inc();
                    let _ = success_tx.send(false);
                } else {
                    // Verify the proof
                    let proof_valid = {
                        let _timer = self.metrics.proof_verification_duration.timer();
                        adb::any::Any::<E, K, V, H, T>::verify_proof(
                            &mut self.config.hasher,
                            &proof,
                            start_loc,
                            &operations,
                            &self.config.target.root,
                        )
                    };
                    // Report success or failure to the resolver
                    let _ = success_tx.send(proof_valid);
                    if proof_valid {
                        // Extract pinned nodes if needed
                        self.set_pinned_nodes(&proof, start_loc, operations_len)?;
                        // Store operations for later application
                        self.store_operations(start_loc, operations);
                    } else {
                        debug!(start_loc, "proof verification failed, retrying");
                        self.metrics.invalid_batches_received.inc();
                    }
                }
            }
            Err(e) => {
                // We couldn't get the operations we requested. When we scan for gaps
                // in the sync range, we will request them again if we haven't already
                // requested or received these operations.
                warn!(start_loc, error = ?e, "batch fetch failed, retrying");
            }
        }
        Ok(())
    }

    /// Wait for the next synchronization event.
    async fn wait_for_event(&mut self) -> Result<SyncEvent<H::Digest, K, V>, Error> {
        let target_update_fut = match &mut self.config.update_receiver {
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
            result = self.outstanding_requests.futures_mut().next() => {
                let fetch_result = result.ok_or(Error::SyncStalled)?;
                Ok(SyncEvent::BatchReceived(fetch_result))
            },
        }
    }

    /// Execute one step of the sync process.
    /// Returns either a new client to continue with, or the final database if complete.
    async fn step(mut self) -> Result<StepResult<Self, adb::any::Any<E, K, V, H, T>>, Error> {
        // Check if sync is complete
        if self.is_complete().await? {
            let target_root = self.config.target.root;
            let lower_bound_ops = self.config.target.lower_bound_ops;
            let upper_bound_ops = self.config.target.upper_bound_ops;
            let database = build_database(self.config, self.log, self.pinned_nodes.clone()).await?;
            info!(
                target_root = ?target_root,
                lower_bound_ops,
                upper_bound_ops,
                "sync completed"
            );
            return Ok(StepResult::Complete(database));
        }

        // Wait for the next synchronization event
        match self.wait_for_event().await? {
            SyncEvent::TargetUpdate(new_target) => {
                self = self.handle_target_update(new_target).await?;
            }
            SyncEvent::UpdateChannelClosed => {
                self.config.update_receiver = None;
            }
            SyncEvent::BatchReceived(fetch_result) => {
                // Process the fetch result
                self.handle_fetch_result(fetch_result)?;

                // Request operations in the sync range
                self.request_operations().await?;

                // Apply operations that are now contiguous with the current log size
                self.apply_operations().await?;
            }
        }
        Ok(StepResult::Continue(self))
    }

    /// Request batches of operations from the resolver.
    async fn request_operations(&mut self) -> Result<(), Error> {
        let target_size = self.config.target.upper_bound_ops + 1;

        // Special case: If we don't have pinned nodes, we need to extract them from a proof
        // for the lower sync bound.
        if self.pinned_nodes.is_none() {
            let start_loc = self.config.target.lower_bound_ops;
            let resolver = self.config.resolver.clone();
            self.outstanding_requests.add(
                start_loc,
                Box::pin(async move {
                    let result = resolver
                        .get_operations(target_size, start_loc, NZU64!(1))
                        .await;
                    IndexedFetchResult { start_loc, result }
                }),
            );
        }

        // Calculate the maximum number of requests to make
        let num_requests = self
            .config
            .max_outstanding_requests
            .saturating_sub(self.outstanding_requests.len());

        let log_size = self
            .log
            .size()
            .await
            .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;

        for _ in 0..num_requests {
            // Find the next gap in the sync range that needs to be fetched.
            let Some((start_loc, end_loc)) = find_next_gap::<K, V>(
                log_size,
                self.config.target.upper_bound_ops,
                &self.fetched_operations,
                self.outstanding_requests.locations(),
                self.config.fetch_batch_size.get(),
            ) else {
                break; // No more gaps to fill
            };

            // Kick off a request for the batch of operations
            let resolver = self.config.resolver.clone();
            let gap_size = NZU64!(end_loc - start_loc + 1);
            let batch_size = self.config.fetch_batch_size.min(gap_size);
            self.outstanding_requests.add(
                start_loc,
                Box::pin(async move {
                    let result = resolver
                        .get_operations(target_size, start_loc, batch_size)
                        .await;
                    IndexedFetchResult { start_loc, result }
                }),
            );
        }

        Ok(())
    }

    /// If `start_loc` is the lower sync bound, extract pinned nodes from the proof
    /// and set them in the `self`. Otherwise, do nothing.
    fn set_pinned_nodes(
        &mut self,
        proof: &Proof<H::Digest>,
        start_loc: u64,
        operations_len: u64,
    ) -> Result<(), Error> {
        if self.pinned_nodes.is_none() && start_loc == self.config.target.lower_bound_ops {
            let start_pos_mmr = leaf_num_to_pos(start_loc);
            let end_pos_mmr = leaf_num_to_pos(start_loc + operations_len - 1);
            match proof.extract_pinned_nodes(start_pos_mmr, end_pos_mmr) {
                Ok(nodes) => self.pinned_nodes = Some(nodes),
                Err(e) => return Err(Error::PinnedNodes(e)),
            }
        }
        Ok(())
    }

    /// Store a verified batch of operations to be applied later
    fn store_operations(&mut self, start_loc: u64, operations: Vec<Fixed<K, V>>) {
        self.metrics
            .operations_fetched
            .inc_by(operations.len() as u64);
        self.metrics.valid_batches_received.inc();
        self.fetched_operations.insert(start_loc, operations);
    }

    /// Apply fetched operations to the tip of the log if we have them.
    async fn apply_operations(&mut self) -> Result<(), Error> {
        let mut next_loc = self
            .log
            .size()
            .await
            .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;

        // Remove any batches of operations with stale data.
        // That is, those whose last operation is before `next_loc`.
        self.fetched_operations.retain(|&start_loc, operations| {
            let end_loc = start_loc + operations.len() as u64 - 1;
            end_loc >= next_loc
        });

        loop {
            // See if we have the next operation to apply (i.e. at the log tip).
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
                // We don't have the next operation to apply (i.e. at the log tip)
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

    /// Apply a batch of operations to the log
    async fn apply_operations_batch<I>(&mut self, operations: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = Fixed<K, V>>,
    {
        let _timer = self.metrics.apply_duration.timer();
        for op in operations {
            self.log
                .append(op)
                .await
                .map_err(adb::Error::JournalError)
                .map_err(Error::Adb)?;
            // No need to sync here -- the log will periodically sync its storage
            // and we will also sync when we're done applying all operations.
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
        self.log = update_log_for_target_update(
            self.log,
            self.config.context.clone(),
            &self.config.db_config,
            self.config.target.lower_bound_ops,
            self.config.target.upper_bound_ops,
        )
        .await?;

        // Reset state for the target update
        self.fetched_operations.clear();
        self.outstanding_requests.clear();
        self.pinned_nodes = None;

        // Reinitialize parallel fetching
        self.request_operations().await?;

        Ok(self)
    }

    /// Check if sync is complete based on the current log size and target
    async fn is_complete(&self) -> Result<bool, Error> {
        let log_size = self
            .log
            .size()
            .await
            .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;

        // Calculate the target log size (upper bound is inclusive)
        let target_log_size = self.config.target.upper_bound_ops + 1;

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
}

/// Find the next gap in operations that needs to be fetched.
/// Returns [start, end] inclusive range, or None if no gaps.
/// We assume that all outstanding requests will return `fetch_batch_size` operations,
/// but the resolver may return fewer. In that case, we'll fetch the remaining operations
/// in a subsequent request.
/// Invariants:
/// - All batches in `fetched_operations` are non-empty.
/// - All start locations in `fetched_operations` are in [lower_bound, upper_bound].
/// - All start locations in `outstanding_requests` are in [lower_bound, upper_bound].
fn find_next_gap<K: Array, V: Array>(
    lower_bound: u64,
    upper_bound: u64,
    fetched_operations: &BTreeMap<u64, Vec<Fixed<K, V>>>,
    outstanding_requests: &BTreeSet<u64>,
    fetch_batch_size: u64,
) -> Option<(u64, u64)> {
    if lower_bound > upper_bound {
        return None;
    }

    let mut current_covered_end: Option<u64> = None; // Nothing covered yet

    // Create iterators for both data structures (already sorted)
    let mut fetched_ops_iter = fetched_operations
        .iter()
        .map(|(&start_loc, operations)| {
            let end_loc = start_loc + operations.len() as u64 - 1;
            (start_loc, end_loc)
        })
        .peekable();

    let mut outstanding_reqs_iter = outstanding_requests
        .iter()
        .map(|&start_loc| {
            let end_loc = start_loc + fetch_batch_size - 1;
            (start_loc, end_loc)
        })
        .peekable();

    // Merge process both iterators in sorted order
    loop {
        let (range_start, range_end) = match (fetched_ops_iter.peek(), outstanding_reqs_iter.peek())
        {
            (Some(&(f_start, _)), Some(&(o_start, _))) => {
                if f_start <= o_start {
                    fetched_ops_iter.next().unwrap()
                } else {
                    outstanding_reqs_iter.next().unwrap()
                }
            }
            (Some(_), None) => fetched_ops_iter.next().unwrap(),
            (None, Some(_)) => outstanding_reqs_iter.next().unwrap(),
            (None, None) => break,
        };

        // Check if there's a gap before this range
        match current_covered_end {
            None => {
                // This is the first range.
                if lower_bound < range_start {
                    // There's a gap between the lower bound and the start of the first range.
                    let gap_end = range_start - 1;
                    return Some((lower_bound, gap_end));
                }
            }
            Some(covered_end) => {
                // Check if there's a gap between current coverage and this range
                if covered_end + 1 < range_start {
                    let gap_start = covered_end + 1;
                    let gap_end = range_start - 1;
                    return Some((gap_start, gap_end));
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
            // Check if there's a gap after the last covered location
            let gap_start = covered_end + 1;
            Some((gap_start, upper_bound))
        }
    }
}

/// Validate a target update against the current target.
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

/// Reinitialize the log for a target update.
///
/// If the last log element is before the new lower bound, we close the log and reinitialize it.
/// If the last log element is after the new lower bound, we prune the log to the lower bound.
async fn update_log_for_target_update<E, K, V, T>(
    mut log: Journal<E, Fixed<K, V>>,
    context: E,
    db_config: &adb::any::Config<T>,
    lower_bound_ops: u64,
    upper_bound_ops: u64,
) -> Result<Journal<E, Fixed<K, V>>, Error>
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
        log = Journal::<E, Fixed<K, V>>::init_sync(
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

/// Build the database from `log` and `pinned_nodes` once sync is complete.
async fn build_database<E, K, V, H, T, R>(
    config: Config<E, K, V, H, T, R>,
    log: Journal<E, Fixed<K, V>>,
    pinned_nodes: Option<Vec<H::Digest>>,
) -> Result<adb::any::Any<E, K, V, H, T>, Error>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
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
    Ok(db)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        adb::any::{
            sync::{resolver::tests::FailResolver, sync},
            test::{apply_ops, create_test_db, create_test_ops},
        },
        translator,
    };
    use commonware_cryptography::{sha256::Digest, Digest as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _};
    use commonware_utils::NZU64;
    use futures::{channel::mpsc, SinkExt as _};
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use std::{
        collections::{HashMap, HashSet},
        sync::Arc,
    };
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
    fn test_sync(target_db_ops: usize, fetch_batch_size: NonZeroU64) {
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
                    Fixed::Update(key, _) => {
                        if let Some((value, loc)) = target_db.get_with_loc(key).await.unwrap() {
                            expected_kvs.insert(*key, (value, loc));
                            deleted_keys.remove(key);
                        }
                    }
                    Fixed::Deleted(key) => {
                        expected_kvs.remove(key);
                        deleted_keys.insert(*key);
                    }
                    _ => {}
                }
            }

            let db_config = create_test_config(context.next_u64());

            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                db_config: db_config.clone(),
                fetch_batch_size,
                target: SyncTarget {
                    root: target_root,
                    lower_bound_ops,
                    upper_bound_ops: target_op_count - 1, // target_op_count is the count, operations are 0-indexed
                },
                context: context.clone(),
                resolver: target_db.clone(),
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
                new_ops.push(Fixed::Update(key, value));
                new_kvs.insert(key, value);
            }
            apply_ops(&mut got_db, new_ops.clone()).await;
            apply_ops(&mut *target_db.write().await, new_ops).await;
            got_db.commit().await.unwrap();
            target_db.write().await.commit().await.unwrap();

            // Verify that the databases match
            for (key, value) in &new_kvs {
                let got_value = got_db.get(key).await.unwrap().unwrap();
                let target_value = target_db.read().await.get(key).await.unwrap().unwrap();
                assert_eq!(got_value, target_value);
                assert_eq!(got_value, *value);
            }

            let final_target_root = target_db.write().await.root(&mut hasher);
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
                resolver: Arc::new(commonware_runtime::RwLock::new(target_db)),
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
                resolver: Arc::new(commonware_runtime::RwLock::new(target_db)),
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
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                db_config: sync_db_config, // Use same config as before
                fetch_batch_size: NZU64!(10),
                target: SyncTarget {
                    root,
                    lower_bound_ops,
                    upper_bound_ops,
                },
                context: context.clone(),
                resolver: target_db.clone(),
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
            Arc::try_unwrap(target_db)
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

    /// Test case structure for find_next_gap tests
    #[derive(Debug)]
    struct FindNextGapTestCase {
        lower_bound: u64,
        upper_bound: u64,
        fetched_ops: Vec<(u64, usize)>, // (start location, num_operations)
        requested_ops: Vec<u64>,
        fetch_batch_size: u64,
        expected: Option<(u64, u64)>,
    }

    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((0, 10)),
    }; "empty_state_full_range")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 10,
        upper_bound: 5,
        fetched_ops: vec![],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: None,
    }; "invalid_bounds")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 5,
        upper_bound: 5,
        fetched_ops: vec![],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((5, 5)),
    }; "zero_length_range")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![],
        requested_ops: vec![0, 3, 8],
        fetch_batch_size: 5,
        expected: None,
    }; "overlapping_outstanding_requests")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![],
        requested_ops: vec![8],
        fetch_batch_size: 5,
        expected: Some((0, 7)),
    }; "outstanding_request_beyond_upper_bound")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![],
        requested_ops: vec![0, 7],
        fetch_batch_size: 4,
        expected: Some((4, 6)),
    }; "outstanding_requests_only")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![(0, 1), (2, 1), (4, 1)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((1, 1)),
    }; "single_ops_with_gaps")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![(0, 3)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((3, 10)),
    }; "multi_op_batch_gap_after")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![(0, 1), (1, 1)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((2, 10)),
    }; "adjacent_single_ops")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![(0, 1), (1, 1), (2, 1), (3, 1), (4, 1), (5, 1), (6, 1), (7, 1), (8, 1), (9, 1), (10, 1)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: None,
    }; "no_gaps_all_covered_by_fetched_ops")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![],
        requested_ops: vec![2, 5, 8],
        fetch_batch_size: 1,
        expected: Some((0, 1)),
    }; "fetch_batch_size_one")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 5,
        upper_bound: 10,
        fetched_ops: vec![(0, 8)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((8, 10)),
    }; "fetched_ops_starts_before_lower_bound")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 6,
        fetched_ops: vec![(4, 5)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((0, 3)),
    }; "fetched_ops_extends_beyond_upper_bound")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 5,
        fetched_ops: vec![],
        requested_ops: vec![2],
        fetch_batch_size: 100,
        expected: Some((0, 1)),
    }; "fetch_batch_size_larger_than_range")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![(0, 5), (8, 3)],
        requested_ops: vec![],
        fetch_batch_size: 5,
        expected: Some((5, 7)),
    }; "coverage_exactly_reaches_upper_bound")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 15,
        fetched_ops: vec![(2, 3), (10, 2)],
        requested_ops: vec![6, 13],
        fetch_batch_size: 3,
        expected: Some((0, 1)),
    }; "mixed_coverage_gap_at_start")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 15,
        fetched_ops: vec![(0, 2), (8, 2)],
        requested_ops: vec![3, 12],
        fetch_batch_size: 4,
        expected: Some((2, 2)),
    }; "mixed_coverage_gap_in_middle")]
    #[test_case(FindNextGapTestCase {
        lower_bound: 0,
        upper_bound: 10,
        fetched_ops: vec![(1, 2), (6, 2)],
        requested_ops: vec![3, 8],
        fetch_batch_size: 2,
        expected: Some((0, 0)),
    }; "mixed_coverage_interleaved_ranges")]
    fn test_find_next_gap(test_case: FindNextGapTestCase) {
        // Create verified batches from input
        let mut verified_batches: BTreeMap<u64, Vec<Fixed<Digest, Digest>>> = BTreeMap::new();
        for (loc, num_ops) in &test_case.fetched_ops {
            let ops = (0..*num_ops)
                .map(|i| {
                    Fixed::Update(
                        Digest::from([i as u8; 32]),
                        Digest::from([(i + 1) as u8; 32]),
                    )
                })
                .collect();
            verified_batches.insert(*loc, ops);
        }

        // Create outstanding requests from input
        let outstanding_requests: BTreeSet<u64> = test_case.requested_ops.into_iter().collect();

        let result = find_next_gap::<Digest, Digest>(
            test_case.lower_bound,
            test_case.upper_bound,
            &verified_batches,
            &outstanding_requests,
            test_case.fetch_batch_size,
        );

        assert_eq!(result, test_case.expected);
    }

    /// Test that the client fails to sync if the lower bound is decreased
    #[test_traced("WARN")]
    fn test_target_update_lower_bound_decrease() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(50);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = create_test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(5),
                target: SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };
            let client = Client::new(config).await.unwrap();

            // Send target update with decreased lower bound
            update_sender
                .send(SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound.saturating_sub(1),
                    upper_bound_ops: initial_upper_bound.saturating_add(1),
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(result, Err(Error::SyncTargetMovedBackward { .. })));

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client fails to sync if the upper bound is decreased
    #[test_traced("WARN")]
    fn test_target_update_upper_bound_decrease() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(50);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = create_test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(5),
                target: SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };
            let client = Client::new(config).await.unwrap();

            // Send target update with decreased upper bound
            update_sender
                .send(SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound.saturating_add(1),
                    upper_bound_ops: initial_upper_bound.saturating_sub(1),
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(result, Err(Error::SyncTargetMovedBackward { .. })));

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client succeeds when bounds are updated to a stale range
    #[test_traced("WARN")]
    fn test_target_update_bounds_increase() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(100);
            apply_ops(&mut target_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture final target state
            let mut hasher = create_test_hasher();
            let final_lower_bound = target_db.inactivity_floor_loc;
            let final_upper_bound = target_db.op_count() - 1;
            let final_root = target_db.root(&mut hasher);

            // Create client with placeholder initial target (stale compared to final target)
            let (mut update_sender, update_receiver) = mpsc::channel(1);

            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(10),
                target: SyncTarget {
                    root: Digest::from([1u8; 32]),
                    lower_bound_ops: 1,
                    upper_bound_ops: 10,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };
            let client = Client::new(config).await.unwrap();

            // Send target update with increased bounds
            let _ = update_sender
                .send(SyncTarget {
                    root: final_root,
                    lower_bound_ops: final_lower_bound,
                    upper_bound_ops: final_upper_bound,
                })
                .await;

            // Complete sync with updated target
            let synced_db = client.sync().await.unwrap();

            // Verify the synced database has the expected state
            let mut hasher = create_test_hasher();
            assert_eq!(synced_db.root(&mut hasher), final_root);
            assert_eq!(synced_db.op_count(), final_upper_bound + 1);
            assert_eq!(synced_db.inactivity_floor_loc, final_lower_bound);
            assert_eq!(synced_db.oldest_retained_loc().unwrap(), final_lower_bound);

            synced_db.destroy().await.unwrap();

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client fails to sync with invalid bounds (lower > upper)
    #[test_traced("WARN")]
    fn test_target_update_invalid_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(50);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = create_test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Create client with initial target
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(5),
                target: SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };
            let client = Client::new(config).await.unwrap();

            // Send target update with invalid bounds (lower > upper)
            let _ = update_sender
                .send(SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_upper_bound, // Greater than upper bound
                    upper_bound_ops: initial_lower_bound, // Less than lower bound
                })
                .await;

            let result = client.step().await;
            assert!(matches!(result, Err(Error::InvalidTarget { .. })));

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that sync completes successfully when target is already available
    #[test_traced("WARN")]
    fn test_target_update_on_done_client() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(10);
            apply_ops(&mut target_db, target_ops).await;
            target_db.commit().await.unwrap();

            // Capture target state
            let mut hasher = create_test_hasher();
            let lower_bound = target_db.inactivity_floor_loc;
            let upper_bound = target_db.op_count() - 1;
            let root = target_db.root(&mut hasher);

            // Create client with target that will complete immediately
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(20),
                target: SyncTarget {
                    root,
                    lower_bound_ops: lower_bound,
                    upper_bound_ops: upper_bound,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };

            // Complete the sync
            let client = Client::new(config).await.unwrap();
            let synced_db = client.sync().await.unwrap();

            // Attempt to apply a target update after sync is complete to verify
            // we don't panic
            let _ = update_sender
                .send(SyncTarget {
                    // Dummy target update
                    root: Digest::from([2u8; 32]),
                    lower_bound_ops: lower_bound + 1,
                    upper_bound_ops: upper_bound + 1,
                })
                .await;

            // Verify the synced database has the expected state
            let mut hasher = create_test_hasher();
            assert_eq!(synced_db.root(&mut hasher), root);
            assert_eq!(synced_db.op_count(), upper_bound + 1);
            assert_eq!(synced_db.inactivity_floor_loc, lower_bound);
            assert_eq!(synced_db.oldest_retained_loc().unwrap(), lower_bound);

            synced_db.destroy().await.unwrap();

            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
        });
    }

    /// Test that the client can handle target updates during sync execution
    #[test_case(1, 1)]
    #[test_case(1, 2)]
    #[test_case(1, 100)]
    #[test_case(2, 1)]
    #[test_case(2, 2)]
    #[test_case(2, 100)]
    // Regression test: panicked when we didn't set pinned nodes after updating target
    #[test_case(20, 10)]
    #[test_case(100, 1)]
    #[test_case(100, 2)]
    #[test_case(100, 100)]
    #[test_case(100, 1000)]
    #[test_traced("WARN")]
    fn test_target_update_during_sync(initial_ops: usize, additional_ops: usize) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate target database with initial operations
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(initial_ops);
            apply_ops(&mut target_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture initial target state
            let mut hasher = create_test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Wrap target database for shared mutable access
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));

            // Create client with initial target and small batch size
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(1), // Small batch size so we don't finish after one batch
                target: SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };

            // Step the client to process a batch
            let client = {
                let mut client = Client::new(config).await.unwrap();
                loop {
                    // Step the client until we have processed a batch of operations
                    client = match client.step().await.unwrap() {
                        StepResult::Continue(new_client) => new_client,
                        StepResult::Complete(_) => panic!("client should not be complete"),
                    };
                    let log_size = client.log.size().await.unwrap();
                    if log_size > initial_lower_bound {
                        break client;
                    }
                }
            };

            // Modify the target database by adding more operations
            let additional_ops = create_test_ops(additional_ops);
            let new_root = {
                let mut db = target_db.write().await;
                apply_ops(&mut db, additional_ops).await;
                db.commit().await.unwrap();

                // Capture new target state
                let mut hasher = create_test_hasher();
                let new_lower_bound = db.inactivity_floor_loc;
                let new_upper_bound = db.op_count() - 1;
                let new_root = db.root(&mut hasher);

                // Send target update with new target
                update_sender
                    .send(SyncTarget {
                        root: new_root,
                        lower_bound_ops: new_lower_bound,
                        upper_bound_ops: new_upper_bound,
                    })
                    .await
                    .unwrap();

                new_root
            };

            // Complete the sync
            let synced_db = client.sync().await.unwrap();

            // Verify the synced database has the expected final state
            let mut hasher = create_test_hasher();
            assert_eq!(synced_db.root(&mut hasher), new_root);

            // Verify the target database matches the synced database
            let target_db = match Arc::try_unwrap(target_db) {
                Ok(rw_lock) => rw_lock.into_inner(),
                Err(_) => panic!("Failed to unwrap Arc - still has references"),
            };
            {
                assert_eq!(synced_db.op_count(), target_db.op_count());
                assert_eq!(
                    synced_db.inactivity_floor_loc,
                    target_db.inactivity_floor_loc
                );
                assert_eq!(
                    synced_db.oldest_retained_loc().unwrap(),
                    target_db.inactivity_floor_loc
                );
                assert_eq!(synced_db.root(&mut hasher), target_db.root(&mut hasher));
            }

            // Verify the expected operations are present in the synced database.
            for i in synced_db.inactivity_floor_loc..synced_db.op_count() {
                let got = synced_db.log.read(i).await.unwrap();
                let expected = target_db.log.read(i).await.unwrap();
                assert_eq!(got, expected);
            }
            for i in synced_db.ops.oldest_retained_pos().unwrap()..synced_db.ops.size() {
                let got = synced_db.ops.get_node(i).await.unwrap();
                let expected = target_db.ops.get_node(i).await.unwrap();
                assert_eq!(got, expected);
            }

            synced_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Test that the client can handle target updates with the same lower bound.
    #[test_traced("WARN")]
    fn test_target_same_lower_bound() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate a larger target database to ensure pruning occurs
            let mut target_db = create_test_db(context.clone()).await;
            let initial_ops = create_test_ops(100);
            apply_ops(&mut target_db, initial_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture the state after first commit (this will have a non-zero inactivity floor)
            let mut hasher = create_test_hasher();
            let initial_lower_bound = target_db.inactivity_floor_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Add more operations to create the extended target
            let additional_ops = create_test_ops(50);
            apply_ops(&mut target_db, additional_ops).await;
            target_db.commit().await.unwrap();
            let final_upper_bound = target_db.op_count() - 1;
            let final_root = target_db.root(&mut hasher);

            // Wrap target database for shared mutable access
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));

            // Create client with initial smaller target and very small batch size
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let config = Config {
                context: context.clone(),
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(2), // Very small batch size to ensure multiple batches needed
                target: SyncTarget {
                    root: initial_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: initial_upper_bound,
                },
                resolver: target_db.clone(),
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_receiver: Some(update_receiver),
            };

            // Step the client to process a batch
            let client = {
                let mut client = Client::new(config).await.unwrap();
                loop {
                    // Step the client until we have processed a batch of operations
                    client = match client.step().await.unwrap() {
                        StepResult::Continue(new_client) => new_client,
                        StepResult::Complete(_) => panic!("client should not be complete"),
                    };
                    let log_size = client.log.size().await.unwrap();
                    if log_size > initial_lower_bound {
                        break client;
                    }
                }
            };

            // Send target update with SAME lower bound but higher upper bound
            update_sender
                .send(SyncTarget {
                    root: final_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: final_upper_bound,
                })
                .await
                .unwrap();

            // Complete the sync
            let synced_db = client.sync().await.unwrap();

            // Verify the synced database has the expected final state
            let mut hasher = create_test_hasher();
            assert_eq!(synced_db.root(&mut hasher), final_root);

            // Verify the target database matches the synced database
            let target_db = match Arc::try_unwrap(target_db) {
                Ok(rw_lock) => rw_lock.into_inner(),
                Err(_) => panic!("Failed to unwrap Arc - still has references"),
            };

            assert_eq!(synced_db.op_count(), target_db.op_count());
            assert_eq!(
                synced_db.inactivity_floor_loc,
                target_db.inactivity_floor_loc
            );
            assert_eq!(
                synced_db.oldest_retained_loc(),
                target_db.oldest_retained_loc()
            );
            assert_eq!(
                synced_db.oldest_retained_loc().unwrap(),
                initial_lower_bound
            );
            assert_eq!(synced_db.root(&mut hasher), target_db.root(&mut hasher));

            // Verify the expected operations are present in the synced database.
            for i in synced_db.inactivity_floor_loc..synced_db.op_count() {
                let got = synced_db.log.read(i).await.unwrap();
                let expected = target_db.log.read(i).await.unwrap();
                assert_eq!(got, expected);
            }
            for i in synced_db.ops.oldest_retained_pos().unwrap()..synced_db.ops.size() {
                let got = synced_db.ops.get_node(i).await.unwrap();
                let expected = target_db.ops.get_node(i).await.unwrap();
                assert_eq!(got, expected);
            }

            synced_db.destroy().await.unwrap();
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
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = Config {
                db_config: db_config.clone(),
                fetch_batch_size: NZU64!(5),
                target: SyncTarget {
                    root: target_root,
                    lower_bound_ops: lower_bound,
                    upper_bound_ops: upper_bound,
                },
                context,
                resolver: target_db.clone(),
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
            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .into_inner()
                .destroy()
                .await
                .unwrap();
            reopened_db.destroy().await.unwrap();
        });
    }
}
