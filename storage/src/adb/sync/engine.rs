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

/// Trait for journals that support sync operations
pub trait SyncJournal {
    type Op;
    type Error: Send + 'static;

    /// Get the current size (number of operations) in the journal
    fn size(&self) -> impl Future<Output = Result<u64, Self::Error>>;

    /// Append an operation to the journal
    fn append(&mut self, op: Self::Op) -> impl Future<Output = Result<(), Self::Error>>;
}

/// Result of executing one sync step
#[derive(Debug)]
pub enum StepResult<C, D> {
    /// Sync should continue with the updated client
    Continue(C),
    /// Sync is complete with the final database
    Complete(D),
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

/// Validate a target update against the current target
pub fn validate_target_update<D: Digest>(
    old_target: &SyncTarget<D>,
    new_target: &SyncTarget<D>,
) -> Result<(), String> {
    if new_target.lower_bound_ops > new_target.upper_bound_ops {
        return Err(format!(
            "Invalid target: lower_bound {} > upper_bound {}",
            new_target.lower_bound_ops, new_target.upper_bound_ops
        ));
    }

    if new_target.lower_bound_ops < old_target.lower_bound_ops
        || new_target.upper_bound_ops < old_target.upper_bound_ops
    {
        return Err(format!(
            "Sync target moved backward: old bounds [{}, {}], new bounds [{}, {}]",
            old_target.lower_bound_ops,
            old_target.upper_bound_ops,
            new_target.lower_bound_ops,
            new_target.upper_bound_ops
        ));
    }

    if new_target.root == old_target.root {
        return Err("Sync target root unchanged".to_string());
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
            let fetch_result = result.ok_or(crate::adb::sync::error::SyncError::SyncStalled)?;
            Ok(SyncEvent::BatchReceived(fetch_result))
        },
    }
}

/// A shared sync engine that manages the core synchronization state and operations.
///
/// This engine handles the common sync logic that can be reused across different
/// ADB implementations (Any, Immutable, Current).
pub struct SyncEngine<J, R, D, E>
where
    J: SyncJournal,
    D: Digest,
{
    /// Tracks outstanding fetch requests and their futures
    pub outstanding_requests: OutstandingRequests<J::Op, D, E>,

    /// Operations that have been fetched but not yet applied to the log
    pub fetched_operations: BTreeMap<u64, Vec<J::Op>>,

    /// Pinned MMR nodes extracted from proofs, used for database construction
    pub pinned_nodes: Option<Vec<D>>,

    /// The current sync target (root digest and operation bounds)
    pub target: SyncTarget<D>,

    /// Maximum number of parallel outstanding requests
    pub max_outstanding_requests: usize,

    /// Maximum operations to fetch in a single batch
    pub fetch_batch_size: NonZeroU64,

    /// Journal that operations are applied to during sync
    pub journal: J,

    /// Resolver for fetching operations and proofs from the sync source
    pub resolver: R,
}

impl<J, R, D, E> SyncEngine<J, R, D, E>
where
    J: SyncJournal<Error = E>,
    J::Op: Clone + Send + 'static,
    R: crate::adb::sync::resolver::Resolver<Digest = D, Op = J::Op>,
    D: Digest + Clone,
    E: Send + 'static + From<crate::adb::any::sync::Error>,
{
    /// Create a new sync engine with the given configuration
    pub fn new(
        journal: J,
        resolver: R,
        target: SyncTarget<D>,
        max_outstanding_requests: usize,
        fetch_batch_size: NonZeroU64,
    ) -> Self {
        Self {
            outstanding_requests: OutstandingRequests::new(),
            fetched_operations: BTreeMap::new(),
            pinned_nodes: None,
            target,
            max_outstanding_requests,
            fetch_batch_size,
            journal,
            resolver,
        }
    }

    /// Schedule new fetch requests based on gap analysis and request limits.
    ///
    /// This method implements the core request scheduling logic that can be used
    /// across different ADB sync implementations.
    pub async fn schedule_requests(&mut self) -> Result<(), E> {
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
                        .map_err(E::from);
                    IndexedFetchResult { start_loc, result }
                }),
            );
        }

        // Calculate the maximum number of requests to make
        let num_requests = self
            .max_outstanding_requests
            .saturating_sub(self.outstanding_requests.len());

        let log_size = self.journal.size().await?;

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
                        .map_err(E::from);
                    IndexedFetchResult { start_loc, result }
                }),
            );
        }

        Ok(())
    }

    /// Clear all sync state for a target update
    pub fn reset_for_target_update(&mut self, new_target: SyncTarget<D>) {
        self.target = new_target;
        self.fetched_operations.clear();
        self.outstanding_requests.clear();
        self.pinned_nodes = None;
    }

    /// Store a batch of fetched operations
    pub fn store_operations(&mut self, start_loc: u64, operations: Vec<J::Op>) {
        self.fetched_operations.insert(start_loc, operations);
    }

    /// Check if we have pinned nodes
    pub fn has_pinned_nodes(&self) -> bool {
        self.pinned_nodes.is_some()
    }

    /// Set pinned nodes from a proof
    pub fn set_pinned_nodes(&mut self, nodes: Vec<D>) {
        self.pinned_nodes = Some(nodes);
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
