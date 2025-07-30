//! Core sync engine components that are shared across sync clients.

use crate::mmr::verification::Proof;
use commonware_cryptography::Digest;
use futures::stream::FuturesUnordered;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    future::Future,
    pin::Pin,
};

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
    /// Using Box to avoid direct tokio dependency
    pub success_tx: Box<dyn FnOnce(bool) + Send + Sync>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::sha256;
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
                    success_tx: Box::new(|_| {}),
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
            assert!(result.is_ok(),);
        } else {
            assert!(result.is_err(),);
        }
    }
}
