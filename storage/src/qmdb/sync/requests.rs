//! Manages outstanding fetch requests

use crate::{mmr::Location, qmdb::sync::engine::IndexedFetchResult};
use commonware_cryptography::Digest;
use futures::stream::FuturesUnordered;
use std::{collections::BTreeSet, future::Future, pin::Pin};

/// Manages outstanding fetch requests
pub(super) struct Requests<Op, D: Digest, E> {
    /// Futures that will resolve to batches of operations
    #[allow(clippy::type_complexity)]
    futures: FuturesUnordered<Pin<Box<dyn Future<Output = IndexedFetchResult<Op, D, E>> + Send>>>,
    /// Start locations of outstanding requests.
    /// A subset of the futures: entries are removed when a request completes
    /// or is discarded, but the corresponding future remains in `futures`
    /// (removing from FuturesUnordered is expensive).
    locations: BTreeSet<Location>,
}

impl<Op, D: Digest, E> Requests<Op, D, E> {
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
        start_loc: Location,
        future: Pin<Box<dyn Future<Output = IndexedFetchResult<Op, D, E>> + Send>>,
    ) {
        self.locations.insert(start_loc);
        self.futures.push(future);
    }

    /// Remove a request from `self.locations` by its starting location.
    /// Returns `true` if the request was tracked, `false` otherwise.
    /// Doesn't remove from `self.futures` as it would be expensive.
    pub fn remove(&mut self, start_loc: Location) -> bool {
        self.locations.remove(&start_loc)
    }

    /// Remove all tracked locations before `loc`, keeping those >= `loc`.
    /// Futures remain in the stream; when they complete, the caller can detect
    /// they are untracked via the `false` return from [`Self::remove`].
    pub fn remove_before(&mut self, loc: Location) {
        self.locations = self.locations.split_off(&loc);
    }

    /// Get the set of outstanding request locations
    pub const fn locations(&self) -> &BTreeSet<Location> {
        &self.locations
    }

    /// Get a mutable reference to the futures stream
    #[allow(clippy::type_complexity)]
    pub fn futures_mut(
        &mut self,
    ) -> &mut FuturesUnordered<Pin<Box<dyn Future<Output = IndexedFetchResult<Op, D, E>> + Send>>>
    {
        &mut self.futures
    }

    /// Get the number of outstanding requests
    pub fn len(&self) -> usize {
        self.locations.len()
    }
}

impl<Op, D: Digest, E> Default for Requests<Op, D, E> {
    fn default() -> Self {
        Self::new()
    }
}
