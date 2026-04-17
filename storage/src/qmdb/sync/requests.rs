//! Manages outstanding fetch requests with monotonically increasing request IDs.
//!
//! Each request is assigned a unique ID when added. This prevents stale futures
//! from colliding with fresh requests at the same location after a target update.

use crate::{
    merkle::{Family, Location},
    qmdb::sync::engine::IndexedFetchResult,
};
use commonware_cryptography::Digest;
use commonware_utils::channel::oneshot;
use futures::stream::FuturesUnordered;
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    pin::Pin,
};

/// Unique identifier for a fetch request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct Id(u64);

/// Manages outstanding fetch requests.
pub(super) struct Requests<F: Family, Op, D: Digest, E> {
    /// Futures that will resolve to fetch results.
    #[allow(clippy::type_complexity)]
    futures:
        FuturesUnordered<Pin<Box<dyn Future<Output = IndexedFetchResult<F, Op, D, E>> + Send>>>,

    /// Counter for assigning unique request IDs.
    next_id: u64,

    /// Active requests keyed by ID. Removing an entry drops the cancel sender,
    /// causing the resolver's `cancel_rx.await` to return `Err`.
    tracked: HashMap<Id, (Location<F>, oneshot::Sender<()>)>,

    /// Reverse index from location to request ID, for gap detection.
    by_location: BTreeMap<Location<F>, Id>,
}

impl<F: Family, Op, D: Digest, E> Requests<F, Op, D, E> {
    pub fn new() -> Self {
        Self {
            futures: FuturesUnordered::new(),
            next_id: 0,
            tracked: HashMap::new(),
            by_location: BTreeMap::new(),
        }
    }

    /// Allocate the next request ID. Use with [`Self::insert`] after building
    /// the future that embeds this ID.
    pub const fn next_id(&mut self) -> Id {
        let id = Id(self.next_id);
        self.next_id += 1;
        id
    }

    /// Register a request with a previously allocated ID. If a request already
    /// exists at `start_loc`, the old one is superseded (its cancel sender is
    /// dropped and its future will be discarded when it completes).
    #[allow(clippy::type_complexity)]
    pub fn insert(
        &mut self,
        id: Id,
        start_loc: Location<F>,
        cancel_tx: oneshot::Sender<()>,
        future: Pin<Box<dyn Future<Output = IndexedFetchResult<F, Op, D, E>> + Send>>,
    ) {
        if let Some(old_id) = self.by_location.insert(start_loc, id) {
            self.tracked.remove(&old_id);
        }
        self.tracked.insert(id, (start_loc, cancel_tx));
        self.futures.push(future);
    }

    /// Complete a request by ID. Returns `true` if it was tracked.
    pub fn remove(&mut self, id: Id) -> bool {
        if let Some((loc, _cancel_tx)) = self.tracked.remove(&id) {
            // Only remove from by_location if it still points to this ID.
            // A newer request may have superseded this location.
            if self.by_location.get(&loc) == Some(&id) {
                self.by_location.remove(&loc);
            }
            true
        } else {
            false
        }
    }

    /// Remove all requests at locations before `loc`. Dropped cancel senders
    /// signal resolvers to abort.
    pub fn remove_before(&mut self, loc: Location<F>) {
        let keep = self.by_location.split_off(&loc);
        for id in self.by_location.values() {
            self.tracked.remove(id);
        }
        self.by_location = keep;
    }

    /// Iterate over outstanding request locations in ascending order.
    pub fn locations(&self) -> impl Iterator<Item = &Location<F>> {
        self.by_location.keys()
    }

    /// Check if a location has an outstanding request.
    pub fn contains(&self, loc: &Location<F>) -> bool {
        self.by_location.contains_key(loc)
    }

    /// Get a mutable reference to the futures stream.
    #[allow(clippy::type_complexity)]
    pub fn futures_mut(
        &mut self,
    ) -> &mut FuturesUnordered<Pin<Box<dyn Future<Output = IndexedFetchResult<F, Op, D, E>> + Send>>>
    {
        &mut self.futures
    }

    /// Get the number of outstanding requests
    pub fn len(&self) -> usize {
        self.tracked.len()
    }
}

impl<F: Family, Op, D: Digest, E> Default for Requests<F, Op, D, E> {
    fn default() -> Self {
        Self::new()
    }
}
