//! Manages outstanding fetch requests with monotonically increasing request IDs.
//!
//! Each request is assigned a unique ID and remembers the request it was issued
//! for, letting the engine validate replies against what was actually asked.
//! Removing a request aborts its future.

use crate::{
    merkle::{Family, Location},
    qmdb::sync::{engine::IndexedFetchResult, source::Request},
};
use commonware_cryptography::Digest;
use commonware_utils::futures::{AbortablePool, Aborter};
use futures::future::Aborted;
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
};

/// Unique identifier for a fetch request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct Id(u64);

/// Mutable request state kept while the request is still tracked.
struct TrackedRequest<F: Family> {
    request: Request<F>,
    _aborter: Aborter,
}

/// Manages outstanding fetch requests.
pub(super) struct Requests<F: Family, Op, D: Digest, E> {
    /// Futures that will resolve to fetch results.
    futures: AbortablePool<IndexedFetchResult<F, Op, D, E>>,

    /// Counter for assigning unique request IDs.
    next_id: u64,

    /// Active requests keyed by ID. Removing an entry drops its [`Aborter`],
    /// which aborts and drops the request's future.
    tracked: HashMap<Id, TrackedRequest<F>>,

    /// Reverse index from location to request ID, for gap detection.
    by_location: BTreeMap<Location<F>, Id>,
}

impl<F: Family, Op: Send, D: Digest, E: Send> Requests<F, Op, D, E> {
    pub fn new() -> Self {
        Self {
            futures: AbortablePool::default(),
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
    /// exists at the same start, the old one is superseded and aborted.
    ///
    /// Panics if the request asks for pins anywhere but its start: the engine verifies pins
    /// at the range start, so answering such a request honestly would read as peer-invalid.
    pub fn insert(
        &mut self,
        id: Id,
        request: Request<F>,
        future: impl Future<Output = IndexedFetchResult<F, Op, D, E>> + Send + 'static,
    ) {
        assert!(
            request
                .retain_from
                .is_none_or(|boundary| boundary == request.start),
            "engine requests pins only at the range start"
        );
        if let Some(old_id) = self.by_location.insert(request.start, id) {
            self.tracked.remove(&old_id);
        }
        let aborter = self.futures.push(future);
        self.tracked.insert(
            id,
            TrackedRequest {
                request,
                _aborter: aborter,
            },
        );
    }

    /// Complete a request by ID. Returns the request it was tracking, if any.
    pub fn remove(&mut self, id: Id) -> Option<Request<F>> {
        let TrackedRequest { request, .. } = self.tracked.remove(&id)?;
        // Only remove from by_location if it still points to this ID.
        // A newer request may have superseded this location.
        if self.by_location.get(&request.start) == Some(&id) {
            self.by_location.remove(&request.start);
        }
        Some(request)
    }

    /// Remove all requests at locations before `loc`, aborting their futures.
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

    /// Resolves to the next fetch result, or [`Aborted`] if the request was cancelled.
    /// Never resolves while no requests are outstanding.
    pub async fn next_completed(&mut self) -> Result<IndexedFetchResult<F, Op, D, E>, Aborted> {
        self.futures.next_completed().await
    }

    /// Get the number of outstanding requests, not including aborted ones.
    pub fn len(&self) -> usize {
        self.tracked.len()
    }
}

impl<F: Family, Op: Send, D: Digest, E: Send> Default for Requests<F, Op, D, E> {
    fn default() -> Self {
        Self::new()
    }
}
