//! Tracks a monotonic boundary below which storage is proven durable.

use crate::SyncCompletion;
use futures::FutureExt as _;

/// The boundary below which every item is known durable.
pub(crate) struct Barrier {
    /// The highest boundary known to be durable.
    boundary: u64,

    /// The boundary captured by the last sync, and its completion.
    pending: Option<(u64, SyncCompletion)>,
}

impl Barrier {
    /// Create a tracker starting at `boundary`.
    pub(crate) const fn new(boundary: u64) -> Self {
        Self {
            boundary,
            pending: None,
        }
    }

    /// The highest proven boundary, observing the pending sync completion if any.
    pub(crate) fn boundary(&mut self) -> u64 {
        self.observe();
        self.boundary
    }

    /// Observe the outcome of the last started sync without blocking.
    fn observe(&mut self) {
        let Some((boundary, completion)) = &mut self.pending else {
            return;
        };
        let Some(result) = completion.now_or_never() else {
            return;
        };
        if result.is_ok() {
            self.boundary = self.boundary.max(*boundary);
        }

        // The layer that started a failed sync owns surfacing the failure. A failed observation
        // cannot advance this proof, so retaining it here would add no information.
        self.pending = None;
    }

    /// Whether no recorded sync remains unobserved.
    ///
    /// Call [Self::boundary] first to observe a completion that already resolved.
    pub(crate) const fn settled(&self) -> bool {
        self.pending.is_none()
    }

    /// Record that everything below `boundary` was proven durable.
    pub(crate) fn mark_durable(&mut self, boundary: u64) {
        self.boundary = self.boundary.max(boundary);
        if matches!(self.pending, Some((pending, _)) if pending <= boundary) {
            self.pending = None;
        }
    }

    /// Track a sync started at `boundary` without observing its completion.
    pub(crate) fn record(&mut self, boundary: u64, completion: SyncCompletion) {
        // Preserve a completed prior proof before replacing its observer.
        self.observe();
        self.pending = Some((boundary, completion));
    }

    /// Lower the proven boundary after storage moves backward.
    pub(crate) fn truncate(&mut self, boundary: u64) {
        self.boundary = self.boundary.min(boundary);
        self.pending = None;
    }
}
