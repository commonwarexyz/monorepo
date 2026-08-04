//! Tracks the barrier below which the journal is proven durable.

use crate::SyncCompletion;
use futures::FutureExt as _;

/// The size below which every item is known durable.
pub(super) struct Barrier {
    /// The highest size known to be durable.
    size: u64,

    /// The size at which the last sync was started, and its completion.
    pending: Option<(u64, SyncCompletion)>,
}

impl Barrier {
    /// Create a tracker starting at `size`.
    pub(super) const fn new(size: u64) -> Self {
        Self {
            size,
            pending: None,
        }
    }

    /// The highest proven size, observing the pending sync completion if any.
    pub(super) fn size(&mut self) -> u64 {
        self.observe();
        self.size
    }

    /// Observe the outcome of the last started sync without blocking.
    /// On success, advance the proven size.
    fn observe(&mut self) {
        let Some((size, completion)) = &self.pending else {
            return;
        };
        let Some(result) = completion.clone().now_or_never() else {
            return;
        };
        if result.is_ok() {
            self.size = self.size.max(*size);
        }

        // A failure is discarded here: the proven size simply does not advance. The layer
        // that started the sync retains the failure and resurfaces it on its next sync of
        // the failed component.
        self.pending = None;
    }

    /// Record that all items below `size` were proven durable.
    pub(super) fn mark_durable(&mut self, size: u64) {
        self.size = self.size.max(size);
        if matches!(self.pending, Some((pending, _)) if pending <= size) {
            self.pending = None;
        }
    }

    /// Track a sync started at `size` until its outcome is observed.
    pub(super) fn record(&mut self, size: u64, completion: SyncCompletion) {
        // Observe the completion of the previously tracked sync before replacing it.
        self.observe();
        self.pending = Some((size, completion));
    }

    /// Lower the proven size to at most `size` after a shrink, discarding any pending
    /// observation.
    pub(super) fn truncate(&mut self, size: u64) {
        self.size = self.size.min(size);
        self.pending = None;
    }
}
