//! Tracks the journal size proven durable.

use super::blobs::SyncCompletion;
use futures::FutureExt as _;

/// The highest size whose covering sync has been observed to complete successfully.
///
/// The tracked value advances only on observed success, so it is always safe to persist as a
/// recovery watermark without ordering against in-flight syncs (see "Watermark advancement" in
/// [super::fixed]).
pub(super) struct DurableSize {
    /// The highest proven size.
    proven: u64,

    /// The size covered by the last started sync and its shared completion, until its outcome
    /// is observed.
    pending: Option<(u64, SyncCompletion)>,
}

impl DurableSize {
    /// Create a tracker with `proven` size.
    pub(super) const fn new(proven: u64) -> Self {
        Self {
            proven,
            pending: None,
        }
    }

    /// The highest proven size.
    pub(super) const fn proven(&self) -> u64 {
        self.proven
    }

    /// Observe the outcome of the last started sync without blocking: on success, advance the
    /// proven size. A failure is discarded here — the blob layer retains it and resurfaces it
    /// on the next durability operation.
    pub(super) fn observe(&mut self) {
        let Some((size, completion)) = &self.pending else {
            return;
        };
        let Some(result) = completion.clone().now_or_never() else {
            return;
        };
        if result.is_ok() {
            self.proven = self.proven.max(*size);
        }
        self.pending = None;
    }

    /// Record that all items below `size` were proven durable, discarding any pending
    /// observation it supersedes.
    pub(super) fn prove(&mut self, size: u64) {
        self.proven = self.proven.max(size);
        if matches!(self.pending, Some((pending, _)) if pending <= size) {
            self.pending = None;
        }
    }

    /// Track a started sync covering `size` until its outcome is observed.
    pub(super) fn record(&mut self, size: u64, completion: SyncCompletion) {
        self.pending = Some((size, completion));
    }

    /// Lower the proven size to at most `size` after a shrink, discarding any pending
    /// observation.
    pub(super) fn truncate(&mut self, size: u64) {
        self.proven = self.proven.min(size);
        self.pending = None;
    }
}
