//! Mutations to one blob file that no completed sync covers.

use crate::Error;
use commonware_utils::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Tracks the writes to one blob file that no completed sync covers.
///
/// Shared by every handle of one open, it counts mutations requiring a full-file barrier.
/// Each sync credits only mutations completed before it began, so a mutation racing a sync
/// stays dirty. It retains the first observed durability failure so later accounting
/// cannot certify bytes the kernel already reported lost.
#[derive(Default)]
pub(crate) struct Tracker {
    written: AtomicU64,
    completed: AtomicU64,
    synced: AtomicU64,
    failed: Mutex<Option<Error>>,
    #[cfg(test)]
    skipped: AtomicU64,
}

impl Tracker {
    /// Record a mutation that needs a completed sync.
    pub(crate) fn write(&self) {
        self.written.fetch_add(1, Ordering::AcqRel);
    }

    /// Count a successful plain write or resize.
    pub(crate) fn complete(&self) {
        self.completed.fetch_add(1, Ordering::AcqRel);
    }

    /// Observe the completed writes a sync about to be issued will cover.
    pub(crate) fn begin_sync(&self) -> u64 {
        self.completed.load(Ordering::Acquire)
    }

    /// Credit a completed sync unless a durability failure was already retained.
    pub(crate) fn end_sync(&self, seen: u64) -> Result<(), Error> {
        let failed = self.failed.lock();
        if let Some(error) = failed.as_ref() {
            return Err(error.clone());
        }
        self.synced.fetch_max(seen, Ordering::AcqRel);
        Ok(())
    }

    /// Whether writes were issued that no completed sync covers.
    pub(crate) fn is_dirty(&self) -> bool {
        self.written.load(Ordering::Acquire) != self.synced.load(Ordering::Acquire)
    }

    /// Retain the first durability failure this open observed.
    pub(crate) fn poison(&self, error: &Error) {
        let mut failed = self.failed.lock();
        if failed.is_none() {
            *failed = Some(error.clone());
        }
    }

    /// The retained durability failure, if any.
    pub(crate) fn failure(&self) -> Option<Error> {
        self.failed.lock().clone()
    }
}

#[cfg(test)]
impl Tracker {
    /// Record a sync that found nothing to persist.
    ///
    /// Callers sync freely and the runtime skips the device flush when every completed
    /// mutation through the open is covered.
    pub(crate) fn skip_sync(&self) {
        self.skipped.fetch_add(1, Ordering::AcqRel);
    }

    /// Number of syncs skipped because the open was clean.
    pub(crate) fn skipped(&self) -> u64 {
        self.skipped.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synced_writes_are_clean() {
        let tracker = Tracker::default();
        assert!(!tracker.is_dirty());
        tracker.write();
        assert!(tracker.is_dirty());
        tracker.complete();
        let seen = tracker.begin_sync();
        tracker.end_sync(seen).unwrap();
        assert!(!tracker.is_dirty());
    }

    #[test]
    fn test_unlanded_write_is_not_credited() {
        let tracker = Tracker::default();
        tracker.write();

        // The sync began before the write reached the file, so it cannot cover it.
        let seen = tracker.begin_sync();
        tracker.complete();
        tracker.end_sync(seen).unwrap();
        assert!(tracker.is_dirty());
        let later = tracker.begin_sync();
        tracker.end_sync(later).unwrap();
        assert!(!tracker.is_dirty());
    }

    #[test]
    fn test_write_racing_sync_stays_dirty() {
        let tracker = Tracker::default();
        tracker.write();
        tracker.complete();
        let seen = tracker.begin_sync();
        tracker.write();
        tracker.complete();
        tracker.end_sync(seen).unwrap();
        assert!(tracker.is_dirty());

        // A sync observing both writes clears the state, and a stale completion
        // cannot regress it.
        let later = tracker.begin_sync();
        tracker.end_sync(later).unwrap();
        tracker.end_sync(seen).unwrap();
        assert!(!tracker.is_dirty());
    }

    #[test]
    fn test_first_failure_is_retained() {
        let tracker = Tracker::default();
        assert!(tracker.failure().is_none());
        tracker.poison(&Error::Closed);
        tracker.poison(&Error::ReadFailed);
        assert!(matches!(tracker.failure(), Some(Error::Closed)));
    }
}
