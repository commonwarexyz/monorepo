//! Sync-facing journal wrapper for the Immutable database.
//!
//! - Sync engine uses `size` and `append` to update the journal.
//! - This wrapper tracks a synthetic global `size` (next append location) and maps it to
//!   sections via `items_per_section` when appending.
//! - Callers must prepare the variable journal (e.g., `init_sync`) and compute the initial
//!   `size` from a replay that considers only `[range.start, range.end)`.
//! - No pruning/bound checks are done here; the sync engine handles range validation.

use crate::{
    adb::{operation::variable::Operation, sync},
    journal::variable,
};
use commonware_codec::Codec;
use commonware_runtime::{Metrics, Storage};
use commonware_utils::Array;
use std::num::NonZeroU64;

/// Wraps a [variable::Journal] to provide a sync-compatible interface.
/// Namely, it provides a `size` method that returns the number of operations in the journal,
/// and an `append` method that appends an operation to the journal. These are used by the
/// sync engine to populate the journal with data from the target database.
pub struct Journal<E, K, V>
where
    E: Storage + Metrics,
    K: Array,
    V: Codec,
{
    /// Underlying variable journal storing the operations.
    inner: variable::Journal<E, Operation<K, V>>,

    /// Logical operations per storage section.
    items_per_section: NonZeroU64,

    /// Logical next append location (number of ops present).
    /// Invariant: computed by caller so `range.start <= size <= range.end`
    /// for the sync range.
    size: u64,
}

impl<E, K, V> Journal<E, K, V>
where
    E: Storage + Metrics,
    K: Array,
    V: Codec,
{
    /// Create a new sync-compatible [Journal].
    ///
    /// # Arguments
    /// * `inner` - The wrapped [variable::Journal], whose logical last operation location is
    ///   `size - 1`.
    /// * `items_per_section` - Operations per section.
    /// * `size` - Logical next append location to report.
    pub fn new(
        inner: variable::Journal<E, Operation<K, V>>,
        items_per_section: NonZeroU64,
        size: u64,
    ) -> Self {
        Self {
            inner,
            items_per_section,
            size,
        }
    }

    /// Return the inner [variable::Journal].
    pub fn into_inner(self) -> variable::Journal<E, Operation<K, V>> {
        self.inner
    }
}

impl<E, K, V> sync::Journal for Journal<E, K, V>
where
    E: Storage + Metrics,
    K: Array,
    V: Codec,
{
    type Op = Operation<K, V>;
    type Error = crate::journal::Error;

    async fn size(&self) -> Result<u64, Self::Error> {
        Ok(self.size)
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        let section = self.size / self.items_per_section;
        self.inner.append(section, op).await?;
        self.size += 1;
        if self.size > 0 && self.size % self.items_per_section == 0 {
            // Sync this full section before appending to the next section.
            // TODO(#1718): Migrate to the new contiguous variable journal type, which will handle section
            // calculation and syncing internally.
            self.inner.sync(section).await?;
        }
        Ok(())
    }
}
