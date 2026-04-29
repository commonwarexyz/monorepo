//! Activity-status bitmap. Owned by [`any::Db`](super::any::db::Db) and shared with live
//! [`MerkleizedBatch`](super::current::batch::MerkleizedBatch)es via `Arc<Shared<N>>`.
//!
//! `any::Db` mutates the inner [`bitmap::Prunable`] under a [`RwLock`] during `apply_batch` /
//! `prune` / `rewind` while live batches read concurrently. Locking (not snapshotting) keeps
//! memory at O(bitmap size); snapshots would couple memory to live-batch count and lifetime.
//!
//! Reads through an invalidated `MerkleizedBatch` (see its "Branch validity" docs) return
//! inconsistent bytes; callers must drop invalid batches.

use commonware_utils::{
    bitmap::{self, Readable as _},
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

pub(crate) struct Shared<const N: usize> {
    inner: RwLock<bitmap::Prunable<N>>,
}

impl<const N: usize> Shared<N> {
    pub(crate) const fn new(bitmap: bitmap::Prunable<N>) -> Self {
        Self {
            inner: RwLock::new(bitmap),
        }
    }

    /// Acquire a shared read guard over the committed bitmap. Kept private so external callers
    /// go through [`bitmap::Readable`] (which doesn't expose a guard across `.await`).
    fn read(&self) -> RwLockReadGuard<'_, bitmap::Prunable<N>> {
        self.inner.read()
    }

    /// Acquire an exclusive write guard. By convention only the inner-`any` mutators
    /// (`apply_batch`, `prune_bitmap`, `rewind`) hold the write lock.
    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, bitmap::Prunable<N>> {
        self.inner.write()
    }

    /// Single-lock alternative to `bitmap::Readable::ones_iter_from(from).next()`.
    pub(crate) fn next_one_from(&self, from: u64) -> Option<u64> {
        self.read().ones_iter_from(from).next()
    }

    /// Return the number of pruned bits. Acquires the read lock briefly.
    #[cfg(any(test, feature = "test-traits"))]
    pub(crate) fn pruned_bits(&self) -> u64 {
        self.read().pruned_bits()
    }

    /// Return the value of the bit at `loc`. Acquires the read lock briefly.
    #[cfg(any(test, feature = "test-traits"))]
    pub(crate) fn get_bit(&self, loc: u64) -> bool {
        self.read().get_bit(loc)
    }
}

impl<const N: usize> std::fmt::Debug for Shared<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("bitmap_len", &bitmap::Readable::<N>::len(&*self.read()))
            .finish()
    }
}

/// [`bitmap::Readable`] over the DB's committed bitmap. Each call acquires the read lock briefly.
impl<const N: usize> bitmap::Readable<N> for Shared<N> {
    fn complete_chunks(&self) -> usize {
        self.read().complete_chunks()
    }

    fn get_chunk(&self, idx: usize) -> [u8; N] {
        *self.read().get_chunk(idx)
    }

    fn last_chunk(&self) -> ([u8; N], u64) {
        let guard = self.read();
        let (chunk, bits) = guard.last_chunk();
        (*chunk, bits)
    }

    fn pruned_chunks(&self) -> usize {
        self.read().pruned_chunks()
    }

    fn len(&self) -> u64 {
        bitmap::Readable::<N>::len(&*self.read())
    }
}
