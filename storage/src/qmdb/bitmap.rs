//! Activity-status bitmap. Owned by [`any::Db`](super::any::db::Db) and shared with live
//! [`MerkleizedBatch`](super::current::batch::MerkleizedBatch)es via `Arc<Shared<N>>`.
//!
//! `any::Db` mutates the inner [`bitmap::Prunable`] under a [`RwLock`] during `apply_batch` /
//! `prune` while live batches read concurrently. Locking (not snapshotting) keeps memory at
//! O(bitmap size). Snapshots would couple memory to live-batch count and lifetime.
//!
//! Merkleization reads this bitmap only after binding the batch's chain to the database that owns
//! it and passing the batch-chain gate, which refuses a stale chain (see
//! [`MerkleizedBatch`](super::current::batch::MerkleizedBatch)'s "Branch validity" docs).

use crate::merkle::{Family, Location};
#[cfg(test)]
use commonware_utils::bitmap::Readable as _;
use commonware_utils::{
    bitmap,
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
    /// (`apply_batch`, `prune_bitmap`) hold the write lock.
    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, bitmap::Prunable<N>> {
        self.inner.write()
    }

    /// Single-lock alternative to `bitmap::Readable::ones_iter_from(from).next()`.
    #[cfg(test)]
    pub(crate) fn next_one_from(&self, from: u64) -> Option<u64> {
        self.read().ones_iter_from(from).next()
    }

    /// Return the number of pruned bits. Acquires the read lock briefly.
    pub(crate) fn pruned_bits(&self) -> u64 {
        self.read().pruned_bits()
    }

    /// Return the value of the bit at `loc`. Acquires the read lock briefly.
    #[cfg(any(test, feature = "test-traits"))]
    pub(crate) fn get_bit(&self, loc: u64) -> bool {
        self.read().get_bit(loc)
    }
}

/// Floor candidates in ascending location order, within and across successive fills. A source
/// yields every location that may hold an active update in the batch chain. Below the database's
/// size, it yields only locations whose activity bit is set.
pub(crate) trait Candidates<F: Family> {
    /// Append candidates in `[floor, tip)` in ascending order while `out.len() < limit`, returning
    /// the next scan location. Successive calls resume there and preserve ascending order. Below
    /// the database's size, candidates must have their activity bit set.
    fn fill(
        &mut self,
        floor: Location<F>,
        tip: u64,
        limit: usize,
        out: &mut Vec<Location<F>>,
    ) -> Location<F>;
}

impl<F: Family, const N: usize> Candidates<F> for &Shared<N> {
    fn fill(
        &mut self,
        floor: Location<F>,
        tip: u64,
        limit: usize,
        out: &mut Vec<Location<F>>,
    ) -> Location<F> {
        Location::new(fill_from(&*self.read(), *floor, tip, limit, out))
    }
}

/// A closure as a [`Candidates`] source, for tests with custom candidate sequences.
#[cfg(test)]
pub(crate) struct FnCandidates<T>(pub(crate) T);

#[cfg(test)]
impl<F: Family, T> Candidates<F> for FnCandidates<T>
where
    T: FnMut(Location<F>, u64, usize, &mut Vec<Location<F>>) -> Location<F>,
{
    fn fill(
        &mut self,
        floor: Location<F>,
        tip: u64,
        limit: usize,
        out: &mut Vec<Location<F>>,
    ) -> Location<F> {
        (self.0)(floor, tip, limit, out)
    }
}

/// Core floor candidate scan over any [`bitmap::Readable`]: set bits in
/// `[scan_from, min(len, tip))` ascending via one `ones_iter_range`, then locations in
/// `[max(scan_from, len), tip)` sequentially. Fills `out` with up to `limit` candidates and
/// returns the next `scan_from`.
///
/// The bitmap is read once per chunk (through the iterator), so a `B` whose reads go through
/// interior mutability must not be mutated for the duration of the call.
pub(crate) fn fill_from<B: bitmap::Readable<N>, T: From<u64>, const N: usize>(
    bitmap: &B,
    scan_from: u64,
    tip: u64,
    limit: usize,
    out: &mut Vec<T>,
) -> u64 {
    let bitmap_len = bitmap.len();
    let committed_end = bitmap_len.min(tip);

    let mut scan = scan_from;
    if scan < committed_end {
        let mut ones = bitmap.ones_iter_range(scan..committed_end);
        while out.len() < limit {
            let Some(idx) = ones.next() else {
                break;
            };
            out.push(idx.into());
            scan = idx + 1;
        }
    }
    while out.len() < limit {
        let candidate = scan.max(bitmap_len);
        if candidate >= tip {
            // Advance only through the span the ones scan verified clear. When `tip < len`
            // (a layered bitmap scanned with a committed-boundary tip), bits in
            // `[committed_end, len)` were never examined and a later call with a larger
            // `tip` must still see them.
            scan = scan.max(committed_end);
            break;
        }
        out.push(candidate.into());
        scan = candidate + 1;
    }
    scan
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
