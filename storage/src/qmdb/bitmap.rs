//! Activity-status bitmap. Owned by [`any::Db`](super::any::db::Db) and shared with live
//! [`MerkleizedBatch`](super::current::batch::MerkleizedBatch)es via `Arc<Shared<N>>`.
//!
//! `any::Db` mutates the inner [`bitmap::Prunable`] under a [`RwLock`] during `apply_batch` /
//! `prune` / `rewind` while live batches read concurrently. Locking (not snapshotting) keeps
//! memory at O(bitmap size); snapshots would couple memory to live-batch count and lifetime.
//!
//! Reads through an invalidated `MerkleizedBatch` (see its "Branch validity" docs) return
//! inconsistent bytes; callers must drop invalid batches.

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
    /// (`apply_batch`, `prune_bitmap`, `rewind`) hold the write lock.
    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, bitmap::Prunable<N>> {
        self.inner.write()
    }

    /// Single-lock alternative to `bitmap::Readable::ones_iter_from(from).next()`.
    #[cfg(test)]
    pub(crate) fn next_one_from(&self, from: u64) -> Option<u64> {
        self.read().ones_iter_from(from).next()
    }

    /// Fill `out` with up to `limit` floor-raise candidates in `[scan_from, tip)`, holding a single
    /// read guard for the whole batch. Returns the next `scan_from`.
    ///
    /// The candidate sequence is identical to repeatedly calling `any::batch::next_candidate`
    /// (the test oracle): set bits in the committed prefix are returned in order via one
    /// `ones_iter_from`, then locations at or beyond the committed boundary are returned
    /// sequentially.
    pub(crate) fn fill_candidates<T: From<u64>>(
        &self,
        scan_from: u64,
        tip: u64,
        limit: usize,
        out: &mut Vec<T>,
    ) -> u64 {
        fill_from(&*self.read(), scan_from, tip, limit, out)
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

/// Core floor-raise scan over any [`bitmap::Readable`]: set bits in `[scan_from, min(len, tip))`
/// ascending via one `ones_iter_from`, then locations in `[max(scan_from, len), tip)`
/// sequentially. Fills `out` with up to `limit` candidates and returns the next `scan_from`.
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
        // Bound the iterator itself: testing a yielded location against the tip
        // would still let next() search an arbitrarily long clear suffix.
        let prefix = Prefix {
            bitmap,
            len: committed_end,
        };
        let mut ones = bitmap::Readable::ones_iter_from(&prefix, scan);
        while out.len() < limit {
            match ones.next() {
                Some(idx) if idx < committed_end => {
                    out.push(idx.into());
                    scan = idx + 1;
                }
                _ => break,
            }
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

/// A bitmap prefix that prevents the set-bit iterator from reading chunks past its end.
struct Prefix<'a, B> {
    bitmap: &'a B,
    len: u64,
}

impl<B: bitmap::Readable<N>, const N: usize> bitmap::Readable<N> for Prefix<'_, B> {
    fn complete_chunks(&self) -> usize {
        (self.len / bitmap::BitMap::<N>::CHUNK_SIZE_BITS) as usize
    }

    fn get_chunk(&self, chunk: usize) -> [u8; N] {
        self.bitmap.get_chunk(chunk)
    }

    fn last_chunk(&self) -> ([u8; N], u64) {
        if self.len <= self.pruned_bits() {
            return ([0; N], 0);
        }
        let chunk_bits = bitmap::BitMap::<N>::CHUNK_SIZE_BITS;
        let index = ((self.len - 1) / chunk_bits) as usize;
        (self.get_chunk(index), (self.len - 1) % chunk_bits + 1)
    }

    fn pruned_chunks(&self) -> usize {
        self.bitmap.pruned_chunks()
    }
    fn len(&self) -> u64 {
        self.len
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
