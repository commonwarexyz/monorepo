//! Activity-status bitmap. Owned by [`any::Db`](super::any::db::Db) and shared with live
//! [`MerkleizedBatch`](super::current::batch::MerkleizedBatch)es via `Arc<Shared<N>>`.
//!
//! `any::Db` mutates the inner [`bitmap::Prunable`] under a [`RwLock`] during `apply_batch` /
//! `prune` while live batches read concurrently. Locking (not snapshotting) keeps memory at
//! O(bitmap size). Snapshots would couple memory to live-batch count and lifetime.
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
    /// (`apply_batch`, `prune_bitmap`) hold the write lock.
    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, bitmap::Prunable<N>> {
        self.inner.write()
    }

    /// Single-lock alternative to `bitmap::Readable::ones_iter_from(from).next()`.
    #[cfg(test)]
    pub(crate) fn next_one_from(&self, from: u64) -> Option<u64> {
        self.read().ones_iter_from(from).next()
    }

    /// Find the first set bit in `[from, end)` under one read lock.
    /// No chunks beyond this range are scanned.
    pub(crate) fn first_one(&self, from: u64, end: u64) -> Option<u64> {
        first_one(&*self.read(), from, end)
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
    pub(crate) fn pruned_bits(&self) -> u64 {
        self.read().pruned_bits()
    }

    /// Return the value of the bit at `loc`. Acquires the read lock briefly.
    #[cfg(any(test, feature = "test-traits"))]
    pub(crate) fn get_bit(&self, loc: u64) -> bool {
        self.read().get_bit(loc)
    }
}

/// Search bounded chunks a word at a time, masking partial boundary bytes.
fn first_one<const N: usize>(bitmap: &bitmap::Prunable<N>, from: u64, end: u64) -> Option<u64> {
    let end = end.min(bitmap.len());
    let from = from.max(bitmap.pruned_bits());
    let mut scan = from;
    let chunk_bits = bitmap::Prunable::<N>::CHUNK_SIZE_BITS;
    while scan < end {
        let chunk_index = (scan / chunk_bits) as usize;
        let chunk_base = scan / chunk_bits * chunk_bits;
        let chunk = bitmap.get_chunk(chunk_index);
        let first_byte = ((scan - chunk_base) / 8) as usize;
        let end_byte = (end - chunk_base).min(chunk_bits).div_ceil(8) as usize;
        for (i, bytes) in chunk[first_byte..end_byte].chunks(8).enumerate() {
            let base = chunk_base + ((first_byte + i * 8) as u64 * 8);
            let mut buf = [0; 8];
            buf[..bytes.len()].copy_from_slice(bytes);
            let mut word = u64::from_le_bytes(buf);
            if base < from {
                word &= u64::MAX << (from - base);
            }
            if end - base < 64 {
                word &= (1u64 << (end - base)) - 1;
            }
            if word != 0 {
                return Some(base + u64::from(word.trailing_zeros()));
            }
        }
        scan = chunk_base.saturating_add(chunk_bits);
    }
    None
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
        let mut ones = bitmap.ones_iter_from(scan);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn check_ranges<const N: usize>() {
        let len = 3 * bitmap::Prunable::<N>::CHUNK_SIZE_BITS + 3;
        for stride in [1, 7, 63, 65, len + 1] {
            let mut bitmap = bitmap::Prunable::<N>::new();
            bitmap.extend_to(len);
            for bit in (0..len).filter(|bit| bit % stride == 0) {
                bitmap.set_bit(bit, true);
            }
            for pruned in [false, true] {
                if pruned {
                    bitmap.prune_to_bit(bitmap::Prunable::<N>::CHUNK_SIZE_BITS);
                }
                for from in (0..=len + 1).filter(|bit| N <= 9 || bit % 8 <= 1 || bit % 8 == 7) {
                    for end in (from..=len + 1).filter(|bit| N <= 9 || bit % 8 <= 1 || bit % 8 == 7)
                    {
                        let expected = (from.max(bitmap.pruned_bits())..end.min(len))
                            .find(|&bit| bitmap.get_bit(bit));
                        assert_eq!(
                            first_one(&bitmap, from, end),
                            expected,
                            "N={N}, {from}..{end}"
                        );
                    }
                    assert_eq!(
                        first_one(&bitmap, from, u64::MAX),
                        (from.max(bitmap.pruned_bits())..len).find(|&bit| bitmap.get_bit(bit))
                    );
                }
            }
        }
    }

    #[test]
    fn first_one_matches_bit_scan() {
        check_ranges::<1>();
        check_ranges::<7>();
        check_ranges::<8>();
        check_ranges::<9>();
        check_ranges::<32>();
        check_ranges::<64>();
    }
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn first_one_near_max() {
        let mut bitmap =
            bitmap::Prunable::<8>::new_with_pruned_chunks((u64::MAX / 64) as usize).unwrap();
        let from = bitmap.pruned_bits();
        bitmap.extend_to(u64::MAX);
        assert_eq!(first_one(&bitmap, from, u64::MAX), None);
        bitmap.set_bit(u64::MAX - 1, true);
        assert_eq!(first_one(&bitmap, from, u64::MAX - 1), None);
        assert_eq!(first_one(&bitmap, from, u64::MAX), Some(u64::MAX - 1));
    }
}
