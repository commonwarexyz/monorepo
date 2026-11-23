//! Floor-raise candidate sources over the activity-status bitmap.
//!
//! `any::Db` owns its bitmap as a plain [`bitmap::Prunable`]. Readers borrow it through the
//! database, so a write (which needs the database by value or `&mut`) never overlaps a read.

use crate::merkle::{Family, Location};
use commonware_utils::bitmap;

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

impl<F: Family, const N: usize> Candidates<F> for &bitmap::Prunable<N> {
    fn fill(
        &mut self,
        floor: Location<F>,
        tip: u64,
        limit: usize,
        out: &mut Vec<Location<F>>,
    ) -> Location<F> {
        Location::new(fill_from(*self, *floor, tip, limit, out))
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
