//! Floor-raise candidate scan over an activity-status bitmap. `any::Db` scans its committed
//! bitmap directly; `current` batches scan a layered view of it (`current::batch::BitmapView`).

use commonware_utils::bitmap;

/// Core floor-raise scan over any [`bitmap::Readable`]: set bits in `[scan_from, min(len, tip))`
/// ascending via one `ones_iter_from`, then locations in `[max(scan_from, len), tip)`
/// sequentially. Fills `out` with up to `limit` candidates and returns the next `scan_from`.
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
