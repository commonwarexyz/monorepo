//! Blob-page buffers recycled between direct reads and the page cache.
//!
//! A read lane reads a whole blob page into a buffer from this pool, and the page cache returns a
//! page's buffer here when it replaces the page. Reusing buffers spares each read a fresh aligned
//! allocation and each replaced page a free.

use crate::{BLOB_PAGE_SIZE, IoBufMut};
use commonware_utils::{Widen, sync::Mutex};

/// The most buffers the pool keeps (32 MiB of blob pages). Buffers given beyond it are freed.
const CAPACITY: usize = 8192;

/// The pooled buffers, each empty.
static POOL: Mutex<Vec<IoBufMut>> = Mutex::new(Vec::new());

/// Move up to `n` pooled buffers into `out`.
#[cfg(target_os = "linux")]
pub(crate) fn take(out: &mut Vec<IoBufMut>, n: usize) {
    let mut pool = POOL.lock();
    let at = pool.len().saturating_sub(n);
    out.extend(pool.drain(at..));
}

/// Whether `buf` is one the pool keeps, with exactly one blob page of capacity, aligned to it.
pub(crate) fn fits(buf: &IoBufMut) -> bool {
    let block: usize = Widen::widen(BLOB_PAGE_SIZE);
    buf.capacity() == block && buf.as_ref().as_ptr().addr().is_multiple_of(block)
}

/// Return the buffers in `bufs` that [fit](fits) to the pool, up to its capacity, and free the
/// rest after releasing the pool.
pub(crate) fn give(bufs: &mut Vec<IoBufMut>) {
    bufs.retain(fits);
    for buf in bufs.iter_mut() {
        buf.clear();
    }
    let mut pool = POOL.lock();
    let room = CAPACITY.saturating_sub(pool.len());
    pool.extend(bufs.drain(..bufs.len().min(room)));
    drop(pool);
    bufs.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Buf as _;
    use commonware_utils::NZUsize;

    #[test]
    fn test_fits_requires_one_aligned_blob_page() {
        let block: usize = Widen::widen(BLOB_PAGE_SIZE);
        assert!(fits(&IoBufMut::zeroed_with_alignment(
            block,
            NZUsize!(block)
        )));
        assert!(!fits(&IoBufMut::zeroed_with_alignment(
            2 * block,
            NZUsize!(block)
        )));
        assert!(!fits(&IoBufMut::zeroed_with_alignment(
            block - 1,
            NZUsize!(block)
        )));
        let mut unaligned = IoBufMut::zeroed_with_alignment(block + 64, NZUsize!(block));
        unaligned.advance(64);
        assert!(!fits(&unaligned));
    }
}
