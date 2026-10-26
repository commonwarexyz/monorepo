//! Cache-line prefetch hints and a lookahead cursor for software-pipelined scans.
//!
//! A scan whose per-item work waits on a cache miss can issue that miss for an item some distance
//! ahead of consuming it, so several misses are in flight at once. [Lookahead] hands the scan each
//! item that distance ahead of consuming it, and [prefetch] and [prefetch_lines] issue the hints.
//!
//! # Examples
//!
//! ```
//! use commonware_utils::prefetch::Lookahead;
//!
//! let items = vec![1u64, 2, 3, 4, 5];
//! let mut hinted = Vec::new();
//! let mut ahead = Lookahead::new(2);
//! let mut scan = items.into_iter();
//! loop {
//!     // Each item comes up once, two items before the scan consumes it.
//!     for item in ahead.advance(scan.as_slice()) {
//!         hinted.push(*item);
//!     }
//!     let Some(item) = scan.next() else { break };
//!     assert!(hinted.contains(&item));
//! }
//! assert_eq!(hinted, [1, 2, 3, 4, 5]);
//! ```

/// Bytes per cache line, the granularity of [prefetch_lines].
const CACHE_LINE: usize = 64;

/// Whether [prefetch] issues a hint on this target. Hint sites return early when it does not, so
/// the overflow and bounds checks on the addresses they compute are compiled out with the hint.
pub const ENABLED: bool = cfg!(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
));

/// Hint the CPU to start loading the cache line holding `ptr`, without waiting for it. A prefetch
/// never faults and has no architectural effect, so `ptr` may be dangling or out of bounds. A no-op
/// on targets other than x86_64 and aarch64, and under Miri.
// Not const because `_mm_prefetch` is const-callable only on nightly toolchains.
#[allow(clippy::missing_const_for_fn)]
#[inline(always)]
pub fn prefetch<T>(ptr: *const T) {
    cfg_if::cfg_if! {
        if #[cfg(all(target_arch = "x86_64", not(miri)))] {
            // SAFETY: `prefetcht0` is a hint that never faults and reads nothing architecturally,
            // so any address is sound.
            unsafe {
                core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T0 }>(ptr.cast());
            }
        } else if #[cfg(all(target_arch = "aarch64", not(miri)))] {
            // SAFETY: `prfm` is a hint that never faults and reads nothing architecturally, so any
            // address is sound.
            unsafe {
                core::arch::asm!(
                    "prfm pldl1keep, [{ptr}]",
                    ptr = in(reg) ptr,
                    options(nostack, readonly, preserves_flags),
                );
            }
        } else {
            let _ = ptr;
        }
    }
}

/// Hint every cache line that the `len` values of `T` at `ptr` intersect, at most `max_lines` of
/// them from the first (see [prefetch]).
#[inline]
pub fn prefetch_lines<T>(ptr: *const T, len: usize, max_lines: usize) {
    if !ENABLED {
        return;
    }
    for line in lines(ptr.cast(), len.saturating_mul(size_of::<T>()), max_lines) {
        prefetch(line);
    }
}

/// The start of each cache line that the `len` bytes at `ptr` intersect, at most `max_lines` of
/// them from the first. A span that starts partway into a line can reach one line further than
/// its length alone would.
#[inline]
fn lines(ptr: *const u8, len: usize, max_lines: usize) -> impl Iterator<Item = *const u8> {
    let misalign = ptr.addr() % CACHE_LINE;
    let count = if len == 0 {
        0
    } else {
        misalign.saturating_add(len).div_ceil(CACHE_LINE)
    };
    let first = ptr.wrapping_sub(misalign);
    (0..count.min(max_lines)).map(move |line| first.wrapping_add(line * CACHE_LINE))
}

/// A cursor that runs a fixed distance ahead of a scan, handing out each item that many items
/// before the scan consumes it, so the caller can prefetch what the item's work reads.
///
/// Call [Self::advance] with the scan's unconsumed tail before consuming its next item. It
/// returns every item exactly once, in scan order, and the first call returns the scan's first
/// `distance + 1` items so the pipeline starts full.
///
/// Over a scan of eight items at distance two, the call before each item returns:
///
/// ```text
/// before item 0   remaining [0 1 2 3 4 5 6 7]   returns [0 1 2]   (fills the window)
/// before item 1   remaining   [1 2 3 4 5 6 7]   returns [3]
/// before item 2   remaining     [2 3 4 5 6 7]   returns [4]
/// ...
/// before item 5   remaining           [5 6 7]   returns [7]
/// before item 6   remaining             [6 7]   returns []        (the tail is spent)
/// ```
#[derive(Clone, Debug)]
pub struct Lookahead {
    /// Items handed out ahead of the one the scan consumes next.
    distance: usize,
    /// Items at the end of the scan that no call has returned: all of them before the first
    /// call, whatever the scan's length.
    unreturned: usize,
}

impl Lookahead {
    /// A cursor over one scan that runs `distance` items ahead.
    pub const fn new(distance: usize) -> Self {
        Self {
            distance,
            unreturned: usize::MAX,
        }
    }

    /// The items within `distance` of the scan's next item that no earlier call returned.
    /// `remaining` holds the scan's unconsumed tail, in order.
    ///
    /// # Panics
    ///
    /// Panics if `remaining` starts more than `distance + 1` items before the first item no
    /// earlier call returned.
    pub fn advance<'a, T>(&mut self, remaining: &'a [T]) -> &'a [T] {
        let reach = remaining.len().min(self.distance.saturating_add(1));
        let returned = remaining.len().saturating_sub(self.unreturned);
        self.unreturned = remaining.len() - reach;
        &remaining[returned..reach]
    }
}

#[cfg(test)]
#[commonware_macros::test_group("miri")]
mod tests {
    use super::*;

    /// The lines [lines] yields for a span `start` bytes past a line boundary, as offsets from that
    /// boundary.
    fn line_offsets(start: usize, len: usize, max_lines: usize) -> Vec<usize> {
        let base = core::ptr::without_provenance::<u8>(0x10000);
        lines(base.wrapping_add(start), len, max_lines)
            .map(|line| line.addr() - base.addr())
            .collect()
    }

    #[test]
    fn test_lines_cover_every_intersected_line() {
        // Aligned spans take exactly the lines their length needs.
        assert_eq!(line_offsets(0, 64, 8), [0]);
        assert_eq!(line_offsets(0, 65, 8), [0, 64]);

        // Unaligned spans also take the line their tail reaches into.
        assert_eq!(line_offsets(16, 64, 8), [0, 64]);
        assert_eq!(line_offsets(16, 128, 8), [0, 64, 128]);
        assert_eq!(line_offsets(63, 2, 8), [0, 64]);

        // An empty span takes no line, and the cap bounds a long one.
        assert!(line_offsets(16, 0, 8).is_empty());
        assert_eq!(
            line_offsets(16, 1024, 8),
            [0, 64, 128, 192, 256, 320, 384, 448]
        );

        // The longest span the signature admits counts its lines without overflow.
        assert_eq!(line_offsets(1, usize::MAX, 2), [0, 64]);
        assert!(line_offsets(1, usize::MAX, 0).is_empty());
    }

    #[test]
    fn test_lookahead_returns_each_item_once_distance_ahead() {
        // Empty and one-item scans, and distances of zero, within the scan, past its end, and the
        // largest.
        for (total, distance) in [(0, 2), (1, 2), (5, 0), (5, 2), (5, 8), (5, usize::MAX)] {
            // Advance the cursor before consuming each item, collecting what it hands out.
            let items: Vec<usize> = (0..total).collect();
            let mut ahead = Lookahead::new(distance);
            let mut scan = items.into_iter();
            let mut hinted = Vec::new();
            let mut consumed = 0;
            loop {
                // Everything up to `distance` past the next item has come up, and nothing beyond.
                hinted.extend_from_slice(ahead.advance(scan.as_slice()));
                assert_eq!(
                    hinted.len(),
                    total.min(distance.saturating_add(consumed + 1)),
                    "{total} {distance}"
                );
                let Some(item) = scan.next() else { break };
                assert_eq!(item, consumed);
                consumed += 1;
            }

            // Every item came up exactly once, in scan order.
            assert_eq!(hinted, (0..total).collect::<Vec<_>>(), "{total} {distance}");
        }
    }

    #[test]
    fn test_lookahead_never_repeats_an_item() {
        // The first call fills the pipeline, and a call with the same tail hands out nothing more.
        let items = [0, 1, 2, 3];
        let mut ahead = Lookahead::new(1);
        assert_eq!(ahead.advance(&items), [0, 1]);
        assert!(ahead.advance(&items).is_empty());

        // An item the scan consumed before any call reached it is never returned.
        assert_eq!(ahead.advance(&items[3..]), [3]);
        assert!(ahead.advance(&items[4..]).is_empty());
    }

    #[test]
    fn test_prefetch_accepts_any_address() {
        // A null address, and a span that runs past the end of the address space.
        prefetch(core::ptr::null::<u8>());
        prefetch_lines(core::ptr::without_provenance::<u64>(usize::MAX - 8), 64, 8);
    }
}
