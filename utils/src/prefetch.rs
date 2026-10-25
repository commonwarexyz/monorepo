//! Cache-line prefetch hints for software-pipelined scans.
//!
//! A scan whose per-item work waits on a cache miss can issue that miss for an item some distance
//! ahead of consuming it, so several misses are in flight at once. [prefetch] and [prefetch_lines]
//! issue the hints.

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

/// Hint every cache line that the `len` bytes at `ptr` intersect, at most `max_lines` of them from
/// the first (see [prefetch]).
#[inline]
pub fn prefetch_lines<T>(ptr: *const T, len: usize, max_lines: usize) {
    if !ENABLED {
        return;
    }
    for line in lines(ptr.cast(), len, max_lines) {
        prefetch(line);
    }
}

/// The start of each cache line that the `len` bytes at `ptr` intersect, at most `max_lines` of
/// them from the first. A span that starts partway into a line reaches one line further than its
/// length alone would.
#[inline]
fn lines(ptr: *const u8, len: usize, max_lines: usize) -> impl Iterator<Item = *const u8> {
    let misalign = ptr.addr() % CACHE_LINE;
    let count = if len == 0 {
        0
    } else {
        (misalign + len).div_ceil(CACHE_LINE)
    };
    let first = ptr.wrapping_sub(misalign);
    (0..count.min(max_lines)).map(move |line| first.wrapping_add(line * CACHE_LINE))
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
    }

    #[test]
    fn test_prefetch_accepts_any_address() {
        prefetch(core::ptr::null::<u8>());
        prefetch_lines(core::ptr::without_provenance::<u64>(usize::MAX - 8), 64, 8);
    }
}
