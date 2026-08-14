//! Parallel stable sort built on the scoped claim primitive.
//!
//! Two phases over the borrowed slice:
//!
//! 1. Run phase: the slice is split into contiguous runs (about two per executor, with a
//!    floor so tiny runs are not worth a claim) and each run is stable-sorted in place.
//!    Runs are disjoint, so executors sort them concurrently, one run per claimed index.
//! 2. Merge rounds: adjacent sorted runs are merged pairwise between the slice and a
//!    scratch buffer (ping-pong: the source and destination swap each round), doubling the
//!    run width until a single run spans the slice. Late rounds have fewer pairs than
//!    executors, so each pair's output is split into segments (merge-path splitting). If
//!    the final image lands in scratch, it is copied back into the slice.
//!
//! Every segment boundary is computed ONCE, serially, on the caller between rounds (a
//! stable co-rank binary search), and units carry absolute source ranges: the units of a
//! pair positionally partition its two source runs no matter how the comparator behaves.
//! Executors then copy each source element exactly once by construction, which is what
//! makes the memory-safety argument below comparator-independent.
//!
//! # Panic safety and adversarial comparators
//!
//! The comparator is caller-supplied: it may unwind, and it may be inconsistent (no total
//! order). Like `slice::sort_by` and rayon's `par_sort_by`, an inconsistent comparator can
//! only produce an unspecified order; it cannot violate memory safety. The invariant that
//! makes every path sound: **at every point where this module returns or resumes a panic,
//! the slice holds every element exactly once, bitwise**. The pieces:
//!
//! - Merges only COPY bits from a fully initialized source buffer into the destination;
//!   the source is never written during a round.
//! - Unit source ranges are clamped, monotone, and shared between neighbors (computed once
//!   on the caller), so they partition the round's source exactly under ANY comparator.
//! - A poisoned round is abandoned before its destination is ever read: if the destination
//!   was the slice (partially clobbered), the complete source image is restored from
//!   scratch before the payload is resumed.
//! - A comparator panic during the caller-side boundary precompute unwinds directly with
//!   the slice untouched by that round.
//! - The scratch buffer is a `Vec` whose length is always zero, so it deallocates without
//!   dropping its bytes on every path; elements only ever appear in it as bitwise copies.
//!
//! Stability: runs are contiguous and in order, each run is sorted with the standard
//! library's stable sort, merges take from the left run on ties, and the co-rank split
//! computes exactly the stable merge's prefix boundaries, so equal elements keep their
//! original relative order end to end (for comparators that are total orders; others get
//! an unspecified order, as with `slice::sort_by`).

use super::{
    pool::Shared,
    scoped::{self, Ctl},
};
use core::{cmp::Ordering, ops::Range};
use std::panic;

/// Minimum items per sort run. Below this, the per-run claim and wake traffic outweighs the
/// sort itself; the slice is handed to the serial path instead of being shredded.
#[cfg(not(miri))]
pub(super) const MIN_RUN: usize = 1024;
/// Small enough under miri that unit tests reach the parallel merge rounds.
#[cfg(miri)]
pub(super) const MIN_RUN: usize = 8;

/// One merge work unit with ABSOLUTE source and destination positions: copies the stable
/// merge of `src[l0..l1]` and `src[r0..r1]` into `dst[out..out + (l1-l0) + (r1-r0)]`.
/// Units are built on the caller so that a pair's units partition its two source runs
/// exactly; see the module docs.
#[derive(Clone, Copy)]
struct Unit {
    l0: usize,
    l1: usize,
    r0: usize,
    r1: usize,
    out: usize,
}

/// Stable parallel sort of `items` by `compare` using up to `parallelism` executors (the
/// caller plus woken pool workers).
pub(super) fn sort_by<T, C>(pool: &Shared, parallelism: usize, items: &mut [T], compare: &C)
where
    T: Send,
    C: Fn(&T, &T) -> Ordering + Send + Sync,
{
    let len = items.len();
    let parallelism = parallelism.max(1);
    // About two runs per executor so a straggler run rebalances, floored so each run is
    // worth its claim.
    let run_len = (len.div_ceil(parallelism.saturating_mul(2))).max(MIN_RUN);
    let runs = len.div_ceil(run_len.max(1));
    if runs <= 1 {
        items.sort_by(compare);
        return;
    }

    let base = super::Ptr(items.as_mut_ptr());

    // Run phase: stable-sort each run in place. Each index is one run.
    let sort_runs = |range: Range<usize>, _ctl: &Ctl<'_>| {
        for i in range {
            let start = i * run_len;
            let end = ((i + 1) * run_len).min(len);
            // SAFETY: run `i` covers `[start, end)`; runs are disjoint by construction and
            // each index is claimed exactly once, so this is the only reference to these
            // elements. The slice outlives the scoped run (the caller's frame owns it).
            let run =
                unsafe { core::slice::from_raw_parts_mut(base.get().add(start), end - start) };
            run.sort_by(compare);
        }
    };
    let outcome = scoped::run(pool, runs, parallelism, 1, &sort_runs);
    if let Some(payload) = outcome.panic {
        // The slice is intact: in-place sorting keeps every element present through any
        // comparator unwind (the standard sort guarantees it per run; untouched runs were
        // never entered).
        panic::resume_unwind(payload);
    }

    // Presorted early exit (`runs - 1` comparisons): if every run boundary is already
    // ordered, the sorted runs concatenate into the answer in place and the merge rounds
    // (and the scratch allocation) are skipped entirely. Nearly-sorted inputs that fail
    // this whole-slice check still collapse per pair below.
    let ordered = (1..runs).all(|r| {
        let b = r * run_len;
        // SAFETY: `0 < b < len` (every run is non-empty), and the run phase completed.
        unsafe { compare(&*base.get().add(b - 1), &*base.get().add(b)) != Ordering::Greater }
    });
    if ordered {
        return;
    }

    // Scratch for the merge rounds. Its length stays zero for its whole life: elements are
    // only ever present in it as bitwise copies, so dropping it never drops a `T`.
    let mut scratch_vec: Vec<T> = Vec::with_capacity(len);
    let scratch = super::Ptr(scratch_vec.as_mut_ptr());

    // Merge rounds, ping-ponging between the slice and scratch. `src` always holds the
    // complete current image; `dst` is write-only until the round completes.
    let mut src = base;
    let mut dst = scratch;
    let mut width = run_len;
    while width < len {
        let pairs = len.div_ceil(width.saturating_mul(2));
        // Merge-path splitting: late rounds have fewer pairs than executors, so cut each
        // pair's output into segments to keep every executor claimable. Each boundary's
        // co-rank is computed exactly once, HERE on the caller, so neighboring units share
        // the identical split point: the units positionally partition the pair's source
        // runs under any comparator (the clamps make even a garbage binary-search result
        // well-formed). A comparator panic here unwinds with the slice untouched.
        let per_pair = parallelism.saturating_mul(2).div_ceil(pairs);
        let mut units: Vec<Unit> = Vec::new();
        for p in 0..pairs {
            let lo = (2 * p).saturating_mul(width);
            let mid = (lo + width).min(len);
            let hi = (lo + width.saturating_mul(2)).min(len);
            let out_len = hi - lo;
            // Ordered-pair fast path (one comparison): when the two runs concatenate
            // already ordered (ties fine: left stays first), the stable merge IS the
            // concatenation, so emit a single unit with an empty right range -- the merge
            // walk skips straight to its bulk tail copy. This is what keeps nearly-sorted
            // inputs cheap after the whole-slice early exit above fails.
            // SAFETY: `lo < mid <= hi <= len` here and the source is fully initialized.
            if mid < hi
                && unsafe { compare(&*src.get().add(mid - 1), &*src.get().add(mid)) }
                    != Ordering::Greater
            {
                units.push(Unit {
                    l0: lo,
                    l1: hi,
                    r0: hi,
                    r1: hi,
                    out: lo,
                });
                continue;
            }
            let segs = per_pair.min(out_len.div_ceil(MIN_RUN)).max(1);
            let mut l_prev = lo;
            let mut r_prev = mid;
            let mut out = lo;
            for s in 1..=segs {
                let (l_cut, r_cut) = if s == segs {
                    // The last unit always ends exactly at the run ends, so the pair's
                    // units cover its full source regardless of earlier cut placement.
                    (mid, hi)
                } else {
                    let k = out_len * s / segs;
                    // SAFETY: `src[lo..hi]` is fully initialized (run phase or previous
                    // completed round). co_rank's index arithmetic is clamped and cannot
                    // read outside `[lo, hi)` for any comparator behavior.
                    let i = unsafe { co_rank(src.get(), lo, mid, hi, k, compare) };
                    // Monotone, in-bounds cuts even if an inconsistent comparator steers
                    // the binary search arbitrarily within its window.
                    (
                        (lo + i).clamp(l_prev, mid),
                        (mid + (k - i)).clamp(r_prev, hi),
                    )
                };
                if l_cut > l_prev || r_cut > r_prev {
                    units.push(Unit {
                        l0: l_prev,
                        l1: l_cut,
                        r0: r_prev,
                        r1: r_cut,
                        out,
                    });
                    out += (l_cut - l_prev) + (r_cut - r_prev);
                    l_prev = l_cut;
                    r_prev = r_cut;
                }
            }
        }

        let merge_units = |range: Range<usize>, _ctl: &Ctl<'_>| {
            for u in range {
                let unit = units[u];
                // SAFETY: `src[..len]` is fully initialized; unit source ranges partition
                // each pair's runs and unit destination ranges partition `dst[..len]`
                // (both by construction above), and each index is claimed exactly once,
                // so every `dst` position is written by exactly one executor and every
                // `src` element is copied exactly once. Both allocations are live for the
                // scoped run (this frame owns them) and never overlap. Only bits are
                // copied; `dst` is not read until the round completes.
                unsafe { merge_unit(src.get(), dst.get(), unit, compare) };
            }
        };
        /// Restores the complete source image (in scratch) into the slice if the round is
        /// abandoned while writing INTO the slice, so the slice again holds every element
        /// exactly once. Armed only for slice-destination rounds; runs on the comparator
        /// poison path (via the `resume_unwind` below) and on any internal unwind.
        struct RestoreGuard<T> {
            scratch: *const T,
            base: *mut T,
            len: usize,
        }
        impl<T> Drop for RestoreGuard<T> {
            fn drop(&mut self) {
                // SAFETY: `scratch[..len]` is fully initialized (it was this round's
                // source) and disjoint from the slice; both allocations are live for the
                // sort's frame (the guard is forgotten before either can die).
                unsafe { core::ptr::copy_nonoverlapping(self.scratch, self.base, self.len) };
            }
        }
        let restore = (dst.get() == base.get()).then(|| RestoreGuard {
            scratch: src.get() as *const T,
            base: base.get(),
            len,
        });

        let outcome = scoped::run(pool, units.len(), parallelism, 1, &merge_units);
        if let Some(payload) = outcome.panic {
            // The guard (when armed) restores the slice as this unwinds.
            panic::resume_unwind(payload);
        }
        // Clean round: the destination is fully written; keep it.
        if let Some(guard) = restore {
            core::mem::forget(guard);
        }
        core::mem::swap(&mut src, &mut dst);
        width *= 2;
    }

    if src.get() != base.get() {
        // The final image landed in scratch; move it home.
        // SAFETY: `src[..len]` (scratch) is fully initialized and disjoint from the
        // slice; both allocations are live.
        unsafe { core::ptr::copy_nonoverlapping(src.get(), base.get(), len) };
    }
    drop(scratch_vec);
}

/// Copies the stable merge of `src[l0..l1]` and `src[r0..r1]` into `dst` starting at
/// `out`, writing exactly `(l1 - l0) + (r1 - r0)` positions. Takes from the left run on
/// ties. Purely positional: every source element in the two ranges is copied exactly once
/// no matter what the comparator returns.
///
/// # Safety
///
/// `src[l0..l1]` and `src[r0..r1]` must be initialized; `dst[out..]` must be valid for
/// `(l1 - l0) + (r1 - r0)` writes; the buffers must not overlap. The caller must treat
/// `dst`'s contents as bitwise copies (never dropping them) and must not read them unless
/// this returns without unwinding.
unsafe fn merge_unit<T, C>(src: *const T, dst: *mut T, unit: Unit, cmp: &C)
where
    C: Fn(&T, &T) -> Ordering,
{
    let Unit {
        mut l0,
        l1,
        mut r0,
        r1,
        mut out,
    } = unit;
    // SAFETY (all blocks below): `l0` and `r0` are dereferenced only while strictly below
    // their range ends; `out` advances exactly once per element copied, totalling the two
    // range lengths.
    while l0 < l1 && r0 < r1 {
        let take_left = unsafe { cmp(&*src.add(l0), &*src.add(r0)) } != Ordering::Greater;
        let from = if take_left {
            let i = l0;
            l0 += 1;
            i
        } else {
            let i = r0;
            r0 += 1;
            i
        };
        unsafe { core::ptr::copy_nonoverlapping(src.add(from), dst.add(out), 1) };
        out += 1;
    }
    unsafe { core::ptr::copy_nonoverlapping(src.add(l0), dst.add(out), l1 - l0) };
    out += l1 - l0;
    unsafe { core::ptr::copy_nonoverlapping(src.add(r0), dst.add(out), r1 - r0) };
}

/// Returns `i`, the number of elements the stable merge of `src[lo..mid]` and
/// `src[mid..hi]` takes from the LEFT run among its first `k` outputs (ties take left).
///
/// For comparators that are not total orders the result is unspecified but always within
/// `[k - min(k, hi - mid), min(k, mid - lo)]`: the search window is maintained by index
/// arithmetic alone, so no comparator behavior can push a probe out of bounds.
///
/// # Safety
///
/// `src[lo..hi]` must be initialized and `k <= hi - lo`.
unsafe fn co_rank<T, C>(src: *const T, lo: usize, mid: usize, hi: usize, k: usize, cmp: &C) -> usize
where
    C: Fn(&T, &T) -> Ordering,
{
    let len_l = mid - lo;
    let len_r = hi - mid;
    // The answer is |{x in L : x among the first k merge outputs}|. With ties taking
    // left, L[i]'s merge position is i plus the number of R elements STRICTLY below it,
    // and R is sorted, so testing R[j-1] (with j = k - i) against L[i] decides whether
    // L[i] made the cut. The predicate is monotone in `i`: binary search.
    let mut i_min = k.saturating_sub(len_r);
    let mut i_max = k.min(len_l);
    while i_min < i_max {
        let i = i_min + (i_max - i_min) / 2;
        let j = k - i;
        // `i < i_max <= k` gives `j >= 1`; `i >= i_min >= k - len_r` gives `j <= len_r`.
        // SAFETY: `i < i_max <= len_l` and `1 <= j <= len_r`, so both reads are inside
        // the initialized runs.
        if unsafe { cmp(&*src.add(mid + j - 1), &*src.add(lo + i)) } == Ordering::Less {
            // R[j-1] < L[i]: at least j right elements precede L[i], so L[i] sits at
            // position >= i + j = k and is NOT among the first k. Answer <= i.
            i_max = i;
        } else {
            // R[j-1] >= L[i] (an equal R element comes after L[i]): at most j - 1 right
            // elements precede L[i], so it sits at position < k and IS taken. Answer > i.
            i_min = i + 1;
        }
    }
    i_min
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Brute-force oracle: count left-run takes among the first `k` outputs of a serial
    /// stable merge (ties take left).
    fn oracle(l: &[u8], r: &[u8], k: usize) -> usize {
        let mut i = 0;
        let mut j = 0;
        let mut taken = 0;
        let mut from_left = 0;
        while taken < k {
            let take_left = j >= r.len() || (i < l.len() && l[i] <= r[j]);
            if take_left {
                i += 1;
                from_left += 1;
            } else {
                j += 1;
            }
            taken += 1;
        }
        from_left
    }

    #[test]
    fn co_rank_matches_oracle_exhaustively() {
        // Every pair of sorted runs with lengths up to 5 over a 3-value alphabet (heavy
        // ties), and every valid k: the binary search must agree with the serial merge.
        fn sorted_runs(max_len: usize) -> Vec<Vec<u8>> {
            let mut out = vec![vec![]];
            for len in 1..=max_len {
                let mut stack = vec![Vec::with_capacity(len)];
                while let Some(cur) = stack.pop() {
                    if cur.len() == len {
                        out.push(cur);
                        continue;
                    }
                    let floor = cur.last().copied().unwrap_or(0);
                    for v in floor..3 {
                        let mut next = cur.clone();
                        next.push(v);
                        stack.push(next);
                    }
                }
            }
            out
        }
        let runs = sorted_runs(5);
        for l in &runs {
            for r in &runs {
                let mut buf: Vec<u8> = l.clone();
                buf.extend_from_slice(r);
                let (lo, mid, hi) = (0, l.len(), l.len() + r.len());
                for k in 0..=hi {
                    // SAFETY: `buf[lo..hi]` is initialized and both halves are sorted.
                    let got = unsafe {
                        co_rank(buf.as_ptr(), lo, mid, hi, k, &|a: &u8, b: &u8| a.cmp(b))
                    };
                    assert_eq!(got, oracle(l, r, k), "l={l:?} r={r:?} k={k}");
                }
            }
        }
    }
}
