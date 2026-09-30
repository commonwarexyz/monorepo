//! Faster alternatives to the MMR size arithmetic of `mmr/iterator.rs` and
//! `mmr/mod.rs`, written in the host's own dialect over the original API.
//! Each is tied to the source function it replaces by a proven `#[rewrite]`
//! lemma in `PROOF.rs` (an optimization lemma: it can make the code faster,
//! never different); the build lowers it into the host's file only when the
//! cost model finds it cheaper (DESIGN.md §2.1, "The optimizer on lifted
//! modules").

// (the host files these alternatives go into also import the `Family`
// trait, `use crate::merkle::Family as _`, for `Family::MAX_NODES`; the
// lift reads that constant without it)
use crate::merkle::mmr::{Family, Position};

/// The number of nodes of an MMR with `n` leaves: `2n - popcount(n)`.
#[inline(always)]
const fn nodes(n: u64) -> u64 {
    2 * n - n.count_ones() as u64
}

/// One step of a binary search on the leaf count: `lo + k` when an MMR of
/// that many leaves has at most `s` nodes, else `lo`.
#[inline(always)]
const fn leaves_step(lo: u64, k: u64, s: u64) -> u64 {
    let m = lo + k;
    if nodes(m) <= s {
        m
    } else {
        lo
    }
}

/// The largest leaf count `n` whose MMR has at most `s` nodes (`s < 2^63`).
/// It lies in `s/2 ..= s/2 + 32` (an MMR of `n` leaves has `2n` nodes less
/// at most 64), so a binary search over those 33 candidates takes six steps.
const fn leaves_at_most(s: u64) -> u64 {
    leaves_fine(leaves_coarse(s), s)
}

/// The first three steps: the answer in `[lo, lo + 8)`.
const fn leaves_coarse(s: u64) -> u64 {
    let lo = leaves_step(s >> 1, 32, s);
    let lo = leaves_step(lo, 16, s);
    leaves_step(lo, 8, s)
}

/// The last three steps, from the answer in `[lo, lo + 8)`.
const fn leaves_fine(lo: u64, s: u64) -> u64 {
    let lo = leaves_step(lo, 4, s);
    let lo = leaves_step(lo, 2, s);
    leaves_step(lo, 1, s)
}

/// `PeakIterator::to_nearest_size`: the largest valid MMR size that is no
/// greater than `size`.
pub fn to_nearest_size_fast(size: Position) -> Position {
    assert!(size <= Family::MAX_NODES, "size exceeds MAX_NODES");
    Position::new(nodes(leaves_at_most(size.as_u64())))
}

/// `Family::is_valid_size`: whether `size` is the size of an MMR (up to
/// `MAX_NODES`).
pub fn is_valid_size_fast(size: Position) -> bool {
    size <= Family::MAX_NODES && to_nearest_size_fast(size) == size
}
