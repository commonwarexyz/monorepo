//! P3: the peaks of a structure are the roots of perfect trees that cover its leaves in order.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! storage/src/merkle/mod.rs, `Family::peaks`: "Return the peaks of a structure with the given
//! `size` as `(position, height)` pairs in canonical oldest-to-newest order". The doc of the trait
//! `Family`: "[`Self::peaks`] and [`Self::nodes_to_pin`] each return at most [`MAX_PINNED_NODES`]
//! entries for every valid size", and "At every valid size, the nodes at height `h` cover exactly
//! the aligned leaf intervals `[k * 2^h, (k + 1) * 2^h)` for `k` in `0..n`, for some `n`."
//!
//! MMR. The module docs of storage/src/merkle/mmr/mod.rs: "An MMR is a list of perfect binary
//! trees (aka _mountains_) of strictly decreasing height. The roots of these trees are called the
//! _peaks_ of the MMR. Each _element_ stored in the MMR is represented by some leaf node in one of
//! these perfect trees", and "The _size_ of an MMR is the total number of nodes summed over all
//! trees." storage/src/merkle/mmr/iterator.rs, `PeakIterator`: the peaks come "in decreasing order
//! of height".
//!
//! MMB. The module docs of storage/src/merkle/mmb/mod.rs: "An MMB is a forest of perfect binary
//! trees (aka _mountains_) of non-increasing height. The roots of these trees are called the
//! _peaks_ of the MMB. Each _element_ stored in the MMB is represented by some leaf node in one of
//! these perfect trees", and "The _size_ of an MMB is the total number of nodes summed over all
//! trees." storage/src/merkle/mmb/iterator.rs, `PeakIterator`: "The number of peaks after N leaves
//! is always exactly `ilog2(N+1)`, and their heights are non-increasing in this iteration order."
//!
//! Node helpers, used to name each peak. storage/src/merkle/mod.rs, `Family::subtree_root_position`
//! returns "the position of the node at `height` whose leftmost leaf is at `leaf_start`", and
//! `Family::pos_to_height` returns "the height of the node at `pos`".
//!
//! storage/src/merkle/mod.rs, `Family::inactive_peaks`: "Count the number of oldest peaks that are
//! entirely inactive. A peak is considered entirely inactive if all of its leaves strictly precede
//! the `inactivity_floor`."
//!
//! `kani_p3_{mmr,mmb}_peaks`: for every leaf count `n` (bounds below) and the size `s` for `n`,
//! the peaks of `s`:
//!
//! - number at most `MAX_PINNED_NODES` (64), and exactly `ilog2(n + 1)` for the MMB;
//! - have strictly decreasing heights (MMR) or non-increasing heights (MMB);
//! - each lies inside the structure (`position < s`), has the height it is listed with, and is
//!   the root of the aligned subtree that starts where the previous peak's leaves end: its first
//!   leaf is a multiple of `2^height` and its position is `subtree_root_position(first, height)`;
//! - together cover exactly `n` leaves, and their trees hold exactly `s` nodes;
//! - and for EVERY valid inactivity floor, `inactive_peaks(n, floor)` counts the oldest peaks
//!   whose last leaf is below the floor. A floor is valid up to `MAX_LEAVES`:
//!   storage/src/merkle/location.rs, `Location::is_valid`: "Returns `true` iff this value is a
//!   valid leaf count (`<= MAX_LEAVES`)." The docs give no behavior for an invalid floor.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! None.
//!
//! # Bounds
//!
//! - MMR: leaf counts below 2^10. The peak walk descends from the top bit, so its length grows
//!   with the bit width of the size; loops unwound 16 times.
//! - MMB: leaf counts below 2^12; loops unwound 14 times.
//!
//! These are the slowest proofs of the package. Below 2^12 the MMB proof took 17 minutes and the
//! MMR proof more than 17 minutes; below 2^10 the MMB proof still took 15 minutes, so the leaf
//! count bound is not what makes them slow, and the MMB keeps 2^12. The MMR uses 2^10: a
//! structure still has up to 10 peaks there, and every valid inactivity floor is checked.
//!
//! The documented panic of the peak iterators on an invalid size is not asserted: see "Not
//! covered" in `README.md`.
//!
//! `usize` is 64 bits: nothing here speaks for 32-bit targets.

use crate::common::{any_leaf_count, max_leaves, size_for};
use commonware_storage::merkle::{Family, Location, MAX_PINNED_NODES, Position, mmb, mmr};

/// How the heights of consecutive peaks are ordered.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Order {
    /// Each peak is lower than the one before it (MMR).
    Decreasing,
    /// No peak is higher than the one before it (MMB).
    NonIncreasing,
}

fn peaks<F: Family>(limit: u64, order: Order, exact_count: bool) {
    let n = any_leaf_count::<F>(limit);
    let s = size_for::<F>(n);
    let floor: u64 = kani::any();
    kani::assume(floor <= max_leaves::<F>());

    let mut count: usize = 0;
    let mut first: u64 = 0; // first leaf of the next peak
    let mut nodes: u64 = 0; // nodes in the trees of the peaks seen so far
    let mut previous: Option<u32> = None;
    let mut inactive: usize = 0;
    let mut active_seen = false;
    for (pos, height) in F::peaks(Position::<F>::new(s)) {
        count += 1;
        assert!(count <= MAX_PINNED_NODES);
        assert!(height < 64);
        let leaves = 1u64 << height;

        match previous {
            Some(h) if order == Order::Decreasing => assert!(height < h),
            Some(h) => assert!(height <= h),
            None => {}
        }
        previous = Some(height);

        assert!(pos.as_u64() < s);
        assert!(F::pos_to_height(pos) == height);
        assert!(first % leaves == 0);
        assert!(F::subtree_root_position(Location::<F>::new(first), height) == pos);

        // A peak is inactive when its last leaf, `first + leaves - 1`, is below the floor.
        if !active_seen && first + leaves <= floor {
            inactive += 1;
        } else {
            active_seen = true;
        }

        first += leaves;
        nodes += 2 * leaves - 1;
    }

    assert!(first == n);
    assert!(nodes == s);
    if exact_count {
        assert!(count as u64 == (n + 1).ilog2() as u64);
    }
    assert!(F::inactive_peaks(Location::<F>::new(n), Location::<F>::new(floor)) == inactive);

    kani::cover!(n == 0, "no peaks");
    kani::cover!(count >= 3, "three or more peaks");
    kani::cover!(n == limit - 1, "the largest leaf count of the bound");
    kani::cover!(
        inactive > 0 && inactive < count,
        "some peaks inactive, some not"
    );
    kani::cover!(inactive == count && count > 0, "every peak inactive");
}

#[kani::proof]
#[kani::unwind(16)]
fn kani_p3_mmr_peaks() {
    peaks::<mmr::Family>(1 << 10, Order::Decreasing, false);
}

#[kani::proof]
#[kani::unwind(14)]
fn kani_p3_mmb_peaks() {
    peaks::<mmb::Family>(1 << 12, Order::NonIncreasing, true);
}
