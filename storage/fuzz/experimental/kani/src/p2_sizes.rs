//! P2: which sizes are valid, and rounding a size down to a valid one.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! storage/src/merkle/mod.rs, `Family::is_valid_size`: "Whether `size` is a valid tree size for
//! this Merkle structure." storage/src/merkle/position.rs, `Position::is_valid_size`: "Returns
//! whether this is a valid size for this Merkle structure."
//!
//! storage/src/merkle/mod.rs, `Family::position_to_location`: "Equivalently, convert a total node
//! count (size) to the corresponding leaf count, returning `None` if the size is not valid. The
//! caller guarantees `pos <= MAX_NODES`." storage/src/merkle/mod.rs, `Family::MAX_NODES`:
//! "Maximum valid node count / size".
//!
//! storage/src/merkle/mod.rs, `Family::to_nearest_size`: "Returns the largest valid size that is
//! no greater than `size`." The panic above `MAX_NODES` (the `# Panics` sections of
//! `PeakIterator::to_nearest_size` in storage/src/merkle/mmr/iterator.rs and
//! storage/src/merkle/mmb/iterator.rs) is not asserted: see "Not covered" in `README.md`.
//!
//! Harnesses:
//!
//! - `kani_p2_{mmr,mmb}_valid_size_agrees`: `is_valid_size` and `Position::is_valid_size` agree
//!   with `position_to_location` on every size up to `MAX_NODES` (bounds below), and no size above
//!   `MAX_NODES` is valid.
//! - `kani_p2_{mmr,mmb}_to_nearest_size`: for every size up to `MAX_NODES` (bounds below), the
//!   result is at most the size, is valid (`position_to_location` maps it to a leaf count), and no
//!   valid size lies between the result and the size. Validity is read through
//!   `position_to_location`, which P1 pins down on the whole domain. Maximality is checked for
//!   EVERY leaf count `k`: if the size for `k` is at most the input, it is at most the result.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! None.
//!
//! # Bounds
//!
//! - MMR, `kani_p2_mmr_valid_size_agrees`: sizes below 2^16 and every size above `MAX_NODES`.
//!   The descent of `is_valid_size` over the full domain gave no answer within 38 minutes.
//!   Below 2^16 the descent runs at most 32 times (15 halvings, each after at most one step to a
//!   right sibling); loops unwound 34 times.
//! - MMR, `kani_p2_mmr_to_nearest_size`: sizes below 2^16; the binary search runs at most 17
//!   times there. Loops unwound 20 times. The leaf count `k` of the maximality check ranges
//!   over the whole domain.
//! - MMB: none, every `u64` (`valid_size_agrees`) and every size up to `MAX_NODES`
//!   (`to_nearest_size`). The refinement loop is unwound 4 times.
//!
//! `usize` is 64 bits: nothing here speaks for 32-bit targets.

use crate::common::{any_leaf_count, leaves_for, max_nodes, size_for};
use commonware_storage::merkle::{Family, Position, mmb, mmr};

/// Sizes below `limit`, plus (when `above_max`) every size above `MAX_NODES`.
fn valid_size_agrees<F: Family>(limit: u64, above_max: bool) {
    let p: u64 = kani::any();
    kani::assume(p < limit || (above_max && p > max_nodes::<F>()));
    let pos = Position::<F>::new(p);

    let valid = F::is_valid_size(pos);
    assert!(valid == pos.is_valid_size());
    if p > max_nodes::<F>() {
        assert!(!valid);
        kani::cover!(p == max_nodes::<F>() + 1, "one past MAX_NODES");
    } else {
        assert!(valid == leaves_for::<F>(p).is_some());
        kani::cover!(valid && p > 0, "a valid nonzero size");
        kani::cover!(!valid, "an invalid size");
    }
}

fn to_nearest_size<F: Family>(limit: u64) {
    let s: u64 = kani::any();
    kani::assume(s <= max_nodes::<F>());
    kani::assume(s < limit);

    let r = F::to_nearest_size(Position::<F>::new(s)).as_u64();
    assert!(r <= s);
    assert!(leaves_for::<F>(r).is_some());

    // Largest: every valid size up to `s` is also up to `r`.
    let k = any_leaf_count::<F>(u64::MAX);
    let size_k = size_for::<F>(k);
    if size_k <= s {
        assert!(size_k <= r);
    }

    kani::cover!(r == s && s > 0, "a valid size maps to itself");
    kani::cover!(r < s, "an invalid size rounds down");
    kani::cover!(size_k == r && r > 0, "the largest check meets the result");
}

#[kani::proof]
#[kani::solver(kissat)]
#[kani::unwind(34)]
fn kani_p2_mmr_valid_size_agrees() {
    valid_size_agrees::<mmr::Family>(1 << 16, true);
}

#[kani::proof]
#[kani::unwind(4)]
fn kani_p2_mmb_valid_size_agrees() {
    valid_size_agrees::<mmb::Family>(u64::MAX, true);
}

#[kani::proof]
#[kani::unwind(20)]
fn kani_p2_mmr_to_nearest_size() {
    to_nearest_size::<mmr::Family>(1 << 16);
}

#[kani::proof]
#[kani::unwind(4)]
fn kani_p2_mmb_to_nearest_size() {
    to_nearest_size::<mmb::Family>(u64::MAX);
}
