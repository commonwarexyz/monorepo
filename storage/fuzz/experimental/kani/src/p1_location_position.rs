//! P1: leaf locations and node positions convert into each other over the whole public domain.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! storage/src/merkle/mod.rs, `Family::location_to_position`: "Convert a leaf location to its
//! node position, or equivalently, convert a leaf count to the corresponding total node count
//! (size). The public, guaranteed domain is `loc <= MAX_LEAVES`."
//!
//! storage/src/merkle/mod.rs, `Family::position_to_location`: "Convert a node position to its
//! leaf location, or `None` if the position is not a leaf. Equivalently, convert a total node
//! count (size) to the corresponding leaf count, returning `None` if the size is not valid. The
//! caller guarantees `pos <= MAX_NODES`."
//!
//! storage/src/merkle/mod.rs, `Family::MAX_NODES`: "Maximum valid node count / size", and
//! `Family::MAX_LEAVES`: "Maximum valid leaf count".
//!
//! storage/src/merkle/position.rs, `impl TryFrom<Location> for Position`: "Convert a leaf
//! [Location] to its corresponding node [Position]. ... Returns
//! [`super::Error::LocationOverflow`] if `!loc.is_valid()`." storage/src/merkle/location.rs,
//! `Location::is_valid`: "Returns `true` iff this value is a valid leaf count (`<= MAX_LEAVES`)."
//!
//! storage/src/merkle/location.rs, `impl TryFrom<Position> for Location`: "Attempt to derive the
//! [Location] of a given node [Position]. ... Returns an error if `pos` exceeds the valid range or
//! if it is neither a leaf position nor a valid size." It names no error kind.
//!
//! Harnesses, for the MMR and for the MMB:
//!
//! - `kani_p1_{mmr,mmb}_location_roundtrip`: for EVERY leaf count `n <= MAX_LEAVES`,
//!   `location_to_position(n)` does not panic, is at most `MAX_NODES`, and `position_to_location`
//!   gives `n` back.
//! - `kani_p1_{mmr,mmb}_position_to_location_sound`: for EVERY position `p <= MAX_NODES`, a
//!   returned location is at most `MAX_LEAVES` and maps back to `p`. With the round trip, this
//!   pins `position_to_location` down on the whole domain: it returns `Some(n)` exactly for the
//!   sizes `location_to_position(n)`, and `None` for every other position.
//! - `kani_p1_{mmr,mmb}_try_from`: for every `u64` (bounds below), `Position::try_from` returns
//!   `location_to_position` inside the domain and a `LocationOverflow` error outside it, and
//!   `Location::try_from` returns an error above `MAX_NODES`, and below it either a location
//!   whose size is the position or an error.
//! - `kani_p1_{mmr,mmb}_try_from_leaf`: for every valid leaf count `n` (bounds below),
//!   `Location::try_from` of the size for `n` is `Ok(n)`. With `try_from`: an error comes exactly
//!   for the positions above `MAX_NODES` and for those up to it that are not such a size.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! - `kani_p1_{mmr,mmb}_try_from`: the error payloads and the error kinds of `Location::try_from`.
//!   `LocationOverflow` carries the location it was given; `Location::try_from` returns
//!   `PositionOverflow` with the position above `MAX_NODES` and `NonLeaf` with the position below
//!   it. The crate's tests in storage/src/merkle/mmr/mod.rs assert these for a few MMR inputs
//!   (`test_try_from_position_error_overflow`, `test_try_from_position_error`); no documentation
//!   states them for every input or for the MMB.
//! - `kani_p1_{mmr,mmb}_location_roundtrip`: one more leaf gives a strictly larger size. A comment
//!   in the body of the MMR `Family::position_to_location` (storage/src/merkle/mmr/mod.rs) states
//!   it ("The forward map is strictly increasing"); the docs do not.
//! - `kani_p1_mmb_refine_loop_bound`: for EVERY MMB leaf position, `position_to_location` ends
//!   with its loop body run at most twice. A comment in the body of the MMB
//!   `Family::position_to_location` (storage/src/merkle/mmb/mod.rs) states it: "One refinement
//!   gives accuracy within -1 if the input is a valid leaf position, so the loop body runs at most
//!   twice." With the feature, the harness runs with `#[kani::unwind(2)]` and Kani's unwinding
//!   check, so a third run of the body fails it (the calibration is in `README.md`); without it,
//!   the harness is the plain round trip at unwind 4.
//!
//! # Bounds
//!
//! None on the values: every leaf count up to `MAX_LEAVES`, every position up to `MAX_NODES`,
//! and every `u64` for `TryFrom`, except for the MMR `Location::try_from`: positions below 2^16
//! and from `MAX_NODES` up in `kani_p1_mmr_try_from`, and leaf counts below 2^16 and
//! `MAX_LEAVES` in `kani_p1_mmr_try_from_leaf`. Building its `Result` over the large error enum
//! makes `Location::try_from` about 150 times slower to prove than `position_to_location` (MMB:
//! 240 s against 1.6 s); the MMR inverse over the whole domain is proven for
//! `position_to_location` by `kani_p1_mmr_location_roundtrip` and `..._sound`.
//! Loops: the MMB refinement loop is unwound 4 times (2 in
//! `kani_p1_mmb_refine_loop_bound` with `--features consistency`); the MMR conversion has no
//! loop. The MMR round trip uses the `kissat` solver.
//!
//! The `TryFrom` results are matched by reference and then forgotten (`core::mem::forget`). The
//! error type, `merkle::Error`, also has variants that wrap journal and metadata errors, and
//! their destructors made these proofs one to two orders of magnitude slower. Every path a proof
//! takes past the match holds a `Location`, a `Position` or a plain variant, which need no
//! destructor; the other variants end in `panic!`.
//!
//! `usize` is 64 bits: nothing here speaks for 32-bit targets.

use crate::common::{any_leaf_count, consistency, leaves_for, max_leaves, max_nodes, size_for};
use commonware_storage::merkle::{Error, Family, Location, Position, mmb, mmr};
use core::mem::forget;

fn location_roundtrip<F: Family>() {
    let n = any_leaf_count::<F>(u64::MAX);

    let size = size_for::<F>(n);
    assert!(size <= max_nodes::<F>());
    assert!(leaves_for::<F>(size) == Some(n));
    consistency!(n == max_leaves::<F>() || size_for::<F>(n + 1) > size);

    kani::cover!(n == 0, "the empty structure");
    kani::cover!(n == max_leaves::<F>(), "the largest leaf count");
    kani::cover!(size == max_nodes::<F>(), "the largest size");
}

fn position_to_location_sound<F: Family>() {
    let p: u64 = kani::any();
    kani::assume(p <= max_nodes::<F>());

    match leaves_for::<F>(p) {
        Some(n) => {
            assert!(n <= max_leaves::<F>());
            assert!(size_for::<F>(n) == p);
            kani::cover!(p == max_nodes::<F>(), "the largest size is a leaf count");
            kani::cover!(p > 0, "a nonzero size");
        }
        None => {
            kani::cover!(true, "a position that is not a size");
            kani::cover!(p > max_nodes::<F>() - 4, "a non-size near MAX_NODES");
        }
    }
}

/// `Location::try_from` is checked for positions below `limit` and from `MAX_NODES` up.
fn try_from<F: Family>(limit: u64) {
    // Location to position, every u64.
    let n: u64 = kani::any();
    let loc = Location::<F>::new(n);
    let result = Position::<F>::try_from(loc);
    match &result {
        Ok(pos) => {
            assert!(n <= max_leaves::<F>());
            assert!(*pos == F::location_to_position(loc));
            kani::cover!(n == max_leaves::<F>(), "the largest leaf count converts");
        }
        Err(e) => {
            assert!(n > max_leaves::<F>());
            assert!(matches!(e, Error::LocationOverflow(_)));
            consistency!(matches!(e, Error::LocationOverflow(l) if *l == loc));
            kani::cover!(
                n == max_leaves::<F>() + 1,
                "one past the largest leaf count"
            );
        }
    }
    forget(result);

    // Position to location, every u64. A returned location is checked through the forward map.
    // That no error comes for a size of a valid leaf count is `try_from_leaf`.
    let p: u64 = kani::any();
    kani::assume(p < limit || p >= max_nodes::<F>());
    let pos = Position::<F>::new(p);
    let result = Location::<F>::try_from(pos);
    match &result {
        Ok(l) => {
            assert!(p <= max_nodes::<F>());
            assert!(l.as_u64() <= max_leaves::<F>());
            assert!(size_for::<F>(l.as_u64()) == p);
            kani::cover!(p == max_nodes::<F>(), "the largest size converts");
        }
        Err(e) => {
            consistency!(if p > max_nodes::<F>() {
                matches!(e, Error::PositionOverflow(q) if *q == pos)
            } else {
                matches!(e, Error::NonLeaf(q) if *q == pos)
            });
            kani::cover!(p == max_nodes::<F>() + 1, "one past the largest size");
            kani::cover!(p <= max_nodes::<F>(), "a position that is not a leaf");
        }
    }
    forget(result);
}

/// Every size of a valid leaf count below `limit`, and of `MAX_LEAVES`, converts back to that leaf
/// count through `Location::try_from`.
fn try_from_leaf<F: Family>(limit: u64) {
    let n: u64 = kani::any();
    kani::assume(n < limit || n == max_leaves::<F>());
    kani::assume(n <= max_leaves::<F>());
    let size = size_for::<F>(n);
    let result = Location::<F>::try_from(Position::<F>::new(size));
    match &result {
        Ok(l) => assert!(l.as_u64() == n),
        Err(_) => panic!("the size of a valid leaf count did not convert"),
    }
    forget(result);
    kani::cover!(n == 0, "the empty structure");
    kani::cover!(n == max_leaves::<F>(), "the largest leaf count");
}

#[kani::proof]
#[kani::solver(kissat)]
fn kani_p1_mmr_location_roundtrip() {
    location_roundtrip::<mmr::Family>();
}

#[kani::proof]
#[kani::unwind(4)]
fn kani_p1_mmb_location_roundtrip() {
    location_roundtrip::<mmb::Family>();
}

#[kani::proof]
fn kani_p1_mmr_position_to_location_sound() {
    position_to_location_sound::<mmr::Family>();
}

#[kani::proof]
#[kani::unwind(4)]
fn kani_p1_mmb_position_to_location_sound() {
    position_to_location_sound::<mmb::Family>();
}

#[kani::proof]
fn kani_p1_mmr_try_from() {
    try_from::<mmr::Family>(1 << 16);
}

#[kani::proof]
#[kani::unwind(4)]
fn kani_p1_mmb_try_from() {
    try_from::<mmb::Family>(u64::MAX);
}

#[kani::proof]
fn kani_p1_mmr_try_from_leaf() {
    try_from_leaf::<mmr::Family>(1 << 16);
}

#[kani::proof]
#[kani::unwind(4)]
fn kani_p1_mmb_try_from_leaf() {
    try_from_leaf::<mmb::Family>(u64::MAX);
}

#[kani::proof]
#[cfg_attr(feature = "consistency", kani::unwind(2))]
#[cfg_attr(not(feature = "consistency"), kani::unwind(4))]
fn kani_p1_mmb_refine_loop_bound() {
    // Any leaf position: the size for any valid leaf count. `location_to_position` has no loop,
    // so the only loop this harness runs is the refinement loop of `position_to_location`.
    let n = any_leaf_count::<mmb::Family>(u64::MAX);
    let size = size_for::<mmb::Family>(n);
    assert!(leaves_for::<mmb::Family>(size) == Some(n));

    kani::cover!(n == 0, "the empty structure");
    kani::cover!(n == max_leaves::<mmb::Family>(), "the largest leaf count");
}
