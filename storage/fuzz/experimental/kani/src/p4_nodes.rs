//! P4: node positions, heights, children and leftmost leaves agree with the append schedule.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! storage/src/merkle/mod.rs, the doc of the trait `Family`: "At every valid size, the nodes at
//! height `h` cover exactly the aligned leaf intervals `[k * 2^h, (k + 1) * 2^h)` for `k` in
//! `0..n`, for some `n`. Nodes of a given height are appended in increasing `k` order."
//!
//! storage/src/merkle/mod.rs, the methods of the trait `Family`:
//!
//! - `children`: "Return the positions of the left and right children of the node at `pos` with
//!   the given `height`. The caller guarantees `height > 0` (leaves have no children)."
//! - `parent_heights`: "Return the heights of the internal nodes that lie between `size_for(N)`
//!   and `size_for(N+1)`, where `N` is the given leaf count. These are the nodes created when the
//!   `N`-th leaf is appended."
//! - `subtree_root_position`: "Return the position of the node at `height` whose leftmost leaf is
//!   at `leaf_start`. The node may not exist yet in a given structure (MMB delays merges). The
//!   returned position is where it is appended once it does."
//! - `leftmost_leaf`: "Return the location of the leftmost leaf covered by the node at `pos` with
//!   `height`. For a leaf (height 0), returns its own location."
//! - `pos_to_height`: "Return the height of the node at `pos`."
//! - `birth_offset`: "Return how many leaves, starting with its leftmost leaf, must be appended
//!   before a node at `height` is created. A node whose leftmost leaf is `leaf_start` exists once
//!   the structure has `leaf_start + birth_offset(height)` leaves."
//!
//! The crate's tests walk the same schedule, in storage/src/merkle/mmr/mod.rs and
//! storage/src/merkle/mmb/mod.rs: each step appends the leaf, then the parents of
//! `parent_heights`, with `pos_to_height` of each new node equal to its height
//! (`test_pos_to_height`), with `subtree_root_position` at the leftmost leaf equal to the new
//! position and `leftmost + birth_offset(h) == leaf_idx + 1` (`test_subtree_root_position`), and
//! `subtree_root_position(leftmost_leaf(pos, h), h) == pos` (`test_leftmost_leaf`, and for the
//! MMB `test_subtree_root_position_virtual_roundtrip`).
//!
//! Harnesses, for the MMR and for the MMB:
//!
//! - `kani_p4_{mmr,mmb}_append_schedule`: for every leaf count `n` (bounds below) with `n + 1`
//!   leaves still valid, the nodes between `size_for(n)` and `size_for(n + 1)` are the leaf `n`
//!   (height 0, `subtree_root_position(n, 0)`, `leftmost_leaf` gives `n`) followed by one node
//!   per height of `parent_heights(n)`. Each such node has that height, its leftmost leaf
//!   `l = n + 1 - birth_offset(h)` is aligned to `2^h`, `subtree_root_position(l, h)` is its
//!   position, and `leftmost_leaf` of its position gives `l`.
//! - `kani_p4_{mmr,mmb}_children`: for every height `h > 0` and every aligned leftmost leaf `a`
//!   (bounds below) whose node exists in some valid structure
//!   (`a + birth_offset(h) <= MAX_LEAVES`), the node
//!   at `subtree_root_position(a, h)` has height `h`, `leftmost_leaf` gives `a` back, and its
//!   children are the nodes of height `h - 1` over the two halves of its leaves:
//!   `subtree_root_position(a, h - 1)` and `subtree_root_position(a + 2^(h-1), h - 1)`.
//!
//! # Implementation consistency (asserted only with `--features consistency`; not a gate)
//!
//! - `kani_p4_mmr_append_schedule`: the parent heights come in increasing order, 1, 2, ...
//!   (the docs do not give an order).
//!
//! # Bounds
//!
//! - `kani_p4_mmr_append_schedule`: leaf counts below 2^12 (`parent_heights` yields up to 11
//!   heights there, and `pos_to_height` walks the bits of each position); loops unwound 16
//!   times.
//! - `kani_p4_mmb_append_schedule`: leaf counts below 2^32 (the module docs of
//!   storage/src/merkle/mmb/mod.rs: "Exactly one parent node is born when leaf `S` is inserted,
//!   *unless* `S + 2` is a power of 2"); loops unwound 4 times.
//! - `kani_p4_mmr_children`: heights 1 to 16 and every aligned leftmost leaf below 2^16; loops
//!   unwound 20 times. `pos_to_height` walks the bits of the position, and `leftmost_leaf` inverts
//!   the size map: over the whole domain (heights up to 62) the solver gave no answer within 20
//!   minutes.
//! - `kani_p4_mmb_children`: heights 1 to 61 and every aligned leftmost leaf, whole domain;
//!   loops unwound 4 times.
//!
//! `usize` is 64 bits: nothing here speaks for 32-bit targets.

use crate::common::{any_leaf_count, consistency, max_leaves, size_for};
use commonware_storage::merkle::{Family, Location, Position, mmb, mmr};

fn append_schedule<F: Family>(limit: u64) {
    let n = any_leaf_count::<F>(limit);
    kani::assume(n < max_leaves::<F>());
    let start = size_for::<F>(n);
    let end = size_for::<F>(n + 1);
    let leaf = Location::<F>::new(n);

    // The leaf comes first.
    assert!(F::subtree_root_position(leaf, 0).as_u64() == start);
    assert!(F::pos_to_height(Position::<F>::new(start)) == 0);
    assert!(F::leftmost_leaf(Position::<F>::new(start), 0) == leaf);

    // Then one node per parent height.
    let mut next = start + 1;
    let mut previous: u32 = 0;
    for h in F::parent_heights(leaf) {
        assert!(h > 0 && h < 64);
        assert!(next < end);
        let pos = Position::<F>::new(next);
        assert!(F::pos_to_height(pos) == h);

        let offset = F::birth_offset(h);
        assert!(offset <= n + 1);
        let leftmost = n + 1 - offset;
        assert!(leftmost % (1u64 << h) == 0);
        assert!(F::subtree_root_position(Location::<F>::new(leftmost), h) == pos);
        assert!(F::leftmost_leaf(pos, h).as_u64() == leftmost);
        consistency!(h > previous);

        kani::cover!(h >= 3, "a parent of height 3 or more");
        previous = h;
        next += 1;
    }
    assert!(next == end);

    kani::cover!(end - start == 1, "a step that appends only the leaf");
    kani::cover!(end - start == 2, "a step that appends one parent");
    kani::cover!(n == limit - 1, "the largest leaf count of the bound");
}

/// Nodes of every height from 1 to `max_height` whose leftmost leaf is below `limit`.
fn children<F: Family>(max_height: u32, limit: u64) {
    let h: u32 = kani::any();
    kani::assume(h >= 1 && h <= max_height);
    let k: u64 = kani::any();
    kani::assume(k <= max_leaves::<F>() >> h);
    let a = k << h;
    kani::assume(a < limit);
    let offset = F::birth_offset(h);
    kani::assume(offset <= max_leaves::<F>() && a <= max_leaves::<F>() - offset);

    let pos = F::subtree_root_position(Location::<F>::new(a), h);
    assert!(F::pos_to_height(pos) == h);
    assert!(F::leftmost_leaf(pos, h).as_u64() == a);

    let half = 1u64 << (h - 1);
    let (left, right) = F::children(pos, h);
    assert!(left == F::subtree_root_position(Location::<F>::new(a), h - 1));
    assert!(right == F::subtree_root_position(Location::<F>::new(a + half), h - 1));

    kani::cover!(h == 1, "children are leaves");
    kani::cover!(h == max_height, "the tallest node");
    kani::cover!(a > 0 && h > 1, "a node that does not start at leaf 0");
}

#[kani::proof]
#[kani::unwind(16)]
fn kani_p4_mmr_append_schedule() {
    append_schedule::<mmr::Family>(1 << 12);
}

#[kani::proof]
#[kani::unwind(4)]
fn kani_p4_mmb_append_schedule() {
    append_schedule::<mmb::Family>(1 << 32);
}

#[kani::proof]
#[kani::unwind(20)]
fn kani_p4_mmr_children() {
    children::<mmr::Family>(16, 1 << 16);
}

#[kani::proof]
#[kani::unwind(4)]
fn kani_p4_mmb_children() {
    children::<mmb::Family>(61, u64::MAX);
}
