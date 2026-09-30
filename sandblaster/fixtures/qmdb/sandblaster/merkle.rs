//! MMR branch reconstruction, peak bagging and bitmap grafting — the
//! sandblaster port of `merkle.bend`.
//!
//! # Tree contract (qmdb/reference/README.md)
//!
//! * Peaks are perfect binary trees for the set bits of `leaves`, largest
//!   first. Positions count every node in postorder, so a width-`w` peak
//!   occupies `2w − 1` positions.
//! * `leaf = H(u64be(position) ‖ operation)`,
//!   `node = H(u64be(position) ‖ left ‖ right)`, `fold(a, b) = H(a ‖ b)`.
//! * At height `G` (width `CHUNK_BITS = 8N = 2^G`: 8 for N = 1, 256 for
//!   N = 32) a complete chunk-sized subtree is grafted with its activity
//!   chunk: `H(chunk ‖ subtree)` unless the chunk is zero.
//! * Leading inactive peaks are folded left to right; the remaining active
//!   peaks are folded from the right and attached to that accumulator.
//! * `tree_root = H(u64be(leaves) ‖ [u64be(inactive) if inactive ≠ 0] ‖ bag)`.
//!
//! # Mapping from the Bend source
//!
//! | `merkle.bend` | here | note |
//! | --- | --- | --- |
//! | `Peak`, `peak.put`, `peaks` | fused into [`shape`], [`shape_go`] | no heap for the peak list; one tail-recursive pass (a loop after codegen) over the 63 widths `2^62 … 1` (Bend: 32 widths, fewer than `2^32` leaves) |
//! | `Shape`, `shape.pick`, `shape` | [`Shape`], [`shape`] | `after` = peaks below the target = set bits of the remaining leaf count |
//! | `fold` | [`fold`] | fixed 64-byte preimage |
//! | `fold_back.join`, `fold_back` | [`fold_back_join`], [`fold_back`] | depth-bounded recursion over the peak list, `max = 64` (§3.7 b) |
//! | `graft` | [`graft`] | fixed `N + 32`-byte preimage (`config::GRAFT_BYTES`) |
//! | `path.node`, `path` | [`path_node`], [`path`] | depth-bounded recursion, `max = 64` (§3.7 b) |
//! | `bag_prefix` | [`bag_prefix`] | tail recursive |
//! | `root.seal`, `root` | [`root_seal`] (with [`seal_leaves`], [`seal_counts`]), [`root`] | fixed 40/48-byte preimages; `root` takes the peak list in three parts |
//! | `reconstruct.finish` | [`reconstruct_finish`], with [`fold_back3`], [`bag_prefix3`] | bags `before ‖ [peak] ‖ after` in place, without concatenating |
//! | `reconstruct.checked`, `reconstruct.shape`, `reconstruct` | same names | |
//! | `List.take`, `List.drop`, `List.get` | [`list_take`], [`list_drop`], [`list_get`] | truncating semantics, like Bend |
//!
//! # Porting rules applied (DESIGN.md §11.2)
//!
//! * Every Bend `Nat.sub` not dominated by a guard is `saturating_sub`
//!   (Bend's `Nat.sub` truncates at 0, so this is exact and has no
//!   obligation): peak positions `p + 2w − 2` / `p + 2w − 1`, child
//!   positions `p − w` / `p − 1`, `before − folded`,
//!   `inactive − (before + 1)`, `inactive − folded`, `effective − 1`.
//! * Types: decoded fields (`leaves`, `inactive`, `location`), widths,
//!   positions and indices are `u64` (Commonware's domain: `leaves ≤
//!   MAX_LEAVES = 2^62`, `inactive` any `u64`); `Shape` counts (`height`,
//!   `before`, `after`, all ≤ 62) are `u32`; digest counts are computed in
//!   `u64` from the `u32` counts, and `inactive` enters them only through
//!   `min` and `saturating_sub`, so every sum is bounded by the types.
//! * Guarded subtractions (`remaining − width`, `index − start`,
//!   `index − half`, `height − 1`) keep plain `-`: the guard is a path
//!   condition.
//!
//! These functions are total for **arbitrary** arguments (the merkle laws
//! quantify over any `Shape`); only two private helpers have preconditions:
//! [`shape_go`] (the search invariants, which [`shape`] establishes) and
//! [`path`] (its stack depth), which [`reconstruct_checked`] establishes with
//! a defensive height check that never fires for shapes produced by
//! [`shape`] (height ≤ 62, law `shape_bounds`).

use sandblaster::prelude::*;

use super::codec::be64;
use super::config::{CHUNK_BITS, CHUNK_BYTES, Chunk, GRAFT_BYTES, hash_graft};
use super::sha256::{Digest, hash_40, hash_48, hash_64, hash_72, hash_73};

/// Largest leaf count of an MMR (Commonware `MAX_LEAVES`,
/// storage/src/merkle/mmr/mod.rs:110): its size `2^63 − 1` is the largest
/// node count. The verifier decodes `location` and `leaves` only up to it
/// (`codec::location`).
pub const MAX_LEAVES: u64 = 1 << 62u32;

/// Largest `path` height accepted (the §3.7 stack-depth bound). Shapes from
/// [`shape`] have height ≤ 62 (a single peak of `MAX_LEAVES` leaves).
pub const MAX_HEIGHT: u32 = 64;

/// Largest peak list [`reconstruct_finish`] bags: an MMR with at most
/// `MAX_LEAVES = 2^62` leaves has at most 62 peaks (one per set bit; 62 at
/// `2^62 − 1`). For a shape from [`shape`], the list `before ‖ [peak] ‖
/// after` has at most `before + 1 + after` = (number of peaks) ≤ 62
/// entries, because `before_count ≤ before` and `after_count ≤ after`.
pub const MAX_PEAK_DIGESTS: usize = 62;

/// The peak containing the queried leaf, and its neighbours. Bend: `Shape`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[view(crate::model::Shape)]
pub struct Shape {
    /// Height of the peak (a width-`2^height` perfect tree).
    pub height: u32,
    /// Number of leaves under the peak.
    pub width: u64,
    /// Postorder position of the peak node.
    pub position: u64,
    /// Index of the queried leaf within the peak.
    pub index: u64,
    /// Number of peaks to the left (larger peaks).
    pub before: u32,
    /// Number of peaks to the right (smaller peaks).
    pub after: u32,
}

/// Locate the peak containing leaf `index` of an MMR with `leaves` leaves.
/// Bend: `shape(peaks(32, leaves, 2^31, 0, 0), index, 0)`, over Commonware's
/// domain: 63 widths from `2^62`.
///
/// The Bend version first builds the list of peaks (`peaks`) and then
/// searches it (`shape`); without a heap both happen in one pass over the 63
/// possible widths `2^62, 2^61, …, 1` ([`shape_go`], one width per step). A
/// width is a peak when the leaves not yet covered (`remaining`) include it.
/// At the peak containing `index`: `height` = log2 of its width,
/// `position = position + 2·width − 2`, `index − start`, `before` = peaks
/// seen so far, and `after` = the number of peaks still to come = the set
/// bits of `remaining − width` (Bend: `List.length(rest)`). Peak ranges are
/// disjoint, so at most one matches (Bend keeps the first match; the result
/// is the same). For fewer than `2^32` leaves the first 31 widths are never
/// peaks, so the result is Bend's.
///
/// A leaf count above [`MAX_LEAVES`] has no MMR and returns `None` (the
/// verifier never asks: `codec::location` rejects it at decode). The guard
/// also bounds the search's sums (see [`shape_go`]). Laws: `shape_bounds`
/// (every shape found lies inside the tree, height ≤ 62),
/// `leaves_above_max_rejected`.
#[refines(crate::model::shape)]
pub fn shape(leaves: u64, index: u64) -> Option<Shape> {
    if leaves > MAX_LEAVES {
        return None;
    }
    // the 63 widths `2^62, …, 1`, from an empty search: nothing covered, nothing found
    shape_go(63, index, leaves, 1 << 62u32, 0, 0, 0, None)
}

/// One width of the [`shape`] search per call, largest first. `fuel` widths
/// are left and the current one is `width` (`2^(fuel − 1)` from [`shape`]);
/// the peaks seen so far cover all leaves before `start` and their nodes all
/// positions before `position`; `remaining` leaves are not covered yet;
/// `before` peaks were seen; `found` is the peak holding `target`, if it was
/// one of them.
///
/// Tail recursive, so a loop after codegen (§3.7 a), measure `fuel`. The
/// requires are the search's invariants, stated over `Int` so they carry no
/// obligations of their own: `start + remaining ≤ MAX_LEAVES`, `position ≤
/// 2·start` and `before + fuel ≤ 63`. They bound every sum by `2·MAX_LEAVES
/// = 2^63` and `before + 1` by 63; no invariant about `width` is needed
/// because the peak positions use `saturating_sub` (Bend's truncating
/// `Nat.sub`). The target test is two nested comparisons rather than one
/// `&&`, so the proof of `shape_bounds` can decide them one at a time.
#[refines(crate::model::shape_go)]
#[requires(fuel <= 63)]
#[requires((start as Int) + (remaining as Int) <= (MAX_LEAVES as Int))]
#[requires((position as Int) <= 2 * (start as Int))]
#[requires((before as Int) + (fuel as Int) <= 63)]
#[decreases(fuel)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn shape_go(
    fuel: u32,
    target: u64,
    remaining: u64,
    width: u64,
    position: u64,
    start: u64,
    before: u32,
    found: Option<Shape>,
) -> Option<Shape> {
    if fuel == 0 {
        return found;
    }
    if remaining < width {
        // not a peak: fewer than `width` leaves are left
        shape_go(fuel - 1, target, remaining, width / 2, position, start, before, found)
    } else {
        // a peak over leaves `start ..< start + width`; its root is the last of
        // its `2·width − 1` nodes
        let found = if target < start {
            found
        } else if target - start < width {
            Some(Shape {
                height: fuel - 1,
                width,
                position: (position + 2 * width).saturating_sub(2),
                index: target - start,
                before,
                after: (remaining - width).count_ones(),
            })
        } else {
            found
        };
        let next = (position + 2 * width).saturating_sub(1);
        shape_go(fuel - 1, target, remaining - width, width / 2, next, start + width, before + 1, found)
    }
}

/// Peak fold `H(left ‖ right)`. Bend: `fold`.
pub fn fold(left: &Digest, right: &Digest) -> Digest {
    let mut msg = [0u8; 64];
    msg[0..32].copy_from_slice(left);
    msg[32..64].copy_from_slice(right);
    hash_64(&msg)
}

/// Attach `head` in front of an optional right fold. Bend: `fold_back.join`.
pub fn fold_back_join(head: &Digest, tail: Option<Digest>) -> Option<Digest> {
    match tail {
        None => Some(*head),
        Some(digest) => Some(fold(head, &digest)),
    }
}

/// Fold a list of peaks from the right: `None` for the empty list, else
/// `fold(x0, fold(x1, … x_{n−1}))`. Bend: `fold_back`. Recursion depth
/// `xs.len()`: at most [`MAX_PEAK_DIGESTS`] for a peak list (§3.7 b).
#[requires(xs.len() <= MAX_PEAK_DIGESTS)]
#[decreases(xs.len(), max = 64)]
pub fn fold_back(xs: &[Digest]) -> Option<Digest> {
    match xs.first() {
        None => None,
        Some(head) => fold_back_join(head, fold_back(&xs[1..])),
    }
}

/// Graft: `H(chunk ‖ digest)` when `enabled`, else `digest`. Bend: `graft`.
pub fn graft(enabled: bool, chunk: &Chunk, digest: &Digest) -> Digest {
    if enabled {
        let mut msg = [0u8; GRAFT_BYTES];
        msg[0..CHUNK_BYTES].copy_from_slice(chunk);
        msg[CHUNK_BYTES..GRAFT_BYTES].copy_from_slice(digest);
        hash_graft(&msg)
    } else {
        *digest
    }
}

/// Leaf digest `H(u64be(position) ‖ operation)` (73 bytes).
pub fn leaf_digest(position: u64, operation: &[u8; 65]) -> Digest {
    let mut msg = [0u8; 73];
    msg[0..8].copy_from_slice(&be64(position));
    msg[8..73].copy_from_slice(operation);
    hash_73(&msg)
}

/// Inner node digest `H(u64be(position) ‖ left ‖ right)` (72 bytes).
pub fn node_digest(position: u64, left: &Digest, right: &Digest) -> Digest {
    let mut msg = [0u8; 72];
    msg[0..8].copy_from_slice(&be64(position));
    msg[8..40].copy_from_slice(left);
    msg[40..72].copy_from_slice(right);
    hash_72(&msg)
}

/// Combine a reconstructed child with its sibling into the parent at
/// `position`, grafting the activity chunk at width [`CHUNK_BITS`] (Commonware
/// grafting.rs:356-401: the height-`G` node, unless the chunk is all zero).
/// `left` says the child is the left subtree. Bend: `path.node`.
pub fn path_node(
    left: bool,
    width: u64,
    position: u64,
    chunk: &Chunk,
    sibling: Option<&Digest>,
    child: Option<Digest>,
) -> Option<Digest> {
    match (sibling, child) {
        (Some(s), Some(c)) => {
            let digest = if left { node_digest(position, &c, s) } else { node_digest(position, s, &c) };
            Some(graft(width == CHUNK_BITS && *chunk != [0u8; CHUNK_BYTES], chunk, &digest))
        }
        _ => None,
    }
}

/// The first `n` digests of `xs`, or all of them if there are fewer.
/// Bend: `List.take`.
pub fn list_take(xs: &[Digest], n: usize) -> &[Digest] {
    match xs.split_at_checked(n) {
        Some((init, _)) => init,
        None => xs,
    }
}

/// `xs` without its first `n` digests, or empty if there are fewer.
/// Bend: `List.drop`.
pub fn list_drop(xs: &[Digest], n: usize) -> &[Digest] {
    match xs.split_at_checked(n) {
        Some((_, rest)) => rest,
        None => &xs[xs.len()..],
    }
}

/// The digest at `i` in `xs`, if there is one. Bend: `List.get`.
pub fn list_get(xs: &[Digest], i: usize) -> Option<&Digest> {
    list_drop(xs, i).first()
}

/// Reconstruct the digest of the subtree of height `height` rooted at
/// `position` (with `width` leaves) that contains leaf `index`, from the
/// operation and the sibling digests. Bend: `path`.
///
/// Single-leaf range proofs list siblings in left-first DFS order: a left
/// branch's sibling follows its descendants (`siblings[height − 1]`, and the
/// child uses the first `height − 1`), a right branch's sibling precedes them
/// (`siblings[0]`, and the child uses the rest).
///
/// Non-tail recursion, depth `height` (≤ 62 for a shape from [`shape`]),
/// bounded by [`MAX_HEIGHT`] (§3.7 b). `position − width` and `position − 1`
/// are Bend `Nat.sub`s and saturate (they never do for MMR geometry). The
/// chunk is passed by reference, so the frame does not grow with N.
#[requires(height <= MAX_HEIGHT)]
#[decreases(height, max = 64)]
pub(crate) fn path(
    height: u32,
    position: u64,
    width: u64,
    index: u64,
    operation: &[u8; 65],
    chunk: &Chunk,
    siblings: &[Digest],
) -> Option<Digest> {
    if height == 0 {
        return Some(leaf_digest(position, operation));
    }
    let p = height - 1;
    let half = width / 2;
    let left = index < half;
    let sibling = list_get(siblings, if left { p as usize } else { 0 });
    let child = if left {
        path(p, position.saturating_sub(width), half, index, operation, chunk, list_take(siblings, p as usize))
    } else {
        path(p, position.saturating_sub(1), half, index - half, operation, chunk, list_drop(siblings, 1))
    };
    path_node(left, width, position, chunk, sibling, child)
}

/// Fold the first `n` digests of `xs` into `acc` from the left, then attach
/// the right fold of the rest. `None` if `xs` has fewer than `n` digests.
/// Bend: `bag_prefix`. Laws: `bag_prefix_partition`, `bag_prefix_order`.
///
/// Tail recursive (§3.7 a), measure `n`. `xs` is at most a peak list.
#[requires(xs.len() <= MAX_PEAK_DIGESTS)]
pub fn bag_prefix(n: usize, xs: &[Digest], acc: Digest) -> Option<Digest> {
    if n == 0 {
        return fold_back_join(&acc, fold_back(xs));
    }
    match xs.first() {
        None => None,
        Some(head) => bag_prefix(n - 1, &xs[1..], fold(&acc, head)),
    }
}

/// The seal without an inactive count: `H(u64be(leaves) ‖ bag)` (40 bytes).
pub fn seal_leaves(leaves: u64, bag: &Digest) -> Digest {
    let mut msg = [0u8; 40];
    msg[0..8].copy_from_slice(&be64(leaves));
    msg[8..40].copy_from_slice(bag);
    hash_40(&msg)
}

/// The seal with an inactive count: `H(u64be(leaves) ‖ u64be(inactive) ‖ bag)`
/// (48 bytes).
pub fn seal_counts(leaves: u64, inactive: u64, bag: &Digest) -> Digest {
    let mut msg = [0u8; 48];
    msg[0..8].copy_from_slice(&be64(leaves));
    msg[8..16].copy_from_slice(&be64(inactive));
    msg[16..48].copy_from_slice(bag);
    hash_48(&msg)
}

/// Seal the bagged peaks into the tree root: [`seal_leaves`] if `inactive ==
/// 0`, else [`seal_counts`]. Bend: `root.seal`.
pub fn root_seal(leaves: u64, inactive: u64, bag: Option<Digest>) -> Option<Digest> {
    match bag {
        None => None,
        Some(digest) => {
            if inactive == 0 { Some(seal_leaves(leaves, &digest)) } else { Some(seal_counts(leaves, inactive, &digest)) }
        }
    }
}

/// Right-fold the peak list `xs ‖ [mid] ‖ ys` without concatenating it:
/// `fold(x0, … fold(mid, fold_back(ys)) …)`. Bend: `fold_back` of the
/// appended list. Recursion depth `xs.len()` (§3.7 b).
#[requires(xs.len() + ys.len() < MAX_PEAK_DIGESTS)]
#[decreases(xs.len(), max = 64)]
pub fn fold_back3(xs: &[Digest], mid: &Digest, ys: &[Digest]) -> Option<Digest> {
    match xs.first() {
        None => fold_back_join(mid, fold_back(ys)),
        Some(head) => fold_back_join(head, fold_back3(&xs[1..], mid, ys)),
    }
}

/// [`bag_prefix`] on the peak list `xs ‖ [mid] ‖ ys`, without concatenating
/// it. Bend: `bag_prefix` of the appended list.
///
/// Tail recursive (§3.7 a), measure `n`.
#[requires(xs.len() + ys.len() < MAX_PEAK_DIGESTS)]
pub fn bag_prefix3(n: usize, xs: &[Digest], mid: &Digest, ys: &[Digest], acc: Digest) -> Option<Digest> {
    if n == 0 {
        return fold_back_join(&acc, fold_back3(xs, mid, ys));
    }
    match xs.first() {
        None => bag_prefix(n - 1, ys, fold(&acc, mid)),
        Some(head) => bag_prefix3(n - 1, &xs[1..], mid, ys, fold(&acc, head)),
    }
}

/// Bag the peak list `before ‖ [peak] ‖ after` (as carried by the proof,
/// target peak included) and seal it. The first `effective` entries are the
/// inactive prefix (the folded-prefix digest counts as one); they are folded
/// from the left, the rest from the right. Bend: `root`.
///
/// `effective = (inactive − folded) + [folded ≠ 0]` cannot overflow: with
/// `folded ≠ 0` the saturating difference is at most `u64::MAX − 1`.
#[requires(before.len() + after.len() < MAX_PEAK_DIGESTS)]
pub fn root(leaves: u64, inactive: u64, folded: u64, before: &[Digest], peak: &Digest, after: &[Digest]) -> Option<Digest> {
    let effective = inactive.saturating_sub(folded) as usize + (folded != 0) as usize;
    let n = effective.saturating_sub(1);
    match before.first() {
        None => root_seal(leaves, inactive, bag_prefix(n, after, *peak)),
        Some(head) => root_seal(leaves, inactive, bag_prefix3(n, &before[1..], peak, after, *head)),
    }
}

/// Bag the peak list `before ‖ [peak] ‖ after` and compute the root.
/// Bend: `reconstruct.finish`.
///
/// Bend appends lists; here [`root`] bags the three parts in place. A peak
/// list longer than [`MAX_PEAK_DIGESTS`] is rejected (it bounds the
/// recursion depth of [`fold_back3`]); that never happens for a shape
/// computed by [`shape`] (see [`MAX_PEAK_DIGESTS`]), only for arbitrary
/// shapes passed to [`reconstruct_shape`] directly, where rejecting keeps the
/// merkle laws true (they only constrain successful reconstructions).
pub fn reconstruct_finish(
    leaves: u64,
    inactive: u64,
    folded: u64,
    before: &[Digest],
    after: &[Digest],
    peak: Option<Digest>,
) -> Option<Digest> {
    let digest = peak?;
    if before.len() + after.len() >= MAX_PEAK_DIGESTS {
        return None;
    }
    root(leaves, inactive, folded, before, &digest, after)
}

/// Split the proof digests into the peaks before the target, the peaks after
/// it and the target's siblings, reconstruct the target peak and the root.
/// `ok` is the digest-count check of [`reconstruct_shape`].
/// Bend: `reconstruct.checked`.
///
/// Besides `ok`, a height above [`MAX_HEIGHT`] is rejected before calling
/// [`path`] (its stack-depth precondition); shapes from [`shape`] never have
/// one.
#[allow(clippy::too_many_arguments)]
pub fn reconstruct_checked(
    ok: bool,
    leaves: u64,
    inactive: u64,
    folded: u64,
    before_count: u64,
    after_count: u64,
    height: u32,
    position: u64,
    width: u64,
    index: u64,
    operation: &[u8; 65],
    chunk: &Chunk,
    digests: &[Digest],
) -> Option<Digest> {
    if !ok {
        return None;
    }
    if height > MAX_HEIGHT {
        return None;
    }
    let before_count = before_count as usize;
    let after_count = after_count as usize;
    let before = list_take(digests, before_count);
    let after = list_take(list_drop(digests, before_count), after_count);
    let siblings = list_drop(digests, before_count.saturating_add(after_count));
    reconstruct_finish(
        leaves,
        inactive,
        folded,
        before,
        after,
        path(height, position, width, index, operation, chunk, siblings),
    )
}

/// Check that the proof carries exactly the digests the target shape needs,
/// then reconstruct. Bend: `reconstruct.shape`. Laws: `merkle_digest_count`,
/// `merkle_wrong_count_rejected` (the count formula is `required_digests`
/// in `LAWS.rs`, written with the same operations).
///
/// * `folded = min(before, inactive)`: inactive peaks before the target,
///   carried as one folded digest (if any);
/// * `before_count = (before − folded) + [folded ≠ 0]`;
/// * `inactive_after = min(after, inactive − (before + 1))`: inactive peaks
///   after the target, carried individually;
/// * `after_count = inactive_after + [after > inactive_after]`: plus one
///   backward-folded digest for the active suffix;
/// * valid iff `inactive ≤ before + after + 1` and
///   `digests.len() == height + before_count + after_count`.
pub fn reconstruct_shape(
    leaves: u64,
    inactive: u64,
    operation: &[u8; 65],
    chunk: &Chunk,
    digests: &[Digest],
    target: Option<Shape>,
) -> Option<Digest> {
    let target = target?;
    let folded = (target.before as u64).min(inactive);
    let before_count = (target.before as u64).saturating_sub(folded) + (folded != 0) as u64;
    let inactive_after = (target.after as u64).min(inactive.saturating_sub(target.before as u64 + 1));
    let after_count = inactive_after + (target.after as u64 > inactive_after) as u64;
    let valid = inactive <= target.before as u64 + target.after as u64 + 1
        && digests.len() as u64 == target.height as u64 + before_count + after_count;
    reconstruct_checked(
        valid,
        leaves,
        inactive,
        folded,
        before_count,
        after_count,
        target.height,
        target.position,
        target.width,
        target.index,
        operation,
        chunk,
        digests,
    )
}

/// Reconstruct the tree root that authenticates `operation` at leaf
/// `index`. Bend: `reconstruct`.
pub fn reconstruct(
    index: u64,
    leaves: u64,
    inactive: u64,
    operation: &[u8; 65],
    chunk: &Chunk,
    digests: &[Digest],
) -> Option<Digest> {
    reconstruct_shape(leaves, inactive, operation, chunk, digests, shape(leaves, index))
}
