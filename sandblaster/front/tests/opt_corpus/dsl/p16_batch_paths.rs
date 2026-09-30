//! P16: a batch of K equal-shape 20-deep hash paths (docs/optimizer-plan.md
//! O1; design §14.2 "fusion / lanes"). Each path folds a leaf up 20 levels
//! (a Merkle inclusion proof); the K paths are independent, so their
//! dependent hash chains can be interleaved (ILP) or run in lanes. Written
//! the natural way: one path at a time.
use sandblaster::prelude::*;

/// Levels of every path.
pub const PATH_DEPTH: usize = 20;
/// Paths per batch.
pub const BATCH: usize = 8;

/// An inner node: two multiply-xorshift rounds over both children.
pub fn path_node(l: u64, r: u64) -> u64 {
    let x = (l ^ r.rotate_left(17)).wrapping_mul(0xd6e8_feb8_6659_fd93);
    let y = (x ^ (x >> 32u32)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    y ^ (y >> 29u32) ^ l
}

/// Folds `acc` up the levels `level..20`: at level `i` the sibling is on the
/// left when bit `i` of `index` is set.
#[requires(level <= 20)]
#[decreases(20 - level)]
fn path_go(level: u32, index: u64, acc: u64, siblings: &[u64; 20]) -> u64 {
    if level >= 20 {
        acc
    } else {
        let s = siblings[level as usize];
        let next = if (index >> level) & 1 == 1 { path_node(s, acc) } else { path_node(acc, s) };
        path_go(level + 1, index, next, siblings)
    }
}

/// The root of one path.
pub fn path_root(leaf: u64, index: u64, siblings: &[u64; 20]) -> u64 {
    path_go(0, index, leaf, siblings)
}

/// The roots of a batch of [`BATCH`] paths of the same shape.
pub fn batch_roots(leaves: &[u64; 8], indices: &[u64; 8], siblings: &[[u64; 20]; 8]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for k in 0..8usize {
        out[k] = path_root(leaves[k], indices[k], &siblings[k]);
    }
    out
}
