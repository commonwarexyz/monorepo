//! P15: threaded-cursor tree DFS (docs/optimizer-plan.md O1; design §14.2
//! "state decoupling"). The root of a perfect binary tree over `2^height`
//! leaves, computed the way Commonware's `reconstruct_digest` walks a proof:
//! depth first, left subtree then right subtree, with a cursor into the leaf
//! list threaded through the recursion. The cursor serializes the two
//! recursive calls; its effect of one subtree is the closed form `+ 2^h`, so
//! the calls are independent (then interleaved, laned or threaded).
use sandblaster::prelude::*;

/// Largest supported height (4096 leaves).
pub const MAX_TREE_HEIGHT: u32 = 12;

/// An inner node: two multiply-xorshift rounds over both children.
pub fn tree_node(l: u64, r: u64) -> u64 {
    let x = (l ^ r.rotate_left(23)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let y = (x ^ (x >> 29u32)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    y ^ (y >> 32u32) ^ r
}

/// The root of the subtree of height `height` whose leaves start at
/// `cursor`, and the cursor after its last leaf (`None` if the leaves run
/// out).
#[requires(height <= MAX_TREE_HEIGHT)]
#[decreases(height, max = 16)]
fn dfs_go(height: u32, leaves: &[u64], cursor: usize) -> Option<(u64, usize)> {
    if height == 0 {
        if cursor < leaves.len() { Some((leaves[cursor], cursor + 1)) } else { None }
    } else {
        let (l, c1) = dfs_go(height - 1, leaves, cursor)?;
        let (r, c2) = dfs_go(height - 1, leaves, c1)?;
        Some((tree_node(l, r), c2))
    }
}

/// The root over exactly `2^height` leaves (`None` for a wrong leaf count
/// or a height above [`MAX_TREE_HEIGHT`]).
pub fn tree_root(height: u32, leaves: &[u64]) -> Option<u64> {
    if height > MAX_TREE_HEIGHT {
        return None;
    }
    let (d, c) = dfs_go(height, leaves, 0)?;
    if c == leaves.len() { Some(d) } else { None }
}
