//! A Current database and the root it commits to: a Merkle mountain range over the operations,
//! each chunk of 8N operations' activity flags grafted onto the node above them, sealed with the
//! sizes and combined with the operations root. Commonware 6e15fe7c: merkle/mmr/{mod,iterator}.rs,
//! merkle/hasher.rs, qmdb/current/{grafting,db}.rs.

use super::config::{C, G, N};
use super::sha256::Digest;
use super::tree::{Tree, bytes, eval, hash};
use crate::stdlib::folds;

/// The most operations a database holds (mmr/mod.rs:110).
pub const MAX_LEAVES: Nat = pow2(62);

/// An encoded operation (65 bytes for Commonware's fixed-size operations).
pub type Op = Seq<u8>;

/// The operation `Update(key, value)`: `0xD2 ‖ key ‖ value` (any/operation/fixed.rs:35-63).
#[example(update(seq![1u8], seq![2u8]) == seq![0xD2u8, 1u8, 2u8])]
pub fn update(key: Seq<u8>, value: Seq<u8>) -> Op { seq![0xD2u8, ..key, ..value] }

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Db {
    pub log: Seq<(Op, bool)>, // operation `i` (leaf `i`), and whether it is active: not superseded
    pub inactive: Nat,        // how many leading peaks the root folds as inactive
    pub ops_root: Digest,     // the operations root: committed, not interpreted by operation proofs
}

impl Db {
    pub fn leaves(&self) -> Nat { self.log.len() }

    /// Commonware's domain: 1 to 2^62 operations, no more inactive peaks than peaks.
    #[example(Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.well_formed() && Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.leaves() == 1)]
    #[example(!Db { log: seq![], inactive: 0, ops_root: [0u8; 32] }.well_formed())]
    pub fn well_formed(&self) -> bool {
        0 < self.leaves() && self.leaves() <= MAX_LEAVES && self.inactive <= popcount(self.leaves())
    }

    /// Operation `i` is `op`, and it is active.
    #[example(Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.is_current(0, seq![5u8]))]
    #[example(!Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.is_current(0, seq![6u8]))]
    pub fn is_current(&self, i: Nat, op: Op) -> bool { self.log.get(i) == Some((op, true)) }

    /// The root commits to the whole database: nothing is pruned but the operations root.
    #[example(Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.root() == eval(current_root(Tree::Pruned([0u8; 32]), 1, 0, leaf(0, seq![5u8]), hash(seq![bytes(seq![..Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.chunk(0)])]))))]
    pub fn root(&self) -> Seq<u8> { eval(self.tree()) }

    pub fn tree(&self) -> Tree {
        let (n, k) = (self.leaves(), self.inactive);
        current_root(Tree::Pruned(self.ops_root), n, k, bag(self.peaks(0, n), k), hash(seq![bytes(self.chunk(n / C))]))
    }

    /// The peaks over the `n` leaves from `s`: a perfect tree per set bit of `n`, largest first.
    #[decreases(n)]
    #[example(Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.peaks(0, 1).len() == 1 && eval(bag(Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.peaks(0, 1), 0)) == eval(Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.subtree(0, 0)))]
    #[example(eval(Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.subtree(0, 0)) == eval(leaf(0, seq![5u8])))]
    pub fn peaks(&self, s: Nat, n: Nat) -> Seq<Tree> {
        if n == 0 { return seq![]; }
        let h = log2(n);
        seq![self.subtree(h, s), ..self.peaks(s + pow2(h), n - pow2(h))]
    }

    /// The perfect tree of height `h` over leaves `s ..< s + 2^h`.
    pub fn subtree(&self, h: Nat, s: Nat) -> Tree {
        if h == 0 { return leaf(s, self.op(s)); }
        node(h, s, self.subtree(h - 1, s), self.subtree(h - 1, s + pow2(h - 1)), self.chunk(s / C))
    }

    /// Activity chunk `j`: the flags of operations `jC ..< (j+1)C`, eight to a byte, least
    /// significant bit first (utils/bitmap/mod.rs:552-560), zero past the last operation.
    /// Opaque in proofs (`unfold(Db::chunk)` reveals it).
    #[opaque]
    #[example(Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.chunk(0)[0] == 1u8 && Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.op(0) == seq![5u8])]
    pub fn chunk(&self, j: Nat) -> [u8; N] { pack(self.log.skip(j * C), N as Nat).to_array::<N>() }

    pub(crate) fn op(&self, i: Nat) -> Op { match self.log.get(i) { Some((op, _)) => op, None => seq![] } }
}

#[example(pack(seq![(seq![], true)], 1) == seq![1u8])]
#[example(pack(seq![(seq![], false), (seq![], false), (seq![], false), (seq![], false), (seq![], false), (seq![], false), (seq![], false), (seq![], true)], 2) == seq![0x80u8, 0u8])] // op 7: bit 7 of byte 0
#[example(pack(seq![(seq![], false), (seq![], false), (seq![], false), (seq![], false), (seq![], false), (seq![], false), (seq![], false), (seq![], false), (seq![0u8], true)], 2) == seq![0u8, 1u8])] // op 8: bit 0 of byte 1
#[example(pack(seq![(seq![], true)], 2) == seq![1u8, 0u8])] // past the log: zero
pub(crate) fn pack(log: Seq<(Op, bool)>, n: Nat) -> Seq<u8> {
    if n == 0 { seq![] } else { seq![flags(log.take(8)) as u8, ..pack(log.skip(8), n - 1)] }
}
#[example(flags(seq![(seq![], true), (seq![], false), (seq![], true)]) == 5)]
pub(crate) fn flags(log: Seq<(Op, bool)>) -> Nat { match log { [] => 0, [(_, active), rest @ ..] => active as Nat + 2 * flags(rest) } }

// The hashes (merkle/hasher.rs, current/grafting.rs:356-401). Numbers are 8-byte big-endian.

/// The postorder position of the node of height `h` over leaves `s ..< s + 2^h` (mmr/mod.rs:112-120):
/// its last leaf `j` is at `2j − popcount(j)`, and the `h` ancestors that end with `j` follow it.
/// Opaque in proofs (`unfold(pos)` reveals it).
#[example(pos(0, 0) == 0 && pos(0, 2) == 3 && pos(1, 0) == 2 && pos(1, 2) == 5 && pos(3, 0) == 14)]
#[opaque]
pub fn pos(h: Nat, s: Nat) -> Nat {
    let j = s + pow2(h) - 1;
    2 * j - popcount(j) + h
}

/// A leaf: `H(u64be(position) ‖ op)`.
#[example(eval(leaf(0, seq![])) == eval(hash(seq![be64(0), bytes(seq![])])))]
pub fn leaf(i: Nat, op: Op) -> Tree { hash(seq![be64(pos(0, i)), bytes(op)]) }

/// An inner node: `H(u64be(position) ‖ left ‖ right)`. A node of height G (8N leaves wide) is
/// grafted with its activity chunk, `H(chunk ‖ node)`, unless the chunk is zero.
#[example(eval(node(1, 0, Tree::Pruned([1u8; 32]), Tree::Pruned([2u8; 32]), [0u8; N])) == eval(hash(seq![be64(2), Tree::Pruned([1u8; 32]), Tree::Pruned([2u8; 32])])))]
#[example(eval(node(G, 0, Tree::Pruned([1u8; 32]), Tree::Pruned([2u8; 32]), [1u8; N])) == eval(hash(seq![bytes(seq![..[1u8; N]]), hash(seq![be64(pos(G, 0)), Tree::Pruned([1u8; 32]), Tree::Pruned([2u8; 32])])])))]
pub fn node(h: Nat, s: Nat, left: Tree, right: Tree, chunk: [u8; N]) -> Tree {
    let inner = hash(seq![be64(pos(h, s)), left, right]);
    if h == G && chunk != [0; N] { hash(seq![bytes(chunk), inner]) } else { inner }
}

/// Bagging (merkle/hasher.rs:95-141): the first `inactive.max(1)` peaks are folded from the
/// left, `H(H(p0 ‖ p1) ‖ p2)…`, then that and the other peaks from the right, `H(a ‖ H(q0 ‖ H(q1 ‖ …)))`.
#[example(eval(bag(seq![Tree::Pruned([1u8; 32])], 0)) == eval(Tree::Pruned([1u8; 32])))]
#[example(eval(bag(seq![Tree::Pruned([1u8; 32]), Tree::Pruned([2u8; 32])], 0)) == eval(hash(seq![Tree::Pruned([1u8; 32]), Tree::Pruned([2u8; 32])])))]
#[example(eval(bag(seq![Tree::Pruned([1u8; 32]), Tree::Pruned([2u8; 32]), Tree::Pruned([3u8; 32])], 2)) == eval(hash(seq![hash(seq![Tree::Pruned([1u8; 32]), Tree::Pruned([2u8; 32])]), Tree::Pruned([3u8; 32])])))]
#[example(eval(bag(seq![Tree::Pruned([1u8; 32]), Tree::Pruned([2u8; 32]), Tree::Pruned([3u8; 32])], 0)) == eval(hash(seq![Tree::Pruned([1u8; 32]), hash(seq![Tree::Pruned([2u8; 32]), Tree::Pruned([3u8; 32])])])))]
pub fn bag(peaks: Seq<Tree>, inactive: Nat) -> Tree {
    let k = inactive.max(1) - 1;
    match peaks {
        [first, rest @ ..] => fold_right(fold_left(first, rest.take(k)), rest.skip(k)),
        [] => bytes(seq![]), // no leaves: not a database (`well_formed`)
    }
}
/// One step of either fold: `H(a ‖ b)`.
pub(crate) fn join(a: Tree, b: Tree) -> Tree { hash(seq![a, b]) }
pub(crate) fn fold_left(a: Tree, xs: Seq<Tree>) -> Tree { folds::fold_left(xs, a, join) }
pub(crate) fn fold_right(a: Tree, xs: Seq<Tree>) -> Tree { folds::fold_right1(a, xs, join) }

/// The Current root. The MMR root seals the bag with the leaf count, and the inactive count when it
/// is not zero: `H(u64be(leaves) ‖ [u64be(inactive) ‖] bag)` (merkle/hasher.rs:132-140). The root
/// is `H(ops_root ‖ mmr)`, or, when the last chunk is partial, with its length and digest:
/// `H(ops_root ‖ mmr ‖ u64be(leaves mod 8N) ‖ partial)` (current/db.rs:835-865).
#[example(eval(current_root(Tree::Pruned([1u8; 32]), 256, 0, Tree::Pruned([2u8; 32]), Tree::Pruned([3u8; 32]))) == eval(hash(seq![Tree::Pruned([1u8; 32]), hash(seq![be64(256), Tree::Pruned([2u8; 32])])])))]
#[example(eval(current_root(Tree::Pruned([1u8; 32]), 1, 2, Tree::Pruned([2u8; 32]), Tree::Pruned([3u8; 32]))) == eval(hash(seq![Tree::Pruned([1u8; 32]), hash(seq![be64(1), be64(2), Tree::Pruned([2u8; 32])]), be64(1), Tree::Pruned([3u8; 32])])))]
pub fn current_root(ops_root: Tree, leaves: Nat, inactive: Nat, bag: Tree, partial: Tree) -> Tree {
    let mmr = if inactive == 0 { hash(seq![be64(leaves), bag]) } else { hash(seq![be64(leaves), be64(inactive), bag]) };
    if leaves % C == 0 { hash(seq![ops_root, mmr]) } else { hash(seq![ops_root, mmr, be64(leaves % C), partial]) }
}

#[example(eval(be64(258)) == eval(bytes(seq![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8, 2u8])))]
pub(crate) fn be64(x: Nat) -> Tree { bytes((x as u64).to_be_bytes()) }
