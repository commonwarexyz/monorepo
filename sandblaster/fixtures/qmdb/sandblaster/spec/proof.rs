//! Operation proofs: what one carries, the tree it describes, and when Commonware accepts it.
//! Commonware 6e15fe7c `constant::OperationProof<mmr::Family, Sha256Digest, N>`:
//! current/proof/{operation,mod}.rs, merkle/proof.rs (docs/prod-domain-commonware-spec.md).

use super::codec::decode;
use super::config::{C, N};
use super::db::{Op, bag, current_root, leaf, node, update};
use super::sha256::{Digest, sha256};
use super::tree::{Tree, bytes, eval, hash};
use crate::stdlib::folds;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    pub location: Nat,           // the operation's leaf
    pub chunk: [u8; N],          // the activity chunk holding its flag
    pub leaves: Nat,             // the tree's leaf count
    pub inactive: Nat,           // how many leading peaks are inactive
    pub digests: Seq<Digest>,    // the other peaks as `layout` carries them, then the path's siblings
    pub partial: Option<Digest>, // the digest of the last chunk, when it is partial
    pub ops_root: Digest,        // the operations root
}

/// Commonware's verdict on "`key ↦ value` is current under `root`" (current/unordered/db.rs:55-65):
/// a 32-byte key and value, and bytes that decode, with nothing left over, to a proof it accepts for
/// `Update(key, value)`.
#[example(!verify(seq![], seq![], seq![], seq![]))]
pub fn verify(root: Seq<u8>, key: Seq<u8>, value: Seq<u8>, proof: Seq<u8>) -> bool {
    key.len() == 32 && value.len() == 32 && match decode(proof) {
        Some((p, rest)) => rest == seq![] && p.accepts(update(key, value), root),
        None => false,
    }
}

impl Proof {
    /// Commonware's checks (operation.rs:63-83, proof/mod.rs:356-508, merkle/proof.rs:449-555).
    /// Each one only rejects, so their order does not matter. (The chain nests to the right, which
    /// keeps its proof terms linear in the number of checks.)
    #[example(!Proof { location: 0, chunk: [0u8; N], leaves: 0, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] }.accepts(seq![], seq![]))]
    #[example(Proof { location: 0, chunk: super::db::Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.chunk(0), leaves: 1, inactive: 0, digests: seq![], partial: Some(sha256(super::db::Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.chunk(0))), ops_root: [0u8; 32] }.accepts(seq![5u8], super::db::Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }.root()))] // a one-operation database and its only proof
    pub fn accepts(&self, op: Op, root: Seq<u8>) -> bool {
        let (n, i) = (self.leaves, self.location);
        let (t, l) = (peak_of(n, i), layout(peak_of(n, i), self.inactive));
        i < n                                                               // the operation is in the tree
            && (bit(self.chunk, i)                                          // and active;
            && (self.inactive <= popcount(n)                                // no more inactive peaks than peaks;
            && (self.digests.len() == l.front + l.back + t.height           // one digest per slot;
            && (self.partial.is_some() == (n % C != 0)                      // a digest for a partial last chunk,
            && ((i < n.saturating_sub(n % C) || self.partial == Some(sha256(self.chunk))) // the target's chunk if it is the last;
            && eval(self.tree(op)) == root)))))                             // and the tree has the trusted root.
    }

    /// The tree the proof describes for `op`: the target's peak rebuilt from `op`'s leaf, the chunk
    /// and the path's siblings; the other peaks, and the partial chunk unless the target is in it,
    /// pruned to the proof's digests. (Missing digests read as zero; `accepts` checks the count.)
    /// Opaque in proofs (`unfold(Proof::tree)` reveals it).
    #[opaque]
    #[example(eval(Proof { location: 0, chunk: [0u8; N], leaves: 1, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] }.tree(seq![])) == eval(current_root(Tree::Pruned([0u8; 32]), 1, 0, leaf(0, seq![]), hash(seq![bytes(seq![..[0u8; N]])]))))]
    // leaf 1 of 2 (both in chunk 0, which is partial): the peak is the node at position 2 over the
    // sibling digest and the leaf; the root carries the leaf count mod 8N and H(chunk)
    #[example(eval(Proof { location: 1, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![[7u8; 32]], partial: None, ops_root: [0u8; 32] }.tree(seq![])) == eval(hash(seq![Tree::Pruned([0u8; 32]), hash(seq![super::db::be64(2), hash(seq![super::db::be64(2), Tree::Pruned([7u8; 32]), leaf(1, seq![])])]), super::db::be64(2), hash(seq![bytes(seq![..[0u8; N]])])])))]
    pub fn tree(&self, op: Op) -> Tree {
        let (n, i, k) = (self.leaves, self.location, self.inactive);
        let (t, l) = (peak_of(n, i), layout(peak_of(n, i), k));
        let target = path(t.height, t.start, i, leaf(i, op), self.digests.skip(l.front + l.back), self.chunk);
        let others = pruned(self.digests);
        let peaks = seq![..others.take(l.front), target, ..others.skip(l.front).take(l.back)];
        let partial = if i / C == n / C { hash(seq![bytes(self.chunk)]) } else { Tree::Pruned(self.partial.unwrap_or([0; 32])) };
        current_root(Tree::Pruned(self.ops_root), n, k, bag(peaks, l.forward), partial)
    }
}

/// Operation `i`'s flag in its chunk: bit `i mod 8N`, least significant bit of each byte first
/// (operation.rs:70-71). Opaque in proofs (`unfold(bit)` reveals it).
#[opaque]
#[example(bit([1u8; N], 0))]
#[example(!bit([1u8; N], 1))]
pub fn bit(chunk: [u8; N], i: Nat) -> bool {
    let b = i % C;
    (chunk[b / 8] as Nat / pow2(b % 8)) % 2 == 1
}

/// The peak holding leaf `i` of `n` (merkle/mmr/iterator.rs:31-110): its height is the highest bit
/// where `n` and `i` differ; the set bits of `n` above it are the peaks before it, those below it
/// the peaks after it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Peak { pub height: Nat, pub start: Nat, pub before: Nat, pub after: Nat }

/// [`Peak`], one bit at a time from the lowest: where `n` and `i` agree above bit 0 the peak is
/// the leaf `i` itself, and the bits of `n` above it are the peaks before it; otherwise it is the
/// peak of `n / 2` holding `i / 2`, one level higher, with bit 0 of `n` one more peak after it.
/// Opaque in proofs (`unfold(peak_of)` reveals it).
#[opaque]
#[example(peak_of(7, 5) == Peak { height: 1, start: 4, before: 1, after: 1 })]
#[decreases(n + i)]
pub fn peak_of(n: Nat, i: Nat) -> Peak {
    if n / 2 == i / 2 {
        Peak { height: 0, start: n / 2 * 2, before: popcount(n / 2), after: 0 }
    } else {
        let t = peak_of(n / 2, i / 2);
        Peak { height: t.height + 1, start: 2 * t.start, before: t.before, after: t.after + n % 2 }
    }
}

/// Where a proof carries the peaks beside the target's (Blueprint with BackwardFold,
/// merkle/proof.rs:815-953). With `k` inactive peaks the digests are, in order: [the inactive
/// peaks before the target, folded into one]? [the other peaks before it] [the inactive peaks after
/// it] [the other peaks after it, folded into one]? [the path's siblings].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub folded: Nat,  // inactive peaks before the target, carried as one digest if there are any
    pub front: Nat,   // digests before the target's peak
    pub listed: Nat,  // inactive peaks after the target, one digest each
    pub back: Nat,    // digests after the target's peak
    pub forward: Nat, // how many of the proof's peaks are bagged as inactive (the carried fold is one)
}

/// Opaque in proofs (`unfold(layout)` reveals it).
#[opaque]
#[example(layout(Peak { height: 1, start: 4, before: 1, after: 1 }, 0) == Layout { folded: 0, front: 1, listed: 0, back: 1, forward: 0 })]
#[example(layout(Peak { height: 1, start: 4, before: 1, after: 1 }, 3) == Layout { folded: 1, front: 1, listed: 1, back: 1, forward: 3 })]
#[example(layout(Peak { height: 0, start: 0, before: 2, after: 0 }, 2).forward == 1)] // both inactive peaks before, carried as one digest
pub fn layout(t: Peak, k: Nat) -> Layout {
    let folded = t.before.min(k);
    let listed = t.after.min(k.saturating_sub(t.before + 1));
    Layout {
        folded,
        front: t.before - folded + (folded > 0) as Nat,
        listed,
        back: listed + (t.after > listed) as Nat,
        forward: if folded > 0 { k - folded + 1 } else { k },
    }
}

/// The path from leaf `i` up to the node of height `h` over leaves `s ..< s + 2^h`, each sibling
/// pruned to its digest. Siblings come left to right: a left sibling before the deeper ones, a
/// right one after them (merkle/proof.rs:610-744).
#[example(eval(path(1, 4, 5, Tree::Pruned([1u8; 32]), seq![[2u8; 32]], [0u8; N])) == eval(node(1, 4, Tree::Pruned([2u8; 32]), Tree::Pruned([1u8; 32]), [0u8; N])))]
#[example(eval(path(1, 4, 4, Tree::Pruned([1u8; 32]), seq![[2u8; 32]], [0u8; N])) == eval(node(1, 4, Tree::Pruned([1u8; 32]), Tree::Pruned([2u8; 32]), [0u8; N])))]
pub fn path(h: Nat, s: Nat, i: Nat, leaf: Tree, sibs: Seq<Digest>, chunk: [u8; N]) -> Tree {
    if h == 0 { return leaf; }
    let m = s + pow2(h - 1);
    if i < m { node(h, s, path(h - 1, s, i, leaf, sibs.take(h - 1), chunk), Tree::Pruned(at(sibs, h - 1)), chunk) }
    else { node(h, s, Tree::Pruned(at(sibs, 0)), path(h - 1, m, i, leaf, sibs.skip(1), chunk), chunk) }
}

#[example(pruned(seq![[1u8; 32]]).len() == 1 && eval(bag(pruned(seq![[1u8; 32]]), 0)) == seq![..[1u8; 32]])]
pub(crate) fn pruned(ds: Seq<Digest>) -> Seq<Tree> { folds::map(ds, Tree::Pruned) }
#[example(at(seq![], 0) == [0u8; 32] && at(seq![[1u8; 32]], 0) == [1u8; 32])]
pub(crate) fn at(ds: Seq<Digest>, j: Nat) -> Digest { ds.get(j).unwrap_or([0; 32]) }
