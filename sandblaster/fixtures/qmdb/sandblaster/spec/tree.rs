//! Hash trees. A Merkle root is the SHA-256 of bytes that contain other digests; written as a
//! tree, a proof is the same tree with the subtrees it does not open replaced by their digests.
//! Two laws carry the security argument, for every QMDB variant alike: trees that agree have one
//! root (so honest proofs verify), and trees with one root agree unless walking them together
//! finds a collision (so a forged proof contains one). Nothing here is about MMRs.

use super::sha256::{Digest, collision, sha256};

/// A byte string built from literal bytes, concatenation and SHA-256. `Pruned(d)` is a subtree
/// known only by its digest.
#[derive(Clone, Copy)]
pub enum Tree { Bytes(Seq<u8>), Cat(Tree, Tree), Hash(Tree), Pruned(Digest) }

/// The bytes a tree stands for (a digest, for `Hash` and `Pruned`).
pub fn eval(t: Tree) -> Seq<u8> {
    match t {
        Tree::Bytes(b) => b,
        Tree::Cat(l, r) => seq![..eval(l), ..eval(r)],
        Tree::Hash(t) => sha256(eval(t)),
        Tree::Pruned(d) => d,
    }
}

/// `H(parts[0] ‖ parts[1] ‖ …)`, and literal bytes.
pub fn hash(parts: Seq<Tree>) -> Tree { Tree::Hash(cat(parts)) }
pub fn bytes(b: Seq<u8>) -> Tree { Tree::Bytes(b) }
pub(crate) fn cat(parts: Seq<Tree>) -> Tree { match parts { [] => bytes(seq![]), [t, rest @ ..] => Tree::Cat(t, cat(rest)) } }

/// `a` and `b` are two views of one tree: where either is pruned, its digest is the other's root
/// there; everywhere else they have the same bytes, split the same way.
#[example(agree(Tree::Bytes(seq![1u8]), Tree::Bytes(seq![1u8])))]
#[example(!agree(Tree::Bytes(seq![1u8]), Tree::Bytes(seq![2u8])))]
#[example(agree(Tree::Pruned(sha256(seq![1u8])), hash(seq![bytes(seq![1u8])])))]
pub fn agree(a: Tree, b: Tree) -> bool {
    match (a, b) {
        (Tree::Pruned(d), b) => d == eval(b),
        (a, Tree::Pruned(d)) => eval(a) == d,
        (Tree::Bytes(x), Tree::Bytes(y)) => x == y,
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => agree(a1, b1) && agree(a2, b2),
        (Tree::Hash(x), Tree::Hash(y)) => agree(x, y),
        _ => false,
    }
}

/// Agreeing trees have one root: a proof rebuilds the root of every tree it agrees with, in
/// particular of the database it was cut from.
#[law]
pub(crate) fn agreeing_trees_have_one_root(a: Tree, b: Tree) {
    requires(agree(a, b));
    ensures(eval(a) == eval(b));
}

/// Wherever `a` and `b` hash the same bytes they split them the same way (domain separation):
/// the same shape, except where either is pruned and inside hashes of different bytes.
#[example(fits(Tree::Cat(bytes(seq![1u8]), bytes(seq![])), Tree::Cat(bytes(seq![2u8]), bytes(seq![]))))]
#[example(!fits(Tree::Cat(bytes(seq![1u8]), bytes(seq![])), Tree::Cat(bytes(seq![]), bytes(seq![1u8]))))]
#[example(fits(Tree::Hash(bytes(seq![1u8])), Tree::Hash(Tree::Cat(bytes(seq![]), bytes(seq![2u8])))))]
#[example(fits(Tree::Hash(Tree::Bytes(seq![])), Tree::Hash(Tree::Bytes(seq![]))))] // equal hashed values fit
pub fn fits(a: Tree, b: Tree) -> bool {
    match (a, b) {
        (Tree::Pruned(_), _) | (_, Tree::Pruned(_)) | (Tree::Bytes(_), Tree::Bytes(_)) => true,
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => eval(a1).len() == eval(b1).len() && fits(a1, b1) && fits(a2, b2),
        (Tree::Hash(x), Tree::Hash(y)) => eval(x) != eval(y) || fits(x, y),
        _ => false,
    }
}

/// Walking `a` and `b` together, the first hash whose two preimages differ: those preimages.
#[example(clash(Tree::Hash(bytes(seq![1u8])), Tree::Hash(bytes(seq![2u8]))) == Some((seq![1u8], seq![2u8])))]
#[example(clash(bytes(seq![1u8]), bytes(seq![1u8])) == None)]
#[example(clash(Tree::Hash(Tree::Bytes(seq![])), Tree::Hash(Tree::Bytes(seq![]))) == None)] // one value: no collision
pub fn clash(a: Tree, b: Tree) -> Option<(Seq<u8>, Seq<u8>)> {
    match (a, b) {
        (Tree::Hash(x), Tree::Hash(y)) => if eval(x) != eval(y) { Some((eval(x), eval(y))) } else { clash(x, y) },
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => match clash(a1, b1) { None => clash(a2, b2), found => found },
        _ => None,
    }
}

/// One root binds: two trees that fit and have one root agree, unless walking them together finds
/// two different messages with one digest.
#[law]
pub(crate) fn equal_roots_agree(a: Tree, b: Tree) {
    requires(eval(a) == eval(b) && fits(a, b));
    ensures(agree(a, b) || collision(clash(a, b)));
}
