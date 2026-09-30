//! Stub of hash trees: a tree is the bytes it stands for.

/// A tree (the draft's is a recursive enum).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tree {
    pub bytes: Seq<u8>,
}

/// The bytes a tree stands for.
pub fn eval(t: Tree) -> Seq<u8> {
    t.bytes
}

/// The first position where two byte strings differ, as a pair of suffixes.
#[decreases(x.len())]
pub fn first_clash(x: Seq<u8>, y: Seq<u8>) -> Option<(Seq<u8>, Seq<u8>)> {
    if x.len() == 0 || y.len() == 0 {
        None
    } else if x[0] != y[0] {
        Some((x, y))
    } else {
        first_clash(x.skip(1), y.skip(1))
    }
}

/// Walking two trees together, the first hash whose preimages differ.
pub fn clash(a: Tree, b: Tree) -> Option<(Seq<u8>, Seq<u8>)> {
    first_clash(a.bytes, b.bytes)
}
