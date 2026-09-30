//! Stub of operation proofs and `verify`.

use super::codec::decode;
use super::config::N;
use super::db::{Op, update};
use super::sha256::Digest;
use super::tree::{Tree, eval};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    pub location: Nat,
    pub chunk: [u8; N],
    pub leaves: Nat,
    pub inactive: Nat,
    pub digests: Seq<Digest>,
    pub partial: Option<Digest>,
    pub ops_root: Digest,
}

/// Commonware's verdict (stub): a 32-byte key and value, and bytes that decode to a proof it
/// accepts for `Update(key, value)`.
pub fn verify(root: Seq<u8>, key: Seq<u8>, value: Seq<u8>, proof: Seq<u8>) -> bool {
    key.len() == 32 && value.len() == 32 && match decode(proof) {
        Some((p, rest)) => rest.len() == 0 && p.accepts(update(key, value), root),
        None => false,
    }
}

/// The digests of a path, as bytes.
#[decreases(ds.len())]
pub fn path(op: Op, ds: Seq<Digest>) -> Seq<u8> {
    if ds.len() == 0 { op } else { seq![..ds[0], ..path(op, ds.skip(1))] }
}

impl Proof {
    pub fn accepts(&self, op: Op, root: Seq<u8>) -> bool {
        self.location < self.leaves && eval(self.tree(op)) == root
    }

    pub fn tree(&self, op: Op) -> Tree {
        Tree { bytes: path(op, self.digests) }
    }

    pub fn in_range(&self) -> bool {
        self.digests.len() <= 122
    }
}
