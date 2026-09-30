//! Stub of a Current database and its root.

use super::sha256::Digest;
use super::tree::{Tree, eval};

/// An encoded operation.
pub type Op = Seq<u8>;

/// The operation `Update(key, value)`.
pub fn update(key: Seq<u8>, value: Seq<u8>) -> Op {
    seq![0xD2u8, ..key, ..value]
}

/// The bytes of a log.
#[decreases(log.len())]
pub fn bytes_of(log: Seq<(Op, bool)>) -> Seq<u8> {
    if log.len() == 0 { seq![] } else { seq![..log[0].0, ..bytes_of(log.skip(1))] }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Db {
    pub log: Seq<(Op, bool)>,
    pub inactive: Nat,
    pub ops_root: Digest,
}

impl Db {
    pub fn leaves(&self) -> Nat {
        self.log.len()
    }

    pub fn well_formed(&self) -> bool {
        0 < self.leaves() && self.inactive <= self.leaves()
    }

    pub fn is_current(&self, i: Nat, op: Op) -> bool {
        i < self.log.len() && self.log[i].0 == op && self.log[i].1
    }

    pub fn root(&self) -> Seq<u8> {
        eval(self.tree())
    }

    pub fn tree(&self) -> Tree {
        Tree { bytes: bytes_of(self.log) }
    }
}
