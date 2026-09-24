//! Shared compact QMDB helpers.

pub(crate) mod batch;
pub(crate) mod db;
mod operation;
mod sync;
pub(crate) mod witness;

use crate::journal::contiguous::variable;
use commonware_parallel::Strategy;
pub use db::{Db, MerkleizedBatch, UnmerkleizedBatch, initial_root};
pub use operation::Operation;
pub(in crate::qmdb) use operation::sealed;

/// Configuration for a compact authenticated db.
#[derive(Clone)]
pub struct Config<C, S: Strategy> {
    /// Strategy used to parallelize merkleization.
    pub strategy: S,

    /// Configuration for the journal that persists the witness.
    pub witness: variable::Config<C>,
}
