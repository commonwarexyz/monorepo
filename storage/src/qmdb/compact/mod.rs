//! The compact QMDB: one db shared by the keyless and immutable variants, its witness journal,
//! and its sync impl.

pub(crate) mod batch;
pub mod db;
mod sync;
pub(crate) mod witness;

use crate::journal::contiguous::variable;
use commonware_parallel::Strategy;

/// Configuration for a compact authenticated db.
#[derive(Clone)]
pub struct Config<C, S: Strategy> {
    /// Strategy used to parallelize merkleization.
    pub strategy: S,

    /// Configuration for the journal that persists the witness.
    pub witness: variable::Config<()>,

    /// Codec config used to decode the persisted last commit operation on reopen.
    pub commit_codec_config: C,
}
