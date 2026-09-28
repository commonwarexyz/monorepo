//! A compact authenticated db that discards historical operations, retaining only a witness
//! for each applied state.
//!
//! One [`Db`] serves the keyless and immutable dbs through the sealed [`Operation`] trait.
//! [`crate::qmdb::keyless`] and [`crate::qmdb::immutable`] pin the operation type through
//! aliases and add `append` and `set`, respectively.
//!
//! Mirrors the API of the full dbs ([`crate::qmdb::keyless::Keyless`],
//! [`crate::qmdb::immutable::Immutable`]): `new_batch -> merkleize -> apply_batch -> commit /
//! sync / start_sync`, pipelined batch chains, `StaleBatch` validation. It is backed by the
//! peak-only [`crate::merkle::compact`]. Because history is discarded, the db has no `get` /
//! `proof` / `bounds` methods. A merkleized batch can prove only its own operations, and only
//! until it is applied. Use a full db for historical proofs.
//!
//! # Witness journal
//!
//! The witness journal is the single durable source of truth. Each entry is a complete witness
//! of one applied state, so bounded [`Db::init`] can restore a retained applied state
//! (history is bounded by [`Db::prune`]). Initialization selects an entry by size, then decodes
//! its commit operation with the witness journal's codec config and rebuilds the in-memory Merkle
//! from the entry's pinned nodes and commit. The commits of entries it does not select are never
//! decoded. An entry the journal cannot decode, or a selected entry whose commit fails to decode,
//! fails the open with [`Error::Journal`](crate::qmdb::Error::Journal). A selected entry that
//! decodes but cannot rebuild fails it with
//! [`Error::DataCorrupted`](crate::qmdb::Error::DataCorrupted). The witness is also what lets
//! compact nodes serve compact sync without retaining historical operations. A compact-sync
//! import is journaled by its first apply or durability operation, which replaces the
//! partition's previous contents without decoding them.
//!
//! Entries are strictly increasing in committed size, so a size uniquely identifies an
//! initialization or prune target. An appended entry becomes durable when [`Db::commit`] or
//! [`Db::sync`] completes, or, for [`Db::start_sync`], when the returned handle completes.
//! Before that point recovery may fall back to the previous entry. The first entry of a
//! compact-sync import has none: a crash that loses it leaves an interrupted import, which fails
//! to open until a re-sync replaces it. The tip entry is never pruned.
//!
//! # Inactivity floor
//!
//! Commits carry the inactivity floor so the compact db's commit leaves and root match the full
//! db's: the root is computed over the peaks the floor leaves active.

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

    /// Configuration for the witness journal. Its codec config decodes the commit operations the
    /// witnesses hold.
    pub witness: variable::Config<C>,
}
