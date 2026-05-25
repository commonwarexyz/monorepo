//! P2P implementations of the QMDB sync resolvers.
//!
//! - [`standard`]: resolver for standard QMDBs that fetch operations from peers.
//! - [`compact`]: resolver for compact-storage QMDBs that fetch one
//!   authenticated frontier state instead of replaying operations.

pub mod compact;
pub mod standard;

/// Safe upper bound on the number of pinned nodes carried in a resolver
/// response for any u64-backed merkle family.
///
/// Pinned nodes are produced by [`commonware_storage::merkle::Family::nodes_to_pin`],
/// whose default (and only) implementation returns the peaks of the
/// sub-structure at the prune location. An MMR with `n` leaves has
/// `popcount(n)` peaks, and since [`commonware_storage::merkle::Location`] is
/// backed by a `u64`, `n <= u64::MAX` gives at most `popcount(u64::MAX) = 64`
/// peaks. Concrete families (e.g. `mmr::Family` with `MAX_LEAVES = 2^62`) cap
/// the bound lower, but 64 covers them all.
pub(super) const MAX_PINNED_NODES: usize = 64;
