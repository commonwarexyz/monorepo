//! An MMB backed by a fixed-item-length journal.
//!
//! A [crate::journal] is used to store all unpruned MMB nodes, and a [crate::metadata] store is
//! used to preserve digests required for root and proof generation that would have otherwise been
//! pruned.
//!
//! This module is a thin wrapper around the generic `Merkle` type, specialized for the
//! MMB [Family]. It re-exports [Config], [SyncConfig], and the append-only
//! [`UnmerkleizedBatch`] wrapper from `merkle::full`. Async proof methods (`proof`,
//! `range_proof`, `historical_proof`, `historical_range_proof`) and the `Storage<F>` impl are
//! provided by the generic `Merkle` in `merkle::full`.

/// Configuration for a journal-backed MMB.
pub use crate::merkle::full::Config;
pub use crate::merkle::full::UnmerkleizedBatch;
use crate::merkle::mmb::Family;

/// Configuration for initializing a full MMB for synchronization.
pub type SyncConfig<D> = crate::merkle::full::SyncConfig<Family, D>;

/// An MMB backed by a fixed-item-length journal.
pub type Mmb<E, D> = crate::merkle::full::Merkle<Family, E, D>;
