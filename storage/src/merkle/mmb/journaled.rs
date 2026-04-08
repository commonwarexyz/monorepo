//! An MMB backed by a fixed-item-length journal.
//!
//! A [crate::journal] is used to store all unpruned MMB nodes, and a [crate::metadata] store is
//! used to preserve digests required for root and proof generation that would have otherwise been
//! pruned.
//!
//! This module is a thin wrapper around the generic `Journaled` type, specialized for the
//! MMB [Family]. It re-exports [Config], [SyncConfig], and the append-only
//! [`UnmerkleizedBatch`] wrapper from `merkle::journaled`. Async proof methods (`proof`,
//! `range_proof`, `historical_proof`, `historical_range_proof`) and the `Storage<F>` impl are
//! provided by the generic `Journaled` in `merkle::journaled`.

/// Configuration for a journal-backed MMB.
pub use crate::merkle::journaled::Config;
pub use crate::merkle::journaled::UnmerkleizedBatch;
use crate::merkle::mmb::Family;

/// Configuration for initializing a journaled MMB for synchronization.
pub type SyncConfig<D> = crate::merkle::journaled::SyncConfig<Family, D>;

/// An MMB backed by a fixed-item-length journal.
pub type Mmb<E, D> = crate::merkle::journaled::Journaled<Family, E, D>;
