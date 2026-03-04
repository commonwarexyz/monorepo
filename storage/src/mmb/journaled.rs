//! An MMB backed by a fixed-item-length journal.
//!
//! Thin wrapper around the generic [`crate::merkle::journaled`] module, fixing the Merkle family
//! to [`super::Mmb`] and the in-memory representation to [`mem::CleanMmb`].

pub use crate::merkle::journaled::Config;

use crate::{merkle, mmb::mem};

/// Sync configuration for a journal-backed MMB.
pub type SyncConfig<D> = crate::merkle::journaled::SyncConfig<super::Mmb, D>;

/// A clean (merkleized) journaled MMB.
pub type CleanMmb<E, D> = merkle::journaled::Clean<super::Mmb, E, D, mem::CleanMmb<D>>;

/// A dirty (unmerkleized) journaled MMB.
pub type DirtyMmb<E, D> = merkle::journaled::Dirty<super::Mmb, E, D, mem::CleanMmb<D>>;
