//! This module re-exports the MMR module from storage-core, and builds upon it with some additional
//! types such as [bitmap::Bitmap] and [journaled::Mmr].

use thiserror::Error;

pub mod bitmap;
pub mod grafting;
// Re-export storage-core modules.
pub use commonware_storage_core::{
    mmr as core,
    mmr::{iterator, Hasher, Proof, StandardHasher},
};
pub mod journaled;
pub mod storage;
pub mod verification;

/// Errors that can occur when interacting with an MMR.
#[derive(Error, Debug)]
pub enum Error {
    #[error("core mmr error: {0}")]
    CoreMmr(#[from] core::Error),
    #[error("metadata error: {0}")]
    MetadataError(#[from] crate::metadata::Error),
    #[error("journal error: {0}")]
    JournalError(#[from] crate::journal::Error),
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("missing node: {0}")]
    MissingNode(u64),
    #[error("invalid proof")]
    InvalidProof,
    #[error("root mismatch")]
    RootMismatch,
    #[error("element pruned: {0}")]
    ElementPruned(u64),
    #[error("missing digest: {0}")]
    MissingDigest(u64),
    #[error("invalid proof length")]
    InvalidProofLength,
    #[error("invalid size: {0}")]
    InvalidSize(u64),
    #[error("empty")]
    Empty,
}
