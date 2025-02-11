//! An append-only log for storing arbitrary data.
//!
//! Journals provide append-only logging for persisting arbitrary data with fast replay, historical
//! pruning, and rudimentary support for fetching individual items. A journal can be used on its own
//! to serve as a backing store for some in-memory data structure, or as a building block for a more
//! complex construction that prescribes some meaning to items in the log.

use thiserror::Error;

pub mod fixed;
pub mod variable;

/// Errors that can occur when interacting with `Journal`.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("invalid blob name: {0}")]
    InvalidBlobName(String),
    #[error("checksum mismatch: expected={0} actual={1}")]
    ChecksumMismatch(u32, u32),
    #[error("item too large: size={0}")]
    ItemTooLarge(usize),
    #[error("already pruned to section: {0}")]
    AlreadyPrunedToSection(u64),
    #[error("usize too small")]
    UsizeTooSmall,
    #[error("offset overflow")]
    OffsetOverflow,
    #[error("unexpected size: expected={0} actual={1}")]
    UnexpectedSize(u32, u32),
    #[error("missing blob: {0}")]
    MissingBlob(u64),
    #[error("item pruned: {0}")]
    ItemPruned(u64),
    #[error("invalid item: {0}")]
    InvalidItem(u64),
    #[error("invalid rewind: {0}")]
    InvalidRewind(u64),
}
