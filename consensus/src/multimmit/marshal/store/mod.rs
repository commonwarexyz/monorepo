//! Marshal's durable stores.
//!
//! - [`log::Log`]: a segmented append log of fixed-width index rows locating values in
//!   per-segment blobs. Every mutation is a job, so the owner never awaits storage.
//! - [`record::DurableRecord`]: one durable value in its own metadata partition.
//!
//! Every stored record leads with a version byte. Loading a record whose version this binary does
//! not know fails the open, so a binary downgrade stops before misreading state.

pub(super) mod blocks;
pub(super) mod log;
pub(super) mod meta;
pub(super) mod proofs;
pub(super) mod record;

use commonware_runtime::buffer::paged::CacheRef;
use commonware_storage::{journal, metadata};
use std::num::NonZeroUsize;

/// A marshal storage operation failed.
///
/// Every failure of a mutation is fatal: the store that failed is not used again.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// Stored state contradicts itself or the operation applied to it.
    #[error("storage is inconsistent: {0}")]
    Inconsistent(&'static str),
    /// A mutable store was lost to a failed or canceled mutation.
    #[error("storage is unavailable after a failed or canceled mutation")]
    Poisoned,
    /// A journal operation failed.
    #[error(transparent)]
    Journal(#[from] journal::Error),
    /// A metadata operation failed.
    #[error(transparent)]
    Metadata(#[from] metadata::Error),
    /// A stored value could not be decoded.
    #[error(transparent)]
    Codec(#[from] commonware_codec::Error),
    /// A storage task failed.
    #[error(transparent)]
    Runtime(#[from] commonware_runtime::Error),
}

/// Journal buffers and page cache shared by every log.
#[derive(Clone)]
pub(crate) struct Buffers {
    /// Cache for index journal pages.
    pub(crate) page_cache: CacheRef,
    /// Bytes buffered by index journals.
    pub(crate) index_write_buffer: NonZeroUsize,
    /// Bytes buffered by value journals.
    pub(crate) value_write_buffer: NonZeroUsize,
    /// Bytes buffered while replaying index journals, and the read prefetch for value reads.
    pub(crate) replay_buffer: NonZeroUsize,
}
