//! A disk-based map.
//!
//! `bmap` provides a simple key-value store that is backed by on-disk journals. It aims to
//! minimize in-memory footprint by not storing keys or an index in memory. Lookups are
//! performed by scanning a journal file on disk.
//!
//! To improve performance for large numbers of keys, `bmap` partitions keys into a configurable
//! number of buckets, where each bucket is a separate journal. A key's hash is used to
//! determine its bucket.
//!
//! # Safety
//!
//! `bmap` is safe against unclean shutdowns, as it builds on `commonware-storage/journal`. Any
//! partially written data will be discarded on restart.

mod storage;

pub use storage::{BMap, Config};
use thiserror::Error;

/// Errors that can occur when interacting with a `bmap`.
#[derive(Debug, Error)]
pub enum Error {
    /// An error occurred in the underlying journal.
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),

    /// An error occurred during codec operations.
    #[error("codec error: {0}")]
    Codec(#[from] commonware_codec::Error),
}
