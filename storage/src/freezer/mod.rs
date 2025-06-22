//! A persistent storage system that provides the same interface as archive but without pruning support.
//!
//! Behind the scenes, it uses diskmap for key-value storage and diskindex for index-key mapping.
//! Key queries use the diskmap directly and index queries lookup the key in the diskindex
//! and then get the value from the diskmap.
//!
//! The diskindex manages the RMap for interval queries.

mod storage;

use crate::{diskindex, diskmap};
pub use storage::Freezer;
use thiserror::Error;

/// Errors that can occur when interacting with the freezer.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("diskmap error: {0}")]
    DiskMap(#[from] crate::diskmap::Error),
    #[error("diskindex error: {0}")]
    DiskIndex(#[from] crate::diskindex::Error),
    #[error("record corrupted")]
    RecordCorrupted,
}

/// Configuration for `Freezer` storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The configuration for the [diskmap::DiskMap].
    pub diskmap: diskmap::Config<C>,

    /// The configuration for the [diskindex::DiskIndex].
    pub diskindex: diskindex::Config,
}
