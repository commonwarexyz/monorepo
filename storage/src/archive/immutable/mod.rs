//! A persistent storage system that provides the same interface as archive but without pruning support.
//!
//! Behind the scenes, it uses diskmap for key-value storage and diskindex for index-key mapping.
//! Key queries use the diskmap directly and index queries lookup the key in the diskindex
//! and then get the value from the diskmap.
//!
//! The diskindex manages the RMap for interval queries.

mod storage;

use crate::store::{immutable, ordinal};
pub use storage::Archive;
use thiserror::Error;

/// Errors that can occur when interacting with the [Archive].
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("immutable index error: {0}")]
    Immutable(#[from] immutable::Error),
    #[error("ordinal index error: {0}")]
    Ordinal(#[from] ordinal::Error),
    #[error("record corrupted")]
    RecordCorrupted,
}

/// Configuration for [Archive] storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The configuration for the [immutable::Index].
    pub immutable: immutable::Config<C>,

    /// The configuration for the [ordinal::Index].
    pub ordinal: ordinal::Config,
}
