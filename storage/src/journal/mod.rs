//! An append-only log for storing arbitrary data.
//!
//! Journals provide append-only logging for persisting arbitrary data with fast replay, historical
//! pruning, and rudimentary support for fetching individual items. A journal can be used on its own
//! to serve as a backing store for some in-memory data structure, or as a building block for a more
//! complex construction that prescribes some meaning to items in the log.

use thiserror::Error;

use crate::adb::sync::error::SyncError;

pub mod fixed;
pub mod variable;

impl<E, Op> crate::adb::sync::engine::Journal for fixed::Journal<E, Op>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
    Op: commonware_codec::Codec<Cfg = ()> + commonware_codec::FixedSize + Send + 'static,
{
    type Op = Op;
    type Error = SyncError<crate::adb::Error>;

    async fn size(&self) -> Result<u64, Self::Error> {
        fixed::Journal::size(self)
            .await
            .map_err(|e| SyncError::Database(crate::adb::Error::JournalError(e)))
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        fixed::Journal::append(self, op)
            .await
            .map(|_| ())
            .map_err(|e| SyncError::Database(crate::adb::Error::JournalError(e)))
    }

    async fn resize(&mut self, lower_bound: u64, upper_bound: u64) -> Result<(), Self::Error> {
        let log_size = self
            .size()
            .await
            .map_err(|e| SyncError::Database(crate::adb::Error::JournalError(e)))?;

        if log_size <= lower_bound {
            // Would need to create new journal first, but we don't have access to context/config here
            // This is a limitation of implementing SyncJournal directly on Journal
            // For now, just fail with an appropriate error using InvalidSyncRange from journal errors
            return Err(SyncError::Database(crate::adb::Error::JournalError(
                Error::InvalidSyncRange(lower_bound, upper_bound),
            )));
        } else {
            // Prune the journal to the new lower bound
            self.prune(lower_bound)
                .await
                .map_err(|e| SyncError::Database(crate::adb::Error::JournalError(e)))?;
        }

        Ok(())
    }
}

/// Errors that can occur when interacting with `Journal`.
#[derive(Debug, Error)]
pub enum Error {
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("codec error: {0}")]
    Codec(#[from] commonware_codec::Error),
    #[error("invalid blob name: {0}")]
    InvalidBlobName(String),
    #[error("invalid blob size: index={0} size={1}")]
    InvalidBlobSize(u64, u64),
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
    #[error("compression failed")]
    CompressionFailed,
    #[error("decompression failed")]
    DecompressionFailed,
    #[error("invalid sync range: lower_bound={0} upper_bound={1}")]
    InvalidSyncRange(u64, u64),
}
