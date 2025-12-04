//! An append-only log for storing arbitrary data.
//!
//! Journals provide append-only logging for persisting arbitrary data with fast replay, historical
//! pruning, and rudimentary support for fetching individual items. A journal can be used on its own
//! to serve as a backing store for some in-memory data structure, or as a building block for a more
//! complex construction that prescribes some meaning to items in the log.

use thiserror::Error;

pub mod authenticated;
pub mod contiguous;
pub mod segmented;

impl<E, Op> crate::adb::sync::Journal for contiguous::fixed::Journal<E, Op>
where
    E: commonware_runtime::Storage + commonware_runtime::Clock + commonware_runtime::Metrics,
    Op: commonware_codec::Codec<Cfg = ()> + commonware_codec::FixedSize,
{
    type Op = Op;
    type Error = Error;

    async fn size(&self) -> u64 {
        Self::size(self)
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        Self::append(self, op).await.map(|_| ())
    }
}

/// Errors that can occur when interacting with `Journal`.
#[derive(Debug, Error)]
pub enum Error {
    #[error("mmr error: {0}")]
    Mmr(anyhow::Error),
    #[error("journal error: {0}")]
    Journal(anyhow::Error),
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
    #[error("section out of range: {0}")]
    SectionOutOfRange(u64),
    #[error("usize too small")]
    UsizeTooSmall,
    #[error("offset overflow")]
    OffsetOverflow,
    #[error("unexpected size: expected={0} actual={1}")]
    UnexpectedSize(u32, u32),
    #[error("missing blob: {0}")]
    MissingBlob(u64),
    #[error("item out of range: {0}")]
    ItemOutOfRange(u64),
    #[error("item pruned: {0}")]
    ItemPruned(u64),
    #[error("invalid rewind: {0}")]
    InvalidRewind(u64),
    #[error("compression failed")]
    CompressionFailed,
    #[error("decompression failed")]
    DecompressionFailed,
    #[error("corruption detected: {0}")]
    Corruption(String),
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
}
