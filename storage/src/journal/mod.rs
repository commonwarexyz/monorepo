//! An append-only log for storing arbitrary data.
//!
//! Journals provide append-only logging for persisting arbitrary data with fast replay, historical
//! pruning, and rudimentary support for fetching individual items. A journal can be used on its own
//! to serve as a backing store for some in-memory data structure, or as a building block for a more
//! complex construction that prescribes some meaning to items in the log.

use thiserror::Error;

commonware_macros::stability_mod!(ALPHA, pub mod authenticated);
pub mod contiguous;
pub(crate) mod durability;
mod frame;
pub mod segmented;

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;

/// Errors that can occur when interacting with a journal.
#[derive(Debug, Error)]
pub enum Error {
    /// The runtime failed.
    #[error(transparent)]
    Runtime(#[from] commonware_runtime::Error),
    /// A stored item failed to decode.
    #[error(transparent)]
    Codec(#[from] commonware_codec::Error),
    /// The metadata store holding the journal's recovery checkpoint or markers failed.
    #[error(transparent)]
    Metadata(#[from] crate::metadata::Error),
    /// A blob in the partition has a name that is not a valid section number.
    #[error("invalid blob name: {0}")]
    InvalidBlobName(String),
    /// An item's encoded size does not fit in a `u32`.
    #[error("item too large: size={0}")]
    ItemTooLarge(usize),
    /// The requested section has already been pruned.
    #[error("already pruned to section: {0}")]
    AlreadyPrunedToSection(u64),
    /// The requested section does not exist.
    #[error("section out of range: {0}")]
    SectionOutOfRange(u64),
    /// An offset or position computation overflowed.
    #[error("offset overflow")]
    OffsetOverflow,
    /// A dropped future cancelled a replay while it was repairing a section.
    #[error("replay interrupted during repair")]
    ReplayInterrupted,
    /// A replay was finished before it was drained, after it yielded an error, after its
    /// validation failed, or with the wrong finish method.
    #[error("replay failed")]
    ReplayFailed,
    /// The journal's size would exceed `u64::MAX`.
    #[error("size overflow")]
    SizeOverflow,
    /// The requested item is past the end of the journal or section. In a segmented variable
    /// journal's replay, the payload is a byte offset.
    #[error("item out of range: {0}")]
    ItemOutOfRange(u64),
    /// The requested item has been pruned.
    #[error("item pruned: {0}")]
    ItemPruned(u64),
    /// zstd failed to compress an item.
    #[error("compression failed")]
    CompressionFailed,
    /// zstd failed to decompress a stored item.
    #[error("decompression failed")]
    DecompressionFailed,
    /// Stored data is inconsistent.
    #[error("corruption detected: {0}")]
    Corruption(String),
    /// The offsets journal and the data journal disagree about an item's layout. Either the
    /// on-disk state is corrupted, or the caller passed offsets that aren't byte-adjacent on disk.
    #[error(
        "offset/data layout mismatch in section {section} at offset {offset}: offsets journal expected {expected_len}, data varint reports {actual_len}"
    )]
    OffsetDataMismatch {
        section: u64,
        offset: u64,
        expected_len: usize,
        actual_len: usize,
    },
    /// A prepared append was encoded with a different compression setting than the journal uses.
    #[error("prepared append compression setting does not match journal")]
    PreparedMismatch,
    /// A stored value's checksum does not match its contents.
    #[error("checksum mismatch: expected={0}, found={1}")]
    ChecksumMismatch(u32, u32),
    /// An append contained no items.
    #[error("empty append")]
    EmptyAppend,
}
