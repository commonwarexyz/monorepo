//! An append-only log for storing arbitrary data.
//!
//! Journals provide append-only logging for persisting arbitrary data with fast replay, historical
//! pruning, and rudimentary support for fetching individual items. A journal can be used on its own
//! to serve as a backing store for some in-memory data structure, or as a building block for a more
//! complex construction that prescribes some meaning to items in the log.

use commonware_codec::{CodecFixedShared, Copying, DecodeExt as _};
use commonware_utils::Cached;
use thiserror::Error;

commonware_macros::stability_mod!(ALPHA, pub mod authenticated);
pub mod contiguous;
pub(crate) mod durability;
mod frame;
pub mod segmented;

#[cfg(all(test, feature = "arbitrary"))]
mod conformance;

/// Errors that can occur when interacting with `Journal`.
#[derive(Debug, Error)]
pub enum Error {
    #[error("merkle error: {0}")]
    Merkle(anyhow::Error),
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("codec error: {0}")]
    Codec(#[from] commonware_codec::Error),
    #[error("metadata error: {0}")]
    Metadata(#[from] crate::metadata::Error),
    #[error("invalid blob name: {0}")]
    InvalidBlobName(String),
    #[error("invalid blob size: index={0} size={1}")]
    InvalidBlobSize(u64, u64),
    #[error("item too large: size={0}")]
    ItemTooLarge(usize),
    #[error("already pruned to section: {0}")]
    AlreadyPrunedToSection(u64),
    #[error("section out of range: {0}")]
    SectionOutOfRange(u64),
    #[error("offset overflow")]
    OffsetOverflow,
    #[error("replay interrupted during repair")]
    ReplayInterrupted,
    #[error("replay failed")]
    ReplayFailed,
    #[error("size overflow")]
    SizeOverflow,
    #[error("item out of range: {0}")]
    ItemOutOfRange(u64),
    #[error("item pruned: {0}")]
    ItemPruned(u64),
    #[error("compression failed")]
    CompressionFailed,
    #[error("decompression failed")]
    DecompressionFailed,
    #[error("value too large (> u32::MAX)")]
    ValueTooLarge,
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
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("checksum mismatch: expected={0}, found={1}")]
    ChecksumMismatch(u32, u32),
    #[error("empty append")]
    EmptyAppend,
}

// Reusable scratch for [`decode_sync`] on items larger than [`SYNC_READ_STACK_SIZE`], grown to
// the largest item served on the thread.
commonware_utils::thread_local_cache!(static SYNC_READ_SCRATCH: Vec<u8>);

/// Largest item [`decode_sync`] reads into a stack buffer instead of a thread-local scratch.
const SYNC_READ_STACK_SIZE: usize = 128;

/// Decode an `A` from the `A::SIZE` bytes `read_into` copies into the buffer it is given,
/// returning `None` if `read_into` reports the bytes are not in memory or they fail to decode.
fn decode_sync<A: CodecFixedShared>(read_into: impl FnOnce(&mut [u8]) -> bool) -> Option<A> {
    let decode = |buf: &mut [u8]| {
        if read_into(buf) {
            A::decode(Copying(buf)).ok()
        } else {
            None
        }
    };
    // Small items fit on the stack, skipping the thread-local scratch handoff.
    if const { A::SIZE <= SYNC_READ_STACK_SIZE } {
        decode(&mut [0u8; SYNC_READ_STACK_SIZE][..A::SIZE])
    } else {
        let mut scratch =
            Cached::take(&SYNC_READ_SCRATCH, || Ok::<_, ()>(Vec::new()), |_| Ok(())).unwrap();
        if scratch.len() < A::SIZE {
            scratch.resize(A::SIZE, 0);
        }
        decode(&mut scratch[..A::SIZE])
    }
}
