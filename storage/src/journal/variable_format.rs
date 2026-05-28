//! Wire-format helpers shared by the variable-length journal implementations.
//!
//! Items are length-prefixed with a u32 varint, optionally followed by a zstd-compressed payload.
//! Both [`segmented::variable`](crate::journal::segmented::variable) and
//! [`contiguous::variable`](crate::journal::contiguous::variable) consume these helpers so the
//! on-disk format remains interchangeable.

use crate::journal::Error;
use commonware_codec::{varint::UInt, Codec, ReadExt as _};
use commonware_runtime::Buf;
use zstd::decode_all;

/// Result of finding an item in a buffer (offsets/lengths, not slices).
pub(super) enum ItemInfo {
    /// All item data is available in the buffer.
    Complete {
        /// Length of the varint prefix.
        varint_len: usize,
        /// Length of the item data.
        data_len: usize,
    },
    /// Only some item data is available.
    Incomplete {
        /// Length of the varint prefix.
        varint_len: usize,
        /// Bytes of item data available in buffer.
        prefix_len: usize,
        /// Full size of the item.
        total_len: usize,
    },
}

/// Decode a varint length prefix from a buffer. Returns `(item_size, varint_len)`.
#[inline]
pub(super) fn decode_length_prefix(buf: &mut impl Buf) -> Result<(usize, usize), Error> {
    let initial = buf.remaining();
    let size = UInt::<u32>::read(buf)?.0 as usize;
    let varint_len = initial - buf.remaining();
    Ok((size, varint_len))
}

/// Inspect the varint header of an item at `offset`, advancing the buffer past the varint.
///
/// Returns `(next_offset, item_info)`. `item_info` is `Complete` if the full item body is
/// available in `buf`, otherwise `Incomplete` with the prefix length already buffered.
pub(super) fn find_item(buf: &mut impl Buf, offset: u64) -> Result<(u64, ItemInfo), Error> {
    let available = buf.remaining();
    let (size, varint_len) = decode_length_prefix(buf)?;
    let next_offset = offset
        .checked_add(varint_len as u64)
        .ok_or(Error::OffsetOverflow)?
        .checked_add(size as u64)
        .ok_or(Error::OffsetOverflow)?;
    let buffered = available.saturating_sub(varint_len);
    let item = if buffered >= size {
        ItemInfo::Complete {
            varint_len,
            data_len: size,
        }
    } else {
        ItemInfo::Incomplete {
            varint_len,
            prefix_len: buffered,
            total_len: size,
        }
    };
    Ok((next_offset, item))
}

/// Decode item data, optionally decompressing first.
pub(super) fn decode_item<V: Codec>(
    item_data: impl Buf,
    cfg: &V::Cfg,
    compressed: bool,
) -> Result<V, Error> {
    if compressed {
        let decompressed =
            decode_all(item_data.reader()).map_err(|_| Error::DecompressionFailed)?;
        V::decode_cfg(decompressed.as_ref(), cfg).map_err(Error::Codec)
    } else {
        V::decode_cfg(item_data, cfg).map_err(Error::Codec)
    }
}
