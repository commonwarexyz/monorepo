//! Varint length-prefixed framing for variable-length journal items.
//!
//! Each item is stored as a varint `u32` length prefix followed by the (optionally
//! zstd-compressed) encoded item. Shared by [super::segmented::variable] and
//! [super::contiguous::variable].

use super::Error;
use commonware_codec::{varint::UInt, Codec, EncodeSize, ReadExt as _, Write as _};
use commonware_runtime::Buf;
use zstd::{bulk::compress, decode_all};

/// Decodes a varint length prefix from a buffer.
/// Returns (item_size, varint_len).
#[inline]
pub(super) fn decode_length_prefix(buf: &mut impl Buf) -> Result<(usize, usize), Error> {
    let initial = buf.remaining();
    let size = UInt::<u32>::read(buf)?.0 as usize;
    let varint_len = initial - buf.remaining();
    Ok((size, varint_len))
}

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

/// Find an item in a buffer by decoding its length prefix.
///
/// Returns (next_offset, item_info). The buffer is advanced past the varint.
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

/// Decode item data with optional decompression.
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

/// Encode an item with its length prefix, appending the encoded bytes to `buf`.
///
/// Existing contents of `buf` are preserved; this allows callers to accumulate
/// multiple encoded items into a single buffer.
///
/// Returns the payload length, excluding the size prefix.
pub(super) fn encode_item_into<V: Codec>(
    compression: Option<u8>,
    item: &V,
    buf: &mut Vec<u8>,
) -> Result<u32, Error> {
    if let Some(compression) = compression {
        // Compressed: encode first, then compress
        let encoded = item.encode();
        let compressed =
            compress(&encoded, compression as i32).map_err(|_| Error::CompressionFailed)?;
        let item_len = compressed.len();
        let item_len_u32: u32 = match item_len.try_into() {
            Ok(len) => len,
            Err(_) => return Err(Error::ItemTooLarge(item_len)),
        };
        let size_len = UInt(item_len_u32).encode_size();
        let entry_len = size_len
            .checked_add(item_len)
            .ok_or(Error::OffsetOverflow)?;

        buf.reserve(entry_len);
        UInt(item_len_u32).write(buf);
        buf.extend_from_slice(&compressed);

        Ok(item_len_u32)
    } else {
        // Uncompressed: pre-allocate exact size to avoid copying
        let item_len = item.encode_size();
        let item_len_u32: u32 = match item_len.try_into() {
            Ok(len) => len,
            Err(_) => return Err(Error::ItemTooLarge(item_len)),
        };
        let size_len = UInt(item_len_u32).encode_size();
        let entry_len = size_len
            .checked_add(item_len)
            .ok_or(Error::OffsetOverflow)?;

        buf.reserve(entry_len);
        UInt(item_len_u32).write(buf);
        item.write(buf);

        Ok(item_len_u32)
    }
}
