//! Shared format helpers for variable-length items in the journal layer.
//!
//! The on-disk format for a variable-length item is a u32 varint length prefix followed by the
//! item bytes (optionally `zstd`-compressed by the caller before encoding):
//!
//! ```text
//! +---+---+---+---+---+---+---+---+
//! |       0 ~ 4       |    ...    |
//! +---+---+---+---+---+---+---+---+
//! | Size (varint u32) |   Data    |
//! +---+---+---+---+---+---+---+---+
//! ```
//!
//! These helpers are format-level only. They do not encode recovery policy (whether to truncate
//! the blob on a bad varint, when to fall back to an anchor, etc.). Recovery policy lives in the
//! specific journal implementations.
//!
//! Consumers: [`crate::journal::segmented::variable`] and the contiguous variable data adapter.

use crate::journal::Error;
use commonware_codec::{
    varint::{UInt, MAX_U32_VARINT_SIZE},
    Codec, CodecShared, EncodeSize, ReadExt, Write as CodecWrite,
};
use commonware_runtime::{
    buffer::paged::{Append, Replay},
    Blob, Buf, IoBuf, IoBufMut,
};
use std::{future::Future, io::Cursor};
use zstd::{bulk::compress, decode_all};

/// Result of finding an item in a buffer (offsets/lengths, not slices).
pub(crate) enum ItemInfo {
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

/// Decode a varint length prefix from `buf`, advancing past it.
///
/// Returns `(item_size, varint_len)`.
pub(crate) fn decode_length_prefix(buf: &mut impl Buf) -> Result<(usize, usize), Error> {
    let initial = buf.remaining();
    let size = UInt::<u32>::read(buf)?.0 as usize;
    let varint_len = initial - buf.remaining();
    Ok((size, varint_len))
}

/// Inspect the item header in `buf`, advancing past the varint.
///
/// Returns `(next_item_offset, item_info)` where `next_item_offset` is the absolute offset just
/// past this item (varint + data) and `item_info` reports whether the full item is buffered.
pub(crate) fn find_item(buf: &mut impl Buf, offset: u64) -> Result<(u64, ItemInfo), Error> {
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

/// Decode item data, decompressing first if `compressed`.
pub(crate) fn decode_item<V: Codec>(
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

/// Minimal read surface needed by variable-item helpers.
///
/// Implementations are intentionally read-only. Callers keep ownership of storage lifecycle and
/// repair policy (resize, rewind, prune, sync) outside this trait.
pub(crate) trait SectionReader: Send + Sync {
    /// Return the logical section size.
    fn size(&self) -> impl Future<Output = Result<u64, Error>> + Send;

    /// Read up to `len` bytes starting at `offset`.
    fn read_prefix(
        &self,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = Result<IoBuf, Error>> + Send;

    /// Read exactly `len` bytes starting at `offset`.
    fn read_exact(
        &self,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = Result<IoBuf, Error>> + Send;

    /// Return the section size if it can be observed without waiting.
    fn try_size(&self) -> Option<u64>;

    /// Try to read from cache / memory without waiting for I/O.
    fn try_read_sync(&self, offset: u64, buf: &mut [u8]) -> bool;
}

impl<B: Blob> SectionReader for Append<B> {
    async fn size(&self) -> Result<u64, Error> {
        Ok(Self::size(self).await)
    }

    async fn read_prefix(&self, offset: u64, len: usize) -> Result<IoBuf, Error> {
        let (buf, _available) = self
            .read_up_to(offset, len, IoBufMut::with_capacity(len))
            .await
            .map_err(Error::Runtime)?;
        Ok(buf.freeze())
    }

    async fn read_exact(&self, offset: u64, len: usize) -> Result<IoBuf, Error> {
        Ok(self
            .read_at(offset, len)
            .await
            .map_err(Error::Runtime)?
            .coalesce())
    }

    fn try_size(&self) -> Option<u64> {
        Self::try_size(self)
    }

    fn try_read_sync(&self, offset: u64, buf: &mut [u8]) -> bool {
        Self::try_read_sync(self, offset, buf)
    }
}

/// One decoded item from replay.
pub(crate) struct ReplayItem<V> {
    /// Byte offset where the item's varint prefix begins.
    pub offset: u64,
    /// Payload size, excluding the varint prefix.
    pub size: u32,
    /// Decoded item.
    pub item: V,
}

/// Result of scanning replay for one item.
pub(crate) enum ReplayScan<V> {
    /// A complete, decoded item was found.
    Item(ReplayItem<V>),
    /// Replay reached trailing bytes or clean end-of-section.
    End {
        /// Offset just past the last fully decoded item.
        valid_offset: u64,
        /// Offset where scanning stopped.
        bad_offset: u64,
    },
}

/// Encode an item.
///
/// Returns `(buf, item_len)` where `item_len` is the encoded payload length, excluding the size
/// prefix.
pub(crate) fn encode_item<V: CodecShared>(
    compression: Option<u8>,
    item: &V,
) -> Result<(Vec<u8>, u32), Error> {
    let mut buf = Vec::new();
    let item_len = encode_item_into(compression, item, &mut buf)?;
    Ok((buf, item_len))
}

/// Encode an item with its length prefix, appending the encoded bytes to `buf`.
///
/// Existing contents of `buf` are preserved so callers can accumulate multiple encoded items into
/// one write buffer.
pub(crate) fn encode_item_into<V: CodecShared>(
    compression: Option<u8>,
    item: &V,
    buf: &mut Vec<u8>,
) -> Result<u32, Error> {
    if let Some(compression) = compression {
        let encoded = item.encode();
        let compressed =
            compress(&encoded, compression as i32).map_err(|_| Error::CompressionFailed)?;
        let item_len = compressed.len();
        let item_len_u32: u32 = item_len
            .try_into()
            .map_err(|_| Error::ItemTooLarge(item_len))?;
        let size_len = UInt(item_len_u32).encode_size();
        let entry_len = size_len
            .checked_add(item_len)
            .ok_or(Error::OffsetOverflow)?;

        buf.reserve(entry_len);
        UInt(item_len_u32).write(buf);
        buf.extend_from_slice(&compressed);

        Ok(item_len_u32)
    } else {
        let item_len = item.encode_size();
        let item_len_u32: u32 = item_len
            .try_into()
            .map_err(|_| Error::ItemTooLarge(item_len))?;
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

/// Read and decode one variable-length item from a section.
pub(crate) async fn read_item<V: Codec, R: SectionReader>(
    section: &R,
    offset: u64,
    cfg: &V::Cfg,
    compressed: bool,
) -> Result<(u64, u32, V), Error> {
    let header = section.read_prefix(offset, MAX_U32_VARINT_SIZE).await?;
    let mut cursor = Cursor::new(header.slice(..));
    let (next_offset, item_info) = find_item(&mut cursor, offset)?;
    let section_size = section.size().await?;
    if next_offset > section_size {
        return Err(Error::Corruption(format!(
            "item at offset {offset} extends past section size {section_size}: end={next_offset}"
        )));
    }

    let (item_size, decoded) = match item_info {
        ItemInfo::Complete {
            varint_len,
            data_len,
        } => {
            let data = header.slice(varint_len..varint_len + data_len);
            let decoded = decode_item::<V>(data, cfg, compressed)?;
            (data_len as u32, decoded)
        }
        ItemInfo::Incomplete {
            varint_len,
            prefix_len,
            total_len,
        } => {
            let prefix = header.slice(varint_len..varint_len + prefix_len);
            let read_offset = offset
                .checked_add(varint_len as u64)
                .and_then(|offset| offset.checked_add(prefix_len as u64))
                .ok_or(Error::OffsetOverflow)?;
            let remainder_len = total_len - prefix_len;
            let remainder = section.read_exact(read_offset, remainder_len).await?;
            let chained = prefix.chain(remainder);
            let decoded = decode_item::<V>(chained, cfg, compressed)?;
            (total_len as u32, decoded)
        }
    };

    Ok((next_offset, item_size, decoded))
}

/// Try to read and decode one item synchronously from cache / memory.
pub(crate) fn try_read_item_sync<V: Codec, R: SectionReader>(
    section: &R,
    offset: u64,
    cfg: &V::Cfg,
    compressed: bool,
    buf: &mut Vec<u8>,
) -> Option<V> {
    let remaining = section.try_size()?.checked_sub(offset)?;
    let header_len = usize::try_from(remaining.min(MAX_U32_VARINT_SIZE as u64)).ok()?;
    if header_len == 0 {
        return None;
    }

    let mut header = [0u8; MAX_U32_VARINT_SIZE];
    if !section.try_read_sync(offset, &mut header[..header_len]) {
        return None;
    }
    let mut cursor = Cursor::new(&header[..header_len]);
    let (_, item_info) = find_item(&mut cursor, offset).ok()?;
    let (varint_len, data_len) = match item_info {
        ItemInfo::Complete {
            varint_len,
            data_len,
        } => (varint_len, data_len),
        ItemInfo::Incomplete {
            varint_len,
            total_len,
            ..
        } => (varint_len, total_len),
    };
    let item_len = varint_len.checked_add(data_len)?;
    if item_len > usize::try_from(remaining).ok()? {
        return None;
    }

    if item_len <= header_len {
        return decode_item::<V>(&header[varint_len..varint_len + data_len], cfg, compressed).ok();
    }

    buf.resize(item_len, 0);
    if !section.try_read_sync(offset, buf) {
        return None;
    }
    decode_item::<V>(&buf[varint_len..varint_len + data_len], cfg, compressed).ok()
}

/// Read byte-adjacent items from one section.
///
/// `offsets` must be strictly increasing and identify adjacent items. The final item is read via
/// [`read_item`] because callers do not provide the byte offset just past it.
pub(crate) async fn read_many_consecutive<V: Codec, R: SectionReader>(
    section_num: u64,
    section: &R,
    offsets: &[u64],
    cfg: &V::Cfg,
    compressed: bool,
) -> Result<Vec<V>, Error> {
    if offsets.len() <= 1 {
        let mut items = Vec::with_capacity(offsets.len());
        for &offset in offsets {
            let (_, _, item) = read_item(section, offset, cfg, compressed).await?;
            items.push(item);
        }
        return Ok(items);
    }

    for window in offsets.windows(2) {
        if window[0] >= window[1] {
            return Err(Error::Corruption(format!(
                "offsets in section {section_num} must be strictly increasing: {} >= {}",
                window[0], window[1]
            )));
        }
    }

    let start = offsets[0];
    let end = offsets[offsets.len() - 1];
    let section_size = section.size().await?;
    if end > section_size {
        return Err(Error::Corruption(format!(
            "offset range {start}..{end} extends past section size {section_size}"
        )));
    }

    for window in offsets.windows(2) {
        let offset = window[0];
        let next_offset = window[1];
        let expected_len =
            usize::try_from(next_offset - offset).map_err(|_| Error::OffsetOverflow)?;

        let header = section.read_prefix(offset, MAX_U32_VARINT_SIZE).await?;
        let mut cursor = Cursor::new(header.slice(..));
        let (size, varint_len) = decode_length_prefix(&mut cursor)?;
        let actual_len = size.checked_add(varint_len).ok_or(Error::OffsetOverflow)?;
        if actual_len != expected_len {
            return Err(Error::OffsetDataMismatch {
                section: section_num,
                offset,
                expected_len,
                actual_len,
            });
        }

        let actual_end = offset
            .checked_add(actual_len as u64)
            .ok_or(Error::OffsetOverflow)?;
        if actual_end > section_size {
            return Err(Error::Corruption(format!(
                "item at offset {offset} extends past section size {section_size}: end={actual_end}"
            )));
        }
    }

    let range_len = usize::try_from(end - start).map_err(|_| Error::OffsetOverflow)?;
    let bytes = section.read_exact(start, range_len).await?;
    let bytes = bytes.as_ref();

    let mut items = Vec::with_capacity(offsets.len());
    let mut local_offset = 0usize;
    for window in offsets.windows(2) {
        let offset = window[0];
        let next_offset = window[1];
        let item_len = usize::try_from(next_offset - offset).map_err(|_| Error::OffsetOverflow)?;
        let mut cursor = Cursor::new(&bytes[local_offset..]);
        let (size, varint_len) = decode_length_prefix(&mut cursor)?;
        let actual_len = size.checked_add(varint_len).ok_or(Error::OffsetOverflow)?;
        if actual_len != item_len {
            return Err(Error::OffsetDataMismatch {
                section: section_num,
                offset,
                expected_len: item_len,
                actual_len,
            });
        }

        let data_start = local_offset
            .checked_add(varint_len)
            .ok_or(Error::OffsetOverflow)?;
        let data_end = local_offset
            .checked_add(item_len)
            .ok_or(Error::OffsetOverflow)?;
        items.push(decode_item::<V>(
            &bytes[data_start..data_end],
            cfg,
            compressed,
        )?);
        local_offset = data_end;
    }

    let (_, _, item) = read_item(section, end, cfg, compressed).await?;
    items.push(item);
    Ok(items)
}

/// Scan a replay stream for one item.
///
/// This function only reports trailing bytes via [`ReplayScan::End`]. It does not resize or sync
/// storage; the caller owns repair policy.
pub(crate) async fn scan_replay_item<B: Blob, V: Codec>(
    replay: &mut Replay<B>,
    offset: &mut u64,
    valid_offset: &mut u64,
    cfg: &V::Cfg,
    compressed: bool,
) -> Result<ReplayScan<V>, Error> {
    match replay.ensure(MAX_U32_VARINT_SIZE).await {
        Ok(true) => {}
        Ok(false) => {
            if replay.remaining() == 0 {
                return Ok(ReplayScan::End {
                    valid_offset: *valid_offset,
                    bad_offset: *offset,
                });
            }
        }
        Err(err) => return Err(Error::Runtime(err)),
    }

    let (item_size, varint_len) = match decode_length_prefix(replay) {
        Ok(result) => result,
        Err(err) => {
            if replay.is_exhausted() {
                return Ok(ReplayScan::End {
                    valid_offset: *valid_offset,
                    bad_offset: *offset,
                });
            }
            return Err(err);
        }
    };

    match replay.ensure(item_size).await {
        Ok(true) => {}
        Ok(false) => {
            return Ok(ReplayScan::End {
                valid_offset: *valid_offset,
                bad_offset: *offset,
            });
        }
        Err(err) => return Err(Error::Runtime(err)),
    }

    let item_offset = *offset;
    let next_offset = (*offset)
        .checked_add(varint_len as u64)
        .and_then(|o| o.checked_add(item_size as u64))
        .ok_or(Error::OffsetOverflow)?;
    let item = decode_item::<V>((&mut *replay).take(item_size), cfg, compressed)?;
    *valid_offset = next_offset;
    *offset = next_offset;

    Ok(ReplayScan::Item(ReplayItem {
        offset: item_offset,
        size: item_size as u32,
        item,
    }))
}

/// Advance `replay` by `skip_bytes`, returning `false` if the stream ends first.
pub(crate) async fn skip_replay<B: Blob>(
    replay: &mut Replay<B>,
    skip_bytes: &mut u64,
    offset: &mut u64,
    valid_offset: &mut u64,
) -> Result<bool, Error> {
    while *skip_bytes > 0 {
        match replay.ensure(MAX_U32_VARINT_SIZE).await {
            Ok(true) => {}
            Ok(false) => {
                if replay.remaining() == 0 {
                    return Ok(false);
                }
            }
            Err(err) => return Err(Error::Runtime(err)),
        }

        let to_skip = (*skip_bytes).min(replay.remaining() as u64) as usize;
        replay.advance(to_skip);
        *skip_bytes -= to_skip as u64;
        *offset += to_skip as u64;
    }

    *valid_offset = *offset;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use rstest::rstest;
    use std::io::Cursor;

    struct MemorySection {
        bytes: Vec<u8>,
        logical_size: Option<u64>,
    }

    impl MemorySection {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                logical_size: None,
            }
        }

        fn with_logical_size(bytes: Vec<u8>, logical_size: u64) -> Self {
            Self {
                bytes,
                logical_size: Some(logical_size),
            }
        }
    }

    impl SectionReader for MemorySection {
        async fn size(&self) -> Result<u64, Error> {
            self.logical_size.map_or_else(
                || {
                    self.bytes
                        .len()
                        .try_into()
                        .map_err(|_| Error::OffsetOverflow)
                },
                Ok,
            )
        }

        async fn read_prefix(&self, offset: u64, len: usize) -> Result<IoBuf, Error> {
            let start = usize::try_from(offset).map_err(|_| Error::OffsetOverflow)?;
            if start >= self.bytes.len() {
                return Err(Error::Corruption(format!(
                    "offset {offset} beyond in-memory section"
                )));
            }
            let end = start.saturating_add(len).min(self.bytes.len());
            Ok(IoBuf::copy_from_slice(&self.bytes[start..end]))
        }

        async fn read_exact(&self, offset: u64, len: usize) -> Result<IoBuf, Error> {
            let start = usize::try_from(offset).map_err(|_| Error::OffsetOverflow)?;
            let end = start.checked_add(len).ok_or(Error::OffsetOverflow)?;
            if end > self.bytes.len() {
                return Err(Error::Corruption(format!(
                    "range {offset}..{end} beyond in-memory section"
                )));
            }
            Ok(IoBuf::copy_from_slice(&self.bytes[start..end]))
        }

        fn try_size(&self) -> Option<u64> {
            self.bytes.len().try_into().ok()
        }

        fn try_read_sync(&self, offset: u64, buf: &mut [u8]) -> bool {
            let Ok(start) = usize::try_from(offset) else {
                return false;
            };
            let Some(end) = start.checked_add(buf.len()) else {
                return false;
            };
            let Some(bytes) = self.bytes.get(start..end) else {
                return false;
            };
            buf.copy_from_slice(bytes);
            true
        }
    }

    fn encode_u64_items(values: &[u64]) -> (Vec<u8>, Vec<u64>) {
        let mut bytes = Vec::new();
        let mut offsets = Vec::with_capacity(values.len());
        for value in values {
            offsets.push(bytes.len() as u64);
            encode_item_into(None, value, &mut bytes).unwrap();
        }
        (bytes, offsets)
    }

    #[rstest]
    #[case::single_item(vec![7], vec![7])]
    #[case::multiple_adjacent_items(vec![11, 22, 33], vec![11, 22, 33])]
    fn test_read_many_consecutive_decodes_adjacent_items(
        #[case] values: Vec<u64>,
        #[case] expected: Vec<u64>,
    ) {
        block_on(async {
            let (bytes, offsets) = encode_u64_items(&values);
            let section = MemorySection::new(bytes);

            // Adjacent offsets let the helper bulk-read all but the final item and then decode the
            // final item via `read_item`, matching the offsets/data journal fast path.
            let actual = read_many_consecutive::<u64, _>(7, &section, &offsets, &(), false)
                .await
                .unwrap();
            assert_eq!(actual, expected);
        });
    }

    #[rstest]
    #[case::gap_too_short(8, 8, 9)]
    #[case::gap_too_long(10, 10, 9)]
    fn test_read_many_consecutive_rejects_offset_data_mismatch(
        #[case] second_offset: u64,
        #[case] expected_len: usize,
        #[case] actual_len: usize,
    ) {
        block_on(async {
            let (bytes, _) = encode_u64_items(&[11, 22]);
            let section = MemorySection::new(bytes);

            // The offsets journal claims the next item starts at `second_offset`, but the data
            // varint says the first item occupies a different number of bytes.
            let err = read_many_consecutive::<u64, _>(7, &section, &[0, second_offset], &(), false)
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                Error::OffsetDataMismatch {
                    section: 7,
                    offset: 0,
                    expected_len: e,
                    actual_len: a,
                } if e == expected_len && a == actual_len
            ));
        });
    }

    #[rstest]
    #[case::duplicate_offset(vec![0, 0])]
    #[case::decreasing_offset(vec![9, 0])]
    fn test_read_many_consecutive_rejects_non_increasing_offsets(#[case] offsets: Vec<u64>) {
        block_on(async {
            let (bytes, _) = encode_u64_items(&[11, 22]);
            let section = MemorySection::new(bytes);

            // Non-increasing offsets can come from a corrupt offsets journal. They should surface
            // as recovery-visible corruption, not as a panic inside the shared format helper.
            let err = read_many_consecutive::<u64, _>(7, &section, &offsets, &(), false)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Corruption(_)));
        });
    }

    #[test]
    fn test_read_item_rejects_length_past_section_size() {
        block_on(async {
            let mut bytes = Vec::new();
            UInt(u32::MAX).write(&mut bytes);
            let section = MemorySection::new(bytes);

            let err = read_item::<u64, _>(&section, 0, &(), false)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Corruption(_)));
        });
    }

    #[test]
    fn test_read_many_consecutive_rejects_offset_gap_past_section_size() {
        block_on(async {
            let (bytes, _) = encode_u64_items(&[11]);
            let section = MemorySection::new(bytes);

            let err = read_many_consecutive::<u64, _>(7, &section, &[0, u64::MAX], &(), false)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Corruption(_)));
        });
    }

    #[test]
    fn test_read_many_consecutive_rejects_huge_gap_before_bulk_read() {
        block_on(async {
            let (bytes, _) = encode_u64_items(&[11]);
            let section = MemorySection::with_logical_size(bytes, 1_000_001);

            let err = read_many_consecutive::<u64, _>(7, &section, &[0, 1_000_000], &(), false)
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                Error::OffsetDataMismatch {
                    section: 7,
                    offset: 0,
                    expected_len: 1_000_000,
                    actual_len: 9,
                }
            ));
        });
    }

    #[rstest]
    #[case::complete_item(9, true, 8)]
    #[case::partial_item(4, false, 3)]
    fn test_find_item_reports_buffered_item_extent(
        #[case] buffered_len: usize,
        #[case] complete: bool,
        #[case] available_data_len: usize,
    ) {
        let (bytes, _) = encode_u64_items(&[42]);
        let mut cursor = Cursor::new(&bytes[..buffered_len]);

        // `find_item` reports the full item boundary from the varint even when the caller has only
        // buffered a prefix of the payload.
        let (next_offset, item) = find_item(&mut cursor, 11).unwrap();
        assert_eq!(next_offset, 20);
        match item {
            ItemInfo::Complete {
                varint_len,
                data_len,
            } => {
                assert!(complete);
                assert_eq!(varint_len, 1);
                assert_eq!(data_len, available_data_len);
            }
            ItemInfo::Incomplete {
                varint_len,
                prefix_len,
                total_len,
            } => {
                assert!(!complete);
                assert_eq!(varint_len, 1);
                assert_eq!(prefix_len, available_data_len);
                assert_eq!(total_len, 8);
            }
        }
    }
}
