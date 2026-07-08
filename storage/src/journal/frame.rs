//! Varint length-prefixed framing for variable-length journal items.
//!
//! Each item is stored as a frame: a varint `u32` length prefix followed by the (optionally
//! zstd-compressed) encoded item.

use super::Error;
use commonware_codec::{
    util::at_least,
    varint::{UInt, MAX_U32_VARINT_SIZE},
    Codec, Decode as _, EncodeSize, Read, ReadExt as _, Write as _,
};
use commonware_runtime::{buffer::paged::Writer, Blob, Buf, IoBufMut, IoBufs};
use std::{future::Future, io::Cursor};
use zstd::{bulk::compress, decode_all};

/// Decodes a varint length prefix followed by exactly that many payload bytes. Used to fuse
/// header parsing and item decoding into a single page-cache decode on the synchronous,
/// uncompressed read path.
///
/// Matches [find_frame]'s varint semantics (u32 range, max 5 bytes, same overflow handling) by
/// using the same [UInt] reader.
pub(super) struct PrefixedItem<V>(pub(super) V);

impl<V: Read> Read for PrefixedItem<V> {
    type Cfg = V::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let data_len = UInt::<u32>::read(buf)?.0 as usize;
        // The at_least guard must stay: it ensures every V (even a decoder driven by
        // `remaining()`) sees exactly `data_len` bytes in both the sync and async paths,
        // rather than successfully decoding a short prefix when a gather is truncated
        // mid-payload.
        at_least(buf, data_len)?;
        V::decode_cfg(buf.take(data_len), cfg).map(Self)
    }
}

/// Read access needed to decode a frame at a known offset.
pub(super) trait FrameReader {
    /// Read up to `len` bytes at `offset`.
    fn read_up_to(
        &self,
        offset: u64,
        len: usize,
        buf: impl Into<IoBufMut> + Send,
    ) -> impl Future<Output = Result<(IoBufMut, usize), Error>> + Send;

    /// Read exactly `len` bytes at `offset`.
    fn read_at(
        &self,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = Result<IoBufs, Error>> + Send;
}

impl<B: Blob> FrameReader for Writer<B> {
    async fn read_up_to(
        &self,
        offset: u64,
        len: usize,
        buf: impl Into<IoBufMut> + Send,
    ) -> Result<(IoBufMut, usize), Error> {
        Self::read_up_to(self, offset, len, buf)
            .await
            .map_err(Error::Runtime)
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        Self::read_at(self, offset, len)
            .await
            .map_err(Error::Runtime)
    }
}

/// Decodes a varint length prefix from a buffer.
/// Returns (item_size, varint_len).
#[inline]
pub(super) fn decode_length_prefix(buf: &mut impl Buf) -> Result<(usize, usize), Error> {
    let initial = buf.remaining();
    let size = UInt::<u32>::read(buf)?.0 as usize;
    let varint_len = initial - buf.remaining();
    Ok((size, varint_len))
}

/// Payload availability of a frame found in a buffer (offsets/lengths, not slices).
pub(super) enum FrameInfo {
    /// The frame's full payload is available in the buffer.
    Complete {
        /// Length of the varint prefix.
        varint_len: usize,
        /// Length of the item data.
        data_len: usize,
    },
    /// Only part of the frame's payload is available.
    Incomplete {
        /// Length of the varint prefix.
        varint_len: usize,
        /// Bytes of item data available in buffer.
        prefix_len: usize,
        /// Full size of the item.
        total_len: usize,
    },
}

/// Find the frame at `offset` in a buffer by decoding its length prefix.
///
/// Returns (next_offset, frame_info). The buffer is advanced past the varint.
pub(super) fn find_frame(buf: &mut impl Buf, offset: u64) -> Result<(u64, FrameInfo), Error> {
    let available = buf.remaining();
    let (size, varint_len) = decode_length_prefix(buf)?;
    let next_offset = offset
        .checked_add(varint_len as u64)
        .ok_or(Error::OffsetOverflow)?
        .checked_add(size as u64)
        .ok_or(Error::OffsetOverflow)?;
    let buffered = available.saturating_sub(varint_len);

    let item = if buffered >= size {
        FrameInfo::Complete {
            varint_len,
            data_len: size,
        }
    } else {
        FrameInfo::Incomplete {
            varint_len,
            prefix_len: buffered,
            total_len: size,
        }
    };

    Ok((next_offset, item))
}

/// Decode a frame's payload into an item, decompressing if needed.
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

/// Read and decode the frame at `offset`.
pub(super) async fn read_frame_at<V: Codec>(
    reader: &impl FrameReader,
    offset: u64,
    cfg: &V::Cfg,
    compressed: bool,
) -> Result<(u64, u32, V), Error> {
    let (buf, available) = reader
        .read_up_to(
            offset,
            MAX_U32_VARINT_SIZE,
            IoBufMut::with_capacity(MAX_U32_VARINT_SIZE),
        )
        .await?;
    let buf = buf.freeze();
    let mut cursor = Cursor::new(buf.slice(..available));
    let (next_offset, item_info) = find_frame(&mut cursor, offset)?;

    let (item_size, decoded) = match item_info {
        FrameInfo::Complete {
            varint_len,
            data_len,
        } => {
            let decoded = decode_item::<V>(
                buf.slice(varint_len..varint_len + data_len),
                cfg,
                compressed,
            )?;
            (data_len as u32, decoded)
        }
        FrameInfo::Incomplete {
            varint_len,
            prefix_len,
            total_len,
        } => {
            let prefix = buf.slice(varint_len..varint_len + prefix_len);
            let read_offset = offset
                .checked_add(varint_len as u64)
                .and_then(|offset| offset.checked_add(prefix_len as u64))
                .ok_or(Error::OffsetOverflow)?;
            let remainder = reader.read_at(read_offset, total_len - prefix_len).await?;
            let decoded = decode_item::<V>(prefix.chain(remainder), cfg, compressed)?;
            (total_len as u32, decoded)
        }
    };

    Ok((next_offset, item_size, decoded))
}

/// Encode an item as a frame (length prefix plus payload), appending the bytes to `buf`.
///
/// Existing contents of `buf` are preserved; this allows callers to accumulate
/// multiple encoded items into a single buffer.
///
/// Returns the payload length, excluding the size prefix.
pub(super) fn encode_frame_into<V: Codec>(
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use commonware_codec::{Read, Write};

    /// Frame a single item and return the raw frame bytes.
    fn frame<V: Codec>(compression: Option<u8>, item: &V) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_frame_into(compression, item, &mut buf).unwrap();
        buf
    }

    /// A decoder driven by `remaining()` rather than the bytes it consumes: it greedily
    /// swallows everything available and always succeeds. Used to prove [PrefixedItem]'s
    /// `at_least` guard rejects short windows before such a decoder can misread them.
    struct Greedy(Vec<u8>);

    impl Read for Greedy {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
            let mut data = vec![0u8; buf.remaining()];
            buf.copy_to_slice(&mut data);
            Ok(Self(data))
        }
    }

    #[test]
    fn test_prefixed_item_roundtrip() {
        let buf = frame(None, &42u64);
        let mut cursor = &buf[..];
        let item = PrefixedItem::<u64>::read_cfg(&mut cursor, &()).unwrap();
        assert_eq!(item.0, 42);
        // The frame is consumed exactly: varint prefix plus payload.
        assert!(cursor.is_empty());
    }

    #[test]
    fn test_prefixed_item_trailing_bytes_preserved() {
        // Two frames back to back: decoding the first must stop exactly at its end.
        let mut buf = frame(None, &1u64);
        buf.extend_from_slice(&frame(None, &2u64));
        let mut cursor = &buf[..];
        assert_eq!(
            PrefixedItem::<u64>::read_cfg(&mut cursor, &()).unwrap().0,
            1
        );
        assert_eq!(
            PrefixedItem::<u64>::read_cfg(&mut cursor, &()).unwrap().0,
            2
        );
        assert!(cursor.is_empty());
    }

    #[test]
    fn test_prefixed_item_zero_length_payload() {
        // A frame declaring zero payload bytes leaves the payload decoder with nothing.
        let buf = [0x00u8];
        let mut cursor = &buf[..];
        assert!(matches!(
            PrefixedItem::<u64>::read_cfg(&mut cursor, &()),
            Err(commonware_codec::Error::EndOfBuffer)
        ));
    }

    #[test]
    fn test_prefixed_item_varint_exceeds_u32() {
        // 5-byte varint encoding a value larger than u32::MAX must fail like find_frame does.
        let buf = [0xFFu8, 0xFF, 0xFF, 0xFF, 0x7F];
        let mut cursor = &buf[..];
        assert!(PrefixedItem::<u64>::read_cfg(&mut cursor, &()).is_err());
        let mut cursor = &buf[..];
        assert!(find_frame(&mut cursor, 0).is_err());
    }

    #[test]
    fn test_prefixed_item_truncated_varint() {
        // A lone continuation byte is an incomplete varint.
        let buf = [0x80u8];
        let mut cursor = &buf[..];
        assert!(PrefixedItem::<u64>::read_cfg(&mut cursor, &()).is_err());
    }

    #[test]
    fn test_prefixed_item_payload_exceeds_window() {
        // The prefix declares 5 payload bytes but only 3 are available: the decode must fail
        // with EndOfBuffer so a truncated cache gather classifies as a miss.
        let buf = [0x05u8, 1, 2, 3];
        let mut cursor = &buf[..];
        assert!(matches!(
            PrefixedItem::<u64>::read_cfg(&mut cursor, &()),
            Err(commonware_codec::Error::EndOfBuffer)
        ));
    }

    #[test]
    fn test_prefixed_item_under_consumption() {
        // The prefix declares 8 payload bytes but a u32 consumes only 4: the leftover bytes
        // inside the declared window must be reported as ExtraData, matching decode_cfg.
        let mut buf = vec![0x08u8];
        buf.extend_from_slice(&7u32.to_be_bytes());
        buf.extend_from_slice(&[0u8; 4]);
        let mut cursor = &buf[..];
        assert!(matches!(
            PrefixedItem::<u32>::read_cfg(&mut cursor, &()),
            Err(commonware_codec::Error::ExtraData(4))
        ));
    }

    #[test]
    fn test_prefixed_item_guards_greedy_decoder_on_short_window() {
        // The at_least guard must reject a window shorter than the declared payload BEFORE
        // handing it to the payload decoder. A remaining()-driven decoder would otherwise
        // successfully consume the short window (Buf::take clamps to the bytes available)
        // and silently return a wrong, shorter value.
        let buf = [0x05u8, 1, 2, 3];
        let mut cursor = &buf[..];
        assert!(matches!(
            PrefixedItem::<Greedy>::read_cfg(&mut cursor, &()),
            Err(commonware_codec::Error::EndOfBuffer)
        ));

        // With the full window available the greedy decoder sees exactly the declared bytes.
        let buf = [0x05u8, 1, 2, 3, 4, 5, 99];
        let mut cursor = &buf[..];
        let item = PrefixedItem::<Greedy>::read_cfg(&mut cursor, &()).unwrap();
        assert_eq!(item.0 .0, vec![1, 2, 3, 4, 5]);
        assert_eq!(cursor, &[99u8][..]);
    }

    #[test]
    fn test_roundtrip_uncompressed() {
        let buf = frame(None, &42u64);
        let mut cursor = &buf[..];
        let (next_offset, info) = find_frame(&mut cursor, 0).unwrap();
        let FrameInfo::Complete {
            varint_len,
            data_len,
        } = info
        else {
            panic!("expected complete frame");
        };
        assert_eq!(varint_len, 1);
        assert_eq!(data_len, 8);
        assert_eq!(next_offset, 9);
        let item: u64 = decode_item(&buf[varint_len..varint_len + data_len], &(), false).unwrap();
        assert_eq!(item, 42);
    }

    #[test]
    fn test_roundtrip_compressed() {
        let buf = frame(Some(3), &42u64);
        let mut cursor = &buf[..];
        let (_, info) = find_frame(&mut cursor, 0).unwrap();
        let FrameInfo::Complete {
            varint_len,
            data_len,
        } = info
        else {
            panic!("expected complete frame");
        };
        let item: u64 = decode_item(&buf[varint_len..varint_len + data_len], &(), true).unwrap();
        assert_eq!(item, 42);
    }

    #[test]
    fn test_accumulation_preserves_existing_contents() {
        let mut buf = Vec::new();
        encode_frame_into(None, &1u64, &mut buf).unwrap();
        let first_frame_len = buf.len();
        encode_frame_into(None, &2u64, &mut buf).unwrap();

        // Walk both frames out of the accumulated buffer.
        let mut cursor = &buf[..];
        let (first_end, _) = find_frame(&mut cursor, 0).unwrap();
        assert_eq!(first_end as usize, first_frame_len);
        let first: u64 = decode_item(&buf[1..9], &(), false).unwrap();
        assert_eq!(first, 1);

        let mut cursor = &buf[first_frame_len..];
        let (second_end, _) = find_frame(&mut cursor, first_end).unwrap();
        assert_eq!(second_end as usize, buf.len());
        let second: u64 = decode_item(&buf[first_frame_len + 1..], &(), false).unwrap();
        assert_eq!(second, 2);
    }

    #[test]
    fn test_find_frame_zero_length_payload() {
        let buf = [0x00u8];
        let mut cursor = &buf[..];
        let (next_offset, info) = find_frame(&mut cursor, 7).unwrap();
        let FrameInfo::Complete {
            varint_len,
            data_len,
        } = info
        else {
            panic!("expected complete frame");
        };
        assert_eq!((varint_len, data_len), (1, 0));
        assert_eq!(next_offset, 8);
    }

    #[test]
    fn test_find_frame_incomplete_payload() {
        // Prefix declares 5 payload bytes; only 3 are buffered.
        let buf = [0x05u8, 1, 2, 3];
        let mut cursor = &buf[..];
        let (next_offset, info) = find_frame(&mut cursor, 100).unwrap();
        let FrameInfo::Incomplete {
            varint_len,
            prefix_len,
            total_len,
        } = info
        else {
            panic!("expected incomplete frame");
        };
        assert_eq!((varint_len, prefix_len, total_len), (1, 3, 5));
        assert_eq!(next_offset, 106);
        // The buffer is advanced past the varint only.
        assert_eq!(cursor.remaining(), 3);
    }

    #[test]
    fn test_find_frame_payload_boundary() {
        // Exactly filling the buffer is complete; one byte short is incomplete.
        let buf = [0x03u8, 1, 2, 3];
        let mut cursor = &buf[..];
        assert!(matches!(
            find_frame(&mut cursor, 0).unwrap().1,
            FrameInfo::Complete { data_len: 3, .. }
        ));

        let buf = [0x03u8, 1, 2];
        let mut cursor = &buf[..];
        assert!(matches!(
            find_frame(&mut cursor, 0).unwrap().1,
            FrameInfo::Incomplete {
                prefix_len: 2,
                total_len: 3,
                ..
            }
        ));
    }

    #[test]
    fn test_find_frame_empty_buffer() {
        let mut cursor = &[][..];
        assert!(matches!(find_frame(&mut cursor, 0), Err(Error::Codec(_))));
    }

    #[test]
    fn test_find_frame_truncated_varint() {
        // A lone continuation byte is an incomplete varint, not a frame.
        let buf = [0x80u8];
        let mut cursor = &buf[..];
        assert!(matches!(find_frame(&mut cursor, 0), Err(Error::Codec(_))));
    }

    #[test]
    fn test_find_frame_varint_exceeds_u32() {
        // 5-byte varint encoding a value larger than u32::MAX.
        let buf = [0xFFu8, 0xFF, 0xFF, 0xFF, 0x7F];
        let mut cursor = &buf[..];
        assert!(matches!(find_frame(&mut cursor, 0), Err(Error::Codec(_))));
    }

    #[test]
    fn test_find_frame_offset_overflow() {
        let buf = frame(None, &42u64);
        let mut cursor = &buf[..];
        assert!(matches!(
            find_frame(&mut cursor, u64::MAX),
            Err(Error::OffsetOverflow)
        ));
    }

    #[test]
    fn test_decode_item_rejects_trailing_bytes() {
        // 9 bytes for a u64: decode must consume exactly the payload.
        let buf = [0u8; 9];
        assert!(matches!(
            decode_item::<u64>(&buf[..], &(), false),
            Err(Error::Codec(commonware_codec::Error::ExtraData(_)))
        ));
    }

    #[test]
    fn test_decode_item_corrupt_compressed_payload() {
        let mut buf = frame(Some(3), &42u64);
        // Corrupt the zstd magic number (first payload byte, after the 1-byte varint).
        buf[1] ^= 0xFF;
        assert!(matches!(
            decode_item::<u64>(&buf[1..], &(), true),
            Err(Error::DecompressionFailed)
        ));
    }

    /// An item whose claimed encoded size exceeds the u32 frame limit. The size check
    /// happens before any bytes are written, so `write` is unreachable.
    struct Oversized;

    impl EncodeSize for Oversized {
        fn encode_size(&self) -> usize {
            u32::MAX as usize + 1
        }
    }

    impl Write for Oversized {
        fn write(&self, _: &mut impl BufMut) {
            unreachable!("size check rejects the item before writing")
        }
    }

    impl Read for Oversized {
        type Cfg = ();

        fn read_cfg(_: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
            unreachable!("never decoded")
        }
    }

    #[test]
    fn test_encode_frame_rejects_oversized_item() {
        let mut buf = Vec::new();
        assert!(matches!(
            encode_frame_into(None, &Oversized, &mut buf),
            Err(Error::ItemTooLarge(_))
        ));
        assert!(buf.is_empty());
    }
}
