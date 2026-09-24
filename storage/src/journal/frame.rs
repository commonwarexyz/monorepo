//! Varint length-prefixed framing for variable-length journal items.
//!
//! Each item is stored as a frame: a varint `u32` length prefix followed by the (optionally
//! zstd-compressed) encoded item.

use super::Error;
use commonware_codec::{
    Buf, Codec, EncodeSize, ReadExt as _, Write as _,
    varint::{MAX_U32_VARINT_SIZE, UInt},
};
use commonware_runtime::{Blob, Buf as _, IoBufMut, IoBufs, buffer::paged::Writer};
use commonware_utils::{Cached, Widen};
use std::{future::Future, io::Cursor};
use zstd::{
    bulk::Decompressor,
    zstd_safe::{CCtx, compress_bound, get_frame_content_size},
};

commonware_utils::thread_local_cache!(static COMPRESSOR: CCtx<'static>);
commonware_utils::thread_local_cache!(static DECOMPRESSOR: Decompressor<'static>);

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

impl<B: Blob, Phase: Send + Sync> FrameReader for Writer<B, Phase> {
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

/// Decompress a journal payload into an owned buffer for zero-copy decoding.
pub(super) fn decompress(compressed: &[u8]) -> Result<Vec<u8>, Error> {
    // Journal writers emit single frames that declare their content size, so we can allocate the
    // output buffer from it.
    let size = get_frame_content_size(compressed)
        .ok()
        .flatten()
        .and_then(|size| usize::try_from(size).ok())
        .ok_or(Error::DecompressionFailed)?;

    // Bulk decompression resets its fixed-size context before each frame, so it can be cached
    // without cleanup, even after a failed decode.
    Cached::take(&DECOMPRESSOR, Decompressor::new, |_| Ok(()))
        .and_then(|mut decompressor| decompressor.decompress(compressed, size))
        .map_err(|_| Error::DecompressionFailed)
}

/// Decode a frame's payload into an item, decompressing if needed.
pub(super) fn decode_item<V: Codec>(
    mut item_data: impl Buf,
    cfg: &V::Cfg,
    compressed: bool,
) -> Result<V, Error> {
    if compressed {
        // Bulk decompression reads one slice, so only a payload split across chunks is copied.
        let len = item_data.remaining();
        let decompressed = if item_data.chunk().len() == len {
            let decompressed = decompress(item_data.chunk());
            item_data.advance(len);
            decompressed?
        } else {
            decompress(&item_data.copy_to_bytes(len))?
        };
        V::decode_cfg(decompressed, cfg).map_err(Error::Codec)
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
    let mut cursor = buf.slice(..available);
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
            total_len,
            ..
        } if compressed => {
            // Reread the buffered prefix so a payload read as one chunk decompresses without a
            // staging copy.
            let data_offset = offset
                .checked_add(varint_len as u64)
                .ok_or(Error::OffsetOverflow)?;
            let data = reader.read_at(data_offset, total_len).await?;
            (total_len as u32, decode_item::<V>(data, cfg, compressed)?)
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

/// Compress `data` into one independent zstd frame appended to `buf`, returning its length.
pub(super) fn compress_into(level: u8, data: &[u8], buf: &mut Vec<u8>) -> Result<usize, Error> {
    let start = buf.len();
    buf.reserve(compress_bound(data.len()));
    let mut compressor = Cached::take(
        &COMPRESSOR,
        || CCtx::try_create().ok_or(Error::CompressionFailed),
        |_| Ok(()),
    )?;
    let mut tail = Cursor::new(buf);
    tail.set_position(start as u64);
    compressor
        .compress(&mut tail, data, level.into())
        .map_err(|_| Error::CompressionFailed)
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
    // Compressed: delegate to an out-of-line encoder so the uncompressed path below saves fewer
    // registers and uses a smaller stack frame.
    if let Some(compression) = compression {
        return encode_compressed_frame_into(compression, item, buf);
    }

    // Uncompressed: pre-allocate exact size to avoid copying.
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

/// Compressed case of [encode_frame_into], kept out of line so the uncompressed path saves
/// fewer registers and uses a smaller stack frame.
#[inline(never)]
fn encode_compressed_frame_into<V: Codec>(
    compression: u8,
    item: &V,
    buf: &mut Vec<u8>,
) -> Result<u32, Error> {
    // Reserve the maximum prefix width so compression writes directly into the output buffer.
    let encoded = item.encode();
    let start = buf.len();
    let max_len = compress_bound(encoded.len());
    let max_size_len = UInt(u32::try_from(max_len).unwrap_or(u32::MAX)).encode_size();
    let max_entry_len = max_size_len
        .checked_add(max_len)
        .ok_or(Error::OffsetOverflow)?;
    buf.reserve(max_entry_len);
    buf.resize(start + max_size_len, 0);
    let item_len = compress_into(compression, &encoded, buf)
        .and_then(|len| u32::try_from(len).map_err(|_| Error::ItemTooLarge(len)))
        .inspect_err(|_| buf.truncate(start))?;

    // Shift the payload down if its size needs a shorter prefix.
    let size_len = UInt(item_len).encode_size();
    if size_len < max_size_len {
        buf.copy_within(start + max_size_len.., start + size_len);
        buf.truncate(start + size_len + Widen::widen(item_len));
    }
    UInt(item_len).write(&mut &mut buf[start..start + size_len]);

    Ok(item_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::codec::View;
    use bytes::{BufMut, Bytes};
    use commonware_codec::{Copying, Encode, Read, Write};
    use commonware_utils::test_rng;
    use rand::{Rng as _, RngExt as _};
    use zstd::bulk::compress;

    /// Frame a single item and return the raw frame bytes.
    fn frame<V: Codec>(compression: Option<u8>, item: &V) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_frame_into(compression, item, &mut buf).unwrap();
        buf
    }

    #[test]
    fn test_roundtrip_uncompressed() {
        let buf = frame(None, &42u64);
        let mut cursor = Copying(&buf);
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
        let item: u64 =
            decode_item(Copying(&buf[varint_len..varint_len + data_len]), &(), false).unwrap();
        assert_eq!(item, 42);
    }

    #[test]
    fn test_roundtrip_compressed() {
        let buf = frame(Some(3), &42u64);
        let mut cursor = Copying(&buf);
        let (_, info) = find_frame(&mut cursor, 0).unwrap();
        let FrameInfo::Complete {
            varint_len,
            data_len,
        } = info
        else {
            panic!("expected complete frame");
        };
        let item: u64 =
            decode_item(Copying(&buf[varint_len..varint_len + data_len]), &(), true).unwrap();
        assert_eq!(item, 42);
    }

    #[test]
    fn test_cached_compressor_matches_independent_frames() {
        // Grow and shrink records while changing the level between them, as journals with
        // different levels would on one thread. Compressible records also shrink the size
        // prefix reserved for the largest possible payload.
        let cases = [
            ("empty", 0, 3),
            ("single byte", 1, 1),
            ("small record", 64, 19),
            ("grow to 1 KiB", 1024, 3),
            ("grow to 16 KiB", 16 * 1024, 1),
            ("row match finder", 64 * 1024, 7),
            ("cross a 128 KiB block", 130 * 1024, 3),
            ("small after large", 64, 0),
            ("clamped level", 1024, 255),
            ("empty after nonempty", 0, 9),
        ];

        // Appending frames must preserve any existing contents.
        let mut rng = test_rng();
        let mut cached_frames = b"existing data".to_vec();
        let mut independent_frames = cached_frames.clone();
        for (case, len, level) in cases {
            let repeated = vec![0xAB; len];
            let mut random = vec![0; len];
            rng.fill_bytes(&mut random);
            let partial = (0..len).map(|_| rng.random_range(0..16u8)).collect();
            for (pattern, item) in [
                ("repeated", repeated),
                ("random", random),
                ("partly compressible", partial),
            ] {
                // Each reference frame uses a fresh context.
                let compressed = zstd::bulk::compress(&item.encode(), level.into()).unwrap();
                UInt(compressed.len() as u32).write(&mut independent_frames);
                independent_frames.extend_from_slice(&compressed);

                let frame_start = cached_frames.len();
                let compressed_len =
                    encode_frame_into(Some(level), &item, &mut cached_frames).unwrap();
                assert_eq!(
                    compressed_len as usize,
                    compressed.len(),
                    "{case}, {pattern}, compression level {level}"
                );
                assert_eq!(
                    cached_frames, independent_frames,
                    "{case}, {pattern}, compression level {level}"
                );

                // Decoding the new frame must not require any earlier frame.
                let mut frame = Copying(&cached_frames[frame_start..]);
                let (frame_len, _) = decode_length_prefix(&mut frame).unwrap();
                assert_eq!(frame.remaining(), frame_len);
                let decoded = decode_item::<Vec<u8>>(frame, &((..).into(), ()), true).unwrap();
                assert_eq!(
                    decoded, item,
                    "{case}, {pattern}, compression level {level}"
                );
            }
        }

        assert!(
            COMPRESSOR.with(|slot| slot.borrow().1.is_some()),
            "the context must return to the thread's cache"
        );
    }

    #[test]
    fn test_accumulation_preserves_existing_contents() {
        let mut buf = Vec::new();
        encode_frame_into(None, &1u64, &mut buf).unwrap();
        let first_frame_len = buf.len();
        encode_frame_into(None, &2u64, &mut buf).unwrap();

        // Walk both frames out of the accumulated buffer.
        let mut cursor = Copying(&buf);
        let (first_end, _) = find_frame(&mut cursor, 0).unwrap();
        assert_eq!(first_end as usize, first_frame_len);
        let first: u64 = decode_item(Copying(&buf[1..9]), &(), false).unwrap();
        assert_eq!(first, 1);

        let mut cursor = Copying(&buf[first_frame_len..]);
        let (second_end, _) = find_frame(&mut cursor, first_end).unwrap();
        assert_eq!(second_end as usize, buf.len());
        let second: u64 = decode_item(Copying(&buf[first_frame_len + 1..]), &(), false).unwrap();
        assert_eq!(second, 2);
    }

    #[test]
    fn test_find_frame_zero_length_payload() {
        let buf = [0x00u8];
        let mut cursor = Copying(&buf);
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
        let mut cursor = Copying(&buf);
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
        let mut cursor = Copying(&buf);
        assert!(matches!(
            find_frame(&mut cursor, 0).unwrap().1,
            FrameInfo::Complete { data_len: 3, .. }
        ));

        let buf = [0x03u8, 1, 2];
        let mut cursor = Copying(&buf);
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
        let mut cursor = Copying(&[]);
        assert!(matches!(find_frame(&mut cursor, 0), Err(Error::Codec(_))));
    }

    #[test]
    fn test_find_frame_truncated_varint() {
        // A lone continuation byte is an incomplete varint, not a frame.
        let buf = [0x80u8];
        let mut cursor = Copying(&buf);
        assert!(matches!(find_frame(&mut cursor, 0), Err(Error::Codec(_))));
    }

    #[test]
    fn test_find_frame_varint_exceeds_u32() {
        // 5-byte varint encoding a value larger than u32::MAX.
        let buf = [0xFFu8, 0xFF, 0xFF, 0xFF, 0x7F];
        let mut cursor = Copying(&buf);
        assert!(matches!(find_frame(&mut cursor, 0), Err(Error::Codec(_))));
    }

    #[test]
    fn test_find_frame_offset_overflow() {
        let buf = frame(None, &42u64);
        let mut cursor = Copying(&buf);
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
            decode_item::<u64>(Copying(&buf), &(), false),
            Err(Error::Codec(commonware_codec::Error::ExtraData(_)))
        ));
    }

    #[test]
    fn test_decode_item_view() {
        let value: Vec<Bytes> = (0..64).map(|_| Bytes::from(vec![7u8; 17])).collect();
        let cfg = ((..).into(), (..).into());
        let buf = value.encode();
        let range = buf.as_ptr_range();

        // Decoding from the owned buffer hands out views of it
        let decoded = decode_item::<Vec<Bytes>>(buf.clone(), &cfg, false).unwrap();
        assert_eq!(decoded, value);
        assert!(decoded.iter().all(|b| range.contains(&b.as_ptr())));

        // Decoding from a slice of it copies every field
        let copied = decode_item::<Vec<Bytes>>(Copying(&buf), &cfg, false).unwrap();
        assert_eq!(copied, value);
        assert!(copied.iter().all(|b| !range.contains(&b.as_ptr())));

        // Decompressed fields share the decoder's input allocation
        let value = vec![View::new(1), View::new(2)];
        let buf = Bytes::from(zstd::bulk::compress(&value.encode(), 3).unwrap());
        let decoded = decode_item::<Vec<View>>(buf, &((..).into(), ()), true).unwrap();
        assert_eq!(decoded.len(), value.len());
        for (decoded, expected) in decoded.iter().zip(&value) {
            assert_eq!(decoded.bytes, expected.bytes);
            decoded.assert_shared();
        }
    }

    #[test]
    fn test_decode_item_corrupt_compressed_payload() {
        let mut buf = frame(Some(3), &42u64);
        // Corrupt the zstd magic number (first payload byte, after the 1-byte varint).
        buf[1] ^= 0xFF;
        assert!(matches!(
            decode_item::<u64>(Copying(&buf[1..]), &(), true),
            Err(Error::DecompressionFailed)
        ));
    }

    #[test]
    fn test_decode_item_decompresses_split_payloads_and_consumes_exactly() {
        let cfg = ((..).into(), ());
        for (len, level) in [(0usize, 3), (1, 1), (4096, 19), (70_000, 3)] {
            let item: Vec<u8> = (0..len).map(|i| (i % 7) as u8).collect();
            let payload = compress(&item.encode(), level).unwrap();

            // A payload in one chunk decompresses without copying its compressed bytes. Decoding
            // consumes exactly the payload and leaves the following bytes for the next frame.
            let mut source = Bytes::from([payload.as_slice(), &[9, 9]].concat());
            let decoded =
                decode_item::<Vec<u8>>((&mut source).take(payload.len()), &cfg, true).unwrap();
            assert_eq!(decoded, item);
            assert_eq!(source.as_ref(), &[9, 9]);

            // A payload split across chunks is copied first and consumed the same way.
            let (head, tail) = payload.split_at(payload.len().min(3));
            let mut split =
                Bytes::copy_from_slice(head).chain(Bytes::from([tail, &[9, 9]].concat()));
            let decoded =
                decode_item::<Vec<u8>>((&mut split).take(payload.len()), &cfg, true).unwrap();
            assert_eq!(decoded, item);
            assert_eq!(split.copy_to_bytes(split.remaining()).as_ref(), &[9, 9]);
        }
    }

    #[test]
    fn test_compressed_frames_declare_content_size() {
        // The reader requires the writer to declare each frame's decompressed size.
        for len in [0usize, 1, 4096] {
            let item = vec![7u8; len];
            let buf = frame(Some(3), &item);
            let (_, varint_len) = decode_length_prefix(&mut Copying(&buf)).unwrap();
            assert_eq!(
                get_frame_content_size(&buf[varint_len..]).unwrap(),
                Some(item.encode_size() as u64)
            );
        }
    }

    #[test]
    fn test_decompress_reuses_thread_context() {
        // Shrinking outputs, ending with an empty one, decompress through one cached context.
        for len in [70_000usize, 64, 0] {
            let data: Vec<u8> = (0..len).map(|i| (i % 7) as u8).collect();
            let payload = compress(&data, 3).unwrap();
            assert_eq!(get_frame_content_size(&payload).unwrap(), Some(len as u64));
            assert_eq!(decompress(&payload).unwrap(), data);
        }
        assert!(
            DECOMPRESSOR.with(|slot| slot.borrow().1.is_some()),
            "the context must return to the thread's cache"
        );
    }

    #[test]
    fn test_decompress_rejects_frame_without_content_size() {
        let payload = zstd::stream::encode_all(42u64.encode().as_ref(), 3).unwrap();
        assert_eq!(get_frame_content_size(&payload).unwrap(), None);
        assert!(matches!(
            decompress(&payload),
            Err(Error::DecompressionFailed)
        ));
    }

    #[test]
    fn test_decompress_rejects_wrong_declared_size() {
        let data = vec![7u8; 100];
        let payload = compress(&data, 3).unwrap();

        // A small single-segment frame stores its one-byte content size after the four-byte
        // magic number and the one-byte frame header descriptor.
        assert_eq!(payload[5], 100);
        for declared in [99u8, 101] {
            let mut corrupted = payload.clone();
            corrupted[5] = declared;
            assert_eq!(
                get_frame_content_size(&corrupted).unwrap(),
                Some(u64::from(declared))
            );
            assert!(matches!(
                decompress(&corrupted),
                Err(Error::DecompressionFailed)
            ));
        }
    }

    #[test]
    fn test_decompress_context_recovers_after_errors() {
        // Each truncation fails, and the cached context then decodes a valid payload.
        let payload = compress(&42u64.encode(), 3).unwrap();
        for len in 0..payload.len() {
            assert!(decompress(&payload[..len]).is_err());
            assert_eq!(
                decode_item::<u64>(Copying(&payload), &(), true).unwrap(),
                42
            );
        }
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
