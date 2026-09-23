//! Varint length-prefixed framing for variable-length journal items.
//!
//! Each item is stored as a frame: a varint `u32` length prefix followed by the (optionally
//! zstd-compressed) encoded item.

use super::Error;
use bytes::BufMut;
use commonware_codec::{
    Buf, Codec, EncodeSize, ReadExt as _, Write,
    varint::{MAX_U32_VARINT_SIZE, UInt},
};
use commonware_runtime::{
    Blob, Buf as _, BufferPool, IoBufMut, IoBufs, buffer::paged::Writer, iobuf::EncodeExt as _,
};
use commonware_utils::Cached;
use std::future::Future;
use zstd::{
    bulk::{Compressor, Decompressor},
    zstd_safe::{WriteBuf, compress_bound, get_frame_content_size},
};

commonware_utils::thread_local_cache!(static COMPRESSOR: Compressor<'static>);
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

/// Decompress one zstd frame into an owned buffer of its declared content size.
///
/// Each thread reuses one zstd context across calls. The output is heap-owned because decoded
/// items may keep zero-copy views of it.
pub(super) fn decompress(compressed: &[u8]) -> Result<Vec<u8>, Error> {
    let size = get_frame_content_size(compressed)
        .ok()
        .flatten()
        .and_then(|size| usize::try_from(size).ok())
        .ok_or(Error::DecompressionFailed)?;
    let mut decompressed = Vec::with_capacity(size);
    let mut decompressor = Cached::take(&DECOMPRESSOR, Decompressor::new, |_| Ok(()))
        .map_err(|_| Error::DecompressionFailed)?;
    decompressor
        .decompress_to_buffer(compressed, &mut decompressed)
        .map_err(|_| Error::DecompressionFailed)?;
    Ok(decompressed)
}

/// Decode a frame's payload into an item, decompressing if needed.
pub(super) fn decode_item<V: Codec>(
    mut item_data: impl Buf,
    cfg: &V::Cfg,
    compressed: bool,
) -> Result<V, Error> {
    if compressed {
        // Bulk decompression reads the frame as one slice. Only a frame split across buffers
        // is copied first.
        let remaining = item_data.remaining();
        let decompressed = if item_data.chunk().len() == remaining {
            let decompressed = decompress(item_data.chunk());
            item_data.advance(remaining);
            decompressed?
        } else {
            decompress(&item_data.copy_to_bytes(remaining))?
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
            // Read the whole payload at once so it decompresses from one buffer.
            let data_offset = offset
                .checked_add(varint_len as u64)
                .ok_or(Error::OffsetOverflow)?;
            let data = reader.read_at(data_offset, total_len).await?;
            let decoded = decode_item::<V>(data, cfg, compressed)?;
            (total_len as u32, decoded)
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

/// An uncompressed item with its length prefix.
pub(super) struct UncompressedFrame<'a, V> {
    item: &'a V,
    item_len: u32,
}

impl<'a, V: EncodeSize> UncompressedFrame<'a, V> {
    /// Validate and size an item before any frame bytes are written.
    pub(super) fn new(item: &'a V) -> Result<Self, Error> {
        let item_len = item.encode_size();
        let item_len_u32 = item_len
            .try_into()
            .map_err(|_| Error::ItemTooLarge(item_len))?;
        UInt(item_len_u32)
            .encode_size()
            .checked_add(item_len)
            .ok_or(Error::OffsetOverflow)?;
        Ok(Self {
            item,
            item_len: item_len_u32,
        })
    }

    /// Return the payload length, excluding the size prefix.
    pub(super) const fn item_len(&self) -> u32 {
        self.item_len
    }
}

impl<V> EncodeSize for UncompressedFrame<'_, V> {
    fn encode_size(&self) -> usize {
        UInt(self.item_len).encode_size() + self.item_len as usize
    }
}

impl<V: Write> Write for UncompressedFrame<'_, V> {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.item_len).write(buf);
        self.item.write(buf);
    }
}

/// Compress an item's encoding into pooled backing with `reserve` writable bytes after it.
///
/// Both the encoding and the compressed payload use `pool`, and each thread reuses one zstd
/// context across calls.
pub(super) fn compress(
    pool: &BufferPool,
    level: u8,
    item: &(impl EncodeSize + Write),
    reserve: usize,
) -> Result<IoBufMut, Error> {
    // Bulk compression consumes one contiguous encoding and writes the payload into backing
    // sized for the worst case. Reusing the context avoids rebuilding its tables.
    let encoded = item.encode_with_pool_mut(pool);
    let capacity = compress_bound(encoded.len())
        .checked_add(reserve)
        .ok_or(Error::OffsetOverflow)?;
    let mut payload = Payload(pool.alloc(capacity));
    let mut compressor = Cached::take(
        &COMPRESSOR,
        || Compressor::new(level.into()),
        |compressor| compressor.set_compression_level(level.into()),
    )
    .map_err(|_| Error::CompressionFailed)?;
    compressor
        .compress_to_buffer(encoded.as_ref(), &mut payload)
        .map_err(|_| Error::CompressionFailed)?;
    Ok(payload.0)
}

/// Pooled compressor output that exposes only the prefix zstd reports as written.
struct Payload(IoBufMut);

// SAFETY: `as_mut_ptr` and `capacity` describe the unique allocation owned by the buffer, whose
// length starts at zero. `as_slice` exposes only initialized bytes, and `filled_until` publishes
// only the prefix the compressor reports as written.
unsafe impl WriteBuf for Payload {
    fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    fn capacity(&self) -> usize {
        self.0.capacity()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    unsafe fn filled_until(&mut self, n: usize) {
        // SAFETY: the caller guarantees the first `n` bytes were initialized.
        unsafe { self.0.set_len(n) };
    }
}

/// A zstd-compressed item with its length prefix.
pub(super) struct CompressedFrame {
    payload: IoBufMut,
    item_len: u32,
}

impl CompressedFrame {
    /// Compress an item and validate its frame size before any frame bytes are written.
    pub(super) fn new<V: Codec>(pool: &BufferPool, level: u8, item: &V) -> Result<Self, Error> {
        let payload = compress(pool, level, item, 0)?;
        let item_len = payload.len();
        let item_len_u32 = item_len
            .try_into()
            .map_err(|_| Error::ItemTooLarge(item_len))?;
        UInt(item_len_u32)
            .encode_size()
            .checked_add(item_len)
            .ok_or(Error::OffsetOverflow)?;
        Ok(Self {
            payload,
            item_len: item_len_u32,
        })
    }

    /// Return the compressed payload length, excluding the size prefix.
    pub(super) const fn item_len(&self) -> u32 {
        self.item_len
    }
}

impl EncodeSize for CompressedFrame {
    fn encode_size(&self) -> usize {
        UInt(self.item_len).encode_size() + self.item_len as usize
    }
}

impl Write for CompressedFrame {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.item_len).write(buf);
        buf.put_slice(self.payload.as_ref());
    }
}

/// Encode an item as a frame (length prefix plus payload), appending the bytes to `buf`.
///
/// Existing contents of `buf` are preserved; this allows callers to accumulate
/// multiple encoded items into a single buffer.
///
/// Returns the payload length, excluding the size prefix.
pub(super) fn encode_frame_into<V: Codec>(
    pool: &BufferPool,
    compression: Option<u8>,
    item: &V,
    buf: &mut Vec<u8>,
) -> Result<u32, Error> {
    match compression {
        Some(level) => {
            let frame = CompressedFrame::new(pool, level, item)?;
            append_frame(&frame, buf);
            Ok(frame.item_len())
        }
        None => {
            let frame = UncompressedFrame::new(item)?;
            append_frame(&frame, buf);
            Ok(frame.item_len())
        }
    }
}

/// Append a validated frame after any existing contents of `buf`.
fn append_frame(frame: &(impl EncodeSize + Write), buf: &mut Vec<u8>) {
    let initial_len = buf.len();
    buf.reserve(frame.encode_size());
    frame.write(buf);
    assert_eq!(
        buf.len() - initial_len,
        frame.encode_size(),
        "write() did not write expected bytes"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::codec::View;
    use bytes::{BufMut, Bytes};
    use commonware_codec::{Copying, Encode, Read, Write};
    use commonware_runtime::{
        BufferPoolConfig, BufferPooler as _, Metrics as _, Runner as _, deterministic,
        telemetry::metrics::{has_metric_value, metric_samples},
    };
    use commonware_utils::{NZU32, NZUsize};
    use std::cell::Cell;

    /// Frame a single item and return the raw frame bytes.
    fn frame<V: Codec>(pool: &BufferPool, compression: Option<u8>, item: &V) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_frame_into(pool, compression, item, &mut buf).unwrap();
        buf
    }

    #[test]
    fn test_roundtrip_uncompressed() {
        deterministic::Runner::default().start(|context| async move {
            let buf = frame(context.storage_buffer_pool(), None, &42u64);
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
        });
    }

    #[test]
    fn test_roundtrip_compressed() {
        deterministic::Runner::default().start(|context| async move {
            let buf = frame(context.storage_buffer_pool(), Some(3), &42u64);
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
        });
    }

    #[test]
    fn test_accumulation_preserves_existing_contents() {
        deterministic::Runner::default().start(|context| async move {
            let pool = context.storage_buffer_pool();
            let mut buf = Vec::new();
            encode_frame_into(pool, None, &1u64, &mut buf).unwrap();
            let first_frame_len = buf.len();
            encode_frame_into(pool, None, &2u64, &mut buf).unwrap();

            // Walk both frames out of the accumulated buffer.
            let mut cursor = Copying(&buf);
            let (first_end, _) = find_frame(&mut cursor, 0).unwrap();
            assert_eq!(first_end as usize, first_frame_len);
            let first: u64 = decode_item(Copying(&buf[1..9]), &(), false).unwrap();
            assert_eq!(first, 1);

            let mut cursor = Copying(&buf[first_frame_len..]);
            let (second_end, _) = find_frame(&mut cursor, first_end).unwrap();
            assert_eq!(second_end as usize, buf.len());
            let second: u64 =
                decode_item(Copying(&buf[first_frame_len + 1..]), &(), false).unwrap();
            assert_eq!(second, 2);
        });
    }

    #[test]
    fn test_compressed_frames_reuse_pool_backing() {
        let cfg = deterministic::Config::default().with_storage_buffer_pool_config(
            BufferPoolConfig::for_storage()
                .with_size_classes([(NZUsize!(8192), NZU32!(2))])
                .with_thread_cache_disabled(),
        );
        deterministic::Runner::new(cfg).start(|context| async move {
            let pool = context.storage_buffer_pool();
            let mut actual = vec![42];
            let mut expected = actual.clone();
            let mut append = |len, byte, level| {
                let item = Bytes::from(vec![byte; len]);
                let compressed = zstd::bulk::compress(&item.encode(), i32::from(level)).unwrap();
                let item_len = encode_frame_into(pool, Some(level), &item, &mut actual).unwrap();
                assert_eq!(item_len as usize, compressed.len());
                UInt(item_len).write(&mut expected);
                expected.extend_from_slice(&compressed);
                assert_eq!(actual, expected);
            };

            // Successive items reuse one input and one output slot. A short item after a long
            // one must compress only its initialized encoding, and earlier frames must stay
            // intact. The reused compressor must adopt each item's level.
            for (len, level) in [
                (0, 3),
                (1, 3),
                (127, 1),
                (128, 19),
                (4093, 3),
                (1, 0),
                (4093, 255),
            ] {
                append(len, 7, level);
            }

            let metrics = context.encode();
            assert!(
                has_metric_value(&metrics, "storage_buffer_pool_buffer_pool_created", 2),
                "successive frames must reuse one input and one output buffer: {metrics}"
            );
            assert!(
                has_metric_value(
                    &metrics,
                    "storage_buffer_pool_buffer_pool_oversized_total",
                    0
                ),
                "oversized requests bypass the pool and would hide allocations"
            );
            assert_eq!(
                metric_samples(&metrics, "storage_buffer_pool_buffer_pool_exhausted_total").count(),
                0,
                "exhausted classes fall back to untracked backing"
            );

            // Pool fallbacks must preserve the compressed format too. Holding both slots forces
            // exhaustion for the small item, and the large item exceeds the class.
            let held = (pool.alloc(8192), pool.alloc(8192));
            for len in [128, 16384] {
                append(len, 9, 3);
            }
            drop(held);
        });
    }

    #[test]
    fn test_uncompressed_frame_dynamic_sizes_and_prefix_thresholds() {
        struct Dynamic<'a> {
            bytes: &'a [u8],
            size_calls: Cell<usize>,
        }

        impl EncodeSize for Dynamic<'_> {
            fn encode_size(&self) -> usize {
                self.size_calls.set(self.size_calls.get() + 1);
                self.bytes.len()
            }
        }

        impl Write for Dynamic<'_> {
            fn write(&self, buf: &mut impl BufMut) {
                buf.put_slice(self.bytes);
            }
        }

        for len in [0, 127, 128, 16_383, 16_384] {
            let bytes = vec![7; len];
            let item = Dynamic {
                bytes: &bytes,
                size_calls: Cell::new(0),
            };
            let frame = UncompressedFrame::new(&item).unwrap();
            assert_eq!(item.size_calls.get(), 1);
            assert_eq!(frame.encode_size(), UInt(len as u32).encode_size() + len);

            let mut encoded = Vec::new();
            frame.write(&mut encoded);
            let mut expected = Vec::new();
            UInt(len as u32).write(&mut expected);
            expected.extend_from_slice(&bytes);
            assert_eq!(encoded, expected);
            assert_eq!(item.size_calls.get(), 1);
        }
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
        deterministic::Runner::default().start(|context| async move {
            let buf = frame(context.storage_buffer_pool(), None, &42u64);
            let mut cursor = Copying(&buf);
            assert!(matches!(
                find_frame(&mut cursor, u64::MAX),
                Err(Error::OffsetOverflow)
            ));
        });
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
        deterministic::Runner::default().start(|context| async move {
            let mut buf = frame(context.storage_buffer_pool(), Some(3), &42u64);

            // Corrupt the zstd magic number (first payload byte, after the 1-byte varint).
            buf[1] ^= 0xFF;
            assert!(matches!(
                decode_item::<u64>(Copying(&buf[1..]), &(), true),
                Err(Error::DecompressionFailed)
            ));
        });
    }

    #[test]
    fn test_decode_item_decompresses_split_payloads_and_consumes_exactly() {
        let cfg = ((..).into(), ());
        for (len, level) in [(0usize, 3), (1, 1), (4096, 19), (70_000, 3)] {
            let item: Vec<u8> = (0..len).map(|i| (i % 7) as u8).collect();
            let payload = zstd::bulk::compress(&item.encode(), level).unwrap();

            // One contiguous buffer decompresses in place, and the read consumes exactly the
            // payload, leaving what follows it for the next frame.
            let mut source = Bytes::from([payload.as_slice(), &[9, 9]].concat());
            let decoded =
                decode_item::<Vec<u8>>((&mut source).take(payload.len()), &cfg, true).unwrap();
            assert_eq!(decoded, item);
            assert_eq!(source.as_ref(), &[9, 9]);

            // A payload split across buffers decodes to the same item.
            let (head, tail) = payload.split_at(payload.len().min(3));
            let split = Bytes::copy_from_slice(head).chain(Bytes::copy_from_slice(tail));
            assert_eq!(decode_item::<Vec<u8>>(split, &cfg, true).unwrap(), item);
        }
    }

    #[test]
    fn test_decompress_rejects_frames_without_content_size() {
        // Every frame this crate writes declares its content size. A streamed frame that
        // omits it is rejected rather than decoded with an unbounded buffer.
        let encoded = 42u64.encode();
        let streamed = zstd::stream::encode_all(encoded.as_ref(), 3).unwrap();
        assert!(matches!(
            decompress(&streamed),
            Err(Error::DecompressionFailed)
        ));
        let sized = zstd::bulk::compress(&encoded, 3).unwrap();
        assert_eq!(decompress(&sized).unwrap(), encoded.as_ref());
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
    fn test_payload_publishes_only_written_prefix() {
        deterministic::Runner::default().start(|context| async move {
            let mut payload = Payload(context.storage_buffer_pool().alloc(64));
            let capacity = WriteBuf::capacity(&payload);
            assert!(capacity >= 64);
            assert!(payload.as_slice().is_empty());

            // A failed write publishes nothing.
            // SAFETY: the closure writes nothing and reports no initialized bytes.
            let failed = unsafe { payload.write_from(|_, _| Err(1)) };
            assert_eq!(failed, Err(1));
            assert!(payload.as_slice().is_empty());

            // A successful write publishes only the prefix it reports, even with room for more.
            // SAFETY: the closure initializes five bytes within the provided capacity.
            let written = unsafe {
                payload.write_from(|ptr, available| {
                    assert_eq!(available, capacity);
                    std::ptr::write_bytes(ptr.cast::<u8>(), 7, 5);
                    Ok(5)
                })
            };
            assert_eq!(written, Ok(5));
            assert_eq!(payload.as_slice(), &[7; 5]);
        });
    }

    #[test]
    fn test_encode_frame_rejects_oversized_item() {
        deterministic::Runner::default().start(|context| async move {
            let mut buf = Vec::new();
            assert!(matches!(
                encode_frame_into(context.storage_buffer_pool(), None, &Oversized, &mut buf),
                Err(Error::ItemTooLarge(_))
            ));
            assert!(buf.is_empty());
        });
    }
}
