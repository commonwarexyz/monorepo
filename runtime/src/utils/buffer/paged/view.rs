//! Shared view for the paged buffer's read-capable types.
//!
//! [`Writer`](super::Writer) and [`Sealed`](super::Sealed) read the same way: logical bytes in
//! `[tail_offset, size)` come from an in-memory tail slice (the writer's tip buffer or the sealed
//! blob's partial last page), and bytes in `[0, tail_offset)` come from the page cache, falling back
//! to a blob read. Each type exposes itself as a borrowed [`View`] so this algorithm lives in
//! exactly one place.

use super::{cache::CachedDecode, CacheRef};
use crate::{Blob, Error, IoBufMut, IoBufs};
use commonware_codec::Read as CodecRead;
use futures::stream::{FuturesUnordered, StreamExt};
use std::num::NonZeroUsize;

/// A borrowed view over a paged blob.
pub struct View<'a, B: Blob> {
    /// Underlying blob, used for bytes below `tail_offset` not resident in the cache.
    pub(super) blob: &'a B,
    /// Page cache used for bytes below `tail_offset`.
    pub(super) cache_ref: &'a CacheRef,
    /// Page-cache id of the originating blob.
    pub(super) id: u64,
    /// Size of the blob, in bytes.
    pub(super) size: u64,
    /// Offset at which the in-memory `tail` bytes begin.
    pub(super) tail_offset: u64,
    /// Logical bytes at `[tail_offset, size)`. May be empty.
    pub(super) tail: &'a [u8],
}

impl<B: Blob> Clone for View<'_, B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<B: Blob> Copy for View<'_, B> {}

impl<B: Blob> View<'_, B> {
    /// Copy any in-memory tail overlap into `buf`, returning the remaining prefix length.
    fn copy_tail_overlap(&self, buf: &mut [u8], offset: u64) -> usize {
        let tail_start = self.tail_offset.max(offset);
        let prefix_len = (tail_start - offset) as usize;
        let tail_offset = (tail_start - self.tail_offset) as usize;
        let tail_len = buf.len() - prefix_len;
        let (_, tail_buf) = buf.split_at_mut(prefix_len);
        tail_buf.copy_from_slice(&self.tail[tail_offset..tail_offset + tail_len]);
        prefix_len
    }

    /// Read into `buf` if it can be done synchronously without I/O. Returns `true` only if all
    /// `buf.len()` bytes were satisfied from the page cache and/or the in-memory tail. When `false`
    /// is returned, the contents of `buf` are unspecified.
    pub fn try_read_sync_into(&self, buf: &mut [u8], offset: u64) -> bool {
        let Some(end_offset) = offset.checked_add(buf.len() as u64) else {
            return false;
        };
        if end_offset > self.size {
            return false;
        }
        if buf.is_empty() {
            return true;
        }

        if end_offset <= self.tail_offset {
            return self.cache_ref.read_cached(self.id, buf, offset) == buf.len();
        }

        // Copy the suffix overlapping the tail, then serve any prefix below `tail_offset` from the
        // cache.
        let dst_start = self.copy_tail_overlap(buf, offset);

        if dst_start == 0 {
            return true;
        }

        self.cache_ref
            .read_cached(self.id, &mut buf[..dst_start], offset)
            == dst_start
    }

    /// Reads bytes starting at `offset` into `buf`.
    pub async fn read_into(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        let end_offset = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        if end_offset > self.size {
            return Err(Error::BlobInsufficientLength);
        }

        // Copy any suffix from the in-memory tail, leaving the prefix below `tail_offset` to be
        // served from the page cache or blob.
        let remaining = if end_offset <= self.tail_offset {
            buf.len()
        } else {
            self.copy_tail_overlap(buf, offset)
        };

        if remaining == 0 {
            return Ok(());
        }

        let cached = self
            .cache_ref
            .read_cached(self.id, &mut buf[..remaining], offset);
        if cached == remaining {
            return Ok(());
        }

        let uncached_offset = offset + cached as u64;
        let uncached_len = remaining - cached;
        self.cache_ref
            .read(
                self.blob,
                self.id,
                &mut buf[cached..cached + uncached_len],
                uncached_offset,
            )
            .await
    }

    /// Read exactly `len` immutable bytes starting at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        // SAFETY: read_into below initializes all `len` bytes.
        let mut buf = unsafe { self.cache_ref.pool().alloc_len(len) };
        self.read_into(buf.as_mut(), offset).await?;
        Ok(buf.into())
    }

    /// Reads up to `len` bytes starting at `offset`, but only as many as are available.
    ///
    /// Returns the buffer (truncated to actual bytes read) and the number of bytes read. Returns an
    /// error if no bytes are available at the given offset.
    pub async fn read_up_to(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufMut> + Send,
    ) -> Result<(IoBufMut, usize), Error> {
        let mut bufs = bufs.into();
        if len == 0 {
            bufs.truncate(0);
            return Ok((bufs, 0));
        }
        let available = (self.size.saturating_sub(offset) as usize).min(len);
        if available == 0 {
            return Err(Error::BlobInsufficientLength);
        }
        // SAFETY: read_into below fills all `available` bytes.
        unsafe { bufs.set_len(available) };
        self.read_into(bufs.as_mut(), offset).await?;
        Ok((bufs, available))
    }

    /// Read multiple fixed-size items at sorted byte offsets into a contiguous caller buffer.
    ///
    /// `buf` must be exactly `offsets.len() * item_size` bytes. All offsets must be sorted,
    /// non-overlapping, and within bounds.
    ///
    /// Returns the number of items fully served without a blob read (from the in-memory tail and the
    /// page cache). The remaining items required at least one blob read.
    pub async fn read_many_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Result<usize, Error> {
        let ranges = || offsets.iter().map(|&o| (o, item_size.get()));
        super::validate_read_ranges(buf.len(), ranges(), self.size)?;
        if offsets.is_empty() {
            return Ok(0);
        }

        let mut cache_ranges = super::split_read_ranges(buf, ranges(), self.tail_offset, self.tail);

        // Fast path: try the page cache for all ranges in a single lock acquisition.
        self.cache_ref.read_cached_many(self.id, &mut cache_ranges);
        let blob_reads = cache_ranges.len();
        if cache_ranges.is_empty() {
            return Ok(offsets.len());
        }

        // Slow path: read remaining ranges from the underlying blob, concurrently.
        let mut reads = cache_ranges
            .iter_mut()
            .map(|(item_buf, offset)| self.cache_ref.read(self.blob, self.id, item_buf, *offset))
            .collect::<FuturesUnordered<_>>();
        while let Some(result) = reads.next().await {
            result?;
        }

        Ok(offsets.len() - blob_reads)
    }

    /// Like [`Self::read_many_into`], but synchronous and cache-only, for variable-length
    /// ranges: `buf` holds one slot per `(offset, len)` range, back to back. Returns the
    /// indices of ranges that require a blob read, which is every index when the ranges extend
    /// past the blob. Their slots hold unspecified bytes.
    pub fn try_read_ranges_sync_into(&self, buf: &mut [u8], ranges: &[(u64, usize)]) -> Vec<usize> {
        if super::validate_read_ranges(buf.len(), ranges.iter().copied(), self.size).is_err() {
            return (0..ranges.len()).collect();
        }
        if ranges.is_empty() {
            return Vec::new();
        }

        let mut cache_ranges =
            super::split_read_ranges(buf, ranges.iter().copied(), self.tail_offset, self.tail);
        if cache_ranges.is_empty() {
            return Vec::new();
        }
        self.cache_ref.read_cached_many(self.id, &mut cache_ranges);
        map_misses(cache_ranges, |idx| ranges[idx])
    }

    /// Decode a `T` from the bytes starting at `offset`, letting the decoder consume up to
    /// `max_len` bytes, without performing I/O. Returns the decoded value and the number of bytes
    /// consumed.
    ///
    /// Returns `None` when the required bytes are not synchronously available (page-cache
    /// miss), and the caller must fall back to an async read. Returns `Some(Err(_))` only when
    /// the bytes were fully available and are malformed.
    ///
    /// The decode runs under the page-cache read lock and must be parse-only: `T::read_cfg`
    /// implementations used here must not block or perform expensive work such as decompression.
    ///
    /// `T`'s decoding must be driven solely by the bytes it consumes (fixed-size or
    /// length-prefixed encodings). The decoder is handed the resident prefix of the requested
    /// range, which may be shorter than `max_len` (it can stop at a page boundary, a
    /// non-resident page, or an internal gathering cap), and a success over that prefix is
    /// returned as authoritative. A decoder whose result depends on `remaining()` (one that
    /// greedily consumes everything available, like `commonware_codec::types::Lazy`) would
    /// observe an arbitrary residency-dependent window and silently diverge from the async
    /// read. Use [Self::try_decode_sync] for such types instead, which only succeeds when the
    /// decoder sees exactly `len` bytes.
    #[inline]
    pub fn try_decode_prefix_sync<T: CodecRead>(
        &self,
        offset: u64,
        max_len: usize,
        cfg: &T::Cfg,
    ) -> Option<Result<(T, usize), commonware_codec::Error>> {
        if max_len == 0 || offset >= self.size {
            return None;
        }
        if offset >= self.tail_offset {
            // The requested range starts in the in-memory tail, so the resident window is the
            // tail clamped to the logical size.
            let start = (offset - self.tail_offset) as usize;
            let end = self.tail.len().min(start.saturating_add(max_len));
            let total = end - start;
            let mut buf = &self.tail[start..end];
            return match T::read_cfg(&mut buf, cfg) {
                Ok(value) => Some(Ok((value, total - buf.len()))),
                // The decoder saw the whole requested window, so the failure is authoritative
                // (mirroring the cache fast path).
                Err(err) if total == max_len => Some(Err(err)),
                // A window clamped by the logical size may have starved the decoder, so let
                // the async path produce the authoritative result.
                Err(_) => None,
            };
        }
        // The range starts below the tail: its window is the cached bytes up to the tail
        // boundary followed by the in-memory tail bytes, clamped to `max_len` and the logical
        // size.
        let window = ((self.size - offset).min(max_len as u64)) as usize;
        let cached_len = ((self.tail_offset - offset).min(window as u64)) as usize;
        let tail = &self.tail[..window - cached_len];
        match self
            .cache_ref
            .decode_cached_prefix::<T>(self.id, offset, cached_len, tail, max_len, cfg)
        {
            CachedDecode::Decoded(value, consumed) => Some(Ok((value, consumed))),
            CachedDecode::Invalid(err) => Some(Err(err)),
            CachedDecode::Missing => None,
        }
    }

    /// Like [Self::try_decode_prefix_sync] but requires the encoding to occupy exactly `len`
    /// bytes. Under-consumption is reported as an error, matching the
    /// `commonware_codec::Decode::decode_cfg` semantics.
    #[inline]
    pub fn try_decode_sync<T: CodecRead>(
        &self,
        offset: u64,
        len: usize,
        cfg: &T::Cfg,
    ) -> Option<Result<T, commonware_codec::Error>> {
        let end = offset.checked_add(len as u64)?;
        if len == 0 || end > self.size {
            // Zero-length and out-of-bounds requests are left for the async path to report.
            return None;
        }
        if offset >= self.tail_offset {
            return Self::decode_slice_exact(
                &self.tail[(offset - self.tail_offset) as usize..],
                len,
                cfg,
            );
        }
        // A range ending at or below the tail boundary is served purely from cached pages;
        // one that crosses it also hands the decoder the overlapping tail bytes.
        let cached_len = ((self.tail_offset - offset).min(len as u64)) as usize;
        let tail = &self.tail[..len - cached_len];
        match self
            .cache_ref
            .decode_cached_exact::<T>(self.id, offset, cached_len, tail, cfg)
        {
            CachedDecode::Decoded(value, _) => Some(Ok(value)),
            CachedDecode::Invalid(err) => Some(Err(err)),
            CachedDecode::Missing => None,
        }
    }

    /// Decode multiple items of exactly `len` bytes each at sorted, non-overlapping offsets
    /// without performing I/O. For each offset, pushes `Some(item)` on success or `None` when
    /// the item's bytes are not synchronously available. Returns an error only when resident
    /// bytes are malformed (corruption). In that case `out` may contain fewer than
    /// `offsets.len()` new entries and must be discarded.
    ///
    /// Amortizes lock acquisition: the page-cache read lock is taken once per internal chunk of
    /// offsets rather than once per item, and tail-resident items need no lock at all.
    pub fn try_decode_sync_many<T: CodecRead>(
        &self,
        offsets: &[u64],
        len: usize,
        cfg: &T::Cfg,
        out: &mut Vec<Option<T>>,
    ) -> Result<(), commonware_codec::Error> {
        assert!(
            offsets
                .windows(2)
                .all(|w| w[0].checked_add(len as u64).is_some_and(|end| end <= w[1])),
            "offsets must be sorted and non-overlapping"
        );
        if len == 0 {
            out.resize_with(out.len() + offsets.len(), || None);
            return Ok(());
        }

        // Offsets are sorted, so the items entirely below the tail form a prefix. Decode those
        // from the page cache in one batched pass.
        let cached = offsets.partition_point(|&offset| {
            offset
                .checked_add(len as u64)
                .is_some_and(|end| end <= self.tail_offset)
        });
        self.cache_ref
            .decode_cached_exact_many::<T>(self.id, &offsets[..cached], len, cfg, out)?;

        // The remainder is tail-resident, boundary-straddling (at most one item), or out of
        // bounds. The single-item path serves each case.
        for &offset in &offsets[cached..] {
            match self.try_decode_sync::<T>(offset, len, cfg) {
                Some(Ok(value)) => out.push(Some(value)),
                // The result is authoritative (all `len` bytes were resident), matching the
                // single-item path.
                Some(Err(err)) => return Err(err),
                None => out.push(None),
            }
        }
        Ok(())
    }

    /// Decode a `T` occupying exactly the first `len` bytes of `slice`.
    ///
    /// Both error outcomes are authoritative: all `len` bytes are resident committed bytes, so
    /// the async path would decode the same bytes to the same result.
    #[inline]
    fn decode_slice_exact<T: CodecRead>(
        slice: &[u8],
        len: usize,
        cfg: &T::Cfg,
    ) -> Option<Result<T, commonware_codec::Error>> {
        let mut buf = &slice[..len];
        match T::read_cfg(&mut buf, cfg) {
            // Under-consumption means the encoding does not occupy exactly `len` bytes.
            // Report the same error as `Decode::decode_cfg`.
            Ok(value) if buf.is_empty() => Some(Ok(value)),
            Ok(_) => Some(Err(commonware_codec::Error::ExtraData(buf.len()))),
            Err(err) => Some(Err(err)),
        }
    }
}

/// Map missed cache reads back to their originating slot indices: each missed read starts at
/// its slot's `(offset, len)` range, and both lists are sorted. Zero-length slots never miss
/// but may share an offset with the slot that follows them, so they are skipped.
fn map_misses(
    missed: Vec<(&mut [u8], u64)>,
    mut slot: impl FnMut(usize) -> (u64, usize),
) -> Vec<usize> {
    let mut misses = Vec::with_capacity(missed.len());
    let mut idx = 0;
    for (_, offset) in missed {
        loop {
            let (slot_offset, slot_len) = slot(idx);
            if slot_len != 0 && slot_offset == offset {
                break;
            }
            idx += 1;
        }
        misses.push(idx);
        idx += 1;
    }
    misses
}

#[cfg(test)]
mod tests {
    use crate::{buffer::paged::Writer, deterministic, Runner as _, Storage as _};
    use commonware_utils::{NZUsize, NZU16};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(103);
    const BUFFER_SIZE: usize = PAGE_SIZE.get() as usize * 2;

    /// A read straddling the persisted prefix and the in-memory tail is served synchronously once
    /// the prefix page is cached (the unified `View` serves the prefix from the cache and the
    /// suffix from the tail in one call).
    #[test]
    fn test_view_try_read_sync_straddles_cache_and_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref =
                super::CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let (blob, blob_size) = context
                .open("test_partition", b"view_straddle")
                .await
                .unwrap();
            let mut writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // A full page (flushed to the blob) followed by a partial tail kept in the tip buffer.
            let page_size = PAGE_SIZE.get() as usize;
            writer.append(&vec![0xAA; page_size]).await.unwrap();
            writer.append(b"TAIL").await.unwrap();
            writer.sync().await.unwrap();

            // Warm the cache for the first page, then read across the page/tail boundary.
            writer.read_at(0, page_size).await.unwrap();
            let mut buf = [0u8; 4];
            assert!(writer.try_read_sync_into(&mut buf, page_size as u64 - 2));
            assert_eq!(&buf, &[0xAA, 0xAA, b'T', b'A']);
        });
    }
}
