//! Shared view for the paged buffer's read-capable types.
//!
//! [`Writer`](super::Writer) and [`Sealed`](super::Sealed) read the same way: logical bytes in
//! `[tail_offset, size)` come from in-memory tail chunks (the writer's tip buffer or the sealed
//! blob's partial last page), and bytes in `[0, tail_offset)` come from the page cache, falling
//! back to a blob read. Each type exposes itself as a borrowed [`View`] so this algorithm lives in
//! exactly one place.

use super::{CacheRef, tip::Buffer};
use crate::{Blob, Error, IoBufMut, IoBufs};
use commonware_utils::Widen;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{num::NonZeroUsize, sync::Arc};

/// Logical bytes served from memory at the end of a paged blob.
#[derive(Clone, Copy)]
pub(super) enum Tail<'a> {
    /// Chunks retained by the writer's tip buffer.
    Buffered(&'a Buffer),
    /// A copied partial page owned by an immutable reader.
    Sealed(&'a [u8]),
}

impl<'a> Tail<'a> {
    /// Copy an in-bounds range relative to the start of the tail.
    fn copy_into(self, mut offset: usize, dst: &mut [u8]) {
        let tail = match self {
            Self::Sealed(tail) => tail,
            Self::Buffered(buffer) => {
                let (_, tail) = buffer.parts();
                let prefix_len = buffer.len() - tail.len();
                if offset < prefix_len {
                    self.cursor().copy_into(offset, dst);
                    return;
                }
                offset -= prefix_len;
                tail
            }
        };
        dst.copy_from_slice(&tail[offset..offset + dst.len()]);
    }

    fn cursor(self) -> Cursor<'a, impl Iterator<Item = &'a [u8]>> {
        let (prefix, tail) = match self {
            Self::Buffered(buffer) => {
                let (prefix, tail) = buffer.parts();
                (Some(prefix), tail)
            }
            Self::Sealed(tail) => (None, tail),
        };

        // An empty initial chunk lets the cursor enter either representation with the same
        // forward walk, including when the buffered prefix is empty.
        Cursor {
            chunks: prefix
                .into_iter()
                .flat_map(|bufs| bufs.iter().map(AsRef::as_ref))
                .chain(std::iter::once(tail)),
            chunk: &[],
            position: 0,
        }
    }
}

/// A forward cursor keeps sorted range reads linear in the number of buffered chunks and ranges.
struct Cursor<'a, I> {
    /// Chunks not yet entered.
    chunks: I,
    /// Unread suffix of the current chunk.
    chunk: &'a [u8],
    /// End of the last completed range, relative to the tail.
    position: usize,
}

impl<'a, I: Iterator<Item = &'a [u8]>> Cursor<'a, I> {
    /// Copy a range at or beyond the previous range's end and advance past it.
    ///
    /// The range must fit within the tail. Empty destinations do not advance the cursor.
    fn copy_into(&mut self, offset: usize, mut dst: &mut [u8]) {
        if dst.is_empty() {
            return;
        }
        let mut skip = offset
            .checked_sub(self.position)
            .expect("tail reads must be sorted");
        while skip >= self.chunk.len() {
            skip -= self.chunk.len();
            self.chunk = self.chunks.next().expect("tail read out of bounds");
        }
        self.chunk = &self.chunk[skip..];
        self.position = offset + dst.len();
        while !dst.is_empty() {
            if self.chunk.is_empty() {
                self.chunk = self.chunks.next().expect("tail read out of bounds");
                continue;
            }
            let len = self.chunk.len().min(dst.len());
            dst[..len].copy_from_slice(&self.chunk[..len]);
            dst = &mut dst[len..];
            self.chunk = &self.chunk[len..];
        }
    }
}

/// A borrowed view over a paged blob.
pub struct View<'a, B: Blob> {
    /// Underlying blob, used for bytes below `tail_offset` not resident in the cache.
    pub(super) blob: &'a Arc<B>,
    /// Page cache used for bytes below `tail_offset`.
    pub(super) cache_ref: &'a CacheRef,
    /// Page-cache id of the originating blob.
    pub(super) id: u64,
    /// Size of the blob, in bytes.
    pub(super) size: u64,
    /// Offset at which the in-memory `tail` bytes begin.
    pub(super) tail_offset: u64,
    /// Logical bytes at `[tail_offset, size)`. May be empty.
    pub(super) tail: Tail<'a>,
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
        let (_, tail_buf) = buf.split_at_mut(prefix_len);
        self.tail.copy_into(tail_offset, tail_buf);
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
            .read_after_miss(
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
        let available = self.size.saturating_sub(offset).min(Widen::widen(len)) as usize;
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
    /// Returns the number of items fully served without a blob read (from the in-memory tail and
    /// the page cache). The remaining items required at least one blob read.
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

        let mut cache_ranges = split_read_ranges(buf, ranges(), self.tail_offset, self.tail);

        // Fast path: try the page cache for all ranges in a single lock acquisition.
        self.cache_ref.read_cached_many(self.id, &mut cache_ranges);
        let blob_reads = cache_ranges.len();
        if cache_ranges.is_empty() {
            return Ok(offsets.len());
        }

        // Slow path: read remaining ranges from the underlying blob, concurrently.
        let mut reads = cache_ranges
            .iter_mut()
            .map(|(item_buf, offset)| {
                self.cache_ref
                    .read_after_miss(self.blob, self.id, item_buf, *offset)
            })
            .collect::<FuturesUnordered<_>>();
        while let Some(result) = reads.next().await {
            result?;
        }

        Ok(offsets.len() - blob_reads)
    }

    /// Like [`Self::read_many_into`], but synchronous and cache-only.
    ///
    /// Items fully served from the in-memory tail and page cache are written to their slots in
    /// `buf`. Returns the indices of items that require a blob read, which is every index when
    /// the offsets extend past the blob. Those slots hold unspecified bytes.
    pub fn try_read_many_sync_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Vec<usize> {
        let ranges = || offsets.iter().map(|&o| (o, item_size.get()));
        if super::validate_read_ranges(buf.len(), ranges(), self.size).is_err() {
            return (0..offsets.len()).collect();
        }
        if offsets.is_empty() {
            return Vec::new();
        }

        let mut cache_ranges = split_read_ranges(buf, ranges(), self.tail_offset, self.tail);
        if cache_ranges.is_empty() {
            return Vec::new();
        }
        self.cache_ref.read_cached_many(self.id, &mut cache_ranges);
        map_misses(cache_ranges, |idx| (offsets[idx], item_size.get()))
    }

    /// Like [`Self::try_read_many_sync_into`], but for variable-length ranges: `buf` holds one
    /// slot per `(offset, len)` range, back to back. Returns the indices of ranges that require
    /// a blob read, which is every index when the ranges extend past the blob. Their slots hold
    /// unspecified bytes.
    pub fn try_read_ranges_sync_into(&self, buf: &mut [u8], ranges: &[(u64, usize)]) -> Vec<usize> {
        if super::validate_read_ranges(buf.len(), ranges.iter().copied(), self.size).is_err() {
            return (0..ranges.len()).collect();
        }
        if ranges.is_empty() {
            return Vec::new();
        }

        let mut cache_ranges =
            split_read_ranges(buf, ranges.iter().copied(), self.tail_offset, self.tail);
        if cache_ranges.is_empty() {
            return Vec::new();
        }
        self.cache_ref.read_cached_many(self.id, &mut cache_ranges);
        map_misses(cache_ranges, |idx| ranges[idx])
    }
}

/// Partition a batch of variable-length range reads into bytes copied from the in-memory tail
/// and ranges that need cache/blob reads.
///
/// Ranges must be sorted and non-overlapping. `buf` holds one slot per range, back to back.
/// [super::validate_read_ranges] checks these preconditions and bounds every range by the
/// blob size.
///
/// `tail` holds the logical bytes starting at `tail_offset`: the writer's tip buffer or the sealed
/// blob's partial last page. Tail overlaps are copied into place. Prefixes below `tail_offset` are
/// returned as `(dest_slice, offset)` pairs for cache/blob reads. `split_at_mut` gives each range a
/// disjoint output slot, so returned slices never alias.
fn split_read_ranges<'a>(
    mut buf: &'a mut [u8],
    ranges: impl ExactSizeIterator<Item = (u64, usize)>,
    tail_offset: u64,
    tail: Tail<'_>,
) -> Vec<(&'a mut [u8], u64)> {
    let mut cache_ranges = Vec::with_capacity(ranges.len());
    let mut cursor = tail.cursor();
    for (offset, len) in ranges {
        let (slot, rest) = buf.split_at_mut(len);
        buf = rest;
        if len == 0 {
            continue;
        }
        let end = offset + len as u64;
        if end <= tail_offset {
            // Entirely below the tail bytes, so this needs a cache/blob read.
            cache_ranges.push((slot, offset));
        } else if offset >= tail_offset {
            // Entirely within the tail bytes.
            let src = (offset - tail_offset) as usize;
            cursor.copy_into(src, slot);
        } else {
            // Straddles the boundary: copy the suffix from the tail bytes, record the prefix
            // for a cache/blob read.
            let prefix_len = (tail_offset - offset) as usize;
            let (prefix, suffix) = slot.split_at_mut(prefix_len);
            cursor.copy_into(0, suffix);
            cache_ranges.push((prefix, offset));
        }
    }
    cache_ranges
}

/// Map unread suffixes back to their originating slot indices. Each suffix starts inside its
/// slot's `(offset, len)` range, and both lists are sorted. Zero-length slots never miss but may
/// share an offset with the slot that follows them, so they are skipped.
fn map_misses(
    missed: Vec<(&mut [u8], u64)>,
    mut slot: impl FnMut(usize) -> (u64, usize),
) -> Vec<usize> {
    let mut misses = Vec::with_capacity(missed.len());
    let mut idx = 0;
    for (_, offset) in missed {
        loop {
            let (slot_offset, slot_len) = slot(idx);
            if offset >= slot_offset && offset - slot_offset < slot_len as u64 {
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
    use super::map_misses;
    use crate::{
        BufferPool, BufferPoolConfig, Runner as _, Storage as _, buffer::paged::Writer,
        deterministic, telemetry::metrics::Registry,
    };
    use commonware_utils::{NZU16, NZU32, NZUsize};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(103);
    const BUFFER_SIZE: usize = PAGE_SIZE.get() as usize * 2;

    #[test]
    fn test_reads_cross_buffer_chunks_and_cache() {
        deterministic::Runner::default().start(|context| async move {
            let pool = BufferPool::new(
                BufferPoolConfig::for_storage()
                    .with_size_classes([(NZUsize!(8), NZU32!(1))])
                    .with_alignment(NZUsize!(1))
                    .with_pool_min_size(0),
                &mut Registry::default(),
            );
            let cache = super::CacheRef::new(pool, PAGE_SIZE, NZUsize!(4));
            let (blob, size) = context
                .open("test_partition", b"chunk_reads")
                .await
                .unwrap();
            let page = PAGE_SIZE.get() as usize;
            let mut writer = Writer::new(blob, size, page * 32, cache.clone())
                .await
                .unwrap();
            let data: Vec<_> = (0..page * 20 + 13).map(|i| (i % 251) as u8).collect();
            let persisted = page * 3 + 17;
            writer.append(&data[..persisted]).await.unwrap();
            writer.sync().await.unwrap();
            for chunk in data[persisted..].chunks(97) {
                writer.append(chunk).await.unwrap();
            }

            let mut all = vec![0; data.len()];
            assert!(writer.try_read_sync_into(&mut all, 0));
            assert_eq!(all, data);

            let offsets = [
                page - 8,
                page * 3 - 8,
                page * 4 - 8,
                page * 8 - 8,
                page * 16 - 8,
            ]
            .map(|offset| offset as u64);
            let expected: Vec<_> = offsets
                .iter()
                .flat_map(|&offset| data[offset as usize..offset as usize + 17].iter().copied())
                .collect();
            let mut batch = vec![0; expected.len()];
            assert!(
                writer
                    .try_read_many_sync_into(&mut batch, &offsets, NZUsize!(17))
                    .is_empty()
            );
            assert_eq!(batch, expected);

            let ranges = [
                (0, 0),
                ((page - 4) as u64, 16),
                ((page * 3 - 4) as u64, 15),
                ((page * 8 - 6) as u64, 19),
                ((data.len() - 13) as u64, 13),
                (data.len() as u64, 0),
            ];
            let expected_ranges: Vec<_> = ranges
                .iter()
                .flat_map(|&(offset, len)| {
                    data[offset as usize..offset as usize + len].iter().copied()
                })
                .collect();
            let mut ranged = vec![0; expected_ranges.len()];
            assert!(
                writer
                    .try_read_ranges_sync_into(&mut ranged, &ranges)
                    .is_empty()
            );
            assert_eq!(ranged, expected_ranges);

            cache.clear();
            writer
                .read_many_into(&mut batch, &offsets, NZUsize!(17))
                .await
                .unwrap();
            assert_eq!(batch, expected);
            assert_eq!(
                writer
                    .read_at(0, data.len())
                    .await
                    .unwrap()
                    .coalesce()
                    .as_ref(),
                data
            );
            writer.sync().await.unwrap();
            drop(writer);
            cache.clear();
            let (blob, size) = context
                .open("test_partition", b"chunk_reads")
                .await
                .unwrap();
            let writer = Writer::new(blob, size, page * 32, cache).await.unwrap();
            assert_eq!(
                writer
                    .read_at(0, data.len())
                    .await
                    .unwrap()
                    .coalesce()
                    .as_ref(),
                data
            );
        });
    }

    #[test]
    fn test_map_misses_with_cached_prefixes() {
        let slots = [
            (0, 4),
            (10, 0),
            (10, 8),
            (18, 0),
            (18, 5),
            (u64::MAX - 4, 4),
        ];
        let mut suffix_a = [0; 2];
        let mut suffix_b = [0; 5];
        let mut suffix_c = [0; 1];
        let missed = vec![
            (suffix_a.as_mut_slice(), 16),
            (suffix_b.as_mut_slice(), 18),
            (suffix_c.as_mut_slice(), u64::MAX - 1),
        ];
        assert_eq!(map_misses(missed, |idx| slots[idx]), vec![2, 4, 5]);
    }

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
