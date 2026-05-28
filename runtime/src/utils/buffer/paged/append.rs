//! The [Append] wrapper consists of a [Blob] and a write buffer, and provides a logical view over
//! the underlying blob which has a page-oriented structure that provides integrity guarantees. The
//! wrapper also provides read caching managed by a page cache.
//!
//! # Recovery
//!
//! On `sync`, this wrapper will durably write buffered data to the underlying blob in pages. All
//! pages have a [Checksum] at the end. If no CRC record existed before for the page being written,
//! then one of the checksums will be all zero. If a checksum already existed for the page being
//! written, then the write will overwrite only the checksum with the lesser length value. Should
//! this write fail, the previously committed page state can still be recovered. Partial-page
//! shrink makes the shorter checksum durable before invalidating the old longer checksum.
//!
//! During initialization, the wrapper will back up over any page that is not accompanied by a
//! valid CRC, treating it as the result of an incomplete write that may be invalid.
//!
//! # Blob Semantics
//!
//! [Append] owns the physical page layout, read cache, and durability bookkeeping for the wrapped
//! [Blob]. Raw [Blob] handles must not be used to write, resize, or otherwise mutate the blob while
//! an [Append] exists. Those mutations bypass the buffer and page cache, can invalidate checksum
//! recovery, and are not covered by [Append]'s [`Blob::write_at_sync`] fast paths.

use super::{
    read::{PageReader, Replay},
    read_and_trim,
};
use crate::{
    buffer::{
        paged::{CacheRef, Checksum, CHECKSUM_SIZE, CHECKSUM_SLOT_SIZE},
        tip::Buffer,
    },
    Blob, Error, IoBufMut, IoBufs,
};
use bytes::BufMut;
use commonware_cryptography::Crc32;
use commonware_utils::sync::{AsyncRwLock, AsyncRwLockWriteGuard};
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    num::{NonZeroU16, NonZeroUsize},
    sync::Arc,
};
use tracing::warn;

/// Indicates which CRC slot in a page record must not be overwritten.
#[derive(Clone, Copy)]
enum ProtectedCrc {
    First,
    Second,
}

/// Describes the state of the underlying blob with respect to the buffer.
#[derive(Clone)]
struct BlobState<B: Blob> {
    blob: B,

    /// The page where the next appended byte will be written to.
    current_page: u64,

    /// The state of the partial page in the blob. If it was written due to a sync call, then this
    /// will contain its CRC record.
    partial_page_state: Option<Checksum>,

    /// Whether prior plain writes or resizes must be made durable by a full sync.
    needs_sync: bool,
}

impl<B: Blob> BlobState<B> {
    /// Write bytes to the underlying blob and mark them as needing sync.
    async fn write_at(&mut self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        self.blob.write_at(offset, bufs).await?;
        self.needs_sync = true;
        Ok(())
    }

    /// Write bytes to the underlying blob and make them durable.
    ///
    /// Uses [`Blob::write_at_sync`] when there are no earlier unsynced
    /// mutations. Otherwise, writes the bytes and then syncs the blob.
    async fn write_at_sync(
        &mut self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        if self.needs_sync {
            self.write_at(offset, bufs).await?;
            self.sync().await
        } else {
            // If `write_at_sync` fails, a later sync must not treat the drained
            // buffer as durable.
            self.needs_sync = true;
            self.blob.write_at_sync(offset, bufs).await?;
            self.needs_sync = false;
            Ok(())
        }
    }

    /// Write bytes to the underlying blob, optionally making them durable.
    async fn write_at_maybe_sync(
        &mut self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        sync: bool,
    ) -> Result<(), Error> {
        if sync {
            self.write_at_sync(offset, bufs).await
        } else {
            self.write_at(offset, bufs).await
        }
    }

    /// Resize the underlying blob and mark it as needing sync.
    async fn resize(&mut self, len: u64) -> Result<(), Error> {
        self.blob.resize(len).await?;
        self.needs_sync = true;
        Ok(())
    }

    /// Sync the underlying blob if there are unsynced mutations.
    async fn sync(&mut self) -> Result<(), Error> {
        if !self.needs_sync {
            return Ok(());
        }
        self.blob.sync().await?;
        self.needs_sync = false;
        Ok(())
    }
}

/// A [Blob] wrapper that supports write-cached appending of data, with checksums for data integrity
/// and page cache managed caching.
pub struct Append<B: Blob> {
    /// The underlying blob being wrapped.
    blob_state: Arc<AsyncRwLock<BlobState<B>>>,

    /// Unique id assigned to this blob by the page cache.
    id: u64,

    /// A reference to the page cache that manages read caching for this blob.
    cache_ref: CacheRef,

    /// The write buffer containing any logical bytes following the last full page boundary in the
    /// underlying blob.
    buffer: Arc<AsyncRwLock<Buffer>>,
}

/// Returns the capacity with a floor applied to ensure it can hold at least one full page of new
/// data even when caching a nearly-full page of already written data.
fn capacity_with_floor(capacity: usize, page_size: u64) -> usize {
    let floor = page_size as usize * 2;
    if capacity < floor {
        warn!(
            floor,
            "requested buffer capacity is too low, increasing it to floor"
        );
        floor
    } else {
        capacity
    }
}

impl<B: Blob> Append<B> {
    /// Create a new [Append] wrapper of the provided `blob` that is known to have `blob_size`
    /// underlying physical bytes, using the provided `cache_ref` for read caching, and a write
    /// buffer with capacity `capacity`. Rewinds the blob if necessary to ensure it only contains
    /// checksum-validated data.
    pub async fn new(
        blob: B,
        original_blob_size: u64,
        capacity: usize,
        cache_ref: CacheRef,
    ) -> Result<Self, Error> {
        let (last, trimmed) =
            read_and_trim(&blob, original_blob_size, cache_ref.page_size()).await?;

        let capacity = capacity_with_floor(capacity, cache_ref.page_size());
        // If we trimmed and synced, the wrapped blob is already durable. Otherwise pending writes
        // need to be synced on the next call.
        let needs_sync = !trimmed;

        let (blob_state, partial_data) = match last.partial {
            Some((partial_page, crc_record)) => (
                BlobState {
                    blob,
                    current_page: last.pages - 1,
                    partial_page_state: Some(crc_record),
                    needs_sync,
                },
                Some(partial_page),
            ),
            None => (
                BlobState {
                    blob,
                    current_page: last.pages,
                    partial_page_state: None,
                    needs_sync,
                },
                None,
            ),
        };

        let buffer = Buffer::from(
            blob_state.current_page * cache_ref.page_size(),
            partial_data.unwrap_or_default(),
            capacity,
            cache_ref.pool().clone(),
        );

        Ok(Self {
            blob_state: Arc::new(AsyncRwLock::new(blob_state)),
            id: cache_ref.next_id(),
            cache_ref,
            buffer: Arc::new(AsyncRwLock::new(buffer)),
        })
    }

    /// Append all bytes in `buf` to the tip of the blob.
    pub async fn append(&self, buf: &[u8]) -> Result<(), Error> {
        let mut buffer = self.buffer.write().await;

        if !buffer.append(buf) {
            return Ok(());
        }

        // Buffer is over capacity, so we need to write data to the blob.
        self.flush_internal(buffer, false, false).await?;
        Ok(())
    }

    /// Flush all full pages from the buffer to disk, resetting the buffer to contain only the bytes
    /// in any final partial page.
    ///
    /// If `write_partial_page` is true, the partial page will be written to the blob as well along
    /// with a CRC record.
    ///
    /// If `sync` is true and the flush emits a single write, that write is made durable
    /// immediately: with [`Blob::write_at_sync`] when there are no earlier unsynced mutations, or
    /// by writing it and syncing the blob when there are. Flushes split around a protected CRC use
    /// plain writes so the caller can make them durable with one sync.
    ///
    /// # Serialization
    ///
    /// This method reads `partial_page_state` from `blob_state` under a read lock, then later
    /// acquires `blob_state` as a write lock to commit the new state. This is safe because the
    /// caller always holds the buffer write lock (`buf_guard`), and all paths into `flush_internal`
    /// require that lock, so concurrent flushes are impossible.
    ///
    /// Returns `true` if the flush made its writes durable, so no additional sync is needed.
    async fn flush_internal(
        &self,
        mut buf_guard: AsyncRwLockWriteGuard<'_, Buffer>,
        write_partial_page: bool,
        sync: bool,
    ) -> Result<bool, Error> {
        let buffer = &mut *buf_guard;

        // Read the old partial page state before doing the heavy work of preparing physical pages.
        // This is safe because partial_page_state is only modified by flush_internal, and we hold
        // the buffer write lock which prevents concurrent flushes.
        let old_partial_page_state = {
            let blob_state = self.blob_state.read().await;
            blob_state.partial_page_state.clone()
        };

        // Prepare the *physical* pages corresponding to the data in the buffer.
        // Pass the old partial page state so the CRC record is constructed correctly.
        let (mut physical_pages, partial_page_state) = self.to_physical_pages(
            &*buffer,
            write_partial_page,
            old_partial_page_state.as_ref(),
        );

        // If there's nothing to write, return early.
        if physical_pages.is_empty() {
            return Ok(false);
        }

        // Split buffered bytes into full logical pages to hand off now, leaving any trailing
        // partial page in tip for continued buffering.
        let logical_page_size = self.cache_ref.page_size() as usize;
        let pages_to_cache = buffer.len() / logical_page_size;
        let bytes_to_drain = pages_to_cache * logical_page_size;

        // Remember the logical start offset and page bytes for caching of flushed full pages.
        let cache_pages = if pages_to_cache > 0 {
            Some((buffer.offset, buffer.slice(..bytes_to_drain)))
        } else {
            None
        };

        // Drain full pages from the buffered logical data. If the tip is fully drained, detach its
        // backing so empty append buffers don't retain pooled storage.
        if bytes_to_drain == buffer.len() && bytes_to_drain != 0 {
            let _ = buffer
                .take()
                .expect("take must succeed when flush drains all buffered bytes");
        } else if bytes_to_drain != 0 {
            buffer.drop_prefix(bytes_to_drain);
            buffer.offset += bytes_to_drain as u64;
        }
        let new_offset = buffer.offset;

        // Cache full pages before releasing the tip lock so reads don't observe stale persisted
        // bytes during the handoff from tip to cache.
        if let Some((cache_offset, pages)) = cache_pages {
            let remaining = self.cache_ref.cache(self.id, pages.as_ref(), cache_offset);
            assert_eq!(remaining, 0, "cached full-page prefix must be page-aligned");
        }

        // Acquire a write lock on the blob state so nobody tries to read or modify the blob while
        // we're writing to it.
        let mut blob_state = self.blob_state.write().await;

        // Release the buffer lock to allow for concurrent reads & buffered writes while we write
        // the physical pages.
        drop(buf_guard);

        let physical_page_size = logical_page_size + CHECKSUM_SIZE as usize;
        let write_at_offset = blob_state.current_page * physical_page_size as u64;

        // Identify protected regions based on the OLD partial page state.
        let protected_regions = Self::identify_protected_regions(old_partial_page_state.as_ref());

        // Update state before writing. This may appear to risk data loss if writes fail,
        // but write failures are fatal per this codebase's design - callers must not use
        // the blob after any mutable method returns an error.
        blob_state.current_page += pages_to_cache as u64;
        blob_state.partial_page_state = partial_page_state;

        // Make sure the buffer offset and underlying blob agree on the state of the tip.
        assert_eq!(
            blob_state.current_page * self.cache_ref.page_size(),
            new_offset
        );

        // Write the physical pages to the blob.
        // If there are protected regions in the first page, we need to write around them.
        match protected_regions {
            Some((prefix_len, ProtectedCrc::First)) => {
                // Protected CRC is first: [page_size..page_size+6].
                //
                // If only one of these writes is emitted, it can be made durable here. If
                // both are emitted, keep them plain so one later sync covers both.
                //
                // Write 1: new data in first page [prefix_len..page_size].
                let has_first_write = prefix_len < logical_page_size;
                if has_first_write {
                    let _ = physical_pages.split_to(prefix_len);
                    let first_payload = physical_pages.split_to(logical_page_size - prefix_len);
                    let has_second_write = physical_pages.len() > CHECKSUM_SLOT_SIZE;
                    blob_state
                        .write_at_maybe_sync(
                            write_at_offset + prefix_len as u64,
                            first_payload,
                            sync && !has_second_write,
                        )
                        .await?;
                    if !has_second_write {
                        return Ok(sync);
                    }
                } else {
                    // Skip the protected first page bytes when they are fully covered.
                    let _ = physical_pages.split_to(logical_page_size);
                }

                // Write 2: second CRC of first page + all remaining pages [page_size+6..end].
                if physical_pages.len() > CHECKSUM_SLOT_SIZE {
                    let _ = physical_pages.split_to(CHECKSUM_SLOT_SIZE);
                    blob_state
                        .write_at_maybe_sync(
                            write_at_offset + (logical_page_size + CHECKSUM_SLOT_SIZE) as u64,
                            physical_pages,
                            sync && !has_first_write,
                        )
                        .await?;
                    if !has_first_write {
                        return Ok(sync);
                    }
                }

                Ok(false)
            }
            Some((prefix_len, ProtectedCrc::Second)) => {
                // Protected CRC is second: [page_size+6..page_size+12].
                //
                // If only one of these writes is emitted, it can be made durable here. If
                // both are emitted, keep them plain so one later sync covers both.
                //
                // Write 1: new data + first CRC of first page [prefix_len..page_size+6].
                let first_crc_end = logical_page_size + CHECKSUM_SLOT_SIZE;
                let skip = physical_page_size - first_crc_end;
                let has_first_write = prefix_len < first_crc_end;
                if has_first_write {
                    let _ = physical_pages.split_to(prefix_len);
                    let first_payload = physical_pages.split_to(first_crc_end - prefix_len);
                    let has_second_write = physical_pages.len() > skip;
                    blob_state
                        .write_at_maybe_sync(
                            write_at_offset + prefix_len as u64,
                            first_payload,
                            sync && !has_second_write,
                        )
                        .await?;
                    if !has_second_write {
                        return Ok(sync);
                    }
                } else {
                    // Skip the fully protected first segment when no bytes from it need update.
                    let _ = physical_pages.split_to(first_crc_end);
                }

                // Write 2: all remaining pages (if any) [physical_page_size..end].
                if physical_pages.len() > skip {
                    let _ = physical_pages.split_to(skip);
                    blob_state
                        .write_at_maybe_sync(
                            write_at_offset + physical_page_size as u64,
                            physical_pages,
                            sync && !has_first_write,
                        )
                        .await?;
                    if !has_first_write {
                        return Ok(sync);
                    }
                }

                Ok(false)
            }
            None => {
                // No protected regions, write everything in one operation
                blob_state
                    .write_at_maybe_sync(write_at_offset, physical_pages, sync)
                    .await?;
                Ok(sync)
            }
        }
    }

    /// Returns the logical size of the blob. This accounts for both written and buffered data.
    pub async fn size(&self) -> u64 {
        let buffer = self.buffer.read().await;
        buffer.size()
    }

    /// Returns the logical size of the blob if it can be observed without waiting.
    ///
    /// This is useful for opportunistic fast paths that should fall back rather than contend with
    /// concurrent writers.
    pub fn try_size(&self) -> Option<u64> {
        let buffer = self.buffer.try_read().ok()?;
        Some(buffer.size())
    }

    /// Read into `buf` if it can be done synchronously (e.g. without I/O), returning `false` otherwise.
    ///
    /// Returns `true` only if all `buf.len()` bytes were satisfied. The caller must have
    /// already validated that `offset + buf.len()` is within the blob's logical size.
    ///
    /// The page cache is consulted first to minimize the risk of writer starvation from a
    /// burst of buffer reads (which jump ahead of queued writers on the buffer lock).
    pub fn try_read_sync(&self, offset: u64, buf: &mut [u8]) -> bool {
        if self.cache_ref.read_cached(self.id, buf, offset) == buf.len() {
            return true;
        }
        let Some(end_offset) = offset.checked_add(buf.len() as u64) else {
            return false;
        };
        let Ok(buffer) = self.buffer.try_read() else {
            return false;
        };
        if offset < buffer.offset || end_offset > buffer.size() {
            return false;
        }
        let src_start = (offset - buffer.offset) as usize;
        buf.copy_from_slice(&buffer.as_ref()[src_start..src_start + buf.len()]);
        true
    }

    /// Read exactly `len` immutable bytes starting at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        // Read into a temporary contiguous buffer and copy back to preserve structure.
        // SAFETY: read_into below initializes all `len` bytes.
        let mut buf = unsafe { self.cache_ref.pool().alloc_len(len) };
        self.read_into(buf.as_mut(), offset).await?;
        Ok(buf.into())
    }

    /// Reads up to `buf.len()` bytes starting at `logical_offset`, but only as many as are
    /// available.
    ///
    /// This is useful for reading variable-length prefixes (like varints) where you want to read
    /// up to a maximum number of bytes but the actual data might be shorter.
    ///
    /// Returns the buffer (truncated to actual bytes read) and the number of bytes read.
    /// Returns an error if no bytes are available at the given offset.
    pub async fn read_up_to(
        &self,
        logical_offset: u64,
        len: usize,
        bufs: impl Into<IoBufMut> + Send,
    ) -> Result<(IoBufMut, usize), Error> {
        let mut bufs = bufs.into();
        if len == 0 {
            bufs.truncate(0);
            return Ok((bufs, 0));
        }
        let blob_size = self.size().await;
        let available = (blob_size.saturating_sub(logical_offset) as usize).min(len);
        if available == 0 {
            return Err(Error::BlobInsufficientLength);
        }
        // SAFETY: read_into below fills all `available` bytes.
        unsafe { bufs.set_len(available) };
        self.read_into(bufs.as_mut(), logical_offset).await?;

        Ok((bufs, available))
    }

    /// Read multiple fixed-size items at sorted byte offsets into a contiguous caller buffer.
    ///
    /// `buf` must be exactly `offsets.len() * item_size` bytes. All offsets must be sorted,
    /// non-overlapping, and within bounds. This amortizes lock acquisition and avoids
    /// per-item buffer allocation compared to calling [`read_at`](Self::read_at) in a loop.
    pub async fn read_many_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: usize,
    ) -> Result<(), Error> {
        assert_eq!(
            buf.len(),
            offsets
                .len()
                .checked_mul(item_size)
                .expect("read_many_into buffer length overflow"),
            "read_many_into requires buf.len() == offsets.len() * item_size"
        );
        if offsets.is_empty() {
            return Ok(());
        }

        let last_end = offsets[offsets.len() - 1]
            .checked_add(item_size as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Acquire the buffer lock once for all items.
        let buffer = self.buffer.read().await;
        if last_end > buffer.size() {
            return Err(Error::BlobInsufficientLength);
        }

        // Iterate over fixed-size output slots and copy items that overlap with the
        // tip buffer directly into place. Items fully or partially below the tip
        // need cache/blob reads and are recorded as (slice, offset) pairs.
        // `chunks_exact_mut` yields disjoint per-item slots, so we never have to
        // reborrow the parent buffer while cache/blob destinations remain live.
        if item_size == 0 {
            return Ok(());
        }
        let mut cache_ranges: Vec<(&mut [u8], u64)> = Vec::new();
        for (item_buf, &offset) in buf.chunks_exact_mut(item_size).zip(offsets.iter()) {
            let end = offset + item_size as u64;

            if end <= buffer.offset {
                // Entirely below tip -- needs cache read.
                cache_ranges.push((item_buf, offset));
            } else if offset >= buffer.offset {
                // Entirely in tip buffer.
                let src = (offset - buffer.offset) as usize;
                item_buf.copy_from_slice(&buffer.as_ref()[src..src + item_size]);
            } else {
                // Straddles tip boundary: copy suffix from tip, record prefix for cache.
                let prefix_len = (buffer.offset - offset) as usize;
                item_buf[prefix_len..].copy_from_slice(&buffer.as_ref()[..item_size - prefix_len]);
                cache_ranges.push((&mut item_buf[..prefix_len], offset));
            }
        }

        drop(buffer);

        if cache_ranges.is_empty() {
            return Ok(());
        }

        // Fast path: try page cache for all ranges in a single lock acquisition.
        // Fully-cached ranges are removed from cache_ranges; only misses remain.
        self.cache_ref.read_cached_many(self.id, &mut cache_ranges);
        if cache_ranges.is_empty() {
            return Ok(());
        }

        // Slow path: read only the ranges that had cache misses, concurrently.
        let blob_guard = self.blob_state.read().await;
        let mut reads = cache_ranges
            .iter_mut()
            .map(|(item_buf, offset)| {
                self.cache_ref
                    .read(&blob_guard.blob, self.id, item_buf, *offset)
            })
            .collect::<FuturesUnordered<_>>();
        while let Some(result) = reads.next().await {
            result?;
        }

        Ok(())
    }

    /// Reads bytes starting at `logical_offset` into `buf`.
    ///
    /// This method allows reading directly into a mutable slice without taking ownership of the
    /// buffer or requiring a specific buffer type.
    pub async fn read_into(&self, buf: &mut [u8], logical_offset: u64) -> Result<(), Error> {
        // Ensure the read doesn't overflow.
        let end_offset = logical_offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Acquire a read lock on the buffer.
        let buffer = self.buffer.read().await;

        // If the data required is beyond the size of the blob, return an error.
        if end_offset > buffer.size() {
            return Err(Error::BlobInsufficientLength);
        }

        // Extract any bytes from the buffer that overlap with the requested range.
        let remaining = if end_offset <= buffer.offset {
            // No overlap with tip.
            buf.len()
        } else {
            // Overlap is always a suffix of requested range.
            let overlap_start = buffer.offset.max(logical_offset);
            let dst_start = (overlap_start - logical_offset) as usize;
            let src_start = (overlap_start - buffer.offset) as usize;
            let copied = buf.len() - dst_start;
            buf[dst_start..].copy_from_slice(&buffer.as_ref()[src_start..src_start + copied]);
            dst_start
        };

        // Release buffer lock before potential I/O.
        drop(buffer);

        if remaining == 0 {
            return Ok(());
        }

        // Fast path: try to read *only* from page cache without acquiring blob lock. This allows
        // concurrent reads even while a flush is in progress.
        let cached = self
            .cache_ref
            .read_cached(self.id, &mut buf[..remaining], logical_offset);

        if cached == remaining {
            // All bytes found in cache.
            return Ok(());
        }

        // Slow path: cache miss (partial or full), acquire blob read lock to ensure any in-flight
        // write completes before we read from the blob.
        let blob_guard = self.blob_state.read().await;

        // Read remaining bytes that were not already obtained from the earlier cache read.
        let uncached_offset = logical_offset + cached as u64;
        let uncached_len = remaining - cached;
        self.cache_ref
            .read(
                &blob_guard.blob,
                self.id,
                &mut buf[cached..cached + uncached_len],
                uncached_offset,
            )
            .await
    }

    /// Returns the protected region info for a partial page, if any.
    ///
    /// # Returns
    ///
    /// `None` if there's no existing partial page.
    ///
    /// `Some((prefix_len, protected_crc))` where:
    /// - `prefix_len`: bytes `[0..prefix_len]` were already written and can be substituted with
    ///   zeros (skip writing)
    /// - `protected_crc`: which CRC slot must not be overwritten
    fn identify_protected_regions(
        partial_page_state: Option<&Checksum>,
    ) -> Option<(usize, ProtectedCrc)> {
        let crc_record = partial_page_state?;
        let (old_len, _) = crc_record.get_crc();
        // The protected CRC is the one with the larger (authoritative) length.
        let protected_crc = if crc_record.len1 >= crc_record.len2 {
            ProtectedCrc::First
        } else {
            ProtectedCrc::Second
        };
        Some((old_len as usize, protected_crc))
    }

    /// Prepare physical-page writes from buffered logical bytes.
    ///
    /// Each physical page contains one logical page plus CRC record. If the last page is not yet
    /// full, it will be included only if `include_partial_page` is true.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The buffer containing logical page data
    /// * `include_partial_page` - Whether to include a partial page if one exists
    /// * `old_crc_record` - The CRC record from a previously committed partial page, if any.
    ///   When present, the first page's CRC record will preserve the old CRC in its original slot
    ///   and place the new CRC in the other slot.
    fn to_physical_pages(
        &self,
        buffer: &Buffer,
        include_partial_page: bool,
        old_crc_record: Option<&Checksum>,
    ) -> (IoBufs, Option<Checksum>) {
        let logical_page_size = self.cache_ref.page_size() as usize;
        let physical_page_size = logical_page_size + CHECKSUM_SIZE as usize;
        let pages_to_write = buffer.len() / logical_page_size;
        let mut write_buffer = IoBufs::default();
        let buffer_data = buffer.as_ref();

        if pages_to_write > 0 {
            let logical_page_size_u16 =
                u16::try_from(logical_page_size).expect("page size must fit in u16 for CRC record");

            // Build CRC bytes for full pages once. Full-page payload bytes are appended below as
            // slices from tip, so we avoid copying logical payload here.
            let mut crcs = self
                .cache_ref
                .pool()
                .alloc(CHECKSUM_SIZE as usize * pages_to_write);
            for page in 0..pages_to_write {
                let start_read_idx = page * logical_page_size;
                let end_read_idx = start_read_idx + logical_page_size;
                let logical_page = &buffer_data[start_read_idx..end_read_idx];
                let crc = Crc32::checksum(logical_page);

                // For the first page, if there's an old partial page CRC, construct the record
                // to preserve the old CRC in its original slot.
                let crc_record = if let (0, Some(old_crc)) = (page, old_crc_record) {
                    Self::build_crc_record_preserving_old(logical_page_size_u16, crc, old_crc)
                } else {
                    Checksum::new(logical_page_size_u16, crc)
                };
                crcs.put_slice(&crc_record.to_bytes());
            }
            let crc_blob = crcs.freeze();

            // Physical full-page layout is [logical_page_bytes, crc_record_bytes].
            for page in 0..pages_to_write {
                let start_read_idx = page * logical_page_size;
                let end_read_idx = start_read_idx + logical_page_size;
                write_buffer.append(buffer.slice(start_read_idx..end_read_idx));

                let crc_start = page * CHECKSUM_SIZE as usize;
                write_buffer.append(crc_blob.slice(crc_start..crc_start + CHECKSUM_SIZE as usize));
            }
        }

        if !include_partial_page {
            return (write_buffer, None);
        }

        let partial_page = &buffer_data[pages_to_write * logical_page_size..];
        if partial_page.is_empty() {
            // No partial page data to write.
            return (write_buffer, None);
        }

        // If there are no full pages and the partial page length matches what was already
        // written, there's nothing new to write.
        if pages_to_write == 0 {
            if let Some(old_crc) = old_crc_record {
                let (old_len, _) = old_crc.get_crc();
                if partial_page.len() == old_len as usize {
                    return (write_buffer, None);
                }
            }
        }
        let partial_len = partial_page.len();
        let crc = Crc32::checksum(partial_page);

        // For partial pages: if this is the first page and there's an old CRC, preserve it.
        // Otherwise just use the new CRC in slot 0.
        let crc_record = if let (0, Some(old_crc)) = (pages_to_write, old_crc_record) {
            Self::build_crc_record_preserving_old(partial_len as u16, crc, old_crc)
        } else {
            Checksum::new(partial_len as u16, crc)
        };

        // A persisted partial page still occupies one full physical page:
        // [partial logical bytes, zero padding, crc record].
        let mut padded = self.cache_ref.pool().alloc(physical_page_size);
        padded.put_slice(partial_page);
        let zero_count = logical_page_size - partial_len;
        if zero_count > 0 {
            padded.put_bytes(0, zero_count);
        }
        padded.put_slice(&crc_record.to_bytes());
        write_buffer.append(padded.freeze());

        // Return the CRC record that matches what we wrote to disk, so that future flushes
        // correctly identify which slot is protected.
        (write_buffer, Some(crc_record))
    }

    /// Encode one checksum slot as `[len: u16][crc: u32]`, matching `Checksum::write`.
    fn checksum_slot_bytes(len: u16, crc: u32) -> [u8; CHECKSUM_SLOT_SIZE] {
        let mut bytes = [0u8; CHECKSUM_SLOT_SIZE];
        bytes[..2].copy_from_slice(&len.to_be_bytes());
        bytes[2..].copy_from_slice(&crc.to_be_bytes());
        bytes
    }

    /// Build a CRC record that preserves the old CRC in its original slot and places
    /// the new CRC in the other slot.
    const fn build_crc_record_preserving_old(
        new_len: u16,
        new_crc: u32,
        old_crc: &Checksum,
    ) -> Checksum {
        let (old_len, old_crc_val) = old_crc.get_crc();
        // The old CRC is in the slot with the larger length value (first slot wins ties).
        if old_crc.len1 >= old_crc.len2 {
            // Old CRC is in slot 0, put new CRC in slot 1
            Checksum {
                len1: old_len,
                crc1: old_crc_val,
                len2: new_len,
                crc2: new_crc,
            }
        } else {
            // Old CRC is in slot 1, put new CRC in slot 0
            Checksum {
                len1: new_len,
                crc1: new_crc,
                len2: old_len,
                crc2: old_crc_val,
            }
        }
    }

    /// Durably rewrite a committed page to a shorter partial length.
    async fn sync_partial_page_shrink(
        blob_state: &mut BlobState<B>,
        page: u64,
        logical_page_size: u64,
        new_len: u16,
        new_crc: u32,
        old_crc: &Checksum,
    ) -> Result<Checksum, Error> {
        // Recovery chooses the valid slot with the larger length. While shrinking, the new
        // checksum must be made durable without becoming authoritative until the old longer slot
        // can be disabled. The sequence below therefore lets recovery observe either the old page
        // or the new shorter page, but not a footer where both slots were damaged by one torn write.
        let physical_page_size = logical_page_size
            .checked_add(CHECKSUM_SIZE)
            .ok_or(Error::OffsetOverflow)?;
        let crc_start = page
            .checked_mul(physical_page_size)
            .and_then(|start| start.checked_add(logical_page_size))
            .ok_or(Error::OffsetOverflow)?;
        let (new_slot_start, old_slot_start) = if old_crc.len1 >= old_crc.len2 {
            (CHECKSUM_SLOT_SIZE, 0)
        } else {
            (0, CHECKSUM_SLOT_SIZE)
        };

        // Stage the new slot with a 0 length and the shrunken page CRC. A crash here leaves the
        // old slot as the only non-zero valid slot.
        let new_slot_offset = crc_start
            .checked_add(new_slot_start as u64)
            .ok_or(Error::OffsetOverflow)?;
        let staged_slot = Self::checksum_slot_bytes(0, new_crc);
        blob_state
            .write_at_sync(new_slot_offset, staged_slot.to_vec())
            .await?;

        // Publish the new shrunken length. If a crash happens before the old slot is invalidated,
        // both slots may be valid, but recovery still chooses the old longer length.
        blob_state
            .write_at_sync(new_slot_offset, new_len.to_be_bytes().to_vec())
            .await?;

        // Clear only the old slot's length bytes. Rewriting the whole footer here could tear across
        // both slots and lose the already-durable shorter checksum. Once this lands, length 0 is
        // never authoritative, so the shrunken slot wins.
        let old_slot_offset = crc_start
            .checked_add(old_slot_start as u64)
            .ok_or(Error::OffsetOverflow)?;
        let len_size = std::mem::size_of::<u16>();
        blob_state
            .write_at_sync(old_slot_offset, vec![0u8; len_size])
            .await?;

        let final_record = if new_slot_start == 0 {
            Checksum {
                len1: new_len,
                crc1: new_crc,
                len2: 0,
                crc2: 0,
            }
        } else {
            Checksum {
                len1: 0,
                crc1: 0,
                len2: new_len,
                crc2: new_crc,
            }
        };
        Ok(final_record)
    }

    /// Flushes any buffered data, then returns a [Replay] for the underlying blob.
    ///
    /// The returned replay can be used to sequentially read all pages from the blob while ensuring
    /// all data passes integrity verification. CRCs are validated but not included in the output.
    ///
    /// This is not a durable operation. Buffered data may be plainly written so the replay can
    /// read it, but callers must still use [`sync`](Self::sync) if that data must survive a crash.
    pub async fn replay(&self, buffer_size: NonZeroUsize) -> Result<Replay<B>, Error> {
        let logical_page_size = self.cache_ref.page_size();
        let logical_page_size_nz =
            NonZeroU16::new(logical_page_size as u16).expect("page_size is non-zero");

        // Flush any buffered data (without fsync) so the reader sees all written data.
        {
            let buf_guard = self.buffer.write().await;
            self.flush_internal(buf_guard, true, false).await?;
        }

        // Convert buffer size (bytes) to page count
        let physical_page_size = logical_page_size + CHECKSUM_SIZE;
        let prefetch_pages = buffer_size.get() / physical_page_size as usize;
        let prefetch_pages = prefetch_pages.max(1); // At least 1 page
        let blob_guard = self.blob_state.read().await;

        // Compute both physical and logical blob sizes.
        let (physical_blob_size, logical_blob_size) =
            blob_guard.partial_page_state.as_ref().map_or_else(
                || {
                    // All pages are full.
                    let physical = physical_page_size * blob_guard.current_page;
                    let logical = logical_page_size * blob_guard.current_page;
                    (physical, logical)
                },
                |crc_record| {
                    // There's a partial page with a checksum.
                    let (partial_len, _) = crc_record.get_crc();
                    let partial_len = partial_len as u64;
                    // Physical: all pages including the partial one (which is padded to full size).
                    let physical = physical_page_size * (blob_guard.current_page + 1);
                    // Logical: full pages before this + partial page's actual data length.
                    let logical = logical_page_size * blob_guard.current_page + partial_len;
                    (physical, logical)
                },
            );

        let reader = PageReader::new(
            blob_guard.blob.clone(),
            physical_blob_size,
            logical_blob_size,
            prefetch_pages,
            logical_page_size_nz,
        );
        Ok(Replay::new(reader))
    }
}

impl<B: Blob> Append<B> {
    /// Flushes buffered data and makes all pending mutations durable.
    ///
    /// A single physical write can be persisted with [`Blob::write_at_sync`]. If there
    /// are earlier unsynced mutations, or if the flush emits multiple physical writes,
    /// durability is completed with [`Blob::sync`].
    pub async fn sync(&self) -> Result<(), Error> {
        // Flush any buffered data, including any partial page.
        let buf_guard = self.buffer.write().await;

        // A single emitted write can be made durable directly during the flush.
        if self.flush_internal(buf_guard, true, true).await? {
            return Ok(());
        }

        // Otherwise, the flush either had no bytes to write or used plain writes. Sync only if a
        // durability barrier is still pending.
        let mut blob_state = self.blob_state.write().await;
        blob_state.sync().await
    }

    /// Resize the blob to the provided logical `size`.
    ///
    /// This truncates the blob to contain only `size` logical bytes. The physical blob size will
    /// be adjusted to include the necessary CRC records for the remaining pages.
    ///
    /// # Warning
    ///
    /// - Concurrent mutable operations (append, resize) are not supported and will cause data loss.
    /// - Concurrent readers which try to read past the new size during the resize may error.
    /// - The resize is not guaranteed durable until the next sync.
    pub async fn resize(&self, size: u64) -> Result<(), Error> {
        let current_size = self.size().await;
        if size == current_size {
            return Ok(());
        }

        // Handle growing by appending zero bytes.
        if size > current_size {
            let zeros_needed = (size - current_size) as usize;
            let mut zeros = self.cache_ref.pool().alloc(zeros_needed);
            zeros.put_bytes(0, zeros_needed);
            self.append(zeros.as_ref()).await?;
            return Ok(());
        }

        self.shrink(size).await
    }

    /// Coordinate the locking and dispatch logic for shrinking the blob.
    async fn shrink(&self, target_size: u64) -> Result<(), Error> {
        let logical_page_size = self.cache_ref.page_size();
        let physical_page_size = logical_page_size
            .checked_add(CHECKSUM_SIZE)
            .ok_or(Error::OffsetOverflow)?;

        // Flush any buffered data first to ensure we have a consistent state on disk.
        self.sync().await?;

        // Acquire both locks to prevent concurrent operations.
        let mut buf_guard = self.buffer.write().await;
        let mut blob_guard = self.blob_state.write().await;

        // Calculate the physical size needed for the new logical size.
        let full_pages = target_size / logical_page_size;
        let partial_bytes = target_size % logical_page_size;
        let physical_pages = full_pages
            .checked_add(u64::from(partial_bytes > 0))
            .ok_or(Error::OffsetOverflow)?;
        let new_physical_size = physical_pages
            .checked_mul(physical_page_size)
            .ok_or(Error::OffsetOverflow)?;
        let tail_offset = full_pages
            .checked_mul(logical_page_size)
            .ok_or(Error::OffsetOverflow)?;
        let current_physical_size = if blob_guard.partial_page_state.is_some() {
            blob_guard
                .current_page
                .checked_add(1)
                .and_then(|pages| pages.checked_mul(physical_page_size))
                .ok_or(Error::OffsetOverflow)?
        } else {
            blob_guard
                .current_page
                .checked_mul(physical_page_size)
                .ok_or(Error::OffsetOverflow)?
        };

        // A logical shrink can leave the physical page count unchanged. Only real physical
        // resizes need to create a pending sync.
        if new_physical_size != current_physical_size {
            blob_guard.resize(new_physical_size).await?;
        }

        // Evict cached pages at or beyond the new full-page boundary. The page at
        // `full_pages` (if partial) is now owned by the tip buffer, and anything above is
        // beyond the new logical size. Leaving their pre-resize contents in the cache
        // lets `try_read_sync` (which bypasses the tip buffer) observe stale bytes once
        // the tip is repopulated.
        self.cache_ref.invalidate_from(self.id, full_pages);

        if partial_bytes > 0 {
            return self
                .shrink_to_partial(
                    &mut buf_guard,
                    &mut blob_guard,
                    full_pages,
                    partial_bytes,
                    logical_page_size,
                    tail_offset,
                )
                .await;
        }

        // Shrink the blob to a page boundary, which requires no CRC-slot rewrite.
        blob_guard.partial_page_state = None;
        blob_guard.current_page = full_pages;
        buf_guard.offset = tail_offset;
        buf_guard.clear();

        Ok(())
    }

    /// Perform a shrink to a partial page tip and make the shorter CRC slot authoritative.
    async fn shrink_to_partial(
        &self,
        buf_guard: &mut Buffer,
        blob_guard: &mut BlobState<B>,
        full_pages: u64,
        partial_bytes: u64,
        logical_page_size: u64,
        tail_offset: u64,
    ) -> Result<(), Error> {
        // Update blob state and buffer based on the desired logical size. The page data is
        // read with CRC validation, then durably rewritten below with a shorter CRC.
        blob_guard.current_page = full_pages;
        buf_guard.offset = tail_offset;

        let (page_data, old_crc) = super::get_page_with_checksum_from_blob(
            &blob_guard.blob,
            full_pages,
            logical_page_size,
        )
        .await?;

        // Ensure the validated data covers what we need.
        if (page_data.len() as u64) < partial_bytes {
            return Err(Error::InvalidChecksum);
        }

        buf_guard.clear();
        let new_data = &page_data.as_ref()[..partial_bytes as usize];
        let over_capacity = buf_guard.append(new_data);
        assert!(!over_capacity);

        let final_record = Self::sync_partial_page_shrink(
            blob_guard,
            full_pages,
            logical_page_size,
            partial_bytes as u16,
            Crc32::checksum(new_data),
            &old_crc,
        )
        .await?;
        blob_guard.partial_page_state = Some(final_record);

        Ok(())
    }

    /// Consume this writable handle and return a read-only [`super::Sealed`] view of the same
    /// blob.
    pub async fn seal(self) -> Result<super::Sealed<B>, Error> {
        // Make all buffered data durable so the sealed view sees a fully committed blob.
        self.sync().await?;

        let logical_page_size = self.cache_ref.page_size();
        let buffer = self.buffer.read().await;
        let blob_state = self.blob_state.read().await;

        let full_pages = blob_state.current_page;
        let partial_page = if blob_state.partial_page_state.is_some() {
            // After sync, the tip buffer holds the partial page's logical bytes starting at the
            // full-page boundary.
            debug_assert_eq!(buffer.offset, full_pages * logical_page_size);
            Some(buffer.slice(..buffer.len()))
        } else {
            debug_assert!(buffer.is_empty());
            None
        };

        let partial_len = partial_page.as_ref().map_or(0, |p| p.len() as u64);
        let size = full_pages * logical_page_size + partial_len;
        let blob = blob_state.blob.clone();

        Ok(super::Sealed::from_parts(
            blob,
            size,
            partial_page,
            self.cache_ref.clone(),
            self.id,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        buffer::tests::SyncTrackingBlob, deterministic, telemetry::metrics::Registry, Buf,
        BufferPool, BufferPoolConfig, IoBufsMut, Runner as _, Storage as _,
    };
    use commonware_codec::ReadExt;
    use commonware_macros::test_traced;
    use commonware_utils::{NZUsize, NZU16, NZU32};
    use std::{
        num::NonZeroU16,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    const PAGE_SIZE: NonZeroU16 = NZU16!(103); // janky size to ensure we test page alignment
    const BUFFER_SIZE: usize = PAGE_SIZE.get() as usize * 2;

    #[test_traced("DEBUG")]
    fn test_read_many_into_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            append.append(&[0u8; 8]).await.unwrap();
            assert_eq!(append.size().await, 8);

            // Empty offsets should succeed immediately.
            let mut buf = [];
            append.read_many_into(&mut buf, &[], 4).await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_many_into_all_in_tip() {
        // All items reside in the unflushed tip buffer.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0..20).collect();
            append.append(&data).await.unwrap();
            assert_eq!(append.size().await, 20);

            // Read 4-byte items at offsets 0, 4, 8, 12, 16.
            let offsets = [0u64, 4, 8, 12, 16];
            let mut buf = vec![0u8; 5 * 4];
            append.read_many_into(&mut buf, &offsets, 4).await.unwrap();

            for (i, &off) in offsets.iter().enumerate() {
                assert_eq!(
                    &buf[i * 4..(i + 1) * 4],
                    &data[off as usize..off as usize + 4],
                );
            }
        });
    }

    #[test_traced("DEBUG")]
    fn test_try_read_sync_all_in_tip() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"try_read_sync_tip")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0..20).collect();
            append.append(&data).await.unwrap();

            let mut buf = vec![0u8; data.len()];
            assert!(append.try_read_sync(0, &mut buf));
            assert_eq!(buf, data);
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_many_into_all_from_cache() {
        // Sync data to disk so tip buffer is empty; reads go through page cache / blob.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0..20).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();
            assert_eq!(append.size().await, 20);

            let offsets = [0u64, 8, 16];
            let mut buf = vec![0u8; 3 * 4];
            append.read_many_into(&mut buf, &offsets, 4).await.unwrap();

            for (i, &off) in offsets.iter().enumerate() {
                assert_eq!(
                    &buf[i * 4..(i + 1) * 4],
                    &data[off as usize..off as usize + 4],
                );
            }
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_many_into_mixed_tip_and_cache() {
        // First chunk synced to disk, second chunk still in tip buffer.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let first: Vec<u8> = (0..16).collect();
            append.append(&first).await.unwrap();
            append.sync().await.unwrap();

            let second: Vec<u8> = (16..32).collect();
            append.append(&second).await.unwrap();
            assert_eq!(append.size().await, 32);

            // Offsets span both synced and unsynced regions.
            let offsets = [0u64, 4, 16, 24];
            let mut buf = vec![0u8; 4 * 4];
            append.read_many_into(&mut buf, &offsets, 4).await.unwrap();

            let all: Vec<u8> = (0..32).collect();
            for (i, &off) in offsets.iter().enumerate() {
                assert_eq!(
                    &buf[i * 4..(i + 1) * 4],
                    &all[off as usize..off as usize + 4],
                );
            }
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_many_into_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            append.append(&[0u8; 8]).await.unwrap();
            assert_eq!(append.size().await, 8);

            // Last offset's end (8 + 4 = 12) exceeds size (8).
            let mut buf = vec![0u8; 4];
            let err = append.read_many_into(&mut buf, &[8], 4).await.unwrap_err();
            assert!(matches!(err, Error::BlobInsufficientLength));
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_many_into_single_item() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data = vec![0xAA; 8];
            append.append(&data).await.unwrap();
            assert_eq!(append.size().await, 8);

            let mut buf = vec![0u8; 8];
            append.read_many_into(&mut buf, &[0], 8).await.unwrap();
            assert_eq!(&buf, &data);
        });
    }

    #[test]
    #[should_panic(expected = "read_many_into requires buf.len() == offsets.len() * item_size")]
    fn test_read_many_into_short_buffer_panics() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0..16).collect();
            append.append(&data).await.unwrap();

            let offsets = [0u64, 4];
            let mut buf = vec![0u8; 7];
            append.read_many_into(&mut buf, &offsets, 4).await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_many_into_matches_read_at() {
        // Verify read_many_into returns the same bytes as individual read_at calls.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Write enough data to span multiple pages (PAGE_SIZE=103).
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();
            // Add more in tip buffer.
            let more: Vec<u8> = (0u8..50).collect();
            append.append(&more).await.unwrap();
            assert_eq!(append.size().await, 350);

            let item_size = 10;
            let offsets: Vec<u64> = (0..35).map(|i| i * item_size as u64).collect();
            let mut batch_buf = vec![0u8; offsets.len() * item_size];
            append
                .read_many_into(&mut batch_buf, &offsets, item_size)
                .await
                .unwrap();

            // Compare each item against individual read_at.
            for (i, &off) in offsets.iter().enumerate() {
                let single = append.read_at(off, item_size).await.unwrap().coalesce();
                assert_eq!(
                    &batch_buf[i * item_size..(i + 1) * item_size],
                    single.as_ref(),
                    "mismatch at offset {off}",
                );
            }
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_many_into_scattered_cache_misses() {
        // Exercises all three source paths in a single read_many_into call:
        // tip buffer, page cache hit, and page cache miss (blob I/O).
        // The tip holds a partial page so one item straddles the tip boundary.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            // Small cache: only 2 pages, so we can force eviction.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(2));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Write 3 pages of data and sync to disk.
            let synced: Vec<u8> = (0u8..=255)
                .cycle()
                .take(PAGE_SIZE.get() as usize * 3)
                .collect();
            append.append(&synced).await.unwrap();
            append.sync().await.unwrap();

            // Write a partial page that stays in the tip buffer. The item_size
            // is chosen so the last item straddles the synced/tip boundary.
            let item_size = 10;
            let tip_len = PAGE_SIZE.get() as usize / 2;
            let tip: Vec<u8> = (100u8..=255).cycle().take(tip_len).collect();
            append.append(&tip).await.unwrap();

            // Prime pages 0 and 2 into cache, leaving page 1 uncached.
            let _ = append.read_at(0, item_size).await.unwrap();
            let _ = append
                .read_at(PAGE_SIZE.get() as u64 * 2, item_size)
                .await
                .unwrap();

            // Offset that straddles the synced/tip boundary: starts in the last
            // synced page, ends in the tip buffer.
            let straddle_off = synced.len() as u64 - (item_size as u64 / 2);
            let tip_off = synced.len() as u64 + item_size as u64;
            let offsets = [
                0u64,                       // page 0 (cached)
                PAGE_SIZE.get() as u64,     // page 1 (not cached - blob I/O)
                PAGE_SIZE.get() as u64 * 2, // page 2 (cached)
                straddle_off,               // straddles synced/tip boundary
                tip_off,                    // entirely in tip buffer
            ];
            let mut buf = vec![0u8; offsets.len() * item_size];
            append
                .read_many_into(&mut buf, &offsets, item_size)
                .await
                .unwrap();

            let read: Vec<u8> = synced.iter().chain(tip.iter()).copied().collect();
            for (i, &off) in offsets.iter().enumerate() {
                assert_eq!(
                    &buf[i * item_size..(i + 1) * item_size],
                    &read[off as usize..off as usize + item_size],
                );
            }
        });
    }

    #[test_traced("DEBUG")]
    fn test_append_crc_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            // Open a new blob.
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            // Create a page cache reference.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));

            // Create an Append wrapper.
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Verify initial size is 0.
            assert_eq!(append.size().await, 0);

            // Close & re-open.
            append.sync().await.unwrap();
            drop(append);

            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0); // There was no need to write a crc since there was no data.

            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            assert_eq!(append.size().await, 0);
        });
    }

    #[test_traced("DEBUG")]
    fn test_append_crc_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            // Open a new blob.
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            // Create a page cache reference.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));

            // Create an Append wrapper.
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Verify initial size is 0.
            assert_eq!(append.size().await, 0);

            // Append some bytes.
            let data = vec![1, 2, 3, 4, 5];
            append.append(&data).await.unwrap();

            // Verify size reflects appended data.
            assert_eq!(append.size().await, 5);

            // Append more bytes.
            let more_data = vec![6, 7, 8, 9, 10];
            append.append(&more_data).await.unwrap();

            // Verify size is cumulative.
            assert_eq!(append.size().await, 10);

            // Read back the first chunk and verify.
            let read_buf = append.read_at(0, 5).await.unwrap().coalesce();
            assert_eq!(read_buf, &data[..]);

            // Read back the second chunk and verify.
            let read_buf = append.read_at(5, 5).await.unwrap().coalesce();
            assert_eq!(read_buf, &more_data[..]);

            // Read all data at once and verify.
            let read_buf = append.read_at(0, 10).await.unwrap().coalesce();
            assert_eq!(read_buf, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

            // Close and reopen the blob and make sure the data is still there and the trailing
            // checksum is written & stripped as expected.
            append.sync().await.unwrap();
            drop(append);

            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            // Physical page = 103 logical + 12 Checksum = 115 bytes (padded partial page)
            assert_eq!(blob_size, 115);
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size().await, 10); // CRC should be stripped after verification

            // Append data that spans a page boundary.
            // PAGE_SIZE=103 is the logical page size. We have 10 bytes, so writing
            // 100 more bytes (total 110) will cross the page boundary at byte 103.
            let spanning_data: Vec<u8> = (11..=110).collect();
            append.append(&spanning_data).await.unwrap();
            assert_eq!(append.size().await, 110);

            // Read back data that spans the page boundary.
            let read_buf = append.read_at(10, 100).await.unwrap().coalesce();
            assert_eq!(read_buf, &spanning_data[..]);

            // Read all 110 bytes at once.
            let read_buf = append.read_at(0, 110).await.unwrap().coalesce();
            let expected: Vec<u8> = (1..=110).collect();
            assert_eq!(read_buf, &expected[..]);

            // Drop and re-open and make sure bytes are still there.
            append.sync().await.unwrap();
            drop(append);

            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            // 2 physical pages: 2 * 115 = 230 bytes
            assert_eq!(blob_size, 230);
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size().await, 110);

            // Append data to reach exactly a page boundary.
            // Logical page size is 103. We have 110 bytes, next boundary is 206 (103 * 2).
            // So we need 96 more bytes.
            let boundary_data: Vec<u8> = (111..=206).collect();
            assert_eq!(boundary_data.len(), 96);
            append.append(&boundary_data).await.unwrap();
            assert_eq!(append.size().await, 206);

            // Verify we can read it back.
            let read_buf = append.read_at(0, 206).await.unwrap().coalesce();
            let expected: Vec<u8> = (1..=206).collect();
            assert_eq!(read_buf, &expected[..]);

            // Drop and re-open at the page boundary.
            append.sync().await.unwrap();
            drop(append);

            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            // Physical size should be exactly 2 pages: 115 * 2 = 230 bytes
            assert_eq!(blob_size, 230);
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size().await, 206);

            // Verify data is still readable after reopen.
            let read_buf = append.read_at(0, 206).await.unwrap().coalesce();
            assert_eq!(read_buf, &expected[..]);
        });
    }

    #[test_traced("DEBUG")]
    fn test_sync_releases_tip_pool_slot_after_full_drain() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let mut registry = Registry::default();
            let pool = BufferPool::new(
                BufferPoolConfig::for_storage()
                    .with_pool_min_size(PAGE_SIZE.get() as usize)
                    .with_max_per_class(NZU32!(2)),
                &mut registry,
            );
            let cache_ref = CacheRef::new(pool.clone(), PAGE_SIZE, NZUsize!(1));

            let (blob, blob_size) = context
                .open("test_partition", b"release_tip_backing")
                .await
                .unwrap();
            assert_eq!(blob_size, 0);

            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            append
                .append(&vec![7; PAGE_SIZE.get() as usize])
                .await
                .unwrap();

            // One pooled slot backs the page cache and one backs the mutable tip.
            assert!(
                matches!(
                    pool.try_alloc(BUFFER_SIZE),
                    Err(crate::iobuf::PoolError::Exhausted)
                ),
                "full-page tip should occupy the remaining pooled slot before sync"
            );

            append.sync().await.unwrap();

            // After a full drain, the tip should no longer pin that slot.
            assert!(
                pool.try_alloc(BUFFER_SIZE).is_ok(),
                "sync should release pooled backing when no partial tail remains"
            );
        });
    }

    #[test_traced("DEBUG")]
    fn test_sync_uses_range_sync_for_single_flush() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // A newly wrapped blob preserves one full barrier before range sync is used.
            append.sync().await.unwrap();
            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 0);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 0);

            // A single buffered write with no remaining dirty state can be made durable directly.
            let data = b"hello world";
            append.append(data).await.unwrap();
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 1);

            // With no new writes and no pending full-sync barrier, sync has no work left.
            append.sync().await.unwrap();
            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 1);

            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let reopened = Append::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let read = reopened.read_at(0, data.len()).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), data);
        });
    }

    #[test_traced("DEBUG")]
    fn test_sync_failed_range_sync_does_not_mark_clean() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let name = b"failed_range_sync";
            let (blob, size) = context.open("test_partition", name).await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Keep the write buffered so sync attempts the clean `write_at_sync` path.
            append.append(b"abc").await.unwrap();

            // Removing the blob makes the range-sync flush fail.
            context.remove("test_partition", Some(name)).await.unwrap();
            assert!(append.sync().await.is_err());

            // The failed `write_at_sync` must leave a pending full-sync barrier, so a
            // later sync cannot report success.
            assert!(append.sync().await.is_err());
        });
    }

    #[test_traced("DEBUG")]
    fn test_sync_uses_full_sync_after_prior_plain_flush() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // This append overflows the buffer, so a plain flush happens before sync writes the
            // remaining tip.
            let data = vec![7u8; BUFFER_SIZE + 1];
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 2);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 0);

            // With no new work, sync should not issue another durability operation.
            append.sync().await.unwrap();
            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 2);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 0);

            // The next sync still needs a full barrier because the append path flushed the full
            // page before the final partial tip.
            append.append(b"tip").await.unwrap();
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 4);
            assert_eq!(full_syncs, 2);
            assert_eq!(range_syncs, 0);

            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let reopened = Append::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let mut expected = data;
            expected.extend_from_slice(b"tip");
            let read = reopened
                .read_at(0, expected.len())
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read.as_ref(), expected.as_slice());
        });
    }

    #[test_traced("DEBUG")]
    fn test_sync_uses_full_sync_after_replay_plain_flush() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Keep data buffered so replay has to flush it without syncing.
            append.append(b"replayed").await.unwrap();

            // Replay flushes buffered data for reading, but does not make that write durable.
            let mut replay = append.replay(NZUsize!(1024)).await.unwrap();
            assert!(replay.ensure(b"replayed".len()).await.unwrap());
            assert_eq!(replay.remaining(), b"replayed".len());
            assert_eq!(replay.chunk(), b"replayed");

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 0);
            assert_eq!(range_syncs, 0);

            // A later sync must use a full barrier for the plain replay flush.
            append.sync().await.unwrap();
            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 0);
        });
    }

    #[test_traced("DEBUG")]
    fn test_recreated_sync_preserves_replay_plain_flush_barrier() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            append.append(b"replayed").await.unwrap();
            let mut replay = append.replay(NZUsize!(1024)).await.unwrap();
            assert!(replay.ensure(b"replayed".len()).await.unwrap());
            assert_eq!(replay.remaining(), b"replayed".len());
            assert_eq!(replay.chunk(), b"replayed");
            drop(replay);
            drop(append);

            let (durable, writes, full_syncs, range_syncs) = blob.snapshot();
            assert!(durable.is_empty());
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 0);
            assert_eq!(range_syncs, 0);

            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let reopened = Append::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(reopened.size().await, b"replayed".len() as u64);
            reopened.sync().await.unwrap();

            let (durable, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(durable.len(), blob.size() as usize);
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 0);
        });
    }

    #[test_traced("DEBUG")]
    fn test_recreated_sync_skips_barrier_after_invalid_truncation() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.sync().await.unwrap();
            append.append(b"valid").await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            blob.write_at(blob.size(), b"junk").await.unwrap();

            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let reopened = Append::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(reopened.size().await, b"valid".len() as u64);

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 2);
            assert_eq!(full_syncs, 2);
            assert_eq!(range_syncs, 1);

            reopened.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 2);
            assert_eq!(full_syncs, 2);
            assert_eq!(range_syncs, 1);
        });
    }

    #[test_traced("DEBUG")]
    fn test_sync_batches_split_protected_writes_with_full_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.sync().await.unwrap();

            // Establish a persisted partial page with one authoritative CRC slot.
            append.append(b"abc").await.unwrap();
            append.sync().await.unwrap();

            // Extending that partial page must write around the protected slot, so the two emitted
            // writes are batched behind one full sync.
            append.append(b"de").await.unwrap();
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 3);
            assert_eq!(full_syncs, 2);
            assert_eq!(range_syncs, 1);

            // On the next extension, the protected slot is the second CRC, so only the prefix
            // write is needed.
            append.append(b"fg").await.unwrap();
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 4);
            assert_eq!(full_syncs, 2);
            assert_eq!(range_syncs, 2);

            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let reopened = Append::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let read = reopened.read_at(0, 7).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"abcdefg");
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_up_to_zero_len_truncates_buffer() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            // Open a new blob.
            let (blob, blob_size) = context
                .open("test_partition", b"read_up_to_zero_len")
                .await
                .unwrap();
            assert_eq!(blob_size, 0);

            // Create a page cache reference.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));

            // Create an Append wrapper and write some data.
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.append(&[1, 2, 3, 4]).await.unwrap();

            // Request a zero-length read with a reused, non-empty buffer.
            let stale = vec![9, 8, 7, 6];
            let (buf, read) = append.read_up_to(0, 0, stale).await.unwrap();

            assert_eq!(read, 0);
            assert_eq!(buf.len(), 0, "read_up_to must truncate returned buffer");
            assert_eq!(buf.freeze().as_ref(), b"");
        });
    }

    /// Helper to read the CRC record from raw blob bytes at the end of a physical page.
    fn read_crc_record_from_page(page_bytes: &[u8]) -> Checksum {
        let crc_start = page_bytes.len() - CHECKSUM_SIZE as usize;
        Checksum::read(&mut &page_bytes[crc_start..]).unwrap()
    }

    /// Blob wrapper that turns one write into a durable partial write followed by an error.
    #[derive(Clone)]
    struct PartialWriteBlob<B: Blob> {
        inner: B,
        writes: Arc<AtomicUsize>,
        failed_write_len: Arc<AtomicUsize>,
        fail_on: usize,
        partial_len: usize,
    }

    impl<B: Blob> PartialWriteBlob<B> {
        fn new(inner: B, fail_on: usize, partial_len: usize) -> Self {
            Self {
                inner,
                writes: Arc::new(AtomicUsize::new(0)),
                failed_write_len: Arc::new(AtomicUsize::new(0)),
                fail_on,
                partial_len,
            }
        }

        fn failed_write_len(&self) -> Arc<AtomicUsize> {
            self.failed_write_len.clone()
        }

        fn write_count(&self) -> Arc<AtomicUsize> {
            self.writes.clone()
        }
    }

    impl<B: Blob> crate::Blob for PartialWriteBlob<B> {
        async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
            self.inner.read_at(offset, len).await
        }

        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
        ) -> Result<IoBufsMut, Error> {
            self.inner.read_at_buf(offset, len, bufs).await
        }

        async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
            let bufs = bufs.into();
            let write = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
            if write == self.fail_on {
                let bytes = bufs.coalesce();
                self.failed_write_len.store(bytes.len(), Ordering::SeqCst);
                let partial_len = self.partial_len.min(bytes.len());
                self.inner
                    .write_at(offset, bytes.slice(..partial_len))
                    .await?;
                self.inner.sync().await?;
                return Err(Error::Io(std::io::Error::other("injected partial write")));
            }

            self.inner.write_at(offset, bufs).await
        }

        async fn write_at_sync(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
        ) -> Result<(), Error> {
            let bufs = bufs.into();
            let write = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
            if write == self.fail_on {
                let bytes = bufs.coalesce();
                self.failed_write_len.store(bytes.len(), Ordering::SeqCst);
                let partial_len = self.partial_len.min(bytes.len());
                self.inner
                    .write_at_sync(offset, bytes.slice(..partial_len))
                    .await?;
                return Err(Error::Io(std::io::Error::other("injected partial write")));
            }

            self.inner.write_at_sync(offset, bufs).await
        }

        async fn resize(&self, len: u64) -> Result<(), Error> {
            self.inner.resize(len).await
        }

        async fn sync(&self) -> Result<(), Error> {
            self.inner.sync().await
        }
    }

    /// Dummy marker bytes with len=0 so the mangled slot is never authoritative.
    /// Format: [len_hi=0, len_lo=0, 0xDE, 0xAD, 0xBE, 0xEF]
    const DUMMY_MARKER: [u8; 6] = [0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];

    #[test]
    fn test_identify_protected_regions_equal_lengths() {
        // When lengths are equal, the first CRC should be protected (tie-breaking rule).
        let record = Checksum {
            len1: 50,
            crc1: 0xAAAAAAAA,
            len2: 50,
            crc2: 0xBBBBBBBB,
        };

        let result =
            Append::<crate::storage::memory::Blob>::identify_protected_regions(Some(&record));
        assert!(result.is_some());
        let (prefix_len, protected_crc) = result.unwrap();
        assert_eq!(prefix_len, 50);
        assert!(
            matches!(protected_crc, ProtectedCrc::First),
            "First CRC should be protected when lengths are equal"
        );
    }

    #[test]
    fn test_identify_protected_regions_len1_larger() {
        // When len1 > len2, the first CRC should be protected.
        let record = Checksum {
            len1: 100,
            crc1: 0xAAAAAAAA,
            len2: 50,
            crc2: 0xBBBBBBBB,
        };

        let result =
            Append::<crate::storage::memory::Blob>::identify_protected_regions(Some(&record));
        assert!(result.is_some());
        let (prefix_len, protected_crc) = result.unwrap();
        assert_eq!(prefix_len, 100);
        assert!(
            matches!(protected_crc, ProtectedCrc::First),
            "First CRC should be protected when len1 > len2"
        );
    }

    #[test]
    fn test_identify_protected_regions_len2_larger() {
        // When len2 > len1, the second CRC should be protected.
        let record = Checksum {
            len1: 50,
            crc1: 0xAAAAAAAA,
            len2: 100,
            crc2: 0xBBBBBBBB,
        };

        let result =
            Append::<crate::storage::memory::Blob>::identify_protected_regions(Some(&record));
        assert!(result.is_some());
        let (prefix_len, protected_crc) = result.unwrap();
        assert_eq!(prefix_len, 100);
        assert!(
            matches!(protected_crc, ProtectedCrc::Second),
            "Second CRC should be protected when len2 > len1"
        );
    }

    /// Test that `to_physical_pages` emits full pages zero-copy while still materializing the
    /// trailing partial page into one padded physical page.
    #[test_traced("DEBUG")]
    fn test_to_physical_pages_zero_copy_full_pages_and_materialized_partial() {
        // Build a tip buffer containing two full logical pages plus a trailing partial
        // page, convert it with `to_physical_pages`, then verify:
        // - the result is chunked rather than one contiguous buffer for the full-page portion
        // - the logical payload bytes for the first two pages are preserved in order
        // - the partial page is padded with zeros up to one full logical page
        // - all three resulting physical pages validate their CRC records
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            // Open a new blob.
            let (blob, blob_size) = context
                .open("test_partition", b"to_physical_pages_zero_copy")
                .await
                .unwrap();
            assert_eq!(blob_size, 0);

            // Create a page cache reference.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));

            // Create an Append wrapper.
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Build logical data with exactly two full pages followed by one trailing partial page.
            // This lets us verify that only the partial page is materialized.
            let logical_page_size = PAGE_SIZE.get() as usize;
            let partial_len = 17usize;
            let data: Vec<u8> = (0..(logical_page_size * 2 + partial_len))
                .map(|i| (i % 251) as u8)
                .collect();

            // Seed a tip buffer with the logical bytes exactly as flush_internal would see them.
            let mut buffer = Buffer::new(0, data.len(), cache_ref.pool().clone());
            let over_capacity = buffer.append(&data);
            assert!(!over_capacity);

            // Convert buffered logical bytes into physical-page writes.
            let (physical_pages, partial_page_state) =
                append.to_physical_pages(&buffer, true, None);

            // Two full pages should each contribute a logical slice and a CRC slice, and the
            // trailing partial page should contribute one materialized padded physical page.
            assert_eq!(physical_pages.chunk_count(), 5);

            // The returned partial-page CRC state must describe the exact trailing logical length.
            let crc_record = partial_page_state.expect("partial page state must be returned");
            let (len, _) = crc_record.get_crc();
            assert_eq!(len as usize, partial_len);

            // Coalesce for easier content inspection. The assembled bytes should still form three
            // full physical pages on disk.
            let physical_page_size = logical_page_size + CHECKSUM_SIZE as usize;
            let coalesced = physical_pages.coalesce();
            assert_eq!(coalesced.len(), physical_page_size * 3);

            // The first two physical pages must preserve the two full logical pages verbatim.
            assert_eq!(
                &coalesced.as_ref()[..logical_page_size],
                &data[..logical_page_size]
            );
            assert_eq!(
                &coalesced.as_ref()[physical_page_size..physical_page_size + logical_page_size],
                &data[logical_page_size..logical_page_size * 2],
            );

            // The trailing partial page must contain the remaining logical bytes followed by zero
            // padding up to one full logical page.
            let partial_start = physical_page_size * 2;
            assert_eq!(
                &coalesced.as_ref()[partial_start..partial_start + partial_len],
                &data[logical_page_size * 2..],
            );
            assert!(coalesced.as_ref()
                [partial_start + partial_len..partial_start + logical_page_size]
                .iter()
                .all(|byte| *byte == 0));

            // Each assembled physical page must carry a valid CRC record.
            assert!(Checksum::validate_page(&coalesced.as_ref()[..physical_page_size]).is_some());
            assert!(Checksum::validate_page(
                &coalesced.as_ref()[physical_page_size..physical_page_size * 2]
            )
            .is_some());
            assert!(Checksum::validate_page(
                &coalesced.as_ref()[physical_page_size * 2..physical_page_size * 3]
            )
            .is_some());
        });
    }

    /// Test that slot 1 is NOT overwritten when it's the protected slot.
    ///
    /// Strategy: After extending twice (so slot 1 becomes authoritative with larger len),
    /// mangle the non-authoritative slot 0. Then extend again - slot 0 should be overwritten
    /// with the new CRC, while slot 1 (protected) should remain untouched.
    #[test_traced("DEBUG")]
    fn test_crc_slot1_protected() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let physical_page_size = PAGE_SIZE.get() as usize + CHECKSUM_SIZE as usize;
            let slot0_offset = PAGE_SIZE.get() as u64;
            let slot1_offset = PAGE_SIZE.get() as u64 + 6;

            // === Step 1: Write 10 bytes → slot 0 authoritative (len=10) ===
            let (blob, _) = context.open("test_partition", b"slot1_prot").await.unwrap();
            let append = Append::new(blob, 0, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&(1..=10).collect::<Vec<u8>>()).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 2: Extend to 30 bytes → slot 1 authoritative (len=30) ===
            let (blob, size) = context.open("test_partition", b"slot1_prot").await.unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append
                .append(&(11..=30).collect::<Vec<u8>>())
                .await
                .unwrap();
            append.sync().await.unwrap();
            drop(append);

            // Verify slot 1 is now authoritative
            let (blob, size) = context.open("test_partition", b"slot1_prot").await.unwrap();
            let page = blob
                .read_at(0, physical_page_size)
                .await
                .unwrap()
                .coalesce();
            let crc = read_crc_record_from_page(page.as_ref());
            assert!(
                crc.len2 > crc.len1,
                "Slot 1 should be authoritative (len2={} > len1={})",
                crc.len2,
                crc.len1
            );

            // Capture slot 1 bytes before mangling slot 0
            let slot1_before: Vec<u8> = blob
                .read_at(slot1_offset, 6)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();

            // === Step 3: Mangle slot 0 (non-authoritative) ===
            blob.write_at(slot0_offset, DUMMY_MARKER.to_vec())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Verify mangle worked
            let slot0_mangled: Vec<u8> = blob
                .read_at(slot0_offset, 6)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_eq!(slot0_mangled, DUMMY_MARKER, "Mangle failed");

            // === Step 4: Extend to 50 bytes → new CRC goes to slot 0, slot 1 protected ===
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append
                .append(&(31..=50).collect::<Vec<u8>>())
                .await
                .unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 5: Verify slot 0 was overwritten, slot 1 unchanged ===
            let (blob, _) = context.open("test_partition", b"slot1_prot").await.unwrap();

            // Slot 0 should have new CRC (not our dummy marker)
            let slot0_after: Vec<u8> = blob
                .read_at(slot0_offset, 6)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_ne!(
                slot0_after, DUMMY_MARKER,
                "Slot 0 should have been overwritten with new CRC"
            );

            // Slot 1 should be UNCHANGED (protected)
            let slot1_after: Vec<u8> = blob
                .read_at(slot1_offset, 6)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_eq!(
                slot1_before, slot1_after,
                "Slot 1 was modified! Protected region violated."
            );

            // Verify the new CRC in slot 0 has len=50
            let page = blob
                .read_at(0, physical_page_size)
                .await
                .unwrap()
                .coalesce();
            let crc = read_crc_record_from_page(page.as_ref());
            assert_eq!(crc.len1, 50, "Slot 0 should have len=50");
        });
    }

    /// Test that slot 0 is NOT overwritten when it's the protected slot.
    ///
    /// Strategy: After extending three times (slot 0 becomes authoritative again with largest len),
    /// mangle the non-authoritative slot 1. Then extend again - slot 1 should be overwritten
    /// with the new CRC, while slot 0 (protected) should remain untouched.
    #[test_traced("DEBUG")]
    fn test_crc_slot0_protected() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let physical_page_size = PAGE_SIZE.get() as usize + CHECKSUM_SIZE as usize;
            let slot0_offset = PAGE_SIZE.get() as u64;
            let slot1_offset = PAGE_SIZE.get() as u64 + 6;

            // === Step 1: Write 10 bytes → slot 0 authoritative (len=10) ===
            let (blob, _) = context.open("test_partition", b"slot0_prot").await.unwrap();
            let append = Append::new(blob, 0, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&(1..=10).collect::<Vec<u8>>()).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 2: Extend to 30 bytes → slot 1 authoritative (len=30) ===
            let (blob, size) = context.open("test_partition", b"slot0_prot").await.unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append
                .append(&(11..=30).collect::<Vec<u8>>())
                .await
                .unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 3: Extend to 50 bytes → slot 0 authoritative (len=50) ===
            let (blob, size) = context.open("test_partition", b"slot0_prot").await.unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append
                .append(&(31..=50).collect::<Vec<u8>>())
                .await
                .unwrap();
            append.sync().await.unwrap();
            drop(append);

            // Verify slot 0 is now authoritative
            let (blob, size) = context.open("test_partition", b"slot0_prot").await.unwrap();
            let page = blob
                .read_at(0, physical_page_size)
                .await
                .unwrap()
                .coalesce();
            let crc = read_crc_record_from_page(page.as_ref());
            assert!(
                crc.len1 > crc.len2,
                "Slot 0 should be authoritative (len1={} > len2={})",
                crc.len1,
                crc.len2
            );

            // Capture slot 0 bytes before mangling slot 1
            let slot0_before: Vec<u8> = blob
                .read_at(slot0_offset, 6)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();

            // === Step 4: Mangle slot 1 (non-authoritative) ===
            blob.write_at(slot1_offset, DUMMY_MARKER.to_vec())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Verify mangle worked
            let slot1_mangled: Vec<u8> = blob
                .read_at(slot1_offset, 6)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_eq!(slot1_mangled, DUMMY_MARKER, "Mangle failed");

            // === Step 5: Extend to 70 bytes → new CRC goes to slot 1, slot 0 protected ===
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append
                .append(&(51..=70).collect::<Vec<u8>>())
                .await
                .unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 6: Verify slot 1 was overwritten, slot 0 unchanged ===
            let (blob, _) = context.open("test_partition", b"slot0_prot").await.unwrap();

            // Slot 1 should have new CRC (not our dummy marker)
            let slot1_after: Vec<u8> = blob
                .read_at(slot1_offset, 6)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_ne!(
                slot1_after, DUMMY_MARKER,
                "Slot 1 should have been overwritten with new CRC"
            );

            // Slot 0 should be UNCHANGED (protected)
            let slot0_after: Vec<u8> = blob
                .read_at(slot0_offset, 6)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_eq!(
                slot0_before, slot0_after,
                "Slot 0 was modified! Protected region violated."
            );

            // Verify the new CRC in slot 1 has len=70
            let page = blob
                .read_at(0, physical_page_size)
                .await
                .unwrap()
                .coalesce();
            let crc = read_crc_record_from_page(page.as_ref());
            assert_eq!(crc.len2, 70, "Slot 1 should have len=70");
        });
    }

    /// Test that the data prefix is NOT overwritten when extending a partial page.
    ///
    /// Strategy: Write data, then mangle the padding area (between data end and CRC start).
    /// After extending, the original data should be unchanged but the mangled padding
    /// should be overwritten with new data.
    #[test_traced("DEBUG")]
    fn test_data_prefix_not_overwritten() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let physical_page_size = PAGE_SIZE.get() as usize + CHECKSUM_SIZE as usize;

            // === Step 1: Write 20 bytes ===
            let (blob, _) = context
                .open("test_partition", b"prefix_test")
                .await
                .unwrap();
            let append = Append::new(blob, 0, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            let data1: Vec<u8> = (1..=20).collect();
            append.append(&data1).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 2: Capture the first 20 bytes and mangle bytes 25-30 (in padding area) ===
            let (blob, size) = context
                .open("test_partition", b"prefix_test")
                .await
                .unwrap();
            assert_eq!(size, physical_page_size as u64);

            let prefix_before: Vec<u8> = blob
                .read_at(0, 20)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();

            // Mangle bytes 25-30 (safely in the padding area, after our 20 bytes of data)
            blob.write_at(25, DUMMY_MARKER.to_vec()).await.unwrap();
            blob.sync().await.unwrap();

            // === Step 3: Extend to 40 bytes ===
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append
                .append(&(21..=40).collect::<Vec<u8>>())
                .await
                .unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 4: Verify prefix unchanged, mangled area overwritten ===
            let (blob, _) = context
                .open("test_partition", b"prefix_test")
                .await
                .unwrap();

            // Original 20 bytes should be unchanged
            let prefix_after: Vec<u8> = blob
                .read_at(0, 20)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_eq!(prefix_before, prefix_after, "Data prefix was modified!");

            // Bytes at offset 25-30: data (21..=40) starts at offset 20, so offset 25 has value 26
            let overwritten: Vec<u8> = blob
                .read_at(25, 6)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_eq!(
                overwritten,
                vec![26, 27, 28, 29, 30, 31],
                "New data should overwrite padding area"
            );
        });
    }

    /// Test CRC slot protection when extending past a page boundary.
    ///
    /// Strategy: Write partial page, mangle slot 0 (non-authoritative after we do first extend),
    /// then extend past page boundary. Verify slot 0 gets new full-page CRC while
    /// the mangled marker is overwritten, and second page is written correctly.
    #[test_traced("DEBUG")]
    fn test_crc_slot_protection_across_page_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let physical_page_size = PAGE_SIZE.get() as usize + CHECKSUM_SIZE as usize;
            let slot0_offset = PAGE_SIZE.get() as u64;
            let slot1_offset = PAGE_SIZE.get() as u64 + 6;

            // === Step 1: Write 50 bytes → slot 0 authoritative ===
            let (blob, _) = context.open("test_partition", b"boundary").await.unwrap();
            let append = Append::new(blob, 0, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&(1..=50).collect::<Vec<u8>>()).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 2: Extend to 80 bytes → slot 1 authoritative ===
            let (blob, size) = context.open("test_partition", b"boundary").await.unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append
                .append(&(51..=80).collect::<Vec<u8>>())
                .await
                .unwrap();
            append.sync().await.unwrap();
            drop(append);

            // Verify slot 1 is authoritative
            let (blob, size) = context.open("test_partition", b"boundary").await.unwrap();
            let page = blob
                .read_at(0, physical_page_size)
                .await
                .unwrap()
                .coalesce();
            let crc = read_crc_record_from_page(page.as_ref());
            assert!(crc.len2 > crc.len1, "Slot 1 should be authoritative");

            // Capture slot 1 before extending past page boundary
            let slot1_before: Vec<u8> = blob
                .read_at(slot1_offset, 6)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();

            // Mangle slot 0 (non-authoritative)
            blob.write_at(slot0_offset, DUMMY_MARKER.to_vec())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // === Step 3: Extend past page boundary (80 + 40 = 120, PAGE_SIZE=103) ===
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append
                .append(&(81..=120).collect::<Vec<u8>>())
                .await
                .unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 4: Verify results ===
            let (blob, size) = context.open("test_partition", b"boundary").await.unwrap();
            assert_eq!(size, (physical_page_size * 2) as u64, "Should have 2 pages");

            // Slot 0 should have been overwritten with full-page CRC (not dummy marker)
            let slot0_after: Vec<u8> = blob
                .read_at(slot0_offset, 6)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_ne!(
                slot0_after, DUMMY_MARKER,
                "Slot 0 should have full-page CRC"
            );

            // Slot 1 should be UNCHANGED (protected during boundary crossing)
            let slot1_after: Vec<u8> = blob
                .read_at(slot1_offset, 6)
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_eq!(
                slot1_before, slot1_after,
                "Slot 1 was modified during page boundary crossing!"
            );

            // Verify page 0 has correct CRC structure
            let page0 = blob
                .read_at(0, physical_page_size)
                .await
                .unwrap()
                .coalesce();
            let crc0 = read_crc_record_from_page(page0.as_ref());
            assert_eq!(
                crc0.len1,
                PAGE_SIZE.get(),
                "Slot 0 should have full page length"
            );

            // Verify data integrity
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size().await, 120);
            let all_data: Vec<u8> = append.read_at(0, 120).await.unwrap().coalesce().into();
            let expected: Vec<u8> = (1..=120).collect();
            assert_eq!(all_data, expected);
        });
    }

    /// Test that corrupting the primary CRC (but not its length) causes fallback to the previous
    /// partial page contents.
    ///
    /// Strategy:
    /// 1. Write 10 bytes → slot 0 authoritative (len=10, valid crc)
    /// 2. Extend to 30 bytes → slot 1 authoritative (len=30, valid crc)
    /// 3. Corrupt ONLY the crc2 value in slot 1 (not the length)
    /// 4. Re-open and verify we fall back to slot 0's 10 bytes
    #[test_traced("DEBUG")]
    fn test_crc_fallback_on_corrupted_primary() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let physical_page_size = PAGE_SIZE.get() as usize + CHECKSUM_SIZE as usize;
            // crc2 is at offset: PAGE_SIZE + 6 (for len2) + 2 (skip len2 bytes) = PAGE_SIZE + 8
            let crc2_offset = PAGE_SIZE.get() as u64 + 8;

            // === Step 1: Write 10 bytes → slot 0 authoritative (len=10) ===
            let (blob, _) = context
                .open("test_partition", b"crc_fallback")
                .await
                .unwrap();
            let append = Append::new(blob, 0, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            let data1: Vec<u8> = (1..=10).collect();
            append.append(&data1).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 2: Extend to 30 bytes → slot 1 authoritative (len=30) ===
            let (blob, size) = context
                .open("test_partition", b"crc_fallback")
                .await
                .unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append
                .append(&(11..=30).collect::<Vec<u8>>())
                .await
                .unwrap();
            append.sync().await.unwrap();
            drop(append);

            // Verify slot 1 is now authoritative and data reads correctly
            let (blob, size) = context
                .open("test_partition", b"crc_fallback")
                .await
                .unwrap();
            assert_eq!(size, physical_page_size as u64);

            let page = blob
                .read_at(0, physical_page_size)
                .await
                .unwrap()
                .coalesce();
            let crc = read_crc_record_from_page(page.as_ref());
            assert!(
                crc.len2 > crc.len1,
                "Slot 1 should be authoritative (len2={} > len1={})",
                crc.len2,
                crc.len1
            );
            assert_eq!(crc.len2, 30, "Slot 1 should have len=30");
            assert_eq!(crc.len1, 10, "Slot 0 should have len=10");

            // Verify we can read all 30 bytes before corruption
            let append = Append::new(blob.clone(), size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size().await, 30);
            let all_data: Vec<u8> = append.read_at(0, 30).await.unwrap().coalesce().into();
            let expected: Vec<u8> = (1..=30).collect();
            assert_eq!(all_data, expected);
            drop(append);

            // === Step 3: Corrupt ONLY crc2 (not len2) ===
            // crc2 is 4 bytes at offset PAGE_SIZE + 8
            blob.write_at(crc2_offset, vec![0xDE, 0xAD, 0xBE, 0xEF])
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Verify corruption: len2 should still be 30, but crc2 is now garbage
            let page = blob
                .read_at(0, physical_page_size)
                .await
                .unwrap()
                .coalesce();
            let crc = read_crc_record_from_page(page.as_ref());
            assert_eq!(crc.len2, 30, "len2 should still be 30 after corruption");
            assert_eq!(crc.crc2, 0xDEADBEEF, "crc2 should be our corrupted value");

            // === Step 4: Re-open and verify fallback to slot 0's 10 bytes ===
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Should fall back to 10 bytes (slot 0's length)
            assert_eq!(
                append.size().await,
                10,
                "Should fall back to slot 0's 10 bytes after primary CRC corruption"
            );

            // Verify the data is the original 10 bytes
            let fallback_data: Vec<u8> = append.read_at(0, 10).await.unwrap().coalesce().into();
            assert_eq!(
                fallback_data, data1,
                "Fallback data should match original 10 bytes"
            );

            // Reading beyond 10 bytes should fail
            let result = append.read_at(0, 11).await;
            assert!(result.is_err(), "Reading beyond fallback size should fail");
        });
    }

    /// Test that corrupting a non-last page's primary CRC fails even if fallback is valid.
    ///
    /// Non-last pages must always be full. If the primary CRC is corrupted and the fallback
    /// indicates a partial page, validation should fail entirely (not fall back to partial).
    ///
    /// Strategy:
    /// 1. Write 10 bytes → slot 0 has len=10 (partial)
    /// 2. Extend to full page (103 bytes) → slot 1 has len=103 (full, authoritative)
    /// 3. Extend past page boundary (e.g., 110 bytes) → page 0 is now non-last
    /// 4. Corrupt the primary CRC of page 0 (slot 1's crc, which has len=103)
    /// 5. Re-open and verify that reading from page 0 fails (fallback has len=10, not full)
    #[test_traced("DEBUG")]
    fn test_non_last_page_rejects_partial_fallback() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let physical_page_size = PAGE_SIZE.get() as usize + CHECKSUM_SIZE as usize;
            // crc2 for page 0 is at offset: PAGE_SIZE + 8
            let page0_crc2_offset = PAGE_SIZE.get() as u64 + 8;

            // === Step 1: Write 10 bytes → slot 0 has len=10 ===
            let (blob, _) = context
                .open("test_partition", b"non_last_page")
                .await
                .unwrap();
            let append = Append::new(blob, 0, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&(1..=10).collect::<Vec<u8>>()).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 2: Extend to exactly full page (103 bytes) → slot 1 has len=103 ===
            let (blob, size) = context
                .open("test_partition", b"non_last_page")
                .await
                .unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            // Add bytes 11 through 103 (93 more bytes)
            append
                .append(&(11..=PAGE_SIZE.get() as u8).collect::<Vec<u8>>())
                .await
                .unwrap();
            append.sync().await.unwrap();
            drop(append);

            // Verify page 0 slot 1 is authoritative with len=103 (full page)
            let (blob, size) = context
                .open("test_partition", b"non_last_page")
                .await
                .unwrap();
            let page = blob
                .read_at(0, physical_page_size)
                .await
                .unwrap()
                .coalesce();
            let crc = read_crc_record_from_page(page.as_ref());
            assert_eq!(crc.len1, 10, "Slot 0 should have len=10");
            assert_eq!(
                crc.len2,
                PAGE_SIZE.get(),
                "Slot 1 should have len=103 (full page)"
            );
            assert!(crc.len2 > crc.len1, "Slot 1 should be authoritative");

            // === Step 3: Extend past page boundary (add 10 more bytes for total of 113) ===
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            // Add bytes 104 through 113 (10 more bytes, now on page 1)
            append
                .append(&(104..=113).collect::<Vec<u8>>())
                .await
                .unwrap();
            append.sync().await.unwrap();
            drop(append);

            // Verify we now have 2 pages
            let (blob, size) = context
                .open("test_partition", b"non_last_page")
                .await
                .unwrap();
            assert_eq!(
                size,
                (physical_page_size * 2) as u64,
                "Should have 2 physical pages"
            );

            // Verify data is readable before corruption
            let append = Append::new(blob.clone(), size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size().await, 113);
            let all_data: Vec<u8> = append.read_at(0, 113).await.unwrap().coalesce().into();
            let expected: Vec<u8> = (1..=113).collect();
            assert_eq!(all_data, expected);
            drop(append);

            // === Step 4: Corrupt page 0's primary CRC (slot 1's crc2) ===
            blob.write_at(page0_crc2_offset, vec![0xDE, 0xAD, 0xBE, 0xEF])
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Verify corruption: page 0's slot 1 still has len=103 but bad CRC
            let page = blob
                .read_at(0, physical_page_size)
                .await
                .unwrap()
                .coalesce();
            let crc = read_crc_record_from_page(page.as_ref());
            assert_eq!(crc.len2, PAGE_SIZE.get(), "len2 should still be 103");
            assert_eq!(crc.crc2, 0xDEADBEEF, "crc2 should be corrupted");
            // Slot 0 fallback has len=10 (partial), which is invalid for non-last page
            assert_eq!(crc.len1, 10, "Fallback slot 0 has partial length");

            // === Step 5: Re-open and try to read from page 0 ===
            // The first page's primary CRC is bad, and fallback indicates partial (len=10).
            // Since page 0 is not the last page, a partial fallback is invalid.
            // Reading from page 0 should fail because the fallback CRC indicates a partial
            // page, which is not allowed for non-last pages.
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // The blob still reports 113 bytes because init only validates the last page.
            // But reading from page 0 should fail because the CRC fallback is partial.
            assert_eq!(append.size().await, 113);

            // Try to read from page 0 - this should fail with InvalidChecksum because
            // the fallback CRC has len=10 (partial), which is invalid for a non-last page.
            let result = append.read_at(0, 10).await;
            assert!(
                result.is_err(),
                "Reading from corrupted non-last page via Append should fail, but got: {:?}",
                result
            );
            drop(append);

            // Also verify that reading via Replay fails the same way.
            let (blob, size) = context
                .open("test_partition", b"non_last_page")
                .await
                .unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            let mut replay = append.replay(NZUsize!(1024)).await.unwrap();

            // Try to fill pages - should fail on CRC validation.
            let result = replay.ensure(1).await;
            assert!(
                result.is_err(),
                "Reading from corrupted non-last page via Replay should fail, but got: {:?}",
                result
            );
        });
    }

    #[test]
    fn test_resize_shrink_validates_crc() {
        // Verify that shrinking a blob to a partial page validates the CRC, rather than
        // blindly reading raw bytes which could silently load corrupted data.
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let physical_page_size = PAGE_SIZE.get() as usize + CHECKSUM_SIZE as usize;

            let (blob, size) = context
                .open("test_partition", b"resize_crc_test")
                .await
                .unwrap();

            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Write data across 3 pages: page 0 (full), page 1 (full), page 2 (partial).
            // PAGE_SIZE = 103, so 250 bytes = 103 + 103 + 44.
            let data: Vec<u8> = (0..=249).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();
            assert_eq!(append.size().await, 250);
            drop(append);

            // Corrupt the CRC record of page 1 (middle page).
            let (blob, size) = context
                .open("test_partition", b"resize_crc_test")
                .await
                .unwrap();
            assert_eq!(size as usize, physical_page_size * 3);

            // Page 1 CRC record is at the end of the second physical page.
            let page1_crc_offset = (physical_page_size * 2 - CHECKSUM_SIZE as usize) as u64;
            blob.write_at(page1_crc_offset, vec![0xFF; CHECKSUM_SIZE as usize])
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Open the blob - Append::new() validates the LAST page (page 2), which is still valid.
            // So it should open successfully with size 250.
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size().await, 250);

            // Try to shrink to 150 bytes, which ends in page 1 (the corrupted page).
            // 150 bytes = page 0 (103 full) + page 1 (47 partial).
            // This should fail because page 1's CRC is corrupted.
            let result = append.resize(150).await;
            assert!(
                matches!(result, Err(crate::Error::InvalidChecksum)),
                "Expected InvalidChecksum when shrinking to corrupted page, got: {:?}",
                result
            );
        });
    }

    #[test]
    fn test_resize_invalidates_cache() {
        // Regression: shrinking a blob across a page boundary must drop cached pages for the
        // truncated region. Before the fix, `try_read_sync` (which bypasses the tip buffer)
        // would observe pre-resize bytes at offsets later reclaimed by new appends.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let (blob, blob_size) = context
                .open("test_partition", b"resize_invalidates_cache")
                .await
                .unwrap();
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Write + sync a full page so it lands in the page cache. Use a distinct byte
            // pattern so a stale cache read would be obvious.
            let page_size = PAGE_SIZE.get() as usize;
            let old_bytes = vec![0xAAu8; page_size];
            append.append(&old_bytes).await.unwrap();
            append.sync().await.unwrap();

            // Confirm page 0 is reachable via the cache-only fast path.
            let mut probe = vec![0u8; 16];
            assert!(append.try_read_sync(0, &mut probe));
            assert_eq!(probe, vec![0xAAu8; 16]);

            // Rewind to 0 (crossing the page boundary) and append a new, distinct pattern.
            append.resize(0).await.unwrap();
            let new_bytes = vec![0xBBu8; 16];
            append.append(&new_bytes).await.unwrap();

            // The cache must not serve pre-resize bytes. Either try_read_sync misses (cache
            // was invalidated) or it returns the new pattern; it must never return 0xAA.
            let mut probe = vec![0u8; 16];
            let hit = append.try_read_sync(0, &mut probe);
            assert!(
                !hit || probe == new_bytes,
                "try_read_sync served stale pre-resize bytes: {probe:?}"
            );
        });
    }

    #[test]
    fn test_resize_same_size_is_noop() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let (blob, blob_size) = context
                .open("test_partition", b"resize_same_size")
                .await
                .unwrap();
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            append.append(b"hello world").await.unwrap();
            assert_eq!(append.size().await, 11);

            // Resize to same size. Should succeed.
            append.resize(11).await.unwrap();
            assert_eq!(append.size().await, 11);

            // Verify content is still readable and intact.
            let read = append.read_at(0, 11).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"hello world");
        });
    }

    #[test]
    fn test_resize_same_page_shrink_reopens_at_shorter_size() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let data: Vec<u8> = (0..50).collect();

            let (blob, size) = context
                .open("test_partition", b"same_page_shrink")
                .await
                .unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Create a partial page whose authoritative CRC is in the first slot. The interrupted
            // tests below exercise the opposite slot orientation.
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            append.resize(45).await.unwrap();
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"same_page_shrink")
                .await
                .unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size().await, 45);
            let read = append.read_at(0, 45).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &data[..45]);
        });
    }

    #[test]
    fn test_resize_same_page_shrink_survives_interrupted_crc_stage() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let data: Vec<u8> = (0..50).collect();

            let (blob, size) = context
                .open("test_partition", b"same_page_shrink_interrupted")
                .await
                .unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&data[..40]).await.unwrap();
            append.sync().await.unwrap();
            append.append(&data[40..]).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"same_page_shrink_interrupted")
                .await
                .unwrap();
            let faulty_blob = PartialWriteBlob::new(blob, 1, 3);
            let write_count = faulty_blob.write_count();
            let failed_write_len = faulty_blob.failed_write_len();
            let append = Append::new(faulty_blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            assert!(
                append.resize(45).await.is_err(),
                "phase-1 partial write should fail"
            );
            assert_eq!(write_count.load(Ordering::SeqCst), 1);
            assert_eq!(failed_write_len.load(Ordering::SeqCst), CHECKSUM_SLOT_SIZE);
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"same_page_shrink_interrupted")
                .await
                .unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size().await, 50);
            let read = append.read_at(0, 50).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &data);
        });
    }

    #[test]
    fn test_resize_same_page_shrink_survives_interrupted_len_stage() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            const LARGE_PAGE_SIZE: NonZeroU16 = NZU16!(600);
            const LARGE_BUFFER_SIZE: usize = 1_200;

            let cache_ref =
                CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(LARGE_BUFFER_SIZE));
            let data: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();

            let (blob, size) = context
                .open("test_partition", b"same_page_shrink_len_stage")
                .await
                .unwrap();
            let append = Append::new(blob, size, LARGE_BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&data[..255]).await.unwrap();
            append.sync().await.unwrap();
            append.append(&data[255..]).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"same_page_shrink_len_stage")
                .await
                .unwrap();
            let faulty_blob = PartialWriteBlob::new(blob, 2, 1);
            let write_count = faulty_blob.write_count();
            let failed_write_len = faulty_blob.failed_write_len();
            let append = Append::new(faulty_blob, size, LARGE_BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            assert!(
                append.resize(257).await.is_err(),
                "length-stage partial write should fail"
            );
            assert_eq!(write_count.load(Ordering::SeqCst), 2);
            assert_eq!(failed_write_len.load(Ordering::SeqCst), 2);
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"same_page_shrink_len_stage")
                .await
                .unwrap();
            let append = Append::new(blob, size, LARGE_BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size().await, 300);
            let read = append.read_at(0, 300).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &data);
        });
    }

    #[test]
    fn test_resize_same_page_shrink_preserves_validated_fallback_slot() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let data: Vec<u8> = (0..52).collect();

            let (blob, size) = context
                .open("test_partition", b"same_page_shrink_fallback_slot")
                .await
                .unwrap();
            let faulty_blob = PartialWriteBlob::new(blob.clone(), 5, 3);
            let write_count = faulty_blob.write_count();
            let failed_write_len = faulty_blob.failed_write_len();
            let append = Append::new(faulty_blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&data[..48]).await.unwrap();
            append.sync().await.unwrap();
            assert_eq!(write_count.load(Ordering::SeqCst), 1);

            append.append(&data[48..50]).await.unwrap();
            append.sync().await.unwrap();
            assert_eq!(write_count.load(Ordering::SeqCst), 3);

            append.append(&data[50..]).await.unwrap();
            append.sync().await.unwrap();
            assert_eq!(write_count.load(Ordering::SeqCst), 4);

            // Corrupt the newer authoritative slot. The older slot still covers the shrink target.
            // `resize()` first syncs the live buffer, which writes a valid fallback slot but leaves
            // the cached footer stale. A torn phase-1 shrink write must preserve that validated
            // fallback slot.
            let slot0_offset = PAGE_SIZE.get() as u64;
            blob.write_at(slot0_offset, DUMMY_MARKER.to_vec())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            assert!(
                append.resize(45).await.is_err(),
                "phase-1 partial write should fail"
            );
            assert_eq!(write_count.load(Ordering::SeqCst), 5);
            assert_eq!(failed_write_len.load(Ordering::SeqCst), CHECKSUM_SLOT_SIZE);
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"same_page_shrink_fallback_slot")
                .await
                .unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size().await, 50);
            let read = append.read_at(0, 50).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &data[..50]);
        });
    }

    #[test]
    fn test_resize_full_page_to_partial_reopens_at_shorter_size() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let page_size = PAGE_SIZE.get() as u64;
            let target = page_size + 45;
            let data: Vec<u8> = (0..page_size * 2).map(|i| (i % 251) as u8).collect();

            let (blob, size) = context
                .open("test_partition", b"full_page_to_partial")
                .await
                .unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            append.resize(target).await.unwrap();
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"full_page_to_partial")
                .await
                .unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size().await, target);
            let read = append.read_at(0, target as usize).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &data[..target as usize]);
        });
    }

    #[test]
    fn test_resize_full_page_to_partial_survives_interrupted_crc_stage() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let page_size = PAGE_SIZE.get() as u64;
            let target = page_size + 45;
            let data: Vec<u8> = (0..page_size * 3).map(|i| (i % 251) as u8).collect();

            let (blob, size) = context
                .open("test_partition", b"full_page_to_partial_interrupted")
                .await
                .unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"full_page_to_partial_interrupted")
                .await
                .unwrap();
            let faulty_blob = PartialWriteBlob::new(blob, 1, 3);
            let write_count = faulty_blob.write_count();
            let failed_write_len = faulty_blob.failed_write_len();
            let append = Append::new(faulty_blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            assert!(
                append.resize(target).await.is_err(),
                "phase-1 partial write should fail"
            );
            assert_eq!(write_count.load(Ordering::SeqCst), 1);
            assert_eq!(failed_write_len.load(Ordering::SeqCst), CHECKSUM_SLOT_SIZE);
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"full_page_to_partial_interrupted")
                .await
                .unwrap();
            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size().await, page_size * 2);
            let read = append
                .read_at(0, (page_size * 2) as usize)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read.as_ref(), &data[..(page_size * 2) as usize]);
        });
    }

    #[test]
    fn test_resize_same_page_shrink_survives_interrupted_length_invalidation() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            const LARGE_PAGE_SIZE: NonZeroU16 = NZU16!(600);
            const LARGE_BUFFER_SIZE: usize = 1_200;

            let cache_ref =
                CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(LARGE_BUFFER_SIZE));
            let data: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();

            let (blob, size) = context
                .open(
                    "test_partition",
                    b"same_page_shrink_interrupted_len_invalidation",
                )
                .await
                .unwrap();
            let append = Append::new(blob, size, LARGE_BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            // Put the old authoritative CRC in slot 1, so the shorter CRC will be staged in slot
            // 0. The old length is above 255, so a one-byte tear changes the decoded length.
            append.append(&data[..255]).await.unwrap();
            append.sync().await.unwrap();
            append.append(&data[255..]).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            let (blob, size) = context
                .open(
                    "test_partition",
                    b"same_page_shrink_interrupted_len_invalidation",
                )
                .await
                .unwrap();
            let faulty_blob = PartialWriteBlob::new(blob, 3, 1);
            let write_count = faulty_blob.write_count();
            let failed_write_len = faulty_blob.failed_write_len();
            let append = Append::new(faulty_blob, size, LARGE_BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            assert!(
                append.resize(40).await.is_err(),
                "old-slot length invalidation should fail"
            );
            assert_eq!(write_count.load(Ordering::SeqCst), 3);
            assert_eq!(
                failed_write_len.load(Ordering::SeqCst),
                std::mem::size_of::<u16>()
            );
            drop(append);

            let (blob, size) = context
                .open(
                    "test_partition",
                    b"same_page_shrink_interrupted_len_invalidation",
                )
                .await
                .unwrap();
            let append = Append::new(blob, size, LARGE_BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size().await, 40);
            let read = append.read_at(0, 40).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &data[..40]);
        });
    }

    #[test_traced("DEBUG")]
    fn test_resize_partial_shrink_without_physical_resize_uses_range_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.sync().await.unwrap();

            let data = vec![5u8; PAGE_SIZE.get() as usize];
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            // Shrinking within the same physical page only rewrites CRC metadata.
            append.resize(50).await.unwrap();
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 4);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 4);
        });
    }

    #[test_traced("DEBUG")]
    fn test_resize_partial_shrink_with_physical_resize_clears_full_sync_requirement() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.sync().await.unwrap();

            let data = vec![9u8; PAGE_SIZE.get() as usize * 2];
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            // Shrinking from two physical pages to one partial page must also make the resize
            // durable.
            append.resize(50).await.unwrap();
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 4);
            assert_eq!(full_syncs, 2);
            assert_eq!(range_syncs, 3);

            // Once the resize barrier is cleared, the next single flush can use range sync again.
            append.append(b"x").await.unwrap();
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 5);
            assert_eq!(full_syncs, 2);
            assert_eq!(range_syncs, 4);

            let mut expected = data[..50].to_vec();
            expected.push(b'x');
            let read = append.read_at(0, expected.len()).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), expected.as_slice());
        });
    }

    #[test_traced("DEBUG")]
    fn test_resize_page_boundary_shrink_uses_full_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.sync().await.unwrap();

            // Start with two durable full pages. After clearing the wrapper barrier, the data sync
            // can persist them with one range-sync write.
            let page_size = PAGE_SIZE.get() as usize;
            let data = vec![11u8; page_size * 2];
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            // Shrinking to a page boundary resizes the blob but does not rewrite CRC metadata.
            append.resize(PAGE_SIZE.get() as u64).await.unwrap();
            append.sync().await.unwrap();

            // Only the resize needs a full sync, no additional writes are emitted by the shrink.
            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 2);
            assert_eq!(range_syncs, 1);

            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let reopened = Append::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(reopened.size().await, PAGE_SIZE.get() as u64);
            let read = reopened.read_at(0, page_size).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &data[..page_size]);
        });
    }

    #[test]
    fn test_reopen_partial_tail_append_and_resize() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            const PAGE_SIZE: NonZeroU16 = NZU16!(64);
            const BUFFER_SIZE: usize = 256;

            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(4));

            let (blob, size) = context
                .open("test_partition", b"partial_tail_test")
                .await
                .unwrap();

            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Write some initial data.
            append.append(&[1, 2, 3, 4, 5]).await.unwrap();
            append.sync().await.unwrap();
            assert_eq!(append.size().await, 5);
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"partial_tail_test")
                .await
                .unwrap();

            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size().await, 5);

            append.append(&[6, 7, 8]).await.unwrap();
            append.resize(6).await.unwrap();
            append.sync().await.unwrap();

            let data: Vec<u8> = append.read_at(0, 6).await.unwrap().coalesce().into();
            assert_eq!(data, vec![1, 2, 3, 4, 5, 6]);
        });
    }

    #[test]
    fn test_corrupted_crc_len_too_large() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let physical_page_size = PAGE_SIZE.get() as usize + CHECKSUM_SIZE as usize;

            // Step 1: Create blob with valid data
            let (blob, size) = context
                .open("test_partition", b"crc_len_test")
                .await
                .unwrap();

            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            append.append(&[0x42; 50]).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            // Step 2: Corrupt the CRC record to have len > page_size
            let (blob, size) = context
                .open("test_partition", b"crc_len_test")
                .await
                .unwrap();
            assert_eq!(size as usize, physical_page_size);

            // CRC record is at the end of the physical page
            let crc_offset = PAGE_SIZE.get() as u64;

            // Create a CRC record with len1 = 0xFFFF (65535), which is >> page_size (103)
            // Format: [len1_hi, len1_lo, crc1 (4 bytes), len2_hi, len2_lo, crc2 (4 bytes)]
            let bad_crc_record: [u8; 12] = [
                0xFF, 0xFF, // len1 = 65535 (way too large)
                0xDE, 0xAD, 0xBE, 0xEF, // crc1 (garbage)
                0x00, 0x00, // len2 = 0
                0x00, 0x00, 0x00, 0x00, // crc2 = 0
            ];
            blob.write_at(crc_offset, bad_crc_record.to_vec())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Step 3: Try to open the blob - should NOT panic, should return error or handle gracefully
            let result = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone()).await;

            // Either returns InvalidChecksum error OR truncates the corrupted data
            // (both are acceptable behaviors - panicking is NOT acceptable)
            match result {
                Ok(append) => {
                    // If it opens successfully, the corrupted page should have been truncated
                    let recovered_size = append.size().await;
                    assert_eq!(
                        recovered_size, 0,
                        "Corrupted page should be truncated, size should be 0"
                    );
                }
                Err(e) => {
                    // Error is also acceptable
                    assert!(
                        matches!(e, crate::Error::InvalidChecksum),
                        "Expected InvalidChecksum error, got: {:?}",
                        e
                    );
                }
            }
        });
    }

    #[test]
    fn test_corrupted_crc_both_slots_len_too_large() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));

            // Step 1: Create blob with valid data
            let (blob, size) = context
                .open("test_partition", b"crc_both_bad")
                .await
                .unwrap();

            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            append.append(&[0x42; 50]).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            // Step 2: Corrupt BOTH CRC slots to have len > page_size
            let (blob, size) = context
                .open("test_partition", b"crc_both_bad")
                .await
                .unwrap();

            let crc_offset = PAGE_SIZE.get() as u64;

            // Both slots have len > page_size
            let bad_crc_record: [u8; 12] = [
                0x01, 0x00, // len1 = 256 (> 103)
                0xDE, 0xAD, 0xBE, 0xEF, // crc1 (garbage)
                0x02, 0x00, // len2 = 512 (> 103)
                0xCA, 0xFE, 0xBA, 0xBE, // crc2 (garbage)
            ];
            blob.write_at(crc_offset, bad_crc_record.to_vec())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Step 3: Try to open - should NOT panic
            let result = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone()).await;

            match result {
                Ok(append) => {
                    // Corrupted page truncated
                    assert_eq!(append.size().await, 0);
                }
                Err(e) => {
                    assert!(
                        matches!(e, crate::Error::InvalidChecksum),
                        "Expected InvalidChecksum, got: {:?}",
                        e
                    );
                }
            }
        });
    }
}
