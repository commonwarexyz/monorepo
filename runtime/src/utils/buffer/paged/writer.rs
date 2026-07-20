//! Single-owner, append-only access to a [Blob].
//!
//! A [Writer] exclusively owns its blob and cannot be cloned. Appended bytes can be read back
//! immediately but are not durable until [Writer::sync].
//!
//! # Snapshot
//!
//! [Writer::snapshot] captures a logical read view without consuming the writer.
//!
//! # Paging
//!
//! Callers append and read logical bytes. The blob stores those bytes raw, so a byte's blob
//! offset equals its logical offset and the blob's size is the logical size. Appends accumulate
//! in a write buffer and reach the blob in page-aligned writes where possible. Buffered bytes
//! are readable immediately but durable only after `sync`. Full pages read from the blob are
//! cached in a shared page cache, so reads are served from the write buffer, the page cache, or
//! the blob itself. Large appends bypass the write buffer and write whole pages directly to the
//! blob.
//!
//! # Append-only writes
//!
//! Flushes write only bytes that have not yet reached the blob, so the blob is only ever
//! extended: previously written bytes are never rewritten. Integrity and crash-atomicity are
//! the storage backend's responsibility (see the storage volume), so [Writer::new]
//! trusts the blob's size as the logical size: a trailing partial page is just logical bytes
//! and seeds the write buffer so appends continue within it.
//!
//! # Raw [Blob] handles
//!
//! The [Writer] owns the page cache entries and durability bookkeeping of its [Blob]. Raw
//! handles cloned before the writer existed do not observe buffered bytes until they are
//! flushed. They must not mutate the blob while a [Writer] exists: such writes bypass the
//! write buffer and page cache.

use super::{
    read::{PageReader, Replay},
    view::View,
};
use crate::{
    buffer::{paged::CacheRef, tip::Buffer, SyncState},
    Blob, Error, Handle, IoBuf, IoBufMut, IoBufs,
};
use bytes::BufMut;
use std::num::{NonZeroU16, NonZeroUsize};
use tracing::warn;

/// Adjusts a requested write-buffer `capacity` upward to the value the buffer actually uses,
/// applying two upward adjustments:
///
/// - Rounds up to a whole multiple of `page_size`, so the buffer always holds an exact number of
///   pages. Callers can then drain and bulk-cache full pages without re-rounding the capacity.
/// - Raises the result to a floor of two pages, so the buffer can hold at least one full page of
///   new data even while caching a nearly-full page of already written data.
fn adjusted_capacity(capacity: usize, page_size: u64) -> usize {
    let page_size = page_size as usize;
    let rounded = capacity.next_multiple_of(page_size);
    let floor = page_size * 2;
    if rounded < floor {
        warn!(
            floor,
            "requested buffer capacity is too low, increasing it to floor"
        );
    }
    rounded.max(floor)
}

/// Returns whether appending `append_len` bytes should bypass the write buffer and write whole
/// pages directly: the append would overflow capacity, and at least one whole page remains to
/// write after filling the current page up to a boundary.
///
/// Larger appends bypass the buffer, so a buffered append exceeds `capacity` by less than one
/// page (given `capacity` is a whole number of pages; see [adjusted_capacity]). The write
/// buffer's peak size therefore stays under `capacity + logical_page_size`.
const fn too_big_for_buffer(
    buffer_len: usize,
    buffer_capacity: usize,
    append_len: usize,
    logical_page_size: usize,
) -> bool {
    let fill = buffer_len.next_multiple_of(logical_page_size) - buffer_len;
    let overflows_capacity = buffer_len + append_len > buffer_capacity;
    let has_full_page_after_fill = append_len >= fill + logical_page_size;

    overflows_capacity && has_full_page_after_fill
}

/// Read the partial tail page `[tail_offset, size)` of `blob`, zero-filling any prefix below
/// the blob's pruned floor. Bytes below the floor were dropped and cannot be read, so the
/// zeros stand in for them: callers honoring the floor never serve those offsets.
async fn read_partial_tail<B: Blob>(
    blob: &B,
    tail_offset: u64,
    size: u64,
) -> Result<Vec<u8>, Error> {
    let mut partial = vec![0u8; (size - tail_offset) as usize];
    let read_start = tail_offset.max(blob.floor());
    if read_start < size {
        let bytes = blob
            .read_at(read_start, (size - read_start) as usize)
            .await?
            .coalesce();
        partial[(read_start - tail_offset) as usize..].copy_from_slice(bytes.as_ref());
    }
    Ok(partial)
}

/// Unique writer to a cache-wrapped [Blob].
pub struct Writer<B: Blob> {
    /// The underlying blob being wrapped.
    blob: B,

    /// Number of logical bytes already written to the blob (the blob's current size). Flushes
    /// write only the bytes at `[written, size)`, so the blob is only ever extended, never
    /// rewritten.
    written: u64,

    /// Durability state for plain writes, resizes, and range-sync writes.
    sync_state: SyncState,

    /// Unique id assigned to this blob by the page cache.
    id: u64,

    /// A reference to the page cache that manages read caching for this blob.
    cache_ref: CacheRef,

    /// The write buffer containing any logical bytes following the last full page boundary
    /// handed to the page cache.
    buffer: Buffer,
}

impl<B: Blob> Writer<B> {
    /// Write bytes to the underlying blob and mark them as needing sync.
    async fn write_at(&mut self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        self.sync_state.write_at(&self.blob, offset, bufs).await
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
        self.sync_state
            .write_at_sync(&self.blob, offset, bufs)
            .await
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

    /// Wrap `blob` in a [Writer]. `blob` must hold exactly `blob_size` logical bytes. Reads are
    /// cached through `cache_ref` and appends stage in a write buffer of capacity `capacity`.
    /// Seeds the write buffer with the trailing partial page (if any) so appends continue
    /// within it.
    pub async fn new(
        blob: B,
        blob_size: u64,
        capacity: usize,
        cache_ref: CacheRef,
    ) -> Result<Self, Error> {
        let page_size = cache_ref.page_size();
        let capacity = adjusted_capacity(capacity, page_size);

        // The blob's size is the logical size: a trailing partial page is just logical bytes.
        // The partial page may straddle a pruned floor, in which case its pruned prefix seeds
        // as zeros (see [read_partial_tail]).
        let tail_offset = blob_size - blob_size % page_size;
        let partial_len = (blob_size - tail_offset) as usize;
        let partial_data = if partial_len > 0 {
            IoBuf::from(read_partial_tail(&blob, tail_offset, blob_size).await?)
        } else {
            IoBuf::default()
        };
        let buffer = Buffer::from(
            tail_offset,
            partial_data,
            capacity,
            cache_ref.pool().clone(),
        );

        Ok(Self {
            blob,
            written: blob_size,
            // The wrapped blob may hold writes that were never synced, so start dirty.
            sync_state: SyncState::Dirty,
            id: cache_ref.next_id(),
            cache_ref,
            buffer,
        })
    }

    /// Append all bytes in `buf` to the tip of the blob, returning the logical offset at which
    /// the first byte was written.
    pub async fn append(&mut self, buf: &[u8]) -> Result<u64, Error> {
        let logical_page_size = self.cache_ref.page_size() as usize;

        // Bypass the write buffer and write whole pages directly when `buf` is large.
        if too_big_for_buffer(
            self.buffer.len(),
            self.buffer.capacity,
            buf.len(),
            logical_page_size,
        ) {
            return self.append_owned(IoBuf::copy_from_slice(buf)).await;
        }

        let offset = self.buffer.size();
        if self.buffer.append(buf) {
            self.flush_internal(false, false).await?;
        }
        Ok(offset)
    }

    /// Append owned bytes to the tip of the blob.
    ///
    /// Large appends fill the current tip to a page boundary, write complete pages directly to the
    /// blob, and leave only a sub-page suffix in the write buffer. This avoids copying full-page
    /// payloads while preserving the invariant that the buffer starts at a page boundary.
    pub async fn append_owned(&mut self, buf: IoBuf) -> Result<u64, Error> {
        let logical_page_size = self.cache_ref.page_size() as usize;
        let offset = self.buffer.size();

        // Buffer the append unless `buf` is too big for the buffer.
        if !too_big_for_buffer(
            self.buffer.len(),
            self.buffer.capacity,
            buf.len(),
            logical_page_size,
        ) {
            if self.buffer.append(buf.as_ref()) {
                self.flush_internal(false, false).await?;
            }
            return Ok(offset);
        }

        // Bytes needed to fill current page to a page boundary (0 if already aligned).
        let fill = self.buffer.len().next_multiple_of(logical_page_size) - self.buffer.len();

        // Top up the tip to a page boundary so its contents flush as full pages.
        if fill > 0 {
            self.buffer.append(&buf.as_ref()[..fill]);
        }
        let boundary = self.buffer.size();
        if !self.buffer.is_empty() {
            self.flush_internal(false, false).await?;
            assert!(
                self.buffer.size() == boundary && self.buffer.is_empty(),
                "flush left unexpected buffered bytes before a direct-path append"
            );
        }
        assert_eq!(
            self.written, boundary,
            "an empty tip implies the blob ends at the tip boundary"
        );

        // The whole pages remaining in `buf` are written directly, without copying.
        let bulk_len = (buf.len() - fill) / logical_page_size * logical_page_size;
        let bulk = buf.slice(fill..fill + bulk_len);

        // Direct blob writes must not overtake an earlier started sync barrier.
        self.sync_state.wait_for_pending().await?;

        // Cache the pages before `replace` publishes the new size, so reads of the bulk range are
        // served from the cache while the blob write is still in flight. Insert in
        // write-buffer-sized chunks. The capacity is a whole number of pages (see
        // [adjusted_capacity]), so each chunk is page-aligned.
        let chunk_len = self.buffer.capacity;
        let mut cache_offset = boundary;
        for chunk in bulk.as_ref().chunks(chunk_len) {
            let remaining = self.cache_ref.cache(self.id, chunk, cache_offset);
            assert_eq!(remaining, 0, "cached bulk pages must be page-aligned");
            cache_offset += chunk.len() as u64;
        }

        // Update state before writing, seeding the tip with the partial-page suffix of `buf`.
        // The suffix (less than one page) is copied: a sub-page tip is never drained by flush,
        // so seeding it with a view of `buf` would pin the entire backing allocation until the
        // next append to this blob (or forever, if there is none).
        let suffix = buf.slice(fill + bulk_len..);
        let suffix = if suffix.is_empty() {
            suffix
        } else {
            let mut copied = self.cache_ref.pool().alloc(suffix.len());
            copied.put_slice(suffix.as_ref());
            copied.freeze()
        };
        self.buffer.replace(boundary + bulk_len as u64, suffix);
        self.written = boundary + bulk_len as u64;

        // Make sure the buffer offset and underlying blob agree on the state of the tip.
        assert_eq!(self.buffer.offset % self.cache_ref.page_size(), 0);

        self.write_at(boundary, bulk).await?;

        Ok(offset)
    }

    /// Flush unwritten bytes from the buffer to the blob, draining full pages from the buffer
    /// into the page cache and leaving the bytes of any final partial page buffered.
    ///
    /// The flush writes only bytes that have not yet reached the blob: everything through the
    /// last full page boundary, plus the partial tail when `write_partial_page` is true.
    /// Previously written bytes are never rewritten.
    ///
    /// If `sync` is true and the flush emits a write, that write is made durable immediately:
    /// with [`Blob::write_at_sync`] when there are no earlier unsynced mutations, or by writing
    /// it and syncing the blob when there are.
    ///
    /// Returns `true` if the flush made its writes durable, so no additional sync is needed.
    async fn flush_internal(
        &mut self,
        write_partial_page: bool,
        sync: bool,
    ) -> Result<bool, Error> {
        let logical_page_size = self.cache_ref.page_size() as usize;

        // Determine how far the flush extends the blob. If nothing new reaches the blob,
        // return early.
        let size = self.buffer.size();
        let write_end = if write_partial_page {
            size
        } else {
            size - size % logical_page_size as u64
        };
        if write_end <= self.written {
            return Ok(false);
        }

        // A flush mutates the blob, so first resolve any outstanding start_sync barrier.
        self.sync_state.wait_for_pending().await?;

        // Slice the unwritten bytes before draining repositions the buffer.
        let write_at_offset = self.written;
        let start = (write_at_offset - self.buffer.offset) as usize;
        let end = (write_end - self.buffer.offset) as usize;
        let data = self.buffer.slice(start..end);

        // Split buffered bytes into full logical pages to hand off now, leaving any trailing
        // partial page in tip for continued buffering.
        let pages_to_cache = self.buffer.len() / logical_page_size;
        let bytes_to_drain = pages_to_cache * logical_page_size;

        // Remember the logical start offset and page bytes for caching of flushed full pages.
        let cache_pages = if pages_to_cache > 0 {
            Some((self.buffer.offset, self.buffer.slice(..bytes_to_drain)))
        } else {
            None
        };

        // Drain full pages from the buffered logical data. If the tip is fully drained, detach its
        // backing so empty append buffers don't retain pooled storage.
        if bytes_to_drain == self.buffer.len() && bytes_to_drain != 0 {
            let _ = self
                .buffer
                .take()
                .expect("take must succeed when flush drains all buffered bytes");
        } else if bytes_to_drain != 0 {
            self.buffer.drop_prefix(bytes_to_drain);
            self.buffer.offset += bytes_to_drain as u64;
        }

        // Cache full pages before publishing the new blob state so reads don't observe stale
        // persisted bytes during the handoff from tip to cache.
        if let Some((cache_offset, pages)) = cache_pages {
            let remaining = self.cache_ref.cache(self.id, pages.as_ref(), cache_offset);
            assert_eq!(remaining, 0, "cached full-page prefix must be page-aligned");
        }
        assert_eq!(self.buffer.offset % logical_page_size as u64, 0);

        // Update state before writing. This may appear to risk data loss if writes fail,
        // but write failures are fatal per this codebase's design: callers must not use
        // the blob after any mutable method returns an error.
        self.written = write_end;

        // Write only the new bytes at their logical offsets.
        self.write_at_maybe_sync(write_at_offset, data, sync)
            .await?;
        Ok(sync)
    }

    /// Returns the size of the blob.
    pub const fn size(&self) -> u64 {
        self.buffer.size()
    }

    /// Returns a borrowed view over this blob.
    fn view(&self) -> View<'_, B> {
        View {
            blob: &self.blob,
            cache_ref: &self.cache_ref,
            id: self.id,
            size: self.buffer.size(),
            tail_offset: self.buffer.offset,
            tail: self.buffer.as_ref(),
        }
    }

    /// Read into `buf` if it can be done synchronously without I/O. Returns `true` only if all
    /// `buf.len()` bytes were satisfied from the page cache and/or the in-memory tail. When `false`
    /// is returned, the contents of `buf` are unspecified.
    pub fn try_read_sync_into(&self, buf: &mut [u8], offset: u64) -> bool {
        self.view().try_read_sync_into(buf, offset)
    }

    /// Read exactly `len` immutable bytes starting at `offset`.
    pub async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufs, Error> {
        self.view().read_at(offset, len).await
    }

    /// Reads up to `len` bytes starting at `offset`, but only as many as are available.
    ///
    /// Returns the buffer (truncated to actual bytes read) and the number of bytes read. Returns
    /// an error if no bytes are available at the given offset.
    pub async fn read_up_to(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufMut> + Send,
    ) -> Result<(IoBufMut, usize), Error> {
        self.view().read_up_to(offset, len, bufs).await
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
        self.view().read_many_into(buf, offsets, item_size).await
    }

    /// Like [`Self::read_many_into`], but synchronous and cache-only. Returns the indices of
    /// items that require a blob read. Their slots in `buf` hold unspecified bytes.
    pub fn try_read_many_sync_into(
        &self,
        buf: &mut [u8],
        offsets: &[u64],
        item_size: NonZeroUsize,
    ) -> Vec<usize> {
        self.view().try_read_many_sync_into(buf, offsets, item_size)
    }

    /// Like [`Self::try_read_many_sync_into`], but for variable-length `(offset, len)` ranges:
    /// `buf` holds one slot per range, back to back.
    pub fn try_read_ranges_sync_into(&self, buf: &mut [u8], ranges: &[(u64, usize)]) -> Vec<usize> {
        self.view().try_read_ranges_sync_into(buf, ranges)
    }

    /// Reads bytes starting at `offset` into `buf`.
    pub async fn read_into(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        self.view().read_into(buf, offset).await
    }

    /// Flushes any buffered data, then returns a [Replay] for the underlying blob.
    ///
    /// The returned replay can be used to sequentially read all logical bytes of the blob.
    ///
    /// This is not a durable operation. Buffered data may be plainly written so the replay can
    /// read it, but callers must still use [`sync`](Self::sync) if that data must survive a crash.
    pub async fn replay(&mut self, buffer_size: NonZeroUsize) -> Result<Replay<B>, Error> {
        let logical_page_size = self.cache_ref.page_size();
        let logical_page_size_nz =
            NonZeroU16::new(logical_page_size as u16).expect("page_size is non-zero");

        // Flush any buffered data (without fsync) so the reader sees all written data.
        self.flush_internal(true, false).await?;

        // Convert buffer size (bytes) to page count, reading at least one page per fill.
        let prefetch_pages = (buffer_size.get() / logical_page_size as usize).max(1);

        let reader = PageReader::new(
            self.blob.clone(),
            self.buffer.size(),
            prefetch_pages,
            logical_page_size_nz,
        );
        Ok(Replay::new(reader))
    }

    /// Flush buffered data and capture an immutable [`super::Sealed`] view without consuming the
    /// writer.
    ///
    /// This writes buffered bytes to the blob but does not make them durable. Call
    /// [`Self::sync`] if the returned handle's bytes must survive a crash.
    ///
    /// If this writer later rewinds or truncates into the returned handle's range, reads from that
    /// handle may observe unspecified contents.
    pub async fn snapshot(&mut self) -> Result<super::Sealed<B>, Error> {
        self.flush_internal(true, false).await?;
        Ok(self.sealed_handle())
    }

    /// Flushes buffered data and makes all pending mutations durable.
    ///
    /// A single physical write can be persisted with [`Blob::write_at_sync`]. If there
    /// are earlier unsynced mutations, durability is completed with [`Blob::sync`].
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Flush any buffered data, including any partial page.
        // An emitted write can be made durable directly during the flush.
        if self.flush_internal(true, true).await? {
            return Ok(());
        }

        // Otherwise, the flush had no bytes to write. Sync only if a durability barrier is
        // still pending.
        self.sync_state.sync(&self.blob).await
    }

    /// Flushes buffered data to the blob and stages the blob's durability
    /// with `batch`: the flushed (and any earlier unsynced) bytes become
    /// durable when the batch is applied with
    /// [`crate::WriteBatch::apply_sync`], atomically with everything else
    /// the batch stages.
    pub async fn sync_into<T: crate::WriteBatch<Blob = B>>(
        &mut self,
        batch: &mut T,
    ) -> Result<(), Error> {
        self.flush_internal(true, false).await?;
        batch.sync(&self.blob);
        Ok(())
    }

    /// Flushes buffered data and begins making all pending mutations durable, returning a
    /// completion handle.
    ///
    /// Awaiting the returned [`Handle`] waits for the same durability guarantee as [`Self::sync`]
    /// for the state flushed by this call. Later calls to [`Self::sync`] and writer methods that
    /// mutate the blob first wait for any outstanding start_sync handles.
    pub async fn start_sync(&mut self) -> Handle<()> {
        if let Err(err) = self.flush_internal(true, false).await {
            return Handle::ready(Err(err));
        }
        self.sync_state.start_sync(&self.blob).await
    }

    /// Wait for any started sync to complete without starting a new sync.
    pub async fn wait_for_sync(&mut self) -> Result<(), Error> {
        self.sync_state.wait_for_pending().await
    }

    /// Resize the blob to the provided logical `size`.
    ///
    /// # Warning
    ///
    /// - Concurrent mutable operations (append, resize) are not supported and will cause data loss.
    /// - Concurrent readers which try to read past the new size during the resize may error.
    /// - The resize is not guaranteed durable until the next sync.
    pub async fn resize(&mut self, size: u64) -> Result<(), Error> {
        let current_size = self.buffer.size();
        if size == current_size {
            return Ok(());
        }

        // Handle growing by appending zero bytes.
        if size > current_size {
            let zeros_needed = (size - current_size) as usize;
            let mut zeros = self.cache_ref.pool().alloc(zeros_needed);
            zeros.put_bytes(0, zeros_needed);
            self.append_owned(zeros.freeze()).await?;
            return Ok(());
        }

        self.shrink(size).await
    }

    /// Drop the blob's bytes below `offset` via [`Blob::prune`], flushing buffered bytes
    /// first so the blob's physical size covers `offset`. The floor is byte-exact — it
    /// becomes exactly `offset` — and its durability follows the blob's next sync (a
    /// crash may regress it to the last synced floor).
    ///
    /// Pages below the floor may linger in the shared page cache and in this writer's
    /// tip buffer, and pages straddling it re-fetch with their pruned prefix zeroed.
    /// Reads below the floor therefore serve stale or zero bytes rather than reliably
    /// failing: callers must confine reads to offsets at or above the floor.
    ///
    /// # Panics
    ///
    /// Panics if `offset` exceeds the logical size.
    pub async fn prune(&mut self, offset: u64) -> Result<(), Error> {
        assert!(
            offset <= self.buffer.size(),
            "prune beyond the logical size"
        );
        self.flush_internal(true, false).await?;
        // Pruning is a mutation: it must not race a started sync (writer exclusivity).
        self.sync_state.wait_for_pending().await?;
        self.blob.prune(offset).await
    }

    /// The blob's pruned floor: bytes below it were dropped (see [`Blob::floor`]).
    pub fn floor(&self) -> u64 {
        self.blob.floor()
    }

    /// Shrink the blob to `size` logical bytes and reposition the tip at the new tail.
    async fn shrink(&mut self, size: u64) -> Result<(), Error> {
        // Flush and persist buffered data first so the blob holds every retained byte before
        // it is truncated.
        self.sync().await?;

        // Truncate the blob to exactly the new logical size.
        self.sync_state.resize(&self.blob, size).await?;

        self.reposition_tip(size).await
    }

    /// Shrink the blob to `size` logical bytes, staging the truncation with `batch` instead of
    /// performing it: the shrink publishes (and becomes durable) when the caller applies the
    /// batch, atomically with everything else the batch stages. Buffered bytes are flushed
    /// (unsynced) first so the staged truncation covers every retained byte. When `size` equals
    /// the current size, this degrades to [`Self::sync_into`] (durability membership only).
    ///
    /// Once the resize is staged the batch is this blob's ONE writer: the caller must apply the
    /// batch before mutating this writer again.
    ///
    /// # Panics
    ///
    /// Panics if `size` exceeds the current logical size.
    pub async fn resize_into<T: crate::WriteBatch<Blob = B>>(
        &mut self,
        size: u64,
        batch: &mut T,
    ) -> Result<(), Error> {
        let current = self.buffer.size();
        assert!(size <= current, "resize_into cannot grow the blob");
        if size == current {
            return self.sync_into(batch).await;
        }

        self.sync_state.wait_for_pending().await?;
        self.flush_internal(true, false).await?;
        batch.resize(&self.blob, size).await?;

        self.reposition_tip(size).await
    }

    /// Reposition the writer's read state after a shrink to `size`.
    async fn reposition_tip(&mut self, size: u64) -> Result<(), Error> {
        // Evict cached pages at or beyond the new full-page boundary. The page at that boundary
        // (if partial) is now owned by the tip buffer, and anything above is beyond the new
        // size. Leaving their pre-resize contents in the cache lets `try_read_sync_into` (whose
        // reads below the tip boundary come straight from the page cache) observe stale bytes
        // once the tip is repopulated.
        let page_size = self.cache_ref.page_size();
        let tail_offset = size - size % page_size;
        self.cache_ref
            .invalidate_from(self.id, tail_offset / page_size);

        // Reposition the tip at the new tail so it holds the bytes of the (now possibly
        // partial) last page.
        if size >= self.buffer.offset {
            // The retained tail bytes are already buffered: truncate them in place.
            let drained = self.buffer.resize(size);
            assert!(drained.is_none(), "shrink cannot drain buffered bytes");
        } else {
            self.buffer.offset = tail_offset;
            self.buffer.clear();
            if size > tail_offset {
                let partial = read_partial_tail(&self.blob, tail_offset, size).await?;
                let over_capacity = self.buffer.append(&partial);
                assert!(!over_capacity);
            }
        }
        self.written = size;

        Ok(())
    }

    /// Page-cache id used for reads. Exposed for tests.
    #[cfg(test)]
    pub(super) const fn cache_id(&self) -> u64 {
        self.id
    }

    /// Construct an immutable read handle for the current blob state, under a fresh
    /// page-cache id: the writer keeps mutating its own cache namespace, so the handle
    /// must not share it.
    fn sealed_handle(&self) -> super::Sealed<B> {
        assert_eq!(
            self.buffer.offset % self.cache_ref.page_size(),
            0,
            "flushed tip must start on a page boundary"
        );
        let partial_page = if self.buffer.is_empty() {
            None
        } else {
            Some(self.buffer.slice(..))
        };
        super::Sealed::new(
            self.blob.clone(),
            self.buffer.size(),
            partial_page,
            self.cache_ref.clone(),
            self.cache_ref.next_id(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        buffer::tests::SyncTrackingBlob,
        deterministic,
        mocks::{next_pending_sync, DelayedSyncBlob},
        telemetry::metrics::Registry,
        Buf, BufferPool, BufferPoolConfig, IoBufsMut, Runner as _, Spawner as _, Storage as _,
        Supervisor as _,
    };
    use commonware_macros::test_traced;
    use commonware_utils::{channel::oneshot, sync::Mutex, NZUsize, NZU16, NZU32};
    use futures::FutureExt as _;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    const PAGE_SIZE: NonZeroU16 = NZU16!(103); // janky size to ensure we test page alignment
    const BUFFER_SIZE: usize = PAGE_SIZE.get() as usize * 2;

    #[test_traced("DEBUG")]
    fn test_read_many_into_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            append.append(&[0u8; 8]).await.unwrap();
            assert_eq!(append.size(), 8);

            // Empty offsets should succeed immediately.
            let mut buf = [];
            append
                .read_many_into(&mut buf, &[], NZUsize!(4))
                .await
                .unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_many_into_all_in_tip() {
        // All items reside in the unflushed tip buffer.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0..20).collect();
            append.append(&data).await.unwrap();
            assert_eq!(append.size(), 20);

            // Read 4-byte items at offsets 0, 4, 8, 12, 16.
            let offsets = [0u64, 4, 8, 12, 16];
            let mut buf = vec![0u8; 5 * 4];
            append
                .read_many_into(&mut buf, &offsets, NZUsize!(4))
                .await
                .unwrap();

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
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0..20).collect();
            append.append(&data).await.unwrap();

            let mut buf = vec![0u8; data.len()];
            assert!(append.try_read_sync_into(&mut buf, 0));
            assert_eq!(buf, data);
        });
    }

    #[test_traced("DEBUG")]
    fn test_try_read_sync_cache_miss() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"try_read_sync_cache_miss")
                .await
                .unwrap();
            // A one-page cache lets us prime the first page while leaving the second uncached.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let data: Vec<u8> = (0u8..=255).cycle().take(page_size * 2).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            let _ = append.read_at(0, page_size).await.unwrap();

            // A read straddling the cached first page and the uncached second page misses.
            let mut buf = vec![0xAA; 4];
            assert!(!append.try_read_sync_into(&mut buf, (page_size - 2) as u64));
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_many_into_all_from_cache() {
        // Sync data to disk so tip buffer is empty; reads go through page cache / blob.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0..20).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();
            assert_eq!(append.size(), 20);

            let offsets = [0u64, 8, 16];
            let mut buf = vec![0u8; 3 * 4];
            append
                .read_many_into(&mut buf, &offsets, NZUsize!(4))
                .await
                .unwrap();

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
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let first: Vec<u8> = (0..16).collect();
            append.append(&first).await.unwrap();
            append.sync().await.unwrap();

            let second: Vec<u8> = (16..32).collect();
            append.append(&second).await.unwrap();
            assert_eq!(append.size(), 32);

            // Offsets span both synced and unsynced regions.
            let offsets = [0u64, 4, 16, 24];
            let mut buf = vec![0u8; 4 * 4];
            append
                .read_many_into(&mut buf, &offsets, NZUsize!(4))
                .await
                .unwrap();

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
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            append.append(&[0u8; 8]).await.unwrap();
            assert_eq!(append.size(), 8);

            // Last offset's end (8 + 4 = 12) exceeds size (8).
            let mut buf = vec![0u8; 4];
            let err = append
                .read_many_into(&mut buf, &[8], NZUsize!(4))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::BlobInsufficientLength));
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_many_into_single_item() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data = vec![0xAA; 8];
            append.append(&data).await.unwrap();
            assert_eq!(append.size(), 8);

            let mut buf = vec![0u8; 8];
            append
                .read_many_into(&mut buf, &[0], NZUsize!(8))
                .await
                .unwrap();
            assert_eq!(&buf, &data);
        });
    }

    #[test_traced("DEBUG")]
    #[should_panic(expected = "buf must hold one slot per range totaling its length")]
    fn test_read_many_into_rejects_invalid_buffer_len() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0..16).collect();
            append.append(&data).await.unwrap();

            let offsets = [0u64, 4];
            let mut buf = vec![0u8; 7];
            let _ = append.read_many_into(&mut buf, &offsets, NZUsize!(4)).await;
        });
    }

    #[test_traced("DEBUG")]
    #[should_panic(expected = "ranges must be sorted and non-overlapping")]
    fn test_read_many_into_rejects_unsorted_offsets() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0..16).collect();
            append.append(&data).await.unwrap();

            let mut buf = vec![0u8; 8];
            let _ = append.read_many_into(&mut buf, &[8, 4], NZUsize!(4)).await;
        });
    }

    #[test_traced("DEBUG")]
    #[should_panic(expected = "ranges must be sorted and non-overlapping")]
    fn test_read_many_into_rejects_overlapping_offsets() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0..16).collect();
            append.append(&data).await.unwrap();

            let mut buf = vec![0u8; 8];
            let _ = append.read_many_into(&mut buf, &[2, 4], NZUsize!(4)).await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_many_into_rejects_offset_overflow() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0..16).collect();
            append.append(&data).await.unwrap();

            let mut buf = vec![0u8; 8];
            let err = append
                .read_many_into(&mut buf, &[u64::MAX - 1, 4], NZUsize!(4))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::OffsetOverflow));
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_many_into_matches_read_at() {
        // Verify read_many_into returns the same bytes as individual read_at calls.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rmany").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Write enough data to span multiple pages (PAGE_SIZE=103).
            let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();
            // Add more in tip buffer.
            let more: Vec<u8> = (0u8..50).collect();
            append.append(&more).await.unwrap();
            assert_eq!(append.size(), 350);

            let item_size = 10;
            let offsets: Vec<u64> = (0..35).map(|i| i * item_size as u64).collect();
            let mut batch_buf = vec![0u8; offsets.len() * item_size];
            append
                .read_many_into(&mut batch_buf, &offsets, NZUsize!(item_size))
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
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
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
                .read_many_into(&mut buf, &offsets, NZUsize!(item_size))
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
    fn test_read_many_into_straddle_prefix_miss() {
        // A straddling item whose synced prefix page is NOT in the page cache: the
        // suffix is copied from the tip buffer and the prefix is read from the blob
        // without clobbering it, and the item is counted as a blob read.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"rmany_smiss")
                .await
                .unwrap();
            // Single-page cache so residency is deterministic.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(1));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Write 3 pages and sync, then a partial page that stays in the tip.
            let synced: Vec<u8> = (0u8..=255)
                .cycle()
                .take(PAGE_SIZE.get() as usize * 3)
                .collect();
            append.append(&synced).await.unwrap();
            append.sync().await.unwrap();
            let item_size = 10;
            let tip: Vec<u8> = (100u8..=255)
                .cycle()
                .take(PAGE_SIZE.get() as usize / 2)
                .collect();
            append.append(&tip).await.unwrap();

            // Fault page 0 in, evicting whatever sync left resident, so the straddle
            // prefix page (page 2) is guaranteed not cached.
            let _ = append.read_at(0, item_size).await.unwrap();

            let straddle_off = synced.len() as u64 - (item_size as u64 / 2);
            let tip_off = synced.len() as u64 + item_size as u64;
            let offsets = [straddle_off, tip_off];
            let mut buf = vec![0u8; offsets.len() * item_size];
            let hits = append
                .read_many_into(&mut buf, &offsets, NZUsize!(item_size))
                .await
                .unwrap();

            // The tip-only item is a hit; the straddle item required a blob read.
            assert_eq!(hits, 1);
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
    fn test_append_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            // Open a new blob.
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            // Create a page cache reference.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));

            // Create a Writer.
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Verify initial size is 0.
            assert_eq!(append.size(), 0);

            // Close & re-open.
            append.sync().await.unwrap();
            drop(append);

            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0); // No data was appended, so no bytes were written.

            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            assert_eq!(append.size(), 0);
        });
    }

    #[test_traced("DEBUG")]
    fn test_append_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            // Open a new blob.
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            // Create a page cache reference.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));

            // Create a Writer.
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Verify initial size is 0.
            assert_eq!(append.size(), 0);

            // Append some bytes.
            let data = vec![1, 2, 3, 4, 5];
            append.append(&data).await.unwrap();

            // Verify size reflects appended data.
            assert_eq!(append.size(), 5);

            // Append more bytes.
            let more_data = vec![6, 7, 8, 9, 10];
            append.append(&more_data).await.unwrap();

            // Verify size is cumulative.
            assert_eq!(append.size(), 10);

            // Read back the first chunk and verify.
            let read_buf = append.read_at(0, 5).await.unwrap().coalesce();
            assert_eq!(read_buf, &data[..]);

            // Read back the second chunk and verify.
            let read_buf = append.read_at(5, 5).await.unwrap().coalesce();
            assert_eq!(read_buf, &more_data[..]);

            // Read all data at once and verify.
            let read_buf = append.read_at(0, 10).await.unwrap().coalesce();
            assert_eq!(read_buf, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

            // Close and reopen the blob and make sure the data is still there.
            append.sync().await.unwrap();
            drop(append);

            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            // A partial page occupies exactly its logical bytes.
            assert_eq!(blob_size, 10);
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size(), 10);

            // Append data that spans a page boundary.
            // PAGE_SIZE=103 is the logical page size. We have 10 bytes, so writing
            // 100 more bytes (total 110) will cross the page boundary at byte 103.
            let spanning_data: Vec<u8> = (11..=110).collect();
            append.append(&spanning_data).await.unwrap();
            assert_eq!(append.size(), 110);

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
            // The blob holds exactly the logical bytes.
            assert_eq!(blob_size, 110);
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size(), 110);

            // Append data to reach exactly a page boundary.
            // Logical page size is 103. We have 110 bytes, next boundary is 206 (103 * 2).
            // So we need 96 more bytes.
            let boundary_data: Vec<u8> = (111..=206).collect();
            assert_eq!(boundary_data.len(), 96);
            append.append(&boundary_data).await.unwrap();
            assert_eq!(append.size(), 206);

            // Verify we can read it back.
            let read_buf = append.read_at(0, 206).await.unwrap().coalesce();
            let expected: Vec<u8> = (1..=206).collect();
            assert_eq!(read_buf, &expected[..]);

            // Drop and re-open at the page boundary.
            append.sync().await.unwrap();
            drop(append);

            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            // The blob ends exactly at the page boundary: 103 * 2 = 206 bytes.
            assert_eq!(blob_size, 206);
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), 206);

            // Verify data is still readable after reopen.
            let read_buf = append.read_at(0, 206).await.unwrap().coalesce();
            assert_eq!(read_buf, &expected[..]);
        });
    }

    #[test_traced("DEBUG")]
    fn test_append_owned_bypass_from_empty_tip() {
        // A large owned append from an empty, page-aligned tip writes whole pages directly to the
        // blob and leaves the partial-page suffix buffered.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"owned_empty")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // 500 bytes = 4 full pages (412 bytes) + 88-byte remainder.
            let data: Vec<u8> = (0..500).map(|i| (i % 251) as u8).collect();
            let src = IoBuf::from(data.clone());
            let src_start = src.as_ptr() as usize;
            let src_range = src_start..src_start + src.len();
            append.append_owned(src.clone()).await.unwrap();
            assert_eq!(append.size(), 500);

            // The buffered suffix is a copy, not a view that would pin the input allocation.
            let tip_ptr = append.buffer.as_ref().as_ptr() as usize;
            assert!(!src_range.contains(&tip_ptr));

            // The directly written pages populate the page cache, exactly as a buffered flush
            // would.
            let mut probe = vec![0u8; PAGE_SIZE.get() as usize];
            assert_eq!(
                append.cache_ref.read_cached(append.id, &mut probe, 0),
                PAGE_SIZE.get() as usize
            );
            assert_eq!(probe, &data[..PAGE_SIZE.get() as usize]);

            // All bytes are readable before any sync (bulk from the cache, suffix from tip).
            let read_buf = append.read_at(0, 500).await.unwrap().coalesce();
            assert_eq!(read_buf, &data[..]);

            // Everything becomes durable with a single sync.
            append.sync().await.unwrap();
            drop(append);

            let (blob, blob_size) = context
                .open("test_partition", b"owned_empty")
                .await
                .unwrap();
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), 500);
            let read_buf = append.read_at(0, 500).await.unwrap().coalesce();
            assert_eq!(read_buf, &data[..]);
        });
    }

    #[test_traced("DEBUG")]
    fn test_append_owned_bypass_with_synced_partial_page() {
        // A large owned append on top of a synced partial page must first flush the fill bytes
        // that complete the partial page before writing the bulk directly.
        let all: Vec<u8> = (0..500).map(|i| (i % 247) as u8).collect();
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover({
            let all = all.clone();
            |context: deterministic::Context| async move {
                let (blob, blob_size) = context
                    .open("test_partition", b"owned_partial")
                    .await
                    .unwrap();
                let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
                let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                    .await
                    .unwrap();

                // Durably write a 50-byte partial page.
                append.append(&all[..50]).await.unwrap();
                append.sync().await.unwrap();

                // 450 more bytes: 53 fill the first page, 3 whole pages (309 bytes) bypass the
                // buffer, 88 remain in the tip.
                append
                    .append_owned(IoBuf::from(all[50..].to_vec()))
                    .await
                    .unwrap();
                assert_eq!(append.size(), 500);
                let read_buf = append.read_at(0, 500).await.unwrap().coalesce();
                assert_eq!(read_buf, &all[..]);
            }
        });

        // The direct write is not durable until sync: a crash without one preserves only the
        // synced 50-byte prefix.
        deterministic::Runner::from(checkpoint).start(|context: deterministic::Context| {
            async move {
                let (blob, blob_size) = context
                    .open("test_partition", b"owned_partial")
                    .await
                    .unwrap();
                let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
                let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                    .await
                    .unwrap();
                assert_eq!(append.size(), 50);
                let read_buf = append.read_at(0, 50).await.unwrap().coalesce();
                assert_eq!(read_buf, &all[..50]);

                // Repeating the owned append after recovery and syncing makes everything durable,
                // exercising the fill path for the recovered partial page.
                append
                    .append_owned(IoBuf::from(all[50..].to_vec()))
                    .await
                    .unwrap();
                append.sync().await.unwrap();
                drop(append);

                let (blob, blob_size) = context
                    .open("test_partition", b"owned_partial")
                    .await
                    .unwrap();
                let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                    .await
                    .unwrap();
                assert_eq!(append.size(), 500);
                let read_buf = append.read_at(0, 500).await.unwrap().coalesce();
                assert_eq!(read_buf, &all[..]);
            }
        });
    }

    #[test_traced("DEBUG")]
    fn test_append_owned_bypass_with_buffered_tip() {
        // A large owned append merges with unsynced buffered bytes: the fill completes the
        // current page, the bulk bypasses the buffer, and everything is readable.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"owned_buffered")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            let all: Vec<u8> = (0..430).map(|i| (i % 239) as u8).collect();
            append.append(&all[..30]).await.unwrap();
            append
                .append_owned(IoBuf::from(all[30..].to_vec()))
                .await
                .unwrap();
            assert_eq!(append.size(), 430);
            let read_buf = append.read_at(0, 430).await.unwrap().coalesce();
            assert_eq!(read_buf, &all[..]);

            append.sync().await.unwrap();
            drop(append);

            let (blob, blob_size) = context
                .open("test_partition", b"owned_buffered")
                .await
                .unwrap();
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), 430);
            let read_buf = append.read_at(0, 430).await.unwrap().coalesce();
            assert_eq!(read_buf, &all[..]);
        });
    }

    #[test_traced("DEBUG")]
    fn test_append_owned_exact_page_multiple_and_small() {
        // An owned append of an exact page multiple leaves an empty tip that later buffered and
        // small owned appends continue from; small owned appends use the buffered path.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"owned_exact")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Exactly 4 pages: no remainder.
            let bulk: Vec<u8> = (0..412).map(|i| (i % 233) as u8).collect();
            append
                .append_owned(IoBuf::from(bulk.clone()))
                .await
                .unwrap();
            assert_eq!(append.size(), 412);

            // A small owned append takes the buffered path.
            let small: Vec<u8> = (0..10).map(|i| (i % 229) as u8).collect();
            append
                .append_owned(IoBuf::from(small.clone()))
                .await
                .unwrap();
            assert_eq!(append.size(), 422);

            let read_buf = append.read_at(0, 422).await.unwrap().coalesce();
            assert_eq!(&read_buf.as_ref()[..412], &bulk[..]);
            assert_eq!(&read_buf.as_ref()[412..], &small[..]);

            append.sync().await.unwrap();
            drop(append);

            let (blob, blob_size) = context
                .open("test_partition", b"owned_exact")
                .await
                .unwrap();
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), 422);
        });
    }

    #[test_traced("DEBUG")]
    fn test_append_owned_physical_bytes_match_buffered() {
        // The direct path must produce byte-identical blob contents to the buffered path for
        // the same logical content.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let data: Vec<u8> = (0..500).map(|i| (i % 251) as u8).collect();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));

            let (blob, size) = context
                .open("test_partition", b"phys_direct")
                .await
                .unwrap();
            let mut direct = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            direct
                .append_owned(IoBuf::from(data.clone()))
                .await
                .unwrap();
            direct.sync().await.unwrap();
            drop(direct);

            // Small appends always stay on the buffered path and force intermediate flushes.
            let (blob, size) = context
                .open("test_partition", b"phys_buffered")
                .await
                .unwrap();
            let mut buffered = Writer::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            for chunk in data.chunks(10) {
                buffered.append(chunk).await.unwrap();
            }
            buffered.sync().await.unwrap();
            drop(buffered);

            let (blob_a, size_a) = context
                .open("test_partition", b"phys_direct")
                .await
                .unwrap();
            let (blob_b, size_b) = context
                .open("test_partition", b"phys_buffered")
                .await
                .unwrap();
            assert_eq!(size_a, size_b);
            let bytes_a = blob_a.read_at(0, size_a as usize).await.unwrap().coalesce();
            let bytes_b = blob_b.read_at(0, size_b as usize).await.unwrap().coalesce();
            assert_eq!(bytes_a.as_ref(), bytes_b.as_ref());
        });
    }

    #[test_traced("DEBUG")]
    fn test_append_borrowed_large_takes_direct_path() {
        // A plain `append` larger than the write buffer is routed through the direct path, so the
        // write buffer holds only the partial-page suffix afterwards instead of the whole input.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"borrowed_large")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Start misaligned with a small buffered prefix.
            let all: Vec<u8> = (0..530).map(|i| (i % 241) as u8).collect();
            append.append(&all[..30]).await.unwrap();

            // 500 more bytes exceed the 206-byte write buffer and take the direct path.
            append.append(&all[30..]).await.unwrap();
            assert_eq!(append.size(), 530);

            // Only the partial-page suffix remains buffered (530 = 5 full pages + 15 bytes).
            assert_eq!(append.buffer.len(), 15);

            let read_buf = append.read_at(0, 530).await.unwrap().coalesce();
            assert_eq!(read_buf, &all[..]);

            append.sync().await.unwrap();
            drop(append);

            let (blob, blob_size) = context
                .open("test_partition", b"borrowed_large")
                .await
                .unwrap();
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), 530);
            let read_buf = append.read_at(0, 530).await.unwrap().coalesce();
            assert_eq!(read_buf, &all[..]);
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

            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
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
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
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
            let reopened = Writer::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let read = reopened.read_at(0, data.len()).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), data);
        });
    }

    #[test_traced("DEBUG")]
    // Verifies a successful start_sync marks the writer clean.
    fn test_start_sync_persists_and_marks_clean() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // A fresh writer is dirty, so start_sync does one full fsync; nothing is buffered to write.
            let handle = writer.start_sync().await;
            // Let the started sync finish.
            handle.await.unwrap();
            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 0);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 0);

            // Now clean, so the next write syncs just its range instead of the whole blob.
            let data = b"hello world";
            writer.append(data).await.unwrap();
            writer.sync().await.unwrap();
            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 1);

            // Nothing left to sync, so start_sync does nothing.
            let handle = writer.start_sync().await;
            handle.await.unwrap();
            let (_, _, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 1);

            // Durable and readable after reopening.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let reopened = Writer::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let read = reopened.read_at(0, data.len()).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), data);
        });
    }

    #[test_traced("DEBUG")]
    // Verifies sync waits for a pending start_sync with no new writes.
    fn test_sync_waits_for_outstanding_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let inner = SyncTrackingBlob::new();
            let (blob, pending) = DelayedSyncBlob::new(inner.clone());
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, 0, BUFFER_SIZE, cache_ref).await.unwrap();

            let handle = writer.start_sync().await;
            let deferred = next_pending_sync(&pending);

            // Try to sync while the started sync is still blocked.
            let mut sync = Box::pin(writer.sync());
            assert!(
                sync.as_mut().now_or_never().is_none(),
                "sync must wait for the outstanding start_sync handle"
            );
            drop(sync);
            let (_, _, full_syncs, range_syncs) = inner.snapshot();
            assert_eq!(full_syncs, 0);
            assert_eq!(range_syncs, 0);

            // Release the started sync and retry.
            deferred.release.send(Ok(())).unwrap();
            writer.sync().await.unwrap();
            handle.await.unwrap();
            let (_, _, full_syncs, range_syncs) = inner.snapshot();
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 0);
        });
    }

    #[test_traced("DEBUG")]
    // Verifies a small buffered write cannot range-sync before pending start_sync finishes.
    fn test_sync_after_start_sync_and_small_write_waits_before_range_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let inner = SyncTrackingBlob::new();
            let (blob, pending) = DelayedSyncBlob::new(inner.clone());
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, 0, BUFFER_SIZE, cache_ref).await.unwrap();

            let handle = writer.start_sync().await;
            let deferred = next_pending_sync(&pending);
            writer.append(b"hello world").await.unwrap();

            // Sync must wait before flushing the buffered write.
            let mut sync = Box::pin(writer.sync());
            assert!(
                sync.as_mut().now_or_never().is_none(),
                "sync must join the outstanding barrier before flushing the small write"
            );
            drop(sync);
            let (_, writes, full_syncs, range_syncs) = inner.snapshot();
            assert_eq!(writes, 0);
            assert_eq!(full_syncs, 0);
            assert_eq!(range_syncs, 0);

            // Release the started sync, then flush the buffered write.
            deferred.release.send(Ok(())).unwrap();
            writer.sync().await.unwrap();
            handle.await.unwrap();
            let (_, writes, full_syncs, range_syncs) = inner.snapshot();
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 1);
        });
    }

    #[test_traced("DEBUG")]
    // Verifies a large append cannot flush before pending start_sync finishes.
    fn test_write_flush_waits_for_outstanding_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let inner = SyncTrackingBlob::new();
            let (blob, pending) = DelayedSyncBlob::new(inner.clone());
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, 0, BUFFER_SIZE, cache_ref).await.unwrap();

            let handle = writer.start_sync().await;
            let deferred = next_pending_sync(&pending);

            let data = vec![7; BUFFER_SIZE + PAGE_SIZE.get() as usize];
            let append = context.child("append").spawn(move |_| async move {
                writer.append(&data).await.unwrap();
                writer
            });
            // The append has reached the pending sync wait.
            deferred
                .blocked
                .await
                .expect("append never waited on start_sync");
            let (_, writes, full_syncs, range_syncs) = inner.snapshot();
            assert_eq!(writes, 0);
            assert_eq!(full_syncs, 0);
            assert_eq!(range_syncs, 0);

            // Release the started sync so the append can flush.
            deferred.release.send(Ok(())).unwrap();
            let mut writer = append.await.unwrap();
            handle.await.unwrap();
            writer.sync().await.unwrap();
            let (_, writes, full_syncs, _) = inner.snapshot();
            assert!(writes > 0);
            assert!(full_syncs > 0);
        });
    }

    #[test_traced("DEBUG")]
    // Verifies snapshot cannot flush buffered bytes before pending start_sync finishes.
    fn test_snapshot_waits_for_outstanding_start_sync_before_flushing() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let inner = SyncTrackingBlob::new();
            let (blob, pending) = DelayedSyncBlob::new(inner.clone());
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, 0, BUFFER_SIZE, cache_ref).await.unwrap();

            // Start a sync, then buffer newer bytes not covered by it.
            let prior = writer.start_sync().await;
            let deferred = next_pending_sync(&pending);
            writer.append(b"hello world").await.unwrap();

            let snapshot = context.child("snapshot").spawn(move |_| async move {
                let snapshot = writer.snapshot().await.unwrap();
                let read = snapshot
                    .read_at(0, b"hello world".len())
                    .await
                    .unwrap()
                    .coalesce();
                assert_eq!(read.as_ref(), b"hello world");
                writer
            });

            // Snapshot must wait before flushing buffered bytes.
            deferred
                .blocked
                .await
                .expect("snapshot never waited on start_sync");
            let (_, writes, full_syncs, range_syncs) = inner.snapshot();
            assert_eq!(writes, 0);
            assert_eq!(full_syncs, 0);
            assert_eq!(range_syncs, 0);

            // Releasing the sync lets snapshot flush and read the buffered bytes.
            deferred.release.send(Ok(())).unwrap();
            let _writer = snapshot.await.unwrap();
            prior.await.unwrap();
            let (_, writes, full_syncs, range_syncs) = inner.snapshot();
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 0);
        });
    }

    #[test_traced("DEBUG")]
    // Verifies replay cannot flush buffered bytes before pending start_sync finishes.
    fn test_replay_waits_for_outstanding_start_sync_before_flushing() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let inner = SyncTrackingBlob::new();
            let (blob, pending) = DelayedSyncBlob::new(inner.clone());
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, 0, BUFFER_SIZE, cache_ref).await.unwrap();

            // Start a sync, then buffer newer bytes not covered by it.
            let prior = writer.start_sync().await;
            let deferred = next_pending_sync(&pending);
            writer.append(b"hello world").await.unwrap();

            let replay = context.child("replay").spawn(move |_| async move {
                {
                    let mut replay = writer.replay(NZUsize!(BUFFER_SIZE)).await.unwrap();
                    assert!(replay.ensure(1).await.unwrap());
                    assert_eq!(replay.chunk()[0], b'h');
                }
                writer
            });

            // Replay must wait before flushing buffered bytes.
            deferred
                .blocked
                .await
                .expect("replay never waited on start_sync");
            let (_, writes, full_syncs, range_syncs) = inner.snapshot();
            assert_eq!(writes, 0);
            assert_eq!(full_syncs, 0);
            assert_eq!(range_syncs, 0);

            // Releasing the sync lets replay flush and read the buffered bytes.
            deferred.release.send(Ok(())).unwrap();
            let _writer = replay.await.unwrap();
            prior.await.unwrap();
            let (_, writes, full_syncs, range_syncs) = inner.snapshot();
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 0);
        });
    }

    #[test_traced("DEBUG")]
    // Verifies resize growth cannot write zeros before pending start_sync finishes.
    fn test_resize_grow_waits_for_outstanding_start_sync_before_writing() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let inner = SyncTrackingBlob::new();
            let (blob, pending) = DelayedSyncBlob::new(inner.clone());
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, 0, BUFFER_SIZE, cache_ref).await.unwrap();

            // Start a sync before growing into the direct-write path.
            let prior = writer.start_sync().await;
            let deferred = next_pending_sync(&pending);

            let target_size = (BUFFER_SIZE + PAGE_SIZE.get() as usize) as u64;
            let resize = context.child("resize_grow").spawn(move |_| async move {
                writer.resize(target_size).await.unwrap();
                writer
            });

            // Growth must wait before writing zero-filled pages.
            deferred
                .blocked
                .await
                .expect("resize grow never waited on start_sync");
            let (_, writes, full_syncs, range_syncs) = inner.snapshot();
            assert_eq!(writes, 0);
            assert_eq!(full_syncs, 0);
            assert_eq!(range_syncs, 0);

            // Releasing the sync lets the resize complete.
            deferred.release.send(Ok(())).unwrap();
            let mut writer = resize.await.unwrap();
            prior.await.unwrap();
            assert_eq!(writer.size(), target_size);
            writer.sync().await.unwrap();
            let (_, writes, full_syncs, _) = inner.snapshot();
            assert!(writes > 0);
            assert!(full_syncs > 0);
        });
    }

    #[test_traced("DEBUG")]
    // Verifies shrink cannot resize the blob before pending start_sync finishes.
    fn test_resize_shrink_waits_for_outstanding_start_sync_before_resizing() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let inner = SyncTrackingBlob::new();
            let (blob, pending) = DelayedSyncBlob::new(inner.clone());
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, 0, BUFFER_SIZE, cache_ref).await.unwrap();

            // Build durable pages, then start a sync for a newer partial page.
            let data = vec![3; PAGE_SIZE.get() as usize * 2];
            writer.append(&data).await.unwrap();
            writer.sync().await.unwrap();
            writer.append(b"x").await.unwrap();
            let prior = writer.start_sync().await;
            let deferred = next_pending_sync(&pending);
            let physical_size = inner.size();

            let resize = context.child("resize_shrink").spawn(move |_| async move {
                writer.resize(PAGE_SIZE.get() as u64).await.unwrap();
                writer
            });

            // Shrink must wait before truncating the physical blob.
            deferred
                .blocked
                .await
                .expect("resize shrink never waited on start_sync");
            assert_eq!(
                inner.size(),
                physical_size,
                "resize must not shrink the blob before the pending sync finishes"
            );

            // Releasing the sync lets the shrink truncate the blob.
            deferred.release.send(Ok(())).unwrap();
            let writer = resize.await.unwrap();
            prior.await.unwrap();
            assert_eq!(writer.size(), PAGE_SIZE.get() as u64);
            assert!(inner.size() < physical_size);
        });
    }

    #[test_traced("DEBUG")]
    fn test_sync_failed_range_sync_does_not_mark_clean() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Keep the write buffered so sync flushes it with a durability step.
            append.append(b"abc").await.unwrap();

            // Fail the flush's durability barrier: the bytes land but are not
            // durable. A fresh writer starts dirty, so the flush uses a write
            // followed by a full sync.
            blob.fail_next_sync();
            assert!(append.sync().await.is_err());

            // The failed durability step must leave the writer dirty, so the next
            // sync issues a full durability barrier instead of reporting clean.
            append.sync().await.unwrap();
            let (durable, _, full_syncs, _) = blob.snapshot();
            assert_eq!(durable.len() as u64, blob.size());
            assert_eq!(full_syncs, 1);
        });
    }

    #[test_traced("DEBUG")]
    fn test_sync_uses_full_sync_after_prior_plain_flush() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
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

            // The writer is clean again, so the next partial-tip flush is a single write that
            // can be range-synced.
            append.append(b"tip").await.unwrap();
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 3);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 1);

            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let reopened = Writer::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
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
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
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
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
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
            let mut reopened = Writer::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(reopened.size(), b"replayed".len() as u64);
            reopened.sync().await.unwrap();

            let (durable, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(durable.len(), blob.size() as usize);
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 0);
        });
    }

    #[test_traced("DEBUG")]
    // Verifies the blob's size is the truth on open: trailing bytes are logical data (no
    // scanning, no truncation), a trailing partial page seeds the tip, and appends continue
    // within it.
    fn test_reopen_size_is_truth() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(b"valid").await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            // Bytes written directly to the blob are logical data like any other.
            blob.write_at(blob.size(), b"junk").await.unwrap();
            blob.sync().await.unwrap();

            let (_, writes_before, _, _) = blob.snapshot();
            let mut reopened = Writer::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(reopened.size(), b"validjunk".len() as u64);
            let read = reopened.read_at(0, 9).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"validjunk");

            // Appends continue within the trailing partial page: syncing writes only the new
            // byte at its logical offset.
            reopened.append(b"!").await.unwrap();
            reopened.sync().await.unwrap();

            let (durable, writes_after, _, _) = blob.snapshot();
            assert_eq!(writes_after, writes_before + 1);
            assert_eq!(durable, b"validjunk!");
        });
    }

    #[test_traced("DEBUG")]
    // Verifies that extending a synced partial page writes only the new suffix bytes at their
    // logical offsets: one write per sync, never a rewrite of the committed prefix.
    fn test_sync_extends_partial_page_with_suffix_only() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.sync().await.unwrap();

            // Establish a persisted partial page, then extend it twice.
            append.append(b"abc").await.unwrap();
            append.sync().await.unwrap();
            append.append(b"de").await.unwrap();
            append.sync().await.unwrap();
            append.append(b"fg").await.unwrap();
            append.sync().await.unwrap();

            // Each sync emitted exactly one range-synced write of the new bytes.
            let (durable, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(durable, b"abcdefg");
            assert_eq!(writes, 3);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 3);

            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let reopened = Writer::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let read = reopened.read_at(0, 7).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), b"abcdefg");
        });
    }

    /// Blob wrapper that records the byte range of every write.
    #[derive(Clone)]
    struct RecordingBlob<B: Blob> {
        inner: B,
        writes: Arc<Mutex<Vec<(u64, u64)>>>,
    }

    impl<B: Blob> RecordingBlob<B> {
        fn new(inner: B) -> Self {
            Self {
                inner,
                writes: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn record(&self, offset: u64, bufs: &IoBufs) {
            self.writes.lock().push((offset, bufs.remaining() as u64));
        }

        fn writes(&self) -> Vec<(u64, u64)> {
            self.writes.lock().clone()
        }
    }

    impl<B: Blob> crate::Blob for RecordingBlob<B> {
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
            self.record(offset, &bufs);
            self.inner.write_at(offset, bufs).await
        }

        async fn write_at_sync(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
        ) -> Result<(), Error> {
            let bufs = bufs.into();
            self.record(offset, &bufs);
            self.inner.write_at_sync(offset, bufs).await
        }

        async fn prune(&self, offset: u64) -> Result<(), Error> {
            self.inner.prune(offset).await
        }

        fn floor(&self) -> u64 {
            self.inner.floor()
        }

        async fn resize(&self, len: u64) -> Result<(), Error> {
            self.inner.resize(len).await
        }

        async fn sync(&self) -> Result<(), Error> {
            self.inner.sync().await
        }

        async fn start_sync(&self) -> Handle<()> {
            self.inner.start_sync().await
        }
    }

    #[test_traced("DEBUG")]
    // Verifies every write a [Writer] emits starts exactly at the end of the previously written
    // bytes: appends never rewrite a byte that already reached the blob (the volume backend
    // relies on this to avoid copy-on-write of frozen bytes).
    fn test_flush_writes_are_append_pure() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (inner, blob_size) = context
                .open("test_partition", b"append_pure")
                .await
                .unwrap();
            let blob = RecordingBlob::new(inner);
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob.clone(), blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Interleave small appends, syncs, a large direct-path append, and a replay flush.
            let data: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
            writer.append(&data[..10]).await.unwrap();
            writer.sync().await.unwrap();
            writer.append(&data[10..50]).await.unwrap();
            writer.sync().await.unwrap();
            writer.append(&data[50..300]).await.unwrap();
            writer.append(&data[300..900]).await.unwrap();
            writer.sync().await.unwrap();
            writer.append(&data[900..]).await.unwrap();
            {
                let mut replay = writer.replay(NZUsize!(BUFFER_SIZE)).await.unwrap();
                assert!(replay.ensure(data.len()).await.unwrap());
            }
            writer.sync().await.unwrap();

            // The writes must tile [0, data.len()) exactly: each starts at the frontier the
            // previous one advanced.
            let mut frontier = 0u64;
            for (offset, len) in blob.writes() {
                assert_eq!(offset, frontier, "write rewrote already-written bytes");
                frontier += len;
            }
            assert_eq!(frontier, data.len() as u64);

            // And the logical bytes read back intact.
            let read = writer.read_at(0, data.len()).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &data[..]);
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

            // Create a Writer and write some data.
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
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

    /// Blob wrapper that delays one selected read after capturing its current bytes.
    #[derive(Clone)]
    struct DelayedReadBlob<B: Blob> {
        inner: B,
        offset: u64,
        len: usize,
        reads: Arc<AtomicUsize>,
        started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
        release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    }

    impl<B: Blob> DelayedReadBlob<B> {
        fn new(
            inner: B,
            offset: u64,
            len: usize,
            started: oneshot::Sender<()>,
            release: oneshot::Receiver<()>,
        ) -> Self {
            Self {
                inner,
                offset,
                len,
                reads: Arc::new(AtomicUsize::new(0)),
                started: Arc::new(Mutex::new(Some(started))),
                release: Arc::new(Mutex::new(Some(release))),
            }
        }
    }

    impl<B: Blob> crate::Blob for DelayedReadBlob<B> {
        async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
            if offset == self.offset
                && len == self.len
                && self.reads.fetch_add(1, Ordering::SeqCst) == 0
            {
                let bytes = self.inner.read_at(offset, len).await?;

                let sender = self
                    .started
                    .lock()
                    .take()
                    .expect("delayed read start signal consumed more than once");
                let _ = sender.send(());

                let release = self
                    .release
                    .lock()
                    .take()
                    .expect("delayed read release receiver consumed more than once");
                release.await.expect("release signal dropped");

                return Ok(bytes);
            }

            self.inner.read_at(offset, len).await
        }

        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
        ) -> Result<IoBufsMut, Error> {
            if offset == self.offset
                && len == self.len
                && self.reads.fetch_add(1, Ordering::SeqCst) == 0
            {
                let bytes = self.inner.read_at_buf(offset, len, bufs).await?;

                let sender = self
                    .started
                    .lock()
                    .take()
                    .expect("delayed read start signal consumed more than once");
                let _ = sender.send(());

                let release = self
                    .release
                    .lock()
                    .take()
                    .expect("delayed read release receiver consumed more than once");
                release.await.expect("release signal dropped");

                return Ok(bytes);
            }

            self.inner.read_at_buf(offset, len, bufs).await
        }

        async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
            self.inner.write_at(offset, bufs).await
        }

        async fn write_at_sync(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
        ) -> Result<(), Error> {
            self.inner.write_at_sync(offset, bufs).await
        }

        async fn prune(&self, offset: u64) -> Result<(), Error> {
            self.inner.prune(offset).await
        }

        fn floor(&self) -> u64 {
            self.inner.floor()
        }

        async fn resize(&self, len: u64) -> Result<(), Error> {
            self.inner.resize(len).await
        }

        async fn sync(&self) -> Result<(), Error> {
            self.inner.sync().await
        }

        async fn start_sync(&self) -> Handle<()> {
            self.inner.start_sync().await
        }
    }

    #[test]
    fn test_resize_invalidates_cache() {
        // Regression: shrinking a blob across a page boundary must drop cached pages for the
        // truncated region. Before the fix, `try_read_sync_into` (whose reads below the tip
        // boundary come straight from the page cache)
        // would observe pre-resize bytes at offsets later reclaimed by new appends.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let (blob, blob_size) = context
                .open("test_partition", b"resize_invalidates_cache")
                .await
                .unwrap();
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
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
            assert!(append.try_read_sync_into(&mut probe, 0));
            assert_eq!(probe, vec![0xAAu8; 16]);

            // Rewind to 0 (crossing the page boundary) and append a new, distinct pattern.
            append.resize(0).await.unwrap();
            let new_bytes = vec![0xBBu8; 16];
            append.append(&new_bytes).await.unwrap();

            // The cache must not serve pre-resize bytes. Either try_read_sync_into misses (cache
            // was invalidated) or it returns the new pattern; it must never return 0xAA.
            let mut probe = vec![0u8; 16];
            let hit = append.try_read_sync_into(&mut probe, 0);
            assert!(
                !hit || probe == new_bytes,
                "try_read_sync_into served stale pre-resize bytes: {probe:?}"
            );
        });
    }

    #[test]
    fn test_snapshot_fetch_cannot_repopulate_live_cache_after_resize() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let page_size = PAGE_SIZE.get() as usize;
            let (inner, blob_size) = context
                .open("test_partition", b"snapshot_resize_cache")
                .await
                .unwrap();
            let (started_tx, started_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let blob =
                DelayedReadBlob::new(inner, page_size as u64, page_size, started_tx, release_rx);
            let mut writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let old_page0 = vec![0x11u8; page_size];
            let old_page1 = vec![0x22u8; page_size];
            writer.append(&old_page0).await.unwrap();
            writer.append(&old_page1).await.unwrap();
            writer.sync().await.unwrap();

            writer.cache_ref.invalidate_from(writer.id, 1);

            let snapshot = writer.snapshot().await.unwrap();
            let snapshot_task = context
                .child("snapshot")
                .spawn(move |_| async move { snapshot.read_at(page_size as u64, page_size).await });
            started_rx.await.expect("snapshot read never started");

            writer.resize(page_size as u64).await.unwrap();
            let new_page1 = vec![0x33u8; page_size];
            writer.append(&new_page1).await.unwrap();
            writer.sync().await.unwrap();

            let _ = release_tx.send(());
            let stale = snapshot_task
                .await
                .expect("snapshot task failed")
                .expect("snapshot read failed")
                .coalesce();
            assert_eq!(stale.as_ref(), old_page1.as_slice());

            let mut probe = vec![0u8; page_size];
            assert!(writer.try_read_sync_into(&mut probe, page_size as u64));
            assert_eq!(probe, new_page1);
        });
    }

    #[test]
    fn test_resize_shrink_allowed_while_snapshot_alive() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let (blob, blob_size) = context
                .open("test_partition", b"snapshot_blocks_shrink")
                .await
                .unwrap();
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let data: Vec<u8> = (0u8..=255).cycle().take(page_size * 2 + 7).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            let snapshot = append.snapshot().await.unwrap();
            let snapshot_clone = snapshot.clone();
            let snapshot_size = snapshot.size();

            let read = snapshot.read_at(0, data.len()).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), data.as_slice());

            // Growing appends after the snapshot's frozen range, so it cannot invalidate it.
            append.resize(snapshot_size + 3).await.unwrap();
            assert_eq!(append.size(), snapshot_size + 3);

            // Shrinking while old handles exist is allowed. Those handles remain memory-safe, but
            // future reads from ranges reused by the writer are unspecified.
            append.resize(snapshot_size - 1).await.unwrap();
            assert_eq!(append.size(), snapshot_size - 1);
            assert_eq!(snapshot_clone.size(), snapshot_size);
        });
    }

    #[test]
    fn test_snapshot_read_many_into_matches_read_at() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let (blob, blob_size) = context
                .open("test_partition", b"snapshot_read_many")
                .await
                .unwrap();
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let item_size = 4;
            let page_size = PAGE_SIZE.get() as usize;
            let total = page_size * 3 + 13;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            let snapshot = append.snapshot().await.unwrap();
            let offsets = [
                0,
                (page_size - item_size) as u64,
                (page_size + 5) as u64,
                (page_size * 3 + 2) as u64,
            ];
            // Cover page-aligned, boundary-crossing, and snapshot-tail reads in one batch.
            let mut batch = vec![0u8; offsets.len() * item_size];
            snapshot
                .read_many_into(&mut batch, &offsets, NZUsize!(item_size))
                .await
                .unwrap();

            for (item, offset) in batch.chunks_exact(item_size).zip(offsets) {
                let single = snapshot
                    .read_at(offset, item_size)
                    .await
                    .unwrap()
                    .coalesce();
                assert_eq!(item, single.as_ref());
                assert_eq!(item, &data[offset as usize..offset as usize + item_size]);
            }
        });
    }

    #[test]
    fn test_snapshot_try_read_sync_prefers_snapshot_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let (blob, blob_size) = context
                .open("test_partition", b"snapshot_try_read_tail")
                .await
                .unwrap();
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            append.append(&vec![0xAA; page_size]).await.unwrap();
            append.sync().await.unwrap();

            let tail = b"oldtail";
            append.append(tail).await.unwrap();
            let snapshot = append.snapshot().await.unwrap();

            let poison = vec![0xBB; page_size];
            // If the snapshot consulted the page cache for its tail, this would leak in.
            assert_eq!(
                append.cache_ref.cache(append.id, &poison, page_size as u64),
                0
            );

            let mut read = vec![0; tail.len()];
            assert!(snapshot.try_read_sync_into(&mut read, page_size as u64));
            assert_eq!(read.as_slice(), tail);
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
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            append.append(b"hello world").await.unwrap();
            assert_eq!(append.size(), 11);

            // Resize to same size. Should succeed.
            append.resize(11).await.unwrap();
            assert_eq!(append.size(), 11);

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
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Create a durable partial page, then shrink within it.
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            append.resize(45).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"same_page_shrink")
                .await
                .unwrap();
            let append = Writer::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), 45);
            let read = append.read_at(0, 45).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &data[..45]);
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
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            append.resize(target).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"full_page_to_partial")
                .await
                .unwrap();
            let append = Writer::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), target);
            let read = append.read_at(0, target as usize).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &data[..target as usize]);
        });
    }

    #[test_traced("DEBUG")]
    // Verifies shrinking is a plain blob resize: no bytes are rewritten, and the resize is
    // made durable by the next sync.
    fn test_resize_shrink_is_plain_resize() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.sync().await.unwrap();

            let data = vec![5u8; PAGE_SIZE.get() as usize];
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            // Shrinking to a mid-page size truncates the blob without writing any bytes. The
            // truncation needs a full barrier on the next sync.
            append.resize(50).await.unwrap();
            assert_eq!(blob.size(), 50);
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 2);
            assert_eq!(range_syncs, 1);

            // The next flush appends from the new tail with a single range-synced write.
            append.append(b"x").await.unwrap();
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 2);
            assert_eq!(full_syncs, 2);
            assert_eq!(range_syncs, 2);

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
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.sync().await.unwrap();

            // Start with two durable full pages. After clearing the wrapper barrier, the data sync
            // can persist them with one range-sync write.
            let page_size = PAGE_SIZE.get() as usize;
            let data = vec![11u8; page_size * 2];
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            // Shrinking to a page boundary resizes the blob without writing any bytes.
            append.resize(PAGE_SIZE.get() as u64).await.unwrap();
            append.sync().await.unwrap();

            // Only the resize needs a full sync, no additional writes are emitted by the shrink.
            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 2);
            assert_eq!(range_syncs, 1);

            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let reopened = Writer::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(reopened.size(), PAGE_SIZE.get() as u64);
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

            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Write some initial data.
            append.append(&[1, 2, 3, 4, 5]).await.unwrap();
            append.sync().await.unwrap();
            assert_eq!(append.size(), 5);
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"partial_tail_test")
                .await
                .unwrap();

            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size(), 5);

            append.append(&[6, 7, 8]).await.unwrap();
            append.resize(6).await.unwrap();
            append.sync().await.unwrap();

            let data: Vec<u8> = append.read_at(0, 6).await.unwrap().coalesce().into();
            assert_eq!(data, vec![1, 2, 3, 4, 5, 6]);
        });
    }

    /// Readers observe buffered (not yet flushed) bytes through both async and sync read paths.
    #[test_traced("DEBUG")]
    fn test_reader_sees_buffered_bytes() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rdr_buf").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data: Vec<u8> = (0u8..50).collect();
            writer.append(&data).await.unwrap();

            // No flush or sync has happened; reads must still see the buffered bytes.
            assert_eq!(writer.size(), 50);
            let read = writer.read_at(0, 50).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), data.as_slice());

            let mut buf = vec![0u8; 10];
            assert!(writer.try_read_sync_into(&mut buf, 20));
            assert_eq!(buf, data[20..30]);
        });
    }

    /// A resize racing a reader yields clean errors or valid pre/post-resize bytes, never
    /// out-of-bounds garbage.
    #[test_traced("DEBUG")]
    fn test_reader_read_past_resize_errors_cleanly() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context.open("test_partition", b"rdr_rsz").await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let data: Vec<u8> = (0u8..=255).cycle().take(page_size * 2).collect();
            writer.append(&data).await.unwrap();
            writer.sync().await.unwrap();
            assert_eq!(writer.size(), (page_size * 2) as u64);

            // Shrink below the last observed size.
            let new_size = (page_size / 2) as u64;
            writer.resize(new_size).await.unwrap();

            // Reads past the new size fail cleanly.
            let err = writer
                .read_at(new_size, page_size)
                .await
                .expect_err("read past resized end must fail");
            assert!(matches!(err, crate::Error::BlobInsufficientLength));

            // Reads within the new size return the retained prefix, not stale cached bytes.
            let read = writer
                .read_at(0, new_size as usize)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read.as_ref(), &data[..new_size as usize]);
        });
    }
}
