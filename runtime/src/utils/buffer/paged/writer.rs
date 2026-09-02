//! Single-owner, append-only access to a [Blob].
//!
//! A [Writer] exclusively owns its blob and cannot be cloned. Appended bytes can be read back
//! immediately but are not durable until a sync completes ([Writer::sync], or the handles
//! returned by [Writer::start_sync] and [Writer::seal]).
//!
//! # Snapshot
//!
//! [Writer::snapshot] captures a logical read view without consuming the writer.
//!
//! # Seal
//!
//! [Writer::seal] consumes the writer, returning an immutable [super::Sealed] view plus a
//! completion handle for the sync it starts.
//!
//! # Paging
//!
//! Callers append and read logical bytes; the blob stores physical pages in the format described
//! in [`super`]. Appends accumulate in a write buffer and reach the blob in pages. Buffered bytes
//! are readable immediately but durable only after `sync`. Full pages read from the blob are
//! cached in a shared page cache, so reads are served from the write buffer, the page cache, or
//! the blob itself. Large appends bypass the write buffer and write whole pages directly to the
//! blob.
//!
//! # Checksums
//!
//! Each physical page ends in a two-slot CRC record. The slots let a partial page be rewritten
//! without clobbering its last durable contents, so an interrupted write loses at most unsynced
//! bytes. [Writer::new] backs up over any trailing bytes not covered by a valid checksum,
//! treating them as an incomplete write.
//!
//! # Raw [Blob] handles
//!
//! The [Writer] owns the page layout, page cache entries, and durability bookkeeping of its
//! [Blob]. Raw handles cloned before the writer existed see physical bytes, including CRC
//! records, and do not observe buffered bytes until they are flushed. They must not mutate the
//! blob while a [Writer] exists: such writes bypass the write buffer and page cache and can
//! invalidate checksum recovery.

use super::{
    read::{PageReader, Replay},
    view::View,
};
use crate::{
    Blob, Error, Handle, IoBuf, IoBufMut, IoBufs, ReadOptions, WriteOptions,
    buffer::{
        SyncState,
        paged::{ActiveChecksum, CHECKSUM_SIZE, CacheRef, Checksum, Slot},
        tip::Buffer,
    },
};
use bytes::BufMut;
use commonware_cryptography::Crc32;
use commonware_utils::Widen;
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
/// buffer's peak size therefore stays under `capacity + page_size`.
const fn too_big_for_buffer(
    buffer_len: usize,
    buffer_capacity: usize,
    append_len: usize,
    page_size: usize,
) -> bool {
    let fill = buffer_len.next_multiple_of(page_size) - buffer_len;
    let overflows_capacity = buffer_len + append_len > buffer_capacity;
    let has_full_page_after_fill = append_len >= fill + page_size;

    overflows_capacity && has_full_page_after_fill
}

/// Unique writer to a cache-wrapped [Blob].
pub struct Writer<B: Blob> {
    /// The underlying blob being wrapped.
    blob: B,

    /// The page where the next appended byte will be written to.
    current_page: u64,

    /// The active checksum of the partial page in the blob, if any.
    partial_page_state: Option<ActiveChecksum>,

    /// The durable checksum of the page a partial-page flush would rewrite, if any.
    ///
    /// Rewrites preserve this slot byte-identically so a torn rewrite can never lose the page's
    /// last durable contents. It trails [Self::partial_page_state] until a completed sync proves
    /// the flushed state durable: an unsynced flush ([Self::replay], [Self::snapshot]) must not
    /// advance it, or a later rewrite would evict the durable checksum and a crash cutting both
    /// writes could leave no slot covering the synced prefix.
    durable_page_state: Option<ActiveChecksum>,

    /// Durability state for plain writes, resizes, and range-sync writes.
    sync_state: SyncState,

    /// Unique id assigned to this blob by the page cache.
    id: u64,

    /// A reference to the page cache that manages read caching for this blob.
    cache_ref: CacheRef,

    /// The write buffer containing any logical bytes following the last full page boundary in the
    /// underlying blob.
    buffer: Buffer,
}

impl<B: Blob> Writer<B> {
    /// Wrap `blob` in a [Writer]. `blob` must already hold `original_blob_size` physical bytes;
    /// reads are cached through `cache_ref` and appends stage in a write buffer of capacity
    /// `capacity`. Rewinds the blob if necessary so it only contains checksum-validated data.
    ///
    /// The blob's tail-page contents must be durable (freshly opened after a crash, or synced
    /// since the last partial-page rewrite): the discovered checksum slot seeds the writer's
    /// durable-slot tracking, so wrapping a blob whose tail rewrite is still volatile would
    /// let a later unsynced flush overwrite the only durable slot.
    pub async fn new(
        blob: B,
        original_blob_size: u64,
        capacity: usize,
        cache_ref: CacheRef,
    ) -> Result<Self, Error> {
        let page_size: u64 = cache_ref.page_size().widen();
        let (partial_page_state, pages, invalid_data_found) =
            Self::read_last_valid_page(&blob, original_blob_size, page_size).await?;
        if invalid_data_found {
            // Invalid data was detected, trim it from the blob.
            let new_blob_size = pages * (page_size + CHECKSUM_SIZE);
            warn!(
                original_blob_size,
                new_blob_size, "truncating blob to remove invalid data"
            );
            blob.resize(new_blob_size).await?;
            blob.sync().await?;
        }

        let capacity = adjusted_capacity(capacity, page_size);
        let needs_sync = !invalid_data_found; // ensure pending writes on the wrapped blob are synced

        let (current_page, partial_page_state, partial_data) = match partial_page_state {
            Some((partial_page, crc_record)) => (pages - 1, Some(crc_record), Some(partial_page)),
            None => (pages, None, None),
        };

        let buffer = Buffer::from(
            current_page * page_size,
            partial_data.unwrap_or_default(),
            capacity,
            cache_ref.pool().clone(),
        );

        Ok(Self {
            blob,
            current_page,
            partial_page_state,
            durable_page_state: partial_page_state,
            sync_state: if needs_sync {
                SyncState::Dirty
            } else {
                SyncState::Clean
            },
            id: cache_ref.next_id(),
            cache_ref,
            buffer,
        })
    }

    /// Scans backwards from the end of the blob, stopping when it finds a valid page.
    ///
    /// # Returns
    ///
    /// A tuple of `(partial_page, page_count, invalid_data_found)`:
    ///
    /// - `partial_page`: If the last valid page is partial (contains fewer than `page_size` logical
    ///   bytes), returns `Some((data, checksum))` containing the logical data and its active
    ///   checksum.
    ///   Returns `None` if the last valid page is full or if no valid pages exist.
    ///
    /// - `page_count`: The number of pages in the blob up to and including the last valid page
    ///   found (whether or not it's partial). Note that it's possible earlier pages may be invalid
    ///   since this function stops scanning when it finds one valid page.
    ///
    /// - `invalid_data_found`: `true` if there are any bytes in the blob that follow the last valid
    ///   page. Typically the blob should be resized to eliminate them since their integrity cannot
    ///   be guaranteed.
    async fn read_last_valid_page(
        blob: &B,
        blob_size: u64,
        page_size: u64,
    ) -> Result<(Option<(IoBuf, ActiveChecksum)>, u64, bool), Error> {
        let physical_page_size = page_size + CHECKSUM_SIZE;
        let partial_bytes = blob_size % physical_page_size;
        let mut last_page_end = blob_size - partial_bytes;

        // If the last physical page in the blob is truncated, it can't have a valid CRC record and
        // must be invalid.
        let mut invalid_data_found = partial_bytes != 0;

        while last_page_end != 0 {
            // Read the last page and parse its CRC record.
            // A valid full page remains disk-authoritative and may be read again after startup.
            let page_start = last_page_end - physical_page_size;
            let buf = blob
                .read_at(
                    page_start,
                    physical_page_size as usize,
                    ReadOptions::default(),
                )
                .await?
                .coalesce()
                .freeze();

            match Checksum::validate_page(buf.as_ref()) {
                Some(checksum) => {
                    // Found a valid page.
                    let len = checksum.len as u64;
                    if len != page_size {
                        // The page is partial (logical data doesn't fill the page).
                        let logical_bytes = buf.slice(..len as usize);
                        return Ok((
                            Some((logical_bytes, checksum)),
                            last_page_end / physical_page_size,
                            invalid_data_found,
                        ));
                    }
                    // The page is full.
                    return Ok((None, last_page_end / physical_page_size, invalid_data_found));
                }
                None => {
                    // The page is invalid.
                    last_page_end = page_start;
                    invalid_data_found = true;
                }
            }
        }

        // No valid page exists in the blob.
        Ok((None, 0, invalid_data_found))
    }

    /// Append all bytes in `buf` to the tip of the blob, returning the logical offset at which
    /// the first byte was written.
    pub async fn append(&mut self, buf: &[u8]) -> Result<u64, Error> {
        let page_size: usize = self.cache_ref.page_size().widen();

        // Bypass the write buffer and write whole pages directly when `buf` is large.
        if too_big_for_buffer(
            self.buffer.len(),
            self.buffer.capacity,
            buf.len(),
            page_size,
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
    /// payloads while preserving the invariant that the buffer starts at `current_page`.
    pub async fn append_owned(&mut self, buf: IoBuf) -> Result<u64, Error> {
        let page_size: usize = self.cache_ref.page_size().widen();
        let offset = self.buffer.size();

        // Buffer the append unless `buf` is too big for the buffer.
        if !too_big_for_buffer(
            self.buffer.len(),
            self.buffer.capacity,
            buf.len(),
            page_size,
        ) {
            if self.buffer.append(buf.as_ref()) {
                self.flush_internal(false, false).await?;
            }
            return Ok(offset);
        }

        // Bytes needed to fill current page to a page boundary (0 if already aligned).
        let fill = self.buffer.len().next_multiple_of(page_size) - self.buffer.len();

        // Top up the tip to a page boundary so its contents flush as full pages, leaving any
        // partial-page CRC handling to the regular flush path.
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

        // Prepare physical pages for the whole pages remaining in `buf` without copying logical
        // payload bytes.
        let bulk_len = (buf.len() - fill) / page_size * page_size;
        let bulk = buf.slice(fill..fill + bulk_len);
        let mut physical_pages = IoBufs::default();
        self.append_full_pages(&bulk, None, &mut physical_pages);

        assert!(
            self.partial_page_state.is_none(),
            "an empty tip implies no partial page state"
        );

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
        self.current_page += (bulk_len / page_size) as u64;
        let suffix = buf.slice(fill + bulk_len..);
        let suffix = if suffix.is_empty() {
            suffix
        } else {
            let mut copied = self.cache_ref.pool().alloc(suffix.len());
            copied.put_slice(suffix.as_ref());
            copied.freeze()
        };
        self.buffer.replace(boundary + bulk_len as u64, suffix);

        // Make sure the buffer offset and underlying blob agree on the state of the tip.
        let page_size: u64 = self.cache_ref.page_size().widen();
        assert_eq!(self.current_page * page_size, self.buffer.offset);

        let physical_page_size = page_size + CHECKSUM_SIZE;
        let write_at_offset = boundary / page_size * physical_page_size;
        self.sync_state
            .write_at(
                &self.blob,
                write_at_offset,
                physical_pages,
                WriteOptions::DONT_CACHE,
            )
            .await?;

        Ok(offset)
    }

    /// Whether a partial page of `partial_len` bytes needs a write when `full_pages` full
    /// pages precede it in the same flush and `flushed` is the last flushed partial state: an
    /// empty tip never writes, a moved tip always writes, and an unmoved tip writes only when
    /// its length changed.
    fn partial_page_dirty(
        full_pages: usize,
        partial_len: usize,
        flushed: Option<&ActiveChecksum>,
    ) -> bool {
        partial_len != 0
            && (full_pages > 0 || flushed.is_none_or(|state| state.len as usize != partial_len))
    }

    /// Whether a flush would emit any physical page write.
    fn has_flush_work(&self, write_partial_page: bool) -> bool {
        let page_size: usize = self.cache_ref.page_size().widen();
        let full_pages = self.buffer.len() / page_size;
        if full_pages > 0 {
            return true;
        }
        write_partial_page
            && Self::partial_page_dirty(
                full_pages,
                self.buffer.len() % page_size,
                self.partial_page_state.as_ref(),
            )
    }

    /// Flush all full pages from the buffer to disk, resetting the buffer to contain only the bytes
    /// in any final partial page.
    ///
    /// If `write_partial_page` is true, the partial page will be written to the blob as well along
    /// with a CRC record.
    ///
    /// A flush emits one write covering whole physical pages. A previously written partial page
    /// is rewritten in full, preserving its durable bytes and protected checksum slot.
    ///
    /// If `sync` is true, the emitted write is made durable immediately. When an earlier mutation
    /// is pending, the write is followed by a blob sync instead of relying on per-write durability.
    ///
    /// Returns `true` if the flush made its writes durable, so no additional sync is needed.
    async fn flush_internal(
        &mut self,
        write_partial_page: bool,
        sync: bool,
    ) -> Result<bool, Error> {
        // If there's nothing to write, return early without observing any pending barrier (an
        // empty start_sync must remain a cheap re-observation of the in-flight sync).
        if !self.has_flush_work(write_partial_page) {
            return Ok(false);
        }

        // A flush mutates the blob, so first resolve any outstanding start_sync barrier. Once
        // no unsynced mutation remains, the last flushed partial state is durable and becomes
        // the checksum the rewrite below must preserve.
        self.sync_state.wait_for_pending().await?;
        if self.sync_state.is_clean() {
            self.durable_page_state = self.partial_page_state;
        }

        // Prepare the *physical* pages corresponding to the data in the buffer. Rewrites
        // preserve the durable checksum, not merely the last flushed one: an unsynced flush
        // (replay, snapshot) may have rewritten the partial page with no barrier, and a torn
        // later rewrite must still leave the durable contents recoverable.
        let (physical_pages, partial_page_state) = self.to_physical_pages(
            &self.buffer,
            write_partial_page,
            self.partial_page_state.as_ref(),
            self.durable_page_state.as_ref(),
        );
        assert!(
            !physical_pages.is_empty(),
            "flush work predicate must match physical page construction"
        );

        // Split buffered bytes into full logical pages to hand off now, leaving any trailing
        // partial page in tip for continued buffering.
        let page_size: usize = self.cache_ref.page_size().widen();
        let pages_to_cache = self.buffer.len() / page_size;
        let bytes_to_drain = pages_to_cache * page_size;

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
        let new_offset = self.buffer.offset;

        // Cache full pages before publishing the new blob state so reads don't observe stale
        // persisted bytes during the handoff from tip to cache.
        if let Some((cache_offset, pages)) = cache_pages {
            let remaining = self.cache_ref.cache(self.id, pages.as_ref(), cache_offset);
            assert_eq!(remaining, 0, "cached full-page prefix must be page-aligned");
        }

        let physical_page_size = page_size + CHECKSUM_SIZE as usize;
        let write_at_offset = self.current_page * physical_page_size as u64;

        // Update state before writing. This may appear to risk data loss if writes fail,
        // but write failures are fatal per this codebase's design: callers must not use
        // the blob after any mutable method returns an error.
        self.current_page += pages_to_cache as u64;
        self.partial_page_state = partial_page_state;
        self.durable_page_state = if sync {
            // The write below is made durable before this flush returns.
            partial_page_state
        } else if pages_to_cache > 0 {
            // The tip moved to a page with no durable contents to preserve yet.
            None
        } else {
            self.durable_page_state
        };

        // Make sure the buffer offset and underlying blob agree on the state of the tip.
        let page_size: u64 = self.cache_ref.page_size().widen();
        assert_eq!(self.current_page * page_size, new_offset);

        // Rewriting a physical page resubmits its durable bytes and protected checksum
        // unchanged, so a torn write leaves the durable state recoverable.
        if sync {
            self.sync_state
                .write_at(
                    &self.blob,
                    write_at_offset,
                    physical_pages,
                    WriteOptions::SYNC | WriteOptions::DONT_CACHE,
                )
                .await?;
        } else {
            self.sync_state
                .write_at(
                    &self.blob,
                    write_at_offset,
                    physical_pages,
                    WriteOptions::DONT_CACHE,
                )
                .await?;
        }
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

    /// Prepare physical-page writes from buffered logical bytes.
    ///
    /// Each physical page contains one logical page plus CRC record. If the last page is not yet
    /// full, it will be included only if `include_partial_page` is true.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The buffer containing logical page data
    /// * `include_partial_page` - Whether to include a partial page if one exists
    /// * `flushed` - The active checksum of the last flushed partial page, if any. Used only to
    ///   detect a partial page with nothing new to write.
    /// * `durable` - The durable checksum of the page being rewritten, if any. When present, the
    ///   first page's CRC record preserves it in its original slot and places the new checksum
    ///   in the other slot.
    ///
    /// Returns the physical pages to write and, for any included partial page, its new active
    /// checksum.
    fn to_physical_pages(
        &self,
        buffer: &Buffer,
        include_partial_page: bool,
        flushed: Option<&ActiveChecksum>,
        durable: Option<&ActiveChecksum>,
    ) -> (IoBufs, Option<ActiveChecksum>) {
        let page_size: usize = self.cache_ref.page_size().widen();
        let physical_page_size = page_size + CHECKSUM_SIZE as usize;
        let pages_to_write = buffer.len() / page_size;
        let mut write_buffer = IoBufs::default();
        let buffer_data = buffer.as_ref();

        if pages_to_write > 0 {
            self.append_full_pages(
                &buffer.slice(..pages_to_write * page_size),
                durable,
                &mut write_buffer,
            );
        }

        if !include_partial_page {
            return (write_buffer, None);
        }

        let partial_page = &buffer_data[pages_to_write * page_size..];
        if !Self::partial_page_dirty(pages_to_write, partial_page.len(), flushed) {
            return (write_buffer, None);
        }
        let partial_len = partial_page.len();
        let crc = Crc32::checksum(partial_page);

        // For partial pages: if this is the first page and there's a durable CRC, preserve it.
        // Otherwise just use the new CRC in slot 0.
        let durable = if pages_to_write == 0 { durable } else { None };
        let (crc_record, active_checksum) =
            Self::build_crc_record(partial_len as u16, crc, durable);

        // A persisted partial page still occupies one full physical page:
        // [partial logical bytes, zero padding, crc record].
        let mut padded = self.cache_ref.pool().alloc(physical_page_size);
        padded.put_slice(partial_page);
        let zero_count = page_size - partial_len;
        if zero_count > 0 {
            padded.put_bytes(0, zero_count);
        }
        padded.put_slice(&crc_record.to_bytes());
        write_buffer.append(padded.freeze());

        (write_buffer, Some(active_checksum))
    }

    /// Appends each page of `data` to `write_buffer` in on-disk format: its payload (a zero-copy
    /// slice of `data`) followed by a CRC record.
    ///
    /// `data.len()` must be a non-zero multiple of the page size. When `old_checksum` is present,
    /// the first page's record preserves it in its original slot.
    fn append_full_pages(
        &self,
        data: &IoBuf,
        old_checksum: Option<&ActiveChecksum>,
        write_buffer: &mut IoBufs,
    ) {
        let page_size: usize = self.cache_ref.page_size().widen();
        let pages = data.len() / page_size;
        debug_assert!(pages > 0);
        debug_assert_eq!(data.len() % page_size, 0);
        let page_size_u16 =
            u16::try_from(page_size).expect("page size must fit in u16 for CRC record");

        // Build CRC bytes for full pages once. Full-page payload bytes are appended below as
        // slices from `data`, so we avoid copying logical payload here.
        let mut crcs = self.cache_ref.pool().alloc(CHECKSUM_SIZE as usize * pages);
        let data_bytes = data.as_ref();
        for page in 0..pages {
            let start_read_idx = page * page_size;
            let end_read_idx = start_read_idx + page_size;
            let logical_page = &data_bytes[start_read_idx..end_read_idx];
            let crc = Crc32::checksum(logical_page);

            // For the first page, if there's an old partial page CRC, construct the record
            // to preserve the old CRC in its original slot.
            let old_checksum = if page == 0 { old_checksum } else { None };
            let (crc_record, _) = Self::build_crc_record(page_size_u16, crc, old_checksum);
            crcs.put_slice(&crc_record.to_bytes());
        }
        let crc_blob = crcs.freeze();

        // Physical full-page layout is [logical_page_bytes, crc_record_bytes].
        for page in 0..pages {
            let start_read_idx = page * page_size;
            let end_read_idx = start_read_idx + page_size;
            write_buffer.append(data.slice(start_read_idx..end_read_idx));

            let crc_start = page * CHECKSUM_SIZE as usize;
            write_buffer.append(crc_blob.slice(crc_start..crc_start + CHECKSUM_SIZE as usize));
        }
    }

    /// Build a CRC record and identify its active checksum. An old checksum remains in its original
    /// slot while the new checksum is placed in the other slot.
    const fn build_crc_record(
        new_len: u16,
        new_crc: u32,
        old_checksum: Option<&ActiveChecksum>,
    ) -> (Checksum, ActiveChecksum) {
        let Some(old_checksum) = old_checksum else {
            return (
                Checksum::new(new_len, new_crc),
                ActiveChecksum::new(Slot::First, new_len, new_crc),
            );
        };

        let new_slot = old_checksum.slot.other();
        let record = match old_checksum.slot {
            Slot::First => Checksum {
                len1: old_checksum.len,
                crc1: old_checksum.crc,
                len2: new_len,
                crc2: new_crc,
            },
            Slot::Second => Checksum {
                len1: new_len,
                crc1: new_crc,
                len2: old_checksum.len,
                crc2: old_checksum.crc,
            },
        };
        (record, ActiveChecksum::new(new_slot, new_len, new_crc))
    }

    /// Durably rewrite a committed page to a shorter partial length.
    async fn sync_partial_page_shrink(
        &mut self,
        page: u64,
        page_size: u64,
        new_len: u16,
        new_crc: u32,
        old_checksum: &ActiveChecksum,
    ) -> Result<ActiveChecksum, Error> {
        // Recovery chooses the valid slot with the larger length. While shrinking, the new
        // checksum must be made durable without becoming authoritative until the old longer slot
        // can be disabled. The sequence below therefore lets recovery observe either the old page
        // or the new shorter page, but not a footer where both slots were damaged by one torn write.
        let physical_page_size = page_size
            .checked_add(CHECKSUM_SIZE)
            .ok_or(Error::OffsetOverflow)?;
        let crc_start = page
            .checked_mul(physical_page_size)
            .and_then(|start| start.checked_add(page_size))
            .ok_or(Error::OffsetOverflow)?;
        let old_slot = old_checksum.slot;
        let new_slot = old_slot.other();

        // Stage the new slot with a 0 length and the shrunken page CRC. A crash here leaves the
        // old slot as the only non-zero valid slot.
        let new_slot_offset = crc_start
            .checked_add(new_slot.offset() as u64)
            .ok_or(Error::OffsetOverflow)?;
        let staged_slot = Checksum::slot_bytes(0, new_crc);
        self.sync_state
            .write_at(
                &self.blob,
                new_slot_offset,
                staged_slot.to_vec(),
                WriteOptions::SYNC | WriteOptions::DONT_CACHE,
            )
            .await?;

        // Publish the new shrunken length. If a crash happens before the old slot is invalidated,
        // both slots may be valid, but recovery still chooses the old longer length.
        let published_len = Checksum::slot_len_bytes(new_len);
        self.sync_state
            .write_at(
                &self.blob,
                new_slot_offset,
                published_len.to_vec(),
                WriteOptions::SYNC | WriteOptions::DONT_CACHE,
            )
            .await?;

        // Clear the old slot entirely. The write stays within the old slot, so it cannot damage
        // the already-durable shorter checksum, and zeroing the CRC alongside the length keeps a
        // later torn rewrite of this page from reassembling the retired longer checksum over the
        // pre-shrink bytes still on the page. Once this lands, the shrunken slot wins.
        let old_slot_offset = crc_start
            .checked_add(old_slot.offset() as u64)
            .ok_or(Error::OffsetOverflow)?;
        self.sync_state
            .write_at(
                &self.blob,
                old_slot_offset,
                Checksum::slot_bytes(0, 0).to_vec(),
                WriteOptions::SYNC | WriteOptions::DONT_CACHE,
            )
            .await?;

        Ok(ActiveChecksum::new(new_slot, new_len, new_crc))
    }

    /// Flushes any buffered data, then returns a [Replay] for the underlying blob.
    ///
    /// The returned replay can be used to sequentially read all pages from the blob while ensuring
    /// all data passes integrity verification. CRCs are validated but not included in the output.
    /// Every underlying blob read performed by the returned replay uses `read_options`, including
    /// refills after seeking.
    ///
    /// This is not a durable operation. Buffered data may be plainly written so the replay can
    /// read it, but callers must still use [`sync`](Self::sync) if that data must survive a crash.
    pub async fn replay(
        &mut self,
        buffer_size: NonZeroUsize,
        read_options: ReadOptions,
    ) -> Result<Replay<B>, Error> {
        let page_size_nz = self.cache_ref.page_size();
        let page_size: u64 = page_size_nz.widen();

        // Flush any buffered data (without fsync) so the reader sees all written data.
        self.flush_internal(true, false).await?;

        // Convert buffer size (bytes) to page count
        let physical_page_size = page_size + CHECKSUM_SIZE;
        let prefetch_pages = buffer_size.get() / physical_page_size as usize;
        let prefetch_pages = prefetch_pages.max(1); // At least 1 page

        // Compute both physical and logical blob sizes.
        let (physical_blob_size, logical_blob_size) = self.partial_page_state.as_ref().map_or_else(
            || {
                // All pages are full.
                let physical = physical_page_size * self.current_page;
                let logical = page_size * self.current_page;
                (physical, logical)
            },
            |checksum| {
                // There's a partial page with a checksum.
                let partial_len = checksum.len as u64;
                // Physical: all pages including the partial one (which is padded to full size).
                let physical = physical_page_size * (self.current_page + 1);
                // Logical: full pages before this + partial page's actual data length.
                let logical = page_size * self.current_page + partial_len;
                (physical, logical)
            },
        );

        let reader = PageReader::new(
            self.blob.clone(),
            physical_blob_size,
            logical_blob_size,
            prefetch_pages,
            page_size_nz,
            read_options,
        );
        Ok(Replay::new(reader))
    }

    /// Flush buffered data and capture an immutable [`super::Sealed`] view without consuming the
    /// writer.
    ///
    /// This writes buffered bytes to the blob layout but does not make them durable. Call
    /// [`Self::sync`] if the returned handle's bytes must survive a crash.
    ///
    /// If this writer later rewinds or truncates into the returned handle's range, reads from that
    /// handle may observe unspecified contents.
    pub async fn snapshot(&mut self) -> Result<super::Sealed<B>, Error> {
        self.flush_internal(true, false).await?;
        Ok(self.sealed_handle(self.cache_ref.next_id()))
    }

    /// Flushes buffered data and makes all pending mutations durable.
    ///
    /// A newly flushed write can carry [`WriteOptions::SYNC`] when no earlier mutation is pending.
    /// Otherwise, [`Blob::sync`] provides the barrier for all pending mutations.
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Flush any buffered data, including any partial page. A flush that writes to the blob
        // makes that write durable itself and returns true.
        if self.flush_internal(true, true).await? {
            return Ok(());
        }

        // The flush had nothing to write. Sync only if a durability barrier is still pending.
        // Everything flushed is durable once it completes.
        self.sync_state.sync(&self.blob).await?;
        self.durable_page_state = self.partial_page_state;
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

    /// Length of the longest contiguous prefix of well-formed pages on the blob.
    ///
    /// [`Self::new`] sizes a blob by scanning backward to its last valid page, which cannot
    /// detect an earlier page that was lost or corrupted. This scans forward instead, stopping
    /// at the first invalid or short page.
    ///
    /// Expects all appended bytes to have reached the blob (as after recovery): a partial page
    /// still buffered in this writer is unreadable from the blob and fails the scan. `buffer_size`
    /// bounds each blob read, with a minimum of one physical page. Applies `read_options` to
    /// every blob read.
    ///
    /// `proven` is a logical byte offset already known valid (a durability watermark or a
    /// replay-validated prefix). Pages wholly below it are accepted without reading, and the
    /// scan starts at the page containing it. A proof past the blob's content clamps to the
    /// full pages that exist, so a partial tail is still read rather than credited as full.
    pub async fn recoverable_prefix_len(
        &self,
        proven: u64,
        buffer_size: NonZeroUsize,
        read_options: ReadOptions,
    ) -> Result<u64, Error> {
        let logical_page_size: u64 = self.cache_ref.page_size().widen();
        let total_pages = self.current_page + u64::from(self.partial_page_state.is_some());
        let physical_page_size = logical_page_size
            .checked_add(CHECKSUM_SIZE)
            .ok_or(Error::OffsetOverflow)?;
        let physical_page_size_usize =
            usize::try_from(physical_page_size).map_err(|_| Error::OffsetOverflow)?;
        let max_batch_pages = u64::try_from((buffer_size.get() / physical_page_size_usize).max(1))
            .map_err(|_| Error::OffsetOverflow)?;

        // Pages below the proof are accepted without reading. An overshooting proof clamps to
        // the full pages: a partial tail backs fewer logical bytes than a skipped page would
        // credit, so it must always be read.
        let start_page = (proven / logical_page_size).min(self.current_page);
        let mut valid_len = start_page
            .checked_mul(logical_page_size)
            .ok_or(Error::OffsetOverflow)?;
        let mut page = start_page;
        while page < total_pages {
            // Bound each read while deriving its physical range with checked arithmetic.
            let batch_pages = max_batch_pages.min(total_pages - page);
            let batch_end = page.checked_add(batch_pages).ok_or(Error::OffsetOverflow)?;
            let physical_offset = page
                .checked_mul(physical_page_size)
                .ok_or(Error::OffsetOverflow)?;
            let physical_len = batch_pages
                .checked_mul(physical_page_size)
                .ok_or(Error::OffsetOverflow)?;
            let physical_len = usize::try_from(physical_len).map_err(|_| Error::OffsetOverflow)?;

            // Coalesce once so each physical page can be checksum-validated in place.
            let physical = self
                .blob
                .read_at(physical_offset, physical_len, read_options)
                .await?
                .coalesce();

            // The first invalid page terminates the only recoverable contiguous prefix.
            for physical_page in physical.as_ref().chunks_exact(physical_page_size_usize) {
                let Some(checksum) = Checksum::validate_page(physical_page) else {
                    return Ok(valid_len);
                };
                let len = u64::from(checksum.len);
                valid_len = valid_len.checked_add(len).ok_or(Error::OffsetOverflow)?;

                // A valid partial logical page ends the contiguous prefix wherever it appears.
                if len < logical_page_size {
                    return Ok(valid_len);
                }
            }
            page = batch_end;
        }
        Ok(valid_len)
    }

    /// Read and validate one page, returning its logical bytes and the range they cover.
    async fn read_page(
        blob: &B,
        page: u64,
        page_size: u64,
        read_options: ReadOptions,
    ) -> Result<(IoBuf, u64, u64), Error> {
        let (logical, _) =
            super::get_page_with_checksum_from_blob(blob, page, page_size, read_options).await?;
        let start = page.checked_mul(page_size).ok_or(Error::OffsetOverflow)?;
        let len = u64::try_from(logical.len()).map_err(|_| Error::OffsetOverflow)?;
        let end = start.checked_add(len).ok_or(Error::OffsetOverflow)?;
        Ok((logical, start, end))
    }

    /// Read a logical range directly from a raw paged blob, validating every page it spans.
    ///
    /// Returns [Error::BlobInsufficientLength] when valid page contents do not cover the whole
    /// range, and [Error::OffsetOverflow] when its end or page offsets overflow.
    pub async fn read_range(
        blob: &B,
        logical_page_size: NonZeroU16,
        offset: u64,
        len: usize,
        read_options: ReadOptions,
    ) -> Result<IoBufs, Error> {
        // Resolve the requested range before allocating or reading any pages.
        let len_u64 = u64::try_from(len).map_err(|_| Error::OffsetOverflow)?;
        let end = offset.checked_add(len_u64).ok_or(Error::OffsetOverflow)?;
        if len == 0 {
            return Ok(IoBufs::default());
        }

        // Identify the inclusive logical page range spanning the requested bytes.
        let logical_page_size: u64 = logical_page_size.widen();
        let first_page = offset / logical_page_size;
        let last_page = (end - 1) / logical_page_size;
        let mut out = IoBufs::default();

        // Validate every spanning page and append only its intersection with the requested range.
        for page in first_page..=last_page {
            let (logical, page_start, page_end) =
                Self::read_page(blob, page, logical_page_size, read_options).await?;
            let overlap_start = offset.max(page_start);
            let overlap_end = end.min(page_end);
            if overlap_start >= overlap_end {
                return Err(Error::BlobInsufficientLength);
            }
            let start = (overlap_start - page_start) as usize;
            let end = (overlap_end - page_start) as usize;
            out.append(logical.slice(start..end));
        }

        // A short terminal page can leave the requested range only partially covered.
        if out.len() != len {
            return Err(Error::BlobInsufficientLength);
        }
        Ok(out)
    }

    /// Read the terminal logical range of a raw paged blob and return its logical size.
    ///
    /// The blob must contain only complete physical pages. The last page is validated first to
    /// determine the logical end. If `len` crosses a page boundary, preceding pages are validated
    /// with [Self::read_range].
    pub async fn read_tail(
        blob: &B,
        physical_size: u64,
        logical_page_size: NonZeroU16,
        len: usize,
        read_options: ReadOptions,
    ) -> Result<(u64, IoBufs), Error> {
        if physical_size == 0 {
            return if len == 0 {
                Ok((0, IoBufs::default()))
            } else {
                Err(Error::BlobInsufficientLength)
            };
        }

        // A trailing partial page means the caller did not size the blob to complete physical
        // pages, so there is no trusted terminal page to read the logical end from.
        let page_size: u64 = logical_page_size.widen();
        let physical_page_size = page_size
            .checked_add(CHECKSUM_SIZE)
            .ok_or(Error::OffsetOverflow)?;
        if !physical_size.is_multiple_of(physical_page_size) {
            return Err(Error::BlobInsufficientLength);
        }

        // The checksum length on the terminal page determines the blob's logical end.
        let page = physical_size / physical_page_size - 1;
        let (tail, page_start, logical_size) =
            Self::read_page(blob, page, page_size, read_options).await?;
        let len_u64 = u64::try_from(len).map_err(|_| Error::OffsetOverflow)?;
        let offset = logical_size
            .checked_sub(len_u64)
            .ok_or(Error::BlobInsufficientLength)?;

        // Read only the portion preceding the terminal page, then append its already-validated
        // suffix. This keeps a terminal item wholly within the last page to one blob read.
        let mut out = if offset < page_start {
            let prefix_len =
                usize::try_from(page_start - offset).map_err(|_| Error::OffsetOverflow)?;
            Self::read_range(blob, logical_page_size, offset, prefix_len, read_options).await?
        } else {
            IoBufs::default()
        };
        let tail_start = usize::try_from(offset.max(page_start) - page_start)
            .map_err(|_| Error::OffsetOverflow)?;
        out.append(tail.slice(tail_start..));
        assert_eq!(out.len(), len);
        Ok((logical_size, out))
    }

    /// Wait for any started sync to complete without starting a new sync.
    pub async fn wait_for_sync(&mut self) -> Result<(), Error> {
        self.sync_state.wait_for_pending().await
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

    /// Coordinate the dispatch logic for shrinking the blob.
    async fn shrink(&mut self, target_size: u64) -> Result<(), Error> {
        let page_size: u64 = self.cache_ref.page_size().widen();
        let physical_page_size = page_size
            .checked_add(CHECKSUM_SIZE)
            .ok_or(Error::OffsetOverflow)?;

        // Flush any buffered data first to ensure we have a consistent state on disk.
        self.sync().await?;

        // Calculate the physical size needed for the new size.
        let full_pages = target_size / page_size;
        let partial_bytes = target_size % page_size;
        let physical_pages = full_pages
            .checked_add(u64::from(partial_bytes > 0))
            .ok_or(Error::OffsetOverflow)?;
        let new_physical_size = physical_pages
            .checked_mul(physical_page_size)
            .ok_or(Error::OffsetOverflow)?;
        let tail_offset = full_pages
            .checked_mul(page_size)
            .ok_or(Error::OffsetOverflow)?;
        let current_physical_size = if self.partial_page_state.is_some() {
            self.current_page
                .checked_add(1)
                .and_then(|pages| pages.checked_mul(physical_page_size))
                .ok_or(Error::OffsetOverflow)?
        } else {
            self.current_page
                .checked_mul(physical_page_size)
                .ok_or(Error::OffsetOverflow)?
        };

        // A logical shrink can leave the physical page count unchanged. Only real physical
        // resizes need to create a pending sync.
        if new_physical_size != current_physical_size {
            self.sync_state
                .resize(&self.blob, new_physical_size)
                .await?;
        }

        // Evict cached pages at or beyond the new full-page boundary. The page at
        // `full_pages` (if partial) is now owned by the tip buffer, and anything above is
        // beyond the new size. Leaving their pre-resize contents in the cache
        // lets `try_read_sync_into` (whose reads below the tip boundary come straight from
        // the page cache) observe stale bytes once
        // the tip is repopulated.
        self.cache_ref.invalidate_from(self.id, full_pages);

        if partial_bytes > 0 {
            return self
                .shrink_to_partial(full_pages, partial_bytes, page_size, tail_offset)
                .await;
        }

        // Shrink the blob to a page boundary, which requires no CRC-slot rewrite.
        self.partial_page_state = None;
        self.durable_page_state = None;
        self.current_page = full_pages;
        self.buffer.offset = tail_offset;
        self.buffer.clear();

        Ok(())
    }

    /// Perform a shrink to a partial page tip and make the shorter CRC slot authoritative.
    async fn shrink_to_partial(
        &mut self,
        full_pages: u64,
        partial_bytes: u64,
        page_size: u64,
        tail_offset: u64,
    ) -> Result<(), Error> {
        // Update blob state and buffer based on the desired size. The page data is
        // read with CRC validation, then durably rewritten below with a shorter CRC.
        self.current_page = full_pages;
        self.buffer.offset = tail_offset;

        // The retained prefix becomes the authoritative tip buffer, so this
        // page need not remain in the OS page cache.
        let (page_data, old_checksum) = super::get_page_with_checksum_from_blob(
            &self.blob,
            full_pages,
            page_size,
            ReadOptions::DONT_CACHE,
        )
        .await?;

        // Ensure the validated data covers what we need.
        if (page_data.len() as u64) < partial_bytes {
            return Err(Error::InvalidChecksum);
        }

        self.buffer.clear();
        let new_data = &page_data.as_ref()[..partial_bytes as usize];
        let over_capacity = self.buffer.append(new_data);
        assert!(!over_capacity);

        let final_record = self
            .sync_partial_page_shrink(
                full_pages,
                page_size,
                partial_bytes as u16,
                Crc32::checksum(new_data),
                &old_checksum,
            )
            .await?;

        // The shrink surgery above made the new record durable.
        self.partial_page_state = Some(final_record);
        self.durable_page_state = Some(final_record);

        Ok(())
    }

    /// Page-cache id used for reads. Exposed for tests.
    #[cfg(test)]
    pub(super) const fn cache_id(&self) -> u64 {
        self.id
    }

    /// Construct an immutable read handle for the current blob state.
    fn sealed_handle(&self, id: u64) -> super::Sealed<B> {
        let page_size: u64 = self.cache_ref.page_size().widen();
        let full_pages = self.current_page;
        assert_eq!(
            full_pages.checked_mul(page_size),
            Some(self.buffer.offset),
            "flushed page count is inconsistent with the buffer offset"
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
            id,
        )
    }

    /// Consume the write handle, flushing buffered bytes and beginning a sync of the blob.
    ///
    /// Returns an immutable [`super::Sealed`] read handle plus a completion handle for the started
    /// sync. Reads through the [`super::Sealed`] handle observe flushed bytes immediately;
    /// durability isn't guaranteed until the sync handle completes.
    pub async fn seal(mut self) -> Result<(super::Sealed<B>, Handle<()>), Error> {
        self.sync_state.wait_for_pending().await?;
        self.flush_internal(true, false).await?;
        let handle = self.sync_state.start_sync(&self.blob).await;
        Ok((self.sealed_handle(self.id), handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Buf, BufferPool, BufferPoolConfig, Handle, IoBufsMut, Runner as _, Spawner as _,
        Storage as _, Supervisor as _,
        buffer::{paged::CHECKSUM_SLOT_SIZE, tests::SyncTrackingBlob},
        deterministic,
        mocks::{DelayedSyncBlob, RecordingContext, next_pending_sync},
        telemetry::metrics::Registry,
    };
    use commonware_codec::ReadExt;
    use commonware_macros::test_traced;
    use commonware_utils::{NZU16, NZU32, NZUsize, channel::oneshot, sync::Mutex};
    use futures::FutureExt as _;
    use std::{
        num::NonZeroU16,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    const PAGE_SIZE: NonZeroU16 = NZU16!(103); // janky size to ensure we test page alignment
    const BUFFER_SIZE: usize = PAGE_SIZE.get() as usize * 2;

    #[test_traced("DEBUG")]
    fn test_writes_use_uncached_hint() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            writer.sync().await.unwrap();

            writer.append(b"first").await.unwrap();
            writer.sync().await.unwrap();
            assert_eq!(blob.uncached_snapshot(), (0, 1));

            writer.append(b"second").await.unwrap();
            let (_, sync) = writer.seal().await.unwrap();
            sync.await.unwrap();
            assert_eq!(blob.uncached_snapshot(), (1, 1));
        });
    }

    /// Unsynced partial-page flushes ([Writer::snapshot], [Writer::replay]) rewrite the tail
    /// page without a durability barrier. Every rewrite must keep the page's durable checksum
    /// slot byte-identical: a crash can cut the unsynced rewrites per byte, and whichever bytes
    /// land, the footer must still validate the synced prefix.
    #[test_traced("DEBUG")]
    fn test_unsynced_flushes_preserve_durable_checksum_slot() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let page_size = PAGE_SIZE.get() as usize;
            let physical_page = page_size + CHECKSUM_SIZE as usize;
            let (blob, blob_size) = context
                .open("test_partition", b"snapshot_torn")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob.clone(), blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Make a mid-page prefix durable and capture the page's durable image.
            let synced: Vec<u8> = (1u8..=24).collect();
            writer.append(&synced).await.unwrap();
            writer.sync().await.unwrap();
            let durable_image = blob
                .read_at(0, physical_page, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();

            // Two unsynced rewrites of the same page.
            writer.append(&[25u8; 8]).await.unwrap();
            drop(writer.snapshot().await.unwrap());
            writer.append(&[26u8; 8]).await.unwrap();
            drop(writer.snapshot().await.unwrap());
            let torn_image = blob
                .read_at(0, physical_page, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();

            // Crash: of the unsynced rewrites, only the final one's footer bytes land, while
            // the logical region keeps its durable bytes.
            let mut crash = durable_image.as_ref().to_vec();
            crash[page_size..].copy_from_slice(&torn_image.as_ref()[page_size..]);
            let (crashed, _) = context
                .open("test_partition", b"snapshot_crash")
                .await
                .unwrap();
            crashed
                .write_at(0, crash, WriteOptions::default())
                .await
                .unwrap();
            crashed.sync().await.unwrap();

            // The synced prefix must recover through the preserved durable slot.
            let recovered = Writer::new(crashed, physical_page as u64, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(recovered.size(), synced.len() as u64);
            let read = recovered.read_at(0, synced.len()).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), synced.as_slice());
        });
    }

    /// `recoverable_prefix_len` returns the full logical size when every page is well-formed.
    #[test_traced("DEBUG")]
    fn test_recoverable_prefix_len_clean() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (context, recordings) = RecordingContext::new(context);
            let (blob, blob_size) = context
                .open("test_partition", b"prefix_clean")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(
                writer
                    .recoverable_prefix_len(0, NZUsize!(BUFFER_SIZE), ReadOptions::default())
                    .await
                    .unwrap(),
                0
            );

            let total = PAGE_SIZE.get() as usize * 2 + 50;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            writer.append(&data).await.unwrap();
            writer.sync().await.unwrap();

            // Prefix validation uses the default options so recovery can reuse the validated pages.
            recordings.clear();
            assert_eq!(
                writer
                    .recoverable_prefix_len(0, NZUsize!(BUFFER_SIZE), ReadOptions::default())
                    .await
                    .unwrap(),
                total as u64
            );
            let reads = recordings.snapshot().reads;
            assert!(!reads.is_empty());
            assert!(
                reads
                    .iter()
                    .all(|options| *options == ReadOptions::default())
            );

            drop(writer);
            let (blob, blob_size) = context
                .open("test_partition", b"prefix_clean")
                .await
                .unwrap();

            // Reopening also validates the disk-authoritative tail with the default options.
            recordings.clear();
            let _recovered = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let reads = recordings.snapshot().reads;
            assert!(!reads.is_empty());
            assert!(
                reads
                    .iter()
                    .all(|options| *options == ReadOptions::default())
            );
        });
    }

    /// The scan stops at the first torn page even when later pages remain valid, catching the
    /// interior hole the backward scan in `Writer::new` misses.
    #[test_traced("DEBUG")]
    fn test_recoverable_prefix_len_torn_interior_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"prefix_torn")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob.clone(), blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let total = PAGE_SIZE.get() as usize * 3 + 10;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            writer.append(&data).await.unwrap();
            writer.sync().await.unwrap();

            // Tear page 1, leaving pages 0 and 2+ valid.
            let physical_page_size = PAGE_SIZE.get() as u64 + CHECKSUM_SIZE;
            let offset = physical_page_size + 7;
            let byte = blob
                .read_at(offset, 1, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            blob.write_at(
                offset,
                vec![byte.as_ref()[0] ^ 0xFF],
                WriteOptions::default(),
            )
            .await
            .unwrap();
            blob.sync().await.unwrap();

            assert_eq!(
                writer
                    .recoverable_prefix_len(0, NZUsize!(BUFFER_SIZE), ReadOptions::default())
                    .await
                    .unwrap(),
                PAGE_SIZE.get() as u64
            );
        });
    }

    /// A proven prefix skips its pages without reading them: a scan started past a torn page
    /// accepts the caller's proof, and a proof past the blob's end clamps without panicking.
    #[test_traced("DEBUG")]
    fn test_recoverable_prefix_len_proven_prefix() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"prefix_proven")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob.clone(), blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            let total = PAGE_SIZE.get() as usize * 4;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            writer.append(&data).await.unwrap();
            writer.sync().await.unwrap();

            // Tear page 1, leaving pages 0 and 2+ valid.
            let physical_page_size = PAGE_SIZE.get() as u64 + CHECKSUM_SIZE;
            let offset = physical_page_size + 7;
            let byte = blob
                .read_at(offset, 1, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            blob.write_at(
                offset,
                vec![byte.as_ref()[0] ^ 0xFF],
                WriteOptions::default(),
            )
            .await
            .unwrap();
            blob.sync().await.unwrap();

            // An unproven scan stops at the torn page. A proof past it skips the damage and
            // scans the remainder, and a mid-page proof rescans the page containing it.
            let page = u64::from(PAGE_SIZE.get());
            for (proven, expected) in [
                (0, page),
                (page, page),
                (2 * page, 4 * page),
                (2 * page + 3, 4 * page),
                (total as u64, 4 * page),
            ] {
                assert_eq!(
                    writer
                        .recoverable_prefix_len(
                            proven,
                            NZUsize!(BUFFER_SIZE),
                            ReadOptions::default()
                        )
                        .await
                        .unwrap(),
                    expected,
                    "proven {proven}"
                );
            }

            // A proof past the blob clamps to the pages that exist. Callers only pass proven
            // prefixes, and storage-level guards reject a prefix the blob cannot back.
            assert_eq!(
                writer
                    .recoverable_prefix_len(
                        100 * page,
                        NZUsize!(BUFFER_SIZE),
                        ReadOptions::default()
                    )
                    .await
                    .unwrap(),
                4 * page
            );

            // A partial tail is still read when the proof overshoots the blob: the clamp stops
            // at the full pages, so the tail contributes its logical length, not a full page.
            writer.append(&data[..20]).await.unwrap();
            writer.sync().await.unwrap();
            for proven in [4 * page + 20, 5 * page, 100 * page] {
                assert_eq!(
                    writer
                        .recoverable_prefix_len(
                            proven,
                            NZUsize!(BUFFER_SIZE),
                            ReadOptions::default()
                        )
                        .await
                        .unwrap(),
                    4 * page + 20,
                    "proven {proven}"
                );
            }
        });
    }

    /// A valid-but-short interior page ends the prefix: a partial page's durable state can
    /// survive a crash while its extension to a full page is lost.
    #[test_traced("DEBUG")]
    fn test_recoverable_prefix_len_stale_short_interior_page() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"prefix_stale")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob.clone(), blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Persist a partial first page and capture its physical bytes.
            let total = PAGE_SIZE.get() as usize * 2;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            writer.append(&data[..20]).await.unwrap();
            writer.sync().await.unwrap();
            let physical_page_size = (PAGE_SIZE.get() as u64 + CHECKSUM_SIZE) as usize;
            let stale = blob
                .read_at(0, physical_page_size, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            let stale = stale.as_ref().to_vec();

            // Extend past the first page, persist, then restore page 0 to its stale partial
            // state as if the extension never reached disk.
            writer.append(&data[20..]).await.unwrap();
            writer.sync().await.unwrap();
            blob.write_at(0, stale, WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            assert_eq!(
                writer
                    .recoverable_prefix_len(0, NZUsize!(BUFFER_SIZE), ReadOptions::default())
                    .await
                    .unwrap(),
                20
            );
        });
    }

    /// A clean scan derives its read batches from the supplied byte budget while always making
    /// progress by at least one page.
    #[test_traced("DEBUG")]
    fn test_recoverable_prefix_len_batches_reads() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (context, recordings) = RecordingContext::new(context);
            let (blob, blob_size) = context
                .open("test_partition", b"prefix_batches")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob.clone(), blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Eight full pages plus a partial tail span three batches under a three-page budget.
            let total = PAGE_SIZE.get() as usize * 8 + 10;
            let data: Vec<u8> = (0u8..=255).cycle().take(total).collect();
            writer.append(&data).await.unwrap();
            writer.sync().await.unwrap();

            // A sub-page budget falls back to one page per read.
            recordings.clear();
            assert_eq!(
                writer
                    .recoverable_prefix_len(0, NZUsize!(1), ReadOptions::default())
                    .await
                    .unwrap(),
                total as u64
            );
            assert_eq!(recordings.snapshot().reads.len(), 9);

            // A three-page budget coalesces the same scan into three reads.
            recordings.clear();
            let physical_page_size = PAGE_SIZE.get() as usize + CHECKSUM_SIZE as usize;
            let scan_buffer = NonZeroUsize::new(physical_page_size * 3).unwrap();
            assert_eq!(
                writer
                    .recoverable_prefix_len(0, scan_buffer, ReadOptions::default())
                    .await
                    .unwrap(),
                total as u64
            );
            assert_eq!(recordings.snapshot().reads.len(), 3);
        });
    }

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
    fn test_append_crc_empty() {
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
            assert_eq!(blob_size, 0); // There was no need to write a crc since there was no data.

            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            assert_eq!(append.size(), 0);
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

            // Close and reopen the blob and make sure the data is still there and the trailing
            // checksum is written & stripped as expected.
            append.sync().await.unwrap();
            drop(append);

            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            // Physical page = 103 logical + 12 Checksum = 115 bytes (padded partial page)
            assert_eq!(blob_size, 115);
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size(), 10); // CRC should be stripped after verification

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
            // 2 physical pages: 2 * 115 = 230 bytes
            assert_eq!(blob_size, 230);
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
            // Physical size should be exactly 2 pages: 115 * 2 = 230 bytes
            assert_eq!(blob_size, 230);
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
        // A large owned append on top of a synced partial page must rewrite the first page in
        // full (preserving the old CRC slot) before writing the bulk directly.
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"owned_partial")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Durably write a 50-byte partial page.
            let all: Vec<u8> = (0..500).map(|i| (i % 247) as u8).collect();
            append.append(&all[..50]).await.unwrap();
            append.sync().await.unwrap();

            // 450 more bytes: 53 fill the first page (rewritten in full), 3 whole pages (309 bytes)
            // bypass the buffer, 88 remain in the tip.
            append
                .append_owned(IoBuf::from(all[50..].to_vec()))
                .await
                .unwrap();
            assert_eq!(append.size(), 500);
            let read_buf = append.read_at(0, 500).await.unwrap().coalesce();
            assert_eq!(read_buf, &all[..]);

            // The direct write is not durable until sync: dropping without one preserves only the
            // synced 50-byte prefix.
            drop(append);
            let (blob, blob_size) = context
                .open("test_partition", b"owned_partial")
                .await
                .unwrap();
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size(), 50);
            let read_buf = append.read_at(0, 50).await.unwrap().coalesce();
            assert_eq!(read_buf, &all[..50]);

            // Repeating the owned append after recovery and syncing makes everything durable,
            // exercising the full rewrite of the recovered partial page.
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
        // The direct path must produce byte-identical physical output (page layout, CRC slot
        // placement, zero padding) to the buffered path for the same logical content.
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
            let bytes_a = blob_a
                .read_at(0, size_a as usize, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            let bytes_b = blob_b
                .read_at(0, size_b as usize, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
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
    // Verifies seal cannot flush buffered bytes before pending start_sync finishes.
    fn test_seal_waits_for_outstanding_start_sync_before_flushing() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let inner = SyncTrackingBlob::new();
            let (blob, pending) = DelayedSyncBlob::new(inner.clone());
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, 0, BUFFER_SIZE, cache_ref).await.unwrap();

            let prior = writer.start_sync().await;
            let deferred = next_pending_sync(&pending);
            writer.append(b"hello world").await.unwrap();

            let seal = context
                .child("seal")
                .spawn(move |_| async move { writer.seal().await });
            // The seal has reached the pending sync wait.
            deferred
                .blocked
                .await
                .expect("seal never waited on start_sync");
            let (_, writes, full_syncs, range_syncs) = inner.snapshot();
            assert_eq!(writes, 0);
            assert_eq!(full_syncs, 0);
            assert_eq!(range_syncs, 0);

            // Release the started sync so seal can flush.
            deferred.release.send(Ok(())).unwrap();
            let (sealed, sync) = seal.await.unwrap().unwrap();
            prior.await.unwrap();

            // Release the sync started by seal itself.
            let deferred = next_pending_sync(&pending);
            deferred.release.send(Ok(())).unwrap();
            sync.await.unwrap();
            let read = sealed
                .read_at(0, b"hello world".len())
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read.as_ref(), b"hello world");
            let (_, writes, full_syncs, range_syncs) = inner.snapshot();
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 2);
            assert_eq!(range_syncs, 0);
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
                    let mut replay = writer
                        .replay(NZUsize!(BUFFER_SIZE), ReadOptions::default())
                        .await
                        .unwrap();
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
            let name = b"failed_range_sync";
            let (blob, size) = context.open("test_partition", name).await.unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Keep the write buffered so sync attempts the clean range-scoped write path.
            append.append(b"abc").await.unwrap();

            // Removing the blob makes the range-sync flush fail.
            context.remove("test_partition", Some(name)).await.unwrap();
            assert!(append.sync().await.is_err());

            // The failed range-scoped write must leave a pending full-sync barrier, so a
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

            // With the earlier flush already durable, extending the partial page is one
            // full-page rewrite fused with a range sync.
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
            let mut replay = append
                .replay(NZUsize!(1024), ReadOptions::default())
                .await
                .unwrap();
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
    fn test_replay_uses_read_options_for_refills_and_seek() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, size) = context
                .open("test_partition", b"replay_read_options")
                .await
                .unwrap();
            let blob = PartialWriteBlob::new(blob, usize::MAX, 0);
            let read_options = blob.read_options();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let data = vec![3; page_size * 2];
            writer.append(&data).await.unwrap();
            writer.sync().await.unwrap();
            read_options.lock().clear();

            let physical_page_size = page_size + CHECKSUM_SIZE as usize;
            let mut replay = writer
                .replay(NZUsize!(physical_page_size), ReadOptions::DONT_CACHE)
                .await
                .unwrap();

            // Every refill uses the replay's read options, including the refill after crossing a
            // page boundary.
            assert!(replay.ensure(1).await.unwrap());
            replay.advance(page_size);
            assert!(replay.ensure(1).await.unwrap());

            // Seeking discards buffered pages but preserves the read options for the next refill.
            replay.seek_to(0).unwrap();
            assert!(replay.ensure(1).await.unwrap());

            assert_eq!(*read_options.lock(), vec![ReadOptions::DONT_CACHE; 3]);
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
            let mut replay = append
                .replay(NZUsize!(1024), ReadOptions::default())
                .await
                .unwrap();
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
    fn test_recreated_sync_skips_barrier_after_invalid_truncation() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.sync().await.unwrap();
            append.append(b"valid").await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            blob.write_at(blob.size(), b"junk", WriteOptions::default())
                .await
                .unwrap();

            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut reopened = Writer::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(reopened.size(), b"valid".len() as u64);

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
    fn test_sync_fuses_partial_page_rewrite() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = SyncTrackingBlob::new();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.sync().await.unwrap();

            // Establish a persisted partial page with the authoritative CRC in slot 0.
            append.append(b"abc").await.unwrap();
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 1);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 1);

            let slot0_offset = PAGE_SIZE.get() as u64;
            let slot1_offset = slot0_offset + CHECKSUM_SLOT_SIZE as u64;
            let slot0_before: Vec<u8> = blob
                .read_at(slot0_offset, CHECKSUM_SLOT_SIZE, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();

            // Extending that partial page rewrites the whole physical page in one write fused
            // with a range sync, resubmitting the protected slot 0 byte-identically and placing
            // the new CRC in slot 1.
            append.append(b"de").await.unwrap();
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 2);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 2);

            let slot0_after: Vec<u8> = blob
                .read_at(slot0_offset, CHECKSUM_SLOT_SIZE, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_eq!(
                slot0_before, slot0_after,
                "protected slot must be resubmitted byte-identically"
            );
            let slot1_between: Vec<u8> = blob
                .read_at(slot1_offset, CHECKSUM_SLOT_SIZE, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();

            // The next extension protects slot 1 and rewrites slot 0, again as one fused write.
            append.append(b"fg").await.unwrap();
            append.sync().await.unwrap();

            let (_, writes, full_syncs, range_syncs) = blob.snapshot();
            assert_eq!(writes, 3);
            assert_eq!(full_syncs, 1);
            assert_eq!(range_syncs, 3);

            let slot1_after: Vec<u8> = blob
                .read_at(slot1_offset, CHECKSUM_SLOT_SIZE, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_eq!(
                slot1_between, slot1_after,
                "protected slot must be resubmitted byte-identically"
            );

            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let reopened = Writer::new(blob.clone(), blob.size(), BUFFER_SIZE, cache_ref)
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

            // Create a Writer and write some data.
            let mut append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.append(&[1, 2, 3, 4]).await.unwrap();

            // Request a zero-length read with a reused, non-empty buffer.
            let stale = vec![9u8, 8, 7, 6];
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
        read_options: Arc<Mutex<Vec<ReadOptions>>>,
        failed_write_len: Arc<AtomicUsize>,
        fail_on: usize,
        partial_len: usize,
    }

    impl<B: Blob> PartialWriteBlob<B> {
        fn new(inner: B, fail_on: usize, partial_len: usize) -> Self {
            Self {
                inner,
                writes: Arc::new(AtomicUsize::new(0)),
                read_options: Arc::new(Mutex::new(Vec::new())),
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

        fn read_options(&self) -> Arc<Mutex<Vec<ReadOptions>>> {
            self.read_options.clone()
        }
    }

    impl<B: Blob> crate::Blob for PartialWriteBlob<B> {
        async fn read_at(
            &self,
            offset: u64,
            len: usize,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.read_options.lock().push(options);
            self.inner.read_at(offset, len, options).await
        }

        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.read_options.lock().push(options);
            self.inner.read_at_buf(offset, len, bufs, options).await
        }

        async fn write_at(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
            options: WriteOptions,
        ) -> Result<(), Error> {
            let bufs = bufs.into();
            let write = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
            if write == self.fail_on {
                let bytes = bufs.coalesce();
                self.failed_write_len.store(bytes.len(), Ordering::SeqCst);
                let partial_len = self.partial_len.min(bytes.len());
                self.inner
                    .write_at(offset, bytes.slice(..partial_len), options)
                    .await?;
                if !options.contains(WriteOptions::SYNC) {
                    self.inner.sync().await?;
                }
                return Err(Error::Io(
                    std::io::Error::other("injected partial write").into(),
                ));
            }

            self.inner.write_at(offset, bufs, options).await
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

    /// Blob wrapper that durably writes a torn extension and its complete incoming footer.
    #[derive(Clone)]
    struct TornExtensionBlob<B: Blob> {
        inner: B,
        writes: Arc<AtomicUsize>,
        fail_on: usize,
        durable_payload_len: usize,
    }

    impl<B: Blob> crate::Blob for TornExtensionBlob<B> {
        async fn read_at(
            &self,
            offset: u64,
            len: usize,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.inner.read_at(offset, len, options).await
        }

        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            self.inner.read_at_buf(offset, len, bufs, options).await
        }

        async fn write_at(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
            options: WriteOptions,
        ) -> Result<(), Error> {
            let write = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
            if write != self.fail_on {
                return self.inner.write_at(offset, bufs, options).await;
            }

            let bytes = bufs.into().coalesce();
            let footer_start = bytes
                .len()
                .checked_sub(CHECKSUM_SIZE as usize)
                .expect("physical page must contain a checksum footer");
            assert!(self.durable_payload_len <= footer_start);
            let footer_offset = offset
                .checked_add(footer_start as u64)
                .ok_or(Error::OffsetOverflow)?;
            let write_options = options.without(WriteOptions::SYNC);

            self.inner
                .write_at(
                    offset,
                    bytes.slice(..self.durable_payload_len),
                    write_options,
                )
                .await?;
            self.inner
                .write_at(footer_offset, bytes.slice(footer_start..), write_options)
                .await?;
            self.inner.sync().await?;

            Err(Error::Io(
                std::io::Error::other("injected torn extension").into(),
            ))
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
    fn test_torn_extension_with_new_footer_recovers_previous_prefix() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"torn_extension_footer")
                .await
                .unwrap();
            let write_count = Arc::new(AtomicUsize::new(0));
            let faulty_blob = TornExtensionBlob {
                inner: blob.clone(),
                writes: write_count.clone(),
                fail_on: 2,
                durable_payload_len: 4,
            };
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(faulty_blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            writer.append(b"abc").await.unwrap();
            writer.sync().await.unwrap();
            assert_eq!(write_count.load(Ordering::SeqCst), 1);

            writer.append(b"def").await.unwrap();
            assert!(writer.sync().await.is_err(), "extension write should fail");
            assert_eq!(write_count.load(Ordering::SeqCst), 2);
            drop(writer);

            let physical_page_size = PAGE_SIZE.get() as usize + CHECKSUM_SIZE as usize;
            let page = blob
                .read_at(0, physical_page_size, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            assert_eq!(&page.as_ref()[..6], b"abcd\0\0");
            let checksum = read_crc_record_from_page(page.as_ref());
            assert_eq!(checksum.len1, 3);
            assert_eq!(checksum.len2, 6);

            let (blob, blob_size) = context
                .open("test_partition", b"torn_extension_footer")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let recovered = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(recovered.size(), 3);

            // The protected slot proves exactly the previously committed boundary: the torn
            // extension cannot make any later byte part of the recoverable prefix.
            assert_eq!(
                recovered
                    .recoverable_prefix_len(0, NZUsize!(BUFFER_SIZE), ReadOptions::default())
                    .await
                    .unwrap(),
                3
            );
            let data = recovered.read_at(0, 3).await.unwrap().coalesce();
            assert_eq!(data.as_ref(), b"abc");
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
        async fn read_at(
            &self,
            offset: u64,
            len: usize,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            if offset == self.offset
                && len == self.len
                && self.reads.fetch_add(1, Ordering::SeqCst) == 0
            {
                let bytes = self.inner.read_at(offset, len, options).await?;

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

            self.inner.read_at(offset, len, options).await
        }

        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
            options: ReadOptions,
        ) -> Result<IoBufsMut, Error> {
            if offset == self.offset
                && len == self.len
                && self.reads.fetch_add(1, Ordering::SeqCst) == 0
            {
                let bytes = self.inner.read_at_buf(offset, len, bufs, options).await?;

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

            self.inner.read_at_buf(offset, len, bufs, options).await
        }

        async fn write_at(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
            options: WriteOptions,
        ) -> Result<(), Error> {
            self.inner.write_at(offset, bufs, options).await
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

    /// Dummy marker bytes with len=0 so the mangled slot is never authoritative.
    /// Format: [len_hi=0, len_lo=0, 0xDE, 0xAD, 0xBE, 0xEF]
    const DUMMY_MARKER: [u8; 6] = [0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];

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

            // Create a Writer.
            let append = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Build logical data with exactly two full pages followed by one trailing partial page.
            // This lets us verify that only the partial page is materialized.
            let page_size = PAGE_SIZE.get() as usize;
            let partial_len = 17usize;
            let data: Vec<u8> = (0..(page_size * 2 + partial_len))
                .map(|i| (i % 251) as u8)
                .collect();

            // Seed a tip buffer with the logical bytes exactly as flush_internal would see them.
            let mut buffer = Buffer::new(0, data.len(), cache_ref.pool().clone());
            let over_capacity = buffer.append(&data);
            assert!(!over_capacity);

            // Convert buffered logical bytes into physical-page writes.
            let (physical_pages, partial_page_state) =
                append.to_physical_pages(&buffer, true, None, None);

            // Two full pages should each contribute a logical slice and a CRC slice, and the
            // trailing partial page should contribute one materialized padded physical page.
            assert_eq!(physical_pages.chunk_count(), 5);

            // The returned partial-page CRC state must describe the exact trailing logical length.
            let checksum = partial_page_state.expect("partial page state must be returned");
            assert_eq!(checksum.len as usize, partial_len);

            // Coalesce for easier content inspection. The assembled bytes should still form three
            // full physical pages on disk.
            let physical_page_size = page_size + CHECKSUM_SIZE as usize;
            let coalesced = physical_pages.coalesce();
            assert_eq!(coalesced.len(), physical_page_size * 3);

            // The first two physical pages must preserve the two full logical pages verbatim.
            assert_eq!(&coalesced.as_ref()[..page_size], &data[..page_size]);
            assert_eq!(
                &coalesced.as_ref()[physical_page_size..physical_page_size + page_size],
                &data[page_size..page_size * 2],
            );

            // The trailing partial page must contain the remaining logical bytes followed by zero
            // padding up to one full logical page.
            let partial_start = physical_page_size * 2;
            assert_eq!(
                &coalesced.as_ref()[partial_start..partial_start + partial_len],
                &data[page_size * 2..],
            );
            assert!(
                coalesced.as_ref()[partial_start + partial_len..partial_start + page_size]
                    .iter()
                    .all(|byte| *byte == 0)
            );

            // Each assembled physical page must carry a valid CRC record.
            assert!(Checksum::validate_page(&coalesced.as_ref()[..physical_page_size]).is_some());
            assert!(
                Checksum::validate_page(
                    &coalesced.as_ref()[physical_page_size..physical_page_size * 2]
                )
                .is_some()
            );
            assert!(
                Checksum::validate_page(
                    &coalesced.as_ref()[physical_page_size * 2..physical_page_size * 3]
                )
                .is_some()
            );
        });
    }

    /// Test that slot 1's durable bytes are unchanged when it's the protected slot.
    ///
    /// Strategy: After extending twice (so slot 1 becomes authoritative with larger len),
    /// mangle the non-authoritative slot 0. Then extend again - slot 0 should be overwritten
    /// with the new CRC, while slot 1 (protected) is resubmitted byte-identically.
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
            let mut append = Writer::new(blob, 0, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&(1..=10).collect::<Vec<u8>>()).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 2: Extend to 30 bytes → slot 1 authoritative (len=30) ===
            let (blob, size) = context.open("test_partition", b"slot1_prot").await.unwrap();
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
                .read_at(0, physical_page_size, ReadOptions::default())
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
                .read_at(slot1_offset, 6, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();

            // === Step 3: Mangle slot 0 (non-authoritative) ===
            blob.write_at(slot0_offset, DUMMY_MARKER.to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Verify mangle worked
            let slot0_mangled: Vec<u8> = blob
                .read_at(slot0_offset, 6, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_eq!(slot0_mangled, DUMMY_MARKER, "Mangle failed");

            // === Step 4: Extend to 50 bytes → new CRC goes to slot 0, slot 1 protected ===
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
                .read_at(slot0_offset, 6, ReadOptions::default())
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
                .read_at(slot1_offset, 6, ReadOptions::default())
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
                .read_at(0, physical_page_size, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            let crc = read_crc_record_from_page(page.as_ref());
            assert_eq!(crc.len1, 50, "Slot 0 should have len=50");
        });
    }

    /// Test that slot 0's durable bytes are unchanged when it's the protected slot.
    ///
    /// Strategy: After extending three times (slot 0 becomes authoritative again with largest len),
    /// mangle the non-authoritative slot 1. Then extend again - slot 1 should be overwritten
    /// with the new CRC, while slot 0 (protected) is resubmitted byte-identically.
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
            let mut append = Writer::new(blob, 0, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&(1..=10).collect::<Vec<u8>>()).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 2: Extend to 30 bytes → slot 1 authoritative (len=30) ===
            let (blob, size) = context.open("test_partition", b"slot0_prot").await.unwrap();
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
                .read_at(0, physical_page_size, ReadOptions::default())
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
                .read_at(slot0_offset, 6, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();

            // === Step 4: Mangle slot 1 (non-authoritative) ===
            blob.write_at(slot1_offset, DUMMY_MARKER.to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Verify mangle worked
            let slot1_mangled: Vec<u8> = blob
                .read_at(slot1_offset, 6, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_eq!(slot1_mangled, DUMMY_MARKER, "Mangle failed");

            // === Step 5: Extend to 70 bytes → new CRC goes to slot 1, slot 0 protected ===
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
                .read_at(slot1_offset, 6, ReadOptions::default())
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
                .read_at(slot0_offset, 6, ReadOptions::default())
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
                .read_at(0, physical_page_size, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            let crc = read_crc_record_from_page(page.as_ref());
            assert_eq!(crc.len2, 70, "Slot 1 should have len=70");
        });
    }

    /// Test that the data prefix content is preserved when extending a partial page: the
    /// rewrite resubmits the committed prefix byte-identically.
    ///
    /// Strategy: Write data, then mangle the padding area (between data end and CRC start).
    /// After extending, the original data should be unchanged but the mangled padding
    /// should be overwritten with new data.
    #[test_traced("DEBUG")]
    fn test_data_prefix_preserved_when_extending() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let physical_page_size = PAGE_SIZE.get() as usize + CHECKSUM_SIZE as usize;

            // === Step 1: Write 20 bytes ===
            let (blob, _) = context
                .open("test_partition", b"prefix_test")
                .await
                .unwrap();
            let mut append = Writer::new(blob, 0, BUFFER_SIZE, cache_ref.clone())
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
                .read_at(0, 20, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();

            // Mangle bytes 25-30 (safely in the padding area, after our 20 bytes of data)
            blob.write_at(25, DUMMY_MARKER.to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // === Step 3: Extend to 40 bytes ===
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
                .read_at(0, 20, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();
            assert_eq!(prefix_before, prefix_after, "Data prefix was modified!");

            // Bytes at offset 25-30: data (21..=40) starts at offset 20, so offset 25 has value 26
            let overwritten: Vec<u8> = blob
                .read_at(25, 6, ReadOptions::default())
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
            let mut append = Writer::new(blob, 0, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&(1..=50).collect::<Vec<u8>>()).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            // === Step 2: Extend to 80 bytes → slot 1 authoritative ===
            let (blob, size) = context.open("test_partition", b"boundary").await.unwrap();
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
                .read_at(0, physical_page_size, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            let crc = read_crc_record_from_page(page.as_ref());
            assert!(crc.len2 > crc.len1, "Slot 1 should be authoritative");

            // Capture slot 1 before extending past page boundary
            let slot1_before: Vec<u8> = blob
                .read_at(slot1_offset, 6, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .freeze()
                .into();

            // Mangle slot 0 (non-authoritative)
            blob.write_at(slot0_offset, DUMMY_MARKER.to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // === Step 3: Extend past page boundary (80 + 40 = 120, PAGE_SIZE=103) ===
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
                .read_at(slot0_offset, 6, ReadOptions::default())
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
                .read_at(slot1_offset, 6, ReadOptions::default())
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
                .read_at(0, physical_page_size, ReadOptions::default())
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
            let append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size(), 120);
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
            let mut append = Writer::new(blob, 0, BUFFER_SIZE, cache_ref.clone())
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
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
                .read_at(0, physical_page_size, ReadOptions::default())
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
            let append = Writer::new(blob.clone(), size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size(), 30);
            let all_data: Vec<u8> = append.read_at(0, 30).await.unwrap().coalesce().into();
            let expected: Vec<u8> = (1..=30).collect();
            assert_eq!(all_data, expected);
            drop(append);

            // === Step 3: Corrupt ONLY crc2 (not len2) ===
            // crc2 is 4 bytes at offset PAGE_SIZE + 8
            blob.write_at(
                crc2_offset,
                vec![0xDE, 0xAD, 0xBE, 0xEF],
                WriteOptions::default(),
            )
            .await
            .unwrap();
            blob.sync().await.unwrap();

            // Verify corruption: len2 should still be 30, but crc2 is now garbage
            let page = blob
                .read_at(0, physical_page_size, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            let crc = read_crc_record_from_page(page.as_ref());
            assert_eq!(crc.len2, 30, "len2 should still be 30 after corruption");
            assert_eq!(crc.crc2, 0xDEADBEEF, "crc2 should be our corrupted value");

            // === Step 4: Re-open and verify fallback to slot 0's 10 bytes ===
            let append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Should fall back to 10 bytes (slot 0's length)
            assert_eq!(
                append.size(),
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
            let mut append = Writer::new(blob, 0, BUFFER_SIZE, cache_ref.clone())
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
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
                .read_at(0, physical_page_size, ReadOptions::default())
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
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
            let append = Writer::new(blob.clone(), size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size(), 113);
            let all_data: Vec<u8> = append.read_at(0, 113).await.unwrap().coalesce().into();
            let expected: Vec<u8> = (1..=113).collect();
            assert_eq!(all_data, expected);
            drop(append);

            // === Step 4: Corrupt page 0's primary CRC (slot 1's crc2) ===
            blob.write_at(
                page0_crc2_offset,
                vec![0xDE, 0xAD, 0xBE, 0xEF],
                WriteOptions::default(),
            )
            .await
            .unwrap();
            blob.sync().await.unwrap();

            // Verify corruption: page 0's slot 1 still has len=103 but bad CRC
            let page = blob
                .read_at(0, physical_page_size, ReadOptions::default())
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
            let append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // The blob still reports 113 bytes because init only validates the last page.
            // But reading from page 0 should fail because the CRC fallback is partial.
            assert_eq!(append.size(), 113);

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
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            let mut replay = append
                .replay(NZUsize!(1024), ReadOptions::default())
                .await
                .unwrap();

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
    fn test_resize_partial_shrink_uses_uncached_read_hint() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (blob, size) = context
                .open("test_partition", b"resize_read_options")
                .await
                .unwrap();
            let blob = PartialWriteBlob::new(blob, usize::MAX, 0);
            let read_options = blob.read_options();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let data = vec![7; PAGE_SIZE.get() as usize];
            writer.append(&data).await.unwrap();
            writer.sync().await.unwrap();

            // The shrink retains the prefix in the in-memory tip, so its backing read requests
            // DONT_CACHE.
            writer.resize(50).await.unwrap();

            assert_eq!(*read_options.lock(), vec![ReadOptions::DONT_CACHE]);
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

            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Write data across 3 pages: page 0 (full), page 1 (full), page 2 (partial).
            // PAGE_SIZE = 103, so 250 bytes = 103 + 103 + 44.
            let data: Vec<u8> = (0..=249).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();
            assert_eq!(append.size(), 250);
            drop(append);

            // Corrupt the CRC record of page 1 (middle page).
            let (blob, size) = context
                .open("test_partition", b"resize_crc_test")
                .await
                .unwrap();
            assert_eq!(size as usize, physical_page_size * 3);

            // Page 1 CRC record is at the end of the second physical page.
            let page1_crc_offset = (physical_page_size * 2 - CHECKSUM_SIZE as usize) as u64;
            blob.write_at(
                page1_crc_offset,
                vec![0xFF; CHECKSUM_SIZE as usize],
                WriteOptions::default(),
            )
            .await
            .unwrap();
            blob.sync().await.unwrap();

            // Open the blob - Writer::new() validates the LAST page (page 2), which is still valid.
            // So it should open successfully with size 250.
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            assert_eq!(append.size(), 250);

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
            let physical_page_size = page_size + CHECKSUM_SIZE as usize;
            let (inner, blob_size) = context
                .open("test_partition", b"snapshot_resize_cache")
                .await
                .unwrap();
            let (started_tx, started_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let blob = DelayedReadBlob::new(
                inner,
                physical_page_size as u64,
                physical_page_size,
                started_tx,
                release_rx,
            );
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
            let append = Writer::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), 45);
            let read = append.read_at(0, 45).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &data[..45]);
        });
    }

    /// A torn tail-page rewrite after a durable shrink must not resurrect the retired slot:
    /// the shrink zeroes the whole slot, so stale length bytes alone cannot reassemble a valid
    /// checksum over the pre-shrink bytes still on the page.
    #[test_traced("DEBUG")]
    fn test_shrink_then_torn_rewrite_does_not_resurrect() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"shrink_torn")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let mut writer = Writer::new(blob.clone(), blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Commit 80 bytes into the first slot, then durably shrink the tail page to 50.
            let data: Vec<u8> = (1u8..=80).collect();
            writer.append(&data).await.unwrap();
            writer.sync().await.unwrap();
            writer.resize(50).await.unwrap();
            drop(writer);

            // Model a rewrite of the tail page back to 80 bytes torn down to only the retired
            // slot's length bytes: the pre-shrink data still on the page must not revalidate.
            let page_size = u64::from(PAGE_SIZE.get());
            blob.write_at(
                page_size,
                80u16.to_be_bytes().to_vec(),
                WriteOptions::default(),
            )
            .await
            .unwrap();
            blob.sync().await.unwrap();

            let (blob, blob_size) = context
                .open("test_partition", b"shrink_torn")
                .await
                .unwrap();
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let recovered = Writer::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(recovered.size(), 50);
            let read = recovered.read_at(0, 50).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &data[..50]);
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
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
            let mut append = Writer::new(faulty_blob, size, BUFFER_SIZE, cache_ref.clone())
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
            let append = Writer::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), 50);
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
            let mut append = Writer::new(blob, size, LARGE_BUFFER_SIZE, cache_ref.clone())
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
            let mut append = Writer::new(faulty_blob, size, LARGE_BUFFER_SIZE, cache_ref.clone())
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
            let append = Writer::new(blob, size, LARGE_BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), 300);
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
            let faulty_blob = PartialWriteBlob::new(blob.clone(), 4, 3);
            let write_count = faulty_blob.write_count();
            let failed_write_len = faulty_blob.failed_write_len();
            let mut append = Writer::new(faulty_blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();
            append.append(&data[..48]).await.unwrap();
            append.sync().await.unwrap();
            assert_eq!(write_count.load(Ordering::SeqCst), 1);

            append.append(&data[48..50]).await.unwrap();
            append.sync().await.unwrap();
            assert_eq!(write_count.load(Ordering::SeqCst), 2);

            append.append(&data[50..]).await.unwrap();
            append.sync().await.unwrap();
            assert_eq!(write_count.load(Ordering::SeqCst), 3);

            // Corrupt the newer authoritative slot. The older slot still covers the shrink target.
            // `resize()` first syncs the live buffer, which writes a valid fallback slot but leaves
            // the cached footer stale. A torn phase-1 shrink write must preserve that validated
            // fallback slot.
            let slot0_offset = PAGE_SIZE.get() as u64;
            blob.write_at(slot0_offset, DUMMY_MARKER.to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            assert!(
                append.resize(45).await.is_err(),
                "phase-1 partial write should fail"
            );
            assert_eq!(write_count.load(Ordering::SeqCst), 4);
            assert_eq!(failed_write_len.load(Ordering::SeqCst), CHECKSUM_SLOT_SIZE);
            drop(append);

            let (blob, size) = context
                .open("test_partition", b"same_page_shrink_fallback_slot")
                .await
                .unwrap();
            let append = Writer::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), 50);
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
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
            let append = Writer::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), target);
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
            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
            let mut append = Writer::new(faulty_blob, size, BUFFER_SIZE, cache_ref.clone())
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
            let append = Writer::new(blob, size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), page_size * 2);
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
            let mut append = Writer::new(blob, size, LARGE_BUFFER_SIZE, cache_ref.clone())
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
            let mut append = Writer::new(faulty_blob, size, LARGE_BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            assert!(
                append.resize(40).await.is_err(),
                "old-slot length invalidation should fail"
            );
            assert_eq!(write_count.load(Ordering::SeqCst), 3);
            assert_eq!(failed_write_len.load(Ordering::SeqCst), CHECKSUM_SLOT_SIZE);
            drop(append);

            let (blob, size) = context
                .open(
                    "test_partition",
                    b"same_page_shrink_interrupted_len_invalidation",
                )
                .await
                .unwrap();
            let append = Writer::new(blob, size, LARGE_BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            assert_eq!(append.size(), 40);
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
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
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
            let mut append = Writer::new(blob.clone(), 0, BUFFER_SIZE, cache_ref)
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

            // Shrinking to a page boundary resizes the blob but does not rewrite CRC metadata.
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

            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
            blob.write_at(crc_offset, bad_crc_record.to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Step 3: Try to open the blob - should NOT panic, should return error or handle gracefully
            let result = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone()).await;

            // Either returns InvalidChecksum error OR truncates the corrupted data
            // (both are acceptable behaviors - panicking is NOT acceptable)
            match result {
                Ok(append) => {
                    // If it opens successfully, the corrupted page should have been truncated
                    let recovered_size = append.size();
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

            let mut append = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone())
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
            blob.write_at(crc_offset, bad_crc_record.to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Step 3: Try to open - should NOT panic
            let result = Writer::new(blob, size, BUFFER_SIZE, cache_ref.clone()).await;

            match result {
                Ok(append) => {
                    // Corrupted page truncated
                    assert_eq!(append.size(), 0);
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
