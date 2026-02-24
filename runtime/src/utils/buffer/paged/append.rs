//! The [Append] wrapper consists of a [Blob] and a write buffer, and provides a logical view over
//! the underlying blob which has a page-oriented structure that provides integrity guarantees. The
//! wrapper also provides read caching managed by a page cache.
//!
//! # Immutability
//!
//! The wrapper can be created in (or converted to) an immutable state, which will prevent any
//! modifications while still supporting cached reads. This can be used to reduce its memory
//! footprint and/or to prevent unintended modifications.
//!
//! # Recovery
//!
//! On `sync`, this wrapper will durably write buffered data to the underlying blob in pages. All
//! pages have a [Checksum] at the end. If no CRC record existed before for the page being written,
//! then one of the checksums will be all zero. If a checksum already existed for the page being
//! written, then the write will overwrite only the checksum with the lesser length value. Should
//! this write fail, the previously committed page state can still be recovered.
//!
//! During non-immutable blob initialization, the wrapper will back up over any page that is not
//! accompanied by a valid CRC, treating it as the result of an incomplete write that may be
//! invalid. Immutable blob initialization will fail if any trailing data is detected that cannot be
//! validated by a CRC.
//!
//! # Allocation Semantics
//!
//! - [Append::new] and [Append::new_immutable] allocate tip backing eagerly through the buffer
//!   pool. Capacity is floored to hold at least one full logical page plus potential recovered
//!   partial-page bytes.
//! - [Append::append] and overwrite-in-tip paths typically reuse existing tip backing. Copy-on-write
//!   allocation occurs only when immutable views still alias the backing or additional capacity is
//!   required.
//! - Flush paths ([Append::sync], capacity-triggered flushes inside [Append::append], and
//!   [Append::to_immutable]) emit immutable views to storage and keep tip backing reusable.
//! - [Append::resize] may allocate one temporary physical-page buffer when recovering a retained
//!   partial page from disk for CRC validation.
//! - Read misses that go through the page cache allocate fetch buffers at physical-page size, cached
//!   slots store logical-page bytes.

use super::read::{PageReader, Replay};
use crate::{
    buffer::{
        paged::{CacheRef, Checksum, CHECKSUM_SIZE},
        tip::Buffer,
    },
    Blob, Error, IoBuf, IoBufs,
};
use bytes::BufMut;
use commonware_cryptography::Crc32;
use commonware_utils::sync::{AsyncRwLock, AsyncRwLockWriteGuard};
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
}

/// A [Blob] wrapper that supports write-cached appending of data, with checksums for data integrity
/// and page cache managed caching.
#[derive(Clone)]
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
        let (partial_page_state, pages, invalid_data_found) =
            Self::read_last_valid_page(&blob, original_blob_size, cache_ref.logical_page_size())
                .await?;
        if invalid_data_found {
            // Invalid data was detected, trim it from the blob.
            let new_blob_size = pages * cache_ref.physical_page_size();
            warn!(
                original_blob_size,
                new_blob_size, "truncating blob to remove invalid data"
            );
            blob.resize(new_blob_size).await?;
            blob.sync().await?;
        }

        let capacity = capacity_with_floor(capacity, cache_ref.logical_page_size());

        let (blob_state, partial_data) = match partial_page_state {
            Some((partial_page, crc_record)) => (
                BlobState {
                    blob,
                    current_page: pages - 1,
                    partial_page_state: Some(crc_record),
                },
                Some(partial_page),
            ),
            None => (
                BlobState {
                    blob,
                    current_page: pages,
                    partial_page_state: None,
                },
                None,
            ),
        };

        let mut buffer = Buffer::new(
            blob_state.current_page * cache_ref.logical_page_size(),
            capacity,
            cache_ref.pool().clone(),
        );
        if let Some(partial_page) = partial_data {
            let over_capacity = buffer.append(partial_page.as_ref());
            assert!(!over_capacity);
        }

        Ok(Self {
            blob_state: Arc::new(AsyncRwLock::new(blob_state)),
            id: cache_ref.next_id(),
            cache_ref,
            buffer: Arc::new(AsyncRwLock::new(buffer)),
        })
    }

    /// Return a new [Append] wrapper of the provided `blob` that is known to have `blob_size`
    /// underlying physical bytes, using the provided `cache_ref` for read caching. The wrapper is
    /// for read-only data, and any append attempts will return error. The provided `capacity` is
    /// used only if the blob is later turned into a mutable one. Immutable blobs are assumed
    /// consistent on disk, so any CRC verification failure results in an error without any recovery
    /// attempt.
    pub async fn new_immutable(
        blob: B,
        blob_size: u64,
        capacity: usize,
        cache_ref: CacheRef,
    ) -> Result<Self, Error> {
        let (partial_page_state, pages, invalid_data_found) =
            Self::read_last_valid_page(&blob, blob_size, cache_ref.logical_page_size()).await?;
        if invalid_data_found {
            // Invalid data was detected, so this blob is not consistent.
            return Err(Error::InvalidChecksum);
        }

        let capacity = capacity_with_floor(capacity, cache_ref.logical_page_size());

        let (blob_state, partial_data) = match partial_page_state {
            Some((partial_page, crc_record)) => (
                BlobState {
                    blob,
                    current_page: pages - 1,
                    partial_page_state: Some(crc_record),
                },
                Some(partial_page),
            ),
            None => (
                BlobState {
                    blob,
                    current_page: pages,
                    partial_page_state: None,
                },
                None,
            ),
        };
        let mut buffer = Buffer::new(
            blob_state.current_page * cache_ref.logical_page_size(),
            capacity,
            cache_ref.pool().clone(),
        );
        if let Some(partial_page) = partial_data {
            let over_capacity = buffer.append(partial_page.as_ref());
            assert!(!over_capacity);
        }
        buffer.set_immutable(true);

        Ok(Self {
            blob_state: Arc::new(AsyncRwLock::new(blob_state)),
            id: cache_ref.next_id(),
            cache_ref,
            buffer: Arc::new(AsyncRwLock::new(buffer)),
        })
    }

    /// Returns `true` if this blob is in the immutable state.
    pub async fn is_immutable(&self) -> bool {
        self.buffer.read().await.is_immutable()
    }

    /// Convert this blob to the immutable state if it's not already in it.
    ///
    /// If there is unwritten data in the buffer, it will be flushed and synced before returning.
    pub async fn to_immutable(&self) -> Result<(), Error> {
        // Flush any buffered data. When flush_internal returns, write_at has completed and data
        // has been written to the underlying blob.
        let mut buf_guard = self.buffer.write().await;
        if buf_guard.is_immutable() {
            return Ok(());
        }
        buf_guard.set_immutable(false);
        self.flush_internal(buf_guard, true).await?;

        // Compact tip backing after flush to match the post-flush logical view.
        {
            let mut buf_guard = self.buffer.write().await;
            buf_guard.set_immutable(true);
        }

        // Sync the underlying blob to ensure new_immutable on restart will succeed even in the
        // event of a crash.
        let blob_state = self.blob_state.read().await;
        blob_state.blob.sync().await
    }

    /// Convert this blob to the mutable state if it's not already in it.
    pub async fn to_mutable(&self) {
        let mut buffer = self.buffer.write().await;
        if !buffer.is_immutable() {
            return;
        }
        buffer.set_mutable();
    }

    /// Scans backwards from the end of the blob, stopping when it finds a valid page.
    ///
    /// # Returns
    ///
    /// A tuple of `(partial_page, page_count, invalid_data_found)`:
    ///
    /// - `partial_page`: If the last valid page is partial (contains fewer than `page_size` logical
    ///   bytes), returns `Some((data, crc_record))` containing the logical data and its CRC record.
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
    ) -> Result<(Option<(IoBuf, Checksum)>, u64, bool), Error> {
        let physical_page_size = page_size + CHECKSUM_SIZE;
        let partial_bytes = blob_size % physical_page_size;
        let mut last_page_end = blob_size - partial_bytes;

        // If the last physical page in the blob is truncated, it can't have a valid CRC record and
        // must be invalid.
        let mut invalid_data_found = partial_bytes != 0;

        while last_page_end != 0 {
            // Read the last page and parse its CRC record.
            let page_start = last_page_end - physical_page_size;
            let buf = blob
                .read_at(page_start, physical_page_size as usize)
                .await?
                .coalesce()
                .freeze();

            match Checksum::validate_page(buf.as_ref()) {
                Some(crc_record) => {
                    // Found a valid page.
                    let (len, _) = crc_record.get_crc();
                    let len = len as u64;
                    if len != page_size {
                        // The page is partial (logical data doesn't fill the page).
                        let logical_bytes = buf.slice(..len as usize);
                        return Ok((
                            Some((logical_bytes, crc_record)),
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

    /// Append all bytes in `buf` to the tip of the blob.
    ///
    /// # Errors
    ///
    /// * `Error::ImmutableBlob` - The blob is in the immutable state.
    pub async fn append(&self, buf: &[u8]) -> Result<(), Error> {
        let mut buffer = self.buffer.write().await;
        if buffer.is_immutable() {
            return Err(Error::ImmutableBlob);
        }

        if !buffer.append(buf) {
            return Ok(());
        }

        // Buffer is over capacity, so we need to write data to the blob.
        self.flush_internal(buffer, false).await
    }

    /// Flush all full pages from the buffer to disk, resetting the buffer to contain only the bytes
    /// in any final partial page. If `write_partial_page` is true, the partial page will be written
    /// to the blob as well along with a CRC record.
    async fn flush_internal(
        &self,
        mut buf_guard: AsyncRwLockWriteGuard<'_, Buffer>,
        write_partial_page: bool,
    ) -> Result<(), Error> {
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
            return Ok(());
        }

        // Split buffered bytes into full logical pages to hand off now, leaving any trailing
        // partial page in tip for continued buffering.
        let logical_page_size = self.cache_ref.logical_page_size() as usize;
        let pages_to_cache = buffer.len() / logical_page_size;
        let bytes_to_drain = pages_to_cache * logical_page_size;

        // Remember the logical start offset and page bytes for caching of flushed full pages.
        let cache_pages = if pages_to_cache > 0 {
            Some((buffer.offset, buffer.slice(..bytes_to_drain)))
        } else {
            None
        };

        // Drain full pages from the buffered logical data.
        buffer.drop_prefix(bytes_to_drain);
        buffer.offset += bytes_to_drain as u64;
        let new_offset = buffer.offset;

        // Cache full pages before releasing the tip lock so reads don't observe stale persisted
        // bytes during the handoff from tip to cache.
        if let Some((cache_offset, pages)) = cache_pages {
            self.cache_ref
                .cache(self.id, &pages, cache_offset, pages_to_cache);
        }

        // Acquire a write lock on the blob state so nobody tries to read or modify the blob while
        // we're writing to it.
        let mut blob_state = self.blob_state.write().await;

        // Release the buffer lock to allow for concurrent reads & buffered writes while we write
        // the physical pages.
        drop(buf_guard);

        let physical_page_size = self.cache_ref.physical_page_size() as usize;
        let write_at_offset = blob_state.current_page * physical_page_size as u64;

        // Count only FULL pages for advancing current_page. A partial page (if included) takes
        // up a full physical page on disk, but it's not complete - the next byte still goes to
        // that same logical page.
        let full_pages_written = pages_to_cache;

        // Identify protected regions based on the OLD partial page state
        let protected_regions = Self::identify_protected_regions(old_partial_page_state.as_ref());

        // Update state before writing. This may appear to risk data loss if writes fail,
        // but write failures are fatal per this codebase's design - callers must not use
        // the blob after any mutable method returns an error.
        blob_state.current_page += full_pages_written as u64;
        blob_state.partial_page_state = partial_page_state;

        // Make sure the buffer offset and underlying blob agree on the state of the tip.
        assert_eq!(
            blob_state.current_page * self.cache_ref.logical_page_size(),
            new_offset
        );

        // Write the physical pages to the blob.
        // If there are protected regions in the first page, we need to write around them.
        if let Some((prefix_len, protected_crc)) = protected_regions {
            match protected_crc {
                ProtectedCrc::First => {
                    // Protected CRC is first: [page_size..page_size+6]
                    // Write 1: New data in first page [prefix_len..page_size]
                    if prefix_len < logical_page_size {
                        let _ = physical_pages.split_to(prefix_len);
                        let first_payload = physical_pages.split_to(logical_page_size - prefix_len);
                        blob_state
                            .blob
                            .write_at(write_at_offset + prefix_len as u64, first_payload)
                            .await?;

                        // Write 2: Second CRC of first page + all remaining pages [page_size+6..end]
                        if physical_pages.len() > 6 {
                            let _ = physical_pages.split_to(6);
                            blob_state
                                .blob
                                .write_at(
                                    write_at_offset + (logical_page_size + 6) as u64,
                                    physical_pages,
                                )
                                .await?;
                        }
                    } else {
                        // Write 2 only: Second CRC of first page + all remaining pages [page_size+6..end]
                        let second_crc_start = logical_page_size + 6;
                        if physical_pages.len() > second_crc_start {
                            let _ = physical_pages.split_to(second_crc_start);
                            blob_state
                                .blob
                                .write_at(write_at_offset + second_crc_start as u64, physical_pages)
                                .await?;
                        }
                    }
                }
                ProtectedCrc::Second => {
                    // Protected CRC is second: [page_size+6..page_size+12]
                    // Write 1: New data + first CRC of first page [prefix_len..page_size+6]
                    let first_crc_end = logical_page_size + 6;
                    if prefix_len < first_crc_end {
                        let _ = physical_pages.split_to(prefix_len);
                        let first_payload = physical_pages.split_to(first_crc_end - prefix_len);
                        blob_state
                            .blob
                            .write_at(write_at_offset + prefix_len as u64, first_payload)
                            .await?;

                        // Write 2: All remaining pages (if any) [physical_page_size..end]
                        let skip = physical_page_size - first_crc_end;
                        if physical_pages.len() > skip {
                            let _ = physical_pages.split_to(skip);
                            blob_state
                                .blob
                                .write_at(
                                    write_at_offset + physical_page_size as u64,
                                    physical_pages,
                                )
                                .await?;
                        }
                    } else if physical_pages.len() > physical_page_size {
                        // Write 2 only: All remaining pages (if any) [physical_page_size..end]
                        let _ = physical_pages.split_to(physical_page_size);
                        blob_state
                            .blob
                            .write_at(write_at_offset + physical_page_size as u64, physical_pages)
                            .await?;
                    }
                }
            }
        } else {
            // No protected regions, write everything in one operation
            blob_state
                .blob
                .write_at(write_at_offset, physical_pages)
                .await?;
        }

        Ok(())
    }

    /// Returns the logical size of the blob. This accounts for both written and buffered data.
    pub async fn size(&self) -> u64 {
        let buffer = self.buffer.read().await;
        buffer.size()
    }

    /// Reads up to `max_len` bytes starting at `logical_offset`, but only as many as are
    /// available.
    ///
    /// This is useful for reading variable-length prefixes (like varints) where you want to read
    /// up to a maximum number of bytes but the actual data might be shorter.
    ///
    /// Returns immutable bytes containing all available data up to `max_len`.
    /// Returns an error if no bytes are available at the given offset.
    pub async fn read_at_up_to(
        &self,
        logical_offset: u64,
        max_len: usize,
    ) -> Result<IoBufs, Error> {
        if max_len == 0 {
            return Ok(IoBufs::default());
        }
        let blob_size = self.size().await;
        let available = (blob_size.saturating_sub(logical_offset) as usize).min(max_len);
        if available == 0 {
            return Err(Error::BlobInsufficientLength);
        }

        self.read_at(logical_offset, available).await
    }

    /// Read exactly `len` immutable bytes starting at `logical_offset`.
    ///
    /// # Errors
    ///
    /// Returns [Error::OffsetOverflow] if `logical_offset + len` overflows.
    /// Returns [Error::BlobInsufficientLength] if the requested range exceeds the logical size.
    /// Returns [Error::ReadFailed] if reading missing persisted pages from the underlying blob
    /// fails.
    pub async fn read_at(&self, logical_offset: u64, len: usize) -> Result<IoBufs, Error> {
        if len == 0 {
            return Ok(IoBufs::default());
        }

        // Ensure the read doesn't overflow.
        let end_offset = logical_offset
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Acquire a read lock on the buffer.
        let buffer = self.buffer.read().await;

        // If the data required is beyond the size of the blob, return an error.
        if end_offset > buffer.size() {
            return Err(Error::BlobInsufficientLength);
        }

        // Entirely in buffered tip.
        if logical_offset >= buffer.offset {
            let start = (logical_offset - buffer.offset) as usize;
            let end = start + len;
            return Ok(buffer.slice(start..end).into());
        }

        // Split the request into:
        // - persisted prefix: bytes before `buffer.offset` (served via cache/blob)
        // - tip suffix: bytes at/after `buffer.offset` (served from tip)
        // If the request is entirely persisted, `persisted_len == len` and `tip` is `None`.
        let persisted_len = ((buffer.offset - logical_offset) as usize).min(len);
        let tip = if persisted_len < len {
            Some(buffer.slice(..(len - persisted_len)))
        } else {
            None
        };

        // Release buffer lock before potential I/O.
        drop(buffer);

        // Fast path: try to read *only* from page cache without acquiring blob lock. This allows
        // concurrent reads even while a flush is in progress.
        let (cached, cached_len) =
            self.cache_ref
                .read_cached(self.id, logical_offset, persisted_len);

        // Full cache hit for the persisted prefix: no blob read required.
        let mut out = if cached_len == persisted_len {
            cached
        } else {
            // Slow path: cache miss (partial or full), acquire blob read lock to ensure any
            // in-flight write completes before we read from the blob.
            let blob_guard = self.blob_state.read().await;
            self.cache_ref
                .read(
                    &blob_guard.blob,
                    self.id,
                    logical_offset,
                    persisted_len,
                    cached,
                    cached_len,
                )
                .await?
        };

        if let Some(tip) = tip {
            out.append(tip);
        }

        Ok(out)
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
        let logical_page_size = self.cache_ref.logical_page_size() as usize;
        let physical_page_size = self.cache_ref.physical_page_size() as usize;
        let pages_to_write = buffer.len() / logical_page_size;
        let mut write_buffer = IoBufs::default();
        let buffer_data = buffer.as_ref();
        let logical_page_size_u16 =
            u16::try_from(logical_page_size).expect("page size must fit in u16 for CRC record");
        let crc_record_size = CHECKSUM_SIZE as usize;

        if pages_to_write > 0 {
            let total_crc_bytes = pages_to_write
                .checked_mul(crc_record_size)
                .expect("crc blob length overflow");
            let mut crc_blob = self.cache_ref.pool().alloc(total_crc_bytes);
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
                crc_blob.put_slice(&crc_record.to_bytes());
            }
            let crc_blob = crc_blob.freeze();

            for page in 0..pages_to_write {
                let start_read_idx = page * logical_page_size;
                let end_read_idx = start_read_idx + logical_page_size;
                write_buffer.append(buffer.slice(start_read_idx..end_read_idx));

                let crc_start = page * crc_record_size;
                write_buffer.append(crc_blob.slice(crc_start..crc_start + crc_record_size));
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

        // Partial page needs zero padding in physical representation.
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

    /// Flushes any buffered data, then returns a [Replay] for the underlying blob.
    ///
    /// The returned replay can be used to sequentially read all pages from the blob while ensuring
    /// all data passes integrity verification. CRCs are validated but not included in the output.
    pub async fn replay(&self, buffer_size: NonZeroUsize) -> Result<Replay<B>, Error> {
        let logical_page_size = self.cache_ref.logical_page_size();
        let logical_page_size_nz =
            NonZeroU16::new(logical_page_size as u16).expect("page_size is non-zero");

        // Flush any buffered data (without fsync) so the reader sees all written data.
        {
            let buf_guard = self.buffer.write().await;
            if !buf_guard.is_immutable() {
                self.flush_internal(buf_guard, true).await?;
            }
        }

        let physical_page_size = self.cache_ref.physical_page_size();

        // Convert buffer size (bytes) to page count
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
    pub async fn sync(&self) -> Result<(), Error> {
        // Flush any buffered data, including any partial page. When flush_internal returns,
        // write_at has completed and data has been written to the underlying blob.
        let buf_guard = self.buffer.write().await;
        if buf_guard.is_immutable() {
            return Ok(());
        }
        self.flush_internal(buf_guard, true).await?;

        // Sync the underlying blob. We need the blob read lock here since sync() requires access
        // to the blob, but only a read lock since we're not modifying blob state.
        let blob_state = self.blob_state.read().await;
        blob_state.blob.sync().await
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

        // Handle growing by appending zero bytes.
        if size > current_size {
            let zeros_needed = (size - current_size) as usize;
            let mut zeros = self.cache_ref.pool().alloc(zeros_needed);
            zeros.put_bytes(0, zeros_needed);
            self.append(zeros.as_ref()).await?;
            return Ok(());
        }

        // Implementation note: rewinding the blob across a page boundary potentially results in
        // stale data remaining in the page cache. We don't proactively purge the data
        // within this function since it would be inaccessible anyway. Instead we ensure it is
        // always updated should the blob grow back to the point where we have new data for the same
        // page, if any old data hasn't expired naturally by then.

        let logical_page_size = self.cache_ref.logical_page_size();
        let physical_page_size = self.cache_ref.physical_page_size();

        // Flush any buffered data first to ensure we have a consistent state on disk.
        self.sync().await?;

        // Acquire both locks to prevent concurrent operations.
        let mut buf_guard = self.buffer.write().await;
        if buf_guard.is_immutable() {
            return Err(Error::ImmutableBlob);
        }
        let mut blob_guard = self.blob_state.write().await;

        // Calculate the physical size needed for the new logical size.
        let full_pages = size / logical_page_size;
        let partial_bytes = size % logical_page_size;
        let new_physical_size = if partial_bytes > 0 {
            // We need full_pages + 1 physical pages to hold the partial data.
            // The partial page will be padded to full physical page size.
            (full_pages + 1) * physical_page_size
        } else {
            // No partial page needed.
            full_pages * physical_page_size
        };

        // Resize the underlying blob.
        blob_guard.blob.resize(new_physical_size).await?;
        blob_guard.partial_page_state = None;

        // Update blob state and buffer based on the desired logical size. The partial page data is
        // read with CRC validation; the validated length may exceed partial_bytes (reflecting the
        // old data length), but we only load the prefix we need. The next sync will write the
        // correct CRC for the new length.
        //
        // Note: This updates state before validation completes, which could leave state
        // inconsistent if validation fails. This is acceptable because failures from mutable
        // methods are fatal - callers must not use the blob after any error.

        blob_guard.current_page = full_pages;
        buf_guard.offset = full_pages * logical_page_size;

        if partial_bytes > 0 {
            // There's a partial page. Read its data from disk with CRC validation.
            let page_data = super::read_page_from_blob(
                &blob_guard.blob,
                full_pages,
                logical_page_size,
                self.cache_ref.pool(),
            )
            .await?;

            // Ensure the validated data covers what we need.
            if (page_data.len() as u64) < partial_bytes {
                return Err(Error::InvalidChecksum);
            }

            buf_guard.clear();
            let over_capacity = buf_guard.append(&page_data.as_ref()[..partial_bytes as usize]);
            assert!(!over_capacity);
        } else {
            // No partial page - all pages are full or blob is empty.
            buf_guard.clear();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, Runner as _, Storage as _};
    use commonware_codec::ReadExt;
    use commonware_macros::test_traced;
    use commonware_utils::{NZUsize, NZU16};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(103); // janky size to ensure we test page alignment
    const PHYSICAL_PAGE_SIZE: NonZeroU16 = NZU16!(115);
    const BUFFER_SIZE: usize = PAGE_SIZE.get() as usize * 2;

    #[test_traced("DEBUG")]
    fn test_append_crc_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            // Open a new blob.
            let (blob, blob_size) = context.open("test_partition", b"test_blob").await.unwrap();
            assert_eq!(blob_size, 0);

            // Create a page cache reference.
            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));

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
            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));

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
    fn test_read_at_up_to_zero_len_returns_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            // Open a new blob.
            let (blob, blob_size) = context
                .open("test_partition", b"read_at_up_to_zero_len")
                .await
                .unwrap();
            assert_eq!(blob_size, 0);

            // Create a page cache reference.
            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));

            // Create an Append wrapper and write some data.
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.append(&[1, 2, 3, 4]).await.unwrap();

            let buf = append.read_at_up_to(0, 0).await.unwrap();
            assert!(buf.is_empty(), "read_at_up_to must return an empty buffer");
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_at_up_to_non_zero_partial_and_eof() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"read_at_up_to_non_zero")
                .await
                .unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.append(&[1, 2, 3, 4]).await.unwrap();

            let partial = append.read_at_up_to(2, 10).await.unwrap().coalesce();
            assert_eq!(partial.as_ref(), &[3, 4]);

            let err = append.read_at_up_to(4, 1).await.unwrap_err();
            assert!(matches!(err, Error::BlobInsufficientLength));
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_at_up_to_overlap_persisted_and_tip() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"read_at_up_to_overlap")
                .await
                .unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            append
                .append(&vec![7u8; PAGE_SIZE.get() as usize])
                .await
                .unwrap();
            append.sync().await.unwrap();
            append.append(&[9, 10, 11, 12]).await.unwrap();

            let start = PAGE_SIZE.get() as u64 - 2;
            let all_available = append.read_at_up_to(start, 128).await.unwrap().coalesce();
            assert_eq!(all_available.as_ref(), &[7, 7, 9, 10, 11, 12]);

            let capped = append.read_at_up_to(start, 4).await.unwrap().coalesce();
            assert_eq!(capped.as_ref(), &[7, 7, 9, 10]);
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_at_zero_len_returns_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"read_at_zero_len")
                .await
                .unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();
            append.append(&[1, 2, 3, 4]).await.unwrap();

            let buf = append.read_at(0, 0).await.unwrap();
            assert!(
                buf.is_empty(),
                "read_at must return an empty buffer for len=0"
            );
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_at_overlap_persisted_and_tip() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"read_at_overlap")
                .await
                .unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            // Persist one full page.
            append
                .append(&vec![7u8; PAGE_SIZE.get() as usize])
                .await
                .unwrap();
            append.sync().await.unwrap();

            // Keep following bytes in tip.
            append.append(&[9, 10, 11, 12]).await.unwrap();

            let start = PAGE_SIZE.get() as u64 - 2;
            let read = append.read_at(start, 6).await.unwrap().coalesce();
            assert_eq!(read.as_ref(), &[7, 7, 9, 10, 11, 12]);
        });
    }

    #[test_traced("DEBUG")]
    fn test_read_at_spans_multiple_cached_pages() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let (blob, blob_size) = context
                .open("test_partition", b"read_at_multi_cached_pages")
                .await
                .unwrap();
            assert_eq!(blob_size, 0);

            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));
            let append = Append::new(blob, blob_size, BUFFER_SIZE, cache_ref)
                .await
                .unwrap();

            let page_size = PAGE_SIZE.get() as usize;
            let data: Vec<u8> = (0..(page_size * 3)).map(|i| (i % 251) as u8).collect();
            append.append(&data).await.unwrap();
            append.sync().await.unwrap();

            // Read across page boundaries from persisted, cached pages.
            let start = (page_size - 16) as u64;
            let len = page_size + 32;
            let read = append.read_at(start, len).await.unwrap();
            assert!(!read.is_single());
            assert_eq!(
                read.coalesce().as_ref(),
                &data[start as usize..start as usize + len]
            );
        });
    }

    /// Helper to read the CRC record from raw blob bytes at the end of a physical page.
    fn read_crc_record_from_page(page_bytes: &[u8]) -> Checksum {
        let crc_start = page_bytes.len() - CHECKSUM_SIZE as usize;
        Checksum::read(&mut &page_bytes[crc_start..]).unwrap()
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

    /// Test that slot 1 is NOT overwritten when it's the protected slot.
    ///
    /// Strategy: After extending twice (so slot 1 becomes authoritative with larger len),
    /// mangle the non-authoritative slot 0. Then extend again - slot 0 should be overwritten
    /// with the new CRC, while slot 1 (protected) should remain untouched.
    #[test_traced("DEBUG")]
    fn test_crc_slot1_protected() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));
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
            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));
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
            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));
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
            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));
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
            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));
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
            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));
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
            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));
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
    fn test_immutable_blob_rejects_append_and_resize() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            const BUFFER_SIZE: usize = 256;

            let cache_ref = CacheRef::from_pooler(&context, NZU16!(76), NZUsize!(4));

            let (blob, size) = context
                .open("test_partition", b"immutable_test")
                .await
                .unwrap();

            let append = Append::new(blob, size, BUFFER_SIZE, cache_ref.clone())
                .await
                .unwrap();

            // Write some initial data.
            append.append(&[1, 2, 3, 4, 5]).await.unwrap();
            append.sync().await.unwrap();
            assert_eq!(append.size().await, 5);

            // Convert to immutable.
            append.to_immutable().await.unwrap();
            assert!(append.is_immutable().await);

            // Verify append() returns ImmutableBlob error.
            let result = append.append(&[6, 7, 8]).await;
            assert!(
                matches!(result, Err(crate::Error::ImmutableBlob)),
                "Expected ImmutableBlob error from append(), got: {:?}",
                result
            );

            // Verify resize() returns ImmutableBlob error.
            let result = append.resize(100).await;
            assert!(
                matches!(result, Err(crate::Error::ImmutableBlob)),
                "Expected ImmutableBlob error from resize(), got: {:?}",
                result
            );

            // Verify sync() returns Ok.
            let result = append.sync().await;
            assert!(
                result.is_ok(),
                "sync() on immutable blob should return Ok, got: {:?}",
                result
            );

            // Verify data is still readable.
            let data: Vec<u8> = append.read_at(0, 5).await.unwrap().coalesce().into();
            assert_eq!(data, vec![1, 2, 3, 4, 5]);
        });
    }

    #[test]
    fn test_corrupted_crc_len_too_large() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));
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
                    // Error is also acceptable (for immutable blobs)
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
            let cache_ref =
                CacheRef::from_pooler(&context, PHYSICAL_PAGE_SIZE, NZUsize!(BUFFER_SIZE));

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
