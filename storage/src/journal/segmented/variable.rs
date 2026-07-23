//! An append-only log for storing arbitrary variable length items.
//!
//! `segmented::Journal` is an append-only log for storing arbitrary variable length data on disk. In
//! addition to replay, stored items can be directly retrieved given their section number and offset
//! within the section.
//!
//! # Format
//!
//! Data stored in `Journal` is persisted in one of many Blobs within a caller-provided `partition`.
//! The particular [Blob] in which data is stored is identified by a `section` number (`u64`).
//! Within a `section`, data is appended as an `item` with the following format:
//!
//! ```text
//! +---+---+---+---+---+---+---+---+
//! |       0 ~ 4       |    ...    |
//! +---+---+---+---+---+---+---+---+
//! | Size (varint u32) |   Data    |
//! +---+---+---+---+---+---+---+---+
//! ```
//!
//! # Open Blobs
//!
//! `Journal` uses 1 `commonware-storage::Blob` per `section` to store data. All `Blobs` in a given
//! `partition` are kept open during the lifetime of `Journal`. If the caller wishes to bound the
//! number of open `Blobs`, they can group data into fewer `sections` and/or prune unused
//! `sections`.
//!
//! # Sync
//!
//! Data written to `Journal` may not be immediately persisted to `Storage`. It is up to the caller
//! to determine when to force pending data to be written to `Storage` using the `sync` (or
//! `sync_all`) method.
//!
//! # Pruning
//!
//! All data appended to `Journal` must be assigned to some `section` (`u64`). This assignment
//! allows the caller to prune data from `Journal` by specifying a minimum `section` number. This
//! could be used, for example, by some blockchain application to prune old blocks.
//!
//! # Replay
//!
//! During application initialization, it is very common to replay data from `Journal` to recover
//! some in-memory state. `Journal` is heavily optimized for this pattern and provides a `replay`
//! method that consumes the journal into an owned [Replay] reader yielding all items in order
//! of their `section` and `offset`. [Replay::finish] returns the journal once exhausted.
//!
//! # Compression
//!
//! `Journal` supports optional compression using `zstd`. This can be enabled by setting the
//! `compression` field in the `Config` struct to a valid `zstd` compression level. This setting can
//! be changed between initializations of `Journal`, however, it must remain populated if any data
//! was written with compression enabled.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic, buffer::paged::CacheRef};
//! use commonware_storage::journal::segmented::variable::{Journal, Config};
//! use commonware_utils::{NZUsize, NZU16};
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a page cache
//!     let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10));
//!
//!     // Create a journal
//!     let journal = Journal::init(context, Config {
//!         partition: "partition".into(),
//!         compression: None,
//!         codec_config: (),
//!         page_cache,
//!         write_buffer: NZUsize!(1024 * 1024),
//!     }).await.unwrap();
//!
//!     // Append data to the journal
//!     let (journal, _, _) = journal.append(1, &128).await.unwrap();
//!
//!     // Sync the journal
//!     journal.sync_all().await.unwrap();
//! });
//! ```

use super::manager::{AppendFactory, Config as ManagerConfig, Manager};
use crate::journal::{
    Error,
    frame::{
        FrameInfo, decode_item, decode_length_prefix, encode_frame_into, find_frame, read_frame_at,
    },
};
use commonware_codec::{Codec, CodecShared, varint::MAX_U32_VARINT_SIZE};
use commonware_runtime::{
    Blob, Buf, Handle, IoBuf, Metrics, Storage,
    buffer::paged::{CacheRef, Replay as BlobReplay, Writer},
};
use std::{collections::VecDeque, io::Cursor, num::NonZeroUsize};
use tracing::{trace, warn};

/// Configuration for `Journal` storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The `commonware-runtime::Storage` partition to use
    /// for storing journal blobs.
    pub partition: String,

    /// Optional compression level (using `zstd`) to apply to data before storing.
    pub compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding items.
    pub codec_config: C,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,
}

/// State for replaying a single section's blob.
struct SectionReplay<B: Blob> {
    section: u64,
    reader: BlobReplay<B>,
    skip_bytes: u64,
    offset: u64,
    valid_offset: u64,
    pending: Option<(usize, usize)>,
}

/// The journal's state, boxed so the public [Journal] handle stays pointer-sized.
struct Inner<E: Storage + Metrics, V: Codec> {
    manager: Manager<E, AppendFactory>,

    /// Compression level (if enabled).
    compression: Option<u8>,

    /// Codec configuration.
    codec_config: V::Cfg,
}

impl<E: Storage + Metrics, V: CodecShared> Inner<E, V> {
    /// See [Journal::init].
    async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let manager_cfg = ManagerConfig {
            partition: cfg.partition,
            factory: AppendFactory {
                write_buffer: cfg.write_buffer,
                page_cache_ref: cfg.page_cache,
            },
        };
        let manager = Manager::init(context, manager_cfg).await?;

        Ok(Self {
            manager,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
        })
    }

    /// Reads an item from the blob at the given offset.
    async fn read(
        compressed: bool,
        cfg: &V::Cfg,
        blob: &Writer<E::Blob>,
        offset: u64,
    ) -> Result<(u64, u32, V), Error> {
        read_frame_at(blob, offset, cfg, compressed).await
    }

    /// Encode an item.
    ///
    /// Returns `(buf, item_len)` where `item_len` is the length of the encoded (and
    /// possibly compressed) payload, excluding the size prefix.
    fn encode_item(compression: Option<u8>, item: &V) -> Result<(Vec<u8>, u32), Error> {
        let mut buf = Vec::new();
        let item_len = encode_frame_into(compression, item, &mut buf)?;
        Ok((buf, item_len))
    }

    /// See [Journal::append].
    async fn append(&mut self, section: u64, item: &V) -> Result<(u64, u32), Error> {
        let (buf, item_len) = Self::encode_item(self.compression, item)?;
        self.append_raw(section, IoBuf::from(buf))
            .await
            .map(|offset| (offset, item_len))
    }

    /// Append pre-encoded bytes to the given section, returning the byte offset
    /// where the data was written.
    ///
    /// The buffer must be in the on-disk format produced by [Self::encode_item].
    async fn append_raw(&mut self, section: u64, buf: IoBuf) -> Result<u64, Error> {
        let blob = self.manager.get_or_create(section).await?;
        let offset = blob.append_owned(buf).await?;
        trace!(blob = section, offset, "appended item");
        Ok(offset)
    }

    /// See [Journal::get].
    async fn get(&self, section: u64, offset: u64) -> Result<V, Error> {
        let blob = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        // Perform a multi-op read.
        let (_, _, item) =
            Self::read(self.compression.is_some(), &self.codec_config, blob, offset).await?;
        Ok(item)
    }

    /// See [Journal::get_many].
    async fn get_many(&self, section: u64, offsets: &[u64]) -> Result<Vec<V>, Error> {
        if offsets.is_empty() {
            return Ok(Vec::new());
        }
        let blob = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        let compressed = self.compression.is_some();
        let cfg = &self.codec_config;
        let mut items = Vec::with_capacity(offsets.len());
        for &offset in offsets {
            let (_, _, item) = Self::read(compressed, cfg, blob, offset).await?;
            items.push(item);
        }
        Ok(items)
    }

    /// See [Journal::try_get_sync].
    fn try_get_sync(&self, section: u64, offset: u64) -> Option<V> {
        let blob = self.manager.get(section).ok()??;
        let remaining = blob.size().checked_sub(offset)?;
        let header_len = usize::try_from(remaining.min(MAX_U32_VARINT_SIZE as u64)).ok()?;
        if header_len == 0 {
            return None;
        }

        // Read the varint header to determine item size.
        let mut header = [0u8; MAX_U32_VARINT_SIZE];
        if !blob.try_read_sync_into(&mut header[..header_len], offset) {
            return None;
        }
        let mut cursor = Cursor::new(&header[..header_len]);
        let (_, frame_info) = find_frame(&mut cursor, offset).ok()?;
        let (varint_len, data_len) = match frame_info {
            FrameInfo::Complete {
                varint_len,
                data_len,
            } => (varint_len, data_len),
            FrameInfo::Incomplete {
                varint_len,
                total_len,
                ..
            } => (varint_len, total_len),
        };
        let item_len = varint_len.checked_add(data_len)?;
        if item_len > usize::try_from(remaining).ok()? {
            return None;
        }

        // If the full item fits in the header read, decode directly.
        let compressed = self.compression.is_some();
        if item_len <= header_len {
            return decode_item::<V>(
                &header[varint_len..varint_len + data_len],
                &self.codec_config,
                compressed,
            )
            .ok();
        }

        // Otherwise try reading the full item from cache.
        let mut buf = vec![0u8; item_len];
        if !blob.try_read_sync_into(&mut buf, offset) {
            return None;
        }
        decode_item::<V>(
            &buf[varint_len..varint_len + data_len],
            &self.codec_config,
            compressed,
        )
        .ok()
    }

    /// See [Journal::size].
    fn size(&self, section: u64) -> Result<u64, Error> {
        self.manager.size(section)
    }

    /// See [Journal::rewind].
    async fn rewind(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.manager.rewind(section, size).await
    }

    /// See [Journal::rewind_section].
    async fn rewind_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.manager.rewind_section(section, size).await
    }

    /// See [Journal::sync].
    async fn sync(&mut self, sections: impl crate::Sections) -> Result<(), Error> {
        self.manager.sync(sections).await
    }

    /// See [Journal::start_sync].
    async fn start_sync(&mut self, sections: impl crate::Sections) -> Result<Handle<()>, Error> {
        self.manager.start_sync(sections).await
    }

    /// See [Journal::sync_all].
    async fn sync_all(&mut self) -> Result<(), Error> {
        self.manager.sync_all().await
    }

    /// See [Journal::prune].
    async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        self.manager.prune(min).await
    }

    /// See [Journal::pruned].
    const fn pruned(&self, section: u64) -> bool {
        self.manager.pruned(section)
    }

    /// See [Journal::oldest_section].
    fn oldest_section(&self) -> Option<u64> {
        self.manager.oldest_section()
    }

    /// See [Journal::newest_section].
    fn newest_section(&self) -> Option<u64> {
        self.manager.newest_section()
    }

    /// See [Journal::is_empty].
    fn is_empty(&self) -> bool {
        self.manager.is_empty()
    }

    /// See [Journal::num_sections].
    fn num_sections(&self) -> usize {
        self.manager.num_sections()
    }

    /// See [Journal::destroy].
    async fn destroy(self) -> Result<(), Error> {
        self.manager.destroy().await
    }

    /// See [Journal::clear].
    async fn clear(&mut self) -> Result<(), Error> {
        self.manager.clear().await
    }
}

/// A segmented journal with variable-size entries.
///
/// Each section is stored in a separate blob. Items are length-prefixed with a varint.
///
/// # Repair
///
/// Like
/// [sqlite](https://github.com/sqlite/sqlite/blob/8658a8df59f00ec8fcfea336a2a6a4b5ef79d2ee/src/wal.c#L1504-L1505)
/// and
/// [rocksdb](https://github.com/facebook/rocksdb/blob/0c533e61bc6d89fdf1295e8e0bcee4edb3aef401/include/rocksdb/options.h#L441-L445),
/// the first invalid data read will be considered the new end of the journal (and the
/// underlying [Blob] will be truncated to the last valid item). Repair occurs during
/// replay (not init) because any blob could have trailing bytes.
///
/// Mutating functions consume the journal and return it only on success: an error (or a dropped
/// future) destroys the handle. [Journal::replay] consumes the journal into an owned [Replay]
/// reader, which returns it via [Replay::finish] once exhausted. Mutations on pruned sections
/// fail with [Error::AlreadyPrunedToSection] without mutating. Check [Journal::pruned] first to
/// keep the handle.
pub struct Journal<E: Storage + Metrics, V: Codec>(Box<Inner<E, V>>);

impl<E: Storage + Metrics, V: CodecShared> std::fmt::Debug for Journal<E, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("oldest_section", &self.oldest_section())
            .field("newest_section", &self.newest_section())
            .finish_non_exhaustive()
    }
}

impl<E: Storage + Metrics, V: CodecShared> Journal<E, V> {
    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during
    /// initialization. The `replay` method can be used
    /// to iterate over all items in the `Journal`.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        Ok(Self(Box::new(Inner::init(context, cfg).await?)))
    }

    /// Consumes the journal and returns an owned [Replay] reader over all items starting
    /// with the item at the given `start_section` and `start_offset` into that section.
    ///
    /// Setup flushes buffered pages so the reader observes every accepted write. It
    /// validates replay setup but does not allocate `buffer` bytes per blob. Page buffers
    /// are allocated lazily as the reader advances.
    pub async fn replay(
        mut self,
        start_section: u64,
        start_offset: u64,
        buffer: NonZeroUsize,
    ) -> Result<Replay<E, V>, Error> {
        let mut sections = VecDeque::new();
        for (&section, blob) in self.0.manager.sections_from(start_section) {
            if section == start_section && start_offset > blob.size() {
                return Err(Error::ItemOutOfRange(start_offset));
            }
            let reader = blob.replay(buffer).await?;
            let skip_bytes = if section == start_section {
                start_offset
            } else {
                0
            };
            sections.push_back(SectionReplay {
                section,
                reader,
                skip_bytes,
                offset: 0,
                valid_offset: skip_bytes,
                pending: None,
            });
        }
        let finished = sections.is_empty();
        Ok(Replay {
            journal: self,
            sections,
            finished,
            errored: false,
            repairing: false,
        })
    }

    /// Appends an item to `Journal` in a given `section`, returning the offset
    /// where the item was written and the size of the item (which may differ
    /// from the raw encoded size if compression is enabled).
    pub async fn append(mut self, section: u64, item: &V) -> Result<(Self, u64, u32), Error> {
        let (offset, item_len) = self.0.append(section, item).await?;
        Ok((self, offset, item_len))
    }

    /// Retrieves an item from `Journal` at a given `section` and `offset`.
    ///
    /// # Errors
    ///  - [Error::AlreadyPrunedToSection] if the requested `section` has been pruned during the
    ///    current execution.
    ///  - [Error::SectionOutOfRange] if the requested `section` is empty (i.e. has never had any
    ///    data appended to it, or has been pruned in a previous execution).
    ///  - An invalid `offset` for a given section (that is, an offset that doesn't correspond to a
    ///    previously appended item) will result in an error, with the specific type being
    ///    undefined.
    pub async fn get(&self, section: u64, offset: u64) -> Result<V, Error> {
        self.0.get(section, offset).await
    }

    /// Read multiple items from the same section.
    ///
    /// Offsets should be sorted in ascending order.
    pub async fn get_many(&self, section: u64, offsets: &[u64]) -> Result<Vec<V>, Error> {
        self.0.get_many(section, offsets).await
    }

    /// Get an item if it can be done synchronously (e.g. without I/O), returning `None` otherwise.
    pub fn try_get_sync(&self, section: u64, offset: u64) -> Option<V> {
        self.0.try_get_sync(section, offset)
    }

    /// Gets the size of the journal for a specific section.
    ///
    /// Returns 0 if the section does not exist.
    pub fn size(&self, section: u64) -> Result<u64, Error> {
        self.0.size(section)
    }

    /// Rewinds the journal to the given `section` and `size`.
    ///
    /// This removes any data beyond the specified `section` and `size`.
    ///
    /// # Warnings
    ///
    /// * This operation is not guaranteed to survive restarts until sync is called.
    /// * This operation is not atomic, but it will always leave the journal in a consistent state
    ///   in the event of failure since blobs are always removed in reverse order of section.
    pub async fn rewind(mut self, section: u64, size: u64) -> Result<Self, Error> {
        self.0.rewind(section, size).await?;
        Ok(self)
    }

    /// Rewinds the `section` to the given `size`.
    ///
    /// Unlike [Self::rewind], this method does not modify anything other than the given `section`.
    ///
    /// # Warning
    ///
    /// This operation is not guaranteed to survive restarts until sync is called.
    pub async fn rewind_section(mut self, section: u64, size: u64) -> Result<Self, Error> {
        self.0.rewind_section(section, size).await?;
        Ok(self)
    }

    /// Ensures the given `sections` are synced to the underlying store.
    ///
    /// If a selected section does not exist (and has not been pruned), no error will be
    /// returned.
    pub async fn sync(mut self, sections: impl crate::Sections) -> Result<Self, Error> {
        self.0.sync(sections).await?;
        Ok(self)
    }

    /// Start syncing the given `sections` to storage.
    ///
    /// An error reported by the returned [Handle] is fatal to the journal: the caller
    /// must stop using the returned journal.
    pub async fn start_sync(
        mut self,
        sections: impl crate::Sections,
    ) -> Result<(Self, Handle<()>), Error> {
        let handle = self.0.start_sync(sections).await?;
        Ok((self, handle))
    }

    /// Syncs all open sections.
    pub async fn sync_all(mut self) -> Result<Self, Error> {
        self.0.sync_all().await?;
        Ok(self)
    }

    /// Prunes all `sections` less than `min`. Returns true if any sections were pruned.
    pub async fn prune(mut self, min: u64) -> Result<(Self, bool), Error> {
        let pruned = self.0.prune(min).await?;
        Ok((self, pruned))
    }

    /// Returns true when `section` is below the prune floor.
    ///
    /// The floor only tracks prunes from the current execution and resets at init, so a
    /// section pruned in a previous execution reports false.
    pub fn pruned(&self, section: u64) -> bool {
        self.0.pruned(section)
    }

    /// Returns the number of the oldest section in the journal.
    pub fn oldest_section(&self) -> Option<u64> {
        self.0.oldest_section()
    }

    /// Returns the number of the newest section in the journal.
    pub fn newest_section(&self) -> Option<u64> {
        self.0.newest_section()
    }

    /// Returns true if no sections exist.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of sections.
    pub fn num_sections(&self) -> usize {
        self.0.num_sections()
    }

    /// Removes any underlying blobs created by the journal.
    pub async fn destroy(self) -> Result<(), Error> {
        self.0.destroy().await
    }

    /// Clear all data, resetting the journal to an empty state.
    ///
    /// Unlike `destroy`, this keeps the journal alive so it can be reused.
    pub async fn clear(mut self) -> Result<Self, Error> {
        self.0.clear().await?;
        Ok(self)
    }
}

/// Owned replay reader over a [Journal]'s items.
///
/// Yields `(section, offset, size, item)` in order and repairs invalid trailing data as it is
/// encountered. Dropping the reader before it is exhausted destroys the journal (leaving later
/// sections unrepaired): recovery is re-initialization. Call [Replay::finish] on an exhausted
/// reader to get the journal back.
pub struct Replay<E: Storage + Metrics, V: Codec> {
    journal: Journal<E, V>,
    sections: VecDeque<SectionReplay<E::Blob>>,
    finished: bool,
    errored: bool,
    repairing: bool,
}

impl<E: Storage + Metrics, V: CodecShared> Replay<E, V> {
    /// Returns the next `(section, offset, size, item)`, or `None` once every section is
    /// exhausted.
    ///
    /// An error ends the section that produced it, and iteration continues with the
    /// next section. The exception is [Error::ReplayInterrupted], which ends the
    /// replay.
    pub async fn next(&mut self) -> Option<Result<(u64, u64, u32, V), Error>> {
        // A dropped future can interrupt a repair, leaving the section's writer with
        // in-memory state that no longer matches the blob. Fail the replay rather than
        // repair or decode over it.
        if self.repairing {
            self.repairing = false;
            self.sections.clear();
            return self.fail(Error::ReplayInterrupted);
        }
        while let Some(current) = self.sections.front_mut() {
            let blob_size = current.reader.blob_size();

            // Resume a recorded frame header or decode the next one
            let (item_size, varint_len) = match current.pending {
                Some(header) => header,
                None => {
                    // Ensure we have enough data for varint header.
                    // ensure() returns Ok(false) if exhausted with fewer bytes,
                    // but we still try to decode from remaining bytes.
                    match current.reader.ensure(MAX_U32_VARINT_SIZE).await {
                        Ok(true) => {}
                        Ok(false) => {
                            // Reader exhausted - check if buffer is empty
                            if current.reader.remaining() == 0 {
                                self.sections.pop_front();
                                continue;
                            }
                            // Buffer still has data - continue to try decoding
                        }
                        Err(err) => {
                            self.sections.pop_front();
                            return self.fail(err.into());
                        }
                    }

                    // Skip bytes if needed (for start_offset)
                    if current.skip_bytes > 0 {
                        let to_skip =
                            current.skip_bytes.min(current.reader.remaining() as u64) as usize;
                        current.reader.advance(to_skip);
                        current.skip_bytes -= to_skip as u64;
                        current.offset += to_skip as u64;
                        continue;
                    }

                    // Try to decode length prefix
                    let before_remaining = current.reader.remaining();
                    match decode_length_prefix(&mut current.reader) {
                        Ok(header) => {
                            // Record the header before awaiting the body so a dropped
                            // next future resumes losslessly.
                            current.pending = Some(header);
                            header
                        }
                        Err(err) => {
                            // Could be incomplete varint - check if reader exhausted
                            if current.reader.is_exhausted()
                                || before_remaining < MAX_U32_VARINT_SIZE
                            {
                                // Treat as trailing bytes
                                if current.valid_offset < blob_size && current.offset < blob_size {
                                    warn!(
                                        blob = current.section,
                                        bad_offset = current.offset,
                                        new_size = current.valid_offset,
                                        "trailing bytes detected: truncating"
                                    );
                                    // Tail repair is exceptional; make it durable
                                    // immediately so callers do not need to track
                                    // replay-time repaired sections separately.
                                    let (section, valid_offset) =
                                        (current.section, current.valid_offset);
                                    self.repairing = true;
                                    let repaired =
                                        repair_blob(&mut self.journal, section, valid_offset).await;
                                    self.repairing = false;
                                    if let Err(err) = repaired {
                                        self.sections.pop_front();
                                        return self.fail(err);
                                    }
                                }
                                self.sections.pop_front();
                                continue;
                            }
                            self.sections.pop_front();
                            return self.fail(err);
                        }
                    }
                }
            };

            // Ensure we have enough data for item body
            match current.reader.ensure(item_size).await {
                Ok(true) => {}
                Ok(false) => {
                    // Incomplete item at end - truncate
                    warn!(
                        blob = current.section,
                        bad_offset = current.offset,
                        new_size = current.valid_offset,
                        "incomplete item at end: truncating"
                    );
                    let (section, valid_offset) = (current.section, current.valid_offset);
                    self.repairing = true;
                    let repaired = repair_blob(&mut self.journal, section, valid_offset).await;
                    self.repairing = false;
                    if let Err(err) = repaired {
                        self.sections.pop_front();
                        return self.fail(err);
                    }
                    self.sections.pop_front();
                    continue;
                }
                Err(err) => {
                    self.sections.pop_front();
                    return self.fail(err.into());
                }
            }

            // Decode item - use take() to limit bytes read
            let item_offset = current.offset;
            let next_offset = match current
                .offset
                .checked_add(varint_len as u64)
                .and_then(|o| o.checked_add(item_size as u64))
            {
                Some(o) => o,
                None => {
                    self.sections.pop_front();
                    return self.fail(Error::OffsetOverflow);
                }
            };
            match decode_item::<V>(
                (&mut current.reader).take(item_size),
                &self.journal.0.codec_config,
                self.journal.0.compression.is_some(),
            ) {
                Ok(decoded) => {
                    current.pending = None;
                    current.valid_offset = next_offset;
                    current.offset = next_offset;
                    return Some(Ok((
                        current.section,
                        item_offset,
                        item_size as u32,
                        decoded,
                    )));
                }
                Err(err) => {
                    self.sections.pop_front();
                    return self.fail(err);
                }
            }
        }
        self.finished = true;
        None
    }

    /// Records a yielded error, which is fatal to the journal.
    const fn fail(&mut self, err: Error) -> Option<Result<(u64, u64, u32, V), Error>> {
        self.errored = true;
        Some(Err(err))
    }

    /// Returns the journal.
    ///
    /// Fails when the reader was not fully drained or yielded an error: the journal is
    /// destroyed and recovery is re-initialization.
    pub fn finish(self) -> Result<Journal<E, V>, Error> {
        if self.errored || !self.finished {
            return Err(Error::ReplayFailed);
        }
        Ok(self.journal)
    }
}

/// Truncates `section`'s blob to `size` and makes the truncation durable.
async fn repair_blob<E: Storage + Metrics, V: Codec>(
    journal: &mut Journal<E, V>,
    section: u64,
    size: u64,
) -> Result<(), Error> {
    // The journal is owned by the reader, so a replayed section cannot be removed.
    let blob = journal
        .0
        .manager
        .get_mut(section)
        .expect("replayed section must exist");
    blob.resize(size).await?;
    blob.sync().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{EncodeSize, Write as _, varint::UInt};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        Blob, BufMut, Runner, Storage, Supervisor as _, deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, release_pending_syncs},
    };
    use commonware_utils::{NZU16, NZUsize};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    #[test_traced]
    fn test_journal_append_and_read() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let index = 1u64;
            let data = 10;
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append an item to the journal
            (journal, _, _) = journal
                .append(index, &data)
                .await
                .expect("Failed to append data");

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("first_tracked 1"));

            // Drop and re-open the journal to simulate a restart
            journal = journal.sync(index).await.expect("Failed to sync journal");
            drop(journal);
            let journal = Journal::<_, i32>::init(context.child("second"), cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::new();
            let mut replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("unable to setup replay");
            while let Some(result) = replay.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {err}"),
                }
            }

            // Verify that the item was replayed correctly
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].0, index);
            assert_eq!(items[0].1, data);

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("second_tracked 1"));
        });
    }

    #[test_traced]
    fn test_journal_multiple_appends_and_reads() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append multiple items to different blobs
            let data_items = vec![(1u64, 1), (1u64, 2), (2u64, 3), (3u64, 4)];
            for (index, data) in &data_items {
                (journal, _, _) = journal
                    .append(*index, data)
                    .await
                    .expect("Failed to append data");
                journal = journal.sync(*index).await.expect("Failed to sync blob");
            }

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("first_tracked 3"));
            assert!(buffer.contains("first_synced_total 4"));

            // Drop and re-open the journal to simulate a restart
            drop(journal);
            let mut journal = Journal::init(context.child("second"), cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::<(u64, u32)>::new();
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                while let Some(result) = replay.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
                journal = replay.finish().expect("failed to finish replay");
            }

            // Verify that all items were replayed correctly
            assert_eq!(items.len(), data_items.len());
            for ((expected_index, expected_data), (actual_index, actual_data)) in
                data_items.iter().zip(items.iter())
            {
                assert_eq!(actual_index, expected_index);
                assert_eq!(actual_data, expected_data);
            }

            // Cleanup
            journal.destroy().await.expect("Failed to destroy journal");
        });
    }

    #[test_traced]
    fn test_journal_prune_blobs() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append items to multiple blobs
            for index in 1u64..=5u64 {
                (journal, _, _) = journal
                    .append(index, &index)
                    .await
                    .expect("Failed to append data");
                journal = journal.sync(index).await.expect("Failed to sync blob");
            }

            // Add one item out-of-order
            let data = 99;
            (journal, _, _) = journal
                .append(2u64, &data)
                .await
                .expect("Failed to append data");
            journal = journal.sync(2u64).await.expect("Failed to sync blob");

            // Prune blobs with indices less than 3
            (journal, _) = journal.prune(3).await.expect("Failed to prune blobs");

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("first_pruned_total 2"));

            // Prune again with a section less than the previous one, should be a no-op
            (journal, _) = journal.prune(2).await.expect("Failed to no-op prune");
            let buffer = context.encode();
            assert!(buffer.contains("first_pruned_total 2"));

            // Drop and re-open the journal to simulate a restart
            drop(journal);
            let mut journal = Journal::init(context.child("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::<(u64, u64)>::new();
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                while let Some(result) = replay.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
                journal = replay.finish().expect("failed to finish replay");
            }

            // Verify that items from blobs 1 and 2 are not present
            assert_eq!(items.len(), 3);
            let expected_indices = [3u64, 4u64, 5u64];
            for (item, expected_index) in items.iter().zip(expected_indices.iter()) {
                assert_eq!(item.0, *expected_index);
            }

            // Prune all blobs
            (journal, _) = journal.prune(6).await.expect("Failed to prune blobs");

            // Drop the journal
            drop(journal);

            // Ensure no remaining blobs exist
            //
            // Note: We don't remove the partition, so this does not error
            // and instead returns an empty list of blobs.
            assert!(
                context
                    .scan(&cfg.partition)
                    .await
                    .expect("Failed to list blobs")
                    .is_empty()
            );
        });
    }

    #[test_traced]
    fn test_journal_prune_guard() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append items to sections 1-5
            for section in 1u64..=5u64 {
                (journal, _, _) = journal
                    .append(section, &(section as i32))
                    .await
                    .expect("Failed to append data");
                journal = journal.sync(section).await.expect("Failed to sync");
            }

            // Prune sections < 3
            (journal, _) = journal.prune(3).await.expect("Failed to prune");

            // The public accessor mirrors the guard
            assert!(journal.pruned(1));
            assert!(journal.pruned(2));
            assert!(!journal.pruned(3));

            // Test that accessing pruned sections returns the correct error

            // Test append on pruned section
            match journal.0.append(1, &100).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
            }

            match journal.0.append(2, &100).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
            }

            // Test get on pruned section
            match journal.get(1, 0).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
            }

            // Test size on pruned section
            match journal.size(1) {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
            }

            // Test rewind on pruned section
            match journal.0.rewind(2, 0).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
            }

            // Test rewind_section on pruned section
            match journal.0.rewind_section(1, 0).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
            }

            // Test sync on pruned section
            match journal.0.sync(2).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
            }

            // Test that accessing sections at or after the threshold works
            assert!(journal.get(3, 0).await.is_ok());
            assert!(journal.get(4, 0).await.is_ok());
            assert!(journal.get(5, 0).await.is_ok());
            assert!(journal.size(3).is_ok());
            assert!(journal.0.sync(4).await.is_ok());

            // Append to section at threshold should work
            (journal, _, _) = journal
                .append(3, &999)
                .await
                .expect("Should be able to append to section 3");

            // Prune more sections
            (journal, _) = journal.prune(5).await.expect("Failed to prune");

            // Verify sections 3 and 4 are now pruned
            assert!(journal.pruned(4));
            assert!(!journal.pruned(5));
            match journal.get(3, 0).await {
                Err(Error::AlreadyPrunedToSection(5)) => {}
                other => panic!("Expected AlreadyPrunedToSection(5), got {other:?}"),
            }

            match journal.get(4, 0).await {
                Err(Error::AlreadyPrunedToSection(5)) => {}
                other => panic!("Expected AlreadyPrunedToSection(5), got {other:?}"),
            }

            // Section 5 should still be accessible
            assert!(journal.get(5, 0).await.is_ok());
        });
    }

    #[test_traced]
    fn test_journal_prune_guard_across_restart() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // First session: create and prune
            {
                let mut journal = Journal::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to initialize journal");

                for section in 1u64..=5u64 {
                    (journal, _, _) = journal
                        .append(section, &(section as i32))
                        .await
                        .expect("Failed to append data");
                    journal = journal.sync(section).await.expect("Failed to sync");
                }

                journal.prune(3).await.expect("Failed to prune");
            }

            // Second session: verify oldest_retained_section is reset
            {
                let journal = Journal::<_, i32>::init(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to re-initialize journal");

                // The floor is execution-scoped, so pruned reports false after restart
                assert!(!journal.pruned(1));
                assert!(!journal.pruned(2));

                // But the actual sections 1 and 2 should be gone from storage
                // so get should return SectionOutOfRange, not AlreadyPrunedToSection
                match journal.get(1, 0).await {
                    Err(Error::SectionOutOfRange(1)) => {}
                    other => panic!("Expected SectionOutOfRange(1), got {other:?}"),
                }

                match journal.get(2, 0).await {
                    Err(Error::SectionOutOfRange(2)) => {}
                    other => panic!("Expected SectionOutOfRange(2), got {other:?}"),
                }

                // Sections 3-5 should still be accessible
                assert!(journal.get(3, 0).await.is_ok());
                assert!(journal.get(4, 0).await.is_ok());
                assert!(journal.get(5, 0).await.is_ok());
            }
        });
    }

    #[test_traced]
    fn test_journal_with_invalid_blob_name() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Manually create a blob with an invalid name (not 8 bytes)
            let invalid_blob_name = b"invalid"; // Less than 8 bytes
            let (blob, _) = context
                .open(&cfg.partition, invalid_blob_name)
                .await
                .expect("Failed to create blob with invalid name");
            blob.sync().await.expect("Failed to sync blob");

            // Attempt to initialize the journal
            let result = Journal::<_, u64>::init(context, cfg).await;

            // Expect an error
            assert!(matches!(result, Err(Error::InvalidBlobName(_))));
        });
    }

    #[test_traced]
    fn test_journal_read_size_missing() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Manually create a blob with incomplete size data
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let (blob, _) = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Write incomplete varint by encoding u32::MAX (5 bytes) and truncating to 1 byte
            let mut incomplete_data = Vec::new();
            UInt(u32::MAX).write(&mut incomplete_data);
            incomplete_data.truncate(1);
            blob.write_at_sync(0, incomplete_data)
                .await
                .expect("Failed to write incomplete data");

            // Initialize the journal
            let journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            let mut replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("unable to setup replay");
            let mut items = Vec::<(u64, u64)>::new();
            while let Some(result) = replay.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {err}"),
                }
            }
            assert!(items.is_empty());
        });
    }

    #[test_traced]
    fn test_journal_replay_empty_finishes_immediately() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let journal = Journal::<_, i32>::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize journal");

            // An empty journal's reader is exhausted from the start
            let replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("Failed to replay");
            let journal = replay.finish().expect("failed to finish replay");
            journal.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_journal_replay_finish_before_drain_fails() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.child("storage"), cfg)
                .await
                .expect("Failed to initialize journal");
            (journal, _, _) = journal.append(1, &7i32).await.expect("Failed to append");
            journal = journal.sync(1).await.expect("Failed to sync");

            let replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("Failed to replay");
            assert!(matches!(replay.finish(), Err(Error::ReplayFailed)));
        });
    }

    #[test_traced]
    fn test_journal_replay_reports_resize_error_on_trailing_bytes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Leave one byte in the first page so the trailing bytes below cross the page
            // boundary and repair must issue a physical resize.
            let section = 1u64;
            let item = [10u8; 1021];
            let item_record_size =
                UInt(item.encode_size() as u32).encode_size() + item.encode_size();
            assert_eq!(item_record_size, PAGE_SIZE.get() as usize - 1);

            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");
            (journal, _, _) = journal
                .append(section, &item)
                .await
                .expect("Failed to append item");
            journal
                .0
                .append_raw(section, IoBuf::copy_from_slice(&[0xFF, 0xFF]))
                .await
                .expect("Failed to append trailing bytes");
            journal = journal.sync(section).await.expect("Failed to sync journal");
            drop(journal);

            let journal = Journal::init(context.child("second"), cfg)
                .await
                .expect("Failed to re-initialize journal");
            *context.storage_fault_config().write() = deterministic::FaultConfig {
                resize_rate: Some(1.0),
                ..Default::default()
            };

            let mut replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("unable to setup replay");

            let first = replay
                .next()
                .await
                .expect("expected item before trailing bytes")
                .expect("failed to replay valid item");
            assert_eq!(first, (section, 0, item.encode_size() as u32, item));

            // The trailing bytes cross the page boundary, so repair must issue a physical resize.
            match replay.next().await {
                Some(Err(_)) => {}
                other => {
                    panic!("expected resize error while repairing trailing bytes, got {other:?}")
                }
            }
            assert!(replay.next().await.is_none());
        });
    }

    #[test_traced]
    fn test_journal_replay_finish_after_error_fails() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Same layout as the resize-error test: trailing bytes cross the page
            // boundary so repair must issue a physical resize, which the fault fails.
            let section = 1u64;
            let item = [10u8; 1021];
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");
            (journal, _, _) = journal
                .append(section, &item)
                .await
                .expect("Failed to append item");
            journal
                .0
                .append_raw(section, IoBuf::copy_from_slice(&[0xFF, 0xFF]))
                .await
                .expect("Failed to append trailing bytes");
            journal = journal.sync(section).await.expect("Failed to sync journal");
            drop(journal);

            let journal = Journal::<_, [u8; 1021]>::init(context.child("second"), cfg)
                .await
                .expect("Failed to re-initialize journal");
            *context.storage_fault_config().write() = deterministic::FaultConfig {
                resize_rate: Some(1.0),
                ..Default::default()
            };

            let mut replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("unable to setup replay");
            let _ = replay
                .next()
                .await
                .expect("expected item before trailing bytes")
                .expect("failed to replay valid item");
            assert!(matches!(replay.next().await, Some(Err(_))));
            assert!(replay.next().await.is_none());

            // The yielded error is fatal, so finish must refuse to return the journal
            assert!(matches!(replay.finish(), Err(Error::ReplayFailed)));
        });
    }

    #[test_traced]
    fn test_journal_replay_dropped_during_repair_fails_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Same layout as the resize-error test: trailing bytes cross the page
            // boundary so repair must issue a physical resize (and its sync).
            let section = 1u64;
            let item = [10u8; 1021];
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");
            (journal, _, _) = journal
                .append(section, &item)
                .await
                .expect("Failed to append item");
            journal
                .0
                .append_raw(section, IoBuf::copy_from_slice(&[0xFF, 0xFF]))
                .await
                .expect("Failed to append trailing bytes");
            journal = journal.sync(section).await.expect("Failed to sync journal");
            drop(journal);

            // Gate syncs so the repair suspends, then drop the in-flight next()
            let pending = PendingSyncs::default();
            let gated = DelayedSyncContext {
                inner: context.child("second"),
                pending: pending.clone(),
            };
            let journal = Journal::<_, [u8; 1021]>::init(gated, cfg.clone())
                .await
                .expect("Failed to re-initialize journal");
            let mut replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("unable to setup replay");
            let _ = replay
                .next()
                .await
                .expect("expected item before trailing bytes")
                .expect("failed to replay valid item");
            pending.arm();
            {
                let fut = replay.next();
                futures::pin_mut!(fut);
                assert!(
                    futures::poll!(fut.as_mut()).is_pending(),
                    "repair must suspend on the gated sync"
                );
            }
            release_pending_syncs(&pending);

            // The interrupted repair fails the replay rather than resuming over it
            assert!(matches!(
                replay.next().await,
                Some(Err(Error::ReplayInterrupted))
            ));
            assert!(replay.next().await.is_none());
            drop(replay);

            // Re-initialization repairs from durable state
            let journal = Journal::<_, [u8; 1021]>::init(context.child("third"), cfg)
                .await
                .expect("Failed to re-initialize journal");
            let mut replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("unable to setup replay");
            let first = replay
                .next()
                .await
                .expect("expected item after recovery")
                .expect("failed to replay valid item");
            assert_eq!(first, (section, 0, item.encode_size() as u32, item));
            assert!(replay.next().await.is_none());
            let journal = replay.finish().expect("failed to finish replay");
            journal.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_journal_read_item_missing() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Manually create a blob with missing item data
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let (blob, _) = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Write size but incomplete item data
            let item_size: u32 = 10; // Size indicates 10 bytes of data
            let mut buf = Vec::new();
            UInt(item_size).write(&mut buf); // Varint encoding
            let data = [2u8; 5];
            BufMut::put_slice(&mut buf, &data);
            blob.write_at_sync(0, buf)
                .await
                .expect("Failed to write incomplete item");

            // Initialize the journal
            let journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            let mut replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("unable to setup replay");
            let mut items = Vec::<(u64, u64)>::new();
            while let Some(result) = replay.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {err}"),
                }
            }
            assert!(items.is_empty());
        });
    }

    #[test_traced]
    fn test_journal_read_checksum_missing() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Manually create a blob with missing checksum
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let (blob, _) = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Prepare item data
            let item_data = b"Test data";
            let item_size = item_data.len() as u32;

            // Write size (varint) and data, but no checksum
            let mut buf = Vec::new();
            UInt(item_size).write(&mut buf);
            BufMut::put_slice(&mut buf, item_data);
            blob.write_at_sync(0, buf)
                .await
                .expect("Failed to write item without checksum");

            // Initialize the journal
            let journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            //
            // This will truncate the leftover bytes from our manual write.
            let mut replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("unable to setup replay");
            let mut items = Vec::<(u64, u64)>::new();
            while let Some(result) = replay.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {err}"),
                }
            }
            assert!(items.is_empty());
        });
    }

    #[test_traced]
    fn test_journal_read_checksum_mismatch() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Manually create a blob with incorrect checksum
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let (blob, _) = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Prepare item data
            let item_data = b"Test data";
            let item_size = item_data.len() as u32;
            let incorrect_checksum: u32 = 0xDEADBEEF;

            // Write size (varint), data, and incorrect checksum
            let mut buf = Vec::new();
            UInt(item_size).write(&mut buf);
            BufMut::put_slice(&mut buf, item_data);
            buf.put_u32(incorrect_checksum);
            blob.write_at_sync(0, buf)
                .await
                .expect("Failed to write item with bad checksum");

            // Initialize the journal
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                let mut items = Vec::<(u64, u64)>::new();
                while let Some(result) = replay.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
                journal = replay.finish().expect("failed to finish replay");
                assert!(items.is_empty());
            }
            drop(journal);

            // Confirm blob is expected length
            let (_, blob_size) = context
                .open(&cfg.partition, &section.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(blob_size, 0);
        });
    }

    #[test_traced]
    fn test_journal_truncation_recovery() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append 1 item to the first index
            (journal, _, _) = journal.append(1, &1).await.expect("Failed to append data");

            // Append multiple items to the second section
            let data_items = vec![(2u64, 2), (2u64, 3), (2u64, 4)];
            for (index, data) in &data_items {
                (journal, _, _) = journal
                    .append(*index, data)
                    .await
                    .expect("Failed to append data");
                journal = journal.sync(*index).await.expect("Failed to sync blob");
            }

            // Sync all sections and drop the journal
            journal = journal.sync_all().await.expect("Failed to sync");
            drop(journal);

            // Manually corrupt the end of the second blob
            let (blob, blob_size) = context
                .open(&cfg.partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(blob_size - 4)
                .await
                .expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::init(context.child("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Attempt to replay the journal
            let mut items = Vec::<(u64, u32)>::new();
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                while let Some(result) = replay.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
                journal = replay.finish().expect("failed to finish replay");
            }
            drop(journal);

            // Verify that replay stopped after corruption detected (the second blob).
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].0, 1);
            assert_eq!(items[0].1, 1);

            // Confirm second blob was truncated.
            let (_, blob_size) = context
                .open(&cfg.partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(blob_size, 0);

            // Attempt to replay journal after truncation
            let mut journal = Journal::init(context.child("third"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Attempt to replay the journal
            let mut items = Vec::<(u64, u32)>::new();
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                while let Some(result) = replay.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
                journal = replay.finish().expect("failed to finish replay");
            }

            // Verify that only non-corrupted items were replayed
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].0, 1);
            assert_eq!(items[0].1, 1);

            // Append a new item to truncated partition
            (journal, _, _) = journal.append(2, &5).await.expect("Failed to append data");
            journal = journal.sync(2).await.expect("Failed to sync blob");

            // Get the new item (offset is 0 since blob was truncated)
            let item = journal.get(2, 0).await.expect("Failed to get item");
            assert_eq!(item, 5);

            // Drop the journal (data already synced)
            drop(journal);

            // Re-initialize the journal to simulate a restart
            let journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Attempt to replay the journal
            let mut items = Vec::<(u64, u32)>::new();
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                while let Some(result) = replay.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
            }

            // Verify that only non-corrupted items were replayed
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].0, 1);
            assert_eq!(items[0].1, 1);
            assert_eq!(items[1].0, 2);
            assert_eq!(items[1].1, 5);
        });
    }

    #[test_traced]
    fn test_journal_handling_extra_data() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append 1 item to the first index
            (journal, _, _) = journal.append(1, &1).await.expect("Failed to append data");

            // Append multiple items to the second index
            let data_items = vec![(2u64, 2), (2u64, 3), (2u64, 4)];
            for (index, data) in &data_items {
                (journal, _, _) = journal
                    .append(*index, data)
                    .await
                    .expect("Failed to append data");
                journal = journal.sync(*index).await.expect("Failed to sync blob");
            }

            // Sync all sections and drop the journal
            journal = journal.sync_all().await.expect("Failed to sync");
            drop(journal);

            // Manually add extra data to the end of the second blob
            let (blob, blob_size) = context
                .open(&cfg.partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.write_at_sync(blob_size, vec![0u8; 16])
                .await
                .expect("Failed to add extra data");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::init(context.child("second"), cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Attempt to replay the journal
            let mut items = Vec::<(u64, i32)>::new();
            let mut replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("unable to setup replay");
            while let Some(result) = replay.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {err}"),
                }
            }
        });
    }

    #[test_traced]
    fn test_journal_rewind() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create journal
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context, cfg).await.unwrap();

            // Check size of non-existent section
            let size = journal.size(1).unwrap();
            assert_eq!(size, 0);

            // Append data to section 1
            (journal, _, _) = journal.append(1, &42i32).await.unwrap();

            // Check size of section 1 - should be greater than 0
            let size = journal.size(1).unwrap();
            assert!(size > 0);

            // Append more data and verify size increases
            (journal, _, _) = journal.append(1, &43i32).await.unwrap();
            let new_size = journal.size(1).unwrap();
            assert!(new_size > size);

            // Check size of different section - should still be 0
            let size = journal.size(2).unwrap();
            assert_eq!(size, 0);

            // Append data to section 2
            (journal, _, _) = journal.append(2, &44i32).await.unwrap();

            // Check size of section 2 - should be greater than 0
            let size = journal.size(2).unwrap();
            assert!(size > 0);

            // Rollback everything in section 1 and 2
            journal = journal.rewind(1, 0).await.unwrap();

            // Check size of section 1 - should be 0
            let size = journal.size(1).unwrap();
            assert_eq!(size, 0);

            // Check size of section 2 - should be 0
            let size = journal.size(2).unwrap();
            assert_eq!(size, 0);
        });
    }

    #[test_traced]
    fn test_journal_rewind_max_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context, cfg).await.unwrap();

            // Append to the maximal section. `section + 1` has no representable successor.
            let offset;
            (journal, offset, _) = journal.append(u64::MAX, &42i32).await.unwrap();
            let size = journal.size(u64::MAX).unwrap();
            assert!(size > 0);

            // Rewinding the maximal section removes no sections above it and must not panic.
            journal = journal.rewind(u64::MAX, size).await.unwrap();

            // The section is intact and readable.
            assert_eq!(journal.size(u64::MAX).unwrap(), size);
            assert_eq!(journal.get(u64::MAX, offset).await.unwrap(), 42i32);
        });
    }

    #[test_traced]
    fn test_journal_rewind_section() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create journal
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context, cfg).await.unwrap();

            // Check size of non-existent section
            let size = journal.size(1).unwrap();
            assert_eq!(size, 0);

            // Append data to section 1
            (journal, _, _) = journal.append(1, &42i32).await.unwrap();

            // Check size of section 1 - should be greater than 0
            let size = journal.size(1).unwrap();
            assert!(size > 0);

            // Append more data and verify size increases
            (journal, _, _) = journal.append(1, &43i32).await.unwrap();
            let new_size = journal.size(1).unwrap();
            assert!(new_size > size);

            // Check size of different section - should still be 0
            let size = journal.size(2).unwrap();
            assert_eq!(size, 0);

            // Append data to section 2
            (journal, _, _) = journal.append(2, &44i32).await.unwrap();

            // Check size of section 2 - should be greater than 0
            let size = journal.size(2).unwrap();
            assert!(size > 0);

            // Rollback everything in section 1
            journal = journal.rewind_section(1, 0).await.unwrap();

            // Check size of section 1 - should be 0
            let size = journal.size(1).unwrap();
            assert_eq!(size, 0);

            // Check size of section 2 - should be greater than 0
            let size = journal.size(2).unwrap();
            assert!(size > 0);
        });
    }

    #[test_traced]
    fn test_journal_small_items() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append many small (1-byte) items to the same section
            let num_items = 100;
            let mut offsets = Vec::new();
            for i in 0..num_items {
                let offset;
                let size;
                (journal, offset, size) = journal
                    .append(1, &(i as u8))
                    .await
                    .expect("Failed to append data");
                assert_eq!(size, 1, "u8 should encode to 1 byte");
                offsets.push(offset);
            }
            journal = journal.sync(1).await.expect("Failed to sync");

            // Read each item back via random access
            for (i, &offset) in offsets.iter().enumerate() {
                let item: u8 = journal.get(1, offset).await.expect("Failed to get item");
                assert_eq!(item, i as u8, "Item mismatch at offset {offset}");
            }

            // Drop and reopen to test replay
            drop(journal);
            let journal = Journal::<_, u8>::init(context.child("second"), cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Replay and verify all items
            let mut replay = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("Failed to setup replay");

            let mut count = 0;
            while let Some(result) = replay.next().await {
                let (section, offset, size, item) = result.expect("Failed to replay item");
                assert_eq!(section, 1);
                assert_eq!(offset, offsets[count]);
                assert_eq!(size, 1);
                assert_eq!(item, count as u8);
                count += 1;
            }
            assert_eq!(count, num_items, "Should replay all items");
        });
    }

    #[test_traced]
    fn test_journal_rewind_many_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .unwrap();

            // Create sections 1-10 with data
            for section in 1u64..=10 {
                (journal, _, _) = journal.append(section, &(section as i32)).await.unwrap();
            }
            journal = journal.sync_all().await.unwrap();

            // Verify all sections exist
            for section in 1u64..=10 {
                let size = journal.size(section).unwrap();
                assert!(size > 0, "section {section} should have data");
            }

            // Rewind to section 5 (should remove sections 6-10)
            let size = journal.size(5).unwrap();
            journal = journal.rewind(5, size).await.unwrap();

            // Verify sections 1-5 still exist with correct data
            for section in 1u64..=5 {
                let size = journal.size(section).unwrap();
                assert!(size > 0, "section {section} should still have data");
            }

            // Verify sections 6-10 are removed (size should be 0)
            for section in 6u64..=10 {
                let size = journal.size(section).unwrap();
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify data integrity via replay
            {
                let mut replay = journal.replay(0, 0, NZUsize!(1024)).await.unwrap();
                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, _, _, item) = result.unwrap();
                    items.push((section, item));
                }
                journal = replay.finish().expect("failed to finish replay");
                assert_eq!(items.len(), 5);
                for (i, (section, item)) in items.iter().enumerate() {
                    assert_eq!(*section, (i + 1) as u64);
                    assert_eq!(*item, (i + 1) as i32);
                }
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journal_rewind_partial_truncation() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .unwrap();

            // Append 5 items and record sizes after each
            let mut sizes = Vec::new();
            for i in 0..5 {
                (journal, _, _) = journal.append(1, &i).await.unwrap();
                journal = journal.sync(1).await.unwrap();
                sizes.push(journal.size(1).unwrap());
            }

            // Rewind to keep only first 3 items
            let target_size = sizes[2];
            journal = journal.rewind(1, target_size).await.unwrap();

            // Verify size is correct
            let new_size = journal.size(1).unwrap();
            assert_eq!(new_size, target_size);

            // Verify first 3 items via replay
            {
                let mut replay = journal.replay(0, 0, NZUsize!(1024)).await.unwrap();
                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (_, _, _, item) = result.unwrap();
                    items.push(item);
                }
                journal = replay.finish().expect("failed to finish replay");
                assert_eq!(items.len(), 3);
                for (i, item) in items.iter().enumerate() {
                    assert_eq!(*item, i as i32);
                }
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journal_rewind_nonexistent_target() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .unwrap();

            // Create sections 5, 6, 7 (skip 1-4)
            for section in 5u64..=7 {
                (journal, _, _) = journal.append(section, &(section as i32)).await.unwrap();
            }
            journal = journal.sync_all().await.unwrap();

            // Rewind to section 3 (doesn't exist)
            journal = journal.rewind(3, 0).await.unwrap();

            // Verify sections 5, 6, 7 are removed
            for section in 5u64..=7 {
                let size = journal.size(section).unwrap();
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify replay returns nothing
            {
                let mut replay = journal.replay(0, 0, NZUsize!(1024)).await.unwrap();
                assert!(replay.next().await.is_none());
                journal = replay.finish().expect("failed to finish replay");
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journal_rewind_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Create sections 1-5 with data
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for section in 1u64..=5 {
                (journal, _, _) = journal.append(section, &(section as i32)).await.unwrap();
            }
            journal = journal.sync_all().await.unwrap();

            // Rewind to section 2
            let size = journal.size(2).unwrap();
            journal = journal.rewind(2, size).await.unwrap();
            journal = journal.sync_all().await.unwrap();
            drop(journal);

            // Re-init and verify only sections 1-2 exist
            let mut journal = Journal::<_, i32>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Verify sections 1-2 have data
            for section in 1u64..=2 {
                let size = journal.size(section).unwrap();
                assert!(size > 0, "section {section} should have data after restart");
            }

            // Verify sections 3-5 are gone
            for section in 3u64..=5 {
                let size = journal.size(section).unwrap();
                assert_eq!(size, 0, "section {section} should be gone after restart");
            }

            // Verify data integrity via replay
            {
                let mut replay = journal.replay(0, 0, NZUsize!(1024)).await.unwrap();
                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, _, _, item) = result.unwrap();
                    items.push((section, item));
                }
                journal = replay.finish().expect("failed to finish replay");
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], (1, 1));
                assert_eq!(items[1], (2, 2));
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journal_rewind_to_zero_removes_all_newer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .unwrap();

            // Create sections 1, 2, 3
            for section in 1u64..=3 {
                (journal, _, _) = journal.append(section, &(section as i32)).await.unwrap();
            }
            journal = journal.sync_all().await.unwrap();

            // Rewind section 1 to size 0
            journal = journal.rewind(1, 0).await.unwrap();

            // Verify section 1 exists but is empty
            let size = journal.size(1).unwrap();
            assert_eq!(size, 0, "section 1 should be empty");

            // Verify sections 2, 3 are completely removed
            for section in 2u64..=3 {
                let size = journal.size(section).unwrap();
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify replay returns nothing
            {
                let mut replay = journal.replay(0, 0, NZUsize!(1024)).await.unwrap();
                assert!(replay.next().await.is_none());
                journal = replay.finish().expect("failed to finish replay");
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journal_replay_start_offset_with_trailing_bytes() {
        // Regression: valid_offset must be initialized to start_offset, not 0.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append several items to build up valid data
            for i in 0..5i32 {
                (journal, _, _) = journal.append(1, &i).await.unwrap();
            }
            journal = journal.sync(1).await.unwrap();
            let valid_logical_size = journal.size(1).unwrap();
            drop(journal);

            // Get the physical blob size before corruption
            let (blob, physical_size_before) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .unwrap();

            // Write incomplete varint: 0xFF has continuation bit set, needs more bytes
            // This creates 2 trailing bytes that cannot form a valid item
            blob.write_at_sync(physical_size_before, vec![0xFF, 0xFF])
                .await
                .unwrap();

            // Reopen journal and replay starting PAST all valid items
            // (start_offset = valid_logical_size means we skip all valid data)
            // The first thing encountered will be the trailing corrupt bytes
            let start_offset = valid_logical_size;
            {
                let journal = Journal::<_, i32>::init(context.child("second"), cfg.clone())
                    .await
                    .unwrap();

                let mut replay = journal
                    .replay(1, start_offset, NZUsize!(1024))
                    .await
                    .unwrap();

                // Consume the reader - should detect trailing bytes and truncate
                while let Some(_result) = replay.next().await {}
            }

            // Verify that valid data before start_offset was NOT lost
            let (_, physical_size_after) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .unwrap();

            // The blob should have been truncated back to the valid physical size
            // (removing the trailing corrupt bytes) but NOT to 0
            assert!(
                physical_size_after >= physical_size_before,
                "Valid data was lost! Physical blob truncated from {physical_size_before} to \
                 {physical_size_after}. Logical valid size was {valid_logical_size}. \
                 This indicates valid_offset was incorrectly initialized to 0 instead of start_offset."
            );
        });
    }

    #[test_traced]
    fn test_journal_replay_rejects_start_offset_past_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.child("storage"), cfg).await.unwrap();
            (journal, _, _) = journal.append(1, &7i32).await.unwrap();

            // A failed replay consumes the journal
            let result = journal.replay(1, u64::MAX, NZUsize!(1024)).await;
            assert!(matches!(result, Err(Error::ItemOutOfRange(u64::MAX))));
        });
    }

    #[test_traced]
    fn test_journal_large_item_spanning_pages() {
        // 2048 bytes spans 2 full pages (PAGE_SIZE = 1024).
        const LARGE_SIZE: usize = 2048;
        type LargeItem = [u8; LARGE_SIZE];

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(4096),
            };
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Create a large item that spans multiple pages.
            let mut large_data: LargeItem = [0u8; LARGE_SIZE];
            for (i, byte) in large_data.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }
            assert!(
                LARGE_SIZE > PAGE_SIZE.get() as usize,
                "Item must be larger than page size"
            );

            // Append the large item
            let offset;
            let size;
            (journal, offset, size) = journal
                .append(1, &large_data)
                .await
                .expect("Failed to append large item");
            assert_eq!(size as usize, LARGE_SIZE);
            journal = journal.sync(1).await.expect("Failed to sync");

            // Read the item back via random access
            let retrieved: LargeItem = journal
                .get(1, offset)
                .await
                .expect("Failed to get large item");
            assert_eq!(retrieved, large_data, "Random access read mismatch");

            // Drop and reopen to test replay
            drop(journal);
            let mut journal = Journal::<_, LargeItem>::init(context.child("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay and verify the large item
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, off, sz, item) = result.expect("Failed to replay item");
                    items.push((section, off, sz, item));
                }
                journal = replay.finish().expect("failed to finish replay");

                assert_eq!(items.len(), 1, "Should have exactly one item");
                let (section, off, sz, item) = &items[0];
                assert_eq!(*section, 1);
                assert_eq!(*off, offset);
                assert_eq!(*sz as usize, LARGE_SIZE);
                assert_eq!(*item, large_data, "Replay read mismatch");
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journal_large_item_direct_path() {
        // Items larger than the write buffer are written directly to the blob. The first append
        // takes the direct path from an empty tip; the second takes it with a non-empty tip
        // (holding the first item's sub-page remainder), covering both top-up branches. The
        // returned offsets must remain correct since callers persist them for random access.
        const LARGE_SIZE: usize = 2048;
        type LargeItem = [u8; LARGE_SIZE];

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            let mut first: LargeItem = [0u8; LARGE_SIZE];
            for (i, byte) in first.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }
            let mut second: LargeItem = [0u8; LARGE_SIZE];
            for (i, byte) in second.iter_mut().enumerate() {
                *byte = ((i + 7) % 251) as u8;
            }

            let first_offset;
            (journal, first_offset, _) = journal
                .append(1, &first)
                .await
                .expect("Failed to append first item");
            let second_offset;
            (journal, second_offset, _) = journal
                .append(1, &second)
                .await
                .expect("Failed to append second item");

            // Both items are readable at their returned offsets before any sync.
            let retrieved: LargeItem = journal.get(1, first_offset).await.unwrap();
            assert_eq!(retrieved, first);
            let retrieved: LargeItem = journal.get(1, second_offset).await.unwrap();
            assert_eq!(retrieved, second);

            // Everything survives a sync and reopen.
            journal = journal.sync(1).await.expect("Failed to sync");
            drop(journal);
            let mut journal = Journal::<_, LargeItem>::init(context.child("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            let retrieved: LargeItem = journal.get(1, first_offset).await.unwrap();
            assert_eq!(retrieved, first);
            let retrieved: LargeItem = journal.get(1, second_offset).await.unwrap();
            assert_eq!(retrieved, second);

            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, off, _, item) = result.expect("Failed to replay item");
                    items.push((section, off, item));
                }
                journal = replay.finish().expect("failed to finish replay");
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], (1, first_offset, first));
                assert_eq!(items[1], (1, second_offset, second));
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journal_non_contiguous_sections() {
        // Test that sections with gaps in numbering work correctly.
        // Sections 1, 5, 10 should all be independent and accessible.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Create sections with gaps: 1, 5, 10
            let sections_and_data = [(1u64, 100i32), (5u64, 500i32), (10u64, 1000i32)];
            let mut offsets = Vec::new();

            for (section, data) in &sections_and_data {
                let offset;
                (journal, offset, _) = journal
                    .append(*section, data)
                    .await
                    .expect("Failed to append");
                offsets.push(offset);
            }
            journal = journal.sync_all().await.expect("Failed to sync");

            // Verify random access to each section
            for (i, (section, expected_data)) in sections_and_data.iter().enumerate() {
                let retrieved: i32 = journal
                    .get(*section, offsets[i])
                    .await
                    .expect("Failed to get item");
                assert_eq!(retrieved, *expected_data);
            }

            // Verify non-existent sections return appropriate errors
            for missing_section in [0u64, 2, 3, 4, 6, 7, 8, 9, 11] {
                let result = journal.get(missing_section, 0).await;
                assert!(
                    matches!(result, Err(Error::SectionOutOfRange(_))),
                    "Expected SectionOutOfRange for section {}, got {:?}",
                    missing_section,
                    result
                );
            }

            // Drop and reopen to test replay
            drop(journal);
            let mut journal = Journal::<_, i32>::init(context.child("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay and verify all items in order
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, _, _, item) = result.expect("Failed to replay item");
                    items.push((section, item));
                }
                journal = replay.finish().expect("failed to finish replay");

                assert_eq!(items.len(), 3, "Should have 3 items");
                assert_eq!(items[0], (1, 100));
                assert_eq!(items[1], (5, 500));
                assert_eq!(items[2], (10, 1000));
            }

            // Test replay starting from middle section (5)
            {
                let mut replay = journal
                    .replay(5, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay from section 5");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, _, _, item) = result.expect("Failed to replay item");
                    items.push((section, item));
                }
                journal = replay.finish().expect("failed to finish replay");

                assert_eq!(items.len(), 2, "Should have 2 items from section 5 onwards");
                assert_eq!(items[0], (5, 500));
                assert_eq!(items[1], (10, 1000));
            }

            // Test replay starting from non-existent section (should skip to next)
            {
                let mut replay = journal
                    .replay(3, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay from section 3");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, _, _, item) = result.expect("Failed to replay item");
                    items.push((section, item));
                }
                journal = replay.finish().expect("failed to finish replay");

                // Should get sections 5 and 10 (skipping non-existent 3, 4)
                assert_eq!(items.len(), 2);
                assert_eq!(items[0], (5, 500));
                assert_eq!(items[1], (10, 1000));
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journal_empty_section_in_middle() {
        // Test that replay correctly handles an empty section between sections with data.
        // Section 1 has data, section 2 is empty, section 3 has data.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append to section 1
            (journal, _, _) = journal.append(1, &100i32).await.expect("Failed to append");

            // Create section 2 but don't append anything - just sync to create the blob
            // Actually, we need to append something and then rewind to make it empty
            (journal, _, _) = journal.append(2, &200i32).await.expect("Failed to append");
            journal = journal.sync(2).await.expect("Failed to sync");
            journal = journal
                .rewind_section(2, 0)
                .await
                .expect("Failed to rewind");

            // Append to section 3
            (journal, _, _) = journal.append(3, &300i32).await.expect("Failed to append");

            journal = journal.sync_all().await.expect("Failed to sync");

            // Verify section sizes
            assert!(journal.size(1).unwrap() > 0);
            assert_eq!(journal.size(2).unwrap(), 0);
            assert!(journal.size(3).unwrap() > 0);

            // Drop and reopen to test replay
            drop(journal);
            let mut journal = Journal::<_, i32>::init(context.child("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay all - should get items from sections 1 and 3, skipping empty section 2
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, _, _, item) = result.expect("Failed to replay item");
                    items.push((section, item));
                }
                journal = replay.finish().expect("failed to finish replay");

                assert_eq!(
                    items.len(),
                    2,
                    "Should have 2 items (skipping empty section)"
                );
                assert_eq!(items[0], (1, 100));
                assert_eq!(items[1], (3, 300));
            }

            // Replay starting from empty section 2 - should get only section 3
            {
                let mut replay = journal
                    .replay(2, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay from section 2");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, _, _, item) = result.expect("Failed to replay item");
                    items.push((section, item));
                }
                journal = replay.finish().expect("failed to finish replay");

                assert_eq!(items.len(), 1, "Should have 1 item from section 3");
                assert_eq!(items[0], (3, 300));
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journal_item_exactly_page_size() {
        // Test that items exactly equal to PAGE_SIZE work correctly.
        // This is a boundary condition where item fills exactly one page.
        const ITEM_SIZE: usize = PAGE_SIZE.get() as usize;
        type ExactItem = [u8; ITEM_SIZE];

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(4096),
            };
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Create an item exactly PAGE_SIZE bytes
            let mut exact_data: ExactItem = [0u8; ITEM_SIZE];
            for (i, byte) in exact_data.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }

            // Append the exact-size item
            let offset;
            let size;
            (journal, offset, size) = journal
                .append(1, &exact_data)
                .await
                .expect("Failed to append exact item");
            assert_eq!(size as usize, ITEM_SIZE);
            journal = journal.sync(1).await.expect("Failed to sync");

            // Read the item back via random access
            let retrieved: ExactItem = journal
                .get(1, offset)
                .await
                .expect("Failed to get exact item");
            assert_eq!(retrieved, exact_data, "Random access read mismatch");

            // Drop and reopen to test replay
            drop(journal);
            let mut journal = Journal::<_, ExactItem>::init(context.child("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay and verify
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, off, sz, item) = result.expect("Failed to replay item");
                    items.push((section, off, sz, item));
                }
                journal = replay.finish().expect("failed to finish replay");

                assert_eq!(items.len(), 1, "Should have exactly one item");
                let (section, off, sz, item) = &items[0];
                assert_eq!(*section, 1);
                assert_eq!(*off, offset);
                assert_eq!(*sz as usize, ITEM_SIZE);
                assert_eq!(*item, exact_data, "Replay read mismatch");
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journal_varint_spanning_page_boundary() {
        // Test that items with data spanning page boundaries work correctly
        // when using a small page size.
        //
        // With PAGE_SIZE=16:
        // - Physical page = 16 + 12 = 28 bytes
        // - Each [u8; 128] item = 2-byte varint + 128 bytes data = 130 bytes
        // - This spans multiple 16-byte pages, testing cross-page reading
        const SMALL_PAGE: NonZeroU16 = NZU16!(16);

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-partition".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal: Journal<_, [u8; 128]> =
                Journal::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to initialize journal");

            // Create items that will span many 16-byte pages
            let item1: [u8; 128] = [1u8; 128];
            let item2: [u8; 128] = [2u8; 128];
            let item3: [u8; 128] = [3u8; 128];

            // Append items - each is 130 bytes (2-byte varint + 128 data)
            // spanning ceil(130/16) = 9 pages worth of logical data
            let offset1;
            (journal, offset1, _) = journal.append(1, &item1).await.expect("Failed to append");
            let offset2;
            (journal, offset2, _) = journal.append(1, &item2).await.expect("Failed to append");
            let offset3;
            (journal, offset3, _) = journal.append(1, &item3).await.expect("Failed to append");

            journal = journal.sync(1).await.expect("Failed to sync");

            // Read items back via random access
            let retrieved1: [u8; 128] = journal.get(1, offset1).await.expect("Failed to get");
            let retrieved2: [u8; 128] = journal.get(1, offset2).await.expect("Failed to get");
            let retrieved3: [u8; 128] = journal.get(1, offset3).await.expect("Failed to get");
            assert_eq!(retrieved1, item1);
            assert_eq!(retrieved2, item2);
            assert_eq!(retrieved3, item3);

            // Drop and reopen to test replay
            drop(journal);
            let mut journal: Journal<_, [u8; 128]> =
                Journal::init(context.child("second"), cfg.clone())
                    .await
                    .expect("Failed to re-initialize journal");

            // Replay and verify all items
            {
                let mut replay = journal
                    .replay(0, 0, NZUsize!(64))
                    .await
                    .expect("Failed to setup replay");

                let mut items = Vec::new();
                while let Some(result) = replay.next().await {
                    let (section, off, _, item) = result.expect("Failed to replay item");
                    items.push((section, off, item));
                }
                journal = replay.finish().expect("failed to finish replay");

                assert_eq!(items.len(), 3, "Should have 3 items");
                assert_eq!(items[0], (1, offset1, item1));
                assert_eq!(items[1], (1, offset2, item2));
                assert_eq!(items[2], (1, offset3, item3));
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journal_clear() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "clear-test".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            let mut journal: Journal<_, u64> = Journal::init(context.child("journal"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append items across multiple sections
            for section in 0..5u64 {
                for i in 0..10u64 {
                    (journal, _, _) = journal
                        .append(section, &(section * 1000 + i))
                        .await
                        .expect("Failed to append");
                }
                journal = journal.sync(section).await.expect("Failed to sync");
            }

            // Verify we have data
            assert_eq!(journal.get(0, 0).await.unwrap(), 0);
            assert_eq!(journal.get(4, 0).await.unwrap(), 4000);

            // Clear the journal
            journal = journal.clear().await.expect("Failed to clear");

            // After clear, all reads should fail
            for section in 0..5u64 {
                assert!(matches!(
                    journal.get(section, 0).await,
                    Err(Error::SectionOutOfRange(s)) if s == section
                ));
            }

            // Append new data after clear
            for i in 0..5u64 {
                (journal, _, _) = journal
                    .append(10, &(i * 100))
                    .await
                    .expect("Failed to append after clear");
            }
            journal = journal.sync(10).await.expect("Failed to sync after clear");

            // New data should be readable
            assert_eq!(journal.get(10, 0).await.unwrap(), 0);

            // Old sections should still be missing
            assert!(matches!(
                journal.get(0, 0).await,
                Err(Error::SectionOutOfRange(0))
            ));

            journal.destroy().await.unwrap();
        });
    }
}
