//! An append-only log for storing arbitrary variable length items.
//!
//! `variable::Journal` is an append-only log for storing arbitrary variable length data on disk. In
//! addition to replay, stored items can be directly retrieved given their section number and offset
//! within the section.
//!
//! # Format
//!
//! Data stored in `Journal` is persisted in one of many Blobs within a caller-provided `partition`.
//! The particular `Blob` in which data is stored is identified by a `section` number (`u64`).
//! Within a `section`, data is appended as an `item` with the following format:
//!
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+
//! | 0 | 1 | 2 | 3 |    ...    | 8 | 9 |10 |11 |
//! +---+---+---+---+---+---+---+---+---+---+---+
//! |   Size (u32)  |   Data    |    C(u32)     |
//! +---+---+---+---+---+---+---+---+---+---+---+
//!
//! C = CRC32(Size | Data)
//! ```
//!
//! _To ensure data returned by `Journal` is correct, a checksum (CRC32) is stored at the end of
//! each item. If the checksum of the read data does not match the stored checksum, an error is
//! returned. This checksum is only verified when data is accessed and not at startup (which would
//! require reading all data in `Journal`)._
//!
//! # Open Blobs
//!
//! `Journal` uses 1 `commonware-storage::Blob` per `section` to store data. All `Blobs` in a given
//! `partition` are kept open during the lifetime of `Journal`. If the caller wishes to bound the
//! number of open `Blobs`, they can group data into fewer `sections` and/or prune unused
//! `sections`.
//!
//! # Offset Alignment
//!
//! In practice, `Journal` users won't store `u64::MAX` bytes of data in a given `section` (the max
//! `Offset` provided by `Blob`). To reduce the memory usage for tracking offsets within `Journal`,
//! offsets are thus `u32` (4 bytes) and aligned to 16 bytes. This means that the maximum size of
//! any `section` is `u32::MAX * 17 = ~70GB` bytes (the last offset item can store up to `u32::MAX`
//! bytes). If more data is written to a `section` past this max, an `OffsetOverflow` error is
//! returned.
//!
//! # Sync
//!
//! Data written to `Journal` may not be immediately persisted to `Storage`. It is up to the caller
//! to determine when to force pending data to be written to `Storage` using the `sync` method. When
//! calling `close`, all pending data is automatically synced and any open blobs are dropped.
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
//! method to produce a stream of all items in the `Journal` in order of their `section` and
//! `offset`.
//!
//! # Exact Reads
//!
//! To allow for items to be fetched in a single disk operation, `Journal` allows callers to specify
//! an `exact` parameter to the `get` method. This `exact` parameter must be cached by the caller
//! (provided during `replay`) and usage of an incorrect `exact` value will result in undefined
//! behavior.
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
//! use commonware_runtime::{Spawner, Runner, deterministic, buffer::PoolRef};
//! use commonware_storage::journal::variable::{Journal, Config};
//! use commonware_utils::NZUsize;
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a journal
//!     let mut journal = Journal::init(context, Config{
//!         partition: "partition".to_string(),
//!         compression: None,
//!         codec_config: (),
//!         buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
//!         write_buffer: NZUsize!(1024 * 1024),
//!     }).await.unwrap();
//!
//!     // Append data to the journal
//!     journal.append(1, 128).await.unwrap();
//!
//!     // Close the journal
//!     journal.close().await.unwrap();
//! });
//! ```

use super::Error;
use bytes::BufMut;
use commonware_codec::Codec;
use commonware_runtime::{
    buffer::{Append, PoolRef, Read},
    Blob, Error as RError, Metrics, Storage,
};
use commonware_utils::hex;
use futures::stream::{self, Stream, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    io::Cursor,
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    ops::Bound,
};
use tracing::{debug, trace, warn};
use zstd::{bulk::compress, decode_all};

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

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,
}

const ITEM_ALIGNMENT: u64 = 16;

/// Computes the next offset for an item using the underlying `u64`
/// offset of `Blob`.
#[inline]
fn compute_next_offset(mut offset: u64) -> Result<u32, Error> {
    let overage = offset % ITEM_ALIGNMENT;
    if overage != 0 {
        offset += ITEM_ALIGNMENT - overage;
    }
    let offset = offset / ITEM_ALIGNMENT;
    let aligned_offset = offset.try_into().map_err(|_| Error::OffsetOverflow)?;
    Ok(aligned_offset)
}

/// Implementation of `Journal` storage.
pub struct Journal<E: Storage + Metrics, V: Codec> {
    context: E,
    cfg: Config<V::Cfg>,

    oldest_allowed: Option<u64>,

    blobs: BTreeMap<u64, Append<E::Blob>>,

    tracked: Gauge,
    synced: Counter,
    pruned: Counter,

    _phantom: PhantomData<V>,
}

impl<E: Storage + Metrics, V: Codec> Journal<E, V> {
    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during
    /// initialization. The `replay` method can be used
    /// to iterate over all items in the `Journal`.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Iterate over blobs in partition
        let mut blobs = BTreeMap::new();
        let stored_blobs = match context.scan(&cfg.partition).await {
            Ok(blobs) => blobs,
            Err(RError::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };
        for name in stored_blobs {
            let (blob, size) = context.open(&cfg.partition, &name).await?;
            let hex_name = hex(&name);
            let section = match name.try_into() {
                Ok(section) => u64::from_be_bytes(section),
                Err(_) => return Err(Error::InvalidBlobName(hex_name)),
            };
            debug!(section, blob = hex_name, size, "loaded section");
            let blob = Append::new(blob, size, cfg.write_buffer, cfg.buffer_pool.clone()).await?;
            blobs.insert(section, blob);
        }

        // Initialize metrics
        let tracked = Gauge::default();
        let synced = Counter::default();
        let pruned = Counter::default();
        context.register("tracked", "Number of blobs", tracked.clone());
        context.register("synced", "Number of syncs", synced.clone());
        context.register("pruned", "Number of blobs pruned", pruned.clone());
        tracked.set(blobs.len() as i64);

        // Create journal instance
        Ok(Self {
            context,
            cfg,

            oldest_allowed: None,

            blobs,
            tracked,
            synced,
            pruned,

            _phantom: PhantomData,
        })
    }

    /// Initialize a Variable journal for use in state sync.
    ///
    /// The bounds are item locations (not section numbers). This function prepares the
    /// on-disk journal so that subsequent appends go to the correct physical location for the
    /// requested range.
    ///
    /// Behavior by existing on-disk state:
    /// - Fresh (no data): returns an empty journal.
    /// - Stale (all data strictly before `lower_bound`): destroys existing data and returns an
    ///   empty journal.
    /// - Overlap within [`lower_bound`, `upper_bound`]:
    ///   - Prunes sections strictly below `lower_bound / items_per_section` (section-aligned).
    ///   - Removes any sections strictly greater than `upper_bound / items_per_section`.
    ///   - Truncates the final retained section so that no item with location greater
    ///     than `upper_bound` remains.
    ///
    /// Note that lower-bound pruning is section-aligned. This means the first retained section may
    /// still contain items whose locations are < `lower_bound`. Callers should ignore these.
    ///
    /// # Arguments
    /// - `context`: storage context
    /// - `cfg`: journal configuration
    /// - `lower_bound`: first item location to retain (inclusive)
    /// - `upper_bound`: last item location to retain (inclusive)
    /// - `items_per_section`: number of items per section
    ///
    /// # Returns
    /// A journal whose sections satisfy:
    /// - No section index < `lower_bound / items_per_section` exists.
    /// - No section index > `upper_bound / items_per_section` exists.
    /// - The last retained section is truncated so that its last item’s location is `<= upper_bound`.
    pub(crate) async fn init_sync(
        context: E,
        cfg: Config<V::Cfg>,
        lower_bound: u64,
        upper_bound: u64,
        items_per_section: NonZeroU64,
    ) -> Result<Self, Error> {
        if lower_bound > upper_bound {
            return Err(Error::InvalidSyncRange(lower_bound, upper_bound));
        }

        // Calculate the section ranges based on item locations
        let items_per_section = items_per_section.get();
        let lower_section = lower_bound / items_per_section;
        let upper_section = upper_bound / items_per_section;

        debug!(
            lower_bound,
            upper_bound,
            lower_section,
            upper_section,
            items_per_section = items_per_section,
            "initializing variable journal"
        );

        // Initialize the base journal to see what existing data we have
        let mut journal = Self::init(context.clone(), cfg.clone()).await?;

        let last_section = journal.blobs.last_key_value().map(|(&s, _)| s);

        // No existing data
        let Some(last_section) = last_section else {
            debug!("no existing journal data, creating fresh journal");
            return Ok(journal);
        };

        // If all existing data is before our sync range, destroy and recreate fresh
        if last_section < lower_section {
            debug!(
                last_section,
                lower_section, "existing journal data is stale, re-initializing"
            );
            journal.destroy().await?;
            return Self::init(context, cfg).await;
        }

        // Prune sections below the lower bound.
        if lower_section > 0 {
            journal.prune(lower_section).await?;
        }

        // Remove any sections beyond the upper bound
        if last_section > upper_section {
            debug!(
                last_section,
                lower_section,
                upper_section,
                "existing journal data exceeds sync range, removing sections beyond upper bound"
            );

            let sections_to_remove: Vec<u64> = journal
                .blobs
                .range((Bound::Excluded(upper_section), Bound::Unbounded))
                .map(|(&section, _)| section)
                .collect();

            for section in sections_to_remove {
                debug!(section, "removing section beyond upper bound");
                if let Some(blob) = journal.blobs.remove(&section) {
                    drop(blob);
                    let name = section.to_be_bytes();
                    journal
                        .context
                        .remove(&journal.cfg.partition, Some(&name))
                        .await?;
                    journal.tracked.dec();
                }
            }
        }

        // Remove any items beyond upper_bound
        Self::truncate_upper_section(&mut journal, upper_bound, items_per_section).await?;

        Ok(journal)
    }

    /// Remove items beyond the `upper_bound` location (inclusive).
    /// Assumes each section contains `items_per_section` items.
    async fn truncate_upper_section(
        journal: &mut Journal<E, V>,
        upper_bound: u64,
        items_per_section: u64,
    ) -> Result<(), Error> {
        // Find which section contains the upper_bound item
        let upper_section = upper_bound / items_per_section;
        let Some(blob) = journal.blobs.get(&upper_section) else {
            return Ok(()); // Section doesn't exist, nothing to truncate
        };

        // Calculate the logical item range for this section
        let section_start = upper_section * items_per_section;
        let section_end = section_start + items_per_section - 1;

        // If upper_bound is at the very end of the section, no truncation needed
        if upper_bound >= section_end {
            return Ok(());
        }

        // Calculate how many items to keep (upper_bound is inclusive)
        let items_to_keep = (upper_bound - section_start + 1) as u32;
        debug!(
            upper_section,
            upper_bound,
            section_start,
            section_end,
            items_to_keep,
            "truncating section to remove items beyond upper_bound"
        );

        // Find where to rewind to (after the last item we want to keep)
        let target_byte_size = Self::compute_offset(
            blob,
            &journal.cfg.codec_config,
            journal.cfg.compression.is_some(),
            items_to_keep,
        )
        .await?;

        // Rewind to the appropriate position to remove items beyond the upper bound
        journal
            .rewind_section(upper_section, target_byte_size)
            .await?;

        debug!(
            upper_section,
            items_to_keep, target_byte_size, "section truncated"
        );

        Ok(())
    }

    /// Return the byte offset of the next element after `items_count` elements of `blob`.
    async fn compute_offset(
        blob: &Append<E::Blob>,
        codec_config: &V::Cfg,
        compressed: bool,
        items_count: u32,
    ) -> Result<u64, Error> {
        if items_count == 0 {
            return Ok(0);
        }

        let mut current_offset = 0u32;

        // Read through items one by one to find where each one ends
        for _ in 0..items_count {
            match Self::read(compressed, codec_config, blob, current_offset).await {
                Ok((next_slot, _item_len, _item)) => {
                    current_offset = next_slot;
                }
                Err(Error::Runtime(commonware_runtime::Error::BlobInsufficientLength)) => {
                    // This section has fewer than `items_count` items.
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        Ok((current_offset as u64) * ITEM_ALIGNMENT)
    }

    /// Ensures that a pruned section is not accessed.
    fn prune_guard(&self, section: u64, inclusive: bool) -> Result<(), Error> {
        if let Some(oldest_allowed) = self.oldest_allowed {
            if section < oldest_allowed || (inclusive && section <= oldest_allowed) {
                return Err(Error::AlreadyPrunedToSection(oldest_allowed));
            }
        }
        Ok(())
    }

    /// Reads an item from the blob at the given offset.
    async fn read(
        compressed: bool,
        cfg: &V::Cfg,
        blob: &Append<E::Blob>,
        offset: u32,
    ) -> Result<(u32, u32, V), Error> {
        // Read item size
        let mut hasher = crc32fast::Hasher::new();
        let offset = offset as u64 * ITEM_ALIGNMENT;
        let size = blob.read_at(vec![0; 4], offset).await?;
        hasher.update(size.as_ref());
        let size = u32::from_be_bytes(size.as_ref().try_into().unwrap()) as usize;
        let offset = offset.checked_add(4).ok_or(Error::OffsetOverflow)?;

        // Read remaining
        let buf_size = size.checked_add(4).ok_or(Error::OffsetOverflow)?;
        let buf = blob.read_at(vec![0u8; buf_size], offset).await?;
        let buf = buf.as_ref();
        let offset = offset
            .checked_add(buf_size as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Read item
        let item = &buf[..size];
        hasher.update(item);

        // Verify integrity
        let checksum = hasher.finalize();
        let stored_checksum = u32::from_be_bytes(buf[size..].try_into().unwrap());
        if checksum != stored_checksum {
            return Err(Error::ChecksumMismatch(stored_checksum, checksum));
        }

        // Compute next offset
        let aligned_offset = compute_next_offset(offset)?;

        // If compression is enabled, decompress the item
        let item = if compressed {
            let decompressed =
                decode_all(Cursor::new(&item)).map_err(|_| Error::DecompressionFailed)?;
            V::decode_cfg(decompressed.as_ref(), cfg).map_err(Error::Codec)?
        } else {
            V::decode_cfg(item, cfg).map_err(Error::Codec)?
        };

        // Return item
        Ok((aligned_offset, size as u32, item))
    }

    /// Helper function to read an item from a [Read].
    async fn read_buffered(
        reader: &mut Read<Append<E::Blob>>,
        offset: u32,
        cfg: &V::Cfg,
        compressed: bool,
    ) -> Result<(u32, u64, u32, V), Error> {
        // Calculate absolute file offset from the item offset
        let file_offset = offset as u64 * ITEM_ALIGNMENT;

        // If we're not at the right position, seek to it
        if reader.position() != file_offset {
            reader.seek_to(file_offset).map_err(Error::Runtime)?;
        }

        // Read item size (4 bytes)
        let mut hasher = crc32fast::Hasher::new();
        let mut size_buf = [0u8; 4];
        reader
            .read_exact(&mut size_buf, 4)
            .await
            .map_err(Error::Runtime)?;
        hasher.update(&size_buf);

        // Read remaining
        let size = u32::from_be_bytes(size_buf) as usize;
        let buf_size = size.checked_add(4).ok_or(Error::OffsetOverflow)?;
        let mut buf = vec![0u8; buf_size];
        reader
            .read_exact(&mut buf, buf_size)
            .await
            .map_err(Error::Runtime)?;

        // Read item
        let item = &buf[..size];
        hasher.update(item);

        // Verify integrity
        let checksum = hasher.finalize();
        let stored_checksum = u32::from_be_bytes(buf[size..].try_into().unwrap());
        if checksum != stored_checksum {
            return Err(Error::ChecksumMismatch(stored_checksum, checksum));
        }

        // If compression is enabled, decompress the item
        let item = if compressed {
            let decompressed =
                decode_all(Cursor::new(&item)).map_err(|_| Error::DecompressionFailed)?;
            V::decode_cfg(decompressed.as_ref(), cfg).map_err(Error::Codec)?
        } else {
            V::decode_cfg(item, cfg).map_err(Error::Codec)?
        };

        // Calculate next offset
        let current_pos = reader.position();
        let aligned_offset = compute_next_offset(current_pos)?;
        Ok((aligned_offset, current_pos, size as u32, item))
    }

    /// Reads an item from the blob at the given offset and of a given size.
    async fn read_exact(
        compressed: bool,
        cfg: &V::Cfg,
        blob: &Append<E::Blob>,
        offset: u32,
        len: u32,
    ) -> Result<V, Error> {
        // Read buffer
        let offset = offset as u64 * ITEM_ALIGNMENT;
        let entry_size = 4 + len as usize + 4;
        let buf = blob.read_at(vec![0u8; entry_size], offset).await?;

        // Check size
        let mut hasher = crc32fast::Hasher::new();
        let disk_size = u32::from_be_bytes(buf.as_ref()[..4].try_into().unwrap());
        hasher.update(&buf.as_ref()[..4]);
        if disk_size != len {
            return Err(Error::UnexpectedSize(disk_size, len));
        }

        // Verify integrity
        let item = &buf.as_ref()[4..4 + len as usize];
        hasher.update(item);
        let checksum = hasher.finalize();
        let stored_checksum =
            u32::from_be_bytes(buf.as_ref()[4 + len as usize..].try_into().unwrap());
        if checksum != stored_checksum {
            return Err(Error::ChecksumMismatch(stored_checksum, checksum));
        }

        // Decompress item
        let item = if compressed {
            decode_all(Cursor::new(item)).map_err(|_| Error::DecompressionFailed)?
        } else {
            item.to_vec()
        };

        // Return item
        let item = V::decode_cfg(item.as_ref(), cfg).map_err(Error::Codec)?;
        Ok(item)
    }

    /// Returns an ordered stream of all items in the journal, each as a tuple of (section, offset,
    /// size, item).
    ///
    /// # Repair
    ///
    /// Like [sqlite](https://github.com/sqlite/sqlite/blob/8658a8df59f00ec8fcfea336a2a6a4b5ef79d2ee/src/wal.c#L1504-L1505)
    /// and [rocksdb](https://github.com/facebook/rocksdb/blob/0c533e61bc6d89fdf1295e8e0bcee4edb3aef401/include/rocksdb/options.h#L441-L445),
    /// the first invalid data read will be considered the new end of the journal (and the underlying [Blob] will be
    /// truncated to the last valid item).
    pub async fn replay(
        &self,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, u32, u32, V), Error>> + '_, Error> {
        // Collect all blobs to replay
        let codec_config = self.cfg.codec_config.clone();
        let compressed = self.cfg.compression.is_some();
        let mut blobs = Vec::with_capacity(self.blobs.len());
        for (section, blob) in self.blobs.iter() {
            let blob_size = blob.size().await;
            let max_offset = compute_next_offset(blob_size)?;
            blobs.push((
                *section,
                blob.clone(),
                max_offset,
                blob_size,
                codec_config.clone(),
                compressed,
            ));
        }

        // Replay all blobs in order and stream items as they are read (to avoid occupying too much
        // memory with buffered data)
        Ok(
            stream::iter(blobs).flat_map(
                move |(section, blob, max_offset, blob_size, codec_config, compressed)| {
                    // Created buffered reader
                    let reader = Read::new(blob, blob_size, buffer);

                    // Read over the blob
                    stream::unfold(
                        (section, reader, 0u32, 0u64, codec_config, compressed),
                        move |(
                            section,
                            mut reader,
                            offset,
                            valid_size,
                            codec_config,
                            compressed,
                        )| async move {
                            // Check if we are at the end of the blob
                            if offset >= max_offset {
                                return None;
                            }

                            // Read an item from the buffer
                            match Self::read_buffered(
                                &mut reader,
                                offset,
                                &codec_config,
                                compressed,
                            )
                            .await
                            {
                                Ok((next_offset, next_valid_size, size, item)) => {
                                    trace!(blob = section, cursor = offset, "replayed item");
                                    Some((
                                        Ok((section, offset, size, item)),
                                        (
                                            section,
                                            reader,
                                            next_offset,
                                            next_valid_size,
                                            codec_config,
                                            compressed,
                                        ),
                                    ))
                                }
                                Err(Error::ChecksumMismatch(expected, found)) => {
                                    // If we encounter corruption, we prune to the last valid item. This
                                    // can happen during an unclean file close (where pending data is not
                                    // fully synced to disk).
                                    warn!(
                                        blob = section,
                                        new_offset = offset,
                                        new_size = valid_size,
                                        expected,
                                        found,
                                        "corruption detected: truncating"
                                    );
                                    reader.resize(valid_size).await.ok()?;
                                    None
                                }
                                Err(Error::Runtime(RError::BlobInsufficientLength)) => {
                                    // If we encounter trailing bytes, we prune to the last
                                    // valid item. This can happen during an unclean file close (where
                                    // pending data is not fully synced to disk).
                                    warn!(
                                        blob = section,
                                        new_offset = offset,
                                        new_size = valid_size,
                                        "trailing bytes detected: truncating"
                                    );
                                    reader.resize(valid_size).await.ok()?;
                                    None
                                }
                                Err(err) => {
                                    // If we encounter an unexpected error, return it without attempting
                                    // to fix anything.
                                    warn!(
                                        blob = section,
                                        cursor = offset,
                                        ?err,
                                        "unexpected error"
                                    );
                                    Some((
                                        Err(err),
                                        (
                                            section,
                                            reader,
                                            offset,
                                            valid_size,
                                            codec_config,
                                            compressed,
                                        ),
                                    ))
                                }
                            }
                        },
                    )
                },
            ),
        )
    }

    /// Appends an item to `Journal` in a given `section`, returning the offset
    /// where the item was written and the size of the item (which may now be smaller
    /// than the encoded size from the codec, if compression is enabled).
    ///
    /// # Warning
    ///
    /// If there exist trailing bytes in the `Blob` of a particular `section` and
    /// `replay` is not called before this, it is likely that subsequent data added
    /// to the `Blob` will be considered corrupted (as the trailing bytes will fail
    /// the checksum verification). It is recommended to call `replay` before calling
    /// `append` to prevent this.
    pub async fn append(&mut self, section: u64, item: V) -> Result<(u32, u32), Error> {
        // Check last pruned
        self.prune_guard(section, false)?;

        // Create item
        let encoded = item.encode();
        let encoded = if let Some(compression) = self.cfg.compression {
            compress(&encoded, compression as i32).map_err(|_| Error::CompressionFailed)?
        } else {
            encoded.into()
        };

        // Ensure item is not too large
        let item_len = encoded.len();
        let entry_len = 4 + item_len + 4;
        let item_len = match item_len.try_into() {
            Ok(len) => len,
            Err(_) => return Err(Error::ItemTooLarge(item_len)),
        };

        // Get existing blob or create new one
        let blob = match self.blobs.entry(section) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let name = section.to_be_bytes();
                let (blob, size) = self.context.open(&self.cfg.partition, &name).await?;
                let blob = Append::new(
                    blob,
                    size,
                    self.cfg.write_buffer,
                    self.cfg.buffer_pool.clone(),
                )
                .await?;
                self.tracked.inc();
                entry.insert(blob)
            }
        };

        // Calculate alignment
        let cursor = blob.size().await;
        let offset = compute_next_offset(cursor)?;
        let aligned_cursor = offset as u64 * ITEM_ALIGNMENT;
        let padding = (aligned_cursor - cursor) as usize;

        // Populate buffer
        let mut buf = Vec::with_capacity(padding + entry_len);

        // Add padding bytes if necessary
        if padding > 0 {
            buf.resize(padding, 0);
        }

        // Add entry data
        let entry_start = buf.len();
        buf.put_u32(item_len);
        buf.put_slice(&encoded);

        // Calculate checksum only for the entry data (without padding)
        let checksum = crc32fast::hash(&buf[entry_start..]);
        buf.put_u32(checksum);
        assert_eq!(buf[entry_start..].len(), entry_len);

        // Append item to blob
        blob.append(buf).await?;
        trace!(blob = section, offset, "appended item");
        Ok((offset, item_len))
    }

    /// Retrieves an item from `Journal` at a given `section` and `offset`.
    pub async fn get(&self, section: u64, offset: u32) -> Result<Option<V>, Error> {
        self.prune_guard(section, false)?;
        let blob = match self.blobs.get(&section) {
            Some(blob) => blob,
            None => return Ok(None),
        };

        // Perform a multi-op read.
        let (_, _, item) = Self::read(
            self.cfg.compression.is_some(),
            &self.cfg.codec_config,
            blob,
            offset,
        )
        .await?;
        Ok(Some(item))
    }

    /// Retrieves an item from `Journal` at a given `section` and `offset` with a given size.
    pub async fn get_exact(
        &self,
        section: u64,
        offset: u32,
        size: u32,
    ) -> Result<Option<V>, Error> {
        self.prune_guard(section, false)?;
        let blob = match self.blobs.get(&section) {
            Some(blob) => blob,
            None => return Ok(None),
        };

        // Perform a multi-op read.
        let item = Self::read_exact(
            self.cfg.compression.is_some(),
            &self.cfg.codec_config,
            blob,
            offset,
            size,
        )
        .await?;
        Ok(Some(item))
    }

    /// Gets the size of the journal for a specific section.
    ///
    /// Returns 0 if the section does not exist.
    pub async fn size(&self, section: u64) -> Result<u64, Error> {
        self.prune_guard(section, false)?;
        match self.blobs.get(&section) {
            Some(blob) => Ok(blob.size().await),
            None => Ok(0),
        }
    }

    /// Rewinds the journal to the given `section` and `offset`, removing any data beyond it.
    pub async fn rewind_to_offset(&mut self, section: u64, offset: u32) -> Result<(), Error> {
        self.rewind(section, offset as u64 * ITEM_ALIGNMENT).await
    }

    /// Rewinds the journal to the given `section` and `size`.
    ///
    /// This removes any data beyond the specified `section` and `size`.
    pub async fn rewind(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section, false)?;

        // Remove any sections beyond the given section
        let trailing: Vec<u64> = self
            .blobs
            .range((
                std::ops::Bound::Excluded(section),
                std::ops::Bound::Unbounded,
            ))
            .map(|(&section, _)| section)
            .collect();
        for index in trailing.iter().rev() {
            // Remove the underlying blob from storage.
            let blob = self.blobs.remove(index).unwrap();

            // Destroy the blob
            drop(blob);
            self.context
                .remove(&self.cfg.partition, Some(&index.to_be_bytes()))
                .await?;
            debug!(section = index, "removed section");
            self.tracked.dec();
        }

        // If the section exists, truncate it to the given offset
        let blob = match self.blobs.get_mut(&section) {
            Some(blob) => blob,
            None => return Ok(()),
        };
        let current = blob.size().await;
        if size >= current {
            return Ok(()); // Already smaller than or equal to target size
        }
        blob.resize(size).await?;
        debug!(
            section,
            from = current,
            to = size,
            ?trailing,
            "rewound journal"
        );
        Ok(())
    }

    /// Rewinds the `section` to the given `size`.
    ///
    /// Unlike [Self::rewind], this method does not modify anything other than the given `section`.
    pub async fn rewind_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section, false)?;

        // Get the blob at the given section
        let blob = match self.blobs.get_mut(&section) {
            Some(blob) => blob,
            None => return Ok(()),
        };

        // Truncate the blob to the given size
        let current = blob.size().await;
        if size >= current {
            return Ok(()); // Already smaller than or equal to target size
        }
        blob.resize(size).await?;
        debug!(section, from = current, to = size, "rewound section");
        Ok(())
    }

    /// Ensures that all data in a given `section` is synced to the underlying store.
    ///
    /// If the `section` does not exist, no error will be returned.
    pub async fn sync(&self, section: u64) -> Result<(), Error> {
        self.prune_guard(section, false)?;
        let blob = match self.blobs.get(&section) {
            Some(blob) => blob,
            None => return Ok(()),
        };
        self.synced.inc();
        blob.sync().await.map_err(Error::Runtime)
    }

    /// Prunes all `sections` less than `min`.
    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        // Prune any blobs that are smaller than the minimum
        while let Some((&section, _)) = self.blobs.first_key_value() {
            // Stop pruning if we reach the minimum
            if section >= min {
                break;
            }

            // Remove blob
            let blob = self.blobs.remove(&section).unwrap();
            let size = blob.size().await;
            drop(blob);

            // Remove blob from storage
            self.context
                .remove(&self.cfg.partition, Some(&section.to_be_bytes()))
                .await?;
            debug!(blob = section, size, "pruned blob");
            self.tracked.dec();
            self.pruned.inc();
        }

        // Update oldest allowed
        self.oldest_allowed = Some(min);
        Ok(())
    }

    /// Syncs and closes all open sections.
    pub async fn close(self) -> Result<(), Error> {
        for (section, blob) in self.blobs.into_iter() {
            let size = blob.size().await;
            blob.sync().await?;
            debug!(blob = section, size, "synced blob");
        }
        Ok(())
    }

    /// Remove any underlying blobs created by the journal.
    pub async fn destroy(self) -> Result<(), Error> {
        for (i, blob) in self.blobs.into_iter() {
            let size = blob.size().await;
            drop(blob);
            debug!(blob = i, size, "destroyed blob");
            self.context
                .remove(&self.cfg.partition, Some(&i.to_be_bytes()))
                .await?;
        }
        match self.context.remove(&self.cfg.partition, None).await {
            Ok(()) => {}
            Err(RError::PartitionMissing(_)) => {
                // Partition already removed or never existed.
            }
            Err(err) => return Err(Error::Runtime(err)),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use commonware_cryptography::hash;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob, Error as RError, Runner, Storage};
    use commonware_utils::{NZUsize, StableBuf, NZU64};
    use futures::{pin_mut, StreamExt};
    use prometheus_client::registry::Metric;

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    #[test_traced]
    fn test_journal_append_and_read() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal
            let cfg = Config {
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let index = 1u64;
            let data = 10;
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append an item to the journal
            journal
                .append(index, data)
                .await
                .expect("Failed to append data");

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("tracked 1"));

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Re-initialize the journal to simulate a restart
            let cfg = Config {
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let journal = Journal::<_, i32>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::new();
            let stream = journal
                .replay(NZUsize!(1024))
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
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
            assert!(buffer.contains("tracked 1"));
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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append multiple items to different blobs
            let data_items = vec![(1u64, 1), (1u64, 2), (2u64, 3), (3u64, 4)];
            for (index, data) in &data_items {
                journal
                    .append(*index, *data)
                    .await
                    .expect("Failed to append data");
                journal.sync(*index).await.expect("Failed to sync blob");
            }

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("tracked 3"));
            assert!(buffer.contains("synced_total 4"));

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::init(context, cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::<(u64, u32)>::new();
            {
                let stream = journal
                    .replay(NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append items to multiple blobs
            for index in 1u64..=5u64 {
                journal
                    .append(index, index)
                    .await
                    .expect("Failed to append data");
                journal.sync(index).await.expect("Failed to sync blob");
            }

            // Add one item out-of-order
            let data = 99;
            journal
                .append(2u64, data)
                .await
                .expect("Failed to append data");
            journal.sync(2u64).await.expect("Failed to sync blob");

            // Prune blobs with indices less than 3
            journal.prune(3).await.expect("Failed to prune blobs");

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 2"));

            // Prune again with a section less than the previous one, should be a no-op
            journal.prune(2).await.expect("Failed to no-op prune");
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 2"));

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::<(u64, u64)>::new();
            {
                let stream = journal
                    .replay(NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
            }

            // Verify that items from blobs 1 and 2 are not present
            assert_eq!(items.len(), 3);
            let expected_indices = [3u64, 4u64, 5u64];
            for (item, expected_index) in items.iter().zip(expected_indices.iter()) {
                assert_eq!(item.0, *expected_index);
            }

            // Prune all blobs
            journal.prune(6).await.expect("Failed to prune blobs");

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Ensure no remaining blobs exist
            //
            // Note: We don't remove the partition, so this does not error
            // and instead returns an empty list of blobs.
            assert!(context
                .scan(&cfg.partition)
                .await
                .expect("Failed to list blobs")
                .is_empty());
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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Manually create a blob with incomplete size data
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let (blob, _) = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Write incomplete size data (less than 4 bytes)
            let incomplete_data = vec![0x00, 0x01]; // Less than 4 bytes
            blob.write_at(incomplete_data, 0)
                .await
                .expect("Failed to write incomplete data");
            blob.sync().await.expect("Failed to sync blob");

            // Initialize the journal
            let journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            let stream = journal
                .replay(NZUsize!(1024))
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            let mut items = Vec::<(u64, u64)>::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {err}"),
                }
            }
            assert!(items.is_empty());
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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Manually create a blob with missing item data
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let (blob, _) = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Write size but no item data
            let item_size: u32 = 10; // Size of the item
            let mut buf = Vec::new();
            buf.put_u32(item_size);
            let data = [2u8; 5];
            BufMut::put_slice(&mut buf, &data);
            blob.write_at(buf, 0)
                .await
                .expect("Failed to write item size");
            blob.sync().await.expect("Failed to sync blob");

            // Initialize the journal
            let journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            let stream = journal
                .replay(NZUsize!(1024))
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            let mut items = Vec::<(u64, u64)>::new();
            while let Some(result) = stream.next().await {
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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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

            // Write size
            let mut offset = 0;
            blob.write_at(item_size.to_be_bytes().to_vec(), offset)
                .await
                .expect("Failed to write item size");
            offset += 4;

            // Write item data
            blob.write_at(item_data.to_vec(), offset)
                .await
                .expect("Failed to write item data");
            // Do not write checksum (omit it)

            blob.sync().await.expect("Failed to sync blob");

            // Initialize the journal
            let journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            //
            // This will truncate the leftover bytes from our manual write.
            let stream = journal
                .replay(NZUsize!(1024))
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            let mut items = Vec::<(u64, u64)>::new();
            while let Some(result) = stream.next().await {
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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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

            // Write size
            let mut offset = 0;
            blob.write_at(item_size.to_be_bytes().to_vec(), offset)
                .await
                .expect("Failed to write item size");
            offset += 4;

            // Write item data
            blob.write_at(item_data.to_vec(), offset)
                .await
                .expect("Failed to write item data");
            offset += item_data.len() as u64;

            // Write incorrect checksum
            blob.write_at(incorrect_checksum.to_be_bytes().to_vec(), offset)
                .await
                .expect("Failed to write incorrect checksum");

            blob.sync().await.expect("Failed to sync blob");

            // Initialize the journal
            let journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            {
                let stream = journal
                    .replay(NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                let mut items = Vec::<(u64, u64)>::new();
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
                assert!(items.is_empty());
            }
            journal.close().await.expect("Failed to close journal");

            // Confirm blob is expected length
            let (_, blob_size) = context
                .open(&cfg.partition, &section.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(blob_size, 0);
        });
    }

    #[test_traced]
    fn test_journal_handling_unaligned_truncated_data() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append 1 item to the first index
            journal.append(1, 1).await.expect("Failed to append data");

            // Append multiple items to the second index (with unaligned values)
            let data_items = vec![(2u64, 2), (2u64, 3), (2u64, 4)];
            for (index, data) in &data_items {
                journal
                    .append(*index, *data)
                    .await
                    .expect("Failed to append data");
                journal.sync(*index).await.expect("Failed to sync blob");
            }

            // Close the journal
            journal.close().await.expect("Failed to close journal");

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
            let journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Attempt to replay the journal
            let mut items = Vec::<(u64, u32)>::new();
            {
                let stream = journal
                    .replay(NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
            }
            journal.close().await.expect("Failed to close journal");

            // Verify that only non-corrupted items were replayed
            assert_eq!(items.len(), 3);
            assert_eq!(items[0].0, 1);
            assert_eq!(items[0].1, 1);
            assert_eq!(items[1].0, data_items[0].0);
            assert_eq!(items[1].1, data_items[0].1);
            assert_eq!(items[2].0, data_items[1].0);
            assert_eq!(items[2].1, data_items[1].1);

            // Confirm blob is expected length
            let (_, blob_size) = context
                .open(&cfg.partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(blob_size, 28);

            // Attempt to replay journal after truncation
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Attempt to replay the journal
            let mut items = Vec::<(u64, u32)>::new();
            {
                let stream = journal
                    .replay(NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
            }

            // Verify that only non-corrupted items were replayed
            assert_eq!(items.len(), 3);
            assert_eq!(items[0].0, 1);
            assert_eq!(items[0].1, 1);
            assert_eq!(items[1].0, data_items[0].0);
            assert_eq!(items[1].1, data_items[0].1);
            assert_eq!(items[2].0, data_items[1].0);
            assert_eq!(items[2].1, data_items[1].1);

            // Append a new item to truncated partition
            journal.append(2, 5).await.expect("Failed to append data");
            journal.sync(2).await.expect("Failed to sync blob");

            // Get the new item
            let item = journal
                .get(2, 2)
                .await
                .expect("Failed to get item")
                .expect("Failed to get item");
            assert_eq!(item, 5);

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Confirm blob is expected length
            let (_, blob_size) = context
                .open(&cfg.partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(blob_size, 44);

            // Re-initialize the journal to simulate a restart
            let journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Attempt to replay the journal
            let mut items = Vec::<(u64, u32)>::new();
            {
                let stream = journal
                    .replay(NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
            }

            // Verify that only non-corrupted items were replayed
            assert_eq!(items.len(), 4);
            assert_eq!(items[0].0, 1);
            assert_eq!(items[0].1, 1);
            assert_eq!(items[1].0, data_items[0].0);
            assert_eq!(items[1].1, data_items[0].1);
            assert_eq!(items[2].0, data_items[1].0);
            assert_eq!(items[2].1, data_items[1].1);
            assert_eq!(items[3].0, 2);
            assert_eq!(items[3].1, 5);
        });
    }

    #[test_traced]
    fn test_journal_handling_aligned_truncated_data() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append 1 item to the first index
            journal.append(1, 1).await.expect("Failed to append data");

            // Append multiple items to the second index (with unaligned values)
            let data_items = vec![(2u64, 2), (2u64, 3), (2u64, 4)];
            for (index, data) in &data_items {
                journal
                    .append(*index, *data)
                    .await
                    .expect("Failed to append data");
                journal.sync(*index).await.expect("Failed to sync blob");
            }

            // Close the journal
            journal.close().await.expect("Failed to close journal");

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
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Attempt to replay the journal
            let mut items = Vec::<(u64, u64)>::new();
            {
                let stream = journal
                    .replay(NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
            }

            // Verify that only non-corrupted items were replayed
            assert_eq!(items.len(), 3);
            assert_eq!(items[0].0, 1);
            assert_eq!(items[0].1, 1);
            assert_eq!(items[1].0, data_items[0].0);
            assert_eq!(items[1].1, data_items[0].1);
            assert_eq!(items[2].0, data_items[1].0);
            assert_eq!(items[2].1, data_items[1].1);

            // Append a new item to the truncated partition
            journal.append(2, 5).await.expect("Failed to append data");
            journal.sync(2).await.expect("Failed to sync blob");

            // Get the new item
            let item = journal
                .get(2, 2)
                .await
                .expect("Failed to get item")
                .expect("Failed to get item");
            assert_eq!(item, 5);

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Confirm blob is expected length
            let (_, blob_size) = context
                .open(&cfg.partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(blob_size, 48);

            // Attempt to replay journal after truncation
            let journal = Journal::init(context, cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Attempt to replay the journal
            let mut items = Vec::<(u64, u64)>::new();
            {
                let stream = journal
                    .replay(NZUsize!(1024))
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
            }
            journal.close().await.expect("Failed to close journal");

            // Verify that only non-corrupted items were replayed
            assert_eq!(items.len(), 4);
            assert_eq!(items[0].0, 1);
            assert_eq!(items[0].1, 1);
            assert_eq!(items[1].0, data_items[0].0);
            assert_eq!(items[1].1, data_items[0].1);
            assert_eq!(items[2].0, data_items[1].0);
            assert_eq!(items[2].1, data_items[1].1);
            assert_eq!(items[3].0, 2);
            assert_eq!(items[3].1, 5);
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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append 1 item to the first index
            journal.append(1, 1).await.expect("Failed to append data");

            // Append multiple items to the second index
            let data_items = vec![(2u64, 2), (2u64, 3), (2u64, 4)];
            for (index, data) in &data_items {
                journal
                    .append(*index, *data)
                    .await
                    .expect("Failed to append data");
                journal.sync(*index).await.expect("Failed to sync blob");
            }

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Manually add extra data to the end of the second blob
            let (blob, blob_size) = context
                .open(&cfg.partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.write_at(vec![0u8; 16], blob_size)
                .await
                .expect("Failed to add extra data");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::init(context, cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Attempt to replay the journal
            let mut items = Vec::<(u64, i32)>::new();
            let stream = journal
                .replay(NZUsize!(1024))
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {err}"),
                }
            }
        });
    }

    // Define `MockBlob` that returns an offset length that should overflow
    #[derive(Clone)]
    struct MockBlob {}

    impl Blob for MockBlob {
        async fn read_at(
            &self,
            buf: impl Into<StableBuf> + Send,
            _offset: u64,
        ) -> Result<StableBuf, RError> {
            Ok(buf.into())
        }

        async fn write_at(
            &self,
            _buf: impl Into<StableBuf> + Send,
            _offset: u64,
        ) -> Result<(), RError> {
            Ok(())
        }

        async fn resize(&self, _len: u64) -> Result<(), RError> {
            Ok(())
        }

        async fn sync(&self) -> Result<(), RError> {
            Ok(())
        }
    }

    // Define `MockStorage` that returns `MockBlob`
    #[derive(Clone)]
    struct MockStorage {
        len: u64,
    }

    impl Storage for MockStorage {
        type Blob = MockBlob;

        async fn open(&self, _partition: &str, _name: &[u8]) -> Result<(MockBlob, u64), RError> {
            Ok((MockBlob {}, self.len))
        }

        async fn remove(&self, _partition: &str, _name: Option<&[u8]>) -> Result<(), RError> {
            Ok(())
        }

        async fn scan(&self, _partition: &str) -> Result<Vec<Vec<u8>>, RError> {
            Ok(vec![])
        }
    }

    impl Metrics for MockStorage {
        fn with_label(&self, _: &str) -> Self {
            self.clone()
        }

        fn label(&self) -> String {
            String::new()
        }

        fn register<N: Into<String>, H: Into<String>>(&self, _: N, _: H, _: impl Metric) {}

        fn encode(&self) -> String {
            String::new()
        }
    }

    // Define the `INDEX_ALIGNMENT` again explicitly to ensure we catch any accidental
    // changes to the value
    const INDEX_ALIGNMENT: u64 = 16;

    #[test_traced]
    fn test_journal_large_offset() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Create journal
            let cfg = Config {
                partition: "partition".to_string(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let context = MockStorage {
                len: u32::MAX as u64 * INDEX_ALIGNMENT, // can store up to u32::Max at the last offset
            };
            let mut journal = Journal::init(context, cfg).await.unwrap();

            // Append data
            let data = 1;
            let (result, _) = journal
                .append(1, data)
                .await
                .expect("Failed to append data");
            assert_eq!(result, u32::MAX);
        });
    }

    #[test_traced]
    fn test_journal_offset_overflow() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Create journal
            let cfg = Config {
                partition: "partition".to_string(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let context = MockStorage {
                len: u32::MAX as u64 * INDEX_ALIGNMENT + 1,
            };
            let mut journal = Journal::init(context, cfg).await.unwrap();

            // Append data
            let data = 1;
            let result = journal.append(1, data).await;
            assert!(matches!(result, Err(Error::OffsetOverflow)));
        });
    }

    #[test_traced]
    fn test_journal_rewind() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create journal
            let cfg = Config {
                partition: "test_partition".to_string(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context, cfg).await.unwrap();

            // Check size of non-existent section
            let size = journal.size(1).await.unwrap();
            assert_eq!(size, 0);

            // Append data to section 1
            journal.append(1, 42i32).await.unwrap();

            // Check size of section 1 - should be greater than 0
            let size = journal.size(1).await.unwrap();
            assert!(size > 0);

            // Append more data and verify size increases
            journal.append(1, 43i32).await.unwrap();
            let new_size = journal.size(1).await.unwrap();
            assert!(new_size > size);

            // Check size of different section - should still be 0
            let size = journal.size(2).await.unwrap();
            assert_eq!(size, 0);

            // Append data to section 2
            journal.append(2, 44i32).await.unwrap();

            // Check size of section 2 - should be greater than 0
            let size = journal.size(2).await.unwrap();
            assert!(size > 0);

            // Rollback everything in section 1 and 2
            journal.rewind(1, 0).await.unwrap();

            // Check size of section 1 - should be 0
            let size = journal.size(1).await.unwrap();
            assert_eq!(size, 0);

            // Check size of section 2 - should be 0
            let size = journal.size(2).await.unwrap();
            assert_eq!(size, 0);
        });
    }

    #[test_traced]
    fn test_journal_rewind_section() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create journal
            let cfg = Config {
                partition: "test_partition".to_string(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context, cfg).await.unwrap();

            // Check size of non-existent section
            let size = journal.size(1).await.unwrap();
            assert_eq!(size, 0);

            // Append data to section 1
            journal.append(1, 42i32).await.unwrap();

            // Check size of section 1 - should be greater than 0
            let size = journal.size(1).await.unwrap();
            assert!(size > 0);

            // Append more data and verify size increases
            journal.append(1, 43i32).await.unwrap();
            let new_size = journal.size(1).await.unwrap();
            assert!(new_size > size);

            // Check size of different section - should still be 0
            let size = journal.size(2).await.unwrap();
            assert_eq!(size, 0);

            // Append data to section 2
            journal.append(2, 44i32).await.unwrap();

            // Check size of section 2 - should be greater than 0
            let size = journal.size(2).await.unwrap();
            assert!(size > 0);

            // Rollback everything in section 1
            journal.rewind_section(1, 0).await.unwrap();

            // Check size of section 1 - should be 0
            let size = journal.size(1).await.unwrap();
            assert_eq!(size, 0);

            // Check size of section 2 - should be greater than 0
            let size = journal.size(2).await.unwrap();
            assert!(size > 0);
        });
    }

    /// Protect against accidental changes to the journal disk format.
    #[test_traced]
    fn test_journal_conformance() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append 100 items to the journal
            for i in 0..100 {
                journal.append(1, i).await.expect("Failed to append data");
            }
            journal.sync(1).await.expect("Failed to sync blob");

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Hash blob contents
            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert!(size > 0);
            let buf = blob
                .read_at(vec![0u8; size as usize], 0)
                .await
                .expect("Failed to read blob");
            let digest = hash(buf.as_ref());
            assert_eq!(
                hex(&digest),
                "ca3845fa7fabd4d2855ab72ed21226d1d6eb30cb895ea9ec5e5a14201f3f25d8",
            );
        });
    }

    /// Test `init_sync` when there is no existing data on disk.
    #[test_traced]
    fn test_init_sync_no_existing_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_fresh_start".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Initialize journal with sync boundaries when no existing data exists
            let lower_bound = 10;
            let upper_bound = 25;
            let items_per_section = NZU64!(5);
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with sync boundaries");

            // Verify the journal is ready for sync items
            assert!(journal.blobs.is_empty()); // No sections created yet
            assert_eq!(journal.oldest_allowed, None); // No pruning applied

            // Verify that items can be appended starting from the sync position
            let lower_section = lower_bound / items_per_section; // 10/5 = 2

            // Append an element
            let (offset, _) = journal.append(lower_section, 42u64).await.unwrap();
            assert_eq!(offset, 0); // First item in section

            // Verify the item can be retrieved
            let retrieved = journal.get(lower_section, offset).await.unwrap();
            assert_eq!(retrieved, Some(42u64));

            // Append another element
            let (offset2, _) = journal.append(lower_section, 43u64).await.unwrap();
            assert_eq!(
                journal.get(lower_section, offset2).await.unwrap(),
                Some(43u64)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when there is existing data that overlaps with the sync target range.
    #[test_traced]
    fn test_init_sync_existing_data_overlap() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_overlap".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Create initial journal with data in multiple sections
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            let items_per_section = NZU64!(5);

            // Add data to sections 0, 1, 2, 3 (simulating items 0-19 with items_per_section=5)
            for section in 0..4 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 10 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries that overlap with existing data
            // lower_bound: 8 (section 1), upper_bound: 30 (section 6)
            let lower_bound = 8;
            let upper_bound = 30;
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with overlap");

            // Verify pruning: sections before lower_section are pruned
            let lower_section = lower_bound / items_per_section; // 8/5 = 1
            assert_eq!(lower_section, 1);
            assert_eq!(journal.oldest_allowed, Some(lower_section));

            // Verify section 0 is pruned (< lower_section), section 1+ are retained (>= lower_section)
            assert!(!journal.blobs.contains_key(&0)); // Section 0 should be pruned
            assert!(journal.blobs.contains_key(&1)); // Section 1 should be retained (contains item 8)
            assert!(journal.blobs.contains_key(&2)); // Section 2 should be retained
            assert!(journal.blobs.contains_key(&3)); // Section 3 should be retained
            assert!(!journal.blobs.contains_key(&4)); // Section 4 should not exist

            // Verify data integrity: existing data in retained sections is accessible
            let item = journal.get(1, 0).await.unwrap();
            assert_eq!(item, Some(10)); // First item in section 1 (1*10+0)
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, Some(11)); // Second item in section 1 (1*10+1)
            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, Some(20)); // First item in section 2 (2*10+0)
            let last_element_section = 19 / items_per_section;
            let last_element_offset = (19 % items_per_section.get()) as u32;
            let item = journal
                .get(last_element_section, last_element_offset)
                .await
                .unwrap();
            assert_eq!(item, Some(34)); // Last item in section 3 (3*10+4)
            let next_element_section = 20 / items_per_section;
            let next_element_offset = (20 % items_per_section.get()) as u32;
            let item = journal
                .get(next_element_section, next_element_offset)
                .await
                .unwrap();
            assert_eq!(item, None); // Next element should not exist

            // Assert journal can accept new items
            let (offset, _) = journal.append(next_element_section, 999).await.unwrap();
            assert_eq!(
                journal.get(next_element_section, offset).await.unwrap(),
                Some(999)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when existing data exactly matches the sync target range.
    #[test_traced]
    fn test_init_sync_existing_data_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_exact_match".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Create initial journal with data exactly matching sync range
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data to sections 1, 2, 3 (items 5-19 with items_per_section=5)
            let items_per_section = NZU64!(5);
            for section in 1..4 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 100 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries that exactly match existing data
            let lower_bound = 5; // section 1
            let upper_bound = 19; // section 3
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with exact match");

            // Verify pruning to lower bound
            let lower_section = lower_bound / items_per_section; // 5/5 = 1
            assert_eq!(journal.oldest_allowed, Some(lower_section));

            // Verify section 0 is pruned, sections 1-3 are retained
            assert!(!journal.blobs.contains_key(&0)); // Section 0 should be pruned
            assert!(journal.blobs.contains_key(&1)); // Section 1 should be retained (contains item 5)
            assert!(journal.blobs.contains_key(&2)); // Section 2 should be retained
            assert!(journal.blobs.contains_key(&3)); // Section 3 should be retained

            // Verify data integrity: existing data in retained sections is accessible
            let item = journal.get(1, 0).await.unwrap();
            assert_eq!(item, Some(100)); // First item in section 1 (1*100+0)
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, Some(101)); // Second item in section 1 (1*100+1)
            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, Some(200)); // First item in section 2 (2*100+0)
            let last_element_section = 19 / items_per_section;
            let last_element_offset = (19 % items_per_section.get()) as u32;
            let item = journal
                .get(last_element_section, last_element_offset)
                .await
                .unwrap();
            assert_eq!(item, Some(304)); // Last item in section 3 (3*100+4)
            let next_element_section = 20 / items_per_section;
            let next_element_offset = (20 % items_per_section.get()) as u32;
            let item = journal
                .get(next_element_section, next_element_offset)
                .await
                .unwrap();
            assert_eq!(item, None); // Next element should not exist

            // Assert journal can accept new items
            let (offset, _) = journal.append(next_element_section, 999).await.unwrap();
            assert_eq!(
                journal.get(next_element_section, offset).await.unwrap(),
                Some(999)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when existing data exceeds the sync target range.
    #[test_traced]
    fn test_init_sync_existing_data_with_rewind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_rewind".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Create initial journal with data beyond sync range
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data to sections 0-5 (items 0-29 with items_per_section=5)
            let items_per_section = NZU64!(5);
            for section in 0..6 {
                for item in 0..items_per_section.get() {
                    journal
                        .append(section, section * 1000 + item)
                        .await
                        .unwrap();
                }
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries that are exceeded by existing data
            let lower_bound = 8; // section 1
            let upper_bound = 17; // section 3
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with rewind");

            // Verify pruning to lower bound and rewinding beyond upper bound
            let lower_section = lower_bound / items_per_section; // 8/5 = 1
            assert_eq!(journal.oldest_allowed, Some(lower_section));

            // Verify section 0 is pruned (< lower_section)
            assert!(!journal.blobs.contains_key(&0));

            // Verify sections within sync range exist (lower_section <= section <= upper_section)
            assert!(journal.blobs.contains_key(&1)); // Section 1 (contains item 8)
            assert!(journal.blobs.contains_key(&2)); // Section 2
            assert!(journal.blobs.contains_key(&3)); // Section 3 (contains item 17)

            // Verify sections beyond upper bound are removed (> upper_section)
            assert!(!journal.blobs.contains_key(&4)); // Section 4 should be removed
            assert!(!journal.blobs.contains_key(&5)); // Section 5 should be removed

            // Verify data integrity in retained sections
            let item = journal.get(1, 0).await.unwrap();
            assert_eq!(item, Some(1000)); // First item in section 1 (1*1000+0)
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, Some(1001)); // Second item in section 1 (1*1000+1)
            let item = journal.get(3, 0).await.unwrap();
            assert_eq!(item, Some(3000)); // First item in section 3 (3*1000+0)
            let last_element_section = 17 / items_per_section;
            let last_element_offset = (17 % items_per_section.get()) as u32;
            let item = journal
                .get(last_element_section, last_element_offset)
                .await
                .unwrap();
            assert_eq!(item, Some(3002)); // Last item in section 3 (3*1000+2)

            // Verify that section 3 was properly truncated
            let section_3_size = journal.size(3).await.unwrap();
            assert_eq!(section_3_size, 3 * ITEM_ALIGNMENT);

            // Verify that items beyond upper_bound (17) are not accessible
            // Reading beyond the truncated section should return an error
            let result = journal.get(3, 3).await;
            assert!(result.is_err()); // item 18 should be inaccessible (beyond upper_bound=17)

            // Assert journal can accept new items
            let (offset, _) = journal.append(3, 999).await.unwrap();
            assert_eq!(journal.get(3, offset).await.unwrap(), Some(999));

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when all existing data is stale (before lower bound).
    #[test_traced]
    fn test_init_sync_existing_data_stale() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_stale".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Create initial journal with stale data
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data to sections 0, 1 (items 0-9 with items_per_section=5)
            let items_per_section = NZU64!(5);
            for section in 0..2 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 100 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries beyond all existing data
            let lower_bound = 15; // section 3
            let upper_bound = 25; // section 5
            let journal = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with stale data");

            // Verify fresh journal (all old data destroyed)
            assert!(journal.blobs.is_empty());
            assert_eq!(journal.oldest_allowed, None);

            // Verify old sections don't exist
            assert!(!journal.blobs.contains_key(&0));
            assert!(!journal.blobs.contains_key(&1));

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` with invalid parameters.
    #[test_traced]
    fn test_init_sync_invalid_parameters() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_invalid".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Test invalid bounds: lower > upper
            let result = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                10,        // lower_bound
                5,         // upper_bound (invalid: < lower_bound)
                NZU64!(5), // items_per_section
            )
            .await;
            assert!(matches!(result, Err(super::Error::InvalidSyncRange(10, 5))));
        });
    }

    /// Test `init_sync` with section boundary edge cases.
    #[test_traced]
    fn test_init_sync_section_boundaries() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_boundaries".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Create journal with data at section boundaries
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            let items_per_section = NZU64!(5);

            // Add data to sections 0, 1, 2, 3, 4
            for section in 0..5 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 100 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Test sync boundaries exactly at section boundaries
            let lower_bound = 10; // Exactly at section boundary (10/5 = 2)
            let upper_bound = 19; // Exactly at section boundary (19/5 = 3)
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal at boundaries");

            // Verify correct section range
            let lower_section = lower_bound / items_per_section; // 2
            assert_eq!(journal.oldest_allowed, Some(lower_section));

            // Verify sections 2, 3, 4 exist, others don't
            assert!(!journal.blobs.contains_key(&0));
            assert!(!journal.blobs.contains_key(&1));
            assert!(journal.blobs.contains_key(&2));
            assert!(journal.blobs.contains_key(&3));
            assert!(!journal.blobs.contains_key(&4)); // Section 4 should not exist

            // Verify data integrity in retained sections
            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, Some(200)); // First item in section 2
            let item = journal.get(3, 4).await.unwrap();
            assert_eq!(item, Some(304)); // Last element
            let next_element_section = 4;
            let item = journal.get(next_element_section, 0).await.unwrap();
            assert_eq!(item, None); // Next element should not exist

            // Assert journal can accept new items
            let (offset, _) = journal.append(next_element_section, 999).await.unwrap();
            assert_eq!(
                journal.get(next_element_section, offset).await.unwrap(),
                Some(999)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when lower_bound and upper_bound are in the same section.
    #[test_traced]
    fn test_init_sync_same_section_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_same_section".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Create journal with data in multiple sections
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            let items_per_section = NZU64!(5);

            // Add data to sections 0, 1, 2
            for section in 0..3 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 100 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Test sync boundaries within the same section
            let lower_bound = 6; // item 6 (section 1: 6/5 = 1)
            let upper_bound = 8; // item 8 (section 1: 8/5 = 1)
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with same-section bounds");

            // Both items are in section 1, so section 0 should be pruned, section 1+ retained
            let target_section = lower_bound / items_per_section; // 6/5 = 1
            assert_eq!(journal.oldest_allowed, Some(target_section));

            // Verify pruning and retention
            assert!(!journal.blobs.contains_key(&0)); // Section 0 should be pruned
            assert!(journal.blobs.contains_key(&1)); // Section 1 should be retained
            assert!(!journal.blobs.contains_key(&2)); // Section 2 should be removed (> upper_section)

            // Verify data integrity
            let item = journal.get(1, 0).await.unwrap();
            assert_eq!(item, Some(100)); // First item in section 1
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, Some(101)); // Second item in section 1 (1*100+1)
            let item = journal.get(1, 3).await.unwrap();
            assert_eq!(item, Some(103)); // Item at offset 3 in section 1 (1*100+3)

            // Verify that section 1 was properly truncated
            let section_1_size = journal.size(1).await.unwrap();
            assert_eq!(section_1_size, 64); // Should be 4 items * 16 bytes = 64 bytes

            // Verify that item beyond upper_bound (8) is not accessible
            let result = journal.get(1, 4).await;
            assert!(result.is_err()); // item 9 should be inaccessible (beyond upper_bound=8)

            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, None); // Section 2 was removed, so no items

            // Assert journal can accept new items
            let (offset, _) = journal.append(target_section, 999).await.unwrap();
            assert_eq!(
                journal.get(target_section, offset).await.unwrap(),
                Some(999)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `compute_offset` correctly calculates byte boundaries for variable-sized items.
    #[test_traced]
    fn test_compute_offset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_compute_offset".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Create a journal and populate a section with 5 items
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create journal");

            let section = 0;
            for i in 0..5 {
                journal.append(section, i as u64).await.unwrap();
            }
            journal.sync(section).await.unwrap();

            let blob = journal.blobs.get(&section).unwrap();

            // Helper function to compute byte size for N items
            let compute_offset = |items_count: u32| async move {
                Journal::<deterministic::Context, u64>::compute_offset(
                    blob,
                    &journal.cfg.codec_config,
                    journal.cfg.compression.is_some(),
                    items_count,
                )
                .await
                .unwrap()
            };

            // Test various item counts (each u64 item takes 16 bytes when aligned)
            assert_eq!(compute_offset(0).await, 0);
            assert_eq!(compute_offset(1).await, 16);
            assert_eq!(compute_offset(3).await, 48);
            assert_eq!(compute_offset(5).await, 80);

            // Test requesting more items than available (should return size of all available)
            assert_eq!(compute_offset(6).await, 80);
            assert_eq!(compute_offset(10).await, 80); // Still 80 bytes (capped at available)

            journal.destroy().await.unwrap();
        });
    }

    /// Test `truncate_upper_section` correctly removes items beyond sync boundaries.
    #[test_traced]
    fn test_truncate_section_to_upper_bound() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_truncate_section".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let items_per_section = 5;

            // Helper to create a fresh journal with test data
            let create_journal = || async {
                let mut journal =
                    Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                        .await
                        .expect("Failed to create journal");

                // Add items to sections 0, 1, 2
                for section in 0..3 {
                    for i in 0..items_per_section {
                        journal.append(section, section * 100 + i).await.unwrap();
                    }
                    journal.sync(section).await.unwrap();
                }
                journal
            };

            // Test 1: No truncation needed (upper_bound at section end)
            {
                let mut journal = create_journal().await;
                let upper_bound = 9; // End of section 1 (section 1: items 5-9)
                Journal::<deterministic::Context, u64>::truncate_upper_section(
                    &mut journal,
                    upper_bound,
                    items_per_section,
                )
                .await
                .unwrap();

                // Section 1 should remain unchanged (5 items = 80 bytes)
                let section_1_size = journal.size(1).await.unwrap();
                assert_eq!(section_1_size, 80);
                journal.destroy().await.unwrap();
            }

            // Test 2: Truncation needed (upper_bound mid-section)
            {
                let mut journal = create_journal().await;
                let upper_bound = 7; // Middle of section 1 (keep items 5, 6, 7)
                Journal::<deterministic::Context, u64>::truncate_upper_section(
                    &mut journal,
                    upper_bound,
                    items_per_section,
                )
                .await
                .unwrap();

                // Section 1 should now have only 3 items (48 bytes)
                let section_1_size = journal.size(1).await.unwrap();
                assert_eq!(section_1_size, 48);

                // Verify the remaining items are accessible
                assert_eq!(journal.get(1, 0).await.unwrap(), Some(100)); // section 1, offset 0 = 1*100+0
                assert_eq!(journal.get(1, 1).await.unwrap(), Some(101)); // section 1, offset 1 = 1*100+1
                assert_eq!(journal.get(1, 2).await.unwrap(), Some(102)); // section 1, offset 2 = 1*100+2

                // Verify truncated items are not accessible
                let result = journal.get(1, 3).await;
                assert!(result.is_err()); // item at logical loc 8 should be gone
                journal.destroy().await.unwrap();
            }

            // Test 3: Non-existent section (should not error)
            {
                let mut journal = create_journal().await;
                Journal::<deterministic::Context, u64>::truncate_upper_section(
                    &mut journal,
                    99, // upper_bound that would be in a non-existent section
                    items_per_section,
                )
                .await
                .unwrap(); // Should not error
                journal.destroy().await.unwrap();
            }

            // Test 4: Upper bound beyond section (no truncation)
            {
                let mut journal = create_journal().await;
                let upper_bound = 15; // Beyond section 2
                let original_section_2_size = journal.size(2).await.unwrap();
                Journal::<deterministic::Context, u64>::truncate_upper_section(
                    &mut journal,
                    upper_bound,
                    items_per_section,
                )
                .await
                .unwrap();

                // Section 2 should remain unchanged
                let section_2_size = journal.size(2).await.unwrap();
                assert_eq!(section_2_size, original_section_2_size);
                journal.destroy().await.unwrap();
            }
        });
    }

    /// Test intra-section truncation.
    #[test_traced]
    fn test_truncate_section_mid_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_truncation_integration".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let items_per_section = 3;

            // Create journal with data across multiple sections
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create journal");

            // Section 0: items 0, 1, 2
            // Section 1: items 3, 4, 5
            // Section 2: items 6, 7, 8
            for section in 0..3 {
                for i in 0..items_per_section {
                    let op_value = section * items_per_section + i;
                    journal.append(section, op_value).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Test sync with upper_bound in middle of section 1 (upper_bound = 4)
            // Should keep: items 2, 3, 4 (sections 0 partially removed, 1 truncated, 2 removed)
            let lower_bound = 2;
            let upper_bound = 4;
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                NZU64!(items_per_section),
            )
            .await
            .expect("Failed to initialize synced journal");

            // Verify section 0 is partially present (only item 2)
            assert!(journal.blobs.contains_key(&0));
            assert_eq!(journal.get(0, 2).await.unwrap(), Some(2));

            // Verify section 1 is truncated (items 3, 4 only)
            assert!(journal.blobs.contains_key(&1));
            assert_eq!(journal.get(1, 0).await.unwrap(), Some(3));
            assert_eq!(journal.get(1, 1).await.unwrap(), Some(4));

            // item 5 should be inaccessible (truncated)
            let result = journal.get(1, 2).await;
            assert!(result.is_err());

            // Verify section 2 is completely removed
            assert!(!journal.blobs.contains_key(&2));

            // Test that new appends work correctly after truncation
            let (offset, _) = journal.append(1, 999).await.unwrap();
            assert_eq!(journal.get(1, offset).await.unwrap(), Some(999));

            journal.destroy().await.unwrap();
        });
    }
}
