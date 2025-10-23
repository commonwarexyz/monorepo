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
    num::NonZeroUsize,
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

pub(crate) const ITEM_ALIGNMENT: u64 = 16;

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
    pub(crate) context: E,
    pub(crate) cfg: Config<V::Cfg>,

    pub(crate) blobs: BTreeMap<u64, Append<E::Blob>>,

    /// A section number before which all sections have been pruned. This value is not persisted,
    /// and is initialized to 0 at startup. It's updated only during calls to `prune` during the
    /// current execution, and therefore provides only a best effort lower-bound on the true value.
    pub(crate) oldest_retained_section: u64,

    pub(crate) tracked: Gauge,
    pub(crate) synced: Counter,
    pub(crate) pruned: Counter,

    pub(crate) _phantom: PhantomData<V>,
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
            blobs,
            oldest_retained_section: 0,
            tracked,
            synced,
            pruned,

            _phantom: PhantomData,
        })
    }

    /// Ensures that a section pruned during the current execution is not accessed.
    fn prune_guard(&self, section: u64) -> Result<(), Error> {
        if section < self.oldest_retained_section {
            Err(Error::AlreadyPrunedToSection(self.oldest_retained_section))
        } else {
            Ok(())
        }
    }

    /// Reads an item from the blob at the given offset.
    pub(crate) async fn read(
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

    /// Returns an ordered stream of all items in the journal starting with the item at the given
    /// `start_section` and `offset` into that section. Each item is returned as a tuple of
    /// (section, offset, size, item).
    ///
    /// # Repair
    ///
    /// Like
    /// [sqlite](https://github.com/sqlite/sqlite/blob/8658a8df59f00ec8fcfea336a2a6a4b5ef79d2ee/src/wal.c#L1504-L1505)
    /// and
    /// [rocksdb](https://github.com/facebook/rocksdb/blob/0c533e61bc6d89fdf1295e8e0bcee4edb3aef401/include/rocksdb/options.h#L441-L445),
    /// the first invalid data read will be considered the new end of the journal (and the
    /// underlying [Blob] will be truncated to the last valid item).
    pub async fn replay(
        &self,
        start_section: u64,
        mut offset: u32,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, u32, u32, V), Error>> + '_, Error> {
        // Collect all blobs to replay
        let codec_config = self.cfg.codec_config.clone();
        let compressed = self.cfg.compression.is_some();
        let mut blobs = Vec::with_capacity(self.blobs.len());
        for (section, blob) in self.blobs.range(start_section..) {
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
        Ok(stream::iter(blobs).flat_map(
            move |(section, blob, max_offset, blob_size, codec_config, compressed)| {
                // Created buffered reader
                let mut reader = Read::new(blob, blob_size, buffer);
                if section == start_section && offset != 0 {
                    if let Err(err) = reader.seek_to(offset as u64 * ITEM_ALIGNMENT) {
                        warn!(section, offset, ?err, "failed to seek to offset");
                        // Return early with the error to terminate the entire stream
                        return stream::once(async move { Err(err.into()) }).left_stream();
                    }
                } else {
                    offset = 0;
                }

                // Read over the blob
                stream::unfold(
                        (section, reader, offset, 0u64, codec_config, compressed),
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
                                        bad_offset = offset,
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
                                        bad_offset = offset,
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
                    ).right_stream()
            },
        ))
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
        self.prune_guard(section)?;

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
    ///
    /// # Errors
    ///  - [Error::AlreadyPrunedToSection] if the requested `section` has been pruned during the
    ///    current execution.
    ///  - [Error::SectionOutOfRange] if the requested `section` is empty (i.e. has never had any
    ///    data appended to it, or has been pruned in a previous execution).
    ///  - An invalid `offset` for a given section (that is, an offset that doesn't correspond to a
    ///    previously appended item) will result in an error, with the specific type being
    ///    undefined.
    pub async fn get(&self, section: u64, offset: u32) -> Result<V, Error> {
        self.prune_guard(section)?;
        let blob = match self.blobs.get(&section) {
            Some(blob) => blob,
            None => return Err(Error::SectionOutOfRange(section)),
        };

        // Perform a multi-op read.
        let (_, _, item) = Self::read(
            self.cfg.compression.is_some(),
            &self.cfg.codec_config,
            blob,
            offset,
        )
        .await?;
        Ok(item)
    }

    /// Retrieves an item from `Journal` at a given `section` and `offset` with a given size.
    pub async fn get_exact(&self, section: u64, offset: u32, size: u32) -> Result<V, Error> {
        self.prune_guard(section)?;
        let blob = match self.blobs.get(&section) {
            Some(blob) => blob,
            None => return Err(Error::SectionOutOfRange(section)),
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
        Ok(item)
    }

    /// Gets the size of the journal for a specific section.
    ///
    /// Returns 0 if the section does not exist.
    pub async fn size(&self, section: u64) -> Result<u64, Error> {
        self.prune_guard(section)?;
        match self.blobs.get(&section) {
            Some(blob) => Ok(blob.size().await),
            None => Ok(0),
        }
    }

    /// Rewinds the journal to the given `section` and `offset`, removing any data beyond it.
    ///
    /// # Warnings
    ///
    /// * This operation is not guaranteed to survive restarts until sync is called.
    /// * This operation is not atomic, but it will always leave the journal in a consistent state
    ///   in the event of failure since blobs are always removed in reverse order of section.
    pub async fn rewind_to_offset(&mut self, section: u64, offset: u32) -> Result<(), Error> {
        self.rewind(section, offset as u64 * ITEM_ALIGNMENT).await
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
    pub async fn rewind(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

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
    ///
    /// # Warning
    ///
    /// This operation is not guaranteed to survive restarts until sync is called.
    pub async fn rewind_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

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
        self.prune_guard(section)?;
        let blob = match self.blobs.get(&section) {
            Some(blob) => blob,
            None => return Ok(()),
        };
        self.synced.inc();
        blob.sync().await.map_err(Error::Runtime)
    }

    /// Prunes all `sections` less than `min`. Returns true if any sections were pruned.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        // Prune any blobs that are smaller than the minimum
        let mut pruned = false;
        while let Some((&section, _)) = self.blobs.first_key_value() {
            // Stop pruning if we reach the minimum
            if section >= min {
                break;
            }

            // Remove blob from journal
            let blob = self.blobs.remove(&section).unwrap();
            let size = blob.size().await;
            drop(blob);

            // Remove blob from storage
            self.context
                .remove(&self.cfg.partition, Some(&section.to_be_bytes()))
                .await?;
            pruned = true;

            debug!(blob = section, size, "pruned blob");
            self.tracked.dec();
            self.pruned.inc();
        }

        if pruned {
            self.oldest_retained_section = min;
        }

        Ok(pruned)
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

    /// Returns the number of the oldest section in the journal.
    pub fn oldest_section(&self) -> Option<u64> {
        self.blobs.first_key_value().map(|(section, _)| *section)
    }

    /// Removes any underlying blobs created by the journal.
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
    use commonware_cryptography::{Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob, Error as RError, Runner, Storage};
    use commonware_utils::{NZUsize, StableBuf};
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
                .replay(0, 0, NZUsize!(1024))
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
                    .replay(0, 0, NZUsize!(1024))
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
                    .replay(0, 0, NZUsize!(1024))
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
    fn test_journal_prune_guard() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append items to sections 1-5
            for section in 1u64..=5u64 {
                journal
                    .append(section, section as i32)
                    .await
                    .expect("Failed to append data");
                journal.sync(section).await.expect("Failed to sync");
            }

            // Verify initial oldest_retained_section is 0
            assert_eq!(journal.oldest_retained_section, 0);

            // Prune sections < 3
            journal.prune(3).await.expect("Failed to prune");

            // Verify oldest_retained_section is updated
            assert_eq!(journal.oldest_retained_section, 3);

            // Test that accessing pruned sections returns the correct error

            // Test append on pruned section
            match journal.append(1, 100).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {:?}", other),
            }

            match journal.append(2, 100).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {:?}", other),
            }

            // Test get on pruned section
            match journal.get(1, 0).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {:?}", other),
            }

            // Test get_exact on pruned section
            match journal.get_exact(2, 0, 12).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {:?}", other),
            }

            // Test size on pruned section
            match journal.size(1).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {:?}", other),
            }

            // Test rewind on pruned section
            match journal.rewind(2, 0).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {:?}", other),
            }

            // Test rewind_section on pruned section
            match journal.rewind_section(1, 0).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {:?}", other),
            }

            // Test sync on pruned section
            match journal.sync(2).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {:?}", other),
            }

            // Test that accessing sections at or after the threshold works
            assert!(journal.get(3, 0).await.is_ok());
            assert!(journal.get(4, 0).await.is_ok());
            assert!(journal.get(5, 0).await.is_ok());
            assert!(journal.size(3).await.is_ok());
            assert!(journal.sync(4).await.is_ok());

            // Append to section at threshold should work
            journal
                .append(3, 999)
                .await
                .expect("Should be able to append to section 3");

            // Prune more sections
            journal.prune(5).await.expect("Failed to prune");
            assert_eq!(journal.oldest_retained_section, 5);

            // Verify sections 3 and 4 are now pruned
            match journal.get(3, 0).await {
                Err(Error::AlreadyPrunedToSection(5)) => {}
                other => panic!("Expected AlreadyPrunedToSection(5), got {:?}", other),
            }

            match journal.get(4, 0).await {
                Err(Error::AlreadyPrunedToSection(5)) => {}
                other => panic!("Expected AlreadyPrunedToSection(5), got {:?}", other),
            }

            // Section 5 should still be accessible
            assert!(journal.get(5, 0).await.is_ok());

            journal.close().await.expect("Failed to close journal");
        });
    }

    #[test_traced]
    fn test_journal_prune_guard_across_restart() {
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // First session: create and prune
            {
                let mut journal = Journal::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to initialize journal");

                for section in 1u64..=5u64 {
                    journal
                        .append(section, section as i32)
                        .await
                        .expect("Failed to append data");
                    journal.sync(section).await.expect("Failed to sync");
                }

                journal.prune(3).await.expect("Failed to prune");
                assert_eq!(journal.oldest_retained_section, 3);

                journal.close().await.expect("Failed to close journal");
            }

            // Second session: verify oldest_retained_section is reset
            {
                let journal = Journal::<_, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to re-initialize journal");

                // After restart, oldest_retained_section should be back to 0
                // since it's not persisted
                assert_eq!(journal.oldest_retained_section, 0);

                // But the actual sections 1 and 2 should be gone from storage
                // so get should return SectionOutOfRange, not AlreadyPrunedToSection
                match journal.get(1, 0).await {
                    Err(Error::SectionOutOfRange(1)) => {}
                    other => panic!("Expected SectionOutOfRange(1), got {:?}", other),
                }

                match journal.get(2, 0).await {
                    Err(Error::SectionOutOfRange(2)) => {}
                    other => panic!("Expected SectionOutOfRange(2), got {:?}", other),
                }

                // Sections 3-5 should still be accessible
                assert!(journal.get(3, 0).await.is_ok());
                assert!(journal.get(4, 0).await.is_ok());
                assert!(journal.get(5, 0).await.is_ok());

                journal.close().await.expect("Failed to close journal");
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
            let incomplete_data = hex!("0x0001").to_vec(); // Less than 4 bytes
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
                .replay(0, 0, NZUsize!(1024))
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
                .replay(0, 0, NZUsize!(1024))
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
                .replay(0, 0, NZUsize!(1024))
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
                    .replay(0, 0, NZUsize!(1024))
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
                    .replay(0, 0, NZUsize!(1024))
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
                    .replay(0, 0, NZUsize!(1024))
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
            let item = journal.get(2, 2).await.expect("Failed to get item");
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
                    .replay(0, 0, NZUsize!(1024))
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
                    .replay(0, 0, NZUsize!(1024))
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
            let item = journal.get(2, 2).await.expect("Failed to get item");
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
                    .replay(0, 0, NZUsize!(1024))
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
                .replay(0, 0, NZUsize!(1024))
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
            let digest = Sha256::hash(buf.as_ref());
            assert_eq!(
                hex(&digest),
                "ca3845fa7fabd4d2855ab72ed21226d1d6eb30cb895ea9ec5e5a14201f3f25d8",
            );
        });
    }
}
