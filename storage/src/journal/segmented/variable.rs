//! An append-only log for storing arbitrary variable length items.
//!
//! `segmented::Journal` is an append-only log for storing arbitrary variable length data on disk. In
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
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! |       0 ~ 4       |    ...    | 8 | 9 |10 |11 |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! | Size (varint u32) |   Data    |    C(u32)     |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//!
//! Size = u32 as varint (1 to 5 bytes)
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
//! use commonware_storage::journal::segmented::variable::{Journal, Config};
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
//!     // Sync the journal
//!     journal.sync_all().await.unwrap();
//! });
//! ```

use super::manager::{AppendFactory, Config as ManagerConfig, Manager};
use crate::journal::Error;
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Codec, EncodeSize, FixedSize, ReadExt, Write as CodecWrite};
use commonware_runtime::{
    buffer::{Append, PoolRef, Read},
    Blob, Error as RError, Metrics, Storage,
};
use futures::stream::{self, Stream, StreamExt};
use std::{io::Cursor, num::NonZeroUsize};
use tracing::{trace, warn};
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

/// Minimum size of any item: 1 byte varint (size=0) + 0 bytes data + 4 bytes checksum.
/// This is also the max varint size for u32, so we can always read this many bytes
/// at the start of an item to get the complete varint.
const MIN_ITEM_SIZE: usize = 5;

/// Implementation of `Journal` storage.
pub struct Journal<E: Storage + Metrics, V: Codec> {
    manager: Manager<E, AppendFactory>,

    /// Compression level (if enabled).
    compression: Option<u8>,

    /// Codec configuration.
    codec_config: V::Cfg,
}

impl<E: Storage + Metrics, V: Codec> Journal<E, V> {
    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during
    /// initialization. The `replay` method can be used
    /// to iterate over all items in the `Journal`.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let manager_cfg = ManagerConfig {
            partition: cfg.partition,
            factory: AppendFactory {
                write_buffer: cfg.write_buffer,
                pool_ref: cfg.buffer_pool,
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
        blob: &Append<E::Blob>,
        offset: u64,
    ) -> Result<(u64, u32, V), Error> {
        // Read varint size (max 5 bytes for u32)
        let mut hasher = crc32fast::Hasher::new();
        let varint_buf = blob.read_at(vec![0; MIN_ITEM_SIZE], offset).await?;
        let mut varint = varint_buf.as_ref();
        let size = UInt::<u32>::read(&mut varint).map_err(Error::Codec)?.0 as usize;
        let varint_len = MIN_ITEM_SIZE - varint.remaining();
        hasher.update(&varint_buf.as_ref()[..varint_len]);
        let offset = offset
            .checked_add(varint_len as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Read remaining
        let buf_size = size.checked_add(u32::SIZE).ok_or(Error::OffsetOverflow)?;
        let buf = blob.read_at(vec![0u8; buf_size], offset).await?;
        let buf = buf.as_ref();
        let next_offset = offset
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

        // If compression is enabled, decompress the item
        let item = if compressed {
            let decompressed =
                decode_all(Cursor::new(&item)).map_err(|_| Error::DecompressionFailed)?;
            V::decode_cfg(decompressed.as_ref(), cfg).map_err(Error::Codec)?
        } else {
            V::decode_cfg(item, cfg).map_err(Error::Codec)?
        };

        // Return item
        Ok((next_offset, size as u32, item))
    }

    /// Helper function to read an item from a [Read].
    async fn read_buffered(
        reader: &mut Read<Append<E::Blob>>,
        offset: u64,
        cfg: &V::Cfg,
        compressed: bool,
    ) -> Result<(u64, u64, u32, V), Error> {
        // If we're not at the right position, seek to it
        if reader.position() != offset {
            reader.seek_to(offset).map_err(Error::Runtime)?;
        }

        // Read varint size (max 5 bytes for u32, and min item size is 5 bytes)
        let mut hasher = crc32fast::Hasher::new();
        let mut varint_buf = [0u8; MIN_ITEM_SIZE];
        reader
            .read_exact(&mut varint_buf, MIN_ITEM_SIZE)
            .await
            .map_err(Error::Runtime)?;
        let mut varint = varint_buf.as_ref();
        let size = UInt::<u32>::read(&mut varint).map_err(Error::Codec)?.0 as usize;
        let varint_len = MIN_ITEM_SIZE - varint.remaining();
        hasher.update(&varint_buf[..varint_len]);

        // Read remaining data+checksum (we already have some bytes from the varint read)
        let buf_size = size.checked_add(u32::SIZE).ok_or(Error::OffsetOverflow)?;
        let already_read = MIN_ITEM_SIZE - varint_len;
        let mut buf = vec![0u8; buf_size];
        buf[..already_read].copy_from_slice(&varint_buf[varint_len..]);
        if buf_size > already_read {
            reader
                .read_exact(&mut buf[already_read..], buf_size - already_read)
                .await
                .map_err(Error::Runtime)?;
        }

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
        let next_offset = reader.position();
        Ok((next_offset, next_offset, size as u32, item))
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
        mut offset: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, u64, u32, V), Error>> + '_, Error> {
        // Collect all blobs to replay
        let codec_config = self.codec_config.clone();
        let compressed = self.compression.is_some();
        let mut blobs = Vec::new();
        for (&section, blob) in self.manager.sections_from(start_section) {
            let blob_size = blob.size().await;
            blobs.push((
                section,
                blob.clone(),
                blob_size,
                codec_config.clone(),
                compressed,
            ));
        }

        // Replay all blobs in order and stream items as they are read (to avoid occupying too much
        // memory with buffered data)
        Ok(stream::iter(blobs).flat_map(
            move |(section, blob, blob_size, codec_config, compressed)| {
                // Created buffered reader
                let mut reader = Read::new(blob, blob_size, buffer);
                if section == start_section && offset != 0 {
                    if let Err(err) = reader.seek_to(offset) {
                        warn!(section, offset, ?err, "failed to seek to offset");
                        // Return early with the error to terminate the entire stream
                        return stream::once(async move { Err(err.into()) }).left_stream();
                    }
                } else {
                    offset = 0;
                }

                // Read over the blob
                stream::unfold(
                    (
                        section,
                        reader,
                        offset,
                        0u64,
                        blob_size,
                        codec_config,
                        compressed,
                    ),
                    move |(
                        section,
                        mut reader,
                        offset,
                        valid_size,
                        blob_size,
                        codec_config,
                        compressed,
                    )| async move {
                        // Check if we are at the end of the blob
                        if offset >= blob_size {
                            return None;
                        }

                        // Read an item from the buffer
                        match Self::read_buffered(&mut reader, offset, &codec_config, compressed)
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
                                        blob_size,
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
                                warn!(blob = section, cursor = offset, ?err, "unexpected error");
                                Some((
                                    Err(err),
                                    (
                                        section,
                                        reader,
                                        offset,
                                        valid_size,
                                        blob_size,
                                        codec_config,
                                        compressed,
                                    ),
                                ))
                            }
                        }
                    },
                )
                .right_stream()
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
    pub async fn append(&mut self, section: u64, item: V) -> Result<(u64, u32), Error> {
        // Create buffer with item data
        let (buf, item_len) = if let Some(compression) = self.compression {
            // Compressed: encode first, then compress
            let encoded = item.encode();
            let compressed =
                compress(&encoded, compression as i32).map_err(|_| Error::CompressionFailed)?;
            let item_len = compressed.len();
            let item_len_u32: u32 = match item_len.try_into() {
                Ok(len) => len,
                Err(_) => return Err(Error::ItemTooLarge(item_len)),
            };
            let size_len = UInt(item_len_u32).encode_size();
            let entry_len = size_len
                .checked_add(item_len)
                .and_then(|v| v.checked_add(4))
                .ok_or(Error::OffsetOverflow)?;

            let mut buf = Vec::with_capacity(entry_len);
            UInt(item_len_u32).write(&mut buf);
            buf.put_slice(&compressed);
            let checksum = crc32fast::hash(&buf);
            buf.put_u32(checksum);

            (buf, item_len)
        } else {
            // Uncompressed: pre-allocate exact size to avoid copying
            let item_len = item.encode_size();
            let item_len_u32: u32 = match item_len.try_into() {
                Ok(len) => len,
                Err(_) => return Err(Error::ItemTooLarge(item_len)),
            };
            let size_len = UInt(item_len_u32).encode_size();
            let entry_len = size_len
                .checked_add(item_len)
                .and_then(|v| v.checked_add(4))
                .ok_or(Error::OffsetOverflow)?;

            let mut buf = Vec::with_capacity(entry_len);
            UInt(item_len_u32).write(&mut buf);
            item.write(&mut buf);
            let checksum = crc32fast::hash(&buf);
            buf.put_u32(checksum);

            (buf, item_len)
        };

        // Get or create blob
        let blob = self.manager.get_or_create(section).await?;

        // Get current position - this is where we'll write
        let offset = blob.size().await;

        // Append item to blob
        blob.append(buf).await?;
        trace!(blob = section, offset, "appended item");
        Ok((offset, item_len as u32))
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
        let blob = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        // Perform a multi-op read.
        let (_, _, item) =
            Self::read(self.compression.is_some(), &self.codec_config, blob, offset).await?;
        Ok(item)
    }

    /// Gets the size of the journal for a specific section.
    ///
    /// Returns 0 if the section does not exist.
    pub async fn size(&self, section: u64) -> Result<u64, Error> {
        self.manager.size(section).await
    }

    /// Rewinds the journal to the given `section` and `offset`, removing any data beyond it.
    ///
    /// # Warnings
    ///
    /// * This operation is not guaranteed to survive restarts until sync is called.
    /// * This operation is not atomic, but it will always leave the journal in a consistent state
    ///   in the event of failure since blobs are always removed in reverse order of section.
    pub async fn rewind_to_offset(&mut self, section: u64, offset: u64) -> Result<(), Error> {
        self.manager.rewind(section, offset).await
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
        self.manager.rewind(section, size).await
    }

    /// Rewinds the `section` to the given `size`.
    ///
    /// Unlike [Self::rewind], this method does not modify anything other than the given `section`.
    ///
    /// # Warning
    ///
    /// This operation is not guaranteed to survive restarts until sync is called.
    pub async fn rewind_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.manager.rewind_section(section, size).await
    }

    /// Ensures that all data in a given `section` is synced to the underlying store.
    ///
    /// If the `section` does not exist, no error will be returned.
    pub async fn sync(&self, section: u64) -> Result<(), Error> {
        self.manager.sync(section).await
    }

    /// Syncs all open sections.
    pub async fn sync_all(&self) -> Result<(), Error> {
        self.manager.sync_all().await
    }

    /// Prunes all `sections` less than `min`. Returns true if any sections were pruned.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        self.manager.prune(min).await
    }

    /// Returns the number of the oldest section in the journal.
    pub fn oldest_section(&self) -> Option<u64> {
        self.manager.oldest_section()
    }

    /// Returns the number of the newest section in the journal.
    pub fn newest_section(&self) -> Option<u64> {
        self.manager.newest_section()
    }

    /// Returns true if no sections exist.
    pub fn is_empty(&self) -> bool {
        self.manager.is_empty()
    }

    /// Returns the number of sections.
    pub fn num_sections(&self) -> usize {
        self.manager.num_sections()
    }

    /// Removes any underlying blobs created by the journal.
    pub async fn destroy(self) -> Result<(), Error> {
        self.manager.destroy().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::NZUsize;
    use futures::{pin_mut, StreamExt};

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

            // Drop and re-open the journal to simulate a restart
            journal.sync(index).await.expect("Failed to sync journal");
            drop(journal);
            let journal = Journal::<_, i32>::init(context.clone(), cfg)
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

            // Drop and re-open the journal to simulate a restart
            drop(journal);
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

            // Drop and re-open the journal to simulate a restart
            drop(journal);
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

            // Drop the journal
            drop(journal);

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

            // Prune sections < 3
            journal.prune(3).await.expect("Failed to prune");

            // Test that accessing pruned sections returns the correct error

            // Test append on pruned section
            match journal.append(1, 100).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
            }

            match journal.append(2, 100).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
            }

            // Test get on pruned section
            match journal.get(1, 0).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
            }

            // Test size on pruned section
            match journal.size(1).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
            }

            // Test rewind on pruned section
            match journal.rewind(2, 0).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
            }

            // Test rewind_section on pruned section
            match journal.rewind_section(1, 0).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
            }

            // Test sync on pruned section
            match journal.sync(2).await {
                Err(Error::AlreadyPrunedToSection(3)) => {}
                other => panic!("Expected AlreadyPrunedToSection(3), got {other:?}"),
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

            // Verify sections 3 and 4 are now pruned
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
            }

            // Second session: verify oldest_retained_section is reset
            {
                let journal = Journal::<_, i32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to re-initialize journal");

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

            // Write incomplete varint by encoding u32::MAX (5 bytes) and truncating to 1 byte
            let mut incomplete_data = Vec::new();
            UInt(u32::MAX).write(&mut incomplete_data);
            incomplete_data.truncate(1);
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

            // Write size but incomplete item data
            let item_size: u32 = 10; // Size indicates 10 bytes of data
            let mut buf = Vec::new();
            UInt(item_size).write(&mut buf); // Varint encoding
            let data = [2u8; 5]; // Only 5 bytes, not 10 + 4 (checksum)
            BufMut::put_slice(&mut buf, &data);
            blob.write_at(buf, 0)
                .await
                .expect("Failed to write incomplete item");
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

            // Write size (varint) and data, but no checksum
            let mut buf = Vec::new();
            UInt(item_size).write(&mut buf);
            BufMut::put_slice(&mut buf, item_data);
            blob.write_at(buf, 0)
                .await
                .expect("Failed to write item without checksum");

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

            // Write size (varint), data, and incorrect checksum
            let mut buf = Vec::new();
            UInt(item_size).write(&mut buf);
            BufMut::put_slice(&mut buf, item_data);
            buf.put_u32(incorrect_checksum);
            blob.write_at(buf, 0)
                .await
                .expect("Failed to write item with bad checksum");

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

            // Append multiple items to the second section
            let data_items = vec![(2u64, 2), (2u64, 3), (2u64, 4)];
            for (index, data) in &data_items {
                journal
                    .append(*index, *data)
                    .await
                    .expect("Failed to append data");
                journal.sync(*index).await.expect("Failed to sync blob");
            }

            // Sync all sections and drop the journal
            journal.sync_all().await.expect("Failed to sync");
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
            drop(journal);

            // Verify that only non-corrupted items were replayed
            assert_eq!(items.len(), 3);
            assert_eq!(items[0].0, 1);
            assert_eq!(items[0].1, 1);
            assert_eq!(items[1].0, data_items[0].0);
            assert_eq!(items[1].1, data_items[0].1);
            assert_eq!(items[2].0, data_items[1].0);
            assert_eq!(items[2].1, data_items[1].1);

            // Confirm blob is expected length
            // entry = 1 (varint for 4) + 4 (data) + 4 (checksum) = 9 bytes
            // Item 2 ends at position 9 + 9 = 18
            let (_, blob_size) = context
                .open(&cfg.partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(blob_size, 18);

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
            let (offset, _) = journal.append(2, 5).await.expect("Failed to append data");
            journal.sync(2).await.expect("Failed to sync blob");

            // Get the new item
            let item = journal.get(2, offset).await.expect("Failed to get item");
            assert_eq!(item, 5);

            // Drop the journal (data already synced)
            drop(journal);

            // Confirm blob is expected length
            // Items 1 and 2 at positions 0 and 9, item 3 (value 5) at position 18
            // Item 3 = 1 (varint) + 4 (data) + 4 (checksum) = 9 bytes, ends at 27
            let (_, blob_size) = context
                .open(&cfg.partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            assert_eq!(blob_size, 27);

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

            // Sync all sections and drop the journal
            journal.sync_all().await.expect("Failed to sync");
            drop(journal);

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

    #[test_traced]
    fn test_journal_rewind_many_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".to_string(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.clone(), cfg.clone()).await.unwrap();

            // Create sections 1-10 with data
            for section in 1u64..=10 {
                journal.append(section, section as i32).await.unwrap();
            }
            journal.sync_all().await.unwrap();

            // Verify all sections exist
            for section in 1u64..=10 {
                let size = journal.size(section).await.unwrap();
                assert!(size > 0, "section {section} should have data");
            }

            // Rewind to section 5 (should remove sections 6-10)
            journal
                .rewind(5, journal.size(5).await.unwrap())
                .await
                .unwrap();

            // Verify sections 1-5 still exist with correct data
            for section in 1u64..=5 {
                let size = journal.size(section).await.unwrap();
                assert!(size > 0, "section {section} should still have data");
            }

            // Verify sections 6-10 are removed (size should be 0)
            for section in 6u64..=10 {
                let size = journal.size(section).await.unwrap();
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify data integrity via replay
            {
                let stream = journal.replay(0, 0, NZUsize!(1024)).await.unwrap();
                pin_mut!(stream);
                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, _, _, item) = result.unwrap();
                    items.push((section, item));
                }
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
                partition: "test_partition".to_string(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.clone(), cfg.clone()).await.unwrap();

            // Append 5 items and record sizes after each
            let mut sizes = Vec::new();
            for i in 0..5 {
                journal.append(1, i).await.unwrap();
                journal.sync(1).await.unwrap();
                sizes.push(journal.size(1).await.unwrap());
            }

            // Rewind to keep only first 3 items
            let target_size = sizes[2];
            journal.rewind(1, target_size).await.unwrap();

            // Verify size is correct
            let new_size = journal.size(1).await.unwrap();
            assert_eq!(new_size, target_size);

            // Verify first 3 items via replay
            {
                let stream = journal.replay(0, 0, NZUsize!(1024)).await.unwrap();
                pin_mut!(stream);
                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (_, _, _, item) = result.unwrap();
                    items.push(item);
                }
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
                partition: "test_partition".to_string(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.clone(), cfg.clone()).await.unwrap();

            // Create sections 5, 6, 7 (skip 1-4)
            for section in 5u64..=7 {
                journal.append(section, section as i32).await.unwrap();
            }
            journal.sync_all().await.unwrap();

            // Rewind to section 3 (doesn't exist)
            journal.rewind(3, 0).await.unwrap();

            // Verify sections 5, 6, 7 are removed
            for section in 5u64..=7 {
                let size = journal.size(section).await.unwrap();
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify replay returns nothing
            {
                let stream = journal.replay(0, 0, NZUsize!(1024)).await.unwrap();
                pin_mut!(stream);
                let items: Vec<_> = stream.collect().await;
                assert!(items.is_empty());
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_journal_rewind_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".to_string(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Create sections 1-5 with data
            let mut journal = Journal::init(context.clone(), cfg.clone()).await.unwrap();
            for section in 1u64..=5 {
                journal.append(section, section as i32).await.unwrap();
            }
            journal.sync_all().await.unwrap();

            // Rewind to section 2
            let size = journal.size(2).await.unwrap();
            journal.rewind(2, size).await.unwrap();
            journal.sync_all().await.unwrap();
            drop(journal);

            // Re-init and verify only sections 1-2 exist
            let journal = Journal::<_, i32>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Verify sections 1-2 have data
            for section in 1u64..=2 {
                let size = journal.size(section).await.unwrap();
                assert!(size > 0, "section {section} should have data after restart");
            }

            // Verify sections 3-5 are gone
            for section in 3u64..=5 {
                let size = journal.size(section).await.unwrap();
                assert_eq!(size, 0, "section {section} should be gone after restart");
            }

            // Verify data integrity via replay
            {
                let stream = journal.replay(0, 0, NZUsize!(1024)).await.unwrap();
                pin_mut!(stream);
                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, _, _, item) = result.unwrap();
                    items.push((section, item));
                }
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
                partition: "test_partition".to_string(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.clone(), cfg.clone()).await.unwrap();

            // Create sections 1, 2, 3
            for section in 1u64..=3 {
                journal.append(section, section as i32).await.unwrap();
            }
            journal.sync_all().await.unwrap();

            // Rewind section 1 to size 0
            journal.rewind(1, 0).await.unwrap();

            // Verify section 1 exists but is empty
            let size = journal.size(1).await.unwrap();
            assert_eq!(size, 0, "section 1 should be empty");

            // Verify sections 2, 3 are completely removed
            for section in 2u64..=3 {
                let size = journal.size(section).await.unwrap();
                assert_eq!(size, 0, "section {section} should be removed");
            }

            // Verify replay returns nothing
            {
                let stream = journal.replay(0, 0, NZUsize!(1024)).await.unwrap();
                pin_mut!(stream);
                let items: Vec<_> = stream.collect().await;
                assert!(items.is_empty());
            }

            journal.destroy().await.unwrap();
        });
    }
}
