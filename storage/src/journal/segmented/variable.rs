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
//! use commonware_utils::{NZUsize, NZU16};
//!
//! let executor = deterministic::Runner::default();
//! executor.start(|context| async move {
//!     // Create a journal
//!     let mut journal = Journal::init(context, Config{
//!         partition: "partition".to_string(),
//!         compression: None,
//!         codec_config: (),
//!         buffer_pool: PoolRef::new(NZU16!(1024), NZUsize!(10)),
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
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    varint::UInt, Codec, CodecShared, EncodeSize, ReadExt, Write as CodecWrite,
};
use commonware_runtime::{
    buffer::pool::{Append, PoolRef, Replay},
    Blob, Metrics, Storage,
};
use futures::stream::{self, Stream, StreamExt};
use std::{io::Cursor, num::NonZeroUsize};
use tracing::{trace, warn};
use zstd::{bulk::compress, decode_all};

/// Maximum size of a varint for u32 (also the minimum useful read size for parsing item headers).
const MAX_VARINT_SIZE: usize = 5;

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

/// Decodes a varint length prefix from a buffer.
/// Returns (item_size, varint_len).
#[inline]
fn decode_length_prefix(buf: &mut impl Buf) -> Result<(usize, usize), Error> {
    let initial = buf.remaining();
    let size = UInt::<u32>::read(buf)?.0 as usize;
    let varint_len = initial - buf.remaining();
    Ok((size, varint_len))
}

/// Result of finding an item in a buffer (offsets/lengths, not slices).
enum ItemInfo {
    /// All item data is available in the buffer.
    Complete {
        /// Length of the varint prefix.
        varint_len: usize,
        /// Length of the item data.
        data_len: usize,
    },
    /// Only some item data is available.
    Incomplete {
        /// Length of the varint prefix.
        varint_len: usize,
        /// Bytes of item data available in buffer.
        prefix_len: usize,
        /// Full size of the item.
        total_len: usize,
    },
}

/// Find an item in a buffer by decoding its length prefix.
///
/// Returns (next_offset, item_info). The buffer is advanced past the varint.
fn find_item(buf: &mut impl Buf, offset: u64) -> Result<(u64, ItemInfo), Error> {
    let available = buf.remaining();
    let (size, varint_len) = decode_length_prefix(buf)?;
    let next_offset = offset
        .checked_add(varint_len as u64)
        .ok_or(Error::OffsetOverflow)?
        .checked_add(size as u64)
        .ok_or(Error::OffsetOverflow)?;
    let buffered = available.saturating_sub(varint_len);

    let item = if buffered >= size {
        ItemInfo::Complete {
            varint_len,
            data_len: size,
        }
    } else {
        ItemInfo::Incomplete {
            varint_len,
            prefix_len: buffered,
            total_len: size,
        }
    };

    Ok((next_offset, item))
}

/// State for replaying a single section's blob.
struct ReplayState<B: Blob, C> {
    section: u64,
    blob: Append<B>,
    replay: Replay<B>,
    skip_bytes: u64,
    offset: u64,
    valid_offset: u64,
    codec_config: C,
    compressed: bool,
    done: bool,
}

/// Decode item data with optional decompression.
fn decode_item<V: Codec>(item_data: impl Buf, cfg: &V::Cfg, compressed: bool) -> Result<V, Error> {
    if compressed {
        let decompressed =
            decode_all(item_data.reader()).map_err(|_| Error::DecompressionFailed)?;
        V::decode_cfg(decompressed.as_ref(), cfg).map_err(Error::Codec)
    } else {
        V::decode_cfg(item_data, cfg).map_err(Error::Codec)
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
pub struct Journal<E: Storage + Metrics, V: Codec> {
    manager: Manager<E, AppendFactory>,

    /// Compression level (if enabled).
    compression: Option<u8>,

    /// Codec configuration.
    codec_config: V::Cfg,
}

impl<E: Storage + Metrics, V: CodecShared> Journal<E, V> {
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
        // Read varint header (max 5 bytes for u32)
        let buf = vec![0u8; MAX_VARINT_SIZE];
        let (stable_buf, available) = blob.read_up_to(buf, offset).await?;
        let buf = Bytes::from(stable_buf);
        let mut cursor = Cursor::new(buf.slice(..available));
        let (next_offset, item_info) = find_item(&mut cursor, offset)?;

        // Decode item - either directly from buffer or by chaining prefix with remainder
        let (item_size, decoded) = match item_info {
            ItemInfo::Complete {
                varint_len,
                data_len,
            } => {
                // Data follows varint in buffer
                let data = buf.slice(varint_len..varint_len + data_len);
                let decoded = decode_item::<V>(data, cfg, compressed)?;
                (data_len as u32, decoded)
            }
            ItemInfo::Incomplete {
                varint_len,
                prefix_len,
                total_len,
            } => {
                // Read remainder and chain with prefix to avoid copying
                let prefix = buf.slice(varint_len..varint_len + prefix_len);
                let read_offset = offset + varint_len as u64 + prefix_len as u64;
                let remainder_len = total_len - prefix_len;
                let mut remainder = vec![0u8; remainder_len];
                blob.read_into(&mut remainder, read_offset).await?;
                let chained = prefix.chain(Bytes::from(remainder));
                let decoded = decode_item::<V>(chained, cfg, compressed)?;
                (total_len as u32, decoded)
            }
        };

        Ok((next_offset, item_size, decoded))
    }

    /// Returns an ordered stream of all items in the journal starting with the item at the given
    /// `start_section` and `offset` into that section. Each item is returned as a tuple of
    /// (section, offset, size, item).
    pub async fn replay(
        &self,
        start_section: u64,
        mut start_offset: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, u64, u32, V), Error>> + Send + '_, Error> {
        // Collect all blobs to replay (keeping blob reference for potential resize)
        let codec_config = self.codec_config.clone();
        let compressed = self.compression.is_some();
        let mut blobs = Vec::new();
        for (&section, blob) in self.manager.sections_from(start_section) {
            blobs.push((
                section,
                blob.clone(),
                blob.replay(buffer).await?,
                codec_config.clone(),
                compressed,
            ));
        }

        // Stream items as they are read to avoid occupying too much memory
        Ok(stream::iter(blobs).flat_map(
            move |(section, blob, replay, codec_config, compressed)| {
                // Calculate initial skip bytes for first blob
                let skip_bytes = if section == start_section {
                    start_offset
                } else {
                    start_offset = 0;
                    0
                };

                stream::unfold(
                    ReplayState {
                        section,
                        blob,
                        replay,
                        skip_bytes,
                        offset: 0,
                        valid_offset: skip_bytes,
                        codec_config,
                        compressed,
                        done: false,
                    },
                    move |mut state| async move {
                        if state.done {
                            return None;
                        }

                        let blob_size = state.replay.blob_size();
                        let mut batch: Vec<Result<(u64, u64, u32, V), Error>> = Vec::new();
                        loop {
                            // Ensure we have enough data for varint header.
                            // ensure() returns Ok(false) if exhausted with fewer bytes,
                            // but we still try to decode from remaining bytes.
                            match state.replay.ensure(MAX_VARINT_SIZE).await {
                                Ok(true) => {}
                                Ok(false) => {
                                    // Reader exhausted - check if buffer is empty
                                    if state.replay.remaining() == 0 {
                                        state.done = true;
                                        return if batch.is_empty() {
                                            None
                                        } else {
                                            Some((batch, state))
                                        };
                                    }
                                    // Buffer still has data - continue to try decoding
                                }
                                Err(err) => {
                                    batch.push(Err(err.into()));
                                    state.done = true;
                                    return Some((batch, state));
                                }
                            }

                            // Skip bytes if needed (for start_offset)
                            if state.skip_bytes > 0 {
                                let to_skip =
                                    state.skip_bytes.min(state.replay.remaining() as u64) as usize;
                                state.replay.advance(to_skip);
                                state.skip_bytes -= to_skip as u64;
                                state.offset += to_skip as u64;
                                continue;
                            }

                            // Try to decode length prefix
                            let before_remaining = state.replay.remaining();
                            let (item_size, varint_len) =
                                match decode_length_prefix(&mut state.replay) {
                                    Ok(result) => result,
                                    Err(err) => {
                                        // Could be incomplete varint - check if reader exhausted
                                        if state.replay.is_exhausted()
                                            || before_remaining < MAX_VARINT_SIZE
                                        {
                                            // Treat as trailing bytes
                                            if state.valid_offset < blob_size
                                                && state.offset < blob_size
                                            {
                                                warn!(
                                                    blob = state.section,
                                                    bad_offset = state.offset,
                                                    new_size = state.valid_offset,
                                                    "trailing bytes detected: truncating"
                                                );
                                                state.blob.resize(state.valid_offset).await.ok()?;
                                            }
                                            state.done = true;
                                            return if batch.is_empty() {
                                                None
                                            } else {
                                                Some((batch, state))
                                            };
                                        }
                                        batch.push(Err(err));
                                        state.done = true;
                                        return Some((batch, state));
                                    }
                                };

                            // Ensure we have enough data for item body
                            match state.replay.ensure(item_size).await {
                                Ok(true) => {}
                                Ok(false) => {
                                    // Incomplete item at end - truncate
                                    warn!(
                                        blob = state.section,
                                        bad_offset = state.offset,
                                        new_size = state.valid_offset,
                                        "incomplete item at end: truncating"
                                    );
                                    state.blob.resize(state.valid_offset).await.ok()?;
                                    state.done = true;
                                    return if batch.is_empty() {
                                        None
                                    } else {
                                        Some((batch, state))
                                    };
                                }
                                Err(err) => {
                                    batch.push(Err(err.into()));
                                    state.done = true;
                                    return Some((batch, state));
                                }
                            }

                            // Decode item - use take() to limit bytes read
                            let item_offset = state.offset;
                            let next_offset = match state
                                .offset
                                .checked_add(varint_len as u64)
                                .and_then(|o| o.checked_add(item_size as u64))
                            {
                                Some(o) => o,
                                None => {
                                    batch.push(Err(Error::OffsetOverflow));
                                    state.done = true;
                                    return Some((batch, state));
                                }
                            };
                            match decode_item::<V>(
                                (&mut state.replay).take(item_size),
                                &state.codec_config,
                                state.compressed,
                            ) {
                                Ok(decoded) => {
                                    batch.push(Ok((
                                        state.section,
                                        item_offset,
                                        item_size as u32,
                                        decoded,
                                    )));
                                    state.valid_offset = next_offset;
                                    state.offset = next_offset;
                                }
                                Err(err) => {
                                    batch.push(Err(err));
                                    state.done = true;
                                    return Some((batch, state));
                                }
                            }

                            // Return batch if we have items and buffer is low
                            if !batch.is_empty() && state.replay.remaining() < MAX_VARINT_SIZE {
                                return Some((batch, state));
                            }
                        }
                    },
                )
                .flat_map(stream::iter)
            },
        ))
    }

    /// Appends an item to `Journal` in a given `section`, returning the offset
    /// where the item was written and the size of the item (which may now be smaller
    /// than the encoded size from the codec, if compression is enabled).
    pub async fn append(&mut self, section: u64, item: V) -> Result<(u64, u32), Error> {
        // Create buffer with item data (no checksum, no alignment)
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
                .ok_or(Error::OffsetOverflow)?;

            let mut buf = Vec::with_capacity(entry_len);
            UInt(item_len_u32).write(&mut buf);
            buf.put_slice(&compressed);

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
                .ok_or(Error::OffsetOverflow)?;

            let mut buf = Vec::with_capacity(entry_len);
            UInt(item_len_u32).write(&mut buf);
            item.write(&mut buf);

            (buf, item_len)
        };

        // Get or create blob
        let blob = self.manager.get_or_create(section).await?;

        // Get current position - this is where we'll write (no alignment)
        let offset = blob.size().await;

        // Append item to blob
        blob.append(&buf).await?;
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

    /// Clear all data, resetting the journal to an empty state.
    ///
    /// Unlike `destroy`, this keeps the journal alive so it can be reused.
    pub async fn clear(&mut self) -> Result<(), Error> {
        self.manager.clear().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob, Metrics, Runner, Storage};
    use commonware_utils::{NZUsize, NZU16};
    use futures::{pin_mut, StreamExt};
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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let index = 1u64;
            let data = 10;
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append an item to the journal
            journal
                .append(index, data)
                .await
                .expect("Failed to append data");

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("first_tracked 1"));

            // Drop and re-open the journal to simulate a restart
            journal.sync(index).await.expect("Failed to sync journal");
            drop(journal);
            let journal = Journal::<_, i32>::init(context.with_label("second"), cfg)
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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
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
            assert!(buffer.contains("first_tracked 3"));
            assert!(buffer.contains("first_synced_total 4"));

            // Drop and re-open the journal to simulate a restart
            drop(journal);
            let journal = Journal::init(context.with_label("second"), cfg)
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
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
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
            assert!(buffer.contains("first_pruned_total 2"));

            // Prune again with a section less than the previous one, should be a no-op
            journal.prune(2).await.expect("Failed to no-op prune");
            let buffer = context.encode();
            assert!(buffer.contains("first_pruned_total 2"));

            // Drop and re-open the journal to simulate a restart
            drop(journal);
            let mut journal = Journal::init(context.with_label("second"), cfg.clone())
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
                let mut journal = Journal::init(context.with_label("first"), cfg.clone())
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
                let journal = Journal::<_, i32>::init(context.with_label("second"), cfg.clone())
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
            let data = [2u8; 5];
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
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
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
            let journal = Journal::init(context.with_label("second"), cfg.clone())
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
            let mut journal = Journal::init(context.with_label("third"), cfg.clone())
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
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].0, 1);
            assert_eq!(items[0].1, 1);

            // Append a new item to truncated partition
            let (_offset, _) = journal.append(2, 5).await.expect("Failed to append data");
            journal.sync(2).await.expect("Failed to sync blob");

            // Get the new item (offset is 0 since blob was truncated)
            let item = journal.get(2, 0).await.expect("Failed to get item");
            assert_eq!(item, 5);

            // Drop the journal (data already synced)
            drop(journal);

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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
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
            let journal = Journal::init(context.with_label("second"), cfg)
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
    fn test_journal_small_items() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append many small (1-byte) items to the same section
            let num_items = 100;
            let mut offsets = Vec::new();
            for i in 0..num_items {
                let (offset, size) = journal
                    .append(1, i as u8)
                    .await
                    .expect("Failed to append data");
                assert_eq!(size, 1, "u8 should encode to 1 byte");
                offsets.push(offset);
            }
            journal.sync(1).await.expect("Failed to sync");

            // Read each item back via random access
            for (i, &offset) in offsets.iter().enumerate() {
                let item: u8 = journal.get(1, offset).await.expect("Failed to get item");
                assert_eq!(item, i as u8, "Item mismatch at offset {offset}");
            }

            // Drop and reopen to test replay
            drop(journal);
            let journal = Journal::<_, u8>::init(context.with_label("second"), cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Replay and verify all items
            let stream = journal
                .replay(0, 0, NZUsize!(1024))
                .await
                .expect("Failed to setup replay");
            pin_mut!(stream);

            let mut count = 0;
            while let Some(result) = stream.next().await {
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
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .unwrap();
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
            let journal = Journal::<_, i32>::init(context.with_label("second"), cfg.clone())
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

    #[test_traced]
    fn test_journal_replay_start_offset_with_trailing_bytes() {
        // Regression: valid_offset must be initialized to start_offset, not 0.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append several items to build up valid data
            for i in 0..5i32 {
                journal.append(1, i).await.unwrap();
            }
            journal.sync(1).await.unwrap();
            let valid_logical_size = journal.size(1).await.unwrap();
            drop(journal);

            // Get the physical blob size before corruption
            let (blob, physical_size_before) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .unwrap();

            // Write incomplete varint: 0xFF has continuation bit set, needs more bytes
            // This creates 2 trailing bytes that cannot form a valid item
            blob.write_at(vec![0xFF, 0xFF], physical_size_before)
                .await
                .unwrap();
            blob.sync().await.unwrap();

            // Reopen journal and replay starting PAST all valid items
            // (start_offset = valid_logical_size means we skip all valid data)
            // The first thing encountered will be the trailing corrupt bytes
            let start_offset = valid_logical_size;
            {
                let journal = Journal::<_, i32>::init(context.with_label("second"), cfg.clone())
                    .await
                    .unwrap();

                let stream = journal
                    .replay(1, start_offset, NZUsize!(1024))
                    .await
                    .unwrap();
                pin_mut!(stream);

                // Consume the stream - should detect trailing bytes and truncate
                while let Some(_result) = stream.next().await {}
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
    fn test_journal_large_item_spanning_pages() {
        // 2048 bytes spans 2 full pages (PAGE_SIZE = 1024).
        const LARGE_SIZE: usize = 2048;
        type LargeItem = [u8; LARGE_SIZE];

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(4096),
            };
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
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
            let (offset, size) = journal
                .append(1, large_data)
                .await
                .expect("Failed to append large item");
            assert_eq!(size as usize, LARGE_SIZE);
            journal.sync(1).await.expect("Failed to sync");

            // Read the item back via random access
            let retrieved: LargeItem = journal
                .get(1, offset)
                .await
                .expect("Failed to get large item");
            assert_eq!(retrieved, large_data, "Random access read mismatch");

            // Drop and reopen to test replay
            drop(journal);
            let journal = Journal::<_, LargeItem>::init(context.with_label("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay and verify the large item
            {
                let stream = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, off, sz, item) = result.expect("Failed to replay item");
                    items.push((section, off, sz, item));
                }

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
    fn test_journal_non_contiguous_sections() {
        // Test that sections with gaps in numbering work correctly.
        // Sections 1, 5, 10 should all be independent and accessible.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Create sections with gaps: 1, 5, 10
            let sections_and_data = [(1u64, 100i32), (5u64, 500i32), (10u64, 1000i32)];
            let mut offsets = Vec::new();

            for (section, data) in &sections_and_data {
                let (offset, _) = journal
                    .append(*section, *data)
                    .await
                    .expect("Failed to append");
                offsets.push(offset);
            }
            journal.sync_all().await.expect("Failed to sync");

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
            let journal = Journal::<_, i32>::init(context.with_label("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay and verify all items in order
            {
                let stream = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, _, _, item) = result.expect("Failed to replay item");
                    items.push((section, item));
                }

                assert_eq!(items.len(), 3, "Should have 3 items");
                assert_eq!(items[0], (1, 100));
                assert_eq!(items[1], (5, 500));
                assert_eq!(items[2], (10, 1000));
            }

            // Test replay starting from middle section (5)
            {
                let stream = journal
                    .replay(5, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay from section 5");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, _, _, item) = result.expect("Failed to replay item");
                    items.push((section, item));
                }

                assert_eq!(items.len(), 2, "Should have 2 items from section 5 onwards");
                assert_eq!(items[0], (5, 500));
                assert_eq!(items[1], (10, 1000));
            }

            // Test replay starting from non-existent section (should skip to next)
            {
                let stream = journal
                    .replay(3, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay from section 3");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, _, _, item) = result.expect("Failed to replay item");
                    items.push((section, item));
                }

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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append to section 1
            journal.append(1, 100i32).await.expect("Failed to append");

            // Create section 2 but don't append anything - just sync to create the blob
            // Actually, we need to append something and then rewind to make it empty
            journal.append(2, 200i32).await.expect("Failed to append");
            journal.sync(2).await.expect("Failed to sync");
            journal
                .rewind_section(2, 0)
                .await
                .expect("Failed to rewind");

            // Append to section 3
            journal.append(3, 300i32).await.expect("Failed to append");

            journal.sync_all().await.expect("Failed to sync");

            // Verify section sizes
            assert!(journal.size(1).await.unwrap() > 0);
            assert_eq!(journal.size(2).await.unwrap(), 0);
            assert!(journal.size(3).await.unwrap() > 0);

            // Drop and reopen to test replay
            drop(journal);
            let journal = Journal::<_, i32>::init(context.with_label("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay all - should get items from sections 1 and 3, skipping empty section 2
            {
                let stream = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, _, _, item) = result.expect("Failed to replay item");
                    items.push((section, item));
                }

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
                let stream = journal
                    .replay(2, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay from section 2");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, _, _, item) = result.expect("Failed to replay item");
                    items.push((section, item));
                }

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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(4096),
            };
            let mut journal = Journal::init(context.with_label("first"), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Create an item exactly PAGE_SIZE bytes
            let mut exact_data: ExactItem = [0u8; ITEM_SIZE];
            for (i, byte) in exact_data.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }

            // Append the exact-size item
            let (offset, size) = journal
                .append(1, exact_data)
                .await
                .expect("Failed to append exact item");
            assert_eq!(size as usize, ITEM_SIZE);
            journal.sync(1).await.expect("Failed to sync");

            // Read the item back via random access
            let retrieved: ExactItem = journal
                .get(1, offset)
                .await
                .expect("Failed to get exact item");
            assert_eq!(retrieved, exact_data, "Random access read mismatch");

            // Drop and reopen to test replay
            drop(journal);
            let journal = Journal::<_, ExactItem>::init(context.with_label("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay and verify
            {
                let stream = journal
                    .replay(0, 0, NZUsize!(1024))
                    .await
                    .expect("Failed to setup replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, off, sz, item) = result.expect("Failed to replay item");
                    items.push((section, off, sz, item));
                }

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
                partition: "test_partition".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(SMALL_PAGE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };
            let mut journal: Journal<_, [u8; 128]> =
                Journal::init(context.with_label("first"), cfg.clone())
                    .await
                    .expect("Failed to initialize journal");

            // Create items that will span many 16-byte pages
            let item1: [u8; 128] = [1u8; 128];
            let item2: [u8; 128] = [2u8; 128];
            let item3: [u8; 128] = [3u8; 128];

            // Append items - each is 130 bytes (2-byte varint + 128 data)
            // spanning ceil(130/16) = 9 pages worth of logical data
            let (offset1, _) = journal.append(1, item1).await.expect("Failed to append");
            let (offset2, _) = journal.append(1, item2).await.expect("Failed to append");
            let (offset3, _) = journal.append(1, item3).await.expect("Failed to append");

            journal.sync(1).await.expect("Failed to sync");

            // Read items back via random access
            let retrieved1: [u8; 128] = journal.get(1, offset1).await.expect("Failed to get");
            let retrieved2: [u8; 128] = journal.get(1, offset2).await.expect("Failed to get");
            let retrieved3: [u8; 128] = journal.get(1, offset3).await.expect("Failed to get");
            assert_eq!(retrieved1, item1);
            assert_eq!(retrieved2, item2);
            assert_eq!(retrieved3, item3);

            // Drop and reopen to test replay
            drop(journal);
            let journal: Journal<_, [u8; 128]> =
                Journal::init(context.with_label("second"), cfg.clone())
                    .await
                    .expect("Failed to re-initialize journal");

            // Replay and verify all items
            {
                let stream = journal
                    .replay(0, 0, NZUsize!(64))
                    .await
                    .expect("Failed to setup replay");
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    let (section, off, _, item) = result.expect("Failed to replay item");
                    items.push((section, off, item));
                }

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
                partition: "clear_test".into(),
                compression: None,
                codec_config: (),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(1024),
            };

            let mut journal: Journal<_, u64> =
                Journal::init(context.with_label("journal"), cfg.clone())
                    .await
                    .expect("Failed to initialize journal");

            // Append items across multiple sections
            for section in 0..5u64 {
                for i in 0..10u64 {
                    journal
                        .append(section, section * 1000 + i)
                        .await
                        .expect("Failed to append");
                }
                journal.sync(section).await.expect("Failed to sync");
            }

            // Verify we have data
            assert_eq!(journal.get(0, 0).await.unwrap(), 0);
            assert_eq!(journal.get(4, 0).await.unwrap(), 4000);

            // Clear the journal
            journal.clear().await.expect("Failed to clear");

            // After clear, all reads should fail
            for section in 0..5u64 {
                assert!(matches!(
                    journal.get(section, 0).await,
                    Err(Error::SectionOutOfRange(s)) if s == section
                ));
            }

            // Append new data after clear
            for i in 0..5u64 {
                journal
                    .append(10, i * 100)
                    .await
                    .expect("Failed to append after clear");
            }
            journal.sync(10).await.expect("Failed to sync after clear");

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
