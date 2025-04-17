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
//! C = CRC32(Data)
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
//! calling `close`, all pending data is automatically synced and any open blobs are closed.
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
//! method that iterates over multiple `sections` concurrently in a single stream.
//!
//! ## Skip Reads
//!
//! Some applications may only want to read the first `n` bytes of each item during `replay`. This
//! can be done by providing a `prefix` parameter to the `replay` method. If `prefix` is provided,
//! `Journal` will only return the first `prefix` bytes of each item and "skip ahead" to the next
//! item (computing the offset using the read `size` value).
//!
//! _Reading only the `prefix` bytes of an item makes it impossible to compute the checksum of an
//! item. It is up to the caller to ensure these reads are safe._
//!
//! # Exact Reads
//!
//! To allow for items to be fetched in a single disk operation, `Journal` allows callers to specify
//! an `exact` parameter to the `get` method. This `exact` parameter must be cached by the caller
//! (provided during `replay`) and usage of an incorrect `exact` value will result in undefined
//! behavior.
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic::Executor};
//! use commonware_storage::journal::variable::{Journal, Config};
//!
//! let (executor, context, _) = Executor::default();
//! executor.start(async move {
//!     // Create a journal
//!     let mut journal = Journal::init(context, Config{
//!         partition: "partition".to_string()
//!     }).await.unwrap();
//!
//!     // Append data to the journal
//!     journal.append(1, "data".into()).await.unwrap();
//!
//!     // Close the journal
//!     journal.close().await.unwrap();
//! });
//! ```

use super::Error;
use bytes::{BufMut, Bytes};
use commonware_runtime::{Blob, Error as RError, Metrics, Storage};
use commonware_utils::hex;
use futures::stream::{self, Stream, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{btree_map::Entry, BTreeMap};
use tracing::{debug, trace, warn};

/// Configuration for `Journal` storage.
#[derive(Clone)]
pub struct Config {
    /// The `commonware-runtime::Storage` partition to use
    /// for storing journal blobs.
    pub partition: String,
}

const ITEM_ALIGNMENT: u64 = 16;

/// Computes the next offset for an item using the underlying `u64`
/// offset of `Blob`.
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
pub struct Journal<E: Storage + Metrics> {
    context: E,
    cfg: Config,

    oldest_allowed: Option<u64>,

    blobs: BTreeMap<u64, E::Blob>,

    tracked: Gauge,
    synced: Counter,
    pruned: Counter,
}

impl<E: Storage + Metrics> Journal<E> {
    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during
    /// initialization. The `replay` method can be used
    /// to iterate over all items in the `Journal`.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error> {
        // Iterate over blobs in partition
        let mut blobs = BTreeMap::new();
        let stored_blobs = match context.scan(&cfg.partition).await {
            Ok(blobs) => blobs,
            Err(RError::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };
        for name in stored_blobs {
            let blob = context.open(&cfg.partition, &name).await?;
            let hex_name = hex(&name);
            let section = match name.try_into() {
                Ok(section) => u64::from_be_bytes(section),
                Err(_) => return Err(Error::InvalidBlobName(hex_name)),
            };
            debug!(section, blob = hex_name, "loaded section");
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
        })
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
    async fn read(blob: &E::Blob, offset: u32) -> Result<(u32, u32, Bytes), Error> {
        // Read item size
        let offset = offset as u64 * ITEM_ALIGNMENT;
        let mut size = [0u8; 4];
        blob.read_at(&mut size, offset).await?;
        let size = u32::from_be_bytes(size);
        let offset = offset.checked_add(4).ok_or(Error::OffsetOverflow)?;

        // Read item
        let mut item = vec![0u8; size as usize];
        blob.read_at(&mut item, offset).await?;
        let offset = offset
            .checked_add(size as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Read checksum
        let mut stored_checksum = [0u8; 4];
        blob.read_at(&mut stored_checksum, offset).await?;
        let stored_checksum = u32::from_be_bytes(stored_checksum);
        let checksum = crc32fast::hash(&item);
        if checksum != stored_checksum {
            return Err(Error::ChecksumMismatch(stored_checksum, checksum));
        }
        let offset = offset.checked_add(4).ok_or(Error::OffsetOverflow)?;

        // Compute next offset
        let aligned_offset = compute_next_offset(offset)?;

        // Return item
        Ok((aligned_offset, size, Bytes::from(item)))
    }

    /// Read `prefix` bytes from the blob at the given offset.
    ///
    /// # Warning
    ///
    /// This method bypasses the checksum verification and the caller is responsible for ensuring
    /// the integrity of any data read. If `prefix` exceeds the size of an item (and runs over the blob
    /// length), it will lead to unintentional truncation of data.
    async fn read_prefix(
        blob: &E::Blob,
        offset: u32,
        prefix: u32,
    ) -> Result<(u32, u32, Bytes), Error> {
        // Read item size and first `prefix` bytes
        let offset = offset as u64 * ITEM_ALIGNMENT;
        let mut buf = vec![0u8; 4 + prefix as usize];
        blob.read_at(&mut buf, offset).await?;

        // Get item size to compute next offset
        let size = u32::from_be_bytes(buf[..4].try_into().unwrap());

        // Get item prefix
        //
        // We don't compute the checksum here nor do we verify that the bytes
        // requested is less than the item size.
        let item_prefix = Bytes::from(buf[4..].to_vec());

        // Compute next offset
        let offset = offset
            .checked_add(4)
            .ok_or(Error::OffsetOverflow)?
            .checked_add(size as u64)
            .ok_or(Error::OffsetOverflow)?
            .checked_add(4)
            .ok_or(Error::OffsetOverflow)?;
        let aligned_offset = compute_next_offset(offset)?;

        // Return item
        Ok((aligned_offset, size, item_prefix))
    }

    /// Read an item from the blob assuming it is of `exact` length. This method verifies the
    /// checksum of the item.
    ///
    /// # Warning
    ///
    /// This method assumes the caller knows the exact size of the item (either because
    /// they store fixed-size items or they previously indexed the size). If an incorrect
    /// `exact` is provided, the method will likely return an error (as integrity is verified).
    async fn read_exact(blob: &E::Blob, offset: u32, exact: u32) -> Result<(u32, Bytes), Error> {
        // Read all of the item into one buffer
        let offset = offset as u64 * ITEM_ALIGNMENT;
        let mut buf = vec![0u8; 4 + exact as usize + 4];
        blob.read_at(&mut buf, offset).await?;

        // Check size
        let size = u32::from_be_bytes(buf[..4].try_into().unwrap());
        if size != exact {
            return Err(Error::UnexpectedSize(size, exact));
        }

        // Get item
        let item = Bytes::from(buf[4..4 + exact as usize].to_vec());

        // Verify integrity
        let stored_checksum = u32::from_be_bytes(buf[4 + exact as usize..].try_into().unwrap());
        let checksum = crc32fast::hash(&item);
        if checksum != stored_checksum {
            return Err(Error::ChecksumMismatch(stored_checksum, checksum));
        }

        // Compute next offset
        let offset = offset
            .checked_add(4)
            .ok_or(Error::OffsetOverflow)?
            .checked_add(exact as u64)
            .ok_or(Error::OffsetOverflow)?
            .checked_add(4)
            .ok_or(Error::OffsetOverflow)?;
        let aligned_offset = compute_next_offset(offset)?;

        // Return item
        Ok((aligned_offset, item))
    }

    /// Returns an unordered stream of all items in the journal.
    ///
    /// # Repair
    ///
    /// If any corrupted data is found, the stream will return an error.
    ///
    /// If any trailing data is found (i.e. misaligned entries), the journal will be truncated
    /// to the last valid item. For this reason, it is recommended to call `replay` before
    /// calling `append` (as data added to trailing bytes will fail checksum after restart).
    ///
    /// # Concurrency
    ///
    /// The `concurrency` parameter controls how many blobs are replayed concurrently. This can dramatically
    /// speed up the replay process if the underlying storage supports concurrent reads across different
    /// blobs.
    ///
    /// # Prefix
    ///
    /// If `prefix` is provided, the stream will only read up to `prefix` bytes of each item. Consequently,
    /// this means we will not compute a checksum of the entire data and it is up to the caller to deal
    /// with the consequences of this.
    ///
    /// Reading `prefix` bytes and skipping ahead to a future location in a blob is the theoretically optimal
    /// way to read only what is required from storage, however, different storage implementations may take
    /// the opportunity to readahead past what is required (needlessly). If the underlying storage can be tuned
    /// for random access prior to invoking replay, it may lead to less IO.
    pub async fn replay(
        &mut self,
        concurrency: usize,
        prefix: Option<u32>,
    ) -> Result<impl Stream<Item = Result<(u64, u32, u32, Bytes), Error>> + '_, Error> {
        // Collect all blobs to replay
        let mut blobs = Vec::with_capacity(self.blobs.len());
        for (section, blob) in self.blobs.iter() {
            let len = blob.len().await?;
            let aligned_len = compute_next_offset(len)?;
            blobs.push((*section, blob, aligned_len));
        }

        // Replay all blobs concurrently and stream items as they are read (to avoid
        // occupying too much memory with buffered data)
        Ok(stream::iter(blobs)
            .map(move |(section, blob, len)| async move {
                stream::unfold(
                    (section, blob, 0u32),
                    move |(section, blob, offset)| async move {
                        // Check if we are at the end of the blob
                        if offset == len {
                            return None;
                        }

                        // Get next item
                        let mut read = match prefix {
                            Some(prefix) => Self::read_prefix(blob, offset, prefix).await,
                            None => Self::read(blob, offset).await,
                        };

                        // Ensure a full read wouldn't put us past the end of the blob
                        if let Ok((next_offset, _, _)) = read {
                            if next_offset > len {
                                read = Err(Error::Runtime(RError::BlobInsufficientLength));
                            }
                        };

                        // Handle read result
                        match read {
                            Ok((next_offset, item_size, item)) => {
                                trace!(blob = section, cursor = offset, len, "replayed item");
                                Some((
                                    Ok((section, offset, item_size, item)),
                                    (section, blob, next_offset),
                                ))
                            }
                            Err(Error::ChecksumMismatch(expected, found)) => {
                                // If we encounter corruption, we don't try to fix it.
                                warn!(
                                    blob = section,
                                    cursor = offset,
                                    expected,
                                    found,
                                    "corruption detected"
                                );
                                Some((
                                    Err(Error::ChecksumMismatch(expected, found)),
                                    (section, blob, len),
                                ))
                            }
                            Err(Error::Runtime(RError::BlobInsufficientLength)) => {
                                // If we encounter trailing bytes, we prune to the last
                                // valid item. This can happen during an unclean file close (where
                                // pending data is not fully synced to disk).
                                warn!(
                                    blob = section,
                                    new_size = offset,
                                    old_size = len,
                                    "trailing bytes detected: truncating"
                                );
                                blob.truncate(offset as u64 * ITEM_ALIGNMENT).await.ok()?;
                                blob.sync().await.ok()?;
                                None
                            }
                            Err(err) => Some((Err(err), (section, blob, len))),
                        }
                    },
                )
            })
            .buffer_unordered(concurrency)
            .flatten())
    }

    /// Appends an item to `Journal` in a given `section`.
    ///
    /// # Warning
    ///
    /// If there exist trailing bytes in the `Blob` of a particular `section` and
    /// `replay` is not called before this, it is likely that subsequent data added
    /// to the `Blob` will be considered corrupted (as the trailing bytes will fail
    /// the checksum verification). It is recommended to call `replay` before calling
    /// `append` to prevent this.
    pub async fn append(&mut self, section: u64, item: Bytes) -> Result<u32, Error> {
        // Check last pruned
        self.prune_guard(section, false)?;

        // Ensure item is not too large
        let item_len = item.len();
        let len = 4 + item_len + 4;
        let item_len = match item_len.try_into() {
            Ok(len) => len,
            Err(_) => return Err(Error::ItemTooLarge(item_len)),
        };

        // Get existing blob or create new one
        let blob = match self.blobs.entry(section) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let name = section.to_be_bytes();
                let blob = self.context.open(&self.cfg.partition, &name).await?;
                self.tracked.inc();
                entry.insert(blob)
            }
        };

        // Populate buffer
        let mut buf = Vec::with_capacity(len);
        buf.put_u32(item_len);
        let checksum = crc32fast::hash(&item);
        buf.put(item);
        buf.put_u32(checksum);

        // Append item to blob
        let cursor = blob.len().await?;
        let offset = compute_next_offset(cursor)?;
        blob.write_at(&buf, offset as u64 * ITEM_ALIGNMENT).await?;
        trace!(blob = section, previous_len = len, offset, "appended item");
        Ok(offset)
    }

    /// Retrieves the first `prefix` bytes of an item from `Journal` at a given `section` and `offset`.
    ///
    /// This method bypasses the checksum verification and the caller is responsible for ensuring
    /// the integrity of any data read.
    pub async fn get_prefix(
        &self,
        section: u64,
        offset: u32,
        prefix: u32,
    ) -> Result<Option<Bytes>, Error> {
        self.prune_guard(section, false)?;
        let blob = match self.blobs.get(&section) {
            Some(blob) => blob,
            None => return Ok(None),
        };
        let (_, _, item) = Self::read_prefix(blob, offset, prefix).await?;
        Ok(Some(item))
    }

    /// Retrieves an item from `Journal` at a given `section` and `offset`.
    ///
    /// If `exact` is provided, it is assumed the item is of size `exact` (which allows
    /// the item to be read in a single read). If `exact` is provided, the checksum of the
    /// data is still verified.
    pub async fn get(
        &self,
        section: u64,
        offset: u32,
        exact: Option<u32>,
    ) -> Result<Option<Bytes>, Error> {
        self.prune_guard(section, false)?;
        let blob = match self.blobs.get(&section) {
            Some(blob) => blob,
            None => return Ok(None),
        };

        // If we have an exact size, we can read the item in one go.
        if let Some(exact) = exact {
            let (_, item) = Self::read_exact(blob, offset, exact).await?;
            return Ok(Some(item));
        }

        // Perform a multi-op read.
        let (_, _, item) = Self::read(blob, offset).await?;
        Ok(Some(item))
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
        // Check if we already ran this prune
        self.prune_guard(min, true)?;

        // Prune any blobs that are smaller than the minimum
        while let Some((&section, _)) = self.blobs.first_key_value() {
            // Stop pruning if we reach the minimum
            if section >= min {
                break;
            }

            // Remove and close blob
            let blob = self.blobs.remove(&section).unwrap();
            blob.close().await?;

            // Remove blob from storage
            self.context
                .remove(&self.cfg.partition, Some(&section.to_be_bytes()))
                .await?;
            debug!(blob = section, "pruned blob");
            self.tracked.dec();
            self.pruned.inc();
        }

        // Update oldest allowed
        self.oldest_allowed = Some(min);
        Ok(())
    }

    /// Closes all open sections.
    pub async fn close(self) -> Result<(), Error> {
        for (section, blob) in self.blobs.into_iter() {
            blob.close().await?;
            debug!(blob = section, "closed blob");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, Bytes};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic::Executor, Blob, Error as RError, Runner, Storage};
    use futures::{pin_mut, StreamExt};
    use prometheus_client::registry::Metric;

    #[test_traced]
    fn test_journal_append_and_read() {
        // Initialize the deterministic context
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Initialize the journal
            let cfg = Config {
                partition: "test_partition".into(),
            };
            let index = 1u64;
            let data = Bytes::from("Test data");
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append an item to the journal
            journal
                .append(index, data.clone())
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
            };
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::new();
            let stream = journal
                .replay(1, None)
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, full_len, item)) => {
                        assert_eq!(full_len as usize, item.len());
                        items.push((blob_index, item))
                    }
                    Err(err) => panic!("Failed to read item: {}", err),
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
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append multiple items to different blobs
            let data_items = vec![
                (1u64, Bytes::from("Data for blob 1")),
                (1u64, Bytes::from("Data for blob 1, second item")),
                (2u64, Bytes::from("Data for blob 2")),
                (3u64, Bytes::from("Data for blob 3")),
            ];
            for (index, data) in &data_items {
                journal
                    .append(*index, data.clone())
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
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::new();
            {
                let stream = journal
                    .replay(2, None)
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((blob_index, _, full_len, item)) => {
                            assert_eq!(full_len as usize, item.len());
                            items.push((blob_index, item))
                        }
                        Err(err) => panic!("Failed to read item: {}", err),
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

            // Replay just first bytes
            {
                let stream = journal
                    .replay(2, Some(4))
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((_, _, full_len, item)) => {
                            assert_eq!(item, Bytes::from("Data"));
                            assert!(full_len as usize > item.len());
                        }
                        Err(err) => panic!("Failed to read item: {}", err),
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_journal_prune_blobs() {
        // Initialize the deterministic context
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append items to multiple blobs
            for index in 1u64..=5u64 {
                let data = Bytes::from(format!("Data for blob {}", index));
                journal
                    .append(index, data)
                    .await
                    .expect("Failed to append data");
                journal.sync(index).await.expect("Failed to sync blob");
            }

            // Add one item out-of-order
            let data = Bytes::from("Data for blob 2, second item");
            journal
                .append(2u64, data)
                .await
                .expect("Failed to append data");
            journal.sync(2u64).await.expect("Failed to sync blob");

            // Prune blobs with indices less than 3
            journal.prune(3).await.expect("Failed to prune blobs");

            // Prune again with a section less than the previous one
            let result = journal.prune(2).await;
            assert!(matches!(result, Err(Error::AlreadyPrunedToSection(3))));

            // Prune again with the same section
            let result = journal.prune(3).await;
            assert!(matches!(result, Err(Error::AlreadyPrunedToSection(3))));

            // Check metrics
            let buffer = context.encode();
            assert!(buffer.contains("pruned_total 2"));

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Replay the journal and collect items
            let mut items = Vec::new();
            {
                let stream = journal
                    .replay(1, None)
                    .await
                    .expect("unable to setup replay");
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                        Err(err) => panic!("Failed to read item: {}", err),
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
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Manually create a blob with an invalid name (not 8 bytes)
            let invalid_blob_name = b"invalid"; // Less than 8 bytes
            let blob = context
                .open(&cfg.partition, invalid_blob_name)
                .await
                .expect("Failed to create blob with invalid name");
            blob.close().await.expect("Failed to close blob");

            // Attempt to initialize the journal
            let result = Journal::init(context, cfg).await;

            // Expect an error
            assert!(matches!(result, Err(Error::InvalidBlobName(_))));
        });
    }

    fn journal_read_size_missing(exact: Option<u32>) {
        // Initialize the deterministic context
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Manually create a blob with incomplete size data
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let blob = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Write incomplete size data (less than 4 bytes)
            let incomplete_data = vec![0x00, 0x01]; // Less than 4 bytes
            blob.write_at(&incomplete_data, 0)
                .await
                .expect("Failed to write incomplete data");
            blob.close().await.expect("Failed to close blob");

            // Initialize the journal
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            let stream = journal
                .replay(1, exact)
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }
            assert!(items.is_empty());
        });
    }

    #[test_traced]
    fn test_journal_read_size_missing_no_exact() {
        journal_read_size_missing(None);
    }

    #[test_traced]
    fn test_journal_read_size_missing_with_exact() {
        journal_read_size_missing(Some(1));
    }

    fn journal_read_item_missing(exact: Option<u32>) {
        // Initialize the deterministic context
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Manually create a blob with missing item data
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let blob = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Write size but no item data
            let item_size: u32 = 10; // Size of the item
            let mut buf = Vec::new();
            buf.put_u32(item_size);
            let data = [2u8; 5];
            buf.put_slice(&data);
            blob.write_at(&buf, 0)
                .await
                .expect("Failed to write item size");
            blob.close().await.expect("Failed to close blob");

            // Initialize the journal
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            let stream = journal
                .replay(1, exact)
                .await
                .expect("unable to setup replay");

            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }
            assert!(items.is_empty());
        });
    }

    #[test_traced]
    fn test_journal_read_item_missing_no_exact() {
        journal_read_item_missing(None);
    }

    #[test_traced]
    fn test_journal_read_item_missing_with_exact() {
        journal_read_item_missing(Some(1));
    }

    #[test_traced]
    fn test_journal_read_checksum_missing() {
        // Initialize the deterministic context
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Manually create a blob with missing checksum
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let blob = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Prepare item data
            let item_data = b"Test data";
            let item_size = item_data.len() as u32;

            // Write size
            let mut offset = 0;
            blob.write_at(&item_size.to_be_bytes(), offset)
                .await
                .expect("Failed to write item size");
            offset += 4;

            // Write item data
            blob.write_at(item_data, offset)
                .await
                .expect("Failed to write item data");
            // Do not write checksum (omit it)

            blob.close().await.expect("Failed to close blob");

            // Initialize the journal
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            //
            // This will truncate the leftover bytes from our manual write.
            let stream = journal
                .replay(1, None)
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }
            assert!(items.is_empty());
        });
    }

    #[test_traced]
    fn test_journal_read_checksum_mismatch() {
        // Initialize the deterministic context
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Manually create a blob with incorrect checksum
            let section = 1u64;
            let blob_name = section.to_be_bytes();
            let blob = context
                .open(&cfg.partition, &blob_name)
                .await
                .expect("Failed to create blob");

            // Prepare item data
            let item_data = b"Test data";
            let item_size = item_data.len() as u32;
            let incorrect_checksum: u32 = 0xDEADBEEF;

            // Write size
            let mut offset = 0;
            blob.write_at(&item_size.to_be_bytes(), offset)
                .await
                .expect("Failed to write item size");
            offset += 4;

            // Write item data
            blob.write_at(item_data, offset)
                .await
                .expect("Failed to write item data");
            offset += item_data.len() as u64;

            // Write incorrect checksum
            blob.write_at(&incorrect_checksum.to_be_bytes(), offset)
                .await
                .expect("Failed to write incorrect checksum");

            blob.close().await.expect("Failed to close blob");

            // Initialize the journal
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to initialize journal");

            // Attempt to replay the journal
            let stream = journal
                .replay(1, None)
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            let mut items = Vec::new();
            let mut got_checksum_error = false;
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => {
                        assert!(matches!(err, Error::ChecksumMismatch(_, _)));
                        got_checksum_error = true;
                        // We explicitly don't return or break here to test that we won't end up in
                        // an infinite loop if the replay caller doesn't abort on error.
                    }
                }
            }
            assert!(got_checksum_error, "expected checksum mismatch error");
        });
    }

    #[test_traced]
    fn test_journal_handling_truncated_data() {
        // Initialize the deterministic context
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Create a journal configuration
            let cfg = Config {
                partition: "test_partition".into(),
            };

            // Initialize the journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to initialize journal");

            // Append 1 item to the first index
            journal
                .append(1, Bytes::from("Valid data"))
                .await
                .expect("Failed to append data");

            // Append multiple items to the second index
            let data_items = vec![
                (2u64, Bytes::from("Valid data")),
                (2u64, Bytes::from("Valid data, second item")),
                (2u64, Bytes::from("Valid data, third item")),
            ];
            for (index, data) in &data_items {
                journal
                    .append(*index, data.clone())
                    .await
                    .expect("Failed to append data");
                journal.sync(*index).await.expect("Failed to sync blob");
            }

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Manually corrupt the end of the second blob
            let blob = context
                .open(&cfg.partition, &2u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let blob_len = blob.len().await.expect("Failed to get blob length");
            blob.truncate(blob_len - 4)
                .await
                .expect("Failed to corrupt blob");
            blob.close().await.expect("Failed to close blob");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::init(context, cfg)
                .await
                .expect("Failed to re-initialize journal");

            // Attempt to replay the journal
            let mut items = Vec::new();
            let stream = journal
                .replay(1, None)
                .await
                .expect("unable to setup replay");
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Ok((blob_index, _, _, item)) => items.push((blob_index, item)),
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }

            // Verify that only non-corrupted items were replayed
            assert_eq!(items.len(), 3);
            assert_eq!(items[0].0, 1);
            assert_eq!(items[0].1, Bytes::from("Valid data"));
            assert_eq!(items[1].0, data_items[0].0);
            assert_eq!(items[1].1, data_items[0].1);
            assert_eq!(items[2].0, data_items[1].0);
            assert_eq!(items[2].1, data_items[1].1);
        });
    }

    // Define `MockBlob` that returns an offset length that should overflow
    #[derive(Clone)]
    struct MockBlob {
        len: u64,
    }

    impl Blob for MockBlob {
        async fn len(&self) -> Result<u64, commonware_runtime::Error> {
            // Return a length that will cause offset overflow
            Ok(self.len)
        }

        async fn read_at(&self, _buf: &mut [u8], _offset: u64) -> Result<(), RError> {
            Ok(())
        }

        async fn write_at(&self, _buf: &[u8], _offset: u64) -> Result<(), RError> {
            Ok(())
        }

        async fn truncate(&self, _len: u64) -> Result<(), RError> {
            Ok(())
        }

        async fn sync(&self) -> Result<(), RError> {
            Ok(())
        }

        async fn close(self) -> Result<(), RError> {
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

        async fn open(&self, _partition: &str, _name: &[u8]) -> Result<MockBlob, RError> {
            Ok(MockBlob { len: self.len })
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
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            // Create journal
            let cfg = Config {
                partition: "partition".to_string(),
            };
            let context = MockStorage {
                len: u32::MAX as u64 * INDEX_ALIGNMENT, // can store up to u32::Max at the last offset
            };
            let mut journal = Journal::init(context, cfg).await.unwrap();

            // Append data
            let data = Bytes::from("Test data");
            let result = journal
                .append(1, data)
                .await
                .expect("Failed to append data");
            assert_eq!(result, u32::MAX);
        });
    }

    #[test_traced]
    fn test_journal_offset_overflow() {
        // Initialize the deterministic context
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            // Create journal
            let cfg = Config {
                partition: "partition".to_string(),
            };
            let context = MockStorage {
                len: u32::MAX as u64 * INDEX_ALIGNMENT + 1,
            };
            let mut journal = Journal::init(context, cfg).await.unwrap();

            // Append data
            let data = Bytes::from("Test data");
            let result = journal.append(1, data).await;
            assert!(matches!(result, Err(Error::OffsetOverflow)));
        });
    }
}
