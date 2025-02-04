//! An append-only log for storing fixed length items on disk.
//!
//! In addition to replay, stored items can be fetched directly by their `position` in the journal,
//! where position is defined as the item's order of insertion starting from 0, unaffected by
//! pruning.
//!
//! _See the [variable crate](crate::journal::variable) for a journal that supports variable length
//! items._
//!
//! # Format
//!
//! Data stored in a `fixed::Journal` is persisted in one of many Blobs within a caller-provided
//! `partition`. Each `Blob` contains a configurable maximum of `items_per_blob`, with each item
//! followed by its checksum (CRC32):
//!
//! ```text
//! +--------+-----------+--------+-----------+--------+----------+-------------+
//! | item_0 | C(Item_0) | item_1 | C(Item_1) |   ...  | item_n-1 | C(Item_n-1) |
//! +--------+-----------+--------+----0------+--------+----------+-------------+
//!
//! n = config.items_per_blob, C = CRC32
//! ```
//!
//! The most recent blob may not necessarily be full, in which case it will contain fewer than the
//! maximum number of items.
//!
//! A fetched or replayed item's checksum is always computed and checked against the stored value
//! before it is returned. If the checksums do not match, an error is returned instead.
//!
//! # Open Blobs
//!
//! All `Blobs` in a given `partition` are kept open during the lifetime of `Journal`. You can limit
//! the number of open blobs by using a higher number of `items_per_blob` or pruning old items.
//!
//! # Sync
//!
//! Data written to `Journal` may not be immediately persisted to `Storage`. It is up to the caller
//! to determine when to force pending data to be written to `Storage` using the `sync` method. When
//! calling `close`, all pending data is automatically synced and any open blobs are closed.
//!
//! # Pruning
//!
//! Old data can be pruned from `Journal` by calling the `prune` method which will remove all blobs
//! consisting entirely of values older than the given item.
//!
//! # Replay
//!
//! The `replay` method iterates over multiple blobs concurrently to support fast reading of all
//! unpruned items into memory.

use super::Error;
use bytes::BufMut;
use commonware_runtime::{Blob, Error as RError, Storage};
use commonware_utils::hex;
use futures::stream::{self, Stream, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use prometheus_client::registry::Registry;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, trace, warn};

/// Configuration for `Journal` storage.
#[derive(Clone)]
pub struct Config {
    /// Registry for metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// The `commonware-runtime::Storage` partition to use for storing journal blobs.
    pub partition: String,

    /// The maximum number of journal items to store in each blob.
    ///
    /// Any unpruned historical blobs will contain exactly this number of items.
    /// Only the newest blob may contain fewer items.
    pub items_per_blob: u64,
}

/// Implementation of `Journal` storage.
pub struct Journal<B: Blob, E: Storage<B>, const N: usize> {
    runtime: E,
    cfg: Config,

    // Blobs are stored in a BTreeMap to ensure they are always iterated in order of their indices.
    // Indices are consecutive and without gaps.
    blobs: BTreeMap<u64, B>,

    tracked: Gauge,
    synced: Counter,
    pruned: Counter,
}

impl<B: Blob, E: Storage<B>, const N: usize> Journal<B, E, N> {
    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during initialization. The `replay` method can be
    /// used to iterate over all items in the `Journal`.
    pub async fn init(runtime: E, cfg: Config) -> Result<Self, Error> {
        // Iterate over blobs in partition
        let mut blobs = BTreeMap::new();
        let stored_blobs = match runtime.scan(&cfg.partition).await {
            Ok(blobs) => blobs,
            Err(RError::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };
        for name in stored_blobs {
            let blob = runtime
                .open(&cfg.partition, &name)
                .await
                .map_err(Error::Runtime)?;
            let index = match name.try_into() {
                Ok(index) => u64::from_be_bytes(index),
                Err(nm) => return Err(Error::InvalidBlobName(hex(&nm))),
            };
            debug!(blob = index, "loaded blob");
            blobs.insert(index, blob);
        }
        if !blobs.is_empty() {
            // Check that there are no gaps in the blob numbering, which would indicate missing data.
            let mut it = blobs.keys();
            let mut previous_index = *it.next().unwrap();
            for index in it {
                if *index != previous_index + 1 {
                    return Err(Error::MissingBlob(previous_index + 1));
                }
                previous_index = *index;
            }
        } else {
            debug!("no blobs found");
            let blob = runtime.open(&cfg.partition, &0u64.to_be_bytes()).await?;
            blobs.insert(0, blob);
        }

        // Initialize metrics
        let tracked = Gauge::default();
        let synced = Counter::default();
        let pruned = Counter::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register("tracked", "Number of blobs", tracked.clone());
            registry.register("synced", "Number of syncs", synced.clone());
            registry.register("pruned", "Number of blobs pruned", pruned.clone());
        }
        tracked.set(blobs.len() as i64);

        // truncate the last blob if it's not the expected length, which might happen from unclean
        // shutdown.
        let newest_blob = blobs.last_key_value().unwrap().1;
        let blob_len: u64 = newest_blob.len().await?;
        let chunk_size: usize = size_of::<u32>() + N;
        if blob_len % chunk_size as u64 != 0 {
            warn!(
                "last blob len ({}) is not a multiple of item size, truncating",
                blob_len
            );
            newest_blob
                .truncate(blob_len - blob_len % chunk_size as u64)
                .await?;
            newest_blob.sync().await?;
        }

        Ok(Self {
            runtime,
            cfg,
            blobs,
            tracked,
            synced,
            pruned,
        })
    }

    /// Sync any pending updates to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.synced.inc();
        let newest_blob = self.newest_blob();
        debug!("syncing blob {}", newest_blob.0);
        self.newest_blob().1.sync().await.map_err(Error::Runtime)
    }

    /// Returns the total number of items in the journal, ignoring any pruning. The next value
    /// appended to the journal will be at this position.
    pub async fn size(&self) -> Result<u64, Error> {
        let chunk_size = size_of::<u32>() + N;
        let newest_blob = self.newest_blob();
        let blob_len = newest_blob.1.len().await?;
        assert_eq!(blob_len % chunk_size as u64, 0);
        let items_in_blob = blob_len / chunk_size as u64;
        Ok(items_in_blob + self.cfg.items_per_blob * newest_blob.0)
    }

    /// Append a new item to the journal. Return the item's position in the journal, or error if the
    /// operation fails.
    pub async fn append(&mut self, item: [u8; N]) -> Result<u64, Error> {
        let chunk_size = size_of::<u32>() + N;
        let mut newest_blob = self.newest_blob();

        let mut blob_len = newest_blob.1.len().await?;
        assert_eq!(blob_len % chunk_size as u64, 0);
        let items_in_blob = blob_len / chunk_size as u64;

        // if the blob is full we need to create the next one and use that instead
        if items_in_blob >= self.cfg.items_per_blob {
            let next_blob_index = newest_blob.0 + 1;
            debug!("creating next blob {}", next_blob_index);
            assert_eq!(items_in_blob, self.cfg.items_per_blob);
            // always sync the previous blob before creating a new one
            newest_blob.1.sync().await?;
            let next_blob = self
                .runtime
                .open(&self.cfg.partition, &next_blob_index.to_be_bytes())
                .await?;
            assert!(self.blobs.insert(next_blob_index, next_blob).is_none());
            newest_blob = self.newest_blob();
            self.tracked.inc();
            blob_len = 0;
        }

        let mut buf: Vec<u8> = Vec::with_capacity(chunk_size);
        let checksum = crc32fast::hash(&item[..]);
        buf.put(&item[..]);
        buf.put_u32(checksum);

        let item_position = blob_len / chunk_size as u64;
        newest_blob.1.write_at(&buf, blob_len).await?;
        trace!(
            blob = newest_blob.0,
            position = item_position,
            "appended item"
        );
        Ok(item_position + self.cfg.items_per_blob * newest_blob.0)
    }

    /// Read the item at the given position in the journal.
    pub async fn read(&self, item_position: u64) -> Result<[u8; N], Error> {
        let chunk_size = size_of::<u32>() + N;
        let blob_index = item_position / self.cfg.items_per_blob;

        let blob = match self.blobs.get(&blob_index) {
            Some(blob) => blob,
            None => {
                let newest_blob = self.newest_blob();
                if blob_index > newest_blob.0 {
                    return Err(Error::InvalidItem(item_position));
                }
                assert!(blob_index < self.oldest_blob().0);
                return Err(Error::ItemPruned(item_position));
            }
        };

        let item_index = item_position % self.cfg.items_per_blob;
        let offset = item_index * chunk_size as u64;
        let mut buf = vec![0u8; chunk_size];
        blob.read_at(&mut buf, offset).await?;

        // Verify integrity
        Self::verify_integrity(&buf)
    }

    fn verify_integrity(buf: &[u8]) -> Result<[u8; N], Error> {
        let stored_checksum = u32::from_be_bytes(buf[N..].try_into().unwrap());
        let checksum = crc32fast::hash(&buf[..N]);
        if checksum != stored_checksum {
            return Err(Error::ChecksumMismatch(stored_checksum, checksum));
        }
        Ok(buf[..N].try_into().unwrap())
    }

    /// Returns an unordered stream of all items in the journal.
    ///
    /// # Integrity
    ///
    /// If any corrupted data is found, the stream will return an error.
    ///
    /// # Concurrency
    ///
    /// The `concurrency` parameter controls how many blobs are replayed concurrently. This can
    /// dramatically speed up the replay process if the underlying storage supports concurrent reads
    /// across different blobs.
    pub async fn replay(
        &mut self,
        concurrency: usize,
    ) -> Result<impl Stream<Item = Result<(u64, [u8; N]), Error>> + '_, Error> {
        let chunk_size = size_of::<u32>() + N;
        // Collect all blobs to replay
        let mut blobs = Vec::with_capacity(self.blobs.len());
        for (index, blob) in self.blobs.iter() {
            let blob_len = {
                if *index == (self.blobs.len() - 1) as u64 {
                    blob.len().await?
                } else {
                    self.cfg.items_per_blob * chunk_size as u64
                }
            };
            blobs.push((index, blob, blob_len));
        }

        // Replay all blobs concurrently and stream items as they are read (to avoid occupying too
        // much memory with buffered data)
        let items_per_blob = self.cfg.items_per_blob;
        Ok(stream::iter(blobs)
            .map(move |(index, blob, blob_len)| async move {
                stream::unfold(
                    (index, blob, 0u64),
                    move |(index, blob, offset)| async move {
                        // Check if we are at the end of the blob
                        if offset == blob_len {
                            return None;
                        }
                        // Get next item
                        let mut buf = vec![0u8; N + size_of::<u32>()];
                        let item = blob.read_at(&mut buf, offset).await.map_err(Error::Runtime);
                        let next_offset = offset + chunk_size as u64;
                        match item {
                            Ok(_) => match Self::verify_integrity(&buf) {
                                Ok(item) => Some((
                                    Ok((
                                        items_per_blob * *index + offset / chunk_size as u64,
                                        item,
                                    )),
                                    (index, blob, next_offset),
                                )),
                                Err(err) => Some((Err(err), (index, blob, next_offset))),
                            },
                            Err(err) => Some((Err(err), (index, blob, blob_len))),
                        }
                    },
                )
            })
            .buffer_unordered(concurrency)
            .flatten())
    }

    /// Return the blob containing the most recent items and its index.
    fn newest_blob(&self) -> (u64, &B) {
        if let Some((index, blob)) = self.blobs.last_key_value() {
            return (*index, blob);
        }
        panic!("no blobs found");
    }

    /// Return the blob containing the oldest unpruned items and its index.
    fn oldest_blob(&self) -> (u64, &B) {
        if let Some((index, blob)) = self.blobs.first_key_value() {
            return (*index, blob);
        }
        panic!("no blobs found");
    }

    /// Allow the journal to prune items older than `min_item_position`. The journal may still
    /// retain some of these items, for example if they are part of the most recent blob.
    pub async fn prune(&mut self, min_item_position: u64) -> Result<(), Error> {
        let oldest_blob = self.oldest_blob().0;
        let mut new_oldest_blob = min_item_position / self.cfg.items_per_blob;
        if new_oldest_blob <= oldest_blob {
            // nothing to prune
            return Ok(());
        }
        // Make sure we never prune the most recent blob
        let newest_blob = self.newest_blob();
        if new_oldest_blob >= newest_blob.0 {
            new_oldest_blob = newest_blob.0
        }

        for index in oldest_blob..new_oldest_blob {
            let blob = self.blobs.remove(&index).unwrap();
            // Close the blob and remove it from storage
            blob.close().await?;
            self.runtime
                .remove(&self.cfg.partition, Some(&index.to_be_bytes()))
                .await?;
            debug!(blob = index, "pruned blob");
            self.pruned.inc();
            self.tracked.dec();
        }
        Ok(())
    }

    /// Close the journal
    pub async fn close(self) -> Result<(), Error> {
        for (i, blob) in self.blobs.into_iter() {
            blob.close().await?;
            debug!(blob = i, "closed blob");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic::Executor, Blob, Runner, Storage};
    use futures::{pin_mut, StreamExt};
    use prometheus_client::encoding::text::encode;

    #[test_traced]
    fn test_fixed_journal_append_and_prune() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Initialize the journal, allowing a max of 2 items per blob.
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
                items_per_blob: 2,
            };
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("tracked 1"));

            // Append an item to the journal
            let mut position = journal
                .append(0u64.to_be_bytes())
                .await
                .expect("failed to append data 0");
            assert_eq!(position, 0);

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Re-initialize the journal to simulate a restart
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
                items_per_blob: 2,
            };
            let mut journal = Journal::init(context, cfg.clone())
                .await
                .expect("failed to re-initialize journal");

            // Append two more items to the journal to trigger a new blob creation
            position = journal
                .append(1u64.to_be_bytes())
                .await
                .expect("failed to append data 1");
            assert_eq!(position, 1);
            position = journal
                .append(2u64.to_be_bytes())
                .await
                .expect("failed to append data 2");
            assert_eq!(position, 2);
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("tracked 2"));

            // Read the items back
            let item0 = journal.read(0).await.expect("failed to read data 0");
            assert_eq!(item0, 0u64.to_be_bytes());
            let item1 = journal.read(1).await.expect("failed to read data 1");
            assert_eq!(item1, 1u64.to_be_bytes());
            let item2 = journal.read(2).await.expect("failed to read data 2");
            assert_eq!(item2, 2u64.to_be_bytes());
            let err = journal.read(3).await.expect_err("expected read to fail");
            assert!(matches!(err, Error::Runtime(_)));
            let err = journal.read(400).await.expect_err("expected read to fail");
            assert!(matches!(err, Error::InvalidItem(x) if x == 400));

            // Sync the journal
            journal.sync().await.expect("failed to sync journal");
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("synced_total 1"));

            // Prune the journal -- this should be a no-op because there's no complete blob covered
            journal.prune(1).await.expect("failed to prune journal 1");
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("tracked 2"));

            // Prune again this time make sure 1 blob is pruned
            journal.prune(2).await.expect("failed to prune journal 2");
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("tracked 1"));
            assert!(buffer.contains("pruned_total 1"));

            // Reading from the first blob should fail
            let result0 = journal.read(0).await;
            assert!(matches!(result0, Err(Error::ItemPruned(0))));
            let result1 = journal.read(1).await;
            assert!(matches!(result1, Err(Error::ItemPruned(1))));

            // Third item should still be readable
            let result2 = journal.read(2).await.unwrap();
            assert_eq!(result2, 2u64.to_be_bytes());

            // Should be able to continue to append items
            for i in 3u64..10 {
                let position = journal
                    .append(i.to_be_bytes())
                    .await
                    .expect("failed to append data");
                assert_eq!(position, i);
            }

            // Check no-op pruning
            journal
                .prune(0)
                .await
                .expect("failed to no-op prune the journal");
            assert_eq!(journal.oldest_blob().0, 1);
            assert_eq!(journal.newest_blob().0, 4);

            // Prune first 3 blobs
            journal
                .prune(3 * cfg.items_per_blob)
                .await
                .expect("failed to prune journal 2");
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert_eq!(journal.oldest_blob().0, 3);
            assert_eq!(journal.newest_blob().0, 4);
            assert!(buffer.contains("tracked 2"));
            assert!(buffer.contains("pruned_total 3"));

            // Try pruning (more than) everything in the journal, which should leave only the most
            // recent blob.
            journal
                .prune(10000)
                .await
                .expect("failed to max-prune journal");
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert_eq!(journal.size().await.unwrap(), 10);
            assert_eq!(journal.oldest_blob().0, 4);
            assert_eq!(journal.newest_blob().0, 4);
            assert!(buffer.contains("tracked 1"));
            assert!(buffer.contains("pruned_total 4"));

            let stream = journal.replay(1).await.expect("failed to replay journal");
            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((position, item)) => {
                        assert_eq!(position, u64::from_be_bytes(item));
                        items.push(position);
                    }
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }
            assert_eq!(items, vec![8u64, 9u64]);
        });
    }

    #[test_traced]
    fn test_fixed_journal_replay() {
        const ITEMS_PER_BLOB: u64 = 7;
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
                items_per_blob: ITEMS_PER_BLOB,
            };
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append many items, filling 100 blobs and part of the 101st
            for i in 0u64..(ITEMS_PER_BLOB * 100 + ITEMS_PER_BLOB / 2) {
                let position = journal
                    .append(i.to_be_bytes())
                    .await
                    .expect("failed to append data");
                assert_eq!(position, i);
            }

            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("tracked 101"));

            // Replay should return all items
            {
                let stream = journal.replay(10).await.expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((position, item)) => {
                            assert_eq!(position, u64::from_be_bytes(item));
                            items.push(position);
                        }
                        Err(err) => panic!("Failed to read item: {}", err),
                    }
                }

                // Make sure all items were replayed
                assert_eq!(
                    items.len(),
                    ITEMS_PER_BLOB as usize * 100 + ITEMS_PER_BLOB as usize / 2
                );
                items.sort();
                for (i, position) in items.iter().enumerate() {
                    assert_eq!(i as u64, *position);
                }
            }
            journal.close().await.expect("Failed to close journal");

            // Corrupt one of the checksums and make sure it's detected.
            let checksum_offset = size_of::<u64>() as u64
                + (ITEMS_PER_BLOB / 2) * (size_of::<u64>() + size_of::<u32>()) as u64;
            let blob = context
                .open(&cfg.partition, &40u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // Write incorrect checksum
            let bad_checksum = 123456789u32;
            blob.write_at(&bad_checksum.to_be_bytes(), checksum_offset)
                .await
                .expect("Failed to write incorrect checksum");
            let corrupted_item_position = 40 * ITEMS_PER_BLOB + ITEMS_PER_BLOB / 2;
            blob.close().await.expect("Failed to close blob");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");
            let err = journal.read(corrupted_item_position).await.unwrap_err();
            assert!(matches!(err, Error::ChecksumMismatch(x, _) if x == bad_checksum));

            // Replay all items, making sure the checksum mismatch error is handled correctly
            {
                let stream = journal.replay(10).await.expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                let mut error_count = 0;
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((position, item)) => {
                            assert_eq!(position, u64::from_be_bytes(item));
                            items.push(position);
                        }
                        Err(err) => {
                            error_count += 1;
                            assert!(matches!(err, Error::ChecksumMismatch(_, _)));
                        }
                    }
                }
                assert_eq!(error_count, 1);
                // Result will be missing only the one corrupted value.
                assert_eq!(
                    items.len(),
                    ITEMS_PER_BLOB as usize * 100 + ITEMS_PER_BLOB as usize / 2 - 1
                );
            }
            journal.close().await.expect("Failed to close journal");

            // Manually truncate one blob to force a partial-read error and make sure it's handled
            // as expected.
            let blob = context
                .open(&cfg.partition, &40u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // truncate the blob at the start of the corrupted checksum
            blob.truncate(checksum_offset)
                .await
                .expect("Failed to corrupt blob");
            blob.close().await.expect("Failed to close blob");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");
            let err = journal.read(corrupted_item_position).await.unwrap_err();
            assert!(matches!(err, Error::Runtime(_)));

            // Replay all items, making sure the partial read error is handled correctly
            {
                let stream = journal.replay(10).await.expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                let mut error_count = 0;
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((position, item)) => {
                            assert_eq!(position, u64::from_be_bytes(item));
                            items.push(position);
                        }
                        Err(err) => {
                            error_count += 1;
                            assert!(matches!(err, Error::Runtime(_)));
                        }
                    }
                }
                assert_eq!(error_count, 1);
                // Result will be missing the 4 items following the truncation
                assert_eq!(
                    items.len(),
                    ITEMS_PER_BLOB as usize * 100 + ITEMS_PER_BLOB as usize / 2 - 4
                );
            }

            // Delete a blob and make sure the gap is detected
            context
                .remove(&cfg.partition, Some(&40u64.to_be_bytes()))
                .await
                .expect("Failed to open blob");
            // Re-initialize the journal to simulate a restart
            let result = Journal::<_, _, 8>::init(context.clone(), cfg.clone()).await;
            assert!(matches!(result.err().unwrap(), Error::MissingBlob(n) if n == 40));
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_from_partial_write() {
        // Initialize the deterministic runtime
        let (executor, context, _) = Executor::default();

        // Start the test within the executor
        executor.start(async move {
            // Initialize the journal, allowing a max of 2 items per blob.
            let cfg = Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition: "test_partition".into(),
                items_per_blob: 2,
            };
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            for i in 0u32..4 {
                journal
                    .append(i.to_be_bytes())
                    .await
                    .expect("failed to append data");
            }
            assert_eq!(journal.size().await.unwrap(), 4);
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("tracked 2"));
            journal.close().await.expect("Failed to close journal");

            // Manually truncate most recent blob to simulate a partial write.
            let blob = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            let blob_len = blob.len().await.expect("Failed to get blob length");
            // truncate the most recent blob by 1 byte which corrupts the most recent item
            blob.truncate(blob_len - 1)
                .await
                .expect("Failed to corrupt blob");
            blob.close().await.expect("Failed to close blob");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::<_, _, 4>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");
            // the last corrupted item should get discarded
            assert_eq!(journal.size().await.unwrap(), 3);
            let mut buffer = String::new();
            encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
            assert!(buffer.contains("tracked 2"));
        });
    }
}
