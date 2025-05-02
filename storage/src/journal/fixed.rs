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
//! The `prune` method allows the `Journal` to prune blobs consisting entirely of items prior to a
//! given point in history.
//!
//! # Replay
//!
//! The `replay` method iterates over multiple blobs concurrently to support fast reading of all
//! unpruned items into memory.

use super::Error;
use bytes::BufMut;
use commonware_codec::{Codec, DecodeExt, FixedSize};
use commonware_runtime::{Blob, Error as RError, Metrics, Storage};
use commonware_utils::hex;
use futures::stream::{self, Stream, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use tracing::{debug, trace, warn};

/// Configuration for `Journal` storage.
#[derive(Clone)]
pub struct Config {
    /// The `commonware-runtime::Storage` partition to use for storing journal blobs.
    pub partition: String,

    /// The maximum number of journal items to store in each blob.
    ///
    /// Any unpruned historical blobs will contain exactly this number of items.
    /// Only the newest blob may contain fewer items.
    pub items_per_blob: u64,
}

/// Implementation of `Journal` storage.
pub struct Journal<E: Storage + Metrics, A> {
    context: E,
    cfg: Config,

    // Blobs are stored in a BTreeMap to ensure they are always iterated in order of their indices.
    // Invariants:
    // - Indices are consecutive and without gaps.
    // - There will always be at least one blob in the map.
    // - The most recent blob will never be completely full, but it may be empty.
    blobs: BTreeMap<u64, (E::Blob, u64)>,

    tracked: Gauge,
    synced: Counter,
    pruned: Counter,

    _array: PhantomData<A>,
}

impl<E: Storage + Metrics, A: Codec<Cfg = ()> + FixedSize> Journal<E, A> {
    const CHUNK_SIZE: usize = u32::SIZE + A::SIZE;
    const CHUNK_SIZE_U64: u64 = Self::CHUNK_SIZE as u64;

    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during initialization. The `replay` method can be
    /// used to iterate over all items in the `Journal`.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error> {
        // Iterate over blobs in partition
        let mut blobs = BTreeMap::new();
        let stored_blobs = match context.scan(&cfg.partition).await {
            Ok(blobs) => blobs,
            Err(RError::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };
        for name in stored_blobs {
            let blob = context
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
            let blob = context.open(&cfg.partition, &0u64.to_be_bytes()).await?;
            blobs.insert(0, blob);
        }

        // Initialize metrics
        let tracked = Gauge::default();
        let synced = Counter::default();
        let pruned = Counter::default();
        context.register("tracked", "Number of blobs", tracked.clone());
        context.register("synced", "Number of syncs", synced.clone());
        context.register("pruned", "Number of blobs pruned", pruned.clone());
        tracked.set(blobs.len() as i64);

        // truncate the last blob if it's not the expected length, which might happen from unclean
        // shutdown.
        let newest_blob_index = *blobs.keys().last().unwrap();
        let (newest_blob, len) = blobs.get_mut(&newest_blob_index).unwrap();
        if *len % Self::CHUNK_SIZE_U64 != 0 {
            warn!(
                blob = newest_blob_index,
                invalid_len = *len,
                "last blob len is not a multiple of item size, truncating"
            );
            *len -= *len % Self::CHUNK_SIZE_U64;
            newest_blob.truncate(*len).await?;
            newest_blob.sync().await?;
        }

        if *len == cfg.items_per_blob * Self::CHUNK_SIZE_U64 {
            warn!(
                blob = newest_blob_index,
                "blob is full, creating a new empty one"
            );
            let next_blob_index = newest_blob_index + 1;
            let next_blob = context
                .open(&cfg.partition, &next_blob_index.to_be_bytes())
                .await?;
            blobs.insert(next_blob_index, next_blob);
            tracked.inc();
        }

        Ok(Self {
            context,
            cfg,
            blobs,
            tracked,
            synced,
            pruned,

            _array: PhantomData,
        })
    }

    /// Sync any pending updates to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.synced.inc();
        let (newest_blob_index, (newest_blob, _)) = self.newest_blob();
        debug!(blob = newest_blob_index, "syncing blob");
        newest_blob.sync().await.map_err(Error::Runtime)
    }

    /// Return the total number of items in the journal, irrespective of pruning. The next value
    /// appended to the journal will be at this position.
    pub async fn size(&self) -> Result<u64, Error> {
        let (newest_blob_index, (_, len)) = self.newest_blob();
        assert_eq!(len % Self::CHUNK_SIZE_U64, 0);
        let items_in_blob = len / Self::CHUNK_SIZE_U64;
        Ok(items_in_blob + self.cfg.items_per_blob * newest_blob_index)
    }

    /// Append a new item to the journal. Return the item's position in the journal, or error if the
    /// operation fails.
    pub async fn append(&mut self, item: A) -> Result<u64, Error> {
        // Get the newest blob and its index
        let newest_blob_index = *self.blobs.keys().last().expect("no blobs found");
        let (newest_blob, len) = self
            .blobs
            .get_mut(&newest_blob_index)
            .expect("no blobs found");

        // There should always be room to append an item in the newest blob
        assert!(*len < self.cfg.items_per_blob * Self::CHUNK_SIZE_U64);
        assert_eq!(*len % Self::CHUNK_SIZE_U64, 0);
        let mut buf: Vec<u8> = Vec::with_capacity(Self::CHUNK_SIZE);
        let item = item.encode();
        let checksum = crc32fast::hash(&item);
        buf.extend_from_slice(&item);
        buf.put_u32(checksum);

        let item_pos = (*len / Self::CHUNK_SIZE_U64) + self.cfg.items_per_blob * newest_blob_index;
        newest_blob.write_at(&buf, *len).await?;
        trace!(blob = newest_blob_index, pos = item_pos, "appended item");
        *len += Self::CHUNK_SIZE_U64;

        if *len == self.cfg.items_per_blob * Self::CHUNK_SIZE_U64 {
            // Newest blob is now full so we need to create a new empty one to fulfill the invariant
            // that the newest blob always has room for a new element.
            let next_blob_index = newest_blob_index + 1;
            // Always sync the previous blob before creating a new one
            newest_blob.sync().await?;
            debug!(blob = next_blob_index, "creating next blob");
            let next_blob = self
                .context
                .open(&self.cfg.partition, &next_blob_index.to_be_bytes())
                .await?;
            assert!(self.blobs.insert(next_blob_index, next_blob).is_none());
            self.tracked.inc();
        }

        Ok(item_pos)
    }

    /// Rewind the journal to the given `journal_size`.
    ///
    /// The journal is not synced after rewinding.
    pub async fn rewind(&mut self, journal_size: u64) -> Result<(), Error> {
        let size = self.size().await?;
        match journal_size.cmp(&size) {
            std::cmp::Ordering::Greater => return Err(Error::InvalidRewind(journal_size)),
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Less => {}
        }
        let rewind_to_blob_index = journal_size / self.cfg.items_per_blob;
        if rewind_to_blob_index < *self.oldest_blob().0 {
            return Err(Error::InvalidRewind(journal_size));
        }
        let rewind_to_offset = (journal_size % self.cfg.items_per_blob) * Self::CHUNK_SIZE_U64;
        let mut current_blob_index = *self.newest_blob().0;

        // Remove blobs until we reach the rewind point.
        while current_blob_index > rewind_to_blob_index {
            let (blob, _) = match self.blobs.remove(&current_blob_index) {
                Some(blob) => blob,
                None => return Err(Error::MissingBlob(current_blob_index)),
            };
            blob.close().await?;
            self.context
                .remove(&self.cfg.partition, Some(&current_blob_index.to_be_bytes()))
                .await?;
            debug!(blob = current_blob_index, "unwound over blob");
            self.tracked.dec();
            current_blob_index -= 1;
        }

        // Truncate the rewind blob to the correct offset.
        let (rewind_blob, len) = match self.blobs.get_mut(&rewind_to_blob_index) {
            Some(blob) => blob,
            None => return Err(Error::MissingBlob(rewind_to_blob_index)),
        };
        rewind_blob.truncate(rewind_to_offset).await?;
        *len = rewind_to_offset;

        Ok(())
    }

    /// Return the position of the oldest item in the journal that remains readable.
    ///
    /// Note that this value could be older than the `min_item_pos` last passed to prune.
    pub async fn oldest_retained_pos(&self) -> Result<Option<u64>, Error> {
        let (oldest_blob_index, (_, len)) = self.oldest_blob();
        if *len == 0 {
            return Ok(None);
        }
        // The oldest retained item is the first item in the oldest blob.
        Ok(Some(*oldest_blob_index * self.cfg.items_per_blob))
    }

    /// Read the item at the given position in the journal.
    pub async fn read(&self, item_pos: u64) -> Result<A, Error> {
        let blob_index = item_pos / self.cfg.items_per_blob;

        let (blob, _) = match self.blobs.get(&blob_index) {
            Some(blob) => blob,
            None => {
                let (newest_blob_index, _) = self.newest_blob();
                if blob_index > *newest_blob_index {
                    return Err(Error::InvalidItem(item_pos));
                }
                let (oldest_blob_index, _) = self.oldest_blob();
                assert!(blob_index < *oldest_blob_index);
                return Err(Error::ItemPruned(item_pos));
            }
        };

        let item_index = item_pos % self.cfg.items_per_blob;
        let offset = item_index * Self::CHUNK_SIZE_U64;
        let mut buf = vec![0u8; Self::CHUNK_SIZE];
        blob.read_at(&mut buf, offset).await?;
        Self::verify_integrity(&buf)
    }

    /// Verify the integrity of the Array + checksum in `buf`, returning the array if it is valid.
    fn verify_integrity(buf: &[u8]) -> Result<A, Error> {
        let stored_checksum = u32::from_be_bytes(buf[A::SIZE..].try_into().unwrap());
        let checksum = crc32fast::hash(&buf[..A::SIZE]);
        if checksum != stored_checksum {
            return Err(Error::ChecksumMismatch(stored_checksum, checksum));
        }
        Ok(A::decode(&buf[..A::SIZE]).unwrap())
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
    ) -> Result<impl Stream<Item = Result<(u64, A), Error>> + '_, Error> {
        assert!(concurrency > 0);
        // Collect all blobs to replay
        let mut blobs = Vec::with_capacity(self.blobs.len());
        let (newest_blob_index, _) = self.newest_blob();
        for (index, (blob, len)) in self.blobs.iter() {
            let len = {
                if index == newest_blob_index {
                    *len
                } else {
                    self.cfg.items_per_blob * Self::CHUNK_SIZE_U64
                }
            };
            if len > 0 {
                blobs.push((index, blob, len));
            }
        }

        // Replay all blobs concurrently and stream items as they are read (to avoid occupying too
        // much memory with buffered data)
        let items_per_blob = self.cfg.items_per_blob;
        Ok(stream::iter(blobs)
            .map(move |(index, blob, len)| async move {
                stream::unfold(
                    (index, blob, 0u64),
                    move |(index, blob, offset)| async move {
                        // Check if we are at the end of the blob
                        if offset == len {
                            return None;
                        }
                        // Get next item
                        let mut buf = vec![0u8; Self::CHUNK_SIZE];
                        let item = blob.read_at(&mut buf, offset).await.map_err(Error::Runtime);
                        let next_offset = offset + Self::CHUNK_SIZE_U64;
                        match item {
                            Ok(_) => match Self::verify_integrity(&buf) {
                                Ok(item) => Some((
                                    Ok((
                                        items_per_blob * *index + offset / Self::CHUNK_SIZE_U64,
                                        item,
                                    )),
                                    (index, blob, next_offset),
                                )),
                                Err(err) => Some((Err(err), (index, blob, next_offset))),
                            },
                            Err(err) => Some((Err(err), (index, blob, len))),
                        }
                    },
                )
            })
            .buffer_unordered(concurrency)
            .flatten())
    }

    /// Return the blob containing the most recently appended items and its index.
    fn newest_blob(&self) -> (&u64, &(E::Blob, u64)) {
        self.blobs.last_key_value().expect("no blobs found")
    }

    /// Return the blob containing the oldest retained items and its index.
    fn oldest_blob(&self) -> (&u64, &(E::Blob, u64)) {
        self.blobs.first_key_value().expect("no blobs found")
    }

    /// Allow the journal to prune items older than `min_item_pos`. The journal may not prune all
    /// such items in order to preserve blob boundaries, but the amount of such items will always be
    /// less than the configured number of items per blob. The result will contain the actual
    /// pruning position.
    ///
    /// Note that this operation may NOT be atomic, however it's guaranteed not to leave gaps in the
    /// event of failure as items are always pruned in order from oldest to newest.
    pub async fn prune(&mut self, min_item_pos: u64) -> Result<u64, Error> {
        let (oldest_blob_index, _) = self.oldest_blob();
        let mut new_oldest_blob = min_item_pos / self.cfg.items_per_blob;
        if new_oldest_blob <= *oldest_blob_index {
            // nothing to prune
            return Ok(new_oldest_blob * self.cfg.items_per_blob);
        }
        // Make sure we never prune the most recent blob
        let (newest_blob_index, _) = self.newest_blob();
        new_oldest_blob = std::cmp::min(new_oldest_blob, *newest_blob_index);

        for index in *oldest_blob_index..new_oldest_blob {
            let (blob, _) = self.blobs.remove(&index).unwrap();
            // Close the blob and remove it from storage
            blob.close().await?;
            self.context
                .remove(&self.cfg.partition, Some(&index.to_be_bytes()))
                .await?;
            debug!(blob = index, "pruned blob");
            self.pruned.inc();
            self.tracked.dec();
        }

        Ok(new_oldest_blob * self.cfg.items_per_blob)
    }

    /// Closes all open sections.
    pub async fn close(self) -> Result<(), Error> {
        for (i, (blob, _)) in self.blobs.into_iter() {
            blob.close().await?;
            debug!(blob = i, "closed blob");
        }
        Ok(())
    }

    /// Close and remove any underlying blobs created by the journal.
    pub async fn destroy(self) -> Result<(), Error> {
        for (i, (blob, _)) in self.blobs.into_iter() {
            blob.close().await?;
            debug!(blob = i, "destroyed blob");
            self.context
                .remove(&self.cfg.partition, Some(&i.to_be_bytes()))
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{hash, sha256::Digest};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Blob, Runner, Storage};
    use futures::{pin_mut, StreamExt};

    /// Generate a SHA-256 digest for the given value.
    fn test_digest(value: u64) -> Digest {
        hash(&value.to_be_bytes())
    }

    #[test_traced]
    fn test_fixed_journal_append_and_prune() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 2 items per blob.
            let cfg = Config {
                partition: "test_partition".into(),
                items_per_blob: 2,
            };
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            let buffer = context.encode();
            assert!(buffer.contains("tracked 1"));

            // Append an item to the journal
            let mut pos = journal
                .append(test_digest(0))
                .await
                .expect("failed to append data 0");
            assert_eq!(pos, 0);

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Re-initialize the journal to simulate a restart
            let cfg = Config {
                partition: "test_partition".into(),
                items_per_blob: 2,
            };
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-initialize journal");

            // Append two more items to the journal to trigger a new blob creation
            pos = journal
                .append(test_digest(1))
                .await
                .expect("failed to append data 1");
            assert_eq!(pos, 1);
            pos = journal
                .append(test_digest(2))
                .await
                .expect("failed to append data 2");
            assert_eq!(pos, 2);
            let buffer = context.encode();
            assert!(buffer.contains("tracked 2"));

            // Read the items back
            let item0 = journal.read(0).await.expect("failed to read data 0");
            assert_eq!(item0, test_digest(0));
            let item1 = journal.read(1).await.expect("failed to read data 1");
            assert_eq!(item1, test_digest(1));
            let item2 = journal.read(2).await.expect("failed to read data 2");
            assert_eq!(item2, test_digest(2));
            let err = journal.read(3).await.expect_err("expected read to fail");
            assert!(matches!(err, Error::Runtime(_)));
            let err = journal.read(400).await.expect_err("expected read to fail");
            assert!(matches!(err, Error::InvalidItem(x) if x == 400));

            // Sync the journal
            journal.sync().await.expect("failed to sync journal");
            let buffer = context.encode();
            assert!(buffer.contains("synced_total 1"));

            // Pruning to 1 should be a no-op because there's no blob with only older items.
            journal.prune(1).await.expect("failed to prune journal 1");
            let buffer = context.encode();
            assert!(buffer.contains("tracked 2"));

            // Pruning to 2 should allow the first blob to be pruned.
            journal.prune(2).await.expect("failed to prune journal 2");
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), Some(2));
            let buffer = context.encode();
            assert!(buffer.contains("tracked 1"));
            assert!(buffer.contains("pruned_total 1"));

            // Reading from the first blob should fail since it's now pruned
            let result0 = journal.read(0).await;
            assert!(matches!(result0, Err(Error::ItemPruned(0))));
            let result1 = journal.read(1).await;
            assert!(matches!(result1, Err(Error::ItemPruned(1))));

            // Third item should still be readable
            let result2 = journal.read(2).await.unwrap();
            assert_eq!(result2, test_digest(2));

            // Should be able to continue to append items
            for i in 3..10 {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }

            // Check no-op pruning
            journal.prune(0).await.expect("no-op pruning failed");
            assert_eq!(*journal.oldest_blob().0, 1);
            assert_eq!(*journal.newest_blob().0, 5);
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), Some(2));

            // Prune first 3 blobs (6 items)
            journal
                .prune(3 * cfg.items_per_blob)
                .await
                .expect("failed to prune journal 2");
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), Some(6));
            let buffer = context.encode();
            assert_eq!(*journal.oldest_blob().0, 3);
            assert_eq!(*journal.newest_blob().0, 5);
            assert!(buffer.contains("tracked 3"));
            assert!(buffer.contains("pruned_total 3"));

            // Try pruning (more than) everything in the journal.
            journal
                .prune(10000)
                .await
                .expect("failed to max-prune journal");
            let buffer = context.encode();
            let size = journal.size().await.unwrap();
            assert_eq!(size, 10);
            assert_eq!(*journal.oldest_blob().0, 5);
            assert_eq!(*journal.newest_blob().0, 5);
            assert!(buffer.contains("tracked 1"));
            assert!(buffer.contains("pruned_total 5"));
            // Since the size of the journal is currently a multiple of items_per_blob, the newest blob
            // will be empty, and there will be no retained items.
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), None);

            let stream = journal.replay(1).await.expect("failed to replay journal");
            pin_mut!(stream);
            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                match result {
                    Ok((pos, item)) => {
                        assert_eq!(test_digest(pos), item);
                        items.push(pos);
                    }
                    Err(err) => panic!("Failed to read item: {}", err),
                }
            }
            assert_eq!(items, Vec::<u64>::new());
        });
    }

    #[test_traced]
    fn test_fixed_journal_replay() {
        const ITEMS_PER_BLOB: u64 = 7;
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = Config {
                partition: "test_partition".into(),
                items_per_blob: ITEMS_PER_BLOB,
            };
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append many items, filling 100 blobs and part of the 101st
            for i in 0u64..(ITEMS_PER_BLOB * 100 + ITEMS_PER_BLOB / 2) {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }

            let buffer = context.encode();
            assert!(buffer.contains("tracked 101"));

            // Replay should return all items
            {
                let stream = journal.replay(10).await.expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert_eq!(test_digest(pos), item);
                            items.push(pos);
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
                for (i, pos) in items.iter().enumerate() {
                    assert_eq!(i as u64, *pos);
                }
            }
            journal.close().await.expect("Failed to close journal");

            // Corrupt one of the checksums and make sure it's detected.
            let checksum_offset =
                Digest::SIZE as u64 + (ITEMS_PER_BLOB / 2) * (Digest::SIZE + u32::SIZE) as u64;
            let (blob, _) = context
                .open(&cfg.partition, &40u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // Write incorrect checksum
            let bad_checksum = 123456789u32;
            blob.write_at(&bad_checksum.to_be_bytes(), checksum_offset)
                .await
                .expect("Failed to write incorrect checksum");
            let corrupted_item_pos = 40 * ITEMS_PER_BLOB + ITEMS_PER_BLOB / 2;
            blob.close().await.expect("Failed to close blob");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");
            let err = journal.read(corrupted_item_pos).await.unwrap_err();
            assert!(matches!(err, Error::ChecksumMismatch(x, _) if x == bad_checksum));

            // Replay all items, making sure the checksum mismatch error is handled correctly
            {
                let stream = journal.replay(10).await.expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                let mut error_count = 0;
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert_eq!(test_digest(pos), item);
                            items.push(pos);
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
            let (blob, _) = context
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
            let err = journal.read(corrupted_item_pos).await.unwrap_err();
            assert!(matches!(err, Error::Runtime(_)));

            // Replay all items, making sure the partial read error is handled correctly
            {
                let stream = journal.replay(10).await.expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                let mut error_count = 0;
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert_eq!(test_digest(pos), item);
                            items.push(pos);
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
                .expect("Failed to remove blob");
            // Re-initialize the journal to simulate a restart
            let result = Journal::<_, Digest>::init(context.clone(), cfg.clone()).await;
            assert!(matches!(result.err().unwrap(), Error::MissingBlob(n) if n == 40));
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_from_partial_write() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 2 items per blob.
            let cfg = Config {
                partition: "test_partition".into(),
                items_per_blob: 3,
            };
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            for i in 0..5 {
                journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            assert_eq!(journal.size().await.unwrap(), 5);
            let buffer = context.encode();
            assert!(buffer.contains("tracked 2"));
            journal.close().await.expect("Failed to close journal");

            // Manually truncate most recent blob to simulate a partial write.
            let (blob, len) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // truncate the most recent blob by 1 byte which corrupts the most recent item
            blob.truncate(len - 1)
                .await
                .expect("Failed to corrupt blob");
            blob.close().await.expect("Failed to close blob");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");
            // the last corrupted item should get discarded
            assert_eq!(journal.size().await.unwrap(), 4);
            let buffer = context.encode();
            assert!(buffer.contains("tracked 2"));
            journal.close().await.expect("Failed to close journal");

            // Delete the last blob to simulate a sync() that wrote the last blob at the point it
            // was entirely full, but a crash happened before the next empty blob could be created.
            context
                .remove(&cfg.partition, Some(&1u64.to_be_bytes()))
                .await
                .expect("Failed to remove blob");
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");
            assert_eq!(journal.size().await.unwrap(), 3);
            let buffer = context.encode();
            assert!(buffer.contains("tracked 2"));
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_to_empty_from_partial_write() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 10 items per blob.
            let cfg = Config {
                partition: "test_partition".into(),
                items_per_blob: 10,
            };
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            // Add only a single item
            journal
                .append(test_digest(0))
                .await
                .expect("failed to append data");
            assert_eq!(journal.size().await.unwrap(), 1);
            journal.close().await.expect("Failed to close journal");

            // Manually truncate most recent blob to simulate a partial write.
            let (blob, len) = context
                .open(&cfg.partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // truncate the most recent blob by 1 byte which corrupts the one appended item
            blob.truncate(len - 1)
                .await
                .expect("Failed to corrupt blob");
            blob.close().await.expect("Failed to close blob");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Since there was only a single item appended which we then corrupted, recovery should
            // leave us in the state of an empty journal.
            assert_eq!(journal.size().await.unwrap(), 0);
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), None);
            // Make sure journal still works for appending.
            journal
                .append(test_digest(0))
                .await
                .expect("failed to append data");
            assert_eq!(journal.size().await.unwrap(), 1);
        });
    }

    #[test_traced]
    fn test_fixed_journal_rewinding() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 2 items per blob.
            let cfg = Config {
                partition: "test_partition".into(),
                items_per_blob: 2,
            };
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            assert!(matches!(journal.rewind(0).await, Ok(())));
            assert!(matches!(
                journal.rewind(1).await,
                Err(Error::InvalidRewind(1))
            ));

            // Append an item to the journal
            journal
                .append(test_digest(0))
                .await
                .expect("failed to append data 0");
            assert_eq!(journal.size().await.unwrap(), 1);
            assert!(matches!(journal.rewind(1).await, Ok(()))); // should be no-op
            assert!(matches!(journal.rewind(0).await, Ok(())));
            assert_eq!(journal.size().await.unwrap(), 0);

            // append 7 items
            for i in 0..7 {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }
            let buffer = context.encode();
            assert!(buffer.contains("tracked 4"));
            assert_eq!(journal.size().await.unwrap(), 7);

            // rewind back to item #4, which should prune 2 blobs
            assert!(matches!(journal.rewind(4).await, Ok(())));
            assert_eq!(journal.size().await.unwrap(), 4);
            let buffer = context.encode();
            assert!(buffer.contains("tracked 3"));

            // rewind back to empty and ensure all blobs are rewound over
            assert!(matches!(journal.rewind(0).await, Ok(())));
            let buffer = context.encode();
            assert!(buffer.contains("tracked 1"));
            assert_eq!(journal.size().await.unwrap(), 0);

            // stress test: add 100 items, rewind 49, repeat x10.
            for _ in 0..10 {
                for i in 0..100 {
                    journal
                        .append(test_digest(i))
                        .await
                        .expect("failed to append data");
                }
                journal
                    .rewind(journal.size().await.unwrap() - 49)
                    .await
                    .unwrap();
            }
            const ITEMS_REMAINING: u64 = 10 * (100 - 49);
            assert_eq!(journal.size().await.unwrap(), ITEMS_REMAINING);

            journal.close().await.expect("Failed to close journal");

            // Repeat with a different blob size (3 items per blob)
            let cfg = Config {
                partition: "test_partition_2".into(),
                items_per_blob: 3,
            };
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            for _ in 0..10 {
                for i in 0..100 {
                    journal
                        .append(test_digest(i))
                        .await
                        .expect("failed to append data");
                }
                journal
                    .rewind(journal.size().await.unwrap() - 49)
                    .await
                    .unwrap();
            }
            assert_eq!(journal.size().await.unwrap(), ITEMS_REMAINING);

            journal.close().await.expect("Failed to close journal");

            // Make sure re-opened journal is as expected
            let mut journal: Journal<_, Digest> = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            assert_eq!(journal.size().await.unwrap(), 10 * (100 - 49));

            // Make sure rewinding works after pruning
            journal.prune(300).await.expect("pruning failed");
            assert_eq!(journal.size().await.unwrap(), ITEMS_REMAINING);
            // Rewinding prior to our prune point should fail.
            assert!(matches!(
                journal.rewind(299).await,
                Err(Error::InvalidRewind(299))
            ));
            // Rewinding to the prune point should work.
            // always remain in the journal.
            assert!(matches!(journal.rewind(300).await, Ok(())));
            assert_eq!(journal.size().await.unwrap(), 300);
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), None);
        });
    }
}
