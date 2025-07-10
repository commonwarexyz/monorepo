//! An append-only log for storing fixed length items on disk.
//!
//! In addition to replay, stored items can be fetched directly by their `position` in the journal,
//! where position is defined as the item's order of insertion starting from 0, unaffected by
//! pruning.
//!
//! _See [crate::journal::variable] for a journal that supports variable length items._
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
//! The `replay` method supports fast reading of all unpruned items into memory.

use super::Error;
use bytes::BufMut;
use commonware_codec::{Codec, DecodeExt, FixedSize};
use commonware_runtime::{
    buffer::{Append, PoolRef, Read},
    Blob, Error as RError, Metrics, Storage,
};
use commonware_utils::hex;
use futures::{
    future::try_join_all,
    stream::{self, Stream},
    StreamExt,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::{collections::BTreeMap, marker::PhantomData};
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

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: usize,
}

/// Implementation of `Journal` storage.
pub struct Journal<E: Storage + Metrics, A> {
    context: E,
    cfg: Config,

    /// Stores the historical blobs. A BTreeMap allows iterating over them from oldest to newest.
    ///
    /// # Invariants
    ///
    /// - Indices are consecutive and without gaps.
    /// - Contains only full blobs.
    /// - Never contains the most recent blob.
    blobs: BTreeMap<u64, Append<E::Blob>>,

    /// The most recent blob.
    ///
    /// # Invariant
    ///
    /// Always has room for at least one more item (and may be empty).
    tail: Append<E::Blob>,

    /// The index of the most recent blob.
    tail_index: u64,

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
    ///
    /// # Repair
    ///
    /// Like [sqlite](https://github.com/sqlite/sqlite/blob/8658a8df59f00ec8fcfea336a2a6a4b5ef79d2ee/src/wal.c#L1504-L1505)
    /// and [rocksdb](https://github.com/facebook/rocksdb/blob/0c533e61bc6d89fdf1295e8e0bcee4edb3aef401/include/rocksdb/options.h#L441-L445),
    /// the first invalid data read will be considered the new end of the journal (and the underlying [Blob] will be truncated to the last
    /// valid item).
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error> {
        // Iterate over blobs in partition
        let mut blobs = BTreeMap::new();
        let stored_blobs = match context.scan(&cfg.partition).await {
            Ok(blobs) => blobs,
            Err(RError::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };
        for name in stored_blobs {
            let (blob, size) = context
                .open(&cfg.partition, &name)
                .await
                .map_err(Error::Runtime)?;
            let index = match name.try_into() {
                Ok(index) => u64::from_be_bytes(index),
                Err(nm) => return Err(Error::InvalidBlobName(hex(&nm))),
            };
            debug!(blob = index, size, "loaded blob");
            blobs.insert(index, (blob, size));
        }

        // Check that there are no gaps in the historical blobs and that they are all full.
        let full_size = cfg.items_per_blob * Self::CHUNK_SIZE_U64;
        if !blobs.is_empty() {
            let mut it = blobs.keys().rev();
            let mut prev_index = *it.next().unwrap();
            for index in it {
                let (_, size) = blobs.get(index).unwrap();
                if *index != prev_index - 1 {
                    return Err(Error::MissingBlob(prev_index - 1));
                }
                prev_index = *index;
                if *size != full_size {
                    // Non-final blobs that have invalid sizes are not recoverable.
                    return Err(Error::InvalidBlobSize(*index, *size));
                }
            }
        } else {
            debug!("no blobs found");
            let (blob, size) = context.open(&cfg.partition, &0u64.to_be_bytes()).await?;
            assert_eq!(size, 0);
            blobs.insert(0, (blob, size));
        }

        // Initialize metrics.
        let tracked = Gauge::default();
        let synced = Counter::default();
        let pruned = Counter::default();
        context.register("tracked", "Number of blobs", tracked.clone());
        context.register("synced", "Number of syncs", synced.clone());
        context.register("pruned", "Number of blobs pruned", pruned.clone());
        tracked.set(blobs.len() as i64);

        // Initialize the tail blob.
        let (mut tail_index, (mut tail, mut tail_size)) = blobs.pop_last().unwrap();

        // Trim invalid items from the tail blob.
        tail_size = Self::trim_tail(&tail, tail_size, tail_index).await?;
        if tail_size > full_size {
            return Err(Error::InvalidBlobSize(tail_index, tail_size));
        }

        // If the tail blob is full we need to start a new one to maintain its invariant that there
        // is always room for another item.
        if tail_size == full_size {
            warn!(
                blob = tail_index,
                "tail blob is full, creating a new empty one"
            );
            blobs.insert(tail_index, (tail, tail_size));
            tail_index += 1;
            (tail, tail_size) = context
                .open(&cfg.partition, &tail_index.to_be_bytes())
                .await?;
            assert_eq!(tail_size, 0);
            tracked.inc();
        }

        // Wrap all blobs with Append wrappers.
        // TODO(https://github.com/commonwarexyz/monorepo/issues/1219): Consider creating an
        // Immutable wrapper which doesn't allocate a write buffer for these.
        let blobs = try_join_all(blobs.into_iter().map(|(index, (blob, size))| {
            let pool = cfg.buffer_pool.clone();
            async move {
                let blob = Append::new(blob, size, cfg.write_buffer, pool).await?;
                Ok::<_, Error>((index, (blob, size)))
            }
        }))
        .await?;
        let tail = Append::new(tail, tail_size, cfg.write_buffer, cfg.buffer_pool.clone()).await?;

        Ok(Self {
            context,
            cfg,
            blobs: blobs
                .into_iter()
                .map(|(index, (blob, _))| (index, blob))
                .collect(),
            tail,
            tail_index,
            tracked,
            synced,
            pruned,
            _array: PhantomData,
        })
    }

    /// Initialize a new [Journal] instance in an empty, pruned state.
    ///
    /// # Arguments
    /// * `context` - The storage context
    /// * `cfg` - Configuration for the journal
    /// * `num_pruned` - The number of operations that have been pruned.
    ///
    /// # Behavior
    /// 1. Removes all existing blobs in the partition
    /// 2. Creates only the tail blob at the index that would contain the operation at `num_pruned`
    /// 3. Sets the tail blob size to represent the "leftover" operations within that blob.
    ///    The [Journal] is not `sync`ed before being returned.
    ///
    /// For example, if `items_per_blob = 10` and `num_pruned = 25`:
    /// - Tail blob index would be 25 / 10 = 2 (third blob, 0-indexed)
    /// - Tail blob size would be (25 % 10) * CHUNK_SIZE = 5 * CHUNK_SIZE
    /// - Tail blob is filled with dummy data up to its size -- this shouldn't be read.
    /// - No blobs are created for indices 0 and 1 (the pruned range)
    /// - Reading from positions 0-19 will return `ItemPruned` since those blobs don't exist
    /// - This represents a journal that had operations 0-24, with operations 0-19 pruned,
    ///   leaving operations 20-24 in tail blob 2.
    pub(crate) async fn init_pruned(
        context: E,
        cfg: Config,
        num_pruned: u64,
    ) -> Result<Self, Error> {
        // Remove all existing blobs
        match context.scan(&cfg.partition).await {
            Ok(blobs) => {
                for blob_name in blobs {
                    context
                        .remove(&cfg.partition, Some(&blob_name))
                        .await
                        .map_err(Error::Runtime)?;
                    debug!(
                        blob_name = hex(&blob_name),
                        "removed existing blob during pruned init"
                    );
                }
            }
            Err(RError::PartitionMissing(_)) => {}
            Err(err) => return Err(Error::Runtime(err)),
        }

        // Calculate the tail blob index and number of items in the tail
        let tail_index = num_pruned / cfg.items_per_blob;
        let tail_items = num_pruned % cfg.items_per_blob;
        let tail_size = tail_items * Self::CHUNK_SIZE_U64;
        debug!(
            tail_index,
            tail_items, tail_size, "initializing journal in pruned state"
        );

        // Create the tail blob with the correct size
        let (tail_blob, tail_actual_size) = context
            .open(&cfg.partition, &tail_index.to_be_bytes())
            .await
            .map_err(Error::Runtime)?;
        assert_eq!(tail_actual_size, 0, "we just emptied all blobs");
        let tail = Append::new(tail_blob, 0, cfg.write_buffer, cfg.buffer_pool.clone()).await?;
        if tail_items > 0 {
            tail.resize(tail_size).await.map_err(Error::Runtime)?;
        }

        // Initialize metrics
        let tracked = Gauge::default();
        tracked.set(tail_index as i64 + 1);
        let synced = Counter::default();
        let pruned = Counter::default();
        context.register("tracked", "Number of blobs", tracked.clone());
        context.register("synced", "Number of syncs", synced.clone());
        context.register("pruned", "Number of blobs pruned", pruned.clone());

        Ok(Self {
            context,
            cfg,
            blobs: BTreeMap::new(),
            tail,
            tail_index,
            tracked,
            synced,
            pruned,
            _array: PhantomData,
        })
    }

    /// Trim any invalid data found at the end of the tail blob and return the new size. The new
    /// size will be less than or equal to the originally provided size, and a multiple of the item
    /// size.
    async fn trim_tail(
        tail: &<E as Storage>::Blob,
        mut tail_size: u64,
        tail_index: u64,
    ) -> Result<u64, Error> {
        let mut truncated = false;
        if !tail_size.is_multiple_of(Self::CHUNK_SIZE_U64) {
            warn!(
                blob = tail_index,
                invalid_size = tail_size,
                "last blob size is not a multiple of item size, truncating"
            );
            tail_size -= tail_size % Self::CHUNK_SIZE_U64;
            tail.resize(tail_size).await?;
            truncated = true;
        }

        // Truncate any records with failing checksums. This can happen if the file system allocated
        // extra space for a blob but there was a crash before any data was written to that space.
        while tail_size > 0 {
            let offset = tail_size - Self::CHUNK_SIZE_U64;
            let read = tail.read_at(vec![0u8; Self::CHUNK_SIZE], offset).await?;
            match Self::verify_integrity(read.as_ref()) {
                Ok(_) => break, // Valid item found, we can stop truncating.
                Err(Error::ChecksumMismatch(_, _)) => {
                    warn!(blob = tail_index, offset, "checksum mismatch: truncating",);
                    tail_size -= Self::CHUNK_SIZE_U64;
                    tail.resize(tail_size).await?;
                    truncated = true;
                }
                Err(err) => return Err(err),
            }
        }

        // If we truncated the blob, make sure to sync it.
        if truncated {
            tail.sync().await?;
        }

        Ok(tail_size)
    }

    /// Sync any pending updates to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.synced.inc();
        debug!(blob = self.tail_index, "syncing blob");
        self.tail.sync().await.map_err(Error::Runtime)
    }

    /// Return the total number of items in the journal, irrespective of pruning. The next value
    /// appended to the journal will be at this position.
    pub async fn size(&self) -> Result<u64, Error> {
        let size = self.tail.size().await;
        assert_eq!(size % Self::CHUNK_SIZE_U64, 0);
        let items_in_blob = size / Self::CHUNK_SIZE_U64;
        Ok(items_in_blob + self.cfg.items_per_blob * self.tail_index)
    }

    /// Append a new item to the journal. Return the item's position in the journal, or error if the
    /// operation fails.
    pub async fn append(&mut self, item: A) -> Result<u64, Error> {
        // There should always be room to append an item in the newest blob
        let mut size = self.tail.size().await;
        assert!(size < self.cfg.items_per_blob * Self::CHUNK_SIZE_U64);
        assert_eq!(size % Self::CHUNK_SIZE_U64, 0);
        let mut buf: Vec<u8> = Vec::with_capacity(Self::CHUNK_SIZE);
        let item = item.encode();
        let checksum = crc32fast::hash(&item);
        buf.extend_from_slice(&item);
        buf.put_u32(checksum);

        // Write the item to the blob
        let item_pos = (size / Self::CHUNK_SIZE_U64) + self.cfg.items_per_blob * self.tail_index;
        self.tail.append(buf).await?;
        trace!(blob = self.tail_index, pos = item_pos, "appended item");
        size += Self::CHUNK_SIZE_U64;

        // If the tail blob is now full we need to create a new empty one to fulfill the invariant
        // that the tail blob always has room for a new element.
        if size == self.cfg.items_per_blob * Self::CHUNK_SIZE_U64 {
            // Sync the tail blob before creating a new one so if we crash we don't end up with a
            // non-full historical blob.
            self.tail.sync().await?;

            // Create a new empty blob.
            let next_blob_index = self.tail_index + 1;
            debug!(blob = next_blob_index, "creating next blob");
            let (next_blob, size) = self
                .context
                .open(&self.cfg.partition, &next_blob_index.to_be_bytes())
                .await?;
            assert_eq!(size, 0);
            let next_blob = Append::new(
                next_blob,
                size,
                self.cfg.write_buffer,
                self.cfg.buffer_pool.clone(),
            )
            .await?;
            self.tracked.inc();

            // Move the old tail blob to the historical blobs map and set the new blob as the tail.
            let old_tail = std::mem::replace(&mut self.tail, next_blob);
            assert!(self.blobs.insert(self.tail_index, old_tail).is_none());
            self.tail_index = next_blob_index;
        }

        Ok(item_pos)
    }

    /// Rewind the journal to the given `size`. Returns [Error::MissingBlob] if the rewind
    /// point precedes the oldest retained element point. The journal is not synced after rewinding.
    ///
    /// Note that this operation is not atomic, but it will always leave the journal in a consistent
    /// state in the event of failure since blobs are always removed from newest to oldest.
    pub async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        match size.cmp(&self.size().await?) {
            std::cmp::Ordering::Greater => return Err(Error::InvalidRewind(size)),
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Less => {}
        }
        let rewind_to_blob_index = size / self.cfg.items_per_blob;
        if rewind_to_blob_index < self.oldest_blob_index() {
            return Err(Error::InvalidRewind(size));
        }
        let rewind_to_offset = (size % self.cfg.items_per_blob) * Self::CHUNK_SIZE_U64;

        // Remove blobs until we reach the rewind point.  Blobs must be removed in reverse order to
        // preserve consistency in the event of failures.
        while rewind_to_blob_index < self.tail_index {
            let (blob_index, mut new_tail) = self.blobs.pop_last().unwrap();
            assert_eq!(blob_index, self.tail_index - 1);
            std::mem::swap(&mut self.tail, &mut new_tail);
            self.remove_blob(self.tail_index, new_tail).await?;
            self.tail_index -= 1;
        }

        // Truncate the tail blob to the correct offset.
        self.tail.resize(rewind_to_offset).await?;

        Ok(())
    }

    /// Return the position of the oldest item in the journal that remains readable.
    ///
    /// Note that this value could be older than the `min_item_pos` last passed to prune.
    pub async fn oldest_retained_pos(&self) -> Result<Option<u64>, Error> {
        let oldest_blob_index = self.oldest_blob_index();
        if oldest_blob_index == self.tail_index && self.tail.size().await == 0 {
            return Ok(None);
        }

        // The oldest retained item is the first item in the oldest blob.
        Ok(Some(oldest_blob_index * self.cfg.items_per_blob))
    }

    /// Read the item at the given position in the journal.
    pub async fn read(&self, item_pos: u64) -> Result<A, Error> {
        let blob_index = item_pos / self.cfg.items_per_blob;
        if blob_index > self.tail_index {
            return Err(Error::InvalidItem(item_pos));
        }

        let blob = if blob_index == self.tail_index {
            &self.tail
        } else {
            self.blobs
                .get(&blob_index)
                .ok_or(Error::ItemPruned(item_pos))?
        };

        let offset = (item_pos % self.cfg.items_per_blob) * Self::CHUNK_SIZE_U64;
        let read = blob.read_at(vec![0u8; Self::CHUNK_SIZE], offset).await?;
        Self::verify_integrity(read.as_ref())
    }

    /// Verify the integrity of the Array + checksum in `buf`, returning:
    /// - The array if it is valid,
    /// - Error::ChecksumMismatch if the checksum is invalid, or
    /// - Error::Codec if the array could not be decoded after passing the checksum check.
    ///
    ///  Error::Codec likely indicates a logic error rather than a corruption issue.
    fn verify_integrity(buf: &[u8]) -> Result<A, Error> {
        let stored_checksum = u32::from_be_bytes(buf[A::SIZE..].try_into().unwrap());
        let checksum = crc32fast::hash(&buf[..A::SIZE]);
        if checksum != stored_checksum {
            return Err(Error::ChecksumMismatch(stored_checksum, checksum));
        }
        A::decode(&buf[..A::SIZE]).map_err(Error::Codec)
    }

    /// Returns an ordered stream of all items in the journal with position >= `start_pos`.
    ///
    /// # Errors
    ///
    /// `Error::InvalidItem` if `start_pos` is greater than the journal size.
    ///
    /// # Integrity
    ///
    /// If any corrupted data is found, the stream will return an error.
    pub async fn replay(
        &self,
        buffer: usize,
        start_pos: u64,
    ) -> Result<impl Stream<Item = Result<(u64, A), Error>> + '_, Error> {
        if start_pos > self.size().await? {
            return Err(Error::InvalidItem(start_pos));
        }

        // Collect all blobs to replay paired with their index.
        let start_blob = start_pos / self.cfg.items_per_blob;
        assert!(start_blob <= self.tail_index);
        let blobs = self.blobs.range(start_blob..).collect::<Vec<_>>();
        let full_size = self.cfg.items_per_blob * Self::CHUNK_SIZE_U64;
        let mut blob_plus = blobs
            .into_iter()
            .map(|(blob_index, blob)| (*blob_index, blob.clone_blob(), full_size))
            .collect::<Vec<_>>();

        // Include the tail blob.
        self.tail.sync().await?; // make sure no data is buffered
        let tail_size = self.tail.size().await;
        blob_plus.push((self.tail_index, self.tail.clone_blob(), tail_size));
        let items_per_blob = self.cfg.items_per_blob;
        let start_offset = (start_pos % items_per_blob) * Self::CHUNK_SIZE_U64;

        // Replay all blobs in order and stream items as they are read (to avoid occupying too much
        // memory with buffered data).
        let stream = stream::iter(blob_plus).flat_map(move |(blob_index, blob, size)| {
            // Create a new reader and buffer for each blob. Preallocating the buffer here to avoid
            // a per-iteration allocation improves performance by ~20%.
            let mut reader = Read::new(blob, size, buffer);
            let buf = vec![0u8; Self::CHUNK_SIZE];
            let initial_offset = if blob_index == start_blob {
                // If this is the very first blob then we need to seek to the starting position.
                reader.seek_to(start_offset).expect("invalid start_pos");
                start_offset
            } else {
                0
            };

            stream::unfold(
                (buf, reader, initial_offset),
                move |(mut buf, mut reader, offset)| async move {
                    if offset >= reader.blob_size() {
                        return None;
                    }

                    // Even though we are reusing the buffer, `read_exact` will overwrite any
                    // previous data, so there's no need to explicitly clear it.
                    let item_pos = items_per_blob * blob_index + offset / Self::CHUNK_SIZE_U64;
                    match reader.read_exact(&mut buf, Self::CHUNK_SIZE).await {
                        Ok(()) => {
                            let next_offset = offset + Self::CHUNK_SIZE_U64;
                            let result = Self::verify_integrity(&buf).map(|item| (item_pos, item));
                            if result.is_err() {
                                debug!("corrupted item at {item_pos}");
                            }
                            Some((result, (buf, reader, next_offset)))
                        }
                        Err(err) => Some((Err(Error::Runtime(err)), (buf, reader, size))),
                    }
                },
            )
        });

        Ok(stream)
    }

    /// Return the index of blob containing the oldest retained items.
    fn oldest_blob_index(&self) -> u64 {
        if self.blobs.is_empty() {
            self.tail_index
        } else {
            *self.blobs.first_key_value().unwrap().0
        }
    }

    /// Allow the journal to prune items older than `min_item_pos`. The journal may not prune all
    /// such items in order to preserve blob boundaries, but the amount of such items will always be
    /// less than the configured number of items per blob.
    ///
    /// Note that this operation may NOT be atomic, however it's guaranteed not to leave gaps in the
    /// event of failure as items are always pruned in order from oldest to newest.
    pub async fn prune(&mut self, min_item_pos: u64) -> Result<(), Error> {
        let oldest_blob_index = self.oldest_blob_index();
        let new_oldest_blob =
            std::cmp::min(min_item_pos / self.cfg.items_per_blob, self.tail_index);

        for index in oldest_blob_index..new_oldest_blob {
            let blob = self.blobs.remove(&index).unwrap();
            self.remove_blob(index, blob).await?;
            self.pruned.inc();
        }

        Ok(())
    }

    /// Safely removes any previously tracked blob from underlying storage.
    async fn remove_blob(&mut self, index: u64, blob: Append<E::Blob>) -> Result<(), Error> {
        blob.close().await?;
        self.context
            .remove(&self.cfg.partition, Some(&index.to_be_bytes()))
            .await?;
        debug!(blob = index, "removed blob");
        self.tracked.dec();

        Ok(())
    }

    /// Closes all open sections.
    pub async fn close(self) -> Result<(), Error> {
        for (i, blob) in self.blobs.into_iter() {
            blob.close().await?;
            debug!(blob = i, "closed blob");
        }
        self.tail.close().await?;
        debug!(blob = self.tail_index, "closed blob");

        Ok(())
    }

    /// Close and remove any underlying blobs created by the journal.
    pub async fn destroy(self) -> Result<(), Error> {
        for (i, blob) in self.blobs.into_iter() {
            blob.close().await?;
            debug!(blob = i, "destroyed blob");
            self.context
                .remove(&self.cfg.partition, Some(&i.to_be_bytes()))
                .await?;
        }

        self.tail.close().await?;
        debug!(blob = self.tail_index, "destroyed blob");
        self.context
            .remove(&self.cfg.partition, Some(&self.tail_index.to_be_bytes()))
            .await?;

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
    use commonware_cryptography::{hash, sha256::Digest};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{self, Context},
        Blob, Runner, Storage,
    };
    use futures::{pin_mut, StreamExt};

    const PAGE_SIZE: usize = 44;
    const PAGE_CACHE_SIZE: usize = 3;

    /// Generate a SHA-256 digest for the given value.
    fn test_digest(value: u64) -> Digest {
        hash(&value.to_be_bytes())
    }

    fn test_cfg(items_per_blob: u64) -> Config {
        Config {
            partition: "test_partition".into(),
            items_per_blob,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: 2048,
        }
    }

    #[test_traced]
    fn test_fixed_journal_append_and_prune() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 2 items per blob.
            let cfg = test_cfg(2);
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
            let cfg = test_cfg(2);
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
            assert_eq!(journal.oldest_blob_index(), 1);
            assert_eq!(journal.tail_index, 5);
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), Some(2));

            // Prune first 3 blobs (6 items)
            journal
                .prune(3 * cfg.items_per_blob)
                .await
                .expect("failed to prune journal 2");
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), Some(6));
            let buffer = context.encode();
            assert_eq!(journal.oldest_blob_index(), 3);
            assert_eq!(journal.tail_index, 5);
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
            assert_eq!(journal.oldest_blob_index(), 5);
            assert_eq!(journal.tail_index, 5);
            assert!(buffer.contains("tracked 1"));
            assert!(buffer.contains("pruned_total 5"));
            // Since the size of the journal is currently a multiple of items_per_blob, the newest blob
            // will be empty, and there will be no retained items.
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), None);

            {
                let stream = journal
                    .replay(1024, 0)
                    .await
                    .expect("failed to replay journal");
                pin_mut!(stream);
                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert_eq!(test_digest(pos), item);
                            items.push(pos);
                        }
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
                assert_eq!(items, Vec::<u64>::new());
            }

            journal.destroy().await.unwrap();
        });
    }

    /// Append a lot of data to make sure we exercise buffer pool paging boundaries.
    #[test_traced]
    fn test_fixed_journal_append_a_lot_of_data() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        const ITEMS_PER_BLOB: u64 = 10000;
        executor.start(|context| async move {
            let cfg = test_cfg(ITEMS_PER_BLOB);
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            // Append 2 blobs worth of items.
            for i in 0u64..ITEMS_PER_BLOB * 2 - 1 {
                journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            // Close, reopen, then read back.
            journal.close().await.expect("failed to close journal");
            let journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            for i in 0u64..10000 {
                let item: Digest = journal.read(i).await.expect("failed to read data");
                assert_eq!(item, test_digest(i));
            }
            journal.destroy().await.expect("failed to destroy journal");
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
            let cfg = test_cfg(ITEMS_PER_BLOB);
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

            // Read them back the usual way.
            for i in 0u64..(ITEMS_PER_BLOB * 100 + ITEMS_PER_BLOB / 2) {
                let item: Digest = journal.read(i).await.expect("failed to read data");
                assert_eq!(item, test_digest(i), "i={i}");
            }

            // Replay should return all items
            {
                let stream = journal
                    .replay(1024, 0)
                    .await
                    .expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert_eq!(test_digest(pos), item, "pos={pos}, item={item:?}");
                            items.push(pos);
                        }
                        Err(err) => panic!("Failed to read item: {err}"),
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
            blob.write_at(bad_checksum.to_be_bytes().to_vec(), checksum_offset)
                .await
                .expect("Failed to write incorrect checksum");
            let corrupted_item_pos = 40 * ITEMS_PER_BLOB + ITEMS_PER_BLOB / 2;
            blob.close().await.expect("Failed to close blob");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Make sure reading the corrupted item fails with appropriate error.
            let err = journal.read(corrupted_item_pos).await.unwrap_err();
            assert!(matches!(err, Error::ChecksumMismatch(x, _) if x == bad_checksum));

            // Replay all items, making sure the checksum mismatch error is handled correctly.
            {
                let stream = journal
                    .replay(1024, 0)
                    .await
                    .expect("failed to replay journal");
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
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_with_corrupted_historical_blobs() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        const ITEMS_PER_BLOB: u64 = 7;
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = test_cfg(ITEMS_PER_BLOB);
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
            journal.close().await.expect("Failed to close journal");

            let buffer = context.encode();
            assert!(buffer.contains("tracked 101"));

            // Manually truncate a non-tail blob to make sure it's detected during initialization.
            let (blob, size) = context
                .open(&cfg.partition, &40u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.close().await.expect("Failed to close blob");
            let result = Journal::<_, Digest>::init(context.clone(), cfg.clone()).await;
            assert!(matches!(
                result.err().unwrap(),
                Error::InvalidBlobSize(_, _)
            ));

            // Delete a blob and make sure the gap is detected during initialization.
            context
                .remove(&cfg.partition, Some(&40u64.to_be_bytes()))
                .await
                .expect("Failed to remove blob");
            let result = Journal::<_, Digest>::init(context.clone(), cfg.clone()).await;
            assert!(matches!(result.err().unwrap(), Error::MissingBlob(n) if n == 40));
        });
    }

    #[test_traced]
    fn test_fixed_journal_test_trim_blob() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        const ITEMS_PER_BLOB: u64 = 7;
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = test_cfg(ITEMS_PER_BLOB);
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Fill one blob and put 3 items in the second.
            let item_count = ITEMS_PER_BLOB + 3;
            for i in 0u64..item_count {
                journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            assert_eq!(journal.size().await.unwrap(), item_count);
            journal.close().await.expect("Failed to close journal");

            // Truncate the tail blob by one byte, which should result in the 3rd item being
            // trimmed.
            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(size - 1).await.expect("Failed to corrupt blob");

            // Write incorrect checksum into the second item in the blob, which should result in the
            // second item being trimmed.
            let checksum_offset = Digest::SIZE + u32::SIZE + Digest::SIZE;

            let bad_checksum = 123456789u32;
            blob.write_at(bad_checksum.to_be_bytes().to_vec(), checksum_offset as u64)
                .await
                .expect("Failed to write incorrect checksum");
            blob.close().await.expect("Failed to close blob");

            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Confirm 2 items were trimmed.
            assert_eq!(journal.size().await.unwrap(), item_count - 2);

            // Corrupt the last item, ensuring last blob is trimmed to empty state.
            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.close().await.expect("Failed to close blob");

            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Confirm last item in blob was trimmed.
            assert_eq!(journal.size().await.unwrap(), item_count - 3);

            // Cleanup.
            journal.destroy().await.expect("Failed to destroy journal");
        });
    }

    #[test_traced]
    fn test_fixed_journal_partial_replay() {
        const ITEMS_PER_BLOB: u64 = 7;
        // 53 % 7 = 4, which will trigger a non-trivial seek in the starting blob to reach the
        // starting position.
        const START_POS: u64 = 53;

        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = test_cfg(ITEMS_PER_BLOB);
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

            // Replay should return all items except the first `START_POS`.
            {
                let stream = journal
                    .replay(1024, START_POS)
                    .await
                    .expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert!(pos >= START_POS, "pos={pos}");
                            assert_eq!(
                                test_digest(pos),
                                item,
                                "Item at position {pos} did not match expected digest"
                            );
                            items.push(pos);
                        }
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }

                // Make sure all items were replayed
                assert_eq!(
                    items.len(),
                    ITEMS_PER_BLOB as usize * 100 + ITEMS_PER_BLOB as usize / 2
                        - START_POS as usize
                );
                items.sort();
                for (i, pos) in items.iter().enumerate() {
                    assert_eq!(i as u64, *pos - START_POS);
                }
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_from_partial_write() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 3 items per blob.
            let cfg = test_cfg(3);
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
            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // truncate the most recent blob by 1 byte which corrupts the most recent item
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
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

            // Delete the tail blob to simulate a sync() that wrote the last blob at the point it
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
            // Even though it was deleted, tail blob should be re-created and left empty by the
            // recovery code. This means we have 2 blobs total, with 3 items in the first, and none
            // in the tail.
            assert!(buffer.contains("tracked 2"));
            assert_eq!(journal.size().await.unwrap(), 3);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_to_empty_from_partial_write() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 10 items per blob.
            let cfg = test_cfg(10);
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
            let (blob, size) = context
                .open(&cfg.partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // Truncate the most recent blob by 1 byte which corrupts the one appended item
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
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

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_from_unwritten_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 10 items per blob.
            let cfg = test_cfg(10);
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

            // Manually extend the blob by an amount at least some multiple of the chunk size to
            // simulate a failure where the file was extended, but no bytes were written due to
            // failure.
            let (blob, size) = context
                .open(&cfg.partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.write_at(vec![0u8; Digest::SIZE * 3 - 1], size)
                .await
                .expect("Failed to extend blob");
            blob.close().await.expect("Failed to close blob");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Ensure we've recovered to the state of a single item.
            assert_eq!(journal.size().await.unwrap(), 1);
            assert_eq!(journal.oldest_retained_pos().await.unwrap(), Some(0));

            // Make sure journal still works for appending.
            journal
                .append(test_digest(1))
                .await
                .expect("failed to append data");
            assert_eq!(journal.size().await.unwrap(), 2);

            // Get the value of the first item
            let item = journal.read(0).await.unwrap();
            assert_eq!(item, test_digest(0));

            // Get the value of new item
            let item = journal.read(1).await.unwrap();
            assert_eq!(item, test_digest(1));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_rewinding() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 2 items per blob.
            let cfg = test_cfg(2);
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
            let mut cfg = test_cfg(3);
            cfg.partition = "test_partition_2".into();
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

            journal.destroy().await.unwrap();
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
            let cfg = test_cfg(60);

            // Initialize the journal
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append 100 items to the journal
            for i in 0..100 {
                journal
                    .append(test_digest(i))
                    .await
                    .expect("Failed to append data");
            }

            // Close the journal
            journal.close().await.expect("Failed to close journal");

            // Hash blob contents
            let (blob, size) = context
                .open(&cfg.partition, &0u64.to_be_bytes())
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
                "ed2ea67208cde2ee8c16cca5aa4f369f55b1402258c6b7760e5baf134e38944a",
            );
            blob.close().await.expect("Failed to close blob");
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
                "cc7efd4fc999aff36b9fd4213ba8da5810dc1849f92ae2ddf7c6dc40545f9aff",
            );
            blob.close().await.expect("Failed to close blob");

            let journal = Journal::<Context, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_pruned() {
        const ITEMS_PER_BLOB: u64 = 5;
        const WRITE_BUFFER: usize = 1024;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test Case 1: Initialize with pruned state at size 0 (empty journal)
            {
                let cfg = Config {
                    partition: "test_pruned_0".into(),
                    items_per_blob: ITEMS_PER_BLOB,
                    write_buffer: WRITE_BUFFER,
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };

                let synced_journal =
                    Journal::<Context, Digest>::init_pruned(context.clone(), cfg.clone(), 0)
                        .await
                        .expect("Failed to init with pruned state at size 0");

                // Verify the synced journal state
                assert_eq!(synced_journal.size().await.unwrap(), 0);
                assert_eq!(synced_journal.oldest_retained_pos().await.unwrap(), None);
                // Empty journal should have no blobs in map, only tail at index 0
                assert_eq!(synced_journal.blobs.len(), 0);
                assert_eq!(synced_journal.tail_index, 0);
                assert_eq!(synced_journal.tail.size().await, 0);

                synced_journal.destroy().await.unwrap();
            }

            // Test Case 2: Initialize with pruned state in the middle of first blob
            {
                const PRUNED_SIZE: u64 = 3;

                let cfg = Config {
                    partition: "test_pruned_3".into(),
                    items_per_blob: ITEMS_PER_BLOB,
                    write_buffer: WRITE_BUFFER,
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };

                let synced_journal = Journal::<Context, Digest>::init_pruned(
                    context.clone(),
                    cfg.clone(),
                    PRUNED_SIZE,
                )
                .await
                .expect("Failed to init with pruned state at size 3");

                // Verify the synced journal matches expected state
                assert_eq!(synced_journal.size().await.unwrap(), PRUNED_SIZE);
                assert_eq!(synced_journal.oldest_retained_pos().await.unwrap(), Some(0));
                // no blobs created for pruned range, partial data in tail at index 0
                assert_eq!(synced_journal.blobs.len(), 0);
                assert_eq!(synced_journal.tail_index, 0);
                assert_eq!(
                    synced_journal.tail.size().await,
                    PRUNED_SIZE * Journal::<Context, Digest>::CHUNK_SIZE_U64
                );

                synced_journal.destroy().await.unwrap();
            }

            // Test Case 3: Initialize with pruned state exactly at blob boundary
            {
                let cfg = Config {
                    partition: "test_pruned_boundary".into(),
                    items_per_blob: ITEMS_PER_BLOB,
                    write_buffer: WRITE_BUFFER,
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };

                let synced_journal = Journal::<Context, Digest>::init_pruned(
                    context.clone(),
                    cfg.clone(),
                    ITEMS_PER_BLOB, // Exactly one full blob
                )
                .await
                .expect("Failed to init with pruned state at blob boundary");

                // Verify the synced journal has correct state
                assert_eq!(synced_journal.size().await.unwrap(), ITEMS_PER_BLOB);
                assert_eq!(synced_journal.oldest_retained_pos().await.unwrap(), None);
                // Boundary case: no blobs created for pruned range, empty tail at next index
                assert_eq!(synced_journal.blobs.len(), 0);
                assert_eq!(synced_journal.tail_index, 1);
                assert_eq!(synced_journal.tail.size().await, 0);

                synced_journal.destroy().await.unwrap();
            }

            // Test Case 4: Initialize with pruned state spanning multiple blobs
            {
                const MULTI_BLOB_SIZE: u64 = 14; // 2 full blobs + 4 items in third blob

                let cfg = Config {
                    partition: "test_pruned_multi".into(),
                    items_per_blob: ITEMS_PER_BLOB,
                    write_buffer: WRITE_BUFFER,
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };

                let synced_journal = Journal::<Context, Digest>::init_pruned(
                    context.clone(),
                    cfg.clone(),
                    MULTI_BLOB_SIZE,
                )
                .await
                .expect("Failed to init with pruned state spanning multiple blobs");

                // Verify the synced journal state
                assert_eq!(synced_journal.size().await.unwrap(), MULTI_BLOB_SIZE);
                assert_eq!(
                    synced_journal.oldest_retained_pos().await.unwrap(),
                    Some(10)
                );
                // Multi-blob case: no blobs created for pruned range, partial data in tail at index 2
                assert_eq!(synced_journal.blobs.len(), 0);
                assert_eq!(synced_journal.tail_index, 2);
                assert_eq!(
                    synced_journal.tail.size().await,
                    4 * Journal::<Context, Digest>::CHUNK_SIZE_U64
                );

                synced_journal.destroy().await.unwrap();
            }

            // Test Case 5: Test operations after initializing in pruned state
            {
                const PRUNED_OPS_SIZE: u64 = 7;
                const OPERATIONS_PER_BLOB: u64 = 3;

                let cfg = Config {
                    partition: "test_pruned_ops".into(),
                    items_per_blob: OPERATIONS_PER_BLOB,
                    write_buffer: WRITE_BUFFER,
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };

                // Initialize journal in pruned state
                let mut synced_journal = Journal::<Context, Digest>::init_pruned(
                    context.clone(),
                    cfg.clone(),
                    PRUNED_OPS_SIZE,
                )
                .await
                .expect("Failed to init with pruned state");

                // Verify initial synced state
                assert_eq!(synced_journal.size().await.unwrap(), PRUNED_OPS_SIZE);
                assert_eq!(synced_journal.oldest_retained_pos().await.unwrap(), Some(6));
                // Multi-blob case: no blobs created for pruned range, partial data in tail at index 2
                assert_eq!(synced_journal.blobs.len(), 0);
                assert_eq!(synced_journal.tail_index, 2);
                assert_eq!(
                    synced_journal.tail.size().await,
                    Journal::<Context, Digest>::CHUNK_SIZE_U64
                );

                // Test that operations work normally after sync
                let pos = synced_journal.append(test_digest(100)).await.unwrap();
                assert_eq!(pos, 7);
                assert_eq!(synced_journal.size().await.unwrap(), 8);

                let pos = synced_journal.append(test_digest(101)).await.unwrap();
                assert_eq!(pos, 8);
                assert_eq!(synced_journal.size().await.unwrap(), 9);

                // Fill the current blob
                let pos = synced_journal.append(test_digest(102)).await.unwrap();
                assert_eq!(pos, 9);
                assert_eq!(synced_journal.size().await.unwrap(), 10);

                // Verify blob creation after filling
                assert_eq!(synced_journal.blobs.len(), 1);
                assert!(synced_journal.blobs.contains_key(&2)); // Only the filled tail blob is now in blobs map

                // Verify we can read the items we added
                let item = synced_journal.read(7).await.unwrap();
                assert_eq!(item, test_digest(100));

                let item = synced_journal.read(8).await.unwrap();
                assert_eq!(item, test_digest(101));

                let item = synced_journal.read(9).await.unwrap();
                assert_eq!(item, test_digest(102));

                // Verify dummy items cannot be read (they exist but are dummy data)
                // Note: In init_pruned, the data is dummy and shouldn't be read in practice,
                // but the read() method doesn't distinguish between real and dummy data

                synced_journal.destroy().await.unwrap();
            }
        });
    }

    /// Test that init_with_pruned_state properly cleans up existing blobs.
    #[test_traced]
    fn test_pruned_state_cleanup_existing_blobs() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_cleanup".into(),
                items_per_blob: 3,
                write_buffer: 1024,
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // First, create a normal journal with some data
            let mut original_journal =
                Journal::<Context, Digest>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to init original journal");

            // Add some items to create multiple blobs
            for i in 0..10 {
                original_journal.append(test_digest(i)).await.unwrap();
            }
            original_journal.sync().await.unwrap();

            // Verify we have multiple blobs
            assert!(original_journal.blobs.len() > 1);
            let original_blob_count = original_journal.blobs.len();
            original_journal.close().await.unwrap();

            // Verify blobs exist in storage
            let stored_blobs = context.scan(&cfg.partition).await.unwrap();
            assert_eq!(stored_blobs.len(), original_blob_count + 1); // +1 for the tail blob

            // Now initialize with pruned state - this should clean up all existing blobs
            let pruned_journal =
                Journal::<Context, Digest>::init_pruned(context.clone(), cfg.clone(), 5)
                    .await
                    .expect("Failed to init with pruned state");

            // Should have only the blobs needed for the pruned state
            // For num_pruned=5, items_per_blob=3: tail_index=1, tail_items=2
            assert_eq!(pruned_journal.blobs.len(), 0);
            assert_eq!(pruned_journal.tail_index, 1);

            // Verify old blobs are gone from storage
            let stored_blobs_after = context.scan(&cfg.partition).await.unwrap();
            assert_eq!(stored_blobs_after.len(), 1); // Only blob 1 (tail with partial data)

            pruned_journal.destroy().await.unwrap();
        });
    }
    #[test_traced]
    fn test_pruned_state_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_replay".into(),
                items_per_blob: 4,
                write_buffer: 1024,
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Initialize journal in pruned state
            let mut journal = Journal::<Context, Digest>::init_pruned(
                context.clone(),
                cfg.clone(),
                6, // 1 full blob + 2 items in second blob
            )
            .await
            .expect("Failed to init with pruned state");

            // Add some actual data to the journal
            journal.append(test_digest(100)).await.unwrap(); // position 6
            journal.append(test_digest(101)).await.unwrap(); // position 7
            journal.append(test_digest(102)).await.unwrap(); // position 8
            journal.sync().await.unwrap();

            // Test replay from the beginning of retained data
            {
                let stream = journal.replay(1024, 4).await.unwrap(); // Start from position 4 (first retained)
                pin_mut!(stream);

                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            items.push((pos, item));
                        }
                        Err(err) => {
                            // Expected for positions 4-5 since they don't have actual data
                            // but positions 6-8 should work
                            if items.len() < 3 {
                                continue; // Skip expected errors for positions without data
                            }
                            panic!("Unexpected error during replay: {err}");
                        }
                    }
                }

                // Should have successfully read the items we actually added
                assert_eq!(items.len(), 3);
                assert_eq!(items[0], (6, test_digest(100)));
                assert_eq!(items[1], (7, test_digest(101)));
                assert_eq!(items[2], (8, test_digest(102)));
            }

            journal.destroy().await.unwrap();
        });
    }

    /// Test that init_pruned maintains Journal invariants and append behavior works correctly
    #[test_traced]
    fn test_init_pruned_invariants_and_append() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_invariants".into(),
                items_per_blob: 3,
                write_buffer: 1024,
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            // Test case: init_pruned with 7 operations (2 full blobs + 1 item in tail)
            let mut journal =
                Journal::<Context, Digest>::init_pruned(context.clone(), cfg.clone(), 7)
                    .await
                    .expect("Failed to init with pruned state");

            // Verify Journal invariants
            // 1. blobs contains only full blobs, never the tail
            // With the new implementation, no blobs are created for pruned range
            assert_eq!(journal.blobs.len(), 0);
            assert!(!journal.blobs.contains_key(&2)); // tail should not be in blobs

            // 2. tail is always the most recent blob
            assert_eq!(journal.tail_index, 2);

            // 3. size calculation is correct
            assert_eq!(journal.size().await.unwrap(), 7);

            // 4. tail has room for more items (should have 1 item, can hold 3)
            assert_eq!(
                journal.tail.size().await,
                Journal::<Context, Digest>::CHUNK_SIZE_U64
            );

            // 5. oldest_blob_index should return tail_index when no blobs exist
            assert_eq!(journal.oldest_blob_index(), 2);

            // Test append behavior - next operation should be at position 7
            let pos = journal.append(test_digest(100)).await.unwrap();
            assert_eq!(pos, 7);
            assert_eq!(journal.size().await.unwrap(), 8);

            // Append another operation
            let pos = journal.append(test_digest(101)).await.unwrap();
            assert_eq!(pos, 8);
            assert_eq!(journal.size().await.unwrap(), 9);

            // Fill the current blob (tail should move to next index)
            let pos = journal.append(test_digest(102)).await.unwrap();
            assert_eq!(pos, 9);
            assert_eq!(journal.size().await.unwrap(), 10);

            // Now tail should have moved to index 3, and blob 2 should be in blobs map
            assert_eq!(journal.tail_index, 3);
            assert_eq!(journal.blobs.len(), 1); // Only blob 2 (the filled tail) is in blobs map
            assert!(journal.blobs.contains_key(&2)); // previous tail should be in blobs now

            // Verify we can read the operations we just appended
            let item = journal.read(7).await.unwrap();
            assert_eq!(item, test_digest(100));

            let item = journal.read(8).await.unwrap();
            assert_eq!(item, test_digest(101));

            let item = journal.read(9).await.unwrap();
            assert_eq!(item, test_digest(102));

            journal.destroy().await.unwrap();
        });
    }
}
