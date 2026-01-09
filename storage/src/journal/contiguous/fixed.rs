//! An append-only log for storing fixed length _items_ on disk.
//!
//! In addition to replay, stored items can be fetched directly by their `position` in the journal,
//! where position is defined as the item's order of insertion starting from 0, unaffected by
//! pruning.
//!
//! _See [super::variable] for a journal that supports variable length items._
//!
//! # Format
//!
//! Data stored in a `fixed::Journal` is persisted in one of many Blobs within a caller-provided
//! `partition`. Each `Blob` contains a configurable maximum of `items_per_blob`, with page-level
//! data integrity provided by a buffer pool.
//!
//! ```text
//! +--------+----- --+--- -+----------+
//! | item_0 | item_1 | ... | item_n-1 |
//! +--------+-----------+--------+----0
//!
//! n = config.items_per_blob
//! ```
//!
//! The most recent blob may not necessarily be full, in which case it will contain fewer than the
//! maximum number of items.
//!
//! Data fetched from disk is always checked for integrity before being returned. If the data is
//! found to be invalid, an error is returned instead.
//!
//! # Open Blobs
//!
//! All `Blobs` in a given `partition` are kept open during the lifetime of `Journal`. You can limit
//! the number of open blobs by using a higher number of `items_per_blob` or pruning old items.
//!
//! # Consistency
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
//! # State Sync
//!
//! `Journal::init_sync` allows for initializing a journal for use in state sync. When opened in
//! this mode, we attempt to populate the journal within the given range with persisted data. If the
//! journal is empty, we create a fresh journal at the specified position. If the journal is not
//! empty, we prune the journal to the specified lower bound and rewind to the specified upper
//! bound.
//!
//! # Replay
//!
//! The `replay` method supports fast reading of all unpruned items into memory.

use crate::{
    journal::{contiguous::MutableContiguous, Error},
    Persistable,
};
use commonware_codec::{CodecFixed, CodecFixedShared, DecodeExt as _};
use commonware_runtime::{
    buffer::pool::{Append, PoolRef},
    telemetry::metrics::status::GaugeExt,
    Blob, Error as RError, Metrics, Storage,
};
use commonware_utils::hex;
use futures::{
    future::try_join_all,
    stream::{self, Stream},
    StreamExt,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
};
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
    pub items_per_blob: NonZeroU64,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,
}

/// Implementation of `Journal` storage.
pub struct Journal<E: Storage + Metrics, A: CodecFixed> {
    pub(crate) context: E,
    pub(crate) cfg: Config,

    /// Stores the historical blobs. A BTreeMap allows iterating over them from oldest to newest.
    ///
    /// # Invariants
    ///
    /// - Indices are consecutive and without gaps.
    /// - Contains only full blobs.
    /// - Never contains the most recent blob.
    pub(crate) blobs: BTreeMap<u64, Append<E::Blob>>,

    /// The most recent blob.
    ///
    /// # Invariant
    ///
    /// Always has room for at least one more item (and may be empty).
    pub(crate) tail: Append<E::Blob>,

    /// The index of the most recent blob.
    pub(crate) tail_index: u64,

    /// Cached size of the journal.
    pub(crate) size: u64,

    /// Cached pruning boundary.
    pub(crate) pruning_boundary: u64,

    pub(crate) tracked: Gauge,
    pub(crate) synced: Counter,
    pub(crate) pruned: Counter,

    pub(crate) _array: PhantomData<A>,
}

impl<E: Storage + Metrics, A: CodecFixedShared> Journal<E, A> {
    pub(crate) const CHUNK_SIZE: usize = A::SIZE;
    pub(crate) const CHUNK_SIZE_U64: u64 = Self::CHUNK_SIZE as u64;

    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during initialization. The `replay` method can be
    /// used to iterate over all items in the `Journal`.
    ///
    /// # Repair
    ///
    /// Like
    /// [sqlite](https://github.com/sqlite/sqlite/blob/8658a8df59f00ec8fcfea336a2a6a4b5ef79d2ee/src/wal.c#L1504-L1505)
    /// and
    /// [rocksdb](https://github.com/facebook/rocksdb/blob/0c533e61bc6d89fdf1295e8e0bcee4edb3aef401/include/rocksdb/options.h#L441-L445),
    /// the first invalid data read will be considered the new end of the journal (and the
    /// underlying [Blob] will be truncated to the last valid item).
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

        // Check that there are no gaps in the historical blobs.
        let full_size = cfg.items_per_blob.get() * Self::CHUNK_SIZE_U64;
        if !blobs.is_empty() {
            let mut it = blobs.keys().rev();
            let mut prev_index = *it.next().unwrap();
            for index in it {
                if *index != prev_index - 1 {
                    return Err(Error::MissingBlob(prev_index - 1));
                }
                prev_index = *index;
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
        let _ = tracked.try_set(blobs.len());

        // Wrap all blobs with Append wrappers, starting with the tail.
        let (mut tail_index, (blob, blob_size)) = blobs.pop_last().unwrap();
        let mut tail = Append::new(
            blob,
            blob_size,
            cfg.write_buffer.get(),
            cfg.buffer_pool.clone(),
        )
        .await?;
        let mut tail_size = tail.size().await;

        // Trim the tail blob if necessary.
        if !tail_size.is_multiple_of(Self::CHUNK_SIZE_U64) {
            warn!(
                blob = tail_index,
                invalid_size = tail_size,
                "last blob size is not a multiple of item size, truncating"
            );
            tail_size -= tail_size % Self::CHUNK_SIZE_U64;
            tail.resize(tail_size).await?;
        }

        // Non-tail blobs can be immutable.
        let mut blobs = try_join_all(blobs.into_iter().map(|(index, (blob, size))| {
            let pool = cfg.buffer_pool.clone();
            async move {
                let blob = Append::new_immutable(blob, size, cfg.write_buffer.get(), pool).await?;
                let logical_size = blob.size().await;
                // Verify the non-tail blobs are full as expected.
                if logical_size != full_size {
                    return Err(Error::InvalidBlobSize(logical_size, full_size));
                }
                Ok::<_, Error>((index, (blob, logical_size)))
            }
        }))
        .await?;

        // If the tail blob is full we need to start a new one to maintain its invariant that there
        // is always room for another item.
        if tail_size == full_size {
            warn!(
                blob = tail_index,
                "tail blob is full, creating a new empty one"
            );
            tail.to_immutable().await?;
            blobs.push((tail_index, (tail, tail_size)));
            tail_index += 1;
            let (blob, blob_size) = context
                .open(&cfg.partition, &tail_index.to_be_bytes())
                .await?;
            assert_eq!(blob_size, 0);
            tail = Append::new(
                blob,
                blob_size,
                cfg.write_buffer.get(),
                cfg.buffer_pool.clone(),
            )
            .await?;
            tail_size = 0;
            tracked.inc();
        }

        let pruning_boundary = if blobs.is_empty() {
            tail_index * cfg.items_per_blob.get()
        } else {
            blobs[0].0 * cfg.items_per_blob.get()
        };
        let size = tail_index * cfg.items_per_blob.get() + (tail_size / Self::CHUNK_SIZE_U64);
        assert!(size >= pruning_boundary);

        Ok(Self {
            context,
            cfg,
            blobs: blobs
                .into_iter()
                .map(|(index, (blob, _))| (index, blob))
                .collect(),
            tail,
            tail_index,
            size,
            pruning_boundary,
            tracked,
            synced,
            pruned,
            _array: PhantomData,
        })
    }

    /// Sync any pending updates to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.synced.inc();
        debug!(blob = self.tail_index, "syncing blob");
        self.tail.sync().await.map_err(Error::Runtime)
    }

    /// Return the total number of items in the journal, irrespective of pruning. The next value
    /// appended to the journal will be at this position.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Append a new item to the journal. Return the item's position in the journal, or error if the
    /// operation fails.
    pub async fn append(&mut self, item: A) -> Result<u64, Error> {
        // There should always be room to append an item in the newest blob
        let mut size = self.tail.size().await;
        assert!(size < self.cfg.items_per_blob.get() * Self::CHUNK_SIZE_U64);
        assert_eq!(size % Self::CHUNK_SIZE_U64, 0);
        let item = item.encode_mut();

        // Write the item to the blob
        let item_pos =
            (size / Self::CHUNK_SIZE_U64) + self.cfg.items_per_blob.get() * self.tail_index;
        self.tail.append(&item).await?;
        trace!(blob = self.tail_index, pos = item_pos, "appended item");
        size += Self::CHUNK_SIZE_U64;

        // If the tail blob is now full we need to create a new empty one to fulfill the invariant
        // that the tail blob always has room for a new element.
        if size == self.cfg.items_per_blob.get() * Self::CHUNK_SIZE_U64 {
            // Sync the tail blob before creating a new one so if we crash we don't end up with a
            // non-full historical blob.
            self.tail.to_immutable().await?;

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
                self.cfg.write_buffer.get(),
                self.cfg.buffer_pool.clone(),
            )
            .await?;
            self.tracked.inc();

            // Move the old tail blob to the historical blobs map and set the new blob as the tail.
            let old_tail = std::mem::replace(&mut self.tail, next_blob);
            assert!(self.blobs.insert(self.tail_index, old_tail).is_none());
            self.tail_index = next_blob_index;
        }
        self.size += 1;

        Ok(item_pos)
    }

    /// Rewind the journal to the given `size`. Returns [Error::MissingBlob] if the rewind point
    /// precedes the oldest retained element point. The journal is not synced after rewinding.
    ///
    /// # Warnings
    ///
    /// * This operation is not guaranteed to survive restarts until sync is called.
    /// * This operation is not atomic, but it will always leave the journal in a consistent state
    ///   in the event of failure since blobs are always removed from newest to oldest.
    pub async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        match size.cmp(&self.size()) {
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
            self.tail.to_mutable().await;
            self.remove_blob(self.tail_index, new_tail).await?;
            self.tail_index -= 1;
        }

        // Truncate the tail blob to the correct offset.
        self.tail.resize(rewind_to_offset).await?;

        self.size = size;
        assert!(size >= self.pruning_boundary);

        Ok(())
    }

    /// Return the position of the oldest item in the journal that remains readable.
    ///
    /// Note that this value could be older than the `min_item_pos` last passed to prune.
    pub const fn oldest_retained_pos(&self) -> Option<u64> {
        if self.pruning_boundary == self.size {
            return None;
        }

        Some(self.pruning_boundary)
    }

    /// Return the location before which all items have been pruned.
    pub const fn pruning_boundary(&self) -> u64 {
        self.pruning_boundary
    }

    /// Read the item at position `pos` in the journal.
    ///
    /// # Errors
    ///
    ///  - [Error::ItemPruned] if the item at position `pos` is pruned.
    ///  - [Error::ItemOutOfRange] if the item at position `pos` does not exist.
    pub async fn read(&self, pos: u64) -> Result<A, Error> {
        let blob_index = pos / self.cfg.items_per_blob.get();
        if blob_index > self.tail_index {
            return Err(Error::ItemOutOfRange(pos));
        }

        let offset = (pos % self.cfg.items_per_blob.get()) * Self::CHUNK_SIZE_U64;

        let blob = if blob_index == self.tail_index {
            if offset >= self.tail.size().await {
                return Err(Error::ItemOutOfRange(pos));
            }
            &self.tail
        } else {
            self.blobs.get(&blob_index).ok_or(Error::ItemPruned(pos))?
        };

        let read = blob.read_at(vec![0u8; Self::CHUNK_SIZE], offset).await?;
        Self::decode_buf(read.as_ref())
    }

    /// Decode the array from `buf`, returning:
    /// - Error::Codec if the array could not be decoded.
    ///
    ///  Error::Codec likely indicates a logic error rather than a corruption issue.
    fn decode_buf(buf: &[u8]) -> Result<A, Error> {
        A::decode(&buf[..A::SIZE]).map_err(Error::Codec)
    }

    /// Returns an ordered stream of all items in the journal with position >= `start_pos`.
    ///
    /// # Panics
    ///
    /// Panics `start_pos` exceeds log size.
    ///
    /// # Integrity
    ///
    /// If any corrupted data is found, the stream will return an error.
    pub async fn replay(
        &self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> Result<impl Stream<Item = Result<(u64, A), Error>> + '_, Error> {
        assert!(start_pos <= self.size());

        // Collect all blobs to replay paired with their index.
        let items_per_blob = self.cfg.items_per_blob.get();
        let start_blob = start_pos / items_per_blob;
        assert!(start_blob <= self.tail_index);
        let blobs = self.blobs.range(start_blob..).collect::<Vec<_>>();
        let mut readers = Vec::with_capacity(blobs.len() + 1);
        for (blob_index, blob) in blobs {
            let reader = blob.as_blob_reader(buffer).await?;
            readers.push((*blob_index, reader));
        }

        // Include the tail blob.
        let tail_reader = self.tail.as_blob_reader(buffer).await?;
        readers.push((self.tail_index, tail_reader));
        let start_offset = (start_pos % items_per_blob) * Self::CHUNK_SIZE_U64;

        // Replay all blobs in order and stream items as they are read (to avoid occupying too much
        // memory with buffered data).
        let stream = stream::iter(readers).flat_map(move |(blob_index, mut reader)| {
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
                            let result = Self::decode_buf(&buf).map(|item| (item_pos, item));
                            if result.is_err() {
                                warn!("corrupted item at {item_pos}");
                            }
                            Some((result, (buf, reader, next_offset)))
                        }
                        Err(err) => {
                            warn!(
                                item_pos,
                                err = err.to_string(),
                                "error reading item during replay"
                            );
                            let blob_size = reader.blob_size();
                            Some((Err(Error::Runtime(err)), (buf, reader, blob_size)))
                        }
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
    /// less than the configured number of items per blob. Returns true if any items were pruned.
    ///
    /// Note that this operation may NOT be atomic, however it's guaranteed not to leave gaps in the
    /// event of failure as items are always pruned in order from oldest to newest.
    pub async fn prune(&mut self, min_item_pos: u64) -> Result<bool, Error> {
        let oldest_blob_index = self.oldest_blob_index();
        let new_oldest_blob =
            std::cmp::min(min_item_pos / self.cfg.items_per_blob, self.tail_index);

        let mut pruned = false;
        for index in oldest_blob_index..new_oldest_blob {
            pruned = true;
            let blob = self.blobs.remove(&index).unwrap();
            self.remove_blob(index, blob).await?;
            self.pruned.inc();
        }
        if pruned {
            self.pruning_boundary = new_oldest_blob * self.cfg.items_per_blob.get();
        }

        Ok(pruned)
    }

    /// Safely removes any previously tracked blob from underlying storage.
    async fn remove_blob(&mut self, index: u64, blob: Append<E::Blob>) -> Result<(), Error> {
        drop(blob);
        self.context
            .remove(&self.cfg.partition, Some(&index.to_be_bytes()))
            .await?;
        debug!(blob = index, "removed blob");
        self.tracked.dec();

        Ok(())
    }

    /// Remove any underlying blobs created by the journal.
    pub async fn destroy(self) -> Result<(), Error> {
        for (i, blob) in self.blobs.into_iter() {
            drop(blob);
            debug!(blob = i, "destroyed blob");
            self.context
                .remove(&self.cfg.partition, Some(&i.to_be_bytes()))
                .await?;
        }

        drop(self.tail);
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

// Implement Contiguous trait for fixed-length journals
impl<E: Storage + Metrics, A: CodecFixedShared> super::Contiguous for Journal<E, A> {
    type Item = A;

    fn size(&self) -> u64 {
        Self::size(self)
    }

    fn oldest_retained_pos(&self) -> Option<u64> {
        Self::oldest_retained_pos(self)
    }

    fn pruning_boundary(&self) -> u64 {
        Self::pruning_boundary(self)
    }

    async fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, Self::Item), Error>> + '_, Error> {
        Self::replay(self, buffer, start_pos).await
    }

    async fn read(&self, position: u64) -> Result<Self::Item, Error> {
        Self::read(self, position).await
    }
}

impl<E: Storage + Metrics, A: CodecFixedShared> MutableContiguous for Journal<E, A> {
    async fn append(&mut self, item: Self::Item) -> Result<u64, Error> {
        Self::append(self, item).await
    }

    async fn prune(&mut self, min_position: u64) -> Result<bool, Error> {
        Self::prune(self, min_position).await
    }

    async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        Self::rewind(self, size).await
    }
}

impl<E: Storage + Metrics, A: CodecFixedShared> Persistable for Journal<E, A> {
    type Error = Error;

    async fn commit(&mut self) -> Result<(), Error> {
        Self::sync(self).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        Self::sync(self).await
    }

    async fn destroy(self) -> Result<(), Error> {
        Self::destroy(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{self, Context},
        Blob, Runner, Storage,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use futures::{pin_mut, StreamExt};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(44);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(3);

    /// Generate a SHA-256 digest for the given value.
    fn test_digest(value: u64) -> Digest {
        Sha256::hash(&value.to_be_bytes())
    }

    fn test_cfg(items_per_blob: NonZeroU64) -> Config {
        Config {
            partition: "test_partition".into(),
            items_per_blob,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(2048),
        }
    }

    #[test_traced]
    fn test_fixed_journal_append_and_prune() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 2 items per blob.
            let cfg = test_cfg(NZU64!(2));
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

            // Drop the journal and re-initialize it to simulate a restart
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            let cfg = test_cfg(NZU64!(2));
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            assert_eq!(journal.size(), 1);

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
            assert!(matches!(err, Error::ItemOutOfRange(3)));

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
            assert_eq!(journal.oldest_retained_pos(), Some(2));
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
            assert_eq!(journal.oldest_retained_pos(), Some(2));

            // Prune first 3 blobs (6 items)
            journal
                .prune(3 * cfg.items_per_blob.get())
                .await
                .expect("failed to prune journal 2");
            assert_eq!(journal.oldest_retained_pos(), Some(6));
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
            let size = journal.size();
            assert_eq!(size, 10);
            assert_eq!(journal.oldest_blob_index(), 5);
            assert_eq!(journal.tail_index, 5);
            assert!(buffer.contains("tracked 1"));
            assert!(buffer.contains("pruned_total 5"));
            // Since the size of the journal is currently a multiple of items_per_blob, the newest blob
            // will be empty, and there will be no retained items.
            assert_eq!(journal.oldest_retained_pos(), None);
            // Pruning boundary should equal size when oldest_retained is None.
            assert_eq!(journal.pruning_boundary(), size);

            {
                let stream = journal
                    .replay(NZUsize!(1024), 0)
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
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10000);
        executor.start(|context| async move {
            let cfg = test_cfg(ITEMS_PER_BLOB);
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            // Append 2 blobs worth of items.
            for i in 0u64..ITEMS_PER_BLOB.get() * 2 - 1 {
                journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            // Sync, reopen, then read back.
            journal.sync().await.expect("failed to sync journal");
            drop(journal);
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
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
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
            for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }

            let buffer = context.encode();
            assert!(buffer.contains("tracked 101"));

            // Read them back the usual way.
            for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
                let item: Digest = journal.read(i).await.expect("failed to read data");
                assert_eq!(item, test_digest(i), "i={i}");
            }

            // Replay should return all items
            {
                let stream = journal
                    .replay(NZUsize!(1024), 0)
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
                    ITEMS_PER_BLOB.get() as usize * 100 + ITEMS_PER_BLOB.get() as usize / 2
                );
                items.sort();
                for (i, pos) in items.iter().enumerate() {
                    assert_eq!(i as u64, *pos);
                }
            }
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Corrupt one of the bytes and make sure it's detected.
            let (blob, _) = context
                .open(&cfg.partition, &40u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // Write junk bytes.
            let bad_bytes = 123456789u32;
            blob.write_at(bad_bytes.to_be_bytes().to_vec(), 1)
                .await
                .expect("Failed to write bad bytes");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Make sure reading an item that resides in the corrupted page fails.
            let err = journal
                .read(40 * ITEMS_PER_BLOB.get() + 1)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Runtime(_)));

            // Replay all items.
            {
                let mut error_found = false;
                let stream = journal
                    .replay(NZUsize!(1024), 0)
                    .await
                    .expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert_eq!(test_digest(pos), item);
                            items.push(pos);
                        }
                        Err(err) => {
                            error_found = true;
                            assert!(matches!(err, Error::Runtime(_)));
                            break;
                        }
                    }
                }
                assert!(error_found); // error should abort replay
            }
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_with_corrupted_historical_blobs() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = test_cfg(ITEMS_PER_BLOB);
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append many items, filling 100 blobs and part of the 101st
            for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            let buffer = context.encode();
            assert!(buffer.contains("tracked 101"));

            // Manually truncate a non-tail blob to make sure it's detected during initialization.
            let (blob, size) = context
                .open(&cfg.partition, &40u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");
            let result = Journal::<_, Digest>::init(context.clone(), cfg.clone()).await;
            assert!(matches!(result.err().unwrap(), Error::Runtime(_)));

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
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = test_cfg(ITEMS_PER_BLOB);
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Fill one blob and put 3 items in the second.
            let item_count = ITEMS_PER_BLOB.get() + 3;
            for i in 0u64..item_count {
                journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            assert_eq!(journal.size(), item_count);
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Truncate the tail blob by one byte, which should result in the last page worth of
            // data being discarded due to an invalid checksum. This will result in one item being
            // lost.
            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .unwrap();

            // Confirm 1 item was lost.
            assert_eq!(journal.size(), item_count - 1);

            // Cleanup.
            journal.destroy().await.expect("Failed to destroy journal");
        });
    }

    #[test_traced]
    fn test_fixed_journal_partial_replay() {
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
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
            for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
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
                    .replay(NZUsize!(1024), START_POS)
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
                    ITEMS_PER_BLOB.get() as usize * 100 + ITEMS_PER_BLOB.get() as usize / 2
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
            let cfg = test_cfg(NZU64!(3));
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            for i in 0..5 {
                journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            assert_eq!(journal.size(), 5);
            let buffer = context.encode();
            assert!(buffer.contains("tracked 2"));
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Manually truncate most recent blob to simulate a partial write.
            let (blob, size) = context
                .open(&cfg.partition, &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // truncate the most recent blob by 1 byte which corrupts the most recent item
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");
            // the last corrupted item should get discarded
            assert_eq!(journal.size(), 4);
            let buffer = context.encode();
            assert!(buffer.contains("tracked 2"));
            drop(journal);

            // Delete the tail blob to simulate a sync() that wrote the last blob at the point it
            // was entirely full, but a crash happened before the next empty blob could be created.
            context
                .remove(&cfg.partition, Some(&1u64.to_be_bytes()))
                .await
                .expect("Failed to remove blob");
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");
            assert_eq!(journal.size(), 3);
            let buffer = context.encode();
            // Even though it was deleted, tail blob should be re-created and left empty by the
            // recovery code. This means we have 2 blobs total, with 3 items in the first, and none
            // in the tail.
            assert!(buffer.contains("tracked 2"));
            assert_eq!(journal.size(), 3);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_to_empty_from_partial_write() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 10 items per blob.
            let cfg = test_cfg(NZU64!(10));
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");
            // Add only a single item
            journal
                .append(test_digest(0))
                .await
                .expect("failed to append data");
            assert_eq!(journal.size(), 1);
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Manually truncate most recent blob to simulate a partial write.
            let (blob, size) = context
                .open(&cfg.partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // Truncate the most recent blob by 1 byte which corrupts the one appended item
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Since there was only a single item appended which we then corrupted, recovery should
            // leave us in the state of an empty journal.
            assert_eq!(journal.size(), 0);
            assert_eq!(journal.oldest_retained_pos(), None);
            // Make sure journal still works for appending.
            journal
                .append(test_digest(0))
                .await
                .expect("failed to append data");
            assert_eq!(journal.size(), 1);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_from_unwritten_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 10 items per blob.
            let cfg = test_cfg(NZU64!(10));
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Add only a single item
            journal
                .append(test_digest(0))
                .await
                .expect("failed to append data");
            assert_eq!(journal.size(), 1);
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Manually extend the blob to simulate a failure where the file was extended, but no
            // bytes were written due to failure.
            let (blob, size) = context
                .open(&cfg.partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.write_at(vec![0u8; PAGE_SIZE.get() as usize * 3], size)
                .await
                .expect("Failed to extend blob");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal to simulate a restart
            let mut journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // No items should be lost since we called sync.
            assert_eq!(journal.size(), 1);
            assert_eq!(journal.oldest_retained_pos(), Some(0));

            // Make sure journal still works for appending.
            journal
                .append(test_digest(1))
                .await
                .expect("failed to append data");
            assert_eq!(journal.size(), 2);

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
            let cfg = test_cfg(NZU64!(2));
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
            assert_eq!(journal.size(), 1);
            assert!(matches!(journal.rewind(1).await, Ok(()))); // should be no-op
            assert!(matches!(journal.rewind(0).await, Ok(())));
            assert_eq!(journal.size(), 0);

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
            assert_eq!(journal.size(), 7);

            // rewind back to item #4, which should prune 2 blobs
            assert!(matches!(journal.rewind(4).await, Ok(())));
            assert_eq!(journal.size(), 4);
            let buffer = context.encode();
            assert!(buffer.contains("tracked 3"));

            // rewind back to empty and ensure all blobs are rewound over
            assert!(matches!(journal.rewind(0).await, Ok(())));
            let buffer = context.encode();
            assert!(buffer.contains("tracked 1"));
            assert_eq!(journal.size(), 0);

            // stress test: add 100 items, rewind 49, repeat x10.
            for _ in 0..10 {
                for i in 0..100 {
                    journal
                        .append(test_digest(i))
                        .await
                        .expect("failed to append data");
                }
                journal.rewind(journal.size() - 49).await.unwrap();
            }
            const ITEMS_REMAINING: u64 = 10 * (100 - 49);
            assert_eq!(journal.size(), ITEMS_REMAINING);

            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Repeat with a different blob size (3 items per blob)
            let mut cfg = test_cfg(NZU64!(3));
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
                journal.rewind(journal.size() - 49).await.unwrap();
            }
            assert_eq!(journal.size(), ITEMS_REMAINING);

            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Make sure re-opened journal is as expected
            let mut journal: Journal<_, Digest> = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            assert_eq!(journal.size(), 10 * (100 - 49));

            // Make sure rewinding works after pruning
            journal.prune(300).await.expect("pruning failed");
            assert_eq!(journal.size(), ITEMS_REMAINING);
            // Rewinding prior to our prune point should fail.
            assert!(matches!(
                journal.rewind(299).await,
                Err(Error::InvalidRewind(299))
            ));
            // Rewinding to the prune point should work.
            // always remain in the journal.
            assert!(matches!(journal.rewind(300).await, Ok(())));
            assert_eq!(journal.size(), 300);
            assert_eq!(journal.oldest_retained_pos(), None);

            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery when blob is truncated to a page boundary with item size not dividing page size.
    ///
    /// This tests the scenario where:
    /// 1. Items (32 bytes) don't divide evenly into page size (44 bytes)
    /// 2. Data spans multiple pages
    /// 3. Blob is truncated to a page boundary (simulating crash before last page was written)
    /// 4. Journal should recover correctly on reopen
    #[test_traced]
    fn test_fixed_journal_recover_from_page_boundary_truncation() {
        let executor = deterministic::Runner::default();
        executor.start(|context: Context| async move {
            // Use a small items_per_blob to keep the test focused on a single blob
            let cfg = test_cfg(NZU64!(100));
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Item size is 32 bytes (Digest), page size is 44 bytes.
            // 32 doesn't divide 44, so items will cross page boundaries.
            // Physical page size = 44 + 12 (CRC) = 56 bytes.
            //
            // Write enough items to span multiple pages:
            // - 10 items = 320 logical bytes
            // - This spans ceil(320/44) = 8 logical pages
            for i in 0u64..10 {
                journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            assert_eq!(journal.size(), 10);
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Open the blob directly and truncate to a page boundary.
            // Physical page size = PAGE_SIZE + CHECKSUM_SIZE = 44 + 12 = 56
            let physical_page_size = PAGE_SIZE.get() as u64 + 12;
            let (blob, size) = context
                .open(&cfg.partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Calculate how many full physical pages we have and truncate to lose the last one.
            let full_pages = size / physical_page_size;
            assert!(full_pages >= 2, "need at least 2 pages for this test");
            let truncate_to = (full_pages - 1) * physical_page_size;

            blob.resize(truncate_to)
                .await
                .expect("Failed to truncate blob");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal - it should recover by truncating to valid data
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to re-initialize journal after page truncation");

            // The journal should have fewer items now (those that fit in the remaining pages).
            // With logical page size 44 and item size 32:
            // - After truncating to (full_pages-1) physical pages, we have (full_pages-1)*44 logical bytes
            // - Number of complete items = floor(logical_bytes / 32)
            let remaining_logical_bytes = (full_pages - 1) * PAGE_SIZE.get() as u64;
            let expected_items = remaining_logical_bytes / 32; // 32 = Digest::SIZE
            assert_eq!(
                journal.size(),
                expected_items,
                "Journal should recover to {} items after truncation",
                expected_items
            );

            // Verify we can still read the remaining items
            for i in 0..expected_items {
                let item = journal
                    .read(i)
                    .await
                    .expect("failed to read recovered item");
                assert_eq!(item, test_digest(i), "item {} mismatch after recovery", i);
            }

            journal.destroy().await.expect("Failed to destroy journal");
        });
    }

    /// Test the contiguous fixed journal with items_per_blob: 1.
    ///
    /// This is an edge case where each item creates its own blob, and the
    /// tail blob is always empty after sync (because the item fills the blob
    /// and a new empty one is created).
    #[test_traced]
    fn test_single_item_per_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "single_item_per_blob".into(),
                items_per_blob: NZU64!(1),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(2048),
            };

            // === Test 1: Basic single item operation ===
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Verify empty state
            assert_eq!(journal.size(), 0);
            assert_eq!(journal.oldest_retained_pos(), None);

            // Append 1 item
            let pos = journal
                .append(test_digest(0))
                .await
                .expect("failed to append");
            assert_eq!(pos, 0);
            assert_eq!(journal.size(), 1);

            // Sync
            journal.sync().await.expect("failed to sync");

            // Read from size() - 1
            let value = journal
                .read(journal.size() - 1)
                .await
                .expect("failed to read");
            assert_eq!(value, test_digest(0));

            // === Test 2: Multiple items with single item per blob ===
            for i in 1..10u64 {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append");
                assert_eq!(pos, i);
                assert_eq!(journal.size(), i + 1);

                // Verify we can read the just-appended item at size() - 1
                let value = journal
                    .read(journal.size() - 1)
                    .await
                    .expect("failed to read");
                assert_eq!(value, test_digest(i));
            }

            // Verify all items can be read
            for i in 0..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            journal.sync().await.expect("failed to sync");

            // === Test 3: Pruning with single item per blob ===
            // Prune to position 5 (removes positions 0-4)
            journal.prune(5).await.expect("failed to prune");

            // Size should still be 10
            assert_eq!(journal.size(), 10);

            // oldest_retained_pos should be 5
            assert_eq!(journal.oldest_retained_pos(), Some(5));

            // Reading from size() - 1 (position 9) should still work
            let value = journal
                .read(journal.size() - 1)
                .await
                .expect("failed to read");
            assert_eq!(value, test_digest(9));

            // Reading from pruned positions should return ItemPruned
            for i in 0..5 {
                assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
            }

            // Reading from retained positions should work
            for i in 5..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            // Append more items after pruning
            for i in 10..15u64 {
                let pos = journal
                    .append(test_digest(i))
                    .await
                    .expect("failed to append");
                assert_eq!(pos, i);

                // Verify we can read from size() - 1
                let value = journal
                    .read(journal.size() - 1)
                    .await
                    .expect("failed to read");
                assert_eq!(value, test_digest(i));
            }

            journal.sync().await.expect("failed to sync");
            drop(journal);

            // === Test 4: Restart persistence with single item per blob ===
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-initialize journal");

            // Verify size is preserved
            assert_eq!(journal.size(), 15);

            // Verify oldest_retained_pos is preserved
            assert_eq!(journal.oldest_retained_pos(), Some(5));

            // Reading from size() - 1 should work after restart
            let value = journal
                .read(journal.size() - 1)
                .await
                .expect("failed to read");
            assert_eq!(value, test_digest(14));

            // Reading all retained positions should work
            for i in 5..15u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            journal.destroy().await.expect("failed to destroy journal");

            // === Test 5: Restart after pruning with non-zero index ===
            // Fresh journal for this test
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append 10 items (positions 0-9)
            for i in 0..10u64 {
                journal.append(test_digest(i + 100)).await.unwrap();
            }

            // Prune to position 5 (removes positions 0-4)
            journal.prune(5).await.unwrap();
            assert_eq!(journal.size(), 10);
            assert_eq!(journal.oldest_retained_pos(), Some(5));

            // Sync and restart
            journal.sync().await.unwrap();
            drop(journal);

            // Re-open journal
            let journal = Journal::<_, Digest>::init(context.clone(), cfg.clone())
                .await
                .expect("failed to re-initialize journal");

            // Verify state after restart
            assert_eq!(journal.size(), 10);
            assert_eq!(journal.oldest_retained_pos(), Some(5));

            // Reading from size() - 1 (position 9) should work
            let value = journal.read(journal.size() - 1).await.unwrap();
            assert_eq!(value, test_digest(109));

            // Verify all retained positions (5-9) work
            for i in 5..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i + 100));
            }

            journal.destroy().await.expect("failed to destroy journal");

            // === Test 6: Prune all items (edge case) ===
            let mut journal = Journal::init(context.clone(), cfg.clone())
                .await
                .expect("failed to initialize journal");

            for i in 0..5u64 {
                journal.append(test_digest(i + 200)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Prune all items
            journal.prune(5).await.unwrap();
            assert_eq!(journal.size(), 5); // Size unchanged
            assert_eq!(journal.oldest_retained_pos(), None); // All pruned

            // size() - 1 = 4, but position 4 is pruned
            let result = journal.read(journal.size() - 1).await;
            assert!(matches!(result, Err(Error::ItemPruned(4))));

            // After appending, reading works again
            journal.append(test_digest(205)).await.unwrap();
            assert_eq!(journal.oldest_retained_pos(), Some(5));
            assert_eq!(
                journal.read(journal.size() - 1).await.unwrap(),
                test_digest(205)
            );

            journal.destroy().await.expect("failed to destroy journal");
        });
    }
}
