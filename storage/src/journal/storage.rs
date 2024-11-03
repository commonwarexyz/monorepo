use super::{Config, Error};
use bytes::{BufMut, Bytes};
use commonware_runtime::{Blob, Error as RError, Storage};
use commonware_utils::hex;
use futures::stream::{self, Stream, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{btree_map::Entry, BTreeMap};
use tracing::{debug, trace, warn};

/// Implementation of an append-only log for storing arbitrary data.
pub struct Journal<B: Blob, E: Storage<B>> {
    runtime: E,
    cfg: Config,

    oldest_allowed: Option<u64>,

    blobs: BTreeMap<u64, B>,

    tracked: Gauge,
    synced: Counter,
    pruned: Counter,
}

impl<B: Blob, E: Storage<B>> Journal<B, E> {
    /// Initialize a new `journal` instance.
    ///
    /// All backing blobs are opened but not read during
    /// initialization. The `replay` method can be used
    /// to iterate over all items in the `journal`.
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
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register("tracked", "Number of journals", tracked.clone());
            registry.register("synced", "Number of syncs", synced.clone());
            registry.register("pruned", "Number of journals pruned", pruned.clone());
        }
        tracked.set(blobs.len() as i64);

        // Create journal instance
        Ok(Self {
            runtime,
            cfg,

            oldest_allowed: None,

            blobs,
            tracked,
            synced,
            pruned,
        })
    }

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
        blob: &B,
        offset: usize,
        blob_len: Option<usize>,
        limit: Option<usize>,
    ) -> Result<(usize, Bytes), Error> {
        // Read item size
        let mut size = [0u8; 4];
        blob.read_at(&mut size, offset)
            .await
            .map_err(Error::Runtime)?;
        let size = u32::from_be_bytes(size)
            .try_into()
            .expect("usize too small");
        let offset = offset + 4;

        // If we are just reading the limit, return it without computing entire checksum
        if let Some(limit) = limit {
            if limit < size {
                // Check if blob is too short before performing limited read
                //
                // This is a heuristic to avoid returning data that isn't fully written (more common
                // than byte corruption).
                let projected_offset = offset + size + 4;
                if let Some(blob_len) = blob_len {
                    if projected_offset > blob_len {
                        return Err(Error::Runtime(RError::InsufficientLength));
                    }
                }

                // If limit < size, we do an "unsafe" read where we don't check the checksum
                let mut item = vec![0u8; limit];
                blob.read_at(&mut item, offset)
                    .await
                    .map_err(Error::Runtime)?;

                // We still set the offset to be what the item would've been
                return Ok((projected_offset, Bytes::from(item)));
            }

            // If limit >= size, we just do a normal read
        }

        // Read item
        let mut item = vec![0u8; size];
        blob.read_at(&mut item, offset)
            .await
            .map_err(Error::Runtime)?;
        let offset = offset + size;

        // Read checksum
        let mut stored_checksum = [0u8; 4];
        blob.read_at(&mut stored_checksum, offset)
            .await
            .map_err(Error::Runtime)?;
        let stored_checksum = u32::from_be_bytes(stored_checksum);
        let checksum = crc32fast::hash(&item);
        if checksum != stored_checksum {
            return Err(Error::ChecksumMismatch(checksum, stored_checksum));
        }
        let offset = offset + 4;

        // Return item
        Ok((offset, Bytes::from(item)))
    }

    /// Returns a stream of all items in the journal.
    ///
    /// If any data is found to be corrupt, it will be removed from the journal during this iteration.
    ///
    /// # Concurrency
    ///
    /// The `concurrency` parameter controls how many blobs are replayed concurrently. This can dramatically
    /// speed up the replay process if the underlying storage supports concurrent reads across different
    /// blobs.
    ///
    /// # Limit
    ///
    /// If `limit` is provided, the stream will only read up to `limit` bytes of each item. Consequently,
    /// this means we will not compute a checksum of the entire data and it is up to the caller to deal
    /// with the consequences of this.
    ///
    /// Reading `limit` bytes and skipping ahead to a future location in a blob is the theoretically optimal
    /// way to read only what is required from storage, however, different storage implementations may take
    /// the opportunity to readahead past what is required (needlessly). If the underlying storage can be tuned
    /// for random access prior to invoking replay, it may lead to less IO.
    pub fn replay(
        &mut self,
        concurrency: usize,
        limit: Option<usize>,
    ) -> impl Stream<Item = Result<(u64, usize, Bytes), Error>> + '_ {
        // Collect all blobs to replay
        let blobs: Vec<(u64, &mut B)> = self
            .blobs
            .iter_mut()
            .map(|(&section, blob)| (section, blob))
            .collect();

        // Replay all blobs concurrently
        stream::iter(blobs)
            .map(move |(section, blob)| async move {
                // Collect all items in blob
                let mut offset = 0;
                let len = blob.len().await.map_err(Error::Runtime)?;
                let mut items = Vec::new();
                loop {
                    // Require the blob to be exactly as long as we expect to exit the loop
                    if offset == len {
                        break;
                    }

                    // Read next item (optionally just to `limit`)
                    match Self::read(blob, offset, Some(len), limit).await {
                        Ok((next_offset, item)) => {
                            trace!(blob = section, cursor = offset, "replayed item");
                            items.push(Ok((section, offset, item)));
                            offset = next_offset;
                        }
                        Err(Error::ChecksumMismatch(_, _))
                        | Err(Error::Runtime(RError::InsufficientLength)) => {
                            warn!(
                                blob = section,
                                new_size = offset,
                                old_size = len,
                                "corruption detected: truncating blob"
                            );
                            blob.truncate(offset).await.map_err(Error::Runtime)?;
                            blob.sync().await.map_err(Error::Runtime)?;
                            break;
                        }
                        Err(err) => return Err(err),
                    }
                }
                Ok(items.into_iter())
            })
            .buffered(concurrency)
            .flat_map(|res| stream::iter(res.into_iter().flatten()))
    }

    /// Appends an item to the `journal` in a given `section`.
    pub async fn append(&mut self, section: u64, item: Bytes) -> Result<usize, Error> {
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
                let blob = self
                    .runtime
                    .open(&self.cfg.partition, &name)
                    .await
                    .map_err(Error::Runtime)?;
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
        let cursor = blob.len().await.map_err(Error::Runtime)?;
        blob.write_at(&buf, cursor).await.map_err(Error::Runtime)?;
        Ok(cursor)
    }

    /// Retrieves an item from the `journal` at a given `section` and `offset`.
    ///
    /// If `limit` is provided, only the first `limit` bytes of the item will be read
    /// and returned. Consequently, this returned data cannot be verified for integrity
    /// and it is up to the caller to deal with the consequences of this.
    pub async fn get(
        &self,
        section: u64,
        offset: usize,
        limit: Option<usize>,
    ) -> Result<Option<Bytes>, Error> {
        self.prune_guard(section, false)?;
        let blob = match self.blobs.get(&section) {
            Some(blob) => blob,
            None => return Ok(None),
        };
        let blob_len = match limit {
            Some(_) => Some(blob.len().await.map_err(Error::Runtime)?),
            None => None,
        };
        let (_, item) = Self::read(blob, offset, blob_len, limit).await?;
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
            blob.close().await.map_err(Error::Runtime)?;

            // Remove blob from storage
            self.runtime
                .remove(&self.cfg.partition, Some(&section.to_be_bytes()))
                .await
                .map_err(Error::Runtime)?;
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
            blob.close().await.map_err(Error::Runtime)?;
            debug!(blob = section, "closed blob");
        }
        Ok(())
    }
}
