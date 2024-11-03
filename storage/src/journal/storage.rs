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
    async fn read(blob: &B, offset: usize) -> Result<(usize, Bytes), Error> {
        // Read item size
        let mut size = [0u8; 4];
        blob.read_at(&mut size, offset)
            .await
            .map_err(Error::Runtime)?;
        let size = u32::from_be_bytes(size)
            .try_into()
            .map_err(|_| Error::UsizeTooSmall)?;
        let offset = offset.checked_add(4).ok_or(Error::OffsetOverflow)?;

        // Read item
        let mut item = vec![0u8; size];
        blob.read_at(&mut item, offset)
            .await
            .map_err(Error::Runtime)?;
        let offset = offset.checked_add(size).ok_or(Error::OffsetOverflow)?;

        // Read checksum
        let mut stored_checksum = [0u8; 4];
        blob.read_at(&mut stored_checksum, offset)
            .await
            .map_err(Error::Runtime)?;
        let stored_checksum = u32::from_be_bytes(stored_checksum);
        let checksum = crc32fast::hash(&item);
        if checksum != stored_checksum {
            return Err(Error::ChecksumMismatch(stored_checksum, checksum));
        }
        let offset = offset.checked_add(4).ok_or(Error::OffsetOverflow)?;

        // Return item
        Ok((offset, Bytes::from(item)))
    }

    /// Read `exact` bytes from the blob at the given offset.
    ///
    /// # Warning
    ///
    /// This method bypasses the checksum verification and the caller is responsible for ensuring
    /// the integrity of any data read. If `exact` exceeds the size of an item (and runs over the blob
    /// length), it will lead to unintentional truncation of data.
    async fn read_exact(blob: &B, offset: usize, exact: usize) -> Result<(usize, Bytes), Error> {
        // Read item size and first `exact` bytes
        let mut buf = vec![0u8; 4 + exact];
        blob.read_at(&mut buf, offset)
            .await
            .map_err(Error::Runtime)?;

        // Get item size to compute next offset
        let size = u32::from_be_bytes(buf[..4].try_into().unwrap())
            .try_into()
            .map_err(|_| Error::UsizeTooSmall)?;

        // Get item prefix
        //
        // We don't compute the checksum here nor do we verify that the bytes
        // requested is less than the item size.
        let item_prefix = Bytes::from(buf[4..].to_vec());

        // Compute next offset
        let offset = offset
            .checked_add(4)
            .ok_or(Error::OffsetOverflow)?
            .checked_add(size)
            .ok_or(Error::OffsetOverflow)?
            .checked_add(4)
            .ok_or(Error::OffsetOverflow)?;
        Ok((offset, item_prefix))
    }

    /// Returns an unordered stream of all items in the journal.
    ///
    /// # Repair
    ///
    /// If any trailing data is found (i.e. misaligned entries), the journal will be truncated
    /// to the last valid item.
    ///
    /// # Concurrency
    ///
    /// The `concurrency` parameter controls how many blobs are replayed concurrently. This can dramatically
    /// speed up the replay process if the underlying storage supports concurrent reads across different
    /// blobs.
    ///
    /// # Exact
    ///
    /// If `exact` is provided, the stream will only read up to `exact` bytes of each item. Consequently,
    /// this means we will not compute a checksum of the entire data and it is up to the caller to deal
    /// with the consequences of this.
    ///
    /// Reading `exact` bytes and skipping ahead to a future location in a blob is the theoretically optimal
    /// way to read only what is required from storage, however, different storage implementations may take
    /// the opportunity to readahead past what is required (needlessly). If the underlying storage can be tuned
    /// for random access prior to invoking replay, it may lead to less IO.
    pub async fn replay(
        &mut self,
        concurrency: usize,
        exact: Option<usize>,
    ) -> Result<impl Stream<Item = Result<(u64, usize, Bytes), Error>> + '_, Error> {
        // Collect all blobs to replay
        let mut blobs = Vec::with_capacity(self.blobs.len());
        for (section, blob) in self.blobs.iter() {
            let len = blob.len().await.map_err(Error::Runtime)?;
            blobs.push((*section, blob, len));
        }

        // Replay all blobs concurrently and stream items as they are read (to avoid
        // occupying too much memory with buffered data)
        Ok(stream::iter(blobs)
            .map(move |(section, blob, len)| async move {
                stream::unfold(
                    (section, blob, 0),
                    move |(section, blob, offset)| async move {
                        if offset == len {
                            return None;
                        }
                        let read = match exact {
                            Some(exact) => Self::read_exact(blob, offset, exact).await,
                            None => Self::read(blob, offset).await,
                        };
                        match read {
                            Ok((next_offset, item)) => {
                                trace!(blob = section, cursor = offset, "replayed item");
                                Some((Ok((section, offset, item)), (section, blob, next_offset)))
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
                                    (section, blob, offset),
                                ))
                            }
                            Err(Error::Runtime(RError::InsufficientLength)) => {
                                // If we encounter trailing bytes, we prune to the last
                                // valid item. This can happen during an unclean file close (where
                                // pending data is not fully synced to disk).
                                warn!(
                                    blob = section,
                                    new_size = offset,
                                    old_size = len,
                                    "trailing bytes detected: truncating"
                                );
                                blob.truncate(offset).await.map_err(Error::Runtime).ok()?;
                                blob.sync().await.map_err(Error::Runtime).ok()?;
                                None
                            }
                            Err(err) => Some((Err(err), (section, blob, offset))),
                        }
                    },
                )
            })
            .buffer_unordered(concurrency)
            .flatten())
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
    /// If `exact` is provided, only the first `exact` bytes of the item will be read
    /// and returned. Consequently, this returned data cannot be verified for integrity
    /// and it is up to the caller to deal with the consequences of this.
    pub async fn get(
        &self,
        section: u64,
        offset: usize,
        exact: Option<usize>,
    ) -> Result<Option<Bytes>, Error> {
        self.prune_guard(section, false)?;
        let blob = match self.blobs.get(&section) {
            Some(blob) => blob,
            None => return Ok(None),
        };
        let (_, item) = match exact {
            Some(exact) => Self::read_exact(blob, offset, exact).await?,
            None => Self::read(blob, offset).await?,
        };
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
