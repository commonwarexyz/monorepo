use super::{Config, Error};
use bytes::{BufMut, Bytes};
use commonware_runtime::{Blob, Error as RError, Storage};
use commonware_utils::hex;
use futures::stream::{self, Stream, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{btree_map::Entry, BTreeMap};
use tracing::{debug, trace, warn};

const ITEM_ALIGNMENT: u64 = 16;

/// Implementation of `Journal` storage.
pub struct Journal<B: Blob, E: Storage<B>> {
    runtime: E,
    cfg: Config,

    oldest_allowed: Option<u64>,

    blobs: BTreeMap<u64, B>,

    tracked: Gauge,
    synced: Counter,
    pruned: Counter,
}

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

impl<B: Blob, E: Storage<B>> Journal<B, E> {
    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during
    /// initialization. The `replay` method can be used
    /// to iterate over all items in the `Journal`.
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
    async fn read(blob: &B, offset: u32) -> Result<(u32, u32, Bytes), Error> {
        // Read item size
        let offset = offset as u64 * ITEM_ALIGNMENT;
        let mut size = [0u8; 4];
        blob.read_at(&mut size, offset)
            .await
            .map_err(Error::Runtime)?;
        let size = u32::from_be_bytes(size);
        let offset = offset.checked_add(4).ok_or(Error::OffsetOverflow)?;

        // Read item
        let mut item = vec![0u8; size as usize];
        blob.read_at(&mut item, offset)
            .await
            .map_err(Error::Runtime)?;
        let offset = offset
            .checked_add(size as u64)
            .ok_or(Error::OffsetOverflow)?;

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
    async fn read_prefix(blob: &B, offset: u32, prefix: u32) -> Result<(u32, u32, Bytes), Error> {
        // Read item size and first `prefix` bytes
        let offset = offset as u64 * ITEM_ALIGNMENT;
        let mut buf = vec![0u8; 4 + prefix as usize];
        blob.read_at(&mut buf, offset)
            .await
            .map_err(Error::Runtime)?;

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
    async fn read_exact(blob: &B, offset: u32, exact: u32) -> Result<(u32, Bytes), Error> {
        // Read all of the item into one buffer
        let offset = offset as u64 * ITEM_ALIGNMENT;
        let mut buf = vec![0u8; 4 + exact as usize + 4];
        blob.read_at(&mut buf, offset)
            .await
            .map_err(Error::Runtime)?;

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
            let len = blob.len().await.map_err(Error::Runtime)?;
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
                                    (section, blob, offset),
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
                                blob.truncate(offset as u64 * ITEM_ALIGNMENT)
                                    .await
                                    .map_err(Error::Runtime)
                                    .ok()?;
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
        let offset = compute_next_offset(cursor)?;
        blob.write_at(&buf, offset as u64 * ITEM_ALIGNMENT)
            .await
            .map_err(Error::Runtime)?;
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
