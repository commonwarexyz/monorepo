use super::{Config, Error};
use bytes::{BufMut, Bytes};
use commonware_runtime::{Blob, Error as RError, Storage};
use commonware_utils::hex;
use futures::{stream, Stream};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    marker::PhantomData,
};
use tracing::{debug, trace, warn};

/// Implementation of an append-only log for storing arbitrary data.
pub struct Journal<B: Blob, E: Storage<B>> {
    runtime: E,
    cfg: Config,

    blobs: BTreeMap<u64, B>,

    _phantom_b: PhantomData<B>,
}

impl<B: Blob, E: Storage<B>> Journal<B, E> {
    /// Initialize a new `journal` instance.
    ///
    /// All backing blobs are opened but not read during
    /// initialization. The `replay` method can be used
    /// to iterate over all items in the `journal`.
    pub async fn init(mut runtime: E, cfg: Config) -> Result<Self, Error> {
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

        // Create journal instance
        Ok(Self {
            runtime,
            cfg,

            blobs,

            _phantom_b: PhantomData,
        })
    }

    /// Reads an item from the blob at the given offset.
    async fn read(blob: &mut B, offset: usize) -> Result<(usize, Bytes), Error> {
        // Read item size
        let mut size = [0u8; 4];
        let bytes_read = blob
            .read_at(&mut size, offset)
            .await
            .map_err(Error::Runtime)?;
        if bytes_read != 4 {
            warn!("size missing");
            return Err(Error::BlobCorrupt);
        }
        let size = u32::from_be_bytes(size)
            .try_into()
            .expect("usize too small");
        let offset = offset + 4;

        // Read item
        let mut item = vec![0u8; size];
        let bytes_read = blob
            .read_at(&mut item, offset)
            .await
            .map_err(Error::Runtime)?;
        if bytes_read != size {
            warn!("item missing");
            return Err(Error::BlobCorrupt);
        }
        let offset = offset + size;

        // Read checksum
        let mut stored_checksum = [0u8; 4];
        let bytes_read = blob
            .read_at(&mut stored_checksum, offset)
            .await
            .map_err(Error::Runtime)?;
        if bytes_read != 4 {
            warn!("checksum missing");
            return Err(Error::BlobCorrupt);
        }
        let stored_checksum = u32::from_be_bytes(stored_checksum);
        let checksum = crc32fast::hash(&item);
        if checksum != stored_checksum {
            warn!(
                expected = checksum,
                actual = stored_checksum,
                "checksum mismatch"
            );
            return Err(Error::BlobCorrupt);
        }
        let offset = offset + 4;

        // Return item
        Ok((offset, Bytes::from(item)))
    }

    /// Returns a stream of all items in the journal.
    ///
    /// If any data is found to be corrupt, it will be removed from the journal during this iteration.
    pub fn replay(&mut self) -> impl Stream<Item = Result<(u64, Bytes), Error>> + '_ {
        stream::try_unfold(
            (self.blobs.iter_mut(), None::<(&u64, &mut B, usize)>, 0usize),
            |(mut stream_iter, mut stream_blob, mut stream_offset)| async move {
                // Select next blob
                loop {
                    if let Some((section, blob, len)) = stream_blob {
                        // Move to next blob if nothing left to read
                        if stream_offset == len {
                            stream_blob = None;
                            continue;
                        }

                        // Attempt to read next item
                        match Self::read(blob, stream_offset).await {
                            Ok((next_offset, item)) => {
                                trace!(blob = *section, cursor = stream_offset, "replayed item");
                                return Ok(Some((
                                    (*section, item),
                                    (stream_iter, Some((section, blob, len)), next_offset),
                                )));
                            }
                            Err(Error::BlobCorrupt) => {
                                // Truncate blob
                                //
                                // This is a best-effort attempt to recover from corruption. If there is an unclean
                                // shutdown, it is possible that some trailing item was not fully written to disk.
                                warn!(
                                    blob = *section,
                                    new_size = stream_offset,
                                    old_size = len,
                                    "corruption detected: truncating blob"
                                );
                                blob.truncate(stream_offset).await.map_err(Error::Runtime)?;
                                blob.sync().await.map_err(Error::Runtime)?;

                                // Move to next blob
                                stream_blob = None;
                            }
                            Err(err) => return Err(err),
                        }
                    } else if let Some((section, blob)) = stream_iter.next() {
                        let len = blob.len().await.map_err(Error::Runtime)?;
                        debug!(blob = *section, len, "replaying blob");
                        stream_blob = Some((section, blob, len));
                        stream_offset = 0;
                        continue;
                    } else {
                        // No more blobs
                        return Ok(None);
                    }
                }
            },
        )
    }

    /// Appends an item to the `journal` in a given `section`.
    pub async fn append(&mut self, section: u64, item: Bytes) -> Result<(), Error> {
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
        blob.write_at(&buf, cursor).await.map_err(Error::Runtime)
    }

    /// Ensures that all data in a given `section` is synced to the underlying store.
    ///
    /// If the `section` does not exist, no error will be returned.
    pub async fn sync(&mut self, section: u64) -> Result<(), Error> {
        let blob = match self.blobs.get_mut(&section) {
            Some(blob) => blob,
            None => return Ok(()),
        };
        blob.sync().await.map_err(Error::Runtime)
    }

    /// Prunes all `sections` less than `min`.
    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        loop {
            // Check if we should remove next blob
            let section = match self.blobs.first_key_value() {
                Some((section, _)) => *section,
                None => {
                    // If there are no more blobs, we return instead
                    // of removing the partition.
                    return Ok(());
                }
            };
            if section >= min {
                return Ok(());
            }

            // Remove and close blob
            let mut blob = self.blobs.remove(&section).unwrap();
            blob.close().await.map_err(Error::Runtime)?;

            // Remove blob from storage
            self.runtime
                .remove(&self.cfg.partition, Some(&section.to_be_bytes()))
                .await
                .map_err(Error::Runtime)?;
            debug!(blob = section, "pruned blob");
        }
    }

    /// Closes all open sections.
    pub async fn close(mut self) -> Result<(), Error> {
        for (section, blob) in self.blobs.iter_mut() {
            blob.close().await.map_err(Error::Runtime)?;
            debug!(blob = section, "closed blob");
        }
        Ok(())
    }
}
