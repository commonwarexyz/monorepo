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

pub struct Journal<B: Blob, E: Storage<B>> {
    runtime: E,
    cfg: Config,

    blobs: BTreeMap<u64, B>,

    _phantom_b: PhantomData<B>,
}

impl<B: Blob, E: Storage<B>> Journal<B, E> {
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
            if name.len() != 8 {
                return Err(Error::InvalidBlobName(hex(&name)));
            }
            let blob_index = u64::from_be_bytes(name.try_into().unwrap());
            debug!(blob = blob_index, "loaded blob");
            blobs.insert(blob_index, blob);
        }

        // Create journal instance
        Ok(Self {
            runtime,
            cfg,

            blobs,

            _phantom_b: PhantomData,
        })
    }

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
        let size = u32::from_be_bytes(size) as usize;
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

    pub fn replay(&mut self) -> impl Stream<Item = Result<(u64, Bytes), Error>> + '_ {
        stream::try_unfold(
            (self.blobs.iter_mut(), None::<(&u64, &mut B, usize)>, 0usize),
            |(mut stream_iter, mut stream_blob, mut stream_offset)| async move {
                // Select next blob
                loop {
                    if let Some((index, blob, len)) = stream_blob {
                        // Move to next blob if nothing left to read
                        if stream_offset == len {
                            stream_blob = None;
                            continue;
                        }

                        // Attempt to read next item
                        match Self::read(blob, stream_offset).await {
                            Ok((next_offset, item)) => {
                                trace!(blob = *index, cursor = stream_offset, "replayed item");
                                return Ok(Some((
                                    (*index, item),
                                    (stream_iter, Some((index, blob, len)), next_offset),
                                )));
                            }
                            Err(Error::BlobCorrupt) => {
                                // Truncate blob
                                //
                                // This is a best-effort attempt to recover from corruption. If there is an unclean
                                // shutdown, it is possible that some trailing item was not fully written to disk.
                                warn!(
                                    blob = *index,
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
                    } else if let Some((index, blob)) = stream_iter.next() {
                        let len = blob.len().await.map_err(Error::Runtime)?;
                        debug!(blob = *index, len, "replaying blob");
                        stream_blob = Some((index, blob, len));
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

    pub async fn append(&mut self, index: u64, item: Bytes) -> Result<(), Error> {
        // Get existing blob or create new one
        let blob = match self.blobs.entry(index) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let name = index.to_be_bytes();
                let blob = self
                    .runtime
                    .open(&self.cfg.partition, &name)
                    .await
                    .map_err(Error::Runtime)?;
                entry.insert(blob)
            }
        };

        // Write item
        let cursor = blob.len().await.map_err(Error::Runtime)?;
        let len = 4 + item.len() + 4;
        let mut buf = Vec::with_capacity(len);
        buf.put_u32(item.len() as u32);
        let checksum = crc32fast::hash(&item);
        buf.put(item);
        buf.put_u32(checksum);
        blob.write_at(&buf, cursor).await.map_err(Error::Runtime)
    }

    /// If the blob does not exist, no error will be returned.
    pub async fn sync(&mut self, index: u64) -> Result<(), Error> {
        let blob = match self.blobs.get_mut(&index) {
            Some(blob) => blob,
            None => return Ok(()),
        };
        blob.sync().await.map_err(Error::Runtime)
    }

    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        loop {
            // Check if we should remove next blob
            let index = match self.blobs.first_key_value() {
                Some((index, _)) => *index,
                None => return Ok(()),
            };
            if index >= min {
                return Ok(());
            }

            // Remove and close blob
            let mut blob = self.blobs.remove(&index).unwrap();
            blob.close().await.map_err(Error::Runtime)?;

            // Remove blob from storage
            self.runtime
                .remove(&self.cfg.partition, Some(&index.to_be_bytes()))
                .await
                .map_err(Error::Runtime)?;
            debug!(blob = index, "pruned blob");
        }
    }
}
