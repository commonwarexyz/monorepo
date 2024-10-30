use super::{Config, Error};
use bytes::{BufMut, Bytes};
use commonware_runtime::{Blob, Error as RError, Storage};
use commonware_utils::hex;
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
            return Err(Error::BlobCorrupt);
        }
        let size = u32::from_be_bytes(size) as usize;
        let offset = offset + 4;

        // Read item
        let mut item = vec![0u8; size];
        let bytes_read = blob
            .read_at(&mut item, offset + 4)
            .await
            .map_err(Error::Runtime)?;
        if bytes_read != size {
            return Err(Error::BlobCorrupt);
        }
        let offset = offset + size;
        let checksum = crc32fast::hash(&item);

        // Read checksum
        let mut stored_checksum = [0u8; 4];
        let bytes_read = blob
            .read_at(&mut stored_checksum, offset)
            .await
            .map_err(Error::Runtime)?;
        if bytes_read != 4 {
            return Err(Error::BlobCorrupt);
        }
        let offset = offset + 4;
        let stored_checksum = u32::from_be_bytes(stored_checksum);
        if checksum != stored_checksum {
            return Err(Error::BlobCorrupt);
        }

        // Return item
        Ok((offset, Bytes::from(item)))
    }

    pub async fn replay(&mut self, mut f: impl FnMut(u64, Bytes) -> bool) -> Result<(), Error> {
        for (index, blob) in self.blobs.iter_mut() {
            debug!(blob = *index, "replaying blob");
            let mut cursor = 0;
            let len = blob.len().await.map_err(Error::Runtime)?;
            loop {
                match Self::read(blob, cursor).await {
                    Ok((new_cursor, item)) => {
                        trace!(blob = *index, cursor, "replayed item");
                        if !f(*index, item) {
                            break;
                        }
                        cursor = new_cursor;
                    }
                    Err(Error::BlobCorrupt) => {
                        // Truncate blob
                        //
                        // This is a best-effort attempt to recover from corruption. If there is an unclean
                        // shutdown, it is possible that some trailing item was not fully written to disk.
                        warn!(
                            blob = *index,
                            new_size = cursor,
                            old_size = len,
                            "corruption detected: truncating blob"
                        );
                        blob.truncate(cursor).await.map_err(Error::Runtime)?;
                        blob.sync().await.map_err(Error::Runtime)?;
                        break;
                    }
                    Err(err) => return Err(err),
                }
                if cursor == len {
                    break;
                }
            }
        }
        Ok(())
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
            let index = match self.blobs.first_key_value() {
                Some((index, _)) => *index,
                None => return Ok(()),
            };
            if index >= min {
                return Ok(());
            }
            self.blobs.remove(&index);
            self.runtime
                .remove(&self.cfg.partition, Some(&index.to_be_bytes()))
                .await
                .map_err(Error::Runtime)?;
        }
    }
}
