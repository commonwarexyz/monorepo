use super::{Config, Error};
use bytes::Bytes;
use commonware_runtime::{Blob, Storage};
use std::{collections::BTreeMap, marker::PhantomData};
use tracing::debug;

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
        let stored_blobs = runtime.scan(&cfg.partition).await.map_err(Error::Runtime)?;
        for name in stored_blobs {
            let blob = runtime
                .open(&cfg.partition, &name)
                .await
                .map_err(Error::Runtime)?;
            let name_bytes = name
                .as_bytes()
                .try_into()
                .map_err(|_| Error::InvalidBlobName(name))?;
            let blob_index = u64::from_be_bytes(name_bytes);
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

    async fn read_next(&self, blob: &mut B, offset: usize) -> Result<(usize, Bytes), Error> {
        // Read item size
        let mut size = [0u8; 4];
        let bytes_read = blob
            .read_at(&mut size, offset)
            .await
            .map_err(Error::Runtime)?;
        if bytes_read != 4 {
            unimplemented!();
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
            unimplemented!();
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
            unimplemented!();
        }
        let offset = offset + 4;
        let stored_checksum = u32::from_be_bytes(stored_checksum);
        if checksum != stored_checksum {
            unimplemented!();
        }

        // Return item
        Ok((offset, Bytes::from(item)))
    }

    pub async fn replay(&mut self, f: impl Fn(u64, Bytes) -> bool) -> Result<(), Error> {
        for (index, blob) in &self.blobs {
            let cursor = 0;
        }
        Ok(())
    }
}
