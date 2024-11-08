use super::{Config, Error};
use bytes::{Buf, BufMut, Bytes};
use commonware_runtime::{Blob, Error as RError, Storage};
use commonware_utils::hex;
use std::collections::{btree_map::Entry, BTreeMap, HashMap};
use tracing::debug;

pub struct Index<B: Blob, E: Storage<B>> {
    runtime: E,
    cfg: Config,

    oldest_allowed: Option<u64>,

    blobs: BTreeMap<u64, B>,
}

impl<B: Blob, E: Storage<B>> Index<B, E> {
    /// Initialize a new `Index` instance.
    ///
    /// All backing blobs are opened but not read during
    /// initialization.
    pub async fn new(runtime: E, cfg: Config) -> Result<Self, Error> {
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
        Ok(Self {
            runtime,
            cfg,
            oldest_allowed: None,
            blobs,
        })
    }

    pub async fn put(&mut self, index: u64, data: &[u8]) -> Result<(), Error> {
        if data.len() > self.cfg.value_size as usize {
            return Err(Error::ItemTooLarge(data.len()));
        }
        let section = index / self.cfg.entries_per_blob;
        let offset = index % self.cfg.entries_per_blob * (self.cfg.value_size as u64 + 4);
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
        let mut buf = Vec::with_capacity(data.len() + 4);
        buf.put(data);
        buf.put_u32(crc32fast::hash(data));
        blob.write_at(&buf, offset).await.map_err(Error::Runtime)
    }

    pub async fn get(&self, index: u64) -> Result<Option<Bytes>, Error> {
        let section = index / self.cfg.entries_per_blob;
        let offset = index % self.cfg.entries_per_blob * (self.cfg.value_size as u64 + 4);
        let blob = match self.blobs.get(&section) {
            Some(blob) => blob,
            None => return Ok(None),
        };
        let value_size = self.cfg.value_size as usize;
        let mut buf = vec![0; value_size + 4];
        blob.read_at(&mut buf, offset)
            .await
            .map_err(Error::Runtime)?;
        let mut buf = buf.as_slice();
        let data = buf.copy_to_bytes(value_size);
        let actual = buf.get_u32();
        let expected = crc32fast::hash(&data);
        if expected != actual {
            return Err(Error::ChecksumMismatch(expected, actual));
        }
        Ok(Some(data))
    }

    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        let min_section = min / self.cfg.entries_per_blob;
        while let Some((&section, _)) = self.blobs.first_key_value() {
            if section >= min_section {
                break;
            }
            let blob = self.blobs.remove(&section).unwrap();
            blob.close().await.map_err(Error::Runtime)?;
            debug!(blob = section, "closed blob");

            // Remove blob from storage
            self.runtime
                .remove(&self.cfg.partition, Some(&section.to_be_bytes()))
                .await
                .map_err(Error::Runtime)?;
            debug!(blob = section, "pruned blob");
        }
        self.oldest_allowed = Some(min_section);
        Ok(())
    }

    pub async fn close(self) -> Result<(), Error> {
        for (section, blob) in self.blobs {
            blob.close().await.map_err(Error::Runtime)?;
            debug!(blob = section, "closed blob");
        }
        Ok(())
    }
}
