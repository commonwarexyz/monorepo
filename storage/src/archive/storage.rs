use super::{Config, Error};
use crate::journal::{Config as JConfig, Journal};
use bytes::{Buf, BufMut, Bytes};
use commonware_runtime::{Blob, Storage};
use futures::{pin_mut, StreamExt};
use std::collections::{hash_map::Entry, HashMap};
use tracing::debug;

struct Index {
    section: u64,
    offset: usize,
    next: Option<Box<Index>>,
}

pub struct Archive<B: Blob, E: Storage<B>> {
    cfg: Config,

    journal: Journal<B, E>,

    keys: HashMap<Vec<u8>, Index>,
}

impl<B: Blob, E: Storage<B>> Archive<B, E> {
    fn extract_key(mut data: Bytes) -> Result<Vec<u8>, Error> {
        if data.remaining() == 0 {
            return Err(Error::RecordCorrupted);
        }
        let key_len = data.get_u8() as usize;
        if data.remaining() < key_len {
            return Err(Error::RecordCorrupted);
        }
        let key = data.copy_to_bytes(key_len);
        Ok(key.to_vec())
    }

    fn construct_key(key: &[u8], index_key_len: u8) -> Vec<u8> {
        let index_key_len = index_key_len as usize;
        if key.len() > index_key_len {
            key[..index_key_len].to_vec()
        } else {
            key.to_vec()
        }
    }

    pub async fn init(runtime: E, cfg: Config) -> Result<Self, Error> {
        // Initialize journal
        let mut journal = Journal::init(
            runtime,
            JConfig {
                partition: cfg.partition.clone(),
            },
        )
        .await
        .map_err(Error::Journal)?;

        // Initialize keys and run corruption check
        let mut keys = HashMap::new();
        let mut overlaps: u128 = 0;
        {
            let stream = journal.replay();
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                // Extract key from record
                let (index, offset, data) = result?;
                let key = Self::extract_key(data)?;

                // Create index key
                let key = Self::construct_key(&key, cfg.index_key_len);

                // Store index
                match keys.entry(key) {
                    Entry::Occupied(entry) => {
                        let entry: &mut Index = entry.into_mut();
                        entry.next = Some(Box::new(Index {
                            section: index,
                            offset,
                            next: entry.next.take(),
                        }));
                        overlaps += 1;
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(Index {
                            section: index,
                            offset,
                            next: None,
                        });
                    }
                };
            }
        }
        debug!(keys = keys.len(), overlaps, "archive initialized");

        // Return populated archive
        Ok(Self { cfg, journal, keys })
    }

    pub async fn put(&mut self, section: u64, key: &[u8], data: Bytes) -> Result<(), Error> {
        // Create index key
        let index_key = Self::construct_key(key, self.cfg.index_key_len);

        // Check if duplicate key
        if index_key.len() == key.len() && self.keys.contains_key(&index_key) {
            return Err(Error::DuplicateKey);
        } else if index_key.len() < key.len() {
            let mut record = self.keys.get(&index_key);
            while let Some(index) = record {
                // Fetch item from disk
                let item = self
                    .journal
                    .get(index.section, index.offset)
                    .await?
                    .ok_or(Error::RecordCorrupted)?;

                // Get key from item
                let item_key = Self::extract_key(item)?;
                if key == item_key {
                    return Err(Error::DuplicateKey);
                }

                // Move to next index
                record = index.next.as_deref();
            }
        }

        // Store item in journal
        let mut buf = Vec::with_capacity(1 + key.len() + data.len());
        buf.put_u8(key.len() as u8);
        buf.put(key);
        buf.put(data);
        let offset = self.journal.append(section, buf.into()).await?;

        // Store item in index
        let entry = self.keys.entry(index_key);
        match entry {
            Entry::Occupied(entry) => {
                let entry: &mut Index = entry.into_mut();
                entry.next = Some(Box::new(Index {
                    section,
                    offset,
                    next: entry.next.take(),
                }));
            }
            Entry::Vacant(entry) => {
                entry.insert(Index {
                    section,
                    offset,
                    next: None,
                });
            }
        }
        Ok(())
    }

    pub async fn get(&self, _key: &[u8]) -> Result<Option<Bytes>, Error> {
        unimplemented!()
    }

    pub async fn prune(&mut self, _min: u64) -> Result<(), Error> {
        // TODO: iterate over all keys in-memory (prefer to storing more memory that would
        // allow for more efficient iteration)
        unimplemented!()
    }
}
