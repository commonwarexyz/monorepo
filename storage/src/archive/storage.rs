use super::{Config, Error, Translator};
use crate::journal::{Config as JConfig, Journal};
use bytes::{Buf, BufMut, Bytes};
use commonware_runtime::{Blob, Storage};
use futures::{pin_mut, StreamExt};
use std::collections::{hash_map::Entry, HashMap};
use tracing::debug;

/// In the case there are multiple records with the same key, we store them in a linked list.
///
/// This is the most memory-efficient way to maintain a multi-map.
struct Index {
    section: u64,
    offset: usize,
    next: Option<Box<Index>>,
}

/// Assumes that all items are spread uniformly across the key space. If that is not the case,
/// lookups may be O(n) instead of O(1).
///
/// If this is not the case, modify the `Capper` implementation to hash keys before returning them.
pub struct Archive<T: Translator, B: Blob, E: Storage<B>> {
    cfg: Config<T>,
    journal: Journal<B, E>,

    // We store the first index of the linked list in the HashMap
    // to significantly reduce the number of random reads we need to do
    // on the heap.
    keys: HashMap<T::Key, Index>,
}

impl<T: Translator, B: Blob, E: Storage<B>> Archive<T, B, E> {
    fn parse_item(mut data: Bytes) -> Result<(Bytes, Bytes), Error> {
        if data.remaining() == 0 {
            return Err(Error::RecordCorrupted);
        }
        let key_len = data.get_u8() as usize;
        if data.remaining() < key_len {
            return Err(Error::RecordCorrupted);
        }
        let key = data.copy_to_bytes(key_len);
        Ok((key, data))
    }

    pub async fn init(runtime: E, cfg: Config<T>) -> Result<Self, Error> {
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
        debug!("initializing archive");
        let mut keys = HashMap::new();
        let mut overlaps: u128 = 0;
        {
            let stream = journal.replay();
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                // Extract key from record
                let (index, offset, data) = result?;
                let (key, _) = Self::parse_item(data)?;

                // Create index key
                let key = cfg.translator.transform(&key);

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
        let index_key = self.cfg.translator.transform(key);

        // Check if duplicate key
        let mut record = self.keys.get(&index_key);
        while let Some(index) = record {
            // Fetch item from disk
            let item = self
                .journal
                .get(index.section, index.offset)
                .await?
                .ok_or(Error::RecordCorrupted)?;

            // Get key from item
            let (item_key, _) = Self::parse_item(item)?;
            if key == item_key {
                return Err(Error::DuplicateKey);
            }

            // Move to next index
            record = index.next.as_deref();
        }

        // Store item in journal
        let mut buf = Vec::with_capacity(1 + key.len() + data.len());
        buf.put_u8(key.len() as u8);
        buf.put(key);
        buf.put(data); // we don't need to store data len because we already get this from the journal
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

    pub async fn get(&mut self, key: &[u8]) -> Result<Option<Bytes>, Error> {
        // Create index key
        let index_key = self.cfg.translator.transform(key);

        // Fetch index
        let mut record = self.keys.get(&index_key);
        while let Some(index) = record {
            // Fetch item from disk
            let item = self
                .journal
                .get(index.section, index.offset)
                .await?
                .ok_or(Error::RecordCorrupted)?;

            // Get key from item
            let (disk_key, value) = Self::parse_item(item)?;
            if disk_key == key {
                return Ok(Some(value));
            }

            // Move to next index
            record = index.next.as_deref();
        }
        Ok(None)
    }

    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        // Prune keys from memory
        //
        // We prefer iterating over all keys in-memory during this infrequent operation to
        // adding more memory overhead to make this pruning more efficient and/or storing
        // list items in sorted order.
        self.keys.retain(|_, head| {
            // Initialize the cursor
            let mut cursor = Some(head);
            let mut keep = false;

            // Iterate over the linked list
            while let Some(item) = cursor {
                if item.section < min {
                    if let Some(next) = item.next.take() {
                        // Replace the current node with the next node
                        *item = *next;
                        // Continue from the current node
                        cursor = Some(item);
                    } else {
                        break;
                    }
                } else {
                    // Move to the next node
                    cursor = item.next.as_deref_mut();
                    keep = true;
                }
            }
            keep
        });

        // Prune journal
        self.journal.prune(min).await.map_err(Error::Journal)
    }
}
