use super::{Config, Error, Translator};
use crate::journal::Journal;
use bytes::{Buf, BufMut, Bytes};
use commonware_runtime::{Blob, Storage};
use futures::{pin_mut, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{hash_map::Entry, BTreeMap, HashMap};
use tracing::debug;

/// In the case there are multiple records with the same key, we store them in a linked list.
///
/// This is the most memory-efficient way to maintain a multi-map.
struct Index {
    section: u64,
    offset: usize,
    next: Option<Box<Index>>,
}

pub struct Archive<T: Translator, B: Blob, E: Storage<B>> {
    cfg: Config<T>,
    journal: Journal<B, E>,

    // We store the first index of the linked list in the HashMap
    // to significantly reduce the number of random reads we need to do
    // on the heap.
    keys: HashMap<T::Key, Index>,

    // We store a vector of keys for each journal section for fast pruning (to
    // avoid a global iteration of values and/or re-reading a journal from disk).
    //
    // There may be duplicate keys in the vector but we don't expect the number
    // of duplicates to be significant.
    journal_keys: BTreeMap<u64, Vec<T::Key>>,

    // Track the number of writes pending for a section to determine when to sync.
    pending_writes: HashMap<u64, usize>,

    keys_tracked: Gauge,
    unnecessary_reads: Counter,
    gets: Counter,
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

    pub async fn init(mut journal: Journal<B, E>, cfg: Config<T>) -> Result<Self, Error> {
        // Initialize keys and run corruption check
        let mut keys = HashMap::new();
        let mut journal_keys = BTreeMap::new();
        let mut overlaps: u128 = 0;
        {
            debug!("initializing archive");
            let stream = journal.replay();
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                // Extract key from record
                let (index, offset, data) = result?;
                let (key, _) = Self::parse_item(data)?;

                // Create index key
                let index_key = cfg.translator.transform(&key);

                // Store index
                match keys.entry(index_key.clone()) {
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

                // Store key in journal_keys
                journal_keys
                    .entry(index)
                    .or_insert_with(Vec::new)
                    .push(index_key);
            }
            debug!(keys = keys.len(), overlaps, "archive initialized");
        }

        // Initialize metrics
        let keys_tracked = Gauge::default();
        let unnecessary_reads = Counter::default();
        let gets = Counter::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register(
                "keys_tracked",
                "Number of keys tracked by the archive",
                keys_tracked.clone(),
            );
            registry.register(
                "unnecessary_reads",
                "Number of unnecessary reads performed by the archive",
                unnecessary_reads.clone(),
            );
            registry.register(
                "gets",
                "Number of gets performed by the archive",
                gets.clone(),
            );
        }

        // Return populated archive
        Ok(Self {
            cfg,
            journal,
            keys,
            journal_keys,
            pending_writes: HashMap::new(),
            keys_tracked,
            unnecessary_reads,
            gets,
        })
    }

    /// Put only ensures uniqueness of keys within the same section.
    pub async fn put(&mut self, section: u64, key: &[u8], data: Bytes) -> Result<(), Error> {
        // Create index key
        let index_key = self.cfg.translator.transform(key);

        // Check if duplicate key
        let mut record = self.keys.get(&index_key);
        while let Some(index) = record {
            // Check key from disk if in same section
            if index.section == section {
                let item = self
                    .journal
                    .get(index.section, index.offset)
                    .await?
                    .ok_or(Error::RecordCorrupted)?;
                let (item_key, _) = Self::parse_item(item)?;
                if key == item_key {
                    return Err(Error::DuplicateKey);
                }
                self.unnecessary_reads.inc();
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
        let entry = self.keys.entry(index_key.clone());
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

        // Update pending writes
        let pending_writes = self.pending_writes.entry(section).or_default();
        *pending_writes += 1;
        if *pending_writes > self.cfg.pending_writes {
            self.journal.sync(section).await.map_err(Error::Journal)?;
            *pending_writes = 0;
        }

        // Store key in journal_keys
        self.journal_keys
            .entry(section)
            .or_default()
            .push(index_key);

        // Update metrics
        self.keys_tracked.inc();
        Ok(())
    }

    pub async fn get(&self, key: &[u8]) -> Result<Option<Bytes>, Error> {
        // Update metrics
        self.gets.inc();

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
            self.unnecessary_reads.inc();

            // Move to next index
            record = index.next.as_deref();
        }
        Ok(None)
    }

    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        // Remove pruned keys from index
        loop {
            // Get next section to prune
            let mut keys_pruned = 0;
            let mut entries_pruned = 0;
            let section = match self.journal_keys.first_key_value() {
                Some((section, _)) if *section < min => *section,
                _ => break,
            };

            // Remove all keys from the journal
            for key in self.journal_keys.remove(&section).unwrap() {
                // Find new head, updating current head in-place to avoid map modification
                let head = match self.keys.get_mut(&key) {
                    Some(head) => head,
                    None => continue,
                };
                let found = loop {
                    if head.section < min {
                        keys_pruned += 1;
                        match head.next {
                            Some(ref mut next) => {
                                head.section = next.section;
                                head.offset = next.offset;
                                head.next = next.next.take();
                            }
                            None => {
                                break false;
                            }
                        }
                    } else {
                        break true;
                    }
                };

                // If there is no valid head, remove key
                if !found {
                    entries_pruned += 1;
                    self.keys.remove(&key);
                    continue;
                }

                // Keep valid post-head entries
                let mut cursor = head;
                while let Some(next) = cursor.next.as_ref().map(|next| next.section) {
                    // If next is invalid, skip it
                    if next < min {
                        cursor.next = cursor.next.as_mut().unwrap().next.take();
                        keys_pruned += 1;
                        continue;
                    }

                    // If next is valid, set current to next
                    cursor = cursor.next.as_mut().unwrap();
                }
            }
            debug!(section, entries_pruned, keys_pruned, "pruned keys");
            self.keys_tracked.dec_by(keys_pruned as i64);
        }

        // Prune journal to same place
        self.journal.prune(min).await.map_err(Error::Journal)
    }

    pub async fn close(self) -> Result<(), Error> {
        self.journal.close().await.map_err(Error::Journal)
    }
}
