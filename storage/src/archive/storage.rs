use super::{Config, Error, Translator};
use crate::journal::Journal;
use bytes::{Buf, BufMut, Bytes};
use commonware_runtime::{Blob, Storage};
use futures::{pin_mut, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
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

pub struct Archive<T: Translator, B: Blob, E: Storage<B>> {
    cfg: Config<T>,
    journal: Journal<B, E>,

    oldest_allowed: Option<u64>,

    // We store the first index of the linked list in the HashMap
    // to significantly reduce the number of random reads we need to do
    // on the heap.
    keys: HashMap<T::Key, Index>,

    // Track the number of writes pending for a section to determine when to sync.
    pending_writes: HashMap<u64, usize>,

    keys_tracked: Gauge,
    keys_pruned: Counter,
    unnecessary_reads: Counter,
    gets: Counter,
}

impl<T: Translator, B: Blob, E: Storage<B>> Archive<T, B, E> {
    pub async fn init(mut journal: Journal<B, E>, cfg: Config<T>) -> Result<Self, Error> {
        // Initialize keys and run corruption check
        let mut keys = HashMap::new();
        let mut overlaps: u128 = 0;
        {
            debug!("initializing archive");
            let stream = journal.replay(Some(cfg.key_len + 4));
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                // Extract key from record
                let (index, offset, data) = result?;
                let key = Self::parse_key(cfg.key_len, data)?;

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
            }
            debug!(keys = keys.len(), overlaps, "archive initialized");
        }

        // Initialize metrics
        let keys_tracked = Gauge::default();
        let keys_pruned = Counter::default();
        let unnecessary_reads = Counter::default();
        let gets = Counter::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register(
                "keys_tracked",
                "Number of keys tracked by the archive",
                keys_tracked.clone(),
            );
            registry.register("keys_pruned", "Number of keys pruned", keys_pruned.clone());
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
            oldest_allowed: None,
            keys,
            pending_writes: HashMap::new(),
            keys_tracked,
            keys_pruned,
            unnecessary_reads,
            gets,
        })
    }

    fn parse_key(key_len: usize, mut data: Bytes) -> Result<Bytes, Error> {
        if data.remaining() != key_len + 4 {
            return Err(Error::RecordCorrupted);
        }
        let key = data.copy_to_bytes(key_len);
        let checksum = data.get_u32();
        if checksum != crc32fast::hash(&key) {
            return Err(Error::RecordCorrupted);
        }
        Ok(key)
    }

    fn parse_item(key_len: usize, mut data: Bytes) -> Result<(Bytes, Bytes), Error> {
        if data.remaining() < key_len + 4 {
            return Err(Error::RecordCorrupted);
        }
        let key = data.copy_to_bytes(key_len);

        // We don't need to compute checksum here as the underlying journal
        // already performs this check for us.
        data.get_u32();

        Ok((key, data))
    }

    /// Checks if there exists a duplicate key in the provided section.
    ///
    /// If any records exist that are older than the oldest allowed section, they are pruned.
    async fn check_existing(
        &mut self,
        section: u64,
        key: &[u8],
        index_key: &T::Key,
        oldest_allowed: u64,
    ) -> Result<(), Error> {
        // Find head
        let head = match self.keys.get_mut(index_key) {
            Some(head) => head,
            None => return Ok(()),
        };

        // Find new head, updating current head in-place to avoid map modification
        let found = loop {
            if head.section < oldest_allowed {
                self.keys_pruned.inc();
                self.keys_tracked.dec();
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
            self.keys.remove(index_key);
            return Ok(());
        }

        // Keep valid post-head entries
        let mut cursor = head;
        loop {
            // Check if key is a match
            if section == cursor.section {
                let item = self
                    .journal
                    .get(cursor.section, cursor.offset, Some(self.cfg.key_len + 4))
                    .await?
                    .ok_or(Error::RecordCorrupted)?;
                let item_key = Self::parse_key(self.cfg.key_len, item)?;
                if key == item_key {
                    return Err(Error::DuplicateKey);
                }
                self.unnecessary_reads.inc();
            }

            // Set next and continue
            if let Some(next) = cursor.next.as_ref().map(|next| next.section) {
                // If next is invalid, skip it
                if next < oldest_allowed {
                    self.keys_pruned.inc();
                    self.keys_tracked.dec();
                    cursor.next = cursor.next.as_mut().unwrap().next.take();
                    continue;
                }

                // If next is valid, set current to next
                cursor = cursor.next.as_mut().unwrap();
                continue;
            }

            // There is no next, we are done
            return Ok(());
        }
    }

    /// Only check for equality at provided section
    pub async fn put(&mut self, section: u64, key: &[u8], data: Bytes) -> Result<(), Error> {
        // Check key length
        if key.len() != self.cfg.key_len {
            return Err(Error::InvalidKeyLength);
        }

        // Check last pruned
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        if section < oldest_allowed {
            return Err(Error::AlreadyPrunedToSection(oldest_allowed));
        }

        // Check for existing key in the same section (and clean up any useless
        // entries)
        let index_key = self.cfg.translator.transform(key);
        self.check_existing(section, key, &index_key, oldest_allowed)
            .await?;

        // Store item in journal
        let mut buf = Vec::with_capacity(1 + key.len() + data.len());
        buf.put(key);
        // We store the checksum of the key because we employ partial reads from
        // the journal, which aren't verified before returning to the archive.
        buf.put_u32(crc32fast::hash(key));
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

        // Update metrics
        self.keys_tracked.inc();
        Ok(())
    }

    pub async fn get(&self, key: &[u8]) -> Result<Option<Bytes>, Error> {
        // Check key length
        if key.len() != self.cfg.key_len {
            return Err(Error::InvalidKeyLength);
        }

        // Update metrics
        self.gets.inc();

        // Create index key
        let index_key = self.cfg.translator.transform(key);

        // Fetch index
        let mut record = self.keys.get(&index_key);
        let min_allowed = self.oldest_allowed.unwrap_or(0);
        while let Some(head) = record {
            // Check for data if section is valid
            if head.section >= min_allowed {
                // Fetch item from disk
                let item = self
                    .journal
                    .get(head.section, head.offset, None)
                    .await?
                    .ok_or(Error::RecordCorrupted)?;

                // Get key from item
                let (disk_key, value) = Self::parse_item(self.cfg.key_len, item)?;
                if disk_key == key {
                    return Ok(Some(value));
                }
                self.unnecessary_reads.inc();
            }

            // Move to next index
            record = head.next.as_deref();
        }
        Ok(None)
    }

    /// Calling `prune` on a section that has already been pruned will return an error.
    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        // Upset pruning marker
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        if min <= oldest_allowed {
            return Err(Error::AlreadyPrunedToSection(oldest_allowed));
        }

        // Prune journal
        self.journal.prune(min).await.map_err(Error::Journal)?;

        // Update last pruned (to prevent reads from
        // pruned sections)
        self.oldest_allowed = Some(min);
        Ok(())
    }

    pub async fn close(self) -> Result<(), Error> {
        self.journal.close().await.map_err(Error::Journal)
    }
}
