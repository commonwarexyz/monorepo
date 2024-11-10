use super::{
    interval_tree::{Interval, IntervalTree},
    Config, Error, Translator,
};
use crate::journal::Journal;
use bytes::{Buf, BufMut, Bytes};
use commonware_runtime::{Blob, Storage};
use futures::{pin_mut, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{hash_map::Entry, BTreeMap, HashMap};
use tracing::debug;
use zstd::bulk::{compress, decompress};

// TODO: infer section from index

struct Location {
    offset: u32,
    len: u32,
}

/// In the case there are multiple records with the same key, we store them in a linked list.
///
/// This is the most memory-efficient way to maintain a multi-map (24 bytes per entry, not including
/// the key used to lookup a given index).
struct Record {
    index: u64,

    next: Option<Box<Record>>,
}

/// Implementation of `Archive` storage.
pub struct Archive<T: Translator, B: Blob, E: Storage<B>> {
    cfg: Config<T>,
    journal: Journal<B, E>,

    oldest_allowed: Option<u64>,

    // We store the first index of the linked list in the HashMap
    // to significantly reduce the number of random reads we need to do
    // on the heap.
    indices: BTreeMap<u64, Location>,
    keys: HashMap<T::Key, Record>,

    // Track gaps in the archive
    intervals: IntervalTree,

    // Track the number of writes pending for a section to determine when to sync.
    pending_writes: BTreeMap<u64, usize>,

    keys_tracked: Gauge,
    keys_pruned: Counter,
    unnecessary_prefix_reads: Counter,
    unnecessary_item_reads: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

impl<T: Translator, B: Blob, E: Storage<B>> Archive<T, B, E> {
    /// Initialize a new `Archive` instance.
    ///
    /// The in-memory index for `Archive` is populated during this call
    /// by replaying the journal.
    pub async fn init(mut journal: Journal<B, E>, cfg: Config<T>) -> Result<Self, Error> {
        // Initialize keys and run corruption check
        let mut indices = BTreeMap::new();
        let mut keys = HashMap::new();
        let mut intervals = IntervalTree::new();
        let mut overlaps: u128 = 0;
        {
            debug!("initializing archive");
            let stream = journal
                .replay(cfg.replay_concurrency, Some(cfg.key_len + 8 + 4))
                .await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                // Extract key from record
                let (_, offset, len, data) = result?;
                let (index, key) = Self::parse_record(cfg.key_len, data)?;

                // Store index
                indices.insert(index, Location { offset, len });

                // Create translated key
                let translated_key = cfg.translator.transform(&key);

                // Store index
                match keys.entry(translated_key.clone()) {
                    Entry::Occupied(entry) => {
                        let entry: &mut Record = entry.into_mut();
                        entry.next = Some(Box::new(Record {
                            index,
                            next: entry.next.take(),
                        }));
                        overlaps += 1;
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(Record { index, next: None });
                    }
                };

                // Store interval
                intervals.insert(index);
            }
            debug!(keys = keys.len(), overlaps, "archive initialized");
        }

        // Initialize metrics
        let keys_tracked = Gauge::default();
        let keys_pruned = Counter::default();
        let unnecessary_prefix_reads = Counter::default();
        let unnecessary_item_reads = Counter::default();
        let gets = Counter::default();
        let has = Counter::default();
        let syncs = Counter::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register(
                "keys_tracked",
                "Number of keys tracked",
                keys_tracked.clone(),
            );
            registry.register("keys_pruned", "Number of keys pruned", keys_pruned.clone());
            registry.register(
                "unnecessary_prefix_reads",
                "Number of unnecessary prefix reads performed",
                unnecessary_prefix_reads.clone(),
            );
            registry.register(
                "unnecessary_item_reads",
                "Number of unnecessary item reads performed",
                unnecessary_item_reads.clone(),
            );
            registry.register("gets", "Number of gets performed", gets.clone());
            registry.register("has", "Number of has performed", has.clone());
            registry.register("syncs", "Number of syncs called", syncs.clone());
        }

        // Return populated archive
        Ok(Self {
            cfg,
            journal,
            oldest_allowed: None,
            indices,
            keys,
            intervals,
            pending_writes: BTreeMap::new(),
            keys_tracked,
            keys_pruned,
            unnecessary_prefix_reads,
            unnecessary_item_reads,
            gets,
            has,
            syncs,
        })
    }

    fn verify_key(&self, key: &[u8]) -> Result<(), Error> {
        if key.len() != self.cfg.key_len as usize {
            return Err(Error::InvalidKeyLength);
        }
        Ok(())
    }

    fn parse_record(key_len: u32, mut data: Bytes) -> Result<(u64, Bytes), Error> {
        let key_len = key_len as usize;
        if data.remaining() != 8 + key_len + 4 {
            return Err(Error::RecordCorrupted);
        }
        let found = crc32fast::hash(&data[..key_len + 8]);
        let index = data.get_u64();
        let key = data.copy_to_bytes(key_len);
        let expected = data.get_u32();
        if found != expected {
            return Err(Error::RecordCorrupted);
        }
        Ok((index, key))
    }

    fn parse_item(key_len: u32, mut data: Bytes) -> Result<(Bytes, Bytes), Error> {
        if data.remaining() < 8 + key_len as usize + 4 {
            return Err(Error::RecordCorrupted);
        }

        // We don't need the index, so we just skip it
        data.get_u64();

        let key = data.copy_to_bytes(key_len as usize);

        // We don't need to compute checksum here as the underlying journal
        // already performs this check for us.
        data.get_u32();

        Ok((key, data))
    }

    /// Cleanup keys that are no longer valid.
    fn cleanup(&mut self, index_key: &T::Key) -> Result<(), Error> {
        // Find new head (first valid key)
        let head = match self.keys.get_mut(index_key) {
            Some(head) => head,
            None => return Ok(()),
        };
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        let found = loop {
            if head.index < oldest_allowed {
                self.keys_pruned.inc();
                self.keys_tracked.dec();
                match head.next {
                    Some(ref mut next) => {
                        // Update invalid head in-place
                        head.index = next.index;
                        head.next = next.next.take();
                    }
                    None => {
                        // No valid entries remaining
                        break false;
                    }
                }
            } else {
                // Found valid head
                break true;
            }
        };

        // If there are no valid entries remaining (there is no head), remove key
        if !found {
            self.keys.remove(index_key);
            return Ok(());
        }

        // Keep valid post-head entries
        let mut cursor = head;
        loop {
            // Set next and continue
            if let Some(next) = cursor.next.as_ref().map(|next| next.index) {
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

    /// Store a key-value pair in `Archive`. Indexes and keys are assumed to be unique.
    ///
    /// If the index already exists, an error is returned. If the same key
    /// is stored multiple times at different indices, any value may be returned.
    pub async fn put(&mut self, index: u64, key: &[u8], data: Bytes) -> Result<(), Error> {
        // Check key length
        self.verify_key(key)?;

        // Check last pruned
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        if index < oldest_allowed {
            return Err(Error::AlreadyPrunedToSection(oldest_allowed));
        }

        // Check for existing index
        if self.indices.contains_key(&index) {
            return Err(Error::DuplicateIndex);
        }

        // If compression is enabled, compress the data before storing it.
        let data = if let Some(level) = self.cfg.compression {
            compress(&data, level as i32)
                .map_err(|_| Error::CompressionFailed)?
                .into()
        } else {
            data
        };

        // Store item in journal
        let buf_len = 8usize
            .checked_add(key.len())
            .and_then(|len| len.checked_add(4))
            .and_then(|len| len.checked_add(data.len()))
            .ok_or(Error::RecordTooLarge)?;
        let mut buf = Vec::with_capacity(buf_len);
        buf.put_u64(index);
        buf.put(key);
        // We store the checksum of the key because we employ partial reads from
        // the journal, which aren't verified before returning to `Archive`.
        buf.put_u32(crc32fast::hash(&buf[..]));
        buf.put(data); // we don't need to store data len because we already get this from the journal
        let section = self.cfg.section_mask & index;
        let offset = self.journal.append(section, buf.into()).await?;

        // Store index
        self.indices.insert(
            index,
            Location {
                offset,
                len: buf_len as u32,
            },
        );

        // Store interval
        self.intervals.insert(index);

        // Store item
        let translated_key = self.cfg.translator.transform(key);
        let entry = self.keys.entry(translated_key.clone());
        match entry {
            Entry::Occupied(entry) => {
                let entry: &mut Record = entry.into_mut();
                entry.next = Some(Box::new(Record {
                    index,
                    next: entry.next.take(),
                }));
            }
            Entry::Vacant(entry) => {
                entry.insert(Record { index, next: None });
            }
        }

        // Cleanup tracked keys
        self.cleanup(&translated_key)?;

        // Update pending writes
        let pending_writes = self.pending_writes.entry(section).or_default();
        *pending_writes += 1;
        if *pending_writes > self.cfg.pending_writes {
            self.journal.sync(section).await.map_err(Error::Journal)?;
            *pending_writes = 0;
            self.syncs.inc();
        }

        // Update metrics
        self.keys_tracked.inc();
        Ok(())
    }

    pub async fn get(&self, index: u64) -> Result<Option<Bytes>, Error> {
        // Get index location
        let location = match self.indices.get(&index) {
            Some(location) => location,
            None => return Ok(None),
        };

        // Fetch item from disk
        let section = self.cfg.section_mask & index;
        let item = self
            .journal
            .get(section, location.offset, Some(location.len))
            .await?
            .ok_or(Error::RecordCorrupted)?;

        // Get key from item
        let (_, value) = Self::parse_item(self.cfg.key_len, item)?;

        // If compression is enabled, decompress the data before returning.
        if self.cfg.compression.is_some() {
            return Ok(Some(
                decompress(&value, u32::MAX as usize)
                    .map_err(|_| Error::DecompressionFailed)?
                    .into(),
            ));
        }
        Ok(Some(value))
    }

    /// Retrieve a value from `Archive`.
    pub async fn get_key(&self, key: &[u8]) -> Result<Option<Bytes>, Error> {
        // Check key length
        self.verify_key(key)?;

        // Update metrics
        self.gets.inc();

        // Create index key
        let index_key = self.cfg.translator.transform(key);

        // Fetch index
        let mut record = self.keys.get(&index_key);
        let min_allowed = self.oldest_allowed.unwrap_or(0);
        while let Some(head) = record {
            // Check for data if section is valid
            if head.index >= min_allowed {
                // Fetch item from disk
                let location = self
                    .indices
                    .get(&head.index)
                    .ok_or(Error::RecordCorrupted)?;
                let section = self.cfg.section_mask & head.index;
                let item = self
                    .journal
                    .get(section, location.offset, Some(location.len))
                    .await?
                    .ok_or(Error::RecordCorrupted)?;

                // Get key from item
                let (disk_key, value) = Self::parse_item(self.cfg.key_len, item)?;
                if disk_key == key {
                    // If compression is enabled, decompress the data before returning.
                    if self.cfg.compression.is_some() {
                        return Ok(Some(
                            decompress(&value, u32::MAX as usize)
                                .map_err(|_| Error::DecompressionFailed)?
                                .into(),
                        ));
                    }
                    return Ok(Some(value));
                }
                self.unnecessary_item_reads.inc();
            }

            // Move to next index
            record = head.next.as_deref();
        }
        Ok(None)
    }

    pub async fn has(&self, index: u64) -> Result<bool, Error> {
        Ok(self.indices.contains_key(&index))
    }

    /// Check if a key exists in `Archive`.
    pub async fn has_key(&self, key: &[u8]) -> Result<bool, Error> {
        // Check key length
        self.verify_key(key)?;

        // Update metrics
        self.has.inc();

        // Create index key
        let index_key = self.cfg.translator.transform(key);

        // Fetch index
        let mut record = self.keys.get(&index_key);
        let min_allowed = self.oldest_allowed.unwrap_or(0);
        while let Some(head) = record {
            // Check for data if section is valid
            if head.index >= min_allowed {
                // Fetch item from disk
                let section = self.cfg.section_mask & head.index;
                let location = self
                    .indices
                    .get(&head.index)
                    .ok_or(Error::RecordCorrupted)?;
                let item = self
                    .journal
                    .get_prefix(section, location.offset, 8 + self.cfg.key_len + 4)
                    .await?
                    .ok_or(Error::RecordCorrupted)?;

                // Get key from item
                let (_, item_key) = Self::parse_record(self.cfg.key_len, item)?;
                if key == item_key {
                    return Ok(true);
                }
                self.unnecessary_prefix_reads.inc();
            }

            // Move to next index
            record = head.next.as_deref();
        }
        Ok(false)
    }

    /// Prune `Archive` to the provided section.
    ///
    /// Calling `prune` on a section that has already been pruned will return an error.
    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        // Upset pruning marker
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        if min <= oldest_allowed {
            // Unlike in `put`, we want to return an error if we try to prune the same
            // section twice. In `put`, we just want to make sure we don't return
            // anything that has already been pruned (`< oldest_allowed`).
            return Err(Error::AlreadyPrunedToSection(oldest_allowed));
        }

        // Remove all pending writes (no need to call `sync` as we are pruning)
        loop {
            let next = match self.pending_writes.first_key_value() {
                Some((section, _)) if *section < min => *section,
                _ => break,
            };
            self.pending_writes.remove(&next);
        }

        // Prune journal
        self.journal.prune(min).await.map_err(Error::Journal)?;

        // Remove all indices that are less than min
        loop {
            let next = match self.indices.first_key_value() {
                Some((index, _)) if *index < min => *index,
                _ => break,
            };
            let location = self.indices.remove(&next).unwrap();

            // TODO: how to handle interval update?
        }

        // Update last pruned (to prevent reads from
        // pruned sections)
        self.oldest_allowed = Some(min);
        Ok(())
    }

    /// Sync all pending writes to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        for (section, count) in self.pending_writes.iter_mut() {
            if *count == 0 {
                continue;
            }
            self.journal.sync(*section).await.map_err(Error::Journal)?;
            self.syncs.inc();
            *count = 0;
        }
        Ok(())
    }

    pub fn next_gap(&self, start: u64) -> Option<Interval> {
        self.intervals.find_next_gap(start)
    }

    /// Close `Archive` (and underlying journal).
    pub async fn close(self) -> Result<(), Error> {
        self.journal.close().await.map_err(Error::Journal)
    }
}
