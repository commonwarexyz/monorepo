use super::{Config, Error, Translator};
use crate::journal::variable::Journal;
use bytes::{Buf, BufMut, Bytes};
use commonware_runtime::{Blob, Storage};
use futures::{pin_mut, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rangemap::RangeInclusiveSet;
use std::collections::{hash_map::Entry, BTreeMap, HashMap};
use tracing::{debug, trace};
use zstd::bulk::{compress, decompress};

/// Subject of a `get` or `has` operation.
pub enum Identifier<'a> {
    Index(u64),
    Key(&'a [u8]),
}

/// Location of a record in `Journal`.
struct Location {
    offset: u32,
    len: u32,
}

/// In the case there are multiple records with the same key, we store them in a linked list.
///
/// To minimize memory usage, we store the corresponding index of a particular item to determine
/// its storage position.
struct Record {
    index: u64,

    next: Option<Box<Record>>,
}

/// Implementation of `Archive` storage.
pub struct Archive<T: Translator, B: Blob, E: Storage<B>> {
    cfg: Config<T>,
    journal: Journal<B, E>,

    // Oldest allowed section to read from. This is updated when `prune` is called.
    oldest_allowed: Option<u64>,

    // We store the first index of the linked list in the HashMap
    // to significantly reduce the number of random reads we need to do
    // on the heap.
    indices: BTreeMap<u64, Location>,
    intervals: RangeInclusiveSet<u64>,
    keys: HashMap<T::Key, Record>,

    // Track the number of writes pending for a section to determine when to sync.
    pending_writes: BTreeMap<u64, usize>,

    items_tracked: Gauge,
    indices_pruned: Counter,
    keys_pruned: Counter,
    unnecessary_reads: Counter,
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
        let mut intervals = RangeInclusiveSet::new();
        let mut overlaps: u128 = 0;
        {
            debug!("initializing archive");
            let stream = journal
                .replay(cfg.replay_concurrency, Some(8 + cfg.key_len + 4))
                .await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                // Extract key from record
                let (_, offset, len, data) = result?;
                let (index, key) = Self::parse_prefix(cfg.key_len, data)?;

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

                // Store index in intervals
                intervals.insert(index..=index);
            }
            debug!(keys = keys.len(), overlaps, "archive initialized");
        }

        // Initialize metrics
        let items_tracked = Gauge::default();
        let indices_pruned = Counter::default();
        let keys_pruned = Counter::default();
        let unnecessary_reads = Counter::default();
        let gets = Counter::default();
        let has = Counter::default();
        let syncs = Counter::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register(
                "items_tracked",
                "Number of items tracked",
                items_tracked.clone(),
            );
            registry.register(
                "indices_pruned",
                "Number of indices pruned",
                indices_pruned.clone(),
            );
            registry.register("keys_pruned", "Number of keys pruned", keys_pruned.clone());
            registry.register(
                "unnecessary_reads",
                "Number of unnecessary reads performed during key lookups",
                unnecessary_reads.clone(),
            );
            registry.register("gets", "Number of gets performed", gets.clone());
            registry.register("has", "Number of has performed", has.clone());
            registry.register("syncs", "Number of syncs called", syncs.clone());
        }
        items_tracked.set(indices.len() as i64);

        // Return populated archive
        Ok(Self {
            cfg,
            journal,
            oldest_allowed: None,
            indices,
            intervals,
            keys,
            pending_writes: BTreeMap::new(),
            items_tracked,
            indices_pruned,
            keys_pruned,
            unnecessary_reads,
            gets,
            has,
            syncs,
        })
    }

    fn check_key(&self, key: &[u8]) -> Result<(), Error> {
        if key.len() != self.cfg.key_len as usize {
            return Err(Error::InvalidKeyLength);
        }
        Ok(())
    }

    fn parse_prefix(key_len: u32, mut data: Bytes) -> Result<(u64, Bytes), Error> {
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
        let key_len = key_len as usize;
        if data.remaining() < 8 + key_len + 4 {
            return Err(Error::RecordCorrupted);
        }

        // We don't need the index, so we just skip it
        data.get_u64();

        // Read key from data
        let key = data.copy_to_bytes(key_len);

        // We don't need to compute checksum here as the underlying journal
        // already performs this check for us.
        data.get_u32();

        // Return remaining data as value
        Ok((key, data))
    }

    /// Cleanup keys in-memory that are no longer valid.
    fn cleanup(&mut self, translated_key: &T::Key) {
        // Find new head (first valid key)
        let head = match self.keys.get_mut(translated_key) {
            Some(head) => head,
            None => return,
        };
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        let found = loop {
            if head.index < oldest_allowed {
                self.keys_pruned.inc();
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

        // If there are no valid entries remaining (there is no head), remove key.
        //
        // In practice, we never expect to hit this when `cleanup` is called because we are
        // always inserting a value at this `translated_key` but include for completeness.
        if !found {
            self.keys.remove(translated_key);
            return;
        }

        // Keep valid post-head entries
        let mut cursor = head;
        loop {
            // Set next and continue
            if let Some(next) = cursor.next.as_ref().map(|next| next.index) {
                // If next is invalid, skip it
                if next < oldest_allowed {
                    cursor.next = cursor.next.as_mut().unwrap().next.take();
                    self.keys_pruned.inc();
                    continue;
                }

                // If next is valid, set current to next
                cursor = cursor.next.as_mut().unwrap();
                continue;
            }

            // There is no next, we are done
            return;
        }
    }

    /// Store an item in `Archive`. Both indices and keys are assumed to both be globally unique.
    ///
    /// If the index already exists, an error is returned. If the same key is stored multiple times
    /// at different indices (not recommended), any value associated with the key may be returned.
    pub async fn put(&mut self, index: u64, key: &[u8], data: Bytes) -> Result<(), Error> {
        // Check key length
        self.check_key(key)?;

        // Check last pruned
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        if index < oldest_allowed {
            return Err(Error::AlreadyPrunedTo(oldest_allowed));
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
        self.intervals.insert(index..=index);

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
        //
        // We call this after insertion to avoid unnecessary underlying map
        // operations.
        self.cleanup(&translated_key);

        // Update pending writes
        let pending_writes = self.pending_writes.entry(section).or_default();
        *pending_writes += 1;
        if *pending_writes > self.cfg.pending_writes {
            self.journal.sync(section).await.map_err(Error::Journal)?;
            trace!(section, mode = "pending", "synced section");
            *pending_writes = 0;
            self.syncs.inc();
        }

        // Update metrics
        self.items_tracked.set(self.indices.len() as i64);
        Ok(())
    }

    /// Retrieve an item from `Archive`.
    pub async fn get(&self, identifier: Identifier<'_>) -> Result<Option<Bytes>, Error> {
        match identifier {
            Identifier::Index(index) => self.get_index(index).await,
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    async fn get_index(&self, index: u64) -> Result<Option<Bytes>, Error> {
        // Update metrics
        self.gets.inc();

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

    async fn get_key(&self, key: &[u8]) -> Result<Option<Bytes>, Error> {
        // Check key length
        self.check_key(key)?;

        // Update metrics
        self.gets.inc();

        // Create index key
        let translated_key = self.cfg.translator.transform(key);

        // Fetch index
        let mut record = self.keys.get(&translated_key);
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
                self.unnecessary_reads.inc();
            }

            // Move to next index
            record = head.next.as_deref();
        }
        Ok(None)
    }

    /// Check if an item exists in the `Archive`.
    pub async fn has(&self, identifier: Identifier<'_>) -> Result<bool, Error> {
        self.has.inc();
        match identifier {
            Identifier::Index(index) => Ok(self.has_index(index)),
            Identifier::Key(key) => self.has_key(key).await,
        }
    }

    fn has_index(&self, index: u64) -> bool {
        // Check if index exists
        self.indices.contains_key(&index)
    }

    async fn has_key(&self, key: &[u8]) -> Result<bool, Error> {
        // Check key length
        self.check_key(key)?;

        // Create index key
        let translated_key = self.cfg.translator.transform(key);

        // Fetch index
        let mut record = self.keys.get(&translated_key);
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
                let (_, item_key) = Self::parse_prefix(self.cfg.key_len, item)?;
                if key == item_key {
                    return Ok(true);
                }
                self.unnecessary_reads.inc();
            }

            // Move to next index
            record = head.next.as_deref();
        }
        Ok(false)
    }

    /// Prune `Archive` to the provided `min` (masked by the configured
    /// section mask).
    ///
    /// If this is called with a min lower than the last pruned, nothing
    /// will happen.
    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        // Update `min` to reflect section mask
        let min = self.cfg.section_mask & min;

        // Check if min is less than last pruned
        if let Some(oldest_allowed) = self.oldest_allowed {
            if min <= oldest_allowed {
                // We don't return an error in this case because the caller
                // shouldn't be burdened with converting `min` to some section.
                return Ok(());
            }
        }
        debug!(min, "pruning archive");

        // Prune journal
        self.journal.prune(min).await.map_err(Error::Journal)?;

        // Remove pending writes (no need to call `sync` as we are pruning)
        loop {
            let next = match self.pending_writes.first_key_value() {
                Some((section, _)) if *section < min => *section,
                _ => break,
            };
            self.pending_writes.remove(&next);
        }

        // Remove all indices that are less than min
        loop {
            let next = match self.indices.first_key_value() {
                Some((index, _)) if *index < min => *index,
                _ => break,
            };
            self.indices.remove(&next).unwrap();
            self.indices_pruned.inc();
        }

        // Remove all keys from interval tree less than min
        if min > 0 {
            self.intervals.remove(0..=min - 1);
        }

        // Update last pruned (to prevent reads from
        // pruned sections)
        self.oldest_allowed = Some(min);
        self.items_tracked.set(self.indices.len() as i64);
        Ok(())
    }

    /// Forcibly sync all pending writes across all `Journals`.
    pub async fn sync(&mut self) -> Result<(), Error> {
        for (section, count) in self.pending_writes.iter_mut() {
            if *count == 0 {
                continue;
            }
            self.journal.sync(*section).await.map_err(Error::Journal)?;
            trace!(
                section = *section,
                count = *count,
                mode = "force",
                "synced section"
            );
            self.syncs.inc();
            *count = 0;
        }
        Ok(())
    }

    /// Retrieve the end of the current range including `index` (inclusive) and
    /// the start of the next range after `index` (if it exists).
    ///
    /// This is useful for driving backfill operations over the archive.
    pub fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        // Get end of current range (if exists)
        let current = self.intervals.get(&index);
        let current_end = current.map(|range| range.end());

        // Get start of next range (if exists)
        let next = self.intervals.iter().find(|range| range.start() > &index);
        let next_start = next.map(|range| range.start());
        (current_end.copied(), next_start.copied())
    }

    /// Close `Archive` (and underlying `Journal`).
    ///
    /// Any pending writes will be synced by `Journal` prior
    /// to closing.
    pub async fn close(self) -> Result<(), Error> {
        self.journal.close().await.map_err(Error::Journal)
    }
}
