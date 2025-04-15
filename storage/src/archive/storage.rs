use super::{Config, Error, Translator};
use crate::{index::Index, journal::variable::Journal};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::FixedSize;
use commonware_runtime::{Metrics, Storage};
use commonware_utils::Array;
use futures::{pin_mut, StreamExt};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rangemap::RangeInclusiveSet;
use std::collections::BTreeMap;
use tracing::{debug, trace};
use zstd::bulk::{compress, decompress};

/// Subject of a `get` or `has` operation.
pub enum Identifier<'a, K: Array> {
    Index(u64),
    Key(&'a K),
}

/// Location of a record in `Journal`.
struct Location {
    offset: u32,
    len: u32,
}

/// Implementation of `Archive` storage.
pub struct Archive<T: Translator, K: Array, E: Storage + Metrics> {
    cfg: Config<T>,
    journal: Journal<E>,

    // Oldest allowed section to read from. This is updated when `prune` is called.
    oldest_allowed: Option<u64>,

    // To efficiently serve `get` and `has` requests, we map a translated representation of each key
    // to its corresponding index. To avoid iterating over this keys map during pruning, we map said
    // indexes to their locations in the journal.
    keys: Index<T, u64>,
    indices: BTreeMap<u64, Location>,
    intervals: RangeInclusiveSet<u64>,

    // Track the number of writes pending for a section to determine when to sync.
    pending_writes: BTreeMap<u64, usize>,

    items_tracked: Gauge,
    indices_pruned: Counter,
    unnecessary_reads: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,

    _phantom: std::marker::PhantomData<K>,
}

impl<T: Translator, K: Array, E: Storage + Metrics> Archive<T, K, E> {
    const PREFIX_LEN: u32 = (u64::SIZE + K::SIZE + u32::SIZE) as u32;

    /// Initialize a new `Archive` instance.
    ///
    /// The in-memory index for `Archive` is populated during this call
    /// by replaying the journal.
    pub async fn init(context: E, mut journal: Journal<E>, cfg: Config<T>) -> Result<Self, Error> {
        // Initialize keys and run corruption check
        let mut indices = BTreeMap::new();
        let mut keys = Index::init(context.with_label("index"), cfg.translator.clone());
        let mut intervals = RangeInclusiveSet::new();
        {
            debug!("initializing archive");
            let stream = journal
                .replay(cfg.replay_concurrency, Some(Self::PREFIX_LEN))
                .await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                // Extract key from record
                let (_, offset, len, data) = result?;
                let (index, key) = Self::parse_prefix(data)?;

                // Store index
                indices.insert(index, Location { offset, len });

                // Store index in keys
                keys.insert(&key, index);

                // Store index in intervals
                intervals.insert(index..=index);
            }
            debug!(keys = keys.len(), "archive initialized");
        }

        // Initialize metrics
        let items_tracked = Gauge::default();
        let indices_pruned = Counter::default();
        let unnecessary_reads = Counter::default();
        let gets = Counter::default();
        let has = Counter::default();
        let syncs = Counter::default();
        context.register(
            "items_tracked",
            "Number of items tracked",
            items_tracked.clone(),
        );
        context.register(
            "indices_pruned",
            "Number of indices pruned",
            indices_pruned.clone(),
        );
        context.register(
            "unnecessary_reads",
            "Number of unnecessary reads performed during key lookups",
            unnecessary_reads.clone(),
        );
        context.register("gets", "Number of gets performed", gets.clone());
        context.register("has", "Number of has performed", has.clone());
        context.register("syncs", "Number of syncs called", syncs.clone());
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
            unnecessary_reads,
            gets,
            has,
            syncs,
            _phantom: std::marker::PhantomData,
        })
    }

    fn parse_prefix(mut data: Bytes) -> Result<(u64, Bytes), Error> {
        if data.remaining() != Self::PREFIX_LEN as usize {
            return Err(Error::RecordCorrupted);
        }
        let found = crc32fast::hash(&data[..K::SIZE + u64::SIZE]);
        let index = data.get_u64();
        let key = data.copy_to_bytes(K::SIZE);
        let expected = data.get_u32();
        if found != expected {
            return Err(Error::RecordCorrupted);
        }
        Ok((index, key))
    }

    fn parse_item(mut data: Bytes) -> Result<(Bytes, Bytes), Error> {
        if data.remaining() < Self::PREFIX_LEN as usize {
            return Err(Error::RecordCorrupted);
        }

        // We don't need the index, so we just skip it
        data.get_u64();

        // Read key from data
        let key = data.copy_to_bytes(K::SIZE);

        // We don't need to compute checksum here as the underlying journal
        // already performs this check for us.
        data.get_u32();

        // Return remaining data as value
        Ok((key, data))
    }

    /// Store an item in `Archive`. Both indices and keys are assumed to both be globally unique.
    ///
    /// If the index already exists, put does nothing and returns. If the same key is stored multiple times
    /// at different indices (not recommended), any value associated with the key may be returned.
    pub async fn put(&mut self, index: u64, key: K, data: Bytes) -> Result<(), Error> {
        // Check last pruned
        let oldest_allowed = self.oldest_allowed.unwrap_or(0);
        if index < oldest_allowed {
            return Err(Error::AlreadyPrunedTo(oldest_allowed));
        }

        // Check for existing index
        if self.indices.contains_key(&index) {
            return Ok(());
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
        let buf_len = u64::SIZE
            .checked_add(K::SIZE)
            .and_then(|len| len.checked_add(u32::SIZE))
            .and_then(|len| len.checked_add(data.len()))
            .ok_or(Error::RecordTooLarge)?;
        let mut buf = Vec::with_capacity(buf_len);
        buf.put_u64(index);
        buf.put(key.as_ref());
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
        self.keys.insert(&key, index);

        // Cleanup tracked keys
        //
        // We call this after insertion to avoid unnecessary underlying map
        // operations.
        self.keys.remove(&key, |index| *index < oldest_allowed);

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
    pub async fn get(&self, identifier: Identifier<'_, K>) -> Result<Option<Bytes>, Error> {
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
        let (_, value) = Self::parse_item(item)?;

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

    async fn get_key(&self, key: &K) -> Result<Option<Bytes>, Error> {
        // Update metrics
        self.gets.inc();

        // Fetch index
        let iter = self.keys.get_iter(key);
        let min_allowed = self.oldest_allowed.unwrap_or(0);
        for index in iter {
            // Continue if index is no longer allowed due to pruning.
            if *index < min_allowed {
                continue;
            }

            // Fetch item from disk
            let location = self.indices.get(index).ok_or(Error::RecordCorrupted)?;
            let section = self.cfg.section_mask & index;
            let item = self
                .journal
                .get(section, location.offset, Some(location.len))
                .await?
                .ok_or(Error::RecordCorrupted)?;

            // Get key from item
            let (disk_key, value) = Self::parse_item(item)?;
            if disk_key.as_ref() == key.as_ref() {
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

        Ok(None)
    }

    /// Check if an item exists in the `Archive`.
    pub async fn has(&self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
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
        let iter = self.keys.get_iter(key);
        let min_allowed = self.oldest_allowed.unwrap_or(0);
        for index in iter {
            // Continue if index is no longer allowed due to pruning.
            if *index < min_allowed {
                continue;
            }

            // Fetch item from disk
            let section = self.cfg.section_mask & index;
            let location = self.indices.get(index).ok_or(Error::RecordCorrupted)?;
            let item = self
                .journal
                .get_prefix(section, location.offset, Self::PREFIX_LEN)
                .await?
                .ok_or(Error::RecordCorrupted)?;

            // Get key from item
            let (_, item_key) = Self::parse_prefix(item)?;
            if key == item_key {
                return Ok(true);
            }
            self.unnecessary_reads.inc();
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
