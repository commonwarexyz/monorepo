use super::{Config, Error};
use crate::rmap::RMap;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_runtime::{
    buffer::{Read as ReadBuffer, Write},
    Blob, Clock, Error as RError, Metrics, Storage,
};
use commonware_utils::{hex, Array, BitVec};
use futures::future::try_join_all;
use prometheus_client::metrics::counter::Counter;
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    marker::PhantomData,
    mem::take,
};
use tracing::{debug, warn};

/// Value stored in the index file.
#[derive(Debug, Clone)]
struct Record<V: Array> {
    value: V,
    crc: u32,
}

impl<V: Array> Record<V> {
    fn new(value: V) -> Self {
        let crc = crc32fast::hash(value.as_ref());
        Self { value, crc }
    }

    fn is_valid(&self) -> bool {
        self.crc == crc32fast::hash(self.value.as_ref())
    }
}

impl<V: Array> FixedSize for Record<V> {
    const SIZE: usize = V::SIZE + u32::SIZE;
}

impl<V: Array> CodecWrite for Record<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.value.write(buf);
        self.crc.write(buf);
    }
}

impl<V: Array> Read for Record<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let value = V::read(buf)?;
        let crc = u32::read(buf)?;

        Ok(Self { value, crc })
    }
}

/// Implementation of [Ordinal].
pub struct Ordinal<E: Storage + Metrics + Clock, V: Array> {
    // Configuration and context
    context: E,
    config: Config,

    // Index blobs for storing key records
    blobs: BTreeMap<u64, Write<E::Blob>>,

    // RMap for interval tracking
    intervals: RMap,

    // Pending index entries to be synced, grouped by section
    pending: BTreeSet<u64>,

    // Metrics
    puts: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,
    pruned: Counter,

    _phantom: PhantomData<V>,
}

impl<E: Storage + Metrics + Clock, V: Array> Ordinal<E, V> {
    /// Initialize a new [Ordinal] instance.
    pub async fn init(context: E, config: Config) -> Result<Self, Error> {
        Self::init_with_bits(context, config, None).await
    }

    /// Initialize a new [Ordinal] instance with a collection of [BitVec]s (indicating which
    /// records should be considered available).
    ///
    /// If a section is not provided in the [BTreeMap], all records in that section are considered
    /// unavailable. If a [BitVec] is provided for a section, all records in that section are
    /// considered available if and only if the [BitVec] is set for the record. If a section is provided
    /// but no [BitVec] is populated, all records in that section are considered available.
    // TODO(#1227): Hide this complexity from the caller.
    pub async fn init_with_bits(
        context: E,
        config: Config,
        bits: Option<BTreeMap<u64, &Option<BitVec>>>,
    ) -> Result<Self, Error> {
        // Scan for all blobs in the partition
        let mut blobs = BTreeMap::new();
        let stored_blobs = match context.scan(&config.partition).await {
            Ok(blobs) => blobs,
            Err(commonware_runtime::Error::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };

        // Open all blobs and check for partial records
        for name in stored_blobs {
            let (blob, mut len) = context.open(&config.partition, &name).await?;
            let index = match name.try_into() {
                Ok(index) => u64::from_be_bytes(index),
                Err(nm) => Err(Error::InvalidBlobName(hex(&nm)))?,
            };

            // Check if blob size is aligned to record size
            let record_size = Record::<V>::SIZE as u64;
            if len % record_size != 0 {
                warn!(
                    blob = index,
                    invalid_size = len,
                    record_size,
                    "blob size is not a multiple of record size, truncating"
                );
                len -= len % record_size;
                blob.resize(len).await?;
                blob.sync().await?;
            }

            debug!(blob = index, len, "found index blob");
            let wrapped_blob = Write::new(blob, len, config.write_buffer);
            blobs.insert(index, wrapped_blob);
        }

        // Initialize intervals by scanning existing records
        debug!(
            blobs = blobs.len(),
            "rebuilding intervals from existing index"
        );
        let start = context.current();
        let mut items = 0;
        let mut intervals = RMap::new();
        for (section, blob) in &blobs {
            // Skip if bits are provided and the section is not in the bits
            if let Some(bits) = &bits {
                if !bits.contains_key(section) {
                    warn!(section, "skipping section without bits");
                    continue;
                }
            }

            // Initialize read buffer
            let size = blob.size().await;
            let mut replay_blob = ReadBuffer::new(blob.clone(), size, config.replay_buffer);

            // Iterate over all records in the blob
            let mut offset = 0;
            let items_per_blob = config.items_per_blob.get();
            while offset < size {
                // Calculate index for this record
                let index = section * items_per_blob + (offset / Record::<V>::SIZE as u64);

                // If bits are provided, skip if not set
                let mut must_exist = false;
                if let Some(bits) = &bits {
                    // If bits are provided, check if the record exists
                    let bits = bits.get(section).unwrap();
                    if let Some(bits) = bits {
                        let bit_index = offset as usize / Record::<V>::SIZE;
                        if !bits.get(bit_index).expect("invalid index") {
                            offset += Record::<V>::SIZE as u64;
                            continue;
                        }
                    }

                    // If bit section exists but it is empty, we must have all records
                    must_exist = true;
                }

                // Attempt to read record at offset
                replay_blob.seek_to(offset)?;
                let mut record_buf = vec![0u8; Record::<V>::SIZE];
                replay_blob
                    .read_exact(&mut record_buf, Record::<V>::SIZE)
                    .await?;
                let record = Record::<V>::read(&mut record_buf.as_slice())?;
                offset += Record::<V>::SIZE as u64;

                // If record is valid, add to intervals
                if record.is_valid() {
                    items += 1;
                    intervals.insert(index);
                    continue;
                }

                // If record is invalid, it may either be empty or corrupted. We only care
                // which is which if the provided bits indicate that the record must exist.
                if must_exist {
                    return Err(Error::MissingRecord(index));
                }
            }
        }
        debug!(
            items,
            elapsed = ?context.current().duration_since(start).unwrap_or_default(),
            "rebuilt intervals"
        );

        // Initialize metrics
        let puts = Counter::default();
        let gets = Counter::default();
        let has = Counter::default();
        let syncs = Counter::default();
        let pruned = Counter::default();
        context.register("puts", "Number of put calls", puts.clone());
        context.register("gets", "Number of get calls", gets.clone());
        context.register("has", "Number of has calls", has.clone());
        context.register("syncs", "Number of sync calls", syncs.clone());
        context.register("pruned", "Number of pruned blobs", pruned.clone());

        Ok(Self {
            context,
            config,
            blobs,
            intervals,
            pending: BTreeSet::new(),
            puts,
            gets,
            has,
            syncs,
            pruned,
            _phantom: PhantomData,
        })
    }

    /// Add a value at the specified index (pending until sync).
    pub async fn put(&mut self, index: u64, value: V) -> Result<(), Error> {
        self.puts.inc();

        // Check if blob exists
        let items_per_blob = self.config.items_per_blob.get();
        let section = index / items_per_blob;
        if let Entry::Vacant(entry) = self.blobs.entry(section) {
            let (blob, len) = self
                .context
                .open(&self.config.partition, &section.to_be_bytes())
                .await?;
            entry.insert(Write::new(blob, len, self.config.write_buffer));
            debug!(section, "created blob");
        }

        // Write the value to the blob
        let blob = self.blobs.get(&section).unwrap();
        let offset = (index % items_per_blob) * Record::<V>::SIZE as u64;
        let record = Record::new(value);
        blob.write_at(record.encode(), offset).await?;
        self.pending.insert(section);

        // Add to intervals
        self.intervals.insert(index);

        Ok(())
    }

    /// Get the value for a given index.
    pub async fn get(&self, index: u64) -> Result<Option<V>, Error> {
        self.gets.inc();

        // If get isn't in an interval, it doesn't exist and we don't need to access disk
        if self.intervals.get(&index).is_none() {
            return Ok(None);
        }

        // Read from disk
        let items_per_blob = self.config.items_per_blob.get();
        let section = index / items_per_blob;
        let blob = self.blobs.get(&section).unwrap();
        let offset = (index % items_per_blob) * Record::<V>::SIZE as u64;
        let read_buf = vec![0u8; Record::<V>::SIZE];
        let read_buf = blob.read_at(read_buf, offset).await?;
        let record = Record::<V>::read(&mut read_buf.as_ref())?;

        // If record is valid, return it
        if record.is_valid() {
            Ok(Some(record.value))
        } else {
            Err(Error::InvalidRecord(index))
        }
    }

    /// Check if an index exists.
    pub fn has(&self, index: u64) -> bool {
        self.has.inc();

        self.intervals.get(&index).is_some()
    }

    /// Get the next gap information for backfill operations.
    pub fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.intervals.next_gap(index)
    }

    /// Get up to the next `max` missing items after `start`.
    pub fn missing_items(&self, start: u64, max: usize) -> Vec<u64> {
        self.intervals.missing_items(start, max)
    }

    /// Prune indices older than `min` by removing entire blobs.
    ///
    /// Pruning is done at blob boundaries to avoid partial deletions. A blob is pruned only if
    /// all possible indices in that blob are less than `min`.
    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        // Collect sections to remove
        let items_per_blob = self.config.items_per_blob.get();
        let min_section = min / items_per_blob;
        let sections_to_remove: Vec<u64> = self
            .blobs
            .keys()
            .filter(|&&section| section < min_section)
            .copied()
            .collect();

        // Remove the collected sections
        for section in sections_to_remove {
            if let Some(blob) = self.blobs.remove(&section) {
                drop(blob);
                self.context
                    .remove(&self.config.partition, Some(&section.to_be_bytes()))
                    .await?;

                // Remove the corresponding index range from intervals
                let start_index = section * items_per_blob;
                let end_index = (section + 1) * items_per_blob - 1;
                self.intervals.remove(start_index, end_index);
                debug!(section, start_index, end_index, "pruned blob");
            }

            // Update metrics
            self.pruned.inc();
        }

        // Clean pending entries that fall into pruned sections.
        self.pending.retain(|&section| section >= min_section);

        Ok(())
    }

    /// Write all pending entries and sync all modified [Blob]s.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.syncs.inc();

        // Sync all modified blobs
        let mut futures = Vec::with_capacity(self.pending.len());
        for &section in &self.pending {
            futures.push(self.blobs.get(&section).unwrap().sync());
        }
        try_join_all(futures).await?;

        // Clear pending sections
        self.pending.clear();

        Ok(())
    }

    /// Sync all pending entries and [Blob]s.
    pub async fn close(mut self) -> Result<(), Error> {
        self.sync().await?;
        for (_, blob) in take(&mut self.blobs) {
            blob.sync().await?;
        }
        Ok(())
    }

    /// Destroy [Ordinal] and remove all data.
    pub async fn destroy(self) -> Result<(), Error> {
        for (i, blob) in self.blobs.into_iter() {
            drop(blob);
            self.context
                .remove(&self.config.partition, Some(&i.to_be_bytes()))
                .await?;
            debug!(section = i, "destroyed blob");
        }
        match self.context.remove(&self.config.partition, None).await {
            Ok(()) => {}
            Err(RError::PartitionMissing(_)) => {
                // Partition already removed or never existed.
            }
            Err(err) => return Err(Error::Runtime(err)),
        }
        Ok(())
    }
}
