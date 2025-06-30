use super::{Config, Error};
use crate::rmap::RMap;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode as _, FixedSize, Read as CodecRead, ReadExt, Write as CodecWrite};
use commonware_runtime::{
    buffer::{Read, Write},
    Blob, Clock, Error as RError, Metrics, Storage,
};
use commonware_utils::{hex, Array};
use futures::future::try_join_all;
use prometheus_client::metrics::counter::Counter;
use std::{
    collections::{btree_map::Entry, BTreeMap},
    mem::take,
};
use tracing::{debug, warn};

const PARITY_BIT: u32 = 1 << 31;
const CRC_MASK: u32 = 0x7FFF_FFFF;

/// Header stored at the beginning of each blob.
#[derive(Debug, Clone, Copy)]
struct Header {
    parity: u8,
}

impl CodecRead for Header {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let parity = u8::read(buf)?;
        Ok(Self { parity })
    }
}

impl CodecWrite for Header {
    fn write(&self, buf: &mut impl BufMut) {
        self.parity.write(buf);
    }
}

impl FixedSize for Header {
    const SIZE: usize = u8::SIZE;
}

/// Value stored in the index file.
#[derive(Debug, Clone)]
struct Record<V: Array> {
    value: V,
    crc: u32,
}

impl<V: Array> Record<V> {
    fn new(value: V, parity: u8) -> Self {
        let mut crc = crc32fast::hash(value.as_ref());
        crc &= CRC_MASK;
        crc |= (parity as u32) << 31;
        Self { value, crc }
    }

    fn is_valid(&self, committed_parity: u8) -> bool {
        let record_parity = (self.crc >> 31) as u8;
        if record_parity != committed_parity {
            return false;
        }
        (self.crc & CRC_MASK) == (crc32fast::hash(self.value.as_ref()) & CRC_MASK)
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

impl<V: Array> CodecRead for Record<V> {
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

    // Committed parity for each blob
    parities: BTreeMap<u64, u8>,

    // RMap for interval tracking
    intervals: RMap,

    // Pending index entries to be synced, grouped by section
    pending: BTreeMap<u64, BTreeMap<u64, V>>,

    // Metrics
    puts: Counter,
    gets: Counter,
    has: Counter,
    syncs: Counter,
    pruned: Counter,
}

impl<E: Storage + Metrics + Clock, V: Array> Ordinal<E, V> {
    /// Initialize a new [Ordinal] instance.
    pub async fn init(context: E, config: Config) -> Result<Self, Error> {
        // Scan for all blobs in the partition
        let mut blobs = BTreeMap::new();
        let mut parities = BTreeMap::new();
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

            // Read header or create one if blob is new/too small
            let header = if len >= HEADER_SIZE {
                let mut header_buf = vec![0u8; Header::SIZE];
                let header_buf = blob.read_at(header_buf, 0).await?;
                Header::read(&mut header_buf.as_slice())?
            } else {
                let header = Header::default();
                blob.write_at(header.encode(), 0).await?;
                len = HEADER_SIZE;
                blob.resize(len).await?;
                blob.sync().await?;
                header
            };
            parities.insert(index, header.committed_parity);

            // Check if blob data size is aligned to record size
            let data_len = len - HEADER_SIZE;
            let record_size = Record::<V>::SIZE as u64;
            if data_len % record_size != 0 {
                warn!(
                    blob = index,
                    invalid_size = len,
                    record_size,
                    "blob size is not a multiple of record size, truncating"
                );
                len = HEADER_SIZE + data_len - (data_len % record_size);
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
            let committed_parity = *parities.get(section).unwrap();

            // Initialize read buffer
            let size = blob.size().await;
            let mut replay_blob = Read::new(blob.clone(), size, config.replay_buffer);

            // Iterate over all records in the blob
            let mut offset = HEADER_SIZE;
            while offset < size {
                // Calculate index for this record
                let index = section * config.items_per_blob
                    + ((offset - HEADER_SIZE) / Record::<V>::SIZE as u64);

                // Attempt to read record at offset
                replay_blob.seek_to(offset)?;
                let mut record_buf = vec![0u8; Record::<V>::SIZE];
                replay_blob
                    .read_exact(&mut record_buf, Record::<V>::SIZE)
                    .await?;
                let record = Record::<V>::read(&mut record_buf.as_slice())?;
                offset += Record::<V>::SIZE as u64;

                // If record is valid, add to intervals
                if record.is_valid(committed_parity) {
                    items += 1;
                    intervals.insert(index);
                    continue;
                }

                // If record is invalid, it may either be empty or corrupted. We don't
                // store enough information to determine which (and thus don't log).
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
            parities,
            intervals,
            pending: BTreeMap::new(),
            puts,
            gets,
            has,
            syncs,
            pruned,
        })
    }

    /// Add a value at the specified index (pending until sync).
    pub fn put(&mut self, index: u64, value: V) -> Result<(), Error> {
        self.puts.inc();
        let section = index / self.config.items_per_blob;
        self.pending
            .entry(section)
            .or_default()
            .insert(index, value);
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

        // Check pending entries first
        let section = index / self.config.items_per_blob;
        if let Some(writes) = self.pending.get(&section) {
            if let Some(value) = writes.get(&index) {
                return Ok(Some(value.clone()));
            }
        }

        // Read from disk
        let section = index / self.config.items_per_blob;
        let blob = self.blobs.get(&section).unwrap();
        let committed_parity = *self.parities.get(&section).unwrap();
        let offset = HEADER_SIZE + (index % self.config.items_per_blob) * Record::<V>::SIZE as u64;
        let read_buf = vec![0u8; Record::<V>::SIZE];
        let read_buf = blob.read_at(read_buf, offset).await?;
        let record = Record::<V>::read(&mut read_buf.as_ref())?;

        // If record is valid, return it
        if record.is_valid(committed_parity) {
            Ok(Some(record.value))
        } else {
            debug!(
                index,
                "record failed validation, likely from an incomplete sync"
            );
            Ok(None)
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

    /// Prune indices older than `min` by removing entire blobs.
    ///
    /// Pruning is done at blob boundaries to avoid partial deletions. A blob is pruned only if
    /// all possible indices in that blob are less than `min`.
    pub async fn prune(&mut self, min: u64) -> Result<(), Error> {
        // Collect sections to remove
        let min_section = min / self.config.items_per_blob;
        let sections_to_remove: Vec<u64> = self
            .blobs
            .keys()
            .filter(|&&section| section < min_section)
            .copied()
            .collect();

        // Remove the collected sections
        for section in sections_to_remove {
            if let Some(blob) = self.blobs.remove(&section) {
                blob.close().await?;
                self.context
                    .remove(&self.config.partition, Some(&section.to_be_bytes()))
                    .await?;

                // Remove the corresponding index range from intervals
                let start_index = section * self.config.items_per_blob;
                let end_index = (section + 1) * self.config.items_per_blob - 1;
                self.intervals.remove(start_index, end_index);
                debug!(section, start_index, end_index, "pruned blob");
            }

            // Update metrics
            self.pruned.inc();
        }

        // Clean pending entries that fall into pruned sections.
        self.pending.retain(|&section, _| section >= min_section);

        Ok(())
    }

    /// Write all pending entries and sync all modified [Blob]s.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.syncs.inc();

        // Take the pending writes, which are already grouped by section.
        let pending = take(&mut self.pending);
        if pending.is_empty() {
            return Ok(());
        }

        // --- Phase 1: Write records with new parity bit ---

        // Ensure all necessary blobs are created and get their current parity.
        let modified: Vec<u64> = pending.keys().copied().collect();
        for &section in &modified {
            if let Entry::Vacant(entry) = self.blobs.entry(section) {
                let (blob, len) = self
                    .context
                    .open(&self.config.partition, &section.to_be_bytes())
                    .await?;

                let (header, final_len) = if len >= HEADER_SIZE {
                    let mut header_buf = vec![0u8; Header::SIZE];
                    let header_buf = blob.read_at(header_buf, 0).await?;
                    (Header::read(&mut header_buf.as_slice())?, len)
                } else {
                    let header = Header::default();
                    blob.write_at(header.encode(), 0).await?;
                    (header, HEADER_SIZE)
                };

                entry.insert(Write::new(blob, final_len, self.config.write_buffer));
                self.parities.insert(section, header.committed_parity);
                debug!(section, "created blob for sync");
            }
        }

        // Write all pending entries to disk with the next parity bit.
        let mut futures = Vec::new();
        for (section, writes) in &pending {
            let blob = self.blobs.get(section).unwrap();
            let new_parity = self.parities.get(section).unwrap() ^ 1;
            for (index, value) in writes {
                let offset =
                    HEADER_SIZE + (index % self.config.items_per_blob) * Record::<V>::SIZE as u64;
                let record = Record::new(value.clone(), new_parity);
                futures.push(blob.write_at(record.encode(), offset));
            }
        }
        try_join_all(futures).await?;

        // Sync the modified blobs to persist the data records.
        let mut futures = Vec::with_capacity(modified.len());
        for &section in &modified {
            futures.push(self.blobs.get(&section).unwrap().sync());
        }
        try_join_all(futures).await?;

        // --- Phase 2: Flip parity bit in header ---

        // Write the new headers to disk.
        let mut futures = Vec::new();
        for &section in &modified {
            let blob = self.blobs.get(&section).unwrap();
            let new_parity = self.parities.get(&section).unwrap() ^ 1;
            let header = Header {
                committed_parity: new_parity,
                ..Default::default()
            };
            futures.push(blob.write_at(header.encode(), 0));
        }
        try_join_all(futures).await?;

        // Sync the modified blobs again to persist the headers.
        let mut futures = Vec::with_capacity(modified.len());
        for &section in &modified {
            futures.push(self.blobs.get(&section).unwrap().sync());
        }
        try_join_all(futures).await?;

        // Update in-memory parity state now that the commit is complete.
        for &section in &modified {
            self.parities.entry(section).and_modify(|p| *p ^= 1);
        }

        Ok(())
    }

    /// Sync all pending entries and close all [Blob]s.
    pub async fn close(mut self) -> Result<(), Error> {
        // Sync any pending entries
        self.sync().await?;

        // Close all blobs
        for (_, blob) in take(&mut self.blobs) {
            blob.close().await?;
        }
        Ok(())
    }

    /// Destroy [Ordinal] and remove all data.
    pub async fn destroy(self) -> Result<(), Error> {
        for (i, blob) in self.blobs.into_iter() {
            blob.close().await?;
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
