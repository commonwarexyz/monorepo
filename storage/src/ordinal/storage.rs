use super::{Config, Error};
use crate::rmap::RMap;
use bytes::{Buf, BufMut, BytesMut};
use commonware_codec::{
    Decode, EncodeSize, FixedSize, Read as CodecRead, ReadExt, Write as CodecWrite,
};
use commonware_runtime::{
    buffer::{Read, Write},
    Blob, Clock, Error as RError, Metrics, Storage,
};
use commonware_utils::{hex, Array, BitVec};
use futures::future::try_join_all;
use prometheus_client::metrics::counter::Counter;
use std::{
    collections::{btree_map::Entry, BTreeMap},
    mem::take,
};
use tracing::{debug, warn};

/// Header stored at the beginning of each blob.
#[derive(Debug, Clone)]
struct Header {
    bit_vec: BitVec,
    crc: u32,
}

impl Header {
    /// Create a new header with a valid CRC.
    fn new(bit_vec: BitVec) -> Self {
        let mut buf = BytesMut::new();
        bit_vec.write(&mut buf);
        let crc = crc32fast::hash(&buf);
        Self { bit_vec, crc }
    }

    /// Check if the header's CRC is valid.
    fn is_valid(&self) -> bool {
        let mut buf = BytesMut::new();
        self.bit_vec.write(&mut buf);
        self.crc == crc32fast::hash(&buf)
    }
}

impl CodecRead for Header {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let bit_vec = BitVec::read(buf)?;
        let crc = u32::read(buf)?;
        Ok(Self { bit_vec, crc })
    }
}

impl CodecWrite for Header {
    fn write(&self, buf: &mut impl BufMut) {
        self.bit_vec.write(buf);
        self.crc.write(buf);
    }
}

impl EncodeSize for Header {
    fn encode_size(&self) -> usize {
        self.bit_vec.len() + u32::SIZE
    }
}

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
    header_size: usize,

    // Index blobs for storing key records
    blobs: BTreeMap<u64, Write<E::Blob>>,

    // In-memory cache of blob bitmaps.
    bitmaps: BTreeMap<u64, BitVec>,

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
        // Calculate header size based on config. This is constant for a given `items_per_blob`.
        let header_size = {
            let temp_bitmap = BitVec::zeroes(config.items_per_blob as usize);
            let temp_header = Header::new(temp_bitmap);
            temp_header.encode().len()
        };

        // Scan for all blobs in the partition
        let mut blobs = BTreeMap::new();
        let mut bitmaps = BTreeMap::new();
        let stored_blobs = match context.scan(&config.partition).await {
            Ok(blobs) => blobs,
            Err(commonware_runtime::Error::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };

        // Open all blobs and process their headers
        for name in stored_blobs {
            let (blob, mut len) = context.open(&config.partition, &name).await?;
            let section = match name.try_into() {
                Ok(index) => u64::from_be_bytes(index),
                Err(nm) => Err(Error::InvalidBlobName(hex(&nm)))?,
            };

            let bitmap = if len >= header_size as u64 {
                let mut header_buf = vec![0u8; header_size];
                let header_buf = blob.read_at(header_buf, 0).await?;
                match Header::decode(&mut header_buf.as_ref()) {
                    Ok(h) if h.is_valid() => {
                        debug!(section, "loaded valid header from blob");
                        h.bitmap
                    }
                    _ => {
                        // Header is corrupt or invalid, rescan to repair.
                        warn!(section, "header invalid, rebuilding from records");
                        Self::rebuild_bitmap(&blob, section, &config, header_size).await?
                    }
                }
            } else {
                // Blob is too small, treat as new/empty.
                debug!(section, "blob too small for header, creating new bitmap");
                let new_bitmap = BitVec::zeroes(config.items_per_blob as usize);
                let new_header = Header::new(new_bitmap.clone());
                blob.write_at(new_header.encode(), 0).await?;
                len = header_size as u64;
                blob.resize(len).await?;
                blob.sync().await?;
                new_bitmap
            };

            // Check if blob data size is aligned to record size
            let data_len = len - header_size as u64;
            let record_size = Record::<V>::SIZE as u64;
            if data_len % record_size != 0 {
                warn!(
                    blob = section,
                    invalid_size = len,
                    record_size,
                    "blob size is not a multiple of record size, truncating"
                );
                len = header_size as u64 + data_len - (data_len % record_size);
                blob.resize(len).await?;
                blob.sync().await?;
            }

            debug!(blob = section, len, "found index blob");
            let wrapped_blob = Write::new(blob, len, config.write_buffer);
            blobs.insert(section, wrapped_blob);
            bitmaps.insert(section, bitmap);
        }

        // Initialize intervals from bitmaps for fast startup
        debug!(
            blobs = blobs.len(),
            "rebuilding intervals from existing bitmaps"
        );
        let start = context.current();
        let mut items = 0;
        let mut intervals = RMap::new();
        for (section, bitmap) in &bitmaps {
            for (i, bit) in bitmap.iter().enumerate() {
                if bit {
                    items += 1;
                    let index = section * config.items_per_blob + i as u64;
                    intervals.insert(index);
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
            header_size,
            blobs,
            bitmaps,
            intervals,
            pending: BTreeMap::new(),
            puts,
            gets,
            has,
            syncs,
            pruned,
        })
    }

    /// Rebuilds a blob's bitmap by scanning all its records. This is a recovery mechanism.
    async fn rebuild_bitmap(
        blob: &E::Blob,
        section: u64,
        config: &Config,
        header_size: usize,
    ) -> Result<BitVec, Error> {
        let mut rebuilt_bitmap = BitVec::zeroes(config.items_per_blob as usize);
        let size = blob.size().await;
        let mut replay_blob = ReadBuffer::new(blob.clone(), size, config.replay_buffer);

        let mut offset = header_size as u64;
        while offset < size {
            let index_in_blob = (offset - header_size as u64) / Record::<V>::SIZE as u64;

            replay_blob.seek_to(offset)?;
            let mut record_buf = vec![0u8; Record::<V>::SIZE];
            if replay_blob
                .read_exact(&mut record_buf, Record::<V>::SIZE)
                .await
                .is_err()
            {
                // Partial record at the end, stop here.
                break;
            }
            let record = Record::<V>::read(&mut record_buf.as_slice())?;
            offset += Record::<V>::SIZE as u64;

            if record.is_valid() {
                rebuilt_bitmap.set(index_in_blob as usize);
            }
        }

        // Write the repaired header back to the blob.
        let new_header = Header::new(rebuilt_bitmap.clone());
        blob.write_at(new_header.encode(), 0).await?;
        blob.sync().await?;
        debug!(section, "repaired and synced new header");

        Ok(rebuilt_bitmap)
    }

    /// Add a value at the specified index (pending until sync).
    pub fn put(&mut self, index: u64, value: V) -> Result<(), Error> {
        self.puts.inc();
        let section = index / self.config.items_per_blob;
        let index_in_blob = (index % self.config.items_per_blob) as usize;

        // Add to pending writes for sync.
        self.pending
            .entry(section)
            .or_default()
            .insert(index, value);

        // Update intervals and in-memory bitmap immediately for `has` and `get` calls.
        self.intervals.insert(index);
        self.bitmaps
            .entry(section)
            .or_insert_with(|| BitVec::zeroes(self.config.items_per_blob as usize))
            .set(index_in_blob);

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
        let blob = self.blobs.get(&section).unwrap();
        let offset = self.header_size as u64
            + (index % self.config.items_per_blob) * Record::<V>::SIZE as u64;
        let read_buf = vec![0u8; Record::<V>::SIZE];
        let read_buf = blob.read_at(read_buf, offset).await?;
        let record = Record::<V>::read(&mut read_buf.as_ref())?;

        // If record is valid, return it
        if record.is_valid() {
            Ok(Some(record.value))
        } else {
            // This case implies a torn write or disk corruption, as the bitmap indicated
            // the record should be valid. We treat it as if it doesn't exist.
            warn!(
                index,
                "record failed crc validation despite being in bitmap"
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

                // Remove from in-memory bitmap cache.
                self.bitmaps.remove(&section);

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

        let modified: Vec<u64> = pending.keys().copied().collect();
        for &section in &modified {
            // This will create a blob on disk if it doesn't exist. The in-memory bitmap
            // should have already been created in `put`.
            if let Entry::Vacant(entry) = self.blobs.entry(section) {
                let (new, len) = self
                    .context
                    .open(&self.config.partition, &section.to_be_bytes())
                    .await?;
                entry.insert(Write::new(new, len, self.config.write_buffer));
                debug!(section, "created blob on-demand for sync");
            }
        }

        // --- Phase 1: Write data records ---
        let mut futures = Vec::new();
        for (section, writes) in &pending {
            let blob = self.blobs.get(section).unwrap();
            for (index, value) in writes {
                let offset = self.header_size as u64
                    + (index % self.config.items_per_blob) * Record::<V>::SIZE as u64;
                let record = Record::new(value.clone());
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

        // --- Phase 2: Write new headers ---
        let mut futures = Vec::new();
        for &section in &modified {
            let blob = self.blobs.get(&section).unwrap();
            let bitmap = self.bitmaps.get(&section).unwrap();
            let header = Header::new(bitmap.clone());
            futures.push(blob.write_at(header.encode(), 0));
        }
        try_join_all(futures).await?;

        // Sync the modified blobs again to persist the headers.
        let mut futures = Vec::with_capacity(modified.len());
        for &section in &modified {
            futures.push(self.blobs.get(&section).unwrap().sync());
        }
        try_join_all(futures).await?;

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
