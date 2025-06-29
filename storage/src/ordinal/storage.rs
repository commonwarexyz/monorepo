use super::{Config, Error};
use crate::rmap::RMap;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_runtime::{
    buffer::{Read as ReadBuffer, Write},
    Blob, Clock, Metrics, Storage,
};
use commonware_utils::{hex, Array};
use prometheus_client::metrics::counter::Counter;
use std::{
    collections::{BTreeMap, BTreeSet},
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

/// Implementation of ordinal storage.
pub struct Store<E: Storage + Metrics + Clock, V: Array> {
    // Configuration and context
    context: E,
    config: Config,

    // Index blobs for storing key records
    blobs: BTreeMap<u64, Write<E::Blob>>,

    // RMap for interval tracking
    intervals: RMap,

    // Pending index entries to be synced
    pending: BTreeMap<u64, V>,

    // Metrics
    puts: Counter,
    gets: Counter,
    pruned: Counter,
}

impl<E: Storage + Metrics + Clock, V: Array> Store<E, V> {
    /// Initialize a new [Store] instance.
    pub async fn init(context: E, config: Config) -> Result<Self, Error> {
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
            // Initialize read buffer
            let size = blob.size().await;
            let mut replay_blob = ReadBuffer::new(blob.clone(), size, config.replay_buffer);

            // Iterate over all records in the blob
            let mut offset = 0;
            while offset < size {
                // Calculate index for this record
                let index = section * config.items_per_blob + (offset / Record::<V>::SIZE as u64);

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
        let pruned = Counter::default();
        context.register("puts", "Number of puts performed", puts.clone());
        context.register("gets", "Number of gets performed", gets.clone());
        context.register("pruned", "Number of blobs pruned", pruned.clone());

        Ok(Self {
            context,
            config,
            blobs,
            intervals,
            pending: BTreeMap::new(),
            puts,
            gets,
            pruned,
        })
    }

    /// Add a value at the specified index (pending until sync).
    pub fn put(&mut self, index: u64, value: V) -> Result<(), Error> {
        self.puts.inc();
        self.pending.insert(index, value);
        self.intervals.insert(index);

        Ok(())
    }

    /// Get the value for a given index.
    pub async fn get(&self, index: u64) -> Result<Option<V>, Error> {
        self.gets.inc();

        // If get isn't in an interval, it doesn't exist and we don't need to access disk.
        if self.intervals.get(&index).is_none() {
            return Ok(None);
        }

        // Check pending entries first
        if let Some(value) = self.pending.get(&index) {
            return Ok(Some(value.clone()));
        }

        // Read from disk
        let section = index / self.config.items_per_blob;
        let blob = self.blobs.get(&section).unwrap();
        let offset = (index % self.config.items_per_blob) * Record::<V>::SIZE as u64;
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
        self.intervals.get(&index).is_some()
    }

    /// Get the next gap information for backfill operations.
    pub fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.intervals.next_gap(index)
    }

    /// Prune indices older than `min_index` by removing entire blobs. Returns the actual pruning point.
    ///
    /// Pruning is done at blob boundaries to avoid partial deletions. A blob is pruned only if
    /// all possible indices in that blob are less than `min_index`.
    pub async fn prune(&mut self, min_index: u64) -> Result<u64, Error> {
        // Calculate section boundaries
        let min_section = min_index / self.config.items_per_blob;

        if self.blobs.is_empty() {
            return Ok(0);
        }

        // Find oldest and newest sections
        let oldest_section = *self.blobs.keys().next().unwrap();
        let newest_section = *self.blobs.keys().last().unwrap();

        // Don't prune beyond the point where we'd remove the newest section
        let prune_up_to_section = std::cmp::min(min_section, newest_section);

        if prune_up_to_section <= oldest_section {
            // Nothing to prune
            return Ok(oldest_section * self.config.items_per_blob);
        }

        // Remove blobs from oldest_section to prune_up_to_section (exclusive)
        for section in oldest_section..prune_up_to_section {
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
                self.pruned.inc();
            }
        }

        Ok(prune_up_to_section * self.config.items_per_blob)
    }

    /// Sync all pending entries to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Check if there is anything to sync
        if self.pending.is_empty() {
            return Ok(());
        }

        // Write all pending entries to disk
        let mut modified = BTreeSet::new();
        for (index, value) in take(&mut self.pending) {
            // Prepare record
            let section = index / self.config.items_per_blob;
            let offset = (index % self.config.items_per_blob) * Record::<V>::SIZE as u64;
            let record = Record::new(value);

            // If blob doesn't exist, create it
            let mut blob = self.blobs.get(&section);
            if blob.is_none() {
                let (new, len) = self
                    .context
                    .open(&self.config.partition, &section.to_be_bytes())
                    .await?;
                self.blobs
                    .insert(section, Write::new(new, len, self.config.write_buffer));
                blob = self.blobs.get(&section);
                debug!(section, "created blob");
            }

            // Write record to blob
            blob.unwrap().write_at(record.encode(), offset).await?;
            modified.insert(section);
        }

        // Sync the blobs
        for section in modified {
            self.blobs.get(&section).unwrap().sync().await?;
        }
        Ok(())
    }

    /// Close the store.
    pub async fn close(mut self) -> Result<(), Error> {
        // Sync any pending entries
        self.sync().await?;

        // Close all blobs
        for (_, blob) in take(&mut self.blobs) {
            blob.close().await?;
        }
        Ok(())
    }

    /// Destroy the store and remove all data.
    pub async fn destroy(self) -> Result<(), Error> {
        for (i, blob) in self.blobs.into_iter() {
            blob.close().await?;
            self.context
                .remove(&self.config.partition, Some(&i.to_be_bytes()))
                .await?;
            debug!(section = i, "destroyed blob");
        }
        self.context.remove(&self.config.partition, None).await?;
        Ok(())
    }
}
