use super::{Config, Error};
use crate::rmap::RMap;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_runtime::{
    buffer::{Read as ReadBuffer, Write},
    Blob, Clock, Metrics, Storage,
};
use commonware_utils::{hex, Array};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    mem::{swap, take},
};
use tracing::{debug, trace, warn};

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

    fn is_empty(&self) -> bool {
        self.value.is_empty() && self.crc == 0
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

/// Implementation of `DiskIndex` storage.
pub struct DiskIndex<E: Storage + Metrics + Clock, V: Array> {
    // Configuration and context
    context: E,
    config: Config,

    // Index blobs for storing key records
    blobs: BTreeMap<u64, Write<E::Blob>>,

    // RMap for interval tracking
    intervals: RMap,

    // Pending index entries to be synced
    pending: HashMap<u64, V>,

    // Metrics
    puts: Counter,
    gets: Counter,
}

impl<E: Storage + Metrics + Clock, V: Array> DiskIndex<E, V> {
    /// Initialize a new `DiskIndex` instance.
    pub async fn init(context: E, config: Config) -> Result<Self, Error> {
        // Scan for all blobs in the partition
        let mut blobs = BTreeMap::new();
        let stored_blobs = context.scan(&config.partition).await?;
        for name in stored_blobs {
            let (blob, len) = context.open(&config.partition, &name).await?;
            let index = match name.try_into() {
                Ok(index) => u64::from_be_bytes(index),
                Err(nm) => Err(Error::InvalidBlobName(nm))?,
            };
            debug!(blob = index, len, "found index blob");
            let blob = Write::new(blob, len, config.write_buffer);
            blobs.insert(index, blob);
        }

        // Initialize intervals by scanning existing records
        debug!(
            blobs = blobs.len(),
            "rebuilding intervals from existing index"
        );
        let mut start = context.current();
        let mut items = 0;
        let mut intervals = RMap::new();
        for (section, blob) in blobs {
            // Initialize read buffer
            let size = blob.size();
            let mut replay_blob = ReadBuffer::new(blob.clone(), size, config.read_buffer);

            // Iterate over all records in the blob
            let mut offset = 0;
            while offset < size {
                // Calculate index for this record
                let index = section * config.items_per_blob + (offset / Record::<V>::SIZE) as u64;

                // Attempt to read record at offset
                replay_blob.seek_to(offset)?;
                let mut record_buf = vec![0u8; Record::<V>::SIZE];
                replay_blob
                    .read_exact(&mut record_buf, Record::<V>::SIZE)
                    .await?;
                let record = Record::<V>::read(&mut record_buf.as_slice())?;

                // If record is empty, skip it
                if record.is_empty() {
                    continue;
                }

                // If record is valid, add to intervals
                if record.is_valid() {
                    items += 1;
                    intervals.insert(index);
                    continue;
                }

                // If record is invalid, do nothing
                warn!(index, "found invalid record during scan");
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
        context.register("puts", "Number of puts performed", puts.clone());
        context.register("gets", "Number of gets performed", gets.clone());

        Ok(Self {
            context,
            config,
            blobs,
            intervals,
            pending: HashMap::new(),
            puts,
            gets,
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
    pub async fn get(&mut self, index: u64) -> Result<Option<V>, Error> {
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
            Err(Error::RecordCorrupted(index))
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

    /// Close the disk index.
    pub async fn close(mut self) -> Result<(), Error> {
        // Sync any pending entries
        self.sync().await?;

        // Close all blobs
        for (_, blob) in take(&mut self.blobs) {
            blob.close().await?;
        }
        Ok(())
    }

    /// Destroy the disk index and remove all data.
    pub async fn destroy(self) -> Result<(), Error> {
        // Close all blobs
        for (i, blob) in self.blobs.into_iter() {
            blob.close().await?;
            self.context
                .remove(&self.config.partition, Some(&i.to_be_bytes()))
                .await?;
            debug!(section = i, "destroyed blob");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::array::FixedBytes;

    type TestKey = FixedBytes<8>;

    #[test]
    fn test_diskindex_basic_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test".to_string(),
                write_buffer: 1024,
            };

            let mut index = DiskIndex::<_, TestKey>::init(context, config)
                .await
                .unwrap();

            // Test put and get
            let key1 = TestKey::new(*b"testkey1");
            index.put(0, key1.clone()).unwrap();

            // Before sync, should find in pending
            assert!(index.has(0));
            let retrieved = index.get(0).await.unwrap();
            assert_eq!(retrieved, Some(key1.clone()));

            // Sync to disk
            index.sync().await.unwrap();

            // After sync, should still work
            assert!(index.has(0));
            let retrieved = index.get(0).await.unwrap();
            assert_eq!(retrieved, Some(key1));

            // Test non-existent index
            assert!(!index.has(999));
            let retrieved = index.get(999).await.unwrap();
            assert_eq!(retrieved, None);

            index.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_diskindex_restart_consistency() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test_restart".to_string(),
                write_buffer: 1024,
            };

            // First session: create and populate index
            {
                let mut index = DiskIndex::<_, TestKey>::init(context.clone(), config.clone())
                    .await
                    .unwrap();

                for i in 0..5u64 {
                    let key = TestKey::new((i as u64).to_be_bytes());
                    index.put(i, key).unwrap();
                }

                index.sync().await.unwrap();
                index.close().await.unwrap();
            }

            // Second session: verify data survives restart
            {
                let mut index = DiskIndex::<_, TestKey>::init(context.clone(), config.clone())
                    .await
                    .unwrap();

                for i in 0..5u64 {
                    assert!(index.has(i));
                    let expected_key = TestKey::new((i as u64).to_be_bytes());
                    let retrieved = index.get(i).await.unwrap();
                    assert_eq!(retrieved, Some(expected_key));
                }

                index.destroy().await.unwrap();
            }
        });
    }

    #[test]
    fn test_diskindex_crash_safety() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test_crash".to_string(),
                write_buffer: 1024,
            };

            // First session: add data but don't sync (simulate crash)
            {
                let mut index = DiskIndex::<_, TestKey>::init(context.clone(), config.clone())
                    .await
                    .unwrap();

                let key = TestKey::new(*b"testkey1");
                index.put(0, key.clone()).unwrap();

                // Don't sync - simulate crash
                // The pending entry should be lost
            }

            // Second session: verify crash safety
            {
                let index = DiskIndex::<_, TestKey>::init(context.clone(), config.clone())
                    .await
                    .unwrap();

                // The unsync'd entry should be gone
                assert!(!index.has(0));

                index.destroy().await.unwrap();
            }
        });
    }
}
