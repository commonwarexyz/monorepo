use super::{Config, Error};
use crate::rmap::RMap;
use bytes::{Buf, BufMut};
use commonware_codec::{FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_runtime::{
    buffer::{Read as ReadBuffer, Write},
    Blob, Metrics, Storage,
};
use commonware_utils::{hex, Array};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{BTreeMap, HashMap};
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
pub struct DiskIndex<E: Storage + Metrics, V: Array> {
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

impl<E: Storage + Metrics, V: Array> DiskIndex<E, V> {
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
        debug!("rebuilding intervals from existing index");
        let mut intervals = RMap::new();
        for (index, blob) in blobs {
            // Initialize read buffer
            let size = blob.size();
            let mut replay_blob = ReadBuffer::new(index.clone(), size, config.read_buffer);

            // Iterate over all records in the blob
            let mut offset = 0;
            while offset < size {
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
                    intervals.insert(index as u64);
                    continue;
                }

                // If record is invalid, do nothing
                warn!(index, "found invalid record during scan");
            }

            debug!(
                "rebuilt RMap with {} indices (blob_len={})",
                intervals.iter().count(),
                blob_len
            );
        }

        // Sync index blob in case we wrote any invalid records
        index_blob.sync().await?;

        // Initialize metrics
        let items_tracked = Gauge::default();
        let puts = Counter::default();
        let gets = Counter::default();
        let syncs = Counter::default();

        context.register(
            "items_tracked",
            "Number of items tracked",
            items_tracked.clone(),
        );
        context.register("puts", "Number of puts performed", puts.clone());
        context.register("gets", "Number of gets performed", gets.clone());
        context.register("syncs", "Number of syncs called", syncs.clone());

        // Set initial item count
        let item_count = intervals.iter().count() as i64;
        items_tracked.set(item_count);

        Ok(Self {
            context,
            config,
            index_blob,
            intervals,
            pending_entries: HashMap::new(),
            items_tracked,
            puts,
            gets,
            syncs,
            record_size,
        })
    }

    /// Add a key at the specified index (pending until sync).
    pub fn put(&mut self, index: u64, key: K) -> Result<(), Error> {
        self.puts.inc();

        // Check if index already exists
        if self.intervals.get(&index).is_some() {
            return Ok(()); // Already exists, no-op
        }

        // Add to pending entries and immediately add to intervals
        trace!(index, key = hex(key.as_ref()), "adding pending index entry");
        self.pending_entries.insert(index, key);
        self.intervals.insert(index);

        Ok(())
    }

    /// Get the key for a given index.
    pub async fn get(&mut self, index: u64) -> Result<Option<V>, Error> {
        self.gets.inc();

        // If get isn't in an interval, it doesn't exist and we don't need to access disk.
        if self.intervals.get(&index).is_none() {
            return Ok(None);
        }

        // Check pending entries first
        if let Some(key) = self.pending_entries.get(&index) {
            return Ok(Some(key.clone()));
        }

        // Read from disk
        let record_offset = index * self.record_size as u64;
        let record_buf = vec![0u8; self.record_size];
        let read_buf = self.index_blob.read_at(record_buf, record_offset).await?;

        let mut buf_slice = read_buf.as_ref();
        let record = Record::<K>::read(&mut buf_slice)?;

        if record.is_valid() {
            Ok(Some(record.key))
        } else {
            Err(Error::RecordCorrupted(index))
        }
    }

    /// Check if an index exists.
    pub fn has(&self, index: u64) -> bool {
        // Check intervals (includes both committed and pending)
        self.intervals.get(&index).is_some()
    }

    /// Get the next gap information for backfill operations.
    pub fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        // Intervals already includes both committed and pending entries
        self.intervals.next_gap(index)
    }

    /// Sync all pending entries to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.syncs.inc();

        if self.pending_entries.is_empty() {
            return Ok(()); // Nothing to sync
        }

        // Write all pending entries to disk
        for (&index, key) in &self.pending_entries {
            let record = Record::new(key.clone());
            let record_offset = index * self.record_size as u64;

            let mut record_buf = Vec::with_capacity(self.record_size);
            record.write(&mut record_buf);

            self.index_blob.write_at(record_buf, record_offset).await?;
        }

        // Sync the blob
        self.index_blob.sync().await?;

        // No need to update intervals - they were already updated in put()

        // Update metrics
        let new_item_count = self.intervals.iter().count() as i64;
        self.items_tracked.set(new_item_count);

        let synced_count = self.pending_entries.len();

        // Clear pending entries
        self.pending_entries.clear();

        debug!("synced {} entries to disk", synced_count);
        Ok(())
    }

    /// Close the disk index.
    pub async fn close(mut self) -> Result<(), Error> {
        // Sync any pending entries
        self.sync().await?;

        self.index_blob.close().await?;
        Ok(())
    }

    /// Destroy the disk index and remove all data.
    pub async fn destroy(self) -> Result<(), Error> {
        self.index_blob.close().await?;
        self.context
            .remove(&self.config.partition, Some(INDEX_BLOB_NAME))
            .await?;
        self.context.remove(&self.config.partition, None).await?;
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
