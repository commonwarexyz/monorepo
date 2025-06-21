use super::{Config, Error};
use crate::rmap::RMap;
use bytes::{Buf, BufMut};
use commonware_codec::{FixedSize, Read, ReadExt, Write as CodecWrite};
use commonware_runtime::{buffer::Read as ReadBuffer, Blob, Metrics, Storage};
use commonware_utils::{hex, Array};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::HashMap;
use tracing::{debug, trace};

const INDEX_BLOB_NAME: &[u8] = b"index";

/// Record stored in the index file
#[derive(Debug, Clone)]
struct IndexRecord<K: Array> {
    key: K,
    crc: u32,
}

impl<K: Array> IndexRecord<K> {
    fn new(key: K) -> Self {
        let crc = crc32fast::hash(key.as_ref());
        Self { key, crc }
    }

    fn is_valid(&self) -> bool {
        self.crc == crc32fast::hash(self.key.as_ref())
    }
}

impl<K: Array> FixedSize for IndexRecord<K> {
    const SIZE: usize = K::SIZE + 4; // key + crc32
}

impl<K: Array> CodecWrite for IndexRecord<K> {
    fn write(&self, buf: &mut impl BufMut) {
        self.key.write(buf);
        buf.put_slice(&self.crc.to_le_bytes());
    }
}

impl<K: Array> Read for IndexRecord<K> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let key = K::read(buf)?;

        let mut crc_bytes = [0u8; 4];
        buf.copy_to_slice(&mut crc_bytes);
        let crc = u32::from_le_bytes(crc_bytes);

        Ok(Self { key, crc })
    }
}

/// Implementation of `DiskIndex` storage.
pub struct DiskIndex<E: Storage + Metrics, K: Array> {
    // Configuration and context
    context: E,
    config: Config,

    // Index blob for storing key records
    index_blob: E::Blob,

    // RMap for interval tracking
    intervals: RMap,

    // Pending index entries to be synced
    pending_entries: HashMap<u64, K>,

    // Metrics
    items_tracked: Gauge,
    puts: Counter,
    gets: Counter,
    syncs: Counter,

    // Record size for this key type
    record_size: usize,
}

impl<E: Storage + Metrics, K: Array> DiskIndex<E, K> {
    /// Initialize a new `DiskIndex` instance.
    pub async fn init(context: E, config: Config) -> Result<Self, Error> {
        let record_size = IndexRecord::<K>::SIZE;

        // Open index blob
        let (index_blob, blob_len) = context.open(&config.partition, INDEX_BLOB_NAME).await?;

        // Initialize RMap by scanning existing records
        let mut intervals = RMap::new();
        if blob_len > 0 {
            debug!("scanning index file to rebuild RMap");

            let mut index_blob = ReadBuffer::new(index_blob.clone(), blob_len, config.write_buffer);
            let num_records = blob_len as usize / record_size;
            for index in 0..num_records {
                let record_offset = (index * record_size) as u64;
                index_blob.seek_to(record_offset)?;
                let mut record_buf = vec![0u8; record_size];
                index_blob.read_exact(&mut record_buf, record_size).await?;
                let record = IndexRecord::<K>::read(&mut record_buf.as_slice())?;

                if record.is_valid() {
                    intervals.insert(index as u64);
                } else {
                    debug!(index, "found invalid record during scan - stopping");
                    break;
                }
            }

            debug!(
                "rebuilt RMap with {} indices (blob_len={})",
                intervals.iter().count(),
                blob_len
            );
        }

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
    pub async fn get(&mut self, index: u64) -> Result<Option<K>, Error> {
        self.gets.inc();

        // Check pending entries first
        if let Some(key) = self.pending_entries.get(&index) {
            return Ok(Some(key.clone()));
        }

        // Check if index exists in intervals
        if self.intervals.get(&index).is_none() {
            return Ok(None);
        }

        // Read from disk
        let record_offset = index * self.record_size as u64;
        let record_buf = vec![0u8; self.record_size];
        let read_buf = self.index_blob.read_at(record_buf, record_offset).await?;

        let mut buf_slice = read_buf.as_ref();
        let record = IndexRecord::<K>::read(&mut buf_slice)?;

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
            let record = IndexRecord::new(key.clone());
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
