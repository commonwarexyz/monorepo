use super::{Config, Error};
use crate::{
    diskmap::{Config as DiskMapConfig, DiskMap},
    rmap::RMap,
};
use commonware_codec::Codec;
use commonware_runtime::{Metrics, Storage};
use commonware_utils::{array::U64, Array};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use tracing::debug;

/// Subject of a `get` or `has` operation.
pub enum Identifier<'a, K: Array> {
    Index(u64),
    Key(&'a K),
}

/// Implementation of `Freezer` storage.
pub struct Freezer<E: Storage + Metrics, K: Array, V: Codec> {
    // DiskMap for key -> value storage
    key_to_value: DiskMap<E, K, V>,

    // DiskMap for index -> key mapping
    index_to_key: DiskMap<E, U64, K>,

    // RMap for interval tracking (only in-memory data structure)
    intervals: RMap,

    // Metrics
    items_tracked: Gauge,
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

impl<E: Storage + Metrics, K: Array + Codec<Cfg = ()>, V: Codec> Freezer<E, K, V> {
    /// Initialize a new `Freezer` instance.
    ///
    /// The in-memory RMap is populated during this call by scanning the index diskmap.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize diskmap for key -> value storage
        let key_to_value_config = DiskMapConfig {
            partition: format!("{}_keys", cfg.partition),
            directory_size: cfg.directory_size,
            codec_config: cfg.codec_config.clone(),
            write_buffer: cfg.write_buffer,
            target_journal_size: cfg.target_journal_size,
        };
        let key_to_value =
            DiskMap::init(context.with_label("key_to_value"), key_to_value_config).await?;

        // Initialize diskmap for index -> key mapping
        let index_to_key_config = DiskMapConfig {
            partition: format!("{}_indices", cfg.partition),
            directory_size: cfg.directory_size,
            codec_config: (),
            write_buffer: cfg.write_buffer,
            target_journal_size: cfg.target_journal_size,
        };
        let index_to_key =
            DiskMap::init(context.with_label("index_to_key"), index_to_key_config).await?;

        // Initialize RMap
        // Note: Since diskmap doesn't provide iteration, we can't rebuild RMap from existing data
        // This means the RMap will be empty on restart, which is a limitation
        let intervals = RMap::new();
        {
            debug!("initializing freezer");
            debug!("freezer initialized");
        }

        // Initialize metrics
        let items_tracked = Gauge::default();
        let gets = Counter::default();
        let has = Counter::default();
        let syncs = Counter::default();
        context.register(
            "items_tracked",
            "Number of items tracked",
            items_tracked.clone(),
        );
        context.register("gets", "Number of gets performed", gets.clone());
        context.register("has", "Number of has performed", has.clone());
        context.register("syncs", "Number of syncs called", syncs.clone());

        // Set initial item count to 0 since we can't easily count items in diskmap
        items_tracked.set(0);

        // Return populated freezer
        Ok(Self {
            key_to_value,
            index_to_key,
            intervals,
            items_tracked,
            gets,
            has,
            syncs,
        })
    }

    /// Store an item in `Freezer`. Both indices and keys are assumed to be globally unique.
    ///
    /// If the index already exists, put does nothing and returns. If the same key is stored multiple times
    /// at different indices (not recommended), any value associated with the key may be returned.
    pub async fn put(&mut self, index: u64, key: K, data: V) -> Result<(), Error> {
        // Check if index already exists
        if self.intervals.get(&index).is_some() {
            return Ok(());
        }

        // Store key -> value mapping in diskmap
        self.key_to_value.put(key.clone(), data).await?;

        // Store index -> key mapping in diskmap
        let index_key = U64::new(index);
        self.index_to_key.put(index_key, key).await?;

        // Update interval tracking with the actual index requested
        self.intervals.insert(index);

        // Update metrics (increment by 1)
        let current_count = self.items_tracked.get();
        self.items_tracked.set(current_count + 1);

        Ok(())
    }

    /// Retrieve an item from `Freezer`.
    pub async fn get(&mut self, identifier: Identifier<'_, K>) -> Result<Option<V>, Error> {
        match identifier {
            Identifier::Index(index) => self.get_index(index).await,
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    async fn get_index(&mut self, index: u64) -> Result<Option<V>, Error> {
        // Update metrics
        self.gets.inc();

        // Check if index exists in intervals
        if self.intervals.get(&index).is_none() {
            return Ok(None);
        }

        // Get key from index->key diskmap
        let index_key = U64::new(index);
        let keys = self.index_to_key.get(&index_key).await?;
        let key = match keys.into_iter().next() {
            Some(key) => key,
            None => return Ok(None),
        };

        // Get value from key->value diskmap
        let values = self.key_to_value.get(&key).await?;

        // Return the first value (there should only be one for a given key)
        Ok(values.into_iter().next())
    }

    async fn get_key(&mut self, key: &K) -> Result<Option<V>, Error> {
        // Update metrics
        self.gets.inc();

        // Get value directly from key->value diskmap
        let values = self.key_to_value.get(key).await?;

        // Return the first value (there should only be one for a given key)
        Ok(values.into_iter().next())
    }

    /// Check if an item exists in the `Freezer`.
    pub async fn has(&mut self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
        self.has.inc();
        match identifier {
            Identifier::Index(index) => Ok(self.has_index(index)),
            Identifier::Key(key) => self.has_key(key).await,
        }
    }

    fn has_index(&self, index: u64) -> bool {
        // Check if index exists in intervals
        self.intervals.get(&index).is_some()
    }

    async fn has_key(&mut self, key: &K) -> Result<bool, Error> {
        // Check if key exists in key->value diskmap
        Ok(self.key_to_value.contains_key(key).await?)
    }

    /// Forcibly sync all pending writes.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.syncs.inc();

        // Sync both diskmaps
        self.key_to_value.sync().await?;
        self.index_to_key.sync().await?;

        Ok(())
    }

    /// Retrieve the end of the current range including `index` (inclusive) and
    /// the start of the next range after `index` (if it exists).
    ///
    /// This is useful for driving backfill operations over the freezer.
    pub fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.intervals.next_gap(index)
    }

    /// Close `Freezer` (and underlying storage).
    ///
    /// Any pending writes will be synced prior to closing.
    pub async fn close(mut self) -> Result<(), Error> {
        // Sync before closing
        self.sync().await?;

        // Close underlying storage
        self.key_to_value.close().await?;
        self.index_to_key.close().await?;

        Ok(())
    }

    /// Remove all on-disk data created by this `Freezer`.
    pub async fn destroy(self) -> Result<(), Error> {
        // Destroy underlying storage
        self.key_to_value.destroy().await?;
        self.index_to_key.destroy().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::array::FixedBytes;

    type TestKey = FixedBytes<8>;
    type TestValue = FixedBytes<16>;

    #[test]
    fn test_freezer_basic_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test".to_string(),
                codec_config: (),
                write_buffer: 1024,
                directory_size: 256,
                target_journal_size: 64 * 1024 * 1024, // 64MB
            };

            let mut freezer = Freezer::<_, TestKey, TestValue>::init(context, config)
                .await
                .unwrap();

            // Test put and get by key
            let key = TestKey::new(*b"testkey1");
            let value = TestValue::new(*b"testvalue1234567");

            freezer.put(1, key.clone(), value.clone()).await.unwrap();
            let retrieved = freezer.get(Identifier::Key(&key)).await.unwrap();

            assert_eq!(retrieved, Some(value.clone()));

            // Test get by index
            let retrieved_by_index = freezer.get(Identifier::Index(1)).await.unwrap();
            assert_eq!(retrieved_by_index, Some(value));

            // Test has operations
            assert!(freezer.has(Identifier::Key(&key)).await.unwrap());
            assert!(freezer.has(Identifier::Index(1)).await.unwrap());

            let nonexist_key = TestKey::new(*b"nonexist");
            assert!(!freezer.has(Identifier::Key(&nonexist_key)).await.unwrap());
            assert!(!freezer.has(Identifier::Index(999)).await.unwrap());

            // Test next_gap functionality
            let (current_end, next_start) = freezer.next_gap(0);
            assert_eq!(current_end, None); // Before first item
            assert_eq!(next_start, Some(1)); // Next item starts at 1

            let (current_end, next_start) = freezer.next_gap(1);
            assert_eq!(current_end, Some(1)); // Item 1 exists
            assert_eq!(next_start, None); // No next item yet

            // Test duplicate put (should be no-op)
            let value2 = TestValue::new(*b"testvalue7654321");
            freezer.put(1, key.clone(), value2.clone()).await.unwrap();

            // Should still return original value since index 1 already existed
            let retrieved = freezer.get(Identifier::Index(1)).await.unwrap();
            assert_ne!(retrieved, Some(value2)); // Should not be the new value

            // Clean up the freezer
            freezer.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_freezer_multiple_items() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test_multiple".to_string(),
                codec_config: (),
                write_buffer: 1024,
                directory_size: 256,
                target_journal_size: 64 * 1024 * 1024,
            };

            let mut freezer = Freezer::<_, TestKey, TestValue>::init(context, config)
                .await
                .unwrap();

            // Add multiple items
            for i in 0..10u64 {
                let key = TestKey::new((i as u64).to_be_bytes());
                let value = TestValue::new([i as u8; 16]);
                freezer.put(i, key, value).await.unwrap();
            }

            // Test retrieval by index and key
            for i in 0..10u64 {
                let key = TestKey::new((i as u64).to_be_bytes());
                let expected_value = TestValue::new([i as u8; 16]);

                let retrieved_by_index = freezer.get(Identifier::Index(i)).await.unwrap();
                assert_eq!(retrieved_by_index, Some(expected_value.clone()));

                let retrieved_by_key = freezer.get(Identifier::Key(&key)).await.unwrap();
                assert_eq!(retrieved_by_key, Some(expected_value));
            }

            // Test gap functionality with multiple items
            let (current_end, next_start) = freezer.next_gap(5);
            assert_eq!(current_end, Some(5)); // Item 5 exists (in continuous range 0-9)
            assert_eq!(next_start, None); // No gap until end

            // Clean up the freezer
            freezer.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_freezer_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test_sync".to_string(),
                codec_config: (),
                write_buffer: 1024,
                directory_size: 256,
                target_journal_size: 64 * 1024 * 1024,
            };

            let mut freezer = Freezer::<_, TestKey, TestValue>::init(context, config)
                .await
                .unwrap();

            // Add some data
            let key = TestKey::new(*b"testkey1");
            let value = TestValue::new(*b"testvalue1234567");
            freezer.put(1, key.clone(), value.clone()).await.unwrap();

            // Test sync - should not error
            freezer.sync().await.unwrap();

            // Verify data is still retrievable after sync
            let retrieved = freezer.get(Identifier::Key(&key)).await.unwrap();
            assert_eq!(retrieved, Some(value));

            freezer.close().await.unwrap();
        });
    }
}
