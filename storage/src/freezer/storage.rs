use super::{Config, Error};
use crate::{
    diskmap::{Config as DiskMapConfig, DiskMap},
    rmap::RMap,
};
use commonware_codec::Codec;
use commonware_runtime::{Metrics, Storage};
use commonware_utils::{array::U64, Array};
use futures::StreamExt;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use tracing::debug;

/// Subject of a `get` or `has` operation.
pub enum Identifier<'a, K: Array> {
    Index(u64),
    Key(&'a K),
}

/// Prefix types for the unified diskmap
#[repr(u8)]
enum Prefix {
    Key = 0x00,
    Index = 0x01,
}

/// Wrapper for prefixed array that properly implements Array trait
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PrefixedArray<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> PrefixedArray<N> {
    #[allow(dead_code)]
    fn new_key(key: &[u8]) -> Self {
        assert_eq!(key.len() + 1, N, "Key size mismatch");
        let mut data = [0u8; N];
        data[0] = Prefix::Key as u8;
        data[1..].copy_from_slice(key);
        Self { data }
    }

    #[allow(dead_code)]
    fn new_index(index: &U64) -> Self {
        assert_eq!(9, N, "Index prefixed array must be 9 bytes");
        let mut data = [0u8; N];
        data[0] = Prefix::Index as u8;
        data[1..].copy_from_slice(index.as_ref());
        Self { data }
    }
}

impl<const N: usize> AsRef<[u8]> for PrefixedArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize> std::ops::Deref for PrefixedArray<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> std::fmt::Display for PrefixedArray<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrefixedArray({})", commonware_utils::hex(&self.data))
    }
}

impl<const N: usize> commonware_codec::FixedSize for PrefixedArray<N> {
    const SIZE: usize = N;
}

impl<const N: usize> commonware_codec::Write for PrefixedArray<N> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_slice(&self.data);
    }
}

impl<const N: usize> commonware_codec::Read for PrefixedArray<N> {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        if buf.remaining() < N {
            return Err(commonware_codec::Error::EndOfBuffer);
        }
        let mut data = [0u8; N];
        buf.copy_to_slice(&mut data);
        Ok(Self { data })
    }
}

impl<const N: usize> Array for PrefixedArray<N> {}

/// Wrapper enum for values in the unified diskmap
#[derive(Clone, Debug)]
enum StorageValue<K: Array, V: Codec> {
    Value(V),
    Key(K),
}

impl<K: Array + Codec<Cfg = ()>, V: Codec> commonware_codec::EncodeSize for StorageValue<K, V> {
    fn encode_size(&self) -> usize {
        match self {
            StorageValue::Value(v) => 1 + v.encode_size(),
            StorageValue::Key(k) => 1 + k.encode_size(),
        }
    }
}

impl<K: Array + Codec<Cfg = ()>, V: Codec> commonware_codec::Write for StorageValue<K, V> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            StorageValue::Value(v) => {
                buf.put_u8(0);
                v.write(buf);
            }
            StorageValue::Key(k) => {
                buf.put_u8(1);
                k.write(buf);
            }
        }
    }
}

impl<K: Array + Codec<Cfg = ()>, V: Codec> commonware_codec::Read for StorageValue<K, V> {
    type Cfg = V::Cfg;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let tag = buf.get_u8();
        match tag {
            0 => Ok(StorageValue::Value(V::read_cfg(buf, cfg)?)),
            1 => Ok(StorageValue::Key(K::read_cfg(buf, &())?)),
            _ => Err(commonware_codec::Error::InvalidEnum(tag)),
        }
    }
}

/// Implementation of `Freezer` storage using a single diskmap with prefixed keys.
pub struct Freezer<E: Storage + Metrics, K: Array, V: Codec> {
    // Single DiskMap for both key->value and index->key storage
    // We use a large enough array to hold any prefixed key (1 byte prefix + max of key or index)
    storage: DiskMap<E, PrefixedArray<256>, StorageValue<K, V>>,

    // RMap for interval tracking (only in-memory data structure)
    intervals: RMap,

    // Metrics
    items_tracked: Gauge,
    gets: Counter,
    has: Counter,
    syncs: Counter,

    // Store the actual key size for runtime validation
    _key_size: usize,
}

impl<E: Storage + Metrics, K: Array + Codec<Cfg = ()>, V: Codec> Freezer<E, K, V> {
    /// Initialize a new `Freezer` instance.
    ///
    /// The in-memory RMap is populated during this call by scanning the index entries.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Validate that our key size fits in the prefixed array
        let key_size = K::SIZE;
        if key_size + 1 > 256 {
            return Err(Error::Runtime(commonware_runtime::Error::PartitionCorrupt(
                format!("Key size {} is too large (max 255)", key_size),
            )));
        }

        // Initialize single diskmap for all storage
        let diskmap_config = DiskMapConfig {
            partition: cfg.partition.clone(),
            directory_size: cfg.directory_size,
            codec_config: cfg.codec_config.clone(),
            write_buffer: cfg.write_buffer,
            target_journal_size: cfg.target_journal_size,
        };
        let storage: DiskMap<E, PrefixedArray<256>, StorageValue<K, V>> =
            DiskMap::init(context.with_label("storage"), diskmap_config).await?;

        // Initialize RMap and rebuild from existing data
        let mut intervals = RMap::new();
        {
            debug!("initializing freezer");

            // Replay the diskmap to rebuild the RMap from index entries
            let stream = storage.replay(cfg.write_buffer).await?;
            let mut stream = Box::pin(stream);

            while let Some(result) = stream.next().await {
                let (prefixed_key, value) = result?;
                // Check if this is an index entry
                if prefixed_key.as_ref()[0] == Prefix::Index as u8 {
                    // Extract the index from the key
                    let mut index_bytes = [0u8; 8];
                    index_bytes.copy_from_slice(&prefixed_key.as_ref()[1..9]);
                    let index = u64::from_le_bytes(index_bytes);

                    // Only add to intervals if the value is a Key (not corrupted)
                    if matches!(value, StorageValue::Key(_)) {
                        intervals.insert(index);
                    }
                }
            }

            debug!(
                "freezer initialized with {} indices",
                intervals.iter().count()
            );
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

        // Set initial item count based on the number of intervals we found
        let item_count = intervals.iter().count() as i64;
        items_tracked.set(item_count);

        // Return populated freezer
        Ok(Self {
            storage,
            intervals,
            items_tracked,
            gets,
            has,
            syncs,
            _key_size: key_size,
        })
    }

    /// Create a prefixed array for a key, padding with zeros to reach 256 bytes
    fn make_key_prefix(&self, key: &[u8]) -> PrefixedArray<256> {
        let mut data = [0u8; 256];
        data[0] = Prefix::Key as u8;
        data[1..1 + key.len()].copy_from_slice(key);
        PrefixedArray { data }
    }

    /// Create a prefixed array for an index, padding with zeros to reach 256 bytes
    fn make_index_prefix(&self, index: &U64) -> PrefixedArray<256> {
        let mut data = [0u8; 256];
        data[0] = Prefix::Index as u8;
        data[1..9].copy_from_slice(index.as_ref());
        PrefixedArray { data }
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

        // First, store key -> value mapping (this ensures the value is persisted before the index)
        let key_prefix = self.make_key_prefix(key.as_ref());
        self.storage
            .put(key_prefix, StorageValue::Value(data))
            .await?;

        // Then, store index -> key mapping (if this fails, we have an orphaned key but that's okay)
        let index_key = U64::new(index);
        let index_prefix = self.make_index_prefix(&index_key);
        self.storage
            .put(index_prefix, StorageValue::Key(key))
            .await?;

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

        // Get key from index->key mapping
        let index_key = U64::new(index);
        let index_prefix = self.make_index_prefix(&index_key);
        let values = self.storage.get(&index_prefix).await?;

        let key = match values.into_iter().next() {
            Some(StorageValue::Key(k)) => k,
            _ => return Ok(None),
        };

        // Get value from key->value mapping
        let key_prefix = self.make_key_prefix(key.as_ref());
        let values = self.storage.get(&key_prefix).await?;

        // Return the first value
        match values.into_iter().next() {
            Some(StorageValue::Value(v)) => Ok(Some(v)),
            _ => Ok(None),
        }
    }

    async fn get_key(&mut self, key: &K) -> Result<Option<V>, Error> {
        // Update metrics
        self.gets.inc();

        // Get value directly from key->value mapping
        let key_prefix = self.make_key_prefix(key.as_ref());
        let values = self.storage.get(&key_prefix).await?;

        // Return the first value
        match values.into_iter().next() {
            Some(StorageValue::Value(v)) => Ok(Some(v)),
            _ => Ok(None),
        }
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
        // Check if key exists in storage
        let key_prefix = self.make_key_prefix(key.as_ref());
        Ok(self.storage.contains_key(&key_prefix).await?)
    }

    /// Forcibly sync all pending writes.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.syncs.inc();

        // Sync the single diskmap
        self.storage.sync().await?;

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
        self.storage.close().await?;

        Ok(())
    }

    /// Remove all on-disk data created by this `Freezer`.
    pub async fn destroy(self) -> Result<(), Error> {
        // Destroy underlying storage
        self.storage.destroy().await?;

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
            assert_eq!(current_end, Some(9)); // Item 5 exists (in continuous range 0-9, so end is 9)
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

    #[test]
    fn test_freezer_consistency_after_restart() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let config = Config {
                partition: "test_consistency".to_string(),
                codec_config: (),
                write_buffer: 1024,
                directory_size: 256,
                target_journal_size: 64 * 1024 * 1024,
            };

            // First, create a freezer and add some data
            {
                let mut freezer =
                    Freezer::<_, TestKey, TestValue>::init(context.clone(), config.clone())
                        .await
                        .unwrap();

                // Add multiple items
                for i in 0..5u64 {
                    let key = TestKey::new((i as u64).to_be_bytes());
                    let value = TestValue::new([i as u8; 16]);
                    freezer.put(i, key, value).await.unwrap();
                }

                // Don't sync - simulate unclean shutdown
                // In the new design, we write key->value first, then index->key
                // So worst case is we have orphaned keys but indices always point to valid keys
            }

            // Restart and verify consistency
            {
                let mut freezer =
                    Freezer::<_, TestKey, TestValue>::init(context.clone(), config.clone())
                        .await
                        .unwrap();

                // The RMap should be rebuilt from index entries during init
                // All indices in RMap should have valid key->value mappings
                for i in 0..5u64 {
                    if freezer.has_index(i) {
                        // If the index exists in RMap, we should be able to retrieve the value
                        let key = TestKey::new((i as u64).to_be_bytes());
                        let expected_value = TestValue::new([i as u8; 16]);

                        let retrieved_by_index = freezer.get(Identifier::Index(i)).await.unwrap();
                        assert!(
                            retrieved_by_index.is_some(),
                            "Index {} exists in RMap but value retrieval failed",
                            i
                        );

                        // The value should match what we expect
                        assert_eq!(retrieved_by_index, Some(expected_value.clone()));

                        // Key lookup should also work
                        let retrieved_by_key = freezer.get(Identifier::Key(&key)).await.unwrap();
                        assert_eq!(retrieved_by_key, Some(expected_value));
                    }
                }

                freezer.destroy().await.unwrap();
            }
        });
    }
}
