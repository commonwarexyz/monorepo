use super::Error;
use crate::journal::variable::{Config as JConfig, Journal};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, Decode, Encode, EncodeSize, Error as CodecError, Read, Write};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::{pin_mut, stream::StreamExt};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

/// An entry in the bmap, containing a key-value pair.
struct Entry<K: Array, V: Codec> {
    key: K,
    value: V,
}

impl<K: Array, V: Codec> Encode for Entry<K, V> {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encode_size());
        self.key.write(&mut buf);
        buf.extend_from_slice(&self.value.encode());
        buf
    }
}

impl<K: Array, V: Codec> EncodeSize for Entry<K, V> {
    fn encode_size(&self) -> usize {
        K::SIZE + self.value.encode_size()
    }
}

impl<K: Array, V: Codec> Decode for Entry<K, V> {
    type Cfg = V::Cfg;

    fn decode_cfg(buf: &[u8], cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let mut mut_buf = buf;
        let key = K::read(&mut mut_buf)?;
        let value = V::decode_cfg(mut_buf, cfg)?;
        Ok(Entry { key, value })
    }
}

impl<K: Array, V: Codec> Codec for Entry<K, V> {}

/// Configuration for a `BMap`.
pub struct Config<K: Array, V: Codec> {
    /// The name of the `commonware-runtime::Storage` partition to use for this bmap.
    pub partition: String,
    /// The number of buckets to partition keys into. More buckets can improve performance
    /// when there are many keys, by reducing the size of each journal to be scanned.
    pub num_buckets: usize,
    /// The size of the write buffer for each bucket's journal.
    pub journal_write_buffer: usize,
    /// The codec configuration for values.
    pub codec_config: V::Cfg,
    /// Phantom data to hold key type.
    pub _key: PhantomData<K>,
}

/// A disk-based map.
pub struct BMap<E: Storage + Metrics + Clock, K: Array, V: Codec> {
    buckets: Vec<Journal<E, Entry<K, V>>>,
    num_buckets: usize,
}

impl<E: Storage + Metrics + Clock, K: Array + Hash + Eq, V: Codec> BMap<E, K, V>
where
    V::Cfg: Clone,
{
    /// Initialize a new `BMap` instance.
    pub async fn init(context: E, cfg: Config<K, V>) -> Result<Self, Error> {
        let mut buckets = Vec::with_capacity(cfg.num_buckets);
        for i in 0..cfg.num_buckets {
            let journal_config = JConfig {
                partition: format!("{}/{}", cfg.partition, i),
                compression: None,
                codec_config: cfg.codec_config.clone(),
                write_buffer: cfg.journal_write_buffer,
            };
            let journal = Journal::init(
                context.with_label(&format!("bmap_bucket_{}", i)),
                journal_config,
            )
            .await?;
            buckets.push(journal);
        }

        Ok(BMap {
            buckets,
            num_buckets: cfg.num_buckets,
        })
    }

    /// Hashes the key to determine its bucket index.
    fn get_bucket_index(&self, key: &K) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() % self.num_buckets as u64) as usize
    }

    /// Inserts a key-value pair into the map.
    pub async fn insert(&mut self, key: K, value: V) -> Result<(), Error> {
        let bucket_index = self.get_bucket_index(&key);
        let bucket = &mut self.buckets[bucket_index];
        let entry = Entry { key, value };
        // Use section 0 within each bucket's journal.
        bucket.append(0, entry).await?;
        Ok(())
    }

    /// Retrieves a value from the map for the given key.
    /// This operation scans the corresponding bucket on disk.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        let bucket_index = self.get_bucket_index(key);
        let bucket = &self.buckets[bucket_index];

        // Replay buffer size, can be made configurable if needed.
        let stream = bucket.replay(1024 * 1024).await?;
        pin_mut!(stream);

        let mut result = None;
        while let Some(res) = stream.next().await {
            let (_, _, _, entry) = res?;
            if &entry.key == key {
                result = Some(entry.value);
            }
        }

        Ok(result)
    }

    /// Syncs all buckets to ensure data is persisted.
    pub async fn sync(&self) -> Result<(), Error> {
        for bucket in &self.buckets {
            // Sync section 0, as it's the only one we use.
            bucket.sync(0).await?;
        }
        Ok(())
    }

    /// Closes the map, syncing any pending writes.
    pub async fn close(self) -> Result<(), Error> {
        for bucket in self.buckets {
            bucket.close().await?;
        }
        Ok(())
    }

    /// Destroys the map, removing all associated data from storage.
    pub async fn destroy(self) -> Result<(), Error> {
        for bucket in self.buckets {
            bucket.destroy().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{hash, sha256::Digest};
    use commonware_macros::test_traced;
    use commonware_runtime::deterministic;
    use commonware_utils::array::FixedBytes;

    type TestKey = Digest;
    type TestValue = FixedBytes<64>;

    fn test_config(num_buckets: usize) -> Config<TestKey, TestValue> {
        Config {
            partition: "test_bmap".into(),
            num_buckets,
            journal_write_buffer: 1024,
            codec_config: (),
            _key: PhantomData,
        }
    }

    fn str_to_test_value(s: &str) -> TestValue {
        let mut bytes = [0u8; 64];
        bytes[..s.len()].copy_from_slice(s.as_bytes());
        FixedBytes::new(bytes)
    }

    #[test_traced]
    fn test_bmap_insert_and_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut bmap = BMap::init(context.clone(), test_config(4)).await.unwrap();

            let key1 = hash(b"key1");
            let value1 = str_to_test_value("value1");
            bmap.insert(key1, value1).await.unwrap();

            let key2 = hash(b"key2");
            let value2 = str_to_test_value("value2");
            bmap.insert(key2, value2).await.unwrap();

            // Overwrite key1
            let value1_new = str_to_test_value("value1_new");
            bmap.insert(key1, value1_new).await.unwrap();

            let retrieved_value1 = bmap.get(&key1).await.unwrap().unwrap();
            assert_eq!(retrieved_value1, value1_new);

            let retrieved_value2 = bmap.get(&key2).await.unwrap().unwrap();
            assert_eq!(retrieved_value2, value2);

            let non_existent_key = hash(b"key3");
            let retrieved_non_existent = bmap.get(&non_existent_key).await.unwrap();
            assert!(retrieved_non_existent.is_none());

            bmap.close().await.unwrap();
            let _ = BMap::init(context, test_config(4)).await.unwrap();
        });
    }

    #[test_traced]
    fn test_bmap_unclean_shutdown() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let key1 = hash(b"key1");
            let value1 = str_to_test_value("value1");

            let key2 = hash(b"key2");
            let value2 = str_to_test_value("value2");

            {
                let mut bmap = BMap::init(context.clone(), test_config(4)).await.unwrap();
                bmap.insert(key1, value1).await.unwrap();
                bmap.sync().await.unwrap(); // Persist key1

                bmap.insert(key2, value2).await.unwrap();
                // Do not sync key2, simulate crash by dropping bmap
            }

            // Re-initialize to recover
            let bmap = BMap::init(context.clone(), test_config(4)).await.unwrap();

            // key1 should exist
            let retrieved_value1 = bmap.get(&key1).await.unwrap().unwrap();
            assert_eq!(retrieved_value1, value1);

            // key2 should NOT exist
            let retrieved_value2 = bmap.get(&key2).await.unwrap();
            assert!(retrieved_value2.is_none());

            bmap.destroy().await.unwrap();
        });
    }
}
