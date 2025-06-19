//! [Journal]-backed implementation of an index.
//!
//! Each key maps to a pointer stored in an "index" blob.  The pointer
//! occupies `size_of::<T::Key>()` bytes and contains the offset of the most
//! recently inserted [`Node`] in a [`Journal`] (offsets are stored 1 based so that
//! `0` represents `None`).  Every node in the journal forms a linked list to the
//! previous value for that key.  Lookups follow this chain and collect all
//! values.

use crate::journal::variable::{Config as JConfig, Journal};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Codec, EncodeSize, Read, Write as CodecWrite};
use commonware_runtime::{buffer::Write, Blob, Metrics, Storage};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::hash::{Hash, Hasher};

/// Errors that can occur when interacting with [Index].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
}

/// Configuration for [Index].
#[derive(Clone)]
pub struct Config<C> {
    /// Partition used for the table.
    pub table_partition: String,
    /// Partition for the journal.
    pub journal_partition: String,
    /// Size of the journal write buffer.
    pub write_buffer: usize,
    /// Codec configuration for stored values.
    pub codec: C,
    /// Size of the hash table.
    pub table_size: u64,
    /// Max size of a journal section.
    pub max_section_size: u64,
}

const NONE: u128 = 0;
const PTR_SIZE: u64 = 8; // section (u32) + offset (u32)

/// Single entry stored in the [`Journal`].
///
/// `next` stores the previous offset (1 based, so `0` is `None`).  The value is
/// encoded using the caller supplied [`Codec`].
struct Node<K: Codec, V: Codec> {
    next: Option<u32>,
    key: K,
    value: V,
}

impl<K: Codec, V: Codec> CodecWrite for Node<K, V> {
    fn write(&self, buf: &mut impl BufMut) {
        let n = self.next.map(|i| i as u128 + 1).unwrap_or(NONE);
        UInt(n).write(buf);
        self.key.write(buf);
        self.value.write(buf);
    }
}

impl<K: Codec, V: Codec> Read for Node<K, V> {
    type Cfg = (K::Cfg, V::Cfg);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let n: u128 = UInt::read_cfg(buf, &())?.into();
        let next = if n == NONE {
            None
        } else {
            Some((n - 1) as u32)
        };
        let key = K::read_cfg(buf, &cfg.0)?;
        let value = V::read_cfg(buf, &cfg.1)?;
        Ok(Self { next, key, value })
    }
}

impl<K: Codec, V: Codec> EncodeSize for Node<K, V> {
    fn encode_size(&self) -> usize {
        UInt(0u128).encode_size() + self.key.encode_size() + self.value.encode_size()
    }
}

/// Disk-backed index mapping translated keys to values.
///
/// Values are appended to a `Journal` and the index blob only stores the
/// pointer to the head of each linked list.  Both the index and the journal live
/// in the same partition provided by [`Config`].
pub struct Index<E: Storage + Metrics, V: Codec> {
    /// Blob storing the pointer table.
    buckets: E::Blob,
    /// Journal storing linked list nodes.
    journal: Journal<E, Node<Vec<u8>, V>>,
    /// Wasted reads due to collisions.
    wasted_reads: Counter,
    /// Number of keys in the index.
    keys: Gauge,
    /// Number of items in the index.
    items: Gauge,
    /// Size of the hash table.
    table_size: u64,
    /// Max size of a journal section.
    max_section_size: u64,
    /// The current active section.
    active_section: u64,
    /// The size of the active section.
    active_section_size: u64,
}

impl<E: Storage + Metrics, V: Codec> Index<E, V> {
    /// Initialize a new [`Disk`].
    ///
    /// The index blob and journal are opened (or created) inside
    /// `cfg.partition`.  Metrics for key and item counts are registered on the
    /// provided [`Metrics`] context.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let mut journal = Journal::init(
            context.with_label("index_journal"),
            JConfig {
                partition: cfg.journal_partition.clone(),
                compression: None,
                codec_config: (Default::default(), cfg.codec),
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        // Find the active section.
        let mut active_section = 0;
        let mut active_section_size = 0;
        let stream = journal.replay(cfg.write_buffer).await?;
        futures::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            let (section, _, size, _) = item?;
            if section > active_section {
                active_section = section;
                active_section_size = 0;
            }
            active_section_size += size as u64;
        }

        let (blob, size) = context.open(&cfg.table_partition, b"table").await?;
        if size == 0 {
            blob.write_at(vec![0; (cfg.table_size * PTR_SIZE) as usize], 0)
                .await?;
        } else if size != cfg.table_size * PTR_SIZE {
            return Err(Error::Runtime(commonware_runtime::Error::PartitionCorrupt(
                "table size mismatch".into(),
            )));
        }
        let wasted_reads = Counter::default();
        context.register(
            "wasted_reads",
            "Wasted reads due to collisions",
            wasted_reads.clone(),
        );
        let keys = Gauge::default();
        context.register("keys", "Number of keys", keys.clone());
        let items = Gauge::default();
        context.register("items", "Number of items", items.clone());
        Ok(Self {
            buckets: blob,
            journal,
            wasted_reads,
            keys,
            items,
            table_size: cfg.table_size,
            max_section_size: cfg.max_section_size,
            active_section,
            active_section_size,
        })
    }

    /// Insert a value for `key`.
    ///
    /// The value is appended to the journal and becomes the new head of the
    /// linked list for the translated key.
    pub async fn insert(&mut self, key: &[u8], value: V) -> Result<(), Error> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        let pos = hasher.finish() % self.table_size;

        let mut buf = [0u8; PTR_SIZE as usize];
        let read = self
            .buckets
            .read_at(vec![0u8; PTR_SIZE as usize], pos)
            .await?;
        buf[..PTR_SIZE as usize].copy_from_slice(read.as_ref());

        let entry = u64::from_le_bytes(buf);
        let head = if entry == 0 { None } else { Some(entry) };

        if self.active_section_size > self.max_section_size {
            self.active_section += 1;
            self.active_section_size = 0;
        }

        let node = Node {
            next: head.map(|h| (h >> 32) as u32),
            key: key.to_vec(),
            value,
        };
        let (offset, size) = self.journal.append(self.active_section, node).await?;
        self.active_section_size += size as u64;

        let ptr = (self.active_section << 32) | offset as u64;
        let bytes = ptr.to_le_bytes();
        self.buckets
            .write_at(bytes[..PTR_SIZE as usize].to_vec(), pos)
            .await?;
        if head.is_none() {
            self.keys.inc();
        }
        self.items.inc();
        Ok(())
    }

    /// Retrieve all values associated with `key`.
    ///
    /// Walks the on disk linked list starting from the pointer stored in the
    /// index blob and collects values in insertion order (most recent first).
    pub async fn get(&self, key: &[u8]) -> Result<Vec<V>, Error> {
        let mut values = Vec::new();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        let pos = hasher.finish() % self.table_size;

        let read = self
            .buckets
            .read_at(vec![0u8; PTR_SIZE as usize], pos)
            .await?;
        let mut buf = [0u8; PTR_SIZE as usize];
        buf[..PTR_SIZE as usize].copy_from_slice(read.as_ref());
        let entry = u64::from_le_bytes(buf);
        let mut current = if entry == 0 { None } else { Some(entry) };

        while let Some(ptr) = current {
            let section = ptr >> 32;
            let offset = ptr as u32;
            let node = self
                .journal
                .get(section, offset)
                .await?
                .expect("record missing");
            if node.key.as_slice() == key {
                values.push(node.value);
            } else {
                self.wasted_reads.inc();
            }
            current = node
                .next
                .map(|next_offset| (section << 32) | next_offset as u64);
        }
        Ok(values)
    }

    /// Flush all pending data to the underlying [`Storage`].
    pub async fn sync(&self) -> Result<(), Error> {
        self.buckets.sync().await?;
        self.journal.sync(0).await?;
        Ok(())
    }

    /// Close the index and persist all pending data.
    pub async fn close(self) -> Result<(), Error> {
        self.buckets.close().await?;
        self.journal.close().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Metrics, Runner};

    #[test_traced]
    fn test_disk_index_basic() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let cfg = Config {
                table_partition: "disk_index_basic_table".into(),
                journal_partition: "disk_index_basic_journal".into(),
                write_buffer: 128,
                codec: (),
                table_size: 1024,
                max_section_size: 1024,
            };
            let mut index = Index::<_, u32>::init(context.clone(), cfg.clone())
                .await
                .expect("init");

            index.insert(b"a1", 1).await.unwrap();
            index.insert(b"b1", 2).await.unwrap();
            index.sync().await.unwrap();
            index.close().await.unwrap();

            let index = Index::<_, u32>::init(context.clone(), cfg)
                .await
                .expect("reinit");
            assert_eq!(index.get(b"a1").await.unwrap(), vec![1]);
            assert_eq!(index.get(b"b1").await.unwrap(), vec![2]);
            let metrics = context.encode();
            assert!(metrics.contains("keys 2"));
            assert!(metrics.contains("items 2"));
        });
    }

    #[test_traced]
    fn test_disk_index_conflicting_keys() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let cfg = Config {
                table_partition: "disk_index_collision_table".into(),
                journal_partition: "disk_index_collision_journal".into(),
                write_buffer: 128,
                codec: (),
                table_size: 1, // force a collision
                max_section_size: 1024,
            };
            let mut index = Index::<_, u32>::init(context.clone(), cfg.clone())
                .await
                .expect("init");

            index.insert(b"ab", 1).await.unwrap();
            index.insert(b"abc", 2).await.unwrap();

            assert_eq!(index.get(b"ab").await.unwrap(), vec![1]);
            assert_eq!(index.get(b"abc").await.unwrap(), vec![2]);

            index.sync().await.unwrap();
            index.close().await.unwrap();

            let index = Index::<_, u32>::init(context.clone(), cfg)
                .await
                .expect("reinit");
            assert_eq!(index.get(b"ab").await.unwrap(), vec![1]);
            let metrics = context.encode();
            assert!(metrics.contains("keys 2"));
            assert!(metrics.contains("items 2"));
        });
    }

    #[test_traced]
    fn test_disk_index_unclean_shutdown() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let cfg = Config {
                table_partition: "disk_index_unclean_table".into(),
                journal_partition: "disk_index_unclean_journal".into(),
                write_buffer: 128,
                codec: (),
                table_size: 1024,
                max_section_size: 1024,
            };
            {
                let mut index = Index::<_, u32>::init(context.clone(), cfg.clone())
                    .await
                    .expect("init");

                // two keys that will be synced
                index.insert(b"ab", 1).await.unwrap();
                index.insert(b"cd", 2).await.unwrap();
                index.sync().await.unwrap();

                // unsynced key
                index.insert(b"ef", 3).await.unwrap();
            }

            // unsynced key should be gone but others remain
            let mut index = Index::<_, u32>::init(context.clone(), cfg.clone())
                .await
                .expect("reinit");
            assert_eq!(index.get(b"ab").await.unwrap(), vec![1]);
            assert_eq!(index.get(b"cd").await.unwrap(), vec![2]);
            assert!(index.get(b"ef").await.unwrap().is_empty());

            index.insert(b"ef", 4).await.unwrap();
            index.sync().await.unwrap();
            index.close().await.unwrap();

            let index = Index::<_, u32>::init(context.clone(), cfg)
                .await
                .expect("final");
            assert_eq!(index.get(b"ab").await.unwrap(), vec![1]);
            assert_eq!(index.get(b"cd").await.unwrap(), vec![2]);
            assert_eq!(index.get(b"ef").await.unwrap(), vec![4]);
            let metrics = context.encode();
            assert!(metrics.contains("keys 3"));
            assert!(metrics.contains("items 3"));
        });
    }
}
