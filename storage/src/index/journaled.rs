//! [Journal]-backed implementation of the [Translator] based index.
//!
//! Each translated key maps to a pointer stored in an "index" blob.  The pointer
//! occupies `size_of::<T::Key>()` bytes and contains the offset of the most
//! recently inserted [`Node`] in a [`Journal`] (offsets are stored 1 based so that
//! `0` represents `None`).  Every node in the journal forms a linked list to the
//! previous value for that key.  Lookups follow this chain and collect all
//! values.

use super::Translator;
use crate::journal::variable::{Config as JConfig, Journal};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Codec, EncodeSize, Read, Write as CodecWrite};
use commonware_runtime::{buffer::Write, Blob, Metrics, Storage};
use prometheus_client::metrics::gauge::Gauge;

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
    /// Partition used for both the index blob and journal.
    pub partition: String,
    /// Size of the journal write buffer.
    pub write_buffer: usize,
    /// Codec configuration for stored values.
    pub codec: C,
}

const NONE: u128 = 0;

/// Single entry stored in the [`Journal`].
///
/// `next` stores the previous offset (1 based, so `0` is `None`).  The value is
/// encoded using the caller supplied [`Codec`].
struct Node<V: Codec> {
    next: Option<u32>,
    value: V,
}

impl<V: Codec> CodecWrite for Node<V> {
    fn write(&self, buf: &mut impl BufMut) {
        let n = self.next.map(|i| i as u128 + 1).unwrap_or(NONE);
        UInt(n).write(buf);
        self.value.write(buf);
    }
}

impl<V: Codec> Read for Node<V> {
    type Cfg = V::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let n: u128 = UInt::read_cfg(buf, &())?.into();
        let next = if n == NONE {
            None
        } else {
            Some((n - 1) as u32)
        };
        let value = V::read_cfg(buf, cfg)?;
        Ok(Self { next, value })
    }
}

impl<V: Codec> EncodeSize for Node<V> {
    fn encode_size(&self) -> usize {
        UInt(0u128).encode_size() + self.value.encode_size()
    }
}

/// Disk-backed index mapping translated keys to values.
///
/// Values are appended to a `Journal` and the index blob only stores the
/// pointer to the head of each linked list.  Both the index and the journal live
/// in the same partition provided by [`Config`].
pub struct Index<E: Storage + Metrics, T: Translator, V: Codec>
where
    T::Key: Into<u64>,
{
    /// Converts external keys into the fixed representation used for indexing.
    translator: T,
    /// Blob storing the pointer table.
    index: Write<E::Blob>,
    /// Current length of the index blob.
    index_len: u64,
    /// Journal storing linked list nodes.
    journal: Journal<E, Node<V>>,
    /// Number of unique translated keys in the index.
    keys: Gauge,
    /// Total number of items stored across all keys.
    items: Gauge,
}

impl<E: Storage + Metrics, T: Translator, V: Codec> Index<E, T, V>
where
    T::Key: Into<u64>,
{
    /// Initialize a new [`Disk`].
    ///
    /// The index blob and journal are opened (or created) inside
    /// `cfg.partition`.  Metrics for key and item counts are registered on the
    /// provided [`Metrics`] context.
    pub async fn init(context: E, cfg: Config<V::Cfg>, translator: T) -> Result<Self, Error> {
        let partition = cfg.partition.clone();
        let journal = Journal::init(
            context.with_label("disk_index"),
            JConfig {
                partition: cfg.partition.clone(),
                compression: None,
                codec_config: cfg.codec,
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;
        let keys = Gauge::default();
        let items = Gauge::default();
        context.register("keys", "Number of keys", keys.clone());
        context.register("items", "Number of items", items.clone());

        // store the pointer table in a separate partition so `Journal` doesn't
        // see it when scanning for section blobs
        let table_partition = format!("{partition}_index");
        let (blob, size) = context.open(&table_partition, b"table").await?;
        let index = Write::new(blob, size, cfg.write_buffer);
        Ok(Self {
            translator,
            index,
            index_len: size,
            journal,
            keys,
            items,
        })
    }

    /// Insert a value for `key`.
    ///
    /// The value is appended to the journal and becomes the new head of the
    /// linked list for the translated key.
    pub async fn insert(&mut self, key: &[u8], value: V) -> Result<(), Error> {
        let k = self.translator.transform(key);
        let ptr = std::mem::size_of::<T::Key>() as u64;
        let pos = k.into() * ptr;

        if pos + ptr > self.index_len {
            let extend = pos + ptr - self.index_len;
            self.index
                .write_at(vec![0u8; extend as usize], self.index_len)
                .await?;
            self.index_len = pos + ptr;
        }

        let mut buf = [0u8; 4];
        if pos < self.index_len {
            let read = self.index.read_at(vec![0u8; ptr as usize], pos).await?;
            buf[..ptr as usize].copy_from_slice(read.as_ref());
        }

        let entry = u32::from_le_bytes(buf);
        let head = if entry == 0 { None } else { Some(entry - 1) };

        let node = Node { next: head, value };
        let (offset, _) = self.journal.append(0, node).await?;
        let bytes = (offset + 1).to_le_bytes();
        self.index
            .write_at(bytes[..ptr as usize].to_vec(), pos)
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
        let k = self.translator.transform(key);
        let ptr = std::mem::size_of::<T::Key>() as u64;
        let pos = k.into() * ptr;
        if pos + ptr > self.index_len {
            return Ok(values);
        }

        let read = self.index.read_at(vec![0u8; ptr as usize], pos).await?;
        let mut buf = [0u8; 4];
        buf[..ptr as usize].copy_from_slice(read.as_ref());
        let entry = u32::from_le_bytes(buf);
        let mut current = if entry == 0 { None } else { Some(entry - 1) };

        while let Some(offset) = current {
            let node = self.journal.get(0, offset).await?.expect("record missing");
            values.push(node.value);
            current = node.next;
        }
        Ok(values)
    }

    /// Flush all pending data to the underlying [`Storage`].
    pub async fn sync(&self) -> Result<(), Error> {
        self.index.sync().await?;
        self.journal.sync(0).await?;
        Ok(())
    }

    /// Close the index and persist all pending data.
    pub async fn close(self) -> Result<(), Error> {
        self.index.close().await?;
        self.journal.close().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::translator::TwoCap;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Metrics, Runner};

    #[test_traced]
    fn test_disk_index_basic() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let cfg = Config {
                partition: "disk_index_basic".into(),
                write_buffer: 128,
                codec: (),
            };
            let translator = TwoCap;
            let mut index =
                Index::<_, _, u32>::init(context.clone(), cfg.clone(), translator.clone())
                    .await
                    .expect("init");

            index.insert(b"a1", 1).await.unwrap();
            index.insert(b"b1", 2).await.unwrap();
            index.sync().await.unwrap();
            index.close().await.unwrap();

            let index = Index::<_, _, u32>::init(context.clone(), cfg, translator)
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
                partition: "disk_index_collision".into(),
                write_buffer: 128,
                codec: (),
            };
            let translator = TwoCap;
            let mut index =
                Index::<_, _, u32>::init(context.clone(), cfg.clone(), translator.clone())
                    .await
                    .expect("init");

            index.insert(b"ab", 1).await.unwrap();
            index.insert(b"abc", 2).await.unwrap();

            let expected = vec![2, 1];
            assert_eq!(index.get(b"ab").await.unwrap(), expected);
            assert_eq!(index.get(b"abc").await.unwrap(), expected);

            index.sync().await.unwrap();
            index.close().await.unwrap();

            let index = Index::<_, _, u32>::init(context.clone(), cfg, translator)
                .await
                .expect("reinit");
            assert_eq!(index.get(b"ab").await.unwrap(), expected);
            let metrics = context.encode();
            assert!(metrics.contains("keys 1"));
            assert!(metrics.contains("items 2"));
        });
    }

    #[test_traced]
    fn test_disk_index_unclean_shutdown() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let cfg = Config {
                partition: "disk_index_unclean".into(),
                write_buffer: 128,
                codec: (),
            };
            let translator = TwoCap;
            {
                let mut index =
                    Index::<_, _, u32>::init(context.clone(), cfg.clone(), translator.clone())
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
            let mut index =
                Index::<_, _, u32>::init(context.clone(), cfg.clone(), translator.clone())
                    .await
                    .expect("reinit");
            assert_eq!(index.get(b"ab").await.unwrap(), vec![1]);
            assert_eq!(index.get(b"cd").await.unwrap(), vec![2]);
            assert!(index.get(b"ef").await.unwrap().is_empty());

            index.insert(b"ef", 4).await.unwrap();
            index.sync().await.unwrap();
            index.close().await.unwrap();

            let index = Index::<_, _, u32>::init(context.clone(), cfg, translator)
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
