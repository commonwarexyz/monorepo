use super::{Config, Error};
use bytes::BufMut;
use commonware_codec::{Codec, EncodeSize, FixedSize, ReadExt};
use commonware_runtime::{Blob, Clock, Error as RError, Metrics, Storage};
use commonware_utils::Array;
use futures::future::try_join_all;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use tracing::{debug, warn};

/// The names of the two blobs that store metadata.
const BLOB_NAMES: [&[u8]; 2] = [b"left", b"right"];

/// Information about a value in a [Wrapper].
struct Info {
    start: usize,
    length: usize,
}

impl Info {
    /// Create a new [Info].
    fn new(start: usize, length: usize) -> Self {
        Self { start, length }
    }
}

/// One of the two wrappers that store metadata.
struct Wrapper<B: Blob, K: Array> {
    blob: B,
    version: u64,
    lengths: HashMap<K, Info>,
    modified: BTreeSet<K>,
    data: Vec<u8>,
}

impl<B: Blob, K: Array> Wrapper<B, K> {
    /// Create a new [Wrapper].
    fn new(blob: B, version: u64, lengths: HashMap<K, Info>, data: Vec<u8>) -> Self {
        Self {
            blob,
            version,
            lengths,
            modified: BTreeSet::new(),
            data,
        }
    }

    /// Create a new empty [Wrapper].
    fn empty(blob: B) -> Self {
        Self {
            blob,
            version: 0,
            lengths: HashMap::new(),
            modified: BTreeSet::new(),
            data: Vec::new(),
        }
    }
}

/// Implementation of [Metadata] storage.
pub struct Metadata<E: Clock + Storage + Metrics, K: Array, V: Codec> {
    context: E,

    map: BTreeMap<K, V>,
    cursor: usize,
    key_order_changed: u64,
    next_version: u64,
    partition: String,
    blobs: [Wrapper<E::Blob, K>; 2],

    sync_overwrites: Counter,
    sync_rewrites: Counter,
    keys: Gauge,
}

impl<E: Clock + Storage + Metrics, K: Array, V: Codec> Metadata<E, K, V> {
    /// Initialize a new [Metadata] instance.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Open dedicated blobs
        let (left_blob, left_len) = context.open(&cfg.partition, BLOB_NAMES[0]).await?;
        let (right_blob, right_len) = context.open(&cfg.partition, BLOB_NAMES[1]).await?;

        // Find latest blob (check which includes a hash of the other)
        let (left_map, left_wrapper) =
            Self::load(&cfg.codec_config, 0, left_blob, left_len).await?;
        let (right_map, right_wrapper) =
            Self::load(&cfg.codec_config, 1, right_blob, right_len).await?;

        // Choose latest blob
        let mut map = left_map;
        let mut cursor = 0;
        let mut version = left_wrapper.version;
        if right_wrapper.version > left_wrapper.version {
            cursor = 1;
            map = right_map;
            version = right_wrapper.version;
        }
        let next_version = version.checked_add(1).expect("version overflow");

        // Create metrics
        let sync_rewrites = Counter::default();
        let sync_overwrites = Counter::default();
        let keys = Gauge::default();
        context.register(
            "sync_rewrites",
            "number of syncs that rewrote all data",
            sync_rewrites.clone(),
        );
        context.register(
            "sync_overwrites",
            "number of syncs that modified existing data",
            sync_overwrites.clone(),
        );
        context.register("keys", "number of tracked keys", keys.clone());

        // Return metadata
        keys.set(map.len() as i64);
        Ok(Self {
            context,

            map,
            cursor,
            key_order_changed: next_version, // rewrite on startup because we don't have a diff record
            next_version,
            partition: cfg.partition,
            blobs: [left_wrapper, right_wrapper],

            sync_rewrites,
            sync_overwrites,
            keys,
        })
    }

    async fn load(
        codec_config: &V::Cfg,
        index: usize,
        blob: E::Blob,
        len: u64,
    ) -> Result<(BTreeMap<K, V>, Wrapper<E::Blob, K>), Error> {
        // Get blob length
        if len == 0 {
            // Empty blob
            return Ok((BTreeMap::new(), Wrapper::empty(blob)));
        }

        // Read blob
        let len = len.try_into().map_err(|_| Error::BlobTooLarge(len))?;
        let buf = blob.read_at(vec![0u8; len], 0).await?;

        // Verify integrity.
        //
        // 8 bytes for version + 4 bytes for checksum.
        if buf.len() < 12 {
            // Truncate and return none
            warn!(
                blob = index,
                len = buf.len(),
                "blob is too short: truncating"
            );
            blob.resize(0).await?;
            blob.sync().await?;
            return Ok((BTreeMap::new(), Wrapper::empty(blob)));
        }

        // Extract checksum
        let checksum_index = buf.len() - 4;
        let stored_checksum =
            u32::from_be_bytes(buf.as_ref()[checksum_index..].try_into().unwrap());
        let computed_checksum = crc32fast::hash(&buf.as_ref()[..checksum_index]);
        if stored_checksum != computed_checksum {
            // Truncate and return none
            warn!(
                blob = index,
                stored = stored_checksum,
                computed = computed_checksum,
                "checksum mismatch: truncating"
            );
            blob.resize(0).await?;
            blob.sync().await?;
            return Ok((BTreeMap::new(), Wrapper::empty(blob)));
        }

        // Get parent
        let version = u64::from_be_bytes(buf.as_ref()[..8].try_into().unwrap());

        // Extract data
        //
        // If the checksum is correct, we assume data is correctly packed and we don't perform
        // length checks on the cursor.
        let mut data = BTreeMap::new();
        let mut lengths = HashMap::new();
        let mut cursor = u64::SIZE;
        while cursor < checksum_index {
            // Read key
            let key = K::read(&mut buf.as_ref()[cursor..].as_ref())
                .expect("unable to read key from blob");
            cursor += key.encode_size();

            // Read value
            let value = V::read_cfg(&mut buf.as_ref()[cursor..].as_ref(), codec_config)
                .expect("unable to read value from blob");
            lengths.insert(key.clone(), Info::new(cursor, value.encode_size()));
            cursor += value.encode_size();
            data.insert(key, value);
        }

        // Return info
        Ok((data, Wrapper::new(blob, version, lengths, buf.into())))
    }

    /// Get a value from [Metadata] (if it exists).
    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    /// Get a mutable reference to a value from [Metadata] (if it exists).
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        // Get value
        let value = self.map.get_mut(key)?;

        // Mark key as modified.
        //
        // We need to mark both blobs as modified because we may need to update both files.
        self.blobs[self.cursor].modified.insert(key.clone());
        self.blobs[1 - self.cursor].modified.insert(key.clone());

        Some(value)
    }

    /// Clear all values from [Metadata]. The new state will not be persisted until [Self::sync] is
    /// called.
    pub fn clear(&mut self) {
        // Clear map
        self.map.clear();

        // Mark key order as changed
        self.key_order_changed = self.next_version;
        self.keys.set(0);
    }

    /// Put a value into [Metadata].
    ///
    /// If the key already exists, the value will be overwritten. The
    /// value stored will not be persisted until [Self::sync] is called.
    pub fn put(&mut self, key: K, value: V) {
        // Get value
        let exists = self.map.insert(key.clone(), value).is_some();

        // Mark key as modified.
        //
        // We need to mark both blobs as modified because we may need to update both files.
        if exists {
            self.blobs[self.cursor].modified.insert(key.clone());
            self.blobs[1 - self.cursor].modified.insert(key.clone());
        } else {
            self.key_order_changed = self.next_version;
        }
        self.keys.set(self.map.len() as i64);
    }

    /// Remove a value from [Metadata] (if it exists).
    pub fn remove(&mut self, key: &K) -> Option<V> {
        // Get value
        let past = self.map.remove(key);

        // Mark key as modified.
        if past.is_some() {
            self.key_order_changed = self.next_version;
        }
        self.keys.set(self.map.len() as i64);

        past
    }

    /// Iterate over all keys in metadata, optionally filtered by prefix.
    ///
    /// If a prefix is provided, only keys that start with the prefix bytes will be returned.
    pub fn keys<'a>(&'a self, prefix: Option<&'a [u8]>) -> impl Iterator<Item = &'a K> + 'a {
        self.map.keys().filter(move |key| {
            if let Some(prefix_bytes) = prefix {
                key.as_ref().starts_with(prefix_bytes)
            } else {
                true
            }
        })
    }

    /// Remove all keys that start with the given prefix.
    pub fn remove_prefix(&mut self, prefix: &[u8]) {
        // Retain only keys that do not start with the prefix
        self.map.retain(|key, _| !key.as_ref().starts_with(prefix));

        // Mark key order as changed since we may have removed keys
        self.key_order_changed = self.next_version;
        self.keys.set(self.map.len() as i64);
    }

    /// Atomically commit the current state of [Metadata].
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Compute next version.
        //
        // While it is possible that extremely high-frequency updates to metadata could cause an eventual
        // overflow of version, syncing once per millisecond would overflow in 584,942,417 years.
        let past_version = self.blobs[self.cursor].version;
        let next_next_version = self.next_version.checked_add(1).expect("version overflow");

        // Get target blob (the one we will modify)
        let target_cursor = 1 - self.cursor;
        let target = &mut self.blobs[target_cursor];

        // Attempt to overwrite existing data if key order has not changed recently
        let mut overwrite = true;
        let mut writes = Vec::with_capacity(target.modified.len());
        if self.key_order_changed < past_version {
            for key in target.modified.iter() {
                let info = target.lengths.get(key).expect("key must exist");
                let new_value = self.map.get(key).expect("key must exist");
                if info.length == new_value.encode_size() {
                    // Overwrite existing value
                    let encoded = new_value.encode();
                    target.data[info.start..info.start + info.length].copy_from_slice(&encoded);
                    writes.push(target.blob.write_at(encoded, info.start as u64));
                } else {
                    // Rewrite all
                    overwrite = false;
                    break;
                }
            }
        } else {
            // If the key order has changed, we need to rewrite all data
            overwrite = false;
        }

        // Clear modified keys to avoid writing the same data
        target.modified.clear();

        // Overwrite existing data
        if overwrite {
            // Update version
            let version = self.next_version.to_be_bytes();
            target.data[0..8].copy_from_slice(&version);
            writes.push(target.blob.write_at(version.as_slice().into(), 0));

            // Update checksum
            let checksum_index = target.data.len() - 4;
            let checksum = crc32fast::hash(&target.data[..checksum_index]).to_be_bytes();
            target.data[checksum_index..].copy_from_slice(&checksum);
            writes.push(
                target
                    .blob
                    .write_at(checksum.as_slice().into(), checksum_index as u64),
            );

            // Persist changes
            try_join_all(writes).await?;
            target.blob.sync().await?;

            // Update state
            target.version = self.next_version;
            self.cursor = target_cursor;
            self.next_version = next_next_version;
            self.sync_overwrites.inc();
            return Ok(());
        }

        // Rewrite all data
        let mut lengths = HashMap::new();
        let mut next_data = Vec::with_capacity(target.data.len());
        next_data.put_u64(self.next_version);
        for (key, value) in &self.map {
            key.write(&mut next_data);
            let start = next_data.len();
            value.write(&mut next_data);
            lengths.insert(key.clone(), Info::new(start, value.encode_size()));
        }
        next_data.put_u32(crc32fast::hash(&next_data[..]));

        // Persist changes
        target.blob.write_at(next_data.clone(), 0).await?;
        if next_data.len() < target.data.len() {
            target.blob.resize(next_data.len() as u64).await?;
        }
        target.blob.sync().await?;

        // Update state
        target.version = self.next_version;
        target.lengths = lengths;
        target.data = next_data;
        self.cursor = target_cursor;
        self.next_version = next_next_version;
        self.sync_rewrites.inc();
        Ok(())
    }

    /// Sync outstanding data and close [Metadata].
    pub async fn close(mut self) -> Result<(), Error> {
        // Sync and close blobs
        self.sync().await?;
        for wrapper in self.blobs.into_iter() {
            wrapper.blob.close().await?;
        }
        Ok(())
    }

    /// Close and remove the underlying blobs.
    pub async fn destroy(self) -> Result<(), Error> {
        for (i, wrapper) in self.blobs.into_iter().enumerate() {
            wrapper.blob.close().await?;
            self.context
                .remove(&self.partition, Some(BLOB_NAMES[i]))
                .await?;
            debug!(blob = i, "destroyed blob");
        }
        match self.context.remove(&self.partition, None).await {
            Ok(()) => {}
            Err(RError::PartitionMissing(_)) => {
                // Partition already removed or never existed.
            }
            Err(err) => return Err(Error::Runtime(err)),
        }
        Ok(())
    }
}
