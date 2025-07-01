use super::{Config, Error};
use bytes::BufMut;
use commonware_codec::{Codec, FixedSize, ReadExt};
use commonware_runtime::{Blob, Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::future::try_join_all;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::{BTreeMap, BTreeSet};
use tracing::{debug, warn};

/// The names of the two blobs that store metadata.
const BLOB_NAMES: [&[u8]; 2] = [b"left", b"right"];

/// One of the two wrappers that store metadata.
struct Wrapper<B: Blob, K> {
    blob: B,
    version: u64,
    data: Vec<u8>,

    // Maps key -> (value_offset, value_len) in `data`.
    index: BTreeMap<K, (usize, usize)>,
}

impl<B: Blob, K: Ord + Clone> Wrapper<B, K> {
    /// Create a new wrapper with the given data.
    fn new(blob: B, version: u64, data: Vec<u8>, index: BTreeMap<K, (usize, usize)>) -> Self {
        Self {
            blob,
            version,
            data,
            index,
        }
    }

    /// Create a new empty wrapper.
    fn empty(blob: B) -> Self {
        Self {
            blob,
            version: 0,
            data: Vec::new(),
            index: BTreeMap::new(),
        }
    }
}

/// Implementation of [Metadata] storage.
pub struct Metadata<E: Clock + Storage + Metrics, K: Array + Ord + Clone, V: Codec> {
    context: E,

    // Data is stored in a BTreeMap to enable deterministic serialization.
    map: BTreeMap<K, V>,
    cursor: usize,
    partition: String,
    blobs: [Wrapper<E::Blob, K>; 2],

    // Dirty tracking.
    dirty_all: bool,
    dirty_keys: BTreeSet<K>,

    syncs: Counter,
    keys: Gauge,
    skipped: Counter,
}

impl<E: Clock + Storage + Metrics, K: Array + Ord + Clone, V: Codec> Metadata<E, K, V> {
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
        if right_wrapper.version > left_wrapper.version {
            cursor = 1;
            map = right_map;
        }

        // Create metrics
        let syncs = Counter::default();
        let keys = Gauge::default();
        let skipped = Counter::default();
        context.register("syncs", "number of syncs of data to disk", syncs.clone());
        context.register("keys", "number of tracked keys", keys.clone());
        context.register(
            "skipped",
            "duplicate bytes not written to disk",
            skipped.clone(),
        );

        // Return metadata
        keys.set(map.len() as i64);
        Ok(Self {
            context,

            map,
            cursor,
            partition: cfg.partition,
            blobs: [left_wrapper, right_wrapper],

            dirty_all: false,
            dirty_keys: BTreeSet::new(),

            syncs,
            keys,
            skipped,
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
        let mut index = BTreeMap::new();
        let mut cursor = u64::SIZE;
        while cursor < checksum_index {
            // Read key
            let next_cursor = cursor + K::SIZE;
            let key = K::read(&mut buf.as_ref()[cursor..next_cursor].as_ref())
                .expect("unable to read key from blob");
            cursor = next_cursor;

            // Read value
            let value_offset = cursor;
            let value = V::read_cfg(&mut buf.as_ref()[cursor..].as_ref(), codec_config)
                .expect("unable to read value from blob");
            cursor = next_cursor + value.encode_size();
            let value_len = value.encode_size();
            index.insert(key.clone(), (value_offset, value_len));
            data.insert(key, value);
        }

        // Return info
        Ok((data, Wrapper::new(blob, version, buf.into(), index)))
    }

    /// Get a value from [Metadata] (if it exists).
    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    /// Get a mutable reference to a value from [Metadata] (if it exists).
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    /// Clear all values from [Metadata]. The new state will not be persisted until [Self::sync] is
    /// called.
    pub fn clear(&mut self) {
        self.map.clear();
        self.keys.set(0);
        self.dirty_all = true;
        self.dirty_keys.clear();
    }

    /// Put a value into [Metadata].
    ///
    /// If the key already exists, the value will be overwritten. The
    /// value stored will not be persisted until [Self::sync] is called.
    pub fn put(&mut self, key: K, value: V) {
        self.map.insert(key.clone(), value);
        self.keys.set(self.map.len() as i64);
        if !self.dirty_all {
            self.dirty_keys.insert(key);
        }
    }

    /// Remove a value from [Metadata] (if it exists).
    pub fn remove(&mut self, key: &K) {
        self.map.remove(key);
        self.keys.set(self.map.len() as i64);
        if !self.dirty_all {
            self.dirty_keys.insert(key.clone());
        }
    }

    /// Atomically commit the current state of [Metadata].
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.syncs.inc();

        // Compute next version.
        // While it is possible that extremely high-frequency updates to metadata could cause an eventual
        // overflow of version, syncing once per millisecond would overflow in 584,942,417 years.
        let past_version = self.blobs[self.cursor].version;
        let next_version = past_version.checked_add(1).expect("version overflow");

        // Build the next blob *and* its index in one pass.
        let past_length = self.blobs[self.cursor].data.len();
        let mut next_data = Vec::with_capacity(past_length);
        next_data.put_u64(next_version);

        let mut new_index = BTreeMap::new();
        for (key, value) in &self.map {
            next_data.put_slice(key.as_ref());
            let value_offset = next_data.len();
            value.write(&mut next_data);
            let value_len = next_data.len() - value_offset;
            new_index.insert(key.clone(), (value_offset, value_len));
        }
        let checksum = crc32fast::hash(&next_data[..]);
        next_data.put_u32(checksum);

        // Target blob (the one we will overwrite)
        let target_cursor = 1 - self.cursor;
        let target = &mut self.blobs[target_cursor];

        // ---- Version header diff ----
        let new_version_bytes = next_data[..u64::SIZE].to_vec();
        let mut writes: Vec<_> = Vec::new();
        let mut patched_bytes = 0usize;
        if target.data.len() >= u64::SIZE {
            // Overwrite only the last byte of the version (big-endian increment).
            writes.push(target.blob.write_at(new_version_bytes[7..].to_vec(), 7));
            patched_bytes += 1;
        } else {
            // Blob previously empty or truncated – write entire version.
            writes.push(target.blob.write_at(new_version_bytes, 0));
            patched_bytes += u64::SIZE;
        }

        // Track earliest offset that forces structural rewrite.
        let mut earliest_rewrite_offset: Option<usize> = None;

        // ---------------- Key-aware patch plan -----------------------------
        let dirty_iter: Box<dyn Iterator<Item = K>> = if self.dirty_all {
            Box::new(self.map.keys().cloned())
        } else {
            Box::new(self.dirty_keys.iter().cloned())
        };

        for key in dirty_iter {
            let new_entry = new_index.get(&key);
            let old_entry = target.index.get(&key);

            match (old_entry, new_entry) {
                (Some(&(old_off, old_len)), Some(&(new_off, new_len))) => {
                    if new_len == old_len {
                        // Value size unchanged → inline patch.
                        writes.push(target.blob.write_at(
                            next_data[new_off..new_off + new_len].to_vec(),
                            old_off as u64,
                        ));
                        patched_bytes += new_len;
                    } else {
                        // Length changed – structural change
                        let rewrite_off = (old_off.min(new_off)) - K::SIZE;
                        earliest_rewrite_offset = Some(match earliest_rewrite_offset {
                            None => rewrite_off,
                            Some(curr) => curr.min(rewrite_off),
                        });
                    }
                }
                (None, Some(&(new_off, _))) => {
                    // New key inserted -> rewrite from the key start (includes key bytes)
                    let key_start = new_off - K::SIZE;
                    earliest_rewrite_offset = Some(match earliest_rewrite_offset {
                        None => key_start,
                        Some(curr) => curr.min(key_start),
                    });
                }
                (Some(&(old_off, _)), None) => {
                    // Key was removed -> rewrite from the key start of the removed entry.
                    let key_start = old_off - K::SIZE;
                    earliest_rewrite_offset = Some(match earliest_rewrite_offset {
                        None => key_start,
                        Some(curr) => curr.min(key_start),
                    });
                }
                (None, None) => unreachable!(),
            }
        }

        // Detect any remaining value differences (e.g., when syncing to alternate blob without
        // user-level mutations).
        for (key, &(new_off, new_len)) in &new_index {
            if self.dirty_all || self.dirty_keys.contains(key) {
                continue; // already processed
            }
            if let Some(&(old_off, old_len)) = target.index.get(key) {
                if new_len == old_len {
                    let old_slice = &target.data[old_off..old_off + old_len];
                    let new_slice = &next_data[new_off..new_off + new_len];
                    if let Some(first_diff) =
                        old_slice.iter().zip(new_slice).position(|(a, b)| a != b)
                    {
                        // Write only the differing tail
                        let start = first_diff;
                        writes.push(
                            target
                                .blob
                                .write_at(new_slice[start..].to_vec(), (old_off + start) as u64),
                        );
                        patched_bytes += new_len - start;
                    }
                }
            }
        }

        // If the target blob is empty (no previous data), perform a full rewrite.
        if target.index.is_empty() {
            earliest_rewrite_offset = Some(0);
        }

        // Patch checksum bytes (always different when any change occurred or version increments).
        let checksum_offset = next_data.len() - 4;
        writes.push(target.blob.write_at(
            next_data[checksum_offset..].to_vec(),
            checksum_offset as u64,
        ));
        patched_bytes += 4;

        // Execute write plan based on whether structural rewrite is needed
        if let Some(offset) = earliest_rewrite_offset {
            // Apply any fixed-size patches prior to the rewrite.
            if offset == 0 {
                // Nothing before 0.
                patched_bytes = 0;
                writes.clear();
            }
            try_join_all(writes).await?;

            // Rewrite the remainder of the file starting from `offset`.
            target
                .blob
                .write_at(next_data[offset..].to_vec(), offset as u64)
                .await?;

            // Resize if blob shrunk.
            if next_data.len() < target.data.len() {
                target.blob.resize(next_data.len() as u64).await?;
            }

            let bytes_written = patched_bytes + (next_data.len() - offset);
            self.skipped
                .inc_by((next_data.len() - bytes_written) as u64);
        } else {
            // Only constant-length patches.
            try_join_all(writes).await?;
            if next_data.len() < target.data.len() {
                target.blob.resize(next_data.len() as u64).await?;
            }
            self.skipped
                .inc_by((next_data.len() - patched_bytes) as u64);
        }

        // Durability
        target.blob.sync().await?;

        // Update state
        self.cursor = target_cursor;
        target.version = next_version;
        target.data = next_data;
        target.index = new_index;

        // Reset dirty tracking
        self.dirty_all = false;
        self.dirty_keys.clear();

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
        Ok(())
    }
}
