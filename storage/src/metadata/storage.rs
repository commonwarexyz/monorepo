use super::{Config, Error};
use bytes::BufMut;
use commonware_codec::{FixedSize, ReadExt};
use commonware_runtime::{Blob, Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::future::try_join_all;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::BTreeMap;
use tracing::{debug, warn};

/// The names of the two blobs that store metadata.
const BLOB_NAMES: [&[u8]; 2] = [b"left", b"right"];

/// The size of the block to fast-forward over.
///
/// This is set to the native word size for optimal performance on the target architecture.
const BLOCK_SIZE: usize = std::mem::size_of::<usize>();

/// One of the two wrappers that store metadata.
struct Wrapper<B: Blob> {
    blob: B,

    version: u64,
    data: Vec<u8>,
}

impl<B: Blob> Wrapper<B> {
    /// Create a new wrapper with the given data.
    fn new(blob: B, version: u64, data: Vec<u8>) -> Self {
        Self {
            blob,
            version,
            data,
        }
    }

    /// Create a new empty wrapper.
    fn empty(blob: B) -> Self {
        Self {
            blob,
            version: 0,
            data: Vec::new(),
        }
    }
}

/// Implementation of [Metadata] storage.
pub struct Metadata<E: Clock + Storage + Metrics, K: Array> {
    context: E,

    // Data is stored in a BTreeMap to enable deterministic serialization.
    map: BTreeMap<K, Vec<u8>>,
    cursor: usize,
    partition: String,
    blobs: [Wrapper<E::Blob>; 2],

    syncs: Counter,
    keys: Gauge,
    skipped: Counter,
}

impl<E: Clock + Storage + Metrics, K: Array> Metadata<E, K> {
    /// Initialize a new [Metadata] instance.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error<K>> {
        // Open dedicated blobs
        let (left_blob, left_len) = context.open(&cfg.partition, BLOB_NAMES[0]).await?;
        let (right_blob, right_len) = context.open(&cfg.partition, BLOB_NAMES[1]).await?;

        // Find latest blob (check which includes a hash of the other)
        let (left_map, left_wrapper) = Self::load(0, left_blob, left_len).await?;
        let (right_map, right_wrapper) = Self::load(1, right_blob, right_len).await?;

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

            syncs,
            keys,
            skipped,
        })
    }

    async fn load(
        index: usize,
        blob: E::Blob,
        len: u64,
    ) -> Result<(BTreeMap<K, Vec<u8>>, Wrapper<E::Blob>), Error<K>> {
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
        let mut cursor = u64::SIZE;
        while cursor < checksum_index {
            // Read key
            let next_cursor = cursor + K::SIZE;
            let key = K::read(&mut buf.as_ref()[cursor..next_cursor].as_ref()).unwrap();
            cursor = next_cursor;

            // Read value length
            let next_cursor = cursor + 4;
            let value_len =
                u32::from_be_bytes(buf.as_ref()[cursor..next_cursor].try_into().unwrap()) as usize;
            cursor = next_cursor;

            // Read value
            let next_cursor = cursor + value_len;
            let value = buf.as_ref()[cursor..next_cursor].to_vec();
            cursor = next_cursor;
            data.insert(key, value);
        }

        // Return info
        Ok((data, Wrapper::new(blob, version, buf.into())))
    }

    /// Get a value from [Metadata] (if it exists).
    pub fn get(&self, key: &K) -> Option<&Vec<u8>> {
        self.map.get(key)
    }

    /// Clear all values from [Metadata]. The new state will not be persisted until [Self::sync] is
    /// called.
    pub fn clear(&mut self) {
        self.map.clear();
        self.keys.set(0);
    }

    /// Put a value into [Metadata].
    ///
    /// If the key already exists, the value will be overwritten. The
    /// value stored will not be persisted until [Self::sync] is called.
    pub fn put(&mut self, key: K, value: Vec<u8>) {
        self.map.insert(key, value);
        self.keys.set(self.map.len() as i64);
    }

    /// Remove a value from [Metadata] (if it exists).
    pub fn remove(&mut self, key: &K) {
        self.map.remove(key);
        self.keys.set(self.map.len() as i64);
    }

    /// Atomically commit the current state of [Metadata].
    pub async fn sync(&mut self) -> Result<(), Error<K>> {
        self.syncs.inc();

        // Compute next version.
        //
        // While it is possible that extremely high-frequency updates to metadata could cause an eventual
        // overflow of version, syncing once per millisecond would overflow in 584,942,417 years.
        let past_version = self.blobs[self.cursor].version;
        let next_version = past_version.checked_add(1).expect("version overflow");

        // Create buffer
        let mut next_data = Vec::new();
        next_data.put_u64(next_version);
        for (key, value) in &self.map {
            next_data.put_slice(key.as_ref());
            let value_len = value
                .len()
                .try_into()
                .map_err(|_| Error::ValueTooBig(key.clone()))?;
            next_data.put_u32(value_len);
            next_data.put(&value[..]);
        }
        let checksum = crc32fast::hash(&next_data[..]);
        next_data.put_u32(checksum);

        // Get target blob (the one we will overwrite)
        let target_cursor = 1 - self.cursor;
        let target = &mut self.blobs[target_cursor];

        // Compute byte-level diff and only write changed segments
        let mut i = 0;
        let mut skipped = 0;
        let mut writes = Vec::new();
        while i < next_data.len() {
            // Fast-forward over identical blocks
            while i + BLOCK_SIZE <= next_data.len()
                && i + BLOCK_SIZE <= target.data.len()
                && next_data[i..i + BLOCK_SIZE] == target.data[i..i + BLOCK_SIZE]
            {
                i += BLOCK_SIZE;
                skipped += BLOCK_SIZE as u64;
            }

            // Skip identical bytes
            while i < next_data.len() && i < target.data.len() && next_data[i] == target.data[i] {
                i += 1;
                skipped += 1;
            }

            // Reached end of new data
            if i >= next_data.len() {
                break;
            }

            // Find end of differing segment
            let diff_start = i;
            while i < next_data.len() {
                if i >= target.data.len() {
                    i = next_data.len();
                    break;
                }
                if next_data[i] == target.data[i] {
                    break;
                }
                i += 1;
            }

            // Write the differing segment
            writes.push(
                target
                    .blob
                    .write_at(next_data[diff_start..i].to_vec(), diff_start as u64),
            );
        }
        try_join_all(writes).await?;
        self.skipped.inc_by(skipped);

        // If the new file is shorter, truncate; if longer, resize was implicitly handled by write_at
        if next_data.len() < target.data.len() {
            target.blob.resize(next_data.len() as u64).await?;
        }
        target.blob.sync().await?;

        // Update state
        self.cursor = target_cursor;
        target.version = next_version;
        target.data = next_data;
        Ok(())
    }

    /// Sync outstanding data and close [Metadata].
    pub async fn close(mut self) -> Result<(), Error<K>> {
        // Sync and close blobs
        self.sync().await?;
        for wrapper in self.blobs.into_iter() {
            wrapper.blob.close().await?;
        }
        Ok(())
    }

    /// Close and remove the underlying blobs.
    pub async fn destroy(self) -> Result<(), Error<K>> {
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
