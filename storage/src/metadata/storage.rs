use super::{Config, Error};
use bytes::BufMut;
use commonware_codec::{FixedSize, ReadExt};
use commonware_runtime::{Blob, Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::future::try_join_all;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::collections::BTreeMap;
use tracing::{debug, warn};

const BLOB_NAMES: [&[u8]; 2] = [b"left", b"right"];

/// Implementation of `Metadata` storage.
pub struct Metadata<E: Clock + Storage + Metrics, K: Array> {
    context: E,

    // Data is stored in a BTreeMap to enable deterministic serialization.
    map: BTreeMap<K, Vec<u8>>,
    cursor: usize,
    partition: String,
    blobs: [(E::Blob, u64, Vec<u8>); 2],

    syncs: Counter,
    keys: Gauge,
    skipped: Counter,
}

impl<E: Clock + Storage + Metrics, K: Array> Metadata<E, K> {
    /// Initialize a new `Metadata` instance.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error<K>> {
        // Open dedicated blobs
        let (left_blob, left_len) = context.open(&cfg.partition, BLOB_NAMES[0]).await?;
        let (right_blob, right_len) = context.open(&cfg.partition, BLOB_NAMES[1]).await?;

        // Find latest blob (check which includes a hash of the other)
        let left_result = Self::load(0, &left_blob, left_len).await?;
        let right_result = Self::load(1, &right_blob, right_len).await?;

        // Set checksums
        let mut left_version = 0;
        let mut left_map = BTreeMap::new();
        let mut left_data = Vec::new();
        if let Some((version, map, data)) = left_result {
            left_version = version;
            left_map = map;
            left_data = data;
        }
        let mut right_version = 0;
        let mut right_map = BTreeMap::new();
        let mut right_data = Vec::new();
        if let Some((version, map, data)) = right_result {
            right_version = version;
            right_map = map;
            right_data = data;
        }

        // Choose latest blob
        let mut map = left_map;
        let mut cursor = 0;
        if right_version > left_version {
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
            "total bytes not written to disk",
            skipped.clone(),
        );

        // Return metadata
        keys.set(map.len() as i64);
        Ok(Self {
            context,

            map,
            cursor,
            partition: cfg.partition,
            blobs: [
                (left_blob, left_version, left_data),
                (right_blob, right_version, right_data),
            ],

            syncs,
            keys,
            skipped,
        })
    }

    async fn load(
        index: usize,
        blob: &E::Blob,
        len: u64,
    ) -> Result<Option<(u64, BTreeMap<K, Vec<u8>>, Vec<u8>)>, Error<K>> {
        // Get blob length
        if len == 0 {
            // Empty blob
            return Ok(None);
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
            return Ok(None);
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
            return Ok(None);
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
        Ok(Some((version, data, buf.into())))
    }

    /// Get a value from `Metadata` (if it exists).
    pub fn get(&self, key: &K) -> Option<&Vec<u8>> {
        self.map.get(key)
    }

    /// Clear all values from `Metadata`. The new state will not be persisted until `sync` is
    /// called.
    pub fn clear(&mut self) {
        self.map.clear();
        self.keys.set(0);
    }

    /// Put a value into `Metadata`.
    ///
    /// If the key already exists, the value will be overwritten. The
    /// value stored will not be persisted until `sync` is called.
    pub fn put(&mut self, key: K, value: Vec<u8>) {
        self.map.insert(key, value);
        self.keys.set(self.map.len() as i64);
    }

    /// Remove a value from `Metadata` (if it exists).
    pub fn remove(&mut self, key: &K) {
        self.map.remove(key);
        self.keys.set(self.map.len() as i64);
    }

    /// Atomically commit the current state of `Metadata`.
    pub async fn sync(&mut self) -> Result<(), Error<K>> {
        self.syncs.inc();

        // Compute next version.
        //
        // While it is possible that extremely high-frequency updates to `Metadata` could cause an eventual
        // overflow of version, syncing once per millisecond would overflow in 584,942,417 years.
        let past_version = self.blobs[self.cursor].1;
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
        let (target_blob, target_version, target_data) = &mut self.blobs[target_cursor];

        // Compute byte-level diff and only write changed segments
        let mut i = 0;
        let mut skipped = 0;
        let mut writes = Vec::new();
        while i < next_data.len() {
            // Skip equal bytes
            while i < next_data.len() && i < target_data.len() && next_data[i] == target_data[i] {
                i += 1;
                skipped += 1;
            }
            if i >= next_data.len() {
                break;
            }

            // Write differing segments
            let start = i;
            while i < next_data.len() && (i >= target_data.len() || next_data[i] != target_data[i])
            {
                i += 1;
            }
            let end = i;
            writes.push(target_blob.write_at(next_data[start..end].to_vec(), start as u64));
        }
        try_join_all(writes).await?;
        self.skipped.inc_by(skipped);

        // If the new file is shorter, truncate; if longer, resize was implicitly handled by write_at
        if next_data.len() < target_data.len() {
            target_blob.resize(next_data.len() as u64).await?;
        }
        target_blob.sync().await?;

        // Update state
        self.cursor = target_cursor;
        *target_version = next_version;
        *target_data = next_data;
        Ok(())
    }

    /// Sync outstanding data and close `Metadata`.
    pub async fn close(mut self) -> Result<(), Error<K>> {
        // Sync and close blobs
        self.sync().await?;
        for (blob, _, _) in self.blobs.into_iter() {
            blob.close().await?;
        }
        Ok(())
    }

    /// Close and remove the underlying blobs.
    pub async fn destroy(self) -> Result<(), Error<K>> {
        for (i, (blob, _, _)) in self.blobs.into_iter().enumerate() {
            blob.close().await?;
            self.context
                .remove(&self.partition, Some(BLOB_NAMES[i]))
                .await?;
            debug!(blob = i, "destroyed blob");
        }
        Ok(())
    }
}
