use super::{Config, Error};
use bytes::BufMut;
use commonware_codec::{FixedSize, ReadExt};
use commonware_runtime::{Blob, Clock, Metrics, Storage};
use commonware_utils::{Array, SystemTimeExt as _};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, trace, warn};

const BLOB_NAMES: [&[u8]; 2] = [b"left", b"right"];
const SECONDS_IN_NANOSECONDS: u128 = 1_000_000_000;

/// Implementation of `Metadata` storage.
pub struct Metadata<E: Clock + Storage + Metrics, K: Array> {
    context: E,

    // Data is stored in a BTreeMap to enable deterministic serialization.
    data: BTreeMap<K, Vec<u8>>,
    cursor: usize,
    partition: String,
    blobs: [(E::Blob, u64, u128); 2],

    syncs: Counter,
    keys: Gauge,
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
        let mut left_timestamp = 0;
        let mut left_data = BTreeMap::new();
        if let Some((timestamp, data)) = left_result {
            left_timestamp = timestamp;
            left_data = data;
        }
        let mut right_timestamp = 0;
        let mut right_data = BTreeMap::new();
        if let Some((timestamp, data)) = right_result {
            right_timestamp = timestamp;
            right_data = data;
        }

        // Choose latest blob
        let mut data = left_data;
        let mut cursor = 0;
        if right_timestamp > left_timestamp {
            cursor = 1;
            data = right_data;
        }

        // Create metrics
        let syncs = Counter::default();
        let keys = Gauge::default();
        context.register("syncs", "number of syncs of data to disk", syncs.clone());
        context.register("keys", "number of tracked keys", keys.clone());

        // Return metadata
        keys.set(data.len() as i64);
        Ok(Self {
            context,

            data,
            cursor,
            partition: cfg.partition,
            blobs: [
                (left_blob, left_len, left_timestamp),
                (right_blob, right_len, right_timestamp),
            ],

            syncs,
            keys,
        })
    }

    async fn load(
        index: usize,
        blob: &E::Blob,
        len: u64,
    ) -> Result<Option<(u128, BTreeMap<K, Vec<u8>>)>, Error<K>> {
        // Get blob length
        if len == 0 {
            // Empty blob
            return Ok(None);
        }

        // Read blob
        let len = len.try_into().map_err(|_| Error::BlobTooLarge(len))?;
        let buf = blob.read_at(vec![0u8; len], 0).await?;

        // Verify integrity
        if buf.len() < 20 {
            // Truncate and return none
            warn!(
                blob = index,
                len = buf.len(),
                "blob is too short: truncating"
            );
            blob.truncate(0).await?;
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
            blob.truncate(0).await?;
            blob.sync().await?;
            return Ok(None);
        }

        // Get parent
        let timestamp = u128::from_be_bytes(buf.as_ref()[..16].try_into().unwrap());

        // Extract data
        //
        // If the checksum is correct, we assume data is correctly packed and we don't perform
        // length checks on the cursor.
        let mut data = BTreeMap::new();
        let mut cursor = u128::SIZE;
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
        Ok(Some((timestamp, data)))
    }

    /// Get a value from `Metadata` (if it exists).
    pub fn get(&self, key: &K) -> Option<&Vec<u8>> {
        self.data.get(key)
    }

    /// Clear all values from `Metadata`. The new state will not be persisted until `sync` is
    /// called.
    pub fn clear(&mut self) {
        self.data.clear();
        self.keys.set(0);
    }

    /// Put a value into `Metadata`.
    ///
    /// If the key already exists, the value will be overwritten. The
    /// value stored will not be persisted until `sync` is called.
    pub fn put(&mut self, key: K, value: Vec<u8>) {
        self.data.insert(key, value);
        self.keys.set(self.data.len() as i64);
    }

    /// Remove a value from `Metadata` (if it exists).
    pub fn remove(&mut self, key: &K) {
        self.data.remove(key);
        self.keys.set(self.data.len() as i64);
    }

    /// Get the timestamp of the last update to `Metadata` (if a previous
    /// update exists).
    pub fn last_update(&self) -> Option<SystemTime> {
        let timestamp = self.blobs[self.cursor].2;
        if timestamp == 0 {
            return None;
        }
        let timestamp = Duration::new(
            (timestamp / SECONDS_IN_NANOSECONDS) as u64,
            (timestamp % SECONDS_IN_NANOSECONDS) as u32,
        );
        Some(UNIX_EPOCH + timestamp)
    }

    /// Atomically commit the current state of `Metadata`.
    pub async fn sync(&mut self) -> Result<(), Error<K>> {
        // Compute next timestamp
        let past_timestamp = &self.blobs[self.cursor].2;
        let mut next_timestamp = self.context.current().epoch().as_nanos();
        if next_timestamp <= *past_timestamp {
            // While it is possible that extremely high-frequency updates to `Metadata` (more than
            // one update per nanosecond) could cause an eventual overflow of the timestamp, this
            // is not treated as a serious concern (as any call to `sync` will take longer than this).
            //
            // The nice benefit of this is that we also can provide the caller with some timestamp
            // of the last update, which can be useful for a variety of things.
            trace!(
                past = *past_timestamp,
                next = next_timestamp,
                "timestamps are not monotonically increasing: adjusting next"
            );
            next_timestamp = *past_timestamp + 1;
        }

        // Create buffer
        let mut buf = Vec::new();
        buf.put_u128(next_timestamp);
        for (key, value) in &self.data {
            buf.put_slice(key.as_ref());
            let value_len = value
                .len()
                .try_into()
                .map_err(|_| Error::ValueTooBig(key.clone()))?;
            buf.put_u32(value_len);
            buf.put(&value[..]);
        }
        let checksum = crc32fast::hash(&buf[..]);
        buf.put_u32(checksum);

        // Get next blob
        let next_cursor = 1 - self.cursor;
        let next_blob = &mut self.blobs[next_cursor];

        // Write and truncate blob
        let buf_len = buf.len() as u64;
        next_blob.0.write_at(buf, 0).await?;
        next_blob.0.truncate(buf_len).await?;
        next_blob.0.sync().await?;
        next_blob.1 = buf_len;
        next_blob.2 = next_timestamp;

        // Switch blobs
        self.cursor = next_cursor;
        self.syncs.inc();
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
