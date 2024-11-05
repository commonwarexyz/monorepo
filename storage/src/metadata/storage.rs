use std::collections::BTreeMap;

use super::{Config, Error};
use bytes::{BufMut, Bytes};
use commonware_runtime::{Blob, Storage};
use tracing::debug;

const BLOB_NAMES: [&[u8]; 2] = [b"left", b"right"];

pub struct Metadata<B: Blob, E: Storage<B>> {
    runtime: E,
    cfg: Config,

    cursor: usize,
    blobs: [(B, u32); 2],
}

pub struct Batch {
    pending: BTreeMap<Vec<u8>, Bytes>,
}

impl Batch {
    pub fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
        }
    }

    /// Insert a key-value pair into the batch.
    ///
    /// If the key already exists in the batch, it will be overwritten.
    pub fn put(&mut self, key: &[u8], value: Bytes) {
        self.pending.insert(key.to_vec(), value);
    }

    /// Get the value associated with a key in the batch (if
    /// it exists).
    pub fn get(&self, key: &[u8]) -> Option<Bytes> {
        self.pending.get(key).cloned()
    }

    /// Remove a key-value pair from the batch.
    pub fn remove(&mut self, key: &[u8]) {
        self.pending.remove(key);
    }
}

impl Default for Batch {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: Blob, E: Storage<B>> Metadata<B, E> {
    async fn verify(blob: &B) -> Result<Option<(u32, BTreeMap<Vec<u8>, Bytes>, u32)>, Error> {
        // Get blob length
        let len = blob.len().await?;
        let len = len.try_into().map_err(|_| Error::BlobTooLarge(len))?;
        if len == 0 {
            // Empty blob
            return Ok(None);
        }

        // Read blob
        let mut buf = vec![0u8; len];
        blob.read_at(&mut buf, 0).await?;

        // Verify integrity
        let stored_checksum = u32::from_be_bytes(buf[buf.len() - 4..].try_into().unwrap());
        let computed_checksum = crc32fast::hash(&buf[..buf.len() - 4]);
        if stored_checksum != computed_checksum {
            // Truncate and return none
            debug!(
                stored = stored_checksum,
                computed = computed_checksum,
                "checksum mismatch: truncating"
            );
            blob.truncate(0).await?;
            blob.sync().await?;
            return Ok(None);
        }

        // Get parent
        let parent = u32::from_be_bytes(buf[..4].try_into().unwrap());

        // Extract data
        let mut data = BTreeMap::new();
        let mut cursor = 4;
        while cursor < buf.len() - 4 {
            let key_len = u32::from_be_bytes(buf[cursor..cursor + 4].try_into().unwrap());
            cursor += 4;
            let key = buf[cursor..cursor + key_len as usize].to_vec();
            cursor += key_len as usize;
            let value_len = u32::from_be_bytes(buf[cursor..cursor + 4].try_into().unwrap());
            cursor += 4;
            let value = Bytes::copy_from_slice(&buf[cursor..cursor + value_len as usize]);
            cursor += value_len as usize;
            data.insert(key, value);
        }

        // Return info
        Ok(Some((parent, data, computed_checksum)))
    }

    pub async fn init(runtime: E, cfg: Config) -> Result<(Self, BTreeMap<Vec<u8>, Bytes>), Error> {
        // Open dedicated blobs
        let left = runtime.open(&cfg.partition, BLOB_NAMES[0]).await?;
        let right = runtime.open(&cfg.partition, BLOB_NAMES[1]).await?;

        // Find latest blob (check which includes a hash of the other)
        let left_result = Self::verify(&left).await?;
        let right_result = Self::verify(&right).await?;

        // Set checksums
        let mut left_parent = 0;
        let mut left_data = BTreeMap::new();
        let mut left_checksum = 0;
        if let Some((parent, data, checksum)) = left_result {
            left_parent = parent;
            left_data = data;
            left_checksum = checksum;
        }
        let mut right_parent = 0;
        let mut right_data = BTreeMap::new();
        let mut right_checksum = 0;
        if let Some((parent, data, checksum)) = right_result {
            right_parent = parent;
            right_data = data;
            right_checksum = checksum;
        }

        // Choose latest blob
        let mut cursor = 0;
        let mut data = left_data;
        if right_checksum != 0 {
            if right_parent == left_checksum {
                cursor = 1;
                data = right_data;
            } else if left_parent == right_checksum {
                // Already set
            } else {
                panic!("cannot determine latest blob");
            }
        }

        // Return metadata
        Ok((
            Self {
                runtime,
                cfg,
                cursor,
                blobs: [(left, left_checksum), (right, right_checksum)],
            },
            data,
        ))
    }

    pub async fn commit(&mut self, batch: Batch) -> Result<(), Error> {
        // Get current blob
        let past_checksum = &self.blobs[self.cursor].1;

        // Get next blob
        let next_cursor = 1 - self.cursor;
        let next_blob = &self.blobs[next_cursor].0;

        // Create buffer
        let mut buf = Vec::with_capacity(4 + batch.pending.len() + 4);
        buf.put_u32(*past_checksum);
        for (key, value) in &batch.pending {
            let key_len = key.len().try_into().map_err(|_| Error::DataTooBig)?;
            buf.put_u32(key_len);
            buf.put(&key[..]);
            let value_len = value.len().try_into().map_err(|_| Error::DataTooBig)?;
            buf.put_u32(value_len);
            buf.put(&value[..]);
        }
        buf.put_u32(crc32fast::hash(&buf[..]));

        // Truncate next blob
        next_blob.truncate(0).await?;

        // Write batch
        next_blob.write_at(&buf, 0).await?;
        next_blob.sync().await?;

        // Switch blobs
        self.cursor = next_cursor;
        Ok(())
    }
}
