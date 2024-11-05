use std::{collections::BTreeMap, marker::PhantomData};

use super::{Config, Error};
use bytes::{BufMut, Bytes};
use commonware_runtime::{Blob, Storage};
use tracing::debug;

const BLOB_NAMES: [&[u8]; 2] = [b"left", b"right"];

pub struct Metadata<B: Blob, E: Storage<B>> {
    // Data is stored in a BTreeMap to enable deterministic serialization.
    data: BTreeMap<u32, Bytes>,

    cursor: usize,
    blobs: [(B, u32); 2],

    _phantom_e: PhantomData<E>,
}

impl<B: Blob, E: Storage<B>> Metadata<B, E> {
    pub async fn init(runtime: E, cfg: Config) -> Result<Self, Error> {
        // Open dedicated blobs
        let left = runtime.open(&cfg.partition, BLOB_NAMES[0]).await?;
        let right = runtime.open(&cfg.partition, BLOB_NAMES[1]).await?;

        // Find latest blob (check which includes a hash of the other)
        let left_result = Self::load(BLOB_NAMES[0], &left).await?;
        let right_result = Self::load(BLOB_NAMES[1], &right).await?;

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
        let mut data = left_data;
        let mut cursor = 0;
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
        Ok(Self {
            data,
            cursor,
            blobs: [(left, left_checksum), (right, right_checksum)],

            _phantom_e: PhantomData,
        })
    }

    async fn load(
        name: &[u8],
        blob: &B,
    ) -> Result<Option<(u32, BTreeMap<u32, Bytes>, u32)>, Error> {
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
                name = std::str::from_utf8(name).unwrap(),
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
            let key = u32::from_be_bytes(buf[cursor..cursor + 4].try_into().unwrap());
            cursor += 4;
            let value_len = u32::from_be_bytes(buf[cursor..cursor + 4].try_into().unwrap());
            cursor += 4;
            let value = Bytes::copy_from_slice(&buf[cursor..cursor + value_len as usize]);
            cursor += value_len as usize;
            data.insert(key, value);
        }

        // Return info
        Ok(Some((parent, data, computed_checksum)))
    }

    /// Get a value from the metadata store (if it exists).
    pub fn get(&self, key: u32) -> Option<&Bytes> {
        self.data.get(&key)
    }

    /// Put a value into the metadata store.
    ///
    /// If the key already exists, the value will be overwritten.
    ///
    /// The value stored will not be persisted until `sync` is called.
    pub fn put(&mut self, key: u32, value: Bytes) {
        self.data.insert(key, value);
    }

    /// Remove a value from the metadata store (if it exists).
    pub fn remove(&mut self, key: u32) {
        self.data.remove(&key);
    }

    /// Persist the current state of the metadata store.
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Get current blob
        let past_checksum = &self.blobs[self.cursor].1;

        // Get next blob
        let next_cursor = 1 - self.cursor;
        let next_blob = &self.blobs[next_cursor].0;

        // Create buffer
        let mut buf = Vec::new();
        buf.put_u32(*past_checksum);
        for (key, value) in &self.data {
            buf.put_u32(*key);
            let value_len = value
                .len()
                .try_into()
                .map_err(|_| Error::ValueTooBig(*key))?;
            buf.put_u32(value_len);
            buf.put(&value[..]);
        }
        buf.put_u32(crc32fast::hash(&buf[..]));

        // Write and truncate blob
        next_blob.write_at(&buf, 0).await?;
        next_blob.truncate(buf.len() as u64).await?;
        next_blob.sync().await?;

        // Switch blobs
        self.cursor = next_cursor;
        Ok(())
    }
}
