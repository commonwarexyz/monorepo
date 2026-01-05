//! Simple section-based blob storage for values.
//!
//! This module provides a minimal blob storage optimized for storing values where
//! the size is tracked externally (in an index entry). Unlike the segmented variable
//! journal, this format does not include a size prefix since the caller already
//! knows the size.
//!
//! # Format
//!
//! Each entry is stored as:
//!
//! ```text
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! |     Compressed Data (variable)      | CRC32   |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! ```
//!
//! - **Compressed Data**: zstd compressed (if enabled) or raw codec output
//! - **CRC32**: 4-byte checksum of the compressed data
//!
//! # Read Flow
//!
//! 1. Get `(offset, size)` from index entry
//! 2. Read `size` bytes directly from blob at `offset`
//! 3. Last 4 bytes are CRC32, verify it
//! 4. Decompress remaining bytes if compression enabled
//! 5. Decode value

use crate::journal::Error;
use bytes::BufMut;
use commonware_codec::Codec;
use commonware_runtime::{Blob as _, Error as RError, Metrics, Storage};
use commonware_utils::hex;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::{
    collections::{btree_map::Entry, BTreeMap},
    io::Cursor,
    marker::PhantomData,
    num::NonZeroUsize,
};
use tracing::debug;
use zstd::{bulk::compress, decode_all};

/// Simple section-based blob storage for values.
///
/// Uses an internal write buffer for batching writes. Reads go directly to
/// blobs without any caching (ideal for large values that shouldn't pollute
/// a buffer pool cache).
pub struct Blob<E: Storage + Metrics, V: Codec> {
    context: E,
    partition: String,
    compression: Option<u8>,
    write_buffer_size: NonZeroUsize,
    codec_config: V::Cfg,

    /// Section blobs: section -> (blob, current_size, write_buffer)
    blobs: BTreeMap<u64, (E::Blob, u64, Vec<u8>)>,

    /// A section number before which all sections have been pruned.
    oldest_retained_section: u64,

    tracked: prometheus_client::metrics::gauge::Gauge,
    synced: Counter,
    pruned: Counter,

    _phantom: PhantomData<V>,
}

impl<E: Storage + Metrics, V: Codec> Blob<E, V> {
    /// Initialize blob storage, opening existing section blobs.
    pub async fn init(
        context: E,
        partition: String,
        compression: Option<u8>,
        write_buffer: NonZeroUsize,
        codec_config: V::Cfg,
    ) -> Result<Self, Error> {
        // Scan for existing blobs
        let mut blobs = BTreeMap::new();
        let stored_blobs = match context.scan(&partition).await {
            Ok(blobs) => blobs,
            Err(RError::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };

        for name in stored_blobs {
            let (blob, size) = context.open(&partition, &name).await?;
            let hex_name = hex(&name);
            let section = match name.try_into() {
                Ok(section) => u64::from_be_bytes(section),
                Err(_) => return Err(Error::InvalidBlobName(hex_name)),
            };
            debug!(section, blob = hex_name, size, "loaded section blob");
            blobs.insert(section, (blob, size, Vec::new()));
        }

        // Initialize metrics
        let tracked = Gauge::default();
        let synced = Counter::default();
        let pruned = Counter::default();
        context.register("tracked", "Number of blobs", tracked.clone());
        context.register("synced", "Number of syncs", synced.clone());
        context.register("pruned", "Number of blobs pruned", pruned.clone());
        tracked.set(blobs.len() as i64);

        Ok(Self {
            context,
            partition,
            compression,
            write_buffer_size: write_buffer,
            codec_config,
            blobs,
            oldest_retained_section: 0,
            tracked,
            synced,
            pruned,
            _phantom: PhantomData,
        })
    }

    /// Ensures that a section pruned during the current execution is not accessed.
    const fn prune_guard(&self, section: u64) -> Result<(), Error> {
        if section < self.oldest_retained_section {
            Err(Error::AlreadyPrunedToSection(self.oldest_retained_section))
        } else {
            Ok(())
        }
    }

    /// Append value to section, returns (offset, size).
    ///
    /// The returned size is the total bytes written (compressed_data + crc32).
    /// This size should be stored in the index entry for later retrieval.
    pub async fn append(&mut self, section: u64, value: &V) -> Result<(u32, u32), Error> {
        self.prune_guard(section)?;

        // Encode and optionally compress
        let encoded = value.encode();
        let compressed = if let Some(level) = self.compression {
            compress(&encoded, level as i32).map_err(|_| Error::CompressionFailed)?
        } else {
            encoded.into()
        };

        // Calculate checksum of compressed data
        let checksum = crc32fast::hash(&compressed);

        // Total entry size: compressed data + 4 bytes checksum
        let entry_size = compressed
            .len()
            .checked_add(4)
            .ok_or(Error::OffsetOverflow)?;
        let entry_size_u32: u32 = entry_size
            .try_into()
            .map_err(|_| Error::ItemTooLarge(entry_size))?;

        // Get or create blob for this section
        let (_blob, blob_size, buffer) = match self.blobs.entry(section) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let name = section.to_be_bytes();
                let (blob, size) = self.context.open(&self.partition, &name).await?;
                self.tracked.inc();
                entry.insert((blob, size, Vec::new()))
            }
        };

        // Calculate offset (current blob size + buffered data)
        let offset = *blob_size + buffer.len() as u64;
        let offset_u32: u32 = offset.try_into().map_err(|_| Error::OffsetOverflow)?;

        // Add to write buffer
        buffer.extend_from_slice(&compressed);
        buffer.put_u32(checksum);

        // Flush if buffer exceeds threshold
        if buffer.len() >= self.write_buffer_size.get() {
            self.flush_section(section).await?;
        }

        Ok((offset_u32, entry_size_u32))
    }

    /// Flush a section's write buffer to disk.
    async fn flush_section(&mut self, section: u64) -> Result<(), Error> {
        let (blob, blob_size, buffer) = match self.blobs.get_mut(&section) {
            Some(entry) => entry,
            None => return Ok(()),
        };

        if buffer.is_empty() {
            return Ok(());
        }

        // Write buffer to blob
        let buf = std::mem::take(buffer);
        let write_len = buf.len() as u64;
        blob.write_at(buf, *blob_size).await?;
        *blob_size += write_len;

        Ok(())
    }

    /// Read value at offset with known size (from index entry).
    ///
    /// Reads directly from blob without any caching.
    pub async fn get(&self, section: u64, offset: u32, size: u32) -> Result<V, Error> {
        self.prune_guard(section)?;

        let (blob, blob_size, buffer) = match self.blobs.get(&section) {
            Some(entry) => entry,
            None => return Err(Error::SectionOutOfRange(section)),
        };

        let offset_u64 = offset as u64;
        let size_usize = size as usize;

        // Check if data is in buffer or on disk
        let buf = if offset_u64 >= *blob_size {
            // Data is in the write buffer
            let buffer_offset = (offset_u64 - *blob_size) as usize;
            let buffer_end = buffer_offset
                .checked_add(size_usize)
                .ok_or(Error::OffsetOverflow)?;
            if buffer_end > buffer.len() {
                return Err(Error::Runtime(RError::BlobInsufficientLength));
            }
            buffer[buffer_offset..buffer_end].to_vec()
        } else {
            // Data is on disk - read directly (no caching)
            let end_offset = offset_u64
                .checked_add(size_usize as u64)
                .ok_or(Error::OffsetOverflow)?;

            if end_offset <= *blob_size {
                // Entirely on disk
                let read_buf = blob.read_at(vec![0u8; size_usize], offset_u64).await?;
                read_buf.into()
            } else {
                // Spans disk and buffer
                let disk_len = (*blob_size - offset_u64) as usize;
                let buffer_len = size_usize - disk_len;

                let mut result = vec![0u8; size_usize];

                // Read disk portion
                let disk_buf = blob.read_at(vec![0u8; disk_len], offset_u64).await?;
                result[..disk_len].copy_from_slice(disk_buf.as_ref());

                // Copy buffer portion
                if buffer_len > buffer.len() {
                    return Err(Error::Runtime(RError::BlobInsufficientLength));
                }
                result[disk_len..].copy_from_slice(&buffer[..buffer_len]);

                result
            }
        };

        // Entry format: [compressed_data] [crc32 (4 bytes)]
        if buf.len() < 4 {
            return Err(Error::Runtime(RError::BlobInsufficientLength));
        }

        let data_len = buf.len() - 4;
        let compressed_data = &buf[..data_len];
        let stored_checksum = u32::from_be_bytes(buf[data_len..].try_into().unwrap());

        // Verify checksum
        let checksum = crc32fast::hash(compressed_data);
        if checksum != stored_checksum {
            return Err(Error::ChecksumMismatch(stored_checksum, checksum));
        }

        // Decompress if needed and decode
        let value = if self.compression.is_some() {
            let decompressed =
                decode_all(Cursor::new(compressed_data)).map_err(|_| Error::DecompressionFailed)?;
            V::decode_cfg(decompressed.as_ref(), &self.codec_config).map_err(Error::Codec)?
        } else {
            V::decode_cfg(compressed_data, &self.codec_config).map_err(Error::Codec)?
        };

        Ok(value)
    }

    /// Sync section to disk (flushes write buffer).
    pub async fn sync(&mut self, section: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

        // Flush buffer first
        self.flush_section(section).await?;

        // Sync the blob
        if let Some((blob, _, _)) = self.blobs.get(&section) {
            self.synced.inc();
            blob.sync().await.map_err(Error::Runtime)?;
        }

        Ok(())
    }

    /// Sync all sections to disk.
    pub async fn sync_all(&mut self) -> Result<(), Error> {
        let sections: Vec<u64> = self.blobs.keys().copied().collect();
        for section in sections {
            self.flush_section(section).await?;
            if let Some((blob, _, _)) = self.blobs.get(&section) {
                self.synced.inc();
                blob.sync().await.map_err(Error::Runtime)?;
            }
        }
        Ok(())
    }

    /// Get the current size of a section (including buffered data).
    pub async fn size(&self, section: u64) -> Result<u64, Error> {
        self.prune_guard(section)?;

        match self.blobs.get(&section) {
            Some((_, blob_size, buffer)) => Ok(*blob_size + buffer.len() as u64),
            None => Ok(0),
        }
    }

    /// Rewind a section to a specific size (for crash recovery).
    ///
    /// Truncates the section to the given size and discards any buffered data.
    pub async fn rewind(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

        if let Some((blob, blob_size, buffer)) = self.blobs.get_mut(&section) {
            // Clear any buffered data
            buffer.clear();

            // Truncate blob if necessary
            if *blob_size > size {
                blob.resize(size).await?;
                *blob_size = size;
            }
        }

        Ok(())
    }

    /// Prune sections before min.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        let mut pruned = false;
        while let Some((&section, _)) = self.blobs.first_key_value() {
            if section >= min {
                break;
            }

            // Remove blob
            let (blob, size, _) = self.blobs.remove(&section).unwrap();
            drop(blob);

            // Remove from storage
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
            pruned = true;

            debug!(section, size, "pruned value blob");
            self.tracked.dec();
            self.pruned.inc();
        }

        if pruned {
            self.oldest_retained_section = min;
        }

        Ok(pruned)
    }

    /// Returns the number of the oldest section.
    pub fn oldest_section(&self) -> Option<u64> {
        self.blobs.first_key_value().map(|(section, _)| *section)
    }

    /// Close all blobs (syncs first).
    pub async fn close(&mut self) -> Result<(), Error> {
        self.sync_all().await
    }

    /// Destroy all blobs.
    pub async fn destroy(self) -> Result<(), Error> {
        for (section, (blob, size, _)) in self.blobs.into_iter() {
            drop(blob);
            debug!(section, size, "destroyed value blob");
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
        }
        match self.context.remove(&self.partition, None).await {
            Ok(()) => {}
            Err(RError::PartitionMissing(_)) => {}
            Err(err) => return Err(Error::Runtime(err)),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::NZUsize;

    #[test_traced]
    fn test_blob_append_and_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut blob: Blob<_, i32> = Blob::init(
                context.clone(),
                "test_partition".to_string(),
                None,
                NZUsize!(1024),
                (),
            )
            .await
            .expect("Failed to init blob");

            // Append a value
            let value: i32 = 42;
            let (offset, size) = blob.append(1, &value).await.expect("Failed to append");
            assert_eq!(offset, 0);

            // Get the value back
            let retrieved = blob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(retrieved, value);

            // Sync and verify
            blob.sync(1).await.expect("Failed to sync");
            let retrieved = blob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(retrieved, value);

            blob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_blob_multiple_values() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut blob: Blob<_, i32> = Blob::init(
                context.clone(),
                "test_partition".to_string(),
                None,
                NZUsize!(1024),
                (),
            )
            .await
            .expect("Failed to init blob");

            // Append multiple values
            let values: Vec<i32> = vec![1, 2, 3, 4, 5];
            let mut locations = Vec::new();

            for value in &values {
                let (offset, size) = blob.append(1, value).await.expect("Failed to append");
                locations.push((offset, size));
            }

            // Get all values back
            for (i, (offset, size)) in locations.iter().enumerate() {
                let retrieved = blob.get(1, *offset, *size).await.expect("Failed to get");
                assert_eq!(retrieved, values[i]);
            }

            blob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_blob_with_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut blob: Blob<_, [u8; 100]> = Blob::init(
                context.clone(),
                "test_partition".to_string(),
                Some(3), // zstd level 3
                NZUsize!(1024),
                (),
            )
            .await
            .expect("Failed to init blob");

            // Append a value
            let value: [u8; 100] = [0u8; 100]; // Compressible data
            let (offset, size) = blob.append(1, &value).await.expect("Failed to append");

            // Size should be smaller due to compression
            assert!(size < 100 + 4);

            // Get the value back
            let retrieved = blob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(retrieved, value);

            blob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_blob_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut blob: Blob<_, i32> = Blob::init(
                context.clone(),
                "test_partition".to_string(),
                None,
                NZUsize!(1024),
                (),
            )
            .await
            .expect("Failed to init blob");

            // Append to multiple sections
            for section in 1..=5 {
                blob.append(section, &(section as i32))
                    .await
                    .expect("Failed to append");
                blob.sync(section).await.expect("Failed to sync");
            }

            // Prune sections < 3
            blob.prune(3).await.expect("Failed to prune");

            // Sections 1 and 2 should be gone
            assert!(blob.get(1, 0, 8).await.is_err());
            assert!(blob.get(2, 0, 8).await.is_err());

            // Sections 3-5 should still exist
            assert!(blob.blobs.contains_key(&3));
            assert!(blob.blobs.contains_key(&4));
            assert!(blob.blobs.contains_key(&5));

            blob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_blob_checksum_mismatch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut blob: Blob<_, i32> = Blob::init(
                context.clone(),
                "test_partition".to_string(),
                None,
                NZUsize!(1024),
                (),
            )
            .await
            .expect("Failed to init blob");

            // Append a value
            let value: i32 = 42;
            let (offset, size) = blob.append(1, &value).await.expect("Failed to append");
            blob.sync(1).await.expect("Failed to sync");

            // Corrupt the data
            let (underlying_blob, _, _) = blob.blobs.get(&1).unwrap();
            underlying_blob
                .write_at(vec![0xFF, 0xFF, 0xFF, 0xFF], offset as u64)
                .await
                .expect("Failed to corrupt");
            underlying_blob.sync().await.expect("Failed to sync");

            // Get should fail with checksum mismatch
            let result = blob.get(1, offset, size).await;
            assert!(matches!(result, Err(Error::ChecksumMismatch(_, _))));

            blob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_blob_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "test_partition".to_string();

            // Create and populate blob
            let mut blob: Blob<_, i32> =
                Blob::init(context.clone(), partition.clone(), None, NZUsize!(1024), ())
                    .await
                    .expect("Failed to init blob");

            let value: i32 = 42;
            let (offset, size) = blob.append(1, &value).await.expect("Failed to append");
            blob.sync(1).await.expect("Failed to sync");
            drop(blob);

            // Reopen and verify
            let blob: Blob<_, i32> =
                Blob::init(context.clone(), partition, None, NZUsize!(1024), ())
                    .await
                    .expect("Failed to reinit blob");

            let retrieved = blob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(retrieved, value);

            blob.destroy().await.expect("Failed to destroy");
        });
    }
}
