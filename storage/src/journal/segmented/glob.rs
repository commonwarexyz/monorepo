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

use super::manager::{Config as ManagerConfig, Manager, WriteFactory};
use crate::journal::Error;
use bytes::BufMut;
use commonware_codec::Codec;
use commonware_runtime::{Blob as _, Error as RError, Metrics, Storage};
use std::{io::Cursor, marker::PhantomData, num::NonZeroUsize};
use zstd::{bulk::compress, decode_all};

/// Configuration for blob storage.
#[derive(Clone)]
pub struct Config<C> {
    /// The partition to use for storing blobs.
    pub partition: String,

    /// Optional compression level (using `zstd`) to apply to data before storing.
    pub compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding items.
    pub codec_config: C,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,
}

/// Simple section-based blob storage for values.
///
/// Uses [`buffer::Write`](commonware_runtime::buffer::Write) for batching writes.
/// Reads go directly to blobs without any caching (ideal for large values that
/// shouldn't pollute a buffer pool cache).
pub struct Glob<E: Storage + Metrics, V: Codec> {
    manager: Manager<E, WriteFactory>,

    /// Compression level (if enabled).
    compression: Option<u8>,

    /// Codec configuration.
    codec_config: V::Cfg,

    _phantom: PhantomData<V>,
}

impl<E: Storage + Metrics, V: Codec> Glob<E, V> {
    /// Initialize blob storage, opening existing section blobs.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let manager_cfg = ManagerConfig {
            partition: cfg.partition,
            factory: WriteFactory {
                capacity: cfg.write_buffer,
            },
        };
        let manager = Manager::init(context, manager_cfg).await?;

        Ok(Self {
            manager,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
            _phantom: PhantomData,
        })
    }

    /// Append value to section, returns (offset, size).
    ///
    /// The returned size is the total bytes written (compressed_data + crc32).
    /// This size should be stored in the index entry for later retrieval.
    pub async fn append(&mut self, section: u64, value: &V) -> Result<(u32, u32), Error> {
        // Encode and optionally compress
        let encoded = value.encode();
        let compressed = if let Some(level) = self.compression {
            compress(&encoded, level as i32).map_err(|_| Error::CompressionFailed)?
        } else {
            encoded.into()
        };

        // Total entry size: compressed data + 4 bytes checksum
        let entry_size = compressed
            .len()
            .checked_add(4)
            .ok_or(Error::OffsetOverflow)?;
        let entry_size_u32: u32 = entry_size
            .try_into()
            .map_err(|_| Error::ItemTooLarge(entry_size))?;

        // Get or create blob for this section
        let writer = self.manager.get_or_create(section).await?;

        // Get current offset (logical size including buffered data)
        let offset = writer.size().await;
        let offset_u32: u32 = offset.try_into().map_err(|_| Error::OffsetOverflow)?;

        // Pre-allocate buffer with exact size: compressed data + checksum
        let mut buf = Vec::with_capacity(entry_size);
        buf.extend_from_slice(&compressed);
        buf.put_u32(crc32fast::hash(&compressed));

        // Write via buffered writer (handles batching internally)
        writer.write_at(buf, offset).await?;

        Ok((offset_u32, entry_size_u32))
    }

    /// Read value at offset with known size (from index entry).
    ///
    /// Reads directly from blob without any caching.
    pub async fn get(&self, section: u64, offset: u32, size: u32) -> Result<V, Error> {
        let writer = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        let size_usize = size as usize;

        // Read via buffered writer (handles read-through for buffered data)
        let buf = writer.read_at(vec![0u8; size_usize], offset as u64).await?;
        let buf = buf.as_ref();

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
    pub async fn sync(&self, section: u64) -> Result<(), Error> {
        self.manager.sync(section).await
    }

    /// Sync all sections to disk.
    pub async fn sync_all(&self) -> Result<(), Error> {
        self.manager.sync_all().await
    }

    /// Get the current size of a section (including buffered data).
    pub async fn size(&self, section: u64) -> Result<u64, Error> {
        self.manager.size(section).await
    }

    /// Rewind a section to a specific size (for crash recovery).
    ///
    /// Truncates the section to the given size and discards any buffered data.
    pub async fn rewind(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.manager.rewind_section(section, size).await
    }

    /// Prune sections before min.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        self.manager.prune(min).await
    }

    /// Returns the number of the oldest section.
    pub fn oldest_section(&self) -> Option<u64> {
        self.manager.oldest_section()
    }

    /// Close all blobs (syncs first).
    pub async fn close(&mut self) -> Result<(), Error> {
        self.sync_all().await
    }

    /// Destroy all blobs.
    pub async fn destroy(self) -> Result<(), Error> {
        self.manager.destroy().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::NZUsize;

    fn test_cfg() -> Config<()> {
        Config {
            partition: "test_partition".to_string(),
            compression: None,
            codec_config: (),
            write_buffer: NZUsize!(1024),
        }
    }

    #[test_traced]
    fn test_glob_append_and_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut glob: Glob<_, i32> = Glob::init(context.clone(), test_cfg())
                .await
                .expect("Failed to init glob");

            // Append a value
            let value: i32 = 42;
            let (offset, size) = glob.append(1, &value).await.expect("Failed to append");
            assert_eq!(offset, 0);

            // Get the value back
            let retrieved = glob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(retrieved, value);

            // Sync and verify
            glob.sync(1).await.expect("Failed to sync");
            let retrieved = glob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(retrieved, value);

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_multiple_values() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut glob: Glob<_, i32> = Glob::init(context.clone(), test_cfg())
                .await
                .expect("Failed to init glob");

            // Append multiple values
            let values: Vec<i32> = vec![1, 2, 3, 4, 5];
            let mut locations = Vec::new();

            for value in &values {
                let (offset, size) = glob.append(1, value).await.expect("Failed to append");
                locations.push((offset, size));
            }

            // Get all values back
            for (i, (offset, size)) in locations.iter().enumerate() {
                let retrieved = glob.get(1, *offset, *size).await.expect("Failed to get");
                assert_eq!(retrieved, values[i]);
            }

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_with_compression() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test_partition".to_string(),
                compression: Some(3), // zstd level 3
                codec_config: (),
                write_buffer: NZUsize!(1024),
            };
            let mut glob: Glob<_, [u8; 100]> = Glob::init(context.clone(), cfg)
                .await
                .expect("Failed to init glob");

            // Append a value
            let value: [u8; 100] = [0u8; 100]; // Compressible data
            let (offset, size) = glob.append(1, &value).await.expect("Failed to append");

            // Size should be smaller due to compression
            assert!(size < 100 + 4);

            // Get the value back
            let retrieved = glob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(retrieved, value);

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut glob: Glob<_, i32> = Glob::init(context.clone(), test_cfg())
                .await
                .expect("Failed to init glob");

            // Append to multiple sections
            for section in 1..=5 {
                glob.append(section, &(section as i32))
                    .await
                    .expect("Failed to append");
                glob.sync(section).await.expect("Failed to sync");
            }

            // Prune sections < 3
            glob.prune(3).await.expect("Failed to prune");

            // Sections 1 and 2 should be gone
            assert!(glob.get(1, 0, 8).await.is_err());
            assert!(glob.get(2, 0, 8).await.is_err());

            // Sections 3-5 should still exist
            assert!(glob.manager.blobs().contains_key(&3));
            assert!(glob.manager.blobs().contains_key(&4));
            assert!(glob.manager.blobs().contains_key(&5));

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_checksum_mismatch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut glob: Glob<_, i32> = Glob::init(context.clone(), test_cfg())
                .await
                .expect("Failed to init glob");

            // Append a value
            let value: i32 = 42;
            let (offset, size) = glob.append(1, &value).await.expect("Failed to append");
            glob.sync(1).await.expect("Failed to sync");

            // Corrupt the data by writing directly to the underlying blob
            let writer = glob.manager.blobs().get(&1).unwrap();
            writer
                .write_at(vec![0xFF, 0xFF, 0xFF, 0xFF], offset as u64)
                .await
                .expect("Failed to corrupt");
            writer.sync().await.expect("Failed to sync");

            // Get should fail with checksum mismatch
            let result = glob.get(1, offset, size).await;
            assert!(matches!(result, Err(Error::ChecksumMismatch(_, _))));

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate glob
            let mut glob: Glob<_, i32> = Glob::init(context.clone(), cfg.clone())
                .await
                .expect("Failed to init glob");

            let value: i32 = 42;
            let (offset, size) = glob.append(1, &value).await.expect("Failed to append");
            glob.sync(1).await.expect("Failed to sync");
            drop(glob);

            // Reopen and verify
            let glob: Glob<_, i32> = Glob::init(context.clone(), cfg)
                .await
                .expect("Failed to reinit glob");

            let retrieved = glob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(retrieved, value);

            glob.destroy().await.expect("Failed to destroy");
        });
    }
}
