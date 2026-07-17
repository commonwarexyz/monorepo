//! Simple section-based blob storage for values.
//!
//! This module provides a minimal blob storage optimized for storing values where
//! the size is tracked externally (in an index entry). Unlike the segmented variable
//! journal, this format does not include a size prefix since the caller already
//! knows the size.
//!
//! # Format
//!
//! Each entry is the zstd compressed (if enabled) or raw codec output of the value,
//! stored back to back. Integrity is provided by the storage backend, which verifies
//! all reads.
//!
//! # Read Flow
//!
//! 1. Get `(offset, size)` from index entry
//! 2. Read `size` bytes directly from blob at byte offset
//! 3. Decompress if compression enabled
//! 4. Decode value

use super::manager::{Config as ManagerConfig, Manager, WriteFactory};
use crate::journal::Error;
use commonware_codec::{Codec, CodecShared};
use commonware_runtime::{BlobOptions, BufferPooler, Handle, Metrics, Storage};
use std::{io::Cursor, num::NonZeroUsize};
use zstd::{bulk::compress, decode_all};

/// Verification-group size for glob blobs: 64 KiB (16 blocks) per checksum
/// instead of the 4 KiB default (see the manager config below for the
/// read-shape justification).
const VERIFICATION_GROUP: u64 = 64 << 10;

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
/// shouldn't pollute a page cache).
pub struct Glob<E: BufferPooler + Storage + Metrics, V: Codec> {
    manager: Manager<E, WriteFactory>,

    /// Compression level (if enabled).
    compression: Option<u8>,

    /// Codec configuration.
    codec_config: V::Cfg,
}

impl<E: BufferPooler + Storage + Metrics, V: CodecShared> Glob<E, V> {
    /// Initialize blob storage, opening existing section blobs.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let manager_cfg = ManagerConfig {
            partition: cfg.partition,
            factory: WriteFactory {
                capacity: cfg.write_buffer,
                pool: context.storage_buffer_pool().clone(),
            },
            // Glob blobs are written contiguously (buffered appends) and
            // read as whole values, uncached, so coarse verification
            // groups cut checksum metadata and commit-manifest size 16x.
            // The trade-off is a one-time group-sized read to verify the
            // first touch of each group after restart — value-sized reads
            // amortize it, and replay-style scans pay nothing extra.
            blob_options: BlobOptions {
                verification_group: Some(VERIFICATION_GROUP),
            },
        };
        let manager = Manager::init(context, manager_cfg).await?;

        Ok(Self {
            manager,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
        })
    }

    /// Append value to section, returns (offset, size).
    ///
    /// The returned offset is the byte offset where the entry was written.
    /// The returned size is the total bytes written.
    /// Both should be stored in the index entry for later retrieval.
    pub async fn append(&mut self, section: u64, value: &V) -> Result<(u64, u32), Error> {
        // Encode and optionally compress
        let buf = if let Some(level) = self.compression {
            let encoded = value.encode();
            compress(&encoded, level as i32).map_err(|_| Error::CompressionFailed)?
        } else {
            // Uncompressed: pre-allocate exact size to avoid copying
            let mut buf = Vec::with_capacity(value.encode_size());
            value.write(&mut buf);
            buf
        };

        // Write to blob
        let entry_size = u32::try_from(buf.len()).map_err(|_| Error::ValueTooLarge)?;
        let writer = self.manager.get_or_create(section).await?;
        let offset = writer.size();
        writer.write_at(offset, buf).await.map_err(Error::Runtime)?;

        Ok((offset, entry_size))
    }

    /// Read value at offset with known size (from index entry).
    ///
    /// The offset should be the byte offset returned by `append()`.
    /// Reads directly from blob without any caching.
    pub async fn get(&self, section: u64, offset: u64, size: u32) -> Result<V, Error> {
        let writer = self
            .manager
            .get(section)?
            .ok_or(Error::SectionOutOfRange(section))?;

        // Read via buffered writer (handles read-through for buffered data)
        let buf = writer.read_at(offset, size as usize).await?.coalesce();

        // Decompress if needed and decode
        let value = if self.compression.is_some() {
            let decompressed =
                decode_all(Cursor::new(buf.as_ref())).map_err(|_| Error::DecompressionFailed)?;
            V::decode_cfg(decompressed.as_ref(), &self.codec_config).map_err(Error::Codec)?
        } else {
            V::decode_cfg(buf.as_ref(), &self.codec_config).map_err(Error::Codec)?
        };

        Ok(value)
    }

    /// Stage the creation of a fresh section's blob with `batch` (see
    /// [super::manager::Manager::create_into] for the caller contract).
    pub(crate) async fn create_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        &mut self,
        section: u64,
        batch: &mut T,
    ) -> Result<(), Error> {
        self.manager.create_into(section, batch).await
    }

    /// Sync the given `sections` to disk (flushes write buffers).
    pub async fn sync(&mut self, sections: impl crate::Sections) -> Result<(), Error> {
        self.manager.sync(sections).await
    }

    /// Stage the durability of the given `sections` with `batch`.
    pub async fn sync_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        &mut self,
        sections: impl crate::Sections,
        batch: &mut T,
    ) -> Result<(), Error> {
        self.manager.sync_into(sections, batch).await
    }

    /// Start syncing the given `sections` to disk.
    pub async fn start_sync(
        &mut self,
        sections: impl crate::Sections,
    ) -> Result<Handle<()>, Error> {
        self.manager.start_sync(sections).await
    }

    /// Sync all sections to disk.
    pub async fn sync_all(&mut self) -> Result<(), Error> {
        self.manager.sync_all().await
    }

    /// Get the current size of a section (including buffered data).
    pub fn size(&self, section: u64) -> Result<u64, Error> {
        self.manager.size(section)
    }

    /// Rewind to a specific section and size.
    ///
    /// Truncates the section to the given size and removes all sections after it.
    pub async fn rewind(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.manager.rewind(section, size).await
    }

    /// Rewind only the given section to a specific size.
    ///
    /// Unlike `rewind`, this does not affect other sections.
    pub async fn rewind_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.manager.rewind_section(section, size).await
    }

    /// Prune sections before min, in ONE atomic commit.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error>
    where
        E: commonware_runtime::Batchable,
    {
        self.manager.prune(min).await
    }

    /// [Self::prune], staged with `batch` (see
    /// [super::manager::Manager::prune_into] for the caller contract).
    pub(crate) async fn prune_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        &mut self,
        min: u64,
        batch: &mut T,
    ) -> Result<bool, Error> {
        self.manager.prune_into(min, batch).await
    }

    /// Returns the number of the oldest section.
    pub fn oldest_section(&self) -> Option<u64> {
        self.manager.oldest_section()
    }

    /// Returns the number of the newest section.
    pub fn newest_section(&self) -> Option<u64> {
        self.manager.newest_section()
    }

    /// Returns an iterator over all section numbers.
    pub fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.manager.sections()
    }

    /// Destroy all blobs and the partition, in ONE atomic commit.
    pub async fn destroy(self) -> Result<(), Error>
    where
        E: commonware_runtime::Batchable,
    {
        self.manager.destroy().await
    }

    /// [Self::destroy], staged with `batch` (see
    /// [super::manager::Manager::destroy_into] for the caller contract).
    pub(crate) async fn destroy_into<T: commonware_runtime::WriteBatch<Blob = E::Blob>>(
        self,
        batch: &mut T,
    ) -> Result<(), Error> {
        self.manager.destroy_into(batch).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner, Supervisor as _};
    use commonware_utils::NZUsize;

    fn test_cfg() -> Config<()> {
        Config {
            partition: "test-partition".into(),
            compression: None,
            codec_config: (),
            write_buffer: NZUsize!(1024),
        }
    }

    #[test_traced]
    fn test_glob_append_and_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut glob: Glob<_, i32> = Glob::init(context.child("storage"), test_cfg())
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
            let mut glob: Glob<_, i32> = Glob::init(context.child("storage"), test_cfg())
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
                partition: "test-partition".into(),
                compression: Some(3), // zstd level 3
                codec_config: (),
                write_buffer: NZUsize!(1024),
            };
            let mut glob: Glob<_, [u8; 100]> = Glob::init(context.child("storage"), cfg)
                .await
                .expect("Failed to init glob");

            // Append a value
            let value: [u8; 100] = [0u8; 100]; // Compressible data
            let (offset, size) = glob.append(1, &value).await.expect("Failed to append");

            // Size should be smaller due to compression
            assert!(size < 100);

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
            let mut glob: Glob<_, i32> = Glob::init(context.child("storage"), test_cfg())
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
            assert!(glob.manager.blobs.contains_key(&3));
            assert!(glob.manager.blobs.contains_key(&4));
            assert!(glob.manager.blobs.contains_key(&5));

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_rewind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut glob: Glob<_, i32> = Glob::init(context.child("storage"), test_cfg())
                .await
                .expect("Failed to init glob");

            // Append multiple values and track sizes
            let values: Vec<i32> = vec![1, 2, 3, 4, 5];
            let mut locations = Vec::new();

            for value in &values {
                let (offset, size) = glob.append(1, value).await.expect("Failed to append");
                locations.push((offset, size));
            }
            glob.sync(1).await.expect("Failed to sync");

            // Rewind to after the third value
            let (third_offset, third_size) = locations[2];
            let rewind_size = third_offset + u64::from(third_size);
            glob.rewind_section(1, rewind_size)
                .await
                .expect("Failed to rewind");

            // First three values should still be readable
            for (i, (offset, size)) in locations.iter().take(3).enumerate() {
                let retrieved = glob.get(1, *offset, *size).await.expect("Failed to get");
                assert_eq!(retrieved, values[i]);
            }

            // Fourth and fifth values should fail (reading past end of blob)
            let (fourth_offset, fourth_size) = locations[3];
            let result = glob.get(1, fourth_offset, fourth_size).await;
            assert!(result.is_err());

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg();

            // Create and populate glob
            let mut glob: Glob<_, i32> = Glob::init(context.child("first"), cfg.clone())
                .await
                .expect("Failed to init glob");

            let value: i32 = 42;
            let (offset, size) = glob.append(1, &value).await.expect("Failed to append");
            glob.sync(1).await.expect("Failed to sync");
            drop(glob);

            // Reopen and verify
            let glob: Glob<_, i32> = Glob::init(context.child("second"), cfg)
                .await
                .expect("Failed to reinit glob");

            let retrieved = glob.get(1, offset, size).await.expect("Failed to get");
            assert_eq!(retrieved, value);

            glob.destroy().await.expect("Failed to destroy");
        });
    }

    #[test_traced]
    fn test_glob_get_wrong_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut glob: Glob<_, i32> = Glob::init(context.child("storage"), test_cfg())
                .await
                .expect("Failed to init glob");

            let (offset, correct_size) = glob.append(1, &42).await.expect("Failed to append");
            glob.sync(1).await.expect("Failed to sync");

            // A size that does not match the stored entry fails to decode
            assert!(matches!(glob.get(1, offset, 0).await, Err(Error::Codec(_))));
            assert!(matches!(
                glob.get(1, offset, correct_size - 1).await,
                Err(Error::Codec(_))
            ));

            glob.destroy().await.expect("Failed to destroy");
        });
    }
}
