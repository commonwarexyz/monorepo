use super::{Header, HeaderError, ParsedHeader};
#[commonware_macros::stability(BETA)]
use crate::{BlobHeaderLayout, BlobInfo};
use crate::{BufferPool, Error};
use commonware_formatting::{from_hex, hex};
#[cfg(unix)]
use std::path::Path;
use std::{ops::RangeInclusive, path::PathBuf, sync::Arc};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

#[cfg(not(unix))]
mod fallback;
#[cfg(unix)]
mod unix;

/// Syncs a directory to ensure directory entry changes are durable.
/// On Unix, directory metadata (file creation/deletion) must be explicitly
/// fsynced.
#[cfg(unix)]
async fn sync_dir(path: &Path) -> Result<(), Error> {
    let dir = fs::File::open(path).await.map_err(|e| {
        Error::BlobOpenFailed(
            path.to_string_lossy().to_string(),
            "directory".to_string(),
            e.into(),
        )
    })?;
    dir.sync_all().await.map_err(|e| {
        Error::BlobSyncFailed(
            path.to_string_lossy().to_string(),
            "directory".to_string(),
            e.into(),
        )
    })
}

#[derive(Clone)]
pub struct Config {
    pub storage_directory: PathBuf,
    pub maximum_buffer_size: usize,
}

impl Config {
    pub const fn new(storage_directory: PathBuf, maximum_buffer_size: usize) -> Self {
        Self {
            storage_directory,
            maximum_buffer_size,
        }
    }
}

#[derive(Clone)]
pub struct Storage {
    lock: Arc<Mutex<()>>,
    cfg: Config,
    pool: BufferPool,
}

impl Storage {
    pub fn new(cfg: Config, pool: BufferPool) -> Self {
        Self {
            lock: Arc::new(Mutex::new(())),
            cfg,
            pool,
        }
    }
}

impl crate::Storage for Storage {
    #[cfg(unix)]
    type Blob = unix::Blob;
    #[cfg(not(unix))]
    type Blob = fallback::Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
        layout: BlobHeaderLayout,
    ) -> Result<(Self::Blob, BlobInfo), Error> {
        super::validate_partition_name(partition)?;

        // Acquire the filesystem lock
        let _guard = self.lock.lock().await;

        // Construct the full path
        let path = self.cfg.storage_directory.join(partition).join(hex(name));
        let parent = match path.parent() {
            Some(parent) => parent,
            None => return Err(Error::PartitionCreationFailed(partition.into())),
        };

        // Check if partition exists before creating
        #[cfg(unix)]
        let parent_existed = parent.exists();

        // Create the partition directory, if it does not exist
        fs::create_dir_all(parent)
            .await
            .map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

        // Open the file, creating it if it doesn't exist
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .await
            .map_err(|e| Error::BlobOpenFailed(partition.into(), hex(name), e.into()))?;

        // Assume empty files are newly created. Existing empty files will be synced too; that's OK.
        let len = file.metadata().await.map_err(|_| Error::ReadFailed)?.len();
        let newly_created = len == 0;

        // Only sync if we created a new file
        if newly_created {
            // Sync the file to ensure it is durable
            file.sync_all()
                .await
                .map_err(|e| Error::BlobSyncFailed(partition.into(), hex(name), e.into()))?;

            // Windows doesn't have a notion of syncing a directory entry to ensure that it's
            // durably persisted. See https://github.com/commonwarexyz/monorepo/issues/2026.
            #[cfg(unix)]
            {
                // Sync the parent directory to ensure the directory entry is durable.
                sync_dir(parent).await?;

                // Sync storage directory if parent directory did not exist
                if !parent_existed {
                    sync_dir(&self.cfg.storage_directory).await?;
                }
            }
        }

        // Set the maximum buffer size
        file.set_max_buf_size(self.cfg.maximum_buffer_size);

        // Handle header: new/corrupted blobs get a fresh header written,
        // existing blobs have their header read.
        let (info, data_offset) = if Header::missing(len) {
            // New or corrupted blob - truncate and write the header region with latest version
            // Truncate to zero before writing so a torn header write cannot splice old
            // bytes into a fully valid header with a wrong version: every partial state
            // stays shorter than the prelude and is recreated on the next open.
            let (region, blob_version, data_offset) = Header::create(&versions, layout);
            file.set_len(0)
                .await
                .map_err(|e| Error::BlobResizeFailed(partition.into(), hex(name), e.into()))?;
            file.write_all(&region)
                .await
                .map_err(|_| Error::WriteFailed)?;
            file.sync_all()
                .await
                .map_err(|e| Error::BlobSyncFailed(partition.into(), hex(name), e.into()))?;
            let info = BlobInfo {
                size: 0,
                blob_version,
                layout,
            };
            (info, data_offset)
        } else {
            // Existing blob - read and validate the header, honoring the layout it records
            let mut prelude = [0u8; Header::SIZE];
            file.read_exact(&mut prelude)
                .await
                .map_err(|_| Error::ReadFailed)?;
            let parsed = Header::parse_prelude(prelude, &versions)
                .map_err(|e| e.into_error(partition, name))?;
            match parsed {
                ParsedHeader::V0 { blob_version } => {
                    let info = BlobInfo {
                        size: len - Header::SIZE_U64,
                        blob_version,
                        layout: BlobHeaderLayout::V0,
                    };
                    (info, Header::SIZE_U64)
                }
                ParsedHeader::NeedsExtension { blob_version } => {
                    let ext_end = Header::SIZE_U64 + Header::EXTENSION_SIZE as u64;
                    if len < ext_end {
                        return Err(HeaderError::TruncatedHeader {
                            data_offset: ext_end,
                            raw_len: len,
                        }
                        .into_error(partition, name));
                    }
                    let mut extension = [0u8; Header::EXTENSION_SIZE];
                    file.read_exact(&mut extension)
                        .await
                        .map_err(|_| Error::ReadFailed)?;
                    let data_offset = Header::parse_extension(prelude, extension, len)
                        .map_err(|e| e.into_error(partition, name))?;
                    let info = BlobInfo {
                        size: len - data_offset,
                        blob_version,
                        layout: BlobHeaderLayout::V1,
                    };
                    (info, data_offset)
                }
            }
        };

        #[cfg(unix)]
        {
            // Convert to a blocking std::fs::File
            let file = file.into_std().await;

            // Construct the blob
            Ok((
                Self::Blob::new(partition.into(), name, file, self.pool.clone(), data_offset),
                info,
            ))
        }
        #[cfg(not(unix))]
        {
            // Construct the blob
            Ok((
                Self::Blob::new(partition.into(), name, file, self.pool.clone(), data_offset),
                info,
            ))
        }
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;

        // Acquire the filesystem lock
        let _guard = self.lock.lock().await;

        // Remove all related files
        let path = self.cfg.storage_directory.join(partition);
        if let Some(name) = name {
            let blob_path = path.join(hex(name));
            fs::remove_file(blob_path)
                .await
                .map_err(|_| Error::BlobMissing(partition.into(), hex(name)))?;

            // Sync the partition directory to ensure the removal is durable.
            // Windows doesn't have a notion of syncing a directory entry to ensure that it's
            // durably persisted. See https://github.com/commonwarexyz/monorepo/issues/2026.
            #[cfg(unix)]
            sync_dir(&path).await?;
        } else {
            fs::remove_dir_all(&path)
                .await
                .map_err(|_| Error::PartitionMissing(partition.into()))?;

            // Sync the storage directory to ensure the removal is durable.
            // Windows doesn't have a notion of syncing a directory entry to ensure that it's
            // durably persisted. See https://github.com/commonwarexyz/monorepo/issues/2026.
            #[cfg(unix)]
            sync_dir(&self.cfg.storage_directory).await?;
        }
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        super::validate_partition_name(partition)?;

        // Acquire the filesystem lock
        let _guard = self.lock.lock().await;

        // Scan the partition directory
        let path = self.cfg.storage_directory.join(partition);
        let mut entries = fs::read_dir(path)
            .await
            .map_err(|_| Error::PartitionMissing(partition.into()))?;
        let mut blobs = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(|_| Error::ReadFailed)? {
            let file_type = entry.file_type().await.map_err(|_| Error::ReadFailed)?;
            if !file_type.is_file() {
                return Err(Error::PartitionCorrupt(partition.into()));
            }
            if let Some(name) = entry.file_name().to_str() {
                // Reject anything that isn't canonical lowercase hex (no `0x`
                // prefix, no whitespace) since `from_hex` is lenient and
                // storage only ever writes the canonical form via `hex()`.
                let decoded = from_hex(name).ok_or(Error::PartitionCorrupt(partition.into()))?;
                if hex(&decoded) != name {
                    return Err(Error::PartitionCorrupt(partition.into()));
                }

                blobs.push(decoded);
            }
        }
        Ok(blobs)
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, *};
    use crate::{
        storage::tests::run_storage_tests, telemetry::metrics::Registry, Blob, BufferPoolConfig,
        Storage as _,
    };
    use rand::{Rng as _, SeedableRng};
    use std::env;

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    #[tokio::test]
    async fn test_storage() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let storage_directory = env::temp_dir().join(format!("storage_tokio_{}", rng.gen::<u64>()));
        let config = Config::new(storage_directory, 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());
        run_storage_tests(storage).await;
    }

    /// Dropping the `start_sync` receiver must not break the blob: the handle stays
    /// usable and a later sync still persists data.
    #[tokio::test]
    async fn test_start_sync_dropped_receiver() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_start_sync_{}", rng.gen::<u64>()));
        let config = Config::new(storage_directory, 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());

        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();
        blob.write_at(0, b"hello world").await.unwrap();

        // Drop the completion receiver immediately.
        drop(blob.start_sync().await);

        // The blob remains usable, and a subsequent sync persists the data.
        blob.start_sync().await.await.unwrap();
        drop(blob);

        let (blob, len) = storage.open("partition", b"test_blob").await.unwrap();
        assert_eq!(len, 11);
        let read = blob.read_at(0, 11).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"hello world");
    }

    #[tokio::test]
    async fn test_blob_header_handling() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_header_{}", rng.gen::<u64>()));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());

        // Test 1: New blob (V1 by default) returns logical size 0 and correct app version
        let (blob, size) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "new blob should have logical size 0");

        // Verify raw file holds one header page
        let data_offset = Header::V1_DATA_OFFSET;
        let file_path = storage_directory.join("partition").join(hex(b"test"));
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            data_offset,
            "raw file should have a full header page"
        );

        // Test 2: Logical offset handling - write at offset 0 stores at the data offset
        let data = b"hello world";
        blob.write_at(0, data).await.unwrap();
        blob.sync().await.unwrap();

        // Verify raw file size
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.len(), data_offset + data.len() as u64);

        // Verify raw file layout
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Header::MAGIC);
        // Header version (bytes 4-5) and App version (bytes 6-7)
        assert_eq!(
            &raw_content[Header::MAGIC_LENGTH..Header::MAGIC_LENGTH + Header::VERSION_LENGTH],
            &BlobHeaderLayout::V1.runtime_version().to_be_bytes()
        );
        // Data should start at the data offset
        assert_eq!(&raw_content[data_offset as usize..], data);

        // Test 3: Read at logical offset 0 returns data from the data offset
        let read_buf = blob.read_at(0, data.len()).await.unwrap();
        assert_eq!(read_buf.coalesce(), data);

        // Test 4: Resize with logical length
        blob.resize(5).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            data_offset + 5,
            "resize(5) should leave 5 raw bytes past the header page"
        );

        // resize(0) should leave only the header page
        blob.resize(0).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            data_offset,
            "resize(0) should leave only the header page"
        );

        // Test 5: Reopen existing blob preserves header and returns correct logical size
        blob.write_at(0, b"test data").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob2, size2) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size2, 9, "reopened blob should have logical size 9");
        let read_buf = blob2.read_at(0, 9).await.unwrap();
        assert_eq!(read_buf.coalesce(), b"test data");
        drop(blob2);

        // Test 6: Corrupted blob recovery (0 < raw_size < 8)
        // Manually create a corrupted file with only 4 bytes
        let corrupted_path = storage_directory.join("partition").join(hex(b"corrupted"));
        std::fs::write(&corrupted_path, vec![0u8; 4]).unwrap();

        // Opening should truncate and write fresh header
        let (blob3, size3) = storage.open("partition", b"corrupted").await.unwrap();
        assert_eq!(size3, 0, "corrupted blob should return logical size 0");

        // Verify raw file now has a proper header page
        let metadata = std::fs::metadata(&corrupted_path).unwrap();
        assert_eq!(
            metadata.len(),
            Header::V1_DATA_OFFSET,
            "corrupted blob should be reset to header-only"
        );

        // Cleanup
        drop(blob3);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Verify the end-to-end storage-page alignment invariant: paged data written to a V1 blob
    /// with a power-of-two physical page size occupies exactly one aligned 4096-byte disk page
    /// per physical page (header page included), so page reads never straddle a page boundary.
    #[tokio::test]
    async fn test_v1_paged_alignment() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_aligned_{}", rng.gen::<u64>()));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());

        // A logical page size whose physical page is exactly one 4096-byte storage page.
        const PHYSICAL_PAGE_SIZE: u64 = 4096;
        let logical = crate::buffer::paged::page_size(PHYSICAL_PAGE_SIZE as u16);
        let cache = crate::buffer::paged::CacheRef::new(
            test_pool(),
            logical,
            std::num::NonZeroUsize::new(16).unwrap(),
        );

        // Write several pages of patterned data through the paged writer (V1 blob via open()).
        let (blob, size) = storage.open("partition", b"aligned").await.unwrap();
        let mut writer = crate::buffer::paged::Writer::new(blob, size, 1024, cache)
            .await
            .unwrap();
        let item: Vec<u8> = (0..1000u32).flat_map(|i| i.to_be_bytes()).collect();
        for _ in 0..12 {
            writer.append(&item).await.unwrap();
        }
        let logical_size = writer.size();
        writer.sync().await.unwrap();

        // The raw file is a whole number of 4096-byte pages: one header page plus one page per
        // physical page of data (the partial tail page is zero-padded to a full physical page).
        let file_path = storage_directory.join("partition").join(hex(b"aligned"));
        let raw = std::fs::read(&file_path).unwrap();
        let pages = (logical_size as usize).div_ceil(logical.get() as usize);
        assert_eq!(raw.len() as u64 % PHYSICAL_PAGE_SIZE, 0);
        assert_eq!(
            raw.len() as u64,
            Header::V1_DATA_OFFSET + pages as u64 * PHYSICAL_PAGE_SIZE
        );

        // Every physical page sits exactly within one aligned 4096-byte disk page, with a valid
        // CRC record in its final 12 bytes.
        for page in 0..pages {
            let start = Header::V1_DATA_OFFSET as usize + page * PHYSICAL_PAGE_SIZE as usize;
            let physical = &raw[start..start + PHYSICAL_PAGE_SIZE as usize];
            assert!(
                crate::buffer::paged::validate_page_for_tests(physical),
                "page {page} failed CRC validation at aligned boundary"
            );
        }

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_truncated_extension_is_corrupt() {
        let storage_directory = env::temp_dir().join(format!(
            "test_truncated_extension_{}",
            rand::random::<u64>()
        ));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        // Create a V1 blob, then truncate its file inside the header extension (a valid prelude
        // with raw length 8..16), as a crash during creation could leave it.
        let (blob, _) = storage.open("partition", b"truncated").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);
        let path = storage_directory.join("partition").join(hex(b"truncated"));
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(Header::SIZE_U64 + 4).unwrap();
        drop(file);

        // Opening must report corruption, not a transient read failure.
        let result = storage.open("partition", b"truncated").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("truncated"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_nondefault_data_offset() {
        let storage_directory = env::temp_dir().join(format!(
            "test_nondefault_data_offset_{}",
            rand::random::<u64>()
        ));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        // Write a blob whose header records a larger data offset than this build writes, as a
        // future writer would produce it.
        let data_offset = 4 * Header::V1_DATA_OFFSET;
        let payload = b"from the future";
        let partition_dir = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_dir).unwrap();
        std::fs::write(
            partition_dir.join(hex(b"future")),
            crate::storage::tests::v1_blob_bytes(data_offset, 0, payload),
        )
        .unwrap();

        // The blob opens with the recorded offset: the logical size covers only the payload,
        // and reads and writes translate against it.
        let (blob, size) = storage.open("partition", b"future").await.unwrap();
        assert_eq!(size, payload.len() as u64);
        assert_eq!(
            blob.read_at(0, payload.len()).await.unwrap().coalesce(),
            payload
        );
        blob.write_at(size, b"!".to_vec()).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob, size) = storage.open("partition", b"future").await.unwrap();
        assert_eq!(size, payload.len() as u64 + 1);
        assert_eq!(
            blob.read_at(0, size as usize).await.unwrap().coalesce(),
            b"from the future!"
        );
        drop(blob);

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_magic_mismatch() {
        let storage_directory =
            env::temp_dir().join(format!("test_magic_mismatch_{}", rand::random::<u64>()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        // Create the partition directory and a file with invalid magic bytes
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();
        let bad_magic_path = partition_path.join(hex(b"bad_magic"));
        std::fs::write(&bad_magic_path, vec![0u8; Header::SIZE]).unwrap();

        // Opening should fail with corrupt error
        let result = storage.open("partition", b"bad_magic").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("invalid magic"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_scan_rejects_non_canonical_hex_file_names() {
        // `commonware_formatting::from_hex` is lenient (strips `0x`/`0X` prefixes
        // and ASCII whitespace), but storage only ever writes filenames in the
        // canonical lowercase hex form produced by `hex()`. Verify that scans
        // reject any filename that decodes successfully but doesn't round-trip
        // to its canonical form.
        for bad_name in ["0x626c6f62", "0X626C6F62", " 626c6f62", "626C6F62"] {
            let storage_directory = env::temp_dir().join(format!(
                "test_scan_non_canonical_{}_{}",
                bad_name.replace([' ', '0', 'x', 'X'], "_"),
                rand::random::<u64>()
            ));
            let storage = Storage::new(
                Config {
                    storage_directory: storage_directory.clone(),
                    maximum_buffer_size: 1024 * 1024,
                },
                test_pool(),
            );

            let partition_path = storage_directory.join("partition");
            std::fs::create_dir_all(&partition_path).unwrap();
            std::fs::write(partition_path.join(bad_name), []).unwrap();

            let err = match storage.scan("partition").await {
                Ok(_) => panic!("scan should have failed for filename {bad_name:?}"),
                Err(err) => err,
            };
            assert_eq!(
                err.to_string(),
                "partition corrupt: partition",
                "filename {bad_name:?} should be rejected as corrupt",
            );

            let _ = std::fs::remove_dir_all(&storage_directory);
        }
    }
}
