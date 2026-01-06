use crate::{Error, Header};
use commonware_utils::{from_hex, hex};
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
            e,
        )
    })?;
    dir.sync_all().await.map_err(|e| {
        Error::BlobSyncFailed(
            path.to_string_lossy().to_string(),
            "directory".to_string(),
            e,
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
}

impl Storage {
    pub fn new(cfg: Config) -> Self {
        Self {
            lock: Arc::new(Mutex::new(())),
            cfg,
        }
    }
}

impl crate::Storage for Storage {
    #[cfg(unix)]
    type Blob = unix::Blob;
    #[cfg(not(unix))]
    type Blob = fallback::Blob;

    async fn open(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
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
            .map_err(|e| Error::BlobOpenFailed(partition.into(), hex(name), e))?;

        // Assume empty files are newly created. Existing empty files will be synced too; that's OK.
        let len = file.metadata().await.map_err(|_| Error::ReadFailed)?.len();
        let newly_created = len == 0;

        // Only sync if we created a new file
        if newly_created {
            // Sync the file to ensure it is durable
            file.sync_all()
                .await
                .map_err(|e| Error::BlobSyncFailed(partition.into(), hex(name), e))?;

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
        let (app_version, logical_size) = if len < Header::SIZE_U64 {
            // New or corrupted blob - truncate and write header with latest version
            let app_version = *versions.end();
            let header = Header::new(app_version);
            file.set_len(Header::SIZE_U64)
                .await
                .map_err(|e| Error::BlobResizeFailed(partition.into(), hex(name), e))?;
            file.write_all(&header.to_bytes())
                .await
                .map_err(|e| Error::BlobSyncFailed(partition.into(), hex(name), e))?;
            file.sync_all()
                .await
                .map_err(|e| Error::BlobSyncFailed(partition.into(), hex(name), e))?;
            (app_version, 0)
        } else {
            // Existing blob - read and validate header
            let mut header_bytes = [0u8; Header::SIZE];
            file.read_exact(&mut header_bytes)
                .await
                .map_err(|_| Error::ReadFailed)?;
            let header = Header::from_bytes(header_bytes);
            header.validate(&versions)?;

            (header.application_version, len - Header::SIZE_U64)
        };

        #[cfg(unix)]
        {
            // Convert to a blocking std::fs::File
            let file = file.into_std().await;

            // Construct the blob
            Ok((
                Self::Blob::new(partition.into(), name, file),
                logical_size,
                app_version,
            ))
        }
        #[cfg(not(unix))]
        {
            // Construct the blob
            Ok((
                Self::Blob::new(partition.into(), name, file),
                logical_size,
                app_version,
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
                let name = from_hex(name).ok_or(Error::PartitionCorrupt(partition.into()))?;
                blobs.push(name);
            }
        }
        Ok(blobs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{storage::tests::run_storage_tests, Blob, Header, Storage as _};
    use rand::{Rng as _, SeedableRng};
    use std::env;

    /// Default version range for tests
    const TEST_VERSIONS: std::ops::RangeInclusive<u16> = 0..=0;

    #[tokio::test]
    async fn test_storage() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let storage_directory = env::temp_dir().join(format!("storage_tokio_{}", rng.gen::<u64>()));
        let config = Config::new(storage_directory, 2 * 1024 * 1024);
        let storage = Storage::new(config);
        run_storage_tests(storage).await;
    }

    #[tokio::test]
    async fn test_blob_header_handling() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_header_{}", rng.gen::<u64>()));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config);

        // Test 1: New blob returns logical size 0 and correct app version
        let (blob, size, app_version) = storage
            .open("partition", b"test", TEST_VERSIONS)
            .await
            .unwrap();
        assert_eq!(size, 0, "new blob should have logical size 0");
        assert_eq!(
            app_version,
            *TEST_VERSIONS.end(),
            "new blob should have app version 0"
        );

        // Verify raw file has 8 bytes (header only)
        let file_path = storage_directory.join("partition").join(hex(b"test"));
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            Header::SIZE_U64,
            "raw file should have 8-byte header"
        );

        // Test 2: Logical offset handling - write at offset 0 stores at raw offset 8
        let data = b"hello world";
        blob.write_at(data.to_vec(), 0).await.unwrap();
        blob.sync().await.unwrap();

        // Verify raw file size
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.len(), Header::SIZE_U64 + data.len() as u64);

        // Verify raw file layout
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Header::MAGIC);
        // Header version (bytes 4-5) and App version (bytes 6-7)
        assert_eq!(
            &raw_content[Header::MAGIC_LENGTH..Header::MAGIC_LENGTH + Header::VERSION_LENGTH],
            &Header::HEADER_VERSION.to_be_bytes()
        );
        // Data should start at offset 8
        assert_eq!(&raw_content[Header::SIZE..], data);

        // Test 3: Read at logical offset 0 returns data from raw offset 8
        let read_buf = blob.read_at(vec![0u8; data.len()], 0).await.unwrap();
        assert_eq!(read_buf.as_ref(), data);

        // Test 4: Resize with logical length
        blob.resize(5).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            Header::SIZE_U64 + 5,
            "resize(5) should result in 13 raw bytes"
        );

        // resize(0) should leave only header
        blob.resize(0).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            Header::SIZE_U64,
            "resize(0) should leave only header"
        );

        // Test 5: Reopen existing blob preserves header and returns correct logical size
        blob.write_at(b"test data".to_vec(), 0).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob2, size2, app_version2) = storage
            .open("partition", b"test", TEST_VERSIONS)
            .await
            .unwrap();
        assert_eq!(size2, 9, "reopened blob should have logical size 9");
        assert_eq!(app_version2, *TEST_VERSIONS.end());
        let read_buf = blob2.read_at(vec![0u8; 9], 0).await.unwrap();
        assert_eq!(read_buf.as_ref(), b"test data");
        drop(blob2);

        // Test 6: Corrupted blob recovery (0 < raw_size < 8)
        // Manually create a corrupted file with only 4 bytes
        let corrupted_path = storage_directory.join("partition").join(hex(b"corrupted"));
        std::fs::write(&corrupted_path, vec![0u8; 4]).unwrap();

        // Opening should truncate and write fresh header
        let (blob3, size3, app_version3) = storage
            .open("partition", b"corrupted", TEST_VERSIONS)
            .await
            .unwrap();
        assert_eq!(size3, 0, "corrupted blob should return logical size 0");
        assert_eq!(app_version3, *TEST_VERSIONS.end());

        // Verify raw file now has proper 8-byte header
        let metadata = std::fs::metadata(&corrupted_path).unwrap();
        assert_eq!(
            metadata.len(),
            Header::SIZE_U64,
            "corrupted blob should be reset to header-only"
        );

        // Cleanup
        drop(blob3);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_magic_mismatch() {
        let storage_directory =
            env::temp_dir().join(format!("test_magic_mismatch_{}", rand::random::<u64>()));
        let storage = Storage::new(Config {
            storage_directory: storage_directory.clone(),
            maximum_buffer_size: 1024 * 1024,
        });

        // Create the partition directory
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();

        // Manually create a file with invalid magic bytes
        let bad_magic_path = partition_path.join(hex(b"bad_magic"));
        std::fs::write(&bad_magic_path, vec![0u8; Header::SIZE]).unwrap();

        // Opening should fail with magic mismatch error
        let result = storage.open("partition", b"bad_magic", TEST_VERSIONS).await;
        match result {
            Err(crate::Error::BlobMagicMismatch { found }) => {
                assert_eq!(found, [0u8; Header::MAGIC_LENGTH]);
            }
            Err(err) => panic!("expected BlobMagicMismatch error, got: {:?}", err),
            Ok(_) => panic!("expected error, got Ok"),
        }

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_version_mismatch() {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_version_{}", rng.gen::<u64>()));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config);

        // Create blob with version 1
        storage.open("partition", b"v1", 1..=1).await.unwrap();

        // Try to open with version range 2..=2
        let result = storage.open("partition", b"v1", 2..=2).await;
        match result {
            Err(crate::Error::BlobApplicationVersionMismatch { expected, found }) => {
                assert_eq!(expected, 2..=2);
                assert_eq!(found, 1);
            }
            Err(err) => panic!(
                "expected BlobApplicationVersionMismatch error, got: {:?}",
                err
            ),
            Ok(_) => panic!("expected error, got Ok"),
        }

        let _ = std::fs::remove_dir_all(&storage_directory);
    }
}
