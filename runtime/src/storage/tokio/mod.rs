use super::Header;
use crate::{BufferPool, Error};
use commonware_formatting::{from_hex, hex};
use commonware_utils::sync::AsyncRwLock;
use std::{
    io::ErrorKind,
    ops::RangeInclusive,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::Mutex,
};

mod blob;

#[cfg(test)]
pub(crate) use blob::pause_write;

/// Syncs a directory to ensure directory entry changes are durable.
/// On Unix, directory metadata (file creation/deletion) must be explicitly
/// fsynced.
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

#[cfg(unix)]
async fn remove_migration_stage(path: &Path) -> Result<bool, Error> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::Io(error.into())),
    }
}

/// Configuration for a [`Storage`].
///
/// `storage_directory` must be owned by exactly one independently constructed [`Storage`] lineage
/// for its full lifetime. Clones belong to that lineage. Another process, storage instance, path
/// alias, or direct filesystem mutation must not access the directory concurrently.
/// Partition names and hex-encoded blob names each occupy one filesystem path component and must
/// fit the filesystem's component-length limit.
#[derive(Clone)]
pub struct Config {
    /// Directory exclusively owned by the resulting storage lineage.
    pub storage_directory: PathBuf,
    /// Maximum buffered bytes for each blob.
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
    atomic_resources: crate::atomic::AtomicResources,
    cfg: Config,
    pool: BufferPool,
}

/// Reads a blob's leading bytes and resolves its header (see [super::header::resolve]).
async fn resolve_header(
    file: &mut fs::File,
    raw_len: u64,
    versions: &RangeInclusive<u16>,
    partition: &str,
    name: &[u8],
) -> Result<Option<(u64, u16, u64)>, Error> {
    let mut raw = vec![0u8; Header::resolve_len(raw_len)];
    file.read_exact(&mut raw)
        .await
        .map_err(|_| Error::ReadFailed)?;
    super::header::resolve(&raw, raw_len, versions, partition, name)
}

impl Storage {
    /// Create storage with exclusive authority over `cfg.storage_directory`.
    ///
    /// Cloning the returned value preserves the same authority. Independently constructing another
    /// storage value for this directory, including through a path alias or another process, is not
    /// supported while this lineage remains live. Before replacing an old lineage, callers must
    /// establish quiescence through that lineage; dropping its last caller-held clone is not a
    /// barrier for unobserved admitted atomic work.
    pub fn new(cfg: Config, pool: BufferPool) -> Self {
        Self {
            atomic_resources: crate::atomic::AtomicResources {
                driver: crate::atomic::Driver::background(),
                exclusion: Arc::new(AsyncRwLock::new(())),
                namespace: Arc::new(Mutex::new(())),
                payload_budget: Arc::new(crate::atomic::PayloadBudget::default()),
            },
            cfg,
            pool,
        }
    }
}

impl crate::Storage for Storage {
    type Blob = blob::Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        super::validate_partition_name(partition)?;

        // Acquire the filesystem lock. The guard is owned so the creation path can move it
        // into a task that outlives a dropped open future.
        let guard = self.atomic_resources.namespace.clone().lock_owned().await;

        // Construct the full path
        let path = self.cfg.storage_directory.join(partition).join(hex(name));
        let parent = match path.parent() {
            Some(parent) => parent,
            None => return Err(Error::PartitionCreationFailed(partition.into())),
        };

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

        let raw_len = file.metadata().await.map_err(|_| Error::ReadFailed)?.len();

        // Set the maximum buffer size
        file.set_max_buf_size(self.cfg.maximum_buffer_size);

        // Handle header: existing blobs have their header read; new blobs and blobs left torn
        // by an interrupted creation get a fresh header written.
        let existing = resolve_header(&mut file, raw_len, &versions, partition, name).await?;
        let (file, guard, (logical_size, blob_version, data_offset)) = match existing {
            Some(resolved) => (file, guard, resolved),
            None => {
                // Run creation to completion on a task that owns the filesystem lock:
                // dropping the open future must not abandon the sequence half-done (a
                // straggling truncate could clobber a successor's blob) or leave a later
                // open trusting a header whose syncs never ran. The task hands the lock
                // back so the open holds it until the blob is returned, like the reopen
                // path.
                let parent = parent.to_path_buf();
                let storage_directory = self.cfg.storage_directory.clone();
                let err_partition = partition.to_string();
                let err_name = hex(name);
                let creation = tokio::task::spawn(async move {
                    // Sync the directories before writing the header so a parseable
                    // header always implies durable directory entries (an open that
                    // parses a header never re-runs these). The storage directory is
                    // synced unconditionally: the partition directory existing in the
                    // namespace does not imply its entry is durable.
                    sync_dir(&parent).await?;
                    sync_dir(&storage_directory).await?;

                    // Truncate to zero before writing, per the [Header::create] contract.
                    let (region, blob_version) = Header::create(&versions);
                    let data_offset = region.len() as u64;
                    file.set_len(0).await.map_err(|e| {
                        Error::BlobResizeFailed(err_partition.clone(), err_name.clone(), e.into())
                    })?;
                    file.rewind().await.map_err(|_| Error::WriteFailed)?;
                    file.write_all(&region)
                        .await
                        .map_err(|_| Error::WriteFailed)?;
                    file.sync_all()
                        .await
                        .map_err(|e| Error::BlobSyncFailed(err_partition, err_name, e.into()))?;

                    Ok::<_, Error>((file, guard, (0, blob_version, data_offset)))
                });
                match creation.await {
                    Ok(result) => result?,
                    Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
                    Err(_) => return Err(Error::Closed),
                }
            }
        };

        // Convert to a blocking std::fs::File
        let file = file.into_std().await;

        // Construct the blob while still holding the filesystem lock.
        let blob = Self::Blob::new(partition.into(), name, file, self.pool.clone(), data_offset);
        drop(guard);
        Ok((blob, logical_size, blob_version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;

        // Acquire the filesystem lock
        let _guard = self.atomic_resources.namespace.lock().await;

        // Remove all related files
        let path = self.cfg.storage_directory.join(partition);
        if let Some(name) = name {
            let blob_path = path.join(hex(name));
            match fs::remove_file(blob_path).await {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    return Err(Error::BlobMissing(partition.into(), hex(name)));
                }
                Err(error) => return Err(Error::Io(error.into())),
            }

            // Sync the partition directory to ensure the removal is durable.
            sync_dir(&path).await?;
        } else {
            fs::remove_dir_all(&path)
                .await
                .map_err(|_| Error::PartitionMissing(partition.into()))?;

            // Sync the storage directory to ensure the removal is durable.
            sync_dir(&self.cfg.storage_directory).await?;
        }
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        super::validate_partition_name(partition)?;

        // Acquire the filesystem lock
        let _guard = self.atomic_resources.namespace.lock().await;

        // Scan the partition directory
        let path = self.cfg.storage_directory.join(partition);
        let mut entries = fs::read_dir(&path)
            .await
            .map_err(|_| Error::PartitionMissing(partition.into()))?;
        let mut blobs = Vec::new();
        #[cfg(unix)]
        let mut removed_stage = false;
        while let Some(entry) = entries.next_entry().await.map_err(|_| Error::ReadFailed)? {
            let file_type = entry.file_type().await.map_err(|_| Error::ReadFailed)?;
            if !file_type.is_file() {
                return Err(Error::PartitionCorrupt(partition.into()));
            }
            let file_name = entry.file_name();
            #[cfg(unix)]
            if super::migration::is_stage_file_name(&file_name) {
                // An interrupted migration can leave one full-size non-authoritative stage.
                // Scanning is a namespace recovery point, so reclaim it instead of leaking the
                // abandoned copy or exposing its reserved name.
                removed_stage |= remove_migration_stage(&entry.path()).await?;
                continue;
            }
            if let Some(name) = file_name.to_str() {
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
        #[cfg(unix)]
        if removed_stage {
            sync_dir(&path).await?;
        }
        Ok(blobs)
    }
}

impl crate::atomic::Backend for Storage {
    type Worker = Self;

    fn atomic_worker(&self) -> Self {
        self.clone()
    }

    fn atomic_resources(&self) -> crate::atomic::AtomicResources {
        self.atomic_resources.clone()
    }

    async fn migrate_atomic_backing(
        &self,
        blob: Self::Blob,
        incarnation: [u8; 16],
    ) -> Result<(), Error> {
        #[cfg(not(unix))]
        {
            let _ = (blob, incarnation);
            return Err(std::io::Error::new(
                ErrorKind::Unsupported,
                "atomic migration requires Unix inode identity",
            )
            .into());
        }

        #[cfg(unix)]
        {
            let partition = blob.partition().to_string();
            let name = blob.name().to_vec();
            let source = blob.file();
            let root = self.cfg.storage_directory.clone();
            let migration_partition = partition.clone();
            let migration_name = name.clone();
            let migration = tokio::task::spawn_blocking(move || {
                super::migration::migrate_live(
                    &root,
                    &migration_partition,
                    &migration_name,
                    &source,
                    incarnation,
                )
            });
            migration
                .await
                .expect("an admitted atomic migration task is not externally abortable")
        }
    }

    async fn open_atomic_existing(
        &self,
        partition: &str,
        name: &[u8],
    ) -> Result<Option<(Self::Blob, u64)>, Error> {
        super::validate_partition_name(partition)?;
        let guard = self.atomic_resources.namespace.clone().lock_owned().await;
        let path = self.cfg.storage_directory.join(partition).join(hex(name));
        let mut file = match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .await
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(Error::BlobOpenFailed(
                    partition.into(),
                    hex(name),
                    error.into(),
                ));
            }
        };

        let raw_len = file.metadata().await.map_err(|_| Error::ReadFailed)?.len();
        file.set_max_buf_size(self.cfg.maximum_buffer_size);
        let versions = crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION;
        let Some((logical_len, _, data_offset)) =
            resolve_header(&mut file, raw_len, &versions, partition, name).await?
        else {
            return Ok(None);
        };
        super::header::require_atomic_layout(data_offset, partition, name)?;
        let file = file.into_std().await;
        let opened = Some((
            blob::Blob::new(partition.into(), name, file, self.pool.clone(), data_offset),
            logical_len,
        ));
        drop(guard);
        Ok(opened)
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, *};
    use crate::{
        AtomicBlob as _, AtomicStorage as _, Blob, BufferPoolConfig, Storage as _, WriteOptions,
        storage::{Layout, tests::run_storage_tests},
        telemetry::metrics::Registry,
    };
    use commonware_utils::sys_rng;
    use rand::RngExt as _;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;
    use std::{
        env,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_ATOMIC_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    fn random_suffix() -> u64 {
        let mut rng = sys_rng();
        rng.random()
    }

    fn atomic_test_directory(label: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "{label}_{}_{}",
            std::process::id(),
            NEXT_ATOMIC_TEST_DIR.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[tokio::test]
    async fn test_storage() {
        let mut rng = sys_rng();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_{}", rng.random::<u64>()));
        let config = Config::new(storage_directory, 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());
        run_storage_tests(storage).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_migration_stage_cleanup_is_classified() {
        let root = atomic_test_directory("storage_tokio_atomic_stage_cleanup");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let missing = root.join("missing");
        assert!(!remove_migration_stage(&missing).await.unwrap());

        let file = root.join("file");
        std::fs::write(&file, b"stage").unwrap();
        assert!(remove_migration_stage(&file).await.unwrap());
        assert!(!file.exists());

        let directory = root.join("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(remove_migration_stage(&directory).await.is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn test_remove_propagates_non_missing_file_errors() {
        let storage_directory = atomic_test_directory("storage_tokio_remove_error");
        let _ = std::fs::remove_dir_all(&storage_directory);
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let blob_path = storage_directory.join("partition").join(hex(b"directory"));
        std::fs::create_dir_all(&blob_path).unwrap();

        let error = storage
            .remove("partition", Some(b"directory"))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Io(_)));
        assert!(blob_path.is_dir());

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_atomic_backend_existing_and_direct_open() {
        let storage_directory = atomic_test_directory("storage_tokio_atomic");
        let _ = std::fs::remove_dir_all(&storage_directory);
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );

        let missing = crate::atomic::Backend::open_atomic_existing(&storage, "partition", b"blob")
            .await
            .unwrap();
        assert!(missing.is_none());
        assert!(!storage_directory.exists());

        let (blob, len) = Box::pin(storage.open_atomic("partition", b"blob"))
            .await
            .unwrap();
        assert_eq!(len, 0);
        drop(blob);
        let (blob, len) = Box::pin(storage.open_atomic("partition", b"blob"))
            .await
            .unwrap();
        assert_eq!(len, 0);
        drop(blob);
        let (_, backing_len) =
            crate::atomic::Backend::open_atomic_existing(&storage, "partition", b"blob")
                .await
                .unwrap()
                .unwrap();
        assert!(backing_len >= crate::atomic::IDENTITY_PAGE_LEN);
        let (direct, direct_len) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(direct_len, backing_len);
        drop(direct);

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_atomic_rejects_v0_ordinary_lookalikes_without_mutation() {
        let storage_directory = atomic_test_directory("storage_tokio_atomic_v0_lookalike");
        let _ = std::fs::remove_dir_all(&storage_directory);
        let mut payload = crate::atomic::migration_prefix([0x11; 16], 0, 0).to_vec();
        payload.extend_from_slice(b"ordinary tail");
        let original =
            crate::storage::header::tests::v0_blob_bytes(crate::DEFAULT_BLOB_VERSION, &payload);
        for (partition, name) in [("v0_atomic_open", b"open"), ("v0_atomic_scan", b"scan")] {
            let partition_path = storage_directory.join(partition);
            std::fs::create_dir_all(&partition_path).unwrap();
            std::fs::write(partition_path.join(hex(name)), &original).unwrap();
        }
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );

        let rejected_open = storage.open_atomic("v0_atomic_open", b"open").await;
        let rejected_scan = storage.scan_atomic("v0_atomic_scan").await;
        assert!(
            std::fs::read(storage_directory.join("v0_atomic_open").join(hex(b"open"))).unwrap()
                == original,
            "atomic open mutated a legacy ordinary blob"
        );
        assert!(
            std::fs::read(storage_directory.join("v0_atomic_scan").join(hex(b"scan"))).unwrap()
                == original,
            "atomic scan mutated a legacy ordinary blob"
        );
        assert!(matches!(
            rejected_open,
            Err(crate::Error::BlobCorrupt(_, _, reason)) if reason == "expected V1 header layout"
        ));
        assert!(matches!(
            rejected_scan,
            Err(crate::Error::BlobCorrupt(_, _, reason)) if reason == "expected V1 header layout"
        ));

        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_backend_normalizes_container_and_retries_without_replacing_again() {
        const VERSION: u16 = 7;
        let storage_directory = atomic_test_directory("storage_tokio_atomic_migration");
        let _ = std::fs::remove_dir_all(&storage_directory);
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let payload = (0u8..=255).cycle().take(160_003).collect::<Vec<_>>();
        let (blob, _, version) = storage
            .open_versioned("partition", b"blob", VERSION..=VERSION)
            .await
            .unwrap();
        assert_eq!(version, VERSION);
        blob.write_at(0, payload.clone(), WriteOptions::default())
            .await
            .unwrap();
        let old = blob.clone();
        let live_path = storage_directory.join("partition").join(hex(b"blob"));
        let ordinary_inode = std::fs::metadata(&live_path).unwrap().ino();
        let incarnation = [0x3C; 16];
        let prefix = crate::atomic::migration_prefix(
            incarnation,
            payload.len() as u64,
            commonware_cryptography::Crc32::checksum(&payload),
        );

        {
            let _namespace = storage
                .atomic_resources
                .namespace
                .clone()
                .lock_owned()
                .await;
            crate::atomic::Backend::migrate_atomic_backing(&storage, blob, incarnation)
                .await
                .unwrap();
        }

        let migrated = std::fs::read(&live_path).unwrap();
        let (logical_len, migrated_version, data_offset) = Header::parse(
            &migrated[..Layout::V1.data_offset() as usize],
            migrated.len() as u64,
            &(crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION),
        )
        .unwrap();
        assert_eq!(migrated_version, crate::DEFAULT_BLOB_VERSION);
        assert_eq!(data_offset, Layout::V1.data_offset());
        assert_eq!(logical_len as usize, prefix.len() + payload.len());
        assert_eq!(
            &migrated[data_offset as usize..data_offset as usize + prefix.len()],
            &prefix
        );
        assert_eq!(&migrated[data_offset as usize + prefix.len()..], &payload);
        assert_ne!(ordinary_inode, std::fs::metadata(&live_path).unwrap().ino());
        let old_read = old.read_at(0, payload.len()).await.unwrap().coalesce();
        assert_eq!(old_read.as_ref(), payload.as_slice());

        let (retry, retry_len, retry_version) = storage
            .open_versioned(
                "partition",
                b"blob",
                crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION,
            )
            .await
            .unwrap();
        assert_eq!(retry_len as usize, prefix.len() + payload.len());
        assert_eq!(retry_version, crate::DEFAULT_BLOB_VERSION);
        let migrated_inode = std::fs::metadata(&live_path).unwrap().ino();
        {
            let _namespace = storage
                .atomic_resources
                .namespace
                .clone()
                .lock_owned()
                .await;
            crate::atomic::Backend::migrate_atomic_backing(&storage, retry, [0xA5; 16])
                .await
                .unwrap();
        }
        assert_eq!(migrated_inode, std::fs::metadata(&live_path).unwrap().ino());
        assert_eq!(std::fs::read(&live_path).unwrap(), migrated);

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_storage_migration_preserves_public_value() {
        const VERSION: u16 = 7;
        let storage_directory = atomic_test_directory("storage_tokio_public_atomic_migration");
        let _ = std::fs::remove_dir_all(&storage_directory);
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let payload = (0u8..=255).cycle().take(160_003).collect::<Vec<_>>();
        let (ordinary, _, version) = storage
            .open_versioned("partition", b"blob", VERSION..=VERSION)
            .await
            .unwrap();
        assert_eq!(version, VERSION);
        ordinary
            .write_at(0, payload.clone(), WriteOptions::default())
            .await
            .unwrap();
        let prior = ordinary.clone();

        storage.migrate_atomic(ordinary).await.unwrap();
        let (atomic, len) = storage.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(len, payload.len() as u64);
        assert_eq!(atomic.tag().await.unwrap(), [0; crate::ATOMIC_BLOB_TAG_LEN]);
        let migrated = atomic.read_at(0, payload.len()).await.unwrap().coalesce();
        assert_eq!(migrated.as_ref(), payload.as_slice());
        let snapshot = atomic.integrity_snapshot().await.unwrap();
        assert_eq!(snapshot.scheme, crate::IntegrityScheme::Unbound);
        let (unit, tail) = snapshot.tail.unwrap();
        assert_eq!(
            unit,
            crate::IntegrityUnit {
                offset: 0,
                len: payload.len() as u64,
            }
        );
        assert_eq!(tail.coalesce().as_ref(), payload.as_slice());
        let old = prior.read_at(0, payload.len()).await.unwrap().coalesce();
        assert_eq!(old.as_ref(), payload.as_slice());

        let token = atomic.integrity_snapshot().await.unwrap().token;
        let append = atomic
            .append_integrity(token, b"!", crate::IntegrityBoundary::Complete, None)
            .await
            .unwrap();
        assert_eq!(append.offset, payload.len() as u64);
        atomic.sync().await.unwrap();
        drop(atomic);

        let (atomic, len) = storage.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(len, payload.len() as u64 + 1 + 4);
        let mut completed = payload.clone();
        completed.push(b'!');
        assert_eq!(
            atomic
                .read_integrity(crate::IntegrityUnit {
                    offset: 0,
                    len: completed.len() as u64,
                })
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            completed.as_slice()
        );

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_scan_discards_atomic_migration_stage() {
        let storage_directory = atomic_test_directory("storage_tokio_atomic_migration_scan");
        let _ = std::fs::remove_dir_all(&storage_directory);
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.sync().await.unwrap();
        let partition_path = storage_directory.join("partition");
        let stage =
            crate::storage::migration::stage_path(&partition_path.join(hex(b"blob"))).unwrap();
        std::fs::write(&stage, b"abandoned migration stage").unwrap();

        assert_eq!(
            storage.scan("partition").await.unwrap(),
            vec![b"blob".to_vec()]
        );
        assert!(!stage.exists());

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_atomic_exact_open_leaves_container_recovery_to_ordinary_open() {
        let storage_directory = atomic_test_directory("storage_tokio_atomic_container_recovery");
        let _ = std::fs::remove_dir_all(&storage_directory);
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let path = partition_path.join(hex(b"blob"));
        let interrupted =
            Header::create(&(crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION)).0
                [..Header::PRELUDE_SIZE]
                .to_vec();
        std::fs::write(&path, &interrupted).unwrap();
        std::fs::File::open(&path).unwrap().sync_all().unwrap();
        std::fs::File::open(&partition_path)
            .unwrap()
            .sync_all()
            .unwrap();

        assert!(
            crate::atomic::Backend::open_atomic_existing(&storage, "partition", b"blob")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(std::fs::read(&path).unwrap(), interrupted);

        let (_, len) = storage.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(len, 0);

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    /// Dropping the `start_sync` receiver must not break the blob: the handle stays
    /// usable and a later sync still persists data.
    #[tokio::test]
    async fn test_start_sync_dropped_receiver() {
        let mut rng = sys_rng();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_start_sync_{}", rng.random::<u64>()));
        let config = Config::new(storage_directory, 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());

        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();
        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();

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
        let mut rng = sys_rng();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_header_{}", rng.random::<u64>()));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());

        // Test 1: New blob (V1 by default) returns logical size 0 and correct app version
        let (blob, size) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "new blob should have logical size 0");

        // Verify raw file holds one header page
        let data_offset = Layout::V1.data_offset();
        let file_path = storage_directory.join("partition").join(hex(b"test"));
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            data_offset,
            "raw file should have a full header page"
        );

        // Test 2: Logical offset handling - write at offset 0 stores at the data offset
        let data = b"hello world";
        blob.write_at(0, data, WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        // Verify raw file size
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.len(), data_offset + data.len() as u64);

        // Verify raw file layout
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V1.magic());
        // Header version (bytes 4-5) and App version (bytes 6-7)
        assert_eq!(
            &raw_content[4..6],
            &Layout::V1.runtime_version().to_be_bytes()
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
        blob.write_at(0, b"test data", WriteOptions::default())
            .await
            .unwrap();
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
            Layout::V1.data_offset(),
            "corrupted blob should be reset to header-only"
        );

        // Cleanup
        drop(blob3);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Verify the end-to-end storage-page alignment invariant: paged data written to a V1 blob
    /// with a 4096-byte physical page size occupies exactly one aligned 4096-byte disk page
    /// per physical page (header page included), so page reads never straddle a page boundary.
    #[tokio::test]
    async fn test_v1_paged_alignment() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_aligned_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());

        // A logical page size whose physical page is exactly one 4096-byte storage page.
        const PHYSICAL_PAGE_SIZE: u64 = 4096;
        let logical = crate::buffer::paged::page_size(PHYSICAL_PAGE_SIZE as u32);
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
            Layout::V1.data_offset() + pages as u64 * PHYSICAL_PAGE_SIZE
        );

        // Every physical page sits exactly within one aligned 4096-byte disk page, with a valid
        // CRC record in its final 12 bytes.
        for page in 0..pages {
            let start = Layout::V1.data_offset() as usize + page * PHYSICAL_PAGE_SIZE as usize;
            let physical = &raw[start..start + PHYSICAL_PAGE_SIZE as usize];
            assert!(
                crate::buffer::paged::validate_page_for_tests(physical),
                "page {page} failed CRC validation at aligned boundary"
            );
        }

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_torn_creation_recovers() {
        let storage_directory =
            env::temp_dir().join(format!("test_torn_creation_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        // Create a durable V1 blob to obtain the canonical header region bytes.
        let (blob, _) = storage.open("partition", b"torn").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);
        let path = storage_directory.join("partition").join(hex(b"torn"));
        let region = std::fs::read(&path).unwrap();

        // Simulate torn creations (the full state enumeration lives in the
        // Layout::interrupted_creation unit tables): a file truncated mid-CRC and the same
        // prefix at a persisted full length.
        let mut torn_content = vec![0u8; region.len()];
        torn_content[..10].copy_from_slice(&region[..10]);
        let states = [region[..10].to_vec(), torn_content];
        for state in states {
            std::fs::write(&path, &state).unwrap();
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, b"data".to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            drop(blob);

            // The healed blob round-trips through a reopen with its data intact.
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 4);
            let read = blob.read_at(0, 4).await.unwrap();
            assert_eq!(read.coalesce(), b"data");
            drop(blob);
        }

        // Foreign bytes are corruption, not a torn creation: nonzero padding behind a
        // torn (unparseable) prefix proves the file was never a canonical prefix of a
        // header region.
        let mut corrupt = vec![0u8; region.len()];
        corrupt[..10].copy_from_slice(&region[..10]);
        corrupt[100] = 0xFF;
        std::fs::write(&path, &corrupt).unwrap();
        let result = storage.open("partition", b"torn").await;
        assert!(matches!(result, Err(crate::Error::BlobCorrupt(_, _, _))));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Dropping an open future at any await point must leave the blob openable: creation
    /// runs to completion on a task that owns the filesystem lock, so a retry serializes
    /// behind it and never observes (or clobbers) a half-created blob.
    #[tokio::test]
    async fn test_open_dropped_mid_creation() {
        use futures::FutureExt;
        use std::{
            future::Future,
            pin::Pin,
            task::{Context, Poll},
        };

        /// Polls the wrapped future normally, but drops it after a fixed number of polls.
        struct DropAfter<F: Future + Unpin> {
            inner: Option<F>,
            remaining: usize,
        }

        impl<F: Future + Unpin> Future for DropAfter<F> {
            type Output = Option<F::Output>;

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                if self.remaining == 0 {
                    self.inner = None;
                    return Poll::Ready(None);
                }
                self.remaining -= 1;
                match self.inner.as_mut().unwrap().poll_unpin(cx) {
                    Poll::Ready(output) => Poll::Ready(Some(output)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }

        let storage_directory =
            env::temp_dir().join(format!("test_dropped_open_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        for depth in 0..64 {
            let name = format!("blob{depth}");
            let name = name.as_bytes();
            let dropped = DropAfter {
                inner: Some(Box::pin(storage.open("partition", name))),
                remaining: depth,
            }
            .await;
            let completed = dropped.is_some();
            drop(dropped);

            // Retry, write data, and confirm it survives reopen.
            let (blob, size) = storage.open("partition", name).await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, b"data".to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            drop(blob);
            let (blob, size) = storage.open("partition", name).await.unwrap();
            assert_eq!(size, 4);
            let read = blob.read_at(0, 4).await.unwrap();
            assert_eq!(read.coalesce(), b"data");
            drop(blob);

            // Once the first open completes within the poll budget, deeper drops add nothing.
            if completed {
                let _ = std::fs::remove_dir_all(&storage_directory);
                return;
            }
        }
        panic!("open never completed within the poll budget");
    }

    #[tokio::test]
    async fn test_blob_v1_rejects_nonzero_header_padding() {
        let storage_directory =
            env::temp_dir().join(format!("test_v1_header_padding_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        let partition_dir = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_dir).unwrap();
        let path = partition_dir.join(hex(b"dirty_padding"));
        let mut raw = crate::storage::header::tests::v1_blob_bytes(0, b"payload");
        raw[Header::PARSE_LEN] = 0xFF;
        std::fs::write(&path, raw).unwrap();

        let result = storage.open("partition", b"dirty_padding").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("header padding"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_v0_legacy_read() {
        let storage_directory =
            env::temp_dir().join(format!("test_v0_legacy_read_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        // Fabricate a legacy V0 blob on disk (creation is always V1): an 8-byte header
        // followed immediately by the payload.
        let payload = b"hello world";
        let partition_dir = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_dir).unwrap();
        let file_path = partition_dir.join(hex(b"v0"));
        std::fs::write(
            &file_path,
            crate::storage::header::tests::v0_blob_bytes(0, payload),
        )
        .unwrap();

        // The blob opens with its data intact and remains readable and writable in place.
        let (blob, size) = storage.open("partition", b"v0").await.unwrap();
        assert_eq!(size, payload.len() as u64);
        assert_eq!(
            blob.read_at(0, payload.len()).await.unwrap().coalesce(),
            payload
        );
        blob.write_at(size, b"!".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        // On disk the payload still sits immediately after the 8-byte V0 header.
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(raw_content.len(), Header::PRELUDE_SIZE + payload.len() + 1);
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V0.magic());
        assert_eq!(&raw_content[Header::PRELUDE_SIZE..], b"hello world!");

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_magic_mismatch() {
        let storage_directory =
            env::temp_dir().join(format!("test_magic_mismatch_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        // Create the partition directory and a file whose magic bytes are foreign (not a
        // prefix of any canonical header, so not a torn creation)
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();
        let bad_magic_path = partition_path.join(hex(b"bad_magic"));
        std::fs::write(&bad_magic_path, b"XXXXXXXX").unwrap();

        // Opening should fail with corrupt error
        let result = storage.open("partition", b"bad_magic").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("invalid magic"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Any file shorter than a header prelude must reset to a valid, empty blob on open
    /// rather than fail as corrupt.
    #[tokio::test]
    async fn test_blob_partial_header_reset() {
        let storage_directory =
            env::temp_dir().join(format!("test_partial_header_reset_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();

        for prefix_len in 0..Header::PRELUDE_SIZE {
            let name = format!("short_{prefix_len}");
            let path = partition_path.join(hex(name.as_bytes()));
            // Seed a file shorter than a full header.
            std::fs::write(&path, vec![0u8; prefix_len]).unwrap();

            let (blob, size) = storage
                .open("partition", name.as_bytes())
                .await
                .expect("interrupted create should recover, not fail");
            assert_eq!(size, 0, "recovered blob should be empty");
            drop(blob);

            // The recovered blob is a valid header-only file and reopens cleanly.
            let raw = std::fs::read(&path).unwrap();
            assert_eq!(
                raw.len(),
                Layout::V1.data_offset() as usize,
                "recovered blob should be header-only"
            );
            assert_eq!(&raw[..Header::MAGIC_LENGTH], &Layout::V1.magic());
            storage
                .open("partition", name.as_bytes())
                .await
                .expect("reopen after recovery should succeed");
        }

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
                random_suffix()
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
