use super::{Header, Layout, hold::Hold, resolve_header, sync_dir};
use crate::{BlobVersion, BufferPool, Error};
use commonware_formatting::{from_hex, hex};
#[cfg(target_os = "macos")]
use std::collections::HashSet;
use std::{
    fs,
    io::{ErrorKind, Seek as _, SeekFrom, Write as _},
    ops::RangeInclusive,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

mod blob;

#[derive(Clone)]
pub struct Config {
    pub storage_directory: PathBuf,
    pub blob_layouts: RangeInclusive<Layout>,
}

impl Config {
    pub const fn new(storage_directory: PathBuf, blob_layouts: RangeInclusive<Layout>) -> Self {
        Self {
            storage_directory,
            blob_layouts,
        }
    }
}

#[derive(Clone)]
pub struct Storage {
    lock: Arc<Mutex<Partitions>>,
    cfg: Config,
    pool: BufferPool,
    hold: Arc<Hold>,
}

/// Partition directory durability tracked by this storage instance.
#[derive(Default)]
struct Partitions {
    /// Partitions whose inherited directory changes are durable. Creation and removal maintain
    /// this state under the same lock. Removal retires the entry before unlinking, and a blob
    /// removal restores it once the partition directory is synced.
    #[cfg(target_os = "macos")]
    synced: HashSet<PathBuf>,
    #[cfg(all(test, target_os = "macos"))]
    sync_hook: tests::SyncHook,
}

impl Partitions {
    /// Makes directory entry changes durable, with test hooks to pause or fail
    /// before the filesystem sync.
    fn sync_dir(&mut self, path: &Path) -> Result<(), Error> {
        #[cfg(all(test, target_os = "macos"))]
        self.sync_hook.run()?;
        sync_dir(path)
    }

    /// Record a partition after its required directory syncs have succeeded.
    fn mark_synced(&mut self, _path: impl Into<PathBuf>) {
        #[cfg(target_os = "macos")]
        self.synced.insert(_path.into());
    }

    /// Retire a partition's durability record before changing its directory entries.
    #[allow(clippy::missing_const_for_fn)]
    fn invalidate(&mut self, _path: &Path) {
        #[cfg(target_os = "macos")]
        self.synced.remove(_path);
    }

    /// Make a partition's inherited directory entries durable on first access.
    #[allow(clippy::missing_const_for_fn)]
    fn sync_once(&mut self, _path: &Path) -> Result<(), Error> {
        #[cfg(target_os = "macos")]
        {
            if self.synced.contains(_path) {
                return Ok(());
            }

            self.sync_dir(_path)?;
            self.mark_synced(_path);
        }
        Ok(())
    }
}

impl Storage {
    /// Create a storage instance rooted at `cfg.storage_directory`, creating the
    /// directory if missing and holding it until every operation of this
    /// instance has finished. Blocks while a previous instance still holds it.
    ///
    /// # Panics
    ///
    /// Panics if the directory cannot be created or its hold cannot be acquired.
    pub fn new(cfg: Config, pool: BufferPool) -> Self {
        let hold = Hold::acquire(&cfg.storage_directory).unwrap_or_else(|e| {
            panic!(
                "failed to acquire storage directory hold ({}): {e}",
                cfg.storage_directory.display()
            )
        });
        Self {
            lock: Arc::new(Mutex::new(Partitions::default())),
            cfg,
            pool,
            hold,
        }
    }

    /// Run `f` to completion on the blocking pool while owning the filesystem
    /// lock and the directory hold, so dropping the returned future neither
    /// abandons `f` mid-sequence nor lets a successor storage instance
    /// initialize before `f` has finished. A closure dropped unstarted at
    /// runtime shutdown yields [Error::Closed].
    async fn dispatch<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Partitions) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, Error> {
        let guard = self.lock.clone().lock_owned().await;
        let hold = self.hold.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _hold = hold;
            let mut guard = guard;
            f(&mut guard)
        });
        match task.await {
            Ok(result) => result,
            Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
            Err(_) => Err(Error::Closed),
        }
    }
}

impl crate::Storage for Storage {
    type Blob = blob::Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<BlobVersion>,
    ) -> Result<(Self::Blob, u64, BlobVersion), Error> {
        super::validate_partition_name(partition)?;

        // Construct the full path
        let path = self.cfg.storage_directory.join(partition).join(hex(name));
        let storage_directory = self.cfg.storage_directory.clone();
        let partition = partition.to_string();
        let name = name.to_vec();
        let blob_layouts = self.cfg.blob_layouts.clone();
        let pool = self.pool.clone();
        let hold = self.hold.clone();

        // Run the open to completion: it mutates the partition directory and the
        // blob (create, truncate, header write, syncs), and dropping this future
        // must not abandon that sequence half-done (a straggling truncate could
        // clobber a successor's blob) or leave a later open trusting a header
        // whose syncs never ran.
        self.dispatch(move |partitions| {
            let parent = match path.parent() {
                Some(parent) => parent,
                None => return Err(Error::PartitionCreationFailed(partition)),
            };

            // Create the partition directory, if it does not exist
            fs::create_dir_all(parent)
                .map_err(|_| Error::PartitionCreationFailed(partition.clone()))?;

            // Open the file, creating it if it doesn't exist
            let mut file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .map_err(|e| Error::BlobOpenFailed(partition.clone(), hex(&name), e.into()))?;
            let raw_len = file.metadata().map_err(|_| Error::ReadFailed)?.len();

            // Handle the header. Existing blobs have their header read. New blobs and blobs
            // left torn by an interrupted creation get a fresh header written.
            let existing = resolve_header(
                &mut file,
                raw_len,
                &blob_layouts,
                &versions,
                &partition,
                &name,
            )?;
            let (logical_size, blob_version, data_offset) = match existing {
                Some(resolved) => {
                    partitions.sync_once(parent)?;
                    resolved
                }
                None => {
                    // Make the blob name and its partition durable before writing a parseable
                    // header. A visible partition directory does not establish its durability.
                    partitions.sync_dir(parent)?;
                    partitions.sync_dir(&storage_directory)?;
                    partitions.mark_synced(parent);

                    // Truncate to zero before writing, per the [Header::create] contract.
                    let (region, blob_version) = Header::create(&blob_layouts, &versions);
                    let data_offset = region.len() as u64;
                    file.set_len(0).map_err(|e| {
                        Error::BlobResizeFailed(partition.clone(), hex(&name), e.into())
                    })?;
                    file.seek(SeekFrom::Start(0))
                        .map_err(|_| Error::WriteFailed)?;
                    file.write_all(&region).map_err(|_| Error::WriteFailed)?;
                    file.sync_all().map_err(|e| {
                        Error::BlobSyncFailed(partition.clone(), hex(&name), e.into())
                    })?;
                    (0, blob_version, data_offset)
                }
            };

            // Construct the blob while still holding the filesystem lock.
            let blob = Self::Blob::new(partition, &name, file, pool, data_offset, hold);
            Ok((blob, logical_size, blob_version))
        })
        .await
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;

        let path = self.cfg.storage_directory.join(partition);
        let storage_directory = self.cfg.storage_directory.clone();
        let partition = partition.to_string();
        let name = name.map(<[u8]>::to_vec);

        // Run the removal to completion: dropping this future must not abandon
        // the sequence between an unlink and the directory sync that makes it
        // durable.
        self.dispatch(move |partitions| {
            // Invalidate before unlinking so a failed removal cannot leave the
            // partition marked durable.
            partitions.invalidate(&path);

            // Remove all related files
            let sync_path = if let Some(name) = &name {
                let blob_path = path.join(hex(name));
                fs::remove_file(blob_path).map_err(|_| Error::BlobMissing(partition, hex(name)))?;

                path
            } else {
                // Distinguish missing partitions from other filesystem failures.
                fs::remove_dir_all(&path).map_err(|error| match error.kind() {
                    ErrorKind::NotFound => Error::PartitionMissing(partition),
                    _ => Error::Io(error.into()),
                })?;

                storage_directory
            };

            // Make the removal durable before restoring the surviving partition's
            // cache entry. Removed partitions stay uncached.
            partitions.sync_dir(&sync_path)?;
            if name.is_some() {
                partitions.mark_synced(sync_path);
            }
            Ok(())
        })
        .await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        super::validate_partition_name(partition)?;

        let path = self.cfg.storage_directory.join(partition);
        let partition = partition.to_string();
        self.dispatch(move |partitions| {
            // Distinguish missing partitions from other filesystem failures.
            let entries = fs::read_dir(&path).map_err(|error| match error.kind() {
                ErrorKind::NotFound => Error::PartitionMissing(partition.clone()),
                _ => Error::ReadFailed,
            })?;
            partitions.sync_once(&path)?;
            let mut blobs = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|_| Error::ReadFailed)?;
                let file_type = entry.file_type().map_err(|_| Error::ReadFailed)?;
                if !file_type.is_file() {
                    return Err(Error::PartitionCorrupt(partition));
                }
                if let Some(name) = entry.file_name().to_str() {
                    // Reject anything that isn't canonical lowercase hex (no `0x`
                    // prefix, no whitespace) since `from_hex` is lenient and
                    // storage only ever writes the canonical form via `hex()`.
                    let decoded =
                        from_hex(name).ok_or_else(|| Error::PartitionCorrupt(partition.clone()))?;
                    if hex(&decoded) != name {
                        return Err(Error::PartitionCorrupt(partition));
                    }

                    blobs.push(decoded);
                }
            }
            Ok(blobs)
        })
        .await
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::{Header, *};
    use crate::{
        Blob, BufferPoolConfig, ReadOptions, Runner as _, Storage as _, WriteOptions,
        storage::{Layout, tests::run_storage_tests},
        telemetry::metrics::Registry,
        tokio::Runner,
    };
    use commonware_utils::sys_rng;
    use futures::FutureExt as _;
    use rand::RngExt as _;
    #[cfg(target_os = "macos")]
    use std::sync::mpsc;
    use std::{env, sync::mpsc::RecvTimeoutError};

    /// One-shot pause and failure controls applied before a directory sync.
    #[cfg(target_os = "macos")]
    #[derive(Default)]
    pub(super) struct SyncHook {
        /// Announces entry and waits for release before the filesystem sync.
        pause: Option<(tokio::sync::oneshot::Sender<()>, mpsc::Receiver<()>)>,
        /// Error returned in place of the next filesystem sync.
        fail: Option<Error>,
    }

    #[cfg(target_os = "macos")]
    impl SyncHook {
        pub(super) fn run(&mut self) -> Result<(), Error> {
            if let Some((entered, released)) = self.pause.take() {
                let _ = entered.send(());
                let _ = released.recv();
            }
            if let Some(error) = self.fail.take() {
                return Err(error);
            }
            Ok(())
        }
    }

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    fn random_suffix() -> u64 {
        let mut rng = sys_rng();
        rng.random()
    }

    #[tokio::test]
    async fn test_hold_waits_for_straggling_remove() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_hold_remove_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config.clone(), test_pool());

        // Fill the partition with enough blobs that its removal takes a while,
        // so a successor that failed to wait would observe it mid-flight.
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();
        for i in 0..5_000u64 {
            std::fs::write(partition_path.join(hex(&i.to_be_bytes())), b"x").unwrap();
        }

        // Dispatch the partition's removal and drop its future mid-flight,
        // leaving the removal to finish on the blocking pool as a straggler.
        {
            let mut remove = Box::pin(storage.remove("partition", None));
            assert!(
                (&mut remove).now_or_never().is_none(),
                "removal completed before it could straggle"
            );
        }
        drop(storage);

        // A successor cannot initialize until the straggler finishes, so the
        // partition is guaranteed gone by the time it scans.
        let storage = Storage::new(config, test_pool());
        let result = storage.scan("partition").await;
        assert!(
            matches!(result, Err(Error::PartitionMissing(_))),
            "{result:?}"
        );

        drop(storage);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_hold_retained_by_open_blob() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_hold_blob_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config.clone(), test_pool());

        // An open blob holds a clone of the directory hold, since a write or
        // resize through it can still straggle. Dropping the storage while the
        // blob lives must not release the hold.
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        drop(storage);

        let config_second = config.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let second = Storage::new(config_second, test_pool());
            tx.send(()).unwrap();
            drop(second);
        });
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Err(RecvTimeoutError::Timeout) => {}
            other => panic!("second instance did not stay blocked on the hold: {other:?}"),
        }
        drop(blob);
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("second instance did not acquire the hold after the blob dropped");
        handle.join().unwrap();

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[test]
    fn test_hold_blocks_second_instance() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_hold_block_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let first = Storage::new(config.clone(), test_pool());

        // A second instance on the same directory cannot acquire the hold
        // until the first releases it.
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let second = Storage::new(config, test_pool());
            tx.send(()).unwrap();
            drop(second);
        });
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Err(RecvTimeoutError::Timeout) => {}
            other => panic!("second instance did not stay blocked on the hold: {other:?}"),
        }
        drop(first);
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("second instance did not acquire the hold after the first released it");
        handle.join().unwrap();

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[test]
    fn test_storage() {
        Runner::default().start(|context| async move {
            let mut rng = sys_rng();
            let storage_directory =
                env::temp_dir().join(format!("storage_tokio_{}", rng.random::<u64>()));
            let config = Config::new(storage_directory, Layout::ALL);
            let storage = Storage::new(config, test_pool());
            run_storage_tests(context, storage).await;
        });
    }

    /// Dropping the `start_sync` receiver must not break the blob: the handle stays
    /// usable and a later sync still persists data.
    #[tokio::test]
    async fn test_start_sync_dropped_receiver() {
        let mut rng = sys_rng();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_start_sync_{}", rng.random::<u64>()));
        let config = Config::new(storage_directory, Layout::ALL);
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
        let read = blob
            .read_at(0, 11, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read.as_ref(), b"hello world");
    }

    #[tokio::test]
    async fn test_blob_header_handling() {
        let mut rng = sys_rng();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_header_{}", rng.random::<u64>()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
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
            &Layout::V1.layout_version().to_be_bytes()
        );
        // Data should start at the data offset
        assert_eq!(&raw_content[data_offset as usize..], data);

        // Test 3: Read at logical offset 0 returns data from the data offset
        let read_buf = blob
            .read_at(0, data.len(), ReadOptions::default())
            .await
            .unwrap();
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
        let read_buf = blob2.read_at(0, 9, ReadOptions::default()).await.unwrap();
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
        let config = Config::new(storage_directory.clone(), Layout::ALL);
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
            Config::new(storage_directory.clone(), Layout::ALL),
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
            let read = blob.read_at(0, 4, ReadOptions::default()).await.unwrap();
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
            Config::new(storage_directory.clone(), Layout::ALL),
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
            let read = blob.read_at(0, 4, ReadOptions::default()).await.unwrap();
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
            Config::new(storage_directory.clone(), Layout::ALL),
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
            Config::new(storage_directory.clone(), Layout::ALL),
            test_pool(),
        );

        // Fabricate a legacy V0 blob on disk (creation here produces V1): an 8-byte header
        // followed immediately by the payload.
        let payload = b"hello world";
        let partition_dir = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_dir).unwrap();
        let file_path = partition_dir.join(hex(b"v0"));
        std::fs::write(&file_path, crate::storage::tests::v0_blob_bytes(0, payload)).unwrap();

        // The blob opens with its data intact and remains readable and writable in place.
        let (blob, size) = storage.open("partition", b"v0").await.unwrap();
        assert_eq!(size, payload.len() as u64);
        assert_eq!(
            blob.read_at(0, payload.len(), ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
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
            Config::new(storage_directory.clone(), Layout::ALL),
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
            Config::new(storage_directory.clone(), Layout::ALL),
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
                Config::new(storage_directory.clone(), Layout::ALL),
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

    /// Scan and removal distinguish missing partitions from existing non-directory paths.
    #[tokio::test]
    async fn test_partition_failures_are_not_absence() {
        let directory = env::temp_dir().join(format!("storage_tokio_enotdir_{}", random_suffix()));
        fs::create_dir_all(&directory).unwrap();
        let partition = directory.join("partition");
        fs::write(&partition, b"not a directory").unwrap();
        let storage = Storage::new(Config::new(directory.clone(), Layout::ALL), test_pool());

        assert!(matches!(
            storage.scan("partition").await,
            Err(Error::ReadFailed)
        ));
        assert!(matches!(
            storage.scan("missing").await,
            Err(Error::PartitionMissing(_))
        ));

        assert!(matches!(
            storage.remove("partition", None).await,
            Err(Error::Io(_))
        ));
        assert!(partition.exists());
        assert!(matches!(
            storage.remove("missing", None).await,
            Err(Error::PartitionMissing(_))
        ));

        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    #[tokio::test]
    async fn test_partition_scan_waits_for_sync(#[case] cancel: bool) {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let directory =
                env::temp_dir().join(format!("storage_tokio_scan_sync_{}", random_suffix()));
            let partition = directory.join("partition");
            let other = directory.join("other");
            fs::create_dir_all(&partition).unwrap();
            fs::create_dir_all(&other).unwrap();
            let storage = Storage::new(Config::new(directory.clone(), Layout::ALL), test_pool());
            crate::storage::sync(&directory).unwrap();

            // Pause the first directory barrier while it owns the namespace lock.
            let (entered, entering) = tokio::sync::oneshot::channel();
            let (release, gate) = mpsc::channel();
            storage.lock.lock().await.sync_hook.pause = Some((entered, gate));
            {
                let mut scan = Box::pin(storage.scan("partition"));
                assert!((&mut scan).now_or_never().is_none());
                entering.await.unwrap();
                assert!((&mut scan).now_or_never().is_none());

                // A queued scan must wait even if the initiating future is dropped.
                let mut next = Box::pin(storage.scan("partition"));
                assert!((&mut next).now_or_never().is_none());
                let scan = if cancel {
                    drop(scan);
                    None
                } else {
                    Some(scan)
                };
                release.send(()).unwrap();
                if let Some(scan) = scan {
                    assert!(scan.await.unwrap().is_empty());
                }
                assert!(next.await.unwrap().is_empty());
            }
            assert!(storage.lock.lock().await.synced.contains(&partition));

            // A cached scan leaves the failure armed for the other partition's first barrier.
            storage.lock.lock().await.sync_hook.fail = Some(Error::WriteFailed);
            assert!(storage.scan("partition").await.unwrap().is_empty());
            assert!(matches!(
                storage.scan("other").await,
                Err(Error::WriteFailed)
            ));
            assert!(storage.scan("other").await.unwrap().is_empty());
            assert!(matches!(
                storage.scan("missing").await,
                Err(Error::PartitionMissing(_))
            ));
            assert_eq!(storage.lock.lock().await.synced.len(), 2);

            drop(storage);
            fs::remove_dir_all(directory).unwrap();
        })
        .await
        .unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_partition_scan_sync_failure() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_scan_fail_{}", random_suffix()));
        let partition = directory.join("partition");
        fs::create_dir_all(&partition).unwrap();
        let storage = Storage::new(Config::new(directory.clone(), Layout::ALL), test_pool());
        crate::storage::sync(&directory).unwrap();
        storage.lock.lock().await.sync_hook.fail = Some(Error::WriteFailed);

        assert!(matches!(
            storage.scan("partition").await,
            Err(Error::WriteFailed)
        ));
        assert!(!storage.lock.lock().await.synced.contains(&partition));

        assert!(storage.scan("partition").await.unwrap().is_empty());
        assert!(storage.lock.lock().await.synced.contains(&partition));

        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_partition_open_syncs_once() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_open_dir_sync_{}", random_suffix()));
        let partition = directory.join("partition");
        let config = Config::new(directory.clone(), Layout::ALL);

        // A fresh storage instance must synchronize the inherited blob's partition on first open.
        {
            let storage = Storage::new(config.clone(), test_pool());
            drop(storage.open("partition", b"blob").await.unwrap());
        }

        let storage = Storage::new(config, test_pool());
        crate::storage::sync(&directory).unwrap();
        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 0);
        assert!(storage.lock.lock().await.synced.contains(&partition));
        drop(blob);

        // A cached reopen must leave the sync failure armed.
        storage.lock.lock().await.sync_hook.fail = Some(Error::WriteFailed);
        drop(storage.open("partition", b"blob").await.unwrap());
        assert!(storage.lock.lock().await.sync_hook.fail.is_some());

        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_partition_sync_creation_and_removal() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_dir_lifecycle_{}", random_suffix()));
        let created = directory.join("created");
        let inherited = directory.join("inherited");
        let retired = directory.join("retired");
        let missing = directory.join("missing");
        let config = Config::new(directory.clone(), Layout::ALL);
        {
            let storage = Storage::new(config.clone(), test_pool());
            for partition in ["inherited", "retired"] {
                drop(storage.open(partition, b"blob").await.unwrap());
            }
        }

        let storage = Storage::new(config, test_pool());
        crate::storage::sync(&directory).unwrap();

        // Creation synchronizes the partition, so its first scan can use the cache.
        drop(storage.open("created", b"blob").await.unwrap());
        assert!(storage.lock.lock().await.synced.contains(&created));
        assert_eq!(
            storage.scan("created").await.unwrap(),
            vec![b"blob".to_vec()]
        );

        // Removing an inherited blob also synchronizes its partition before caching it.
        storage.remove("inherited", Some(b"blob")).await.unwrap();
        assert!(storage.lock.lock().await.synced.contains(&inherited));
        assert!(storage.scan("inherited").await.unwrap().is_empty());

        // Removing a partition retires its cache entry before the name is reused.
        assert_eq!(
            storage.scan("retired").await.unwrap(),
            vec![b"blob".to_vec()]
        );
        storage.remove("retired", None).await.unwrap();
        assert!(matches!(
            storage.scan("retired").await,
            Err(Error::PartitionMissing(_))
        ));
        assert!(!storage.lock.lock().await.synced.contains(&retired));
        drop(storage.open("retired", b"new").await.unwrap());
        assert!(storage.lock.lock().await.synced.contains(&retired));
        assert_eq!(
            storage.scan("retired").await.unwrap(),
            vec![b"new".to_vec()]
        );

        assert!(matches!(
            storage.remove("missing", Some(b"blob")).await,
            Err(Error::BlobMissing(_, _))
        ));
        assert!(!storage.lock.lock().await.synced.contains(&missing));
        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    /// A failed blob-removal directory sync leaves the partition uncached so the next scan
    /// completes that barrier before reporting the removal.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_blob_remove_sync_failure_retires_partition() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_remove_fail_{}", random_suffix()));
        let partition = directory.join("partition");
        let config = Config::new(directory.clone(), Layout::ALL);
        {
            let storage = Storage::new(config.clone(), test_pool());
            drop(storage.open("partition", b"blob").await.unwrap());
        }

        let storage = Storage::new(config, test_pool());
        crate::storage::sync(&directory).unwrap();
        assert_eq!(
            storage.scan("partition").await.unwrap(),
            vec![b"blob".to_vec()]
        );
        assert!(storage.lock.lock().await.synced.contains(&partition));

        // The unlink lands, then the directory sync fails.
        storage.lock.lock().await.sync_hook.fail = Some(Error::WriteFailed);
        assert!(matches!(
            storage.remove("partition", Some(b"blob")).await,
            Err(Error::WriteFailed)
        ));
        assert!(!partition.join(hex(b"blob")).exists());
        assert!(!storage.lock.lock().await.synced.contains(&partition));

        // A later scan must finish the missing barrier before caching the empty partition.
        assert!(storage.scan("partition").await.unwrap().is_empty());
        assert!(storage.lock.lock().await.synced.contains(&partition));

        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }
}
