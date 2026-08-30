use super::{Header, Layout};
use crate::{
    Buf, BufferPool, Handle, IoBufs, IoBufsMut, ReadOptions, WriteOptions,
    deterministic::AuditHasher,
};
use commonware_formatting::hex;
use commonware_utils::sync::{Mutex, RwLock};
use std::{collections::BTreeMap, ops::RangeInclusive, sync::Arc};

/// Resolves a blob's header from its full contents (see [super::header::resolve]).
fn resolve_header(
    content: &[u8],
    versions: &RangeInclusive<u16>,
    partition: &str,
    name: &[u8],
) -> Result<Option<(u64, u16, u64)>, crate::Error> {
    let raw = &content[..Header::resolve_len(content.len() as u64)];
    super::header::resolve(raw, content.len() as u64, versions, partition, name)
}

type BlobKey = (String, Vec<u8>);
type Partition = BTreeMap<Vec<u8>, Vec<u8>>;

/// Durable contents detached from all live storage and blob handles.
pub(crate) struct Snapshot(BTreeMap<String, Partition>);

#[derive(Default)]
struct Generations {
    next: u64,
    current: BTreeMap<BlobKey, u64>,
}

impl Generations {
    fn get_or_insert(&mut self, key: &BlobKey) -> u64 {
        if let Some(generation) = self.current.get(key) {
            return *generation;
        }
        self.rotate(key)
    }

    fn rotate(&mut self, key: &BlobKey) -> u64 {
        let generation = self.next;
        self.next = self.next.checked_add(1).expect("blob generation overflow");
        self.current.insert(key.clone(), generation);
        generation
    }

    fn remove_partition(&mut self, partition: &str) {
        self.current
            .retain(|(current_partition, _), _| current_partition != partition);
    }
}

/// In-memory storage implementation for the commonware runtime.
#[derive(Clone)]
pub struct Storage {
    partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
    generations: Arc<Mutex<Generations>>,
    pool: BufferPool,
}

impl Storage {
    pub fn new(pool: BufferPool) -> Self {
        Self::with_partitions(BTreeMap::new(), pool)
    }

    fn with_partitions(partitions: BTreeMap<String, Partition>, pool: BufferPool) -> Self {
        Self {
            partitions: Arc::new(Mutex::new(partitions)),
            generations: Arc::new(Mutex::new(Generations::default())),
            pool,
        }
    }

    /// Transfer durable contents and retire every live blob generation.
    pub(crate) fn take_snapshot(&self) -> Snapshot {
        let mut generations = self.generations.lock();
        generations.current.clear();
        let mut partitions = self.partitions.lock();
        Snapshot(std::mem::take(&mut *partitions))
    }

    /// Rebuild storage from detached durable contents.
    pub(crate) fn from_snapshot(snapshot: Snapshot, pool: BufferPool) -> Self {
        Self::with_partitions(snapshot.0, pool)
    }
}

impl Storage {
    /// Compute a SHA-256 digest of all blob contents.
    pub fn audit(&self) -> [u8; 32] {
        let partitions = self.partitions.lock();
        let mut hasher = AuditHasher::new();
        hasher.update(b"commonware-runtime-storage-audit-v1");

        for (partition_name, blobs) in partitions.iter() {
            for (blob_name, content) in blobs.iter() {
                hasher.update(b"partition");
                hasher.update(partition_name.as_bytes());
                hasher.update(b"blob");
                hasher.update(blob_name);
                hasher.update(b"content");
                hasher.update(content);
            }
        }

        hasher.finalize()
    }

    fn open_inner(
        &self,
        partition: &str,
        name: &[u8],
        layout: Layout,
        versions: RangeInclusive<u16>,
    ) -> Result<(Blob, u64, u16), crate::Error> {
        super::validate_partition_name(partition)?;

        let key = (partition.to_string(), name.to_vec());
        let mut generations = self.generations.lock();
        let mut partitions = self.partitions.lock();
        let partition_entry = partitions.entry(partition.into()).or_default();
        let content = partition_entry.entry(name.into()).or_default();

        // Handle header: existing blobs have their header read; new blobs and blobs left torn
        // by an interrupted creation get a fresh header written.
        let existing = resolve_header(content, &versions, partition, name)?;
        let (logical_size, blob_version, data_offset, generation) = match existing {
            Some((logical_size, blob_version, data_offset)) => (
                logical_size,
                blob_version,
                data_offset,
                generations.get_or_insert(&key),
            ),
            None => {
                let (region, blob_version) = Header::create(layout, &versions);
                let data_offset = region.len() as u64;
                content.clear();
                content.extend_from_slice(&region);
                (0, blob_version, data_offset, generations.rotate(&key))
            }
        };

        Ok((
            Blob::new(
                self.partitions.clone(),
                self.generations.clone(),
                key,
                content.clone(),
                self.pool.clone(),
                data_offset,
                generation,
            ),
            logical_size,
            blob_version,
        ))
    }

    /// Return a copy of a blob's durable raw contents without interpreting its container header.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn raw_blob(&self, partition: &str, name: &[u8]) -> Option<Vec<u8>> {
        self.partitions.lock().get(partition)?.get(name).cloned()
    }

    /// Install durable raw contents without validating the blob's container header.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_raw_blob(&self, partition: &str, name: &[u8], content: Vec<u8>) {
        let key = (partition.to_string(), name.to_vec());
        let mut generations = self.generations.lock();
        let mut partitions = self.partitions.lock();
        generations.current.remove(&key);
        partitions
            .entry(partition.into())
            .or_default()
            .insert(name.into(), content);
    }
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), crate::Error> {
        self.open_inner(partition, name, Layout::V1, versions)
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), crate::Error> {
        super::validate_partition_name(partition)?;

        let mut generations = self.generations.lock();
        let mut partitions = self.partitions.lock();
        match name {
            Some(name) => {
                partitions
                    .get_mut(partition)
                    .ok_or(crate::Error::PartitionMissing(partition.into()))?
                    .remove(name)
                    .ok_or(crate::Error::BlobMissing(partition.into(), hex(name)))?;
                generations
                    .current
                    .remove(&(partition.to_string(), name.to_vec()));
            }
            None => {
                partitions
                    .remove(partition)
                    .ok_or(crate::Error::PartitionMissing(partition.into()))?;
                generations.remove_partition(partition);
            }
        }
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, crate::Error> {
        super::validate_partition_name(partition)?;

        let partitions = self.partitions.lock();
        let partition = partitions
            .get(partition)
            .ok_or(crate::Error::PartitionMissing(partition.into()))?;
        let mut results = Vec::with_capacity(partition.len());
        for name in partition.keys() {
            results.push(name.clone());
        }
        results.sort(); // Ensure deterministic output
        Ok(results)
    }
}

#[derive(Clone)]
pub struct Blob {
    partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
    generations: Arc<Mutex<Generations>>,
    partition: String,
    name: Vec<u8>,
    content: Arc<RwLock<Vec<u8>>>,
    pool: BufferPool,
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
    /// Namespace generation captured when this handle was opened.
    generation: u64,
}

impl Blob {
    fn new(
        partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
        generations: Arc<Mutex<Generations>>,
        (partition, name): BlobKey,
        content: Vec<u8>,
        pool: BufferPool,
        data_offset: u64,
        generation: u64,
    ) -> Self {
        Self {
            partitions,
            generations,
            partition,
            name,
            content: Arc::new(RwLock::new(content)),
            pool,
            data_offset,
            generation,
        }
    }

    fn ensure_current(&self, generations: &Generations) -> Result<(), crate::Error> {
        let key = (self.partition.clone(), self.name.clone());
        if generations.current.get(&key) == Some(&self.generation) {
            return Ok(());
        }
        Err(crate::Error::BlobMissing(
            self.partition.clone(),
            hex(&self.name),
        ))
    }

    fn sync_inner(&self) -> Result<(), crate::Error> {
        // Create new content for partition
        let new_content = self.content.read().clone();

        // Update partition content
        let generations = self.generations.lock();
        self.ensure_current(&generations)?;
        let mut partitions = self.partitions.lock();
        let partition = partitions
            .get_mut(&self.partition)
            .ok_or(crate::Error::PartitionMissing(self.partition.clone()))?;
        let content = partition
            .get_mut(&self.name)
            .ok_or(crate::Error::BlobMissing(
                self.partition.clone(),
                hex(&self.name),
            ))?;
        *content = new_content;
        Ok(())
    }

    fn sync_range_inner(&self, offset: usize, buf: &[u8]) -> Result<(), crate::Error> {
        let end = offset
            .checked_add(buf.len())
            .ok_or(crate::Error::OffsetOverflow)?;
        let generations = self.generations.lock();
        self.ensure_current(&generations)?;
        let mut partitions = self.partitions.lock();
        let content = partitions
            .get_mut(&self.partition)
            .and_then(|partition| partition.get_mut(&self.name))
            .expect("a current blob generation has durable content");
        if end > content.len() {
            content.resize(end, 0);
        }
        content[offset..end].copy_from_slice(buf);
        Ok(())
    }

    /// Merge selected bytes into durable storage without changing this handle's live contents.
    pub(crate) fn retain_crash_write(
        &self,
        offset: u64,
        mut bufs: IoBufs,
        mut keep: impl FnMut() -> bool,
    ) -> Result<(), crate::Error> {
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(crate::Error::OffsetOverflow)?;
        let offset: usize = offset
            .try_into()
            .map_err(|_| crate::Error::OffsetOverflow)?;
        offset
            .checked_add(bufs.remaining())
            .ok_or(crate::Error::OffsetOverflow)?;

        let generations = self.generations.lock();
        if self.ensure_current(&generations).is_err() {
            return Ok(());
        }
        let mut partitions = self.partitions.lock();
        let content = partitions
            .get_mut(&self.partition)
            .and_then(|partition| partition.get_mut(&self.name))
            .expect("a current blob generation has durable content");

        let mut position = 0usize;
        while bufs.has_remaining() {
            let chunk = bufs.chunk();
            let chunk_len = chunk.len();
            let mut run_start = None;

            let mut retain_run = |run_start: usize, run_end: usize| {
                let physical_start = offset + position + run_start;
                let physical_end = offset + position + run_end;
                if physical_end > content.len() {
                    content.resize(physical_end, 0);
                }
                content[physical_start..physical_end].copy_from_slice(&chunk[run_start..run_end]);
            };

            for index in 0..chunk_len {
                if keep() {
                    if run_start.is_none() {
                        run_start = Some(index);
                    }
                } else if let Some(start) = run_start.take() {
                    retain_run(start, index);
                }
            }
            if let Some(start) = run_start {
                retain_run(start, chunk_len);
            }

            position += chunk_len;
            bufs.advance(chunk_len);
        }
        Ok(())
    }

    /// Apply a retained resize to durable storage without changing this handle's live contents.
    pub(crate) fn retain_crash_resize(&self, len: u64) -> Result<(), crate::Error> {
        let len = len
            .checked_add(self.data_offset)
            .ok_or(crate::Error::OffsetOverflow)?;
        let len: usize = len.try_into().map_err(|_| crate::Error::OffsetOverflow)?;

        let generations = self.generations.lock();
        if self.ensure_current(&generations).is_err() {
            return Ok(());
        }
        let mut partitions = self.partitions.lock();
        let content = partitions
            .get_mut(&self.partition)
            .and_then(|partition| partition.get_mut(&self.name))
            .expect("a current blob generation has durable content");
        content.resize(len, 0);
        Ok(())
    }
}

impl crate::Blob for Blob {
    async fn read_at(
        &self,
        offset: u64,
        len: usize,
        options: ReadOptions,
    ) -> Result<IoBufsMut, crate::Error> {
        self.read_at_buf(offset, len, self.pool.alloc(len), options)
            .await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
        _options: ReadOptions,
    ) -> Result<IoBufsMut, crate::Error> {
        let mut bufs = bufs.into();
        // SAFETY: `len` bytes are filled via copy_from_slice below.
        unsafe { bufs.set_len(len) };
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(crate::Error::OffsetOverflow)?;
        let offset: usize = offset
            .try_into()
            .map_err(|_| crate::Error::OffsetOverflow)?;
        let end = offset
            .checked_add(len)
            .ok_or(crate::Error::OffsetOverflow)?;
        let content = self.content.read();
        if end > content.len() {
            return Err(crate::Error::BlobInsufficientLength);
        }
        bufs.copy_from_slice(&content[offset..end]);
        Ok(bufs)
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), crate::Error> {
        let bufs = bufs.into();
        let sync = options.contains(WriteOptions::SYNC);
        if sync && !bufs.has_remaining() {
            return Ok(());
        }
        let buf = bufs.coalesce();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(crate::Error::OffsetOverflow)?;
        let offset: usize = offset
            .try_into()
            .map_err(|_| crate::Error::OffsetOverflow)?;
        let required = offset
            .checked_add(buf.len())
            .ok_or(crate::Error::OffsetOverflow)?;
        {
            let mut content = self.content.write();
            if required > content.len() {
                content.resize(required, 0);
            }
            content[offset..offset + buf.len()].copy_from_slice(buf.as_ref());
        }
        if sync {
            self.sync_range_inner(offset, buf.as_ref())
        } else {
            Ok(())
        }
    }

    async fn resize(&self, len: u64) -> Result<(), crate::Error> {
        let len = len
            .checked_add(self.data_offset)
            .ok_or(crate::Error::OffsetOverflow)?;
        let len: usize = len.try_into().map_err(|_| crate::Error::OffsetOverflow)?;
        let mut content = self.content.write();
        content.resize(len, 0);
        Ok(())
    }

    async fn sync(&self) -> Result<(), crate::Error> {
        self.sync_inner()
    }

    async fn start_sync(&self) -> Handle<()> {
        Handle::ready(self.sync().await)
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, *};
    use crate::{
        Blob, BufferPoolConfig, Storage as _,
        deterministic::BoxDynRng,
        storage::{
            Layout,
            faulty::{
                Config as FaultConfig, PartialWriteMode, Storage as FaultyStorage, WriteConfig,
            },
            tests::run_storage_tests,
        },
        telemetry::metrics::Registry,
    };
    use commonware_utils::{ScriptedRng, probability};

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    #[tokio::test]
    async fn test_memory_storage() {
        let storage = Storage::new(test_pool());
        run_storage_tests(storage).await;
    }

    #[tokio::test]
    async fn test_empty_write_semantics() {
        let storage = Storage::new(test_pool());

        let (plain, _) = storage.open("partition", b"plain").await.unwrap();
        plain
            .write_at(8, Vec::<u8>::new(), WriteOptions::default())
            .await
            .unwrap();
        plain.sync().await.unwrap();
        drop(plain);
        let (_, plain_len) = storage.open("partition", b"plain").await.unwrap();
        assert_eq!(plain_len, 8);

        let (sync, _) = storage.open("partition", b"sync").await.unwrap();
        sync.write_at(8, Vec::<u8>::new(), WriteOptions::SYNC)
            .await
            .unwrap();
        drop(sync);
        let (_, sync_len) = storage.open("partition", b"sync").await.unwrap();
        assert_eq!(sync_len, 0);
    }

    #[tokio::test]
    async fn test_set_raw_blob_retires_live_generation() {
        const PARTITION: &str = "partition";
        const NAME: &[u8] = b"blob";
        const INSTALLED: &[u8] = b"current";

        let storage = Storage::new(test_pool());
        let (stale, _) = storage.open(PARTITION, NAME).await.unwrap();
        stale
            .write_at(0, b"stale", WriteOptions::default())
            .await
            .unwrap();

        let installed = crate::storage::header::tests::v1_blob_bytes(0, INSTALLED);
        storage.set_raw_blob(PARTITION, NAME, installed.clone());

        assert!(matches!(
            stale.sync().await,
            Err(crate::Error::BlobMissing(_, _))
        ));
        assert_eq!(
            storage.raw_blob(PARTITION, NAME).as_deref(),
            Some(installed.as_slice())
        );

        let (fresh, size, version) = storage
            .open_versioned(PARTITION, NAME, 0..=0)
            .await
            .unwrap();
        assert_eq!(size, INSTALLED.len() as u64);
        assert_eq!(version, 0);
        assert_eq!(
            fresh
                .read_at(0, INSTALLED.len(), ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            INSTALLED
        );
    }

    #[tokio::test]
    async fn test_crash_write_merges_durable_bytes_only() {
        let storage = Storage::new(test_pool());
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"abcdefgh", WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        blob.write_at(0, b"ABCDEFGH", WriteOptions::default())
            .await
            .unwrap();

        let mut index = 0usize;
        blob.retain_crash_write(0, IoBufs::from(&b"12345678"[..]), || {
            let keep = index % 2 == 1;
            index += 1;
            keep
        })
        .unwrap();

        let live = blob.read_at(0, 8, ReadOptions::default()).await.unwrap();
        assert_eq!(live.coalesce(), b"ABCDEFGH");
        let (reopened, len) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(len, 8);
        let durable = reopened
            .read_at(0, 8, ReadOptions::default())
            .await
            .unwrap();
        assert_eq!(durable.coalesce(), b"a2c4e6g8");

        let (sparse, _) = storage.open("partition", b"sparse").await.unwrap();
        let mut index = 0usize;
        sparse
            .retain_crash_write(4, IoBufs::from(&b"xyz"[..]), || {
                let keep = index == 1;
                index += 1;
                keep
            })
            .unwrap();
        let (sparse, len) = storage.open("partition", b"sparse").await.unwrap();
        assert_eq!(len, 6);
        assert_eq!(
            sparse
                .read_at(0, 6, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"\0\0\0\0\0y"
        );

        let (removed, _) = storage.open("partition", b"removed").await.unwrap();
        storage.remove("partition", Some(b"removed")).await.unwrap();
        let (replacement, _) = storage.open("partition", b"removed").await.unwrap();
        replacement
            .write_at(0, b"new!", WriteOptions::SYNC)
            .await
            .unwrap();
        removed
            .retain_crash_write(0, IoBufs::from(&b"lost"[..]), || true)
            .unwrap();
        let (replacement, len) = storage.open("partition", b"removed").await.unwrap();
        assert_eq!(len, 4);
        assert_eq!(
            replacement
                .read_at(0, 4, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"new!"
        );
    }

    #[derive(Clone, Copy, Debug)]
    enum SubsetWriteCut {
        FailedWrite,
        Crash,
    }

    async fn assert_subset_write_preserves_header(layout: Layout, cut: SubsetWriteCut) {
        // Alternating case makes a retained subset distinguishable from a contiguous prefix.
        const ORIGINAL: &[u8] = b"abcdefghijklmnop";
        const REPLACEMENT: &[u8] = b"ABCDEFGHIJKLMNOP";
        const RETAINED: &[u8] = b"AbCdEfGhIjKlMnOp";
        const PARTITION: &str = "partition";
        const NAME: &[u8] = b"blob";

        // Seed a canonical image so both layouts enter the same logical blob interface.
        let inner = Storage::new(test_pool());
        let raw = match layout {
            Layout::V0 => crate::storage::header::tests::v0_blob_bytes(0, ORIGINAL),
            Layout::V1 => crate::storage::header::tests::v1_blob_bytes(0, ORIGINAL),
        };
        let data_offset = layout.data_offset() as usize;
        let expected_header = raw[..data_offset].to_vec();
        inner.set_raw_blob(PARTITION, NAME, raw);

        // Select whether the subset is retained by a failed write or by a later crash, and script
        // alternating per-byte retention decisions for an exact expected image.
        let failure_rate = match cut {
            SubsetWriteCut::FailedWrite => probability!(1.0),
            SubsetWriteCut::Crash => probability!(0.0),
        };
        let rng: BoxDynRng = Box::new(ScriptedRng::new(
            (0..REPLACEMENT.len()).map(|index| if index % 2 == 0 { 0 } else { u64::MAX }),
        ));
        let faulty = FaultyStorage::new(
            inner.clone(),
            Arc::new(Mutex::new(rng)),
            Arc::new(RwLock::new(FaultConfig::default().write(WriteConfig {
                failure_rate,
                retention_rate: probability!(0.5),
                mode: PartialWriteMode::Subset,
            }))),
        );

        // Apply the overwrite through the faulty wrapper and assert the selected write boundary.
        let (blob, size, version) = faulty.open_versioned(PARTITION, NAME, 0..=0).await.unwrap();
        assert_eq!(size, ORIGINAL.len() as u64);
        assert_eq!(version, 0);
        let result = blob.write_at(0, REPLACEMENT, WriteOptions::default()).await;
        match cut {
            SubsetWriteCut::FailedWrite => {
                assert!(matches!(result, Err(crate::Error::Io(_))));
            }
            SubsetWriteCut::Crash => result.unwrap(),
        }
        drop(blob);

        // Failed writes retain their subset immediately, while successful unsynchronized writes
        // remain volatile. Neither path may address bytes in the container header.
        let raw = inner.raw_blob(PARTITION, NAME).unwrap();
        assert_eq!(&raw[..data_offset], expected_header);
        let expected_payload = match cut {
            SubsetWriteCut::FailedWrite => RETAINED,
            SubsetWriteCut::Crash => ORIGINAL,
        };
        assert_eq!(&raw[data_offset..], expected_payload);

        // Simulating a crash applies the snapshotted retention policy to the durable payload while
        // leaving the complete container header unchanged.
        faulty.crash().unwrap();
        drop(faulty);
        let recovered = Storage::from_snapshot(inner.take_snapshot(), test_pool());
        let raw = recovered.raw_blob(PARTITION, NAME).unwrap();
        assert_eq!(&raw[..data_offset], expected_header);
        assert_eq!(&raw[data_offset..], RETAINED);

        // Reopen the crashed image through the versioned API to prove the retained subset remains
        // a valid logical blob under both layouts.
        let (blob, size, version) = recovered
            .open_versioned(PARTITION, NAME, 0..=0)
            .await
            .unwrap();
        assert_eq!(size, ORIGINAL.len() as u64);
        assert_eq!(version, 0);
        assert_eq!(
            blob.read_at(0, ORIGINAL.len(), ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            RETAINED
        );
    }

    #[tokio::test]
    async fn test_subset_write_preserves_v0_and_v1_headers() {
        for layout in [Layout::V0, Layout::V1] {
            for cut in [SubsetWriteCut::FailedWrite, SubsetWriteCut::Crash] {
                assert_subset_write_preserves_header(layout, cut).await;
            }
        }
    }

    #[tokio::test]
    async fn test_v0_writer_reopens_with_current_layout() {
        const PARTITION: &str = "legacy";
        const NAME: &[u8] = b"blob";
        const PAYLOAD: &[u8] = b"payload";
        const VERSION: u16 = 7;

        let legacy_writer = Storage::new(test_pool());
        let (blob, size, version) = legacy_writer
            .open_inner(PARTITION, NAME, Layout::V0, VERSION..=VERSION)
            .unwrap();
        assert_eq!(size, 0);
        assert_eq!(version, VERSION);
        blob.write_at(0, PAYLOAD, WriteOptions::SYNC).await.unwrap();
        drop(blob);

        let data_offset = Layout::V0.data_offset() as usize;
        let raw = legacy_writer.raw_blob(PARTITION, NAME).unwrap();
        assert_eq!(&raw[..Header::MAGIC_LENGTH], &Layout::V0.magic());
        assert_eq!(&raw[data_offset..], PAYLOAD);

        let current = Storage::from_snapshot(legacy_writer.take_snapshot(), test_pool());
        let (blob, size, version) = current
            .open_versioned(PARTITION, NAME, VERSION..=VERSION)
            .await
            .unwrap();
        assert_eq!(size, PAYLOAD.len() as u64);
        assert_eq!(version, VERSION);
        assert_eq!(
            blob.read_at(0, PAYLOAD.len(), ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            PAYLOAD
        );

        blob.write_at(PAYLOAD.len() as u64, b"!", WriteOptions::SYNC)
            .await
            .unwrap();
        drop(blob);
        let (blob, size, version) = current
            .open_versioned(PARTITION, NAME, VERSION..=VERSION)
            .await
            .unwrap();
        assert_eq!(size, (PAYLOAD.len() + 1) as u64);
        assert_eq!(version, VERSION);
        assert_eq!(
            blob.read_at(0, PAYLOAD.len() + 1, ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            b"payload!"
        );
    }

    #[tokio::test]
    async fn test_blob_header_handling() {
        let storage = Storage::new(test_pool());

        // New blob (V1 by default) returns logical size 0
        let (blob, size) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "new blob should have logical size 0");

        // Verify raw storage has one header page
        let data_offset = Layout::V1.data_offset() as usize;
        {
            let partitions = storage.partitions.lock();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"test".to_vec()).unwrap();
            assert_eq!(
                raw_content.len(),
                data_offset,
                "raw storage should have a full header page"
            );
        }

        // Write at logical offset 0 stores at the data offset
        let data = b"hello world";
        blob.write_at(0, data, WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        // Verify raw storage layout
        {
            let partitions = storage.partitions.lock();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"test".to_vec()).unwrap();
            assert_eq!(raw_content.len(), data_offset + data.len());
            assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V1.magic());
            assert_eq!(&raw_content[data_offset..], data);
        }

        // Read at logical offset 0 returns data from the data offset
        let read_buf = blob
            .read_at(0, data.len(), ReadOptions::default())
            .await
            .unwrap();
        assert_eq!(read_buf.coalesce(), data);

        // A legacy V0 blob (fabricated raw: creation is always V1) places data immediately
        // after the 8-byte header and stays fully readable and writable.
        {
            let mut partitions = storage.partitions.lock();
            let partition = partitions.get_mut("partition").unwrap();
            let raw = crate::storage::header::tests::v0_blob_bytes(0, data);
            partition.insert(b"v0".to_vec(), raw);
        }
        let (blob, size, _) = storage
            .open_versioned("partition", b"v0", 0..=0)
            .await
            .unwrap();
        assert_eq!(size, data.len() as u64);
        let read_buf = blob
            .read_at(0, data.len(), ReadOptions::default())
            .await
            .unwrap();
        assert_eq!(read_buf.coalesce(), data);
        blob.write_at(data.len() as u64, b"!", WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        {
            let partitions = storage.partitions.lock();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"v0".to_vec()).unwrap();
            assert_eq!(raw_content.len(), Header::PRELUDE_SIZE + data.len() + 1);
            assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V0.magic());
            assert_eq!(&raw_content[Header::PRELUDE_SIZE..], b"hello world!");
        }

        // Corrupted blob recovery (0 < raw_size < 8)
        {
            let mut partitions = storage.partitions.lock();
            let partition = partitions.get_mut("partition").unwrap();
            partition.insert(b"corrupted".to_vec(), vec![0u8; 2]);
        }

        // Opening should truncate and write a fresh header page
        let (_blob, size) = storage.open("partition", b"corrupted").await.unwrap();
        assert_eq!(size, 0, "corrupted blob should return logical size 0");

        // Verify raw storage now has a proper header page
        {
            let partitions = storage.partitions.lock();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"corrupted".to_vec()).unwrap();
            assert_eq!(
                raw_content.len(),
                data_offset,
                "corrupted blob should be reset to header-only"
            );
        }
    }

    #[tokio::test]
    async fn test_blob_magic_mismatch() {
        let storage = Storage::new(test_pool());

        // Manually insert a blob whose magic bytes are foreign (not a prefix of any
        // canonical header, so not a torn creation)
        {
            let mut partitions = storage.partitions.lock();
            let partition = partitions.entry("partition".into()).or_default();
            partition.insert(b"bad_magic".to_vec(), b"XXXXXXXX".to_vec());
        }

        // Opening should fail with corrupt error
        let result = storage.open("partition", b"bad_magic").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("invalid magic"))
        );
    }

    #[tokio::test]
    async fn test_audit_separates_partition_and_blob_names() {
        let storage_a = Storage::new(test_pool());
        let (blob_a, _) = storage_a.open("a", b"bc").await.unwrap();
        blob_a
            .write_at(0, b"d", WriteOptions::default())
            .await
            .unwrap();
        blob_a.sync().await.unwrap();

        let storage_b = Storage::new(test_pool());
        let (blob_b, _) = storage_b.open("ab", b"c").await.unwrap();
        blob_b
            .write_at(0, b"d", WriteOptions::default())
            .await
            .unwrap();
        blob_b.sync().await.unwrap();

        assert_ne!(storage_a.audit(), storage_b.audit());
    }

    /// Required recovery outcome for an installed V0 crash image.
    enum Expect {
        Recreated,
        Kept,
        Rejected,
    }

    /// Exhaustively verify recovery of every torn V0 creation image against the oracle: the
    /// V0 prelude is 8 bytes, so the whole crash-image space (every persisted length, every
    /// zero-hole subset) is enumerable. Recreated images must heal to the canonical V1
    /// region, kept images must open unchanged, and everything else must fail without
    /// mutation.
    #[tokio::test]
    async fn test_v0_creation_images_exhaustive() {
        for version in [0u16, 3, 0x0100, 0xFFFF] {
            let versions = version..=version;
            let storage = Storage::new(test_pool());

            let (blob, _, _) = storage
                .open_versioned("partition", b"v1", versions.clone())
                .await
                .unwrap();
            drop(blob);
            let canonical_v1 = storage.raw_blob("partition", b"v1").unwrap();
            let (blob, _, _) = storage
                .open_inner("partition", b"v0", Layout::V0, versions.clone())
                .unwrap();
            drop(blob);
            let canonical_v0 = storage.raw_blob("partition", b"v0").unwrap();

            for len in 0..=canonical_v0.len() {
                for mask in 0u16..1 << len {
                    let mut image = canonical_v0[..len].to_vec();
                    for (bit, byte) in image.iter_mut().enumerate() {
                        if mask & (1 << bit) != 0 {
                            *byte = 0;
                        }
                    }

                    // Expected outcome per the header spec: a sub-prelude file is always
                    // recreated, an intact prelude parses (the stamped version decides,
                    // and only the version bytes can differ once the first six match), and
                    // anything else heals only as a canonical V1 creation prefix, which a
                    // V0 image can satisfy just through the shared "CWI" brand.
                    let written = image
                        .iter()
                        .rposition(|&byte| byte != 0)
                        .map_or(0, |i| i + 1);
                    let expected = if image.len() < canonical_v0.len() {
                        Expect::Recreated
                    } else if image == canonical_v0 {
                        Expect::Kept
                    } else if image[..6] == canonical_v0[..6] {
                        Expect::Rejected
                    } else if written <= 3 && image[..written] == canonical_v0[..written] {
                        Expect::Recreated
                    } else {
                        Expect::Rejected
                    };

                    // Install the image, reopen, and hold recovery to the expected outcome.
                    storage.set_raw_blob("partition", b"v0", image.clone());
                    let result = storage
                        .open_versioned("partition", b"v0", versions.clone())
                        .await;
                    match expected {
                        Expect::Recreated => {
                            let (_, size, opened) =
                                result.expect("torn creation image did not recover");
                            assert_eq!(size, 0);
                            assert_eq!(opened, version);
                            assert_eq!(storage.raw_blob("partition", b"v0").unwrap(), canonical_v1);
                        }
                        Expect::Kept => {
                            let (_, size, opened) = result.expect("intact image did not open");
                            assert_eq!(size, 0);
                            assert_eq!(opened, version);
                            assert_eq!(storage.raw_blob("partition", b"v0").unwrap(), image);
                        }
                        Expect::Rejected => {
                            assert!(result.is_err(), "non-canonical image was accepted");
                            assert_eq!(storage.raw_blob("partition", b"v0").unwrap(), image);
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_blob_torn_creation_recovers() {
        let storage = Storage::new(test_pool());

        // Manually insert a torn-creation leftover: a prefix of a canonical V1 header
        // region (the full state enumeration lives in the Layout::interrupted_creation
        // unit tables)
        let (region, _) = Header::create(Layout::V1, &(0..=0));
        let states = [region[..10].to_vec()];
        for (i, state) in states.into_iter().enumerate() {
            let name = format!("torn_{i}").into_bytes();
            {
                let mut partitions = storage.partitions.lock();
                let partition = partitions.entry("partition".into()).or_default();
                partition.insert(name.clone(), state);
            }

            // Opening recreates the blob as new
            let (blob, size, _) = storage
                .open_versioned("partition", &name, 0..=0)
                .await
                .unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, b"data".to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            drop(blob);

            // The healed blob round-trips through a reopen with its data intact.
            let (blob, size, _) = storage
                .open_versioned("partition", &name, 0..=0)
                .await
                .unwrap();
            assert_eq!(size, 4);
            let read = blob.read_at(0, 4, ReadOptions::default()).await.unwrap();
            assert_eq!(read.coalesce(), b"data");
            drop(blob);
        }
    }

    #[tokio::test]
    async fn test_blob_v1_rejects_nonzero_header_padding() {
        let storage = Storage::new(test_pool());

        let mut raw = crate::storage::header::tests::v1_blob_bytes(0, b"payload");
        raw[Header::PARSE_LEN] = 0xFF;
        {
            let mut partitions = storage.partitions.lock();
            let partition = partitions.entry("partition".into()).or_default();
            partition.insert(b"dirty_padding".to_vec(), raw);
        }

        let result = storage.open("partition", b"dirty_padding").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("header padding"))
        );
    }

    #[tokio::test]
    async fn test_blob_zero_payload_with_lost_crc_stays_corrupt() {
        let storage = Storage::new(test_pool());

        // A synced V1 blob whose payload is all zeros, with the header's CRC bytes
        // rotted away: the file extends past the header region, so healing it would
        // erase the payload.
        let mut raw = crate::storage::header::tests::v1_blob_bytes(0, &[0u8; 100]);
        raw[8..12].fill(0);
        {
            let mut partitions = storage.partitions.lock();
            let partition = partitions.entry("partition".into()).or_default();
            partition.insert(b"rotted".to_vec(), raw);
        }

        let result = storage.open("partition", b"rotted").await;
        assert!(matches!(result, Err(crate::Error::BlobCorrupt(_, _, _))));
    }
}
