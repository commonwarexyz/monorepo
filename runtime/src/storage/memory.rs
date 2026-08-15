use super::{Header, Layout};
use crate::{Buf, BufferPool, Handle, IoBufs, IoBufsMut, WriteOptions, deterministic::AuditHasher};
use commonware_formatting::hex;
use commonware_utils::sync::{AsyncMutex, AsyncRwLock, Mutex, RwLock};
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
    atomic_resources: crate::atomic::AtomicResources,
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
            atomic_resources: crate::atomic::AtomicResources {
                driver: crate::atomic::Driver::inline(),
                exclusion: Arc::new(AsyncRwLock::new(())),
                namespace: Arc::new(AsyncMutex::new(())),
                payload_budget: Arc::new(crate::atomic::PayloadBudget::default()),
            },
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
    fn owns(&self, blob: &Blob) -> bool {
        Arc::ptr_eq(&self.partitions, &blob.partitions)
            && Arc::ptr_eq(&self.generations, &blob.generations)
    }

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
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), crate::Error> {
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
                let (region, blob_version) = Header::create(&versions);
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
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, crate::Error> {
        self.read_at_buf(offset, len, self.pool.alloc(len)).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
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
        let content = self.content.read();
        let content_len = content.len();
        if offset + len > content_len {
            return Err(crate::Error::BlobInsufficientLength);
        }
        bufs.copy_from_slice(&content[offset..offset + len]);
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
        incarnation: [u8; crate::atomic::INCARNATION_LEN],
    ) -> Result<(), crate::Error> {
        if !self.owns(&blob) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "migration source belongs to another storage instance",
            )
            .into());
        }
        crate::atomic::validate_atomic_location(&blob.partition, &blob.name)?;

        {
            let generations = self.generations.lock();
            blob.ensure_current(&generations)?;
        }
        blob.sync_inner()?;

        let key = (blob.partition.clone(), blob.name.clone());
        let mut generations = self.generations.lock();
        blob.ensure_current(&generations)?;
        let mut partitions = self.partitions.lock();
        let content = partitions
            .get_mut(&blob.partition)
            .and_then(|partition| partition.get_mut(&blob.name))
            .ok_or_else(|| crate::Error::BlobMissing(blob.partition.clone(), hex(&blob.name)))?;
        let raw = &content[..Header::resolve_len(content.len() as u64)];
        let (logical_len, blob_version, data_offset) =
            Header::parse(raw, content.len() as u64, &(u16::MIN..=u16::MAX))
                .map_err(|error| error.into_error(&blob.partition, &blob.name))?;
        let payload_start =
            usize::try_from(data_offset).map_err(|_| crate::Error::OffsetOverflow)?;
        if blob_version == crate::DEFAULT_BLOB_VERSION
            && data_offset == Layout::V1.data_offset()
            && logical_len >= crate::atomic::IDENTITY_PAGE_LEN
        {
            let identity_end = payload_start
                .checked_add(crate::atomic::IDENTITY_PAGE_LEN as usize)
                .ok_or(crate::Error::OffsetOverflow)?;
            let identity = content
                .get(payload_start..identity_end)
                .ok_or(crate::Error::BlobInsufficientLength)?
                .try_into()
                .expect("the identity page slice has a fixed width");
            if crate::atomic::decode_identity(identity).is_some() {
                return Ok(());
            }
        }

        let payload_len = usize::try_from(logical_len).map_err(|_| crate::Error::OffsetOverflow)?;
        let payload_end = payload_start
            .checked_add(payload_len)
            .ok_or(crate::Error::OffsetOverflow)?;
        let payload = content
            .get(payload_start..payload_end)
            .ok_or(crate::Error::BlobInsufficientLength)?
            .to_vec();
        let (mut replacement, replacement_version) =
            Header::create(&(crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION));
        debug_assert_eq!(replacement_version, crate::DEFAULT_BLOB_VERSION);
        let integrity_checksum = commonware_cryptography::Crc32::checksum(&payload);
        let prefix = crate::atomic::migration_prefix(incarnation, logical_len, integrity_checksum);
        debug_assert_eq!(prefix.len(), crate::atomic::DATA_OFFSET as usize);
        replacement.extend_from_slice(&prefix);
        replacement.extend_from_slice(&payload);
        *content = replacement;
        generations.rotate(&key);
        Ok(())
    }

    async fn open_atomic_existing(
        &self,
        partition: &str,
        name: &[u8],
    ) -> Result<Option<(Self::Blob, u64)>, crate::Error> {
        super::validate_partition_name(partition)?;
        let key = (partition.to_string(), name.to_vec());
        let mut generations = self.generations.lock();
        let mut partitions = self.partitions.lock();
        let Some(blobs) = partitions.get_mut(partition) else {
            return Ok(None);
        };
        let Some(content) = blobs.get(name) else {
            return Ok(None);
        };
        let versions = crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION;
        let Some((logical_size, _, data_offset)) =
            resolve_header(content, &versions, partition, name)?
        else {
            return Ok(None);
        };
        super::header::require_atomic_layout(data_offset, partition, name)?;
        let generation = generations.get_or_insert(&key);
        Ok(Some((
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
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, *};
    use crate::{
        AtomicBlob as _, AtomicStorage as _, Blob, BufferPoolConfig, Storage as _,
        storage::{Layout, tests::run_storage_tests},
        telemetry::metrics::Registry,
    };

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
    async fn test_atomic_backing_matches_the_ordinary_default_container() {
        let storage = Storage::new(test_pool());
        let (ordinary, _) = storage.open("headers", b"ordinary").await.unwrap();
        let (atomic, _) = storage.open_atomic("headers", b"atomic").await.unwrap();
        drop(ordinary);
        drop(atomic);

        let partitions = storage.partitions.lock();
        let partition = partitions.get("headers").unwrap();
        let ordinary = partition.get(b"ordinary".as_slice()).unwrap();
        let atomic = partition.get(b"atomic".as_slice()).unwrap();
        let (header, version) =
            Header::create(&(crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION));
        assert_eq!(version, crate::DEFAULT_BLOB_VERSION);
        let header_len = header.len();
        assert_eq!(&atomic[..header_len], &ordinary[..header_len]);
        assert_eq!(&atomic[..header_len], header.as_slice());
    }

    #[tokio::test]
    async fn test_atomic_exact_open_preserves_incomplete_container_and_generation() {
        let storage = Storage::new(test_pool());
        let partition = "atomic_container_recovery";
        let name = b"blob".to_vec();
        let key = (partition.to_string(), name.clone());
        let interrupted =
            Header::create(&(crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION)).0
                [..Header::PRELUDE_SIZE]
                .to_vec();
        storage
            .partitions
            .lock()
            .entry(partition.to_string())
            .or_default()
            .insert(name.clone(), interrupted.clone());
        let generation = storage.generations.lock().get_or_insert(&key);

        assert!(
            crate::atomic::Backend::open_atomic_existing(&storage, partition, &name)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(storage.partitions.lock()[partition][&name], interrupted);
        assert_eq!(
            storage.generations.lock().current.get(&key),
            Some(&generation)
        );

        let (_, len) = storage.open_atomic(partition, &name).await.unwrap();
        assert_eq!(len, 0);
        assert_ne!(
            storage.generations.lock().current.get(&key),
            Some(&generation)
        );
    }

    #[tokio::test]
    async fn test_atomic_rejects_v0_ordinary_lookalikes_without_mutation() {
        let storage = Storage::new(test_pool());
        let mut payload = crate::atomic::migration_prefix([0x11; 16], 0, 0).to_vec();
        payload.extend_from_slice(b"ordinary tail");
        let original =
            crate::storage::header::tests::v0_blob_bytes(crate::DEFAULT_BLOB_VERSION, &payload);

        for (partition, name) in [("v0_atomic_open", b"open"), ("v0_atomic_scan", b"scan")] {
            storage
                .partitions
                .lock()
                .entry(partition.to_string())
                .or_default()
                .insert(name.to_vec(), original.clone());
        }

        let rejected_open = storage.open_atomic("v0_atomic_open", b"open").await;
        let rejected_scan = storage.scan_atomic("v0_atomic_scan").await;
        let partitions = storage.partitions.lock();
        assert!(
            partitions["v0_atomic_open"][b"open".as_slice()].as_slice() == original.as_slice(),
            "atomic open mutated a legacy ordinary blob"
        );
        assert!(
            partitions["v0_atomic_scan"][b"scan".as_slice()].as_slice() == original.as_slice(),
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

        let live = blob.read_at(0, 8).await.unwrap();
        assert_eq!(live.coalesce(), b"ABCDEFGH");
        let (reopened, len) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(len, 8);
        let durable = reopened.read_at(0, 8).await.unwrap();
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
            sparse.read_at(0, 6).await.unwrap().coalesce(),
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
        assert_eq!(replacement.read_at(0, 4).await.unwrap().coalesce(), b"new!");
    }

    #[tokio::test]
    async fn test_atomic_migration_normalizes_container_and_retry_is_idempotent() {
        const VERSION: u16 = 7;
        let storage = Storage::new(test_pool());
        let mut payload = crate::atomic::migration_prefix([0xA5; 16], 0, 0).to_vec();
        payload.extend_from_slice(b"ordinary payload");
        let (ordinary, _, version) = storage
            .open_versioned("migration", b"blob", VERSION..=VERSION)
            .await
            .unwrap();
        assert_eq!(version, VERSION);
        ordinary
            .write_at(0, payload.clone(), WriteOptions::default())
            .await
            .unwrap();

        storage.migrate_atomic(ordinary).await.unwrap();
        {
            let partitions = storage.partitions.lock();
            let content = partitions
                .get("migration")
                .and_then(|partition| partition.get(b"blob".as_slice()))
                .unwrap();
            assert_eq!(
                &content[..Layout::V1.data_offset() as usize],
                Header::create(&(crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION))
                    .0
                    .as_slice()
            );
        }
        let (atomic, len) = storage.open_atomic("migration", b"blob").await.unwrap();
        assert_eq!(len, payload.len() as u64);
        assert_eq!(
            atomic.read_at(0, payload.len()).await.unwrap().coalesce(),
            payload.as_slice()
        );
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
        assert_eq!(tail.coalesce(), payload.as_slice());
        drop(atomic);

        let (retry, retry_len, retry_version) = storage
            .open_versioned(
                "migration",
                b"blob",
                crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION,
            )
            .await
            .unwrap();
        assert_eq!(retry_len, crate::atomic::DATA_OFFSET + payload.len() as u64);
        assert_eq!(retry_version, crate::DEFAULT_BLOB_VERSION);
        storage.migrate_atomic(retry).await.unwrap();

        let (_, backing_len) = storage.open("migration", b"blob").await.unwrap();
        assert_eq!(
            backing_len,
            crate::atomic::DATA_OFFSET + payload.len() as u64
        );

        let (atomic, _) = storage.open_atomic("migration", b"blob").await.unwrap();
        let token = atomic.integrity_snapshot().await.unwrap().token;
        let append = atomic
            .append_integrity(token, b"!", crate::IntegrityBoundary::Complete, None)
            .await
            .unwrap();
        assert_eq!(append.offset, payload.len() as u64);
        atomic.sync().await.unwrap();
        drop(atomic);

        let (atomic, len) = storage.open_atomic("migration", b"blob").await.unwrap();
        assert_eq!(len, payload.len() as u64 + 1 + 4);
        let mut completed = payload.to_vec();
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
    }

    #[tokio::test]
    async fn test_atomic_migration_recognizes_identity_only_canonical_image() {
        const INCARNATION: [u8; crate::atomic::INCARNATION_LEN] = [0x3C; 16];

        let storage = Storage::new(test_pool());
        let partition = "identity_only_migration";
        let name = b"blob";
        let key = (partition.to_string(), name.to_vec());
        let prefix = crate::atomic::migration_prefix(INCARNATION, 0, 0);
        let (ordinary, _, version) = storage
            .open_versioned(
                partition,
                name,
                crate::DEFAULT_BLOB_VERSION..=crate::DEFAULT_BLOB_VERSION,
            )
            .await
            .unwrap();
        assert_eq!(version, crate::DEFAULT_BLOB_VERSION);
        ordinary
            .write_at(
                0,
                prefix[..crate::atomic::IDENTITY_PAGE_LEN as usize].to_vec(),
                WriteOptions::SYNC,
            )
            .await
            .unwrap();
        let generation = ordinary.generation;
        drop(ordinary);

        let (ordinary, len) = storage.open(partition, name).await.unwrap();
        assert_eq!(len, crate::atomic::IDENTITY_PAGE_LEN);
        storage.migrate_atomic(ordinary).await.unwrap();
        assert_eq!(
            storage.generations.lock().current.get(&key),
            Some(&generation)
        );

        let (_, len) = storage.open(partition, name).await.unwrap();
        assert_eq!(len, crate::atomic::IDENTITY_PAGE_LEN);
        let (_, len) = storage.open_atomic(partition, name).await.unwrap();
        assert_eq!(len, 0);
    }

    #[tokio::test]
    async fn test_atomic_migration_does_not_mistake_a_large_ordinary_payload_for_identity() {
        let storage = Storage::new(test_pool());
        let payload = vec![0xA5; crate::atomic::DATA_OFFSET as usize];
        let (ordinary, _, _) = storage
            .open_versioned("migration", b"large", 0..=0)
            .await
            .unwrap();
        ordinary
            .write_at(0, payload.clone(), WriteOptions::default())
            .await
            .unwrap();

        storage.migrate_atomic(ordinary).await.unwrap();
        let (atomic, len) = storage.open_atomic("migration", b"large").await.unwrap();
        assert_eq!(len, payload.len() as u64);
        assert_eq!(
            atomic
                .read_at(0, payload.len())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            payload.as_slice()
        );
    }

    #[tokio::test]
    async fn test_atomic_migration_rejects_foreign_and_stale_sources() {
        let owner = Storage::new(test_pool());
        let foreign = Storage::new(test_pool());
        let (foreign_blob, _) = foreign.open("migration", b"foreign").await.unwrap();
        assert!(owner.migrate_atomic(foreign_blob).await.is_err());

        let (stale, _) = owner.open("migration", b"stale").await.unwrap();
        owner.remove("migration", Some(b"stale")).await.unwrap();
        let (replacement, _) = owner.open("migration", b"stale").await.unwrap();
        replacement
            .write_at(0, b"replacement", WriteOptions::SYNC)
            .await
            .unwrap();
        assert!(owner.migrate_atomic(stale).await.is_err());
        assert_eq!(
            replacement
                .read_at(0, b"replacement".len())
                .await
                .unwrap()
                .coalesce(),
            b"replacement"
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
        let read_buf = blob.read_at(0, data.len()).await.unwrap();
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
        let read_buf = blob.read_at(0, data.len()).await.unwrap();
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

    #[tokio::test]
    async fn test_blob_torn_creation_recovers() {
        let storage = Storage::new(test_pool());

        // Manually insert a torn-creation leftover: a prefix of a canonical V1 header
        // region (the full state enumeration lives in the Layout::interrupted_creation
        // unit tables)
        let (region, _) = Header::create(&(0..=0));
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
            let read = blob.read_at(0, 4).await.unwrap();
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
