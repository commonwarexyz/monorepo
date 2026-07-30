use super::Header;
use crate::{
    BatchOperation, Buf, BufferPool, Handle, IoBufs, IoBufsMut, RemoveTarget,
    deterministic::AuditHasher,
};
use commonware_formatting::hex;
use commonware_utils::sync::{Mutex, RwLock};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::RangeInclusive,
    sync::Arc,
};

type BlobKey = (String, Vec<u8>);

#[derive(Default)]
struct Namespace {
    next_generation: u64,
    generations: BTreeMap<BlobKey, u64>,
}

impl Namespace {
    fn generation(&mut self, key: &BlobKey) -> u64 {
        if let Some(generation) = self.generations.get(key) {
            return *generation;
        }
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("blob generation overflow");
        self.generations.insert(key.clone(), generation);
        generation
    }

    fn remove(&mut self, key: &BlobKey) {
        self.generations.remove(key);
    }
}

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

/// In-memory storage implementation for the commonware runtime.
#[derive(Clone)]
pub struct Storage {
    partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
    namespace: Arc<Mutex<Namespace>>,
    pool: BufferPool,
}

impl Storage {
    pub fn new(pool: BufferPool) -> Self {
        Self {
            partitions: Arc::new(Mutex::new(BTreeMap::new())),
            namespace: Arc::new(Mutex::new(Namespace::default())),
            pool,
        }
    }

    fn owns(&self, blob: &Blob) -> bool {
        Arc::ptr_eq(&self.partitions, &blob.partitions)
            && Arc::ptr_eq(&self.namespace, &blob.namespace)
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
        let mut namespace = self.namespace.lock();
        let mut partitions = self.partitions.lock();
        let partition_entry = partitions.entry(partition.into()).or_default();
        let content = partition_entry.entry(name.into()).or_default();
        let mut opened_content = content.clone();

        // Handle header: existing blobs have their header read; new blobs and blobs left torn
        // by an interrupted creation get a fresh header written.
        let existing = resolve_header(&opened_content, &versions, partition, name)?;
        let (logical_size, blob_version, data_offset) = existing.unwrap_or_else(|| {
            let (region, blob_version) = Header::create(&versions);
            let data_offset = region.len() as u64;
            content.clear();
            content.extend_from_slice(&region);
            opened_content.clone_from(content);
            (0, blob_version, data_offset)
        });
        let generation = namespace.generation(&key);

        Ok((
            Blob {
                partitions: self.partitions.clone(),
                namespace: self.namespace.clone(),
                partition: partition.into(),
                name: name.into(),
                content: Arc::new(RwLock::new(opened_content)),
                pool: self.pool.clone(),
                data_offset,
                generation,
            },
            logical_size,
            blob_version,
        ))
    }

    async fn start_apply(
        &self,
        operations: Vec<BatchOperation<Self::Blob>>,
    ) -> Result<Handle<()>, crate::Error> {
        let mut descriptors = Vec::with_capacity(operations.len());
        let mut mutation_blobs = BTreeMap::<BlobKey, Vec<Blob>>::new();
        for operation in operations {
            match operation {
                BatchOperation::Remove(target) => {
                    descriptors.push(super::batch::Operation::Remove(target));
                }
                BatchOperation::Resize { blob, len } => {
                    if !self.owns(&blob) {
                        return Err(crate::Error::BlobMissing(
                            blob.partition.clone(),
                            hex(&blob.name),
                        ));
                    }
                    let len = len
                        .checked_add(blob.data_offset)
                        .ok_or(crate::Error::OffsetOverflow)?;
                    usize::try_from(len).map_err(|_| crate::Error::OffsetOverflow)?;
                    let partition = blob.partition.clone();
                    let name = blob.name.clone();
                    mutation_blobs
                        .entry((partition.clone(), name.clone()))
                        .or_default()
                        .push(blob);
                    descriptors.push(super::batch::Operation::Resize {
                        partition,
                        name,
                        len,
                    });
                }
                BatchOperation::Update {
                    blob,
                    offset,
                    data,
                    len,
                } => {
                    if !self.owns(&blob) {
                        return Err(crate::Error::BlobMissing(
                            blob.partition.clone(),
                            hex(&blob.name),
                        ));
                    }
                    let offset = offset
                        .checked_add(blob.data_offset)
                        .ok_or(crate::Error::OffsetOverflow)?;
                    let len = len
                        .checked_add(blob.data_offset)
                        .ok_or(crate::Error::OffsetOverflow)?;
                    usize::try_from(offset).map_err(|_| crate::Error::OffsetOverflow)?;
                    usize::try_from(len).map_err(|_| crate::Error::OffsetOverflow)?;
                    let partition = blob.partition.clone();
                    let name = blob.name.clone();
                    mutation_blobs
                        .entry((partition.clone(), name.clone()))
                        .or_default()
                        .push(blob);
                    descriptors.push(super::batch::Operation::Update {
                        partition,
                        name,
                        offset,
                        data,
                        len,
                    });
                }
            }
        }
        let operations = super::batch::canonicalize_operations(descriptors)?;
        let mutations = operations
            .iter()
            .filter_map(|operation| match operation {
                super::batch::Operation::Resize {
                    partition, name, ..
                }
                | super::batch::Operation::Update {
                    partition, name, ..
                } => Some((
                    operation,
                    mutation_blobs
                        .get(&(partition.clone(), name.clone()))
                        .expect("canonical mutation must retain its blob handles"),
                )),
                super::batch::Operation::Remove(_) => None,
            })
            .collect::<Vec<_>>();

        // Blob operations acquire the content lock before the namespace and partition locks.
        // Acquiring every content lock in namespace order extends that ordering across the batch.
        let mut contents = Vec::with_capacity(mutations.len());
        for (_, blobs) in &mutations {
            contents.push(blobs[0].content.write());
        }

        let mut namespace = self.namespace.lock();
        for (_, blobs) in &mutations {
            for blob in blobs.iter() {
                let key = (blob.partition.clone(), blob.name.clone());
                blob.ensure_current(&namespace, &key)?;
            }
        }

        let mut partitions = self.partitions.lock();
        for (_, blobs) in &mutations {
            let blob = &blobs[0];
            if partitions
                .get(&blob.partition)
                .and_then(|partition| partition.get(&blob.name))
                .is_none()
            {
                return Err(crate::Error::BlobMissing(
                    blob.partition.clone(),
                    hex(&blob.name),
                ));
            }
        }

        for ((operation, blobs), content) in mutations.iter().zip(&mut contents) {
            let blob = &blobs[0];
            match operation {
                super::batch::Operation::Resize { len, .. } => {
                    let len = usize::try_from(*len).expect("validated length must fit in memory");
                    content.resize(len, 0);
                }
                super::batch::Operation::Update {
                    offset, data, len, ..
                } => {
                    let offset =
                        usize::try_from(*offset).expect("validated offset must fit in memory");
                    let len = usize::try_from(*len).expect("validated length must fit in memory");
                    content.resize(len, 0);
                    let end = offset
                        .checked_add(data.len())
                        .expect("validated update range fits in memory");
                    content[offset..end].copy_from_slice(data.as_ref());
                }
                super::batch::Operation::Remove(_) => {
                    unreachable!("mutation set contains a removal")
                }
            }
            partitions
                .get_mut(&blob.partition)
                .and_then(|partition| partition.get_mut(&blob.name))
                .expect("validated mutated blob must exist")
                .clone_from(content);
        }

        let removed_partitions = operations
            .iter()
            .filter_map(|operation| match operation {
                super::batch::Operation::Remove(RemoveTarget::Partition(partition)) => {
                    Some(partition.clone())
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        for operation in &operations {
            match operation {
                super::batch::Operation::Remove(RemoveTarget::Partition(partition)) => {
                    partitions.remove(partition);
                }
                super::batch::Operation::Remove(RemoveTarget::Blob { partition, name }) => {
                    if let Some(blobs) = partitions.get_mut(partition) {
                        blobs.remove(name);
                    }
                    namespace.remove(&(partition.clone(), name.clone()));
                }
                super::batch::Operation::Resize { .. }
                | super::batch::Operation::Update { .. } => {}
            }
        }
        if !removed_partitions.is_empty() {
            namespace
                .generations
                .retain(|key, _| !removed_partitions.contains(&key.0));
        }
        Ok(Handle::ready(Ok(())))
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

type Partition = BTreeMap<Vec<u8>, Vec<u8>>;

#[derive(Clone)]
pub struct Blob {
    partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
    namespace: Arc<Mutex<Namespace>>,
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
    fn ensure_current(&self, namespace: &Namespace, key: &BlobKey) -> Result<(), crate::Error> {
        if namespace.generations.get(key) == Some(&self.generation) {
            return Ok(());
        }
        Err(crate::Error::BlobMissing(
            self.partition.clone(),
            hex(&self.name),
        ))
    }

    fn sync_inner(&self) -> Result<(), crate::Error> {
        let new_content = self.content.read();
        let key = (self.partition.clone(), self.name.clone());
        let namespace = self.namespace.lock();
        self.ensure_current(&namespace, &key)?;

        // Update partition content
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
        content.clone_from(&new_content);
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
        let end = offset
            .checked_add(len)
            .ok_or(crate::Error::OffsetOverflow)?;
        let content = self.content.read();
        let content_len = content.len();
        if end > content_len {
            return Err(crate::Error::BlobInsufficientLength);
        }
        bufs.copy_from_slice(&content[offset..end]);
        Ok(bufs)
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), crate::Error> {
        let buf = bufs.into().coalesce();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(crate::Error::OffsetOverflow)?;
        let offset: usize = offset
            .try_into()
            .map_err(|_| crate::Error::OffsetOverflow)?;
        let mut content = self.content.write();
        let required = offset
            .checked_add(buf.len())
            .ok_or(crate::Error::OffsetOverflow)?;
        if required > content.len() {
            content.resize(required, 0);
        }
        content[offset..offset + buf.len()].copy_from_slice(buf.as_ref());
        Ok(())
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), crate::Error> {
        let bufs = bufs.into();
        if !bufs.has_remaining() {
            return Ok(());
        }

        self.write_at(offset, bufs).await?;
        self.sync().await
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
        storage::{
            Layout,
            tests::{run_storage_foreign_handle_test, run_storage_tests},
        },
        telemetry::metrics::Registry,
    };

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    #[tokio::test]
    async fn test_memory_storage() {
        let storage = Storage::new(test_pool());
        let tested = storage.clone();
        run_storage_tests(storage).await;

        let foreign = Storage::new(test_pool());
        run_storage_foreign_handle_test(&tested, &foreign).await;
    }

    #[tokio::test]
    async fn test_apply_batch_preserves_handles_and_rotates_generations() {
        let storage = Storage::new(test_pool());
        let (old_blob, _) = storage.open("batch_blob", b"name").await.unwrap();
        old_blob.write_at(0, b"old blob").await.unwrap();
        let old_blob_generation = old_blob.generation;

        let (old_partition, _) = storage.open("batch_partition", b"name").await.unwrap();
        old_partition.write_at(0, b"old partition").await.unwrap();
        let old_partition_generation = old_partition.generation;

        storage
            .apply(vec![
                BatchOperation::Remove(RemoveTarget::Blob {
                    partition: "batch_blob".into(),
                    name: b"name".to_vec(),
                }),
                BatchOperation::Remove(RemoveTarget::Blob {
                    partition: "batch_blob".into(),
                    name: b"name".to_vec(),
                }),
                BatchOperation::Remove(RemoveTarget::Blob {
                    partition: "batch_partition".into(),
                    name: b"name".to_vec(),
                }),
                BatchOperation::Remove(RemoveTarget::Partition("batch_partition".into())),
            ])
            .await
            .unwrap();

        assert_eq!(
            old_blob.read_at(0, 8).await.unwrap().coalesce(),
            b"old blob"
        );
        assert_eq!(
            old_partition.read_at(0, 13).await.unwrap().coalesce(),
            b"old partition"
        );

        let (new_blob, blob_len) = storage.open("batch_blob", b"name").await.unwrap();
        assert_eq!(blob_len, 0);
        assert_ne!(old_blob_generation, new_blob.generation);
        new_blob.write_at(0, b"new blob").await.unwrap();
        new_blob.sync().await.unwrap();

        let (new_partition, partition_len) =
            storage.open("batch_partition", b"name").await.unwrap();
        assert_eq!(partition_len, 0);
        assert_ne!(old_partition_generation, new_partition.generation);
        new_partition.write_at(0, b"new partition").await.unwrap();
        new_partition.sync().await.unwrap();

        assert!(old_blob.sync().await.is_err());
        assert!(old_partition.sync().await.is_err());
        drop((old_blob, old_partition, new_blob, new_partition));

        let (blob, blob_len) = storage.open("batch_blob", b"name").await.unwrap();
        assert_eq!(blob_len, 8);
        assert_eq!(blob.read_at(0, 8).await.unwrap().coalesce(), b"new blob");
        let (partition, partition_len) = storage.open("batch_partition", b"name").await.unwrap();
        assert_eq!(partition_len, 13);
        assert_eq!(
            partition.read_at(0, 13).await.unwrap().coalesce(),
            b"new partition"
        );
    }

    #[tokio::test]
    async fn test_read_range_overflow() {
        let storage = Storage::new(test_pool());
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        let offset = u64::MAX - Layout::V1.data_offset();

        assert!(matches!(
            blob.read_at(offset, 1).await,
            Err(crate::Error::OffsetOverflow)
        ));
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
        blob.write_at(0, data).await.unwrap();
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
        blob.write_at(data.len() as u64, b"!").await.unwrap();
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
        blob_a.write_at(0, b"d").await.unwrap();
        blob_a.sync().await.unwrap();

        let storage_b = Storage::new(test_pool());
        let (blob_b, _) = storage_b.open("ab", b"c").await.unwrap();
        blob_b.write_at(0, b"d").await.unwrap();
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
            blob.write_at(0, b"data".to_vec()).await.unwrap();
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
