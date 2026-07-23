use super::Header;
use crate::{Buf, BufferPool, Handle, IoBufs, IoBufsMut, deterministic::AuditHasher};
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

/// In-memory storage implementation for the commonware runtime.
#[derive(Clone)]
pub struct Storage {
    partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
    pool: BufferPool,
}

impl Storage {
    pub fn new(pool: BufferPool) -> Self {
        Self {
            partitions: Arc::new(Mutex::new(BTreeMap::new())),
            pool,
        }
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

        let mut partitions = self.partitions.lock();
        let partition_entry = partitions.entry(partition.into()).or_default();
        let content = partition_entry.entry(name.into()).or_default();

        // Handle header: existing blobs have their header read; new blobs and blobs left torn
        // by an interrupted creation get a fresh header written.
        let existing = resolve_header(content, &versions, partition, name)?;
        let (logical_size, blob_version, data_offset) = existing.unwrap_or_else(|| {
            let (region, blob_version) = Header::create(&versions);
            let data_offset = region.len() as u64;
            content.clear();
            content.extend_from_slice(&region);
            (0, blob_version, data_offset)
        });

        Ok((
            Blob::new(
                self.partitions.clone(),
                partition.into(),
                name,
                content.clone(),
                self.pool.clone(),
                data_offset,
            ),
            logical_size,
            blob_version,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), crate::Error> {
        super::validate_partition_name(partition)?;

        let mut partitions = self.partitions.lock();
        match name {
            Some(name) => {
                partitions
                    .get_mut(partition)
                    .ok_or(crate::Error::PartitionMissing(partition.into()))?
                    .remove(name)
                    .ok_or(crate::Error::BlobMissing(partition.into(), hex(name)))?;
            }
            None => {
                partitions
                    .remove(partition)
                    .ok_or(crate::Error::PartitionMissing(partition.into()))?;
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

type Partition = BTreeMap<Vec<u8>, Vec<u8>>;

#[derive(Clone)]
pub struct Blob {
    partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
    partition: String,
    name: Vec<u8>,
    content: Arc<RwLock<Vec<u8>>>,
    pool: BufferPool,
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
}

impl Blob {
    fn new(
        partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
        partition: String,
        name: &[u8],
        content: Vec<u8>,
        pool: BufferPool,
        data_offset: u64,
    ) -> Self {
        Self {
            partitions,
            partition,
            name: name.into(),
            content: Arc::new(RwLock::new(content)),
            pool,
            data_offset,
        }
    }

    fn sync_inner(&self) -> Result<(), crate::Error> {
        // Create new content for partition
        let new_content = self.content.read().clone();

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
        *content = new_content;
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
    ) -> Result<(), crate::Error> {
        let buf = bufs.into().coalesce();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(crate::Error::OffsetOverflow)?;
        let offset: usize = offset
            .try_into()
            .map_err(|_| crate::Error::OffsetOverflow)?;
        let mut content = self.content.write();
        let required = offset + buf.len();
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
