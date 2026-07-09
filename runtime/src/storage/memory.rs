use super::{Header, HeaderError, ParsedHeader};
#[commonware_macros::stability(BETA)]
use crate::{BlobHeaderLayout, BlobInfo};
use crate::{Buf, BufferPool, Handle, IoBufs, IoBufsMut};
use commonware_formatting::hex;
use commonware_utils::sync::{Mutex, RwLock};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, ops::RangeInclusive, sync::Arc};

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
    /// Compute a [Sha256] digest of all blob contents.
    pub fn audit(&self) -> [u8; 32] {
        let partitions = self.partitions.lock();
        let mut hasher = Sha256::new();

        for (partition_name, blobs) in partitions.iter() {
            for (blob_name, content) in blobs.iter() {
                hasher.update(partition_name.as_bytes());
                hasher.update(blob_name);
                hasher.update(content);
            }
        }

        hasher.finalize().into()
    }
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
        layout: BlobHeaderLayout,
    ) -> Result<(Self::Blob, BlobInfo), crate::Error> {
        super::validate_partition_name(partition)?;

        let mut partitions = self.partitions.lock();
        let partition_entry = partitions.entry(partition.into()).or_default();
        let content = partition_entry.entry(name.into()).or_default();

        let raw_len = content.len() as u64;
        let (info, data_offset) = if Header::missing(raw_len) {
            // New or corrupted blob - truncate and write the header region with latest version
            let (region, blob_version, data_offset) = Header::create(&versions, layout);
            content.clear();
            content.extend_from_slice(&region);
            let info = BlobInfo {
                size: 0,
                blob_version,
                layout,
            };
            (info, data_offset)
        } else {
            // Existing blob - read and validate the header, honoring the layout it records
            let mut prelude = [0u8; Header::PRELUDE_SIZE];
            prelude.copy_from_slice(&content[..Header::PRELUDE_SIZE]);
            let parsed = Header::parse_prelude(prelude, &versions)
                .map_err(|e| e.into_error(partition, name))?;
            match parsed {
                ParsedHeader::V0 { blob_version } => {
                    let info = BlobInfo {
                        size: raw_len - Header::PRELUDE_SIZE_U64,
                        blob_version,
                        layout: BlobHeaderLayout::V0,
                    };
                    (info, Header::PRELUDE_SIZE_U64)
                }
                ParsedHeader::NeedsExtension { blob_version } => {
                    let ext_end = Header::PRELUDE_SIZE + Header::EXTENSION_SIZE;
                    if content.len() < ext_end {
                        return Err(HeaderError::TruncatedHeader {
                            data_offset: ext_end as u64,
                            raw_len,
                        }
                        .into_error(partition, name));
                    }
                    let mut extension = [0u8; Header::EXTENSION_SIZE];
                    extension.copy_from_slice(&content[Header::PRELUDE_SIZE..ext_end]);
                    let data_offset = Header::parse_extension(prelude, extension, raw_len)
                        .map_err(|e| e.into_error(partition, name))?;
                    let info = BlobInfo {
                        size: raw_len - data_offset,
                        blob_version,
                        layout: BlobHeaderLayout::V1,
                    };
                    (info, data_offset)
                }
            }
        };

        Ok((
            Blob::new(
                self.partitions.clone(),
                partition.into(),
                name,
                content.clone(),
                self.pool.clone(),
                data_offset,
            ),
            info,
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
        storage::tests::run_storage_tests, telemetry::metrics::Registry, Blob, BufferPoolConfig,
        Storage as _,
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
        let data_offset = Header::V1_DATA_OFFSET as usize;
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
            assert_eq!(
                &raw_content[..Header::MAGIC_LENGTH],
                &BlobHeaderLayout::V1.magic()
            );
            assert_eq!(&raw_content[data_offset..], data);
        }

        // Read at logical offset 0 returns data from the data offset
        let read_buf = blob.read_at(0, data.len()).await.unwrap();
        assert_eq!(read_buf.coalesce(), data);

        // A V0 blob places data immediately after the 8-byte header
        let (blob, info) = storage
            .open_versioned("partition", b"v0", 0..=0, BlobHeaderLayout::V0)
            .await
            .unwrap();
        assert_eq!(info.size, 0);
        blob.write_at(0, data).await.unwrap();
        blob.sync().await.unwrap();
        {
            let partitions = storage.partitions.lock();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"v0".to_vec()).unwrap();
            assert_eq!(raw_content.len(), Header::PRELUDE_SIZE + data.len());
            assert_eq!(
                &raw_content[..Header::MAGIC_LENGTH],
                &BlobHeaderLayout::V0.magic()
            );
            assert_eq!(&raw_content[Header::PRELUDE_SIZE..], data);
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
    async fn test_blob_nondefault_data_offset() {
        let storage = Storage::new(test_pool());

        // Insert a blob whose header records a larger data offset than this build writes, as
        // a future writer would produce it.
        let data_offset = 4 * Header::V1_DATA_OFFSET;
        let payload = b"from the future";
        {
            let mut partitions = storage.partitions.lock();
            let partition = partitions.entry("partition".into()).or_default();
            partition.insert(
                b"future".to_vec(),
                crate::storage::tests::v1_blob_bytes(data_offset, 0, payload),
            );
        }

        // The blob opens with the recorded offset: the logical size covers only the payload,
        // and reads and writes translate against it.
        let (blob, size) = storage.open("partition", b"future").await.unwrap();
        assert_eq!(size, payload.len() as u64);
        assert_eq!(
            blob.read_at(0, payload.len()).await.unwrap().coalesce(),
            payload
        );
        blob.write_at(size, b"!").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob, size) = storage.open("partition", b"future").await.unwrap();
        assert_eq!(size, payload.len() as u64 + 1);
        assert_eq!(
            blob.read_at(0, size as usize).await.unwrap().coalesce(),
            b"from the future!"
        );
    }

    #[tokio::test]
    async fn test_blob_magic_mismatch() {
        let storage = Storage::new(test_pool());

        // Manually insert a blob with invalid magic bytes
        {
            let mut partitions = storage.partitions.lock();
            let partition = partitions.entry("partition".into()).or_default();
            partition.insert(b"bad_magic".to_vec(), vec![0u8; Header::PRELUDE_SIZE]);
        }

        // Opening should fail with corrupt error
        let result = storage.open("partition", b"bad_magic").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("invalid magic"))
        );
    }
}
