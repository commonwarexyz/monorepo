use super::Header;
use crate::{
    deterministic::{AuditHasher, BoxDynRng},
    Buf, BufferPool, Handle, IoBufs, IoBufsMut,
};
use commonware_codec::Encode;
use commonware_formatting::hex;
use commonware_utils::sync::{Mutex, RwLock};
use rand::RngExt as _;
use std::{collections::BTreeMap, ops::RangeInclusive, sync::Arc};

/// Writes not yet published by a sync, per blob (keyed by partition then
/// blob name, in write order, at logical offsets). Shared by every handle
/// so records survive handle drops.
type CrashLog = Arc<Mutex<BTreeMap<String, BTreeMap<Vec<u8>, Vec<(u64, Vec<u8>)>>>>>;

/// In-memory storage implementation for the commonware runtime.
#[derive(Clone)]
pub struct Storage {
    partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
    pool: BufferPool,
    crash_log: Option<CrashLog>,
}

impl Storage {
    pub fn new(pool: BufferPool) -> Self {
        Self {
            partitions: Arc::new(Mutex::new(BTreeMap::new())),
            pool,
            crash_log: None,
        }
    }

    /// Like [Self::new], but additionally records every write until a sync
    /// publishes it, so [Self::crash] can materialize power-loss outcomes
    /// for unsynced writes.
    pub(crate) fn crash_logged(pool: BufferPool) -> Self {
        Self {
            partitions: Arc::new(Mutex::new(BTreeMap::new())),
            pool,
            crash_log: Some(Arc::new(Mutex::new(BTreeMap::new()))),
        }
    }

    /// Materialize a simulated power loss over the recorded unsynced
    /// writes, then clear the log. A no-op unless the storage was built
    /// with [Self::crash_logged].
    ///
    /// Mirrors the tearing granularity the volume assumes
    /// ([super::volume::BLOCK]): each recorded write is split at block
    /// boundaries of the blob's logical offset space, and each piece
    /// independently vanishes, lands, or fills its whole containing block
    /// with garbage derived from the published bytes. Pieces resolve in
    /// write order (blobs in key order) with one `rng` draw each, so the
    /// outcome is reproducible from the rng state.
    pub(crate) fn crash(&self, rng: &mut BoxDynRng) {
        let Some(log) = &self.crash_log else {
            return;
        };
        let block = super::volume::BLOCK as usize;
        let mut log = log.lock();
        let mut partitions = self.partitions.lock();
        for (partition, blobs) in log.iter() {
            for (name, writes) in blobs.iter() {
                // A blob removed after its last write has nothing to keep.
                let Some(content) = partitions
                    .get_mut(partition)
                    .and_then(|blobs| blobs.get_mut(name))
                else {
                    continue;
                };
                for (offset, bytes) in writes {
                    // Split the write into block-granular pieces. Blocks
                    // align to logical offsets: the raw content additionally
                    // carries the header prefix.
                    let mut cursor = 0usize;
                    while cursor < bytes.len() {
                        let at = *offset as usize + cursor;
                        let piece_end =
                            bytes.len().min((at / block + 1) * block - *offset as usize);
                        match rng.random_range(0..3u8) {
                            // Vanished
                            0 => {}
                            // Landed
                            1 => {
                                let raw = Header::SIZE + at;
                                let stop = raw + (piece_end - cursor);
                                if content.len() < stop {
                                    content.resize(stop, 0);
                                }
                                content[raw..stop].copy_from_slice(&bytes[cursor..piece_end]);
                            }
                            // Torn: the whole containing block becomes garbage
                            _ => {
                                let start = Header::SIZE + (at / block) * block;
                                let stop = start + block;
                                if content.len() < stop {
                                    content.resize(stop, 0);
                                }
                                for b in &mut content[start..stop] {
                                    *b = !*b ^ 0x5a;
                                }
                            }
                        }
                        cursor = piece_end;
                    }
                }
            }
        }
        log.clear();
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

        let raw_len = content.len() as u64;
        let (blob_version, logical_len) = if Header::missing(raw_len) {
            // New or corrupted blob - truncate and write default header with latest version
            let (header, blob_version) = Header::new(&versions);
            content.clear();
            content.extend_from_slice(&header.encode());
            (blob_version, 0)
        } else {
            // Existing blob - read and validate header
            let mut header_bytes = [0u8; Header::SIZE];
            header_bytes.copy_from_slice(&content[..Header::SIZE]);
            Header::from(header_bytes, raw_len, &versions, Header::SIZE_U64)
                .map_err(|e| e.into_error(partition, name))?
        };

        Ok((
            Blob::new(
                self.partitions.clone(),
                partition.into(),
                name,
                content.clone(),
                self.pool.clone(),
                self.crash_log.clone(),
            ),
            logical_len,
            blob_version,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), crate::Error> {
        super::validate_partition_name(partition)?;

        {
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
        }

        // Removed blobs have no unsynced writes to materialize. The
        // partitions guard is released first: [Self::crash] locks the log
        // and then the partitions.
        if let Some(log) = &self.crash_log {
            let mut log = log.lock();
            match name {
                Some(name) => {
                    if let Some(blobs) = log.get_mut(partition) {
                        blobs.remove(name);
                    }
                }
                None => {
                    log.remove(partition);
                }
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
    crash_log: Option<CrashLog>,
    // TODO(prune-campaign): persist the floor in the blob header prefix so
    // it survives reopen, and zero the pruned range.
    floor: Arc<std::sync::atomic::AtomicU64>,
}

impl Blob {
    fn new(
        partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
        partition: String,
        name: &[u8],
        content: Vec<u8>,
        pool: BufferPool,
        crash_log: Option<CrashLog>,
    ) -> Self {
        Self {
            partitions,
            partition,
            name: name.into(),
            content: Arc::new(RwLock::new(content)),
            pool,
            crash_log,
            floor: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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
        drop(partitions);

        // The publish supersedes every record for this blob: the durable
        // image is now this handle's full content.
        if let Some(log) = &self.crash_log {
            if let Some(blobs) = log.lock().get_mut(&self.partition) {
                blobs.remove(&self.name);
            }
        }
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
            .checked_add(Header::SIZE_U64)
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
        let raw = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(crate::Error::OffsetOverflow)?;
        let raw: usize = raw.try_into().map_err(|_| crate::Error::OffsetOverflow)?;

        // Record the write until a sync publishes it.
        if let Some(log) = &self.crash_log {
            log.lock()
                .entry(self.partition.clone())
                .or_default()
                .entry(self.name.clone())
                .or_default()
                .push((offset, buf.as_ref().to_vec()));
        }

        let mut content = self.content.write();
        let required = raw + buf.len();
        if required > content.len() {
            content.resize(required, 0);
        }
        content[raw..raw + buf.len()].copy_from_slice(buf.as_ref());
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

    async fn prune(&self, offset: u64) -> Result<(), crate::Error> {
        use std::sync::atomic::Ordering;
        let size = self.content.read().len() as u64 - Header::SIZE_U64;
        if offset > size {
            return Err(crate::Error::BlobInsufficientLength);
        }
        self.floor.fetch_max(offset, Ordering::Relaxed);
        Ok(())
    }

    fn floor(&self) -> u64 {
        self.floor.load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn resize(&self, len: u64) -> Result<(), crate::Error> {
        let len = len
            .checked_add(Header::SIZE_U64)
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

        // New blob returns logical size 0
        let (blob, size) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "new blob should have logical size 0");

        // Verify raw storage has 8 bytes (header only)
        {
            let partitions = storage.partitions.lock();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"test".to_vec()).unwrap();
            assert_eq!(
                raw_content.len(),
                Header::SIZE,
                "raw storage should have 8-byte header"
            );
        }

        // Write at logical offset 0 stores at raw offset 8
        let data = b"hello world";
        blob.write_at(0, data).await.unwrap();
        blob.sync().await.unwrap();

        // Verify raw storage layout
        {
            let partitions = storage.partitions.lock();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"test".to_vec()).unwrap();
            assert_eq!(raw_content.len(), Header::SIZE + data.len());
            assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Header::MAGIC);
            assert_eq!(&raw_content[Header::SIZE..], data);
        }

        // Read at logical offset 0 returns data from raw offset 8
        let read_buf = blob.read_at(0, data.len()).await.unwrap();
        assert_eq!(read_buf.coalesce(), data);

        // Corrupted blob recovery (0 < raw_size < 8)
        {
            let mut partitions = storage.partitions.lock();
            let partition = partitions.get_mut("partition").unwrap();
            partition.insert(b"corrupted".to_vec(), vec![0u8; 2]);
        }

        // Opening should truncate and write fresh header
        let (_blob, size) = storage.open("partition", b"corrupted").await.unwrap();
        assert_eq!(size, 0, "corrupted blob should return logical size 0");

        // Verify raw storage now has proper 8-byte header
        {
            let partitions = storage.partitions.lock();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"corrupted".to_vec()).unwrap();
            assert_eq!(
                raw_content.len(),
                Header::SIZE,
                "corrupted blob should be reset to header-only"
            );
        }
    }

    #[tokio::test]
    async fn test_blob_magic_mismatch() {
        let storage = Storage::new(test_pool());

        // Manually insert a blob with invalid magic bytes
        {
            let mut partitions = storage.partitions.lock();
            let partition = partitions.entry("partition".into()).or_default();
            partition.insert(b"bad_magic".to_vec(), vec![0u8; Header::SIZE]);
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
}
