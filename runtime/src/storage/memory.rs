use crate::Header;
use commonware_utils::{hex, StableBuf};
use std::{
    collections::BTreeMap,
    ops::RangeInclusive,
    sync::{Arc, Mutex, RwLock},
};

/// In-memory storage implementation for the commonware runtime.
#[derive(Clone)]
pub struct Storage {
    partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            partitions: Arc::new(Mutex::new(BTreeMap::new())),
        }
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

        let mut partitions = self.partitions.lock().unwrap();
        let partition_entry = partitions.entry(partition.into()).or_default();
        let content = partition_entry.entry(name.into()).or_default();

        let raw_len = content.len() as u64;
        let (app_version, logical_len) = if raw_len < Header::SIZE_U64 {
            // New or corrupted blob - truncate and write default header with latest version
            let app_version = *versions.end();
            let header = Header::new(app_version);
            content.clear();
            content.extend_from_slice(&header.to_bytes());
            (app_version, 0)
        } else {
            // Existing blob - read and validate header
            let mut header_bytes = [0u8; Header::SIZE];
            header_bytes.copy_from_slice(&content[..Header::SIZE]);
            let header = Header::from_bytes(header_bytes);
            header.validate(&versions)?;

            (header.application_version, raw_len - Header::SIZE_U64)
        };

        Ok((
            Blob::new(
                self.partitions.clone(),
                partition.into(),
                name,
                content.clone(),
            ),
            logical_len,
            app_version,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), crate::Error> {
        super::validate_partition_name(partition)?;

        let mut partitions = self.partitions.lock().unwrap();
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

        let partitions = self.partitions.lock().unwrap();
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
}

impl Blob {
    fn new(
        partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
        partition: String,
        name: &[u8],
        content: Vec<u8>,
    ) -> Self {
        Self {
            partitions,
            partition,
            name: name.into(),
            content: Arc::new(RwLock::new(content)),
        }
    }
}

impl crate::Blob for Blob {
    async fn read_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> Result<StableBuf, crate::Error> {
        let mut buf = buf.into();
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(crate::Error::OffsetOverflow)?;
        let offset: usize = offset
            .try_into()
            .map_err(|_| crate::Error::OffsetOverflow)?;
        let content = self.content.read().unwrap();
        let content_len = content.len();
        if offset + buf.len() > content_len {
            return Err(crate::Error::BlobInsufficientLength);
        }
        buf.put_slice(&content[offset..offset + buf.len()]);
        Ok(buf)
    }

    async fn write_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> Result<(), crate::Error> {
        let buf = buf.into();
        let offset = offset
            .checked_add(Header::SIZE_U64)
            .ok_or(crate::Error::OffsetOverflow)?;
        let offset: usize = offset
            .try_into()
            .map_err(|_| crate::Error::OffsetOverflow)?;
        let mut content = self.content.write().unwrap();
        let required = offset + buf.len();
        if required > content.len() {
            content.resize(required, 0);
        }
        content[offset..offset + buf.len()].copy_from_slice(buf.as_ref());
        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), crate::Error> {
        let len = len
            .checked_add(Header::SIZE_U64)
            .ok_or(crate::Error::OffsetOverflow)?;
        let len: usize = len.try_into().map_err(|_| crate::Error::OffsetOverflow)?;
        let mut content = self.content.write().unwrap();
        content.resize(len, 0);
        Ok(())
    }

    async fn sync(&self) -> Result<(), crate::Error> {
        // Create new content for partition
        let new_content = self.content.read().unwrap().clone();

        // Update partition content
        let mut partitions = self.partitions.lock().unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{storage::tests::run_storage_tests, Blob, Header, Storage as _};

    #[tokio::test]
    async fn test_memory_storage() {
        let storage = Storage::default();
        run_storage_tests(storage).await;
    }

    #[tokio::test]
    async fn test_blob_header_handling() {
        let storage = Storage::default();

        // Test 1: New blob returns logical size 0 and correct app version
        let (blob, size) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "new blob should have logical size 0");

        // Verify raw storage has 8 bytes (header only)
        {
            let partitions = storage.partitions.lock().unwrap();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"test".to_vec()).unwrap();
            assert_eq!(
                raw_content.len(),
                Header::SIZE,
                "raw storage should have 8-byte header"
            );
        }

        // Test 2: Logical offset handling - write at offset 0 stores at raw offset 8
        let data = b"hello world";
        blob.write_at(data.to_vec(), 0).await.unwrap();
        blob.sync().await.unwrap();

        // Verify raw storage layout
        {
            let partitions = storage.partitions.lock().unwrap();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"test".to_vec()).unwrap();
            assert_eq!(raw_content.len(), Header::SIZE + data.len());
            // First 4 bytes should be magic bytes
            assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Header::MAGIC);
            // Next 2 bytes should be header version
            assert_eq!(
                &raw_content[Header::MAGIC_LENGTH..Header::MAGIC_LENGTH + Header::VERSION_LENGTH],
                &Header::HEADER_VERSION.to_be_bytes()
            );
            // Data should start at offset 8
            assert_eq!(&raw_content[Header::SIZE..], data);
        }

        // Test 3: Read at logical offset 0 returns data from raw offset 8
        let read_buf = blob.read_at(vec![0u8; data.len()], 0).await.unwrap();
        assert_eq!(read_buf.as_ref(), data);

        // Test 4: Resize with logical length
        blob.resize(5).await.unwrap();
        blob.sync().await.unwrap();
        {
            let partitions = storage.partitions.lock().unwrap();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"test".to_vec()).unwrap();
            assert_eq!(
                raw_content.len(),
                Header::SIZE + 5,
                "resize(5) should result in 13 raw bytes"
            );
        }

        // resize(0) should leave only header
        blob.resize(0).await.unwrap();
        blob.sync().await.unwrap();
        {
            let partitions = storage.partitions.lock().unwrap();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"test".to_vec()).unwrap();
            assert_eq!(
                raw_content.len(),
                Header::SIZE,
                "resize(0) should leave only header"
            );
        }

        // Test 5: Reopen existing blob preserves header and returns correct logical size
        blob.write_at(b"test data".to_vec(), 0).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob2, size2) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size2, 9, "reopened blob should have logical size 9");
        let read_buf = blob2.read_at(vec![0u8; 9], 0).await.unwrap();
        assert_eq!(read_buf.as_ref(), b"test data");

        // Test 6: Corrupted blob recovery (0 < raw_size < 8)
        // Manually corrupt the raw storage to have only 2 bytes
        {
            let mut partitions = storage.partitions.lock().unwrap();
            let partition = partitions.get_mut("partition").unwrap();
            partition.insert(b"corrupted".to_vec(), vec![0u8; 2]);
        }

        // Opening should truncate and write fresh header
        let (_blob3, size3) = storage.open("partition", b"corrupted").await.unwrap();
        assert_eq!(size3, 0, "corrupted blob should return logical size 0");

        // Verify raw storage now has proper 8-byte header
        {
            let partitions = storage.partitions.lock().unwrap();
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
        let storage = Storage::default();

        // Manually insert a blob with invalid magic bytes
        {
            let mut partitions = storage.partitions.lock().unwrap();
            let partition = partitions.entry("partition".into()).or_default();
            // Create a blob with wrong magic bytes (all zeros)
            partition.insert(b"bad_magic".to_vec(), vec![0u8; Header::SIZE]);
        }

        // Opening should fail with magic mismatch error
        let result = storage.open("partition", b"bad_magic").await;
        match result {
            Err(crate::Error::BlobMagicMismatch { found }) => {
                assert_eq!(found, [0u8; Header::MAGIC_LENGTH]);
            }
            Err(err) => panic!("expected BlobMagicMismatch error, got: {:?}", err),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn test_blob_version_mismatch() {
        let storage = Storage::default();

        // Create blob with version 1
        let (_, _, app_version) = storage
            .open_versioned("partition", b"v1", 1..=1)
            .await
            .unwrap();
        assert_eq!(app_version, 1, "new blob should have version 1");

        // Reopen with a range that includes version 1
        let (_, _, app_version) = storage
            .open_versioned("partition", b"v1", 0..=2)
            .await
            .unwrap();
        assert_eq!(app_version, 1, "existing blob should retain version 1");

        // Try to open with version range 2..=2 (should fail)
        let result = storage.open_versioned("partition", b"v1", 2..=2).await;
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
    }
}
