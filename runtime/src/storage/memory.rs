use crate::Header;
use commonware_utils::{hex, StableBuf};
use std::{
    collections::BTreeMap,
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

    async fn open(&self, partition: &str, name: &[u8]) -> Result<(Self::Blob, u64), crate::Error> {
        super::validate_partition_name(partition)?;

        let mut partitions = self.partitions.lock().unwrap();
        let partition_entry = partitions.entry(partition.into()).or_default();
        let content = partition_entry.entry(name.into()).or_default();

        let raw_len = content.len() as u64;
        let (header, logical_len) = if raw_len < Header::SIZE_U64 {
            // New or corrupted blob - truncate and write default header
            let header = Header::default();
            content.clear();
            content.extend_from_slice(header.as_ref());
            (header, 0)
        } else {
            // Existing blob - read header from first 32 bytes
            let mut header_bytes = [0u8; Header::SIZE];
            header_bytes.copy_from_slice(&content[..Header::SIZE]);
            let header = Header(header_bytes);
            header.validate_magic()?;
            (header, raw_len - Header::SIZE_U64)
        };

        Ok((
            Blob::new(
                self.partitions.clone(),
                partition.into(),
                name,
                content.clone(),
                header,
            ),
            logical_len,
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
    header: Header,
}

impl Blob {
    fn new(
        partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
        partition: String,
        name: &[u8],
        content: Vec<u8>,
        header: Header,
    ) -> Self {
        Self {
            partitions,
            partition,
            name: name.into(),
            content: Arc::new(RwLock::new(content)),
            header,
        }
    }
}

impl crate::Blob for Blob {
    fn header(&self) -> Header {
        self.header
    }

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

        // Test 1: New blob returns logical size 0 and has default header
        let (blob, size) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "new blob should have logical size 0");
        assert_eq!(
            blob.header(),
            Header::default(),
            "new blob should have default header"
        );

        // Verify raw storage has 32 bytes (header only)
        {
            let partitions = storage.partitions.lock().unwrap();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"test".to_vec()).unwrap();
            assert_eq!(
                raw_content.len(),
                Header::SIZE,
                "raw storage should have 32-byte header"
            );
        }

        // Test 2: Logical offset handling - write at offset 0 stores at raw offset 32
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
            assert_eq!(
                &raw_content[Header::MAGIC_LENGTH..Header::SIZE],
                &[0u8; Header::SIZE - Header::MAGIC_LENGTH]
            );
            // Data should start at offset 32
            assert_eq!(&raw_content[Header::SIZE..], data);
        }

        // Test 3: Read at logical offset 0 returns data from raw offset 32
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
                "resize(5) should result in 37 raw bytes"
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
        assert_eq!(blob2.header(), Header::default());
        let read_buf = blob2.read_at(vec![0u8; 9], 0).await.unwrap();
        assert_eq!(read_buf.as_ref(), b"test data");

        // Test 6: Corrupted blob recovery (0 < raw_size < 32)
        // Manually corrupt the raw storage to have only 10 bytes
        {
            let mut partitions = storage.partitions.lock().unwrap();
            let partition = partitions.get_mut("partition").unwrap();
            partition.insert(b"corrupted".to_vec(), vec![0u8; 10]);
        }

        // Opening should truncate and write fresh header
        let (blob3, size3) = storage.open("partition", b"corrupted").await.unwrap();
        assert_eq!(size3, 0, "corrupted blob should return logical size 0");
        assert_eq!(blob3.header(), Header::default());

        // Verify raw storage now has proper 32-byte header
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
}
