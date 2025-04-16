use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use commonware_utils::hex;

/// In-memory storage implementation for the commonware runtime.
#[derive(Clone)]
pub struct Storage {
    partitions: Arc<Mutex<HashMap<String, Partition>>>,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            partitions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<Self::Blob, crate::Error> {
        let mut partitions = self.partitions.lock().unwrap();
        let partition_entry = partitions.entry(partition.into()).or_default();
        let content = partition_entry.entry(name.into()).or_default();
        Ok(Blob::new(
            self.partitions.clone(),
            partition.into(),
            name,
            content.clone(),
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), crate::Error> {
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

type Partition = HashMap<Vec<u8>, Vec<u8>>;

#[derive(Clone)]
pub struct Blob {
    partitions: Arc<Mutex<HashMap<String, Partition>>>,
    partition: String,
    name: Vec<u8>,
    content: Arc<RwLock<Vec<u8>>>,
}

impl Blob {
    fn new(
        partitions: Arc<Mutex<HashMap<String, Partition>>>,
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
    async fn len(&self) -> Result<u64, crate::Error> {
        let content = self.content.read().unwrap();
        Ok(content.len() as u64)
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), crate::Error> {
        let offset = offset
            .try_into()
            .map_err(|_| crate::Error::OffsetOverflow)?;
        let content = self.content.read().unwrap();
        let content_len = content.len();
        if offset + buf.len() > content_len {
            return Err(crate::Error::BlobInsufficientLength);
        }
        buf.copy_from_slice(&content[offset..offset + buf.len()]);
        Ok(())
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> Result<(), crate::Error> {
        let offset = offset
            .try_into()
            .map_err(|_| crate::Error::OffsetOverflow)?;
        let mut content = self.content.write().unwrap();
        let required = offset + buf.len();
        if required > content.len() {
            content.resize(required, 0);
        }
        content[offset..offset + buf.len()].copy_from_slice(buf);
        Ok(())
    }

    async fn truncate(&self, len: u64) -> Result<(), crate::Error> {
        let len = len.try_into().map_err(|_| crate::Error::OffsetOverflow)?;
        let mut content = self.content.write().unwrap();
        content.truncate(len);
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

    async fn close(self) -> Result<(), crate::Error> {
        self.sync().await?;
        Ok(())
    }
}
