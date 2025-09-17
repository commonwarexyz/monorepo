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
        let mut partitions = self.partitions.lock().unwrap();
        let partition_entry = partitions.entry(partition.into()).or_default();
        let content = partition_entry.entry(name.into()).or_default();
        Ok((
            Blob::new(
                self.partitions.clone(),
                partition.into(),
                name,
                content.clone(),
            ),
            content.len() as u64,
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
        let len = len.try_into().map_err(|_| crate::Error::OffsetOverflow)?;
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
    use crate::storage::tests::run_storage_tests;

    #[tokio::test]
    async fn test_memory_storage() {
        let storage = Storage::default();
        run_storage_tests(storage).await;
    }
}
