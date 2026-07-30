use super::Header;
use crate::{
    BatchOperation, Buf, BufferPool, Handle, IoBuf, IoBufs, IoBufsMut, RemoveTarget,
    deterministic::AuditHasher,
};
use commonware_formatting::hex;
use commonware_utils::sync::{Mutex, RwLock};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::RangeInclusive,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

type BlobKey = (String, Vec<u8>);

#[derive(Default)]
struct PartitionBatch {
    remove: bool,
    removed_blobs: BTreeSet<Vec<u8>>,
    mutations: BTreeMap<Vec<u8>, BlobBatch>,
}

struct BlobBatch {
    mutation: BatchMutation,
    blobs: Vec<Blob>,
}

#[derive(Eq, PartialEq)]
enum BatchMutation {
    Resize {
        len: usize,
    },
    Update {
        offset: usize,
        data: IoBuf,
        len: usize,
    },
}

fn invalid_batch(reason: &'static str) -> crate::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, reason).into()
}

fn insert_mutation(
    partitions: &mut BTreeMap<String, PartitionBatch>,
    blob: Blob,
    mutation: BatchMutation,
) -> Result<(), crate::Error> {
    let batch = partitions.entry(blob.partition.clone()).or_default();
    if batch.remove || batch.removed_blobs.contains(&blob.name) {
        return Err(invalid_batch("cannot remove and mutate the same blob"));
    }
    match batch.mutations.entry(blob.name.clone()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(BlobBatch {
                mutation,
                blobs: vec![blob],
            });
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            if entry.get().mutation != mutation {
                return Err(invalid_batch(
                    "cannot apply different mutations to the same blob",
                ));
            }
            entry.get_mut().blobs.push(blob);
        }
    }
    Ok(())
}

enum Mutation {
    Write {
        offset: usize,
        data: IoBuf,
        durable: bool,
    },
    Resize {
        len: usize,
    },
}

#[derive(Default)]
struct Recovery {
    next_generation: u64,
    generations: BTreeMap<BlobKey, u64>,
    pending: BTreeMap<BlobKey, Vec<Mutation>>,
}

fn apply_mutations(content: &mut Vec<u8>, mutations: &[Mutation]) {
    for mutation in mutations {
        match mutation {
            Mutation::Write { offset, data, .. } => {
                Storage::apply_write(content, *offset, data.as_ref());
            }
            Mutation::Resize { len } => content.resize(*len, 0),
        }
    }
}

fn apply_crash(
    recovery: &mut Recovery,
    partitions: &mut BTreeMap<String, Partition>,
    mut next_mask: impl FnMut() -> u64,
) {
    let pending = std::mem::take(&mut recovery.pending);

    for (key, mutations) in pending {
        let Some(content) = partitions
            .get_mut(&key.0)
            .and_then(|partition| partition.get_mut(&key.1))
        else {
            continue;
        };

        for mutation in mutations {
            match mutation {
                Mutation::Write {
                    offset,
                    data,
                    durable,
                } => {
                    if durable {
                        Storage::apply_write(content, offset, data.as_ref());
                        continue;
                    }

                    let decision = next_mask();
                    let end = offset + data.len();
                    if decision & 0b100 != 0 && end > content.len() {
                        content.resize(end, 0);
                    }

                    match decision & 0b11 {
                        // Lose all data bytes. The extent above is still independent.
                        0 => {}
                        // Retain the entire write so later valid islands are exercised often.
                        1 => Storage::apply_write(content, offset, data.as_ref()),
                        // Retain a strict prefix when one exists.
                        2 if data.len() > 1 => {
                            let len = 1 + (next_mask() as usize % (data.len() - 1));
                            Storage::apply_write(content, offset, &data.as_ref()[..len]);
                        }
                        2 => Storage::apply_write(content, offset, data.as_ref()),
                        // Sample individual bytes. This branch can produce any subset.
                        _ => {
                            let mut mask = 0;
                            for (i, byte) in data.as_ref().iter().copied().enumerate() {
                                let bit = i % u64::BITS as usize;
                                if bit == 0 {
                                    mask = next_mask();
                                }
                                if mask & (1 << bit) == 0 {
                                    continue;
                                }
                                Storage::apply_byte(content, offset + i, byte);
                            }
                        }
                    }
                }
                Mutation::Resize { len } => {
                    if next_mask() & 1 != 0 {
                        content.resize(len, 0);
                    }
                }
            }
        }
    }
}

impl Recovery {
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
        self.pending.remove(key);
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
    recovery: Arc<Mutex<Recovery>>,
    epoch: Arc<AtomicU64>,
    pool: BufferPool,
}

impl Storage {
    pub fn new(pool: BufferPool) -> Self {
        Self {
            partitions: Arc::new(Mutex::new(BTreeMap::new())),
            recovery: Arc::new(Mutex::new(Recovery::default())),
            epoch: Arc::new(AtomicU64::new(0)),
            pool,
        }
    }

    /// Simulate an unclean shutdown by sampling every mutation since each blob's last completed
    /// sync. Writes can be lost, retained, prefix-torn, or retain an arbitrary subset of bytes;
    /// write extents and resizes are sampled independently.
    pub(crate) fn simulate_crash(&self, mut next_mask: impl FnMut() -> u64) {
        let mut recovery = self.recovery.lock();
        let mut partitions = self.partitions.lock();
        apply_crash(&mut recovery, &mut partitions, &mut next_mask);
        self.epoch
            .try_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .expect("storage crash epoch overflow");
    }

    fn apply_write(content: &mut Vec<u8>, offset: usize, data: &[u8]) {
        let end = offset + data.len();
        if end > content.len() {
            content.resize(end, 0);
        }
        content[offset..end].copy_from_slice(data);
    }

    fn apply_byte(content: &mut Vec<u8>, offset: usize, byte: u8) {
        if offset >= content.len() {
            content.resize(offset + 1, 0);
        }
        content[offset] = byte;
    }

    fn owns(&self, blob: &Blob) -> bool {
        Arc::ptr_eq(&self.partitions, &blob.partitions)
            && Arc::ptr_eq(&self.recovery, &blob.recovery)
            && Arc::ptr_eq(&self.epoch, &blob.epoch)
    }

    fn canonicalize_batch(
        &self,
        operations: Vec<BatchOperation<Blob>>,
    ) -> Result<BTreeMap<String, PartitionBatch>, crate::Error> {
        let mut partitions = BTreeMap::<String, PartitionBatch>::new();
        for operation in operations {
            match operation {
                BatchOperation::Remove(RemoveTarget::Blob { partition, name }) => {
                    super::validate_partition_name(&partition)?;
                    let batch = partitions.entry(partition).or_default();
                    if batch.mutations.contains_key(&name) {
                        return Err(invalid_batch("cannot remove and mutate the same blob"));
                    }
                    if !batch.remove {
                        batch.removed_blobs.insert(name);
                    }
                }
                BatchOperation::Remove(RemoveTarget::Partition(partition)) => {
                    super::validate_partition_name(&partition)?;
                    let batch = partitions.entry(partition).or_default();
                    if !batch.mutations.is_empty() {
                        return Err(invalid_batch(
                            "cannot remove a partition containing a blob mutation",
                        ));
                    }
                    batch.remove = true;
                    batch.removed_blobs.clear();
                }
                BatchOperation::Resize { blob, len } => {
                    if !self.owns(&blob) {
                        return Err(crate::Error::BlobMissing(
                            blob.partition.clone(),
                            hex(&blob.name),
                        ));
                    }
                    super::validate_partition_name(&blob.partition)?;
                    let len = len
                        .checked_add(blob.data_offset)
                        .ok_or(crate::Error::OffsetOverflow)?;
                    let len: usize = len.try_into().map_err(|_| crate::Error::OffsetOverflow)?;
                    insert_mutation(&mut partitions, blob, BatchMutation::Resize { len })?;
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
                    super::validate_partition_name(&blob.partition)?;
                    let data_len: u64 = data
                        .len()
                        .try_into()
                        .map_err(|_| crate::Error::OffsetOverflow)?;
                    let end = offset
                        .checked_add(data_len)
                        .ok_or(crate::Error::OffsetOverflow)?;
                    if end > len {
                        return Err(invalid_batch("update data exceeds the final blob length"));
                    }
                    let offset = offset
                        .checked_add(blob.data_offset)
                        .ok_or(crate::Error::OffsetOverflow)?;
                    let offset: usize = offset
                        .try_into()
                        .map_err(|_| crate::Error::OffsetOverflow)?;
                    let len = len
                        .checked_add(blob.data_offset)
                        .ok_or(crate::Error::OffsetOverflow)?;
                    let len: usize = len.try_into().map_err(|_| crate::Error::OffsetOverflow)?;
                    let raw_end = offset
                        .checked_add(data.len())
                        .ok_or(crate::Error::OffsetOverflow)?;
                    if raw_end > len {
                        return Err(invalid_batch("update data exceeds the final blob length"));
                    }
                    insert_mutation(
                        &mut partitions,
                        blob,
                        BatchMutation::Update { offset, data, len },
                    )?;
                }
            }
        }
        Ok(partitions)
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
        let mut recovery = self.recovery.lock();
        let mut partitions = self.partitions.lock();
        let partition_entry = partitions.entry(partition.into()).or_default();
        let content = partition_entry.entry(name.into()).or_default();
        let mut opened_content = content.clone();
        if let Some(mutations) = recovery.pending.get(&key) {
            apply_mutations(&mut opened_content, mutations);
        }

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
        let generation = recovery.generation(&key);

        Ok((
            Blob {
                partitions: self.partitions.clone(),
                recovery: self.recovery.clone(),
                epoch: self.epoch.clone(),
                partition: partition.into(),
                name: name.into(),
                content: Arc::new(RwLock::new(opened_content)),
                pool: self.pool.clone(),
                data_offset,
                generation,
                opened_epoch: self.epoch.load(Ordering::Acquire),
            },
            logical_size,
            blob_version,
        ))
    }

    async fn apply_batch(
        &self,
        operations: Vec<BatchOperation<Self::Blob>>,
    ) -> Result<(), crate::Error> {
        let batch = self.canonicalize_batch(operations)?;
        let mutations = batch
            .values()
            .flat_map(|partition| partition.mutations.values())
            .collect::<Vec<_>>();

        // Blob operations acquire the content lock before recovery and namespace locks. Acquiring
        // every content lock in namespace order extends that ordering safely across the batch.
        let mut contents = Vec::with_capacity(mutations.len());
        for mutation in &mutations {
            contents.push(mutation.blobs[0].content.write());
        }

        let mut recovery = self.recovery.lock();
        for mutation in &mutations {
            for blob in &mutation.blobs {
                let key = (blob.partition.clone(), blob.name.clone());
                blob.ensure_current(&recovery, &key)?;
            }
        }

        let mut partitions = self.partitions.lock();
        for mutation in &mutations {
            let blob = &mutation.blobs[0];
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

        for (mutation, content) in mutations.iter().zip(&mut contents) {
            let blob = &mutation.blobs[0];
            match &mutation.mutation {
                BatchMutation::Resize { len } => content.resize(*len, 0),
                BatchMutation::Update { offset, data, len } => {
                    Self::apply_write(content, *offset, data.as_ref());
                    content.resize(*len, 0);
                }
            }
            partitions
                .get_mut(&blob.partition)
                .and_then(|partition| partition.get_mut(&blob.name))
                .expect("validated mutated blob must exist")
                .clone_from(content);
            recovery
                .pending
                .remove(&(blob.partition.clone(), blob.name.clone()));
        }

        let removes_partitions = batch.values().any(|operations| operations.remove);
        for (partition, operations) in &batch {
            if operations.remove {
                partitions.remove(partition);
                continue;
            }
            for name in &operations.removed_blobs {
                if let Some(blobs) = partitions.get_mut(partition) {
                    blobs.remove(name);
                }
                recovery.remove(&(partition.clone(), name.clone()));
            }
        }
        if removes_partitions {
            recovery.generations.retain(|key, _| {
                !batch
                    .get(key.0.as_str())
                    .is_some_and(|operations| operations.remove)
            });
            recovery.pending.retain(|key, _| {
                !batch
                    .get(key.0.as_str())
                    .is_some_and(|operations| operations.remove)
            });
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
    recovery: Arc<Mutex<Recovery>>,
    epoch: Arc<AtomicU64>,
    partition: String,
    name: Vec<u8>,
    content: Arc<RwLock<Vec<u8>>>,
    pool: BufferPool,
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
    generation: u64,
    opened_epoch: u64,
}

impl Blob {
    fn ensure_current_epoch(&self) -> Result<(), crate::Error> {
        if self.epoch.load(Ordering::Acquire) == self.opened_epoch {
            return Ok(());
        }
        Err(crate::Error::BlobMissing(
            self.partition.clone(),
            hex(&self.name),
        ))
    }

    fn ensure_current(&self, recovery: &Recovery, key: &BlobKey) -> Result<(), crate::Error> {
        self.ensure_current_epoch()?;
        if recovery.generations.get(key) == Some(&self.generation) {
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
        let mut recovery = self.recovery.lock();
        self.ensure_current(&recovery, &key)?;

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
        recovery.pending.remove(&key);
        Ok(())
    }

    fn record(&self, mutation: Mutation) -> Result<(), crate::Error> {
        let key = (self.partition.clone(), self.name.clone());
        let mut recovery = self.recovery.lock();
        self.ensure_current(&recovery, &key)?;
        recovery.pending.entry(key).or_default().push(mutation);
        Ok(())
    }

    fn persist_write(&self, offset: usize, data: &IoBuf) -> Result<(), crate::Error> {
        let key = (self.partition.clone(), self.name.clone());
        let mut recovery = self.recovery.lock();
        self.ensure_current(&recovery, &key)?;

        let mut partitions = self.partitions.lock();
        let content = partitions
            .get_mut(&self.partition)
            .and_then(|partition| partition.get_mut(&self.name))
            .ok_or_else(|| crate::Error::BlobMissing(self.partition.clone(), hex(&self.name)))?;
        Storage::apply_write(content, offset, data.as_ref());
        if let Some(pending) = recovery.pending.get_mut(&key) {
            pending.push(Mutation::Write {
                offset,
                data: data.clone(),
                durable: true,
            });
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
        self.ensure_current_epoch()?;
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
        self.ensure_current_epoch()?;
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
        if !buf.is_empty() {
            self.record(Mutation::Write {
                offset,
                data: buf,
                durable: false,
            })?;
        }
        Ok(())
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), crate::Error> {
        self.ensure_current_epoch()?;
        let bufs = bufs.into();
        if !bufs.has_remaining() {
            return Ok(());
        }

        let buf = bufs.coalesce();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(crate::Error::OffsetOverflow)?;
        let offset: usize = offset
            .try_into()
            .map_err(|_| crate::Error::OffsetOverflow)?;
        offset
            .checked_add(buf.len())
            .ok_or(crate::Error::OffsetOverflow)?;
        let mut content = self.content.write();
        Storage::apply_write(&mut content, offset, buf.as_ref());
        self.persist_write(offset, &buf)
    }

    async fn resize(&self, len: u64) -> Result<(), crate::Error> {
        self.ensure_current_epoch()?;
        let len = len
            .checked_add(self.data_offset)
            .ok_or(crate::Error::OffsetOverflow)?;
        let len: usize = len.try_into().map_err(|_| crate::Error::OffsetOverflow)?;
        let mut content = self.content.write();
        content.resize(len, 0);
        self.record(Mutation::Resize { len })?;
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

    struct Paused<T> {
        checked_epoch: Arc<std::sync::Barrier>,
        resume: Arc<std::sync::Barrier>,
        value: T,
    }

    impl<T> Paused<T> {
        fn into_inner(self) -> T {
            self.checked_epoch.wait();
            self.resume.wait();
            self.value
        }
    }

    impl From<Paused<Self>> for IoBufs {
        fn from(paused: Paused<Self>) -> Self {
            paused.into_inner()
        }
    }

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    fn update(
        blob: &super::Blob,
        offset: u64,
        data: &[u8],
        len: u64,
    ) -> BatchOperation<super::Blob> {
        BatchOperation::Update {
            blob: blob.clone(),
            offset,
            data: data.to_vec().into(),
            len,
        }
    }

    fn assert_invalid_batch(result: Result<(), crate::Error>) {
        assert!(
            matches!(result, Err(crate::Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput)
        );
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
    async fn test_crash_preserves_arbitrary_pending_bytes() {
        let storage = Storage::new(test_pool());
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"abcdefgh").await.unwrap();
        blob.sync().await.unwrap();

        blob.write_at(0, b"1234").await.unwrap();
        blob.write_at(4, b"WXYZ").await.unwrap();
        drop(blob);

        // Keep alternating bytes from each write. This is neither a prefix of either write nor a
        // prefix of the pending mutation sequence.
        let mut masks = [0b11, 0b0101, 0b11, 0b1010].into_iter();
        storage.simulate_crash(|| masks.next().unwrap());

        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 8);
        assert_eq!(blob.read_at(0, 8).await.unwrap().coalesce(), b"1b3deXgZ");

        // A completed sync clears the pending log, while a later unsynced resize is sampled
        // independently at the next crash.
        blob.write_at(0, b"SYNC").await.unwrap();
        blob.sync().await.unwrap();
        blob.resize(4).await.unwrap();
        drop(blob);
        storage.simulate_crash(|| u64::MAX);

        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 4);
        assert_eq!(blob.read_at(0, 4).await.unwrap().coalesce(), b"SYNC");
    }

    #[tokio::test]
    async fn test_write_at_sync_does_not_promote_prior_writes() {
        let storage = Storage::new(test_pool());
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"dirty").await.unwrap();
        blob.write_at_sync(5, b"S").await.unwrap();
        drop(blob);

        // Lose the earlier ordinary write. The later range-durable write and its extent survive.
        storage.simulate_crash(|| 0);

        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 6);
        assert_eq!(
            blob.read_at(0, 6).await.unwrap().coalesce().as_ref(),
            &[0, 0, 0, 0, 0, b'S']
        );
    }

    #[tokio::test]
    async fn test_write_at_sync_range_survives_prior_pending_mutations() {
        let storage = Storage::new(test_pool());
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"dirty").await.unwrap();
        blob.resize(1).await.unwrap();
        blob.write_at_sync(1, b"SYNC").await.unwrap();
        drop(blob);

        // Retain the overlapping dirty write and the shrink. The later durable range marker must
        // replay after both and restore exactly the bytes submitted to write_at_sync.
        storage.simulate_crash(|| 1);

        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 5);
        assert_eq!(blob.read_at(0, 5).await.unwrap().coalesce(), b"dSYNC");
    }

    #[tokio::test]
    async fn test_reopen_and_sync_preserves_pending_mutations() {
        let storage = Storage::new(test_pool());
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"pending").await.unwrap();
        drop(blob);

        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 7);
        assert_eq!(blob.read_at(0, 7).await.unwrap().coalesce(), b"pending");
        blob.sync().await.unwrap();
        drop(blob);

        storage.simulate_crash(|| 0);

        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 7);
        assert_eq!(blob.read_at(0, 7).await.unwrap().coalesce(), b"pending");
    }

    #[tokio::test]
    async fn test_crash_ignores_removed_blob_generation() {
        let storage = Storage::new(test_pool());
        let (old, _) = storage.open("partition", b"blob").await.unwrap();
        old.write_at(0, b"old").await.unwrap();
        storage.remove("partition", Some(b"blob")).await.unwrap();

        let (new, _) = storage.open("partition", b"blob").await.unwrap();
        new.write_at(0, b"new").await.unwrap();
        new.sync().await.unwrap();
        drop(old);
        drop(new);
        storage.simulate_crash(|| u64::MAX);

        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 3);
        assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"new");
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
            .apply_batch(vec![
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

        storage.simulate_crash(|| u64::MAX);
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
    async fn test_apply_batch_update_is_atomic_and_durable() {
        let storage = Storage::new(test_pool());
        let (updated, _) = storage.open("batch_update", b"updated").await.unwrap();
        updated.write_at(0, b"abcdefghij").await.unwrap();
        let (removed, _) = storage.open("batch_update", b"removed").await.unwrap();
        removed.write_at_sync(0, b"remove me").await.unwrap();

        storage
            .apply_batch(vec![
                BatchOperation::Remove(RemoveTarget::Blob {
                    partition: "batch_update".into(),
                    name: b"removed".to_vec(),
                }),
                update(&updated, 3, b"XYZ", 8),
            ])
            .await
            .unwrap();

        assert_eq!(updated.read_at(0, 8).await.unwrap().coalesce(), b"abcXYZgh");
        assert!(updated.read_at(8, 1).await.is_err());
        assert_eq!(
            storage.scan("batch_update").await.unwrap(),
            vec![b"updated".to_vec()]
        );

        drop((updated, removed));
        storage.simulate_crash(|| 0);

        let (updated, len) = storage.open("batch_update", b"updated").await.unwrap();
        assert_eq!(len, 8);
        assert_eq!(updated.read_at(0, 8).await.unwrap().coalesce(), b"abcXYZgh");
        assert_eq!(
            storage.scan("batch_update").await.unwrap(),
            vec![b"updated".to_vec()]
        );
    }

    #[tokio::test]
    async fn test_apply_batch_update_validates_ranges_before_mutation() {
        let storage = Storage::new(test_pool());
        let (updated, _) = storage
            .open("batch_update_validation", b"updated")
            .await
            .unwrap();
        updated.write_at_sync(0, b"stable").await.unwrap();
        let (victim, _) = storage
            .open("batch_update_validation", b"victim")
            .await
            .unwrap();
        victim.write_at_sync(0, b"keep").await.unwrap();

        let removal = || {
            BatchOperation::Remove(RemoveTarget::Blob {
                partition: "batch_update_validation".into(),
                name: b"victim".to_vec(),
            })
        };

        let result = storage
            .apply_batch(vec![removal(), update(&updated, u64::MAX, b"X", u64::MAX)])
            .await;
        assert!(matches!(result, Err(crate::Error::OffsetOverflow)));

        let result = storage
            .apply_batch(vec![removal(), update(&updated, 4, b"XY", 5)])
            .await;
        assert_invalid_batch(result);

        let result = storage
            .apply_batch(vec![removal(), update(&updated, 0, b"", u64::MAX)])
            .await;
        assert!(matches!(result, Err(crate::Error::OffsetOverflow)));

        assert_eq!(updated.read_at(0, 6).await.unwrap().coalesce(), b"stable");
        assert_eq!(victim.read_at(0, 4).await.unwrap().coalesce(), b"keep");
        assert_eq!(
            storage.scan("batch_update_validation").await.unwrap(),
            vec![b"updated".to_vec(), b"victim".to_vec()]
        );
    }

    #[tokio::test]
    async fn test_apply_batch_update_duplicates_and_conflicts() {
        let storage = Storage::new(test_pool());
        let (duplicate, _) = storage
            .open("batch_update_duplicate", b"blob")
            .await
            .unwrap();
        duplicate.write_at_sync(0, b"abcdef").await.unwrap();

        storage
            .apply_batch(vec![
                update(&duplicate, 1, b"ZZ", 6),
                update(&duplicate, 1, b"ZZ", 6),
            ])
            .await
            .unwrap();
        assert_eq!(duplicate.read_at(0, 6).await.unwrap().coalesce(), b"aZZdef");

        let (conflicted, _) = storage
            .open("batch_update_conflict", b"blob")
            .await
            .unwrap();
        conflicted.write_at_sync(0, b"abcdef").await.unwrap();
        let (victim, _) = storage
            .open("batch_update_conflict_victim", b"victim")
            .await
            .unwrap();
        victim.write_at_sync(0, b"keep").await.unwrap();

        let removal = || {
            BatchOperation::Remove(RemoveTarget::Blob {
                partition: "batch_update_conflict_victim".into(),
                name: b"victim".to_vec(),
            })
        };
        let remove_blob = || {
            BatchOperation::Remove(RemoveTarget::Blob {
                partition: "batch_update_conflict".into(),
                name: b"blob".to_vec(),
            })
        };
        let remove_partition =
            || BatchOperation::Remove(RemoveTarget::Partition("batch_update_conflict".into()));
        let resize = || BatchOperation::Resize {
            blob: conflicted.clone(),
            len: 6,
        };

        for conflict in [
            [
                update(&conflicted, 1, b"XX", 6),
                update(&conflicted, 1, b"YY", 6),
            ],
            [
                update(&conflicted, 1, b"XX", 6),
                update(&conflicted, 2, b"XX", 6),
            ],
            [
                update(&conflicted, 1, b"XX", 6),
                update(&conflicted, 1, b"XX", 5),
            ],
            [resize(), update(&conflicted, 1, b"XX", 6)],
            [update(&conflicted, 1, b"XX", 6), resize()],
            [remove_blob(), update(&conflicted, 1, b"XX", 6)],
            [update(&conflicted, 1, b"XX", 6), remove_blob()],
            [remove_partition(), update(&conflicted, 1, b"XX", 6)],
            [update(&conflicted, 1, b"XX", 6), remove_partition()],
        ] {
            let mut operations = vec![removal()];
            operations.extend(conflict);
            assert_invalid_batch(storage.apply_batch(operations).await);
            assert_eq!(
                conflicted.read_at(0, 6).await.unwrap().coalesce(),
                b"abcdef"
            );
            assert_eq!(victim.read_at(0, 4).await.unwrap().coalesce(), b"keep");
        }
    }

    #[tokio::test]
    async fn test_apply_batch_update_validates_every_handle_before_mutation() {
        let storage = Storage::new(test_pool());
        let foreign_storage = Storage::new(test_pool());
        let (stale, _) = storage
            .open("batch_update_handle", b"shared")
            .await
            .unwrap();
        stale.write_at_sync(0, b"stale").await.unwrap();
        storage
            .apply_batch(vec![BatchOperation::Remove(RemoveTarget::Blob {
                partition: "batch_update_handle".into(),
                name: b"shared".to_vec(),
            })])
            .await
            .unwrap();

        let (current, _) = storage
            .open("batch_update_handle", b"shared")
            .await
            .unwrap();
        current.write_at_sync(0, b"current").await.unwrap();
        let (victim, _) = storage
            .open("batch_update_handle_victim", b"victim")
            .await
            .unwrap();
        victim.write_at_sync(0, b"keep").await.unwrap();
        let (foreign, _) = foreign_storage
            .open("batch_update_handle", b"shared")
            .await
            .unwrap();
        foreign.write_at_sync(0, b"foreign").await.unwrap();

        let removal = || {
            BatchOperation::Remove(RemoveTarget::Blob {
                partition: "batch_update_handle_victim".into(),
                name: b"victim".to_vec(),
            })
        };
        for invalid in [&stale, &foreign] {
            let result = storage
                .apply_batch(vec![
                    removal(),
                    update(&current, 0, b"updated", 7),
                    update(invalid, 0, b"updated", 7),
                ])
                .await;
            assert!(matches!(result, Err(crate::Error::BlobMissing(..))));
            assert_eq!(current.read_at(0, 7).await.unwrap().coalesce(), b"current");
            assert_eq!(victim.read_at(0, 4).await.unwrap().coalesce(), b"keep");
        }
        assert_eq!(stale.read_at(0, 5).await.unwrap().coalesce(), b"stale");
        assert_eq!(foreign.read_at(0, 7).await.unwrap().coalesce(), b"foreign");
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
    async fn test_crash_can_preserve_write_extent_without_bytes() {
        let storage = Storage::new(test_pool());
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(4, b"X").await.unwrap();
        drop(blob);

        // Retain only the write's extent (bit 2), not its data bytes (mode 0).
        storage.simulate_crash(|| 0b100);

        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 5);
        assert_eq!(
            blob.read_at(0, 5).await.unwrap().coalesce().as_ref(),
            &[0; 5]
        );
    }

    #[tokio::test]
    async fn test_crash_rejects_write_that_passed_initial_epoch_check() {
        let storage = Storage::new(test_pool());
        let (escaped, _) = storage.open("partition", b"blob").await.unwrap();
        escaped.write_at(0, b"safe").await.unwrap();
        escaped.sync().await.unwrap();

        let checked_epoch = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        let writer = std::thread::spawn({
            let checked_epoch = checked_epoch.clone();
            let resume = resume.clone();
            move || {
                futures::executor::block_on(escaped.write_at(
                    0,
                    Paused {
                        checked_epoch,
                        resume,
                        value: IoBufs::from(&b"stale"[..]),
                    },
                ))
            }
        });

        // The escaped handle has passed write_at's initial epoch check. Crash before it can record
        // the mutation, then let it acquire the recovery lock with its now-stale epoch.
        checked_epoch.wait();
        storage.simulate_crash(|| 0);
        resume.wait();

        assert!(matches!(
            writer.join().unwrap(),
            Err(crate::Error::BlobMissing(..))
        ));
        let (recovered, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 4);
        assert_eq!(recovered.read_at(0, 4).await.unwrap().coalesce(), b"safe");
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
