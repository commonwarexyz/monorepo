use super::{Header, Layout};
use crate::{
    BatchOperation, Buf, BufferPool, Handle, IoBufs, IoBufsMut, RemoveTarget, WriteOptions,
    deterministic::AuditHasher,
};
use commonware_formatting::hex;
use commonware_utils::sync::{Mutex, RwLock};
use std::{
    collections::BTreeMap,
    ops::RangeInclusive,
    sync::{Arc, Weak},
};

type BlobKey = (String, Vec<u8>);

struct V2State {
    logical_len: u64,
    committed_len: u64,
    dirty: bool,
    poisoned: bool,
}

impl V2State {
    const fn new(logical_len: u64) -> Self {
        Self {
            logical_len,
            committed_len: logical_len,
            dirty: false,
            poisoned: false,
        }
    }

    fn ensure_available(&self) -> Result<(), crate::Error> {
        if self.poisoned {
            return Err(std::io::Error::other("atomic blob is poisoned").into());
        }
        Ok(())
    }
}

struct V2Live {
    content: Arc<RwLock<Vec<u8>>>,
    state: Mutex<V2State>,
}

impl V2Live {
    fn new(content: Vec<u8>, logical_len: u64) -> Self {
        Self {
            content: Arc::new(RwLock::new(content)),
            state: Mutex::new(V2State::new(logical_len)),
        }
    }
}

struct V2Generation {
    generation: u64,
    live: Weak<V2Live>,
}

fn atomic_layout_required(partition: &str, name: &[u8]) -> crate::Error {
    crate::Error::BlobOpenFailed(
        partition.into(),
        hex(name),
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "blob was not created with atomic storage",
        )
        .into(),
    )
}

#[derive(Default)]
struct Namespace {
    next_generation: u64,
    generations: BTreeMap<BlobKey, u64>,
    v2_generations: BTreeMap<BlobKey, V2Generation>,
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
        self.v2_generations.remove(key);
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

    fn open_versioned_inner(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
        require_atomic: bool,
    ) -> Result<(Blob, u64, u16), crate::Error> {
        super::validate_partition_name(partition)?;

        let key = (partition.to_string(), name.to_vec());
        let mut namespace = self.namespace.lock();
        let mut partitions = self.partitions.lock();
        let partition_entry = partitions.entry(partition.into()).or_default();
        let durable_content = partition_entry.entry(name.into()).or_default();

        let existing = resolve_header(durable_content, &versions, partition, name)?;
        let (logical_size, blob_version, data_offset, is_v2) = match existing {
            Some((logical_size, blob_version, data_offset)) => {
                let is_v2 = data_offset == Layout::V2.data_offset();
                if require_atomic && !is_v2 {
                    return Err(atomic_layout_required(partition, name));
                }
                // The memory backend snapshots V2 content directly. Its durable length is the
                // snapshotted payload length, while the shared V2 header only identifies the
                // layout.
                let logical_size = if is_v2 {
                    u64::try_from(durable_content.len())
                        .map_err(|_| crate::Error::OffsetOverflow)?
                        .checked_sub(data_offset)
                        .ok_or_else(|| {
                            crate::Error::BlobCorrupt(
                                partition.into(),
                                hex(name),
                                "atomic blob is shorter than its header".into(),
                            )
                        })?
                } else {
                    logical_size
                };
                (logical_size, blob_version, data_offset, is_v2)
            }
            None => {
                let (region, blob_version) = if require_atomic {
                    Header::create_atomic(&versions)
                } else {
                    Header::create(&versions)
                };
                let data_offset = region.len() as u64;
                durable_content.clear();
                durable_content.extend_from_slice(&region);
                (0, blob_version, data_offset, require_atomic)
            }
        };
        let generation = namespace.generation(&key);
        let (content, v2) = if is_v2 {
            let live = namespace
                .v2_generations
                .get(&key)
                .filter(|entry| entry.generation == generation)
                .and_then(|entry| entry.live.upgrade());
            let live = live.unwrap_or_else(|| {
                let live = Arc::new(V2Live::new(durable_content.clone(), logical_size));
                namespace.v2_generations.insert(
                    key,
                    V2Generation {
                        generation,
                        live: Arc::downgrade(&live),
                    },
                );
                live
            });
            (live.content.clone(), Some(live))
        } else {
            (Arc::new(RwLock::new(durable_content.clone())), None)
        };
        drop(partitions);
        drop(namespace);
        let logical_size = match &v2 {
            Some(live) => {
                let state = live.state.lock();
                state.ensure_available()?;
                state.logical_len
            }
            None => logical_size,
        };

        Ok((
            Blob {
                partitions: self.partitions.clone(),
                namespace: self.namespace.clone(),
                partition: partition.into(),
                name: name.into(),
                content,
                v2,
                pool: self.pool.clone(),
                data_offset,
                generation,
            },
            logical_size,
            blob_version,
        ))
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
        self.open_versioned_inner(partition, name, versions, false)
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), crate::Error> {
        super::validate_partition_name(partition)?;

        let mut namespace = self.namespace.lock();
        let mut partitions = self.partitions.lock();
        match name {
            Some(name) => {
                partitions
                    .get_mut(partition)
                    .ok_or(crate::Error::PartitionMissing(partition.into()))?
                    .remove(name)
                    .ok_or(crate::Error::BlobMissing(partition.into(), hex(name)))?;
                namespace.remove(&(partition.to_string(), name.to_vec()));
            }
            None => {
                partitions
                    .remove(partition)
                    .ok_or(crate::Error::PartitionMissing(partition.into()))?;
                namespace
                    .generations
                    .retain(|(candidate, _), _| candidate != partition);
                namespace
                    .v2_generations
                    .retain(|(candidate, _), _| candidate != partition);
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

impl crate::AtomicStorage for Storage {
    type AtomicBlob = Blob;

    async fn open_atomic_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::AtomicBlob, u64, u16), crate::Error> {
        self.open_versioned_inner(partition, name, versions, true)
    }
}

impl crate::BatchStorage for Storage {
    async fn start_apply(
        &self,
        operations: Vec<BatchOperation<Self::AtomicBlob>>,
    ) -> Result<Handle<()>, crate::Error> {
        let mut operation_blobs = BTreeMap::<BlobKey, Vec<&Blob>>::new();
        for operation in &operations {
            let blob = match operation {
                BatchOperation::Remove(blob) | BatchOperation::Publish(blob) => blob,
                BatchOperation::Rewind { blob, .. } => blob,
            };
            if !self.owns(blob) {
                return Err(crate::Error::BlobMissing(
                    blob.partition.clone(),
                    hex(&blob.name),
                ));
            }
            if blob.v2.is_none() {
                return Err(atomic_layout_required(&blob.partition, &blob.name));
            }
            operation_blobs
                .entry((blob.partition.clone(), blob.name.clone()))
                .or_default()
                .push(blob);
        }
        let operations = super::batch::canonicalize_descriptors(&operations, |blob| {
            (blob.partition.clone(), blob.name.clone())
        })?;
        let participants = operations
            .iter()
            .map(|operation| {
                let (partition, name) = match operation {
                    super::batch::Operation::Remove(RemoveTarget::Blob { partition, name })
                    | super::batch::Operation::Publish { partition, name }
                    | super::batch::Operation::Rewind {
                        partition, name, ..
                    } => (partition, name),
                    super::batch::Operation::Remove(RemoveTarget::Partition(_)) => {
                        unreachable!("blob handles cannot describe partition removals")
                    }
                };
                (
                    operation,
                    operation_blobs
                        .get(&(partition.clone(), name.clone()))
                        .expect("canonical operation must retain its blob handles"),
                )
            })
            .collect::<Vec<_>>();

        // Every V2 operation locks state before content. Extending that order across blobs in
        // canonical namespace order prevents concurrent batches from deadlocking.
        let mut states = Vec::with_capacity(participants.len());
        let mut contents = Vec::with_capacity(participants.len());
        for (_, blobs) in &participants {
            let live = blobs[0]
                .v2
                .as_ref()
                .expect("validated batch mutation must use an atomic blob");
            for blob in blobs.iter().skip(1) {
                let duplicate = blob
                    .v2
                    .as_ref()
                    .expect("validated batch mutation must use an atomic blob");
                if !Arc::ptr_eq(live, duplicate) {
                    return Err(crate::Error::BlobMissing(
                        blob.partition.clone(),
                        hex(&blob.name),
                    ));
                }
            }
            states.push(live.state.lock());
            contents.push(live.content.write());
        }

        let mut namespace = self.namespace.lock();
        for (_, blobs) in &participants {
            for blob in blobs.iter() {
                let key = (blob.partition.clone(), blob.name.clone());
                blob.ensure_current(&namespace, &key)?;
            }
        }

        let mut partitions = self.partitions.lock();
        let mut final_lengths = Vec::with_capacity(participants.len());
        for (index, (operation, blobs)) in participants.iter().enumerate() {
            let blob = &blobs[0];
            let state = &mut states[index];
            state.ensure_available()?;
            if matches!(operation, super::batch::Operation::Remove(_)) {
                partitions
                    .get(&blob.partition)
                    .and_then(|partition| partition.get(&blob.name))
                    .ok_or_else(|| {
                        crate::Error::BlobMissing(blob.partition.clone(), hex(&blob.name))
                    })?;
                final_lengths.push(None);
                continue;
            }
            let content = &mut contents[index];
            blob.validate_v2_content(state, content)?;
            let logical_len = match operation {
                super::batch::Operation::Publish { .. } => state.logical_len,
                super::batch::Operation::Rewind { len, .. } => {
                    if *len > state.logical_len {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "atomic rewind cannot extend a blob",
                        )
                        .into());
                    }
                    *len
                }
                super::batch::Operation::Remove(_) => {
                    unreachable!("removals skip publication validation")
                }
            };
            let physical_len = blob.physical_len(logical_len)?;
            Blob::reserve_v2(content, physical_len)?;
            let durable = partitions
                .get_mut(&blob.partition)
                .and_then(|partition| partition.get_mut(&blob.name))
                .ok_or_else(|| {
                    crate::Error::BlobMissing(blob.partition.clone(), hex(&blob.name))
                })?;
            Blob::reserve_v2(durable, physical_len)?;
            final_lengths.push(Some((logical_len, physical_len)));
        }

        // All fallible work is complete. The held blob, namespace, and partition locks make the
        // following publication and namespace changes one logical and durable memory transaction.
        for (index, (_, blobs)) in participants.iter().enumerate() {
            let Some((logical_len, physical_len)) = final_lengths[index] else {
                continue;
            };
            let blob = &blobs[0];
            let state = &mut states[index];
            let content = &mut contents[index];
            content.resize(physical_len, 0);
            let durable = partitions
                .get_mut(&blob.partition)
                .and_then(|partition| partition.get_mut(&blob.name))
                .expect("validated mutated blob must exist");
            durable.resize(physical_len, 0);
            durable.copy_from_slice(content);
            state.logical_len = logical_len;
            state.committed_len = logical_len;
            state.dirty = false;
        }

        for operation in &operations {
            match operation {
                super::batch::Operation::Remove(RemoveTarget::Blob { partition, name }) => {
                    if let Some(blobs) = partitions.get_mut(partition) {
                        blobs.remove(name);
                    }
                    namespace.remove(&(partition.clone(), name.clone()));
                }
                super::batch::Operation::Publish { .. }
                | super::batch::Operation::Rewind { .. } => {}
                super::batch::Operation::Remove(RemoveTarget::Partition(_)) => {
                    unreachable!("blob handles cannot describe partition removals")
                }
            }
        }
        Ok(Handle::ready(Ok(())))
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
    v2: Option<Arc<V2Live>>,
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

    fn physical_len(&self, logical_len: u64) -> Result<usize, crate::Error> {
        logical_len
            .checked_add(self.data_offset)
            .ok_or(crate::Error::OffsetOverflow)?
            .try_into()
            .map_err(|_| crate::Error::OffsetOverflow)
    }

    fn validate_v2_content(&self, state: &mut V2State, content: &[u8]) -> Result<(), crate::Error> {
        let expected = match self.physical_len(state.logical_len) {
            Ok(expected) => expected,
            Err(error) => {
                state.poisoned = true;
                return Err(error);
            }
        };
        if content.len() == expected {
            return Ok(());
        }
        state.poisoned = true;
        Err(crate::Error::BlobCorrupt(
            self.partition.clone(),
            hex(&self.name),
            "atomic blob length does not match its live state".into(),
        ))
    }

    fn reserve_v2(content: &mut Vec<u8>, required: usize) -> Result<(), crate::Error> {
        content
            .try_reserve(required.saturating_sub(content.len()))
            .map_err(|_| crate::Error::WriteFailed)
    }

    fn write_v2_payload(
        content: &mut [u8],
        offset: usize,
        data: &IoBufs,
    ) -> Result<(), crate::Error> {
        let mut cursor = offset;
        let mut result = Ok(());
        data.for_each_chunk(|chunk| {
            if result.is_err() {
                return;
            }
            let Some(end) = cursor.checked_add(chunk.len()) else {
                result = Err(crate::Error::OffsetOverflow);
                return;
            };
            let Some(destination) = content.get_mut(cursor..end) else {
                result = Err(crate::Error::WriteFailed);
                return;
            };
            destination.copy_from_slice(chunk);
            cursor = end;
        });
        result
    }

    fn append_v2(
        &self,
        live: &V2Live,
        data: IoBufs,
        expected_offset: Option<u64>,
    ) -> Result<u64, crate::Error> {
        let mut state = live.state.lock();
        state.ensure_available()?;
        let offset = state.logical_len;
        if data.is_empty() {
            return Ok(offset);
        }
        if expected_offset.is_some_and(|expected| expected != offset) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "atomic writes must append at the current logical tail",
            )
            .into());
        }
        if offset < state.committed_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "atomic append requires syncing the committed rewind first",
            )
            .into());
        }

        let mut content = live.content.write();
        self.validate_v2_content(&mut state, &content)?;
        let data_len = u64::try_from(data.len()).map_err(|_| crate::Error::OffsetOverflow)?;
        let logical_end = offset
            .checked_add(data_len)
            .ok_or(crate::Error::OffsetOverflow)?;
        let start = self.physical_len(offset)?;
        let required = self.physical_len(logical_end)?;
        Self::reserve_v2(&mut content, required)?;
        content.resize(required, 0);
        if let Err(error) = Self::write_v2_payload(&mut content, start, &data) {
            state.poisoned = true;
            return Err(error);
        }
        state.logical_len = logical_end;
        state.dirty = true;
        Ok(offset)
    }

    fn rewind_v2(&self, live: &V2Live, len: u64) -> Result<(), crate::Error> {
        let mut state = live.state.lock();
        state.ensure_available()?;
        let mut content = live.content.write();
        self.validate_v2_content(&mut state, &content)?;
        if len > state.logical_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "atomic rewind cannot extend a blob",
            )
            .into());
        }
        if len == state.logical_len {
            return Ok(());
        }
        let required = self.physical_len(len)?;
        content.resize(required, 0);
        state.logical_len = len;
        state.dirty = len != state.committed_len;
        Ok(())
    }

    fn sync_v2(&self, live: &V2Live) -> Result<(), crate::Error> {
        let mut state = live.state.lock();
        state.ensure_available()?;
        let live_content = live.content.read();
        self.validate_v2_content(&mut state, &live_content)?;

        let key = (self.partition.clone(), self.name.clone());
        let namespace = self.namespace.lock();
        self.ensure_current(&namespace, &key)?;
        let mut partitions = self.partitions.lock();
        let partition = partitions
            .get_mut(&self.partition)
            .ok_or(crate::Error::PartitionMissing(self.partition.clone()))?;
        let durable_content = partition
            .get_mut(&self.name)
            .ok_or(crate::Error::BlobMissing(
                self.partition.clone(),
                hex(&self.name),
            ))?;
        if state.dirty {
            Self::reserve_v2(durable_content, live_content.len())?;
            durable_content.clone_from(&live_content);
            state.committed_len = state.logical_len;
            state.dirty = false;
        }
        Ok(())
    }

    fn sync_inner(&self) -> Result<(), crate::Error> {
        if let Some(live) = &self.v2 {
            return self.sync_v2(live);
        }

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
        if let Some(live) = &self.v2 {
            let len_u64 = u64::try_from(len).map_err(|_| crate::Error::OffsetOverflow)?;
            let logical_end = offset
                .checked_add(len_u64)
                .ok_or(crate::Error::OffsetOverflow)?;
            let mut state = live.state.lock();
            state.ensure_available()?;
            if logical_end > state.logical_len {
                return Err(crate::Error::BlobInsufficientLength);
            }
            let start = self.physical_len(offset)?;
            let end = start.checked_add(len).ok_or(crate::Error::OffsetOverflow)?;
            let content = live.content.read();
            self.validate_v2_content(&mut state, &content)?;
            bufs.copy_from_slice(
                content
                    .get(start..end)
                    .ok_or(crate::Error::BlobInsufficientLength)?,
            );
            return Ok(bufs);
        }
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
        options: WriteOptions,
    ) -> Result<(), crate::Error> {
        let bufs = bufs.into();
        let sync = options.contains(WriteOptions::SYNC);
        if !bufs.has_remaining() && (self.v2.is_some() || sync) {
            return Ok(());
        }
        if let Some(live) = &self.v2 {
            self.append_v2(live, bufs, Some(offset))?;
            return if sync { self.sync_v2(live) } else { Ok(()) };
        }
        let buf = bufs.coalesce();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(crate::Error::OffsetOverflow)?;
        let offset: usize = offset
            .try_into()
            .map_err(|_| crate::Error::OffsetOverflow)?;
        {
            let mut content = self.content.write();
            let required = offset
                .checked_add(buf.len())
                .ok_or(crate::Error::OffsetOverflow)?;
            if required > content.len() {
                content.resize(required, 0);
            }
            content[offset..offset + buf.len()].copy_from_slice(buf.as_ref());
        }
        if sync { self.sync_inner() } else { Ok(()) }
    }

    async fn resize(&self, len: u64) -> Result<(), crate::Error> {
        if let Some(live) = &self.v2 {
            return self.rewind_v2(live, len);
        }
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

impl crate::AtomicBlob for Blob {
    async fn append(&self, data: impl Into<IoBufs> + Send) -> Result<u64, crate::Error> {
        let Some(live) = &self.v2 else {
            return Err(atomic_layout_required(&self.partition, &self.name));
        };
        self.append_v2(live, data.into(), None)
    }

    async fn rewind(&self, len: u64) -> Result<(), crate::Error> {
        let Some(live) = &self.v2 else {
            return Err(atomic_layout_required(&self.partition, &self.name));
        };
        self.rewind_v2(live, len)
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, *};
    use crate::{
        AtomicBlob as _, AtomicStorage as _, BatchStorage as _, Blob, BufferPoolConfig,
        Storage as _,
        storage::{
            Layout,
            tests::{
                run_atomic_blob_tests, run_batch_storage_tests, run_storage_foreign_handle_test,
                run_storage_tests,
            },
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
        run_storage_tests(storage.clone()).await;
        run_batch_storage_tests(storage.clone()).await;
        let (atomic, _) = storage
            .open_atomic("atomic_storage", b"blob")
            .await
            .unwrap();
        run_atomic_blob_tests(atomic).await;

        let foreign = Storage::new(test_pool());
        run_storage_foreign_handle_test(&tested, &foreign).await;
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
    async fn test_atomic_live_generation_and_durability() {
        let storage = Storage::new(test_pool());
        let (first, _) = storage.open_atomic("atomic", b"blob").await.unwrap();
        let (second, _) = storage.open("atomic", b"blob").await.unwrap();
        assert!(Arc::ptr_eq(&first.content, &second.content));
        assert!(Arc::ptr_eq(
            first.v2.as_ref().unwrap(),
            second.v2.as_ref().unwrap()
        ));

        assert_eq!(first.append(b"abcdef").await.unwrap(), 0);
        assert_eq!(second.read_at(0, 6).await.unwrap().coalesce(), b"abcdef");
        second.resize(4).await.unwrap();
        assert_eq!(first.read_at(0, 4).await.unwrap().coalesce(), b"abcd");
        first
            .write_at(4, b"z", WriteOptions::default())
            .await
            .unwrap();
        assert_eq!(second.read_at(0, 5).await.unwrap().coalesce(), b"abcdz");

        first.rewind(0).await.unwrap();
        assert_eq!(first.append(b"old").await.unwrap(), 0);
        second.sync().await.unwrap();
        assert_eq!(first.append(b" pending").await.unwrap(), 3);
        let dropped = Arc::downgrade(first.v2.as_ref().unwrap());
        drop((first, second));
        assert!(dropped.upgrade().is_none());

        let (reopened, len) = storage.open_atomic("atomic", b"blob").await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(reopened.read_at(0, 3).await.unwrap().coalesce(), b"old");
        reopened
            .write_at(3, b"!", WriteOptions::SYNC)
            .await
            .unwrap();
        drop(reopened);

        let (reopened, len) = storage.open_atomic("atomic", b"blob").await.unwrap();
        assert_eq!(len, 4);
        assert_eq!(reopened.read_at(0, 4).await.unwrap().coalesce(), b"old!");
        let partitions = storage.partitions.lock();
        let raw = partitions
            .get("atomic")
            .unwrap()
            .get(b"blob".as_slice())
            .unwrap();
        let data_offset = Layout::V2.data_offset() as usize;
        assert_eq!(raw.len(), data_offset + 4);
        assert_eq!(&raw[data_offset..], b"old!");
    }

    #[tokio::test]
    async fn test_atomic_committed_rewind_fences_append_until_sync() {
        let storage = Storage::new(test_pool());
        let (blob, _) = storage.open_atomic("atomic_fence", b"blob").await.unwrap();
        blob.append(b"abcdef").await.unwrap();
        blob.sync().await.unwrap();

        blob.rewind(4).await.unwrap();
        assert!(matches!(blob.append(b"z").await, Err(crate::Error::Io(_))));
        assert!(matches!(
            blob.write_at(4, b"z", WriteOptions::default()).await,
            Err(crate::Error::Io(_))
        ));
        assert!(matches!(blob.resize(5).await, Err(crate::Error::Io(_))));
        assert_eq!(blob.read_at(0, 4).await.unwrap().coalesce(), b"abcd");

        blob.sync().await.unwrap();
        assert_eq!(blob.append(b"z").await.unwrap(), 4);
        assert_eq!(blob.read_at(0, 5).await.unwrap().coalesce(), b"abcdz");
    }

    #[tokio::test]
    async fn test_atomic_remove_recreate_rotates_live_generation() {
        let storage = Storage::new(test_pool());
        let (old, _) = storage.open_atomic("atomic_remove", b"blob").await.unwrap();
        old.append(b"old").await.unwrap();

        storage
            .remove("atomic_remove", Some(b"blob"))
            .await
            .unwrap();
        let (new, len) = storage.open_atomic("atomic_remove", b"blob").await.unwrap();
        assert_eq!(len, 0);
        assert!(!Arc::ptr_eq(&old.content, &new.content));
        assert!(!Arc::ptr_eq(
            old.v2.as_ref().unwrap(),
            new.v2.as_ref().unwrap()
        ));
        assert_eq!(old.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert!(old.sync().await.is_err());
        assert_eq!(old.read_at(0, 3).await.unwrap().coalesce(), b"old");

        new.append(b"new").await.unwrap();
        new.sync().await.unwrap();
        drop((old, new));
        let (reopened, len) = storage.open_atomic("atomic_remove", b"blob").await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(reopened.read_at(0, 3).await.unwrap().coalesce(), b"new");
    }

    #[tokio::test]
    async fn test_atomic_batch_publishes_and_rewinds_live_contents() {
        let storage = Storage::new(test_pool());
        let (published, _) = storage
            .open_atomic("atomic_batch", b"published")
            .await
            .unwrap();
        let (rewound, _) = storage
            .open_atomic("atomic_batch", b"rewound")
            .await
            .unwrap();
        let (removed, _) = storage
            .open_atomic("atomic_batch_remove", b"victim")
            .await
            .unwrap();

        published.append(b"alpha-old").await.unwrap();
        rewound.append(b"bravo-old").await.unwrap();
        removed.append(b"removed-pending").await.unwrap();
        storage
            .apply(vec![
                BatchOperation::Rewind {
                    blob: rewound.clone(),
                    len: 5,
                },
                BatchOperation::Remove(removed.clone()),
                BatchOperation::Publish(published.clone()),
            ])
            .await
            .unwrap();

        assert_eq!(
            published.read_at(0, 9).await.unwrap().coalesce(),
            b"alpha-old"
        );
        assert_eq!(rewound.read_at(0, 5).await.unwrap().coalesce(), b"bravo");
        assert!(
            storage
                .scan("atomic_batch_remove")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            removed.read_at(0, 15).await.unwrap().coalesce(),
            b"removed-pending"
        );
        assert!(removed.sync().await.is_err());
        let (_, removed_len) = storage
            .open_atomic("atomic_batch_remove", b"victim")
            .await
            .unwrap();
        assert_eq!(removed_len, 0);

        // Later pending appends disappear when the live generation is dropped, proving the batch
        // durably snapshotted exactly the contents and final lengths it published.
        published.append(b"-new").await.unwrap();
        rewound.append(b"-new").await.unwrap();
        drop((published, rewound));

        let (published, published_len) = storage
            .open_atomic("atomic_batch", b"published")
            .await
            .unwrap();
        assert_eq!(published_len, 9);
        assert_eq!(
            published.read_at(0, 9).await.unwrap().coalesce(),
            b"alpha-old"
        );
        let (rewound, rewound_len) = storage
            .open_atomic("atomic_batch", b"rewound")
            .await
            .unwrap();
        assert_eq!(rewound_len, 5);
        assert_eq!(rewound.read_at(0, 5).await.unwrap().coalesce(), b"bravo");
    }

    #[tokio::test]
    async fn test_atomic_batch_rejects_non_atomic_handle_before_publication() {
        let storage = Storage::new(test_pool());
        let (published, _) = storage
            .open_atomic("atomic_batch_reject", b"published")
            .await
            .unwrap();
        published.append(b"pending").await.unwrap();
        let (ordinary, _) = storage
            .open("atomic_batch_reject", b"ordinary")
            .await
            .unwrap();
        ordinary
            .write_at(0, b"ordinary", WriteOptions::SYNC)
            .await
            .unwrap();

        let result = storage
            .apply(vec![
                BatchOperation::Publish(published.clone()),
                BatchOperation::Remove(ordinary.clone()),
            ])
            .await;
        assert!(matches!(result, Err(crate::Error::BlobOpenFailed(..))));
        assert_eq!(
            published.read_at(0, 7).await.unwrap().coalesce(),
            b"pending"
        );
        assert_eq!(
            ordinary.read_at(0, 8).await.unwrap().coalesce(),
            b"ordinary"
        );
        assert_eq!(
            storage.scan("atomic_batch_reject").await.unwrap(),
            vec![b"ordinary".to_vec(), b"published".to_vec()]
        );

        drop(published);
        let (published, len) = storage
            .open_atomic("atomic_batch_reject", b"published")
            .await
            .unwrap();
        assert_eq!(len, 0);
        assert!(published.read_at(0, 1).await.is_err());
    }

    #[tokio::test]
    async fn test_atomic_batch_rejects_extending_rewind_before_publication() {
        let storage = Storage::new(test_pool());
        let (published, _) = storage.open_atomic("a_publish", b"blob").await.unwrap();
        published.append(b"pending").await.unwrap();
        let (rewound, _) = storage.open_atomic("z_rewind", b"blob").await.unwrap();
        rewound.append(b"old").await.unwrap();
        rewound.sync().await.unwrap();

        assert!(matches!(
            storage
                .apply(vec![
                    BatchOperation::Publish(published.clone()),
                    BatchOperation::Rewind {
                        blob: rewound,
                        len: 4,
                    },
                ])
                .await,
            Err(crate::Error::Io(_))
        ));

        drop(published);
        let (published, len) = storage.open_atomic("a_publish", b"blob").await.unwrap();
        assert_eq!(len, 0);
        assert!(published.read_at(0, 1).await.is_err());
        let (rewound, len) = storage.open_atomic("z_rewind", b"blob").await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(rewound.read_at(0, 3).await.unwrap().coalesce(), b"old");
    }

    #[tokio::test]
    async fn test_apply_batch_remove_invalidates_handles_and_rotates_generations() {
        let storage = Storage::new(test_pool());
        let (old_blob, _) = storage.open_atomic("batch_blob", b"name").await.unwrap();
        old_blob.append(b"old blob").await.unwrap();
        let old_blob_generation = old_blob.generation;

        let (old_second, _) = storage.open_atomic("batch_second", b"name").await.unwrap();
        old_second.append(b"old second").await.unwrap();
        let old_second_generation = old_second.generation;

        storage
            .apply(vec![
                BatchOperation::Remove(old_blob.clone()),
                BatchOperation::Remove(old_blob.clone()),
                BatchOperation::Remove(old_second.clone()),
            ])
            .await
            .unwrap();

        assert_eq!(
            old_blob.read_at(0, 8).await.unwrap().coalesce(),
            b"old blob"
        );
        assert_eq!(
            old_second.read_at(0, 10).await.unwrap().coalesce(),
            b"old second"
        );

        let (new_blob, blob_len) = storage.open_atomic("batch_blob", b"name").await.unwrap();
        assert_eq!(blob_len, 0);
        assert_ne!(old_blob_generation, new_blob.generation);
        new_blob.append(b"new blob").await.unwrap();
        new_blob.sync().await.unwrap();

        let (new_second, second_len) = storage.open_atomic("batch_second", b"name").await.unwrap();
        assert_eq!(second_len, 0);
        assert_ne!(old_second_generation, new_second.generation);
        new_second.append(b"new second").await.unwrap();
        new_second.sync().await.unwrap();

        assert!(old_blob.sync().await.is_err());
        assert!(old_second.sync().await.is_err());
        drop((old_blob, old_second, new_blob, new_second));

        let (blob, blob_len) = storage.open_atomic("batch_blob", b"name").await.unwrap();
        assert_eq!(blob_len, 8);
        assert_eq!(blob.read_at(0, 8).await.unwrap().coalesce(), b"new blob");
        let (second, second_len) = storage.open_atomic("batch_second", b"name").await.unwrap();
        assert_eq!(second_len, 10);
        assert_eq!(
            second.read_at(0, 10).await.unwrap().coalesce(),
            b"new second"
        );
    }

    #[tokio::test]
    async fn test_atomic_batch_remove_rejects_stale_duplicate() {
        let storage = Storage::new(test_pool());
        let (old, _) = storage.open_atomic("batch_stale", b"name").await.unwrap();
        old.append(b"old").await.unwrap();
        old.sync().await.unwrap();
        storage
            .apply(vec![BatchOperation::Remove(old.clone())])
            .await
            .unwrap();

        let (current, _) = storage.open_atomic("batch_stale", b"name").await.unwrap();
        current.append(b"current").await.unwrap();
        current.sync().await.unwrap();

        assert!(matches!(
            storage
                .apply(vec![
                    BatchOperation::Remove(current.clone()),
                    BatchOperation::Remove(old.clone()),
                ])
                .await,
            Err(crate::Error::BlobMissing(..))
        ));
        assert_eq!(old.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert_eq!(current.read_at(0, 7).await.unwrap().coalesce(), b"current");
        assert_eq!(
            storage.scan("batch_stale").await.unwrap(),
            vec![b"name".to_vec()]
        );
    }

    #[tokio::test]
    async fn test_atomic_batch_remove_rejects_foreign_handle() {
        let storage = Storage::new(test_pool());
        let foreign = Storage::new(test_pool());
        let (local, _) = storage.open_atomic("batch_foreign", b"name").await.unwrap();
        local.append(b"local").await.unwrap();
        local.sync().await.unwrap();
        let (foreign_blob, _) = foreign.open_atomic("batch_foreign", b"name").await.unwrap();

        assert!(matches!(
            storage
                .apply(vec![BatchOperation::Remove(foreign_blob)])
                .await,
            Err(crate::Error::BlobMissing(..))
        ));
        assert_eq!(local.read_at(0, 5).await.unwrap().coalesce(), b"local");
        assert_eq!(
            storage.scan("batch_foreign").await.unwrap(),
            vec![b"name".to_vec()]
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
