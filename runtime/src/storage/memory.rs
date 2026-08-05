use super::{Header, preflush, uno};
use crate::{
    ATOMIC_BLOB_TAG_LEN, BatchOperation, Buf, BufferPool, Error, Handle, IntegrityAppend,
    IntegrityBoundary, IntegrityScheme, IntegritySnapshot, IntegrityToken, IntegrityUnit, IoBufs,
    IoBufsMut, RemoveTarget, WriteOptions, deterministic::AuditHasher,
};
use commonware_formatting::hex;
use commonware_utils::sync::{Mutex, RwLock};
use std::{
    collections::BTreeMap,
    future::Future,
    ops::RangeInclusive,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

type BlobKey = (String, Vec<u8>);
type Partition = BTreeMap<Vec<u8>, Vec<u8>>;
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(test)]
#[derive(Clone)]
struct BatchHook {
    entered: Arc<std::sync::Barrier>,
    resume: Arc<std::sync::Barrier>,
}

/// The ordinary backing blob reserves one page for UNO's two root slots.
const UNO_ROOT_PAGE_LEN: usize = 4096;

/// Memory blob operations complete on their first poll. Keeping the driver inline preserves the
/// backend's synchronous snapshot boundary without depending on an ambient runtime.
fn drive_ready<F: Future>(future: F) -> Result<F::Output, Error> {
    let mut future = std::pin::pin!(future);
    let waker = futures::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => Ok(output),
        Poll::Pending => Err(Error::Closed),
    }
}

fn atomic_read_at_buf(
    atomic: &uno::AtomicBlob<Blob, Publisher>,
    offset: u64,
    len: usize,
    bufs: IoBufsMut,
) -> BoxFuture<'_, Result<IoBufsMut, Error>> {
    Box::pin(crate::Blob::read_at_buf(atomic, offset, len, bufs))
}

fn atomic_write_at_with_options(
    atomic: &uno::AtomicBlob<Blob, Publisher>,
    offset: u64,
    bufs: IoBufs,
    options: WriteOptions,
) -> BoxFuture<'_, Result<(), Error>> {
    Box::pin(crate::Blob::write_at_with_options(
        atomic, offset, bufs, options,
    ))
}

fn atomic_resize(
    atomic: &uno::AtomicBlob<Blob, Publisher>,
    len: u64,
) -> BoxFuture<'_, Result<(), Error>> {
    Box::pin(crate::Blob::resize(atomic, len))
}

fn atomic_sync(atomic: &uno::AtomicBlob<Blob, Publisher>) -> BoxFuture<'_, Result<(), Error>> {
    Box::pin(crate::Blob::sync(atomic))
}

fn atomic_start_sync(atomic: &uno::AtomicBlob<Blob, Publisher>) -> BoxFuture<'_, Handle<()>> {
    Box::pin(crate::Blob::start_sync(atomic))
}

struct AtomicGeneration {
    generation: u64,
    live: Weak<uno::Core<Blob>>,
}

fn atomic_layout_required(partition: &str, name: &[u8]) -> Error {
    Error::BlobOpenFailed(
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
    atomic_generations: BTreeMap<BlobKey, AtomicGeneration>,
    #[cfg(test)]
    durability_snapshots: usize,
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
        self.atomic_generations.remove(key);
    }

    const fn record_durability_snapshot(&mut self) {
        #[cfg(test)]
        {
            self.durability_snapshots += 1;
        }
    }
}

/// Resolves a blob's header from its full contents (see super::header::resolve).
fn resolve_header(
    content: &[u8],
    versions: &RangeInclusive<u16>,
    partition: &str,
    name: &[u8],
) -> Result<Option<(u64, u16, u64)>, Error> {
    let raw = &content[..Header::resolve_len(content.len() as u64)];
    super::header::resolve(raw, content.len() as u64, versions, partition, name)
}

/// In-memory storage implementation for the commonware runtime.
#[derive(Clone)]
pub struct Storage {
    partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
    namespace: Arc<Mutex<Namespace>>,
    #[cfg(test)]
    batch_hook: Arc<Mutex<Option<BatchHook>>>,
    pool: BufferPool,
}

impl Storage {
    pub fn new(pool: BufferPool) -> Self {
        Self {
            partitions: Arc::new(Mutex::new(BTreeMap::new())),
            namespace: Arc::new(Mutex::new(Namespace::default())),
            #[cfg(test)]
            batch_hook: Arc::new(Mutex::new(None)),
            pool,
        }
    }

    #[cfg(test)]
    fn pause_batch_once(&self) {
        let Some(hook) = self.batch_hook.lock().take() else {
            return;
        };
        hook.entered.wait();
        hook.resume.wait();
    }

    fn owns(&self, blob: &Blob) -> bool {
        Arc::ptr_eq(&self.partitions, &blob.partitions)
            && Arc::ptr_eq(&self.namespace, &blob.namespace)
    }

    fn owns_atomic(&self, blob: &AtomicBlob) -> bool {
        self.owns(blob.backing())
    }

    fn is_atomic_name(&self, partition: &str, name: &[u8]) -> bool {
        let key = (partition.to_string(), name.to_vec());
        let namespace = self.namespace.lock();
        namespace.generations.get(&key).is_some_and(|generation| {
            namespace
                .atomic_generations
                .get(&key)
                .is_some_and(|entry| entry.generation == *generation)
        })
    }

    fn open_versioned_inner(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Blob, u64, u16), Error> {
        super::validate_partition_name(partition)?;

        let key = (partition.to_string(), name.to_vec());
        let mut namespace = self.namespace.lock();
        let mut partitions = self.partitions.lock();
        let partition_entry = partitions.entry(partition.into()).or_default();
        let durable_content = partition_entry.entry(name.into()).or_default();

        let existing = resolve_header(durable_content, &versions, partition, name)?;
        let (logical_size, blob_version, data_offset) = existing.unwrap_or_else(|| {
            let (region, blob_version) = Header::create(&versions);
            let data_offset = region.len() as u64;
            durable_content.clear();
            durable_content.extend_from_slice(&region);
            (0, blob_version, data_offset)
        });
        let generation = namespace.generation(&key);
        let content = Arc::new(RwLock::new(durable_content.clone()));
        drop(partitions);
        drop(namespace);

        Ok((
            Blob {
                partitions: self.partitions.clone(),
                namespace: self.namespace.clone(),
                partition: partition.into(),
                name: name.into(),
                content,
                atomic: None,
                pool: self.pool.clone(),
                data_offset,
                generation,
            },
            logical_size,
            blob_version,
        ))
    }

    fn open_atomic_versioned_inner(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(AtomicBlob, u16), Error> {
        super::validate_partition_name(partition)?;

        let key = (partition.to_string(), name.to_vec());
        let mut namespace = self.namespace.lock();
        let mut partitions = self.partitions.lock();
        let partition_entry = partitions.entry(partition.into()).or_default();
        let durable_content = partition_entry.entry(name.into()).or_default();

        let existing = resolve_header(durable_content, &versions, partition, name)?;
        let (backing_len, blob_version, data_offset) = match existing {
            Some((backing_len, blob_version, data_offset)) => {
                let generation = namespace.generation(&key);
                let atomic = namespace
                    .atomic_generations
                    .get(&key)
                    .filter(|entry| entry.generation == generation)
                    .ok_or_else(|| atomic_layout_required(partition, name))?;
                if backing_len < UNO_ROOT_PAGE_LEN as u64 {
                    return Err(Error::BlobCorrupt(
                        partition.into(),
                        hex(name),
                        "atomic backing is shorter than its root page".into(),
                    ));
                }
                if let Some(core) = atomic.live.upgrade() {
                    let backing = core.backing().clone();
                    return Ok((
                        AtomicBlob {
                            inner: uno::AtomicBlob::new(core, Publisher::new(&backing)),
                        },
                        blob_version,
                    ));
                }
                (backing_len, blob_version, data_offset)
            }
            None => {
                let (region, blob_version) = Header::create(&versions);
                let data_offset = region.len() as u64;
                durable_content.clear();
                durable_content.extend_from_slice(&region);
                durable_content.resize(
                    region
                        .len()
                        .checked_add(UNO_ROOT_PAGE_LEN)
                        .ok_or(Error::OffsetOverflow)?,
                    0,
                );
                let generation = namespace.generation(&key);
                namespace.atomic_generations.insert(
                    key.clone(),
                    AtomicGeneration {
                        generation,
                        live: Weak::new(),
                    },
                );
                (UNO_ROOT_PAGE_LEN as u64, blob_version, data_offset)
            }
        };

        let generation = namespace.generation(&key);
        let backing = Blob {
            partitions: self.partitions.clone(),
            namespace: self.namespace.clone(),
            partition: partition.into(),
            name: name.into(),
            content: Arc::new(RwLock::new(durable_content.clone())),
            atomic: None,
            pool: self.pool.clone(),
            data_offset,
            generation,
        };
        let recovered = drive_ready(uno::Core::recover(&backing, backing_len))??;
        let state = preflush::Context::new(recovered)?;
        let core = uno::Core::new(backing.clone(), state);
        namespace
            .atomic_generations
            .get_mut(&key)
            .expect("atomic creation installs its generation")
            .live = Arc::downgrade(&core);
        drop(partitions);
        drop(namespace);

        Ok((
            AtomicBlob {
                inner: uno::AtomicBlob::new(core, Publisher::new(&backing)),
            },
            blob_version,
        ))
    }

    fn build_atomic_replacement(
        &self,
        partition: &str,
        name: &[u8],
        header: &[u8],
        payload: &[u8],
        blob_version: u16,
    ) -> Result<Vec<u8>, Error> {
        let temporary = Self::new(self.pool.clone());
        let key = (partition.to_string(), name.to_vec());
        let mut replacement = header.to_vec();
        replacement.resize(
            replacement
                .len()
                .checked_add(UNO_ROOT_PAGE_LEN)
                .ok_or(Error::OffsetOverflow)?,
            0,
        );
        temporary
            .partitions
            .lock()
            .entry(partition.into())
            .or_default()
            .insert(name.to_vec(), replacement);
        {
            let mut namespace = temporary.namespace.lock();
            let generation = namespace.generation(&key);
            namespace.atomic_generations.insert(
                key,
                AtomicGeneration {
                    generation,
                    live: Weak::new(),
                },
            );
        }

        let (atomic, version) =
            temporary.open_atomic_versioned_inner(partition, name, blob_version..=blob_version)?;
        debug_assert_eq!(version, blob_version);
        if !payload.is_empty() {
            drive_ready(crate::AtomicBlob::append(&atomic, payload.to_vec()))??;
            drive_ready(crate::Blob::sync(&atomic))??;
        }

        let partitions = temporary.partitions.lock();
        Ok(partitions
            .get(partition)
            .and_then(|blobs| blobs.get(name))
            .expect("temporary migration blob remains present")
            .clone())
    }

    /// Compute a SHA-256 digest of all blob contents.
    pub fn audit(&self) -> [u8; 32] {
        let namespace = self.namespace.lock();
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
        for (partition, name) in namespace.atomic_generations.keys() {
            hasher.update(b"atomic");
            hasher.update(partition.as_bytes());
            hasher.update(name);
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
    ) -> Result<(Self::Blob, u64, u16), Error> {
        if self.is_atomic_name(partition, name) {
            let (atomic, version) =
                self.open_atomic_versioned_inner(partition, name, versions.clone())?;
            let len = atomic.inner.lock_state().await?.logical_len();
            return Ok((Blob::from_atomic(atomic.inner), len, version));
        }
        let ordinary = self.open_versioned_inner(partition, name, versions.clone())?;
        if !self.is_atomic_name(partition, name) {
            return Ok(ordinary);
        }
        let (atomic, version) = self.open_atomic_versioned_inner(partition, name, versions)?;
        let len = atomic.inner.lock_state().await?.logical_len();
        Ok((Blob::from_atomic(atomic.inner), len, version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;

        let mut namespace = self.namespace.lock();
        let mut partitions = self.partitions.lock();
        match name {
            Some(name) => {
                partitions
                    .get_mut(partition)
                    .ok_or(Error::PartitionMissing(partition.into()))?
                    .remove(name)
                    .ok_or(Error::BlobMissing(partition.into(), hex(name)))?;
                namespace.remove(&(partition.to_string(), name.to_vec()));
            }
            None => {
                partitions
                    .remove(partition)
                    .ok_or(Error::PartitionMissing(partition.into()))?;
                namespace
                    .generations
                    .retain(|(candidate, _), _| candidate != partition);
                namespace
                    .atomic_generations
                    .retain(|(candidate, _), _| candidate != partition);
            }
        }
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        super::validate_partition_name(partition)?;

        let partitions = self.partitions.lock();
        let partition = partitions
            .get(partition)
            .ok_or(Error::PartitionMissing(partition.into()))?;
        let mut results = Vec::with_capacity(partition.len());
        for name in partition.keys() {
            results.push(name.clone());
        }
        results.sort();
        Ok(results)
    }
}

/// Private backing that coalesces the two generic direct-publication barriers into one memory
/// snapshot after the committed root and any physical rewind have both been staged.
#[derive(Clone)]
struct PublicationBlob {
    backing: Blob,
    deferred_syncs: Arc<Mutex<usize>>,
}

impl PublicationBlob {
    fn new(backing: Blob) -> Self {
        Self {
            backing,
            deferred_syncs: Arc::new(Mutex::new(2)),
        }
    }

    fn deferred_syncs(&self) -> usize {
        *self.deferred_syncs.lock()
    }

    async fn sync_inner(&self) -> Result<(), Error> {
        {
            let mut deferred_syncs = self.deferred_syncs.lock();
            if *deferred_syncs > 0 {
                *deferred_syncs -= 1;
                return Ok(());
            }
        }
        crate::Blob::sync(&self.backing).await
    }
}

impl crate::Blob for PublicationBlob {
    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        crate::Blob::read_at_buf(&self.backing, offset, len, bufs).await
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        crate::Blob::read_at(&self.backing, offset, len).await
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        self.write_at_with_options(offset, bufs, WriteOptions::default())
            .await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.write_at_with_options(offset, bufs, WriteOptions::SYNC)
            .await
    }

    async fn write_at_with_options(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let sync = options.contains(WriteOptions::SYNC);
        crate::Blob::write_at_with_options(
            &self.backing,
            offset,
            bufs,
            options.without(WriteOptions::SYNC),
        )
        .await?;
        if sync {
            self.sync_inner().await
        } else {
            Ok(())
        }
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        crate::Blob::resize(&self.backing, len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.sync_inner().await
    }

    async fn start_sync(&self) -> Handle<()> {
        Handle::ready(self.sync_inner().await)
    }
}

#[derive(Clone)]
struct Publisher {
    namespace: Arc<Mutex<Namespace>>,
    partition: String,
    name: Vec<u8>,
    generation: u64,
}

impl Publisher {
    fn new(backing: &Blob) -> Self {
        Self {
            namespace: backing.namespace.clone(),
            partition: backing.partition.clone(),
            name: backing.name.clone(),
            generation: backing.generation,
        }
    }

    fn ensure_admitted(
        &self,
        core: &Arc<uno::Core<Blob>>,
        namespace: &Namespace,
    ) -> Result<(), Error> {
        let backing = core.backing();
        let key = (self.partition.clone(), self.name.clone());
        backing.ensure_current(namespace, &key)?;
        let current = namespace
            .atomic_generations
            .get(&key)
            .filter(|entry| entry.generation == self.generation)
            .and_then(|entry| entry.live.upgrade());
        if current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, core))
        {
            Ok(())
        } else {
            Err(Error::BlobMissing(self.partition.clone(), hex(&self.name)))
        }
    }

    fn publish_snapshot(
        &self,
        core: &Arc<uno::Core<Blob>>,
        state: &mut uno::MutationGuard,
    ) -> Result<(), Error> {
        let backing = core.backing();
        let key = (backing.partition.clone(), backing.name.clone());
        let mut namespace = self.namespace.lock();
        self.ensure_admitted(core, &namespace)?;
        let mut partitions = backing.partitions.lock();
        let durable = partitions
            .get_mut(&backing.partition)
            .and_then(|partition| partition.get_mut(&backing.name))
            .ok_or_else(|| Error::BlobMissing(backing.partition.clone(), hex(&backing.name)))?;

        let mut staged_namespace = Namespace::default();
        staged_namespace.generations.insert(key, backing.generation);
        let staged_namespace = Arc::new(Mutex::new(staged_namespace));
        let staged_partitions = Arc::new(Mutex::new(BTreeMap::from([(
            backing.partition.clone(),
            BTreeMap::from([(backing.name.clone(), Vec::new())]),
        )])));
        let staged_backing = Blob {
            partitions: staged_partitions.clone(),
            namespace: staged_namespace,
            partition: backing.partition.clone(),
            name: backing.name.clone(),
            content: backing.content.clone(),
            atomic: None,
            pool: backing.pool.clone(),
            data_offset: backing.data_offset,
            generation: backing.generation,
        };
        let staged_backing = PublicationBlob::new(staged_backing);
        let staged_core = uno::Core::new(staged_backing.clone(), core.state().clone());

        drive_ready(staged_core.publish_direct(state))??;
        assert_eq!(
            staged_backing.deferred_syncs(),
            0,
            "direct publication must cross both deferred barriers"
        );
        drive_ready(crate::Blob::sync(&staged_backing))??;

        let staged = staged_partitions
            .lock()
            .get_mut(&backing.partition)
            .and_then(|partition| partition.remove(&backing.name))
            .expect("the final staging sync preserves the publication blob");
        *durable = staged;
        namespace.record_durability_snapshot();
        Ok(())
    }
}

impl uno::Publisher<Blob> for Publisher {
    fn spawn(&self, task: uno::Task) -> Result<(), Error> {
        drive_ready(task)
    }

    async fn publish(
        &self,
        core: Arc<uno::Core<Blob>>,
        mut state: uno::MutationGuard,
    ) -> Result<(), Error> {
        let admitted = {
            let namespace = self.namespace.lock();
            self.ensure_admitted(&core, &namespace)
        };
        if let Err(error) = admitted {
            state.finish();
            return Err(error);
        }
        if !state.is_dirty() {
            state.finish();
            return Ok(());
        }
        state.arm();
        if state.preflush_requested()? {
            core.ensure_preflush(state.preflush_target()).await?;
        }
        self.publish_snapshot(&core, &mut state)?;
        state.finish();
        Ok(())
    }
}

impl crate::AtomicStorage for Storage {
    type AtomicBlob = AtomicBlob;

    async fn migrate_atomic(&self, blob: Self::Blob) -> Result<(), Error> {
        if !self.owns(&blob) {
            return Err(Error::BlobMissing(blob.partition.clone(), hex(&blob.name)));
        }

        let key = (blob.partition.clone(), blob.name.clone());
        {
            let namespace = self.namespace.lock();
            blob.ensure_current(&namespace, &key)?;
        }
        crate::Blob::sync(&blob).await?;

        let mut namespace = self.namespace.lock();
        blob.ensure_current(&namespace, &key)?;
        if namespace
            .atomic_generations
            .get(&key)
            .is_some_and(|entry| entry.generation == blob.generation)
        {
            return Ok(());
        }
        let mut partitions = self.partitions.lock();
        let durable = partitions
            .get_mut(&blob.partition)
            .and_then(|partition| partition.get_mut(&blob.name))
            .ok_or_else(|| Error::BlobMissing(blob.partition.clone(), hex(&blob.name)))?;
        let (_, blob_version, data_offset) =
            resolve_header(durable, &(0..=u16::MAX), &blob.partition, &blob.name)?.ok_or_else(
                || {
                    Error::BlobCorrupt(
                        blob.partition.clone(),
                        hex(&blob.name),
                        "opened blob has no durable header".into(),
                    )
                },
            )?;
        if data_offset != blob.data_offset {
            return Err(Error::BlobCorrupt(
                blob.partition.clone(),
                hex(&blob.name),
                "opened blob layout does not match its durable header".into(),
            ));
        }
        let payload_offset = usize::try_from(data_offset).map_err(|_| Error::OffsetOverflow)?;
        let header = durable
            .get(..payload_offset)
            .ok_or(Error::BlobInsufficientLength)?
            .to_vec();
        let payload = durable
            .get(payload_offset..)
            .ok_or(Error::BlobInsufficientLength)?
            .to_vec();
        let replacement = self.build_atomic_replacement(
            &blob.partition,
            &blob.name,
            &header,
            &payload,
            blob_version,
        )?;

        *durable = replacement;
        namespace.remove(&key);
        let generation = namespace.generation(&key);
        namespace.atomic_generations.insert(
            key,
            AtomicGeneration {
                generation,
                live: Weak::new(),
            },
        );
        Ok(())
    }

    async fn open_atomic_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::AtomicBlob, u64, u16), Error> {
        let (blob, version) = self.open_atomic_versioned_inner(partition, name, versions)?;
        let len = blob.inner.lock_state().await?.logical_len();
        Ok((blob, len, version))
    }
}

impl crate::BatchStorage for Storage {
    async fn start_apply(
        &self,
        operations: Vec<BatchOperation<Self::AtomicBlob>>,
    ) -> Result<Handle<()>, Error> {
        let mut operation_blobs = BTreeMap::<BlobKey, Vec<&AtomicBlob>>::new();
        for operation in &operations {
            let blob = match operation {
                BatchOperation::Remove(blob) | BatchOperation::Publish(blob) => blob,
                BatchOperation::Rewind { blob, .. } => blob,
            };
            if !self.owns_atomic(blob) {
                return Err(Error::BlobMissing(
                    blob.backing().partition.clone(),
                    hex(&blob.backing().name),
                ));
            }
            operation_blobs
                .entry((
                    blob.backing().partition.clone(),
                    blob.backing().name.clone(),
                ))
                .or_default()
                .push(blob);
        }
        let operations = super::batch::canonicalize_descriptors(&operations, |blob| {
            (
                blob.backing().partition.clone(),
                blob.backing().name.clone(),
            )
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
                        .expect("canonical operation retains its blob handles"),
                )
            })
            .collect::<Vec<_>>();

        let mut states = Vec::with_capacity(participants.len());
        for (_, blobs) in &participants {
            let core = blobs[0].inner.core();
            for duplicate in blobs.iter().skip(1) {
                if !Arc::ptr_eq(core, duplicate.inner.core()) {
                    return Err(Error::BlobMissing(
                        duplicate.backing().partition.clone(),
                        hex(&duplicate.backing().name),
                    ));
                }
            }
            states.push(blobs[0].inner.lock_state().await?);
        }

        {
            let namespace = self.namespace.lock();
            let partitions = self.partitions.lock();
            for (index, (operation, blobs)) in participants.iter().enumerate() {
                let blob = blobs[0];
                blob.ensure_current(&namespace)?;
                if matches!(operation, super::batch::Operation::Remove(_)) {
                    partitions
                        .get(&blob.backing().partition)
                        .and_then(|partition| partition.get(&blob.backing().name))
                        .ok_or_else(|| {
                            Error::BlobMissing(
                                blob.backing().partition.clone(),
                                hex(&blob.backing().name),
                            )
                        })?;
                    continue;
                }
                if let super::batch::Operation::Rewind { len, .. } = operation {
                    states[index].rewind_integrity_source(*len, None)?;
                }
            }
        }

        // Drain payload preflushes before taking the synchronous namespace locks below. State
        // guards remain held, so no participant can mutate while its durability frontier moves.
        for (index, (operation, blobs)) in participants.iter().enumerate() {
            if matches!(operation, super::batch::Operation::Remove(_)) {
                continue;
            }
            let core = blobs[0].inner.core();
            let target = if matches!(operation, super::batch::Operation::Rewind { .. }) {
                states[index].raw_len()?
            } else if states[index].preflush_requested()? {
                states[index].preflush_target()
            } else {
                continue;
            };
            drive_ready(core.ensure_preflush(target))??;
            drive_ready(core.state().preflush().wait_idle())??;
        }

        let mut namespace = self.namespace.lock();
        let mut partitions = self.partitions.lock();

        // Generic UNO publication performs ordinary-blob syncs into this private snapshot. The
        // snapshot is installed in the canonical partitions only after every participant is ready.
        let mut staged_namespace = Namespace::default();
        let mut staged_partitions = BTreeMap::<String, Partition>::new();
        for (_, blobs) in &participants {
            let blob = blobs[0];
            blob.ensure_current(&namespace)?;
            let backing = blob.backing();
            let durable = partitions
                .get(&backing.partition)
                .and_then(|partition| partition.get(&backing.name))
                .ok_or_else(|| Error::BlobMissing(backing.partition.clone(), hex(&backing.name)))?;
            staged_namespace.generations.insert(
                (backing.partition.clone(), backing.name.clone()),
                backing.generation,
            );
            staged_partitions
                .entry(backing.partition.clone())
                .or_default()
                .insert(backing.name.clone(), durable.clone());
        }
        let staged_namespace = Arc::new(Mutex::new(staged_namespace));
        let staged_partitions = Arc::new(Mutex::new(staged_partitions));
        let staged_cores = participants
            .iter()
            .map(|(_, blobs)| {
                let backing = blobs[0].backing();
                let staged_backing = Blob {
                    partitions: staged_partitions.clone(),
                    namespace: staged_namespace.clone(),
                    partition: backing.partition.clone(),
                    name: backing.name.clone(),
                    content: backing.content.clone(),
                    atomic: None,
                    pool: backing.pool.clone(),
                    data_offset: backing.data_offset,
                    generation: backing.generation,
                };
                uno::Core::new(staged_backing, blobs[0].inner.core().state().clone())
            })
            .collect::<Vec<_>>();

        let mut force_truncate = vec![false; participants.len()];
        for (index, (operation, _)) in participants.iter().enumerate() {
            if let super::batch::Operation::Rewind { len, .. } = operation {
                force_truncate[index] = *len >= states[index].committed_len();
                drive_ready(staged_cores[index].rewind_state(&mut states[index], *len, None))??;
            }
        }

        let mut prepared = Vec::with_capacity(participants.len());
        for (index, (operation, _)) in participants.iter().enumerate() {
            prepared.push(if matches!(operation, super::batch::Operation::Remove(_)) {
                None
            } else {
                states[index].prepare_commit()?
            });
        }

        for (index, ((operation, _), core)) in participants.iter().zip(&staged_cores).enumerate() {
            if let Some(commit) = &prepared[index] {
                drive_ready(crate::Blob::write_at(
                    core.backing(),
                    uno::Core::<Blob>::backing_offset(commit.root_offset)?,
                    commit.prepared_root.clone(),
                ))??;
                drive_ready(crate::Blob::sync(core.backing()))??;
                drive_ready(crate::Blob::write_at(
                    core.backing(),
                    uno::Core::<Blob>::backing_offset(commit.root_offset)?,
                    commit.committed_root.to_vec(),
                ))??;
            }
            if force_truncate[index]
                || prepared[index]
                    .as_ref()
                    .is_some_and(|commit| commit.requires_truncate())
            {
                drive_ready(crate::Blob::resize(
                    core.backing(),
                    uno::Core::<Blob>::backing_len(states[index].raw_len()?)?,
                ))??;
            }
            if prepared[index].is_some() || force_truncate[index] {
                drive_ready(crate::Blob::sync(core.backing()))??;
            }
            debug_assert!(
                !matches!(operation, super::batch::Operation::Remove(_))
                    || prepared[index].is_none()
            );

            #[cfg(test)]
            self.pause_batch_once();
        }

        {
            let staged = staged_partitions.lock();
            for (operation, blobs) in &participants {
                if matches!(operation, super::batch::Operation::Remove(_)) {
                    continue;
                }
                let backing = blobs[0].backing();
                let content = staged
                    .get(&backing.partition)
                    .and_then(|partition| partition.get(&backing.name))
                    .expect("validated staged blobs remain present");
                *partitions
                    .get_mut(&backing.partition)
                    .and_then(|partition| partition.get_mut(&backing.name))
                    .expect("validated durable blobs remain present") = content.clone();
            }
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

        for (index, commit) in prepared.into_iter().enumerate() {
            if let Some(commit) = commit {
                staged_cores[index]
                    .state()
                    .preflush()
                    .record_durable(commit.raw_len());
                states[index].finish_commit(commit);
            }
        }
        Ok(Handle::ready(Ok(())))
    }
}

#[derive(Clone)]
pub struct Blob {
    partitions: Arc<Mutex<BTreeMap<String, Partition>>>,
    namespace: Arc<Mutex<Namespace>>,
    partition: String,
    name: Vec<u8>,
    content: Arc<RwLock<Vec<u8>>>,
    /// Compatibility view for ordinary opens of an atomic name. Core backings always leave this
    /// empty so protocol I/O takes the direct ordinary path.
    atomic: Option<uno::AtomicBlob<Self, Publisher>>,
    pool: BufferPool,
    /// Physical offset where logical offset 0 begins.
    data_offset: u64,
    /// Namespace generation captured when this handle was opened.
    generation: u64,
}

impl Blob {
    fn from_atomic(atomic: uno::AtomicBlob<Self, Publisher>) -> Self {
        let backing = atomic.core().backing();
        let partitions = backing.partitions.clone();
        let namespace = backing.namespace.clone();
        let partition = backing.partition.clone();
        let name = backing.name.clone();
        let content = backing.content.clone();
        let pool = backing.pool.clone();
        let data_offset = backing.data_offset;
        let generation = backing.generation;
        Self {
            partitions,
            namespace,
            partition,
            name,
            content,
            atomic: Some(atomic),
            pool,
            data_offset,
            generation,
        }
    }

    fn ensure_current(&self, namespace: &Namespace, key: &BlobKey) -> Result<(), Error> {
        if namespace.generations.get(key) == Some(&self.generation) {
            return Ok(());
        }
        Err(Error::BlobMissing(self.partition.clone(), hex(&self.name)))
    }

    fn sync_inner(&self) -> Result<(), Error> {
        let key = (self.partition.clone(), self.name.clone());
        let mut namespace = self.namespace.lock();
        self.ensure_current(&namespace, &key)?;
        let new_content = self.content.read();

        let mut partitions = self.partitions.lock();
        let partition = partitions
            .get_mut(&self.partition)
            .ok_or(Error::PartitionMissing(self.partition.clone()))?;
        let content = partition
            .get_mut(&self.name)
            .ok_or(Error::BlobMissing(self.partition.clone(), hex(&self.name)))?;
        content.clone_from(&new_content);
        namespace.record_durability_snapshot();
        Ok(())
    }
}

impl crate::Blob for Blob {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.read_at_buf(offset, len, self.pool.alloc(len)).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let mut bufs = bufs.into();
        if let Some(atomic) = &self.atomic {
            return atomic_read_at_buf(atomic, offset, len, bufs).await;
        }
        // SAFETY: len bytes are filled via copy_from_slice below.
        unsafe { bufs.set_len(len) };
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        let offset: usize = offset.try_into().map_err(|_| Error::OffsetOverflow)?;
        let end = offset.checked_add(len).ok_or(Error::OffsetOverflow)?;
        let content = self.content.read();
        if end > content.len() {
            return Err(Error::BlobInsufficientLength);
        }
        bufs.copy_from_slice(&content[offset..end]);
        Ok(bufs)
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        self.write_at_with_options(offset, bufs, WriteOptions::default())
            .await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.write_at_with_options(offset, bufs, WriteOptions::SYNC)
            .await
    }

    async fn write_at_with_options(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        if let Some(atomic) = &self.atomic {
            return atomic_write_at_with_options(atomic, offset, bufs, options).await;
        }
        let sync = options.contains(WriteOptions::SYNC);
        if !bufs.has_remaining() && sync {
            return Ok(());
        }
        let buf = bufs.coalesce();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        let offset: usize = offset.try_into().map_err(|_| Error::OffsetOverflow)?;
        {
            let mut content = self.content.write();
            let required = offset.checked_add(buf.len()).ok_or(Error::OffsetOverflow)?;
            if required > content.len() {
                content.resize(required, 0);
            }
            content[offset..offset + buf.len()].copy_from_slice(buf.as_ref());
        }
        if sync { self.sync_inner() } else { Ok(()) }
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        if let Some(atomic) = &self.atomic {
            return atomic_resize(atomic, len).await;
        }
        let len = len
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        let len: usize = len.try_into().map_err(|_| Error::OffsetOverflow)?;
        self.content.write().resize(len, 0);
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        if let Some(atomic) = &self.atomic {
            return atomic_sync(atomic).await;
        }
        self.sync_inner()
    }

    async fn start_sync(&self) -> Handle<()> {
        if let Some(atomic) = &self.atomic {
            return atomic_start_sync(atomic).await;
        }
        Handle::ready(self.sync().await)
    }
}

/// Atomic UNO view over an ordinary-geometry in-memory blob.
#[derive(Clone)]
pub struct AtomicBlob {
    inner: uno::AtomicBlob<Blob, Publisher>,
}

impl AtomicBlob {
    fn backing(&self) -> &Blob {
        self.inner.core().backing()
    }

    fn ensure_current(&self, namespace: &Namespace) -> Result<(), Error> {
        let backing = self.backing();
        let key = (backing.partition.clone(), backing.name.clone());
        backing.ensure_current(namespace, &key)?;
        let current = namespace
            .atomic_generations
            .get(&key)
            .filter(|entry| entry.generation == backing.generation)
            .and_then(|entry| entry.live.upgrade());
        if current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, self.inner.core()))
        {
            Ok(())
        } else {
            Err(Error::BlobMissing(
                backing.partition.clone(),
                hex(&backing.name),
            ))
        }
    }
}

impl crate::Blob for AtomicBlob {
    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        crate::Blob::read_at_buf(&self.inner, offset, len, bufs).await
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        crate::Blob::read_at(&self.inner, offset, len).await
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        crate::Blob::write_at(&self.inner, offset, bufs).await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        crate::Blob::write_at_sync(&self.inner, offset, bufs).await
    }

    async fn write_at_with_options(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        crate::Blob::write_at_with_options(&self.inner, offset, bufs, options).await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        crate::Blob::resize(&self.inner, len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        crate::Blob::sync(&self.inner).await
    }

    async fn start_sync(&self) -> Handle<()> {
        crate::Blob::start_sync(&self.inner).await
    }
}

impl crate::AtomicBlob for AtomicBlob {
    async fn tag(&self) -> Result<[u8; ATOMIC_BLOB_TAG_LEN], Error> {
        crate::AtomicBlob::tag(&self.inner).await
    }

    async fn set_tag(&self, tag: [u8; ATOMIC_BLOB_TAG_LEN]) -> Result<(), Error> {
        crate::AtomicBlob::set_tag(&self.inner, tag).await
    }

    async fn integrity_scheme(&self) -> Result<IntegrityScheme, Error> {
        crate::AtomicBlob::integrity_scheme(&self.inner).await
    }

    async fn integrity_snapshot(&self) -> Result<IntegritySnapshot, Error> {
        crate::AtomicBlob::integrity_snapshot(&self.inner).await
    }

    async fn compare_set_tag(
        &self,
        expected: IntegrityToken,
        tag: [u8; ATOMIC_BLOB_TAG_LEN],
    ) -> Result<IntegrityToken, Error> {
        crate::AtomicBlob::compare_set_tag(&self.inner, expected, tag).await
    }

    async fn append(&self, data: impl Into<IoBufs> + Send) -> Result<u64, Error> {
        crate::AtomicBlob::append(&self.inner, data).await
    }

    async fn append_tagged(
        &self,
        data: impl Into<IoBufs> + Send,
        tag: [u8; ATOMIC_BLOB_TAG_LEN],
    ) -> Result<u64, Error> {
        crate::AtomicBlob::append_tagged(&self.inner, data, tag).await
    }

    async fn append_integrity(
        &self,
        expected: IntegrityToken,
        data: impl Into<IoBufs> + Send,
        boundary: IntegrityBoundary,
        tag: Option<[u8; ATOMIC_BLOB_TAG_LEN]>,
    ) -> Result<IntegrityAppend, Error> {
        crate::AtomicBlob::append_integrity(&self.inner, expected, data, boundary, tag).await
    }

    async fn read_integrity_tail(&self) -> Result<Option<(IntegrityUnit, IoBufs)>, Error> {
        crate::AtomicBlob::read_integrity_tail(&self.inner).await
    }

    async fn read_integrity(&self, unit: IntegrityUnit) -> Result<IoBufs, Error> {
        crate::AtomicBlob::read_integrity(&self.inner, unit).await
    }

    async fn rewind(&self, len: u64) -> Result<(), Error> {
        crate::AtomicBlob::rewind(&self.inner, len).await
    }

    async fn rewind_tagged(&self, len: u64, tag: [u8; ATOMIC_BLOB_TAG_LEN]) -> Result<(), Error> {
        crate::AtomicBlob::rewind_tagged(&self.inner, len, tag).await
    }

    async fn rewind_integrity(
        &self,
        expected: IntegrityToken,
        len: u64,
        unit: Option<IntegrityUnit>,
        tag: Option<[u8; ATOMIC_BLOB_TAG_LEN]>,
    ) -> Result<IntegrityToken, Error> {
        crate::AtomicBlob::rewind_integrity(&self.inner, expected, len, unit, tag).await
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
                run_atomic_blob_tests, run_atomic_storage_tests, run_batch_storage_tests,
                run_storage_foreign_handle_test, run_storage_tests,
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
        run_atomic_storage_tests(storage.clone()).await;
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
        plain.write_at(8, Vec::<u8>::new()).await.unwrap();
        plain.sync().await.unwrap();
        drop(plain);
        let (_, plain_len) = storage.open("partition", b"plain").await.unwrap();
        assert_eq!(plain_len, 8);

        let (sync, _) = storage.open("partition", b"sync").await.unwrap();
        sync.write_at_sync(8, Vec::<u8>::new()).await.unwrap();
        drop(sync);
        let (_, sync_len) = storage.open("partition", b"sync").await.unwrap();
        assert_eq!(sync_len, 0);
    }

    #[tokio::test]
    async fn test_atomic_publish_uses_one_durability_snapshot() {
        let storage = Storage::new(test_pool());
        let (blob, _) = storage
            .open_atomic("atomic_snapshot_count", b"blob")
            .await
            .unwrap();
        blob.append(b"pending").await.unwrap();

        let before = storage.namespace.lock().durability_snapshots;
        blob.sync().await.unwrap();
        let after = storage.namespace.lock().durability_snapshots;

        assert_eq!(after - before, 1);
    }

    #[tokio::test]
    async fn test_atomic_live_generation_and_durability() {
        let storage = Storage::new(test_pool());
        let (first, _) = storage.open_atomic("atomic", b"blob").await.unwrap();
        let (second, _) = storage.open("atomic", b"blob").await.unwrap();
        assert!(Arc::ptr_eq(
            first.inner.core(),
            second.atomic.as_ref().unwrap().core()
        ));

        assert_eq!(first.append(b"abcdef").await.unwrap(), 0);
        assert_eq!(second.read_at(0, 6).await.unwrap().coalesce(), b"abcdef");
        second.resize(4).await.unwrap();
        assert_eq!(first.read_at(0, 4).await.unwrap().coalesce(), b"abcd");
        first.write_at(4, b"z").await.unwrap();
        assert_eq!(second.read_at(0, 5).await.unwrap().coalesce(), b"abcdz");

        first.rewind(0).await.unwrap();
        assert_eq!(first.append(b"old").await.unwrap(), 0);
        second.sync().await.unwrap();
        assert_eq!(first.append(b" pending").await.unwrap(), 3);
        let dropped = Arc::downgrade(first.inner.core());
        drop((first, second));
        assert!(dropped.upgrade().is_none());

        let (reopened, len) = storage.open_atomic("atomic", b"blob").await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(reopened.read_at(0, 3).await.unwrap().coalesce(), b"old");
        reopened.write_at_sync(3, b"!").await.unwrap();
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
        let data_offset = Layout::V1.data_offset() as usize + UNO_ROOT_PAGE_LEN;
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
            blob.write_at(4, b"z").await,
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
        assert!(!Arc::ptr_eq(old.inner.core(), new.inner.core()));
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
    async fn test_atomic_batch_durable_snapshot_is_not_partially_observable() {
        let storage = Storage::new(test_pool());
        let (first, _) = storage.open_atomic("atomic_batch", b"a").await.unwrap();
        let (second, _) = storage.open_atomic("atomic_batch", b"b").await.unwrap();
        first.append(b"a0").await.unwrap();
        second.append(b"b0").await.unwrap();
        first.sync().await.unwrap();
        second.sync().await.unwrap();
        first.append(b"a1").await.unwrap();
        second.append(b"b1").await.unwrap();

        let entered = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        *storage.batch_hook.lock() = Some(BatchHook {
            entered: entered.clone(),
            resume: resume.clone(),
        });

        let batch_storage = storage.clone();
        let batch = std::thread::spawn(move || {
            futures::executor::block_on(batch_storage.apply(vec![
                BatchOperation::Publish(first),
                BatchOperation::Publish(second),
            ]))
        });
        entered.wait();

        let namespace_exposed = storage.namespace.try_lock().is_some();
        let durable_snapshot_exposed = storage.partitions.try_lock().is_some();
        resume.wait();
        batch.join().unwrap().unwrap();

        assert!(
            !namespace_exposed && !durable_snapshot_exposed,
            "the batch exposed its namespace or durable snapshot before all participants were ready"
        );
        let (first, first_len) = storage.open_atomic("atomic_batch", b"a").await.unwrap();
        let (second, second_len) = storage.open_atomic("atomic_batch", b"b").await.unwrap();
        assert_eq!(first_len, 4);
        assert_eq!(second_len, 4);
        assert_eq!(first.read_at(0, 4).await.unwrap().coalesce(), b"a0a1");
        assert_eq!(second.read_at(0, 4).await.unwrap().coalesce(), b"b0b1");
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
        let old_blob_generation = old_blob.backing().generation;

        let (old_second, _) = storage.open_atomic("batch_second", b"name").await.unwrap();
        old_second.append(b"old second").await.unwrap();
        let old_second_generation = old_second.backing().generation;

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
        assert_ne!(old_blob_generation, new_blob.backing().generation);
        new_blob.append(b"new blob").await.unwrap();
        new_blob.sync().await.unwrap();

        let (new_second, second_len) = storage.open_atomic("batch_second", b"name").await.unwrap();
        assert_eq!(second_len, 0);
        assert_ne!(old_second_generation, new_second.backing().generation);
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

        let prior = blob.clone();
        storage.migrate_atomic(blob).await.unwrap();
        let (atomic, size, version) = storage
            .open_atomic_versioned("partition", b"v0", 0..=0)
            .await
            .unwrap();
        assert_eq!(size, 12);
        assert_eq!(version, 0);
        assert_eq!(
            atomic.read_at(0, 12).await.unwrap().coalesce(),
            b"hello world!"
        );
        assert_eq!(
            prior.read_at(0, 12).await.unwrap().coalesce(),
            b"hello world!"
        );
        {
            let partitions = storage.partitions.lock();
            let partition = partitions.get("partition").unwrap();
            let raw_content = partition.get(&b"v0".to_vec()).unwrap();
            assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V0.magic());
            assert_eq!(
                &raw_content[Header::PRELUDE_SIZE + UNO_ROOT_PAGE_LEN..],
                b"hello world!"
            );
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
    async fn test_atomic_audit_is_deterministic() {
        let storages = [Storage::new(test_pool()), Storage::new(test_pool())];
        for storage in &storages {
            let (blob, _) = storage.open_atomic("partition", b"blob").await.unwrap();
            blob.append(b"payload").await.unwrap();
            blob.sync().await.unwrap();
        }

        assert_eq!(storages[0].audit(), storages[1].audit());
    }

    #[tokio::test]
    async fn test_opening_migrated_atomic_blob_does_not_change_audit() {
        let storage = Storage::new(test_pool());
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"payload").await.unwrap();
        storage.migrate_atomic(blob).await.unwrap();

        let before = storage.audit();
        let (blob, size) = storage.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(size, 7);
        drop(blob);
        assert_eq!(storage.audit(), before);
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
