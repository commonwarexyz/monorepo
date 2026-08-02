use super::{Header, Layout};
use crate::{BatchOperation, BufferPool, Error, Handle};
use commonware_formatting::{from_hex, hex};
#[cfg(unix)]
use commonware_utils::sync::Mutex as SyncMutex;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::sync::Weak;
use std::{
    collections::BTreeMap,
    ops::RangeInclusive,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::{Mutex, OwnedMutexGuard, oneshot},
};

#[cfg(not(unix))]
mod fallback;
#[cfg(unix)]
mod unix;

#[cfg(not(unix))]
type Blob = fallback::Blob;
#[cfg(unix)]
type Blob = unix::Blob;

#[cfg(not(unix))]
fn unsupported_atomic(partition: &str, name: &[u8]) -> Error {
    Error::BlobOpenFailed(
        partition.into(),
        hex(name),
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "atomic storage requires a Unix filesystem backend",
        )
        .into(),
    )
}

const MAX_BATCH_WORKERS: usize = 32;

/// Run blocking batch work on a bounded number of native threads while preserving input order.
fn run_batch_workers<T, U, F>(items: Vec<T>, run: F) -> Vec<U>
where
    T: Send,
    U: Send,
    F: Fn(T) -> U + Sync,
{
    if items.is_empty() {
        return Vec::new();
    }

    let item_count = items.len();
    let worker_count = item_count.min(MAX_BATCH_WORKERS);
    let chunk_len = item_count.div_ceil(worker_count);
    let mut items = items.into_iter();
    let mut chunks = Vec::with_capacity(worker_count);
    loop {
        let chunk = items.by_ref().take(chunk_len).collect::<Vec<_>>();
        if chunk.is_empty() {
            break;
        }
        chunks.push(chunk);
    }

    std::thread::scope(|scope| {
        let workers = chunks
            .into_iter()
            .map(|chunk| {
                let run = &run;
                scope.spawn(move || chunk.into_iter().map(run).collect::<Vec<_>>())
            })
            .collect::<Vec<_>>();
        let mut results = Vec::with_capacity(item_count);
        let mut first_panic = None;
        for worker in workers {
            match worker.join() {
                Ok(chunk) => results.extend(chunk),
                Err(panic) if first_panic.is_none() => first_panic = Some(panic),
                Err(_) => {}
            }
        }
        if let Some(panic) = first_panic {
            std::panic::resume_unwind(panic);
        }
        results
    })
}

/// Syncs a directory to ensure directory entry changes are durable.
/// On Unix, directory metadata (file creation/deletion) must be explicitly
/// fsynced.
#[cfg(unix)]
async fn sync_dir(path: &Path) -> Result<(), Error> {
    let dir = fs::File::open(path).await.map_err(|e| {
        Error::BlobOpenFailed(
            path.to_string_lossy().to_string(),
            "directory".to_string(),
            e.into(),
        )
    })?;
    dir.sync_all().await.map_err(|e| {
        Error::BlobSyncFailed(
            path.to_string_lossy().to_string(),
            "directory".to_string(),
            e.into(),
        )
    })
}

#[derive(Clone)]
pub struct Config {
    /// Directory exclusively owned by this storage instance and its clones.
    ///
    /// Concurrent access by another storage instance or process is unsupported.
    pub storage_directory: PathBuf,
    /// Largest buffer Tokio may retain for a file.
    pub maximum_buffer_size: usize,
}

impl Config {
    pub const fn new(storage_directory: PathBuf, maximum_buffer_size: usize) -> Self {
        Self {
            storage_directory,
            maximum_buffer_size,
        }
    }
}

#[derive(Clone)]
pub struct Storage {
    namespace: Arc<Namespace>,
    cfg: Config,
    pool: BufferPool,
}

type Generation = super::generation::Token;
#[cfg(unix)]
type SharedV2State = Arc<tokio::sync::Mutex<unix::V2State>>;
#[cfg(unix)]
type V2StateEntry = (Weak<Generation>, Weak<tokio::sync::Mutex<unix::V2State>>);

struct Namespace {
    lock: Arc<Mutex<()>>,
    recovery_required: AtomicBool,
    carried_batch_decision: AtomicBool,
    generations: super::generation::Registry,
    #[cfg(unix)]
    v2_states: SyncMutex<BTreeMap<(String, Vec<u8>), V2StateEntry>>,
}

impl Namespace {
    fn knows_partition(&self, partition: &str) -> bool {
        self.generations.knows_partition(partition)
    }

    fn generation(&self, partition: &str, name: &[u8]) -> Arc<Generation> {
        self.generations.generation(partition, name)
    }

    fn is_current(&self, partition: &str, name: &[u8], generation: &Arc<Generation>) -> bool {
        self.generations.is_current(partition, name, generation)
    }

    fn invalidate_operations(&self, operations: &[super::batch::Operation]) {
        self.generations.invalidate(operations);
        #[cfg(unix)]
        {
            let mut states = self.v2_states.lock();
            for operation in operations {
                match operation {
                    super::batch::Operation::Remove(crate::RemoveTarget::Blob {
                        partition,
                        name,
                    }) => {
                        states.remove(&(partition.clone(), name.clone()));
                    }
                    super::batch::Operation::Remove(crate::RemoveTarget::Partition(partition)) => {
                        states.retain(|(candidate, _), _| candidate != partition);
                    }
                    super::batch::Operation::Publish { .. }
                    | super::batch::Operation::Resize { .. } => {}
                }
            }
        }
    }

    #[cfg(unix)]
    fn v2_state(
        &self,
        partition: &str,
        name: &[u8],
        generation: &Arc<Generation>,
    ) -> Option<SharedV2State> {
        let key = (partition.to_string(), name.to_vec());
        let mut states = self.v2_states.lock();
        let (stored_generation, state) = states.get(&key)?;
        let Some(stored_generation) = stored_generation.upgrade() else {
            states.remove(&key);
            return None;
        };
        if !Arc::ptr_eq(&stored_generation, generation) {
            states.remove(&key);
            return None;
        }
        let state = state.upgrade();
        if state.is_none() {
            states.remove(&key);
        }
        state
    }

    #[cfg(unix)]
    fn insert_v2_state(
        &self,
        partition: &str,
        name: &[u8],
        generation: &Arc<Generation>,
        state: &SharedV2State,
    ) {
        let mut states = self.v2_states.lock();
        states.retain(|_, (_, state)| state.strong_count() != 0);
        states.insert(
            (partition.to_string(), name.to_vec()),
            (Arc::downgrade(generation), Arc::downgrade(state)),
        );
    }

    #[cfg(test)]
    fn generation_count(&self) -> usize {
        self.generations.len()
    }
}

/// Reads a blob's leading bytes and resolves its header (see [super::header::resolve]).
async fn resolve_header(
    file: &mut fs::File,
    raw_len: u64,
    versions: &RangeInclusive<u16>,
    partition: &str,
    name: &[u8],
) -> Result<Option<(u64, u16, u64)>, Error> {
    let mut raw = vec![0u8; Header::resolve_len(raw_len)];
    file.read_exact(&mut raw)
        .await
        .map_err(|_| Error::ReadFailed)?;
    super::header::resolve(&raw, raw_len, versions, partition, name)
}

/// Complete any committed coordinator decision while retaining the namespace guard.
async fn recover_namespace(
    namespace: Arc<Namespace>,
    root: PathBuf,
    guard: OwnedMutexGuard<()>,
) -> Result<OwnedMutexGuard<()>, Error> {
    if !namespace.recovery_required.load(Ordering::Acquire) {
        return Ok(guard);
    }

    let recovery = tokio::task::spawn_blocking(move || {
        let invalidator = namespace.clone();
        let result = super::batch::recover_notifying(&root, move |operations| {
            invalidator.invalidate_operations(operations);
        });
        if result.is_ok() {
            namespace.recovery_required.store(false, Ordering::Release);
            namespace
                .carried_batch_decision
                .store(false, Ordering::Release);
        }
        (guard, result)
    });
    match recovery.await {
        Ok((guard, result)) => {
            result?;
            Ok(guard)
        }
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(_) => Err(Error::Closed),
    }
}

impl Storage {
    pub fn new(cfg: Config, pool: BufferPool) -> Self {
        Self {
            namespace: Arc::new(Namespace {
                lock: Arc::new(Mutex::new(())),
                recovery_required: AtomicBool::new(true),
                carried_batch_decision: AtomicBool::new(false),
                generations: super::generation::Registry::default(),
                #[cfg(unix)]
                v2_states: SyncMutex::new(BTreeMap::new()),
            }),
            cfg,
            pool,
        }
    }

    /// Lock the namespace after completing any prior committed batch. The blocking task owns the
    /// guard so cancellation cannot expose recovery halfway through.
    async fn lock_recovered(&self) -> Result<OwnedMutexGuard<()>, Error> {
        let guard = self.namespace.lock.clone().lock_owned().await;
        recover_namespace(
            self.namespace.clone(),
            self.cfg.storage_directory.clone(),
            guard,
        )
        .await
    }

    /// Lock the namespace while retaining a committed publication decision for direct replacement
    /// by the next batch.
    async fn lock_batch(&self) -> Result<(OwnedMutexGuard<()>, bool), Error> {
        let guard = self.namespace.lock.clone().lock_owned().await;
        if self
            .namespace
            .carried_batch_decision
            .load(Ordering::Acquire)
        {
            return Ok((guard, true));
        }
        let guard = recover_namespace(
            self.namespace.clone(),
            self.cfg.storage_directory.clone(),
            guard,
        )
        .await?;
        Ok((guard, false))
    }

    /// Commit a storage batch from a self-driving worker that owns the namespace guard.
    async fn start_apply_guarded<F, C, D>(
        &self,
        operations: Vec<BatchOperation<<Self as crate::AtomicStorage>::AtomicBlob>>,
        on_worker_start: F,
        on_commit: C,
        on_complete: D,
    ) -> Result<Handle<()>, Error>
    where
        F: FnOnce() + Send + 'static,
        C: FnOnce() + Send + 'static,
        D: FnOnce() + Send + 'static,
    {
        let mut descriptors = Vec::with_capacity(operations.len());
        let mut blobs = BTreeMap::new();
        let mut handles = Vec::new();
        for operation in operations {
            match operation {
                BatchOperation::Remove(target) => {
                    descriptors.push(super::batch::Operation::Remove(target));
                }
                BatchOperation::Publish(blob) => {
                    let partition = blob.partition().to_string();
                    let name = blob.name().to_vec();
                    if !blob.is_atomic() {
                        return Err(Error::BlobOpenFailed(
                            partition,
                            hex(&name),
                            std::io::Error::new(
                                std::io::ErrorKind::Unsupported,
                                "batch publication requires an atomic blob",
                            )
                            .into(),
                        ));
                    }
                    descriptors.push(super::batch::Operation::Publish {
                        partition: partition.clone(),
                        name: name.clone(),
                    });
                    handles.push(blob.clone());
                    blobs.entry((partition, name)).or_insert(blob);
                }
                BatchOperation::Resize { blob, len } => {
                    let partition = blob.partition().to_string();
                    let name = blob.name().to_vec();
                    if !blob.is_atomic() {
                        return Err(Error::BlobOpenFailed(
                            partition,
                            hex(&name),
                            std::io::Error::new(
                                std::io::ErrorKind::Unsupported,
                                "batch resize requires an atomic blob",
                            )
                            .into(),
                        ));
                    }
                    descriptors.push(super::batch::Operation::Resize {
                        partition: partition.clone(),
                        name: name.clone(),
                        len,
                    });
                    handles.push(blob.clone());
                    blobs.entry((partition, name)).or_insert(blob);
                }
            }
        }
        let mut filesystem_operations = super::batch::canonicalize_operations(descriptors)?;
        super::batch::preflight(&filesystem_operations)?;
        if filesystem_operations.is_empty() {
            drop(self.lock_recovered().await?);
            return Ok(Handle::ready(Ok(())));
        }

        let mutation_keys = filesystem_operations
            .iter()
            .filter_map(|operation| match operation {
                super::batch::Operation::Publish { partition, name }
                | super::batch::Operation::Resize {
                    partition, name, ..
                } => Some((partition.clone(), name.clone())),
                super::batch::Operation::Remove(_) => None,
            })
            .collect::<Vec<_>>();
        let mut locked = Vec::with_capacity(mutation_keys.len());
        for key in mutation_keys {
            let blob = blobs
                .remove(&key)
                .expect("canonical mutation retains one input blob handle");
            let state = blob.lock_batch_state().await?;
            locked.push((blob, state));
        }

        let (guard, carry_decision) = self.lock_batch().await?;
        for blob in &handles {
            if !self
                .namespace
                .is_current(blob.partition(), blob.name(), blob.generation())
            {
                return Err(Error::BlobMissing(
                    blob.partition().to_string(),
                    hex(blob.name()),
                ));
            }
        }
        let root = self.cfg.storage_directory.clone();
        let resolution = tokio::task::spawn_blocking(move || {
            super::batch::resolve_operation_partitions(&root, &mut filesystem_operations)?;
            Ok::<_, std::io::Error>(filesystem_operations)
        });
        let filesystem_operations = match resolution.await {
            Ok(result) => result?,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => return Err(Error::Closed),
        };
        let filesystem_operations = super::batch::canonicalize_operations(filesystem_operations)?;
        super::batch::preflight(&filesystem_operations)?;

        self.namespace
            .recovery_required
            .store(true, Ordering::Release);
        let root = self.cfg.storage_directory.clone();
        let namespace = self.namespace.clone();
        let (commit_sender, commit_receiver) = oneshot::channel();
        let (completion_sender, completion_receiver) = oneshot::channel();
        drop(tokio::task::spawn_blocking(move || {
            on_worker_start();
            let resize_lengths = filesystem_operations
                .iter()
                .filter_map(|operation| match operation {
                    super::batch::Operation::Resize {
                        partition,
                        name,
                        len,
                    } => Some(((partition.clone(), name.clone()), *len)),
                    super::batch::Operation::Publish { .. }
                    | super::batch::Operation::Remove(_) => None,
                })
                .collect::<BTreeMap<_, _>>();
            let mut prepared_states = run_batch_workers(locked, |(blob, mut state)| {
                let resize = resize_lengths
                    .get(&(blob.partition().to_string(), blob.name().to_vec()))
                    .copied();
                if let Some(len) = resize {
                    state.resize(len);
                }
                let prepared = blob.prepare_batch_commit(&mut state);
                (blob, state, prepared)
            });

            let preparation_error = prepared_states
                .iter()
                .find_map(|(_, _, result)| result.as_ref().err().cloned());
            if let Some(error) = preparation_error {
                for (_, state, _) in &mut prepared_states {
                    Blob::poison_batch_state(state);
                }
                let _ = commit_sender.send(Err(error.clone()));
                drop(guard);
                on_complete();
                let _ = completion_sender.send(Err(error));
                return;
            }
            let participants =
                prepared_states
                    .iter()
                    .filter_map(|(blob, _, prepared)| {
                        prepared.as_ref().unwrap().as_ref().map(|prepared| {
                            super::batch::Participant {
                                partition: blob.partition().to_string(),
                                name: blob.name().to_vec(),
                                candidate: prepared.candidate(),
                            }
                        })
                    })
                    .collect::<Vec<_>>();
            let materialized_previous = prepared_states
                .iter()
                .filter_map(|(blob, _, prepared)| {
                    prepared
                        .as_ref()
                        .unwrap()
                        .as_ref()?
                        .materialized_previous()
                        .cloned()
                        .map(|candidate| super::batch::Participant {
                            partition: blob.partition().to_string(),
                            name: blob.name().to_vec(),
                            candidate,
                        })
                })
                .collect::<Vec<_>>();
            let defer_participant_roots = filesystem_operations
                .iter()
                .all(|operation| !matches!(operation, super::batch::Operation::Remove(_)));

            let invalidator = namespace.clone();
            let committed = std::cell::Cell::new(false);
            let commit_sender = std::cell::Cell::new(Some(commit_sender));
            let result = super::batch::apply_batch_with(
                &root,
                &participants,
                &materialized_previous,
                &filesystem_operations,
                carry_decision,
                |operations| {
                    invalidator.invalidate_operations(operations);
                    invalidator
                        .carried_batch_decision
                        .store(false, Ordering::Release);
                    committed.set(true);
                    if let Some(sender) = commit_sender.take() {
                        let _ = sender.send(Ok(()));
                    }
                    on_commit();
                },
                || {
                    let installers = prepared_states
                        .drain(..)
                        .filter_map(|(blob, mut state, prepared)| {
                            let prepared = prepared.unwrap()?;
                            let candidate = Blob::activate_batch_commit(
                                &mut state,
                                prepared,
                                defer_participant_roots,
                            );
                            drop(state);
                            Some((blob, candidate))
                        })
                        .collect::<Vec<_>>();
                    if defer_participant_roots {
                        return Ok(());
                    }
                    for result in run_batch_workers(installers, |(blob, candidate)| {
                        blob.publish_batch_candidate(&candidate)
                    }) {
                        result.map_err(|error| std::io::Error::other(error.to_string()))?;
                    }
                    Ok(())
                },
            )
            .map_err(Error::from);
            if result.is_err() {
                for (_, state, _) in &mut prepared_states {
                    Blob::poison_batch_state(state);
                }
            }
            if !committed.get() {
                if result.is_ok() {
                    namespace.invalidate_operations(&filesystem_operations);
                }
                if let Some(sender) = commit_sender.take() {
                    let _ = sender.send(result.clone().map(|_| ()));
                }
            }
            if let Ok(carried) = &result {
                namespace
                    .recovery_required
                    .store(*carried, Ordering::Release);
                namespace
                    .carried_batch_decision
                    .store(*carried, Ordering::Release);
            }
            drop(guard);
            on_complete();
            let _ = completion_sender.send(result.map(|_| ()));
        }));

        match commit_receiver.await {
            Ok(Ok(())) => Ok(Handle::from_receiver(completion_receiver)),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(Error::Closed),
        }
    }
}

impl Storage {
    async fn open_versioned_inner(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
        require_atomic: bool,
    ) -> Result<(Blob, u64, u16), Error> {
        super::validate_partition_name(partition)?;

        #[cfg(not(unix))]
        if require_atomic {
            return Err(unsupported_atomic(partition, name));
        }

        let mut guard = self.lock_recovered().await?;
        let requested_parent = self.cfg.storage_directory.join(partition);
        fs::create_dir_all(&requested_parent)
            .await
            .map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

        let stored_partition = if self.namespace.knows_partition(partition) {
            partition.to_string()
        } else {
            let root = self.cfg.storage_directory.clone();
            let requested = partition.to_string();
            let resolution = tokio::task::spawn_blocking(move || {
                super::batch::resolve_partition_name(&root, &requested)
            });
            match resolution.await {
                Ok(result) => result?,
                Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
                Err(_) => return Err(Error::Closed),
            }
        };
        super::validate_partition_name(&stored_partition)?;

        let path = self
            .cfg
            .storage_directory
            .join(&stored_partition)
            .join(hex(name));
        let parent = path
            .parent()
            .ok_or_else(|| Error::PartitionCreationFailed(partition.into()))?;

        // Open existing first so stale sidecars are durably discarded before create_new makes a
        // replacement user name visible.
        let existing_open = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .await;
        let (mut file, _new_name) = match existing_open {
            Ok(file) => (file, false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(unix)]
                {
                    let root = self.cfg.storage_directory.clone();
                    let cleanup_partition = stored_partition.clone();
                    let cleanup_name = name.to_vec();
                    let cleanup = tokio::task::spawn_blocking(move || {
                        let result =
                            super::atomic::discard(&root, &cleanup_partition, &cleanup_name);
                        (guard, result)
                    });
                    let (returned_guard, result) = match cleanup.await {
                        Ok(result) => result,
                        Err(error) if error.is_panic() => {
                            std::panic::resume_unwind(error.into_panic())
                        }
                        Err(_) => return Err(Error::Closed),
                    };
                    guard = returned_guard;
                    result?;
                }
                #[cfg(unix)]
                let file = if require_atomic {
                    let region = Header::create_atomic(&versions).0;
                    let root = self.cfg.storage_directory.clone();
                    let creation_partition = stored_partition.clone();
                    let creation_name = name.to_vec();
                    let live_path = path.clone();
                    let creation = tokio::task::spawn_blocking(move || {
                        let result = super::atomic::create_live(
                            &root,
                            &creation_partition,
                            &creation_name,
                            &live_path,
                            &region,
                        );
                        (guard, result)
                    });
                    let (returned_guard, result) = match creation.await {
                        Ok(result) => result,
                        Err(error) if error.is_panic() => {
                            std::panic::resume_unwind(error.into_panic())
                        }
                        Err(_) => return Err(Error::Closed),
                    };
                    guard = returned_guard;
                    fs::File::from_std(result.map_err(|error| {
                        Error::BlobOpenFailed(partition.into(), hex(name), error.into())
                    })?)
                } else {
                    fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .await
                        .map_err(|error| {
                            Error::BlobOpenFailed(partition.into(), hex(name), error.into())
                        })?
                };
                #[cfg(not(unix))]
                let file = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .await
                    .map_err(|error| {
                        Error::BlobOpenFailed(partition.into(), hex(name), error.into())
                    })?;
                (file, true)
            }
            Err(error) => {
                return Err(Error::BlobOpenFailed(
                    partition.into(),
                    hex(name),
                    error.into(),
                ));
            }
        };
        #[cfg(not(unix))]
        let _ = _new_name;
        file.set_max_buf_size(self.cfg.maximum_buffer_size);

        #[cfg(unix)]
        let generation = self.namespace.generation(&stored_partition, name);
        #[cfg(unix)]
        let shared_v2 = self
            .namespace
            .v2_state(&stored_partition, name, &generation);

        let raw_len = file.metadata().await.map_err(|_| Error::ReadFailed)?.len();
        let existing = resolve_header(&mut file, raw_len, &versions, partition, name).await?;
        let (file, guard, (logical_size, blob_version, data_offset)) = match existing {
            Some(resolved) => {
                if require_atomic && resolved.2 != Layout::V2.data_offset() {
                    return Err(Error::BlobOpenFailed(
                        partition.into(),
                        hex(name),
                        std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "blob was not created with atomic storage",
                        )
                        .into(),
                    ));
                }
                #[cfg(unix)]
                if shared_v2.is_some() && resolved.2 != Layout::V2.data_offset() {
                    return Err(Error::BlobCorrupt(
                        partition.into(),
                        hex(name),
                        "atomic state restored a non-V2 header".into(),
                    ));
                }
                (file, guard, (resolved.0, resolved.1, resolved.2))
            }
            None => {
                let parent = parent.to_path_buf();
                let storage_directory = self.cfg.storage_directory.clone();
                let err_partition = partition.to_string();
                let err_name = hex(name);
                let creation = tokio::task::spawn(async move {
                    #[cfg(unix)]
                    {
                        sync_dir(&parent).await?;
                        sync_dir(&storage_directory).await?;
                    }
                    #[cfg(not(unix))]
                    let _ = (parent, storage_directory);

                    let (region, blob_version) = if require_atomic {
                        Header::create_atomic(&versions)
                    } else {
                        Header::create(&versions)
                    };
                    let data_offset = region.len() as u64;
                    file.set_len(0).await.map_err(|error| {
                        Error::BlobResizeFailed(
                            err_partition.clone(),
                            err_name.clone(),
                            error.into(),
                        )
                    })?;
                    file.rewind().await.map_err(|_| Error::WriteFailed)?;
                    file.write_all(&region)
                        .await
                        .map_err(|_| Error::WriteFailed)?;
                    file.sync_all().await.map_err(|error| {
                        Error::BlobSyncFailed(err_partition.clone(), err_name.clone(), error.into())
                    })?;

                    Ok::<_, Error>((file, guard, (0, blob_version, data_offset)))
                });
                match creation.await {
                    Ok(result) => result?,
                    Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
                    Err(_) => return Err(Error::Closed),
                }
            }
        };

        #[cfg(not(unix))]
        if data_offset == Layout::V2.data_offset() {
            return Err(unsupported_atomic(partition, name));
        }

        #[cfg(unix)]
        let file = file.into_std().await;

        let mut logical_size = logical_size;
        #[cfg(unix)]
        let atomic_state = if data_offset == Layout::V2.data_offset() {
            let state = if let Some(state) = shared_v2 {
                state
            } else {
                let recovery_file = file.try_clone().map_err(|_| Error::ReadFailed)?;
                let recovered = tokio::task::spawn_blocking(move || {
                    unix::V2State::recover(&recovery_file, data_offset)
                })
                .await
                .map_err(|_| Error::Closed)?
                .map_err(|error| {
                    Error::BlobCorrupt(
                        partition.into(),
                        hex(name),
                        format!("atomic log recovery failed: {error}"),
                    )
                })?;
                let state = Arc::new(tokio::sync::Mutex::new(recovered));
                self.namespace
                    .insert_v2_state(&stored_partition, name, &generation, &state);
                state
            };
            Some(state)
        } else {
            None
        };
        #[cfg(unix)]
        let atomic = atomic_state.clone().map(|state| {
            unix::V2Context::new(
                state,
                self.namespace.clone(),
                self.cfg.storage_directory.clone(),
            )
        });

        #[cfg(not(unix))]
        let generation = self.namespace.generation(&stored_partition, name);
        #[cfg(unix)]
        let blob = Blob::new(
            stored_partition.clone(),
            name,
            file,
            self.pool.clone(),
            data_offset,
            generation.clone(),
            atomic,
        );
        #[cfg(not(unix))]
        let blob = Blob::new(
            stored_partition,
            name,
            file,
            self.pool.clone(),
            data_offset,
            generation,
        );
        drop(guard);

        #[cfg(unix)]
        if let Some(state) = atomic_state {
            let state = state.lock().await;
            if state.is_poisoned() {
                return Err(Error::BlobCorrupt(
                    partition.into(),
                    hex(name),
                    "atomic blob generation is poisoned".into(),
                ));
            }
            logical_size = state.logical_len();
        }
        Ok((blob, logical_size, blob_version))
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
        self.open_versioned_inner(partition, name, versions, false)
            .await
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;

        let _guard = self.lock_recovered().await?;
        let root = self.cfg.storage_directory.clone();
        let requested = partition.to_string();
        let resolution = tokio::task::spawn_blocking(move || {
            super::batch::resolve_partition_name(&root, &requested)
        });
        let stored_partition = match resolution.await {
            Ok(result) => result?,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => return Err(Error::Closed),
        };
        let path = self.cfg.storage_directory.join(&stored_partition);
        let operation = if let Some(name) = name {
            fs::remove_file(path.join(hex(name)))
                .await
                .map_err(|_| Error::BlobMissing(partition.into(), hex(name)))?;
            #[cfg(unix)]
            sync_dir(&path).await?;
            super::batch::Operation::Remove(crate::RemoveTarget::Blob {
                partition: stored_partition.clone(),
                name: name.to_vec(),
            })
        } else {
            fs::remove_dir_all(&path)
                .await
                .map_err(|_| Error::PartitionMissing(partition.into()))?;
            #[cfg(unix)]
            sync_dir(&self.cfg.storage_directory).await?;
            super::batch::Operation::Remove(crate::RemoveTarget::Partition(
                stored_partition.clone(),
            ))
        };
        self.namespace.invalidate_operations(&[operation]);

        #[cfg(unix)]
        {
            let root = self.cfg.storage_directory.clone();
            let cleanup_partition = stored_partition.clone();
            let cleanup_name = name.map(<[u8]>::to_vec);
            let cleanup = tokio::task::spawn_blocking(move || {
                let result = cleanup_name.map_or_else(
                    || super::atomic::discard_partition(&root, &cleanup_partition),
                    |name| super::atomic::discard(&root, &cleanup_partition, &name),
                );
                (_guard, result)
            });
            let (_guard, result) = match cleanup.await {
                Ok(result) => result,
                Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
                Err(_) => return Err(Error::Closed),
            };
            result?;
        }
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        super::validate_partition_name(partition)?;

        // Acquire the filesystem lock
        let _guard = self.lock_recovered().await?;

        // Scan the partition directory
        let path = self.cfg.storage_directory.join(partition);
        let mut entries = fs::read_dir(path)
            .await
            .map_err(|_| Error::PartitionMissing(partition.into()))?;
        let mut blobs = Vec::new();
        let mut removed_creation = false;
        while let Some(entry) = entries.next_entry().await.map_err(|_| Error::ReadFailed)? {
            let file_type = entry.file_type().await.map_err(|_| Error::ReadFailed)?;
            if !file_type.is_file() {
                return Err(Error::PartitionCorrupt(partition.into()));
            }
            let file_name = entry.file_name();
            if super::atomic::is_creation_file_name(&file_name) {
                fs::remove_file(entry.path())
                    .await
                    .map_err(|_| Error::ReadFailed)?;
                removed_creation = true;
                continue;
            }
            if let Some(name) = file_name.to_str() {
                // Reject anything that isn't canonical lowercase hex (no `0x`
                // prefix, no whitespace) since `from_hex` is lenient and
                // storage only ever writes the canonical form via `hex()`.
                let decoded = from_hex(name).ok_or(Error::PartitionCorrupt(partition.into()))?;
                if hex(&decoded) != name {
                    return Err(Error::PartitionCorrupt(partition.into()));
                }

                blobs.push(decoded);
            }
        }
        if removed_creation {
            sync_dir(&self.cfg.storage_directory.join(partition)).await?;
        }
        Ok(blobs)
    }
}

impl crate::AtomicStorage for Storage {
    type AtomicBlob = Blob;

    async fn open_atomic_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::AtomicBlob, u64, u16), Error> {
        self.open_versioned_inner(partition, name, versions, true)
            .await
    }
}

impl crate::BatchStorage for Storage {
    async fn start_apply(
        &self,
        operations: Vec<BatchOperation<Self::AtomicBlob>>,
    ) -> Result<Handle<()>, Error> {
        self.start_apply_guarded(operations, || {}, || {}, || {})
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, *};
    #[cfg(unix)]
    use crate::{AtomicBlob as _, AtomicStorage as _, storage::tests::run_atomic_blob_tests};
    use crate::{
        BatchStorage as _, Blob, BufferPoolConfig, RemoveTarget, Storage as _, WriteOptions,
        storage::{
            Layout,
            tests::{run_batch_storage_tests, run_storage_foreign_handle_test, run_storage_tests},
        },
        telemetry::metrics::Registry,
    };
    use commonware_utils::sys_rng;
    use rand::RngExt as _;
    use std::{env, time::Duration};

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    fn random_suffix() -> u64 {
        let mut rng = sys_rng();
        rng.random()
    }

    #[test]
    fn test_batch_worker_fanout_is_bounded() {
        let jobs = MAX_BATCH_WORKERS * 2 + 1;
        let threads = commonware_utils::sync::Mutex::new(std::collections::HashSet::new());
        let results = run_batch_workers((0..jobs).collect(), |job| {
            threads.lock().insert(std::thread::current().id());
            job
        });

        assert_eq!(results, (0..jobs).collect::<Vec<_>>());
        assert!(threads.lock().len() <= MAX_BATCH_WORKERS);
    }

    #[cfg(unix)]
    fn copy_tree(source: &Path, destination: &Path) {
        std::fs::create_dir_all(destination).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn test_storage() {
        let storage_directory = env::temp_dir().join(format!("storage_tokio_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());
        let tested = storage.clone();
        run_storage_tests(storage.clone()).await;
        run_batch_storage_tests(storage.clone()).await;
        #[cfg(unix)]
        {
            let (atomic, _) = storage
                .open_atomic("atomic_storage", b"blob")
                .await
                .unwrap();
            run_atomic_blob_tests(atomic).await;
        }

        let foreign_directory =
            env::temp_dir().join(format!("storage_tokio_foreign_{}", random_suffix()));
        let foreign = Storage::new(
            Config::new(foreign_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        run_storage_foreign_handle_test(&tested, &foreign).await;

        let _ = std::fs::remove_dir_all(storage_directory);
        let _ = std::fs::remove_dir_all(foreign_directory);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_recovery_discards_arbitrary_unsynced_log_tail() {
        let source_directory =
            env::temp_dir().join(format!("storage_tokio_atomic_source_{}", random_suffix()));
        let storage = Storage::new(
            Config::new(source_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let (blob, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        let baseline = (0..16_384)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        blob.update(0, baseline.clone(), baseline.len() as u64)
            .await
            .unwrap();
        blob.sync().await.unwrap();
        let live_path = source_directory
            .join("partition")
            .join(commonware_formatting::hex(b"blob"));
        let committed_end = std::fs::metadata(&live_path).unwrap().len();
        blob.update(0, vec![0xa5; baseline.len()], baseline.len() as u64)
            .await
            .unwrap();
        drop((blob, storage));

        for damage in 0..4 {
            let directory =
                env::temp_dir().join(format!("storage_tokio_atomic_torn_{}", random_suffix()));
            copy_tree(&source_directory, &directory);
            let live_path = directory
                .join("partition")
                .join(commonware_formatting::hex(b"blob"));
            let raw_len = std::fs::metadata(&live_path).unwrap().len();
            match damage {
                0 => std::fs::OpenOptions::new()
                    .write(true)
                    .open(&live_path)
                    .unwrap()
                    .set_len(committed_end)
                    .unwrap(),
                1 => std::fs::OpenOptions::new()
                    .write(true)
                    .open(&live_path)
                    .unwrap()
                    .set_len(committed_end + 3)
                    .unwrap(),
                2 => {
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&live_path)
                        .unwrap();
                    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(committed_end))
                        .unwrap();
                    std::io::Write::write_all(&mut file, b"bad").unwrap();
                }
                3 => std::fs::OpenOptions::new()
                    .write(true)
                    .open(&live_path)
                    .unwrap()
                    .set_len(raw_len + 4096)
                    .unwrap(),
                _ => unreachable!(),
            }

            let recovered =
                Storage::new(Config::new(directory.clone(), 2 * 1024 * 1024), test_pool());
            let (blob, len) = recovered.open_atomic("partition", b"blob").await.unwrap();
            assert_eq!(len, baseline.len() as u64, "damage case {damage}");
            assert_eq!(
                blob.read_at(0, baseline.len()).await.unwrap().coalesce(),
                baseline.as_slice(),
                "damage case {damage}"
            );
            assert_eq!(std::fs::metadata(live_path).unwrap().len(), committed_end);
            drop((blob, recovered));
            std::fs::remove_dir_all(directory).unwrap();
        }
        std::fs::remove_dir_all(source_directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_independent_opens_share_dirty_generation() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_atomic_shared_{}", random_suffix()));
        let config = Config::new(directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config.clone(), test_pool());
        let (first, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        first.update(0, b"old", 3).await.unwrap();
        first.sync().await.unwrap();
        first.update(0, b"new-value", 9).await.unwrap();

        let (second, len) = storage.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(len, 9);
        assert_eq!(second.read_at(0, 9).await.unwrap().coalesce(), b"new-value");
        second.sync().await.unwrap();
        drop((first, second, storage));

        let recovered = Storage::new(config, test_pool());
        let (blob, len) = recovered.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(len, 9);
        assert_eq!(blob.read_at(0, 9).await.unwrap().coalesce(), b"new-value");
        drop((blob, recovered));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_sync_frontiers_recover_exactly() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_atomic_frontier_{}", random_suffix()));
        let config = Config::new(directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config.clone(), test_pool());
        let (updated, _) = storage.open_atomic("partition", b"updated").await.unwrap();
        updated.update(0, b"durable", 7).await.unwrap();
        updated.sync().await.unwrap();
        updated.update(0, b"pending", 7).await.unwrap();

        let (written, _) = storage.open_atomic("partition", b"written").await.unwrap();
        written
            .write_at(0, b"sync-write", WriteOptions::SYNC)
            .await
            .unwrap();
        drop((updated, written, storage));

        let recovered = Storage::new(config, test_pool());
        let (updated, len) = recovered
            .open_atomic("partition", b"updated")
            .await
            .unwrap();
        assert_eq!(len, 7);
        assert_eq!(updated.read_at(0, 7).await.unwrap().coalesce(), b"durable");
        let (written, len) = recovered
            .open_atomic("partition", b"written")
            .await
            .unwrap();
        assert_eq!(len, 10);
        assert_eq!(
            written.read_at(0, 10).await.unwrap().coalesce(),
            b"sync-write"
        );
        drop((updated, written, recovered));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_remove_recreate_rejects_stale_publication() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_atomic_recreate_{}", random_suffix()));
        let config = Config::new(directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config.clone(), test_pool());
        let (old, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        old.update(0, b"old", 3).await.unwrap();
        old.sync().await.unwrap();
        storage.remove("partition", Some(b"blob")).await.unwrap();
        old.update(0, b"stale", 5).await.unwrap();

        let (new, len) = storage.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(len, 0);
        new.write_at(0, b"new", WriteOptions::SYNC).await.unwrap();
        assert!(matches!(old.sync().await, Err(Error::BlobMissing(..))));
        drop((old, new, storage));

        let recovered = Storage::new(config, test_pool());
        let (blob, len) = recovered.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"new");
        drop((blob, recovered));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_start_sync_is_self_driving() {
        let directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_start_sync_{}",
            random_suffix()
        ));
        let config = Config::new(directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config.clone(), test_pool());
        let (blob, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        blob.update(0, b"durable", 7).await.unwrap();
        drop(blob.start_sync().await);
        blob.update(0, b"pending", 7).await.unwrap();
        drop((blob, storage));

        let recovered = Storage::new(config, test_pool());
        let (blob, len) = recovered.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(blob.read_at(0, 7).await.unwrap().coalesce(), b"durable");
        drop((blob, recovered));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_scan_sweeps_interrupted_creation() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_atomic_scan_{}", random_suffix()));
        let storage = Storage::new(Config::new(directory.clone(), 2 * 1024 * 1024), test_pool());
        let (blob, _) = storage.open_atomic("partition", b"live").await.unwrap();
        drop(blob);
        let partition = directory.join("partition");
        let staged = partition.join(".commonware-uno-create-interrupted");
        std::fs::write(&staged, b"partial").unwrap();
        std::fs::File::open(&partition).unwrap().sync_all().unwrap();

        assert_eq!(
            storage.scan("partition").await.unwrap(),
            vec![b"live".to_vec()]
        );
        assert!(!staged.exists());

        let _ = std::fs::remove_dir_all(directory);
    }

    /// Dropping the `start_sync` receiver must not break the blob: the handle stays
    /// usable and a later sync still persists data.
    #[tokio::test]
    async fn test_start_sync_dropped_receiver() {
        let mut rng = sys_rng();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_start_sync_{}", rng.random::<u64>()));
        let config = Config::new(storage_directory, 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());

        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();
        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();

        // Drop the completion receiver immediately.
        drop(blob.start_sync().await);

        // The blob remains usable, and a subsequent sync persists the data.
        blob.start_sync().await.await.unwrap();
        drop(blob);

        let (blob, len) = storage.open("partition", b"test_blob").await.unwrap();
        assert_eq!(len, 11);
        let read = blob.read_at(0, 11).await.unwrap().coalesce();
        assert_eq!(read.as_ref(), b"hello world");
    }

    /// Once the blocking worker owns the namespace guard, dropping the caller cannot abandon a
    /// committed batch or let a later open observe its partial progress.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_apply_batch_cancellation_completes() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_batch_cancel_{}", random_suffix()));
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let (old, _) = storage.open("batch_cancel", b"victim").await.unwrap();
        old.write_at(0, b"old", WriteOptions::SYNC).await.unwrap();

        let operations = vec![
            RemoveTarget::Blob {
                partition: "batch_cancel".into(),
                name: b"victim".to_vec(),
            }
            .into(),
        ];
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
        let removing = storage.clone();
        let task = tokio::spawn(async move {
            removing
                .start_apply_guarded(
                    operations,
                    move || {
                        started_tx.send(()).expect("caller waits for worker");
                        proceed_rx.recv().expect("caller releases worker");
                    },
                    || {},
                    || {},
                )
                .await
        });

        tokio::time::timeout(Duration::from_secs(10), started_rx)
            .await
            .expect("blocking worker did not start")
            .expect("blocking worker dropped its start signal");
        task.abort();
        proceed_tx.send(()).expect("blocking worker is waiting");
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));

        // This open serializes behind the worker and can only recreate the fully removed name.
        let (new, size) = storage.open("batch_cancel", b"victim").await.unwrap();
        assert_eq!(size, 0);
        new.write_at(0, b"new", WriteOptions::SYNC).await.unwrap();
        assert_eq!(old.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert_eq!(new.read_at(0, 3).await.unwrap().coalesce(), b"new");

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    /// A committed batch no longer depends on its completion observer being retained or polled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_start_apply_returns_at_commit_and_survives_handle_drop() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_batch_start_{}", random_suffix()));
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let (old, _) = storage.open("batch_start", b"victim").await.unwrap();
        old.write_at(0, b"old", WriteOptions::SYNC).await.unwrap();
        let (resized, _) = storage
            .open_atomic("batch_resize", b"retained")
            .await
            .unwrap();
        resized
            .write_at(0, b"resize", WriteOptions::SYNC)
            .await
            .unwrap();
        let victim = storage_directory
            .join("batch_start")
            .join(commonware_formatting::hex(b"victim"));
        let operations = vec![
            RemoveTarget::Blob {
                partition: "batch_start".into(),
                name: b"victim".to_vec(),
            }
            .into(),
            BatchOperation::Resize {
                blob: resized.clone(),
                len: 3,
            },
        ];
        let (parked_tx, parked_rx) = oneshot::channel();
        let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = oneshot::channel();
        let completion = storage
            .start_apply_guarded(
                operations,
                || {},
                move || {
                    parked_tx
                        .send(())
                        .expect("caller waits for committed worker");
                    proceed_rx.recv().expect("caller releases committed worker");
                },
                move || {
                    let _ = finished_tx.send(());
                },
            )
            .await
            .unwrap();
        parked_rx.await.unwrap();

        // The decision is durable, while its committed namespace effects remain pending.
        assert!(victim.exists());
        drop(completion);
        proceed_tx.send(()).unwrap();

        tokio::time::timeout(Duration::from_secs(10), finished_rx)
            .await
            .expect("committed worker did not finish without an observer")
            .unwrap();
        assert!(!victim.exists());
        let blobs = storage.scan("batch_start").await.unwrap();
        assert!(blobs.is_empty());
        assert_eq!(old.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert_eq!(resized.read_at(0, 3).await.unwrap().coalesce(), b"res");

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_committed_removal_invalidates_generation_before_cleanup_finishes() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_batch_generation_{}",
            random_suffix()
        ));
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let (old, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        old.write_at(0, b"old", WriteOptions::SYNC).await.unwrap();
        let operations = vec![crate::storage::batch::Operation::Remove(
            RemoveTarget::Blob {
                partition: "partition".into(),
                name: b"blob".to_vec(),
            },
        )];

        storage
            .namespace
            .recovery_required
            .store(true, Ordering::Release);
        let error = crate::storage::batch::fail_final_control_sync_for_test(
            &storage_directory,
            &operations,
            |operations| storage.namespace.invalidate_operations(operations),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(
            !storage
                .namespace
                .is_current(old.partition(), old.name(), old.generation())
        );

        // Recovery can confirm the absent marker, but must not make the committed generation
        // current again.
        let error = storage
            .apply(vec![BatchOperation::Resize { blob: old, len: 1 }])
            .await
            .unwrap_err();
        assert!(matches!(error, Error::BlobMissing(..)));

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_atomic_sync_recovers_committed_candidate_before_republishing() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_batch_candidate_recovery_{}",
            random_suffix()
        ));
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let (blob, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        blob.update(0, b"candidate", 9).await.unwrap();

        let mut state = blob.lock_batch_state().await.unwrap();
        let prepared = blob
            .prepare_batch_commit(&mut state)
            .unwrap()
            .expect("pending update prepares a candidate");
        let participant = crate::storage::batch::Participant {
            partition: "partition".into(),
            name: b"blob".to_vec(),
            candidate: prepared.candidate(),
        };
        let operations = vec![crate::storage::batch::Operation::Publish {
            partition: "partition".into(),
            name: b"blob".to_vec(),
        }];
        unix::Blob::activate_batch_commit(&mut state, prepared, false);
        drop(state);

        storage
            .namespace
            .recovery_required
            .store(true, Ordering::Release);
        let error = crate::storage::batch::apply_batch_with(
            &storage_directory,
            &[participant],
            &[],
            &operations,
            false,
            |_| {},
            || {
                Err(std::io::Error::other(
                    "injected participant install failure",
                ))
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);

        blob.sync().await.unwrap();
        assert!(!storage.namespace.recovery_required.load(Ordering::Acquire));
        drop(blob);
        drop(storage);
        let recovered = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let (blob, len) = recovered.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(len, 9);
        assert_eq!(blob.read_at(0, 9).await.unwrap().coalesce(), b"candidate");

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_partition_case_aliases_share_batch_identity() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_batch_case_alias_{}",
            random_suffix()
        ));
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let (old, _) = storage.open_atomic("CaseAlias", b"blob").await.unwrap();
        old.write_at(0, b"old", WriteOptions::SYNC).await.unwrap();

        // Case-sensitive filesystems correctly expose these as distinct namespaces.
        if !storage_directory.join("casealias").is_dir() {
            let (distinct, _) = storage.open_atomic("casealias", b"blob").await.unwrap();
            distinct
                .write_at(0, b"lower", WriteOptions::SYNC)
                .await
                .unwrap();
            storage
                .apply(vec![
                    BatchOperation::Remove(RemoveTarget::Partition("CaseAlias".into())),
                    BatchOperation::Resize {
                        blob: distinct.clone(),
                        len: 3,
                    },
                ])
                .await
                .unwrap();
            assert!(matches!(
                storage.scan("CaseAlias").await,
                Err(Error::PartitionMissing(_))
            ));
            assert_eq!(distinct.read_at(0, 3).await.unwrap().coalesce(), b"low");
            let _ = std::fs::remove_dir_all(storage_directory);
            return;
        }

        let error = storage
            .apply(vec![
                BatchOperation::Remove(RemoveTarget::Partition("casealias".into())),
                BatchOperation::Resize {
                    blob: old.clone(),
                    len: 3,
                },
            ])
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            Error::Io(error) if error.kind() == std::io::ErrorKind::InvalidInput
        ));
        assert_eq!(old.read_at(0, 3).await.unwrap().coalesce(), b"old");

        storage.remove("casealias", None).await.unwrap();
        let (new, len) = storage.open_atomic("casealias", b"blob").await.unwrap();
        assert_eq!(len, 0);
        new.write_at(0, b"new", WriteOptions::SYNC).await.unwrap();
        let (victim, _) = storage
            .open_atomic("case_alias_victim", b"blob")
            .await
            .unwrap();
        victim
            .write_at(0, b"keep", WriteOptions::SYNC)
            .await
            .unwrap();

        let error = storage
            .apply(vec![
                BatchOperation::Remove(RemoveTarget::Blob {
                    partition: "case_alias_victim".into(),
                    name: b"blob".to_vec(),
                }),
                BatchOperation::Resize { blob: old, len: 1 },
            ])
            .await
            .unwrap_err();
        assert!(matches!(error, Error::BlobMissing(..)));
        assert_eq!(new.read_at(0, 3).await.unwrap().coalesce(), b"new");
        assert_eq!(victim.read_at(0, 4).await.unwrap().coalesce(), b"keep");

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_missing_root_removal_invalidates_generation() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_batch_missing_root_{}",
            random_suffix()
        ));
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let (old, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        std::fs::remove_dir_all(&storage_directory).unwrap();

        storage
            .apply(vec![
                RemoveTarget::Blob {
                    partition: "partition".into(),
                    name: b"blob".to_vec(),
                }
                .into(),
            ])
            .await
            .unwrap();
        let error = storage
            .apply(vec![BatchOperation::Resize { blob: old, len: 0 }])
            .await
            .unwrap_err();
        assert!(matches!(error, Error::BlobMissing(..)));
    }

    #[tokio::test]
    async fn test_dropped_blob_generations_are_reclaimed() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_batch_generation_reclaim_{}",
            random_suffix()
        ));
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );

        for name in 0u64..65 {
            let (blob, _) = storage
                .open("partition", &name.to_be_bytes())
                .await
                .unwrap();
            drop(blob);
        }
        assert!(
            storage.namespace.generation_count() <= 64,
            "dropped handles must not accumulate one registry entry per opened name"
        );

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_first_namespace_operation_recovers_committed_batch() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_batch_recover_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config.clone(), test_pool());
        storage.open("alpha", b"remove").await.unwrap();
        storage.open("alpha", b"keep").await.unwrap();
        storage.open("beta", b"remove").await.unwrap();
        drop(storage);

        let operations = crate::storage::batch::canonicalize_operations(vec![
            crate::storage::batch::Operation::Remove(RemoveTarget::Partition("beta".into())),
            crate::storage::batch::Operation::Remove(RemoveTarget::Blob {
                partition: "alpha".into(),
                name: b"remove".to_vec(),
            }),
        ])
        .unwrap();
        assert!(
            crate::storage::batch::interrupt_committed_for_test(
                &storage_directory,
                &operations,
                1,
            )
            .is_err()
        );

        // A fresh instance completes the committed partition deletion before returning this scan.
        let restarted = Storage::new(config, test_pool());
        assert_eq!(
            restarted.scan("alpha").await.unwrap(),
            vec![b"keep".to_vec()]
        );
        assert!(restarted.scan("beta").await.is_err());

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_recovery_installs_every_committed_atomic_participant() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_batch_source_{}",
            random_suffix()
        ));
        let crash_directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_batch_crash_{}",
            random_suffix()
        ));
        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let (first, _) = storage.open_atomic("group", b"first").await.unwrap();
        let (second, _) = storage.open_atomic("group", b"second").await.unwrap();
        first
            .write_at(0, b"old-one", WriteOptions::default())
            .await
            .unwrap();
        second
            .write_at(0, b"old-two", WriteOptions::default())
            .await
            .unwrap();
        first.sync().await.unwrap();
        second.sync().await.unwrap();
        first
            .write_at(0, b"new-one", WriteOptions::default())
            .await
            .unwrap();
        second
            .write_at(0, b"new-two", WriteOptions::default())
            .await
            .unwrap();

        let (parked_tx, parked_rx) = tokio::sync::oneshot::channel();
        let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
        let completion = storage
            .start_apply_guarded(
                vec![
                    BatchOperation::Publish(first.clone()),
                    BatchOperation::Publish(second.clone()),
                ],
                || {},
                move || {
                    parked_tx
                        .send(())
                        .expect("test waits for the durable coordinator decision");
                    proceed_rx
                        .recv()
                        .expect("test releases coordinator completion");
                },
                || {},
            )
            .await
            .unwrap();
        parked_rx.await.unwrap();

        copy_tree(&storage_directory, &crash_directory);
        proceed_tx.send(()).unwrap();
        completion.await.unwrap();
        drop(first);
        drop(second);
        drop(storage);

        let recovered = Storage::new(
            Config::new(crash_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        let (first, first_len) = recovered.open_atomic("group", b"first").await.unwrap();
        let (second, second_len) = recovered.open_atomic("group", b"second").await.unwrap();
        assert_eq!(first_len, 7);
        assert_eq!(second_len, 7);
        assert_eq!(first.read_at(0, 7).await.unwrap().coalesce(), b"new-one");
        assert_eq!(second.read_at(0, 7).await.unwrap().coalesce(), b"new-two");

        let _ = std::fs::remove_dir_all(storage_directory);
        let _ = std::fs::remove_dir_all(crash_directory);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_recovery_installs_second_carried_batch() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_batch_carry_source_{}",
            random_suffix()
        ));
        let crash_directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_batch_carry_crash_{}",
            random_suffix()
        ));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());
        let mut blobs = Vec::new();
        for name in [b"first".as_slice(), b"second", b"third", b"fourth"] {
            blobs.push(storage.open_atomic("group", name).await.unwrap().0);
        }

        for epoch in *b"12" {
            for (index, blob) in blobs.iter().enumerate() {
                blob.write_at(
                    0,
                    vec![epoch, u8::try_from(index).unwrap()],
                    WriteOptions::default(),
                )
                .await
                .unwrap();
            }
            storage
                .apply(
                    blobs
                        .iter()
                        .cloned()
                        .map(BatchOperation::Publish)
                        .collect(),
                )
                .await
                .unwrap();
        }
        assert!(
            storage
                .namespace
                .carried_batch_decision
                .load(Ordering::Acquire)
        );

        copy_tree(&storage_directory, &crash_directory);
        drop(blobs);
        drop(storage);

        let recovered = Storage::new(
            Config::new(crash_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        for (index, name) in [b"first".as_slice(), b"second", b"third", b"fourth"]
            .into_iter()
            .enumerate()
        {
            let (blob, len) = recovered.open_atomic("group", name).await.unwrap();
            assert_eq!(len, 2);
            assert_eq!(
                blob.read_at(0, 2).await.unwrap().coalesce(),
                [b'2', u8::try_from(index).unwrap()]
            );
        }

        let _ = std::fs::remove_dir_all(storage_directory);
        let _ = std::fs::remove_dir_all(crash_directory);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_completed_removal_does_not_replay_over_recreation() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_batch_recreate_{}",
            random_suffix()
        ));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config.clone(), test_pool());
        storage.open_atomic("group", b"blob").await.unwrap();
        storage
            .apply(vec![BatchOperation::Remove(RemoveTarget::Blob {
                partition: "group".into(),
                name: b"blob".to_vec(),
            })])
            .await
            .unwrap();
        let (replacement, len) = storage.open_atomic("group", b"blob").await.unwrap();
        assert_eq!(len, 0);
        replacement
            .write_at(0, b"new", WriteOptions::default())
            .await
            .unwrap();
        replacement.sync().await.unwrap();
        drop(replacement);
        drop(storage);

        let recovered = Storage::new(config, test_pool());
        let (replacement, len) = recovered.open_atomic("group", b"blob").await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(replacement.read_at(0, 3).await.unwrap().coalesce(), b"new");

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_empty_batch_cannot_bypass_malformed_recovery() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_batch_malformed_{}", random_suffix()));
        let control = storage_directory.join(".commonware");
        std::fs::create_dir_all(&control).unwrap();
        let committed = control.join("_COMMONWARE_RUNTIME_UNO_COORDINATOR");
        std::fs::write(&committed, b"malformed").unwrap();

        let storage = Storage::new(
            Config::new(storage_directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        assert!(storage.apply(Vec::new()).await.is_err());
        assert!(storage.open("partition", b"blob").await.is_err());
        assert!(committed.exists());

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_blob_header_handling() {
        let mut rng = sys_rng();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_header_{}", rng.random::<u64>()));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());

        // Test 1: New blob (V1 by default) returns logical size 0 and correct app version
        let (blob, size) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "new blob should have logical size 0");

        // Verify raw file holds one header page
        let data_offset = Layout::V1.data_offset();
        let file_path = storage_directory.join("partition").join(hex(b"test"));
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            data_offset,
            "raw file should have a full header page"
        );

        // Test 2: Logical offset handling - write at offset 0 stores at the data offset
        let data = b"hello world";
        blob.write_at(0, data, WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        // Verify raw file size
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.len(), data_offset + data.len() as u64);

        // Verify raw file layout
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V1.magic());
        // Header version (bytes 4-5) and App version (bytes 6-7)
        assert_eq!(
            &raw_content[4..6],
            &Layout::V1.runtime_version().to_be_bytes()
        );
        // Data should start at the data offset
        assert_eq!(&raw_content[data_offset as usize..], data);

        // Test 3: Read at logical offset 0 returns data from the data offset
        let read_buf = blob.read_at(0, data.len()).await.unwrap();
        assert_eq!(read_buf.coalesce(), data);

        // Test 4: Resize with logical length
        blob.resize(5).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            data_offset + 5,
            "resize(5) should leave 5 raw bytes past the header page"
        );

        // resize(0) should leave only the header page
        blob.resize(0).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            data_offset,
            "resize(0) should leave only the header page"
        );

        // Test 5: Reopen existing blob preserves header and returns correct logical size
        blob.write_at(0, b"test data", WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob2, size2) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size2, 9, "reopened blob should have logical size 9");
        let read_buf = blob2.read_at(0, 9).await.unwrap();
        assert_eq!(read_buf.coalesce(), b"test data");
        drop(blob2);

        // Test 6: Corrupted blob recovery (0 < raw_size < 8)
        // Manually create a corrupted file with only 4 bytes
        let corrupted_path = storage_directory.join("partition").join(hex(b"corrupted"));
        std::fs::write(&corrupted_path, vec![0u8; 4]).unwrap();

        // Opening should truncate and write fresh header
        let (blob3, size3) = storage.open("partition", b"corrupted").await.unwrap();
        assert_eq!(size3, 0, "corrupted blob should return logical size 0");

        // Verify raw file now has a proper header page
        let metadata = std::fs::metadata(&corrupted_path).unwrap();
        assert_eq!(
            metadata.len(),
            Layout::V1.data_offset(),
            "corrupted blob should be reset to header-only"
        );

        // Cleanup
        drop(blob3);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Verify the end-to-end storage-page alignment invariant: paged data written to a V1 blob
    /// with a 4096-byte physical page size occupies exactly one aligned 4096-byte disk page
    /// per physical page (header page included), so page reads never straddle a page boundary.
    #[tokio::test]
    async fn test_v1_paged_alignment() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_aligned_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config, test_pool());

        // A logical page size whose physical page is exactly one 4096-byte storage page.
        const PHYSICAL_PAGE_SIZE: u64 = 4096;
        let logical = crate::buffer::paged::page_size(PHYSICAL_PAGE_SIZE as u32);
        let cache = crate::buffer::paged::CacheRef::new(
            test_pool(),
            logical,
            std::num::NonZeroUsize::new(16).unwrap(),
        );

        // Write several pages of patterned data through the paged writer (V1 blob via open()).
        let (blob, size) = storage.open("partition", b"aligned").await.unwrap();
        let mut writer = crate::buffer::paged::Writer::new(blob, size, 1024, cache)
            .await
            .unwrap();
        let item: Vec<u8> = (0..1000u32).flat_map(|i| i.to_be_bytes()).collect();
        for _ in 0..12 {
            writer.append(&item).await.unwrap();
        }
        let logical_size = writer.size();
        writer.sync().await.unwrap();

        // The raw file is a whole number of 4096-byte pages: one header page plus one page per
        // physical page of data (the partial tail page is zero-padded to a full physical page).
        let file_path = storage_directory.join("partition").join(hex(b"aligned"));
        let raw = std::fs::read(&file_path).unwrap();
        let pages = (logical_size as usize).div_ceil(logical.get() as usize);
        assert_eq!(raw.len() as u64 % PHYSICAL_PAGE_SIZE, 0);
        assert_eq!(
            raw.len() as u64,
            Layout::V1.data_offset() + pages as u64 * PHYSICAL_PAGE_SIZE
        );

        // Every physical page sits exactly within one aligned 4096-byte disk page, with a valid
        // CRC record in its final 12 bytes.
        for page in 0..pages {
            let start = Layout::V1.data_offset() as usize + page * PHYSICAL_PAGE_SIZE as usize;
            let physical = &raw[start..start + PHYSICAL_PAGE_SIZE as usize];
            assert!(
                crate::buffer::paged::validate_page_for_tests(physical),
                "page {page} failed CRC validation at aligned boundary"
            );
        }

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_torn_creation_recovers() {
        let storage_directory =
            env::temp_dir().join(format!("test_torn_creation_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        // Create a durable V1 blob to obtain the canonical header region bytes.
        let (blob, _) = storage.open("partition", b"torn").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);
        let path = storage_directory.join("partition").join(hex(b"torn"));
        let region = std::fs::read(&path).unwrap();

        // Simulate torn creations (the full state enumeration lives in the
        // Layout::interrupted_creation unit tables): a file truncated mid-CRC and the same
        // prefix at a persisted full length.
        let mut torn_content = vec![0u8; region.len()];
        torn_content[..10].copy_from_slice(&region[..10]);
        let states = [region[..10].to_vec(), torn_content];
        for state in states {
            std::fs::write(&path, &state).unwrap();
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, b"data".to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            drop(blob);

            // The healed blob round-trips through a reopen with its data intact.
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 4);
            let read = blob.read_at(0, 4).await.unwrap();
            assert_eq!(read.coalesce(), b"data");
            drop(blob);
        }

        // Foreign bytes are corruption, not a torn creation: nonzero padding behind a
        // torn (unparseable) prefix proves the file was never a canonical prefix of a
        // header region.
        let mut corrupt = vec![0u8; region.len()];
        corrupt[..10].copy_from_slice(&region[..10]);
        corrupt[100] = 0xFF;
        std::fs::write(&path, &corrupt).unwrap();
        let result = storage.open("partition", b"torn").await;
        assert!(matches!(result, Err(crate::Error::BlobCorrupt(_, _, _))));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Dropping an open future at any await point must leave the blob openable: creation
    /// runs to completion on a task that owns the filesystem lock, so a retry serializes
    /// behind it and never observes (or clobbers) a half-created blob.
    #[tokio::test]
    async fn test_open_dropped_mid_creation() {
        use futures::FutureExt;
        use std::{
            future::Future,
            pin::Pin,
            task::{Context, Poll},
        };

        /// Polls the wrapped future normally, but drops it after a fixed number of polls.
        struct DropAfter<F: Future + Unpin> {
            inner: Option<F>,
            remaining: usize,
        }

        impl<F: Future + Unpin> Future for DropAfter<F> {
            type Output = Option<F::Output>;

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                if self.remaining == 0 {
                    self.inner = None;
                    return Poll::Ready(None);
                }
                self.remaining -= 1;
                match self.inner.as_mut().unwrap().poll_unpin(cx) {
                    Poll::Ready(output) => Poll::Ready(Some(output)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }

        let storage_directory =
            env::temp_dir().join(format!("test_dropped_open_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        for depth in 0..64 {
            let name = format!("blob{depth}");
            let name = name.as_bytes();
            let dropped = DropAfter {
                inner: Some(Box::pin(storage.open("partition", name))),
                remaining: depth,
            }
            .await;
            let completed = dropped.is_some();
            drop(dropped);

            // Retry, write data, and confirm it survives reopen.
            let (blob, size) = storage.open("partition", name).await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, b"data".to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            drop(blob);
            let (blob, size) = storage.open("partition", name).await.unwrap();
            assert_eq!(size, 4);
            let read = blob.read_at(0, 4).await.unwrap();
            assert_eq!(read.coalesce(), b"data");
            drop(blob);

            // Once the first open completes within the poll budget, deeper drops add nothing.
            if completed {
                let _ = std::fs::remove_dir_all(&storage_directory);
                return;
            }
        }
        panic!("open never completed within the poll budget");
    }

    #[tokio::test]
    async fn test_blob_v1_rejects_nonzero_header_padding() {
        let storage_directory =
            env::temp_dir().join(format!("test_v1_header_padding_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        let partition_dir = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_dir).unwrap();
        let path = partition_dir.join(hex(b"dirty_padding"));
        let mut raw = crate::storage::header::tests::v1_blob_bytes(0, b"payload");
        raw[Header::PARSE_LEN] = 0xFF;
        std::fs::write(&path, raw).unwrap();

        let result = storage.open("partition", b"dirty_padding").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("header padding"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_v0_legacy_read() {
        let storage_directory =
            env::temp_dir().join(format!("test_v0_legacy_read_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        // Fabricate a legacy V0 blob on disk (creation is always V1): an 8-byte header
        // followed immediately by the payload.
        let payload = b"hello world";
        let partition_dir = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_dir).unwrap();
        let file_path = partition_dir.join(hex(b"v0"));
        std::fs::write(
            &file_path,
            crate::storage::header::tests::v0_blob_bytes(0, payload),
        )
        .unwrap();

        // The blob opens with its data intact and remains readable and writable in place.
        let (blob, size) = storage.open("partition", b"v0").await.unwrap();
        assert_eq!(size, payload.len() as u64);
        assert_eq!(
            blob.read_at(0, payload.len()).await.unwrap().coalesce(),
            payload
        );
        blob.write_at(size, b"!".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        // On disk the payload still sits immediately after the 8-byte V0 header.
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(raw_content.len(), Header::PRELUDE_SIZE + payload.len() + 1);
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V0.magic());
        assert_eq!(&raw_content[Header::PRELUDE_SIZE..], b"hello world!");

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_magic_mismatch() {
        let storage_directory =
            env::temp_dir().join(format!("test_magic_mismatch_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );

        // Create the partition directory and a file whose magic bytes are foreign (not a
        // prefix of any canonical header, so not a torn creation)
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();
        let bad_magic_path = partition_path.join(hex(b"bad_magic"));
        std::fs::write(&bad_magic_path, b"XXXXXXXX").unwrap();

        // Opening should fail with corrupt error
        let result = storage.open("partition", b"bad_magic").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("invalid magic"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Any file shorter than a header prelude must reset to a valid, empty blob on open
    /// rather than fail as corrupt.
    #[tokio::test]
    async fn test_blob_partial_header_reset() {
        let storage_directory =
            env::temp_dir().join(format!("test_partial_header_reset_{}", random_suffix()));
        let storage = Storage::new(
            Config {
                storage_directory: storage_directory.clone(),
                maximum_buffer_size: 1024 * 1024,
            },
            test_pool(),
        );
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();

        for prefix_len in 0..Header::PRELUDE_SIZE {
            let name = format!("short_{prefix_len}");
            let path = partition_path.join(hex(name.as_bytes()));
            // Seed a file shorter than a full header.
            std::fs::write(&path, vec![0u8; prefix_len]).unwrap();

            let (blob, size) = storage
                .open("partition", name.as_bytes())
                .await
                .expect("interrupted create should recover, not fail");
            assert_eq!(size, 0, "recovered blob should be empty");
            drop(blob);

            // The recovered blob is a valid header-only file and reopens cleanly.
            let raw = std::fs::read(&path).unwrap();
            assert_eq!(
                raw.len(),
                Layout::V1.data_offset() as usize,
                "recovered blob should be header-only"
            );
            assert_eq!(&raw[..Header::MAGIC_LENGTH], &Layout::V1.magic());
            storage
                .open("partition", name.as_bytes())
                .await
                .expect("reopen after recovery should succeed");
        }

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_scan_rejects_non_canonical_hex_file_names() {
        // `commonware_formatting::from_hex` is lenient (strips `0x`/`0X` prefixes
        // and ASCII whitespace), but storage only ever writes filenames in the
        // canonical lowercase hex form produced by `hex()`. Verify that scans
        // reject any filename that decodes successfully but doesn't round-trip
        // to its canonical form.
        for bad_name in ["0x626c6f62", "0X626C6F62", " 626c6f62", "626C6F62"] {
            let storage_directory = env::temp_dir().join(format!(
                "test_scan_non_canonical_{}_{}",
                bad_name.replace([' ', '0', 'x', 'X'], "_"),
                random_suffix()
            ));
            let storage = Storage::new(
                Config {
                    storage_directory: storage_directory.clone(),
                    maximum_buffer_size: 1024 * 1024,
                },
                test_pool(),
            );

            let partition_path = storage_directory.join("partition");
            std::fs::create_dir_all(&partition_path).unwrap();
            std::fs::write(partition_path.join(bad_name), []).unwrap();

            let err = match storage.scan("partition").await {
                Ok(_) => panic!("scan should have failed for filename {bad_name:?}"),
                Err(err) => err,
            };
            assert_eq!(
                err.to_string(),
                "partition corrupt: partition",
                "filename {bad_name:?} should be rejected as corrupt",
            );

            let _ = std::fs::remove_dir_all(&storage_directory);
        }
    }
}
