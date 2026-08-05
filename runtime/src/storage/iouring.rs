//! This module provides an io_uring-based implementation of the [crate::Storage] trait,
//! offering fast, high-throughput file operations on Linux systems.
//!
//! ## Architecture
//!
//! I/O operations are submitted through an io_uring [Handle][crate::iouring::Handle] to a
//! dedicated event loop running in another thread.
//!
//! ## Memory Safety
//!
//! Buffers and file descriptors are owned by the active request state machine inside the io_uring
//! loop, ensuring that the memory location is valid for the duration of the operation.
//!
//! ## Feature Flag
//!
//! This implementation is enabled by using the `iouring-storage` feature.
//!
//! ## Linux Only
//!
//! This implementation is only available on Linux systems that support io_uring.
//! It requires Linux kernel 6.1 or newer. See [crate::iouring] for details.

use super::{Header, uno};
use crate::{
    BatchOperation, Blob as _, Buf, BufferPool, Error, Handle, IntegrityAppend, IntegrityBoundary,
    IntegrityScheme, IntegritySnapshot, IntegrityToken, IntegrityUnit, IoBufs, IoBufsMut,
    WriteOptions,
    iouring::{self},
    telemetry::metrics::Register,
    utils,
};
use commonware_formatting::{from_hex, hex};
use commonware_utils::{channel::oneshot, sync::Mutex as SyncMutex};
use futures::future::join_all;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    future::Future,
    io::{Error as IoError, Read, Seek, SeekFrom, Write},
    ops::RangeInclusive,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Mutex, OwnedMutexGuard as TokioOwnedMutexGuard};

type ResolvedHeader = (u64, u16, u64, Option<[u8; Header::V2_INCARNATION_LEN]>);
type BoxedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Reads a blob's leading bytes and resolves its header (see [super::header::resolve]).
fn resolve_header(
    file: &mut File,
    raw_len: u64,
    versions: &RangeInclusive<u16>,
    partition: &str,
    name: &[u8],
) -> Result<Option<ResolvedHeader>, Error> {
    let mut raw = vec![0u8; Header::resolve_len(raw_len)];
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error::ReadFailed)?;
    file.read_exact(&mut raw).map_err(|_| Error::ReadFailed)?;
    Ok(
        super::header::resolve(&raw, raw_len, versions, partition, name)?.map(
            |(logical_size, blob_version, data_offset)| {
                (
                    logical_size,
                    blob_version,
                    data_offset,
                    Header::atomic_incarnation(&raw),
                )
            },
        ),
    )
}

/// Syncs a directory to ensure directory entry changes are durable.
/// On Unix, directory metadata (file creation/deletion) must be explicitly fsynced.
fn sync_dir(path: &Path) -> Result<(), Error> {
    let dir = File::open(path).map_err(|e| {
        Error::BlobOpenFailed(
            path.to_string_lossy().to_string(),
            "directory".to_string(),
            e.into(),
        )
    })?;
    dir.sync_all().map_err(|e| {
        Error::BlobSyncFailed(
            path.to_string_lossy().to_string(),
            "directory".to_string(),
            e.into(),
        )
    })
}

/// Configuration for a [Storage].
#[derive(Clone, Debug)]
pub struct Config {
    /// Directory exclusively owned by this storage instance and its clones.
    ///
    /// Concurrent access by another storage instance or process is unsupported.
    pub storage_directory: PathBuf,
    /// Configuration for the iouring instance.
    pub iouring_config: iouring::Config,
    /// Stack size for the dedicated io_uring worker thread.
    pub thread_stack_size: usize,
}

#[derive(Clone)]
pub struct Storage {
    namespace: Arc<Namespace>,
    storage_directory: PathBuf,
    io_handle: iouring::Handle,
    pool: BufferPool,
}

struct Namespace {
    lock: Arc<Mutex<()>>,
    recovery_required: AtomicBool,
    carried_batch_decision: AtomicBool,
    embedded_batch_decision: SyncMutex<Option<Arc<super::batch::EmbeddedBatch>>>,
    storage_directory: PathBuf,
    generations: super::generation::Registry,
    atomic_states: SyncMutex<BTreeMap<(String, Vec<u8>), AtomicStateEntry>>,
}

struct AtomicStateEntry {
    generation: Weak<super::generation::Token>,
    state: Weak<super::preflush::Context>,
}

/// Mutable log/index state shared by every handle opened for one current V2 name generation.
type V2State = super::atomic::State;

/// Poisons a batch participant if its worker exits after mutation admission but before completion.
struct ArmedBatchState {
    state: TokioOwnedMutexGuard<V2State>,
    armed: bool,
}

impl ArmedBatchState {
    const fn new(state: TokioOwnedMutexGuard<V2State>) -> Self {
        Self { state, armed: true }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }

    fn poison(&mut self) {
        self.state.poison();
        self.armed = false;
    }
}

impl Drop for ArmedBatchState {
    fn drop(&mut self) {
        if self.armed {
            self.state.poison();
        }
    }
}

impl Namespace {
    /// Complete any carried embedded or removal decision while the caller holds `lock`.
    fn recover_locked(&self) -> Result<(), Error> {
        if !self.recovery_required.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Some(decision) = self.embedded_batch_decision.lock().clone() {
            super::batch::materialize_embedded(&self.storage_directory, &decision)?;
        }
        super::batch::recover_notifying(&self.storage_directory, |operations| {
            self.invalidate_operations(operations);
        })?;
        *self.embedded_batch_decision.lock() = None;
        self.recovery_required.store(false, Ordering::Release);
        self.carried_batch_decision.store(false, Ordering::Release);
        Ok(())
    }

    fn knows_partition(&self, partition: &str) -> bool {
        self.generations.knows_partition(partition)
    }

    fn generation(&self, partition: &str, name: &[u8]) -> Arc<super::generation::Token> {
        self.generations.generation(partition, name)
    }

    fn is_current(
        &self,
        partition: &str,
        name: &[u8],
        generation: &Arc<super::generation::Token>,
    ) -> bool {
        self.generations.is_current(partition, name, generation)
    }

    fn atomic_state(
        &self,
        partition: &str,
        name: &[u8],
        generation: &Arc<super::generation::Token>,
    ) -> Option<Arc<super::preflush::Context>> {
        let key = (partition.to_string(), name.to_vec());
        let mut states = self.atomic_states.lock();
        let entry = states.get(&key)?;
        let Some(entry_generation) = entry.generation.upgrade() else {
            states.remove(&key);
            return None;
        };
        if !Arc::ptr_eq(&entry_generation, generation) {
            states.remove(&key);
            return None;
        }
        let Some(state) = entry.state.upgrade() else {
            states.remove(&key);
            return None;
        };
        Some(state)
    }

    fn insert_atomic_state(
        &self,
        partition: &str,
        name: &[u8],
        generation: &Arc<super::generation::Token>,
        state: V2State,
    ) -> Result<Arc<super::preflush::Context>, Error> {
        let state = super::preflush::Context::new(state).map_err(|error| {
            Error::BlobCorrupt(
                partition.into(),
                hex(name),
                format!("atomic preflush initialization failed: {error}"),
            )
        })?;
        let mut states = self.atomic_states.lock();
        states.retain(|_, entry| entry.state.strong_count() != 0);
        states.insert(
            (partition.to_string(), name.to_vec()),
            AtomicStateEntry {
                generation: Arc::downgrade(generation),
                state: Arc::downgrade(&state),
            },
        );
        Ok(state)
    }

    fn invalidate_operations(&self, operations: &[super::batch::Operation]) {
        self.generations.invalidate(operations);
        let mut states = self.atomic_states.lock();
        for operation in operations {
            match operation {
                super::batch::Operation::Remove(crate::RemoveTarget::Blob { partition, name }) => {
                    states.remove(&(partition.clone(), name.clone()));
                }
                super::batch::Operation::Remove(crate::RemoveTarget::Partition(partition)) => {
                    states.retain(|(candidate, _), _| candidate != partition);
                }
                super::batch::Operation::Publish { .. }
                | super::batch::Operation::Rewind { .. } => {}
            }
        }
    }
}

impl Storage {
    /// Returns a new `Storage` instance.
    pub(crate) fn start(cfg: Config, registry: &mut impl Register, pool: BufferPool) -> Self {
        let Config {
            storage_directory,
            mut iouring_config,
            thread_stack_size,
        } = cfg;

        // Optimize performance by hinting the kernel that a single task will
        // submit requests. This is safe because each iouring instance runs in a
        // dedicated thread, which guarantees that the same thread that creates
        // the ring is the only thread submitting work to it.
        iouring_config.single_issuer = true;

        let (io_handle, iouring_loop) = iouring::IoUringLoop::new(iouring_config, registry);

        let storage = Self {
            namespace: Arc::new(Namespace {
                lock: Arc::new(Mutex::new(())),
                recovery_required: AtomicBool::new(true),
                carried_batch_decision: AtomicBool::new(false),
                embedded_batch_decision: SyncMutex::new(None),
                storage_directory: storage_directory.clone(),
                generations: super::generation::Registry::default(),
                atomic_states: SyncMutex::new(BTreeMap::new()),
            }),
            storage_directory,
            io_handle,
            pool,
        };

        utils::thread::spawn(thread_stack_size, move || iouring_loop.run());
        storage
    }

    /// Complete any prior committed batch while the namespace lock is held.
    fn recover_locked(&self) -> Result<(), Error> {
        self.namespace.recover_locked()
    }

    /// Commit a storage batch from a self-driving worker that owns the namespace lock.
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
        let mut mutation_handles = Vec::new();
        let mut removals = BTreeSet::new();
        for operation in operations {
            match operation {
                BatchOperation::Remove(blob) => {
                    let partition = blob.partition.clone();
                    let name = blob.name.clone();
                    if blob.atomic.is_none() {
                        return Err(Error::BlobOpenFailed(
                            partition,
                            hex(&name),
                            IoError::new(
                                std::io::ErrorKind::Unsupported,
                                "batch deletion requires an atomic blob",
                            )
                            .into(),
                        ));
                    }
                    descriptors.push(super::batch::Operation::Remove(crate::RemoveTarget::Blob {
                        partition: partition.clone(),
                        name: name.clone(),
                    }));
                    mutation_handles.push((
                        partition.clone(),
                        name.clone(),
                        blob.generation.clone(),
                    ));
                    removals.insert((partition.clone(), name.clone()));
                    blobs.entry((partition, name)).or_insert(blob);
                }
                BatchOperation::Publish(blob) => {
                    let partition = blob.partition.clone();
                    let name = blob.name.clone();
                    if blob.atomic.is_none() {
                        return Err(Error::BlobOpenFailed(
                            partition,
                            hex(&name),
                            IoError::new(
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
                    mutation_handles.push((
                        partition.clone(),
                        name.clone(),
                        blob.generation.clone(),
                    ));
                    blobs.entry((partition, name)).or_insert(blob);
                }
                BatchOperation::Rewind { blob, len } => {
                    let partition = blob.partition.clone();
                    let name = blob.name.clone();
                    if blob.atomic.is_none() {
                        return Err(Error::BlobOpenFailed(
                            partition,
                            hex(&name),
                            IoError::new(
                                std::io::ErrorKind::Unsupported,
                                "batch rewind requires an atomic blob",
                            )
                            .into(),
                        ));
                    }
                    descriptors.push(super::batch::Operation::Rewind {
                        partition: partition.clone(),
                        name: name.clone(),
                        len,
                    });
                    mutation_handles.push((
                        partition.clone(),
                        name.clone(),
                        blob.generation.clone(),
                    ));
                    blobs.entry((partition, name)).or_insert(blob);
                }
            }
        }
        let filesystem_operations = super::batch::canonicalize_operations(descriptors)?;
        super::batch::preflight(&filesystem_operations)?;
        if filesystem_operations.is_empty() {
            let _guard = self.namespace.lock.clone().lock_owned().await;
            self.recover_locked()?;
            return Ok(Handle::ready(Ok(())));
        }

        let mutation_keys =
            filesystem_operations
                .iter()
                .filter_map(|operation| match operation {
                    super::batch::Operation::Publish { partition, name }
                    | super::batch::Operation::Rewind {
                        partition, name, ..
                    }
                    | super::batch::Operation::Remove(crate::RemoveTarget::Blob {
                        partition,
                        name,
                    }) => Some((partition.clone(), name.clone())),
                    super::batch::Operation::Remove(crate::RemoveTarget::Partition(_)) => None,
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

        let guard = self.namespace.lock.clone().lock_owned().await;
        let carry_decision = self
            .namespace
            .carried_batch_decision
            .load(Ordering::Acquire);
        let embedded_decision = if carry_decision {
            self.namespace.embedded_batch_decision.lock().clone()
        } else {
            self.recover_locked()?;
            None
        };
        for (partition, name, generation) in mutation_handles {
            if !self.namespace.is_current(&partition, &name, &generation) {
                return Err(Error::BlobMissing(partition, hex(&name)));
            }
        }
        let rewind_lengths = filesystem_operations
            .iter()
            .filter_map(|operation| match operation {
                super::batch::Operation::Rewind {
                    partition,
                    name,
                    len,
                } => Some(((partition.clone(), name.clone()), *len)),
                super::batch::Operation::Publish { .. } | super::batch::Operation::Remove(_) => {
                    None
                }
            })
            .collect::<BTreeMap<_, _>>();
        for (blob, state) in &locked {
            if let Some(len) = rewind_lengths.get(&(blob.partition.clone(), blob.name.clone())) {
                let _ = state.rewind_integrity_source(*len, None)?;
            }
        }
        let mut participants = Vec::new();
        for (blob, state) in &locked {
            let key = (blob.partition.clone(), blob.name.clone());
            let participates = if removals.contains(&key) {
                true
            } else if let Some(len) = rewind_lengths.get(&key) {
                state.participates_after_rewind(*len)?
            } else {
                state.is_dirty()
            };
            if participates {
                participants.push((blob.partition.as_str(), blob.name.as_slice()));
            }
        }
        super::batch::preflight_embedded(&filesystem_operations, participants)?;

        self.namespace
            .recovery_required
            .store(true, Ordering::Release);
        let root = self.storage_directory.clone();
        let namespace = self.namespace.clone();
        let (commit_sender, commit_receiver) = oneshot::channel();
        let (completion_sender, completion_receiver) = oneshot::channel();
        drop(tokio::spawn(async move {
            match tokio::task::spawn_blocking(on_worker_start).await {
                Ok(()) => {}
                Err(error) if error.is_panic() => {
                    std::panic::resume_unwind(error.into_panic());
                }
                Err(_) => {
                    let error = Error::Closed;
                    let _ = commit_sender.send(Err(error.clone()));
                    drop(guard);
                    on_complete();
                    let _ = completion_sender.send(Err(error));
                    return;
                }
            }

            let payload_budget = if locked.is_empty() {
                super::atomic::MAX_VALIDATED_PAYLOAD_LEN
            } else {
                super::atomic::MAX_VALIDATED_PAYLOAD_LEN / locked.len() as u64
            };
            let preparations =
                locked.into_iter().map(|(blob, state)| {
                    let removed = removals.contains(&(blob.partition.clone(), blob.name.clone()));
                    let resize = rewind_lengths
                        .get(&(blob.partition.clone(), blob.name.clone()))
                        .copied();
                    async move {
                        let mut operation = ArmedBatchState::new(state);
                        if let Some(len) = resize {
                            let rewound = blob.rewind_log(&mut operation.state, len, None).await;
                            if let Err(error) = rewound {
                                return (blob, operation, Err(error), removed);
                            }
                        }
                        let mut prepared = if removed {
                            blob.prepare_batch_delete_unflushed(&operation.state)
                                .map(Some)
                        } else {
                            blob.prepare_batch_commit_unflushed(&mut operation.state)
                                .await
                        };
                        let preflush = prepared.as_ref().ok().and_then(Option::as_ref).is_some_and(
                            |prepared| match prepared.payload_checksum() {
                                super::atomic::PayloadChecksumEligibility::Eligible(Some(
                                    checksum,
                                )) => checksum.len > payload_budget,
                                super::atomic::PayloadChecksumEligibility::Eligible(None) => false,
                                super::atomic::PayloadChecksumEligibility::Ineligible => true,
                            },
                        );
                        if preflush {
                            let target = prepared.as_ref().unwrap().as_ref().unwrap().raw_len();
                            match blob.ensure_preflush(target).await {
                                Ok(()) => prepared
                                    .as_mut()
                                    .unwrap()
                                    .as_mut()
                                    .unwrap()
                                    .mark_payload_preflushed(),
                                Err(error) => prepared = Err(error),
                            }
                        }
                        (blob, operation, prepared, removed)
                    }
                });
            let mut prepared_states = join_all(preparations).await;

            let preparation_error = prepared_states
                .iter()
                .find_map(|(_, _, result, _)| result.as_ref().err().cloned());
            if let Some(error) = preparation_error {
                for (_, operation, _, _) in &mut prepared_states {
                    operation.poison();
                }
                let _ = commit_sender.send(Err(error.clone()));
                drop(guard);
                on_complete();
                let _ = completion_sender.send(Err(error));
                return;
            }
            let mut speculative_payload_bytes = Some(0u64);
            for (_, _, prepared, _) in &prepared_states {
                let Some(prepared) = prepared.as_ref().unwrap() else {
                    continue;
                };
                match prepared.payload_checksum() {
                    super::atomic::PayloadChecksumEligibility::Eligible(checksum) => {
                        speculative_payload_bytes = speculative_payload_bytes.and_then(|total| {
                            total.checked_add(checksum.map_or(0, |checksum| checksum.len))
                        });
                    }
                    super::atomic::PayloadChecksumEligibility::Ineligible => {
                        speculative_payload_bytes = None;
                    }
                }
            }
            let participant_count = prepared_states
                .iter()
                .filter(|(_, _, prepared, _)| prepared.as_ref().unwrap().is_some())
                .count();
            let verifiable = speculative_payload_bytes.is_some();
            let embedded_eligible = verifiable
                && speculative_payload_bytes.is_some_and(|verified_bytes| {
                    super::batch::supports_speculation(
                        &filesystem_operations,
                        participant_count,
                        verified_bytes,
                    )
                });
            let participants = prepared_states
                .iter()
                .filter_map(|(blob, _, prepared, _)| {
                    prepared.as_ref().unwrap().as_ref().map(|prepared| {
                        let payload_checksum = if verifiable {
                            let super::atomic::PayloadChecksumEligibility::Eligible(checksum) =
                                prepared.payload_checksum()
                            else {
                                unreachable!("verifiable groups contain only eligible epochs")
                            };
                            checksum
                        } else {
                            None
                        };
                        super::batch::Participant {
                            partition: blob.partition.clone(),
                            name: blob.name.clone(),
                            incarnation: blob.incarnation(),
                            candidate: prepared.candidate(),
                            payload_start: if verifiable {
                                prepared.payload_start()
                            } else {
                                0
                            },
                            payload_checksum,
                        }
                    })
                })
                .collect::<Vec<_>>();
            let embedded_witness = embedded_eligible
                .then(|| super::batch::prepare_embedded(&participants, &filesystem_operations))
                .transpose()
                .ok()
                .flatten()
                .map(Arc::new);

            if carry_decision && embedded_decision.is_none() {
                let error: Error = IoError::new(
                    std::io::ErrorKind::InvalidData,
                    "carried batch decision has no embedded witness",
                )
                .into();
                for (_, operation, _, _) in &mut prepared_states {
                    operation.poison();
                }
                let _ = commit_sender.send(Err(error.clone()));
                drop(guard);
                on_complete();
                let _ = completion_sender.send(Err(error));
                return;
            }

            let transition = embedded_decision.as_ref().map_or(Ok(None), |previous| {
                embedded_witness
                    .as_ref()
                    .map_or(Ok(false), |_| {
                        super::batch::can_supersede_embedded(previous, &participants)
                            .map_err(Error::from)
                    })
                    .map(|can_supersede| (!can_supersede).then(|| previous.clone()))
            });
            let transition = match transition {
                Ok(transition) => transition,
                Err(error) => {
                    for (_, operation, _, _) in &mut prepared_states {
                        operation.poison();
                    }
                    let _ = commit_sender.send(Err(error.clone()));
                    drop(guard);
                    on_complete();
                    let _ = completion_sender.send(Err(error));
                    return;
                }
            };
            let retire_embedded = transition.is_some();
            let transition_result = if let Some(previous) = transition {
                let transition_root = root.clone();
                tokio::task::spawn_blocking(move || {
                    super::batch::materialize_embedded(&transition_root, &previous)
                })
                .await
            } else {
                Ok(Ok(()))
            };
            match transition_result {
                Ok(Ok(())) => {
                    if retire_embedded {
                        *namespace.embedded_batch_decision.lock() = None;
                        namespace
                            .carried_batch_decision
                            .store(false, Ordering::Release);
                    }
                }
                Ok(Err(error)) => {
                    let error = Error::from(error);
                    for (_, operation, _, _) in &mut prepared_states {
                        operation.poison();
                    }
                    let _ = commit_sender.send(Err(error.clone()));
                    drop(guard);
                    on_complete();
                    let _ = completion_sender.send(Err(error));
                    return;
                }
                Err(error) if error.is_panic() => {
                    std::panic::resume_unwind(error.into_panic());
                }
                Err(_) => {
                    let error = Error::Closed;
                    for (_, operation, _, _) in &mut prepared_states {
                        operation.poison();
                    }
                    let _ = commit_sender.send(Err(error.clone()));
                    drop(guard);
                    on_complete();
                    let _ = completion_sender.send(Err(error));
                    return;
                }
            }

            if participant_count != 0 && embedded_witness.is_none() {
                let error: Error = IoError::new(
                    std::io::ErrorKind::InvalidInput,
                    "storage batch is not eligible for embedded crash recovery",
                )
                .into();
                for (_, operation, _, _) in &mut prepared_states {
                    operation.poison();
                }
                let _ = commit_sender.send(Err(error.clone()));
                drop(guard);
                on_complete();
                let _ = completion_sender.send(Err(error));
                return;
            }

            let stage_witness = embedded_witness.clone();
            let participant_commits =
                prepared_states
                    .iter_mut()
                    .filter_map(|(blob, _, prepared, removed)| {
                        let prepared = prepared.as_mut().unwrap().as_mut()?;
                        Some(async {
                            let witness = stage_witness
                                .as_ref()
                                .and_then(|batch| batch.witness(&blob.partition, &blob.name));
                            if *removed {
                                blob.stage_batch_delete(
                                    prepared,
                                    witness.expect("eligible deletions have an embedded witness"),
                                )
                                .await
                            } else {
                                blob.stage_batch_commit(prepared, witness).await?;
                                blob.sync_batch_commit().await
                            }
                        })
                    });
            let commit_error = join_all(participant_commits)
                .await
                .into_iter()
                .find_map(Result::err);
            if let Some(error) = commit_error {
                for (_, operation, _, _) in &mut prepared_states {
                    operation.poison();
                }
                let _ = commit_sender.send(Err(error.clone()));
                drop(guard);
                on_complete();
                let _ = completion_sender.send(Err(error));
                return;
            }

            if let Some(batch) = embedded_witness {
                let has_removals = filesystem_operations
                    .iter()
                    .any(|operation| matches!(operation, super::batch::Operation::Remove(_)));
                *namespace.embedded_batch_decision.lock() = Some(batch.clone());
                namespace.invalidate_operations(&filesystem_operations);
                namespace
                    .carried_batch_decision
                    .store(false, Ordering::Release);
                let _ = commit_sender.send(Ok(()));
                match tokio::task::spawn_blocking(on_commit).await {
                    Ok(()) => {}
                    Err(error) if error.is_panic() => {
                        std::panic::resume_unwind(error.into_panic());
                    }
                    Err(_) => {}
                }
                let mut completion = if has_removals {
                    let materialization_root = root.clone();
                    let materialization_witness = batch.clone();
                    match tokio::task::spawn_blocking(move || {
                        super::batch::materialize_embedded(
                            &materialization_root,
                            &materialization_witness,
                        )
                    })
                    .await
                    {
                        Ok(Ok(())) => {
                            *namespace.embedded_batch_decision.lock() = None;
                            Ok(())
                        }
                        Ok(Err(error)) => Err(Error::from(error)),
                        Err(error) if error.is_panic() => {
                            std::panic::resume_unwind(error.into_panic())
                        }
                        Err(_) => Err(Error::Closed),
                    }
                } else {
                    Ok(())
                };
                for (blob, mut operation, prepared, removed) in prepared_states {
                    if completion.is_err() {
                        operation.poison();
                        continue;
                    }
                    if removed {
                        debug_assert!(prepared.as_ref().is_ok_and(Option::is_some));
                        operation.disarm();
                        continue;
                    }
                    let force_truncate =
                        rewind_lengths.contains_key(&(blob.partition.clone(), blob.name.clone()));
                    let result = blob
                        .activate_batch_commit(
                            &mut operation.state,
                            prepared.unwrap(),
                            !has_removals,
                            force_truncate,
                        )
                        .await;
                    if let Err(error) = result {
                        operation.poison();
                        completion = Err(error);
                        continue;
                    }
                    operation.disarm();
                }
                namespace
                    .recovery_required
                    .store(completion.is_err() || !has_removals, Ordering::Release);
                namespace
                    .carried_batch_decision
                    .store(completion.is_ok() && !has_removals, Ordering::Release);
                drop(guard);
                on_complete();
                let _ = completion_sender.send(completion);
                return;
            }

            namespace.invalidate_operations(&filesystem_operations);
            namespace
                .carried_batch_decision
                .store(false, Ordering::Release);
            let _ = commit_sender.send(Ok(()));
            match tokio::task::spawn_blocking(on_commit).await {
                Ok(()) => {}
                Err(error) if error.is_panic() => {
                    std::panic::resume_unwind(error.into_panic());
                }
                Err(_) => {}
            }

            let mut result = Ok(());
            if result.is_ok() {
                for (blob, operation, prepared, removed) in &mut prepared_states {
                    debug_assert!(!*removed);
                    let force_truncate =
                        rewind_lengths.contains_key(&(blob.partition.clone(), blob.name.clone()));
                    let prepared = std::mem::replace(prepared, Ok(None))
                        .expect("successful preparation retains no error");
                    let completion = blob
                        .activate_batch_commit(
                            &mut operation.state,
                            prepared,
                            false,
                            force_truncate,
                        )
                        .await;
                    if let Err(error) = completion {
                        operation.poison();
                        result = Err(error);
                        break;
                    }
                    operation.disarm();
                }
            } else {
                for (_, operation, _, _) in &mut prepared_states {
                    operation.poison();
                }
            }
            if result.is_ok() {
                namespace.recovery_required.store(false, Ordering::Release);
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

    async fn open_versioned_inner(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
        require_atomic: bool,
    ) -> Result<(Blob, u64, u16), Error> {
        super::validate_partition_name(partition)?;

        let guard = self.namespace.lock.clone().lock_owned().await;
        self.recover_locked()?;

        let requested_parent = self.storage_directory.join(partition);
        fs::create_dir_all(&requested_parent)
            .map_err(|_| Error::PartitionCreationFailed(partition.into()))?;

        let stored_partition = if self.namespace.knows_partition(partition) {
            partition.to_string()
        } else {
            super::batch::resolve_partition_name(&self.storage_directory, partition)?
        };
        super::validate_partition_name(&stored_partition)?;
        let parent = self.storage_directory.join(&stored_partition);
        let path = parent.join(hex(name));

        let removed =
            super::batch::recover_named_embedded(&self.storage_directory, &stored_partition, name)?;
        if removed {
            self.namespace
                .invalidate_operations(&[super::batch::Operation::Remove(
                    crate::RemoveTarget::Blob {
                        partition: stored_partition.clone(),
                        name: name.to_vec(),
                    },
                )]);
            // The blob is durably removed, but a non-anchor tombstone left by a crash during a
            // multi-blob deletion keeps its name on disk (only ordinal-zero recovery unlinks the
            // descending frontier, and there is no global startup scan). Unlink it here so the
            // create path below produces a fresh generation, rather than reopening it as a live
            // blob and resurrecting the pre-delete committed root that is retained only for open
            // handles. Ordinary open uses create_new, which needs an absent name; create_live
            // (atomic) recreates via rename regardless.
            if let Err(error) = fs::remove_file(&path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(Error::BlobOpenFailed(partition.into(), hex(name), error.into()));
            }
        }

        // Open existing first so stale sidecars are durably discarded before create_new makes a
        // replacement user name visible.
        let mut file = match fs::OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                super::atomic::discard(&self.storage_directory, &stored_partition, name)?;
                if require_atomic {
                    let region = Header::create_atomic(&versions).0;
                    super::atomic::create_live(
                        &self.storage_directory,
                        &stored_partition,
                        name,
                        &path,
                        &region,
                    )
                    .map_err(|error| {
                        Error::BlobOpenFailed(partition.into(), hex(name), error.into())
                    })?
                } else {
                    fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .map_err(|error| {
                            Error::BlobOpenFailed(partition.into(), hex(name), error.into())
                        })?
                }
            }
            Err(error) => {
                return Err(Error::BlobOpenFailed(
                    partition.into(),
                    hex(name),
                    error.into(),
                ));
            }
        };

        let generation = self.namespace.generation(&stored_partition, name);
        let shared_atomic = self
            .namespace
            .atomic_state(&stored_partition, name, &generation);
        let raw_len = file.metadata().map_err(|_| Error::ReadFailed)?.len();
        let existing = resolve_header(&mut file, raw_len, &versions, partition, name)?;

        let (ordinary_len, blob_version, data_offset, incarnation) = match existing {
            Some(resolved) => {
                if require_atomic && resolved.2 != super::Layout::V2.data_offset() {
                    return Err(Error::BlobOpenFailed(
                        partition.into(),
                        hex(name),
                        IoError::new(
                            std::io::ErrorKind::Unsupported,
                            "blob was not created with atomic storage",
                        )
                        .into(),
                    ));
                }
                if shared_atomic.is_some() && resolved.2 != super::Layout::V2.data_offset() {
                    return Err(Error::BlobCorrupt(
                        partition.into(),
                        hex(name),
                        "atomic state restored a non-V2 header".into(),
                    ));
                }
                resolved
            }
            None => {
                // A parseable header implies its namespace entries were made durable first.
                sync_dir(&parent)?;
                sync_dir(&self.storage_directory)?;

                let (region, blob_version) = if require_atomic {
                    Header::create_atomic(&versions)
                } else {
                    Header::create(&versions)
                };
                let data_offset = region.len() as u64;
                if require_atomic {
                    drop(file);
                    file = super::atomic::discard(&self.storage_directory, &stored_partition, name)
                        .and_then(|()| {
                            super::atomic::create_live(
                                &self.storage_directory,
                                &stored_partition,
                                name,
                                &path,
                                &region,
                            )
                        })
                        .map_err(|error| {
                            Error::BlobOpenFailed(partition.into(), hex(name), error.into())
                        })?;
                } else {
                    file.set_len(0).map_err(|error| {
                        Error::BlobResizeFailed(partition.into(), hex(name), error.into())
                    })?;
                    file.seek(SeekFrom::Start(0))
                        .map_err(|_| Error::WriteFailed)?;
                    file.write_all(&region).map_err(|_| Error::WriteFailed)?;
                    file.sync_all().map_err(|error| {
                        Error::BlobSyncFailed(partition.into(), hex(name), error.into())
                    })?;
                }
                (
                    0,
                    blob_version,
                    data_offset,
                    Header::atomic_incarnation(&region),
                )
            }
        };

        let atomic = if data_offset == super::Layout::V2.data_offset() {
            match shared_atomic {
                Some(state) => Some(state),
                None => {
                    super::batch::recover_embedded(
                        &self.storage_directory,
                        &stored_partition,
                        name,
                        &file,
                        data_offset,
                    )
                    .map_err(|error| {
                        Error::BlobCorrupt(
                            partition.into(),
                            hex(name),
                            format!("atomic log recovery failed: {error}"),
                        )
                    })?;
                    let recovery_blob = Blob::new_with_generation(
                        stored_partition.clone(),
                        name,
                        file.try_clone().map_err(|_| Error::ReadFailed)?,
                        self.io_handle.clone(),
                        self.pool.clone(),
                        data_offset,
                        BlobContext {
                            generation: generation.clone(),
                            namespace: Some(self.namespace.clone()),
                            atomic: None,
                            incarnation,
                        },
                    );
                    let backing = recovery_blob.atomic_backing();
                    let backing_len = file
                        .metadata()
                        .map_err(|_| Error::ReadFailed)?
                        .len()
                        .checked_sub(super::Layout::V1.data_offset())
                        .ok_or(Error::BlobInsufficientLength)?;
                    let state = uno::Core::recover(&backing, backing_len)
                        .await
                        .map_err(|error| {
                            Error::BlobCorrupt(
                                partition.into(),
                                hex(name),
                                format!("atomic root recovery failed: {error}"),
                            )
                        })?;
                    Some(self.namespace.insert_atomic_state(
                        &stored_partition,
                        name,
                        &generation,
                        state,
                    )?)
                }
            }
        } else {
            None
        };

        let blob = Blob::new_with_generation(
            stored_partition,
            name,
            file,
            self.io_handle.clone(),
            self.pool.clone(),
            data_offset,
            BlobContext {
                generation,
                namespace: Some(self.namespace.clone()),
                atomic: atomic.clone(),
                incarnation,
            },
        );
        drop(guard);

        let logical_len = if let Some(context) = atomic {
            let state = context.lock().await;
            if state.is_poisoned() {
                return Err(Error::BlobCorrupt(
                    partition.into(),
                    hex(name),
                    "atomic blob generation is poisoned".into(),
                ));
            }
            if let Some(error) = context.preflush().failure() {
                return Err(error);
            }
            state.logical_len()
        } else {
            ordinary_len
        };
        Ok((blob, logical_len, blob_version))
    }
}

impl crate::Storage for Storage {
    type Blob = Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Blob, u64, u16), Error> {
        self.open_versioned_inner(partition, name, versions, false)
            .await
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;

        let _guard = self.namespace.lock.lock().await;
        self.recover_locked()?;
        let stored_partition =
            super::batch::resolve_partition_name(&self.storage_directory, partition)?;
        let path = self.storage_directory.join(&stored_partition);
        let recovery_operation = name.map_or_else(
            || {
                super::batch::Operation::Remove(crate::RemoveTarget::Partition(
                    stored_partition.clone(),
                ))
            },
            |name| {
                super::batch::Operation::Remove(crate::RemoveTarget::Blob {
                    partition: stored_partition.clone(),
                    name: name.to_vec(),
                })
            },
        );
        super::batch::recover_removal_witnesses(
            &self.storage_directory,
            std::slice::from_ref(&recovery_operation),
        )?;
        let operation = if let Some(name) = name {
            fs::remove_file(path.join(hex(name)))
                .map_err(|_| Error::BlobMissing(partition.into(), hex(name)))?;
            sync_dir(&path)?;
            super::batch::Operation::Remove(crate::RemoveTarget::Blob {
                partition: stored_partition.clone(),
                name: name.to_vec(),
            })
        } else {
            fs::remove_dir_all(&path).map_err(|_| Error::PartitionMissing(partition.into()))?;
            sync_dir(&self.storage_directory)?;
            super::batch::Operation::Remove(crate::RemoveTarget::Partition(
                stored_partition.clone(),
            ))
        };
        self.namespace.invalidate_operations(&[operation]);
        if let Some(name) = name {
            super::atomic::discard(&self.storage_directory, &stored_partition, name)?;
        } else {
            super::atomic::discard_partition(&self.storage_directory, &stored_partition)?;
        }
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        super::validate_partition_name(partition)?;

        // Acquire the filesystem lock
        let _guard = self.namespace.lock.lock().await;
        self.recover_locked()?;

        super::batch::recover_partition_embedded(&self.storage_directory, partition)?;

        let path = self.storage_directory.join(partition);

        let entries =
            std::fs::read_dir(&path).map_err(|_| Error::PartitionMissing(partition.into()))?;

        let mut blobs = Vec::new();
        let mut removed_creation = false;
        for entry in entries {
            let entry = entry.map_err(|_| Error::ReadFailed)?;
            let file_type = entry.file_type().map_err(|_| Error::ReadFailed)?;

            if !file_type.is_file() {
                return Err(Error::PartitionCorrupt(partition.into()));
            }

            let file_name = entry.file_name();
            if super::atomic::is_creation_file_name(&file_name) {
                fs::remove_file(entry.path()).map_err(|_| Error::ReadFailed)?;
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
            sync_dir(&path)?;
        }

        Ok(blobs)
    }
}

impl crate::AtomicStorage for Storage {
    type AtomicBlob = AtomicBlob;

    async fn migrate_atomic(&self, blob: Self::Blob) -> Result<(), Error> {
        let partition = blob.partition.clone();
        let name = blob.name.clone();
        let mut guard = self.namespace.lock.clone().lock_owned().await;
        self.recover_locked()?;
        if !self
            .namespace
            .is_current(&partition, &name, &blob.generation)
        {
            return Err(Error::BlobMissing(partition, hex(&name)));
        }
        let is_atomic = blob.atomic.is_some();
        if is_atomic {
            drop(guard);
            crate::Blob::sync(&blob).await?;
            guard = self.namespace.lock.clone().lock_owned().await;
            self.recover_locked()?;
            if !self
                .namespace
                .is_current(&partition, &name, &blob.generation)
            {
                return Err(Error::BlobMissing(partition, hex(&name)));
            }
        }

        let root = self.storage_directory.clone();
        let source = blob.file.clone();
        let data_offset = blob.data_offset;
        let namespace = self.namespace.clone();
        let migration_partition = partition.clone();
        let migration_name = name.clone();
        let migration = tokio::task::spawn_blocking(move || {
            let result = super::atomic::migrate_live(
                &root,
                &migration_partition,
                &migration_name,
                &source,
                data_offset,
            );
            if !is_atomic {
                namespace.invalidate_operations(&[super::batch::Operation::Remove(
                    crate::RemoveTarget::Blob {
                        partition: migration_partition,
                        name: migration_name,
                    },
                )]);
            }
            (guard, result)
        });
        let (guard, result) = match migration.await {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => return Err(Error::Closed),
        };
        drop(guard);
        result
    }

    async fn open_atomic_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::AtomicBlob, u64, u16), Error> {
        let (blob, len, version) = self
            .open_versioned_inner(partition, name, versions, true)
            .await?;
        Ok((AtomicBlob::from_legacy(blob), len, version))
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

pub struct Blob {
    /// The partition this blob lives in
    partition: String,
    /// The name of the blob
    name: Vec<u8>,
    /// Identity of the current namespace generation for this name.
    generation: Arc<super::generation::Token>,
    /// The underlying file
    file: Arc<File>,
    /// Where to send IO operations to be executed
    io_handle: iouring::Handle,
    /// Buffer pool for read allocations
    pool: BufferPool,
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
    /// Namespace owner used to validate V2 commit publication.
    namespace: Option<Arc<Namespace>>,
    /// Log/index state shared by every open of the current V2 name generation.
    atomic: Option<Arc<super::preflush::Context>>,
    /// Persistent identity of this exact V2 creation.
    incarnation: Option<[u8; Header::V2_INCARNATION_LEN]>,
    /// Shared page-cache policy and learned `RWF_DONTCACHE` support.
    cache: iouring::Cache,
}

struct BlobContext {
    generation: Arc<super::generation::Token>,
    namespace: Option<Arc<Namespace>>,
    atomic: Option<Arc<super::preflush::Context>>,
    incarnation: Option<[u8; Header::V2_INCARNATION_LEN]>,
}

/// Direct ordinary-geometry view used as UNO's backing boundary.
#[derive(Clone)]
struct AtomicBacking {
    blob: Blob,
    retained: Arc<AtomicBackingRetention>,
}

/// Keeps a canceled, admitted write attached to its original logical generation until final CQE.
struct AtomicBackingRetention {
    _generation: Arc<super::generation::Token>,
    _state: Option<Arc<super::preflush::Context>>,
}

impl Clone for Blob {
    fn clone(&self) -> Self {
        Self {
            partition: self.partition.clone(),
            name: self.name.clone(),
            generation: self.generation.clone(),
            file: self.file.clone(),
            io_handle: self.io_handle.clone(),
            pool: self.pool.clone(),
            data_offset: self.data_offset,
            namespace: self.namespace.clone(),
            atomic: self.atomic.clone(),
            incarnation: self.incarnation,
            cache: self.cache.clone(),
        }
    }
}

impl Blob {
    /// Construct a blob handle around an already-open file and shared io_uring loop.
    #[cfg(test)]
    fn new(
        partition: String,
        name: &[u8],
        file: File,
        io_handle: iouring::Handle,
        pool: BufferPool,
        data_offset: u64,
    ) -> Self {
        Self::new_with_generation(
            partition,
            name,
            file,
            io_handle,
            pool,
            data_offset,
            BlobContext {
                generation: super::generation::Token::detached(),
                namespace: None,
                atomic: None,
                incarnation: None,
            },
        )
    }

    fn new_with_generation(
        partition: String,
        name: &[u8],
        file: File,
        io_handle: iouring::Handle,
        pool: BufferPool,
        data_offset: u64,
        context: BlobContext,
    ) -> Self {
        Self {
            partition,
            name: name.to_vec(),
            generation: context.generation,
            file: Arc::new(file),
            io_handle,
            pool,
            data_offset,
            namespace: context.namespace,
            atomic: context.atomic,
            incarnation: context.incarnation,
            cache: iouring::Cache::Disabled(Arc::new(AtomicBool::new(true))),
        }
    }

    fn cache_for(&self, options: WriteOptions) -> iouring::Cache {
        if options.contains(WriteOptions::DONT_CACHE) {
            self.cache.clone()
        } else {
            iouring::Cache::Enabled
        }
    }

    /// Return an ordinary V1-geometry view whose logical offset zero begins after the immutable
    /// typed-envelope header. UNO keeps the root page private above this view.
    fn atomic_backing(&self) -> AtomicBacking {
        let retained = Arc::new(AtomicBackingRetention {
            _generation: self.generation.clone(),
            _state: self.atomic.clone(),
        });
        let mut backing = self.clone();
        backing.data_offset = super::Layout::V1.data_offset();
        backing.atomic = None;
        AtomicBacking {
            blob: backing,
            retained,
        }
    }

    async fn read_at_buf_v1(
        &self,
        offset: u64,
        len: usize,
        mut input_bufs: IoBufsMut,
    ) -> Result<IoBufsMut, Error> {
        // SAFETY: `len` bytes are filled via the io_uring read below.
        unsafe { input_bufs.set_len(len) };

        // For single buffers, read directly into them (zero-copy).
        // For multi-chunk buffers, use a temporary and copy to preserve the input structure.
        let (io_buf, original_bufs) = if input_bufs.is_single() {
            (input_bufs.coalesce(), None)
        } else {
            // SAFETY: `len` bytes are filled via the io_uring read below.
            let tmp = unsafe { self.pool.alloc_len(len) };
            (tmp, Some(input_bufs))
        };
        let physical_offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;

        // Zero-length reads succeed trivially without submitting to the ring.
        if len == 0 {
            return Ok(original_bufs.unwrap_or_else(|| io_buf.into()));
        }

        let io_buf = self
            .io_handle
            .read_at(self.file.clone(), physical_offset, len, io_buf)
            .await
            .map_err(|(_, error)| error)?;
        match original_bufs {
            None => Ok(io_buf.into()),
            Some(mut bufs) => {
                bufs.copy_from_slice(io_buf.as_ref());
                Ok(bufs)
            }
        }
    }

    async fn write_at_v1(
        &self,
        offset: u64,
        bufs: IoBufs,
        options: WriteOptions,
    ) -> Result<(), Error> {
        if !bufs.has_remaining() {
            return Ok(());
        }
        let physical_offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        self.io_handle
            .write_at(
                self.file.clone(),
                physical_offset,
                bufs,
                options,
                self.cache_for(options),
            )
            .await
    }

    // TODO: Make this async. See https://github.com/commonwarexyz/monorepo/issues/831
    fn resize_v1(&self, len: u64) -> Result<(), Error> {
        let raw_len = len
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        self.file.set_len(raw_len).map_err(|error| {
            Error::BlobResizeFailed(
                self.partition.clone(),
                hex(&self.name),
                IoError::other(error).into(),
            )
        })
    }

    async fn sync_v1(&self) -> Result<(), Error> {
        self.io_handle
            .sync(self.file.clone())
            .await
            .map_err(|error| self.map_sync_error(error))
    }

    async fn start_sync_v1(&self) -> Handle<()> {
        let partition = self.partition.clone();
        let name = self.name.clone();
        let receiver = self.io_handle.start_sync(self.file.clone()).await;
        Handle::from_future(async move {
            match receiver.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(Error::Io(error))) => {
                    Err(Error::BlobSyncFailed(partition, hex(&name), error))
                }
                Ok(Err(error)) => Err(error),
                Err(_) => Err(Error::Closed),
            }
        })
    }

    const fn incarnation(&self) -> [u8; Header::V2_INCARNATION_LEN] {
        self.incarnation
            .expect("atomic blobs have a persistent incarnation")
    }

    fn map_sync_error(&self, error: Error) -> Error {
        match error {
            Error::Io(error) => {
                Error::BlobSyncFailed(self.partition.clone(), hex(&self.name), error)
            }
            error => error,
        }
    }

    async fn lock_publication_namespace(&self) -> Result<TokioOwnedMutexGuard<()>, Error> {
        let namespace = self
            .namespace
            .as_ref()
            .expect("V2 blobs always retain their namespace")
            .clone();
        let namespace_guard = namespace.lock.clone().lock_owned().await;
        if namespace.carried_batch_decision.load(Ordering::Acquire) {
            if namespace.embedded_batch_decision.lock().is_none() {
                return Err(IoError::new(
                    std::io::ErrorKind::InvalidData,
                    "carried batch decision has no embedded witness",
                )
                .into());
            }
        } else {
            namespace.recover_locked()?;
        }
        if !namespace.is_current(&self.partition, &self.name, &self.generation) {
            return Err(Error::BlobMissing(self.partition.clone(), hex(&self.name)));
        }
        Ok(namespace_guard)
    }
}

#[derive(Clone)]
struct V2Publisher {
    blob: Blob,
}

impl crate::Blob for AtomicBacking {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.blob
            .read_at_buf_v1(offset, len, self.blob.pool.alloc(len).into())
            .await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        self.blob.read_at_buf_v1(offset, len, bufs.into()).await
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
        if !bufs.has_remaining() {
            return Ok(());
        }
        let physical_offset = offset
            .checked_add(self.blob.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        self.blob
            .io_handle
            .write_at_retained(
                self.blob.file.clone(),
                physical_offset,
                bufs,
                options,
                self.blob.cache_for(options),
                self.retained.clone(),
            )
            .await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.blob.resize_v1(len)
    }

    async fn sync(&self) -> Result<(), Error> {
        self.blob.sync_v1().await
    }

    async fn start_sync(&self) -> Handle<()> {
        self.blob.start_sync_v1().await
    }
}

impl uno::Publisher<AtomicBacking> for V2Publisher {
    fn spawn(&self, task: uno::Task) -> Result<(), Error> {
        drop(tokio::spawn(task));
        Ok(())
    }

    async fn publish(
        &self,
        core: Arc<uno::Core<AtomicBacking>>,
        mut state: uno::MutationGuard,
    ) -> Result<(), Error> {
        let namespace_guard = match self.blob.lock_publication_namespace().await {
            Ok(namespace_guard) => namespace_guard,
            Err(error) => {
                // Namespace admission has not touched the backing blob or guarded mutation.
                // Stale handles remain readable even though they cannot publish.
                state.finish();
                return Err(error);
            }
        };
        if !state.is_dirty() {
            state.finish();
            return Ok(());
        }
        state.arm();
        if state.preflush_requested()? {
            core.ensure_preflush(state.preflush_target()).await?;
        }

        let previous_candidate = state.deferred_batch_root().cloned();
        let mut prepared = state
            .prepare_commit()?
            .expect("dirty atomic state always prepares a commit");
        if matches!(
            prepared.payload_checksum(),
            super::atomic::PayloadChecksumEligibility::Ineligible
        ) {
            core.backing().sync().await?;
            prepared.mark_payload_preflushed();
        }
        prepared.mark_batch_prepared();
        let namespace = self
            .blob
            .namespace
            .as_ref()
            .expect("V2 blobs always retain their namespace");
        let (participant, batch) = super::batch::prepare_single_publish(
            &self.blob.partition,
            &self.blob.name,
            self.blob.incarnation(),
            &prepared,
        )?;

        let previous = namespace.embedded_batch_decision.lock().clone();
        if let Some(previous) = &previous {
            let supersedes =
                super::batch::can_supersede_embedded(previous, std::slice::from_ref(&participant))?;
            if !supersedes {
                let root = namespace.storage_directory.clone();
                let previous = previous.clone();
                match tokio::task::spawn_blocking(move || {
                    super::batch::materialize_embedded(&root, &previous)
                })
                .await
                {
                    Ok(result) => result?,
                    Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
                    Err(_) => return Err(Error::Closed),
                }
                *namespace.embedded_batch_decision.lock() = None;
                namespace
                    .carried_batch_decision
                    .store(false, Ordering::Release);
            }
        }
        if previous.is_none()
            && let Some(candidate) = previous_candidate
        {
            let root = super::atomic::materialized_candidate_root(&candidate)?;
            core.backing()
                .write_at(
                    uno::Core::<AtomicBacking>::backing_offset(candidate.root_offset)?,
                    root.to_vec(),
                )
                .await?;
        }
        let witness = batch
            .witness(&self.blob.partition, &self.blob.name)
            .expect("single-participant batches retain their local witness");
        prepared.attach_batch_witness(witness)?;
        core.backing()
            .write_at(
                uno::Core::<AtomicBacking>::backing_offset(prepared.root_offset)?,
                prepared.prepared_root.clone(),
            )
            .await?;
        core.backing().sync().await?;

        let raw_len = prepared.raw_len();
        let requires_truncate = prepared.requires_truncate();
        *namespace.embedded_batch_decision.lock() = Some(Arc::new(batch));
        namespace.recovery_required.store(true, Ordering::Release);
        namespace
            .carried_batch_decision
            .store(true, Ordering::Release);
        if requires_truncate {
            core.backing()
                .resize(uno::Core::<AtomicBacking>::backing_len(raw_len)?)
                .await?;
        }
        core.state().preflush().record_durable(raw_len);
        state.finish_batch_commit(prepared);
        state.finish();
        drop(namespace_guard);
        Ok(())
    }
}

/// Atomic UNO view over an ordinary V1-geometry io_uring blob.
#[derive(Clone)]
#[commonware_macros::stability(ALPHA)]
pub struct AtomicBlob {
    inner: uno::AtomicBlob<AtomicBacking, V2Publisher>,
}

impl AtomicBlob {
    fn from_legacy(blob: Blob) -> Self {
        let state = blob
            .atomic
            .as_ref()
            .expect("atomic wrappers require recovered V2 state")
            .clone();
        let core = uno::Core::new(blob.atomic_backing(), state);
        Self {
            inner: uno::AtomicBlob::new(core, V2Publisher { blob }),
        }
    }

    async fn lock_batch_state(&self) -> Result<TokioOwnedMutexGuard<V2State>, Error> {
        self.inner.lock_state().await
    }

    async fn rewind_log(
        &self,
        state: &mut V2State,
        len: u64,
        unit: Option<IntegrityUnit>,
    ) -> Result<(), Error> {
        self.inner.core().rewind_state(state, len, unit).await
    }

    async fn prepare_batch_commit_unflushed(
        &self,
        state: &mut V2State,
    ) -> Result<Option<super::atomic::PreparedCommit>, Error> {
        let prepared = self.inner.core().prepare_batch_commit(state).await?;
        if let Some(prepared) = &prepared {
            let start = prepared.payload_start();
            // Begin payload writeback early so the later inode barrier has less dirty data to drain.
            super::atomic::begin_payload_writeback(
                &self.inner.publisher().blob.file,
                start,
                prepared.raw_len() - start,
            )?;
        }
        Ok(prepared)
    }

    fn prepare_batch_delete_unflushed(
        &self,
        state: &V2State,
    ) -> Result<super::atomic::PreparedCommit, Error> {
        self.inner.core().prepare_batch_delete(state)
    }

    async fn ensure_preflush(&self, target: u64) -> Result<(), Error> {
        self.inner.core().ensure_preflush(target).await
    }

    async fn stage_batch_commit(
        &self,
        prepared: &mut super::atomic::PreparedCommit,
        witness: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.inner
            .core()
            .stage_batch_commit(prepared, witness)
            .await
    }

    async fn stage_batch_delete(
        &self,
        prepared: &mut super::atomic::PreparedCommit,
        witness: &[u8],
    ) -> Result<(), Error> {
        self.inner
            .core()
            .stage_batch_delete(prepared, witness)
            .await
    }

    async fn sync_batch_commit(&self) -> Result<(), Error> {
        self.inner.core().sync_batch_commit().await
    }

    async fn activate_batch_commit(
        &self,
        state: &mut V2State,
        prepared: Option<super::atomic::PreparedCommit>,
        defer_root: bool,
        force_truncate: bool,
    ) -> Result<Option<super::atomic::Candidate>, Error> {
        self.inner
            .core()
            .activate_batch_commit(state, prepared, defer_root, force_truncate)
            .await
    }
}

impl std::ops::Deref for AtomicBlob {
    type Target = Blob;

    fn deref(&self) -> &Self::Target {
        &self.inner.publisher().blob
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

#[commonware_macros::stability(ALPHA)]
impl crate::AtomicBlob for AtomicBlob {
    async fn tag(&self) -> Result<[u8; crate::ATOMIC_BLOB_TAG_LEN], Error> {
        crate::AtomicBlob::tag(&self.inner).await
    }

    async fn set_tag(&self, tag: [u8; crate::ATOMIC_BLOB_TAG_LEN]) -> Result<(), Error> {
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
        tag: [u8; crate::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<IntegrityToken, Error> {
        crate::AtomicBlob::compare_set_tag(&self.inner, expected, tag).await
    }

    async fn append(&self, data: impl Into<IoBufs> + Send) -> Result<u64, Error> {
        crate::AtomicBlob::append(&self.inner, data).await
    }

    async fn append_tagged(
        &self,
        data: impl Into<IoBufs> + Send,
        tag: [u8; crate::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<u64, Error> {
        crate::AtomicBlob::append_tagged(&self.inner, data, tag).await
    }

    async fn append_integrity(
        &self,
        expected: IntegrityToken,
        data: impl Into<IoBufs> + Send,
        boundary: IntegrityBoundary,
        tag: Option<[u8; crate::ATOMIC_BLOB_TAG_LEN]>,
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

    async fn rewind_tagged(
        &self,
        len: u64,
        tag: [u8; crate::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<(), Error> {
        crate::AtomicBlob::rewind_tagged(&self.inner, len, tag).await
    }

    async fn rewind_integrity(
        &self,
        expected: IntegrityToken,
        len: u64,
        unit: Option<IntegrityUnit>,
        tag: Option<[u8; crate::ATOMIC_BLOB_TAG_LEN]>,
    ) -> Result<IntegrityToken, Error> {
        crate::AtomicBlob::rewind_integrity(&self.inner, expected, len, unit, tag).await
    }
}

impl crate::Blob for Blob {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        if self.atomic.is_some() {
            let atomic = AtomicBlob::from_legacy(self.clone());
            let future: BoxedFuture<'_, Result<IoBufsMut, Error>> =
                Box::pin(async move { crate::Blob::read_at(&atomic, offset, len).await });
            return future.await;
        }
        self.read_at_buf_v1(offset, len, self.pool.alloc(len).into())
            .await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        if self.atomic.is_some() {
            let atomic = AtomicBlob::from_legacy(self.clone());
            let future: BoxedFuture<'_, Result<IoBufsMut, Error>> =
                Box::pin(async move { crate::Blob::read_at_buf(&atomic, offset, len, bufs).await });
            return future.await;
        }
        self.read_at_buf_v1(offset, len, bufs.into()).await
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
        if self.atomic.is_some() {
            let atomic = AtomicBlob::from_legacy(self.clone());
            let future: BoxedFuture<'_, Result<(), Error>> = Box::pin(async move {
                crate::Blob::write_at_with_options(&atomic, offset, bufs, options).await
            });
            return future.await;
        }
        self.write_at_v1(offset, bufs.into(), options).await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        if self.atomic.is_some() {
            let atomic = AtomicBlob::from_legacy(self.clone());
            let future: BoxedFuture<'_, Result<(), Error>> =
                Box::pin(async move { crate::Blob::resize(&atomic, len).await });
            return future.await;
        }
        self.resize_v1(len)
    }

    async fn sync(&self) -> Result<(), Error> {
        if self.atomic.is_some() {
            let atomic = AtomicBlob::from_legacy(self.clone());
            let future: BoxedFuture<'_, Result<(), Error>> =
                Box::pin(async move { crate::Blob::sync(&atomic).await });
            return future.await;
        }
        self.sync_v1().await
    }

    // The outer future creates the awaitable handle returned by this API.
    #[allow(clippy::async_yields_async)]
    async fn start_sync(&self) -> Handle<()> {
        if self.atomic.is_some() {
            let atomic = AtomicBlob::from_legacy(self.clone());
            let future: BoxedFuture<'_, Handle<()>> =
                Box::pin(async move { crate::Blob::start_sync(&atomic).await });
            return future.await;
        }
        self.start_sync_v1().await
    }
}

#[cfg(test)]
mod tests {
    use super::{Header, *};
    use crate::{
        AtomicBlob as _, AtomicStorage as _, BatchStorage as _, BufferPool, BufferPoolConfig,
        IoBuf, IoBufMut, Storage as _,
        storage::{
            Layout,
            tests::{
                run_atomic_blob_tests, run_atomic_storage_tests, run_batch_storage_tests,
                run_storage_foreign_handle_test, run_storage_tests,
            },
        },
        telemetry::metrics::Registry,
        utils::thread,
    };
    use futures::{pin_mut, poll};
    use std::{
        env,
        ffi::OsString,
        os::{
            fd::{FromRawFd, IntoRawFd},
            unix::{ffi::OsStringExt, net::UnixStream},
        },
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    static NEXT_STORAGE_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    fn test_pool(scope: &mut impl Register) -> BufferPool {
        BufferPool::new(BufferPoolConfig::for_storage(), scope)
    }

    /// Build a fresh storage instance rooted in a unique temporary directory.
    fn create_test_storage() -> (Storage, PathBuf) {
        let storage_directory = env::temp_dir().join(format!(
            "commonware_iouring_storage_{}_{}",
            std::process::id(),
            NEXT_STORAGE_TEST_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&storage_directory);

        let storage = start_test_storage(storage_directory.clone());
        (storage, storage_directory)
    }

    fn start_test_storage(storage_directory: PathBuf) -> Storage {
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        Storage::start(
            Config {
                storage_directory,
                iouring_config: Default::default(),
                thread_stack_size: thread::system_thread_stack_size(),
            },
            &mut registry.sub_registry("storage"),
            pool,
        )
    }

    /// Build a fresh temporary directory without starting a storage loop.
    fn create_test_directory() -> PathBuf {
        let storage_directory = env::temp_dir().join(format!(
            "commonware_iouring_storage_{}_{}",
            std::process::id(),
            NEXT_STORAGE_TEST_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&storage_directory);
        std::fs::create_dir_all(&storage_directory).unwrap();
        storage_directory
    }

    /// Verify the end-to-end storage-page alignment invariant on the io_uring backend: paged
    /// data written to a V1 blob with a 4096-byte physical page size occupies exactly one
    /// aligned 4096-byte disk page per physical page (header page included), so page reads
    /// never straddle a page boundary.
    #[tokio::test]
    async fn test_v1_paged_alignment() {
        let (storage, storage_directory) = create_test_storage();

        // A logical page size whose physical page is exactly one 4096-byte storage page.
        const PHYSICAL_PAGE_SIZE: u64 = 4096;
        let logical = crate::buffer::paged::page_size(PHYSICAL_PAGE_SIZE as u32);
        let mut registry = Registry::default();
        let cache = crate::buffer::paged::CacheRef::new(
            test_pool(&mut registry.sub_registry("pool")),
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
    async fn test_iouring_storage() {
        // Verify the io_uring storage backend satisfies the shared storage trait suite.
        let (storage, storage_directory) = create_test_storage();
        let tested = storage.clone();
        run_storage_tests(storage.clone()).await;
        run_atomic_storage_tests(storage.clone()).await;
        let (atomic, _) = storage
            .open_atomic("atomic_storage", b"blob")
            .await
            .unwrap();
        run_atomic_blob_tests(atomic).await;
        run_batch_storage_tests(storage.clone()).await;
        let (foreign, foreign_directory) = create_test_storage();
        run_storage_foreign_handle_test(&tested, &foreign).await;
        let _ = std::fs::remove_dir_all(storage_directory);
        let _ = std::fs::remove_dir_all(foreign_directory);
    }

    #[tokio::test]
    async fn test_atomic_reopen_second_open_and_sync_write() {
        let (storage, storage_directory) = create_test_storage();
        let (first, size) = storage.open_atomic("atomic", b"shared").await.unwrap();
        assert_eq!(size, 0);
        first.append(b"stable").await.unwrap();

        // An independent ordinary open shares the current generation state and must not recover
        // the initial empty root over the first handle's pending append.
        let (second, size) = storage.open("atomic", b"shared").await.unwrap();
        assert_eq!(size, 6);
        assert_eq!(second.read_at(0, 6).await.unwrap().coalesce(), b"stable");
        second.sync().await.unwrap();

        // Recovery discards the unsynced log tail and selects the last committed root.
        first.append(b"losing").await.unwrap();
        drop(first);
        drop(second);
        drop(storage);
        let storage = start_test_storage(storage_directory.clone());
        let (blob, size) = storage.open("atomic", b"shared").await.unwrap();
        assert_eq!(size, 6);
        assert_eq!(blob.read_at(0, 6).await.unwrap().coalesce(), b"stable");

        // A tail-positioned V2 SYNC write appends its payload and publishes the complete epoch.
        blob.write_at_sync(6, b"synced").await.unwrap();
        drop(blob);
        drop(storage);
        let storage = start_test_storage(storage_directory.clone());
        let (blob, size) = storage.open_atomic("atomic", b"shared").await.unwrap();
        assert_eq!(size, 12);
        assert_eq!(
            blob.read_at(0, 12).await.unwrap().coalesce(),
            b"stablesynced"
        );

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_atomic_remove_recreate_and_stale_sync() {
        let (storage, storage_directory) = create_test_storage();
        let (old, _) = storage.open_atomic("atomic", b"replace").await.unwrap();
        old.append(b"old").await.unwrap();
        old.sync().await.unwrap();

        storage.remove("atomic", Some(b"replace")).await.unwrap();
        let (new, size) = storage.open_atomic("atomic", b"replace").await.unwrap();
        assert_eq!(size, 0);
        new.append(b"new").await.unwrap();
        new.sync().await.unwrap();

        old.append(b"bad").await.unwrap();
        assert!(matches!(old.sync().await, Err(Error::BlobMissing(..))));

        storage
            .apply(vec![BatchOperation::Rewind {
                blob: new.clone(),
                len: 1,
            }])
            .await
            .unwrap();

        drop(old);
        drop(new);
        drop(storage);
        let storage = start_test_storage(storage_directory.clone());
        let (blob, size) = storage.open_atomic("atomic", b"replace").await.unwrap();
        assert_eq!(size, 1);
        assert_eq!(blob.read_at(0, 1).await.unwrap().coalesce(), b"n");

        let (ordinary, _) = storage.open("ordinary", b"v1").await.unwrap();
        drop(ordinary);
        assert!(storage.open_atomic("ordinary", b"v1").await.is_err());

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_atomic_append_writes_payload_once() {
        let (storage, storage_directory) = create_test_storage();
        let (blob, _) = storage.open_atomic("atomic", b"append-once").await.unwrap();
        let live_path = storage_directory.join("atomic").join(hex(b"append-once"));
        assert_eq!(
            std::fs::metadata(&live_path).unwrap().len(),
            Layout::V2.data_offset()
        );

        assert_eq!(blob.append(b"data").await.unwrap(), 0);
        let raw = std::fs::read(&live_path).unwrap();
        assert_eq!(raw.len() as u64, Layout::V2.data_offset() + 4);
        assert_eq!(&raw[Layout::V2.data_offset() as usize..], b"data");
        assert_eq!(blob.read_at(0, 4).await.unwrap().coalesce(), b"data");

        blob.sync().await.unwrap();
        drop((blob, storage));
        let storage = start_test_storage(storage_directory.clone());
        let (blob, len) = storage.open_atomic("atomic", b"append-once").await.unwrap();
        assert_eq!(len, 4);
        assert_eq!(blob.read_at(0, 4).await.unwrap().coalesce(), b"data");

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_atomic_background_preflush_writes_payload_before_marker() {
        let (storage, storage_directory) = create_test_storage();
        let (blob, _) = storage.open_atomic("atomic", b"background").await.unwrap();
        let prefix_len = super::super::atomic::BACKGROUND_PREFLUSH_INTERVAL as usize;
        blob.append(vec![0x5a; prefix_len]).await.unwrap();

        let atomic = blob.atomic.as_ref().unwrap();
        let target = {
            let state = atomic.lock().await;
            state.preflush_target()
        };
        assert!(atomic.preflush().requested() >= target);
        atomic.preflush().wait(target).await.unwrap();
        assert_eq!(target, Layout::V2.data_offset() + prefix_len as u64);

        let path = storage_directory.join("atomic").join(hex(b"background"));
        let file = std::fs::File::open(&path).unwrap();
        assert!(
            super::super::atomic::embedded_batch_witnesses(&file, Layout::V2.data_offset())
                .unwrap()
                .is_empty(),
            "background payload durability must not publish a root"
        );

        blob.append(b"tail").await.unwrap();
        storage
            .apply(vec![BatchOperation::Publish(blob.clone())])
            .await
            .unwrap();
        drop((blob, storage));

        let storage = start_test_storage(storage_directory.clone());
        let (blob, len) = storage.open_atomic("atomic", b"background").await.unwrap();
        assert_eq!(len, prefix_len as u64 + 4);
        assert_eq!(
            blob.read_at(prefix_len as u64, 4).await.unwrap().coalesce(),
            b"tail"
        );

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_atomic_rewind_forgets_preflush_credit_before_reusing_offsets() {
        let (storage, storage_directory) = create_test_storage();
        let (blob, _) = storage
            .open_atomic("atomic", b"preflush-rewind")
            .await
            .unwrap();
        let payload_len = super::super::atomic::BACKGROUND_PREFLUSH_INTERVAL as usize;
        blob.append(vec![0x5a; payload_len]).await.unwrap();

        let atomic = blob.atomic.as_ref().unwrap();
        let target = {
            let state = atomic.lock().await;
            state.preflush_target()
        };
        atomic.preflush().wait(target).await.unwrap();
        blob.rewind(0).await.unwrap();
        assert_eq!(
            atomic.preflush().requested(),
            Layout::V2.data_offset(),
            "rewind must remove durability credit for the discarded physical offsets"
        );

        blob.append(vec![0xa5; payload_len]).await.unwrap();
        let replacement_target = {
            let state = atomic.lock().await;
            state.preflush_target()
        };
        assert_eq!(
            replacement_target,
            Layout::V2.data_offset() + payload_len as u64
        );
        atomic.preflush().wait(replacement_target).await.unwrap();
        storage
            .apply(vec![BatchOperation::Publish(blob.clone())])
            .await
            .unwrap();

        drop((blob, storage));
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_atomic_invalid_rewind_does_not_flush_or_poison() {
        let (storage, storage_directory) = create_test_storage();
        let (blob, _) = storage
            .open_atomic("atomic", b"invalid-rewind")
            .await
            .unwrap();
        blob.append(b"base").await.unwrap();
        blob.sync().await.unwrap();
        blob.append(b"tail").await.unwrap();
        let preflush = blob.atomic.as_ref().unwrap().preflush();
        let requested = preflush.requested();

        assert!(blob.rewind(9).await.is_err());
        assert_eq!(preflush.requested(), requested);
        assert_eq!(blob.append(b"ok").await.unwrap(), 8);
        blob.sync().await.unwrap();

        drop((blob, storage));
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_atomic_reopen_rejects_sticky_preflush_failure() {
        let (storage, storage_directory) = create_test_storage();
        let (blob, _) = storage
            .open_atomic("atomic", b"failed-preflush")
            .await
            .unwrap();
        let target = Layout::V2.data_offset() + 1;
        let preflush = blob.atomic.as_ref().unwrap().preflush();
        assert_eq!(preflush.request(target).unwrap(), Some(target));
        assert_eq!(preflush.complete(target, Err(Error::WriteFailed)), None);

        assert!(matches!(
            storage.open_atomic("atomic", b"failed-preflush").await,
            Err(Error::WriteFailed)
        ));

        drop((blob, storage));
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_atomic_batch_rewind_reclaims_unpublished_tail_on_completion() {
        let (storage, storage_directory) = create_test_storage();
        let (blob, _) = storage
            .open_atomic("atomic", b"batch-rewind")
            .await
            .unwrap();
        let live_path = storage_directory.join("atomic").join(hex(b"batch-rewind"));
        let data_offset = Layout::V2.data_offset();

        blob.append(b"base").await.unwrap();
        blob.sync().await.unwrap();
        blob.append(b"discarded").await.unwrap();
        storage
            .apply(vec![BatchOperation::Rewind {
                blob: blob.clone(),
                len: 4,
            }])
            .await
            .unwrap();
        assert_eq!(
            std::fs::metadata(&live_path).unwrap().len(),
            data_offset + 4
        );

        blob.append(b"abcdef").await.unwrap();
        assert_eq!(
            std::fs::metadata(&live_path).unwrap().len(),
            data_offset + 10
        );

        storage
            .apply(vec![BatchOperation::Rewind {
                blob: blob.clone(),
                len: 7,
            }])
            .await
            .unwrap();
        assert_eq!(blob.read_at(0, 7).await.unwrap().coalesce(), b"baseabc");
        assert_eq!(
            std::fs::metadata(&live_path).unwrap().len(),
            data_offset + 7
        );

        blob.append(b"XYZ").await.unwrap();
        storage
            .apply(vec![BatchOperation::Rewind {
                blob: blob.clone(),
                len: 7,
            }])
            .await
            .unwrap();
        assert_eq!(
            std::fs::metadata(&live_path).unwrap().len(),
            data_offset + 7
        );

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_dropped_batch_state_guard_poisons_generation() {
        let (storage, storage_directory) = create_test_storage();
        let (blob, _) = storage.open_atomic("atomic", b"canceled").await.unwrap();
        let state = blob.atomic.as_ref().unwrap().lock().await;

        drop(ArmedBatchState::new(state));

        assert!(blob.atomic.as_ref().unwrap().lock().await.is_poisoned());
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_canceled_atomic_append_after_backing_admission_blocks_reopen() {
        let (storage, storage_directory) = create_test_storage();
        let (opened, _) = storage.open_atomic("atomic", b"queued").await.unwrap();

        // Keep the loop stopped so an admitted write remains queued after its observer is dropped.
        let mut registry = Registry::default();
        let (submitter, io_loop) = iouring::IoUringLoop::new(
            iouring::Config {
                size: 1,
                ..Default::default()
            },
            &mut registry.sub_registry("blocked_iouring"),
        );
        let mut legacy = (*opened).clone();
        legacy.io_handle = submitter.clone();
        let state = Arc::downgrade(legacy.atomic.as_ref().unwrap());
        let generation = Arc::downgrade(&legacy.generation);
        let queued = AtomicBlob::from_legacy(legacy);
        drop(opened);

        {
            let append = queued.append(b"data");
            pin_mut!(append);
            assert!(poll!(append.as_mut()).is_pending());
        }
        drop(queued);

        assert!(state.upgrade().is_some());
        assert!(generation.upgrade().is_some());
        assert!(matches!(
            storage.open_atomic("atomic", b"queued").await,
            Err(Error::BlobCorrupt(_, _, reason)) if reason.contains("poisoned")
        ));

        drop(submitter);
        let loop_thread = std::thread::spawn(move || io_loop.run());
        loop_thread.join().unwrap();
        assert!(state.upgrade().is_none());
        assert!(generation.upgrade().is_none());
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_atomic_scan_sweeps_interrupted_creation() {
        let (storage, storage_directory) = create_test_storage();
        let (blob, _) = storage.open_atomic("atomic", b"live").await.unwrap();
        drop(blob);
        let partition = storage_directory.join("atomic");
        let staged = partition.join(".commonware-uno-create-interrupted");
        std::fs::write(&staged, b"partial").unwrap();
        std::fs::File::open(&partition).unwrap().sync_all().unwrap();

        assert_eq!(
            storage.scan("atomic").await.unwrap(),
            vec![b"live".to_vec()]
        );
        assert!(!staged.exists());

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_committed_batch_survives_completion_drop() {
        let (storage, storage_directory) = create_test_storage();
        let (old, _) = storage.open_atomic("batch_start", b"victim").await.unwrap();
        old.write_at_sync(0, b"old").await.unwrap();
        let (resized, _) = storage
            .open_atomic("batch_resize", b"retained")
            .await
            .unwrap();
        resized.write_at_sync(0, b"resize").await.unwrap();
        let victim = storage_directory.join("batch_start").join(hex(b"victim"));
        let operations = vec![
            BatchOperation::Remove(old.clone()),
            BatchOperation::Rewind {
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

        assert!(victim.exists());
        drop(completion);
        proceed_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), finished_rx)
            .await
            .expect("committed worker did not finish without an observer")
            .unwrap();
        assert!(!victim.exists());
        assert_eq!(old.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert_eq!(resized.read_at(0, 3).await.unwrap().coalesce(), b"res");

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_blob_header_handling() {
        // Verify header creation, logical offsets, resize, reopen, and corruption recovery.
        let (storage, storage_directory) = create_test_storage();

        // Test 1: New blob (V1 by default) returns logical size 0 and correct application version
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
        blob.write_at(0, data.to_vec()).await.unwrap();
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
        let read_buf = blob.read_at(0, data.len()).await.unwrap().coalesce();
        assert_eq!(read_buf, data);

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
        blob.write_at(0, b"test data".to_vec()).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob2, size2) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size2, 9, "reopened blob should have logical size 9");
        let read_buf = blob2.read_at(0, 9).await.unwrap().coalesce();
        assert_eq!(read_buf, b"test data");
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

    #[tokio::test]
    async fn test_blob_magic_mismatch() {
        // Verify opening a blob with an invalid runtime header fails as corrupt.
        let (storage, storage_directory) = create_test_storage();

        // Create the partition directory
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();

        // Manually create a file whose magic bytes are foreign (not a prefix of any
        // canonical header, so not a torn creation)
        let bad_magic_path = partition_path.join(hex(b"bad_magic"));
        std::fs::write(&bad_magic_path, b"XXXXXXXX").unwrap();

        // Opening should fail with corrupt error
        let err = storage
            .open("partition", b"bad_magic")
            .await
            .err()
            .expect("bad magic should fail");
        assert!(
            err.to_string()
                .starts_with("blob corrupt: partition/6261645f6d61676963 reason: invalid magic")
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_atomic_torn_v1_recreation_replaces_live_inode() {
        let (storage, storage_directory) = create_test_storage();
        let partition = storage_directory.join("partition");
        std::fs::create_dir_all(&partition).unwrap();

        let mut canonical = Header::create(&(0..=u16::MAX)).0;
        canonical.truncate(Header::PARSE_LEN - 1);
        let cases: [(&[u8], Vec<u8>); 2] = [(b"short", b"CWI".to_vec()), (b"canonical", canonical)];

        for (name, torn) in &cases {
            let live = partition.join(hex(name));
            std::fs::write(&live, torn).unwrap();
            let old_live = std::fs::File::open(&live).unwrap();

            let staged = partition.join(format!(".commonware-uno-create-{}", hex(name)));
            let atomic_region = Header::create_atomic(&(0..=u16::MAX)).0;
            std::fs::write(&staged, &atomic_region[..Header::PARSE_LEN - 1]).unwrap();
            std::fs::File::open(&partition).unwrap().sync_all().unwrap();

            let (blob, size) = storage.open_atomic("partition", name).await.unwrap();
            assert_eq!(size, 0);
            assert_eq!(
                old_live.metadata().unwrap().len(),
                torn.len() as u64,
                "atomic recreation must not rewrite the visible torn inode"
            );
            assert!(!staged.exists());
            let raw = std::fs::read(&live).unwrap();
            assert_eq!(raw.len(), Layout::V2.data_offset() as usize);
            assert_eq!(&raw[..Header::MAGIC_LENGTH], &Layout::V2.magic());
            drop(blob);
        }

        drop(storage);
        let storage = start_test_storage(storage_directory.clone());
        for (name, _) in &cases {
            storage
                .open_atomic("partition", name)
                .await
                .expect("atomically recreated blob must remain reopenable");
        }

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_partial_header_reset() {
        // Any file shorter than a header prelude must reset to a valid, empty blob on open
        // rather than fail as corrupt.
        let (storage, storage_directory) = create_test_storage();
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
    async fn test_vectored_write_partial_progress() {
        // Verify multi-buffer writes survive partial progress and preserve byte order.
        let (storage, storage_directory) = create_test_storage();

        let (blob, _) = storage.open("partition", b"vectest").await.unwrap();
        blob.resize(200).await.unwrap();

        // Write multiple buffers in one vectored call.
        let mut bufs = crate::IoBufs::default();
        bufs.append(crate::IoBuf::from(vec![0xAAu8; 80]));
        bufs.append(crate::IoBuf::from(vec![0xBBu8; 80]));
        blob.write_at(0, bufs).await.unwrap();
        blob.sync().await.unwrap();

        // Read back and verify.
        let data = blob.read_at(0, 160).await.unwrap().coalesce();
        assert_eq!(&data.as_ref()[..80], &[0xAAu8; 80]);
        assert_eq!(&data.as_ref()[80..], &[0xBBu8; 80]);

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_read_at_reports_eof_when_blob_is_too_short() {
        // Verify read-at returns `BlobInsufficientLength` when the kernel reports EOF mid-read.
        let (storage, storage_directory) = create_test_storage();

        // Persist fewer bytes than the upcoming read requests so the wrapper
        // encounters EOF after the header-adjusted offset has already started reading.
        let (blob, _) = storage.open("partition", b"short").await.unwrap();
        blob.write_at(0, b"abc".to_vec()).await.unwrap();
        blob.sync().await.unwrap();

        // The wrapper should surface this as an insufficient-length error instead
        // of silently returning a short buffer.
        let err = blob.read_at(0, 5).await.unwrap_err();
        assert_eq!(err.to_string(), "blob insufficient length");

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_read_at_buf_preserves_multichunk_layout() {
        // Verify multi-chunk caller buffers keep their shape after the temporary-buffer fallback.
        let (storage, storage_directory) = create_test_storage();

        let (blob, _) = storage.open("partition", b"multichunk").await.unwrap();
        blob.write_at(0, b"hello world".to_vec()).await.unwrap();
        blob.sync().await.unwrap();

        // Use a two-chunk destination so the read path must rebuild the original
        // chunk layout after reading through a temporary contiguous buffer.
        let bufs = IoBufsMut::from(vec![IoBufMut::with_capacity(5), IoBufMut::with_capacity(6)]);
        let read = blob.read_at_buf(0, 11, bufs).await.unwrap();
        // The result should keep the split layout rather than collapsing to one buffer.
        assert!(!read.is_single());
        assert_eq!(read.coalesce(), b"hello world");

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_zero_length_read_and_write_short_circuit() {
        // Verify zero-length reads and writes complete without touching the ring.
        let (storage, storage_directory) = create_test_storage();

        let (blob, size) = storage.open("partition", b"empty").await.unwrap();
        assert_eq!(size, 0);

        // Zero-length operations should succeed immediately and preserve the empty blob.
        blob.write_at(0, IoBufs::default()).await.unwrap();
        blob.write_at(0, IoBuf::default()).await.unwrap();
        blob.write_at(0, Vec::<u8>::new()).await.unwrap();
        let empty = blob.read_at(0, 0).await.unwrap();
        assert!(empty.is_empty());
        let _ = blob
            .read_at_buf(0, 0, IoBufsMut::from(IoBufMut::with_capacity(8)))
            .await
            .unwrap();

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_scan_rejects_non_file_entries() {
        // Verify partition scans reject unexpected directory contents as corruption.
        let (storage, storage_directory) = create_test_storage();

        // Inject a nested directory where `scan` expects only regular blob files.
        let partition = storage_directory.join("partition");
        std::fs::create_dir_all(partition.join("nested")).unwrap();

        // The wrapper should treat the partition as corrupt rather than silently skipping it.
        let err = storage.scan("partition").await.unwrap_err();
        assert_eq!(err.to_string(), "partition corrupt: partition");

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_remove_missing_targets_preserves_errors() {
        let (storage, storage_directory) = create_test_storage();

        assert!(matches!(
            storage.remove("missing", None).await,
            Err(Error::PartitionMissing(_))
        ));

        std::fs::create_dir_all(storage_directory.join("partition")).unwrap();
        assert!(matches!(
            storage.remove("partition", Some(b"missing")).await,
            Err(Error::BlobMissing(..))
        ));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_scan_ignores_non_utf8_file_names() {
        // Verify partition scans ignore entries whose names cannot be represented as UTF-8.
        let (storage, storage_directory) = create_test_storage();

        let partition = storage_directory.join("partition");
        std::fs::create_dir_all(&partition).unwrap();

        // Create a valid file entry with a non-UTF8 name so `scan` exercises
        // the branch that skips names it cannot decode.
        let invalid_name = OsString::from_vec(vec![0xff, 0xfe, 0xfd]);
        std::fs::write(partition.join(invalid_name), []).unwrap();

        let scanned = storage.scan("partition").await.unwrap();
        assert!(scanned.is_empty());

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_scan_rejects_non_hex_file_names() {
        // Verify partition scans reject UTF-8 entries that are not valid blob names.
        let (storage, storage_directory) = create_test_storage();

        let partition = storage_directory.join("partition");
        std::fs::create_dir_all(&partition).unwrap();

        // Create a file whose name is valid UTF-8 but not valid hex.
        std::fs::write(partition.join("not-hex"), []).unwrap();

        let err = storage.scan("partition").await.unwrap_err();
        assert_eq!(err.to_string(), "partition corrupt: partition");

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
            let (storage, storage_directory) = create_test_storage();

            let partition = storage_directory.join("partition");
            std::fs::create_dir_all(&partition).unwrap();
            std::fs::write(partition.join(bad_name), []).unwrap();

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

    #[tokio::test]
    async fn test_open_reports_partition_creation_failure() {
        // Verify opening a blob reports partition-creation failures when the
        // configured storage root is not a directory.
        let storage_directory = create_test_directory();
        let storage_root = storage_directory.join("root-file");
        std::fs::write(&storage_root, b"not a directory").unwrap();

        // Start storage against the invalid root so `open` reaches the
        // filesystem setup path under realistic wrapper code.
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let storage = Storage::start(
            Config {
                storage_directory: storage_root.clone(),
                iouring_config: Default::default(),
                thread_stack_size: utils::thread::system_thread_stack_size(),
            },
            &mut registry.sub_registry("storage"),
            pool,
        );

        let err = storage
            .open("partition", b"blob")
            .await
            .err()
            .expect("invalid storage root should fail");
        assert_eq!(err.to_string(), "partition creation failed: partition");

        let _ = std::fs::remove_file(&storage_root);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_open_reports_blob_open_failure_for_directory_path() {
        // Verify opening a blob reports `BlobOpenFailed` when the blob path
        // already exists as a directory instead of a regular file.
        let storage_directory = create_test_directory();
        let partition = storage_directory.join("partition");
        let blob_name = hex(b"blob");

        // Pre-create the would-be blob path as a directory so `OpenOptions`
        // fails once the wrapper reaches the open call.
        std::fs::create_dir_all(partition.join(&blob_name)).unwrap();

        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let storage = Storage::start(
            Config {
                storage_directory: storage_directory.clone(),
                iouring_config: Default::default(),
                thread_stack_size: utils::thread::system_thread_stack_size(),
            },
            &mut registry.sub_registry("storage"),
            pool,
        );

        let err = storage
            .open("partition", b"blob")
            .await
            .err()
            .expect("opening a directory as a blob should fail");
        assert!(
            err.to_string()
                .starts_with(&format!("blob open failed: partition/{blob_name} error:"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_offset_overflow_guards() {
        // Verify logical offsets are checked before any filesystem or io_uring work.
        let (storage, storage_directory) = create_test_storage();
        let (blob, _) = storage.open("partition", b"overflow").await.unwrap();

        // Each operation adds the runtime header size internally, so using the
        // maximum logical offset must fail before any request is submitted.
        assert_eq!(
            blob.read_at(u64::MAX, 1).await.unwrap_err().to_string(),
            "offset overflow"
        );
        assert_eq!(
            blob.write_at(u64::MAX, b"x".to_vec())
                .await
                .unwrap_err()
                .to_string(),
            "offset overflow"
        );
        assert_eq!(
            blob.resize(u64::MAX).await.unwrap_err().to_string(),
            "offset overflow"
        );

        drop(blob);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_read_and_write_report_handle_disconnect() {
        // Verify read/write wrappers report channel disconnects before any work
        // reaches the io_uring loop.
        let storage_directory = create_test_directory();
        let path = storage_directory.join("disconnected");
        let file = File::create(&path).unwrap();

        // Drop the loop immediately so the handle behaves like a dead
        // backend while the blob handle still exists.
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let (submitter, io_loop) = iouring::IoUringLoop::new(
            iouring::Config::default(),
            &mut registry.sub_registry("iouring"),
        );
        drop(io_loop);

        let blob = Blob::new(
            "partition".into(),
            b"blob",
            file,
            submitter,
            pool,
            Layout::V0.data_offset(),
        );

        // Read and write should fail through their wrapper-specific error enums
        // when the submission channel has already been disconnected.
        assert_eq!(
            blob.read_at(0, 1).await.unwrap_err().to_string(),
            "read failed"
        );
        assert_eq!(
            blob.write_at(0, b"x".to_vec())
                .await
                .unwrap_err()
                .to_string(),
            "write failed"
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_sync_dir_reports_missing_directory() {
        // Verify directory fsync reports missing paths through the open-failure wrapper.
        let storage_directory = create_test_directory();
        let missing = storage_directory.join("missing");

        let err = sync_dir(&missing).expect_err("missing directory should fail");
        assert!(err.to_string().starts_with(&format!(
            "blob open failed: {}/directory error:",
            missing.to_string_lossy()
        )));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_sync_reports_handle_disconnect() {
        // Verify the storage wrapper maps submission-channel disconnects to
        // `BlobSyncFailed(..., "failed to send work")`.
        let storage_directory = create_test_directory();
        let path = storage_directory.join("disconnected");
        let file = File::create(&path).unwrap();

        // Construct a blob handle whose handle has already lost its loop so
        // the wrapper must synthesize the disconnect error locally.
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let (submitter, io_loop) = iouring::IoUringLoop::new(
            iouring::Config::default(),
            &mut registry.sub_registry("iouring"),
        );
        drop(io_loop);

        let blob = Blob::new(
            "partition".into(),
            b"blob",
            file,
            submitter,
            pool,
            Layout::V0.data_offset(),
        );
        // Sync should fail through the blob-specific wrapper before any kernel work is attempted.
        let err = blob
            .sync()
            .await
            .expect_err("sync should fail without a loop");
        assert_eq!(
            err.to_string(),
            format!(
                "blob sync failed: partition/{} error: failed to send work",
                hex(b"blob")
            )
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_start_sync_reports_handle_disconnect() {
        // Verify start_sync completion errors use the same blob-specific wrapper as sync.
        let storage_directory = create_test_directory();
        let path = storage_directory.join("disconnected_start_sync");
        let file = File::create(&path).unwrap();

        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let (submitter, io_loop) = iouring::IoUringLoop::new(
            iouring::Config::default(),
            &mut registry.sub_registry("iouring"),
        );
        drop(io_loop);

        let blob = Blob::new(
            "partition".into(),
            b"blob",
            file,
            submitter,
            pool,
            Layout::V0.data_offset(),
        );
        let err = blob
            .start_sync()
            .await
            .await
            .expect_err("start_sync should fail without a loop");
        assert_eq!(
            err.to_string(),
            format!(
                "blob sync failed: partition/{} error: failed to send work",
                hex(b"blob")
            )
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_resize_reports_kernel_error() {
        // Verify resize preserves its storage-specific wrapper when the
        // underlying descriptor is a socket rather than a regular file.
        let storage_directory = create_test_directory();
        let (socket, _peer) = UnixStream::pair().unwrap();
        // SAFETY: `into_raw_fd` transfers ownership of the socket fd into `File`.
        let file = unsafe { File::from_raw_fd(socket.into_raw_fd()) };

        // `set_len` on a socket-backed file descriptor should fail in the
        // kernel, letting the wrapper expose `BlobResizeFailed`.
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let (submitter, io_loop) = iouring::IoUringLoop::new(
            iouring::Config::default(),
            &mut registry.sub_registry("iouring"),
        );
        drop(io_loop);

        let blob = Blob::new(
            "partition".into(),
            b"blob",
            file,
            submitter,
            pool,
            Layout::V0.data_offset(),
        );
        let err = blob
            .resize(0)
            .await
            .expect_err("resize should fail on a socket fd");
        assert!(err.to_string().starts_with(&format!(
            "blob resize failed: partition/{} error:",
            hex(b"blob")
        )));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_sync_reports_kernel_error() {
        // Verify completed sync CQE failures round-trip through the storage wrapper.
        let storage_directory = create_test_directory();
        let (socket, _peer) = UnixStream::pair().unwrap();
        // SAFETY: `into_raw_fd` transfers ownership of the socket fd into `File`.
        let file = unsafe { File::from_raw_fd(socket.into_raw_fd()) };

        // Run a real loop so the request reaches the kernel and fails there
        // rather than through the wrapper's disconnected-submit path.
        let mut registry = Registry::default();
        let pool = test_pool(&mut registry.sub_registry("pool"));
        let (submitter, io_loop) = iouring::IoUringLoop::new(
            iouring::Config::default(),
            &mut registry.sub_registry("iouring"),
        );
        let handle = std::thread::spawn(move || io_loop.run());

        let blob = Blob::new(
            "partition".into(),
            b"blob",
            file,
            submitter.clone(),
            pool,
            Layout::V0.data_offset(),
        );
        // The request should reach the kernel and come back as a wrapped sync failure.
        let err = blob
            .sync()
            .await
            .expect_err("sync should fail on a socket fd");
        let message = err.to_string();
        assert!(message.starts_with(&format!(
            "blob sync failed: partition/{} error:",
            hex(b"blob")
        )));
        assert_ne!(
            message,
            format!(
                "blob sync failed: partition/{} error: failed to send work",
                hex(b"blob")
            )
        );

        drop(blob);
        drop(submitter);
        // Joining the loop proves the live backend path shut down cleanly after the error.
        handle.join().unwrap();

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_torn_creation_recovers() {
        let (storage, storage_directory) = create_test_storage();

        // Create a durable V1 blob to obtain the canonical header region bytes.
        let (blob, _) = storage.open("partition", b"torn").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);
        let path = storage_directory.join("partition").join(hex(b"torn"));
        let region = std::fs::read(&path).unwrap();

        // Simulate a torn creation: a prefix of the canonical header region (the full
        // state enumeration lives in the Layout::interrupted_creation unit tables).
        let states = [region[..10].to_vec()];
        for state in states {
            std::fs::write(&path, &state).unwrap();
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 0);
            blob.sync().await.unwrap();
            drop(blob);

            // The healed blob round-trips through a reopen.
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 0);
            drop(blob);
        }

        // Foreign bytes are corruption, not a torn creation: nonzero padding behind a
        // torn (unparseable) prefix.
        let mut corrupt = vec![0u8; region.len()];
        corrupt[..10].copy_from_slice(&region[..10]);
        corrupt[100] = 0xFF;
        std::fs::write(&path, &corrupt).unwrap();
        let result = storage.open("partition", b"torn").await;
        assert!(matches!(result, Err(Error::BlobCorrupt(_, _, _))));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_v1_rejects_nonzero_header_padding() {
        let (storage, storage_directory) = create_test_storage();

        let partition_dir = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_dir).unwrap();
        let path = partition_dir.join(hex(b"dirty_padding"));
        let mut raw = crate::storage::header::tests::v1_blob_bytes(0, b"payload");
        raw[Header::PARSE_LEN] = 0xFF;
        std::fs::write(&path, raw).unwrap();

        let result = storage.open("partition", b"dirty_padding").await;
        assert!(
            matches!(result, Err(Error::BlobCorrupt(_, _, reason)) if reason.contains("header padding"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_v0_legacy_read() {
        let (storage, storage_directory) = create_test_storage();

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
        blob.write_at(size, b"!".to_vec()).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        // On disk the payload still sits immediately after the 8-byte V0 header.
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(raw_content.len(), Header::PRELUDE_SIZE + payload.len() + 1);
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V0.magic());
        assert_eq!(&raw_content[Header::PRELUDE_SIZE..], b"hello world!");

        let (blob, size) = storage.open("partition", b"v0").await.unwrap();
        assert_eq!(size, payload.len() as u64 + 1);
        let prior = blob.clone();
        storage.migrate_atomic(blob).await.unwrap();
        let (atomic, size) = storage.open_atomic("partition", b"v0").await.unwrap();
        assert_eq!(size, payload.len() as u64 + 1);
        assert_eq!(
            atomic.read_at(0, 12).await.unwrap().coalesce(),
            b"hello world!"
        );
        assert_eq!(
            prior.read_at(0, 12).await.unwrap().coalesce(),
            b"hello world!"
        );

        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V2.magic());
        assert_eq!(
            &raw_content[Layout::V2.data_offset() as usize..],
            b"hello world!"
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }
}
