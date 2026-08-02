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
    collections::{BTreeMap, BTreeSet},
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
#[cfg(test)]
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
type SharedV2State = Arc<super::preflush::Context>;
#[cfg(unix)]
type V2StateEntry = (Weak<Generation>, Weak<super::preflush::Context>);

struct Namespace {
    lock: Arc<Mutex<()>>,
    recovery_required: AtomicBool,
    carried_batch_decision: AtomicBool,
    generations: super::generation::Registry,
    #[cfg(unix)]
    embedded_batch_decision: SyncMutex<Option<Arc<[u8]>>>,
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
                    | super::batch::Operation::Rewind { .. } => {}
                }
            }
        }
    }

    #[cfg(unix)]
    fn embedded_batch_decision(&self) -> Option<Arc<[u8]>> {
        self.embedded_batch_decision.lock().clone()
    }

    #[cfg(not(unix))]
    const fn embedded_batch_decision(&self) -> Option<Arc<[u8]>> {
        None
    }

    #[cfg(unix)]
    fn set_embedded_batch_decision(&self, decision: Option<Arc<[u8]>>) {
        *self.embedded_batch_decision.lock() = decision;
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
) -> Result<Option<(u64, u16, u64, Option<[u8; Header::V2_INCARNATION_LEN]>)>, Error> {
    let mut raw = vec![0u8; Header::resolve_len(raw_len)];
    file.read_exact(&mut raw)
        .await
        .map_err(|_| Error::ReadFailed)?;
    Ok(super::header::resolve(
        &raw, raw_len, versions, partition, name,
    )?
    .map(|(logical_size, blob_version, data_offset)| {
        (
            logical_size,
            blob_version,
            data_offset,
            Header::atomic_incarnation(&raw),
        )
    }))
}

/// Complete any carried embedded or removal decision while retaining the namespace guard.
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
        #[cfg(unix)]
        let embedded = namespace.embedded_batch_decision();
        #[cfg(unix)]
        let result = embedded
            .as_deref()
            .map_or(Ok(()), |decision| {
                super::batch::materialize_embedded(&root, decision)
            })
            .and_then(|()| {
                super::batch::recover_notifying(&root, move |operations| {
                    invalidator.invalidate_operations(operations);
                })
            });
        #[cfg(not(unix))]
        let result = super::batch::recover_notifying(&root, move |operations| {
            invalidator.invalidate_operations(operations);
        });
        if result.is_ok() {
            #[cfg(unix)]
            namespace.set_embedded_batch_decision(None);
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
                embedded_batch_decision: SyncMutex::new(None),
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
    async fn lock_batch(&self) -> Result<(OwnedMutexGuard<()>, bool, Option<Arc<[u8]>>), Error> {
        let guard = self.namespace.lock.clone().lock_owned().await;
        if self
            .namespace
            .carried_batch_decision
            .load(Ordering::Acquire)
        {
            return Ok((guard, true, self.namespace.embedded_batch_decision()));
        }
        let guard = recover_namespace(
            self.namespace.clone(),
            self.cfg.storage_directory.clone(),
            guard,
        )
        .await?;
        Ok((guard, false, None))
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
        let mut removals = BTreeSet::new();
        for operation in operations {
            match operation {
                BatchOperation::Remove(blob) => {
                    let partition = blob.partition().to_string();
                    let name = blob.name().to_vec();
                    if !blob.is_atomic() {
                        return Err(Error::BlobOpenFailed(
                            partition,
                            hex(&name),
                            std::io::Error::new(
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
                    handles.push(blob.clone());
                    removals.insert((partition.clone(), name.clone()));
                    blobs.entry((partition, name)).or_insert(blob);
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
                BatchOperation::Rewind { blob, len } => {
                    let partition = blob.partition().to_string();
                    let name = blob.name().to_vec();
                    if !blob.is_atomic() {
                        return Err(Error::BlobOpenFailed(
                            partition,
                            hex(&name),
                            std::io::Error::new(
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
                    handles.push(blob.clone());
                    blobs.entry((partition, name)).or_insert(blob);
                }
            }
        }
        let filesystem_operations = super::batch::canonicalize_operations(descriptors)?;
        super::batch::preflight(&filesystem_operations)?;
        if filesystem_operations.is_empty() {
            drop(self.lock_recovered().await?);
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

        let (guard, carry_decision, embedded_decision) = self.lock_batch().await?;
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
            if let Some(len) =
                rewind_lengths.get(&(blob.partition().to_string(), blob.name().to_vec()))
            {
                state.validate_rewind(*len)?;
            }
        }

        self.namespace
            .recovery_required
            .store(true, Ordering::Release);
        let root = self.cfg.storage_directory.clone();
        let namespace = self.namespace.clone();
        let (commit_sender, commit_receiver) = oneshot::channel();
        let (completion_sender, completion_receiver) = oneshot::channel();
        drop(tokio::task::spawn_blocking(move || {
            on_worker_start();
            struct ParticipantPreparation {
                partition: String,
                name: Vec<u8>,
                incarnation: [u8; Header::V2_INCARNATION_LEN],
                candidate: super::atomic::Candidate,
                payload_start: u64,
                payload_checksum: super::atomic::PayloadChecksumEligibility,
                witness_capacity: usize,
            }

            enum PreparationMessage {
                Ready(Vec<(usize, Result<Option<ParticipantPreparation>, Error>)>),
                Panicked,
            }

            enum BatchControl {
                Abort,
                StageAndSync(Option<Arc<[u8]>>),
            }

            let resize_lengths = Arc::new(rewind_lengths);
            let removal_keys = Arc::new(removals);

            let item_count = locked.len();
            let worker_count = item_count.min(MAX_BATCH_WORKERS);
            let payload_budget = if item_count == 0 {
                super::atomic::MAX_VALIDATED_PAYLOAD_LEN
            } else {
                super::atomic::MAX_VALIDATED_PAYLOAD_LEN / item_count as u64
            };
            let mut chunks = Vec::with_capacity(worker_count);
            if worker_count != 0 {
                let chunk_len = item_count.div_ceil(worker_count);
                let mut locked = locked.into_iter().enumerate();
                loop {
                    let chunk = locked.by_ref().take(chunk_len).collect::<Vec<_>>();
                    if chunk.is_empty() {
                        break;
                    }
                    chunks.push(chunk);
                }
            }

            // Keep each participant worker alive between candidate preparation and its durability
            // barrier. Tokio's blocking pool retains these threads across batches while the owner
            // constructs the shared participant-embedded witness.
            let (mut prepared_states, embedded_witness, has_participant_mutations, staging_error) = {
                let (summary_sender, summary_receiver) = std::sync::mpsc::channel();
                let (result_sender, result_receiver) = std::sync::mpsc::channel();
                let mut controls = Vec::with_capacity(chunks.len());
                for chunk in chunks {
                    let resize_lengths = resize_lengths.clone();
                    let removal_keys = removal_keys.clone();
                    let summary_sender = summary_sender.clone();
                    let result_sender = result_sender.clone();
                    let (control_sender, control_receiver) = std::sync::mpsc::sync_channel(1);
                    controls.push(control_sender);
                    drop(tokio::task::spawn_blocking(move || {
                        let mut summary_sent = false;
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let mut states = Vec::with_capacity(chunk.len());
                            let mut summaries = Vec::with_capacity(chunk.len());
                            for (index, (blob, mut state)) in chunk {
                                let removed = removal_keys.contains(&(
                                    blob.partition().to_string(),
                                    blob.name().to_vec(),
                                ));
                                let resize = resize_lengths
                                    .get(&(blob.partition().to_string(), blob.name().to_vec()))
                                    .copied();
                                if let Some(len) = resize {
                                    let rewound = blob.rewind_log(&mut state, len);
                                    if let Err(error) = rewound {
                                        summaries.push((index, Err(error.clone())));
                                        states.push((index, blob, state, Err(error), removed));
                                        continue;
                                    }
                                }
                                let mut prepared = if removed {
                                    blob.prepare_batch_delete_unflushed(&state).map(Some)
                                } else {
                                    blob.prepare_batch_commit_unflushed(&mut state)
                                };
                                let preflush = prepared
                                    .as_ref()
                                    .ok()
                                    .and_then(Option::as_ref)
                                    .is_some_and(|prepared| match prepared.payload_checksum() {
                                        super::atomic::PayloadChecksumEligibility::Eligible(
                                            Some(checksum),
                                        ) => checksum.len > payload_budget,
                                        super::atomic::PayloadChecksumEligibility::Eligible(
                                            None,
                                        ) => false,
                                        super::atomic::PayloadChecksumEligibility::Ineligible => {
                                            true
                                        }
                                    });
                                if preflush {
                                    let target =
                                        prepared.as_ref().unwrap().as_ref().unwrap().raw_len();
                                    match blob.ensure_preflush_blocking(target) {
                                        Ok(()) => prepared
                                            .as_mut()
                                            .unwrap()
                                            .as_mut()
                                            .unwrap()
                                            .mark_payload_preflushed(),
                                        Err(error) => prepared = Err(error),
                                    }
                                }
                                let summary = match &prepared {
                                    Ok(Some(prepared)) => Ok(Some(ParticipantPreparation {
                                        partition: blob.partition().to_string(),
                                        name: blob.name().to_vec(),
                                        incarnation: blob.incarnation(),
                                        candidate: prepared.candidate(),
                                        payload_start: prepared.payload_start(),
                                        payload_checksum: prepared.payload_checksum(),
                                        witness_capacity: prepared.batch_witness_capacity(),
                                    })),
                                    Ok(None) => Ok(None),
                                    Err(error) => Err(error.clone()),
                                };
                                summaries.push((index, summary));
                                states.push((index, blob, state, prepared, removed));
                            }
                            let _ = summary_sender.send(PreparationMessage::Ready(summaries));
                            summary_sent = true;
                            let control = control_receiver.recv().unwrap_or(BatchControl::Abort);
                            let mut barrier_errors = Vec::new();
                            if let BatchControl::StageAndSync(witness) = control {
                                for (_, blob, _, prepared, removed) in &mut states {
                                    let Ok(Some(prepared)) = prepared else {
                                        continue;
                                    };
                                    let result = if *removed {
                                        witness.as_deref().map_or_else(
                                            || {
                                                Err(std::io::Error::new(
                                                    std::io::ErrorKind::InvalidInput,
                                                    "batch deletion requires an embedded witness",
                                                )
                                                .into())
                                            },
                                            |witness| blob.stage_batch_delete(prepared, witness),
                                        )
                                    } else {
                                        blob.stage_batch_commit(prepared, witness.as_deref())
                                    };
                                    if let Err(error) = result {
                                        barrier_errors.push(error);
                                    }
                                }
                                for (_, blob, _, prepared, removed) in &states {
                                    if !removed
                                        && prepared.as_ref().is_ok_and(Option::is_some)
                                        && let Err(error) = blob.sync_batch_commit()
                                    {
                                        barrier_errors.push(error);
                                    }
                                }
                            }
                            (states, barrier_errors)
                        }));
                        if !summary_sent {
                            let _ = summary_sender.send(PreparationMessage::Panicked);
                        }
                        drop(summary_sender);
                        let _ = result_sender.send(result);
                    }));
                }
                drop(summary_sender);
                drop(result_sender);

                let mut summaries = std::iter::repeat_with(|| None)
                    .take(item_count)
                    .collect::<Vec<_>>();
                let mut preparation_panicked = false;
                for _ in 0..worker_count {
                    match summary_receiver.recv() {
                        Ok(PreparationMessage::Ready(worker_summaries)) => {
                            for (index, summary) in worker_summaries {
                                summaries[index] = Some(summary);
                            }
                        }
                        Ok(PreparationMessage::Panicked) => {
                            preparation_panicked = true;
                        }
                        Err(_) => {
                            preparation_panicked = true;
                            break;
                        }
                    }
                }

                let mut staging_error = summaries
                    .iter()
                    .filter_map(Option::as_ref)
                    .find_map(|summary| summary.as_ref().err().cloned());
                let mut speculative_payload_bytes = Some(0u64);
                let mut participant_count = 0usize;
                if staging_error.is_none() && !preparation_panicked {
                    for summary in summaries.iter().filter_map(Option::as_ref) {
                        let Some(prepared) = summary.as_ref().unwrap() else {
                            continue;
                        };
                        participant_count += 1;
                        match prepared.payload_checksum {
                            super::atomic::PayloadChecksumEligibility::Eligible(checksum) => {
                                speculative_payload_bytes =
                                    speculative_payload_bytes.and_then(|total| {
                                        total.checked_add(
                                            checksum.map_or(0, |checksum| checksum.len),
                                        )
                                    });
                            }
                            super::atomic::PayloadChecksumEligibility::Ineligible => {
                                speculative_payload_bytes = None;
                            }
                        }
                    }
                }
                let verifiable = staging_error.is_none()
                    && !preparation_panicked
                    && speculative_payload_bytes.is_some();
                let embedded_eligible = verifiable
                    && speculative_payload_bytes.is_some_and(|verified_bytes| {
                        super::batch::supports_speculation(
                            &filesystem_operations,
                            participant_count,
                            verified_bytes,
                        )
                    });
                let participants = summaries
                    .iter()
                    .filter_map(Option::as_ref)
                    .filter_map(|summary| summary.as_ref().ok()?.as_ref())
                    .map(|prepared| {
                        let payload_checksum = if verifiable {
                            let super::atomic::PayloadChecksumEligibility::Eligible(checksum) =
                                prepared.payload_checksum
                            else {
                                unreachable!("verifiable groups contain only eligible epochs")
                            };
                            checksum
                        } else {
                            None
                        };
                        super::batch::Participant {
                            partition: prepared.partition.clone(),
                            name: prepared.name.clone(),
                            incarnation: prepared.incarnation,
                            candidate: prepared.candidate.clone(),
                            payload_start: if verifiable {
                                prepared.payload_start
                            } else {
                                0
                            },
                            payload_checksum,
                        }
                    })
                    .collect::<Vec<_>>();

                let embedded_witness = embedded_eligible
                    .then(|| super::batch::prepare_embedded(&participants, &filesystem_operations))
                    .transpose()
                    .ok()
                    .flatten()
                    .filter(|descriptor| {
                        summaries
                            .iter()
                            .filter_map(Option::as_ref)
                            .filter_map(|summary| summary.as_ref().ok()?.as_ref())
                            .all(|prepared| prepared.witness_capacity >= descriptor.len())
                    })
                    .map(Arc::<[u8]>::from);

                if staging_error.is_none() && !preparation_panicked {
                    if let Some(previous) = embedded_decision.as_deref() {
                        let can_supersede = embedded_witness.as_deref().is_some_and(|_| {
                            super::batch::can_supersede_embedded(previous, &participants)
                                .unwrap_or(false)
                        });
                        if !can_supersede {
                            match super::batch::materialize_embedded(&root, previous) {
                                Ok(()) => {
                                    namespace.set_embedded_batch_decision(None);
                                    namespace
                                        .carried_batch_decision
                                        .store(false, Ordering::Release);
                                }
                                Err(error) => staging_error = Some(Error::from(error)),
                            }
                        }
                    } else if carry_decision {
                        staging_error = Some(
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "carried batch decision has no embedded witness",
                            )
                            .into(),
                        );
                    }
                }

                if staging_error.is_none()
                    && !preparation_panicked
                    && participant_count != 0
                    && embedded_witness.is_none()
                {
                    staging_error = Some(
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "storage batch is not eligible for embedded crash recovery",
                        )
                        .into(),
                    );
                }
                let stage_witness = embedded_witness.clone();
                let run_barrier = staging_error.is_none() && !preparation_panicked;
                for control in controls {
                    let command = if run_barrier {
                        BatchControl::StageAndSync(stage_witness.clone())
                    } else {
                        BatchControl::Abort
                    };
                    let _ = control.send(command);
                }
                let mut indexed_states = Vec::with_capacity(item_count);
                let mut sync_error = None;
                let mut first_panic = None;
                for _ in 0..worker_count {
                    match result_receiver.recv() {
                        Ok(Ok((states, sync_errors))) => {
                            indexed_states.extend(states);
                            if sync_error.is_none() {
                                sync_error = sync_errors.into_iter().next();
                            }
                        }
                        Ok(Err(panic)) if first_panic.is_none() => {
                            first_panic = Some(panic);
                        }
                        Ok(Err(_)) => {}
                        Err(_) => {
                            if staging_error.is_none() {
                                staging_error = Some(Error::Closed);
                            }
                            break;
                        }
                    }
                }
                if let Some(panic) = first_panic {
                    std::panic::resume_unwind(panic);
                }
                indexed_states.sort_unstable_by_key(|(index, _, _, _, _)| *index);
                let prepared_states = indexed_states
                    .into_iter()
                    .map(|(_, blob, state, prepared, removed)| (blob, state, prepared, removed))
                    .collect::<Vec<_>>();
                if staging_error.is_none() {
                    staging_error = sync_error;
                }
                (
                    prepared_states,
                    embedded_witness,
                    participant_count != 0,
                    staging_error,
                )
            };

            let invalidator = namespace.clone();
            let committed = std::cell::Cell::new(false);
            let commit_sender = std::cell::Cell::new(Some(commit_sender));
            let mut on_commit = Some(on_commit);
            let result = {
                let mut notify_commit = |operations: &[super::batch::Operation]| {
                    invalidator.invalidate_operations(operations);
                    invalidator
                        .carried_batch_decision
                        .store(false, Ordering::Release);
                    committed.set(true);
                    if let Some(sender) = commit_sender.take() {
                        let _ = sender.send(Ok(()));
                    }
                    on_commit
                        .take()
                        .expect("storage batch commits exactly once")();
                };
                staging_error.map_or_else(
                    || {
                        if let Some(witness) = embedded_witness {
                            let has_removals = filesystem_operations
                                .iter()
                                .any(|operation| matches!(operation, super::batch::Operation::Remove(_)));
                            namespace.set_embedded_batch_decision(Some(witness.clone()));
                            notify_commit(&filesystem_operations);
                            if has_removals {
                                super::batch::materialize_embedded(&root, &witness)?;
                                namespace.set_embedded_batch_decision(None);
                            }
                            for (blob, mut state, prepared, removed) in prepared_states.drain(..) {
                                if removed {
                                    debug_assert!(prepared.as_ref().is_ok_and(Option::is_some));
                                    continue;
                                }
                                let force_truncate = resize_lengths.contains_key(&(
                                    blob.partition().to_string(),
                                    blob.name().to_vec(),
                                ));
                                blob.activate_batch_commit(
                                    &mut state,
                                    prepared.unwrap(),
                                    !has_removals,
                                    force_truncate,
                                )?;
                            }
                            return Ok(!has_removals);
                        }

                        debug_assert!(!has_participant_mutations);
                        notify_commit(&filesystem_operations);
                        for (blob, mut state, prepared, removed) in prepared_states.drain(..) {
                            debug_assert!(!removed);
                            let prepared = prepared.unwrap();
                            debug_assert!(prepared.is_none());
                            let force_truncate = resize_lengths.contains_key(&(
                                blob.partition().to_string(),
                                blob.name().to_vec(),
                            ));
                            blob.activate_batch_commit(
                                &mut state,
                                prepared,
                                false,
                                force_truncate,
                            )?;
                        }
                        Ok(false)
                    },
                    Err,
                )
            };
            if result.is_err() {
                for (_, state, _, _) in &mut prepared_states {
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

        #[cfg(unix)]
        {
            let root = self.cfg.storage_directory.clone();
            let recovery_partition = stored_partition.clone();
            let recovery_name = name.to_vec();
            let recovery = tokio::task::spawn_blocking(move || {
                super::batch::recover_named_embedded(&root, &recovery_partition, &recovery_name)
            });
            let removed = match recovery.await {
                Ok(result) => result?,
                Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
                Err(_) => return Err(Error::Closed),
            };
            if removed {
                self.namespace
                    .invalidate_operations(&[super::batch::Operation::Remove(
                        crate::RemoveTarget::Blob {
                            partition: stored_partition.clone(),
                            name: name.to_vec(),
                        },
                    )]);
            }
        }

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
        let (file, guard, (logical_size, blob_version, data_offset, incarnation)) = match existing {
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
                (file, guard, resolved)
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
                    let incarnation = Header::atomic_incarnation(&region);
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

                    Ok::<_, Error>((file, guard, (0, blob_version, data_offset, incarnation)))
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
                let recovery_root = self.cfg.storage_directory.clone();
                let recovery_partition = stored_partition.clone();
                let recovery_name = name.to_vec();
                let recovered = tokio::task::spawn_blocking(move || {
                    super::batch::recover_embedded(
                        &recovery_root,
                        &recovery_partition,
                        &recovery_name,
                        &recovery_file,
                        data_offset,
                    )?;
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
                let state = super::preflush::Context::new(recovered).map_err(|error| {
                    Error::BlobCorrupt(
                        partition.into(),
                        hex(name),
                        format!("atomic preflush initialization failed: {error}"),
                    )
                })?;
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
                incarnation.expect("V2 headers have a persistent incarnation"),
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
        if let Some(context) = atomic_state {
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
        #[cfg(unix)]
        {
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
            let recovery_root = self.cfg.storage_directory.clone();
            let recovery = tokio::task::spawn_blocking(move || {
                super::batch::recover_removal_witnesses(
                    &recovery_root,
                    std::slice::from_ref(&recovery_operation),
                )
            });
            match recovery.await {
                Ok(result) => result?,
                Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
                Err(_) => return Err(Error::Closed),
            }
        }
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

        #[cfg(unix)]
        {
            let root = self.cfg.storage_directory.clone();
            let recovery_partition = partition.to_string();
            match tokio::task::spawn_blocking(move || {
                super::batch::recover_partition_embedded(&root, &recovery_partition)
            })
            .await
            {
                Ok(result) => result?,
                Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
                Err(_) => return Err(Error::Closed),
            }
        }

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
        BatchStorage as _, Blob, BufferPoolConfig, Storage as _, WriteOptions,
        storage::{
            Layout,
            tests::{run_batch_storage_tests, run_storage_foreign_handle_test, run_storage_tests},
        },
        telemetry::metrics::Registry,
    };
    use commonware_utils::sys_rng;
    use rand::RngExt as _;
    #[cfg(unix)]
    use std::os::unix::fs::FileExt as _;
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
        blob.append(baseline.clone()).await.unwrap();
        blob.sync().await.unwrap();
        let live_path = source_directory
            .join("partition")
            .join(commonware_formatting::hex(b"blob"));
        let committed_end = std::fs::metadata(&live_path).unwrap().len();
        blob.append(vec![0xa5; baseline.len()]).await.unwrap();
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
    async fn test_atomic_rewind_reclaims_only_unpublished_tail_before_sync() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_atomic_rewind_{}", random_suffix()));
        let storage = Storage::new(Config::new(directory.clone(), 2 * 1024 * 1024), test_pool());
        let (blob, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        let path = directory
            .join("partition")
            .join(commonware_formatting::hex(b"blob"));
        let data_offset = Layout::V2.data_offset();

        blob.append(b"abcdef").await.unwrap();
        blob.sync().await.unwrap();
        blob.append(b"ghij").await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), data_offset + 10);

        blob.rewind(8).await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), data_offset + 8);
        blob.rewind(6).await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), data_offset + 6);

        // The current durable root still names six bytes, so crossing that frontier cannot
        // truncate until the shorter root is durable.
        blob.rewind(3).await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), data_offset + 6);
        blob.sync().await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), data_offset + 3);

        drop((blob, storage));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_batch_rewind_reclaims_unpublished_tail_on_completion() {
        let directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_batch_rewind_{}",
            random_suffix()
        ));
        let storage = Storage::new(Config::new(directory.clone(), 2 * 1024 * 1024), test_pool());
        let (blob, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        let path = directory
            .join("partition")
            .join(commonware_formatting::hex(b"blob"));
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
        assert_eq!(std::fs::metadata(&path).unwrap().len(), data_offset + 4);

        blob.append(b"abcdef").await.unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), data_offset + 10);

        storage
            .apply(vec![BatchOperation::Rewind {
                blob: blob.clone(),
                len: 7,
            }])
            .await
            .unwrap();
        assert_eq!(blob.read_at(0, 7).await.unwrap().coalesce(), b"baseabc");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), data_offset + 7);

        blob.append(b"XYZ").await.unwrap();
        storage
            .apply(vec![BatchOperation::Rewind {
                blob: blob.clone(),
                len: 7,
            }])
            .await
            .unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), data_offset + 7);

        drop((blob, storage));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_batch_preflushes_payload_above_recovery_bound() {
        let directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_large_batch_{}",
            random_suffix()
        ));
        let config = Config::new(directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config.clone(), test_pool());
        let (blob, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        let len = usize::try_from(crate::storage::atomic::MAX_VALIDATED_PAYLOAD_LEN).unwrap() + 1;
        blob.append(vec![0x5a; len]).await.unwrap();
        storage
            .apply(vec![BatchOperation::Publish(blob.clone())])
            .await
            .unwrap();
        drop((blob, storage));

        let recovered = Storage::new(config, test_pool());
        let (blob, recovered_len) = recovered.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(recovered_len, len as u64);
        assert_eq!(blob.read_at(0, 1).await.unwrap().coalesce(), b"Z");
        assert_eq!(
            blob.read_at(len as u64 - 1, 1).await.unwrap().coalesce(),
            b"Z"
        );

        drop((blob, recovered));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_background_preflush_writes_payload_before_marker() {
        let directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_background_preflush_{}",
            random_suffix()
        ));
        let config = Config::new(directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config.clone(), test_pool());
        let (blob, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        let prefix_len = crate::storage::atomic::BACKGROUND_PREFLUSH_INTERVAL as usize;
        blob.append(vec![0x5a; prefix_len]).await.unwrap();
        let target = blob.wait_for_background_preflush().await.unwrap();
        assert_eq!(target, Layout::V2.data_offset() + prefix_len as u64);

        let path = directory.join("partition").join(hex(b"blob"));
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

        let recovered = Storage::new(config, test_pool());
        let (blob, len) = recovered.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(len, prefix_len as u64 + 4);
        assert_eq!(
            blob.read_at(prefix_len as u64, 4).await.unwrap().coalesce(),
            b"tail"
        );

        drop((blob, recovered));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_rewind_forgets_preflush_credit_before_reusing_offsets() {
        let directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_preflush_rewind_{}",
            random_suffix()
        ));
        let storage = Storage::new(Config::new(directory.clone(), 2 * 1024 * 1024), test_pool());
        let (blob, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        let payload_len = crate::storage::atomic::BACKGROUND_PREFLUSH_INTERVAL as usize;
        blob.append(vec![0x5a; payload_len]).await.unwrap();
        blob.wait_for_background_preflush().await.unwrap();

        blob.rewind(0).await.unwrap();
        assert_eq!(
            blob.background_preflush_requested(),
            Layout::V2.data_offset(),
            "rewind must remove durability credit for the discarded physical offsets"
        );

        blob.append(vec![0xa5; payload_len]).await.unwrap();
        assert_eq!(
            blob.wait_for_background_preflush().await.unwrap(),
            Layout::V2.data_offset() + payload_len as u64
        );
        storage
            .apply(vec![BatchOperation::Publish(blob.clone())])
            .await
            .unwrap();

        drop((blob, storage));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_invalid_rewind_does_not_flush_or_poison() {
        let directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_invalid_rewind_{}",
            random_suffix()
        ));
        let storage = Storage::new(Config::new(directory.clone(), 2 * 1024 * 1024), test_pool());
        let (blob, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        blob.append(b"base").await.unwrap();
        blob.sync().await.unwrap();
        blob.append(b"tail").await.unwrap();
        let requested = blob.background_preflush_requested();

        assert!(blob.rewind(9).await.is_err());
        assert_eq!(blob.background_preflush_requested(), requested);
        assert_eq!(blob.append(b"ok").await.unwrap(), 8);
        blob.sync().await.unwrap();

        drop((blob, storage));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_reopen_rejects_sticky_preflush_failure() {
        let directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_failed_preflush_{}",
            random_suffix()
        ));
        let storage = Storage::new(Config::new(directory.clone(), 2 * 1024 * 1024), test_pool());
        let (blob, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        blob.fail_background_preflush_for_test(Layout::V2.data_offset() + 1);

        assert!(matches!(
            storage.open_atomic("partition", b"blob").await,
            Err(Error::WriteFailed)
        ));

        drop((blob, storage));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_atomic_fused_sync_large_write_with_one_blocking_thread() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let directory = env::temp_dir().join(format!(
                "storage_tokio_atomic_fused_sync_{}",
                random_suffix()
            ));
            let config = Config::new(directory.clone(), 2 * 1024 * 1024);
            let storage = Storage::new(config.clone(), test_pool());
            let (blob, _) = storage.open_atomic("partition", b"blob").await.unwrap();
            let payload_len = crate::storage::atomic::BACKGROUND_PREFLUSH_INTERVAL as usize;
            tokio::time::timeout(
                Duration::from_secs(10),
                blob.write_at(0, vec![0x5a; payload_len], WriteOptions::SYNC),
            )
            .await
            .expect("fused sync deadlocked behind its own queued preflush")
            .unwrap();
            drop((blob, storage));

            let recovered = Storage::new(config, test_pool());
            let (blob, len) = recovered.open_atomic("partition", b"blob").await.unwrap();
            assert_eq!(len, payload_len as u64);
            assert_eq!(blob.read_at(0, 1).await.unwrap().coalesce(), b"Z");
            assert_eq!(
                blob.read_at(payload_len as u64 - 1, 1)
                    .await
                    .unwrap()
                    .coalesce(),
                b"Z"
            );
            drop((blob, recovered));
            std::fs::remove_dir_all(directory).unwrap();
        });
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_atomic_independent_opens_share_dirty_generation() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_atomic_shared_{}", random_suffix()));
        let config = Config::new(directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config.clone(), test_pool());
        let (first, _) = storage.open_atomic("partition", b"blob").await.unwrap();
        first.append(b"old").await.unwrap();
        first.sync().await.unwrap();
        first.append(b"new-value").await.unwrap();

        let (second, len) = storage.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(len, 12);
        assert_eq!(
            second.read_at(0, 12).await.unwrap().coalesce(),
            b"oldnew-value"
        );
        second.sync().await.unwrap();
        drop((first, second, storage));

        let recovered = Storage::new(config, test_pool());
        let (blob, len) = recovered.open_atomic("partition", b"blob").await.unwrap();
        assert_eq!(len, 12);
        assert_eq!(
            blob.read_at(0, 12).await.unwrap().coalesce(),
            b"oldnew-value"
        );
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
        updated.append(b"durable").await.unwrap();
        updated.sync().await.unwrap();
        updated.append(b"pending").await.unwrap();

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
        old.append(b"old").await.unwrap();
        old.sync().await.unwrap();
        storage.remove("partition", Some(b"blob")).await.unwrap();
        old.append(b"stale").await.unwrap();

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
        blob.append(b"durable").await.unwrap();
        drop(blob.start_sync().await);
        blob.append(b"pending").await.unwrap();
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
        let (old, _) = storage
            .open_atomic("batch_cancel", b"victim")
            .await
            .unwrap();
        old.write_at(0, b"old", WriteOptions::SYNC).await.unwrap();

        let operations = vec![BatchOperation::Remove(old.clone())];
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
        let (old, _) = storage
            .open_atomic("batch_start", b"victim")
            .await
            .unwrap();
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
        first.append(b"old-one").await.unwrap();
        second.append(b"old-two").await.unwrap();
        first.sync().await.unwrap();
        second.sync().await.unwrap();
        first.append(b"new-one").await.unwrap();
        second.append(b"new-two").await.unwrap();

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
                        .expect("test waits for the durable group decision");
                    proceed_rx
                        .recv()
                        .expect("test releases group completion");
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
        assert_eq!(first_len, 14);
        assert_eq!(second_len, 14);
        assert_eq!(
            first.read_at(0, 14).await.unwrap().coalesce(),
            b"old-onenew-one"
        );
        assert_eq!(
            second.read_at(0, 14).await.unwrap().coalesce(),
            b"old-twonew-two"
        );

        let _ = std::fs::remove_dir_all(storage_directory);
        let _ = std::fs::remove_dir_all(crash_directory);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_remove_recovers_an_unopened_embedded_participant() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_batch_remove_witness_{}",
            random_suffix()
        ));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config.clone(), test_pool());
        let (first, _) = storage.open_atomic("group", b"first").await.unwrap();
        let (second, _) = storage.open_atomic("group", b"second").await.unwrap();
        first.append(b"old-one").await.unwrap();
        second.append(b"old-two").await.unwrap();
        first.sync().await.unwrap();
        second.sync().await.unwrap();
        first.append(b"new-one").await.unwrap();
        second.append(b"new-two").await.unwrap();
        storage
            .apply(vec![
                BatchOperation::Publish(first.clone()),
                BatchOperation::Publish(second.clone()),
            ])
            .await
            .unwrap();
        drop(first);
        drop(second);
        drop(storage);

        let restarted = Storage::new(config, test_pool());
        restarted.remove("group", Some(b"first")).await.unwrap();
        let (second, len) = restarted.open_atomic("group", b"second").await.unwrap();
        assert_eq!(len, 14);
        assert_eq!(
            second.read_at(0, 14).await.unwrap().coalesce(),
            b"old-twonew-two"
        );

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_remove_read_only_legacy_blob() {
        use std::os::unix::fs::PermissionsExt as _;

        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_remove_read_only_legacy_{}",
            random_suffix()
        ));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config.clone(), test_pool());
        let (blob, _) = storage.open("legacy", b"blob").await.unwrap();
        blob.write_at(0, b"value", WriteOptions::SYNC)
            .await
            .unwrap();
        drop((blob, storage));

        let path = storage_directory.join("legacy").join(hex(b"blob"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let restarted = Storage::new(config, test_pool());
        let result = restarted.remove("legacy", Some(b"blob")).await;
        if path.exists() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        result.unwrap();
        assert!(!path.exists());

        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_batch_remove_recovers_embedded_witnesses() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_batch_remove_partition_{}",
            random_suffix()
        ));
        let config = Config::new(storage_directory.clone(), 2 * 1024 * 1024);
        let storage = Storage::new(config.clone(), test_pool());
        let (removed, _) = storage.open_atomic("removed", b"first").await.unwrap();
        let (kept, _) = storage.open_atomic("kept", b"second").await.unwrap();
        removed.append(b"old-one").await.unwrap();
        kept.append(b"old-two").await.unwrap();
        removed.sync().await.unwrap();
        kept.sync().await.unwrap();
        removed.append(b"new-one").await.unwrap();
        kept.append(b"new-two").await.unwrap();
        storage
            .apply(vec![
                BatchOperation::Publish(removed.clone()),
                BatchOperation::Publish(kept.clone()),
            ])
            .await
            .unwrap();
        drop(removed);
        drop(kept);
        drop(storage);

        let restarted = Storage::new(config, test_pool());
        let (removed, len) = restarted.open_atomic("removed", b"first").await.unwrap();
        assert_eq!(len, 14);
        restarted
            .apply(vec![BatchOperation::Remove(removed)])
            .await
            .unwrap();
        assert!(restarted.scan("removed").await.unwrap().is_empty());
        let (kept, len) = restarted.open_atomic("kept", b"second").await.unwrap();
        assert_eq!(len, 14);
        assert_eq!(
            kept.read_at(0, 14).await.unwrap().coalesce(),
            b"old-twonew-two"
        );

        let _ = std::fs::remove_dir_all(storage_directory);
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
        let fallback_directory = env::temp_dir().join(format!(
            "storage_tokio_atomic_batch_carry_fallback_{}",
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
                blob.append(vec![epoch, u8::try_from(index).unwrap()])
                    .await
                    .unwrap();
            }
            storage
                .apply(blobs.iter().cloned().map(BatchOperation::Publish).collect())
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
        copy_tree(&storage_directory, &fallback_directory);
        let participant = fallback_directory.join("group").join(hex(b"first"));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(participant)
            .unwrap();
        let embedded =
            super::super::atomic::embedded_batch_witnesses(&file, Layout::V2.data_offset())
                .unwrap();
        let latest = embedded
            .first()
            .expect("second batch has an embedded witness");
        let witness_offset = latest.root_offset + super::super::atomic::ROOT_LEN as u64;
        let mut byte = [0u8; 1];
        file.read_exact_at(&mut byte, witness_offset).unwrap();
        byte[0] ^= 1;
        file.write_all_at(&byte, witness_offset).unwrap();
        file.sync_all().unwrap();
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
            assert_eq!(len, 4);
            assert_eq!(
                blob.read_at(0, 4).await.unwrap().coalesce(),
                [
                    b'1',
                    u8::try_from(index).unwrap(),
                    b'2',
                    u8::try_from(index).unwrap()
                ]
            );
        }

        let recovered = Storage::new(
            Config::new(fallback_directory.clone(), 2 * 1024 * 1024),
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
                [b'1', u8::try_from(index).unwrap()]
            );
        }

        let _ = std::fs::remove_dir_all(storage_directory);
        let _ = std::fs::remove_dir_all(crash_directory);
        let _ = std::fs::remove_dir_all(fallback_directory);
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
        let (removed, _) = storage.open_atomic("group", b"blob").await.unwrap();
        storage
            .apply(vec![BatchOperation::Remove(removed)])
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
    async fn test_batches_do_not_depend_on_a_coordinator_file() {
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
        storage.apply(Vec::new()).await.unwrap();
        storage.open("partition", b"blob").await.unwrap();
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
