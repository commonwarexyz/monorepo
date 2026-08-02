use crate::{Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut, WriteOptions, storage::atomic};
use cfg_if::cfg_if;
use commonware_formatting::hex;
use commonware_utils::channel::oneshot;
use std::{
    fs::File,
    io::IoSlice,
    os::{fd::AsRawFd, unix::fs::FileExt},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    sync::{Mutex, OwnedMutexGuard},
    task,
};

// Linux rejects more than IOV_MAX (1024) iovecs with EINVAL. Use the maximum so storage writes
// span as few submissions as possible.
const IOVEC_BATCH_SIZE: usize = 1024;

/// Mutable log/index state shared by every handle opened for one current V2 name generation.
pub(super) type V2State = atomic::State;

/// Namespace and content state needed only by V2 blobs.
#[derive(Clone)]
pub(super) struct V2Context {
    state: Arc<Mutex<V2State>>,
    namespace: Arc<super::Namespace>,
    storage_directory: PathBuf,
}

impl V2Context {
    pub(super) const fn new(
        state: Arc<Mutex<V2State>>,
        namespace: Arc<super::Namespace>,
        storage_directory: PathBuf,
    ) -> Self {
        Self {
            state,
            namespace,
            storage_directory,
        }
    }

    async fn lock(&self) -> OwnedMutexGuard<V2State> {
        if let Ok(state) = self.state.clone().try_lock_owned() {
            return state;
        }
        self.state.clone().lock_owned().await
    }
}

/// Page-cache policy for one write request.
enum Cache {
    /// Use the operating system's normal page-cache behavior.
    Enabled,
    /// Best-effort bypass of the page cache while the backend supports it.
    Disabled(Arc<AtomicBool>),
}

impl Cache {
    /// Return whether the next Linux submission should request cache bypass.
    fn is_disabled(&self) -> bool {
        cfg!(target_os = "linux")
            && matches!(self, Self::Disabled(supported) if supported.load(Ordering::Relaxed))
    }

    /// Return whether an unsupported cache-bypass attempt should be retried with normal caching.
    fn retry_cached(&mut self, err: &std::io::Error, attempted_dont_cache: bool) -> bool {
        if err.raw_os_error() != Some(libc::EOPNOTSUPP) || !attempted_dont_cache {
            return false;
        }
        let Self::Disabled(supported) = std::mem::replace(self, Self::Enabled) else {
            return false;
        };
        supported.store(false, Ordering::Relaxed);
        true
    }
}

#[derive(Clone)]
pub struct Blob {
    partition: String,
    name: Vec<u8>,
    generation: Arc<super::Generation>,
    file: Arc<File>,
    pool: BufferPool,
    /// Physical offset where logical offset 0 begins (the size of the header region).
    data_offset: u64,
    /// Log-structured V2 state shared by independently opened handles of this name generation.
    atomic: Option<V2Context>,
    /// Whether the kernel and filesystem may support `RWF_DONTCACHE`.
    /// Cleared on the first EOPNOTSUPP to avoid probing on every hinted write.
    dont_cache_supported: Arc<AtomicBool>,
}

impl Blob {
    pub(super) fn new(
        partition: String,
        name: &[u8],
        file: File,
        pool: BufferPool,
        data_offset: u64,
        generation: Arc<super::Generation>,
        atomic: Option<V2Context>,
    ) -> Self {
        Self {
            partition,
            name: name.into(),
            generation,
            file: Arc::new(file),
            pool,
            data_offset,
            atomic,
            dont_cache_supported: Arc::new(AtomicBool::new(true)),
        }
    }

    pub(super) fn partition(&self) -> &str {
        &self.partition
    }

    pub(super) fn name(&self) -> &[u8] {
        &self.name
    }

    pub(super) const fn generation(&self) -> &Arc<super::Generation> {
        &self.generation
    }

    pub(super) const fn is_atomic(&self) -> bool {
        self.atomic.is_some()
    }

    fn sync_inner(file: &File, partition: &str, name: &[u8]) -> Result<(), Error> {
        // Data durability is the contract. `sync_data` covers the bytes and metadata required to
        // retrieve them, including file size, while avoiding timestamp-only journal commits.
        // Other platforms retain `sync_all` for their platform-specific guarantees.
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                let result = file.sync_data();
            } else {
                let result = file.sync_all();
            }
        }
        result.map_err(|e| Error::BlobSyncFailed(partition.to_string(), hex(name), e.into()))
    }

    fn write_single_at(file: &File, offset: u64, buf: &[u8]) -> Result<(), Error> {
        file.write_all_at(buf, offset)?;
        Ok(())
    }

    /// Write `bufs` at `offset`, batching up to [IOVEC_BATCH_SIZE] iovecs per submission.
    ///
    /// `flags` apply to every submission, so callers must only pass durability flags when the
    /// write fits one submission. Hinted submissions carry `RWF_DONTCACHE` on Linux while the
    /// backend may support it. An EOPNOTSUPP disables the hint and retries normally.
    fn write_vectored_at(
        mut cache: Cache,
        file: &File,
        mut offset: u64,
        mut bufs: IoBufs,
        flags: Option<libc::c_int>,
    ) -> Result<(), Error> {
        assert!(
            flags.is_none() || bufs.chunk_count() <= IOVEC_BATCH_SIZE,
            "durability flags on a multi-submission write serialize its batches"
        );

        while bufs.has_remaining() {
            // Scratch sized to the write, so small vectored writes never initialize a full
            // IOVEC_BATCH_SIZE array.
            let mut io_slices = vec![IoSlice::new(&[]); bufs.chunk_count().min(IOVEC_BATCH_SIZE)];
            let io_slices_len = bufs.chunks_vectored(&mut io_slices);
            assert!(
                io_slices_len > 0,
                "chunks_vectored should produce at least one slice when bufs has remaining"
            );

            cfg_if! {
                if #[cfg(target_os = "linux")] {
                    let attempted_dont_cache = cache.is_disabled();
                    // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                    // `io_slices` points to valid readable buffers held alive for this syscall.
                    let ret = unsafe {
                        libc::pwritev2(
                            file.as_raw_fd(),
                            io_slices.as_ptr().cast::<libc::iovec>(),
                            io_slices_len as i32,
                            offset.try_into().map_err(|_| Error::OffsetOverflow)?,
                            flags.unwrap_or(0)
                                | if attempted_dont_cache { libc::RWF_DONTCACHE } else { 0 },
                        )
                    };
                } else {
                    let attempted_dont_cache = false;
                    assert!(flags.is_none(), "flags are only supported on Linux");

                    // SAFETY: `IoSlice` is ABI-compatible with `libc::iovec` on Unix.
                    // `io_slices` points to valid readable buffers held alive for this syscall.
                    let ret = unsafe {
                        libc::pwritev(
                            file.as_raw_fd(),
                            io_slices.as_ptr().cast::<libc::iovec>(),
                            io_slices_len as i32,
                            offset.try_into().map_err(|_| Error::OffsetOverflow)?,
                        )
                    };
                }
            }

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if cache.retry_cached(&err, attempted_dont_cache) {
                    continue;
                }
                return Err(err.into());
            }

            let bytes_written = ret as usize;
            if bytes_written == 0 {
                return Err(Error::WriteFailed);
            }
            bufs.advance(bytes_written);
            offset = offset
                .checked_add(bytes_written as u64)
                .ok_or(Error::OffsetOverflow)?;
        }

        Ok(())
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

    fn poisoned(partition: &str, name: &[u8]) -> Error {
        Error::BlobCorrupt(
            partition.into(),
            hex(name),
            "atomic blob generation is poisoned".into(),
        )
    }

    fn ensure_healthy(&self, state: &V2State) -> Result<(), Error> {
        if state.is_poisoned() {
            return Err(Self::poisoned(&self.partition, &self.name));
        }
        Ok(())
    }

    async fn rewind_atomic(&self, len: u64) -> Result<(), Error> {
        let Some(atomic) = &self.atomic else {
            return Err(Self::atomic_layout_required(&self.partition, &self.name));
        };
        let mut state = atomic.lock().await;
        self.ensure_healthy(&state)?;
        let truncate = len < state.logical_len() && len >= state.committed_len();
        state.rewind(len)?;
        if !truncate {
            return Ok(());
        }

        let raw_len = state.raw_len()?;
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        let generation = self.generation.clone();
        task::spawn_blocking(move || {
            let _generation = generation;
            let result = file
                .set_len(raw_len)
                .map_err(|error| Error::BlobResizeFailed(partition, hex(&name), error.into()));
            if result.is_err() {
                state.poison();
            }
            result
        })
        .await
        .map_err(|error| {
            let error: std::io::Error = error.into();
            Error::BlobResizeFailed(self.partition.clone(), hex(&self.name), error.into())
        })?
    }

    fn prepare_log_writes(
        state: &mut V2State,
        file: &File,
        materialize_previous: bool,
        batch_prepared: bool,
    ) -> Result<Option<atomic::PreparedCommit>, Error> {
        if !state.is_dirty() {
            return Ok(None);
        }
        let materialized_previous = state.deferred_batch_root().cloned();
        let (payload_start, payload_len) = state.pending_payload()?;
        atomic::begin_payload_writeback(file, payload_start, payload_len)?;
        let mut prepared = state
            .prepare_commit()?
            .expect("dirty atomic state always prepares a commit");
        if batch_prepared {
            prepared.mark_batch_prepared();
        }
        if materialize_previous && let Some(candidate) = &materialized_previous {
            let root = atomic::materialized_candidate_root(candidate)?;
            file.write_all_at(&root, candidate.root_offset)?;
        }
        if !batch_prepared {
            file.write_all_at(&prepared.prepared_root, prepared.root_offset)?;
        }
        Ok(Some(prepared))
    }

    fn prepare_log(
        state: &mut V2State,
        file: &File,
        partition: &str,
        name: &[u8],
    ) -> Result<Option<atomic::PreparedCommit>, Error> {
        let prepared = Self::prepare_log_writes(state, file, true, false)?;
        if prepared.is_some() {
            // A committed root is written only after every payload byte is durable.
            // Recovery can therefore accept it without rereading payload data.
            Self::sync_inner(file, partition, name)?;
        }
        Ok(prepared)
    }

    fn commit_log(
        state: &mut V2State,
        file: &File,
        partition: &str,
        name: &[u8],
    ) -> Result<(), Error> {
        let Some(prepared) = Self::prepare_log(state, file, partition, name)? else {
            return Ok(());
        };
        atomic::write_durable_at(file, prepared.root_offset, &prepared.committed_root)
            .map_err(Error::from)?;
        if prepared.requires_truncate() {
            file.set_len(prepared.raw_len()).map_err(|error| {
                Error::BlobResizeFailed(partition.to_string(), hex(name), error.into())
            })?;
        }
        state.finish_commit(prepared);
        Ok(())
    }

    pub(super) async fn lock_batch_state(&self) -> Result<OwnedMutexGuard<V2State>, Error> {
        let atomic = self
            .atomic
            .as_ref()
            .ok_or_else(|| Self::atomic_layout_required(&self.partition, &self.name))?;
        let state = atomic.lock().await;
        self.ensure_healthy(&state)?;
        Ok(state)
    }

    pub(super) fn prepare_batch_commit_unflushed(
        &self,
        state: &mut V2State,
    ) -> Result<Option<atomic::PreparedCommit>, Error> {
        Self::prepare_log_writes(state, &self.file, false, true)
    }

    pub(super) fn stage_batch_commit(
        &self,
        prepared: &mut atomic::PreparedCommit,
        witness: Option<&[u8]>,
    ) -> Result<(), Error> {
        if let Some(witness) = witness {
            prepared.attach_batch_witness(witness)?;
        }
        self.file
            .write_all_at(&prepared.prepared_root, prepared.root_offset)
            .map_err(Error::from)
    }

    pub(super) fn sync_batch_commit(&self) -> Result<(), Error> {
        Self::sync_inner(&self.file, &self.partition, &self.name)
    }

    pub(super) fn activate_batch_commit(
        &self,
        state: &mut V2State,
        prepared: Option<atomic::PreparedCommit>,
        defer_root: bool,
        force_truncate: bool,
    ) -> Result<Option<atomic::Candidate>, Error> {
        let Some(prepared) = prepared else {
            if force_truncate {
                self.truncate_batch_rewind(state)?;
            }
            return Ok(None);
        };
        if force_truncate || prepared.requires_truncate() {
            self.truncate_batch_rewind(state)?;
        }
        Ok(Some(if defer_root {
            state.finish_batch_commit(prepared)
        } else {
            let candidate = prepared.candidate();
            state.finish_commit(prepared);
            candidate
        }))
    }

    /// Reclaim a batch-rewound suffix after the group decision is durable.
    pub(super) fn truncate_batch_rewind(&self, state: &mut V2State) -> Result<(), Error> {
        let raw_len = state.raw_len()?;
        if let Err(error) = self.file.set_len(raw_len) {
            state.poison();
            return Err(Error::BlobResizeFailed(
                self.partition.clone(),
                hex(&self.name),
                error.into(),
            ));
        }
        Ok(())
    }

    pub(super) const fn poison_batch_state(state: &mut V2State) {
        state.poison();
    }

    async fn lock_publication(
        &self,
    ) -> Result<(OwnedMutexGuard<V2State>, OwnedMutexGuard<()>), Error> {
        let atomic = self
            .atomic
            .as_ref()
            .expect("publication is only used for V2 blobs");
        let state = atomic.lock().await;
        self.ensure_healthy(&state)?;
        let namespace_guard = atomic.namespace.lock.clone().lock_owned().await;
        let namespace_guard = super::recover_namespace(
            atomic.namespace.clone(),
            atomic.storage_directory.clone(),
            namespace_guard,
        )
        .await?;
        if !atomic
            .namespace
            .is_current(&self.partition, &self.name, &self.generation)
        {
            return Err(Error::BlobMissing(self.partition.clone(), hex(&self.name)));
        }
        Ok((state, namespace_guard))
    }

    fn start_atomic_sync_locked(
        &self,
        mut state: OwnedMutexGuard<V2State>,
        namespace_guard: OwnedMutexGuard<()>,
    ) -> Handle<()> {
        let (tx, rx) = oneshot::channel();
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        let generation = self.generation.clone();
        task::spawn_blocking(move || {
            let _generation = generation;
            let _namespace_guard = namespace_guard;
            let result = Self::commit_log(&mut state, &file, &partition, &name);
            if result.is_err() {
                state.poison();
            }
            let _ = tx.send(result);
        });
        Handle::from_receiver(rx)
    }

    fn write_with_options(
        file: &File,
        offset: u64,
        bufs: IoBufs,
        options: WriteOptions,
        dont_cache_supported: Arc<AtomicBool>,
        partition: &str,
        name: &[u8],
    ) -> Result<(), Error> {
        let sync = options.contains(WriteOptions::SYNC);
        let cache = if options.contains(WriteOptions::DONT_CACHE) {
            Cache::Disabled(dont_cache_supported)
        } else {
            Cache::Enabled
        };

        let bufs = if !sync && !cache.is_disabled() {
            match bufs.try_into_single() {
                Ok(buf) => return Self::write_single_at(file, offset, buf.as_ref()),
                Err(bufs) => bufs,
            }
        } else {
            bufs
        };

        cfg_if! {
            if #[cfg(target_os = "linux")] {
                let fused = sync && bufs.chunk_count() <= IOVEC_BATCH_SIZE;
                Self::write_vectored_at(
                    cache,
                    file,
                    offset,
                    bufs,
                    fused.then_some(libc::RWF_DSYNC),
                )?;
                if sync && !fused {
                    file.sync_data().map_err(|error| {
                        Error::BlobSyncFailed(partition.into(), hex(name), error.into())
                    })?;
                }
            } else {
                Self::write_vectored_at(cache, file, offset, bufs, None)?;
                if sync {
                    Self::sync_inner(file, partition, name)?;
                }
            }
        }
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
        // SAFETY: `len` bytes are filled via read_exact below.
        unsafe { bufs.set_len(len) };
        if let Some(atomic) = &self.atomic {
            let state = atomic.lock().await;
            self.ensure_healthy(&state)?;
            let len_u64 = u64::try_from(len).map_err(|_| Error::OffsetOverflow)?;
            let end = offset.checked_add(len_u64).ok_or(Error::OffsetOverflow)?;
            if end > state.logical_len() {
                return Err(Error::BlobInsufficientLength);
            }
            let plan = state.read_plan(offset, len)?;
            let file = self.file.clone();
            let pool = self.pool.clone();
            let generation = self.generation.clone();
            return task::spawn_blocking(move || {
                let _state = state;
                let _generation = generation;
                if let Some(buf) = bufs.as_single_mut() {
                    for span in &plan {
                        let destination =
                            &mut buf.as_mut()[span.destination..span.destination + span.len];
                        let atomic::ReadSource::File(offset) = span.source;
                        file.read_exact_at(destination, offset)
                            .map_err(|_| Error::ReadFailed)?;
                    }
                } else {
                    // SAFETY: every byte is filled from the planned file span.
                    let mut temp = unsafe { pool.alloc_len(len) };
                    for span in &plan {
                        let destination =
                            &mut temp.as_mut()[span.destination..span.destination + span.len];
                        let atomic::ReadSource::File(offset) = span.source;
                        file.read_exact_at(destination, offset)
                            .map_err(|_| Error::ReadFailed)?;
                    }
                    bufs.copy_from_slice(temp.as_ref());
                }
                Ok(bufs)
            })
            .await
            .map_err(|_| Error::ReadFailed)?;
        }
        let file = self.file.clone();
        let pool = self.pool.clone();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        task::spawn_blocking(move || {
            if let Some(buf) = bufs.as_single_mut() {
                // Read directly into the single buffer (zero-copy).
                file.read_exact_at(buf.as_mut(), offset)?;
            } else {
                // Read into a temporary contiguous buffer and copy back to preserve structure.
                // SAFETY: `len` bytes are filled via read_exact_at below.
                let mut temp = unsafe { pool.alloc_len(len) };
                file.read_exact_at(temp.as_mut(), offset)?;
                bufs.copy_from_slice(temp.as_ref());
            }
            Ok(bufs)
        })
        .await
        .map_err(|_| Error::ReadFailed)?
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        if !bufs.has_remaining() {
            return Ok(());
        }
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        let dont_cache_supported = self.dont_cache_supported.clone();
        if let Some(atomic) = &self.atomic {
            let mut state = atomic.lock().await;
            self.ensure_healthy(&state)?;
            let sync = options.contains(WriteOptions::SYNC);
            let namespace_guard = if sync {
                let guard = atomic.namespace.lock.clone().lock_owned().await;
                let guard = super::recover_namespace(
                    atomic.namespace.clone(),
                    atomic.storage_directory.clone(),
                    guard,
                )
                .await?;
                if !atomic
                    .namespace
                    .is_current(&self.partition, &self.name, &self.generation)
                {
                    return Err(Error::BlobMissing(self.partition.clone(), hex(&self.name)));
                }
                Some(guard)
            } else {
                None
            };
            let generation = self.generation.clone();
            return task::spawn_blocking(move || {
                let _generation = generation;
                let _namespace_guard = namespace_guard;
                if offset != state.logical_len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "atomic writes must append at the current logical tail",
                    )
                    .into());
                }
                let prepared = state
                    .prepare_append(bufs)?
                    .expect("nonempty writes always prepare payload storage");
                let result = (|| {
                    Self::write_with_options(
                        &file,
                        prepared.file_offset,
                        prepared.data,
                        options.without(WriteOptions::SYNC),
                        dont_cache_supported,
                        &partition,
                        &name,
                    )?;
                    state.finish_mutation(prepared.mutation);
                    if sync {
                        Self::commit_log(&mut state, &file, &partition, &name)?;
                    }
                    Ok(())
                })();
                if result.is_err() {
                    state.poison();
                }
                result
            })
            .await
            .unwrap_or(Err(Error::WriteFailed));
        }

        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        task::spawn_blocking(move || {
            Self::write_with_options(
                &file,
                offset,
                bufs,
                options,
                dont_cache_supported,
                &partition,
                &name,
            )
        })
        .await
        .unwrap_or(Err(Error::WriteFailed))
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        if self.atomic.is_some() {
            return self.rewind_atomic(len).await;
        }
        let file = self.file.clone();
        let len = len
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        task::spawn_blocking(move || file.set_len(len))
            .await
            .map_err(|e| e.into())
            .and_then(|r| r)
            .map_err(|e| {
                Error::BlobResizeFailed(self.partition.clone(), hex(&self.name), e.into())
            })?;
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        if self.atomic.is_some() {
            let (state, namespace_guard) = self.lock_publication().await?;
            return self.start_atomic_sync_locked(state, namespace_guard).await;
        }
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        task::spawn_blocking(move || Self::sync_inner(&file, &partition, &name))
            .await
            .map_err(|e| {
                let err: std::io::Error = e.into();
                Error::BlobSyncFailed(self.partition.clone(), hex(&self.name), err.into())
            })?
    }

    async fn start_sync(&self) -> Handle<()> {
        if self.atomic.is_some() {
            return match self.lock_publication().await {
                Ok((state, namespace_guard)) => {
                    self.start_atomic_sync_locked(state, namespace_guard)
                }
                Err(error) => Handle::ready(Err(error)),
            };
        }
        let (tx, rx) = oneshot::channel();
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        task::spawn_blocking(move || {
            let result = Self::sync_inner(&file, &partition, &name);
            let _ = tx.send(result);
        });
        Handle::from_receiver(rx)
    }
}

impl crate::AtomicBlob for Blob {
    async fn append(&self, data: impl Into<IoBufs> + Send) -> Result<u64, Error> {
        let Some(atomic) = &self.atomic else {
            return Err(Self::atomic_layout_required(&self.partition, &self.name));
        };
        let data = data.into();
        let mut state = atomic.lock().await;
        self.ensure_healthy(&state)?;
        let offset = state.logical_len();
        let Some(prepared) = state.prepare_append(data)? else {
            return Ok(offset);
        };
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        let dont_cache_supported = self.dont_cache_supported.clone();
        let generation = self.generation.clone();
        task::spawn_blocking(move || {
            let _generation = generation;
            let result = (|| {
                Self::write_with_options(
                    &file,
                    prepared.file_offset,
                    prepared.data,
                    WriteOptions::default(),
                    dont_cache_supported,
                    &partition,
                    &name,
                )?;
                state.finish_mutation(prepared.mutation);
                Ok(offset)
            })();
            if result.is_err() {
                state.poison();
            }
            result
        })
        .await
        .unwrap_or(Err(Error::WriteFailed))
    }

    async fn rewind(&self, len: u64) -> Result<(), Error> {
        self.rewind_atomic(len).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_cache_bypass_is_ignored_off_linux() {
        let cache = Cache::Disabled(Arc::new(AtomicBool::new(true)));
        assert!(!cache.is_disabled());
    }

    #[test]
    fn test_cache_bypass_retry_decision() {
        let supported = Arc::new(AtomicBool::new(true));
        let mut cache = Cache::Disabled(supported.clone());
        let sibling = Cache::Disabled(supported.clone());
        let unsupported = std::io::Error::from_raw_os_error(libc::EOPNOTSUPP);
        let invalid = std::io::Error::from_raw_os_error(libc::EINVAL);

        assert!(!cache.retry_cached(&invalid, true));
        assert!(supported.load(Ordering::Relaxed));
        assert!(!cache.retry_cached(&unsupported, false));
        assert!(supported.load(Ordering::Relaxed));
        assert!(cache.retry_cached(&unsupported, true));
        assert!(!supported.load(Ordering::Relaxed));
        assert!(!sibling.is_disabled());
        assert!(!cache.retry_cached(&unsupported, true));
    }
}
