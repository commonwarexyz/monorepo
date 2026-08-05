use crate::{
    Blob as _, Buf, BufferPool, Error, Handle, IoBufs, IoBufsMut, WriteOptions,
    storage::{atomic, uno},
};
commonware_macros::stability_scope!(ALPHA {
    use crate::atomic_api::{
        IntegrityAppend, IntegrityBoundary, IntegrityScheme, IntegritySnapshot, IntegrityToken,
        IntegrityUnit,
    };
});
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
use tokio::{sync::OwnedMutexGuard, task};

// Linux rejects more than IOV_MAX (1024) iovecs with EINVAL. Use the maximum so storage writes
// span as few submissions as possible.
const IOVEC_BATCH_SIZE: usize = 1024;

/// Mutable log/index state shared by every handle opened for one current V2 name generation.
#[cfg_attr(commonware_stability_BETA, allow(dead_code))]
pub(super) type V2State = atomic::State;

/// Namespace and content state needed only by V2 blobs.
#[derive(Clone)]
pub(super) struct V2Context {
    state: Arc<super::super::preflush::Context>,
    namespace: Arc<super::Namespace>,
    storage_directory: PathBuf,
    incarnation: [u8; super::super::header::Header::V2_INCARNATION_LEN],
}

impl V2Context {
    pub(super) const fn new(
        state: Arc<super::super::preflush::Context>,
        namespace: Arc<super::Namespace>,
        storage_directory: PathBuf,
        incarnation: [u8; super::super::header::Header::V2_INCARNATION_LEN],
    ) -> Self {
        Self {
            state,
            namespace,
            storage_directory,
            incarnation,
        }
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

/// Direct ordinary-blob view used beneath UNO.
///
/// Keeping this as a distinct type prevents the legacy ordinary-open adapter from creating a
/// recursive future type: public [`Blob`] methods may route V2 handles through UNO, while this
/// backing view always executes ordinary V1 byte operations directly.
#[derive(Clone)]
pub(super) struct BackingBlob {
    blob: Blob,
    retained: Arc<BackingRetention>,
}

/// Keeps canceled, admitted blocking I/O attached to its original logical generation.
struct BackingRetention {
    _generation: Arc<super::Generation>,
    _state: Option<Arc<super::super::preflush::Context>>,
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

    #[commonware_macros::stability(ALPHA)]
    pub(super) fn partition(&self) -> &str {
        &self.partition
    }

    #[commonware_macros::stability(ALPHA)]
    pub(super) fn name(&self) -> &[u8] {
        &self.name
    }

    #[commonware_macros::stability(ALPHA)]
    pub(super) const fn generation(&self) -> &Arc<super::Generation> {
        &self.generation
    }

    #[commonware_macros::stability(ALPHA)]
    pub(super) fn file(&self) -> Arc<File> {
        self.file.clone()
    }

    #[commonware_macros::stability(ALPHA)]
    pub(super) const fn data_offset(&self) -> u64 {
        self.data_offset
    }

    #[commonware_macros::stability(ALPHA)]
    pub(super) const fn is_atomic(&self) -> bool {
        self.atomic.is_some()
    }

    /// Return an ordinary V1-geometry view whose logical offset zero begins after the immutable
    /// typed-envelope header. UNO keeps the root page private above this view.
    pub(super) fn atomic_backing(&self) -> BackingBlob {
        let retained = Arc::new(BackingRetention {
            _generation: self.generation.clone(),
            _state: self.atomic.as_ref().map(|atomic| atomic.state.clone()),
        });
        let mut backing = self.clone();
        backing.data_offset = super::super::Layout::V1.data_offset();
        backing.atomic = None;
        BackingBlob {
            blob: backing,
            retained,
        }
    }

    #[commonware_macros::stability(ALPHA)]
    pub(super) const fn incarnation(
        &self,
    ) -> [u8; super::super::header::Header::V2_INCARNATION_LEN] {
        self.atomic
            .as_ref()
            .expect("atomic blobs have a persistent incarnation")
            .incarnation
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

    #[cfg(test)]
    pub(super) async fn wait_for_background_preflush(&self) -> Result<u64, Error> {
        let atomic = self
            .atomic
            .as_ref()
            .expect("payload preflush is only used for V2 blobs");
        let target = {
            let state = atomic.state.lock().await;
            state.preflush_target()
        };
        if atomic.state.preflush().requested() < target {
            return Err(Error::WriteFailed);
        }
        let preflush = atomic.state.preflush().clone();
        task::spawn_blocking(move || preflush.wait_blocking(target))
            .await
            .map_err(|_| Error::Closed)??;
        Ok(target)
    }

    #[cfg(test)]
    pub(super) fn background_preflush_requested(&self) -> u64 {
        self.atomic
            .as_ref()
            .expect("payload preflush is only used for V2 blobs")
            .state
            .preflush()
            .requested()
    }

    #[cfg(test)]
    pub(super) fn fail_background_preflush_for_test(&self, target: u64) {
        let preflush = self
            .atomic
            .as_ref()
            .expect("payload preflush is only used for V2 blobs");
        let preflush = preflush.state.preflush();
        assert_eq!(preflush.request(target).unwrap(), Some(target));
        assert_eq!(preflush.complete(target, Err(Error::WriteFailed)), None);
    }

    async fn lock_publication_namespace(&self) -> Result<OwnedMutexGuard<()>, Error> {
        let atomic = self
            .atomic
            .as_ref()
            .expect("publication is only used for V2 blobs");
        let namespace_guard = atomic.namespace.lock.clone().lock_owned().await;
        let namespace_guard = if atomic
            .namespace
            .carried_batch_decision
            .load(Ordering::Acquire)
        {
            if atomic.namespace.embedded_batch_decision().is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "carried batch decision has no embedded witness",
                )
                .into());
            }
            namespace_guard
        } else {
            super::recover_namespace(
                atomic.namespace.clone(),
                atomic.storage_directory.clone(),
                namespace_guard,
            )
            .await?
        };
        if !atomic
            .namespace
            .is_current(&self.partition, &self.name, &self.generation)
        {
            return Err(Error::BlobMissing(self.partition.clone(), hex(&self.name)));
        }
        Ok(namespace_guard)
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

    async fn read_at_buf_v1(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let mut bufs = bufs.into();
        // SAFETY: `len` bytes are filled via read_exact below.
        unsafe { bufs.set_len(len) };
        let file = self.file.clone();
        let pool = self.pool.clone();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        task::spawn_blocking(move || {
            if let Some(buf) = bufs.as_single_mut() {
                file.read_exact_at(buf.as_mut(), offset)?;
            } else {
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

    async fn write_at_v1(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        self.write_at_v1_retained(offset, bufs, options, None).await
    }

    async fn write_at_v1_retained(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
        retained: Option<Arc<BackingRetention>>,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        if !bufs.has_remaining() {
            return Ok(());
        }
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        let dont_cache_supported = self.dont_cache_supported.clone();
        let offset = offset
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        task::spawn_blocking(move || {
            let _retained = retained;
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

    async fn resize_v1(&self, len: u64) -> Result<(), Error> {
        self.resize_v1_retained(len, None).await
    }

    async fn resize_v1_retained(
        &self,
        len: u64,
        retained: Option<Arc<BackingRetention>>,
    ) -> Result<(), Error> {
        let file = self.file.clone();
        let len = len
            .checked_add(self.data_offset)
            .ok_or(Error::OffsetOverflow)?;
        task::spawn_blocking(move || {
            let _retained = retained;
            file.set_len(len)
        })
            .await
            .map_err(|e| e.into())
            .and_then(|r| r)
            .map_err(|e| {
                Error::BlobResizeFailed(self.partition.clone(), hex(&self.name), e.into())
            })?;
        Ok(())
    }

    async fn sync_v1(&self) -> Result<(), Error> {
        self.sync_v1_retained(None).await
    }

    async fn sync_v1_retained(
        &self,
        retained: Option<Arc<BackingRetention>>,
    ) -> Result<(), Error> {
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        task::spawn_blocking(move || {
            let _retained = retained;
            Self::sync_inner(&file, &partition, &name)
        })
            .await
            .map_err(|e| {
                let err: std::io::Error = e.into();
                Error::BlobSyncFailed(self.partition.clone(), hex(&self.name), err.into())
            })?
    }

    fn start_sync_v1(&self) -> Handle<()> {
        self.start_sync_v1_retained(None)
    }

    fn start_sync_v1_retained(
        &self,
        retained: Option<Arc<BackingRetention>>,
    ) -> Handle<()> {
        let (tx, rx) = oneshot::channel();
        let file = self.file.clone();
        let partition = self.partition.clone();
        let name = self.name.clone();
        task::spawn_blocking(move || {
            let _retained = retained;
            let result = Self::sync_inner(&file, &partition, &name);
            let _ = tx.send(result);
        });
        Handle::from_receiver(rx)
    }
}

#[derive(Clone)]
struct V2Publisher {
    blob: Blob,
}

impl uno::Publisher<BackingBlob> for V2Publisher {
    fn spawn(&self, task: uno::Task) -> Result<(), Error> {
        drop(task::spawn(task));
        Ok(())
    }

    async fn publish(
        &self,
        core: Arc<uno::Core<BackingBlob>>,
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
            atomic::PayloadChecksumEligibility::Ineligible
        ) {
            core.backing().sync().await?;
            prepared.mark_payload_preflushed();
        }
        prepared.mark_batch_prepared();
        let atomic = self
            .blob
            .atomic
            .as_ref()
            .expect("atomic commits require recovered namespace state");
        let (participant, batch) = super::super::batch::prepare_single_publish(
            &self.blob.partition,
            &self.blob.name,
            atomic.incarnation,
            &prepared,
        )?;

        let previous = atomic.namespace.embedded_batch_decision();
        if let Some(previous) = &previous {
            let supersedes = super::super::batch::can_supersede_embedded(
                previous,
                std::slice::from_ref(&participant),
            )?;
            if !supersedes {
                let directory = atomic.storage_directory.clone();
                let previous = previous.clone();
                task::spawn_blocking(move || {
                    super::super::batch::materialize_embedded(&directory, &previous)
                })
                .await
                .map_err(|_| Error::Closed)??;
                atomic.namespace.set_embedded_batch_decision(None);
                atomic
                    .namespace
                    .carried_batch_decision
                    .store(false, Ordering::Release);
            }
        }
        if previous.is_none()
            && let Some(candidate) = previous_candidate
        {
            let root = atomic::materialized_candidate_root(&candidate)?;
            core.backing()
                .write_at(
                    uno::Core::<BackingBlob>::backing_offset(candidate.root_offset)?,
                    root.to_vec(),
                    WriteOptions::default(),
                )
                .await?;
        }
        let witness = batch
            .witness(&self.blob.partition, &self.blob.name)
            .expect("single-participant batches retain their local witness");
        prepared.attach_batch_witness(witness)?;
        core.backing()
            .write_at(
                uno::Core::<BackingBlob>::backing_offset(prepared.root_offset)?,
                prepared.prepared_root.clone(),
                WriteOptions::default(),
            )
            .await?;
        core.backing().sync().await?;

        let raw_len = prepared.raw_len();
        let requires_truncate = prepared.requires_truncate();
        atomic
            .namespace
            .set_embedded_batch_decision(Some(Arc::new(batch)));
        atomic
            .namespace
            .recovery_required
            .store(true, Ordering::Release);
        atomic
            .namespace
            .carried_batch_decision
            .store(true, Ordering::Release);
        if requires_truncate {
            core.backing()
                .resize(uno::Core::<BackingBlob>::backing_len(raw_len)?)
                .await?;
        }
        core.state().preflush().record_durable(raw_len);
        state.finish_batch_commit(prepared);
        state.finish();
        drop(namespace_guard);
        Ok(())
    }
}

/// Atomic UNO view over an ordinary V1-geometry filesystem blob.
#[derive(Clone)]
pub struct AtomicBlob {
    inner: uno::AtomicBlob<BackingBlob, V2Publisher>,
}

#[cfg_attr(commonware_stability_BETA, allow(dead_code))]
impl AtomicBlob {
    pub(super) fn from_legacy(blob: Blob) -> Self {
        let state = blob
            .atomic
            .as_ref()
            .expect("atomic wrappers require recovered V2 state")
            .state
            .clone();
        let core = uno::Core::new(blob.atomic_backing(), state);
        Self {
            inner: uno::AtomicBlob::new(core, V2Publisher { blob }),
        }
    }

    pub(super) async fn lock_batch_state(
        &self,
    ) -> Result<tokio::sync::OwnedMutexGuard<V2State>, Error> {
        self.inner.lock_state().await
    }

    pub(super) async fn rewind_log(
        &self,
        state: &mut V2State,
        len: u64,
        unit: Option<crate::atomic_api::IntegrityUnit>,
    ) -> Result<(), Error> {
        self.inner.core().rewind_state(state, len, unit).await
    }

    pub(super) fn prepare_batch_commit_unflushed(
        &self,
        state: &mut V2State,
    ) -> Result<Option<atomic::PreparedCommit>, Error> {
        self.inner.core().prepare_batch_commit(state)
    }

    #[commonware_macros::stability(ALPHA)]
    pub(super) fn prepare_batch_delete_unflushed(
        &self,
        state: &V2State,
    ) -> Result<atomic::PreparedCommit, Error> {
        self.inner.core().prepare_batch_delete(state)
    }

    pub(super) async fn ensure_preflush(&self, target: u64) -> Result<(), Error> {
        self.inner.core().ensure_preflush(target).await
    }

    pub(super) async fn stage_batch_commit(
        &self,
        prepared: &mut atomic::PreparedCommit,
        witness: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.inner
            .core()
            .stage_batch_commit(prepared, witness)
            .await
    }

    pub(super) async fn stage_batch_delete(
        &self,
        prepared: &mut atomic::PreparedCommit,
        witness: &[u8],
    ) -> Result<(), Error> {
        self.inner
            .core()
            .stage_batch_delete(prepared, witness)
            .await
    }

    pub(super) async fn sync_batch_commit(&self) -> Result<(), Error> {
        self.inner.core().sync_batch_commit().await
    }

    pub(super) async fn activate_batch_commit(
        &self,
        state: &mut V2State,
        prepared: Option<atomic::PreparedCommit>,
        defer_root: bool,
        force_truncate: bool,
    ) -> Result<Option<atomic::Candidate>, Error> {
        self.inner
            .core()
            .activate_batch_commit(state, prepared, defer_root, force_truncate)
            .await
    }

    #[cfg(test)]
    pub(super) fn lifecycle_weak_for_test(
        &self,
    ) -> (
        std::sync::Weak<super::Generation>,
        std::sync::Weak<super::super::preflush::Context>,
    ) {
        let blob = &self.inner.publisher().blob;
        (
            Arc::downgrade(&blob.generation),
            Arc::downgrade(
                &blob
                    .atomic
                    .as_ref()
                    .expect("atomic handles retain recovered state")
                    .state,
            ),
        )
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

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        crate::Blob::write_at(&self.inner, offset, bufs, options).await
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
    async fn tag(&self) -> Result<[u8; super::super::ATOMIC_BLOB_TAG_LEN], Error> {
        crate::AtomicBlob::tag(&self.inner).await
    }

    async fn set_tag(&self, tag: [u8; super::super::ATOMIC_BLOB_TAG_LEN]) -> Result<(), Error> {
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
        tag: [u8; super::super::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<IntegrityToken, Error> {
        crate::AtomicBlob::compare_set_tag(&self.inner, expected, tag).await
    }

    async fn append(&self, data: impl Into<IoBufs> + Send) -> Result<u64, Error> {
        crate::AtomicBlob::append(&self.inner, data).await
    }

    async fn append_tagged(
        &self,
        data: impl Into<IoBufs> + Send,
        tag: [u8; super::super::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<u64, Error> {
        crate::AtomicBlob::append_tagged(&self.inner, data, tag).await
    }

    async fn append_integrity(
        &self,
        expected: IntegrityToken,
        data: impl Into<IoBufs> + Send,
        boundary: IntegrityBoundary,
        tag: Option<[u8; super::super::ATOMIC_BLOB_TAG_LEN]>,
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
        tag: [u8; super::super::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<(), Error> {
        crate::AtomicBlob::rewind_tagged(&self.inner, len, tag).await
    }

    async fn rewind_integrity(
        &self,
        expected: IntegrityToken,
        len: u64,
        unit: Option<IntegrityUnit>,
        tag: Option<[u8; super::super::ATOMIC_BLOB_TAG_LEN]>,
    ) -> Result<IntegrityToken, Error> {
        crate::AtomicBlob::rewind_integrity(&self.inner, expected, len, unit, tag).await
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
        if self.atomic.is_some() {
            let atomic = AtomicBlob::from_legacy(self.clone());
            return crate::Blob::read_at_buf(&atomic, offset, len, bufs).await;
        }
        self.read_at_buf_v1(offset, len, bufs).await
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        if self.atomic.is_some() {
            let atomic = AtomicBlob::from_legacy(self.clone());
            return crate::Blob::write_at(&atomic, offset, bufs, options).await;
        }
        self.write_at_v1(offset, bufs, options).await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        if self.atomic.is_some() {
            let atomic = AtomicBlob::from_legacy(self.clone());
            return crate::Blob::resize(&atomic, len).await;
        }
        self.resize_v1(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        if self.atomic.is_some() {
            let atomic = AtomicBlob::from_legacy(self.clone());
            return crate::Blob::sync(&atomic).await;
        }
        self.sync_v1().await
    }

    async fn start_sync(&self) -> Handle<()> {
        if self.atomic.is_some() {
            let atomic = AtomicBlob::from_legacy(self.clone());
            return crate::Blob::start_sync(&atomic).await;
        }
        self.start_sync_v1()
    }
}

impl crate::Blob for BackingBlob {
    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        self.blob.read_at_buf_v1(offset, len, bufs).await
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.blob
            .read_at_buf_v1(offset, len, self.blob.pool.alloc(len))
            .await
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        self.blob
            .write_at_v1_retained(offset, bufs, options, Some(self.retained.clone()))
            .await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.blob
            .resize_v1_retained(len, Some(self.retained.clone()))
            .await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.blob
            .sync_v1_retained(Some(self.retained.clone()))
            .await
    }

    async fn start_sync(&self) -> Handle<()> {
        self.blob
            .start_sync_v1_retained(Some(self.retained.clone()))
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
