//! Runtime-agnostic UNO blob envelope over an ordinary blob.
//!
//! The backing blob begins immediately after the immutable container header. UNO presents that
//! backing through the protocol's historical file coordinate system by adding a virtual 4 KiB
//! header prefix: root offsets 4 KiB and 6 KiB therefore map to backing offsets 0 and 2 KiB, and
//! payload offset 8 KiB maps to backing offset 4 KiB. The adapter keeps the on-disk format stable
//! while ensuring every payload and root operation goes through [`crate::Blob`].

use super::{atomic, preflush};
use crate::{
    Blob, Error, Handle, IoBufs, IoBufsMut, WriteOptions,
    atomic_api::{IntegrityBoundary, IntegrityToken, IntegrityUnit},
};
commonware_macros::stability_scope!(ALPHA {
    use crate::atomic_api::{
        AtomicBlob as AtomicBlobTrait, IntegrityAppend, IntegrityScheme, IntegritySnapshot,
    };
});
use commonware_utils::channel::oneshot;
use commonware_utils::sync::AsyncOwnedMutexGuard;
use std::{
    future::Future,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Arc,
};

/// Size of the immutable typed-envelope header hidden by an ordinary backing blob.
const VIRTUAL_HEADER_LEN: u64 = 4096;

/// A self-driving task accepted by a backend publication driver.
pub(super) type Task = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Backend-specific publication and task scheduling around the byte-oriented UNO core.
///
/// Payload mutation, integrity, roots, and durability-frontier tracking remain generic. The
/// publisher owns only namespace recovery, exact-generation validation, linked decisions, and the
/// runtime mechanism used to drive detached work.
pub(super) trait Publisher<B>: Clone + Send + Sync + 'static
where
    B: Blob,
{
    /// Start `task` independently of its completion observer.
    fn spawn(&self, task: Task) -> Result<(), Error>;

    /// Publish the mutation represented by `state` while its exclusive guard is held.
    fn publish<'a>(
        &'a self,
        core: Arc<Core<B>>,
        state: MutationGuard,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'a;
}

/// Shared byte store and mutation state for one exact atomic-blob incarnation.
pub(super) struct Core<B>
where
    B: Blob,
{
    backing: B,
    state: Arc<preflush::Context>,
}

impl<B> Core<B>
where
    B: Blob,
{
    /// Construct a core around an already recovered shared state.
    pub(super) fn new(backing: B, state: Arc<preflush::Context>) -> Arc<Self> {
        Arc::new(Self { backing, state })
    }

    pub(super) const fn backing(&self) -> &B {
        &self.backing
    }

    pub(super) const fn state(&self) -> &Arc<preflush::Context> {
        &self.state
    }

    pub(super) fn backing_offset(virtual_offset: u64) -> Result<u64, Error> {
        virtual_offset
            .checked_sub(VIRTUAL_HEADER_LEN)
            .ok_or_else(|| invalid_data("UNO attempted to access its immutable envelope header"))
    }

    pub(super) fn backing_len(virtual_len: u64) -> Result<u64, Error> {
        Self::backing_offset(virtual_len)
    }

    /// Recover the root state from a typed backing blob without reading historical payload.
    pub(super) async fn recover(backing: &B, backing_len: u64) -> Result<atomic::State, Error> {
        let virtual_len = backing_len
            .checked_add(VIRTUAL_HEADER_LEN)
            .ok_or(Error::OffsetOverflow)?;
        let mut slots = [[0u8; atomic::ROOT_LEN]; atomic::ROOT_OFFSETS.len()];
        for (slot, virtual_offset) in slots.iter_mut().zip(atomic::ROOT_OFFSETS) {
            let offset = Self::backing_offset(virtual_offset)?;
            let bytes = backing.read_at(offset, atomic::ROOT_LEN).await?;
            let bytes = bytes.coalesce();
            slot.copy_from_slice(bytes.as_ref());
        }
        let (state, truncate_to) = atomic::State::recover_from_root_slots(
            super::Layout::V2.data_offset(),
            virtual_len,
            &slots,
        )?;
        if let Some(virtual_len) = truncate_to {
            backing.resize(Self::backing_len(virtual_len)?).await?;
        }
        Ok(state)
    }

    fn ensure_healthy(&self, state: &atomic::State) -> Result<(), Error> {
        if state.is_poisoned() {
            return Err(invalid_data("atomic blob generation is poisoned"));
        }
        if let Some(error) = self.state.preflush().failure() {
            return Err(error);
        }
        Ok(())
    }

    fn schedule_preflush<P>(self: &Arc<Self>, publisher: &P, target: u64) -> Result<(), Error>
    where
        P: Publisher<B>,
    {
        let Some(first) = self.state.preflush().request(target)? else {
            return Ok(());
        };
        let backing = self.backing.clone();
        let preflush = self.state.preflush().clone();
        let mut driver = preflush.driver();
        publisher.spawn(Box::pin(async move {
            let mut target = first;
            loop {
                let result = backing.sync().await;
                let Some(next) = driver.complete(target, result) else {
                    break;
                };
                target = next;
            }
        }))
    }

    pub(super) async fn ensure_preflush(&self, target: u64) -> Result<(), Error> {
        if let Some(first) = self.state.preflush().request(target)? {
            let mut driver = self.state.preflush().driver();
            let mut target = first;
            loop {
                let result = self.backing.sync().await;
                let Some(next) = driver.complete(target, result) else {
                    break;
                };
                target = next;
            }
        }
        self.state.preflush().wait(target).await
    }

    /// Rewind a locked state after validating any integrity unit that straddles the new tail.
    ///
    /// This updates only the pending logical state. Batch publication deliberately defers the
    /// physical truncation until its group decision is durable.
    pub(super) async fn rewind_state(
        &self,
        state: &mut atomic::State,
        len: u64,
        unit: Option<IntegrityUnit>,
    ) -> Result<(), Error> {
        state.validate_rewind(len)?;
        if len == state.logical_len() {
            return state.rewind(len).map_err(Error::from);
        }
        let source = state.rewind_integrity_source(len, unit)?;
        let target = state.raw_len()?;
        self.ensure_preflush(target).await?;
        self.state.preflush().wait_idle().await?;
        let source_data = if let Some(source) = source {
            let data_len = usize::try_from(source.unit.len).map_err(|_| Error::OffsetOverflow)?;
            let encoded_len = if source.current {
                data_len
            } else {
                data_len
                    .checked_add(size_of::<u32>())
                    .ok_or(Error::OffsetOverflow)?
            };
            let span = state
                .read_plan(source.unit.offset, encoded_len)?
                .into_iter()
                .next()
                .expect("nonempty integrity sources have one backing span");
            let atomic::ReadSource::File(offset) = span.source;
            let encoded = self
                .backing
                .read_at(Self::backing_offset(offset)?, encoded_len)
                .await?
                .coalesce();
            let mut encoded = encoded.as_ref().to_vec();
            if source.current {
                state.validate_integrity_tail(&encoded)?;
            } else {
                let expected = u32::from_be_bytes(
                    encoded[data_len..]
                        .try_into()
                        .expect("integrity checksum footer has a fixed length"),
                );
                atomic::validate_integrity(&encoded[..data_len], expected)?;
                encoded.truncate(data_len);
            }
            source.retain_prefix.then_some((source.unit, encoded))
        } else {
            None
        };
        state.rewind_preflushed(
            len,
            source_data
                .as_ref()
                .map(|(unit, data)| (*unit, data.as_slice())),
        )?;
        self.state.preflush().reset_after_rewind(state.raw_len()?);
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn prepare_batch_commit(
        &self,
        state: &mut atomic::State,
    ) -> Result<Option<atomic::PreparedCommit>, Error> {
        if !state.is_dirty() {
            return Ok(None);
        }
        let mut prepared = state
            .prepare_commit()?
            .expect("dirty atomic state always prepares a commit");
        prepared.mark_batch_prepared();
        Ok(Some(prepared))
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[commonware_macros::stability(ALPHA)]
    pub(super) fn prepare_batch_delete(
        &self,
        state: &atomic::State,
    ) -> Result<atomic::PreparedCommit, Error> {
        let mut prepared = state.prepare_delete()?;
        prepared.mark_batch_prepared();
        Ok(prepared)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(super) async fn stage_batch_commit(
        &self,
        prepared: &mut atomic::PreparedCommit,
        witness: Option<&[u8]>,
    ) -> Result<(), Error> {
        if let Some(witness) = witness {
            prepared.attach_batch_witness(witness)?;
        }
        self.backing
            .write_at(
                Self::backing_offset(prepared.root_offset)?,
                prepared.prepared_root.clone(),
                WriteOptions::default(),
            )
            .await
    }

    /// Durably stage a tombstone without imposing a barrier on discarded payload writes.
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) async fn stage_batch_delete(
        &self,
        prepared: &mut atomic::PreparedCommit,
        witness: &[u8],
    ) -> Result<(), Error> {
        prepared.attach_batch_witness(witness)?;
        self.backing
            .write_at(
                Self::backing_offset(prepared.root_offset)?,
                prepared.prepared_root.clone(),
                WriteOptions::SYNC,
            )
            .await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(super) async fn sync_batch_commit(&self) -> Result<(), Error> {
        self.backing.sync().await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(super) async fn activate_batch_commit(
        &self,
        state: &mut atomic::State,
        prepared: Option<atomic::PreparedCommit>,
        defer_root: bool,
        force_truncate: bool,
    ) -> Result<Option<atomic::Candidate>, Error> {
        let Some(prepared) = prepared else {
            if force_truncate {
                self.backing
                    .resize(Self::backing_len(state.raw_len()?)?)
                    .await?;
            }
            return Ok(None);
        };
        self.state.preflush().record_durable(prepared.raw_len());
        if force_truncate || prepared.requires_truncate() {
            self.backing
                .resize(Self::backing_len(prepared.raw_len())?)
                .await?;
        }
        Ok(Some(if defer_root {
            state.finish_batch_commit(prepared)
        } else {
            let candidate = prepared.candidate();
            state.finish_commit(prepared);
            candidate
        }))
    }

    /// Conventional two-step publication used by simple backends and protocol tests.
    ///
    /// Filesystem publishers use the linked one-barrier UNO path instead. Keeping this helper in
    /// the generic core gives non-filesystem backends a correctness-first implementation without
    /// duplicating root or payload logic.
    pub(super) async fn publish_direct(
        &self,
        state: &mut atomic::State,
    ) -> Result<(), Error> {
        self.ensure_healthy(state)?;
        if !state.is_dirty() {
            return Ok(());
        }
        if state.preflush_requested()? {
            self.ensure_preflush(state.preflush_target()).await?;
        }
        let previous = state.deferred_batch_root().cloned();
        let prepared = state
            .prepare_commit()?
            .expect("dirty atomic state always prepares a commit");
        if let Some(previous) = previous {
            let root = atomic::materialized_candidate_root(&previous)?;
            self.backing
                .write_at(
                    Self::backing_offset(previous.root_offset)?,
                    root.to_vec(),
                    WriteOptions::default(),
                )
                .await?;
        }
        self.backing
            .write_at(
                Self::backing_offset(prepared.root_offset)?,
                prepared.prepared_root.clone(),
                WriteOptions::default(),
            )
            .await?;
        self.backing.sync().await?;
        self.state.preflush().record_durable(prepared.raw_len());
        self.backing
            .write_at(
                Self::backing_offset(prepared.root_offset)?,
                prepared.committed_root.to_vec(),
                WriteOptions::SYNC,
            )
            .await?;
        if prepared.requires_truncate() {
            self.backing
                .resize(Self::backing_len(prepared.raw_len())?)
                .await?;
        }
        state.finish_commit(prepared);
        Ok(())
    }
}

/// Atomic append-only view over an ordinary V1-geometry backing blob.
pub(super) struct AtomicBlob<B, P>
where
    B: Blob,
    P: Publisher<B>,
{
    core: Arc<Core<B>>,
    publisher: P,
}

struct AppendRequest {
    expected_offset: Option<u64>,
    expected: Option<IntegrityToken>,
    options: WriteOptions,
    boundary: IntegrityBoundary,
    tag: Option<[u8; super::ATOMIC_BLOB_TAG_LEN]>,
    publish: bool,
}

impl<B, P> Clone for AtomicBlob<B, P>
where
    B: Blob,
    P: Publisher<B>,
{
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
            publisher: self.publisher.clone(),
        }
    }
}

impl<B, P> AtomicBlob<B, P>
where
    B: Blob,
    P: Publisher<B>,
{
    pub(super) fn new(core: Arc<Core<B>>, publisher: P) -> Self {
        Self { core, publisher }
    }

    pub(super) const fn core(&self) -> &Arc<Core<B>> {
        &self.core
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(super) const fn publisher(&self) -> &P {
        &self.publisher
    }

    pub(super) async fn lock_state(&self) -> Result<AsyncOwnedMutexGuard<atomic::State>, Error> {
        let state = self.core.state.lock().await;
        self.core.ensure_healthy(&state)?;
        Ok(state)
    }

    async fn append_inner(
        &self,
        data: IoBufs,
        request: AppendRequest,
    ) -> Result<(u64, IntegrityToken), Error> {
        let AppendRequest {
            expected_offset,
            expected,
            options,
            boundary,
            tag,
            publish,
        } = request;
        let state = self.lock_state().await?;
        let mut operation = MutationGuard::new(state);
        if expected_offset.is_some_and(|offset| offset != operation.logical_len()) {
            operation.finish();
            return Err(invalid_input(
                "atomic writes must append at the current logical tail",
            ));
        }
        if let Some(expected) = expected {
            operation.expect_integrity_token(expected)?;
        }
        let offset = operation.logical_len();
        let Some(prepared) = operation.prepare_integrity_append(data, boundary)? else {
            if let Some(tag) = tag {
                operation.set_tag(tag)?;
            }
            let result = (offset, operation.integrity_token());
            operation.finish();
            return Ok(result);
        };
        let result_offset = prepared.result_offset;
        let backing_offset = Core::<B>::backing_offset(prepared.file_offset)?;
        operation.arm();
        self.core
            .backing
            .write_at(backing_offset, prepared.data, options)
            .await?;
        if let Some(range) = operation.finish_mutation(prepared.mutation, !publish) {
            self.core
                .schedule_preflush(&self.publisher, range.end)?;
        }
        if let Some(tag) = tag {
            operation.set_tag(tag)?;
        }
        if publish {
            let token = operation.integrity_token();
            self.publisher
                .publish(self.core.clone(), operation)
                .await?;
            return Ok((result_offset, token));
        }
        let result = (result_offset, operation.integrity_token());
        operation.finish();
        Ok(result)
    }

    async fn rewind_inner(
        &self,
        expected: Option<IntegrityToken>,
        len: u64,
        unit: Option<IntegrityUnit>,
        tag: Option<[u8; super::ATOMIC_BLOB_TAG_LEN]>,
    ) -> Result<IntegrityToken, Error> {
        let state = self.lock_state().await?;
        let mut operation = MutationGuard::new(state);
        if let Some(expected) = expected {
            operation.expect_integrity_token(expected)?;
        }
        let truncate = len < operation.logical_len() && len >= operation.committed_len();
        self.core.rewind_state(&mut operation, len, unit).await?;
        if truncate {
            operation.arm();
            self.core
                .backing
                .resize(Core::<B>::backing_len(operation.raw_len()?)?)
                .await?;
        }
        if let Some(tag) = tag {
            operation.set_tag(tag)?;
        }
        let token = operation.integrity_token();
        operation.finish();
        Ok(token)
    }
}

/// Poisons a generation if an admitted mutation is canceled or fails before normal completion.
pub(super) struct MutationGuard {
    state: Option<AsyncOwnedMutexGuard<atomic::State>>,
    armed: bool,
}

impl MutationGuard {
    const fn new(state: AsyncOwnedMutexGuard<atomic::State>) -> Self {
        Self {
            state: Some(state),
            armed: false,
        }
    }

    /// Poison the generation if this operation is canceled or returns after protocol I/O begins.
    pub(super) const fn arm(&mut self) {
        self.armed = true;
    }

    pub(super) fn finish(mut self) {
        self.state.take();
    }
}

impl Deref for MutationGuard {
    type Target = atomic::State;

    fn deref(&self) -> &Self::Target {
        self.state.as_deref().expect("active mutation owns its state")
    }
}

impl DerefMut for MutationGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.state
            .as_deref_mut()
            .expect("active mutation owns its state")
    }
}

impl Drop for MutationGuard {
    fn drop(&mut self) {
        if self.armed && let Some(state) = &mut self.state {
            state.poison();
        }
    }
}

impl<B, P> Blob for AtomicBlob<B, P>
where
    B: Blob,
    P: Publisher<B>,
{
    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        let state = self.lock_state().await?;
        let plan = state.read_plan(offset, len)?;
        let virtual_offset = plan.first().map_or(super::Layout::V2.data_offset(), |span| {
            debug_assert_eq!(span.destination, 0);
            debug_assert_eq!(span.len, len);
            let atomic::ReadSource::File(offset) = span.source;
            offset
        });
        let result = self
            .core
            .backing
            .read_at_buf(
                Core::<B>::backing_offset(virtual_offset)?,
                len,
                bufs,
            )
            .await;
        drop(state);
        result
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        let state = self.lock_state().await?;
        let span = state
            .read_plan(offset, len)?
            .into_iter()
            .next()
            .unwrap_or(atomic::ReadSpan {
                destination: 0,
                len: 0,
                source: atomic::ReadSource::File(super::Layout::V2.data_offset()),
            });
        let atomic::ReadSource::File(virtual_offset) = span.source;
        let result = self
            .core
            .backing
            .read_at(Core::<B>::backing_offset(virtual_offset)?, len)
            .await;
        drop(state);
        result
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        if bufs.is_empty() {
            return Ok(());
        }
        self.append_inner(
            bufs,
            AppendRequest {
                expected_offset: Some(offset),
                expected: None,
                options: options.without(WriteOptions::SYNC),
                boundary: IntegrityBoundary::Continue,
                tag: None,
                publish: options.contains(WriteOptions::SYNC),
            },
        )
        .await
        .map(|_| ())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.rewind_inner(None, len, None, None).await.map(|_| ())
    }

    async fn sync(&self) -> Result<(), Error> {
        self.start_sync().await.await
    }

    async fn start_sync(&self) -> Handle<()> {
        let state = match self.lock_state().await {
            Ok(state) => state,
            Err(error) => return Handle::ready(Err(error)),
        };
        let core = self.core.clone();
        let publisher = self.publisher.clone();
        let (sender, receiver) = oneshot::channel();
        let task = Box::pin(async move {
            let operation = MutationGuard::new(state);
            let result = publisher.publish(core, operation).await;
            let _ = sender.send(result);
        });
        match self.publisher.spawn(task) {
            Ok(()) => Handle::from_receiver(receiver),
            Err(error) => Handle::ready(Err(error)),
        }
    }
}

#[commonware_macros::stability(ALPHA)]
impl<B, P> AtomicBlobTrait for AtomicBlob<B, P>
where
    B: Blob,
    P: Publisher<B>,
{
    async fn tag(&self) -> Result<[u8; super::ATOMIC_BLOB_TAG_LEN], Error> {
        Ok(self.lock_state().await?.tag())
    }

    async fn set_tag(&self, tag: [u8; super::ATOMIC_BLOB_TAG_LEN]) -> Result<(), Error> {
        let mut state = self.lock_state().await?;
        state.set_tag(tag)?;
        Ok(())
    }

    async fn integrity_scheme(&self) -> Result<IntegrityScheme, Error> {
        Ok(self.lock_state().await?.integrity_scheme())
    }

    async fn integrity_snapshot(&self) -> Result<IntegritySnapshot, Error> {
        let state = self.lock_state().await?;
        let encoded_len = state.logical_len();
        let scheme = state.integrity_scheme();
        let tag = state.tag();
        let token = state.integrity_token();
        let Some(unit) = state.integrity_tail() else {
            return Ok(IntegritySnapshot {
                encoded_len,
                scheme,
                tag,
                tail: None,
                token,
            });
        };
        let len = usize::try_from(unit.len).map_err(|_| Error::OffsetOverflow)?;
        let span = state
            .read_plan(unit.offset, len)?
            .into_iter()
            .next()
            .expect("nonempty integrity tails have one backing span");
        let atomic::ReadSource::File(offset) = span.source;
        let data = self
            .core
            .backing
            .read_at(Core::<B>::backing_offset(offset)?, len)
            .await?
            .coalesce();
        state.validate_integrity_tail(data.as_ref())?;
        Ok(IntegritySnapshot {
            encoded_len,
            scheme,
            tag,
            tail: Some((unit, IoBufs::from(data.freeze()))),
            token,
        })
    }

    async fn compare_set_tag(
        &self,
        expected: IntegrityToken,
        tag: [u8; super::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<IntegrityToken, Error> {
        let mut state = self.lock_state().await?;
        state.expect_integrity_token(expected)?;
        state.set_tag(tag)?;
        Ok(state.integrity_token())
    }

    async fn append(&self, data: impl Into<IoBufs> + Send) -> Result<u64, Error> {
        self.append_inner(
            data.into(),
            AppendRequest {
                expected_offset: None,
                expected: None,
                options: WriteOptions::default(),
                boundary: IntegrityBoundary::Continue,
                tag: None,
                publish: false,
            },
        )
        .await
        .map(|(offset, _)| offset)
    }

    async fn append_tagged(
        &self,
        data: impl Into<IoBufs> + Send,
        tag: [u8; super::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<u64, Error> {
        self.append_inner(
            data.into(),
            AppendRequest {
                expected_offset: None,
                expected: None,
                options: WriteOptions::default(),
                boundary: IntegrityBoundary::Continue,
                tag: Some(tag),
                publish: false,
            },
        )
        .await
        .map(|(offset, _)| offset)
    }

    async fn append_integrity(
        &self,
        expected: IntegrityToken,
        data: impl Into<IoBufs> + Send,
        boundary: IntegrityBoundary,
        tag: Option<[u8; super::ATOMIC_BLOB_TAG_LEN]>,
    ) -> Result<IntegrityAppend, Error> {
        self.append_inner(
            data.into(),
            AppendRequest {
                expected_offset: None,
                expected: Some(expected),
                options: WriteOptions::default(),
                boundary,
                tag,
                publish: false,
            },
        )
            .await
            .map(|(offset, token)| IntegrityAppend { offset, token })
    }

    async fn read_integrity_tail(&self) -> Result<Option<(IntegrityUnit, IoBufs)>, Error> {
        Ok(self.integrity_snapshot().await?.tail)
    }

    async fn read_integrity(&self, unit: IntegrityUnit) -> Result<IoBufs, Error> {
        let state = self.lock_state().await?;
        state.integrity_scheme().validate_completed_unit(unit)?;
        let data_len = usize::try_from(unit.len).map_err(|_| Error::OffsetOverflow)?;
        let encoded_len = data_len
            .checked_add(size_of::<u32>())
            .ok_or(Error::OffsetOverflow)?;
        let encoded_end = unit
            .offset
            .checked_add(encoded_len as u64)
            .ok_or(Error::OffsetOverflow)?;
        if encoded_end > state.completed_integrity_len() {
            return Err(invalid_input(
                "integrity unit is not within the completed payload prefix",
            ));
        }
        let span = state
            .read_plan(unit.offset, encoded_len)?
            .into_iter()
            .next()
            .expect("nonempty integrity units have one backing span");
        let atomic::ReadSource::File(offset) = span.source;
        let encoded = self
            .core
            .backing
            .read_at(Core::<B>::backing_offset(offset)?, encoded_len)
            .await?
            .coalesce();
        let mut encoded = encoded.as_ref().to_vec();
        let expected = u32::from_be_bytes(
            encoded[data_len..]
                .try_into()
                .expect("integrity checksum footer has a fixed length"),
        );
        atomic::validate_integrity(&encoded[..data_len], expected)?;
        encoded.truncate(data_len);
        Ok(IoBufs::from(encoded))
    }

    async fn rewind(&self, len: u64) -> Result<(), Error> {
        self.rewind_inner(None, len, None, None).await.map(|_| ())
    }

    async fn rewind_tagged(
        &self,
        len: u64,
        tag: [u8; super::ATOMIC_BLOB_TAG_LEN],
    ) -> Result<(), Error> {
        self.rewind_inner(None, len, None, Some(tag))
            .await
            .map(|_| ())
    }

    async fn rewind_integrity(
        &self,
        expected: IntegrityToken,
        len: u64,
        unit: Option<IntegrityUnit>,
        tag: Option<[u8; super::ATOMIC_BLOB_TAG_LEN]>,
    ) -> Result<IntegrityToken, Error> {
        self.rewind_inner(Some(expected), len, unit, tag).await
    }
}

fn invalid_data(message: impl Into<String>) -> Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into()).into()
}

fn invalid_input(message: impl Into<String>) -> Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BufferPool, BufferPoolConfig,
        mocks::{SyncFaultContext, WriteFaultContext, WriteFaults},
        storage::memory,
        telemetry::metrics::Registry,
    };
    use commonware_utils::sync::Mutex;

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    #[derive(Clone)]
    struct InlinePublisher;

    #[derive(Default)]
    struct Trace {
        writes: Vec<(u64, WriteOptions)>,
        resizes: Vec<u64>,
    }

    #[derive(Clone)]
    struct RecordingBlob<B> {
        inner: B,
        trace: Arc<Mutex<Trace>>,
    }

    impl<B: Blob> Blob for RecordingBlob<B> {
        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
        ) -> Result<IoBufsMut, Error> {
            self.inner.read_at_buf(offset, len, bufs).await
        }

        async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
            self.inner.read_at(offset, len).await
        }

        async fn write_at(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
            options: WriteOptions,
        ) -> Result<(), Error> {
            self.trace.lock().writes.push((offset, options));
            self.inner.write_at(offset, bufs, options).await
        }

        async fn resize(&self, len: u64) -> Result<(), Error> {
            self.trace.lock().resizes.push(len);
            self.inner.resize(len).await
        }

        async fn sync(&self) -> Result<(), Error> {
            self.inner.sync().await
        }

        async fn start_sync(&self) -> Handle<()> {
            self.inner.start_sync().await
        }
    }

    impl<B> Publisher<B> for InlinePublisher
    where
        B: Blob,
    {
        fn spawn(&self, task: Task) -> Result<(), Error> {
            futures::executor::block_on(task);
            Ok(())
        }

        async fn publish(
            &self,
            core: Arc<Core<B>>,
            mut state: MutationGuard,
        ) -> Result<(), Error> {
            state.arm();
            core.publish_direct(&mut state).await?;
            state.finish();
            Ok(())
        }
    }

    async fn wrap<B>(backing: B, len: u64) -> AtomicBlob<B, InlinePublisher>
    where
        B: Blob,
    {
        let state = Core::recover(&backing, len).await.unwrap();
        let state = preflush::Context::new(state).unwrap();
        AtomicBlob::new(Core::new(backing, state), InlinePublisher)
    }

    async fn open<S>(storage: &S, partition: &str, name: &[u8]) -> AtomicBlob<S::Blob, InlinePublisher>
    where
        S: crate::Storage,
        S::Blob: Blob,
    {
        let (backing, mut len) = storage.open(partition, name).await.unwrap();
        if len == 0 {
            backing.resize(4096).await.unwrap();
            backing.sync().await.unwrap();
            len = 4096;
        }
        wrap(backing, len).await
    }

    async fn recording_blob(
        storage: &memory::Storage,
        partition: &str,
    ) -> (
        AtomicBlob<RecordingBlob<memory::Blob>, InlinePublisher>,
        Arc<Mutex<Trace>>,
    ) {
        let (backing, len) = crate::Storage::open(storage, partition, b"blob")
            .await
            .unwrap();
        assert_eq!(len, 0);
        backing.resize(4096).await.unwrap();
        backing.sync().await.unwrap();
        let trace = Arc::new(Mutex::new(Trace::default()));
        let backing = RecordingBlob {
            inner: backing,
            trace: trace.clone(),
        };
        (wrap(backing, 4096).await, trace)
    }

    #[tokio::test]
    async fn v1_backing_hides_roots_and_writes_payload_once() {
        let storage = memory::Storage::new(test_pool());
        let blob = open(&storage, "uno_v1", b"blob").await;
        assert_eq!(blob.append(b"payload").await.unwrap(), 0);

        let backing = blob.core().backing();
        assert_eq!(backing.read_at(4096, 7).await.unwrap().coalesce(), b"payload");
        assert_ne!(backing.read_at(0, 7).await.unwrap().coalesce(), b"payload");
        assert_eq!(blob.read_at(0, 7).await.unwrap().coalesce(), b"payload");
    }

    #[tokio::test]
    async fn wrapper_reconstructs_state_from_v1_bytes() {
        let storage = memory::Storage::new(test_pool());
        let blob = open(&storage, "uno_reopen", b"blob").await;
        blob.append_tagged(b"durable", [0xA5; super::super::ATOMIC_BLOB_TAG_LEN])
            .await
            .unwrap();
        drop(blob.start_sync().await);
        drop(blob);

        let reopened = open(&storage, "uno_reopen", b"blob").await;
        assert_eq!(reopened.read_at(0, 7).await.unwrap().coalesce(), b"durable");
        assert_eq!(
            reopened.tag().await.unwrap(),
            [0xA5; super::super::ATOMIC_BLOB_TAG_LEN]
        );
    }

    #[tokio::test]
    async fn backing_write_failures_poison_and_preserve_the_durable_epoch() {
        let inner = memory::Storage::new(test_pool());
        let faults = WriteFaults::default();
        let storage = WriteFaultContext {
            inner,
            faults: faults.clone(),
        };
        let blob = open(&storage, "uno_write_fault", b"blob").await;
        blob.append(b"old").await.unwrap();
        blob.sync().await.unwrap();

        faults.arm();
        assert!(blob.append(b"discarded").await.is_err());
        assert!(blob.append(b"poisoned").await.is_err());
        drop(blob);

        faults.disarm();
        let reopened = open(&storage, "uno_write_fault", b"blob").await;
        assert_eq!(reopened.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert!(reopened.read_at(3, 1).await.is_err());
    }

    #[tokio::test]
    async fn backing_sync_failures_do_not_publish_prepared_roots() {
        let storage = memory::Storage::new(test_pool());
        let blob = open(&storage, "uno_sync_fault", b"blob").await;
        blob.append(b"old").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let faulting = SyncFaultContext {
            inner: storage.clone(),
            fail_partition: "uno_sync_fault".into(),
        };
        let blob = open(&faulting, "uno_sync_fault", b"blob").await;
        blob.append(b"discarded").await.unwrap();
        assert!(blob.sync().await.is_err());
        drop(blob);

        let reopened = open(&storage, "uno_sync_fault", b"blob").await;
        assert_eq!(reopened.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert!(reopened.read_at(3, 1).await.is_err());
    }

    #[tokio::test]
    async fn blob_write_options_reach_the_payload_write() {
        let storage = memory::Storage::new(test_pool());
        let (blob, trace) = recording_blob(&storage, "uno_options").await;

        blob.write_at(0, b"payload", WriteOptions::DONT_CACHE)
            .await
            .unwrap();

        let trace = trace.lock();
        assert_eq!(trace.writes.len(), 1);
        assert_eq!(trace.writes[0].0, 4096);
        assert!(trace.writes[0].1.contains(WriteOptions::DONT_CACHE));
        assert!(!trace.writes[0].1.contains(WriteOptions::SYNC));
    }

    #[tokio::test]
    async fn same_length_rewinds_do_not_resize_the_backing_blob() {
        let storage = memory::Storage::new(test_pool());
        let (blob, trace) = recording_blob(&storage, "uno_noop_rewind").await;
        blob.append(b"old").await.unwrap();
        blob.sync().await.unwrap();
        *trace.lock() = Trace::default();

        blob.rewind(3).await.unwrap();
        let tag = [0xA5; super::super::ATOMIC_BLOB_TAG_LEN];
        blob.rewind_tagged(3, tag).await.unwrap();

        assert!(trace.lock().resizes.is_empty());
        assert_eq!(blob.tag().await.unwrap(), tag);
    }
}
