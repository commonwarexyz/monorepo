//! Exclusive mutable archive state owned by the catalog actor.
//!
//! Finalized rows contain compact block metadata and reference bodies in per-producer custody.
//! Immutable mode copies those bodies into a write-once archive asynchronously, then advances a
//! durable promotion cursor before reclaiming temporary copies. A publication synchronizes every
//! authoritative archive before its checkpoint, so recovery can trust every referenced body.

use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        config::CodecConfig,
        marshal::{
            actors::catalog::{Commit, Error, metadata_blob_size},
            storage::{
                archive::{
                    FinalizedArchive, ReadOutcome as ArchiveReadOutcome,
                    ReadRequest as ArchiveReadRequest, ReadStep as ArchiveReadStep, Shared,
                },
                blocks::{BlockMeta, FinalBlock, FinalBlockMeta, validated_reference},
                checkpoint::{CatalogState, Checkpoint, Prune, next_lqc_index},
                pending::{BodyReadGroup, BodyReader, PendingBlocks},
                temporary::{ReadPlan as TemporaryReadPlan, TemporaryArchive},
            },
            types::OutputIndex,
        },
        types::{
            BlockRef, CertificateId, ChainId, Height, Lqc, TipRecord, TransactionBlock,
            TransactionBlockHeader,
        },
    },
    types::View,
};
use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::{Digestible, Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::Handle;
use commonware_storage::{Context, metadata::Metadata, translator::Translator};
use commonware_utils::sequence::Unit;
use futures::future::try_join_all;
use std::{collections::BTreeSet, num::NonZeroUsize, sync::Arc};

type SharedLqc<V, H> = Shared<Lqc<V, <H as Hasher>::Digest>>;
type SharedHistory<H> = Shared<TipRecord<<H as Hasher>::Digest>>;
type InstallArtifacts<V, H> = (
    Arc<Lqc<V, <H as Hasher>::Digest>>,
    Arc<TipRecord<<H as Hasher>::Digest>>,
);
pub(in crate::multimmit::marshal) type FinalLqc<T, E, H, V> =
    FinalizedArchive<T, E, <H as Hasher>::Digest, SharedLqc<V, H>>;
pub(in crate::multimmit::marshal) type FinalHistory<T, E, H> =
    FinalizedArchive<T, E, <H as Hasher>::Digest, SharedHistory<H>>;
pub(in crate::multimmit::marshal) type PendingLqc<T, E, H, V> =
    TemporaryArchive<T, E, <H as Hasher>::Digest, SharedLqc<V, H>>;
pub(in crate::multimmit::marshal) type PendingHistory<T, E, H> =
    TemporaryArchive<T, E, <H as Hasher>::Digest, SharedHistory<H>>;

pub(in crate::multimmit::marshal) type FinalBlockReadRequest<H> =
    ArchiveReadRequest<<H as Hasher>::Digest>;
pub(in crate::multimmit::marshal) type FinalBlockReadStep<E, H> =
    ArchiveReadStep<E, <H as Hasher>::Digest, FinalBlockMeta<<H as Hasher>::Digest>>;
pub(in crate::multimmit::marshal) type FinalBlockReadOutcome<H> =
    ArchiveReadOutcome<<H as Hasher>::Digest, FinalBlockMeta<<H as Hasher>::Digest>>;

/// Exact finalized step plus the pending fallback captured for one history key.
pub(in crate::multimmit::marshal) struct HistoryRead<E: Context, H: Hasher> {
    finalized: ArchiveReadStep<E, H::Digest, SharedHistory<H>>,
    pending: Option<TemporaryReadPlan<E, H::Digest, SharedHistory<H>>>,
}

pub(in crate::multimmit::marshal) struct HistoryReadContinuation<E: Context, H: Hasher> {
    finalized: ArchiveReadRequest<H::Digest>,
    pending: Option<TemporaryReadPlan<E, H::Digest, SharedHistory<H>>>,
}

pub(in crate::multimmit::marshal) enum HistoryReadOutcome<E: Context, H: Hasher> {
    Done(Option<Arc<TipRecord<H::Digest>>>),
    Continue(HistoryReadContinuation<E, H>),
}

impl<E: Context, H: Hasher> HistoryRead<E, H> {
    pub(in crate::multimmit::marshal) async fn execute(
        self,
    ) -> Result<HistoryReadOutcome<E, H>, Error> {
        match self.finalized.execute().await.map_err(Error::storage)? {
            ArchiveReadOutcome::Done(Some((_, record))) => {
                Ok(HistoryReadOutcome::Done(Some(record.into_inner())))
            }
            ArchiveReadOutcome::Done(None) => {
                let record = match self.pending {
                    Some(plan) => plan
                        .execute()
                        .await
                        .map_err(Error::storage)?
                        .map(Shared::into_inner),
                    None => None,
                };
                Ok(HistoryReadOutcome::Done(record))
            }
            ArchiveReadOutcome::Continue(finalized) => {
                Ok(HistoryReadOutcome::Continue(HistoryReadContinuation {
                    finalized,
                    pending: self.pending,
                }))
            }
        }
    }
}

pub(in crate::multimmit::marshal) struct StoredRef<D: commonware_cryptography::Digest> {
    pub index: OutputIndex,
    pub reference: BlockRef<D>,
    pub encoded_len: u64,
    pub generation: u64,
}

pub(in crate::multimmit::marshal) enum Admission<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    Lqc(View, CertificateId<H::Digest>, Arc<Lqc<V, H::Digest>>),
    History(View, H::Digest, Arc<TipRecord<H::Digest>>),
    #[cfg(test)]
    Finality {
        view: View,
        id: CertificateId<H::Digest>,
        proof: Arc<Lqc<V, H::Digest>>,
        history: Arc<TipRecord<H::Digest>>,
    },
    Block(BlockRef<H::Digest>, Arc<TransactionBlock<H, B>>),
}

/// Temporary archives containing durable admissions in one catalog cut.
pub(in crate::multimmit::marshal) struct AdmissionFootprint {
    lqc: bool,
    history: bool,
    blocks: bool,
}

impl AdmissionFootprint {
    /// Extends this cut to cover writes buffered by a later admission batch.
    pub(in crate::multimmit::marshal) const fn merge(&mut self, later: Self) {
        self.lqc |= later.lqc;
        self.history |= later.history;
        self.blocks |= later.blocks;
    }
}

struct FinalizedWrites {
    lqc: bool,
    history: bool,
    blocks: bool,
}

/// One exact finalized-archive cut awaiting checkpoint-last publication.
pub(in crate::multimmit::marshal) struct CommitPublication<D: commonware_cryptography::Digest> {
    pub(in crate::multimmit::marshal) checkpoint: Checkpoint<D>,
    pub(in crate::multimmit::marshal) lqc_index: Option<u64>,
    pub(in crate::multimmit::marshal) cleanup: PendingCleanup,
    writes: FinalizedWrites,
}

/// The latest ordinary pending-store cleanup obligation.
#[derive(Clone)]
pub(in crate::multimmit::marshal) struct PendingCleanup {
    selected: Option<View>,
}

impl PendingCleanup {
    /// Coalesces cleanup through a later published checkpoint.
    pub(in crate::multimmit::marshal) fn coalesce(&mut self, later: Self) {
        self.selected = self.selected.max(later.selected);
    }
}

pub(in crate::multimmit::marshal) struct Stores<T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    final_lqc: Option<FinalLqc<T, E, H, V>>,
    final_history: Option<FinalHistory<T, E, H>>,
    final_blocks: Option<FinalBlock<T, E, H>>,
    pending_lqc: Option<PendingLqc<T, E, H, V>>,
    pending_history: Option<PendingHistory<T, E, H>>,
    pending_blocks: Option<PendingBlocks<T, E, H, B>>,
    metadata: Option<Metadata<E, Unit, CatalogState<H::Digest>>>,
    accepted_lqc_index: Option<u64>,
    accepted_cleanup_selected: Option<View>,
    /// Prunable finalized rows retain their bodies in temporary custody until application pruning.
    prunable_blocks: bool,
    codec_config: CodecConfig,
    max_metadata_blob_size: usize,
}

impl<T, E, H, V, B> Stores<T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    B::Cfg: Clone,
{
    #[allow(clippy::too_many_arguments)]
    pub(in crate::multimmit::marshal) fn new(
        final_lqc: FinalLqc<T, E, H, V>,
        final_history: FinalHistory<T, E, H>,
        final_blocks: FinalBlock<T, E, H>,
        pending_lqc: PendingLqc<T, E, H, V>,
        pending_history: PendingHistory<T, E, H>,
        pending_blocks: PendingBlocks<T, E, H, B>,
        metadata: Metadata<E, Unit, CatalogState<H::Digest>>,
        codec_config: CodecConfig,
        max_metadata_blob_size: usize,
    ) -> Result<Self, Error> {
        if pending_blocks.chain_count() == 0
            || metadata.get(&Unit).is_some_and(|state| {
                state.checkpoint().ordered().len() != pending_blocks.chain_count()
            })
        {
            return Err(Error::Invalid(
                "checkpoint and block-store chain counts differ",
            ));
        }
        let accepted_lqc_index = metadata.get(&Unit).and_then(CatalogState::lqc_index);
        let accepted_cleanup_selected = metadata
            .get(&Unit)
            .and_then(CatalogState::commit_cleanup)
            .flatten();
        let prunable_blocks = metadata
            .get(&Unit)
            .expect("catalog metadata is initialized before stores")
            .checkpoint()
            .archive_layout()
            .blocks_prunable();
        Ok(Self {
            final_lqc: Some(final_lqc),
            final_history: Some(final_history),
            final_blocks: Some(final_blocks),
            pending_lqc: Some(pending_lqc),
            pending_history: Some(pending_history),
            pending_blocks: Some(pending_blocks),
            metadata: Some(metadata),
            accepted_lqc_index,
            accepted_cleanup_selected,
            prunable_blocks,
            codec_config,
            max_metadata_blob_size,
        })
    }

    pub(in crate::multimmit::marshal) fn checkpoint(&self) -> Option<&Checkpoint<H::Digest>> {
        self.metadata
            .as_ref()
            .expect("catalog owns metadata")
            .get(&Unit)
            .map(CatalogState::checkpoint)
    }

    pub(in crate::multimmit::marshal) const fn chain_count(&self) -> usize {
        self.pending_blocks
            .as_ref()
            .expect("catalog owns pending blocks")
            .chain_count()
    }

    pub(in crate::multimmit::marshal) async fn start_sync_checkpoint(
        &mut self,
        checkpoint: Checkpoint<H::Digest>,
    ) -> Result<Handle<()>, Error> {
        let state = self
            .metadata
            .as_ref()
            .expect("catalog owns metadata")
            .get(&Unit)
            .ok_or(Error::Invalid("catalog has no checkpoint"))?
            .checkpointed(checkpoint)
            .ok_or(Error::Invalid(
                "acknowledgement cannot replace an install intent",
            ))?;
        self.start_sync_state(state).await
    }

    async fn sync_state(&mut self, state: CatalogState<H::Digest>) -> Result<(), Error> {
        self.validate_state(&state)?;
        let metadata = self.metadata.take().expect("catalog owns metadata");
        self.metadata = Some(
            metadata
                .put_sync(Unit, state)
                .await
                .map_err(Error::storage)?,
        );
        Ok(())
    }

    async fn start_sync_state(
        &mut self,
        state: CatalogState<H::Digest>,
    ) -> Result<Handle<()>, Error> {
        self.validate_state(&state)?;
        let mut metadata = self.metadata.take().expect("catalog owns metadata");
        metadata.put(Unit, state);
        let (metadata, sync) = metadata.start_sync().await.map_err(Error::storage)?;
        self.metadata = Some(metadata);
        Ok(sync)
    }

    fn validate_state(&self, state: &CatalogState<H::Digest>) -> Result<(), Error> {
        if metadata_blob_size(state).is_none_or(|size| size > self.max_metadata_blob_size) {
            return Err(Error::Invalid(
                "catalog state exceeds configured metadata bound",
            ));
        }
        Ok(())
    }

    pub(in crate::multimmit::marshal) async fn buffer_admissions(
        &mut self,
        writes: Vec<(Admission<H, V, B>, bool)>,
    ) -> Result<Option<AdmissionFootprint>, Error> {
        let pending_blocks = self
            .pending_blocks
            .as_ref()
            .expect("catalog owns pending blocks");
        if writes.iter().any(|(write, _)| match write {
            Admission::Block(reference, _) => !pending_blocks.admits(*reference),
            _ => false,
        }) {
            return Err(Error::Invalid("producer block is below the custody floor"));
        }
        let mut footprint = writes
            .iter()
            .any(|(write, durable)| *durable || matches!(write, Admission::Block(_, _)))
            .then_some(AdmissionFootprint {
                lqc: false,
                history: false,
                blocks: false,
            });
        for (write, durable) in writes {
            match write {
                Admission::Lqc(view, id, proof) => {
                    self.put_pending_lqc(view, id, proof).await?;
                    if durable {
                        footprint.as_mut().expect("durable footprint exists").lqc = true;
                    }
                }
                Admission::History(view, commitment, record) => {
                    self.put_pending_history(view, commitment, record).await?;
                    if durable {
                        footprint
                            .as_mut()
                            .expect("durable footprint exists")
                            .history = true;
                    }
                }
                #[cfg(test)]
                Admission::Finality {
                    view,
                    id,
                    proof,
                    history,
                } => {
                    let commitment = proof.leader().history();
                    self.put_pending_lqc(view, id, proof).await?;
                    self.put_pending_history(view, commitment, history).await?;
                    if durable {
                        let footprint = footprint.as_mut().expect("durable footprint exists");
                        footprint.lqc = true;
                        footprint.history = true;
                    }
                }
                Admission::Block(reference, block) => {
                    self.pending_blocks
                        .as_mut()
                        .expect("catalog owns pending blocks")
                        .put(reference, block)
                        .await
                        .map_err(Error::storage)?;
                    footprint
                        .as_mut()
                        .expect("block admission creates a durability footprint")
                        .blocks = true;
                }
            }
        }
        Ok(footprint)
    }

    /// Starts the exact temporary-archive durability cut accumulated by the catalog.
    pub(in crate::multimmit::marshal) async fn start_admission_sync(
        &mut self,
        footprint: AdmissionFootprint,
    ) -> Result<Vec<Handle<()>>, Error> {
        let AdmissionFootprint {
            lqc: sync_lqc,
            history: sync_history,
            blocks: sync_blocks,
        } = footprint;
        let lqc = self.pending_lqc.take().expect("catalog owns pending LQCs");
        let history = self
            .pending_history
            .take()
            .expect("catalog owns pending history");
        let blocks = self
            .pending_blocks
            .take()
            .expect("catalog owns pending blocks");
        let (lqc, history, blocks) = futures::try_join!(
            async move {
                if sync_lqc {
                    lqc.start_sync()
                        .await
                        .map(|(store, handle)| (store, Some(handle)))
                        .map_err(Error::storage)
                } else {
                    Ok((lqc, None))
                }
            },
            async move {
                if sync_history {
                    history
                        .start_sync()
                        .await
                        .map(|(store, handle)| (store, Some(handle)))
                        .map_err(Error::storage)
                } else {
                    Ok((history, None))
                }
            },
            async move {
                let mut blocks = blocks;
                let handles = if sync_blocks {
                    blocks.start_sync().await.map_err(Error::storage)?
                } else {
                    Vec::new()
                };
                Ok::<_, Error>((blocks, handles))
            },
        )?;
        self.pending_lqc = Some(lqc.0);
        self.pending_history = Some(history.0);
        let mut handles = Vec::with_capacity(4);
        handles.extend(lqc.1);
        handles.extend(history.1);
        handles.extend(blocks.1);
        self.pending_blocks = Some(blocks.0);
        Ok(handles)
    }

    pub(in crate::multimmit::marshal) fn sealed_body_readers(&self) -> Vec<BodyReader<E, H, B>> {
        self.pending_blocks
            .as_ref()
            .expect("catalog owns pending blocks")
            .sealed_body_readers()
    }

    /// Starts durable seal proofs for full pending segments whose admission cut completed.
    /// The returned segments must come back through [`Self::finish_pending_seals`] once every
    /// handle completes.
    pub(in crate::multimmit::marshal) async fn start_pending_seals(
        &mut self,
    ) -> Result<(Vec<u64>, Vec<Handle<()>>), Error> {
        self.pending_blocks
            .as_mut()
            .expect("catalog owns pending blocks")
            .start_seals()
            .await
            .map_err(Error::storage)
    }

    /// Releases pending segments whose durable seal proof landed and returns any segments
    /// reclaimed now that sealing no longer defers them.
    pub(in crate::multimmit::marshal) async fn finish_pending_seals(
        &mut self,
        segments: Vec<u64>,
        pinned: &BTreeSet<u64>,
    ) -> Result<Vec<u64>, Error> {
        self.pending_blocks
            .as_mut()
            .expect("catalog owns pending blocks")
            .finish_seals(segments, pinned)
            .await
            .map_err(Error::storage)
    }

    async fn put_pending_lqc(
        &mut self,
        view: View,
        id: CertificateId<H::Digest>,
        proof: Arc<Lqc<V, H::Digest>>,
    ) -> Result<(), Error> {
        let store = self.pending_lqc.take().expect("catalog owns pending LQCs");
        let (store, _) = store
            .put(view.get(), id.get(), Shared::new(proof))
            .await
            .map_err(Error::storage)?;
        self.pending_lqc = Some(store);
        Ok(())
    }

    async fn put_pending_history(
        &mut self,
        view: View,
        commitment: H::Digest,
        record: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Error> {
        let store = self
            .pending_history
            .take()
            .expect("catalog owns pending history");
        let (store, _) = store
            .put(view.get(), commitment, Shared::new(record))
            .await
            .map_err(Error::storage)?;
        self.pending_history = Some(store);
        Ok(())
    }

    pub(in crate::multimmit::marshal) async fn lqc(
        &self,
        id: CertificateId<H::Digest>,
    ) -> Result<Option<Arc<Lqc<V, H::Digest>>>, Error> {
        if let Some(value) = self
            .final_lqc
            .as_ref()
            .expect("catalog owns finalized LQCs")
            .get_by_key(&id.get())
            .await
            .map_err(Error::storage)?
        {
            return Ok(Some(value.into_inner()));
        }
        self.pending_lqc
            .as_ref()
            .expect("catalog owns pending LQCs")
            .get(&id.get())
            .await
            .map_err(Error::storage)
            .map(|value| value.map(Shared::into_inner))
    }

    pub(in crate::multimmit::marshal) async fn final_lqc(
        &self,
        id: CertificateId<H::Digest>,
    ) -> Result<bool, Error> {
        self.final_lqc
            .as_ref()
            .expect("catalog owns finalized LQCs")
            .get_by_key(&id.get())
            .await
            .map(|proof| proof.is_some())
            .map_err(Error::storage)
    }

    pub(in crate::multimmit::marshal) async fn latest_lqc(
        &self,
    ) -> Result<Option<Arc<Lqc<V, H::Digest>>>, Error> {
        let pending = self
            .pending_lqc
            .as_ref()
            .expect("catalog owns pending LQCs");
        let Some(view) = pending.last_index() else {
            return Ok(None);
        };
        pending
            .get_all(view)
            .await
            .map_err(Error::storage)
            .map(|values| {
                values
                    .and_then(|values| values.into_iter().next())
                    .map(Shared::into_inner)
            })
    }

    pub(in crate::multimmit::marshal) async fn history(
        &self,
        key: H::Digest,
    ) -> Result<Option<Arc<TipRecord<H::Digest>>>, Error> {
        if let Some(value) = self
            .final_history
            .as_ref()
            .expect("catalog owns finalized history")
            .get_by_key(&key)
            .await
            .map_err(Error::storage)?
        {
            return Ok(Some(value.into_inner()));
        }
        self.pending_history
            .as_ref()
            .expect("catalog owns pending history")
            .get(&key)
            .await
            .map_err(Error::storage)
            .map(|value| value.map(Shared::into_inner))
    }

    /// Captures finalized history and its pending fallback at the same owner turn.
    pub(in crate::multimmit::marshal) fn history_read(
        &self,
        commitment: H::Digest,
    ) -> Result<HistoryRead<E, H>, Error> {
        let pending = self
            .pending_history
            .as_ref()
            .expect("catalog owns pending history")
            .read_plan(&commitment)
            .map_err(Error::storage)?;
        let finalized = self
            .final_history
            .as_ref()
            .expect("catalog owns finalized history")
            .read_step(ArchiveReadRequest::Key(commitment))
            .map_err(Error::storage)?;
        Ok(HistoryRead { finalized, pending })
    }

    pub(in crate::multimmit::marshal) fn continue_history_read(
        &self,
        continuation: HistoryReadContinuation<E, H>,
    ) -> Result<HistoryRead<E, H>, Error> {
        let finalized = self
            .final_history
            .as_ref()
            .expect("catalog owns finalized history")
            .read_step(continuation.finalized)
            .map_err(Error::storage)?;
        Ok(HistoryRead {
            finalized,
            pending: continuation.pending,
        })
    }

    pub(in crate::multimmit::marshal) fn body_read_groups(
        &self,
        references: Vec<(usize, BlockRef<H::Digest>)>,
        max_bytes: u64,
        target_groups: NonZeroUsize,
    ) -> Result<Vec<BodyReadGroup<E, H, B>>, Error> {
        self.pending_blocks
            .as_ref()
            .expect("catalog owns pending blocks")
            .body_read_groups(references, max_bytes, target_groups)
            .map_err(Error::storage)
    }

    pub(in crate::multimmit::marshal) fn pending_reference_by_digest(
        &self,
        chain: ChainId,
        digest: H::Digest,
    ) -> Option<BlockRef<H::Digest>> {
        self.pending_blocks
            .as_ref()
            .expect("catalog owns pending blocks")
            .reference_by_digest(chain, digest)
    }

    fn validated_reference(
        &self,
        digest: H::Digest,
        meta: &BlockMeta<H::Digest>,
    ) -> Result<BlockRef<H::Digest>, Error> {
        let epoch = self
            .checkpoint()
            .map(Checkpoint::epoch)
            .ok_or(Error::Invalid("catalog has no checkpoint"))?;
        validated_reference::<H>(meta, digest, epoch, self.chain_count())
            .ok_or_else(|| Error::storage("finalized block reference is invalid"))
    }

    /// Returns a header still covered by pending custody.
    pub(in crate::multimmit::marshal) fn pending_block_header(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Option<TransactionBlockHeader<H::Digest>> {
        self.pending_blocks
            .as_ref()
            .expect("catalog owns pending blocks")
            .header(reference)
    }

    pub(in crate::multimmit::marshal) fn final_block_by_key_read(
        &self,
        digest: H::Digest,
    ) -> Result<FinalBlockReadStep<E, H>, Error> {
        self.final_blocks
            .as_ref()
            .expect("catalog owns finalized block metadata")
            .read_step(ArchiveReadRequest::Key(digest))
            .map_err(Error::storage)
    }

    pub(in crate::multimmit::marshal) fn final_block_at_read(
        &self,
        index: u64,
    ) -> Result<FinalBlockReadStep<E, H>, Error> {
        self.final_blocks
            .as_ref()
            .expect("catalog owns finalized block metadata")
            .read_step(ArchiveReadRequest::Index(index))
            .map_err(Error::storage)
    }

    pub(in crate::multimmit::marshal) fn continue_final_block_read(
        &self,
        request: FinalBlockReadRequest<H>,
    ) -> Result<FinalBlockReadStep<E, H>, Error> {
        self.final_blocks
            .as_ref()
            .expect("catalog owns finalized block metadata")
            .read_step(request)
            .map_err(Error::storage)
    }

    pub(in crate::multimmit::marshal) fn finalized_block_header(
        &self,
        reference: BlockRef<H::Digest>,
        value: Option<(H::Digest, FinalBlockMeta<H::Digest>)>,
    ) -> Result<Option<TransactionBlockHeader<H::Digest>>, Error> {
        let Some((digest, meta)) = value else {
            return Ok(None);
        };
        Ok(
            (self.validated_reference(digest, meta.block())? == reference)
                .then(|| meta.block().header().clone()),
        )
    }

    pub(in crate::multimmit::marshal) fn stored_ref(
        &self,
        index: u64,
        value: Option<(H::Digest, FinalBlockMeta<H::Digest>)>,
    ) -> Result<StoredRef<H::Digest>, Error> {
        let (digest, meta) =
            value.ok_or_else(|| Error::storage("committed output row is missing"))?;
        Ok(StoredRef {
            index: OutputIndex::new(index),
            reference: self.validated_reference(digest, meta.block())?,
            encoded_len: meta.block().encoded_len(),
            generation: meta.generation(),
        })
    }

    /// Returns exact custody metadata without decoding the block body.
    ///
    /// Pending custody remains authoritative until pruning; the finalized archive is the
    /// historical fallback after custody is reclaimed.
    pub(in crate::multimmit::marshal) async fn block_meta(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<BlockMeta<H::Digest>>, Error> {
        if let Some(meta) = self
            .pending_blocks
            .as_ref()
            .expect("catalog owns pending blocks")
            .custody_meta(reference)
        {
            return Ok(Some(meta));
        }
        if let Some(meta) = self
            .final_blocks
            .as_ref()
            .expect("catalog owns finalized block metadata")
            .get_by_key(&reference.digest())
            .await
            .map_err(Error::storage)?
        {
            return Ok(
                (self.validated_reference(reference.digest(), meta.block())? == reference)
                    .then(|| meta.block().clone()),
            );
        }
        Ok(None)
    }

    /// Reclaims immutable-mode temporary bodies covered by a durable promotion cursor.
    ///
    /// Returns the destroyed custody segments so their advisory readers can be released.
    pub(in crate::multimmit::marshal) async fn promoted(
        &mut self,
        frontiers: Vec<BlockRef<H::Digest>>,
        pinned: &BTreeSet<u64>,
    ) -> Result<Vec<u64>, Error> {
        if self.prunable_blocks {
            return Err(Error::Invalid(
                "prunable finalized bodies cannot be promoted away",
            ));
        }
        let emitted = self
            .checkpoint()
            .ok_or(Error::Invalid("catalog has no checkpoint"))?
            .emitted();
        if frontiers.len() != emitted.len()
            || frontiers.iter().zip(emitted).any(|(promoted, emitted)| {
                promoted.chain() != emitted.chain() || promoted.height() > emitted.height()
            })
        {
            return Err(Error::Invalid(
                "promotion frontier is outside the checkpoint",
            ));
        }
        let floors = frontiers
            .into_iter()
            .map(|frontier| Some(Height::new(frontier.height().get().saturating_add(1))))
            .collect::<Vec<_>>();
        self.pending_blocks
            .as_mut()
            .expect("catalog owns pending blocks")
            .prune(&floors, pinned)
            .await
            .map_err(Error::storage)
    }

    #[cfg(test)]
    pub(in crate::multimmit::marshal) async fn publish_commit(
        &mut self,
        batch: Commit<H, V>,
    ) -> Result<(Option<View>, Checkpoint<H::Digest>), Error> {
        let mut publication = self.buffer_commit(batch).await?;
        try_join_all(self.start_finalized_sync(&publication).await?)
            .await
            .map_err(Error::storage)?;
        self.start_sync_publication(&mut publication)
            .await?
            .await
            .map_err(Error::storage)?;
        Ok((publication.cleanup.selected, publication.checkpoint))
    }

    /// Buffers one validated ordinary commit without starting durability or cleanup.
    pub(in crate::multimmit::marshal) async fn buffer_commit(
        &mut self,
        batch: Commit<H, V>,
    ) -> Result<CommitPublication<H::Digest>, Error> {
        let Commit {
            selected,
            history,
            outputs,
            checkpoint,
        } = batch;
        let selected_view = selected.last().map(|selected| selected.view);
        let cleanup_selected = self.accepted_cleanup_selected.max(selected_view);
        let current_lqc_index = self.accepted_lqc_index;
        let mut lqc_index = current_lqc_index;
        for selected in &selected {
            lqc_index = Some(
                next_lqc_index(lqc_index, selected.view)
                    .ok_or(Error::Invalid("finalized LQC index overflow"))?,
            );
        }
        let state = self
            .metadata
            .as_ref()
            .expect("catalog owns metadata")
            .get(&Unit)
            .ok_or(Error::Invalid("catalog has no checkpoint"))?
            .publish_commit(checkpoint.clone(), lqc_index, cleanup_selected)
            .ok_or(Error::Invalid(
                "ordinary commit cannot replace an install intent",
            ))?;
        self.validate_state(&state)?;
        let history_start = if history.is_empty() {
            None
        } else {
            let count = u64::try_from(history.len())
                .map_err(|_| Error::Invalid("history index overflow"))?;
            let last = checkpoint
                .history_index()
                .ok_or(Error::Invalid("history index overflow"))?;
            Some(
                last.checked_sub(count - 1)
                    .ok_or(Error::Invalid("history index overflow"))?,
            )
        };
        let mut lqc = self.final_lqc.take().expect("catalog owns finalized LQCs");
        let mut index = current_lqc_index;
        for selected in selected {
            index = Some(
                next_lqc_index(index, selected.view).expect("finalized LQC range was validated"),
            );
            lqc = lqc
                .put(
                    index.expect("selected LQC has an archive index"),
                    selected.id.get(),
                    Shared::new(selected.proof),
                )
                .await
                .map_err(Error::storage)?;
        }
        let history_touched = !history.is_empty();
        let mut histories = self
            .final_history
            .take()
            .expect("catalog owns finalized history");
        for (offset, opening) in history.into_iter().enumerate() {
            let index = history_start
                .expect("non-empty history has a start index")
                .checked_add(u64::try_from(offset).expect("history length was validated"))
                .expect("history range was validated");
            histories = histories
                .put(index, opening.commitment, Shared::new(opening.record))
                .await
                .map_err(Error::storage)?;
        }
        let blocks_touched = !outputs.is_empty();
        let mut blocks = self
            .final_blocks
            .take()
            .expect("catalog owns finalized blocks");
        let generation = checkpoint.generation();
        for output in outputs {
            let (index, reference, value) = output.into_parts();
            blocks = blocks
                .put(
                    index.get(),
                    reference.digest(),
                    FinalBlockMeta::new(value, generation),
                )
                .await
                .map_err(Error::storage)?;
        }
        self.final_lqc = Some(lqc);
        self.final_history = Some(histories);
        self.final_blocks = Some(blocks);
        self.accepted_lqc_index = lqc_index;
        self.accepted_cleanup_selected = cleanup_selected;
        let cleanup = PendingCleanup {
            selected: state
                .commit_cleanup()
                .expect("ordinary publication carries cleanup"),
        };
        Ok(CommitPublication {
            checkpoint,
            lqc_index,
            cleanup,
            writes: FinalizedWrites {
                lqc: selected_view.is_some(),
                history: history_touched,
                blocks: blocks_touched,
            },
        })
    }

    /// Starts finalized-archive durability for one exact buffered publication.
    pub(in crate::multimmit::marshal) async fn start_finalized_sync(
        &mut self,
        publication: &CommitPublication<H::Digest>,
    ) -> Result<Vec<Handle<()>>, Error> {
        let lqc = self.final_lqc.take().expect("catalog owns finalized LQCs");
        let histories = self
            .final_history
            .take()
            .expect("catalog owns finalized history");
        let blocks = self
            .final_blocks
            .take()
            .expect("catalog owns finalized blocks");
        let writes = &publication.writes;
        let (lqc, histories, blocks) = futures::try_join!(
            async move {
                if writes.lqc {
                    lqc.start_sync()
                        .await
                        .map(|(store, handle)| (store, Some(handle)))
                        .map_err(Error::storage)
                } else {
                    Ok((lqc, None))
                }
            },
            async move {
                if writes.history {
                    histories
                        .start_sync()
                        .await
                        .map(|(store, handle)| (store, Some(handle)))
                        .map_err(Error::storage)
                } else {
                    Ok((histories, None))
                }
            },
            async move {
                if writes.blocks {
                    blocks
                        .start_sync()
                        .await
                        .map(|(store, handle)| (store, Some(handle)))
                        .map_err(Error::storage)
                } else {
                    Ok((blocks, None))
                }
            },
        )?;
        self.final_lqc = Some(lqc.0);
        self.final_history = Some(histories.0);
        self.final_blocks = Some(blocks.0);
        let mut handles = Vec::with_capacity(3);
        handles.extend(lqc.1);
        handles.extend(histories.1);
        handles.extend(blocks.1);
        Ok(handles)
    }

    /// Starts checkpoint-last metadata durability for an archive-durable publication.
    pub(in crate::multimmit::marshal) async fn start_sync_publication(
        &mut self,
        publication: &mut CommitPublication<H::Digest>,
    ) -> Result<Handle<()>, Error> {
        let current = self
            .metadata
            .as_ref()
            .expect("catalog owns metadata")
            .get(&Unit)
            .ok_or(Error::Invalid("catalog has no checkpoint"))?;
        if !publication
            .checkpoint
            .preserve_acknowledged(current.checkpoint().acknowledged())
        {
            return Err(Error::Invalid(
                "ordering publication regressed below acknowledged delivery",
            ));
        }
        let state = current
            .publish_commit(
                publication.checkpoint.clone(),
                publication.lqc_index,
                publication.cleanup.selected,
            )
            .ok_or(Error::Invalid(
                "ordinary commit cannot replace an install intent",
            ))?;
        self.start_sync_state(state).await
    }

    /// Completes checkpoint-last cleanup interrupted after an ordinary commit was published.
    pub(in crate::multimmit::marshal) async fn recover_commit(&mut self) -> Result<(), Error> {
        let Some(selected) = self
            .metadata
            .as_ref()
            .expect("catalog owns metadata")
            .get(&Unit)
            .and_then(CatalogState::commit_cleanup)
        else {
            return Ok(());
        };
        self.cleanup_pending(PendingCleanup { selected }).await
    }

    /// Completes one coalesced ordinary pending-store cleanup obligation.
    pub(in crate::multimmit::marshal) async fn cleanup_pending(
        &mut self,
        cleanup: PendingCleanup,
    ) -> Result<(), Error> {
        let PendingCleanup { selected } = cleanup;
        let lqc = self.pending_lqc.take().expect("catalog owns pending LQCs");
        let history = self
            .pending_history
            .take()
            .expect("catalog owns pending history");
        let (lqc, history) = futures::try_join!(
            async move {
                match selected {
                    Some(selected) => lqc
                        .prune(selected.get().saturating_add(1))
                        .await
                        .map_err(Error::storage),
                    None => Ok(lqc),
                }
            },
            async move {
                match selected {
                    Some(view) => history
                        .prune(view.get().saturating_add(1))
                        .await
                        .map_err(Error::storage),
                    None => Ok(history),
                }
            },
        )?;
        self.pending_lqc = Some(lqc);
        self.pending_history = Some(history);
        Ok(())
    }

    /// Prunes acknowledged finalized data and returns destroyed temporary custody segments.
    pub(in crate::multimmit::marshal) async fn prune_finalized(
        &mut self,
        generation: u64,
        acknowledged: Option<OutputIndex>,
        pinned: &BTreeSet<u64>,
    ) -> Result<Vec<u64>, Error> {
        let checkpoint = self
            .checkpoint()
            .filter(|checkpoint| checkpoint.generation() == generation)
            .cloned()
            .ok_or(Error::Invalid("prune generation is not current"))?;
        let (floor, lqc_index) = self
            .metadata
            .as_ref()
            .expect("catalog owns metadata")
            .get(&Unit)
            .map(|state| (state.checkpoint().floor(), state.lqc_index()))
            .ok_or(Error::Invalid("catalog has no checkpoint"))?;
        let floor = self
            .final_lqc
            .as_ref()
            .expect("catalog owns finalized LQCs")
            .get_by_key(&floor.get())
            .await
            .map_err(Error::storage)?;
        let floor = match (floor, lqc_index) {
            (Some(_), Some(index)) => index,
            (None, None) if checkpoint.history_index().is_none() => 0,
            _ => {
                return Err(Error::storage("checkpoint floor LQC is missing"));
            }
        };
        let history = checkpoint.history_index().unwrap_or(0);
        let output = acknowledged.map_or(OutputIndex::ZERO, |index| index.next().unwrap_or(index));

        let blocks = self
            .final_blocks
            .as_ref()
            .expect("catalog owns finalized blocks");
        let reclaimed = if self.prunable_blocks {
            let mut floors: Vec<Option<Height>> = vec![None; self.chain_count()];
            if let (Some(first), Some(acknowledged)) = (blocks.first_index(), acknowledged) {
                for index in first..=acknowledged.get() {
                    let Some((digest, row)) = blocks.get_at(index).await.map_err(Error::storage)?
                    else {
                        return Err(Error::storage("finalized block row is missing"));
                    };
                    let reference = self.validated_reference(digest, row.block())?;
                    let floor = &mut floors[reference.chain().get() as usize];
                    *floor = Some((*floor).map_or(reference.height(), |current| {
                        current.max(reference.height())
                    }));
                }
            }

            for floor in floors.iter_mut().flatten() {
                *floor = Height::new(floor.get().saturating_add(1));
            }
            // An unchanged floor still reclaims segments retained by an earlier materialization
            // pin, so every application prune reaches pending custody.
            self.pending_blocks
                .as_mut()
                .expect("catalog owns pending blocks")
                .prune(&floors, pinned)
                .await
                .map_err(Error::storage)?
        } else {
            Vec::new()
        };

        let lqc = self.final_lqc.take().expect("catalog owns finalized LQCs");
        let histories = self
            .final_history
            .take()
            .expect("catalog owns finalized history");
        let blocks = self
            .final_blocks
            .take()
            .expect("catalog owns finalized blocks");
        let (lqc, histories, blocks) = futures::try_join!(
            async move { lqc.prune(floor).await.map_err(Error::storage) },
            async move { histories.prune(history).await.map_err(Error::storage) },
            async move { blocks.prune(output.get()).await.map_err(Error::storage) },
        )?;
        self.final_lqc = Some(lqc);
        self.final_history = Some(histories);
        self.final_blocks = Some(blocks);
        Ok(reclaimed)
    }

    /// Completes every durably started floor installation before catalog reads become available.
    pub(in crate::multimmit::marshal) async fn recover_install(&mut self) -> Result<(), Error> {
        let Some(checkpoint) = self
            .metadata
            .as_ref()
            .expect("catalog owns metadata")
            .get(&Unit)
            .and_then(CatalogState::install_checkpoint)
            .cloned()
        else {
            return Ok(());
        };
        let (proof, history) = self.install_artifacts(&checkpoint)?;
        self.archive_install(&checkpoint, proof, history).await?;
        self.finish_install().await
    }

    pub(in crate::multimmit::marshal) async fn install(
        &mut self,
        checkpoint: Checkpoint<H::Digest>,
        prune: Prune,
        proof: Arc<Lqc<V, H::Digest>>,
        history: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Error> {
        self.begin_install(
            checkpoint.clone(),
            proof.view(),
            prune,
            proof.encode(),
            history.encode(),
        )
        .await?;
        self.archive_install(&checkpoint, proof, history).await?;
        self.finish_install().await
    }

    pub(in crate::multimmit::marshal) async fn begin_install(
        &mut self,
        checkpoint: Checkpoint<H::Digest>,
        proof_view: View,
        prune: Prune,
        proof: bytes::Bytes,
        history: bytes::Bytes,
    ) -> Result<(), Error> {
        let state = self
            .metadata
            .as_ref()
            .expect("catalog owns metadata")
            .get(&Unit)
            .ok_or(Error::Invalid("catalog has no checkpoint"))?
            .begin(checkpoint, proof_view, prune, proof, history)
            .ok_or(Error::Invalid("floor install intent is not canonical"))?;
        self.sync_state(state).await
    }

    pub(in crate::multimmit::marshal) async fn archive_install(
        &mut self,
        checkpoint: &Checkpoint<H::Digest>,
        proof: Arc<Lqc<V, H::Digest>>,
        history: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Error> {
        let lqc_index = self
            .metadata
            .as_ref()
            .expect("catalog owns metadata")
            .get(&Unit)
            .filter(|state| state.install_checkpoint().is_some())
            .and_then(CatalogState::lqc_index)
            .ok_or(Error::storage("floor install LQC index is missing"))?;
        let history_index = checkpoint
            .history_index()
            .expect("installed floor has a finalized history row");
        let lqc = self.final_lqc.take().expect("catalog owns finalized LQCs");
        let histories = self
            .final_history
            .take()
            .expect("catalog owns finalized history");
        let (lqc, histories) = futures::try_join!(
            async move {
                lqc.put(lqc_index, proof.id::<H>().get(), Shared::new(proof))
                    .await
                    .map_err(Error::storage)?
                    .sync()
                    .await
                    .map_err(Error::storage)
            },
            async move {
                histories
                    .put(
                        history_index,
                        history.commitment::<H>(),
                        Shared::new(history),
                    )
                    .await
                    .map_err(Error::storage)?
                    .sync()
                    .await
                    .map_err(Error::storage)
            },
        )?;
        self.final_lqc = Some(lqc);
        self.final_history = Some(histories);
        Ok(())
    }

    pub(in crate::multimmit::marshal) async fn finish_install(&mut self) -> Result<(), Error> {
        let (prune, state) = {
            let state = self
                .metadata
                .as_ref()
                .expect("catalog owns metadata")
                .get(&Unit)
                .ok_or(Error::Invalid("catalog has no checkpoint"))?;
            let prune = state
                .install_prune()
                .cloned()
                .ok_or(Error::Invalid("floor install is not prepared"))?;
            let ready = state.finish().expect("prepared install has a ready state");
            (prune, ready)
        };
        self.prune_install(prune).await?;
        let lqc_index = state.lqc_index();
        self.sync_state(state).await?;
        self.accepted_lqc_index = lqc_index;
        self.accepted_cleanup_selected = None;
        Ok(())
    }

    fn install_artifacts(
        &self,
        checkpoint: &Checkpoint<H::Digest>,
    ) -> Result<InstallArtifacts<V, H>, Error> {
        let state = self
            .metadata
            .as_ref()
            .expect("catalog owns metadata")
            .get(&Unit)
            .ok_or(Error::storage("floor install intent is missing"))?;
        let proof = state
            .install_proof()
            .ok_or(Error::storage("floor install proof is missing"))?
            .clone();
        let history = state
            .install_history()
            .ok_or(Error::storage("floor install history is missing"))?
            .clone();
        let proof = Arc::new(
            Lqc::<V, H::Digest>::decode_cfg(proof, &self.codec_config).map_err(Error::storage)?,
        );
        let history = Arc::new(
            TipRecord::<H::Digest>::decode_cfg(history, &self.chain_count())
                .map_err(Error::storage)?,
        );
        self.validate_install_artifacts(checkpoint, Some(proof), Some(history))
    }

    fn validate_install_artifacts(
        &self,
        checkpoint: &Checkpoint<H::Digest>,
        proof: Option<Arc<Lqc<V, H::Digest>>>,
        history: Option<Arc<TipRecord<H::Digest>>>,
    ) -> Result<InstallArtifacts<V, H>, Error> {
        let (Some(proof), Some(history)) = (proof, history) else {
            return Err(Error::storage("floor install artifacts are missing"));
        };
        if proof.id::<H>() != checkpoint.floor()
            || proof.epoch() != checkpoint.epoch()
            || proof.leader().history() != checkpoint.history()
            || history.commitment::<H>() != checkpoint.history()
        {
            return Err(Error::storage(
                "floor install artifacts do not establish checkpoint",
            ));
        }
        Ok((proof, history))
    }

    async fn prune_install(&mut self, prune: Prune) -> Result<(), Error> {
        let retained = if self.prunable_blocks {
            let emitted = self
                .checkpoint()
                .expect("floor installation has a current checkpoint")
                .emitted()
                .to_vec();
            let blocks = self
                .final_blocks
                .as_ref()
                .expect("catalog owns finalized blocks");
            try_join_all(emitted.into_iter().map(|reference| async move {
                match blocks
                    .get_by_key(&reference.digest())
                    .await
                    .map_err(Error::storage)?
                {
                    Some(_) => Ok(true),
                    None => Ok(false),
                }
            }))
            .await?
        } else {
            // Immutable promotion may still be copying a pre-install output. Retaining custody is
            // safe across every crash cut; the durable promotion cursor reclaims it after restart.
            vec![true; self.chain_count()]
        };
        let pending_lqc = self.pending_lqc.take().expect("catalog owns pending LQCs");
        let pending_history = self
            .pending_history
            .take()
            .expect("catalog owns pending history");
        let pending_floors = prune.pending_blocks;
        let block_floors = pending_floors
            .into_iter()
            .zip(retained)
            .map(|(floor, retained)| (!retained).then_some(floor))
            .collect::<Vec<_>>();
        let pending_blocks = self
            .pending_blocks
            .take()
            .expect("catalog owns pending blocks");
        let (pending_lqc, pending_history, pending_blocks) = futures::try_join!(
            async move {
                pending_lqc
                    .prune(prune.pending_lqc.get())
                    .await
                    .map_err(Error::storage)
            },
            async move {
                pending_history
                    .prune(prune.pending_history.get())
                    .await
                    .map_err(Error::storage)
            },
            async move {
                let mut pending_blocks = pending_blocks;
                pending_blocks
                    .prune(&block_floors, &BTreeSet::new())
                    .await
                    .map_err(Error::storage)?;
                Ok::<_, Error>(pending_blocks)
            },
        )?;
        self.pending_lqc = Some(pending_lqc);
        self.pending_history = Some(pending_history);
        self.pending_blocks = Some(pending_blocks);
        Ok(())
    }
}
