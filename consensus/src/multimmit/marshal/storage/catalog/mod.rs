//! Mutable archive state owned by the catalog actor.
//!
//! Finalized block rows hold compact metadata and point at bodies kept in pending custody. In
//! immutable mode the promoter copies those bodies into a write-once archive and advances its
//! durable cursor before the catalog reclaims pending copies. Every archive a commit touches is
//! durable before the checkpoint naming it, so recovery can trust every referenced body.
//!
//! # Commit
//!
//! 1. [`CatalogStore::buffer_commit`] validates the commit against the current record and buffers
//!    its finalized L-QC, history, and output rows.
//! 2. [`CatalogStore::start_finalized_sync`] makes the touched finalized archives durable.
//! 3. [`CatalogStore::start_sync_publication`] publishes the checkpoint with a commit-cleanup
//!    obligation.
//! 4. [`CatalogStore::cleanup_pending`] prunes pending L-QCs and history at or below the selected
//!    view. [`CatalogStore::recover_commit`] replays the obligation if this step was interrupted.
//!
//! # Install
//!
//! 1. Begin: durably record the target checkpoint, pending floors, and encoded artifacts as an
//!    install intent while the current checkpoint stays visible.
//! 2. Archive: make the floor L-QC and history opening durable in the finalized archives.
//! 3. Finish: apply the pending floors, then publish the target checkpoint.
//!
//! [`CatalogStore::open`] leaves an interrupted installation pending, because its target
//! checkpoint is the cut the delivery cursor is opened against. [`CatalogStore::recover_install`]
//! then completes it from its recorded artifacts.

mod admission;
mod commit;
mod install;
mod prune;
mod reads;
#[cfg(test)]
mod tests;

use super::{
    Error,
    archive::{
        FinalBlockRows, FinalHistory, FinalLqc, FinalizedArchive, PendingHistory, PendingLqc,
    },
    blocks::BlockMeta,
    catalog_state::{
        CatalogState, Checkpoint, CheckpointCodecConfig, CheckpointParts, CommitCleanup,
        PendingFloors,
    },
    commit::OutputRow,
    pending::{JournalBuffers, PendingBlocks, PendingConfig, Retirement},
    record::DurableRecord,
};
use crate::{
    multimmit::{
        marshal::{
            config::{ArchiveConfig, ArchiveMode, Config, Retention, Start},
            types::{Families, OutputIndex},
        },
        types::{
            BlockRef, Body, CertificateId, CodecConfig, Lqc, TipRecord, TransactionBlock,
            genesis_history,
        },
    },
    types::{Height, View},
};
pub(crate) use admission::{AdmissionFuture, AdmissionWrite};
use commonware_codec::{CodecShared, EncodeSize as _};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::Handle;
use commonware_storage::{Context, archive::prunable, translator::Translator};
use commonware_utils::Array;
pub(crate) use install::InstallRequest;
use std::{collections::BTreeSet, future::Future, sync::Arc};

/// A committed output row resolved to its block reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoredRef<D: Digest> {
    /// Dense output index of the row.
    pub(crate) index: OutputIndex,
    /// Block committed at the row.
    pub(crate) reference: BlockRef<D>,
    /// Encoded length of the complete block.
    pub(crate) encoded_len: u64,
    /// Floor generation that committed the row.
    pub(crate) floor_generation: u64,
}

impl<D: Digest> StoredRef<D> {
    /// Returns the stored form of an output row committed by `floor_generation`.
    pub(crate) const fn new(row: &OutputRow<D>, floor_generation: u64) -> Self {
        Self {
            index: row.index,
            reference: row.reference(),
            encoded_len: row.meta().encoded_len(),
            floor_generation,
        }
    }

    /// Returns whether `block` is the block this row committed.
    ///
    /// The reference digest authenticates the header, so matching the reference and encoded
    /// length matches the block.
    pub(crate) fn matches<H, B>(&self, block: &TransactionBlock<H, B>) -> bool
    where
        H: Hasher<Digest = D>,
        B: Body<H>,
    {
        block.reference() == self.reference
            && u64::try_from(block.encode_size()).is_ok_and(|len| len == self.encoded_len)
    }
}

/// One unfinalized artifact admitted into pending storage.
pub(crate) enum Admission<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// An L-QC for `view` with certificate identity `id`.
    Lqc(View, CertificateId<H::Digest>, Arc<Lqc<V, H::Digest>>),
    /// A tip-history opening committed by the leader of `view`, keyed by its commitment.
    History(View, H::Digest, Arc<TipRecord<H::Digest>>),
    /// A complete producer block.
    Block(BlockRef<H::Digest>, Arc<TransactionBlock<H, B>>),
}

/// An admission and whether its caller waits for it to become durable.
pub(crate) struct StagedAdmission<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// The admitted artifact.
    pub(crate) admission: Admission<H, V, B>,
    /// Whether the admission belongs in the next durability cut. Blocks always do.
    pub(crate) durable: bool,
}

/// The families an admission cut or commit wrote and must make durable.
pub(crate) type Footprint = Families<bool>;

/// One finalized-archive cut awaiting checkpoint-last publication.
pub(crate) struct CommitPublication<D: Digest> {
    /// Checkpoint published by the commit.
    pub(crate) checkpoint: Checkpoint<D>,
    /// Finalized L-QC high-water mark attached to the checkpoint.
    pub(crate) lqc_index: Option<u64>,
    /// Pending-archive cleanup owed once the checkpoint is published.
    pub(crate) cleanup: CommitCleanup,
    /// Finalized archives the commit wrote.
    pub(crate) touched: Footprint,
}

/// A store handle that consuming mutations take for their duration.
///
/// A failed or canceled mutation leaves the slot empty, and every later access returns
/// [`Error::Poisoned`].
struct Owned<T>(Option<T>);

impl<T> Owned<T> {
    const fn new(value: T) -> Self {
        Self(Some(value))
    }

    fn get(&self) -> Result<&T, Error> {
        self.0.as_ref().ok_or(Error::Poisoned)
    }

    fn take(&mut self) -> Result<T, Error> {
        self.0.take().ok_or(Error::Poisoned)
    }

    fn restore(&mut self, value: T) {
        self.0 = Some(value);
    }
}

/// Archives whose buffered writes can start durability in the background.
trait StartSync: Sized + Send {
    /// Starts durability for buffered writes and returns the archive with the sync handle.
    fn start_sync(self) -> impl Future<Output = Result<(Self, Handle<()>), Error>> + Send;
}

impl<T, E, K, V> StartSync for prunable::Archive<T, E, K, V>
where
    T: Translator,
    E: Context,
    K: Array,
    V: CodecShared,
{
    async fn start_sync(self) -> Result<(Self, Handle<()>), Error> {
        Ok(commonware_storage::archive::Archive::start_sync(self).await?)
    }
}

impl<T, E, K, V> StartSync for FinalizedArchive<T, E, K, V>
where
    T: Translator,
    E: Context,
    K: Array,
    V: CodecShared,
{
    async fn start_sync(self) -> Result<(Self, Handle<()>), Error> {
        Self::start_sync(self).await
    }
}

/// Starts durability for `store` when `on`, returning it with any sync handle.
async fn start_sync_if<S: StartSync>(store: S, on: bool) -> Result<(S, Option<Handle<()>>), Error> {
    if !on {
        return Ok((store, None));
    }
    let (store, handle) = store.start_sync().await?;
    Ok((store, Some(handle)))
}

/// Opens one finalized archive with the backend `mode` selects.
async fn open_finalized<T, E, K, V>(
    context: E,
    mode: ArchiveMode,
    archive: &ArchiveConfig<T>,
    prefix: String,
    codec: V::Cfg,
) -> Result<FinalizedArchive<T, E, K, V>, Error>
where
    T: Translator,
    E: Context,
    K: Array,
    V: CodecShared,
{
    match mode {
        ArchiveMode::Prunable => {
            FinalizedArchive::init_prunable(context, archive.prunable(prefix, codec)).await
        }
        ArchiveMode::Immutable => {
            FinalizedArchive::init_immutable(context, archive.immutable(prefix, codec)).await
        }
    }
}

/// Exclusive mutable archive state owned by the catalog actor.
pub(crate) struct CatalogStore<T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    final_lqc: Owned<FinalLqc<T, E, H, V>>,
    final_history: Owned<FinalHistory<T, E, H>>,
    final_blocks: Owned<FinalBlockRows<T, E, H>>,
    pending_lqc: Owned<PendingLqc<T, E, H, V>>,
    pending_history: Owned<PendingHistory<T, E, H>>,
    pending_blocks: PendingBlocks<E, H, B>,
    record: DurableRecord<E, CatalogState<H::Digest>>,
    /// The value last handed to `record`, whose durability may still be in flight.
    state: CatalogState<H::Digest>,
    /// L-QC high-water mark of the latest buffered commit or installation. It leads the
    /// published value while commits are pipelined.
    accepted_lqc_index: Option<u64>,
    /// Highest finalized L-QC ordinal allocated, including ordinals written by a commit whose
    /// checkpoint is not yet published.
    allocated_lqc_index: Option<u64>,
    /// Cleanup owed by buffered commits since the last installation, before coalescing with the
    /// published record's obligation.
    accepted_cleanup: CommitCleanup,
    /// Whether finalized block rows retain their bodies in pending custody until application
    /// pruning, rather than in the immutable body archive.
    prunable_blocks: bool,
    codec_config: CodecConfig,
}

impl<T, E, H, V, B> CatalogStore<T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    B::Cfg: Clone,
{
    /// Opens every catalog-owned store under `context` and seeds a fresh namespace from
    /// `config.start`.
    ///
    /// A fresh floor start runs the installation protocol, so a crash during seeding recovers
    /// like any other interrupted installation. An interrupted installation or commit cleanup is
    /// left for [`Self::recover_install`] and [`Self::recover_commit`].
    pub(crate) async fn open(context: &E, config: &Config<T, V, B>) -> Result<Self, Error> {
        let name = |suffix: &str| format!("{}_{suffix}", config.partition_prefix);
        let chains = config.chains();
        let layout = config.retention;
        let final_lqc = open_finalized(
            context.child("final_lqc"),
            layout.lqc,
            &config.archive,
            name("final_lqc"),
            config.codec_config,
        )
        .await?;
        let final_history = open_finalized(
            context.child("final_history"),
            layout.history,
            &config.archive,
            name("final_history"),
            config.codec_config,
        )
        .await?;
        let final_blocks = open_finalized(
            context.child("final_blocks"),
            layout.blocks,
            &config.archive,
            name("final_block_rows"),
            (),
        )
        .await?;
        let pending_lqc = prunable::Archive::init(
            context.child("pending_lqc"),
            config
                .archive
                .prunable(name("pending_lqc"), config.codec_config),
        )
        .await?;
        let pending_history = prunable::Archive::init(
            context.child("pending_history"),
            config
                .archive
                .prunable(name("pending_history"), config.codec_config),
        )
        .await?;
        let record: DurableRecord<E, CatalogState<H::Digest>> = DurableRecord::init(
            context.child("checkpoint"),
            name("checkpoint"),
            CheckpointCodecConfig::new(
                config.epoch(),
                chains,
                config.limits.max_checkpoint_bytes.get(),
            ),
            Some(config.limits.max_checkpoint_bytes),
        )
        .await?;
        let recovered = record.get()?.cloned();
        if recovered
            .as_ref()
            .is_some_and(|state| state.checkpoint().archive_layout() != layout)
        {
            return Err(Error::Invalid(
                "finalized archive modes do not match the existing namespace",
            ));
        }
        let fresh = recovered.is_none();
        let state = match recovered {
            Some(state) => state,
            None => CatalogState::ready(Self::start_checkpoint(config, layout)?, None),
        };
        if fresh && matches!(config.start, Start::Genesis(_)) && !record.fits(&state) {
            return Err(Error::Invalid(
                "initial catalog state exceeds max_checkpoint_bytes",
            ));
        }
        let pending_blocks = PendingBlocks::init(
            context.child("pending_blocks"),
            PendingConfig {
                prefix: name("pending_blocks"),
                buffers: JournalBuffers {
                    page_cache: config.archive.page_cache.clone(),
                    key_write_buffer: config.archive.key_write_buffer,
                    value_write_buffer: config.archive.value_write_buffer,
                    replay_buffer: config.archive.replay_buffer,
                },
                body_codec_config: config.body_codec_config.clone(),
                epoch: config.epoch(),
                chains,
                segment_capacity: config.capacities.pending_segment_items,
                max_manifest_bytes: config.limits.max_checkpoint_bytes,
            },
        )
        .await?;
        if state.checkpoint().chains() != pending_blocks.chain_count() {
            return Err(Error::Invalid(
                "checkpoint and block-store chain counts differ",
            ));
        }
        let accepted_lqc_index = state.lqc_index();
        let mut store = Self {
            allocated_lqc_index: accepted_lqc_index.max(final_lqc.last_index()),
            final_lqc: Owned::new(final_lqc),
            final_history: Owned::new(final_history),
            final_blocks: Owned::new(final_blocks),
            pending_lqc: Owned::new(pending_lqc),
            pending_history: Owned::new(pending_history),
            pending_blocks,
            record,
            accepted_lqc_index,
            accepted_cleanup: state.commit_cleanup().unwrap_or_default(),
            state,
            prunable_blocks: layout.blocks == ArchiveMode::Prunable,
            codec_config: config.codec_config,
        };
        if fresh {
            store.seed(config).await?;
        }
        Ok(store)
    }

    /// Returns the checkpoint a fresh namespace starts from: genesis, or the parent of a floor.
    fn start_checkpoint(
        config: &Config<T, V, B>,
        archive_layout: Retention,
    ) -> Result<Checkpoint<H::Digest>, Error> {
        let parts = match &config.start {
            Start::Genesis(genesis) => CheckpointParts {
                epoch: config.epoch(),
                floor_generation: 0,
                archive_layout,
                floor: genesis.lqc(),
                history: genesis_history::<H>(genesis),
                history_index: None,
                ordered: genesis.tips().to_vec(),
                emitted: genesis.tips().to_vec(),
                committed: None,
            },
            // A floor start installs the floor over its own parent, so the target checkpoint
            // stays hidden behind an install intent until its artifacts are archived.
            Start::Floor {
                floor_generation,
                floor,
            } => CheckpointParts {
                epoch: config.epoch(),
                floor_generation: floor_generation.checked_sub(1).ok_or(Error::Invalid(
                    "state-sync floor generation must be positive",
                ))?,
                archive_layout,
                floor: floor.anchor().leader().parent(),
                history: floor.history().parent(),
                history_index: None,
                ordered: floor.history().tips().to_vec(),
                emitted: floor.history().tips().to_vec(),
                committed: None,
            },
        };
        Checkpoint::try_from(parts).map_err(|_| Error::Invalid("startup frontier is not canonical"))
    }

    /// Makes a fresh namespace's first record durable.
    async fn seed(&mut self, config: &Config<T, V, B>) -> Result<(), Error> {
        let (floor_generation, floor) = match &config.start {
            Start::Genesis(_) => return self.sync_state(self.state.clone()).await,
            Start::Floor {
                floor_generation,
                floor,
            } => (*floor_generation, floor),
        };
        let proof = floor.anchor();
        let history = floor.history();
        let commitment = history.commitment::<H>();
        if proof.leader().history() != commitment {
            return Err(Error::Invalid(
                "state-sync floor proof does not commit to its history",
            ));
        }
        let target = Checkpoint::try_from(CheckpointParts {
            epoch: config.epoch(),
            floor_generation,
            archive_layout: self.state.checkpoint().archive_layout(),
            floor: proof.id::<H>(),
            history: commitment,
            history_index: Some(0),
            ordered: history.tips().to_vec(),
            emitted: floor.emitted().to_vec(),
            committed: None,
        })
        .map_err(|_| Error::Invalid("startup frontier is not canonical"))?;
        let floors = PendingFloors {
            lqc: View::new(0),
            history: View::new(0),
            blocks: vec![Height::zero(); target.chains()],
        };
        self.install(InstallRequest {
            checkpoint: target,
            floors,
            proof: Arc::clone(&floor.anchor),
            history: Arc::clone(&floor.history),
        })
        .await
    }

    /// Returns the catalog record last handed to storage.
    pub(crate) const fn state(&self) -> &CatalogState<H::Digest> {
        &self.state
    }

    /// Returns the checkpoint visible to ordinary catalog operations.
    pub(crate) const fn checkpoint(&self) -> &Checkpoint<H::Digest> {
        self.state.checkpoint()
    }

    /// Returns pending custody.
    pub(crate) const fn pending(&self) -> &PendingBlocks<E, H, B> {
        &self.pending_blocks
    }

    /// Starts persisting recovery markers for full pending segments; see
    /// [`PendingBlocks::start_retire`].
    pub(crate) fn start_retire(&mut self) -> Result<Option<Retirement>, Error> {
        self.pending_blocks.start_retire()
    }

    /// Reclaims retired pending segments outside `pinned`; see [`PendingBlocks::finish_retire`].
    pub(crate) async fn finish_retire(
        &mut self,
        segments: Vec<u64>,
        pinned: &BTreeSet<u64>,
    ) -> Result<Vec<u64>, Error> {
        self.pending_blocks.finish_retire(segments, pinned).await
    }

    /// Rejects a record that exceeds the configured metadata bound before anything changes.
    fn check_state(&self, state: &CatalogState<H::Digest>) -> Result<(), Error> {
        if self.record.fits(state) {
            Ok(())
        } else {
            Err(Error::Invalid(
                "catalog state exceeds configured metadata bound",
            ))
        }
    }

    async fn sync_state(&mut self, state: CatalogState<H::Digest>) -> Result<(), Error> {
        self.check_state(&state)?;
        self.record.put_sync(state.clone()).await?;
        self.state = state;
        Ok(())
    }

    async fn start_sync_state(
        &mut self,
        state: CatalogState<H::Digest>,
    ) -> Result<Handle<()>, Error> {
        self.check_state(&state)?;
        let sync = self.record.put_start_sync(state.clone()).await?;
        self.state = state;
        Ok(sync)
    }

    /// Authenticates finalized row metadata against its archive key and the namespace.
    fn authenticate(
        &self,
        digest: H::Digest,
        meta: &BlockMeta<H::Digest>,
    ) -> Result<BlockRef<H::Digest>, Error> {
        meta.authenticate::<H>(
            digest,
            self.checkpoint().epoch(),
            self.pending_blocks.chain_count(),
        )
        .ok_or(Error::Inconsistent("finalized block reference is invalid"))
    }
}
