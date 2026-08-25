//! Configuration and storage construction for Multimmit marshal.

use super::{
    actors::{
        catalog::{self, CatalogClient, Shared},
        delivery::DeliveryClient,
        promoter, synchronizer,
    },
    storage::{
        archive::FinalizedArchive,
        blocks::FinalBlock,
        checkpoint::{ArchiveLayout, CatalogState, Checkpoint, CheckpointCodecConfig, Prune},
        pending::PendingBlocks,
        promotion::{FinalBody, PromotionState, Store as PromotionStore},
        temporary::TemporaryArchive,
    },
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        config::CodecConfig,
        types::{BlockRef, EpochGenesis, Height, Lqc, TipRecord, genesis_history},
    },
    types::{Epoch, View},
};
use commonware_codec::{Codec, CodecShared, Encode as _};
use commonware_cryptography::{Digest, Digestible, Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::{Clock, Handle, Spawner, buffer::paged::CacheRef};
use commonware_storage::{
    Context,
    archive::{immutable, prunable},
    journal::segmented::variable,
    metadata::{self, Metadata},
    translator::Translator,
};
use commonware_utils::{Array, NZU64, NZUsize, sequence::Unit};
use std::{
    future::Future,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::Arc,
};

const DEFAULT_BACKFILL_CONCURRENCY: NonZeroUsize = NZUsize!(512);
const DEFAULT_MAX_BACKFILL_BYTES: NonZeroUsize = NZUsize!(256 * 1024 * 1024);
const DEFAULT_HEADER_CACHE_CAPACITY: NonZeroUsize = NZUsize!(16 * 1024);
const DEFAULT_MAX_COMMIT_BLOCK_BYTES: NonZeroUsize = NZUsize!(256 * 1024 * 1024);
const DEFAULT_MAX_PENDING_ACKS: NonZeroUsize = NZUsize!(128);
const DEFAULT_MAX_DELIVERY_BYTES: NonZeroUsize = NZUsize!(16 * 1024 * 1024);
const DEFAULT_MAX_HOT_BLOCK_BYTES: NonZeroUsize = NZUsize!(512 * 1024 * 1024);
const DEFAULT_MAX_MATERIALIZED_BLOCK_BYTES: NonZeroUsize = NZUsize!(512 * 1024 * 1024);

type Spawned<H, V, B> = (
    CatalogClient<H, V, B>,
    Handle<Result<(), catalog::Error>>,
    Option<promoter::Client<H, B>>,
    Option<Handle<Result<(), promoter::Error>>>,
);

/// Storage backend used for one finalized artifact family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveMode {
    /// Retain data only until marshal installs a newer authorized floor.
    Prunable,
    /// Retain data for the lifetime of the namespace.
    Immutable,
}

/// Shared inputs used to derive exclusive archive partitions.
#[derive(Clone)]
pub struct ArchiveConfig<T: Translator> {
    /// Key translator used by every prunable archive.
    pub translator: T,
    /// Shared cache used by archive key journals.
    pub page_cache: CacheRef,
    /// Rows in each independently prunable section.
    pub items_per_section: NonZeroU64,
    /// Bytes buffered while replaying archive journals.
    pub replay_buffer: NonZeroUsize,
    /// Bytes buffered by key and ordinal journals.
    pub key_write_buffer: NonZeroUsize,
    /// Bytes buffered by value journals.
    pub value_write_buffer: NonZeroUsize,
}

impl<T: Translator> ArchiveConfig<T> {
    /// Constructs archive inputs with general-purpose defaults.
    pub const fn new(translator: T, page_cache: CacheRef) -> Self {
        Self {
            translator,
            page_cache,
            items_per_section: NZU64!(1024),
            replay_buffer: NZUsize!(1024 * 1024),
            key_write_buffer: NZUsize!(1024 * 1024),
            value_write_buffer: NZUsize!(1024 * 1024),
        }
    }

    pub(super) fn prunable<C>(&self, prefix: String, codec_config: C) -> prunable::Config<T, C> {
        prunable::Config {
            translator: self.translator.clone(),
            key_partition: format!("{prefix}_key"),
            key_page_cache: self.page_cache.clone(),
            value_partition: format!("{prefix}_value"),
            compression: None,
            codec_config,
            items_per_section: self.items_per_section,
            key_write_buffer: self.key_write_buffer,
            value_write_buffer: self.value_write_buffer,
            replay_buffer: self.replay_buffer,
        }
    }

    pub(super) fn scratch<C>(&self, partition: String, codec_config: C) -> variable::Config<C> {
        variable::Config {
            partition,
            compression: None,
            codec_config,
            page_cache: self.page_cache.clone(),
            write_buffer: self.value_write_buffer,
        }
    }

    fn immutable<C>(&self, prefix: String, codec_config: C) -> immutable::Config<C> {
        immutable::Config {
            metadata_partition: format!("{prefix}_metadata"),
            freezer_table_partition: format!("{prefix}_table"),
            freezer_table_initial_size: 65_536,
            freezer_table_resize_frequency: 4,
            freezer_table_resize_chunk_size: 16_384,
            freezer_key_partition: format!("{prefix}_freezer_key"),
            freezer_key_page_cache: self.page_cache.clone(),
            freezer_value_partition: format!("{prefix}_freezer_value"),
            freezer_value_target_size: 16 * 1024 * 1024,
            freezer_value_compression: None,
            ordinal_partition: format!("{prefix}_ordinal"),
            items_per_section: self.items_per_section,
            freezer_key_write_buffer: self.key_write_buffer,
            freezer_value_write_buffer: self.value_write_buffer,
            ordinal_write_buffer: self.key_write_buffer,
            replay_buffer: self.replay_buffer,
            codec_config,
        }
    }
}

/// A trusted application-state floor used to start a fresh namespace.
///
/// The caller must authenticate `proof` with the epoch's LQC verifier and must bind `emitted` and
/// `generation` to the application snapshot being imported. Marshal checks canonical structure
/// and the proof-to-history commitment while opening storage, but cannot verify signatures before
/// [`super::Service::start`] receives a verifier. Use [`super::Mailbox::install_floor`] for an
/// untrusted floor received while the service is running.
#[derive(Clone, Debug)]
pub struct Floor<V: Variant, D: Digest> {
    /// Positive monotone generation authenticated by the state-sync owner.
    generation: u64,
    /// Authenticated L-QC anchoring the snapshot.
    proof: Lqc<V, D>,
    /// Exact tip-history opening committed by the anchor's leader.
    history: TipRecord<D>,
    /// Highest block present in the application snapshot on every chain.
    emitted: Vec<BlockRef<D>>,
}

impl<V: Variant, D: Digest> Floor<V, D> {
    /// Creates a caller-authenticated application-state floor.
    pub const fn new(
        generation: u64,
        proof: Lqc<V, D>,
        history: TipRecord<D>,
        emitted: Vec<BlockRef<D>>,
    ) -> Self {
        Self {
            generation,
            proof,
            history,
            emitted,
        }
    }

    /// Returns the state-sync generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the authenticated floor proof.
    pub const fn proof(&self) -> &Lqc<V, D> {
        &self.proof
    }

    /// Returns the history opening committed by the proof.
    pub const fn history(&self) -> &TipRecord<D> {
        &self.history
    }

    /// Returns the application snapshot frontier in chain order.
    pub fn emitted(&self) -> &[BlockRef<D>] {
        &self.emitted
    }
}

/// Startup anchor used only when no durable checkpoint exists.
///
/// A recovered checkpoint always wins over this value. [`Start::Floor`] is therefore an import
/// authority for a fresh storage namespace, not a runtime floor-update mechanism.
#[derive(Clone, Debug)]
pub enum Start<V: Variant, D: Digest> {
    /// Start after the synthetic height-zero tips.
    Genesis(EpochGenesis<D>),
    /// Start after a state sync authenticated by the caller.
    Floor(Floor<V, D>),
}

/// Marshal configuration for one Multimmit epoch.
pub struct Config<T: Translator, V: Variant, B: Codec + Digestible> {
    /// Epoch accepted by recovery and resolver admissions.
    pub epoch: Epoch,
    /// Exact non-zero number of producer chains.
    pub chains: NonZeroU32,
    /// Anchor for a namespace without durable marshal progress.
    pub start: Start<V, B::Digest>,
    /// Prefix from which exclusive storage partitions are derived.
    pub partition_prefix: String,
    /// Capacity of the single-owner catalog command mailbox.
    ///
    /// This bounds queued commands and waiting body requests only; admission durability and
    /// pending storage geometry are configured independently below.
    pub catalog_mailbox_size: NonZeroUsize,
    /// Maximum items coalesced into one pending-custody admission durability cut.
    ///
    /// Must not exceed [`Self::pending_segment_items`] so one maximum admission wave crosses at
    /// most one segment boundary and dirties at most two body and two compact-metadata journals.
    pub admission_cut_capacity: NonZeroUsize,
    /// Items in each pending-block storage segment.
    ///
    /// A segment is the unit of pending-custody reclamation and of sealed-reader recovery, so
    /// its byte bound is approximately `pending_segment_items * resolver_max_value_bytes` plus
    /// framing. This value is persisted storage geometry and must remain unchanged when
    /// reopening an existing storage namespace.
    pub pending_segment_items: NonZeroU64,
    /// Capacity bounding ready resolver deliveries and validation work.
    pub resolver_mailbox_size: NonZeroUsize,
    /// Maximum encoded bytes accepted in one producer block or resolved artifact.
    pub resolver_max_value_bytes: NonZeroUsize,
    /// Maximum outputs accepted in one atomic catalog commit.
    pub max_commit_outputs: NonZeroUsize,
    /// Target encoded-byte bound for the producer blocks in one atomic catalog commit.
    ///
    /// A single larger block is committed alone so a valid block cannot stall publication.
    pub max_commit_block_bytes: NonZeroUsize,
    /// Maximum blocks dispatched to the application without a durable acknowledgement.
    ///
    /// A larger value lets the application batch durable work without stalling delivery.
    pub max_pending_acks: NonZeroUsize,
    /// Target encoded-byte bound for each catalog delivery request.
    ///
    /// A single larger block may be returned alone so the bound cannot stall progress.
    pub max_delivery_bytes: NonZeroUsize,
    /// Encoded-byte budget for live producer blocks bridging custody and delivery.
    ///
    /// The catalog retains newly admitted blocks under this bound until promotion or pruning.
    /// Publication and delivery share those bodies by reference, so their handoff bounds do not
    /// duplicate payload bytes. Size this for the expected finalized-delivery lag and short
    /// scheduling stalls on the normal path.
    pub max_hot_block_bytes: NonZeroUsize,
    /// Encoded-byte budget for historically materialized producer blocks.
    ///
    /// Historical reads use an independent cache and active-read budget so backfill cannot evict
    /// live custody. Size this for concurrent delivery and promotion batches; it need not cover
    /// the live-custody horizon.
    pub max_materialized_block_bytes: NonZeroUsize,
    /// Maximum independent ancestry or finalized-body fetches in flight.
    ///
    /// Ancestry discovery is sequential within each producer chain because each header reveals
    /// its parent. Once ancestry is known, complete bodies are independent and use this bound
    /// across the entire output batch. Defaults to 512 and cannot exceed
    /// [`Self::resolver_mailbox_size`].
    pub backfill_concurrency: NonZeroUsize,
    /// Target encoded-byte bound for concurrent ancestry and finalized-body fetches.
    ///
    /// Marshal derives its effective fetch concurrency from this budget and
    /// [`Self::resolver_max_value_bytes`], capped by [`Self::backfill_concurrency`]. A single
    /// maximum-sized fetch is always permitted so a budget smaller than one block cannot prevent
    /// progress.
    pub max_backfill_bytes: NonZeroUsize,
    /// Maximum authenticated producer headers retained as non-authoritative ancestry hints.
    ///
    /// Entries only avoid complete-block reads during ancestry planning. The catalog's validated
    /// custody and the resolver remain authoritative for complete bodies.
    pub header_cache_capacity: NonZeroUsize,
    /// Maximum encoded bytes read from one checkpoint, prepared floor-install slot, or pending
    /// custody manifest.
    pub max_checkpoint_bytes: NonZeroUsize,
    /// Bounds used to decode Multimmit proofs and histories.
    pub codec_config: CodecConfig,
    /// Bounds used to decode application block bodies.
    pub body_codec_config: B::Cfg,
    /// Finalized L-QC retention mode.
    pub finalized_lqc: ArchiveMode,
    /// Finalized tip-history retention mode.
    pub finalized_history: ArchiveMode,
    /// Finalized application-block retention mode.
    pub finalized_blocks: ArchiveMode,
    /// Archive buffers, page cache, section sizing, and translator.
    pub archive: ArchiveConfig<T>,
}

impl<T: Translator, V: Variant, B: Codec + Digestible> Config<T, V, B> {
    /// Constructs a validated configuration with immutable finalized archives.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch: Epoch,
        chains: NonZeroU32,
        start: Start<V, B::Digest>,
        partition_prefix: String,
        codec_config: CodecConfig,
        body_codec_config: B::Cfg,
        archive: ArchiveConfig<T>,
    ) -> Result<Self, ConfigError> {
        let this = Self {
            epoch,
            chains,
            start,
            partition_prefix,
            catalog_mailbox_size: NZUsize!(1024),
            admission_cut_capacity: NZUsize!(1024),
            pending_segment_items: NZU64!(1024),
            resolver_mailbox_size: NZUsize!(1024),
            resolver_max_value_bytes: NZUsize!(4 * 1024 * 1024),
            max_commit_outputs: NZUsize!(1024),
            max_commit_block_bytes: DEFAULT_MAX_COMMIT_BLOCK_BYTES,
            max_pending_acks: DEFAULT_MAX_PENDING_ACKS,
            max_delivery_bytes: DEFAULT_MAX_DELIVERY_BYTES,
            max_hot_block_bytes: DEFAULT_MAX_HOT_BLOCK_BYTES,
            max_materialized_block_bytes: DEFAULT_MAX_MATERIALIZED_BLOCK_BYTES,
            backfill_concurrency: DEFAULT_BACKFILL_CONCURRENCY,
            max_backfill_bytes: DEFAULT_MAX_BACKFILL_BYTES,
            header_cache_capacity: DEFAULT_HEADER_CACHE_CAPACITY,
            max_checkpoint_bytes: NZUsize!(1024 * 1024),
            codec_config,
            body_codec_config,
            finalized_lqc: ArchiveMode::Immutable,
            finalized_history: ArchiveMode::Immutable,
            finalized_blocks: ArchiveMode::Immutable,
            archive,
        };
        this.validate()?;
        Ok(this)
    }

    /// Validates relationships not captured by field types.
    ///
    /// This performs structural validation only. In particular, it does not authenticate a
    /// [`Start::Floor`] LQC signature.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.partition_prefix.is_empty()
            || !self
                .partition_prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(ConfigError::InvalidPartitionPrefix);
        }
        if self.codec_config.chains() != self.chains.get() as usize {
            return Err(ConfigError::ChainCount);
        }
        if self.backfill_concurrency > self.resolver_mailbox_size {
            return Err(ConfigError::BackfillConcurrency);
        }
        if u64::try_from(self.admission_cut_capacity.get()).unwrap_or(u64::MAX)
            > self.pending_segment_items.get()
        {
            return Err(ConfigError::AdmissionCutCapacity);
        }
        let (epoch, ordered, emitted) = match &self.start {
            Start::Genesis(genesis) => (genesis.epoch(), genesis.tips(), genesis.tips()),
            Start::Floor(floor) => {
                if floor.generation == 0 {
                    return Err(ConfigError::FloorGeneration);
                }
                floor
                    .proof
                    .validate(self.codec_config)
                    .map_err(|_| ConfigError::FloorProof)?;
                (
                    floor.proof.epoch(),
                    floor.history.tips(),
                    floor.emitted.as_slice(),
                )
            }
        };
        if epoch != self.epoch {
            return Err(ConfigError::StartEpoch);
        }
        if !valid_frontier(ordered, self.chains)
            || !valid_frontier(emitted, self.chains)
            || ordered.iter().zip(emitted).any(|(ordered, emitted)| {
                emitted.height() < ordered.height()
                    || (emitted.height() == ordered.height() && emitted != ordered)
            })
        {
            return Err(ConfigError::StartFrontier);
        }
        Ok(())
    }

    /// Returns the fetch count satisfying both configured backfill bounds.
    pub(super) fn effective_backfill_concurrency(&self) -> NonZeroUsize {
        let by_bytes =
            (self.max_backfill_bytes.get() / self.resolver_max_value_bytes.get()).max(1);
        NonZeroUsize::new(self.backfill_concurrency.get().min(by_bytes))
            .expect("both backfill bounds permit at least one fetch")
    }
}

fn valid_frontier<D: Digest>(frontier: &[BlockRef<D>], chains: NonZeroU32) -> bool {
    frontier.len() == chains.get() as usize
        && frontier.iter().enumerate().all(|(chain, reference)| {
            u32::try_from(chain).is_ok_and(|chain| chain == reference.chain().get())
        })
}

/// A marshal configuration is internally inconsistent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The storage namespace is empty or cannot be used as a runtime metric label.
    #[error("partition prefix must contain only ASCII alphanumeric characters or underscores")]
    InvalidPartitionPrefix,
    /// Protocol decoding and marshal storage disagree on chain count.
    #[error("protocol codec and marshal chain counts differ")]
    ChainCount,
    /// Backfill could exhaust the resolver's pending-request registry by itself.
    #[error("backfill concurrency exceeds resolver mailbox capacity")]
    BackfillConcurrency,
    /// One maximum admission cut must fit within one pending storage segment.
    #[error("admission cut capacity exceeds pending segment items")]
    AdmissionCutCapacity,
    /// A state-sync floor must advance beyond the genesis generation.
    #[error("state-sync floor generation must be positive")]
    FloorGeneration,
    /// The startup anchor belongs to another epoch.
    #[error("startup anchor does not match the configured epoch")]
    StartEpoch,
    /// The startup frontier has another chain count or ordering.
    #[error("startup frontier does not match the configured chains")]
    StartFrontier,
    /// A state-sync L-QC is structurally invalid under the codec bounds.
    #[error("state-sync floor proof is structurally invalid")]
    FloorProof,
}

async fn finalized<T, E, K, V>(
    context: E,
    mode: ArchiveMode,
    archive: &ArchiveConfig<T>,
    prefix: String,
    codec: V::Cfg,
) -> Result<FinalizedArchive<T, E, K, V>, String>
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
    .map_err(|error| error.to_string())
}

impl<T: Translator, V: Variant, B: Codec + Digestible> Config<T, V, B>
where
    B::Cfg: Clone,
{
    /// Opens every store and transfers ownership to a catalog actor.
    pub(super) fn spawn<E, H>(
        self,
        context: E,
        delivery: DeliveryClient<H, B>,
    ) -> impl Future<Output = Result<Spawned<H, V, B>, String>> + Send
    where
        E: Clock + Context + Spawner,
        H: Hasher<Digest = B::Digest>,
    {
        Box::pin(self.spawn_inner(context, delivery))
    }

    async fn spawn_inner<E, H>(
        self,
        context: E,
        delivery: DeliveryClient<H, B>,
    ) -> Result<Spawned<H, V, B>, String>
    where
        E: Clock + Context + Spawner,
        H: Hasher<Digest = B::Digest>,
    {
        self.validate().map_err(|error| error.to_string())?;
        let metadata_step_capacity = self.effective_backfill_concurrency();
        // Resolver deliveries and synchronizer lookup pages can wait simultaneously behind one
        // durable admission cut.
        let custody_waiter_capacity = NonZeroUsize::new(
            self.resolver_mailbox_size
                .get()
                .checked_add(synchronizer::CUSTODY_WINDOW_PAGES)
                .ok_or_else(|| "custody waiter capacity overflow".to_string())?,
        )
        .expect("adding a reservation to a non-zero capacity remains non-zero");
        let actor_context = context.child("catalog");
        let name = |suffix: &str| format!("{}_{suffix}", self.partition_prefix);
        let chains = self.chains.get() as usize;
        let archive_layout = ArchiveLayout::new(
            self.finalized_lqc == ArchiveMode::Prunable,
            self.finalized_history == ArchiveMode::Prunable,
            self.finalized_blocks == ArchiveMode::Prunable,
        );
        let mut fl = finalized(
            context.child("final_lqc"),
            self.finalized_lqc,
            &self.archive,
            name("final_lqc"),
            self.codec_config,
        )
        .await?;
        let mut fh = finalized(
            context.child("final_history"),
            self.finalized_history,
            &self.archive,
            name("final_history"),
            chains,
        )
        .await?;
        let fb: FinalBlock<T, E, H> = finalized(
            context.child("final_blocks"),
            self.finalized_blocks,
            &self.archive,
            name("final_block_rows"),
            (),
        )
        .await?;
        let pl = TemporaryArchive::init(
            context.child("pending_lqc"),
            self.archive
                .prunable(name("pending_lqc"), self.codec_config),
        )
        .await
        .map_err(|error| error.to_string())?;
        let ph = TemporaryArchive::init(
            context.child("pending_history"),
            self.archive.prunable(name("pending_history"), chains),
        )
        .await
        .map_err(|error| error.to_string())?;
        let mut metadata: Metadata<E, Unit, CatalogState<H::Digest>> = Metadata::init_bounded(
            context.child("checkpoint"),
            metadata::Config {
                partition: name("checkpoint"),
                codec_config: CheckpointCodecConfig::new(
                    self.epoch,
                    chains,
                    self.max_checkpoint_bytes.get(),
                ),
            },
            self.max_checkpoint_bytes,
        )
        .await
        .map_err(|error| error.to_string())?;
        let fresh = metadata.get(&Unit).is_none();
        if metadata
            .get(&Unit)
            .is_some_and(|state| state.checkpoint().archive_layout() != archive_layout)
        {
            return Err("finalized archive modes do not match the existing namespace".into());
        }
        if fresh {
            match self.start {
                Start::Genesis(genesis) => {
                    let checkpoint = Checkpoint::new(
                        self.epoch,
                        0,
                        archive_layout,
                        genesis.lqc(),
                        genesis_history::<H>(&genesis),
                        None,
                        genesis.tips().to_vec(),
                        genesis.tips().to_vec(),
                        None,
                        None,
                    )
                    .unwrap();
                    let state = CatalogState::ready(checkpoint, None);
                    if catalog::metadata_blob_size(&state)
                        .is_none_or(|size| size > self.max_checkpoint_bytes.get())
                    {
                        return Err("initial catalog state exceeds max_checkpoint_bytes".into());
                    }
                    metadata = metadata
                        .put_sync(Unit, state)
                        .await
                        .map_err(|error| error.to_string())?;
                }
                Start::Floor(floor) => {
                    let id = floor.proof.id::<H>();
                    let lqc_index = floor.proof.view().get();
                    let history = floor.history.commitment::<H>();
                    if floor.proof.leader().history() != history {
                        return Err("state-sync floor proof does not commit to its history".into());
                    }
                    let generation = floor
                        .generation
                        .checked_sub(1)
                        .expect("state-sync floor generation is positive");
                    let checkpoint = Checkpoint::new(
                        self.epoch,
                        floor.generation,
                        archive_layout,
                        id,
                        history,
                        Some(0),
                        floor.history.tips().to_vec(),
                        floor.emitted,
                        None,
                        None,
                    )
                    .unwrap();
                    // Initialization remains hidden behind a durable install intent until the
                    // exact trusted artifacts are archived.
                    let initial = Checkpoint::new(
                        self.epoch,
                        generation,
                        archive_layout,
                        floor.proof.leader().parent(),
                        floor.history.parent(),
                        None,
                        floor.history.tips().to_vec(),
                        floor.history.tips().to_vec(),
                        None,
                        None,
                    )
                    .unwrap();
                    let state = CatalogState::ready(initial, None)
                        .begin(
                            checkpoint.clone(),
                            floor.proof.view(),
                            Prune {
                                pending_lqc: View::new(0),
                                pending_history: View::new(0),
                                pending_blocks: vec![Height::zero(); chains],
                            },
                            floor.proof.encode(),
                            floor.history.encode(),
                        )
                        .expect("fresh floor advances its initialization checkpoint");
                    if catalog::metadata_blob_size(&state)
                        .is_none_or(|size| size > self.max_checkpoint_bytes.get())
                    {
                        return Err("initial catalog state exceeds max_checkpoint_bytes".into());
                    }
                    metadata = metadata
                        .put_sync(Unit, state)
                        .await
                        .map_err(|error| error.to_string())?;
                    (fl, fh) = futures::try_join!(
                        async move {
                            fl.put(lqc_index, id.get(), Shared::new(Arc::new(floor.proof)))
                                .await
                                .map_err(|error| error.to_string())?
                                .sync()
                                .await
                                .map_err(|error| error.to_string())
                        },
                        async move {
                            fh.put(0, history, Shared::new(Arc::new(floor.history)))
                                .await
                                .map_err(|error| error.to_string())?
                                .sync()
                                .await
                                .map_err(|error| error.to_string())
                        },
                    )?;
                    metadata = metadata
                        .put_sync(Unit, CatalogState::ready(checkpoint, Some(lqc_index)))
                        .await
                        .map_err(|error| error.to_string())?;
                }
            }
        }
        let stored_checkpoint = metadata
            .get(&Unit)
            .expect("catalog checkpoint was initialized")
            .checkpoint()
            .clone();
        let pending_blocks = PendingBlocks::init(
            context.child("pending_blocks"),
            self.archive.clone(),
            name("pending_blocks"),
            self.body_codec_config.clone(),
            self.epoch,
            chains,
            self.pending_segment_items,
            self.max_checkpoint_bytes,
        )
        .await
        .map_err(|error| error.to_string())?;
        let (promoter_client, promoter_receiver, promotion_store) =
            if self.finalized_blocks == ArchiveMode::Immutable {
                let (client, receiver) = promoter::channel(
                    context.child("promoter").child("mailbox"),
                    NonZeroUsize::MIN,
                );
                let bodies: FinalBody<T, E, H, B> = FinalizedArchive::init_immutable(
                    context.child("final_block_bodies"),
                    self.archive
                        .immutable(name("final_block_bodies"), self.body_codec_config.clone()),
                )
                .await
                .map_err(|error| error.to_string())?;
                let mut promotion = Metadata::init_bounded(
                    context.child("block_promotion"),
                    metadata::Config {
                        partition: name("block_promotion"),
                        codec_config: chains,
                    },
                    self.max_checkpoint_bytes,
                )
                .await
                .map_err(|error| error.to_string())?;
                if promotion.get(&Unit).is_none() {
                    if !fresh && stored_checkpoint.committed().is_some() {
                        return Err("immutable promotion state is missing".into());
                    }
                    promotion = promotion
                        .put_sync(
                            Unit,
                            PromotionState::new(
                                stored_checkpoint.committed(),
                                stored_checkpoint.emitted().to_vec(),
                                vec![stored_checkpoint.generation(); chains],
                            ),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                }
                (
                    Some(client),
                    Some(receiver),
                    Some(PromotionStore::new(bodies, promotion)?),
                )
            } else {
                (None, None, None)
            };
        let (catalog, catalog_handle) = catalog::spawn(
            actor_context,
            self.catalog_mailbox_size,
            self.admission_cut_capacity,
            metadata_step_capacity,
            custody_waiter_capacity,
            self.max_commit_outputs,
            self.max_commit_block_bytes,
            self.resolver_max_value_bytes,
            delivery,
            promoter_client.clone(),
            self.max_hot_block_bytes,
            self.max_materialized_block_bytes,
            fl,
            fh,
            fb,
            pl,
            ph,
            pending_blocks,
            metadata,
            self.codec_config,
            self.max_checkpoint_bytes,
        )
        .await
        .map_err(|error| error.to_string())?;
        let checkpoint = catalog
            .checkpoint()
            .await
            .map_err(|error| error.to_string())?;
        let promoter_handle = match (promotion_store, promoter_receiver) {
            (Some(store), Some(receiver)) => Some(promoter::spawn(
                context.child("promoter"),
                catalog.clone(),
                store,
                receiver,
                checkpoint.committed(),
                checkpoint.generation(),
                checkpoint.emitted().to_vec(),
                self.max_commit_outputs,
                self.max_commit_block_bytes,
            )),
            (None, None) => None,
            _ => unreachable!("promoter storage and mailbox are allocated together"),
        };
        Ok((catalog, catalog_handle, promoter_client, promoter_handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::mocks::block::EmptyBlock,
        multimmit::{
            config::Limits,
            marshal::actors::{
                catalog::{Commit, Error as CatalogError, HistoryOpening},
                delivery,
            },
            mocks::Committee,
            types::{
                CertificateId, ChainId, Height, TipRecord,
                genesis_history as protocol_genesis_history,
            },
        },
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::translator::TwoCap;
    use commonware_utils::NZU16;

    type TestConfig = Config<TwoCap, MinPk, EmptyBlock<Sha256>>;

    fn genesis(epoch: Epoch, chains: u32) -> EpochGenesis<Sha256Digest> {
        let tips = (0..chains)
            .map(|chain| {
                BlockRef::new(
                    ChainId::new(chain),
                    Height::zero(),
                    Sha256::hash(&[&chain.to_be_bytes()]),
                )
            })
            .collect();
        EpochGenesis::new(
            epoch,
            Sha256::hash(&[b"leader"]),
            CertificateId::new(Sha256::hash(&[b"vqc"])),
            CertificateId::new(Sha256::hash(&[b"lqc"])),
            tips,
        )
        .unwrap()
    }

    fn config(context: &deterministic::Context, epoch: Epoch, chains: u32) -> TestConfig {
        TestConfig::new(
            epoch,
            NonZeroU32::new(chains).unwrap(),
            Start::Genesis(genesis(epoch, chains)),
            "marshal_config_test".into(),
            CodecConfig::new(5, chains as usize, Limits::new(4, 0).unwrap()).unwrap(),
            (),
            ArchiveConfig::new(
                TwoCap,
                CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8)),
            ),
        )
        .unwrap()
    }

    #[test]
    fn default_construction_is_bounded_and_exact_acknowledgement() {
        deterministic::Runner::default().start(|context| async move {
            let config = config(&context, Epoch::new(7), 2);
            assert_eq!(config.chains.get(), 2);
            assert_eq!(config.backfill_concurrency.get(), 512);
            assert_eq!(config.max_backfill_bytes.get(), 256 * 1024 * 1024);
            assert_eq!(config.header_cache_capacity.get(), 16 * 1024);
            assert_eq!(config.finalized_lqc, ArchiveMode::Immutable);
            assert_eq!(config.max_commit_block_bytes.get(), 256 * 1024 * 1024);
            assert_eq!(config.max_pending_acks.get(), 128);
            assert_eq!(config.max_delivery_bytes.get(), 16 * 1024 * 1024);
            assert_eq!(config.max_hot_block_bytes.get(), 512 * 1024 * 1024);
            assert_eq!(
                config.max_materialized_block_bytes.get(),
                512 * 1024 * 1024
            );
            assert!(config.validate().is_ok());
        });
    }

    #[test]
    fn backfill_concurrency_obeys_item_and_byte_bounds() {
        deterministic::Runner::default().start(|context| async move {
            let mut config = config(&context, Epoch::new(7), 2);
            config.resolver_max_value_bytes = NZUsize!(512 * 1024);
            assert_eq!(config.effective_backfill_concurrency().get(), 512);

            config.resolver_max_value_bytes = NZUsize!(4 * 1024 * 1024);
            assert_eq!(config.effective_backfill_concurrency().get(), 64);

            config.max_backfill_bytes = NonZeroUsize::MIN;
            assert_eq!(config.effective_backfill_concurrency().get(), 1);
        });
    }

    #[test]
    fn validation_rejects_cross_context_configuration() {
        deterministic::Runner::default().start(|context| async move {
            let mut invalid = config(&context, Epoch::new(7), 2);
            invalid.partition_prefix.clear();
            assert_eq!(invalid.validate(), Err(ConfigError::InvalidPartitionPrefix));
            let mut invalid = config(&context, Epoch::new(7), 2);
            invalid.codec_config = CodecConfig::new(5, 1, Limits::new(4, 0).unwrap()).unwrap();
            assert_eq!(invalid.validate(), Err(ConfigError::ChainCount));
            let mut invalid = config(&context, Epoch::new(7), 2);
            invalid.backfill_concurrency = NZUsize!(3);
            invalid.resolver_mailbox_size = NZUsize!(2);
            assert_eq!(invalid.validate(), Err(ConfigError::BackfillConcurrency));
            let mut invalid = config(&context, Epoch::new(7), 2);
            invalid.epoch = Epoch::new(8);
            assert_eq!(invalid.validate(), Err(ConfigError::StartEpoch));
            let mut invalid = config(&context, Epoch::new(7), 2);
            invalid.admission_cut_capacity = NZUsize!(2048);
            invalid.pending_segment_items = NZU64!(1024);
            assert_eq!(invalid.validate(), Err(ConfigError::AdmissionCutCapacity));
        });
    }

    /// Opens the shared geometry-test namespace with `configure` applied, then stops it.
    async fn open_geometry_namespace(
        context: &deterministic::Context,
        label: &'static str,
        configure: impl FnOnce(&mut TestConfig),
    ) -> Result<(), String> {
        let mut config = config(context, Epoch::new(7), 2);
        config.partition_prefix = "marshal_geometry_test".into();
        configure(&mut config);
        let (delivery, _receiver) = delivery::channel(context.child(label).child("delivery"));
        let (_, handle, _, promoter) = config
            .spawn::<_, Sha256>(context.child(label), delivery)
            .await?;
        promoter.unwrap().abort();
        handle.abort();
        let _ = handle.await;
        Ok(())
    }

    #[test]
    fn mailbox_capacity_is_independent_of_pending_storage_geometry() {
        deterministic::Runner::default().start(|context| async move {
            open_geometry_namespace(&context, "original", |_| {})
                .await
                .unwrap();

            // Queue pressure is reconfigurable; persisted segment geometry is not.
            open_geometry_namespace(&context, "resized", |config| {
                config.catalog_mailbox_size = NZUsize!(8);
                config.admission_cut_capacity = NZUsize!(8);
            })
            .await
            .unwrap();

            let error = open_geometry_namespace(&context, "reshaped", |config| {
                config.admission_cut_capacity = NZUsize!(512);
                config.pending_segment_items = NZU64!(512);
            })
            .await
            .expect_err("pending segment geometry is namespace state");
            assert!(error.contains("pending segment capacity differs"));
        });
    }

    #[test]
    fn fresh_namespace_rejects_checkpoint_larger_than_metadata_blob_bound() {
        deterministic::Runner::default().start(|context| async move {
            let mut config = config(&context, Epoch::new(7), 2);
            config.max_checkpoint_bytes = NZUsize!(1);
            let (delivery, _receiver) =
                delivery::channel::<Sha256, EmptyBlock<Sha256>>(context.child("delivery"));
            let Err(error) = config
                .spawn::<_, Sha256>(context.child("bounded"), delivery)
                .await
            else {
                panic!("an oversized initial checkpoint must be rejected");
            };
            assert!(error.contains("initial catalog state exceeds max_checkpoint_bytes"));
        });
    }

    #[test]
    fn oversized_commit_cleanup_is_rejected_before_finalized_writes() {
        deterministic::Runner::default().start(|context| async move {
            let epoch = Epoch::new(7);
            let genesis = genesis(epoch, 2);
            let initial = Checkpoint::new(
                epoch,
                0,
                ArchiveLayout::new(false, false, false),
                genesis.lqc(),
                genesis_history::<Sha256>(&genesis),
                None,
                genesis.tips().to_vec(),
                genesis.tips().to_vec(),
                None,
                None,
            )
            .unwrap();
            let record =
                Arc::new(TipRecord::new(initial.history(), genesis.tips().to_vec()).unwrap());
            let commitment = record.commitment::<Sha256>();
            let checkpoint = Checkpoint::new(
                epoch,
                0,
                ArchiveLayout::new(false, false, false),
                genesis.lqc(),
                commitment,
                Some(0),
                genesis.tips().to_vec(),
                genesis.tips().to_vec(),
                None,
                None,
            )
            .unwrap();
            let ready_size =
                catalog::metadata_blob_size(&CatalogState::ready(checkpoint.clone(), None))
                    .unwrap();
            assert!(
                catalog::metadata_blob_size(&CatalogState::committed(
                    checkpoint.clone(),
                    None,
                    None,
                ))
                .unwrap()
                    > ready_size
            );

            let mut bounded = config(&context, epoch, 2);
            bounded.max_checkpoint_bytes = NonZeroUsize::new(ready_size).unwrap();
            let (delivery, _bounded_delivery) =
                delivery::channel(context.child("bounded_delivery"));
            let (client, handle, _, promoter) = bounded
                .spawn::<_, Sha256>(context.child("bounded_commit"), delivery)
                .await
                .unwrap();
            assert!(matches!(
                client
                    .commit(Commit {
                        selected: Vec::new(),
                        history: vec![HistoryOpening {
                            commitment,
                            record: record.clone(),
                        }],
                        outputs: Vec::new(),
                        checkpoint,
                    })
                    .await,
                Err(CatalogError::Invalid(
                    "catalog state exceeds configured metadata bound"
                ))
            ));
            assert_eq!(client.checkpoint().await.unwrap(), initial);
            assert!(client.history(commitment).await.unwrap().is_none());
            let promoter = promoter.unwrap();
            promoter.abort();
            let _ = promoter.await;
            drop(client);
            assert!(handle.await.is_ok());

            let mut reopened = config(&context, epoch, 2);
            reopened.max_checkpoint_bytes = NonZeroUsize::new(ready_size).unwrap();
            let (delivery, _reopened_delivery) =
                delivery::channel(context.child("reopened_delivery"));
            let (client, handle, _, promoter) = reopened
                .spawn::<_, Sha256>(context.child("reopened_commit"), delivery)
                .await
                .unwrap();
            assert_eq!(client.checkpoint().await.unwrap(), initial);
            assert!(client.history(commitment).await.unwrap().is_none());
            let promoter = promoter.unwrap();
            promoter.abort();
            let _ = promoter.await;
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn trusted_start_floor_seeds_only_a_fresh_namespace() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(8, 6, Limits::new(4, 0).unwrap());
            let genesis = committee.config.genesis();
            let history = TipRecord::new(
                protocol_genesis_history::<Sha256>(genesis),
                genesis.tips().to_vec(),
            )
            .unwrap();
            let proof = committee.lqc(1);
            assert_eq!(proof.leader().history(), history.commitment::<Sha256>());
            let make_config = |generation| {
                TestConfig::new(
                    committee.config.epoch(),
                    NonZeroU32::new(committee.codec().chains() as u32).unwrap(),
                    Start::Floor(Floor::new(
                        generation,
                        proof.clone(),
                        history.clone(),
                        genesis.tips().to_vec(),
                    )),
                    "marshal_trusted_floor_test".into(),
                    committee.codec(),
                    (),
                    ArchiveConfig::new(
                        TwoCap,
                        CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8)),
                    ),
                )
            };
            assert!(matches!(make_config(0), Err(ConfigError::FloorGeneration)));
            let config = make_config(7).unwrap();
            let (delivery, _delivery_receiver) = delivery::channel(context.child("delivery"));
            let (catalog, handle, _, promoter) = config
                .spawn::<_, Sha256>(context.child("marshal"), delivery)
                .await
                .unwrap();
            let checkpoint = catalog.checkpoint().await.unwrap();
            assert_eq!(checkpoint.generation(), 7);
            assert_eq!(checkpoint.floor(), proof.id::<Sha256>());
            assert_eq!(checkpoint.ordered(), genesis.tips());
            assert_eq!(checkpoint.emitted(), genesis.tips());
            promoter.unwrap().abort();
            handle.abort();
            let _ = handle.await;
        });
    }

    #[test]
    fn interrupted_fresh_floor_seed_recovers_original_intent() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(8, 6, Limits::new(4, 0).unwrap());
            let genesis = committee.config.genesis();
            let history = TipRecord::new(
                protocol_genesis_history::<Sha256>(genesis),
                genesis.tips().to_vec(),
            )
            .unwrap();
            let original = committee.lqc(1);
            let replacement = committee.lqc(3);
            assert_eq!(original.leader().history(), history.commitment::<Sha256>());
            assert_eq!(
                replacement.leader().history(),
                history.commitment::<Sha256>()
            );
            let original_id = original.id::<Sha256>();
            let replacement_id = replacement.id::<Sha256>();
            assert_ne!(original_id, replacement_id);
            let prefix = "marshal_interrupted_floor_test";
            let max_checkpoint_bytes = NZUsize!(1024 * 1024);
            let checkpoint = Checkpoint::new(
                committee.config.epoch(),
                7,
                ArchiveLayout::new(false, false, false),
                original_id,
                history.commitment::<Sha256>(),
                Some(0),
                history.tips().to_vec(),
                genesis.tips().to_vec(),
                None,
                None,
            )
            .unwrap();
            let initial = Checkpoint::new(
                committee.config.epoch(),
                6,
                ArchiveLayout::new(false, false, false),
                original.leader().parent(),
                history.parent(),
                None,
                history.tips().to_vec(),
                history.tips().to_vec(),
                None,
                None,
            )
            .unwrap();
            let intent = CatalogState::ready(initial, None)
                .begin(
                    checkpoint.clone(),
                    original.view(),
                    Prune {
                        pending_lqc: View::new(0),
                        pending_history: View::new(0),
                        pending_blocks: vec![Height::zero(); genesis.tips().len()],
                    },
                    original.encode(),
                    history.encode(),
                )
                .unwrap();
            let metadata: Metadata<_, Unit, CatalogState<Sha256Digest>> = Metadata::init_bounded(
                context.child("interrupted_intent"),
                metadata::Config {
                    partition: format!("{prefix}_checkpoint"),
                    codec_config: CheckpointCodecConfig::new(
                        committee.config.epoch(),
                        genesis.tips().len(),
                        max_checkpoint_bytes.get(),
                    ),
                },
                max_checkpoint_bytes,
            )
            .await
            .unwrap();
            drop(metadata.put_sync(Unit, intent).await.unwrap());

            let config = TestConfig::new(
                committee.config.epoch(),
                NonZeroU32::new(committee.codec().chains() as u32).unwrap(),
                Start::Floor(Floor::new(
                    8,
                    replacement,
                    history.clone(),
                    genesis.tips().to_vec(),
                )),
                prefix.into(),
                committee.codec(),
                (),
                ArchiveConfig::new(
                    TwoCap,
                    CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8)),
                ),
            )
            .unwrap();
            let (delivery, _delivery_receiver) = delivery::channel(context.child("delivery"));
            let (catalog, handle, _, promoter) = config
                .spawn::<_, Sha256>(context.child("recovered"), delivery)
                .await
                .unwrap();
            assert_eq!(catalog.checkpoint().await.unwrap(), checkpoint);
            assert_eq!(
                catalog.lqc(original_id).await.unwrap().as_deref(),
                Some(&original)
            );
            assert!(catalog.lqc(replacement_id).await.unwrap().is_none());
            let promoter = promoter.unwrap();
            promoter.abort();
            let _ = promoter.await;
            drop(catalog);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn reopen_rejects_changed_finalized_archive_modes() {
        deterministic::Runner::default().start(|context| async move {
            let mut original = config(&context, Epoch::new(9), 2);
            original.finalized_lqc = ArchiveMode::Prunable;
            let (delivery, _original_delivery) =
                delivery::channel(context.child("original_delivery"));
            let (_, handle, _, promoter) = original
                .spawn::<_, Sha256>(context.child("original"), delivery)
                .await
                .unwrap();
            promoter.unwrap().abort();
            handle.abort();
            let _ = handle.await;

            let changed = config(&context, Epoch::new(9), 2);
            let (delivery, _changed_delivery) =
                delivery::channel(context.child("changed_delivery"));
            let Err(error) = changed
                .spawn::<_, Sha256>(context.child("changed"), delivery)
                .await
            else {
                panic!("archive backend selection is namespace state");
            };
            assert!(error.contains("finalized archive modes"));
        });
    }
}
