//! Marshal configuration and its validation.
//!
//! A [`Config`] names the startup anchor ([`Start`]), the storage partition prefix, the
//! [`Capacities`] of queues and batches, the byte [`Limits`], the [`Retention`] of each finalized
//! artifact family ([`ArchiveMode`]), the protocol and body codec bounds, and the shared
//! [`ArchiveConfig`]. [`open`](fn@super::open) validates it before touching storage, rejecting
//! inconsistent capacities, a response bound that cannot carry one maximum-size block, or a
//! malformed startup floor with a [`ConfigError`]. Reopening a namespace under a different
//! retention also fails in `open`.

use super::{
    actors::synchronizer,
    types::{Families, Floor},
};
use crate::{
    Epochable as _,
    multimmit::{
        storage::valid_partition_prefix,
        types::{CodecConfig, EpochGenesis, Frontier},
    },
    types::Epoch,
};
use commonware_codec::{Codec, EncodeSize as _};
use commonware_cryptography::{Digest, Digestible, bls12381::primitives::variant::Variant};
use commonware_runtime::buffer::paged::CacheRef;
use commonware_storage::{
    archive::{immutable, prunable},
    journal::segmented::variable,
    translator::Translator,
};
use commonware_utils::{NZU64, NZUsize};
use std::num::{NonZeroU64, NonZeroUsize};

const DEFAULT_CATALOG_MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);
const DEFAULT_ADMISSION_CUT_CAPACITY: NonZeroUsize = NZUsize!(1024);
const DEFAULT_PENDING_SEGMENT_ITEMS: NonZeroU64 = NZU64!(1024);
const DEFAULT_RESOLVER_MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);
const DEFAULT_RESOLVER_MAX_VALUE_BYTES: NonZeroUsize = NZUsize!(4 * 1024 * 1024);
const DEFAULT_MAX_COMMIT_OUTPUTS: NonZeroUsize = NZUsize!(1024);
const DEFAULT_MAX_CHECKPOINT_BYTES: NonZeroUsize = NZUsize!(1024 * 1024);
const DEFAULT_BACKFILL_CONCURRENCY: NonZeroUsize = NZUsize!(512);
const DEFAULT_MAX_BACKFILL_BYTES: NonZeroUsize = NZUsize!(256 * 1024 * 1024);
const DEFAULT_HEADER_CACHE_CAPACITY: NonZeroUsize = NZUsize!(16 * 1024);
const DEFAULT_MAX_BLOCK_BYTES: NonZeroUsize = NZUsize!(1024 * 1024);
const DEFAULT_MAX_COMMIT_BLOCK_BYTES: NonZeroUsize = NZUsize!(256 * 1024 * 1024);
const DEFAULT_MAX_PENDING_ACKS: NonZeroUsize = NZUsize!(128);
const DEFAULT_MAX_DELIVERY_BYTES: NonZeroUsize = NZUsize!(16 * 1024 * 1024);
const DEFAULT_MAX_HOT_BLOCK_BYTES: NonZeroUsize = NZUsize!(512 * 1024 * 1024);
const DEFAULT_MAX_MATERIALIZED_BLOCK_BYTES: NonZeroUsize = NZUsize!(512 * 1024 * 1024);

/// Producer blocks one finalized-backfill response carries under [`Config::with_max_block_bytes`].
const SIZED_RESPONSE_BLOCKS: usize = 16;
/// Finalized-backfill responses held at once under [`Config::with_max_block_bytes`].
const SIZED_CONCURRENT_RESPONSES: usize = 128;
/// Target bytes of one pending-block segment under [`Config::with_max_block_bytes`].
const SIZED_PENDING_SEGMENT_BYTES: usize = 128 * 1024 * 1024;

const DEFAULT_ITEMS_PER_SECTION: NonZeroU64 = NZU64!(1024);
const DEFAULT_ARCHIVE_BUFFER_BYTES: NonZeroUsize = NZUsize!(1024 * 1024);

/// Initial entry count of each immutable archive's freezer table.
const FREEZER_TABLE_INITIAL_SIZE: u32 = 65_536;
/// Items added to half of the freezer table's entries before the table grows.
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
/// Freezer table entries moved per resize step.
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 16_384;
/// Target size of each freezer value section.
const FREEZER_VALUE_TARGET_SIZE: u64 = 16 * 1024 * 1024;

/// Storage backend used for one finalized artifact family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveMode {
    /// Retain data only until marshal installs a newer authorized floor.
    Prunable,
    /// Retain data for the lifetime of the namespace.
    Immutable,
}

/// The storage backend of each finalized artifact family.
///
/// Retention is namespace state: reopening a namespace with other modes fails.
pub type Retention = Families<ArchiveMode>;

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
            items_per_section: DEFAULT_ITEMS_PER_SECTION,
            replay_buffer: DEFAULT_ARCHIVE_BUFFER_BYTES,
            key_write_buffer: DEFAULT_ARCHIVE_BUFFER_BYTES,
            value_write_buffer: DEFAULT_ARCHIVE_BUFFER_BYTES,
        }
    }

    pub(super) fn prunable<C>(&self, prefix: String, codec_config: C) -> prunable::Config<T, C> {
        prunable::Config {
            translator: self.translator.clone(),
            metadata_partition: format!("{prefix}_metadata"),
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

    pub(super) fn immutable<C>(&self, prefix: String, codec_config: C) -> immutable::Config<C> {
        immutable::Config {
            metadata_partition: format!("{prefix}_metadata"),
            freezer_table_partition: format!("{prefix}_table"),
            freezer_table_initial_size: FREEZER_TABLE_INITIAL_SIZE,
            freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
            freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
            freezer_key_partition: format!("{prefix}_freezer_key"),
            freezer_key_page_cache: self.page_cache.clone(),
            freezer_value_partition: format!("{prefix}_freezer_value"),
            freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
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

/// Startup anchor used only when no durable checkpoint exists.
///
/// A recovered checkpoint always wins over this value. [`Start::Floor`] is therefore an import
/// authority for a fresh storage namespace, not a runtime floor-update mechanism; use
/// [`super::Mailbox::install_floor`] for a floor received while the service is running.
#[derive(Clone, Debug)]
pub enum Start<V: Variant, D: Digest> {
    /// Start after the synthetic height-zero tips.
    Genesis(EpochGenesis<D>),
    /// Start after a state sync authenticated by the caller.
    ///
    /// The caller must authenticate the floor's anchor with the epoch's L-QC verifier and bind
    /// its emitted frontier and `floor_generation` to the application snapshot being imported.
    /// Marshal checks structure and the anchor-to-history commitment while opening storage, but
    /// cannot verify signatures before [`super::Service::start`] receives a verifier.
    Floor {
        /// Positive monotone generation authenticated by the state-sync owner.
        floor_generation: u64,
        /// The floor to start after.
        floor: Box<Floor<V, D>>,
    },
}

impl<V: Variant, D: Digest> Start<V, D> {
    /// Returns the epoch the anchor belongs to.
    pub fn epoch(&self) -> Epoch {
        match self {
            Self::Genesis(genesis) => genesis.epoch(),
            Self::Floor { floor, .. } => floor.anchor.epoch(),
        }
    }
}

/// Queue, batch and cache capacities, in items.
#[derive(Clone, Copy, Debug)]
pub struct Capacities {
    /// Capacity of the catalog's command and read mailboxes and of the public mailbox.
    ///
    /// The same value bounds body requests waiting in the catalog and concurrent catalog body
    /// reads.
    pub catalog_mailbox_size: NonZeroUsize,
    /// Most items coalesced into one pending-custody admission durability cut.
    ///
    /// Must not exceed [`Self::pending_segment_items`] so one maximum admission cut crosses at
    /// most one segment boundary and dirties at most two pending-block segments.
    pub admission_cut_capacity: NonZeroUsize,
    /// Items in each pending-block storage segment.
    ///
    /// A segment is the unit of pending-custody reclamation and startup recovery, so its byte
    /// bound is approximately `pending_segment_items * max_block_bytes` plus framing. This value
    /// is namespace state and must not change when reopening a namespace.
    pub pending_segment_items: NonZeroU64,
    /// Capacity bounding ready resolver deliveries and validation work.
    ///
    /// Sizes the backfill, serve and synchronizer mailboxes and bounds pending backfill requests,
    /// keys reserved for staging, peer callers waiting for a served value, finality proofs batched
    /// by the synchronizer, concurrent router jobs, block-subscription callers, and (with a fixed
    /// reservation for synchronizer lookups) callers waiting for catalog custody.
    pub resolver_mailbox_size: NonZeroUsize,
    /// Most outputs in one catalog commit, and in one promotion batch.
    pub max_commit_outputs: NonZeroUsize,
    /// Most blocks reported to the application whose acknowledgement is unresolved.
    ///
    /// Contiguous acknowledged prefixes coalesce in constant space while the delivery cursor
    /// syncs, so cursor storage latency does not occupy this window.
    pub max_pending_acks: NonZeroUsize,
    /// Most independent ancestry or finalized-body fetches in flight.
    ///
    /// Ancestry discovery is sequential within each producer chain because each header reveals
    /// its parent. Once ancestry is known, bodies are independent and share this bound across
    /// the whole output batch. Cannot exceed [`Self::resolver_mailbox_size`].
    ///
    /// The effective value (see [`Limits::max_backfill_bytes`]) also bounds concurrent serve
    /// lookups, local rechecks before a peer fetch, producer-block batches being staged, and
    /// the segment requests in one catalog header lookup.
    pub backfill_concurrency: NonZeroUsize,
    /// Capacity of each producer ancestry hint cache, in headers or block references.
    ///
    /// Selected paths are charged by their full reference count. One active output plan can pin
    /// up to the same number of references independently of cache eviction.
    pub header_cache_capacity: NonZeroUsize,
}

impl Default for Capacities {
    fn default() -> Self {
        Self {
            catalog_mailbox_size: DEFAULT_CATALOG_MAILBOX_SIZE,
            admission_cut_capacity: DEFAULT_ADMISSION_CUT_CAPACITY,
            pending_segment_items: DEFAULT_PENDING_SEGMENT_ITEMS,
            resolver_mailbox_size: DEFAULT_RESOLVER_MAILBOX_SIZE,
            max_commit_outputs: DEFAULT_MAX_COMMIT_OUTPUTS,
            max_pending_acks: DEFAULT_MAX_PENDING_ACKS,
            backfill_concurrency: DEFAULT_BACKFILL_CONCURRENCY,
            header_cache_capacity: DEFAULT_HEADER_CACHE_CAPACITY,
        }
    }
}

/// Byte bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Most encoded bytes in one producer block.
    ///
    /// Bounds catalog admission and pending storage geometry independently of the resolver
    /// response bound.
    pub max_block_bytes: NonZeroUsize,
    /// Most encoded bytes in one resolved artifact or peer response.
    ///
    /// Must hold one maximum block plus its response framing. Larger values let finalized
    /// backfill fetch several consecutive blocks in one response.
    pub resolver_max_value_bytes: NonZeroUsize,
    /// Target encoded bytes of the producer blocks in one catalog commit, and in one promotion
    /// batch.
    ///
    /// A single larger block is committed alone so a valid block cannot stall publication.
    pub max_commit_block_bytes: NonZeroUsize,
    /// Target encoded bytes of one delivery read from custody.
    ///
    /// A single larger block is read alone so the bound cannot stall progress.
    pub max_delivery_bytes: NonZeroUsize,
    /// Encoded bytes of recently admitted blocks kept in memory for delivery and promotion.
    ///
    /// The catalog keeps admitted blocks under this bound until promotion or pruning, and hands
    /// them to delivery with each commit. Delivery keeps each commit's output descriptors ahead
    /// of its bodies, so dropping a body never needs another catalog lookup. Size this for the
    /// expected delivery lag and short scheduling stalls.
    pub max_hot_block_bytes: NonZeroUsize,
    /// Encoded bytes of blocks read back from custody and kept in memory.
    ///
    /// Reads of older blocks use their own cache and read budget so backfill cannot evict
    /// recent admissions. Size this for concurrent delivery and promotion batches.
    pub max_materialized_block_bytes: NonZeroUsize,
    /// Target encoded bytes of concurrent ancestry and finalized-body fetches.
    ///
    /// The effective fetch concurrency is the smaller of this budget divided by
    /// [`Self::resolver_max_value_bytes`] and [`Capacities::backfill_concurrency`], and at least
    /// one. The resulting response capacity also bounds staged finalized-custody lookahead.
    pub max_backfill_bytes: NonZeroUsize,
    /// Most encoded bytes read from one checkpoint, prepared floor installation, or pending
    /// custody manifest.
    pub max_checkpoint_bytes: NonZeroUsize,
}

impl Limits {
    /// Returns the resolver response bound [`Config::with_max_block_bytes`] derives for producer
    /// blocks of at most `max_block_bytes` encoded bytes.
    ///
    /// A response carries up to 16 such blocks plus its length prefix. Deployments size their
    /// network message bound from this value.
    pub fn sized_resolver_max_value_bytes(max_block_bytes: NonZeroUsize) -> NonZeroUsize {
        max_block_bytes
            .saturating_mul(NZUsize!(SIZED_RESPONSE_BLOCKS))
            .saturating_add(SIZED_RESPONSE_BLOCKS.encode_size())
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_block_bytes: DEFAULT_MAX_BLOCK_BYTES,
            resolver_max_value_bytes: DEFAULT_RESOLVER_MAX_VALUE_BYTES,
            max_commit_block_bytes: DEFAULT_MAX_COMMIT_BLOCK_BYTES,
            max_delivery_bytes: DEFAULT_MAX_DELIVERY_BYTES,
            max_hot_block_bytes: DEFAULT_MAX_HOT_BLOCK_BYTES,
            max_materialized_block_bytes: DEFAULT_MAX_MATERIALIZED_BLOCK_BYTES,
            max_backfill_bytes: DEFAULT_MAX_BACKFILL_BYTES,
            max_checkpoint_bytes: DEFAULT_MAX_CHECKPOINT_BYTES,
        }
    }
}

/// Marshal configuration for one Multimmit epoch.
///
/// The epoch is the start anchor's, and the chain count is the protocol codec's.
pub struct Config<T: Translator, V: Variant, B: Codec + Digestible> {
    /// Anchor for a namespace without durable marshal progress.
    pub start: Start<V, B::Digest>,
    /// Prefix from which exclusive storage partitions are derived.
    pub partition_prefix: String,
    /// Queue, batch and cache capacities.
    pub capacities: Capacities,
    /// Byte bounds.
    pub limits: Limits,
    /// Backend of each finalized artifact family.
    pub retention: Retention,
    /// Bounds used to decode Multimmit proofs and histories.
    pub codec_config: CodecConfig,
    /// Bounds used to decode application block bodies.
    pub body_codec_config: B::Cfg,
    /// Archive buffers, page cache, section sizing, and translator.
    pub archive: ArchiveConfig<T>,
}

impl<T: Translator, V: Variant, B: Codec + Digestible> Config<T, V, B> {
    /// Constructs a configuration with default bounds and immutable finalized archives.
    ///
    /// [`open`](fn@super::open) validates the configuration.
    pub fn new(
        start: Start<V, B::Digest>,
        partition_prefix: String,
        codec_config: CodecConfig,
        body_codec_config: B::Cfg,
        archive: ArchiveConfig<T>,
    ) -> Self {
        Self {
            start,
            partition_prefix,
            capacities: Capacities::default(),
            limits: Limits::default(),
            retention: Retention {
                lqc: ArchiveMode::Immutable,
                history: ArchiveMode::Immutable,
                blocks: ArchiveMode::Immutable,
            },
            codec_config,
            body_codec_config,
            archive,
        }
    }

    /// Sizes every bound that follows from the largest encoded producer block.
    ///
    /// Sets [`Limits::max_block_bytes`], lets one resolver response carry 16 such blocks (see
    /// [`Limits::sized_resolver_max_value_bytes`]) and backfill hold 128 responses at once, and
    /// sizes each pending-block segment near 128 MiB with an admission cut no larger than one
    /// segment or the default cut. Other bounds keep their values.
    pub fn with_max_block_bytes(mut self, max_block_bytes: NonZeroUsize) -> Self {
        let resolver_max_value_bytes = Limits::sized_resolver_max_value_bytes(max_block_bytes);
        self.limits.max_block_bytes = max_block_bytes;
        self.limits.resolver_max_value_bytes = resolver_max_value_bytes;
        self.limits.max_backfill_bytes =
            resolver_max_value_bytes.saturating_mul(NZUsize!(SIZED_CONCURRENT_RESPONSES));
        let segment_items = (SIZED_PENDING_SEGMENT_BYTES / max_block_bytes).max(1);
        self.capacities.pending_segment_items =
            NonZeroU64::new(u64::try_from(segment_items).unwrap_or(u64::MAX))
                .expect("a segment holds at least one block");
        self.capacities.admission_cut_capacity =
            NonZeroUsize::new(segment_items.min(DEFAULT_ADMISSION_CUT_CAPACITY.get()))
                .expect("an admission cut holds at least one block");
        self
    }

    /// Returns the epoch of the start anchor.
    pub fn epoch(&self) -> Epoch {
        self.start.epoch()
    }

    /// Returns the number of producer chains.
    pub const fn chains(&self) -> usize {
        self.codec_config.chains()
    }

    /// Validates relationships not captured by field types.
    ///
    /// This performs structural validation only. In particular, it does not authenticate a
    /// [`Start::Floor`] anchor signature.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.actor_bounds().map(|_| ())
    }

    /// Validates the configuration and derives the bound of each actor queue and pool.
    pub(super) fn actor_bounds(&self) -> Result<ActorBounds, ConfigError> {
        if !valid_partition_prefix(&self.partition_prefix) {
            return Err(ConfigError::InvalidPartitionPrefix);
        }
        let capacities = &self.capacities;
        let limits = &self.limits;
        if capacities.backfill_concurrency > capacities.resolver_mailbox_size {
            return Err(ConfigError::BackfillConcurrency);
        }
        if limits
            .max_block_bytes
            .get()
            .checked_add(1usize.encode_size())
            .is_none_or(|minimum| minimum > limits.resolver_max_value_bytes.get())
        {
            return Err(ConfigError::ResolverResponseCapacity);
        }
        if u64::try_from(capacities.admission_cut_capacity.get()).unwrap_or(u64::MAX)
            > capacities.pending_segment_items.get()
        {
            return Err(ConfigError::AdmissionCutCapacity);
        }
        self.validate_start()?;
        // Resolver deliveries and synchronizer lookup pages can wait behind the same admission
        // cut.
        let custody_waiters = capacities
            .resolver_mailbox_size
            .checked_add(synchronizer::CUSTODY_LOOKUP_CONCURRENCY)
            .ok_or(ConfigError::CustodyWaiterCapacity)?;
        let by_bytes =
            (limits.max_backfill_bytes.get() / limits.resolver_max_value_bytes.get()).max(1);
        let backfill_concurrency =
            NonZeroUsize::new(capacities.backfill_concurrency.get().min(by_bytes))
                .expect("both backfill bounds permit at least one fetch");
        Ok(ActorBounds {
            catalog_mailbox: capacities.catalog_mailbox_size,
            custody_waiters,
            body_waiters: capacities.catalog_mailbox_size,
            body_reads: capacities.catalog_mailbox_size,
            header_requests: backfill_concurrency,
            router_mailbox: capacities.catalog_mailbox_size,
            router_jobs: capacities.resolver_mailbox_size,
            subscription_callers: capacities.resolver_mailbox_size,
            backfill_mailbox: capacities.resolver_mailbox_size,
            backfill_pending: capacities.resolver_mailbox_size,
            serve_active: backfill_concurrency,
            synchronizer_mailbox: capacities.resolver_mailbox_size,
            synchronizer_fetches: backfill_concurrency,
        })
    }

    /// Checks the start anchor's generation, proof structure and frontiers.
    fn validate_start(&self) -> Result<(), ConfigError> {
        let (ordered, emitted) = match &self.start {
            Start::Genesis(genesis) => (genesis.tips(), genesis.tips()),
            Start::Floor {
                floor_generation,
                floor,
            } => {
                if *floor_generation == 0 {
                    return Err(ConfigError::FloorGeneration);
                }
                floor
                    .anchor
                    .validate(self.codec_config)
                    .map_err(|_| ConfigError::FloorProof)?;
                (floor.history.tips(), floor.emitted.as_slice())
            }
        };
        let ordered = Frontier::new(ordered.to_vec()).map_err(|_| ConfigError::StartFrontier)?;
        let emitted = Frontier::new(emitted.to_vec()).map_err(|_| ConfigError::StartFrontier)?;
        if ordered.chains() != self.chains() || emitted.dominates(&ordered).is_err() {
            return Err(ConfigError::StartFrontier);
        }
        Ok(())
    }
}

/// The bound of each actor queue and pool, derived from a [`Config`] and passed by name.
#[derive(Clone, Copy, Debug)]
pub(super) struct ActorBounds {
    /// Capacity of the catalog's command and read mailboxes.
    pub(super) catalog_mailbox: NonZeroUsize,
    /// Most custody requests waiting for admission cuts: every resolver delivery plus the
    /// synchronizer's custody lookups.
    pub(super) custody_waiters: NonZeroUsize,
    /// Most body requests waiting for catalog body reads.
    pub(super) body_waiters: NonZeroUsize,
    /// Most catalog body requests reading at once.
    pub(super) body_reads: NonZeroUsize,
    /// Most segment requests in one catalog header lookup.
    pub(super) header_requests: NonZeroUsize,
    /// Capacity of the public mailbox's router queue.
    pub(super) router_mailbox: NonZeroUsize,
    /// Most router jobs in flight.
    pub(super) router_jobs: NonZeroUsize,
    /// Most callers waiting for block subscriptions.
    pub(super) subscription_callers: NonZeroUsize,
    /// Capacity of the backfill bridge and serve mailboxes.
    pub(super) backfill_mailbox: NonZeroUsize,
    /// Most backfill requests waiting for a peer response, which also bounds the keys backfill
    /// reserves for staging and the peer callers waiting for a served value.
    pub(super) backfill_pending: NonZeroUsize,
    /// Most peer requests served at once, which also bounds backfill rechecks and staged
    /// batches.
    pub(super) serve_active: NonZeroUsize,
    /// Capacity of the synchronizer mailbox, which also bounds the proofs it batches.
    pub(super) synchronizer_mailbox: NonZeroUsize,
    /// Most ancestry or body fetches the synchronizer keeps in flight.
    pub(super) synchronizer_fetches: NonZeroUsize,
}

/// A marshal configuration is internally inconsistent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The storage namespace is empty or cannot be used as a runtime metric label.
    #[error("partition prefix must contain only ASCII alphanumeric characters or underscores")]
    InvalidPartitionPrefix,
    /// Backfill could exhaust the resolver's pending-request registry by itself.
    #[error("backfill concurrency exceeds resolver mailbox capacity")]
    BackfillConcurrency,
    /// One maximum block and its vector framing must fit in a resolver response.
    #[error("resolver response capacity cannot hold one maximum block and its framing")]
    ResolverResponseCapacity,
    /// One maximum admission cut must fit within one pending storage segment.
    #[error("admission cut capacity exceeds pending segment items")]
    AdmissionCutCapacity,
    /// The resolver mailbox leaves no room for the synchronizer's custody lookups.
    #[error("resolver mailbox capacity leaves no room for synchronizer custody lookups")]
    CustodyWaiterCapacity,
    /// A state-sync floor must advance beyond the genesis generation.
    #[error("state-sync floor generation must be positive")]
    FloorGeneration,
    /// The startup frontier has another chain count or ordering.
    #[error("startup frontier does not match the configured chains")]
    StartFrontier,
    /// A state-sync L-QC is structurally invalid under the codec bounds.
    #[error("state-sync floor proof is structurally invalid")]
    FloorProof,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{BlockRef, CertificateId, ChainId, PathLimits},
        simplex::marshal::mocks::block::EmptyBlock,
        types::Height,
    };
    use commonware_cryptography::{
        Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{Runner as _, deterministic};
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
            Start::Genesis(genesis(epoch, chains)),
            "marshal_config_test".into(),
            CodecConfig::new(5, chains as usize, PathLimits::new(4, 0).unwrap()).unwrap(),
            (),
            ArchiveConfig::new(
                TwoCap,
                CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8)),
            ),
        )
    }

    #[test]
    fn default_construction_is_bounded() {
        deterministic::Runner::default().start(|context| async move {
            let config = config(&context, Epoch::new(7), 2);
            assert_eq!(config.chains(), 2);
            assert_eq!(config.epoch(), Epoch::new(7));
            assert_eq!(config.limits.max_block_bytes.get(), 1024 * 1024);
            assert_eq!(
                config.limits.resolver_max_value_bytes.get(),
                4 * 1024 * 1024
            );
            assert_eq!(config.capacities.backfill_concurrency.get(), 512);
            assert_eq!(config.limits.max_backfill_bytes.get(), 256 * 1024 * 1024);
            assert_eq!(config.capacities.header_cache_capacity.get(), 16 * 1024);
            assert_eq!(config.retention.lqc, ArchiveMode::Immutable);
            assert_eq!(
                config.limits.max_commit_block_bytes.get(),
                256 * 1024 * 1024
            );
            assert_eq!(config.capacities.max_pending_acks.get(), 128);
            assert_eq!(config.limits.max_delivery_bytes.get(), 16 * 1024 * 1024);
            assert_eq!(config.limits.max_hot_block_bytes.get(), 512 * 1024 * 1024);
            assert_eq!(
                config.limits.max_materialized_block_bytes.get(),
                512 * 1024 * 1024
            );
            assert!(config.validate().is_ok());
        });
    }

    #[test]
    fn actor_bounds_derive_from_capacities() {
        deterministic::Runner::default().start(|context| async move {
            let mut config = config(&context, Epoch::new(7), 2);
            config.capacities.catalog_mailbox_size = NZUsize!(32);
            config.capacities.resolver_mailbox_size = NZUsize!(600);
            let bounds = config.actor_bounds().unwrap();
            assert_eq!(bounds.catalog_mailbox.get(), 32);
            assert_eq!(bounds.body_waiters.get(), 32);
            assert_eq!(bounds.body_reads.get(), 32);
            assert_eq!(bounds.router_mailbox.get(), 32);
            assert_eq!(
                bounds.custody_waiters.get(),
                600 + synchronizer::CUSTODY_LOOKUP_CONCURRENCY
            );
            for bound in [
                bounds.router_jobs,
                bounds.subscription_callers,
                bounds.backfill_mailbox,
                bounds.backfill_pending,
                bounds.synchronizer_mailbox,
            ] {
                assert_eq!(bound.get(), 600);
            }
            for bound in [
                bounds.header_requests,
                bounds.serve_active,
                bounds.synchronizer_fetches,
            ] {
                assert_eq!(bound.get(), 64);
            }
        });
    }

    #[test]
    fn backfill_concurrency_obeys_item_and_byte_bounds() {
        deterministic::Runner::default().start(|context| async move {
            let mut config = config(&context, Epoch::new(7), 2);
            let concurrency =
                |config: &TestConfig| config.actor_bounds().unwrap().serve_active.get();
            config.limits.max_block_bytes = NZUsize!(256 * 1024);
            config.limits.resolver_max_value_bytes = NZUsize!(512 * 1024);
            assert_eq!(concurrency(&config), 512);

            config.limits.max_block_bytes = NZUsize!(128 * 1024);
            assert_eq!(concurrency(&config), 512);

            config.limits.resolver_max_value_bytes = NZUsize!(4 * 1024 * 1024);
            assert_eq!(concurrency(&config), 64);

            config.limits.max_backfill_bytes = NonZeroUsize::MIN;
            assert_eq!(concurrency(&config), 1);
        });
    }

    #[test]
    fn validation_rejects_cross_context_configuration() {
        deterministic::Runner::default().start(|context| async move {
            let mut invalid = config(&context, Epoch::new(7), 2);
            invalid.partition_prefix.clear();
            assert_eq!(invalid.validate(), Err(ConfigError::InvalidPartitionPrefix));
            let mut invalid = config(&context, Epoch::new(7), 2);
            invalid.codec_config = CodecConfig::new(5, 1, PathLimits::new(4, 0).unwrap()).unwrap();
            assert_eq!(invalid.validate(), Err(ConfigError::StartFrontier));
            let mut invalid = config(&context, Epoch::new(7), 2);
            invalid.capacities.backfill_concurrency = NZUsize!(3);
            invalid.capacities.resolver_mailbox_size = NZUsize!(2);
            assert_eq!(invalid.validate(), Err(ConfigError::BackfillConcurrency));
            let mut invalid = config(&context, Epoch::new(7), 2);
            invalid.limits.max_block_bytes = NZUsize!(1024);
            invalid.limits.resolver_max_value_bytes = NZUsize!(1024);
            assert_eq!(
                invalid.validate(),
                Err(ConfigError::ResolverResponseCapacity)
            );
            invalid.limits.resolver_max_value_bytes = NZUsize!(1025);
            assert!(invalid.validate().is_ok());
            let mut invalid = config(&context, Epoch::new(7), 2);
            invalid.capacities.admission_cut_capacity = NZUsize!(2048);
            invalid.capacities.pending_segment_items = NZU64!(1024);
            assert_eq!(invalid.validate(), Err(ConfigError::AdmissionCutCapacity));
            let mut invalid = config(&context, Epoch::new(7), 2);
            invalid.capacities.resolver_mailbox_size = NonZeroUsize::MAX;
            assert_eq!(invalid.validate(), Err(ConfigError::CustodyWaiterCapacity));
        });
    }

    #[test]
    fn max_block_bytes_sizes_every_block_dependent_bound() {
        deterministic::Runner::default().start(|context| async move {
            for max_block_bytes in [1, 1_024, 524_387, 256 * 1024 * 1024] {
                let max_block_bytes = NonZeroUsize::new(max_block_bytes).unwrap();
                let config =
                    config(&context, Epoch::new(3), 2).with_max_block_bytes(max_block_bytes);
                let resolver = Limits::sized_resolver_max_value_bytes(max_block_bytes);
                assert_eq!(config.limits.max_block_bytes, max_block_bytes);
                assert_eq!(config.limits.resolver_max_value_bytes, resolver);
                assert_eq!(
                    resolver.get(),
                    max_block_bytes.get() * SIZED_RESPONSE_BLOCKS + 1
                );
                assert_eq!(
                    config.limits.max_backfill_bytes.get(),
                    resolver.get() * SIZED_CONCURRENT_RESPONSES
                );
                let segment = (SIZED_PENDING_SEGMENT_BYTES / max_block_bytes.get()).max(1);
                assert_eq!(
                    config.capacities.pending_segment_items.get(),
                    segment as u64
                );
                assert_eq!(
                    config.capacities.admission_cut_capacity.get(),
                    segment.min(DEFAULT_ADMISSION_CUT_CAPACITY.get())
                );
                config.validate().expect("sized configuration is valid");
            }
        });
    }
}
