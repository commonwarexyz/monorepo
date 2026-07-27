use crate::stateful::{
    Application,
    db::{Anchor, DatabaseSet},
};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_consensus::{
    CertifiableBlock, Heightable, Roundable,
    marshal::{
        Identifier,
        core::{CommitmentFallback, Mailbox as MarshalMailbox, Variant},
    },
    simplex::types::Finalization,
    types::Height,
};
use commonware_cryptography::{Digest, Digestible, certificate::Scheme};
use commonware_runtime::{Buf, BufMut, Clock, Metrics, Spawner};
use commonware_storage::{
    Context,
    metadata::{self, Metadata},
};
use commonware_utils::{fixed_bytes, sequence::FixedBytes};
use rand_core::Rng;

mod actor;
pub(crate) use actor::{Config, Syncer};

pub(crate) mod mailbox;
pub(crate) use mailbox::{Artifact, Mailbox};

mod plan;
pub use plan::SyncPlan;

const SYNC_METADATA_SUFFIX: &str = "state_sync_metadata";
const SYNC_STATE_KEY: FixedBytes<1> = fixed_bytes!("C0");

type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;

/// Durable sync progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SyncState<S, C>
where
    S: Scheme,
    C: Digest,
{
    InProgress(Finalization<S, C>),
    Complete(Height),
}

impl<S, C> SyncState<S, C>
where
    S: Scheme,
    C: Digest,
{
    /// Returns the completed state sync height, if state sync has finished.
    pub(crate) const fn sync_height(&self) -> Option<Height> {
        match self {
            Self::InProgress(_) => None,
            Self::Complete(height) => Some(*height),
        }
    }
}

impl<S, C> Write for SyncState<S, C>
where
    S: Scheme,
    C: Digest,
{
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::InProgress(floor) => {
                0u8.write(writer);
                floor.write(writer);
            }
            Self::Complete(height) => {
                1u8.write(writer);
                height.write(writer);
            }
        }
    }
}

impl<S, C> EncodeSize for SyncState<S, C>
where
    S: Scheme,
    C: Digest,
{
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::InProgress(floor) => floor.encode_size(),
                Self::Complete(height) => height.encode_size(),
            }
    }
}

impl<S, C> Read for SyncState<S, C>
where
    S: Scheme,
    C: Digest,
{
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(reader)? {
            0 => Ok(Self::InProgress(Finalization::read_cfg(reader, cfg)?)),
            1 => Ok(Self::Complete(Height::read(reader)?)),
            n => Err(Error::InvalidEnum(n)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, S, C> arbitrary::Arbitrary<'a> for SyncState<S, C>
where
    S: Scheme,
    S::Certificate: for<'b> arbitrary::Arbitrary<'b>,
    C: Digest + for<'b> arbitrary::Arbitrary<'b>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(if u.arbitrary::<bool>()? {
            Self::InProgress(u.arbitrary()?)
        } else {
            Self::Complete(u.arbitrary()?)
        })
    }
}

/// The result of a state sync operation.
pub struct SyncResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The database handle set.
    pub databases: A::Databases,
    /// The anchor at which state sync completed.
    pub anchor: Anchor<BlockDigest<A, E>>,
}

/// Resolved state sync floor data derived from the selected finalization.
pub(crate) struct ResolvedFloor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub anchor: Anchor<BlockDigest<A, E>>,
    pub targets: <A::Databases as DatabaseSet<E>>::SyncTargets,
}

/// Durable state-sync metadata.
///
/// Mutating functions consume the metadata and return it only on success. Storage failures
/// panic.
pub(crate) struct StateSyncMetadata<E, S, C>
where
    E: Context,
    S: Scheme,
    C: Digest,
{
    partition_prefix: String,
    metadata: Metadata<E, FixedBytes<1>, SyncState<S, C>>,
}

impl<E, S, C> StateSyncMetadata<E, S, C>
where
    E: Context,
    S: Scheme,
    C: Digest,
{
    /// Load the durable state-sync metadata partition, creating it if needed.
    pub(crate) async fn init(context: &E, partition_prefix: impl AsRef<str>) -> Self {
        let partition_prefix = partition_prefix.as_ref().to_string();
        let metadata = Metadata::init(
            context.child("metadata"),
            metadata::Config {
                partition: format!("{partition_prefix}{SYNC_METADATA_SUFFIX}"),
                codec_config: S::certificate_codec_config_unbounded(),
            },
        )
        .await
        .expect("failed to load sync metadata");
        Self {
            partition_prefix,
            metadata,
        }
    }

    /// Returns the partition prefix for this state-sync metadata store.
    pub(crate) const fn partition_prefix(&self) -> &str {
        self.partition_prefix.as_str()
    }

    /// Returns the completed state sync height, if state sync has finished.
    pub(crate) fn sync_height(&self) -> Option<Height> {
        self.metadata
            .get(&SYNC_STATE_KEY)
            .map(SyncState::sync_height)
            .unwrap_or_default()
    }

    /// Returns whether state sync is in progress.
    pub(crate) fn in_progress(&self) -> bool {
        matches!(
            self.metadata.get(&SYNC_STATE_KEY),
            Some(SyncState::InProgress(_))
        )
    }

    /// Returns the floor selected before an interrupted state sync.
    pub(crate) fn in_progress_floor(&self) -> Option<&Finalization<S, C>> {
        match self.metadata.get(&SYNC_STATE_KEY) {
            Some(SyncState::InProgress(floor)) => Some(floor),
            _ => None,
        }
    }

    /// Marks state sync as in progress for the resolved floor.
    ///
    /// This must be persisted before any state sync database mutation begins so the database
    /// sync engine can reopen partial sync state and validate the next selected floor after a crash.
    ///
    /// If an interrupted state sync already stored a floor, the newly selected
    /// floor must resume from the same or a later consensus round.
    pub(crate) async fn begin_sync(mut self, floor: Finalization<S, C>) -> Self {
        match self.metadata.get(&SYNC_STATE_KEY) {
            Some(SyncState::InProgress(existing)) => {
                assert!(
                    floor.round() >= existing.round(),
                    "selected state sync floor cannot move behind the persisted in-progress floor",
                );
                if floor.round() == existing.round() {
                    assert!(
                        floor.proposal.payload == existing.proposal.payload,
                        "selected state sync floor conflicts with the persisted in-progress round",
                    );
                }
            }
            Some(SyncState::Complete(_)) => {
                panic!("completed state sync cannot be marked in-progress");
            }
            None => {}
        }

        self.metadata = self
            .metadata
            .put_sync(SYNC_STATE_KEY, SyncState::InProgress(floor))
            .await
            .expect("failed to set state sync state to in-progress");
        self
    }

    /// Records that one-time state sync completed at the given height.
    ///
    /// Once this height is set, future startups skip peer state sync and initialize
    /// from the later of this height and marshal's processed height instead. This
    /// action is irreversible.
    pub(crate) async fn set_complete(mut self, height: Height) -> Self {
        if let Some(SyncState::Complete(existing)) = self.metadata.get(&SYNC_STATE_KEY) {
            assert!(
                height >= *existing,
                "completed state sync height cannot move backward",
            );
        }

        self.metadata = self
            .metadata
            .put_sync(SYNC_STATE_KEY, SyncState::Complete(height))
            .await
            .expect("failed to set state sync state to complete");
        self
    }
}

/// Resolves the selected state sync floor into its anchor and targets.
pub(crate) async fn resolve_state_sync_floor<E, A, S, V>(
    marshal: &MarshalMailbox<S, V>,
    finalization: &Finalization<S, V::Commitment>,
) -> ResolvedFloor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    // Wait to retrieve the floor block from marshal. We use `Wait` here,
    // since marshal triggers a fetch for the floor block if it is not
    // already available.
    let floor = {
        let block = marshal
            .subscribe_by_commitment(finalization.proposal.payload, CommitmentFallback::Wait)
            .await
            .expect("marshal must yield floor block");
        V::into_inner_shared(block)
    };

    ResolvedFloor {
        anchor: Anchor::from(floor.as_ref()),
        targets: A::sync_targets(floor.as_ref()),
    }
}

/// The result of initializing state from marshal on startup.
pub(crate) struct StartupResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The initialized database set and anchor.
    pub sync: SyncResult<E, A>,

    /// Finalized marshal blocks at or below this height are already reflected
    /// in the initialized database set and should be acknowledged without
    /// applying them again.
    pub skip_finalized_until: Option<Height>,
}

/// Initializes databases at marshal's current startup anchor.
///
/// This initialization route is used when startup should recover from marshal
/// instead of running peer state sync. If marshal has not yet recorded a
/// processed height, this falls back to marshal's genesis block so fresh boots
/// and post-sync restarts share the same path.
///
/// If the databases are found to be inconsistent with the marshal floor, this
/// function will attempt to repair by rewinding the databases which are ahead. If the
/// databases are entirely inconsistent, this function will panic.
pub(crate) async fn init_databases_from_marshal<E, A, S, V>(
    context: &E,
    marshal: &MarshalMailbox<S, V>,
    db_config: <A::Databases as DatabaseSet<E>>::Config,
    sync_metadata: StateSyncMetadata<E, S, V::Commitment>,
) -> StartupResult<E, A>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    let sync_height = sync_metadata.sync_height();
    let processed_height = marshal.get_processed_height().await;
    let skip_finalized_until = match (sync_height, processed_height) {
        (Some(sync_height), Some(processed_height)) if processed_height < sync_height => {
            Some(sync_height)
        }
        (Some(sync_height), None) => Some(sync_height),
        _ => None,
    };
    let marshal_floor = sync_height
        .into_iter()
        .chain(processed_height)
        .max()
        .unwrap_or_else(Height::zero);
    let floor_block = {
        let marshal_block = marshal
            .get_block(Identifier::Height(marshal_floor))
            .await
            .expect("marshal must return floor block");
        V::into_inner(marshal_block)
    };

    let mut databases = A::Databases::init(context.child("db_set"), db_config).await;
    let processed_targets = A::sync_targets(&floor_block);

    // In the case that the committed targets do not match the marshal floor, we may
    // have suffered a crash that left the set in an inconsistent state. In this case,
    // we attempt to repair by rewinding the databases back to the marshal floor. If
    // the rewind fails to produce a consistent state, we must crash. This can occur
    // if the databases were corrupted or pruned too aggressively.
    if databases.applied_targets() != processed_targets {
        databases = databases.rewind_to_targets(processed_targets.clone()).await;
        let rewound_targets = databases.applied_targets();
        assert!(
            rewound_targets == processed_targets,
            "databases must be consistent with marshal floor after rewind"
        );
    }

    // Once startup has aligned databases with marshal, future boots should skip peer
    // state sync and recover from the later of this anchor and marshal's durable
    // processed height.
    sync_metadata.set_complete(floor_block.height()).await;

    let anchor = Anchor {
        height: floor_block.height(),
        round: floor_block.context().round(),
        digest: floor_block.digest(),
    };
    StartupResult {
        sync: SyncResult { databases, anchor },
        skip_finalized_until,
    }
}

#[cfg(test)]
mod tests {
    use super::{StateSyncMetadata, init_databases_from_marshal};
    use crate::stateful::{
        Application, Input, Proposed,
        db::{DatabaseSet, ManagedDb},
        tests::mocks::{TestBlock, TestMerkleized, TestScheme, TestUnmerkleized, TestVariant},
    };
    use commonware_actor::Feedback;
    use commonware_consensus::{
        Heightable as _, Reporter,
        marshal::{
            self, Update, ancestry::Ancestry, core::Actor as MarshalActor, resolver::handler,
        },
        simplex::{mocks::scheme as scheme_mocks, types::Context as SimplexContext},
        types::{FixedEpocher, Height, ViewDelta},
    };
    use commonware_cryptography::{
        certificate::ConstantProvider, ed25519, sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_resolver::{Fetch, Resolver, TargetedResolver};
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        Acknowledgement as _, NZU16, NZU64, NZUsize, sync::Mutex, vec::NonEmptyVec,
    };
    use std::{convert::Infallible, sync::Arc};

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use crate::stateful::{actor::syncer::SyncState, tests::mocks::TestScheme};
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<SyncState<TestScheme, Sha256Digest>>,
        }
    }

    /// Database whose applied sync target is set by config, recording every
    /// rewind. A stubborn instance ignores rewinds, modeling state that cannot
    /// converge on the marshal floor.
    struct RewindDb {
        target: u64,
        stubborn: bool,
        rewinds: Arc<Mutex<Vec<u64>>>,
    }

    impl ManagedDb<deterministic::Context> for RewindDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = (u64, bool, Arc<Mutex<Vec<u64>>>);
        type SyncTarget = u64;
        type Snapshot = ();

        fn initial_sync_target() -> Self::SyncTarget {
            0
        }

        async fn init(
            _context: deterministic::Context,
            (target, stubborn, rewinds): Self::Config,
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                target,
                stubborn,
                rewinds,
            })
        }

        fn new_batch(&self) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        async fn finalize(
            self,
            _batch: Self::Merkleized,
        ) -> Result<(Self, Self::Snapshot, commonware_runtime::Handle<()>), Self::Error> {
            unreachable!("startup reconciliation never finalizes")
        }

        fn sync_target(&self) -> Self::SyncTarget {
            self.target
        }

        async fn rewind_to_target(mut self, target: Self::SyncTarget) -> Result<Self, Self::Error> {
            self.rewinds.lock().push(target);
            if !self.stubborn {
                self.target = target;
            }
            Ok(self)
        }
    }

    /// Application binding [`RewindDb`] for startup reconciliation; only
    /// `sync_targets` is ever called.
    #[derive(Clone)]
    struct RewindApp;

    impl Application<deterministic::Context> for RewindApp {
        type SigningScheme = TestScheme;
        type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;
        type Block = TestBlock;
        type Databases = (RewindDb,);
        type Provider = ();
        type Input = ();

        fn sync_targets(
            block: &Self::Block,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
            (block.height().get(),)
        }

        async fn genesis(&mut self) -> Self::Block {
            unreachable!("startup reconciliation never proposes")
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _databases: &Self::Databases,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            unreachable!("startup reconciliation never proposes")
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _databases: &Self::Databases,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
            unreachable!("startup reconciliation never verifies")
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _databases: &Self::Databases,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized {
            unreachable!("startup reconciliation never applies")
        }
    }

    fn archive_config(page_cache: CacheRef, partition: &str) -> immutable::Config<()> {
        immutable::Config {
            metadata_partition: format!("{partition}-metadata"),
            freezer_table_partition: format!("{partition}-freezer-table"),
            freezer_table_initial_size: 4,
            freezer_table_resize_frequency: 2,
            freezer_table_resize_chunk_size: 2,
            freezer_key_partition: format!("{partition}-freezer-key"),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!("{partition}-freezer-value"),
            freezer_value_target_size: 128,
            freezer_value_compression: None,
            ordinal_partition: format!("{partition}-ordinal"),
            items_per_section: NZU64!(4),
            codec_config: (),
            replay_buffer: NZUsize!(64),
            freezer_key_write_buffer: NZUsize!(64),
            freezer_value_write_buffer: NZUsize!(64),
            ordinal_write_buffer: NZUsize!(64),
        }
    }

    /// Reporter for the started marshal fixture that acknowledges every dispatched block.
    #[derive(Clone)]
    struct NoopReporter;

    impl Reporter for NoopReporter {
        type Activity = Update<TestBlock>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            if let Update::Block(_, ack) = activity {
                ack.acknowledge();
            }
            Feedback::Ok
        }
    }

    /// Backfill resolver for the started marshal fixture; every fetch is ignored.
    #[derive(Clone)]
    struct IgnoreResolver;

    impl Resolver for IgnoreResolver {
        type Key = handler::Key<Sha256Digest>;
        type Subscriber = handler::Annotation;

        fn fetch<F>(&mut self, _key: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, _keys: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }

        fn retain(
            &mut self,
            _predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            Feedback::Ok
        }
    }

    impl TargetedResolver for IgnoreResolver {
        type PublicKey = ed25519::PublicKey;

        fn fetch_targeted(
            &mut self,
            _fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
            _targets: NonEmptyVec<Self::PublicKey>,
        ) -> Feedback {
            Feedback::Ok
        }

        fn fetch_all_targeted<F>(
            &mut self,
            _keys: Vec<(F, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }
    }

    /// Start a fresh marshal whose floor is the genesis block.
    async fn init_marshal_mailbox(
        mut context: deterministic::Context,
    ) -> (
        commonware_consensus::marshal::core::Mailbox<TestScheme, TestVariant>,
        handler::Handler<Sha256Digest>,
        commonware_runtime::Handle<()>,
    ) {
        let fixture = scheme_mocks::fixture(&mut context, b"syncer-harness", 1);
        let provider = ConstantProvider::new(fixture.schemes[0].clone());
        let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8));
        let finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(page_cache.clone(), "syncer-finalizations"),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(page_cache.clone(), "syncer-blocks"),
        )
        .await
        .expect("failed to initialize blocks archive");

        let (actor, mailbox, _height) = MarshalActor::<_, TestVariant, _, _, _, _, _>::init(
            context.child("marshal_actor"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider,
                epocher: FixedEpocher::new(NZU64!(u64::MAX)),
                start: marshal::Start::Genesis(TestBlock::new(0, 0)),
                partition_prefix: "syncer-harness".to_string(),
                mailbox_size: NZUsize!(8),
                view_retention: ViewDelta::new(1),
                prunable_items_per_section: NZU64!(4),
                page_cache,
                replay_buffer: NZUsize!(64),
                key_write_buffer: NZUsize!(64),
                value_write_buffer: NZUsize!(64),
                block_codec_config: (),
                max_repair: NZUsize!(1),
                max_pending_acks: NZUsize!(1),
                strategy: Sequential,
            },
        )
        .await;
        let (resolver_receiver, resolver_handler) =
            handler::init(context.child("resolver_handler"), NZUsize!(8));
        let handle = actor.start_unbuffered(NoopReporter, (resolver_receiver, IgnoreResolver));
        (mailbox, resolver_handler, handle)
    }

    /// Run startup reconciliation for a [`RewindDb`] whose applied target is
    /// `target`, returning the recorded rewinds and the startup anchor height.
    async fn reconcile(
        context: deterministic::Context,
        target: u64,
        stubborn: bool,
    ) -> (Vec<u64>, Height) {
        let (marshal, _resolver_handler, _marshal_handle) =
            init_marshal_mailbox(context.child("marshal")).await;
        let sync_metadata = StateSyncMetadata::init(&context, "syncer-test").await;
        let rewinds: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let result = init_databases_from_marshal::<_, RewindApp, TestScheme, TestVariant>(
            &context,
            &marshal,
            ((target, stubborn, rewinds.clone()),),
            sync_metadata,
        )
        .await;
        let recorded = rewinds.lock().clone();
        (recorded, result.sync.anchor.height)
    }

    /// Databases ahead of the marshal floor are rewound back to it, repairing
    /// a crash between a database flush and its marshal acknowledgement.
    #[test]
    fn startup_rewinds_databases_ahead_of_the_marshal_floor() {
        deterministic::Runner::default().start(|context| async move {
            let (rewinds, anchor_height) = reconcile(context, 5, false).await;
            assert_eq!(rewinds, vec![0], "the set must rewind to the floor");
            assert_eq!(anchor_height, Height::zero());
        });
    }

    /// Databases already consistent with the marshal floor start as-is.
    #[test]
    fn startup_leaves_consistent_databases_untouched() {
        deterministic::Runner::default().start(|context| async move {
            let (rewinds, anchor_height) = reconcile(context, 0, false).await;
            assert!(rewinds.is_empty(), "a consistent set must not rewind");
            assert_eq!(anchor_height, Height::zero());
        });
    }

    /// A rewind that fails to converge on the marshal floor is unrecoverable.
    #[test]
    #[should_panic(expected = "databases must be consistent with marshal floor after rewind")]
    fn startup_panics_when_rewind_cannot_reach_the_floor() {
        deterministic::Runner::default().start(|context| async move {
            let _ = reconcile(context, 5, true).await;
        });
    }
}
