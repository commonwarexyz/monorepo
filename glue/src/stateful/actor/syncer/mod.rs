use crate::stateful::{
    db::{Anchor, DatabaseSet},
    Application,
};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_consensus::{
    marshal::{
        core::{CommitmentFallback, Mailbox as MarshalMailbox, Variant},
        Identifier,
    },
    simplex::types::Finalization,
    types::Height,
};
use commonware_cryptography::{certificate::Scheme, Digest, Digestible};
use commonware_runtime::{Buf, BufMut, Clock, Metrics, Spawner};
use commonware_storage::{
    metadata::{self, Metadata},
    Context,
};
use commonware_utils::{fixed_bytes, sequence::FixedBytes};
use rand_core::Rng;

mod actor;
pub(crate) use actor::{Config, Syncer};

mod mailbox;
pub(crate) use mailbox::Mailbox;

mod plan;
pub use plan::SyncPlan;

const SYNC_METADATA_SUFFIX: &str = "state_sync_metadata";
const SYNC_STATE_KEY: FixedBytes<1> = fixed_bytes!("C0");

type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;

/// Identity of a state sync floor used to validate restarts.
///
/// The height enforces monotonic restarts, and the commitment distinguishes
/// conflicting blocks at the same height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FloorMarker<C>
where
    C: Digest,
{
    height: Height,
    commitment: C,
}

impl<C> FloorMarker<C>
where
    C: Digest,
{
    /// Constructs a durable floor marker from the resolved floor block.
    pub(crate) const fn new(height: Height, commitment: C) -> Self {
        Self { height, commitment }
    }

    /// Ensures a newly selected floor is compatible with this persisted one.
    ///
    /// Restarts may resume from the same floor or advance to a newer one, but
    /// must never move backward or switch to a different block at the same height.
    pub(crate) fn ensure_not_behind(&self, selected: &Self) {
        assert!(
            selected.height >= self.height,
            "selected state sync floor cannot move behind the persisted in-progress floor",
        );

        if selected.height == self.height {
            assert!(
                selected.commitment == self.commitment,
                "selected state sync floor conflicts with the persisted in-progress floor",
            );
        }
    }
}

/// Durable sync progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SyncState<S, C>
where
    S: Scheme,
    C: Digest,
{
    /// Peer state sync is running from `floor`, whose block sits at `height`.
    InProgress {
        height: Height,
        floor: Finalization<S, C>,
    },
    /// Startup completed at `height`. `floor` is the finalization this node
    /// originally state synced from, if it ever ran peer state sync. It is
    /// re-provided to marshal as its startup anchor on every future boot.
    Complete {
        height: Height,
        floor: Option<Finalization<S, C>>,
    },
}

impl<S, C> SyncState<S, C>
where
    S: Scheme,
    C: Digest,
{
    /// Returns the completed state sync height, if state sync has finished.
    pub(crate) const fn sync_height(&self) -> Option<Height> {
        match self {
            Self::InProgress { .. } => None,
            Self::Complete { height, .. } => Some(*height),
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
            Self::InProgress { height, floor } => {
                0u8.write(writer);
                height.write(writer);
                floor.write(writer);
            }
            Self::Complete { height, floor } => {
                1u8.write(writer);
                height.write(writer);
                floor.write(writer);
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
                Self::InProgress { height, floor } => height.encode_size() + floor.encode_size(),
                Self::Complete { height, floor } => height.encode_size() + floor.encode_size(),
            }
    }
}

impl<S, C> Read for SyncState<S, C>
where
    S: Scheme,
    C: Digest,
{
    type Cfg = <Finalization<S, C> as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(reader)? {
            0 => Ok(Self::InProgress {
                height: Height::read(reader)?,
                floor: Finalization::read_cfg(reader, cfg)?,
            }),
            1 => Ok(Self::Complete {
                height: Height::read(reader)?,
                floor: Option::<Finalization<S, C>>::read_cfg(reader, cfg)?,
            }),
            n => Err(Error::InvalidEnum(n)),
        }
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
    /// The anchor on which the database set converged.
    pub anchor: Anchor<BlockDigest<A, E>>,
}

impl<E, A> Clone for SyncResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn clone(&self) -> Self {
        Self {
            databases: self.databases.clone(),
            anchor: self.anchor,
        }
    }
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
    ///
    /// `certificate_cfg` is the scheme's certificate codec configuration,
    /// used to read the stored floor finalization.
    pub(crate) async fn init(
        context: &E,
        partition_prefix: impl AsRef<str>,
        certificate_cfg: <S::Certificate as Read>::Cfg,
    ) -> Self {
        let partition_prefix = partition_prefix.as_ref().to_string();
        let metadata = Metadata::init(
            context.child("metadata"),
            metadata::Config {
                partition: format!("{partition_prefix}{SYNC_METADATA_SUFFIX}"),
                codec_config: certificate_cfg,
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
            Some(SyncState::InProgress { .. })
        )
    }

    /// Returns the finalization this node originally state synced from, if
    /// it ever ran peer state sync to completion.
    pub(crate) fn completed_floor(&self) -> Option<&Finalization<S, C>> {
        match self.metadata.get(&SYNC_STATE_KEY) {
            Some(SyncState::Complete { floor, .. }) => floor.as_ref(),
            _ => None,
        }
    }

    /// Returns the floor an interrupted state sync was armed with, if one is
    /// in progress.
    pub(crate) fn in_progress_floor(&self) -> Option<&Finalization<S, C>> {
        match self.metadata.get(&SYNC_STATE_KEY) {
            Some(SyncState::InProgress { floor, .. }) => Some(floor),
            _ => None,
        }
    }

    /// Marks state sync as in progress for the resolved floor.
    ///
    /// This must be persisted before any state sync database mutation begins so the database
    /// sync engine can reopen partial sync state and validate the next selected floor after a crash.
    ///
    /// If an interrupted state sync already stored a floor, the newly selected
    /// floor must resume from that same floor or a later one. State sync runs
    /// at most once per node, so arming it after a completed sync panics.
    ///
    /// `height` is the height of the block `floor` finalizes.
    pub(crate) async fn begin_sync(&mut self, height: Height, floor: Finalization<S, C>) {
        let marker = FloorMarker::new(height, floor.proposal.payload);
        match self.metadata.get(&SYNC_STATE_KEY) {
            Some(SyncState::InProgress {
                height: existing_height,
                floor: existing,
            }) => {
                FloorMarker::new(*existing_height, existing.proposal.payload)
                    .ensure_not_behind(&marker);
            }
            Some(SyncState::Complete { .. }) => {
                unreachable!("state sync cannot restart after completion");
            }
            None => {}
        }

        self.metadata
            .put_sync(SYNC_STATE_KEY, SyncState::InProgress { height, floor })
            .await
            .expect("failed to set state sync state to in-progress");
    }

    /// Records that one-time state sync completed at the given height.
    ///
    /// Once this height is set, future startups skip peer state sync and initialize
    /// from the later of this height and marshal's processed height instead. The
    /// completed height only moves forward.
    pub(crate) async fn set_complete(&mut self, height: Height) {
        let floor = match self.metadata.get(&SYNC_STATE_KEY) {
            Some(SyncState::InProgress {
                height: floor_height,
                floor,
            }) => {
                assert!(
                    height >= *floor_height,
                    "completed state sync height cannot be behind the in-progress floor",
                );
                Some(floor.clone())
            }
            Some(SyncState::Complete {
                height: existing,
                floor,
            }) => {
                assert!(
                    height >= *existing,
                    "completed state sync height cannot move backward",
                );
                floor.clone()
            }
            None => None,
        };

        self.metadata
            .put_sync(SYNC_STATE_KEY, SyncState::Complete { height, floor })
            .await
            .expect("failed to set state sync state to complete");
    }
}

/// Resolves the selected state sync floor into the anchor, targets, and
/// durable floor marker used by restart validation.
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
        V::into_inner(block)
    };

    ResolvedFloor {
        anchor: Anchor::from(&floor),
        targets: A::sync_targets(&floor),
    }
}

/// Initializes databases at marshal's current startup floor.
///
/// This initialization route is used when startup should recover from marshal
/// instead of running peer state sync. If marshal has not yet recorded a
/// processed height, this falls back to marshal's genesis block so fresh boots
/// and post-sync restarts share the same path.
///
/// The floor block is always retained: marshal is anchored either at genesis
/// or at the stored state sync floor ([SyncPlan] re-provides the original
/// floor on every boot, so durable progress always supersedes it), and
/// pruning keeps at least the ack window behind the processed height. A
/// missing floor block means a floor was provided outside the plan, a state
/// sync request was withdrawn before durable sync progress existed (see
/// [SyncPlan::should_state_sync]), or storage was corrupted, and this
/// function panics.
///
/// Databases ahead of the floor are repaired by rewinding back to it.
/// Outside of state sync (which resumes through the state-sync path when
/// interrupted), blocks are acknowledged only after they are durably
/// finalized, so databases behind the floor are unreachable without storage
/// corruption or a marshal floor above them. Rewind cannot move forward, so
/// this function panics on them instead of falling back to peer state sync.
/// If the databases are entirely inconsistent, this function will panic.
pub(crate) async fn init_databases_from_marshal<E, A, S, V>(
    context: &E,
    marshal: &MarshalMailbox<S, V>,
    db_config: <A::Databases as DatabaseSet<E>>::Config,
    sync_height: Option<Height>,
) -> SyncResult<E, A>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    let processed_height = marshal.get_processed_height().await;
    let floor_height = sync_height
        .into_iter()
        .chain(processed_height)
        .max()
        .unwrap_or_else(Height::zero);
    let floor_block = {
        let block = marshal
            .get_block(Identifier::Height(floor_height))
            .await
            .expect("marshal must retain the block at the startup floor");
        V::into_inner(block)
    };

    let databases = A::Databases::init(context.child("db_set"), db_config).await;
    let floor_targets = A::sync_targets(&floor_block);

    // In the case that the committed targets do not match the marshal floor,
    // we may have suffered a crash that left the set in an inconsistent
    // state. Outside of state sync, blocks are acknowledged only after they
    // are durably finalized and marshal prunes at least an ack window behind
    // its processed height, so crash recovery only finds databases at or
    // ahead of the floor, which rewind repairs. A database behind the floor
    // (storage corruption or a marshal floor above it) cannot rewind forward
    // and fails fatally inside rewind.
    let committed_targets = databases.committed_targets().await;
    if committed_targets != floor_targets {
        databases.rewind_to_targets(floor_targets.clone()).await;
        let rewound_targets = databases.committed_targets().await;
        assert!(
            rewound_targets == floor_targets,
            "databases must be consistent with marshal floor {floor_height} after rewind"
        );
    }

    SyncResult {
        databases,
        anchor: Anchor::from(&floor_block),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::init_databases_from_marshal;
    use crate::stateful::tests::mocks::{TestApp, TestBlock, TestScheme, TestVariant};
    use commonware_actor::Feedback;
    use commonware_consensus::{
        marshal::{
            self,
            core::Actor as MarshalActor,
            resolver::handler::{self, Annotation, Key},
            store::{Blocks, Certificates},
            Update,
        },
        simplex::{
            mocks::scheme as scheme_mocks,
            types::{Finalization, Finalize, Proposal},
        },
        types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
        Heightable as _, Reporter,
    };
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider},
        ed25519,
        sha256::Digest as Sha256Digest,
        Digestible as _,
    };
    use commonware_parallel::Sequential;
    use commonware_resolver::{Fetch, Resolver, TargetedResolver};
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Clock as _, Runner as _, Supervisor as _,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        acknowledgement::Exact, sync::Mutex, vec::NonEmptyVec, Acknowledgement as _, NZUsize,
        NZU16, NZU64,
    };
    use std::{sync::Arc, time::Duration};

    /// A resolver stub that drops every fetch. Startup tests only exercise
    /// blocks marshal already stores locally.
    #[derive(Clone)]
    struct DroppingResolver;

    impl Resolver for DroppingResolver {
        type Key = Key<Sha256Digest>;
        type Subscriber = Annotation;

        fn fetch<F>(&mut self, _fetch: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, _fetches: Vec<F>) -> Feedback
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

    impl TargetedResolver for DroppingResolver {
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
            _fetches: Vec<(F, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }
    }

    /// A marshal reporter that acknowledges dispatched blocks up to a height
    /// and holds later acknowledgements, so marshal stays alive without
    /// advancing its processed height further.
    #[derive(Clone)]
    pub(crate) struct AckingReporter {
        ack_until: Height,
        held: Arc<Mutex<Vec<Exact>>>,
    }

    impl AckingReporter {
        pub(crate) fn new(ack_until: Height) -> Self {
            Self {
                ack_until,
                held: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl Reporter for AckingReporter {
        type Activity = Update<TestBlock>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            if let Update::Block(block, acknowledgement) = activity {
                if block.height() <= self.ack_until {
                    acknowledgement.acknowledge();
                } else {
                    self.held.lock().push(acknowledgement);
                }
            }
            Feedback::Ok
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

    pub(crate) fn make_finalization(
        fixture: &Fixture<TestScheme>,
        block: &TestBlock,
    ) -> Finalization<TestScheme, Sha256Digest> {
        let height = block.height().get();
        let proposal = Proposal::new(
            Round::new(Epoch::zero(), View::new(height)),
            View::new(height.saturating_sub(1)),
            block.digest(),
        );
        let votes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        Finalization::from_finalizes(&fixture.verifier, &votes, &Sequential)
            .expect("finalization quorum")
    }

    /// Start a marshal actor over pre-seeded finalized blocks and
    /// finalizations. The returned handler must be kept alive for the actor
    /// to keep serving mailbox requests.
    pub(crate) async fn start_marshal(
        context: &deterministic::Context,
        partition_prefix: &str,
        start: marshal::Start<TestScheme, Sha256Digest, TestBlock>,
        provider: ConstantProvider<TestScheme, Epoch>,
        blocks: Vec<TestBlock>,
        finalizations: Vec<(TestBlock, Finalization<TestScheme, Sha256Digest>)>,
        reporter: AckingReporter,
    ) -> (
        marshal::core::Mailbox<TestScheme, TestVariant>,
        handler::Handler<Sha256Digest>,
    ) {
        let page_cache = CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8));
        let mut finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(
                page_cache.clone(),
                &format!("{partition_prefix}-finalizations"),
            ),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let mut finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(page_cache.clone(), &format!("{partition_prefix}-blocks")),
        )
        .await
        .expect("failed to initialize blocks archive");

        for block in blocks {
            Blocks::put(&mut finalized_blocks, block)
                .await
                .expect("failed to seed block");
        }
        Blocks::sync(&mut finalized_blocks)
            .await
            .expect("failed to sync seeded blocks");
        for (block, finalization) in finalizations {
            Certificates::put(
                &mut finalizations_by_height,
                block.height(),
                block.digest(),
                finalization,
            )
            .await
            .expect("failed to seed finalization");
        }
        Certificates::sync(&mut finalizations_by_height)
            .await
            .expect("failed to sync seeded finalizations");

        let (actor, mailbox, _height) = MarshalActor::<_, TestVariant, _, _, _, _, _>::init(
            context.child("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider,
                epocher: FixedEpocher::new(NZU64!(u64::MAX)),
                start,
                partition_prefix: format!("{partition_prefix}-marshal"),
                mailbox_size: NZUsize!(16),
                view_retention_timeout: ViewDelta::new(1),
                prunable_items_per_section: NZU64!(4),
                page_cache,
                replay_buffer: NZUsize!(64),
                key_write_buffer: NZUsize!(64),
                value_write_buffer: NZUsize!(64),
                block_codec_config: (),
                max_repair: NZUsize!(4),
                max_pending_acks: NZUsize!(8),
                strategy: Sequential,
            },
        )
        .await;
        let (receiver, handler) = handler::init(context.child("resolver_handler"), NZUsize!(16));
        actor.start_unbuffered(reporter, (receiver, DroppingResolver));
        (mailbox, handler)
    }

    /// A marshal startup floor above durable progress (see
    /// [`marshal::Start::Floor`]) anchors marshal on the floor block, records
    /// the anchor's predecessor as processed, and prunes below the anchor.
    /// Without a stored sync height naming the anchor, startup resolves its
    /// floor to the pruned predecessor and must panic: floors reach marshal
    /// only through the plan, so this layout means a mis-wired caller.
    #[test]
    #[should_panic(expected = "must retain the block at the startup floor")]
    fn startup_panics_when_floor_provided_outside_plan() {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let mut signing_context = context.child("signing");
            let fixture = scheme_mocks::fixture(&mut signing_context, b"startup-floor-jump", 1);
            let provider = ConstantProvider::new(fixture.schemes[0].clone());

            // Marshal holds only the floor anchor: everything below it was
            // pruned when the floor was installed.
            let anchor_block = TestBlock::new(6, 6);
            let finalization = make_finalization(&fixture, &anchor_block);
            let (marshal, _handler) = start_marshal(
                &context,
                "startup-floor-jump",
                marshal::Start::Floor(finalization.clone()),
                provider,
                vec![anchor_block.clone()],
                vec![(anchor_block.clone(), finalization.clone())],
                AckingReporter::new(Height::zero()),
            )
            .await;
            assert_eq!(
                marshal.get_processed_height().await,
                Some(Height::new(5)),
                "startup floor must record the anchor's predecessor as processed",
            );

            let _ = init_databases_from_marshal::<_, TestApp, TestScheme, TestVariant>(
                &context, &marshal, 0, None,
            )
            .await;
        });
    }

    /// Databases behind the marshal floor are fatal even when every block
    /// in the gap is still retained: that state is unreachable without
    /// storage corruption, so startup must panic instead of attempting
    /// repair.
    #[test]
    #[should_panic(expected = "cannot rewind forward")]
    fn startup_panics_when_databases_behind_retained_floor() {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let mut signing_context = context.child("signing");
            let fixture = scheme_mocks::fixture(&mut signing_context, b"behind-retained", 1);
            let provider = ConstantProvider::new(fixture.schemes[0].clone());

            // Marshal retains finalized blocks through height 5 and the
            // application acknowledged them all, while the databases recover
            // at genesis (their committed targets match block 0).
            let mut blocks = Vec::new();
            let mut finalizations = Vec::new();
            for height in 1..=5u64 {
                let block = TestBlock::new(height, height as u8);
                finalizations.push((block.clone(), make_finalization(&fixture, &block)));
                blocks.push(block);
            }
            let (marshal, _handler) = start_marshal(
                &context,
                "behind-retained",
                marshal::Start::Genesis(TestBlock::new(0, 0)),
                provider,
                blocks,
                finalizations,
                AckingReporter::new(Height::new(5)),
            )
            .await;
            while marshal.get_processed_height().await != Some(Height::new(5)) {
                context.sleep(Duration::from_millis(10)).await;
            }

            let _ = init_databases_from_marshal::<_, TestApp, TestScheme, TestVariant>(
                &context, &marshal, 0, None,
            )
            .await;
        });
    }

    /// A restart after completed state sync recovers the anchor from the
    /// stored sync height: marshal's recorded processed height is the
    /// anchor's pruned predecessor, and databases already at the anchor must
    /// start there without rewind or panic.
    #[test]
    fn startup_starts_at_stored_sync_floor() {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let mut signing_context = context.child("signing");
            let fixture = scheme_mocks::fixture(&mut signing_context, b"floor-jump-anchored", 1);
            let provider = ConstantProvider::new(fixture.schemes[0].clone());

            let anchor_block = TestBlock::new(6, 6);
            let finalization = make_finalization(&fixture, &anchor_block);
            let (marshal, _handler) = start_marshal(
                &context,
                "floor-jump-anchored",
                marshal::Start::Floor(finalization.clone()),
                provider,
                vec![anchor_block.clone()],
                vec![(anchor_block.clone(), finalization.clone())],
                AckingReporter::new(Height::zero()),
            )
            .await;

            let result = init_databases_from_marshal::<_, TestApp, TestScheme, TestVariant>(
                &context,
                &marshal,
                6,
                Some(Height::new(6)),
            )
            .await;
            assert_eq!(
                result.anchor.height,
                Height::new(6),
                "databases at the stored sync floor must start there",
            );
        });
    }
}
