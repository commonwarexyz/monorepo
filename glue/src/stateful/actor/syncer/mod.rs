use crate::stateful::{
    Application,
    db::{Anchor, DatabaseSet},
};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_consensus::{
    Block as _, CertifiableBlock, Heightable,
    marshal::{
        Identifier,
        core::{CommitmentFallback, Floor, Mailbox as MarshalMailbox, Variant},
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
use std::future::Future;

mod actor;
pub(crate) use actor::{Config, Syncer};

pub(crate) mod mailbox;
pub(crate) use mailbox::Mailbox;

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
    /// Returns the durable database replay base, if state sync has finished.
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

/// Resolved state sync floor data derived from the selected finalization and marshal progress.
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

    /// Returns the durable database replay base, if state sync has finished.
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

    /// Marks state sync as in progress for the selected floor.
    ///
    /// This must be persisted before any state sync database mutation begins so the database
    /// sync engine can reopen partial sync state and validate the next selected floor after a crash.
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

    /// Records a durable database replay base at the given height.
    ///
    /// Once this height is set, future startups skip peer state sync, reopen the
    /// databases at this block, and replay marshal's retained finalized suffix.
    /// The height may advance only after the database state is durable and before
    /// marshal prunes any block required by the new replay base.
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

/// Returns the archived block that covers marshal's durable processed position.
///
/// Glue cannot reopen below this position because marshal will not redeliver acknowledged blocks.
/// An acknowledgement-derived position retains its own block. Installing a floor instead records
/// and prunes the anchor's predecessor so marshal redispatches the anchor, leaving `height.next()`
/// as the block that covers the processed position.
async fn processed_anchor<S, V>(marshal: &MarshalMailbox<S, V>, height: Height) -> V::Block
where
    S: Scheme,
    V: Variant,
{
    if let Some(block) = marshal.get_block(Identifier::Height(height)).await {
        return block;
    }
    marshal
        .get_block(Identifier::Height(height.next()))
        .await
        .expect("marshal must return floor anchor after processed height")
}

/// Resolves a state sync floor that covers both the selected finalization and marshal's
/// durable processed height.
pub(crate) async fn resolve_state_sync_floor<E, A, S, V>(
    marshal: &MarshalMailbox<S, V>,
    floor: Floor,
    finalization: &Finalization<S, V::Commitment>,
) -> ResolvedFloor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    // Marshal skips installing a startup floor whose round is already processed. Its block may
    // have been pruned, so apply the same rule before registering a local-only waiter.
    let block = if let Some(height) = floor.height()
        && floor.round() >= finalization.round()
    {
        V::owned_into_inner_shared(processed_anchor(marshal, height).await)
    } else {
        // Marshal's configured startup floor fetches its anchor when needed. This local-only
        // subscription observes that result without starting a separate fetch.
        let selected = {
            let block = marshal
                .subscribe_by_commitment(finalization.proposal.payload, CommitmentFallback::Wait)
                .await
                .expect("marshal must yield floor block");
            V::into_inner_shared(block)
        };

        // Marshal does not redeliver acknowledged blocks. A newly installed floor is the
        // exception: its processed position is the predecessor so the retained anchor is
        // dispatched once.
        match marshal.get_processed_height().await {
            Some(height) if height > selected.height() => {
                V::owned_into_inner_shared(processed_anchor(marshal, height).await)
            }
            _ => selected,
        }
    };

    ResolvedFloor {
        anchor: Anchor::from(block.as_ref()),
        targets: A::sync_targets(block.as_ref()),
    }
}

/// Startup recovery result carrying the replay-base metadata into normal processing.
pub(crate) struct RecoveryResult<E, A, S, C>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    S: Scheme,
    C: Digest,
{
    /// The initialized database set and recovered anchor.
    pub sync: SyncResult<E, A>,

    /// Finalized blocks at or below this height are already reflected in the databases.
    pub skip_finalized_until: Option<Height>,

    /// Exclusive lower bound of startup-replayed blocks whose finalized hooks already ran.
    /// When present, it is bounded above by `skip_finalized_until`.
    pub replayed_finalized_after: Option<Height>,

    /// Durable replay-base metadata owned by normal processing after startup.
    pub sync_metadata: StateSyncMetadata<E, S, C>,
}

/// Reopens databases at an inclusive durable base and replays a finalized suffix.
async fn replay_databases_from_base<E, A, F, Fut>(
    context: &E,
    db_config: <A::Databases as DatabaseSet<E>>::Config,
    application: &mut A,
    base_block: A::Block,
    replay_tip: Height,
    mut get_block: F,
) -> SyncResult<E, A>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    F: FnMut(Height) -> Fut + Send,
    Fut: Future<Output = Option<A::Block>> + Send,
{
    assert!(
        replay_tip >= base_block.height(),
        "replay tip cannot precede the durable base",
    );

    let databases = A::Databases::init(context.child("db_set"), db_config).await;
    let base_targets = A::sync_targets(&base_block);
    databases.rewind_to_targets(base_targets.clone()).await;
    assert!(
        databases.committed_targets().await == base_targets,
        "databases must match the durable replay base after rewind",
    );

    let mut previous = base_block;
    while previous.height() < replay_tip {
        let expected_height = previous.height().next();
        let block = get_block(expected_height)
            .await
            .expect("marshal must retain every finalized block after the replay base");
        assert!(
            block.height() == expected_height,
            "archived replay blocks must have contiguous heights",
        );
        assert!(
            block.parent() == previous.digest(),
            "archived replay blocks must have contiguous parents",
        );

        let batches = databases.new_batches().await;
        let merkleized = application
            .apply((context.child("apply"), block.context()), &block, batches)
            .await;
        let targets = A::sync_targets(&block);
        // Application execution only constructs batches. Validate their commitments before the
        // database set publishes the replayed state.
        assert!(
            A::Databases::matches_sync_targets(&merkleized, &targets),
            "replayed database batches must match block sync targets",
        );
        databases.apply(merkleized).await;
        application
            .finalized(
                (context.child("finalized"), block.context()),
                &block,
                databases.readers(),
            )
            .await;

        previous = block;
    }

    let anchor = Anchor::from(&previous);
    SyncResult { databases, anchor }
}

/// Initializes databases from their durable replay base and reconstructs marshal's startup tip.
pub(crate) async fn recover_databases_from_marshal<E, A, S, V>(
    context: &E,
    marshal: &MarshalMailbox<S, V>,
    db_config: <A::Databases as DatabaseSet<E>>::Config,
    sync_metadata: StateSyncMetadata<E, S, V::Commitment>,
    application: &mut A,
) -> RecoveryResult<E, A, S, V::Commitment>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    assert!(
        !sync_metadata.in_progress(),
        "startup replay cannot replace an interrupted state sync",
    );
    let sync_height = sync_metadata.sync_height();
    let base_height = sync_height.unwrap_or_else(Height::zero);
    let processed_height = marshal.get_processed_height().await;
    let startup_replay_tip = marshal.get_startup_replay_tip().await;
    let replay_tip = [processed_height, startup_replay_tip]
        .into_iter()
        .flatten()
        .fold(base_height, Height::max);
    let skip_finalized_until = [sync_height, startup_replay_tip]
        .into_iter()
        .flatten()
        .any(|height| processed_height.is_none_or(|processed| height > processed))
        .then_some(replay_tip);
    let replayed_finalized_after =
        (skip_finalized_until.is_some() && replay_tip > base_height).then_some(base_height);

    let base_block = marshal
        .get_block(Identifier::Height(base_height))
        .await
        .expect("marshal must retain the durable replay base block");
    let base_block = V::into_inner(base_block);
    assert!(
        base_block.height() == base_height,
        "marshal must return the exact durable replay base block",
    );

    let sync = replay_databases_from_base(
        context,
        db_config,
        application,
        base_block,
        replay_tip,
        |height| async move {
            marshal
                .get_block(Identifier::Height(height))
                .await
                .map(V::into_inner)
        },
    )
    .await;

    let sync_metadata = if sync_height.is_none() {
        sync_metadata.set_complete(base_height).await
    } else {
        sync_metadata
    };

    RecoveryResult {
        sync,
        skip_finalized_until,
        replayed_finalized_after,
        sync_metadata,
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod tests {
    mod conformance {
        use crate::stateful::{actor::syncer::SyncState, tests::mocks::TestScheme};
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<SyncState<TestScheme, Sha256Digest>>,
        }
    }
}
