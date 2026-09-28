use crate::stateful::{
    Application,
    actor::BlockDigest,
    db::{Anchor, DatabaseSet},
};
use commonware_codec::{Buf, EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_consensus::{
    Heightable,
    marshal::{
        Identifier,
        core::{CommitmentFallback, Floor, Mailbox as MarshalMailbox, Processed, Variant},
    },
    simplex::types::Finalization,
    types::Height,
};
use commonware_cryptography::{Digest, certificate::Scheme};
use commonware_runtime::{BufMut, Clock, Metrics, Spawner};
use commonware_storage::{
    Context,
    metadata::{self, Metadata},
};
use commonware_utils::{fixed_bytes, sequence::FixedBytes};
use rand_core::Rng;
use std::sync::Arc;

mod actor;
pub(crate) use actor::{Config, Syncer};

pub(crate) mod mailbox;
pub(crate) use mailbox::Mailbox;

mod plan;
pub use plan::SyncPlan;

const SYNC_METADATA_SUFFIX: &str = "state_sync_metadata";
const SYNC_STATE_KEY: FixedBytes<1> = fixed_bytes!("C0");

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

impl<S, C> Write for SyncState<S, C>
where
    S: Scheme,
    C: Digest,
{
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::InProgress(finalization) => {
                0u8.write(writer);
                finalization.write(writer);
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
                Self::InProgress(finalization) => finalization.encode_size(),
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

/// Databases and the anchor they reflect.
pub struct Artifact<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The database handle set.
    pub databases: A::Databases,
    /// The anchor the databases reflect.
    pub anchor: Anchor<BlockDigest<A, E>>,
}

impl<E, A> Clone for Artifact<E, A>
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
    metadata: Metadata<E, FixedBytes<1>, SyncState<S, C>>,
}

impl<E, S, C> StateSyncMetadata<E, S, C>
where
    E: Context,
    S: Scheme,
    C: Digest,
{
    /// Load the durable state-sync metadata partition, creating it if needed.
    pub(crate) async fn init(context: E, partition_prefix: impl AsRef<str>) -> Self {
        let partition_prefix = partition_prefix.as_ref();
        let metadata = Metadata::init(
            context,
            metadata::Config {
                partition: format!("{partition_prefix}{SYNC_METADATA_SUFFIX}"),
                codec_config: S::certificate_codec_config_unbounded(),
            },
        )
        .await
        .expect("failed to load sync metadata");
        Self { metadata }
    }

    /// Returns the completed state sync height, if state sync has finished.
    pub(crate) fn completed(&self) -> Option<Height> {
        match self.metadata.get(&SYNC_STATE_KEY) {
            Some(SyncState::Complete(height)) => Some(*height),
            _ => None,
        }
    }

    /// Returns the selected floor while state sync is in progress.
    pub(crate) fn floor(&self) -> Option<&Finalization<S, C>> {
        match self.metadata.get(&SYNC_STATE_KEY) {
            Some(SyncState::InProgress(finalization)) => Some(finalization),
            _ => None,
        }
    }

    /// Marks state sync as in progress for the selected floor.
    ///
    /// This must be persisted before marshal starts from the floor or any state sync database
    /// mutation begins. A crash then resumes state sync instead of recovering from marshal, and
    /// the database sync engine can reopen partial sync state and validate the next selected floor.
    /// The storage target may still advance to marshal's durable processed height during startup.
    ///
    /// If a floor is already persisted, whether or not its sync has started, the
    /// new floor must be at the same or a later consensus round, and a floor at
    /// the same round must have the same payload. Unlike [`SyncPlan::set_floor`],
    /// which ignores a floor that is not newer, this panics on a backward or
    /// conflicting floor.
    pub(crate) async fn set_floor(mut self, finalization: Finalization<S, C>) -> Self {
        match self.metadata.get(&SYNC_STATE_KEY) {
            Some(SyncState::InProgress(existing)) => {
                assert!(
                    finalization.round() >= existing.round(),
                    "selected state sync floor cannot move behind the persisted in-progress floor",
                );
                if finalization.round() == existing.round() {
                    assert!(
                        finalization.proposal.payload == existing.proposal.payload,
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
            .put_sync(SYNC_STATE_KEY, SyncState::InProgress(finalization))
            .await
            .expect("failed to set state sync state to in-progress");
        self
    }

    /// Records that one-time state sync completed at the given height.
    ///
    /// Once this height is set, future startups skip peer state sync and initialize
    /// from the later of this height and marshal's processed height instead. This
    /// action is irreversible.
    pub(crate) async fn set_completed(mut self, height: Height) -> Self {
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

/// Resolves the state sync anchor block, which covers both the selected finalization and
/// marshal's durable processed height.
pub(crate) async fn resolve<S, V>(
    marshal: &MarshalMailbox<S, V>,
    floor: Floor,
    finalization: &Finalization<S, V::Commitment>,
) -> Arc<V::ApplicationBlock>
where
    S: Scheme,
    V: Variant,
{
    // Marshal skips installing a startup floor whose round is already processed. Its block may
    // have been pruned, so apply the same rule before registering a local-only waiter.
    if floor.processed().is_some() && floor.round() >= finalization.round() {
        // A live floor can advance the processed position after marshal's startup snapshot and
        // prune the snapshot's anchor, so resolve from the current position.
        let (processed, anchor) = marshal
            .get_anchor()
            .await
            .expect("marshal must report the processed position it started with");

        // A retained successor can be the selected floor block. Prefer it to its processed
        // predecessor so the resolved target covers the selected finalization. An absent
        // block is already backed by the floor block at the next height.
        if let Processed::Block(height) = processed
            && let Some(next) = height.get().checked_add(1)
            && let Some(block) = marshal
                .get_block(Identifier::Height(Height::new(next)))
                .await
            && V::commitment(&block) == finalization.proposal.payload
        {
            V::into_shared(block)
        } else {
            V::into_shared(anchor)
        }
    } else {
        // Marshal's configured startup floor fetches its anchor when needed. This local-only
        // subscription observes that result without starting a separate fetch.
        let selected = {
            let block = marshal
                .subscribe_by_commitment(finalization.proposal.payload, CommitmentFallback::Wait)
                .await
                .expect("marshal must yield floor block");
            V::into_shared(block)
        };

        // Marshal does not redeliver blocks at or below its durable processed position.
        // A newly installed floor records its predecessor, leaving the anchor for delivery.
        match marshal.get_anchor().await {
            Some((processed, block)) if processed.height() > selected.height() => {
                V::into_shared(block)
            }
            _ => selected,
        }
    }
}

/// Opens databases at the later of `completed` and marshal's processed height.
///
/// Startup uses this route to recover from marshal instead of running peer state
/// sync. When neither height exists, this opens at marshal's genesis block, so fresh
/// boots and post-sync restarts share the same path.
///
/// The marshal target constrains recovery before database publication. Startup panics
/// if any recovered database does not match its complete target.
pub(crate) async fn open<E, A, S, V>(
    context: E,
    marshal: &MarshalMailbox<S, V>,
    db_config: <A::Databases as DatabaseSet<E>>::Config,
    completed: Option<Height>,
) -> Artifact<E, A>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    // A completed state sync may be ahead of marshal's processed height. Recover from the
    // later anchor while marshal catches up.
    let anchor = marshal.get_anchor().await;
    let height = completed
        .into_iter()
        .chain(anchor.as_ref().map(|(processed, _)| processed.height()))
        .max()
        .unwrap_or_else(Height::zero);
    let block = if let Some((processed, block)) = anchor
        && processed.height() == height
    {
        V::into_shared(block)
    } else {
        V::into_shared(
            marshal
                .get_block(Identifier::Height(height))
                .await
                .expect("marshal must return completed state sync block"),
        )
    };

    // A crash can leave databases ahead of marshal or at different checkpoints. Opening each
    // at this target discards its extra suffix before the set is exposed. A missing target,
    // including one lost to corruption or excessive pruning, makes startup fail.
    let processed_targets = A::sync_targets(&block);
    let databases = A::Databases::init(context, db_config, Some(processed_targets)).await;
    Artifact {
        databases,
        anchor: Anchor::from(block.as_ref()),
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
