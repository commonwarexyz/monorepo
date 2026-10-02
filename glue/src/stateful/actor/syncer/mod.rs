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
use commonware_storage::Context;
use rand_core::Rng;
use std::sync::Arc;

mod actor;
pub(crate) use actor::{Config, Syncer};

pub(crate) mod mailbox;
pub(crate) use mailbox::Mailbox;

mod plan;
pub use plan::SyncPlan;

/// Durable state sync progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SyncState<S, C>
where
    S: Scheme,
    C: Digest,
{
    /// A floor is selected and state sync has not completed.
    InProgress(Finalization<S, C>),
    /// Completion is recorded at this height, and peer state sync never runs again.
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
    /// Anchor of the block reflected by `databases`.
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

/// Returns the block state sync starts from.
///
/// This is the block of `finalization` unless marshal's processed position has passed it, in
/// which case it is the block backing marshal's current processed height: marshal does not
/// redeliver blocks at or below that height, so starting lower would leave a gap. Panics if
/// marshal cannot return its processed position or the floor block.
pub(crate) async fn resolve<S, V>(
    marshal: &MarshalMailbox<S, V>,
    floor: Floor,
    finalization: &Finalization<S, V::Commitment>,
) -> Arc<V::ApplicationBlock>
where
    S: Scheme,
    V: Variant,
{
    // Marshal skips a startup floor at or below its durable round floor, and that floor block may
    // be pruned, so a local wait for it could hang. Resolve from marshal's current position, since
    // a live floor may also have pruned the startup snapshot's anchor.
    if floor.processed().is_some() && floor.round() >= finalization.round() {
        let (processed, anchor) = marshal
            .get_anchor()
            .await
            .expect("marshal must report the processed position it started with");

        // Prefer the selected floor when it is the retained successor, so its delivery skips
        // application hooks. A `Processed::Absent` anchor already holds the floor.
        if let Processed::Block(height) = processed
            && let Some(block) = marshal.get_block(Identifier::Height(height.next())).await
            && V::commitment(&block) == finalization.proposal.payload
        {
            V::into_shared(block)
        } else {
            V::into_shared(anchor)
        }
    } else {
        // Marshal fetches the configured floor block itself, so wait for it without starting
        // another fetch.
        let selected = {
            let block = marshal
                .subscribe_by_commitment(finalization.proposal.payload, CommitmentFallback::Wait)
                .await
                .expect("marshal must yield floor block");
            V::into_shared(block)
        };

        // A newly installed floor records its predecessor as processed, leaving the floor block
        // for delivery.
        match marshal.get_anchor().await {
            Some((processed, block)) if processed.height() > selected.height() => {
                V::into_shared(block)
            }
            _ => selected,
        }
    }
}

/// Opens the database set at the later of the block at `completed` and the block backing marshal's
/// processed position ([`Processed::anchor`]), or at genesis when neither exists.
///
/// A crash can leave databases ahead of that block or at different checkpoints. Each database is
/// opened at the targets of that block, discarding any suffix beyond them, and the set is returned
/// with that block as its anchor. Panics if marshal cannot return that block or a database cannot
/// be opened at its target (for example, because corruption or excessive pruning lost it).
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
