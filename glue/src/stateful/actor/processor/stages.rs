//! The stages a job runs through.
//!
//! Each stage is a future over owned inputs that resolves to what it learned.
//! Stages never touch the processor's state, which only the
//! [`Processor`](super::Processor) touches between stages.

use super::jobs::Stale;
use crate::stateful::{
    Application, ExecutionError, Input, Proposed,
    db::{Anchor, MerkleizedOf, UnmerkleizedOf},
};
use commonware_consensus::{
    Block, CertifiableBlock,
    marshal::{
        Identifier,
        ancestry::{self as marshal_ancestry, BlockProvider, BoxedAncestry},
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
    types::Height,
};
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::traces::TracedExt as _};
use futures::{StreamExt, future};
use rand_core::Rng;
use std::{collections::BTreeSet, future::Future, sync::Arc};
use tracing::{debug, warn};

type Unmerkleized<A, E> = UnmerkleizedOf<<A as Application<E>>::Databases, E>;
type Merkleized<A, E> = MerkleizedOf<<A as Application<E>>::Databases, E>;

/// What the processor needs from marshal.
pub(in crate::stateful::actor) trait Marshal:
    BlockProvider + Clone
{
    /// The digest of the canonical block at `height`, or `None` when marshal
    /// does not have it.
    fn canonical(
        &self,
        height: Height,
    ) -> impl Future<Output = Option<<Self::Block as Digestible>::Digest>> + Send;

    /// Prune finalized blocks below `height`.
    fn prune(&self, height: Height);
}

impl<S, V> Marshal for MarshalMailbox<S, V>
where
    S: Scheme,
    V: MarshalVariant,
    Self: BlockProvider<Block = V::ApplicationBlock>,
{
    async fn canonical(
        &self,
        height: Height,
    ) -> Option<<V::ApplicationBlock as Digestible>::Digest> {
        self.get_block(Identifier::Height(height))
            .await
            .map(|block| block.digest())
    }

    fn prune(&self, height: Height) {
        Self::prune(self, height);
    }
}

/// Read the next block of the ancestry, or `None` once it ended.
#[tracing::instrument(name = "stateful.processor.fetch_ancestor", level = "info", skip_all)]
pub(super) async fn fetch<B: Block>(ancestry: &mut BoxedAncestry<B>) -> Option<Arc<B>> {
    ancestry.next().await
}

/// Look up the canonical block at `height`, so a candidate below the applied
/// height is decided without re-executing it.
#[tracing::instrument(
    name = "stateful.processor.canonical",
    level = "info",
    skip_all,
    fields(height = height.traced())
)]
pub(super) async fn canonical<P: Marshal>(
    provider: P,
    height: Height,
) -> Option<<P::Block as Digestible>::Digest> {
    provider.canonical(height).await
}

/// Walk marshal backward from `parent` to the nearest block in `known` or the
/// anchor, returning the blocks to replay oldest first. `None` is invalid
/// ancestry.
pub(super) async fn walk<B, P>(
    provider: P,
    parent: Arc<B>,
    anchor: Anchor<B::Digest>,
    known: BTreeSet<B::Digest>,
) -> Option<Vec<Arc<B>>>
where
    B: Block,
    P: BlockProvider<Block = B>,
{
    let target_digest = parent.digest();
    let mut path = Vec::new();
    let mut cursor = parent;
    loop {
        let digest = cursor.digest();
        if digest == anchor.digest || known.contains(&digest) {
            break;
        }

        let cursor_height = cursor.height();
        if cursor_height <= anchor.height {
            warn!(
                ?target_digest,
                cursor = ?digest,
                current_height = cursor_height.get(),
                last_processed_height = anchor.height.get(),
                last_processed = ?anchor.digest,
                "walk reached stale ancestry at or below processed height"
            );
            return None;
        }

        let Some(parent) = provider.subscribe_parent(&cursor).await else {
            debug!(
                ?target_digest,
                cursor = ?digest,
                "ancestor subscription ended before delivery"
            );
            // Incomplete ancestry is not a verdict. Only cancellation ends the stage.
            return future::pending().await;
        };

        if parent.digest() != cursor.parent() || parent.height().next() != cursor_height {
            warn!(
                ?target_digest,
                cursor = ?digest,
                parent = ?parent.digest(),
                cursor_height = cursor_height.get(),
                parent_height = parent.height().get(),
                expected_parent = ?cursor.parent(),
                "walk received non-contiguous ancestry"
            );
            return None;
        }

        path.push(cursor);
        cursor = parent;
    }
    path.reverse();
    Some(path)
}

/// Execute `block` on `batches`, forked from its parent.
pub(super) async fn replay<E, A>(
    mut app: A,
    context: E,
    block: Arc<A::Block>,
    batches: Unmerkleized<A, E>,
) -> Result<Merkleized<A, E>, Stale>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    let consensus_context = block.context();
    executed(
        app.apply((context, consensus_context), &block, batches)
            .await,
        "replay",
    )
}

/// Run the application's verification of `candidate` on `batches`, forked
/// from `parent`.
pub(super) async fn verify<E, A>(
    mut app: A,
    context: (E, A::Context),
    candidate: Arc<A::Block>,
    parent: Arc<A::Block>,
    ancestry: BoxedAncestry<A::Block>,
    batches: Unmerkleized<A, E>,
) -> Result<Option<Merkleized<A, E>>, Stale>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    // The application expects the full candidate-first ancestry even though
    // the job consumed those two entries while fetching them.
    let ancestry = marshal_ancestry::with_prefix([candidate, parent], ancestry);
    executed(app.verify(context, ancestry, batches).await, "verification")
}

/// Build a block on `batches`, forked from `parent`.
pub(super) async fn propose<E, A>(
    mut app: A,
    context: (E, A::Context),
    parent: Arc<A::Block>,
    ancestry: BoxedAncestry<A::Block>,
    batches: Unmerkleized<A, E>,
    input: Input<A::Input, A::Provider>,
) -> Result<Option<Proposed<A, E>>, Stale>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    let ancestry = marshal_ancestry::with_prefix([parent], ancestry);
    executed(
        app.propose(context, ancestry, batches, input).await,
        "proposal",
    )
}

/// `Stale` is the step's decision. `Fatal` has no caller to answer.
fn executed<T>(result: Result<T, ExecutionError>, what: &str) -> Result<T, Stale> {
    match result {
        Ok(value) => Ok(value),
        Err(ExecutionError::Stale) => Err(Stale),
        Err(err @ ExecutionError::Fatal(_)) => panic!("application {what} failed: {err}"),
    }
}
