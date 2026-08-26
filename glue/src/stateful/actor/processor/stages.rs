//! The stages a job runs through.
//!
//! Each stage is a future over owned inputs and a [`Job`] it may advance (its
//! ancestry cursor, its blocks) but never the processor's state, which only the
//! [`Processor`](super::Processor) touches between stages.

use super::jobs::{Caller, Failure, Job, Outcome, Stale};
use crate::stateful::{
    Application, ExecutionError,
    db::{DatabaseSet, UnmerkleizedOf},
};
use commonware_consensus::{
    Block, CertifiableBlock, Heightable,
    marshal::{
        Identifier,
        ancestry::{self as marshal_ancestry, BlockProvider},
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
    types::Height,
};
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::traces::TracedExt as _};
use futures::{Stream, StreamExt};
use rand_core::Rng;
use std::{collections::BTreeSet, future::Future, sync::Arc};
use tracing::{debug, info_span, warn};

type Unmerkleized<A, E> = UnmerkleizedOf<<A as Application<E>>::Databases, E>;

/// What jobs need from marshal.
pub(in crate::stateful::actor) trait Provider:
    BlockProvider + Clone
{
    /// The digest of the canonical block at `height`, or `None` when marshal
    /// does not have it.
    fn canonical(
        &self,
        height: Height,
    ) -> impl Future<Output = Option<<Self::Block as Digestible>::Digest>> + Send;
}

impl<S, V> Provider for MarshalMailbox<S, V>
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
}

/// Wait for `future` unless the caller drops its request.
async fn await_or_cancel<B, I, P, T>(
    caller: &mut Caller<B, I, P>,
    future: impl Future<Output = T>,
) -> Option<T> {
    select! {
        _ = caller.cancelled() => None,
        output = future => Some(output),
    }
}

/// Read the next ancestry item unless the caller drops its request.
#[tracing::instrument(name = "stateful.processor.fetch_ancestor", level = "info", skip_all)]
pub(super) async fn fetch_ancestor<B, I, P, T>(
    caller: &mut Caller<B, I, P>,
    stream: &mut (impl Stream<Item = T> + Unpin),
) -> Option<Option<T>> {
    await_or_cancel(caller, stream.next()).await
}

/// Read the next block of the ancestry. `Err` ends the job: an exhausted
/// stream declines a proposal, while a verification is not a verdict without
/// its blocks and parks until its caller drops it.
async fn fetch<E, A>(job: &mut Job<E, A>) -> Result<Arc<A::Block>, Outcome<E, A>>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    match fetch_ancestor(&mut job.caller, &mut job.ancestry).await {
        Some(Some(block)) => Ok(block),
        Some(None) if job.is_proposal() => Err(Outcome::Declined),
        Some(None) => {
            debug!("verification request waiting on incomplete ancestry");
            job.caller.cancelled().await;
            Err(Outcome::Cancelled)
        }
        None => {
            debug!("request cancelled before its ancestry arrived");
            Err(Outcome::Cancelled)
        }
    }
}

/// Fetch the block under verification from the ancestry stream.
pub(super) async fn candidate<E, A>(job: &mut Job<E, A>) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    match fetch(job).await {
        Ok(block) => {
            job.candidate = Some(block);
            Outcome::Candidate
        }
        Err(outcome) => outcome,
    }
}

/// Fetch the block to fork from out of the ancestry stream, leaving the cursor
/// after it.
pub(super) async fn parent<E, A>(job: &mut Job<E, A>) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    match fetch(job).await {
        Ok(block) => {
            job.parent = Some(block);
            Outcome::Parent
        }
        Err(outcome) => outcome,
    }
}

/// Decide a candidate below the applied height from the canonical block at its
/// height, without re-executing it.
#[tracing::instrument(
    name = "stateful.processor.canonical",
    level = "info",
    skip_all,
    fields(height = job.candidate().height().traced(), digest = %job.candidate().digest())
)]
pub(super) async fn canonical<E, A, P>(job: &mut Job<E, A>, provider: P) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: Provider<Block = A::Block>,
{
    let candidate = Arc::clone(job.candidate());
    let height = candidate.height();
    let Some(canonical) = await_or_cancel(&mut job.caller, provider.canonical(height)).await else {
        debug!(
            block_digest = ?candidate.digest(),
            "verification request cancelled during canonical-block check"
        );
        return Outcome::Cancelled;
    };
    let Some(canonical) = canonical else {
        warn!(
            target_height = height.get(),
            processed_height = job.anchor.height.get(),
            "failed to fetch canonical block for a candidate below the processed height"
        );
        // Incomplete ancestry is not a verdict. Park until the caller drops the request.
        job.caller.cancelled().await;
        return Outcome::Cancelled;
    };
    Outcome::Classified(canonical == candidate.digest())
}

/// Walk marshal backward from the parent to the nearest block in `known` or the
/// anchor the job was looked up under, returning the blocks to replay oldest
/// first.
pub(super) async fn walk<E, A, P>(
    job: &mut Job<E, A>,
    provider: P,
    known: BTreeSet<<A::Block as Digestible>::Digest>,
) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    let anchor = job.anchor;
    let target_digest = job.parent().digest();
    let mut path = Vec::new();
    let mut cursor = Arc::clone(job.parent());
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
            return Outcome::Walked(None);
        }

        let Some(parent) =
            await_or_cancel(&mut job.caller, provider.subscribe_parent(&cursor)).await
        else {
            return Outcome::Cancelled;
        };
        let Some(parent) = parent else {
            debug!(
                ?target_digest,
                cursor = ?digest,
                "ancestor subscription ended before delivery"
            );
            // Incomplete ancestry is not a verdict. Park until the caller drops the request.
            job.caller.cancelled().await;
            return Outcome::Cancelled;
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
            return Outcome::Walked(None);
        }

        path.push(cursor);
        cursor = parent;
    }
    path.reverse();
    Outcome::Walked(Some(path))
}

/// Execute the first block of the path on `batches`, forked from its parent.
pub(super) async fn replay<E, A>(
    job: &mut Job<E, A>,
    mut app: A,
    batches: Unmerkleized<A, E>,
) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    let block = Arc::clone(
        job.path
            .front()
            .expect("a replay stage has a block to replay"),
    );
    let consensus_context = block.context();
    let Some(applied) = await_or_cancel(
        &mut job.caller,
        app.apply(
            (job.context.0.child("replay_apply"), consensus_context),
            &block,
            batches,
        ),
    )
    .await
    else {
        return Outcome::Replayed(Err(Failure::Cancelled));
    };
    let merkleized = match applied {
        Ok(merkleized) => merkleized,
        Err(ExecutionError::Stale) => return Outcome::Replayed(Err(Failure::Stale)),
        Err(err @ ExecutionError::Fatal(_)) => panic!("application replay failed: {err}"),
    };

    if !A::Databases::matches_sync_targets(&merkleized, &A::sync_targets(&block)) {
        warn!(
            target_digest = ?job.parent().digest(),
            block = ?block.digest(),
            "replayed state root must match block commitments"
        );
        return Outcome::Replayed(Err(Failure::Invalid));
    }
    Outcome::Replayed(Ok(merkleized))
}

/// Run the application's verification of the candidate on `batches`, forked
/// from the parent.
pub(super) async fn verify<E, A>(
    job: &mut Job<E, A>,
    mut app: A,
    batches: Unmerkleized<A, E>,
) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    let candidate = Arc::clone(job.candidate());
    let parent = Arc::clone(job.parent());
    let (block_digest, parent_digest) = (candidate.digest(), parent.digest());

    // The application expects the full candidate-first ancestry even though
    // the stages consumed those two entries while fetching them.
    let ancestry =
        marshal_ancestry::with_prefix([Arc::clone(&candidate), parent], job.ancestry.clone());
    let verified = match await_or_cancel(
        &mut job.caller,
        app.verify(
            (
                job.context.0.child("application").child("verify_attempt"),
                job.context.1.clone(),
            ),
            ancestry,
            batches,
        ),
    )
    .await
    {
        Some(Ok(result)) => result,
        Some(Err(ExecutionError::Stale)) => {
            debug!(
                ?parent_digest,
                ?block_digest,
                "verification went stale during application execution"
            );
            return Outcome::Verified(Err(Stale));
        }
        Some(Err(err @ ExecutionError::Fatal(_))) => {
            panic!("application verification failed: {err}")
        }
        None => {
            debug!(
                ?parent_digest,
                "verification request cancelled during verify"
            );
            return Outcome::Cancelled;
        }
    };

    let Some(merkleized) = verified else {
        warn!(
            ?parent_digest,
            ?block_digest,
            "verification rejected: app.verify returned None"
        );
        return Outcome::Verified(Ok(None));
    };
    let _tail = info_span!(
        "stateful.processor.match_commitments",
        block = %block_digest,
        parent = %parent_digest,
    )
    .entered();

    // Application output is adversarial until it matches the commitments
    // carried by the candidate block. Never retain it before this check.
    if !A::Databases::matches_sync_targets(&merkleized, &A::sync_targets(&candidate)) {
        warn!(
            ?parent_digest,
            ?block_digest,
            "verification rejected: verified state must match block commitments"
        );
        return Outcome::Verified(Ok(None));
    }
    Outcome::Verified(Ok(Some(merkleized)))
}

/// Build a block on `batches`, forked from the parent.
pub(super) async fn propose<E, A>(
    job: &mut Job<E, A>,
    mut app: A,
    batches: Unmerkleized<A, E>,
) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    let parent = Arc::clone(job.parent());
    let parent_digest = parent.digest();
    let Caller::Propose { input, .. } = &mut job.caller else {
        unreachable!("only proposals reach the propose stage")
    };
    let input = input.take().expect("a proposal builds once");
    let ancestry = marshal_ancestry::with_prefix([parent], job.ancestry.clone());

    // The application takes the caller's runtime context by value. Keep a
    // child as the clock for the proposal timer.
    let clock = job.context.0.child("propose_timer");
    let runtime_context = std::mem::replace(&mut job.context.0, clock);
    match await_or_cancel(
        &mut job.caller,
        app.propose(
            (runtime_context, job.context.1.clone()),
            ancestry,
            batches,
            input,
        ),
    )
    .await
    {
        Some(Ok(proposed)) => Outcome::Proposed(Ok(proposed)),
        Some(Err(err @ ExecutionError::Fatal(_))) => {
            panic!("application proposal failed: {err}")
        }
        Some(Err(ExecutionError::Stale)) => {
            warn!(?parent_digest, "proposal went stale during propose");
            Outcome::Proposed(Err(Stale))
        }
        None => {
            debug!(?parent_digest, "proposal request cancelled during propose");
            Outcome::Cancelled
        }
    }
}
