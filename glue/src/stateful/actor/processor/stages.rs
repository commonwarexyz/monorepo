//! The stages a job runs through.
//!
//! Each stage is a future over owned inputs and a [`Carry`] it may advance
//! (its ancestry cursor, its blocks) but never the processor's state, which
//! only [`Processor::step`](super::Processor::step) touches between stages.

use super::jobs::{Acquired, Caller, Carry, Failure, Fetched, Interrupted, Outcome, ReplayResult};
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
};
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::traces::TracedExt as _};
use commonware_utils::channel::oneshot;
use futures::{Stream, StreamExt};
use rand_core::Rng;
use std::{collections::BTreeSet, future::Future, sync::Arc};
use tracing::{debug, info_span, warn};

type Unmerkleized<A, E> = UnmerkleizedOf<<A as Application<E>>::Databases, E>;

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

/// Fetch the block under verification from the ancestry stream.
pub(super) async fn candidate<E, A>(carry: &mut Carry<E, A>) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    // Acquire the candidate independently for each request. Availability is
    // round-scoped, so requests cannot safely share this part of the work.
    let candidate = match fetch_ancestor(&mut carry.caller, &mut carry.ancestry).await {
        Some(Some(block)) => block,
        Some(None) => {
            debug!("verification request waiting on incomplete block ancestry");
            carry.caller.cancelled().await;
            return Outcome::Candidate(Fetched::Cancelled);
        }
        None => {
            debug!("verification request cancelled before initial block arrived");
            return Outcome::Candidate(Fetched::Cancelled);
        }
    };
    carry.candidate = Some(candidate);
    Outcome::Candidate(Fetched::Ready)
}

/// Fetch the block to fork from out of the ancestry stream, leaving the cursor
/// after it.
pub(super) async fn parent<E, A>(carry: &mut Carry<E, A>) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    let parent = match fetch_ancestor(&mut carry.caller, &mut carry.ancestry).await {
        Some(Some(block)) => block,
        // An exhausted stream declines a proposal. A verification is not a
        // verdict without its parent, so it parks until its caller drops it.
        Some(None) => match carry.caller {
            Caller::Verify(_) => {
                debug!("verification request waiting on incomplete parent ancestry");
                carry.caller.cancelled().await;
                return Outcome::Parent(Acquired::Cancelled);
            }
            Caller::Propose { .. } => return Outcome::Parent(Acquired::Declined),
        },
        None => {
            debug!("request cancelled before parent ancestry arrived");
            return Outcome::Parent(Acquired::Cancelled);
        }
    };
    carry.parent = Some(parent);
    Outcome::Parent(Acquired::Ready)
}

/// Decide a candidate below the applied height from the canonical block at its
/// height, without re-executing it.
#[tracing::instrument(
    name = "stateful.processor.is_already_processed",
    level = "info",
    skip_all,
    fields(height = carry.candidate().height().traced(), digest = %carry.candidate().digest())
)]
pub(super) async fn classify<E, A, S, V>(
    carry: &mut Carry<E, A>,
    marshal: MarshalMailbox<S, V>,
) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: MarshalVariant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    let candidate = Arc::clone(carry.candidate());
    let height = candidate.height();
    let Some(canonical) = await_or_cancel(
        &mut carry.caller,
        marshal.get_block(Identifier::Height(height)),
    )
    .await
    else {
        debug!(
            block_digest = ?candidate.digest(),
            "verification request cancelled during processed-block check"
        );
        return Outcome::Classified(None);
    };
    let Some(canonical) = canonical else {
        warn!(
            target_height = height.get(),
            processed_height = carry.anchor.height.get(),
            "failed to fetch canonical processed block for stale-block check"
        );

        // Incomplete ancestry is not an invalid verdict. Keep the job parked
        // until its request future is dropped.
        carry.caller.cancelled().await;
        return Outcome::Classified(None);
    };
    Outcome::Classified(Some(canonical.digest() == candidate.digest()))
}

/// Walk marshal backward from the parent to the nearest block in `known` or the
/// anchor the carry was looked up under, returning the blocks to replay oldest
/// first.
pub(super) async fn walk<E, A, P>(
    carry: &mut Carry<E, A>,
    provider: P,
    known: BTreeSet<<A::Block as Digestible>::Digest>,
) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block> + Clone,
{
    let anchor = carry.anchor;
    let target_digest = carry.parent().digest();
    let mut path = Vec::new();
    let mut cursor = Arc::clone(carry.parent());
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
                "rebuild_pending reached stale ancestry at or below processed height"
            );
            return Outcome::Walked(Err(Failure::Invalid));
        }

        let Some(parent) = await_or_cancel(
            &mut carry.caller,
            provider.clone().subscribe_parent(&cursor),
        )
        .await
        else {
            return Outcome::Walked(Err(Failure::Cancelled));
        };

        let Some(parent) = parent else {
            debug!(
                ?target_digest,
                cursor = ?digest,
                "ancestor subscription ended before delivery"
            );

            // Incomplete ancestry is not a verdict. Park until the caller drops
            // the request.
            carry.caller.cancelled().await;
            return Outcome::Walked(Err(Failure::Cancelled));
        };

        if parent.digest() != cursor.parent() || parent.height().next() != cursor_height {
            warn!(
                ?target_digest,
                cursor = ?digest,
                parent = ?parent.digest(),
                cursor_height = cursor_height.get(),
                parent_height = parent.height().get(),
                expected_parent = ?cursor.parent(),
                "rebuild_pending received non-contiguous ancestry"
            );
            return Outcome::Walked(Err(Failure::Invalid));
        }

        path.push(cursor);
        cursor = parent;
    }
    path.reverse();
    Outcome::Walked(Ok(path))
}

/// Execute the first block of the path on `batches`, forked from its parent.
pub(super) async fn replay<E, A>(
    carry: &mut Carry<E, A>,
    mut app: A,
    batches: Unmerkleized<A, E>,
) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    let block = Arc::clone(
        carry
            .path
            .front()
            .expect("a replay stage has a block to replay"),
    );
    let consensus_context = block.context();
    let Some(applied) = await_or_cancel(
        &mut carry.caller,
        app.apply(
            (
                carry.context.0.child("rebuild_pending_apply"),
                consensus_context,
            ),
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
        // A block finalized while this replay executed. The step re-checks
        // canonical state, so this replay never panics on it.
        Err(ExecutionError::Stale) => return Outcome::Replayed(Err(Failure::Stale)),
        Err(err @ ExecutionError::Fatal(_)) => panic!("application replay failed: {err}"),
    };

    if !A::Databases::matches_sync_targets(&merkleized, &A::sync_targets(&block)) {
        warn!(
            target_digest = ?carry.parent().digest(),
            block = ?block.digest(),
            "rebuild replay state root must match block commitments"
        );
        return Outcome::Replayed(Err(Failure::Invalid));
    }
    Outcome::Replayed(Ok(merkleized))
}

/// Run the application's verification of the candidate on `batches`, forked
/// from the parent.
pub(super) async fn verify<E, A>(
    carry: &mut Carry<E, A>,
    mut app: A,
    batches: Unmerkleized<A, E>,
) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    let candidate = Arc::clone(carry.candidate());
    let parent = Arc::clone(carry.parent());
    let (block_digest, parent_digest) = (candidate.digest(), parent.digest());

    // The application expects the full candidate-first ancestry even though
    // the processor consumed those two entries while acquiring them.
    let ancestry =
        marshal_ancestry::with_prefix([Arc::clone(&candidate), parent], carry.ancestry.clone());
    let verified = match await_or_cancel(
        &mut carry.caller,
        app.verify(
            (
                carry.context.0.child("application").child("verify_attempt"),
                carry.context.1.clone(),
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
            return Outcome::Verified(Err(Interrupted::Stale));
        }
        Some(Err(err @ ExecutionError::Fatal(_))) => {
            panic!("application verification failed: {err}")
        }
        None => {
            debug!(
                ?parent_digest,
                "verification request cancelled during verify"
            );
            return Outcome::Verified(Err(Interrupted::Cancelled));
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
    carry: &mut Carry<E, A>,
    mut app: A,
    batches: Unmerkleized<A, E>,
) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    let parent = Arc::clone(carry.parent());
    let parent_digest = parent.digest();
    let Caller::Propose { input, .. } = &mut carry.caller else {
        unreachable!("only proposals reach the propose stage")
    };
    let input = input.take().expect("a proposal builds once");
    let ancestry = marshal_ancestry::with_prefix([parent], carry.ancestry.clone());

    // The application takes the caller's runtime context by value. Keep a
    // child as the clock for the proposal timer.
    let clock = carry.context.0.child("propose_timer");
    let runtime_context = std::mem::replace(&mut carry.context.0, clock);
    match await_or_cancel(
        &mut carry.caller,
        app.propose(
            (runtime_context, carry.context.1.clone()),
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
            Outcome::Proposed(Err(Interrupted::Stale))
        }
        None => {
            debug!(?parent_digest, "proposal request cancelled during propose");
            Outcome::Proposed(Err(Interrupted::Cancelled))
        }
    }
}

/// Park until the replay this job waits on finishes.
pub(super) async fn wait<E, A>(
    carry: &mut Carry<E, A>,
    completion: oneshot::Receiver<ReplayResult>,
) -> Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    match await_or_cancel(&mut carry.caller, completion).await {
        None => Outcome::Woken(None),
        Some(Ok(result)) => Outcome::Woken(Some(result)),
        // The owner is gone without a result. Claim the replay afresh.
        Some(Err(_)) => Outcome::Woken(Some(Err(Failure::Cancelled))),
    }
}
