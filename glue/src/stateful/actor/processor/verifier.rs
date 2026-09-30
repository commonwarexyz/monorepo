use super::{
    Application, Cancellation, Execution, PendingEntry, PrepareBatchesError, Provenance,
    ReplayFlights, VerificationResult, await_or_cancel, fetch_ancestor, is_already_processed,
    panic_unless_stopping,
};
use crate::stateful::{
    ExecutionError,
    actor::{BlockDigest, core::Verification},
    db::DatabaseSet,
};
use commonware_consensus::{
    CertifiableBlock, Heightable, Roundable,
    marshal::{
        ancestry::{self as marshal_ancestry, Ancestry, BlockProvider},
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
};
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_runtime::{Clock, Metrics, Spawner};
use futures::future;
use rand_core::Rng;
use std::sync::Arc;
use tracing::{debug, info_span, warn};

/// Parent-relative database batches passed to application verification.
type Unmerkleized<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::Unmerkleized;

/// Result of checking a candidate against the canonical chain through the processed anchor.
enum ProcessedBlock {
    /// The candidate is above the processed height and requires execution.
    Continue,
    /// The candidate is the canonical block at its height.
    Accepted,
    /// The candidate is at or below the processed height but is not the canonical block there.
    Rejected,
    /// The check ended without a verdict because its request was cancelled.
    Cancelled,
}

/// Failure to prepare the parent state needed for verification.
enum PrepareFailure {
    /// The supplied ancestry is provably invalid.
    Invalid,
    /// Preparation ended without a verdict because its request was cancelled.
    Cancelled,
    /// A finalization of a non-ancestor (possibly the candidate itself) landed or is in flight
    /// during preparation. Re-check the candidate against the new canonical state.
    Stale,
}

/// Outcome of one execution attempt of the candidate against applied state.
enum Attempt {
    /// The attempt finished with a result.
    Done(VerificationResult),
    /// A finalization of a non-ancestor made the attempt's batches stale. Re-check the
    /// candidate against the new canonical state and try again.
    Stale,
}

/// A candidate's parent and forked batches, ready for application verification.
struct PreparedParent<A, E>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Parent block taken from the candidate's ancestry.
    block: Arc<A::Block>,
    /// Digest of `block`.
    digest: BlockDigest<A, E>,
    /// Batches forked from the parent's speculative or applied state.
    batches: Unmerkleized<A, E>,
}

/// Executes one verification request against the processor's shared speculative state.
pub(in crate::stateful::actor) struct Verifier<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub(super) app: A,
    pub(super) execution: Execution<E, A>,
    pub(super) replays: ReplayFlights<BlockDigest<A, E>>,
}

impl<E, A> Clone for Verifier<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn clone(&self) -> Self {
        Self {
            app: self.app.clone(),
            execution: self.execution.clone(),
            replays: self.replays.clone(),
        }
    }
}

impl<E, A> Verifier<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Verifies the first block of `ancestry` on its parent's state.
    ///
    /// Returns [`VerificationResult::Decided`] with the verdict, or
    /// [`VerificationResult::Cancelled`] if `verification` is cancelled first. Incomplete
    /// ancestry is not a verdict: the request stays pending until cancelled.
    ///
    /// A block that was proposed or verified locally, or that is the canonical block at or below
    /// the processed height, is accepted without execution. Any other block at or below the
    /// processed height is rejected. Otherwise, the block is accepted only if the application
    /// verifies it and the resulting state matches the block's commitments. That state is cached
    /// only if the block can still extend the canonical chain, which never changes the verdict.
    /// An attempt that a finalization makes stale re-checks the block once the anchor moves. A
    /// fatal application error panics, or parks the request once shutdown has fired.
    pub(in crate::stateful::actor) async fn run<S, V>(
        &mut self,
        context: &E,
        marshal: MarshalMailbox<S, V>,
        consensus_context: A::Context,
        ancestry: impl Ancestry<A::Block>,
        verification: &mut Verification,
    ) -> VerificationResult
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        let timer = self.execution.metrics.verify_duration.timer(context);
        let mut ancestry = ancestry;

        // Acquire the candidate independently for each request. Availability is
        // round-scoped, so requests cannot safely share this part of the work.
        let block = match fetch_ancestor(verification, &mut ancestry).await {
            Some(Some(block)) => block,
            Some(None) => {
                debug!("verification request waiting on incomplete block ancestry");
                verification.cancelled().await;
                return VerificationResult::Cancelled;
            }
            None => {
                debug!("verification request cancelled before initial block arrived");
                return VerificationResult::Cancelled;
            }
        };
        let block_digest = block.digest();

        // Each iteration classifies the candidate against the canonical chain,
        // then executes it. A stale or invalid-looking attempt means a
        // finalization landed mid-attempt, and re-classifying answers correctly
        // whether the finalized block was the candidate, an ancestor, or a
        // competitor. Each retry consumes an anchor move, so the loop is
        // bounded.
        loop {
            // A replayed state is not a verdict, so only locally built or verified blocks skip
            // execution. A concurrent request may have verified the candidate since the last
            // attempt.
            if self.execution.pending_verified(&block_digest) {
                timer.observe(context);
                return VerificationResult::Decided(true);
            }
            let seen = self.execution.processed();

            // A finalized candidate cannot be re-executed against newer database
            // state. Prove it belongs to the canonical chain before accepting it.
            match self
                .check_processed(marshal.clone(), block.as_ref(), verification)
                .await
            {
                ProcessedBlock::Continue => {}
                ProcessedBlock::Accepted => {
                    timer.observe(context);
                    return VerificationResult::Decided(true);
                }
                ProcessedBlock::Rejected => return VerificationResult::Decided(false),
                ProcessedBlock::Cancelled => return VerificationResult::Cancelled,
            }

            // Reconstruct the candidate's parent state. This is the only phase
            // shared across requests, keyed by each replayed ancestor's block digest.
            let mut attempt_ancestry = ancestry.clone();
            let parent = match self
                .prepare_parent(
                    context,
                    marshal.clone(),
                    block_digest,
                    &mut attempt_ancestry,
                    verification,
                )
                .await
            {
                Ok(parent) => parent,
                Err(PrepareFailure::Invalid) => {
                    // An anchor that moved during this attempt can make valid
                    // ancestry look invalid (the finalization dropped the
                    // parent from the pending map), so retry and let the loop's classification
                    // decide. A stable anchor means the ancestry is genuinely
                    // invalid.
                    if self.execution.processed().digest != seen.digest {
                        continue;
                    }
                    return VerificationResult::Decided(false);
                }
                Err(PrepareFailure::Cancelled) => return VerificationResult::Cancelled,
                Err(PrepareFailure::Stale) => {
                    if await_or_cancel(verification, self.execution.anchor_past(&seen))
                        .await
                        .is_none()
                    {
                        return VerificationResult::Cancelled;
                    }
                    continue;
                }
            };

            match self
                .verify(
                    context,
                    consensus_context.clone(),
                    Arc::clone(&block),
                    parent,
                    attempt_ancestry,
                    verification,
                )
                .await
            {
                Attempt::Done(result) => {
                    if matches!(result, VerificationResult::Decided(true)) {
                        timer.observe(context);
                    }
                    return result;
                }
                Attempt::Stale => {
                    if await_or_cancel(verification, self.execution.anchor_past(&seen))
                        .await
                        .is_none()
                    {
                        return VerificationResult::Cancelled;
                    }
                    continue;
                }
            }
        }
    }

    /// Classifies `block` against the canonical chain through the processed anchor without
    /// executing it.
    async fn check_processed<S, V>(
        &mut self,
        marshal: MarshalMailbox<S, V>,
        block: &A::Block,
        verification: &mut Verification,
    ) -> ProcessedBlock
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        let block_digest = block.digest();
        let processed = self.execution.processed();
        match is_already_processed(processed, marshal, block, verification).await {
            Ok(true) => ProcessedBlock::Accepted,
            Ok(false) if block.height() <= processed.height => ProcessedBlock::Rejected,
            Ok(false) => ProcessedBlock::Continue,
            Err(PrepareBatchesError::Cancelled) => {
                debug!(
                    ?block_digest,
                    "verification request cancelled during processed-block check"
                );
                ProcessedBlock::Cancelled
            }
            Err(PrepareBatchesError::Incomplete) => {
                debug!(
                    ?block_digest,
                    "verification request waiting on incomplete processed-block ancestry"
                );

                // Incomplete ancestry is not an invalid verdict. Keep the job
                // parked until its request future is dropped.
                verification.cancelled().await;
                ProcessedBlock::Cancelled
            }
            Err(PrepareBatchesError::Invalid | PrepareBatchesError::Stale) => {
                unreachable!("processed-block check cannot return Invalid or Stale")
            }
        }
    }

    /// Takes the candidate's parent from `ancestry`, replays its missing ancestry, and forks
    /// batches from its state.
    async fn prepare_parent<S, V>(
        &mut self,
        context: &E,
        marshal: MarshalMailbox<S, V>,
        block_digest: BlockDigest<A, E>,
        ancestry: &mut impl Ancestry<A::Block>,
        verification: &mut Verification,
    ) -> Result<PreparedParent<A, E>, PrepareFailure>
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        let block = match fetch_ancestor(verification, ancestry).await {
            Some(Some(block)) => block,
            Some(None) => {
                debug!(
                    ?block_digest,
                    "verification request waiting on incomplete parent ancestry"
                );

                // As with incomplete candidate ancestry, only dropping the
                // request future should release this pending request.
                verification.cancelled().await;
                return Err(PrepareFailure::Cancelled);
            }
            None => {
                debug!(
                    ?block_digest,
                    "verification request cancelled before parent ancestry arrived"
                );
                return Err(PrepareFailure::Cancelled);
            }
        };
        let digest = block.digest();
        let batches = match self
            .execution
            .prepare_batches(
                &mut self.app,
                context,
                marshal,
                block.clone(),
                verification,
                Some(&self.replays),
            )
            .await
        {
            Ok(batches) => batches,
            Err(PrepareBatchesError::Invalid) => {
                let (processed, pending_keys) = self.execution.summary();
                warn!(
                    parent_digest = ?digest,
                    ?block_digest,
                    pending_keys,
                    last_processed = ?processed.digest,
                    "verification rejected: prepare_batches returned Invalid"
                );
                return Err(PrepareFailure::Invalid);
            }
            Err(PrepareBatchesError::Incomplete) => {
                debug!(
                    parent_digest = ?digest,
                    ?block_digest,
                    "verification request waiting on incomplete ancestry during prepare_batches"
                );
                verification.cancelled().await;
                return Err(PrepareFailure::Cancelled);
            }
            Err(PrepareBatchesError::Cancelled) => {
                debug!(
                    parent_digest = ?digest,
                    "verification request cancelled during prepare_batches"
                );
                return Err(PrepareFailure::Cancelled);
            }
            Err(PrepareBatchesError::Stale) => {
                debug!(
                    parent_digest = ?digest,
                    ?block_digest,
                    "verification went stale during prepare_batches"
                );
                return Err(PrepareFailure::Stale);
            }
        };

        Ok(PreparedParent {
            block,
            digest,
            batches,
        })
    }

    /// Executes application verification and caches commitment-matching state.
    async fn verify(
        &mut self,
        context: &E,
        consensus_context: A::Context,
        block: Arc<A::Block>,
        parent: PreparedParent<A, E>,
        ancestry: impl Ancestry<A::Block>,
        verification: &mut Verification,
    ) -> Attempt {
        let block_digest = block.digest();
        let round = block.context().round();

        // Restore the candidate and parent taken from `ancestry`, so the application receives the
        // full candidate-first ancestry.
        let ancestry = marshal_ancestry::with_prefix([block.clone(), parent.block], ancestry);
        let verified = match await_or_cancel(
            verification,
            self.app.verify(
                (
                    context.child("application").child("verify_attempt"),
                    consensus_context,
                ),
                ancestry,
                parent.batches,
            ),
        )
        .await
        {
            Some(Ok(result)) => result,
            Some(Err(ExecutionError::Stale)) => {
                debug!(
                    parent_digest = ?parent.digest,
                    ?block_digest,
                    "verification went stale during application execution"
                );
                return Attempt::Stale;
            }
            Some(Err(ExecutionError::Invalid(reason))) => {
                debug!(
                    parent_digest = ?parent.digest,
                    ?block_digest,
                    reason,
                    "verification rejected: invalid execution"
                );
                return Attempt::Done(VerificationResult::Decided(false));
            }
            Some(Err(err @ ExecutionError::Fatal(_))) => {
                panic_unless_stopping(context, "application verification", &err);
                return future::pending().await;
            }
            None => {
                debug!(
                    parent_digest = ?parent.digest,
                    "verification request cancelled during verify"
                );
                return Attempt::Done(VerificationResult::Cancelled);
            }
        };

        let Some(merkleized) = verified else {
            warn!(
                parent_digest = ?parent.digest,
                ?block_digest,
                "verification rejected: app.verify returned None"
            );
            return Attempt::Done(VerificationResult::Decided(false));
        };
        let tail = info_span!(
            "stateful.processor.match_commitments",
            block = %block_digest,
            parent = %parent.digest,
        )
        .entered();

        // Application::verify need not check sync targets, so state that does not match the
        // candidate's commitments is rejected before it is cached.
        if !A::Databases::matches_sync_targets(&merkleized, &A::sync_targets(&block)) {
            warn!(
                parent_digest = ?parent.digest,
                ?block_digest,
                "verification rejected: verified state must match block commitments"
            );
            return Attempt::Done(VerificationResult::Decided(false));
        }
        // Caching is retention, not part of the verdict. The execution matched
        // the block's commitments on its own branch, and a finalization
        // discarding the entry does not change that answer.
        if !self.execution.cache_pending(
            block_digest,
            PendingEntry {
                round,
                parent: parent.digest,
                merkleized,
                provenance: Provenance::Verified,
            },
        ) {
            debug!(
                parent_digest = ?parent.digest,
                ?block_digest,
                "verified state not cached, overtaken by finalization"
            );
            return Attempt::Done(VerificationResult::Decided(true));
        }
        self.execution.update_pending_metric();
        drop(block);
        drop(tail);
        Attempt::Done(VerificationResult::Decided(true))
    }
}
