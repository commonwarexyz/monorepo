use super::{
    Application, Cancellation, Execution, PendingDigest, PrepareBatchesError, ReplayFlights,
    ReplayTracking, VerificationProgress, await_or_cancel, fetch_ancestor, is_already_processed,
};
use crate::stateful::{actor::core::Verification, db::DatabaseSet};
use commonware_consensus::{
    Heightable, Roundable,
    marshal::{
        ancestry::{self as marshal_ancestry, Ancestry, BlockProvider},
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
};
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_runtime::{Clock, Metrics, Spawner};
use rand_core::Rng;
use std::sync::Arc;
use tracing::{debug, info_span, warn};

/// Parent-relative database batches passed to application verification.
type Unmerkleized<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::Unmerkleized;

/// Result of comparing a candidate with the applied canonical chain.
enum ProcessedBlock {
    /// The candidate is above the applied anchor and still requires execution.
    Continue,
    /// The candidate is already on the applied canonical chain.
    Accepted,
    /// The candidate conflicts with the applied canonical chain.
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
}

/// A candidate's parent and forked batches, ready for application verification.
struct PreparedParent<A, E>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Parent block consumed while preparing the candidate's state.
    block: Arc<A::Block>,
    /// Digest of `block`.
    digest: PendingDigest<A, E>,
    /// Batches forked from the parent's speculative or applied state.
    batches: Unmerkleized<A, E>,
}

/// Executes one independently-polled verification request.
pub(in crate::stateful::actor) struct Verifier<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub(super) app: A,
    pub(super) execution: Execution<E, A>,
    pub(super) replays: ReplayFlights<PendingDigest<A, E>>,
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
    /// Runs one verification request while allowing unrelated requests to be
    /// polled.
    pub(in crate::stateful::actor) async fn run<S, V>(
        &mut self,
        context: &E,
        marshal: MarshalMailbox<S, V>,
        consensus_context: A::Context,
        ancestry: impl Ancestry<A::Block>,
        progress: &VerificationProgress<PendingDigest<A, E>>,
        verification: &mut Verification,
    ) -> Option<bool>
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
                return None;
            }
            None => {
                debug!("verification request cancelled before initial block arrived");
                return None;
            }
        };
        let block_digest = block.digest();

        if self.execution.pending_contains(&block_digest) {
            timer.observe(context);
            return Some(true);
        }

        // A finalized candidate cannot be re-executed against newer database
        // state. Prove it belongs to the canonical chain before accepting it.
        match self
            .check_processed(marshal.clone(), block.as_ref(), verification)
            .await
        {
            ProcessedBlock::Continue => {}
            ProcessedBlock::Accepted => {
                timer.observe(context);
                return Some(true);
            }
            ProcessedBlock::Rejected => return Some(false),
            ProcessedBlock::Cancelled => return None,
        }

        // Reconstruct the candidate's parent state. This is the only phase
        // shared across requests, keyed by the acquired parent's block digest.
        let parent = match self
            .prepare_parent(
                context,
                marshal,
                block_digest,
                &mut ancestry,
                progress,
                verification,
            )
            .await
        {
            Ok(parent) => parent,
            Err(PrepareFailure::Invalid) => return Some(false),
            Err(PrepareFailure::Cancelled) => return None,
        };

        progress.verifying(block_digest, parent.digest, consensus_context.round());
        let result = self
            .verify(
                context,
                consensus_context,
                block,
                parent,
                ancestry,
                verification,
            )
            .await;
        if result == Some(true) {
            timer.observe(context);
        }
        result
    }

    /// Classifies a candidate at or below the applied height without
    /// re-executing it.
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
        let last_processed = self.execution.last_processed();
        match is_already_processed(last_processed, marshal, block, verification).await {
            Ok(true) => ProcessedBlock::Accepted,
            Ok(false) if block.height() <= last_processed.height => ProcessedBlock::Rejected,
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
                // parked until its caller leaves.
                verification.cancelled().await;
                ProcessedBlock::Cancelled
            }
            Err(PrepareBatchesError::Invalid) => {
                unreachable!("processed-block check cannot return Invalid")
            }
        }
    }

    /// Reconstructs and forks the candidate's parent state.
    async fn prepare_parent<S, V>(
        &mut self,
        context: &E,
        marshal: MarshalMailbox<S, V>,
        block_digest: PendingDigest<A, E>,
        ancestry: &mut impl Ancestry<A::Block>,
        progress: &VerificationProgress<PendingDigest<A, E>>,
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

                // As with incomplete candidate ancestry, only cancellation or
                // actor-driven invalidation should release this pending request.
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
                Some(ReplayTracking {
                    flights: &self.replays,
                    progress: Some(progress),
                }),
            )
            .await
        {
            Ok(batches) => batches,
            Err(PrepareBatchesError::Invalid) => {
                let (last_processed, pending_keys) = self.execution.summary();
                warn!(
                    parent_digest = ?digest,
                    ?block_digest,
                    pending_keys,
                    last_processed = ?last_processed.digest,
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
        };

        Ok(PreparedParent {
            block,
            digest,
            batches,
        })
    }

    /// Executes application verification and publishes commitment-matching state.
    async fn verify(
        &mut self,
        context: &E,
        consensus_context: A::Context,
        block: Arc<A::Block>,
        parent: PreparedParent<A, E>,
        ancestry: impl Ancestry<A::Block>,
        verification: &mut Verification,
    ) -> Option<bool> {
        let block_digest = block.digest();
        let round = consensus_context.round();

        // The application expects the full candidate-first ancestry even
        // though the processor consumed those two entries while preparing state.
        let ancestry = marshal_ancestry::with_prefix([block.clone(), parent.block], ancestry);
        let verified = match await_or_cancel(
            verification,
            self.app.verify(
                (
                    context.child("application").child("verify_attempt"),
                    consensus_context.clone(),
                ),
                ancestry,
                parent.batches,
            ),
        )
        .await
        {
            Some(result) => result,
            None => {
                debug!(
                    parent_digest = ?parent.digest,
                    "verification request cancelled during verify"
                );
                return None;
            }
        };

        let Some(merkleized) = verified else {
            warn!(
                parent_digest = ?parent.digest,
                ?block_digest,
                "verification rejected: app.verify returned None"
            );
            return Some(false);
        };
        let tail = info_span!(
            "stateful.processor.match_commitments",
            block = %block_digest,
            parent = %parent.digest,
        )
        .entered();

        // Application output is adversarial until it matches the commitments
        // carried by the candidate block. Never cache it before this check.
        if !A::Databases::matches_sync_targets(&merkleized, &A::sync_targets(&block)) {
            warn!(
                parent_digest = ?parent.digest,
                ?block_digest,
                "verification rejected: verified state must match block commitments"
            );
            return Some(false);
        }
        if !self
            .execution
            .cache_pending(block_digest, parent.digest, round, merkleized)
        {
            warn!(
                parent_digest = ?parent.digest,
                ?block_digest,
                "verification result became incompatible before publication"
            );
            return Some(false);
        }
        self.execution.update_pending_metric();
        drop(block);
        drop(tail);
        Some(true)
    }
}
