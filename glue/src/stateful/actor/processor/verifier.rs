use super::{
    Application, Cancellation, Execution, PendingEntry, PrepareBatchesError, ReplayFlights,
    ReplayTracking, Unmerkleized, VerificationProgress, await_or_cancel, fetch_ancestor,
    is_already_processed,
};
use crate::stateful::{
    actor::{BlockDigest, core::Verification},
    db::DatabaseSet,
};
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
    /// Returns `Some(true)` to accept the block, `Some(false)` to reject it, and `None` if
    /// `verification` is cancelled first. Incomplete ancestry is not a verdict: the request stays
    /// pending until cancelled.
    ///
    /// A block that was proposed or verified locally, or that is the canonical block at or below
    /// the processed height, is accepted without execution. Any other block at or below the
    /// processed height is rejected. Otherwise, the block is accepted only if the application
    /// verifies it and the resulting state matches the block's commitments and can still be
    /// cached.
    ///
    /// `progress` records the attempt's phase so it can be classified across a finalization.
    pub(in crate::stateful::actor) async fn run<S, V>(
        &mut self,
        context: &E,
        marshal: MarshalMailbox<S, V>,
        consensus_context: A::Context,
        ancestry: impl Ancestry<A::Block>,
        progress: &VerificationProgress<BlockDigest<A, E>>,
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

        // A replayed state is not a verdict, so only locally built or verified blocks skip
        // execution.
        if self.execution.pending_verified(&block_digest) {
            timer.observe(context);
            return Some(true);
        }

        // A block at or below the processed height cannot be re-executed on the applied state, so
        // it is accepted only if it is canonical.
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

        // Reconstructing the parent's state is the only work shared across requests.
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

        progress.set_verifying(block_digest, parent.digest, consensus_context.round());
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
                verification.cancelled().await;
                ProcessedBlock::Cancelled
            }
            Err(PrepareBatchesError::Invalid) => {
                unreachable!("processed-block check cannot return Invalid")
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
        progress: &VerificationProgress<BlockDigest<A, E>>,
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
                    progress,
                }),
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
    ) -> Option<bool> {
        let block_digest = block.digest();
        let round = consensus_context.round();

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

        // Application::verify need not check sync targets, so state that does not match the
        // candidate's commitments is rejected before it is cached.
        if !A::Databases::matches_sync_targets(&merkleized, &A::sync_targets(&block)) {
            warn!(
                parent_digest = ?parent.digest,
                ?block_digest,
                "verification rejected: verified state must match block commitments"
            );
            return Some(false);
        }
        if !self.execution.cache_pending(
            block_digest,
            PendingEntry {
                round,
                parent: parent.digest,
                merkleized,
                verified: true,
            },
        ) {
            warn!(
                parent_digest = ?parent.digest,
                ?block_digest,
                "verification result became incompatible before caching"
            );
            return Some(false);
        }
        self.execution.update_pending_metric();
        drop(block);
        drop(tail);
        Some(true)
    }
}
