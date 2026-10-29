use super::{
    Application, Cancellation, Execution, PrepareBatchesError, ReplayFlights, ReplayTracking,
    VerificationProgress, await_or_cancel, fetch_ancestor, is_already_processed,
};
use crate::stateful::actor::{BlockDigest, core::Verification};
use commonware_consensus::{
    Heightable, Roundable,
    marshal::{
        ancestry::{self as marshal_ancestry, Ancestry, BlockProvider},
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
};
use commonware_cryptography::{Digested, Digestible, certificate::Scheme};
use commonware_runtime::{Clock, Supervisor};
use tracing::{debug, warn};

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

/// Executes one verification request against the processor's shared speculative state.
pub(in crate::stateful::actor) struct Verifier<E, A>
where
    A: Application<E>,
{
    pub(super) app: A,
    pub(super) execution: Execution<E, A>,
    pub(super) replays: ReplayFlights<BlockDigest<A, E>>,
}

impl<E, A> Clone for Verifier<E, A>
where
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
    E: Supervisor + Clock,
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
    /// verifies it and its shared execution matches the block's commitments and can still be
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
            .check_processed(marshal.clone(), &block, verification)
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

        // Recovering the parent's state and executing the block are shared with concurrent
        // requests. The verdict on the block's rules is this request's own, and the block is
        // executed only once they accept it.
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
        let valid = self
            .verify(
                context,
                consensus_context,
                (block, parent),
                ancestry,
                progress,
                verification,
            )
            .await?;
        if valid {
            timer.observe(context);
        }
        Some(valid)
    }

    /// Classifies `block` against the canonical chain through the processed anchor without
    /// executing it.
    async fn check_processed<S, V>(
        &mut self,
        marshal: MarshalMailbox<S, V>,
        block: &Digested<A::Block>,
        verification: &mut Verification,
    ) -> ProcessedBlock
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
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

    /// Takes the candidate's parent from `ancestry` and replays its missing ancestry.
    async fn prepare_parent<S, V>(
        &mut self,
        context: &E,
        marshal: MarshalMailbox<S, V>,
        block_digest: BlockDigest<A, E>,
        ancestry: &mut impl Ancestry<A::Block>,
        progress: &VerificationProgress<BlockDigest<A, E>>,
        verification: &mut Verification,
    ) -> Result<Digested<A::Block>, PrepareFailure>
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
        match self
            .execution
            .recover(
                &mut self.app,
                context,
                marshal,
                block.clone(),
                verification,
                ReplayTracking {
                    flights: &self.replays,
                    progress: Some(progress),
                },
            )
            .await
        {
            Ok(()) => Ok(block),
            Err(PrepareBatchesError::Invalid) => {
                let (processed, pending_keys) = self.execution.summary();
                warn!(
                    parent_digest = ?digest,
                    ?block_digest,
                    pending_keys,
                    last_processed = ?processed.digest,
                    "verification rejected: parent recovery returned Invalid"
                );
                Err(PrepareFailure::Invalid)
            }
            Err(PrepareBatchesError::Incomplete) => {
                debug!(
                    parent_digest = ?digest,
                    ?block_digest,
                    "verification request waiting on incomplete ancestry during parent recovery"
                );
                verification.cancelled().await;
                Err(PrepareFailure::Cancelled)
            }
            Err(PrepareBatchesError::Cancelled) => {
                debug!(
                    parent_digest = ?digest,
                    "verification request cancelled during parent recovery"
                );
                Err(PrepareFailure::Cancelled)
            }
        }
    }

    /// Checks the rules of the candidate in `blocks` with the application, then executes it on
    /// the state of its parent, the second of `blocks`, and records the executed state as
    /// verified.
    ///
    /// Returns `Some(false)` at the first rejection and `None` if `verification` is cancelled
    /// first. A rejection by the rules executes nothing. The execution is shared with concurrent
    /// requests for the candidate; dropping this future while it owns the execution lets a waiting
    /// request execute the block itself.
    async fn verify(
        &mut self,
        context: &E,
        consensus_context: A::Context,
        (block, parent): (Digested<A::Block>, Digested<A::Block>),
        ancestry: impl Ancestry<A::Block>,
        progress: &VerificationProgress<BlockDigest<A, E>>,
        verification: &mut Verification,
    ) -> Option<bool> {
        let (block_digest, parent_digest) = (block.digest(), parent.digest());
        progress.set_verifying(block_digest, parent_digest, consensus_context.round());

        // Restore the candidate and parent taken from `ancestry`, so the application receives the
        // full candidate-first ancestry.
        let ancestry = marshal_ancestry::with_prefix([block.clone(), parent], ancestry);
        let Some(valid) = await_or_cancel(
            verification,
            self.app.verify(
                (
                    context.child("application").child("verify_attempt"),
                    consensus_context,
                ),
                ancestry,
            ),
        )
        .await
        else {
            debug!(?block_digest, "verification request cancelled during verify");
            return None;
        };
        if !valid {
            warn!(
                ?parent_digest,
                ?block_digest,
                "verification rejected: app.verify returned false"
            );
            return Some(false);
        }

        match self
            .execution
            .replay_shared(
                &mut self.app,
                context,
                block_digest,
                block,
                verification,
                ReplayTracking {
                    flights: &self.replays,
                    progress: Some(progress),
                },
            )
            .await
        {
            Ok(()) => {}
            Err(PrepareBatchesError::Cancelled) => {
                debug!(?block_digest, "verification request cancelled during execution");
                return None;
            }
            Err(error) => {
                warn!(
                    ?parent_digest,
                    ?block_digest,
                    ?error,
                    "verification rejected: execution failed"
                );
                return Some(false);
            }
        }

        if !self.execution.mark_verified(block_digest) {
            warn!(
                ?parent_digest,
                ?block_digest,
                "verification result became incompatible before it was marked verified"
            );
            return Some(false);
        }
        Some(true)
    }
}
