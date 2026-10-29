use super::{
    Application, Execution, PrepareBatchesError, Progress, ReplayFlights, ReplayTracking,
    is_already_processed,
};
use crate::stateful::actor::BlockDigest;
use commonware_consensus::{
    Heightable,
    marshal::{
        ancestry::{self as marshal_ancestry, Ancestry, BlockProvider, BoxedAncestry},
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
};
use commonware_cryptography::{Digested, Digestible, certificate::Scheme};
use commonware_runtime::{Clock, Supervisor};
use futures::StreamExt;
use std::future::pending;
use tracing::{debug, warn};

/// Result of checking a candidate against the canonical chain through the processed anchor.
enum ProcessedBlock {
    /// The candidate is above the processed height and requires execution.
    Continue,
    /// The candidate is the canonical block at its height.
    Accepted,
    /// The candidate is at or below the processed height but is not the canonical block there.
    Rejected,
}

/// Processes candidates for verification and parent recovery against shared speculative state.
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
    /// Recovers the first block's state and leaves it buffered at the front of `ancestry`.
    ///
    /// Returns `true` once the parent's state is ready, or `false` if the ancestry is invalid or
    /// incomplete. The original cursor is replaced only after recovery succeeds, so an interrupted
    /// attempt can restart from the same ancestry.
    pub(in crate::stateful::actor) async fn recover_parent<S, V>(
        &mut self,
        context: &E,
        marshal: MarshalMailbox<S, V>,
        ancestry: &mut BoxedAncestry<A::Block>,
        progress: &Progress<BlockDigest<A, E>>,
    ) -> bool
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        let mut cursor = ancestry.clone();
        let Some(parent) = cursor.next().await else {
            return false;
        };
        let result = self
            .execution
            .recover(
                &mut self.app,
                context,
                marshal,
                parent.clone(),
                ReplayTracking {
                    flights: &self.replays,
                    progress,
                },
            )
            .await;
        if let Err(error) = result {
            debug!(?error, "proposal declined: parent recovery failed");
            return false;
        }
        *ancestry = BoxedAncestry::new(marshal_ancestry::with_prefix([parent], cursor));
        true
    }

    /// Verifies the first block of `ancestry` on its parent's state.
    ///
    /// Returns `true` to accept the block or `false` to reject it. Incomplete ancestry stays pending
    /// until the attempt is dropped.
    ///
    /// A block whose state is cached, or that is the canonical block at or below the processed
    /// height, is accepted without processing. Any other block at or below the processed height
    /// is rejected. Otherwise, the block is accepted only if its shared processing accepts it,
    /// matches the block's commitments, and can still be cached.
    ///
    /// `progress` records the attempt's phase so it can be classified across a finalization.
    pub(in crate::stateful::actor) async fn run<S, V>(
        &mut self,
        context: &E,
        marshal: MarshalMailbox<S, V>,
        ancestry: impl Ancestry<A::Block>,
        progress: &Progress<BlockDigest<A, E>>,
    ) -> bool
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        let timer = self.execution.metrics.verify_duration.timer(context);
        let mut ancestry = ancestry;

        // Acquire the candidate independently for each request. Availability is
        // round-scoped, so requests cannot safely share this part of the work.
        let Some(block) = ancestry.next().await else {
            debug!("verification request waiting on incomplete block ancestry");
            return pending().await;
        };
        let block_digest = block.digest();

        // A cached state was built locally or processed as a candidate, so it answers the
        // verification.
        if self.execution.pending_contains(&block_digest) {
            timer.observe(context);
            return true;
        }

        // A block at or below the processed height cannot be processed on the applied state, so
        // it is accepted only if it is canonical.
        match self.check_processed(marshal.clone(), &block).await {
            ProcessedBlock::Continue => {}
            ProcessedBlock::Accepted => {
                timer.observe(context);
                return true;
            }
            ProcessedBlock::Rejected => return false,
        }

        // Recovering the parent's state and processing the block are shared with concurrent
        // requests.
        let Some(parent) = self
            .prepare_parent(context, marshal, block_digest, &mut ancestry, progress)
            .await
        else {
            return false;
        };
        let valid = self
            .process((block, parent), context, ancestry, progress)
            .await;
        if valid {
            timer.observe(context);
        }
        valid
    }

    /// Classifies `block` against the canonical chain through the processed anchor without
    /// processing it.
    async fn check_processed<S, V>(
        &mut self,
        marshal: MarshalMailbox<S, V>,
        block: &Digested<A::Block>,
    ) -> ProcessedBlock
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
    {
        let block_digest = block.digest();
        let processed = self.execution.processed();
        match is_already_processed(processed, marshal, block).await {
            Ok(true) => ProcessedBlock::Accepted,
            Ok(false) if block.height() <= processed.height => ProcessedBlock::Rejected,
            Ok(false) => ProcessedBlock::Continue,
            Err(PrepareBatchesError::Incomplete) => {
                debug!(
                    ?block_digest,
                    "verification request waiting on incomplete processed-block ancestry"
                );
                pending().await
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
        progress: &Progress<BlockDigest<A, E>>,
    ) -> Option<Digested<A::Block>>
    where
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    {
        let Some(block) = ancestry.next().await else {
            debug!(
                ?block_digest,
                "verification request waiting on incomplete parent ancestry"
            );
            return pending().await;
        };
        let digest = block.digest();
        match self
            .execution
            .recover(
                &mut self.app,
                context,
                marshal,
                block.clone(),
                ReplayTracking {
                    flights: &self.replays,
                    progress,
                },
            )
            .await
        {
            Ok(()) => Some(block),
            Err(PrepareBatchesError::Invalid) => {
                let (processed, pending_keys) = self.execution.summary();
                warn!(
                    parent_digest = ?digest,
                    ?block_digest,
                    pending_keys,
                    last_processed = ?processed.digest,
                    "verification rejected: parent recovery returned Invalid"
                );
                None
            }
            Err(PrepareBatchesError::Incomplete) => {
                debug!(
                    parent_digest = ?digest,
                    ?block_digest,
                    "verification request waiting on incomplete ancestry during parent recovery"
                );
                pending().await
            }
        }
    }

    /// Processes `block` on its parent's state, sharing the work with concurrent requests.
    ///
    /// Returns `true` if the state is available or processing succeeds, or `false` if shared
    /// processing fails.
    async fn process(
        &mut self,
        (block, parent): (Digested<A::Block>, Digested<A::Block>),
        context: &E,
        ancestry: impl Ancestry<A::Block>,
        progress: &Progress<BlockDigest<A, E>>,
    ) -> bool {
        let (block_digest, parent_digest) = (block.digest(), parent.digest());

        // Restore the candidate and parent taken from `ancestry`, so the application receives the
        // full candidate-first ancestry.
        let ancestry = marshal_ancestry::with_prefix([block, parent], ancestry);
        match self
            .execution
            .replay_shared(
                &mut self.app,
                context,
                block_digest,
                ancestry,
                ReplayTracking {
                    flights: &self.replays,
                    progress,
                },
            )
            .await
        {
            Ok(()) => true,
            Err(error) => {
                warn!(
                    ?parent_digest,
                    ?block_digest,
                    ?error,
                    "verification rejected: processing failed"
                );
                false
            }
        }
    }
}
