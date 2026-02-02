//! Wrapper for consensus applications that handles epochs and block dissemination.
//!
//! # Overview
//!
//! [`Marshaled`] is an adapter that wraps any [`VerifyingApplication`] implementation to handle
//! epoch transitions automatically. It intercepts consensus operations (propose, verify) and
//! ensures blocks are only produced within valid epoch boundaries.
//!
//! # Epoch Boundaries
//!
//! When the parent is the last block in an epoch (as determined by the [`Epocher`]), this wrapper
//! re-proposes that boundary block instead of building a new block. This avoids producing blocks
//! that would be pruned by the epoch transition.
//!
//! # Deferred Verification
//!
//! Before casting a notarize vote, [`Marshaled`] waits for the block to become available and
//! then verifies that the block's embedded context matches the consensus context. However, it does not
//! wait for the application to finish verifying the block contents before voting. This enables verification
//! to run while we wait for a quorum of votes to form a certificate (hiding verification latency behind network
//! latency). Once a certificate is formed, we wait on the verification result in [`CertifiableAutomaton::certify`]
//! before voting to finalize (ensuring no invalid blocks are admitted to the canonical chain).
//!
//! # Usage
//!
//! Wrap your [`Application`] implementation with [`Marshaled::new`] and provide it to your
//! consensus engine for the [`Automaton`] and [`Relay`]. The wrapper handles all epoch logic transparently.
//!
//! ```rust,ignore
//! let application = Marshaled::new(
//!     context,
//!     my_application,
//!     marshal_mailbox,
//!     epocher,
//! );
//! ```
//!
//! # Implementation Notes
//!
//! - Genesis blocks are handled specially: epoch 0 returns the application's genesis block,
//!   while subsequent epochs use the last block of the previous epoch as genesis
//! - Blocks are automatically verified to be within the current epoch
//!
//! # Future Work
//!
//! - To further reduce view latency, a participant could optimistically vote for a block prior to
//!   observing its availability during [`Automaton::verify`]. However, this would require updating
//!   other components (like [`crate::marshal`]) to handle backfill where notarization does not imply
//!   a block is fetchable (without modification, a malicious leader that withholds blocks during propose
//!   could get an honest node to exhaust their network rate limit fetching things that don't exist rather
//!   than blocks they need AND can fetch).

use crate::{
    marshal::{ancestry::AncestorStream, core::Mailbox, standard::Standard, Update},
    simplex::types::Context,
    types::{Epoch, Epocher, Height, Round},
    Application, Automaton, Block, CertifiableAutomaton, CertifiableBlock, Epochable, Relay,
    Reporter, VerifyingApplication,
};
use commonware_cryptography::{certificate::Scheme, Committable, Digestible};
use commonware_macros::select;
use commonware_runtime::{telemetry::metrics::status::GaugeExt, Clock, Metrics, Spawner};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use futures::lock::Mutex;
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::{collections::HashMap, sync::Arc, time::Instant};
use tracing::{debug, warn};

type TasksMap<B> = HashMap<(Round, <B as Digestible>::Digest), oneshot::Receiver<bool>>;

/// An [`Application`] adapter that handles epoch transitions and validates block ancestry.
///
/// This wrapper intercepts consensus operations to enforce epoch boundaries and validate
/// block ancestry. It prevents blocks from being produced outside their valid epoch,
/// handles the special case of re-proposing boundary blocks at epoch boundaries,
/// and ensures all blocks have valid parent linkage and contiguous heights.
///
/// # Ancestry Validation
///
/// Applications wrapped by [`Marshaled`] can rely on the following ancestry checks being
/// performed automatically during verification:
/// - Parent digest matches the consensus context's expected parent
/// - Block height is exactly one greater than the parent's height
///
/// Verifying only the immediate parent is sufficient since the parent itself must have
/// been notarized by consensus, which guarantees it was verified and accepted by a quorum.
/// This means the entire ancestry chain back to genesis is transitively validated.
///
/// Applications do not need to re-implement these checks in their own verification logic.
///
/// # Context Recovery
///
/// With deferred verification, validators wait for data availability (DA) and verify the context
/// before voting. If a validator crashes after voting but before certification, they lose their in-memory
/// verification task. When recovering, validators extract context from a [`CertifiableBlock`].
///
/// _This embedded context is trustworthy because the notarizing quorum (which contains at least f+1 honest
/// validators) verified that the block's context matched the consensus context before voting._
#[derive(Clone)]
pub struct Marshaled<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E>,
    B: CertifiableBlock + Committable<Commitment = <B as Digestible>::Digest>,
    ES: Epocher,
{
    context: E,
    application: A,
    marshal: Mailbox<S, Standard<B>>,
    epocher: ES,
    last_built: Arc<Mutex<Option<(Round, B)>>>,
    verification_tasks: Arc<Mutex<TasksMap<B>>>,

    build_duration: Gauge,
}

impl<E, S, A, B, ES> Marshaled<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = S,
        Context = Context<B::Digest, S::PublicKey>,
    >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>
        + Committable<Commitment = <B as Digestible>::Digest>,
    ES: Epocher,
{
    /// Creates a new [`Marshaled`] wrapper.
    pub fn new(context: E, application: A, marshal: Mailbox<S, Standard<B>>, epocher: ES) -> Self {
        let build_duration = Gauge::default();
        context.register(
            "build_duration",
            "Time taken for the application to build a new block, in milliseconds",
            build_duration.clone(),
        );

        Self {
            context,
            application,
            marshal,
            epocher,
            last_built: Arc::new(Mutex::new(None)),
            verification_tasks: Arc::new(Mutex::new(HashMap::new())),

            build_duration,
        }
    }

    /// Verifies a proposed block's application-level validity.
    ///
    /// This method validates that:
    /// 1. The block's parent digest matches the expected parent
    /// 2. The block's height is exactly one greater than the parent's height
    /// 3. The underlying application's verification logic passes
    ///
    /// Verification is spawned in a background task and returns a receiver that will contain
    /// the verification result. Valid blocks are reported to the marshal as verified.
    #[inline]
    async fn deferred_verify(
        &mut self,
        context: <Self as Automaton>::Context,
        block: B,
    ) -> oneshot::Receiver<bool> {
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let (mut tx, rx) = oneshot::channel();
        self.context
            .with_label("deferred_verify")
            .with_attribute("round", context.round)
            .spawn(move |runtime_context| async move {
                let (parent_view, parent_digest) = context.parent;
                let parent_request = fetch_parent(
                    parent_digest,
                    Some(Round::new(context.epoch(), parent_view)),
                    &mut application,
                    &mut marshal,
                )
                .await;

                // If consensus drops the receiver, we can stop work early.
                let parent = select! {
                    _ = tx.closed() => {
                        debug!(
                            reason = "consensus dropped receiver",
                            "skipping verification"
                        );
                        return;
                    },
                    result = parent_request => match result {
                        Ok(parent) => parent,
                        Err(_) => {
                            debug!(
                                reason = "failed to fetch parent or block",
                                "skipping verification"
                            );
                            return;
                        }
                    },
                };

                // Validate parent digest and height contiguity.
                if block.parent() != parent.digest() || parent.digest() != parent_digest {
                    debug!(
                        block_parent = %block.parent(),
                        expected_parent = %parent.digest(),
                        "block parent digest does not match expected parent"
                    );
                    tx.send_lossy(false);
                    return;
                }
                if parent.height().next() != block.height() {
                    debug!(
                        parent_height = %parent.height(),
                        block_height = %block.height(),
                        "block height is not contiguous with parent height"
                    );
                    tx.send_lossy(false);
                    return;
                }

                // Request verification from the application.
                let ancestry_stream =
                    AncestorStream::new(marshal.clone(), [block.clone(), parent]);
                let validity_request = application.verify(
                    (runtime_context.with_label("app_verify"), context.clone()),
                    ancestry_stream,
                );

                // If consensus drops the receiver, we can stop work early.
                let application_valid = select! {
                    _ = tx.closed() => {
                        debug!(
                            reason = "consensus dropped receiver",
                            "skipping verification"
                        );
                        return;
                    },
                    valid = validity_request => valid,
                };

                // Handle the verification result.
                if application_valid {
                    marshal.verified(context.round, block).await;
                }
                tx.send_lossy(application_valid);
            });

        rx
    }
}

impl<E, S, A, B, ES> Automaton for Marshaled<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = S,
        Context = Context<B::Digest, S::PublicKey>,
    >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>
        + Committable<Commitment = <B as Digestible>::Digest>,
    ES: Epocher,
{
    type Digest = B::Digest;
    type Context = Context<Self::Digest, S::PublicKey>;

    /// Returns the genesis digest for a given epoch.
    ///
    /// For epoch 0, this returns the application's genesis block digest. For subsequent
    /// epochs, it returns the digest of the last block from the previous epoch, which
    /// serves as the genesis block for the new epoch.
    ///
    /// # Panics
    ///
    /// Panics if a non-zero epoch is requested but the previous epoch's final block is not
    /// available in storage. This indicates a critical error in the consensus engine startup
    /// sequence, as engines must always have the genesis block before starting.
    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        if epoch.is_zero() {
            return self.application.genesis().await.digest();
        }

        let prev = epoch.previous().expect("checked to be non-zero above");
        let last_height = self
            .epocher
            .last(prev)
            .expect("previous epoch should exist");
        let Some(block) = self.marshal.get_block(last_height).await else {
            // A new consensus engine will never be started without having the genesis block
            // of the new epoch (the last block of the previous epoch) already stored.
            unreachable!("missing starting epoch block at height {}", last_height);
        };
        block.digest()
    }

    /// Proposes a new block or re-proposes the epoch boundary block.
    ///
    /// This method builds a new block from the underlying application unless the parent block
    /// is the last block in the current epoch. When at an epoch boundary, it re-proposes the
    /// boundary block to avoid creating blocks that would be invalidated by the epoch transition.
    ///
    /// The proposal operation is spawned in a background task and returns a receiver that will
    /// contain the proposed block's digest when ready. The built block is cached for later
    /// broadcasting.
    async fn propose(
        &mut self,
        consensus_context: Context<Self::Digest, S::PublicKey>,
    ) -> oneshot::Receiver<Self::Digest> {
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let last_built = self.last_built.clone();
        let epocher = self.epocher.clone();

        // Metrics
        let build_duration = self.build_duration.clone();

        let (mut tx, rx) = oneshot::channel();
        self.context
            .with_label("propose")
            .with_attribute("round", consensus_context.round)
            .spawn(move |runtime_context| async move {
                let (parent_view, parent_digest) = consensus_context.parent;
                let parent_request = fetch_parent(
                    parent_digest,
                    Some(Round::new(consensus_context.epoch(), parent_view)),
                    &mut application,
                    &mut marshal,
                )
                .await;

                let parent = select! {
                    _ = tx.closed() => {
                        debug!(reason = "consensus dropped receiver", "skipping proposal");
                        return;
                    },
                    result = parent_request => match result {
                        Ok(parent) => parent,
                        Err(_) => {
                            debug!(
                                ?parent_digest,
                                reason = "failed to fetch parent block",
                                "skipping proposal"
                            );
                            return;
                        }
                    },
                };

                // Special case: If the parent block is the last block in the epoch,
                // re-propose it as to not produce any blocks that will be cut out
                // by the epoch transition.
                let last_in_epoch = epocher
                    .last(consensus_context.epoch())
                    .expect("current epoch should exist");
                if parent.height() == last_in_epoch {
                    let digest = parent.digest();
                    {
                        let mut lock = last_built.lock().await;
                        *lock = Some((consensus_context.round, parent));
                    }

                    let success = tx.send_lossy(digest);
                    debug!(
                        round = ?consensus_context.round,
                        ?digest,
                        success,
                        "re-proposed parent block at epoch boundary"
                    );
                    return;
                }

                let ancestor_stream = AncestorStream::new(marshal.clone(), [parent]);
                let build_request = application.propose(
                    (
                        runtime_context.with_label("app_propose"),
                        consensus_context.clone(),
                    ),
                    ancestor_stream,
                );

                let start = Instant::now();
                let built_block = select! {
                    _ = tx.closed() => {
                        debug!(reason = "consensus dropped receiver", "skipping proposal");
                        return;
                    },
                    result = build_request => match result {
                        Some(block) => block,
                        None => {
                            debug!(
                                ?parent_digest,
                                reason = "block building failed",
                                "skipping proposal"
                            );
                            return;
                        }
                    },
                };
                let _ = build_duration.try_set(start.elapsed().as_millis());

                let digest = built_block.digest();
                {
                    let mut lock = last_built.lock().await;
                    *lock = Some((consensus_context.round, built_block));
                }

                let success = tx.send_lossy(digest);
                debug!(
                    round = ?consensus_context.round,
                    ?digest,
                    success,
                    "proposed new block"
                );
            });
        rx
    }

    async fn verify(
        &mut self,
        context: Context<Self::Digest, S::PublicKey>,
        digest: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let mut marshal = self.marshal.clone();
        let mut marshaled = self.clone();

        let (mut tx, rx) = oneshot::channel();
        self.context
            .with_label("optimistic_verify")
            .with_attribute("round", context.round)
            .spawn(move |_| async move {
                let block_request = marshal.subscribe(Some(context.round), digest).await;
                let block = select! {
                    _ = tx.closed() => {
                        debug!(
                            reason = "consensus dropped receiver",
                            "skipping optimistic verification"
                        );
                        return;
                    },
                    result = block_request => match result {
                        Ok(block) => block,
                        Err(_) => {
                            debug!(
                                ?digest,
                                reason = "failed to fetch block for optimistic verification",
                                "skipping optimistic verification"
                            );
                            return;
                        }
                    },
                };

                // Blocks are invalid if they are not within the current epoch and they aren't
                // a re-proposal of the boundary block.
                let Some(block_bounds) = marshaled.epocher.containing(block.height()) else {
                    debug!(
                        height = %block.height(),
                        "block height not in any known epoch"
                    );
                    tx.send_lossy(false);
                    return;
                };
                if block_bounds.epoch() != context.epoch() {
                    debug!(
                        epoch = %context.epoch(),
                        block_epoch = %block_bounds.epoch(),
                        "block is not in the current epoch"
                    );
                    tx.send_lossy(false);
                    return;
                }

                // Re-proposal detection: consensus signals a re-proposal by setting
                // context.parent to the block being verified (digest == context.parent.1).
                //
                // Re-proposals skip normal verification because:
                // 1. The block was already verified when originally proposed
                // 2. The parent-child height check would fail (parent IS the block)
                let is_reproposal = digest == context.parent.1;
                if is_reproposal {
                    if !is_at_epoch_boundary(&marshaled.epocher, block.height(), context.epoch()) {
                        debug!(
                            height = %block.height(),
                            last_in_epoch = %block_bounds.last(),
                            "re-proposal is not at epoch boundary"
                        );
                        tx.send_lossy(false);
                        return;
                    }

                    // Valid re-proposal. Create a completed verification task for `certify`
                    let round = context.round;
                    marshal.verified(round, block).await;

                    let (task_tx, task_rx) = oneshot::channel();
                    task_tx.send_lossy(true);
                    marshaled
                        .verification_tasks
                        .lock()
                        .await
                        .insert((round, digest), task_rx);

                    tx.send_lossy(true);
                    return;
                }

                // Before casting a notarize vote, ensure the block's embedded context matches
                // the consensus context.
                //
                // This is a critical step - the notarize quorum is guaranteed to have at least
                // f+1 honest validators who will verify against this context, preventing a Byzantine
                // proposer from embedding a malicious context. The other f honest validators who did
                // not vote will later use the block-embedded context to help finalize if Byzantine
                // validators withhold their finalize votes.
                if block.context() != context {
                    debug!(
                        ?context,
                        block_context = ?block.context(),
                        "block-embedded context does not match consensus context during optimistic verification"
                    );
                    tx.send_lossy(false);
                    return;
                }

                // Begin the rest of the verification process asynchronously.
                let round = context.round;
                let task = marshaled.deferred_verify(context, block).await;
                marshaled
                    .verification_tasks
                    .lock()
                    .await
                    .insert((round, digest), task);

                tx.send_lossy(true);
            });
        rx
    }
}

impl<E, S, A, B, ES> CertifiableAutomaton for Marshaled<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = S,
        Context = Context<B::Digest, S::PublicKey>,
    >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>
        + Committable<Commitment = <B as Digestible>::Digest>,
    ES: Epocher,
{
    async fn certify(&mut self, round: Round, digest: Self::Digest) -> oneshot::Receiver<bool> {
        // Attempt to retrieve the existing verification task for this (round, payload).
        let mut tasks_guard = self.verification_tasks.lock().await;
        let task = tasks_guard.remove(&(round, digest));
        drop(tasks_guard);
        if let Some(task) = task {
            return task;
        }

        // No in-progress task means we never verified this proposal locally. We can use the
        // block's embedded context to help complete finalization when Byzantine validators
        // withhold their finalize votes. If a Byzantine proposer embedded a malicious context,
        // the f+1 honest validators from the notarizing quorum will verify against the proper
        // context and reject the mismatch, preventing a 2f+1 finalization quorum.
        //
        // Subscribe to the block and verify using its embedded context once available.
        debug!(
            ?round,
            ?digest,
            "subscribing to block for certification using embedded context"
        );
        let block_rx = self.marshal.subscribe(Some(round), digest).await;
        let mut marshaled = self.clone();
        let epocher = self.epocher.clone();
        let (mut tx, rx) = oneshot::channel();
        self.context
            .with_label("certify")
            .with_attribute("round", round)
            .spawn(move |_| async move {
                let block = select! {
                    _ = tx.closed() => {
                        debug!(
                            reason = "consensus dropped receiver",
                            "skipping certification"
                        );
                        return;
                    },
                    result = block_rx => match result {
                        Ok(block) => block,
                        Err(_) => {
                            debug!(
                                ?digest,
                                reason = "failed to fetch block for certification",
                                "skipping certification"
                            );
                            return;
                        }
                    },
                };

                // Re-proposal detection for certify path: we don't have the consensus context,
                // only the block's embedded context from original proposal. Infer re-proposal from:
                // 1. Block is at epoch boundary (only boundary blocks can be re-proposed)
                // 2. Certification round's view > embedded context's view (re-proposals retain their
                //    original embedded context, so a later view indicates the block was re-proposed)
                // 3. Same epoch (re-proposals don't cross epoch boundaries)
                let embedded_context = block.context();
                let is_reproposal =
                    is_at_epoch_boundary(&epocher, block.height(), embedded_context.round.epoch())
                        && round.view() > embedded_context.round.view()
                        && round.epoch() == embedded_context.round.epoch();
                if is_reproposal {
                    // NOTE: It is possible that, during crash recovery, we call `marshal.verified`
                    // twice for the same block. That function is idempotent, so this is safe.
                    marshaled.marshal.verified(round, block).await;
                    tx.send_lossy(true);
                    return;
                }

                let verify_rx = marshaled.deferred_verify(embedded_context, block).await;
                if let Ok(result) = verify_rx.await {
                    tx.send_lossy(result);
                }
            });
        rx
    }
}

impl<E, S, A, B, ES> Relay for Marshaled<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>
        + Committable<Commitment = <B as Digestible>::Digest>,
    ES: Epocher,
{
    type Digest = B::Digest;

    /// Broadcasts a previously built block to the network.
    ///
    /// This uses the cached block from the last proposal operation. If no block was built or
    /// the digest does not match the cached block, the broadcast is skipped with a warning.
    async fn broadcast(&mut self, digest: Self::Digest) {
        let Some((round, block)) = self.last_built.lock().await.clone() else {
            warn!("missing block to broadcast");
            return;
        };

        if block.digest() != digest {
            warn!(
                round = %round,
                digest = %block.digest(),
                height = %block.height(),
                "skipping requested broadcast of block with mismatched digest"
            );
            return;
        }

        debug!(
            round = %round,
            digest = %block.digest(),
            height = %block.height(),
            "requested broadcast of built block"
        );
        self.marshal.proposed(round, block, ()).await;
    }
}

impl<E, S, A, B, ES> Reporter for Marshaled<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>
        + Reporter<Activity = Update<B>>,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>
        + Committable<Commitment = <B as Digestible>::Digest>,
    ES: Epocher,
{
    type Activity = A::Activity;

    /// Relays a report to the underlying [`Application`] and cleans up old verification tasks.
    async fn report(&mut self, update: Self::Activity) {
        // Clean up verification tasks for rounds <= the finalized round.
        if let Update::Tip(round, _, _) = &update {
            let mut tasks_guard = self.verification_tasks.lock().await;
            tasks_guard.retain(|(task_round, _), _| task_round > round);
        }
        self.application.report(update).await
    }
}

/// Returns true if the block is at an epoch boundary (last block in its epoch).
///
/// This is used to validate re-proposals, which are only allowed for boundary blocks.
#[inline]
fn is_at_epoch_boundary<ES: Epocher>(epocher: &ES, block_height: Height, epoch: Epoch) -> bool {
    epocher.last(epoch).is_some_and(|last| last == block_height)
}

/// Fetches the parent block given its digest and optional round.
///
/// This is a helper function used during proposal and verification to retrieve the parent
/// block. If the parent digest matches the genesis block, it returns the genesis block
/// directly without querying the marshal. Otherwise, it subscribes to the marshal to await
/// the parent block's availability.
///
/// Returns an error if the marshal subscription is cancelled.
#[inline]
async fn fetch_parent<E, S, A, B>(
    parent_digest: B::Digest,
    parent_round: Option<Round>,
    application: &mut A,
    marshal: &mut Mailbox<S, Standard<B>>,
) -> oneshot::Receiver<B>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>,
    B: Block + Committable<Commitment = <B as Digestible>::Digest>,
{
    let genesis = application.genesis().await;
    if parent_digest == genesis.digest() {
        let (tx, rx) = oneshot::channel();
        tx.send_lossy(genesis);
        rx
    } else {
        marshal.subscribe(parent_round, parent_digest).await
    }
}
