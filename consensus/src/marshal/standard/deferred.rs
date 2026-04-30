//! Wrapper for consensus applications that handles epochs and block dissemination.
//!
//! # Overview
//!
//! [`Deferred`] is an adapter that wraps any [`VerifyingApplication`] implementation to handle
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
//! Before casting a notarize vote, [`Deferred`] waits for the block to become available and
//! then verifies that the block's embedded context matches the consensus context. However, it does not
//! wait for the application to finish verifying the block contents before voting. This enables verification
//! to run while we wait for a quorum of votes to form a certificate (hiding verification latency behind network
//! latency). Once a certificate is formed, we wait on the verification result in [`CertifiableAutomaton::certify`]
//! before voting to finalize (ensuring no invalid blocks are admitted to the canonical chain).
//!
//! # Usage
//!
//! Wrap your [`Application`] implementation with [`Deferred::new`] and provide it to your
//! consensus engine for the [`Automaton`] and [`Relay`]. The wrapper handles all epoch logic transparently.
//!
//! ```rust,ignore
//! let application = Deferred::new(
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
//! # Notarization and Data Availability
//!
//! In rare crash cases, it is possible for a notarization certificate to exist without a block being
//! available to the honest parties if [`CertifiableAutomaton::certify`] fails after a notarization is
//! formed.
//!
//! For this reason, it should not be expected that every notarized payload will be certifiable due
//! to the lack of an available block. However, if even one honest and online party has the block,
//! they will attempt to forward it to others via marshal's resolver.
//!
//! ```text
//!                                      ┌───────────────────────────────────────────────────┐
//!                                      ▼                                                   │
//! ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
//! │          B1         │◀──│          B2         │◀──│          B3         │XXX│          B4         │
//! └─────────────────────┘   └─────────────────────┘   └──────────┬──────────┘   └─────────────────────┘
//!                                                                │
//!                                                          Failed Certify
//! ```
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
    marshal::{
        ancestry::AncestorStream,
        application::{
            validation::{is_inferred_reproposal_at_certify, Stage},
            verification_tasks::VerificationTasks,
        },
        core::Mailbox,
        standard::{
            validation::{
                fetch_parent, precheck_epoch_and_reproposal, verify_with_parent, Decision,
            },
            Standard,
        },
        Update,
    },
    simplex::{types::Context, Plan},
    types::{Epoch, Epocher, Round},
    Application, Automaton, CertifiableAutomaton, CertifiableBlock, Epochable, Relay, Reporter,
    VerifyingApplication,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_runtime::{
    telemetry::metrics::{
        histogram::{Buckets, Timed},
        MetricsExt as _,
    },
    Clock, Metrics, Shared, Spawner,
};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use rand::Rng;
use tracing::debug;

/// An [`Application`] adapter that handles epoch transitions and validates block ancestry.
///
/// This wrapper intercepts consensus operations to enforce epoch boundaries and validate
/// block ancestry. It prevents blocks from being produced outside their valid epoch,
/// handles the special case of re-proposing boundary blocks at epoch boundaries,
/// and ensures all blocks have valid parent linkage and contiguous heights.
///
/// # Ancestry Validation
///
/// Applications wrapped by [`Deferred`] can rely on the following ancestry checks being
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
pub struct Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E>,
    B: CertifiableBlock,
    ES: Epocher,
{
    context: Shared<E>,
    application: A,
    marshal: Mailbox<S, Standard<B>>,
    epocher: ES,
    verification_tasks: VerificationTasks<<B as Digestible>::Digest>,

    build_duration: Timed,
}

impl<E, S, A, B, ES> Clone for Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E>,
    B: CertifiableBlock,
    ES: Epocher,
{
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            application: self.application.clone(),
            marshal: self.marshal.clone(),
            epocher: self.epocher.clone(),
            verification_tasks: self.verification_tasks.clone(),
            build_duration: self.build_duration.clone(),
        }
    }
}

impl<E, S, A, B, ES> Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = S,
        Context = Context<B::Digest, S::PublicKey>,
    >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    ES: Epocher,
{
    /// Creates a new [`Deferred`] wrapper.
    pub fn new(context: E, application: A, marshal: Mailbox<S, Standard<B>>, epocher: ES) -> Self {
        let build_histogram = context.histogram(
            "build_duration",
            "Histogram of time taken for the application to build a new block, in seconds",
            Buckets::LOCAL,
        );
        let build_duration = Timed::new(build_histogram);

        Self {
            context: Shared::new(context),
            application,
            marshal,
            epocher,
            verification_tasks: VerificationTasks::new(),

            build_duration,
        }
    }
}

impl<E, S, A, B, ES> Automaton for Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = S,
        Context = Context<B::Digest, S::PublicKey>,
    >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
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
    /// contain the proposed block's digest when ready. The built block is persisted via
    /// [`Mailbox::verified`] before the digest is delivered, so consensus can rely on the
    /// block surviving restart.
    async fn propose(
        &mut self,
        consensus_context: Context<Self::Digest, S::PublicKey>,
    ) -> oneshot::Receiver<Self::Digest> {
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let epocher = self.epocher.clone();

        // Metrics
        let build_duration = self.build_duration.clone();

        let (mut tx, rx) = oneshot::channel();
        let context = self
            .context
            .lock()
            .await
            .child("propose")
            .with_attribute("round", consensus_context.round);
        context.spawn(move |runtime_context| async move {
                // On leader recovery, marshal may already hold a verified block
                // for this round (persisted by a pre-crash propose whose
                // notarize vote never reached the journal).
                //
                // Building a fresh block would land on the same prunable archive
                // index and be silently dropped, so the stored block is the only proposal
                // we can broadcast for this round.
                //
                // The recovered block is safe to reuse only if its embedded
                // context matches the context simplex just recovered. Otherwise the
                // cached block was built against a different parent and cannot be
                // broadcast under the current header, so drop the receiver
                // and let the voter nullify the view via timeout.
                if let Some(block) = marshal.get_verified(consensus_context.round).await {
                    let block_context = block.context();
                    if block_context != consensus_context {
                        debug!(
                            round = ?consensus_context.round,
                            ?consensus_context,
                            ?block_context,
                            "skipping proposal: cached verified block context no longer matches"
                        );
                        return;
                    }
                    let digest = block.digest();
                    let success = tx.send_lossy(digest);
                    debug!(
                        round = ?consensus_context.round,
                        ?digest,
                        success,
                        "reused verified block from marshal on leader recovery"
                    );
                    return;
                }

                let (parent_view, parent_digest) = consensus_context.parent;
                let parent_request = fetch_parent(
                    parent_digest,
                    // We are guaranteed that the parent round for any `consensus_context` is
                    // in the same epoch (recall, the boundary block of the previous epoch
                    // is the genesis block of the current epoch).
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
                    if !marshal.verified(consensus_context.round, parent).await {
                        debug!(
                            round = ?consensus_context.round,
                            ?digest,
                            "marshal rejected re-proposed boundary block"
                        );
                        return;
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
                        runtime_context.child("app_propose"),
                        consensus_context.clone(),
                    ),
                    ancestor_stream,
                );

                let build_timer = build_duration.timer(&runtime_context);
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
                build_timer.observe(&runtime_context);

                let digest = built_block.digest();
                if !marshal.proposed(consensus_context.round, built_block).await {
                    debug!(
                        round = ?consensus_context.round,
                        ?digest,
                        "marshal rejected proposed block"
                    );
                    return;
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
        let mut application = self.application.clone();
        let epocher = self.epocher.clone();
        let verification_tasks = self.verification_tasks.clone();
        let round = context.round;
        let (mut task_tx, task_rx) = oneshot::channel();
        verification_tasks.insert(round, digest, task_rx);

        let (mut tx, rx) = oneshot::channel();
        let runtime_context = self
            .context
            .lock()
            .await
            .child("optimistic_verify")
            .with_attribute("round", round);
        runtime_context.spawn(move |runtime_context| async move {
                let block_request = marshal.subscribe_by_digest(Some(context.round), digest).await;
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

                // Shared pre-checks enforce:
                // - Block epoch membership.
                // - Re-proposal detection via `digest == context.parent.1`.
                //
                // Re-proposals return early and skip normal parent/height checks
                // because they were already verified when originally proposed and
                // parent-child checks would fail by construction when parent == block.
                let Some(decision) = precheck_epoch_and_reproposal(
                    &epocher,
                    &mut marshal,
                    &context,
                    digest,
                    block,
                )
                .await
                else {
                    return;
                };
                let block = match decision {
                    Decision::Complete(valid) => {
                        // `certify` expects the task registered before this spawn to resolve.
                        task_tx.send_lossy(valid);
                        // `Complete` means either immediate rejection or successful
                        // re-proposal handling with no further ancestry validation.
                        tx.send_lossy(valid);
                        return;
                    }
                    Decision::Continue(block) => block,
                };

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
                    task_tx.send_lossy(false);
                    tx.send_lossy(false);
                    return;
                }

                // The optimistic result is available now. Keep this task alive to finish the
                // deferred verification so children under `runtime_context` are not aborted.
                tx.send_lossy(true);

                let application_valid = match verify_with_parent(
                    runtime_context
                        .child("deferred_verify")
                        .with_attribute("round", round),
                    context,
                    block,
                    &mut application,
                    &mut marshal,
                    &mut task_tx,
                    Stage::Verified,
                )
                .await
                {
                    Some(valid) => valid,
                    None => return,
                };
                task_tx.send_lossy(application_valid);
        });
        rx
    }
}

impl<E, S, A, B, ES> CertifiableAutomaton for Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = S,
        Context = Context<B::Digest, S::PublicKey>,
    >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    ES: Epocher,
{
    async fn certify(&mut self, round: Round, digest: Self::Digest) -> oneshot::Receiver<bool> {
        // Attempt to retrieve the existing verification task for this (round, payload).
        let task = self.verification_tasks.take(round, digest);
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
        let block_rx = self.marshal.subscribe_by_digest(Some(round), digest).await;
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let epocher = self.epocher.clone();
        let (mut tx, rx) = oneshot::channel();
        let context = self
            .context
            .lock()
            .await
            .child("certify")
            .with_attribute("round", round);
        context.spawn(move |runtime_context| async move {
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
                let is_reproposal = is_inferred_reproposal_at_certify(
                    &epocher,
                    block.height(),
                    embedded_context.round,
                    round,
                );
                if is_reproposal {
                    // Certifier holds a notarization for this block, so route
                    // the write to the notarized cache. `certified` is
                    // idempotent, so crash-recovery double-invocation is safe.
                    if !marshal.certified(round, block).await {
                        debug!(?round, "marshal unable to accept block");
                        return;
                    }
                    tx.send_lossy(true);
                    return;
                }

                let application_valid = match verify_with_parent(
                    runtime_context
                        .child("deferred_verify")
                        .with_attribute("round", round),
                    embedded_context,
                    block,
                    &mut application,
                    &mut marshal,
                    &mut tx,
                    Stage::Certified,
                )
                .await
                {
                    Some(valid) => valid,
                    None => return,
                };
                tx.send_lossy(application_valid);
        });
        rx
    }
}

impl<E, S, A, B, ES> Relay for Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    ES: Epocher,
{
    type Digest = B::Digest;
    type PublicKey = S::PublicKey;
    type Plan = Plan<S::PublicKey>;

    async fn broadcast(&mut self, digest: Self::Digest, plan: Plan<S::PublicKey>) {
        let (round, recipients) = match plan {
            Plan::Propose { round } => (round, Recipients::All),
            Plan::Forward { round, recipients } => (round, recipients),
        };
        self.marshal.forward(round, digest, recipients).await;
    }
}

impl<E, S, A, B, ES> Reporter for Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>
        + Reporter<Activity = Update<B>>,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    ES: Epocher,
{
    type Activity = A::Activity;

    /// Relays a report to the underlying [`Application`] and cleans up old verification tasks.
    async fn report(&mut self, update: Self::Activity) {
        // Clean up verification tasks for rounds <= the finalized round.
        if let Update::Tip(round, _, _) = &update {
            self.verification_tasks.retain_after(round);
        }
        self.application.report(update).await
    }
}

#[cfg(test)]
mod tests {
    use super::Deferred;
    use crate::{
        marshal::mocks::{
            harness::{
                default_leader, make_raw_block, setup_network_with_participants, Ctx,
                StandardHarness, TestHarness, B, BLOCKS_PER_EPOCH, NAMESPACE, NUM_VALIDATORS, S, V,
            },
            verifying::{GatedVerifyingApp, MockVerifyingApp},
        },
        simplex::scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
        types::{Epoch, Epocher, FixedEpocher, Height, Round, View},
        Automaton, CertifiableAutomaton,
    };
    use commonware_broadcast::Broadcaster;
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider},
        sha256::Sha256,
        Digestible, Hasher as _,
    };
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{deterministic, Clock, Runner, Supervisor as _};
    use commonware_utils::{channel::fallible::OneshotExt, NZUsize};
    use std::time::Duration;

    #[test_traced("INFO")]
    fn test_certify_lower_view_after_higher_view() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new(genesis.clone());

            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Create parent block at height 1
            let parent = make_raw_block(genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();
            assert!(
                marshal
                    .verified(Round::new(Epoch::new(0), View::new(1)), parent.clone())
                    .await
            );

            // Block A at view 5 (height 2)
            let round_a = Round::new(Epoch::new(0), View::new(5));
            let context_a = Ctx {
                round: round_a,
                leader: me.clone(),
                parent: (View::new(1), parent_digest),
            };
            let block_a = B::new::<Sha256>(context_a.clone(), parent_digest, Height::new(2), 200);
            let commitment_a = block_a.digest();
            assert!(marshal.verified(round_a, block_a.clone()).await);

            // Block B at view 10 (height 2, different block same height)
            let round_b = Round::new(Epoch::new(0), View::new(10));
            let context_b = Ctx {
                round: round_b,
                leader: me.clone(),
                parent: (View::new(1), parent_digest),
            };
            let block_b = B::new::<Sha256>(context_b.clone(), parent_digest, Height::new(2), 300);
            let commitment_b = block_b.digest();
            assert!(marshal.verified(round_b, block_b.clone()).await);

            context.sleep(Duration::from_millis(10)).await;

            // Step 1: Verify block A at view 5
            let _ = marshaled.verify(context_a, commitment_a).await.await;

            // Step 2: Verify block B at view 10
            let _ = marshaled.verify(context_b, commitment_b).await.await;

            // Step 3: Certify block B at view 10 FIRST
            let certify_b = marshaled.certify(round_b, commitment_b).await;
            assert!(
                certify_b.await.unwrap(),
                "Block B certification should succeed"
            );

            // Step 4: Certify block A at view 5 - should succeed
            let certify_a = marshaled.certify(round_a, commitment_a).await;

            select! {
                result = certify_a => {
                    assert!(result.unwrap(), "Block A certification should succeed");
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("Block A certification timed out");
                },
            }
        })
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_unsupported_epoch() {
        #[derive(Clone)]
        struct LimitedEpocher {
            inner: FixedEpocher,
            max_epoch: u64,
        }

        impl Epocher for LimitedEpocher {
            fn containing(&self, height: Height) -> Option<crate::types::EpochInfo> {
                let bounds = self.inner.containing(height)?;
                if bounds.epoch().get() > self.max_epoch {
                    None
                } else {
                    Some(bounds)
                }
            }

            fn first(&self, epoch: Epoch) -> Option<Height> {
                if epoch.get() > self.max_epoch {
                    None
                } else {
                    self.inner.first(epoch)
                }
            }

            fn last(&self, epoch: Epoch) -> Option<Height> {
                if epoch.get() > self.max_epoch {
                    None
                } else {
                    self.inner.last(epoch)
                }
            }
        }

        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new(genesis.clone());
            let limited_epocher = LimitedEpocher {
                inner: FixedEpocher::new(BLOCKS_PER_EPOCH),
                max_epoch: 0,
            };

            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                limited_epocher,
            );

            // Create a parent block at height 19 (last block in epoch 0, which is supported)
            let parent_ctx = Ctx {
                round: Round::new(Epoch::zero(), View::new(19)),
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()),
            };
            let parent =
                B::new::<Sha256>(parent_ctx.clone(), genesis.digest(), Height::new(19), 1000);
            let parent_digest = parent.digest();
            assert!(
                marshal
                    .clone()
                    .verified(Round::new(Epoch::zero(), View::new(19)), parent.clone())
                    .await
            );

            // Create a block at height 20 (first block in epoch 1, which is NOT supported)
            let unsupported_round = Round::new(Epoch::new(1), View::new(20));
            let unsupported_context = Ctx {
                round: unsupported_round,
                leader: me.clone(),
                parent: (View::new(19), parent_digest),
            };
            let block = B::new::<Sha256>(
                unsupported_context.clone(),
                parent_digest,
                Height::new(20),
                2000,
            );
            let block_commitment = block.digest();
            assert!(
                marshal
                    .clone()
                    .verified(unsupported_round, block.clone())
                    .await
            );

            context.sleep(Duration::from_millis(10)).await;

            // Call verify and wait for the result (verify returns optimistic result,
            // but also spawns deferred verification)
            let verify_result = marshaled
                .verify(unsupported_context, block_commitment)
                .await;
            // Wait for optimistic verify to complete so the verification task is registered
            let optimistic_result = verify_result.await;

            // The optimistic verify should return false because the block is in an unsupported epoch
            assert!(
                !optimistic_result.unwrap(),
                "Optimistic verify should reject block in unsupported epoch"
            );
        })
    }

    /// Test that marshaled rejects blocks when consensus context doesn't match block's embedded context.
    ///
    /// This tests that when verify() is called with a context that doesn't match what's embedded
    /// in the block, the verification should fail. A Byzantine proposer could broadcast a block
    /// with one embedded context but consensus could call verify() with a different context.
    #[test_traced("WARN")]
    fn test_marshaled_rejects_mismatched_context() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new(genesis.clone());

            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Create parent block at height 1 so the commitment is well-formed.
            let parent_ctx = Ctx {
                round: Round::new(Epoch::zero(), View::new(1)),
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()),
            };
            let parent = B::new::<Sha256>(parent_ctx, genesis.digest(), Height::new(1), 100);
            let parent_commitment = parent.digest();
            assert!(
                marshal
                    .clone()
                    .verified(Round::new(Epoch::zero(), View::new(1)), parent.clone())
                    .await
            );

            // Build a block with context A (embedded in the block).
            let round_a = Round::new(Epoch::zero(), View::new(2));
            let context_a = Ctx {
                round: round_a,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let block_a = B::new::<Sha256>(context_a, parent.digest(), Height::new(2), 200);
            let commitment_a = block_a.digest();
            assert!(marshal.verified(round_a, block_a).await);

            context.sleep(Duration::from_millis(10)).await;

            // Verify using a different consensus context B (hash mismatch).
            let round_b = Round::new(Epoch::zero(), View::new(3));
            let context_b = Ctx {
                round: round_b,
                leader: participants[1].clone(),
                parent: (View::new(1), parent_commitment),
            };

            let verify_rx = marshaled.verify(context_b, commitment_a).await;
            select! {
                result = verify_rx => {
                    assert!(
                        !result.unwrap(),
                        "mismatched context hash should be rejected"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("verify should reject mismatched context hash promptly");
                },
            }
        })
    }

    /// Regression: `certify` resolving true drives the finalize vote, so it must imply
    /// the block is durably persisted. In deferred mode `verify()` spawns the
    /// `deferred_verify` background task and `certify()` returns that same receiver; the
    /// persistence ack happens inside `verify_with_parent` after `app.verify` returns.
    ///
    /// The gated app holds `app.verify()` open until the test releases it, so we can
    /// abort the marshal actor deterministically after the optimistic path has run but
    /// before the persistence-ack path runs. With the ack in place `verified()` returns
    /// false once the actor is gone, `verify_with_parent` returns `None`, and the tx is
    /// dropped unresolved; we assert the certify receiver errors.
    #[test_traced("WARN")]
    fn test_deferred_certify_does_not_bypass_failed_verify_persistence() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let buffer = setup.extra;
            let marshal_actor_handle = setup.actor_handle;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let (mock_app, verify_started, release_verify): (GatedVerifyingApp<B, S>, _, _) =
                GatedVerifyingApp::new(genesis.clone());
            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Seed parent and child via the buffer (in-memory only) so
            // `deferred_verify` can fetch them without going through the
            // persisted marshal path.
            let parent = make_raw_block(genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();

            let child_round = Round::new(Epoch::zero(), View::new(2));
            let child_ctx = Ctx {
                round: child_round,
                leader: me,
                parent: (View::new(1), parent_digest),
            };
            let child = B::new::<Sha256>(child_ctx.clone(), parent_digest, Height::new(2), 200);
            let child_digest = child.digest();

            buffer
                .broadcast(commonware_p2p::Recipients::Some(vec![]), parent)
                .await
                .await
                .expect("buffer broadcast for parent should ack");
            buffer
                .broadcast(commonware_p2p::Recipients::Some(vec![]), child)
                .await
                .await
                .expect("buffer broadcast for child should ack");

            // Kick off the optimistic verify, which spawns `deferred_verify`.
            // Its gated `app.verify` blocks until we release it, giving us a
            // deterministic window to abort the marshal actor.
            let _optimistic_rx = marshaled.verify(child_ctx, child_digest).await;
            let certify_rx = marshaled.certify(child_round, child_digest).await;
            verify_started
                .await
                .expect("verify should reach application before marshal abort");
            marshal_actor_handle.abort();
            release_verify.send_lossy(());

            select! {
                result = certify_rx => {
                    assert!(
                        result.is_err(),
                        "certify must not resolve after marshal.verified loses its persistence ack"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should terminate after marshal abort");
                },
            }
        });
    }

    /// Regression: when marshal holds a verified block for a round from a
    /// pre-crash propose, a restarted leader's `propose` must return that
    /// block's digest instead of asking the application to build afresh.
    /// See `standard::inline::tests::test_propose_reuses_verified_block_on_restart`.
    #[test_traced("WARN")]
    fn test_propose_reuses_verified_block_on_restart() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();
            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let round = Round::new(Epoch::zero(), View::new(1));
            let ctx = Ctx {
                round,
                leader: me.clone(),
                parent: (View::zero(), genesis.digest()),
            };
            let block_a = B::new::<Sha256>(ctx.clone(), genesis.digest(), Height::new(1), 100);
            let digest_a = block_a.digest();
            assert!(marshal.verified(round, block_a.clone()).await);

            let block_b = B::new::<Sha256>(ctx.clone(), genesis.digest(), Height::new(1), 200);
            let digest_b = block_b.digest();
            assert_ne!(digest_a, digest_b, "test requires distinct digests");

            let mock_app: MockVerifyingApp<B, S> =
                MockVerifyingApp::new(genesis.clone()).with_propose_result(block_b);
            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let digest_rx = marshaled.propose(ctx).await;
            let digest = digest_rx.await.expect("propose must return a digest");
            assert_eq!(
                digest, digest_a,
                "propose must reuse the block marshal already persisted for this round"
            );
        });
    }

    /// Regression: if a pre-crash leader persisted a verified block for a
    /// round but the simplex `Notarize` never reached the journal, replay
    /// can recover a `consensus_context` whose parent differs from the one
    /// the cached block was built against (e.g. a late certification of an
    /// older view changes the parent selected by `State::find_parent`).
    /// In that case the restarted leader must not broadcast the stale
    /// cached block; it must drop the receiver so the voter nullifies the
    /// view via `MissingProposal`.
    #[test_traced("WARN")]
    fn test_propose_skips_when_verified_block_context_changed() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();
            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);

            // Stash a stale block built against genesis as its parent at round V=2.
            let round = Round::new(Epoch::zero(), View::new(2));
            let stale_ctx = Ctx {
                round,
                leader: me.clone(),
                parent: (View::zero(), genesis.digest()),
            };
            let stale_block = B::new::<Sha256>(stale_ctx, genesis.digest(), Height::new(1), 100);
            assert!(marshal.verified(round, stale_block).await);

            // Simulate a replay where parent selection now points to a
            // different parent view than the cached block was built for.
            let new_parent_digest = Sha256::hash(b"late-certified-parent");
            let new_ctx = Ctx {
                round,
                leader: me.clone(),
                parent: (View::new(1), new_parent_digest),
            };

            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new(genesis.clone());
            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let digest_rx = marshaled.propose(new_ctx).await;
            assert!(
                digest_rx.await.is_err(),
                "propose must drop the receiver when the cached block's context no longer matches"
            );
        });
    }
}
