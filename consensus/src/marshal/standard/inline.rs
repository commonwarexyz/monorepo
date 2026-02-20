//! Wrapper for standard marshal with inline verification.
//!
//! # Overview
//!
//! [`Inline`] adapts any [`VerifyingApplication`] to the marshal/consensus interfaces
//! while keeping block validation in the [`Automaton::verify`] path. Unlike
//! [`super::Deferred`], it does not defer application verification to certification.
//! Instead, it only reports `true` from `verify` after parent/height checks and
//! application verification complete.
//!
//! # Epoch Boundaries
//!
//! As with [`super::Deferred`], when the parent is the last block of the epoch,
//! [`Inline`] re-proposes that boundary block instead of building a new block.
//! This prevents proposing blocks that would be excluded by epoch transition.
//!
//! # Verification Model
//!
//! Inline mode intentionally avoids relying on embedded block context. This allows
//! usage with block types that implement [`crate::Block`] but not
//! [`crate::CertifiableBlock`].
//!
//! Because verification is completed inline, the default
//! [`CertifiableAutomaton::certify`] behavior (always `true`) is sufficient: no
//! additional deferred verification state must be awaited at certify time.
//!
//! # Usage
//!
//! ```rust,ignore
//! let application = Inline::new(
//!     context,
//!     my_application,
//!     marshal_mailbox,
//!     epocher,
//! );
//! ```
//!
//! # When to Use
//!
//! Prefer this wrapper when:
//! - Your application block type is not certifiable.
//! - You prefer simpler verification semantics over deferred verification latency hiding.
//! - You are willing to perform full application verification before casting a notarize vote.

use crate::{
    marshal::{
        ancestry::AncestorStream,
        application::validation::{
            is_block_in_expected_epoch, is_valid_reproposal_at_verify,
            validate_standard_block_for_verification, LastBuilt,
        },
        core::Mailbox,
        standard::Standard,
        Update,
    },
    simplex::types::Context,
    types::{Epoch, Epocher, Round},
    Application, Automaton, Block, CertifiableAutomaton, Epochable, Relay, Reporter,
    VerifyingApplication,
};
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select;
use commonware_runtime::{
    telemetry::metrics::histogram::{Buckets, Timed},
    Clock, Metrics, Spawner,
};
use commonware_utils::{
    channel::{
        fallible::OneshotExt,
        oneshot::{self, error::RecvError},
    },
    sync::Mutex,
};
use futures::future::{ready, Either, Ready};
use prometheus_client::metrics::histogram::Histogram;
use rand::Rng;
use std::sync::Arc;
use tracing::{debug, warn};

/// Standard marshal wrapper that verifies blocks inline in `verify`.
///
/// # Ancestry Validation
///
/// [`Inline`] always validates immediate ancestry before invoking application
/// verification:
/// - Parent digest matches consensus context's expected parent
/// - Child height is exactly parent height plus one
///
/// This is sufficient because the parent must have already been accepted by consensus.
///
/// # Certifiability
///
/// This wrapper requires only [`crate::Block`] for `B`, not
/// [`crate::CertifiableBlock`]. It is designed for applications that cannot
/// recover consensus context directly from block payloads.
#[derive(Clone)]
pub struct Inline<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E>,
    B: Block + Clone,
    ES: Epocher,
{
    context: E,
    application: A,
    marshal: Mailbox<S, Standard<B>>,
    epocher: ES,
    last_built: LastBuilt<B>,

    build_duration: Timed<E>,
}

impl<E, S, A, B, ES> Inline<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = S,
        Context = Context<B::Digest, S::PublicKey>,
    >,
    B: Block + Clone,
    ES: Epocher,
{
    /// Creates a new inline-verification wrapper.
    ///
    /// Registers a `build_duration` histogram for proposal latency and initializes
    /// the shared "last built block" cache used by [`Relay::broadcast`].
    pub fn new(context: E, application: A, marshal: Mailbox<S, Standard<B>>, epocher: ES) -> Self {
        let build_histogram = Histogram::new(Buckets::LOCAL);
        context.register(
            "build_duration",
            "Histogram of time taken for the application to build a new block, in seconds",
            build_histogram.clone(),
        );
        let build_duration = Timed::new(build_histogram, Arc::new(context.clone()));

        Self {
            context,
            application,
            marshal,
            epocher,
            last_built: Arc::new(Mutex::new(None)),
            build_duration,
        }
    }
}

impl<E, S, A, B, ES> Automaton for Inline<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = S,
        Context = Context<B::Digest, S::PublicKey>,
    >,
    B: Block + Clone,
    ES: Epocher,
{
    type Digest = B::Digest;
    type Context = Context<Self::Digest, S::PublicKey>;

    /// Returns the genesis digest for `epoch`.
    ///
    /// For epoch zero, returns the application genesis digest. For later epochs,
    /// uses the previous epoch's terminal block from marshal storage.
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
            unreachable!("missing starting epoch block at height {}", last_height);
        };
        block.digest()
    }

    /// Proposes a new block or re-proposes an epoch boundary block.
    ///
    /// Proposal runs in a spawned task and returns a receiver for the resulting digest.
    /// Built/re-proposed blocks are cached in `last_built` so relay can broadcast
    /// exactly what was proposed.
    async fn propose(
        &mut self,
        consensus_context: Context<Self::Digest, S::PublicKey>,
    ) -> oneshot::Receiver<Self::Digest> {
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let last_built = self.last_built.clone();
        let epocher = self.epocher.clone();
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

                // At epoch boundary, re-propose the parent block.
                let last_in_epoch = epocher
                    .last(consensus_context.epoch())
                    .expect("current epoch should exist");
                if parent.height() == last_in_epoch {
                    let digest = parent.digest();
                    {
                        let mut lock = last_built.lock();
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

                let mut build_timer = build_duration.timer();
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
                build_timer.observe();

                let digest = built_block.digest();
                {
                    let mut lock = last_built.lock();
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

    /// Performs complete verification inline.
    ///
    /// This method:
    /// 1. Fetches the block by digest
    /// 2. Enforces epoch/re-proposal rules
    /// 3. Fetches and validates the parent relationship
    /// 4. Runs application verification over ancestry
    ///
    /// It reports `true` only after all verification steps finish. Successful
    /// verification marks the block as verified in marshal immediately.
    async fn verify(
        &mut self,
        context: Context<Self::Digest, S::PublicKey>,
        digest: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let mut marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let epocher = self.epocher.clone();

        let (mut tx, rx) = oneshot::channel();
        self.context
            .with_label("inline_verify")
            .with_attribute("round", context.round)
            .spawn(move |runtime_context| async move {
                let round = context.round;
                let block_request = marshal.subscribe_by_digest(Some(round), digest).await;
                let block = select! {
                    _ = tx.closed() => {
                        debug!(reason = "consensus dropped receiver", "skipping verification");
                        return;
                    },
                    result = block_request => match result {
                        Ok(block) => block,
                        Err(_) => {
                            debug!(
                                ?digest,
                                reason = "failed to fetch block for verification",
                                "skipping verification"
                            );
                            return;
                        }
                    },
                };

                // Block heights must map to the expected epoch.
                if !is_block_in_expected_epoch(&epocher, block.height(), context.epoch()) {
                    debug!(height = %block.height(), "block height not in expected epoch");
                    tx.send_lossy(false);
                    return;
                }

                // Re-proposals are signaled by `digest == context.parent.1`.
                // They skip normal parent/height checks because parent == block.
                if digest == context.parent.1 {
                    if !is_valid_reproposal_at_verify(&epocher, block.height(), context.epoch()) {
                        debug!(height = %block.height(), "re-proposal is not at epoch boundary");
                        tx.send_lossy(false);
                        return;
                    }
                    marshal.verified(round, block).await;
                    tx.send_lossy(true);
                    return;
                }

                // Non-reproposal path: fetch the expected parent and validate ancestry.
                let (parent_view, parent_digest) = context.parent;
                let parent_request = fetch_parent(
                    parent_digest,
                    Some(Round::new(context.epoch(), parent_view)),
                    &mut application,
                    &mut marshal,
                )
                .await;
                let parent = select! {
                    _ = tx.closed() => {
                        debug!(reason = "consensus dropped receiver", "skipping verification");
                        return;
                    },
                    result = parent_request => match result {
                        Ok(parent) => parent,
                        Err(_) => {
                            debug!(
                                ?parent_digest,
                                reason = "failed to fetch parent block",
                                "skipping verification"
                            );
                            return;
                        }
                    },
                };

                if let Err(err) =
                    validate_standard_block_for_verification(&block, &parent, parent_digest)
                {
                    debug!(
                        ?err,
                        expected_parent = %parent.digest(),
                        block_parent = %block.parent(),
                        parent_height = %parent.height(),
                        block_height = %block.height(),
                        "block failed standard invariant validation"
                    );
                    tx.send_lossy(false);
                    return;
                }

                let ancestry_stream = AncestorStream::new(marshal.clone(), [block.clone(), parent]);
                let application_valid = application
                    .verify(
                        (runtime_context.with_label("app_verify"), context),
                        ancestry_stream,
                    )
                    .await;
                if application_valid {
                    marshal.verified(round, block).await;
                }
                tx.send_lossy(application_valid);
            });
        rx
    }
}

/// Inline mode relies on the default certification behavior.
///
/// Verification is completed during [`Automaton::verify`], so certify does not
/// need additional wrapper-managed checks.
impl<E, S, A, B, ES> CertifiableAutomaton for Inline<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: VerifyingApplication<
        E,
        Block = B,
        SigningScheme = S,
        Context = Context<B::Digest, S::PublicKey>,
    >,
    B: Block + Clone,
    ES: Epocher,
{
}

impl<E, S, A, B, ES> Relay for Inline<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>,
    B: Block + Clone,
    ES: Epocher,
{
    type Digest = B::Digest;

    /// Broadcasts the last proposed block, if it matches the requested digest.
    async fn broadcast(&mut self, digest: Self::Digest) {
        let Some((round, block)) = self.last_built.lock().take() else {
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
        self.marshal.proposed(round, block).await;
    }
}

impl<E, S, A, B, ES> Reporter for Inline<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>
        + Reporter<Activity = Update<B>>,
    B: Block + Clone,
    ES: Epocher,
{
    type Activity = A::Activity;

    /// Forwards consensus activity to the wrapped application reporter.
    async fn report(&mut self, update: Self::Activity) {
        self.application.report(update).await
    }
}

/// Fetches the parent block given its digest and optional round hint.
///
/// If the digest matches genesis, returns genesis directly. Otherwise, subscribes
/// to marshal for parent availability.
///
/// `parent_round` is only a resolver hint. Callers should supply it when the
/// source context is trusted.
#[inline]
async fn fetch_parent<E, S, A, B>(
    parent_digest: B::Digest,
    parent_round: Option<Round>,
    application: &mut A,
    marshal: &mut Mailbox<S, Standard<B>>,
) -> Either<Ready<Result<B, RecvError>>, oneshot::Receiver<B>>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>,
    B: Block + Clone,
{
    let genesis = application.genesis().await;
    if parent_digest == genesis.digest() {
        Either::Left(ready(Ok(genesis)))
    } else {
        Either::Right(
            marshal
                .subscribe_by_digest(parent_round, parent_digest)
                .await,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Inline;
    use crate::{
        marshal::mocks::{
            harness::{
                default_leader, make_raw_block, setup_network, Ctx, StandardHarness, TestHarness,
                B, BLOCKS_PER_EPOCH, NAMESPACE, NUM_VALIDATORS, S, V,
            },
            verifying::MockVerifyingApp,
        },
        simplex::{scheme::bls12381_threshold::vrf as bls12381_threshold_vrf, types::Context},
        types::{Epoch, FixedEpocher, Height, Round, View},
        Automaton, Block, CertifiableAutomaton, Relay, VerifyingApplication,
    };
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider, Scheme},
        sha256::Sha256,
        Digestible, Hasher as _,
    };
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
    use rand::Rng;
    use std::time::Duration;

    #[test_traced("WARN")]
    fn test_inline_propose_paths() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new(genesis.clone());
            let mut inline = Inline::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Non-boundary propose should drop the response because mock app cannot build.
            let non_boundary_context = Ctx {
                round: Round::new(Epoch::zero(), View::new(1)),
                leader: me.clone(),
                parent: (View::zero(), genesis.digest()),
            };
            let proposal_rx = inline.propose(non_boundary_context).await;
            assert!(
                proposal_rx.await.is_err(),
                "proposal should be dropped when application returns no block"
            );

            // Boundary propose should re-propose the parent block even if the app can't build.
            let boundary_height = Height::new(BLOCKS_PER_EPOCH.get() - 1);
            let boundary_round = Round::new(Epoch::zero(), View::new(boundary_height.get()));
            let boundary_block = B::new::<Sha256>(
                Ctx {
                    round: boundary_round,
                    leader: default_leader(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                boundary_height,
                1900,
            );
            let boundary_digest = boundary_block.digest();
            marshal
                .clone()
                .proposed(boundary_round, boundary_block.clone())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            let reproposal_context = Ctx {
                round: Round::new(Epoch::zero(), View::new(boundary_height.get() + 1)),
                leader: me,
                parent: (View::new(boundary_height.get()), boundary_digest),
            };
            let reproposal_rx = inline.propose(reproposal_context).await;
            assert_eq!(
                reproposal_rx.await.expect("reproposal result missing"),
                boundary_digest,
                "epoch boundary proposal should re-propose parent digest"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_inline_verify_reproposal_validation() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new(genesis.clone());
            let mut inline = Inline::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let boundary_height = Height::new(BLOCKS_PER_EPOCH.get() - 1);
            let boundary_round = Round::new(Epoch::zero(), View::new(boundary_height.get()));
            let boundary_block = B::new::<Sha256>(
                Ctx {
                    round: boundary_round,
                    leader: default_leader(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                boundary_height,
                1900,
            );
            let boundary_digest = boundary_block.digest();
            marshal
                .clone()
                .proposed(boundary_round, boundary_block.clone())
                .await;

            context.sleep(Duration::from_millis(10)).await;

            // Valid re-proposal: boundary block in same epoch.
            let valid_reproposal_context = Ctx {
                round: Round::new(Epoch::zero(), View::new(boundary_height.get() + 1)),
                leader: me.clone(),
                parent: (View::new(boundary_height.get()), boundary_digest),
            };
            assert!(
                inline
                    .verify(valid_reproposal_context, boundary_digest)
                    .await
                    .await
                    .expect("verify result missing"),
                "boundary re-proposal should be accepted"
            );

            // Invalid re-proposal: non-boundary block.
            let non_boundary_height = Height::new(10);
            let non_boundary_round =
                Round::new(Epoch::zero(), View::new(non_boundary_height.get()));
            let non_boundary_block = B::new::<Sha256>(
                Ctx {
                    round: non_boundary_round,
                    leader: default_leader(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                non_boundary_height,
                1000,
            );
            let non_boundary_digest = non_boundary_block.digest();
            marshal
                .clone()
                .proposed(non_boundary_round, non_boundary_block)
                .await;

            context.sleep(Duration::from_millis(10)).await;

            let invalid_reproposal_context = Ctx {
                round: Round::new(Epoch::zero(), View::new(15)),
                leader: me.clone(),
                parent: (View::new(non_boundary_height.get()), non_boundary_digest),
            };
            assert!(
                !inline
                    .verify(invalid_reproposal_context, non_boundary_digest)
                    .await
                    .await
                    .expect("verify result missing"),
                "non-boundary re-proposal should be rejected"
            );

            // Invalid re-proposal: cross-epoch context.
            let cross_epoch_context = Ctx {
                round: Round::new(Epoch::new(1), View::new(boundary_height.get() + 1)),
                leader: me,
                parent: (View::new(boundary_height.get()), boundary_digest),
            };
            assert!(
                !inline
                    .verify(cross_epoch_context, boundary_digest)
                    .await
                    .await
                    .expect("verify result missing"),
                "cross-epoch re-proposal should be rejected"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_inline_verify_rejects_invalid_ancestry() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new(genesis.clone());
            let mut inline = Inline::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Malformed block: parent is genesis but height skips from 0 to 2.
            let malformed_round = Round::new(Epoch::zero(), View::new(2));
            let malformed_context = Ctx {
                round: malformed_round,
                leader: me,
                parent: (View::zero(), genesis.digest()),
            };
            let malformed_block = B::new::<Sha256>(
                malformed_context.clone(),
                genesis.digest(),
                Height::new(2),
                200,
            );
            let malformed_digest = malformed_block.digest();
            marshal
                .clone()
                .proposed(malformed_round, malformed_block)
                .await;

            context.sleep(Duration::from_millis(10)).await;

            assert!(
                !inline
                    .verify(malformed_context, malformed_digest)
                    .await
                    .await
                    .expect("verify result missing"),
                "verify should reject non-contiguous ancestry"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_inline_verify_propagates_application_failure() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut oracle = setup_network(context.clone(), None);
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> =
                MockVerifyingApp::with_verify_result(genesis.clone(), false);
            let mut inline = Inline::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Structurally valid child of genesis; app-level verify decides false.
            let round = Round::new(Epoch::zero(), View::new(1));
            let verify_context = Ctx {
                round,
                leader: me,
                parent: (View::zero(), genesis.digest()),
            };
            let block = B::new::<Sha256>(
                verify_context.clone(),
                genesis.digest(),
                Height::new(1),
                100,
            );
            let digest = block.digest();
            marshal.clone().proposed(round, block).await;

            context.sleep(Duration::from_millis(10)).await;

            assert!(
                !inline
                    .verify(verify_context, digest)
                    .await
                    .await
                    .expect("verify result missing"),
                "verify should return application-level failure"
            );
        });
    }

    // Compile-time assertion only: inline standard wrapper must not require `CertifiableBlock`.
    #[allow(dead_code)]
    fn assert_non_certifiable_block_supported<E, S, A, B, ES>()
    where
        E: Rng + Spawner + Metrics + Clock,
        S: Scheme,
        A: VerifyingApplication<
            E,
            Block = B,
            SigningScheme = S,
            Context = Context<B::Digest, S::PublicKey>,
        >,
        B: Block + Clone,
        ES: crate::types::Epocher,
    {
        fn assert_automaton<T: Automaton>() {}
        fn assert_certifiable<T: CertifiableAutomaton>() {}
        fn assert_relay<T: Relay>() {}

        assert_automaton::<Inline<E, S, A, B, ES>>();
        assert_certifiable::<Inline<E, S, A, B, ES>>();
        assert_relay::<Inline<E, S, A, B, ES>>();
    }
}
