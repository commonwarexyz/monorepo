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
//! Because verification is completed inline, `certify` must only wait for data
//! availability in marshal. No additional deferred verification state needs to
//! be awaited at certify time.
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
        application::validation::LastBuilt,
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
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use prometheus_client::metrics::histogram::Histogram;
use rand::Rng;
use std::{collections::BTreeSet, sync::Arc};
use tracing::{debug, warn};

/// Tracks `(round, digest)` pairs for which `verify` has already fetched the
/// block, so `certify` can return immediately without re-subscribing to marshal.
type AvailableBlocks<D> = Arc<Mutex<BTreeSet<(Round, D)>>>;

/// Waits for a marshal block subscription while allowing consensus to cancel the work.
async fn await_block_subscription<T, D>(
    tx: &mut oneshot::Sender<bool>,
    block_rx: oneshot::Receiver<T>,
    digest: &D,
    stage: &'static str,
) -> Option<T>
where
    D: std::fmt::Debug + ?Sized,
{
    select! {
        _ = tx.closed() => {
            debug!(
                stage,
                reason = "consensus dropped receiver",
                "skipping block wait"
            );
            None
        },
        result = block_rx => {
            if result.is_err() {
                debug!(
                    stage,
                    ?digest,
                    reason = "failed to fetch block",
                    "skipping block wait"
                );
            }
            result.ok()
        },
    }
}

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
    available_blocks: AvailableBlocks<B::Digest>,

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
            available_blocks: Arc::new(Mutex::new(BTreeSet::new())),
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
    /// Blocks are persisted and broadcast via `marshal.proposed()` before the digest
    /// is returned to consensus.
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
        let available_blocks = self.available_blocks.clone();

        let (mut tx, rx) = oneshot::channel();
        self.context
            .with_label("inline_verify")
            .with_attribute("round", context.round)
            .spawn(move |runtime_context| async move {
                let block_request = marshal
                    .subscribe_by_digest(Some(context.round), digest)
                    .await;
                let Some(block) =
                    await_block_subscription(&mut tx, block_request, &digest, "verification").await
                else {
                    return;
                };

                // Shared pre-checks:
                // - Blocks are invalid if they are not in the expected epoch and are
                //   not a valid boundary re-proposal.
                // - Re-proposals are detected when `digest == context.parent.1`.
                // - Re-proposals skip normal parent/height checks because:
                //   1) the block was already verified when originally proposed
                //   2) parent-child checks would fail by construction when parent == block
                let Some(decision) =
                    precheck_epoch_and_reproposal(&epocher, &mut marshal, &context, digest, block)
                        .await
                else {
                    return;
                };
                let block = match decision {
                    Decision::Complete(valid) => {
                        if valid {
                            available_blocks.lock().insert((context.round, digest));
                        }
                        tx.send_lossy(valid);
                        return;
                    }
                    Decision::Continue(block) => block,
                };

                // Non-reproposal path: fetch expected parent, validate ancestry, then
                // run application verification over the ancestry stream.
                //
                // The helper returns `None` when work should stop early (for example,
                // receiver closed or parent unavailable).
                let round = context.round;
                let application_valid = match verify_with_parent(
                    runtime_context,
                    context,
                    block,
                    &mut application,
                    &mut marshal,
                    &mut tx,
                )
                .await
                {
                    Some(valid) => valid,
                    None => return,
                };
                if application_valid {
                    available_blocks.lock().insert((round, digest));
                }
                tx.send_lossy(application_valid);
            });
        rx
    }
}

/// Inline mode only waits for block availability during certification.
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
    async fn certify(&mut self, round: Round, digest: Self::Digest) -> oneshot::Receiver<bool> {
        // If block was already seen, return immediately.
        if self.available_blocks.lock().contains(&(round, digest)) {
            let (tx, rx) = oneshot::channel();
            tx.send_lossy(true);
            return rx;
        }

        // Otherwise, subscribe to marshal for block availability.
        let block_rx = self.marshal.subscribe_by_digest(Some(round), digest).await;
        let marshal = self.marshal.clone();
        let (mut tx, rx) = oneshot::channel();
        self.context
            .with_label("inline_certify")
            .with_attribute("round", round)
            .spawn(move |_| async move {
                let Some(block) =
                    await_block_subscription(&mut tx, block_rx, &digest, "certification").await
                else {
                    return;
                };

                // `certify` resolving true drives the finalize vote, so mere
                // buffered availability is not sufficient here. Persist the
                // block through marshal before signaling success.
                if marshal.verified(round, block).await {
                    tx.send_lossy(true);
                }
            });

        // We don't need to verify the block here because we could not have
        // reached certification without a notarization (implying at least f+1
        // honest validators have verified the block).
        rx
    }
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
    type PublicKey = S::PublicKey;
    type Plan = Plan<S::PublicKey>;

    async fn broadcast(&mut self, digest: Self::Digest, plan: Plan<S::PublicKey>) -> bool {
        match plan {
            Plan::Propose => {
                let Some((round, block)) = self.last_built.lock().take() else {
                    warn!(?digest, "missing block to broadcast");
                    return false;
                };
                if block.digest() != digest {
                    warn!(
                        round = %round,
                        digest = %block.digest(),
                        height = %block.height(),
                        "skipping requested broadcast of block with mismatched digest"
                    );
                    return false;
                };
                if !self.marshal.proposed(round, block).await {
                    warn!(?round, ?digest, "marshal unable to accept block");
                    return false;
                }
                true
            }
            Plan::Forward { round, peers } => {
                self.marshal.forward(round, digest, peers).await;
                true
            }
        }
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
        if let Update::Tip(tip_round, _, _) = &update {
            self.available_blocks
                .lock()
                .retain(|(round, _)| round > tip_round);
        }
        self.application.report(update).await
    }
}

#[cfg(test)]
mod tests {
    use super::Inline;
    use crate::{
        marshal::mocks::{
            harness::{
                default_leader, make_raw_block, setup_network_with_participants, Ctx,
                StandardHarness, TestHarness, B, BLOCKS_PER_EPOCH, NAMESPACE, NUM_VALIDATORS, S, V,
            },
            verifying::{GatedVerifyingApp, MockVerifyingApp},
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
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
    use commonware_utils::{channel::fallible::OneshotExt, NZUsize};
    use rand::Rng;
    use std::time::Duration;

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

    #[test_traced("INFO")]
    fn test_certify_returns_immediately_after_verify_fetches_block() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle =
                setup_network_with_participants(context.clone(), NZUsize!(1), participants.clone())
                    .await;

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

            // Seed the parent and child blocks in marshal so verify can fetch locally.
            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_ctx = Ctx {
                round: parent_round,
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()),
            };
            let parent = B::new::<Sha256>(parent_ctx, genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();
            assert!(marshal.proposed(parent_round, parent).await);

            let round = Round::new(Epoch::zero(), View::new(2));
            let verify_context = Ctx {
                round,
                leader: me,
                parent: (View::new(1), parent_digest),
            };
            let block =
                B::new::<Sha256>(verify_context.clone(), parent_digest, Height::new(2), 200);
            let digest = block.digest();
            assert!(marshal.proposed(round, block).await);

            // Complete verify first so the block is already available locally.
            let verify_rx = inline.verify(verify_context, digest).await;
            assert!(
                verify_rx.await.unwrap(),
                "verify should complete successfully before certify"
            );

            // Certify should return immediately instead of waiting on marshal.
            let certify_rx = inline.certify(round, digest).await;

            select! {
                result = certify_rx => {
                    assert!(
                        result.unwrap(),
                        "certify should return immediately once verify has fetched the block"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should not hang after local verify completed");
                },
            }
        });
    }

    #[test_traced("INFO")]
    fn test_certify_succeeds_without_verify_task() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle =
                setup_network_with_participants(context.clone(), NZUsize!(1), participants.clone())
                    .await;

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

            // Seed the parent and child blocks in marshal without starting a verify task.
            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_ctx = Ctx {
                round: parent_round,
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()),
            };
            let parent = B::new::<Sha256>(parent_ctx, genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();
            assert!(marshal.proposed(parent_round, parent).await);

            let round = Round::new(Epoch::zero(), View::new(2));
            let verify_context = Ctx {
                round,
                leader: me,
                parent: (View::new(1), parent_digest),
            };
            let block =
                B::new::<Sha256>(verify_context.clone(), parent_digest, Height::new(2), 200);
            let digest = block.digest();
            assert!(marshal.proposed(round, block).await);

            // Certify should still resolve by waiting on marshal block availability directly.
            let certify_rx = inline.certify(round, digest).await;

            select! {
                result = certify_rx => {
                    assert!(
                        result.unwrap(),
                        "certify should resolve once block availability is known"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should not hang when block is already available in marshal");
                },
            }
        });
    }

    #[test_traced("INFO")]
    fn test_certify_reproposal_uses_available_blocks_after_verify() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle =
                setup_network_with_participants(context.clone(), NZUsize!(1), participants.clone())
                    .await;

            let me = participants[0].clone();
            let setup = StandardHarness::setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let marshal_actor_handle = setup.actor_handle;

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
            assert!(marshal.proposed(boundary_round, boundary_block).await);

            let reproposal_round = Round::new(Epoch::zero(), View::new(boundary_height.get() + 1));
            let reproposal_context = Ctx {
                round: reproposal_round,
                leader: me,
                parent: (View::new(boundary_height.get()), boundary_digest),
            };

            let verify_rx = inline.verify(reproposal_context, boundary_digest).await;
            assert!(
                verify_rx.await.unwrap(),
                "verify should accept a valid boundary re-proposal"
            );

            marshal_actor_handle.abort();
            drop(marshal);
            context.sleep(Duration::from_millis(1)).await;

            let certify_rx = inline.certify(reproposal_round, boundary_digest).await;
            select! {
                result = certify_rx => {
                    assert!(
                        result.unwrap(),
                        "certify should use the available_blocks fast path for verified re-proposals"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should not depend on marshal after verify cached a re-proposal");
                },
            }
        });
    }

    /// Regression: in inline mode, `verify` itself returns true after running
    /// app verification. That return value drives the notarize vote, so it
    /// must imply "block is durably persisted" -- otherwise a crash between
    /// vote and persistence leaves the validator having voted for a block it
    /// cannot serve.
    ///
    /// As with the deferred-mode test, the parent and child are seeded via
    /// the buffered broadcast layer (in-memory only), bypassing
    /// `marshal.proposed` which would already persist them.
    #[test_traced("WARN")]
    fn test_inline_verify_persists_block_before_resolving() {
        for seed in 0u64..16 {
            inline_verify_persists_block_before_resolving_at(seed);
        }
    }

    fn inline_verify_persists_block_before_resolving_at(seed: u64) {
        use commonware_broadcast::Broadcaster;
        let runner = deterministic::Runner::new(
            deterministic::Config::new()
                .with_seed(seed)
                .with_timeout(Some(Duration::from_secs(60))),
        );
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle =
                setup_network_with_participants(context.clone(), NZUsize!(1), participants.clone())
                    .await;

            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let buffer = setup.extra;
            let actor_handle = setup.actor_handle;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new(genesis.clone());

            let mut inline = Inline::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Build parent (height 1) and child (height 2). Seed both into
            // the buffered broadcast cache (in-memory only).
            let parent = make_raw_block(genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();

            let child_round = Round::new(Epoch::zero(), View::new(2));
            let child_ctx = Ctx {
                round: child_round,
                leader: me.clone(),
                parent: (View::new(1), parent_digest),
            };
            let child = B::new::<Sha256>(child_ctx.clone(), parent_digest, Height::new(2), 200);
            let child_digest = child.digest();

            buffer
                .broadcast(commonware_p2p::Recipients::Some(vec![]), parent.clone())
                .await
                .await
                .expect("buffer broadcast for parent should ack");
            buffer
                .broadcast(commonware_p2p::Recipients::Some(vec![]), child.clone())
                .await
                .await
                .expect("buffer broadcast for child should ack");

            // Inline verify runs full validation inline and returns true only
            // after `marshal.verified` is enqueued. With the persistence-ack
            // fix, that enqueue blocks until put_sync completes.
            let verify_result = inline
                .verify(child_ctx, child_digest)
                .await
                .await
                .expect("verify result missing");
            assert!(verify_result, "inline verify should pass");

            // CRITICAL: abort the marshal actor synchronously, with no
            // intervening await. If verify returned true but the actor had
            // only enqueued (not processed) the `Verified` message, this
            // abort kills the actor before persistence completes.
            actor_handle.abort();
            drop(inline);
            drop(marshal);
            drop(buffer);

            // Restart from the same partition. The block must be durably
            // persisted - otherwise the validator would have voted notarize
            // for a block it cannot serve from local storage.
            let setup2 = StandardHarness::setup_validator(
                context.with_label("validator_0_restart"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal2 = setup2.mailbox;

            let post_restart = marshal2.get_block(&child_digest).await;
            assert!(
                post_restart.is_some(),
                "verify resolved true ⟹ block must be durably persisted (seed={seed})"
            );
        });
    }

    /// Regression: `certify` resolving true drives the finalize vote in inline
    /// mode, so it must imply the block is durably persisted even when the
    /// certify path subscribed before `verify()` finished.
    #[test_traced("WARN")]
    fn test_inline_certify_persists_block_before_resolving() {
        for seed in 0u64..16 {
            inline_certify_persists_block_before_resolving_at(seed);
        }
    }

    fn inline_certify_persists_block_before_resolving_at(seed: u64) {
        use commonware_broadcast::Broadcaster;
        let runner = deterministic::Runner::new(
            deterministic::Config::new()
                .with_seed(seed)
                .with_timeout(Some(Duration::from_secs(60))),
        );
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle =
                setup_network_with_participants(context.clone(), NZUsize!(1), participants.clone())
                    .await;

            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.with_label("validator_0"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let buffer = setup.extra;
            let actor_handle = setup.actor_handle;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new(genesis.clone());
            let mut inline = Inline::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let parent = make_raw_block(genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();

            let child_round = Round::new(Epoch::zero(), View::new(2));
            let child_ctx = Ctx {
                round: child_round,
                leader: me.clone(),
                parent: (View::new(1), parent_digest),
            };
            let child = B::new::<Sha256>(child_ctx.clone(), parent_digest, Height::new(2), 200);
            let child_digest = child.digest();

            buffer
                .broadcast(commonware_p2p::Recipients::Some(vec![]), parent.clone())
                .await
                .await
                .expect("buffer broadcast for parent should ack");
            buffer
                .broadcast(commonware_p2p::Recipients::Some(vec![]), child.clone())
                .await
                .await
                .expect("buffer broadcast for child should ack");

            let verify_rx = inline.verify(child_ctx, child_digest).await;
            let certify_result = inline
                .certify(child_round, child_digest)
                .await
                .await
                .expect("certify result missing");
            assert!(certify_result, "certify should succeed");

            actor_handle.abort();
            drop(verify_rx);
            drop(inline);
            drop(marshal);
            drop(buffer);

            let setup2 = StandardHarness::setup_validator(
                context.with_label("validator_0_restart"),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal2 = setup2.mailbox;

            let post_restart = marshal2.get_block(&child_digest).await;
            assert!(
                post_restart.is_some(),
                "certify resolved true ⟹ block must be durably persisted (seed={seed})"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_inline_certify_does_not_bypass_failed_verify_persistence() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            use commonware_broadcast::Broadcaster;

            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle =
                setup_network_with_participants(context.clone(), NZUsize!(1), participants.clone())
                    .await;

            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.with_label("validator_0"),
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
            let mut inline = Inline::new(
                context.clone(),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let parent = make_raw_block(genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();

            let child_round = Round::new(Epoch::zero(), View::new(2));
            let child_ctx = Ctx {
                round: child_round,
                leader: me.clone(),
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

            let verify_rx = inline.verify(child_ctx, child_digest).await;
            verify_started
                .await
                .expect("verify should reach application before marshal abort");
            marshal_actor_handle.abort();
            release_verify.send_lossy(());

            select! {
                result = verify_rx => {
                    assert!(
                        result.is_err(),
                        "verify must not resolve after marshal.verified loses its persistence ack"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("verify should terminate after marshal abort");
                },
            }

            let certify_rx = inline.certify(child_round, child_digest).await;
            select! {
                result = certify_rx => {
                    assert!(
                        result.is_err(),
                        "certify must not bypass failed verify persistence via stale availability"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should terminate after marshal abort");
                },
            }

            drop(inline);
            drop(marshal);
            drop(buffer);

            let setup2 = StandardHarness::setup_validator(
                context.with_label("validator_0_restart"),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal2 = setup2.mailbox;

            let post_restart = marshal2.get_block(&child_digest).await;
            assert!(
                post_restart.is_none(),
                "failed marshal.verified ack must not leave a durably recoverable block"
            );
        });
    }
}
