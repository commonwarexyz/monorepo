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
        application::validation::LastBuilt,
        core::Mailbox,
        standard::{
            verification::{self, VerificationDecision},
            Standard,
        },
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
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
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
                let parent_request = verification::fetch_parent(
                    parent_digest,
                    // This context is produced by simplex for the active epoch, so
                    // `(consensus_context.epoch(), parent_view)` is a trusted hint
                    // for parent lookup.
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
                let block_request = marshal
                    .subscribe_by_digest(Some(context.round), digest)
                    .await;
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

                // Shared pre-checks:
                // - Blocks are invalid if they are not in the expected epoch and are
                //   not a valid boundary re-proposal.
                // - Re-proposals are detected when `digest == context.parent.1`.
                // - Re-proposals skip normal parent/height checks because:
                //   1) the block was already verified when originally proposed
                //   2) parent-child checks would fail by construction when parent == block
                let block = match verification::precheck_epoch_and_reproposal(
                    &epocher,
                    &mut marshal,
                    &context,
                    digest,
                    block,
                )
                .await
                {
                    VerificationDecision::Complete(valid) => {
                        // `Complete` means either an immediate reject or a valid
                        // re-proposal accepted without further ancestry checks.
                        tx.send_lossy(valid);
                        return;
                    }
                    VerificationDecision::Continue(block) => block,
                };

                // Non-reproposal path: fetch expected parent, validate ancestry, then
                // run application verification over the ancestry stream.
                // The helper returns `None` when work should stop early (for example,
                // receiver closed or parent unavailable).
                let application_valid = match verification::verify_with_parent(
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

#[cfg(test)]
mod tests {
    use super::Inline;
    use crate::{
        simplex::types::Context, Automaton, Block, CertifiableAutomaton, Relay,
        VerifyingApplication,
    };
    use commonware_cryptography::certificate::Scheme;
    use commonware_runtime::{Clock, Metrics, Spawner};
    use rand::Rng;

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
