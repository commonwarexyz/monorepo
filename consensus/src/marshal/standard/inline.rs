//! Inline-verification standard marshal wrapper.
//!
//! This wrapper is similar to [`super::Marshaled`], but it performs block verification
//! inline in [`Automaton::verify`] and uses the default always-true certification step.
//! It does not rely on extracting embedded consensus context from blocks and therefore
//! supports applications whose block type is not [`crate::CertifiableBlock`].

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
#[derive(Clone)]
pub struct InlineMarshaled<E, S, A, B, ES>
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

impl<E, S, A, B, ES> InlineMarshaled<E, S, A, B, ES>
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

impl<E, S, A, B, ES> Automaton for InlineMarshaled<E, S, A, B, ES>
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

                if !is_block_in_expected_epoch(&epocher, block.height(), context.epoch()) {
                    debug!(height = %block.height(), "block height not in expected epoch");
                    tx.send_lossy(false);
                    return;
                }

                // Re-proposals are signaled by `digest == context.parent.1`.
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

impl<E, S, A, B, ES> CertifiableAutomaton for InlineMarshaled<E, S, A, B, ES>
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

impl<E, S, A, B, ES> Relay for InlineMarshaled<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>,
    B: Block + Clone,
    ES: Epocher,
{
    type Digest = B::Digest;

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

impl<E, S, A, B, ES> Reporter for InlineMarshaled<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>
        + Reporter<Activity = Update<B>>,
    B: Block + Clone,
    ES: Epocher,
{
    type Activity = A::Activity;

    async fn report(&mut self, update: Self::Activity) {
        self.application.report(update).await
    }
}

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
    use super::InlineMarshaled;
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

        assert_automaton::<InlineMarshaled<E, S, A, B, ES>>();
        assert_certifiable::<InlineMarshaled<E, S, A, B, ES>>();
        assert_relay::<InlineMarshaled<E, S, A, B, ES>>();
    }
}
