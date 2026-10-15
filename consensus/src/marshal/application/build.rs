//! The prepare and propose tasks shared by the marshal application wrappers.
//!
//! Each task runs the wrapper's proposal checks and then re-proposes the epoch boundary block,
//! declines a parent the marshal cannot build on, or builds on the fetched parent through the
//! application. A built block is sealed into its staged form and staged for the relay broadcast
//! and certification before consensus hears of it. The tasks differ in the application method
//! they call and in their answer: a prepare answers a [`Handoff`] and declines with
//! [`Handoff::Wait`], and a propose answers the digest and declines by closing the receiver.

use crate::{
    Application, Block, Handoff,
    marshal::{application::gates::Gates, blocks::Blocks},
    simplex::types::Context,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::metrics::histogram::Timer};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use rand_core::Rng;
use std::{future::Future, sync::Arc};
use tracing::{Instrument as _, Span, debug};

/// The outcome of the marshal's proposal checks for a parent.
pub(crate) enum Resolved<D, S, B: Block, M = ()> {
    /// The marshal re-proposes the epoch boundary block, whose digest is the first field.
    Reuse(D, Arc<S>),
    /// The marshal cannot build on this parent.
    Skip,
    /// The parent is fetched and the application may build on it and the selected branch
    /// ending at it. The timer measures the application's build from this point. The metadata
    /// (the coding configuration, or unit for standard blocks) is passed to the sealing
    /// callback with the built block.
    Build(Arc<B>, Blocks<B>, Timer, M),
}

/// Answers a prepare request for `consensus_context` from a task spawned from `context` and
/// instrumented with `span`.
///
/// `checks` resolves the parent. The epoch boundary block is re-proposed as is and answered
/// [`Handoff::Stage`], and a parent the marshal cannot build on answers [`Handoff::Wait`], in
/// both cases without the application. Otherwise `application` builds on the fetched parent
/// under the span `build_span` returns, and `seal` turns a block it returned, with the metadata
/// the checks resolved, into the block's staged form and digest, which is answered under the
/// application's decision. The block is staged before its digest is sent. Dropping the receiver
/// cancels the wait for the parent and the build.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare<E, A, D, P, S, Fut, M>(
    context: &E,
    application: &A,
    gates: Gates<D, S>,
    consensus_context: Context<D, P>,
    checks: Fut,
    span: Span,
    build_span: impl FnOnce() -> Span + Send + 'static,
    seal: impl FnOnce(A::Block, M) -> (D, Arc<S>) + Send + 'static,
) -> oneshot::Receiver<Handoff<D>>
where
    E: Rng + Clock + Spawner + Metrics,
    A: Application<E, Context = Context<D, P>, Input = ()>,
    D: Digest,
    P: PublicKey,
    S: Send + Sync + 'static,
    M: Send + 'static,
    Fut: Future<Output = Resolved<D, S, A::Block, M>> + Send + 'static,
{
    let mut application = application.clone();
    let (mut tx, rx) = oneshot::channel();
    let round = consensus_context.round;
    let context = context.child("prepare").with_attribute("round", round);
    context.spawn(move |runtime_context| {
        async move {
            // Consensus abandons the request by dropping the receiver, which cancels the wait
            // for the parent and the build.
            let resolved = select! {
                _ = tx.closed() => {
                    debug!(reason = "consensus dropped receiver", "skipping prepare");
                    return;
                },
                resolved = checks => resolved,
            };
            let (parent, blocks, timer, metadata) = match resolved {
                // The boundary block is re-proposed as is and carries no application decision,
                // so the answer withholds the vote until the parent certifies. Staging it under
                // this round lets the relay broadcast and certification find it here.
                Resolved::Reuse(digest, block) => {
                    gates
                        .stage(
                            round,
                            digest,
                            block,
                            |digest| {
                                tx.send_lossy(Handoff::Stage(digest));
                            },
                            "prepared boundary block",
                        )
                        .await;
                    return;
                }
                // Consensus requests an ordinary proposal once the parent certifies.
                Resolved::Skip => {
                    tx.send_lossy(Handoff::Wait);
                    return;
                }
                Resolved::Build(parent, blocks, timer, metadata) => {
                    (parent, blocks, timer, metadata)
                }
            };

            let build = application
                .prepare(
                    (runtime_context.child("app_prepare"), consensus_context),
                    parent,
                    blocks,
                    (),
                )
                .instrument(build_span());
            let prepared = select! {
                _ = tx.closed() => {
                    debug!(reason = "consensus dropped receiver", "skipping prepare");
                    return;
                },
                prepared = build => prepared,
            };
            let (block, decision) = match prepared {
                Handoff::Vote(block) => (block, Handoff::Vote(())),
                Handoff::Stage(block) => (block, Handoff::Stage(())),
                Handoff::Wait => {
                    debug!(reason = "application declined", "skipping prepare");
                    tx.send_lossy(Handoff::Wait);
                    return;
                }
            };

            // Only a build that yields a block is timed.
            timer.observe(&runtime_context);

            // The block is staged under the application's decision, and its digest reaches
            // consensus only once the relay broadcast and certification can find the block.
            let (digest, block) = seal(block, metadata);
            gates
                .stage(
                    round,
                    digest,
                    block,
                    |digest| {
                        tx.send_lossy(decision.map(|()| digest));
                    },
                    "prepared block",
                )
                .await;
        }
        .instrument(span)
    });
    rx
}

/// Answers a propose request for `consensus_context` from a task spawned from `context` and
/// instrumented with `span`.
///
/// `checks` resolves the parent. The epoch boundary block is re-proposed as is. A parent the
/// marshal cannot build on, or a build that produces no block, closes the receiver. Otherwise
/// `application` builds on the fetched parent under the span `build_span` returns, and
/// `seal` turns the built block, with the metadata the checks resolved, into the block's staged
/// form and digest. The block is staged before its digest is sent. Dropping the receiver
/// cancels the wait for the parent and the build.
#[allow(clippy::too_many_arguments)]
pub(crate) fn propose<E, A, D, P, S, Fut, M>(
    context: &E,
    application: &A,
    gates: Gates<D, S>,
    consensus_context: Context<D, P>,
    checks: Fut,
    span: Span,
    build_span: impl FnOnce() -> Span + Send + 'static,
    seal: impl FnOnce(A::Block, M) -> (D, Arc<S>) + Send + 'static,
) -> oneshot::Receiver<D>
where
    E: Rng + Clock + Spawner + Metrics,
    A: Application<E, Context = Context<D, P>, Input = ()>,
    D: Digest,
    P: PublicKey,
    S: Send + Sync + 'static,
    M: Send + 'static,
    Fut: Future<Output = Resolved<D, S, A::Block, M>> + Send + 'static,
{
    let mut application = application.clone();
    let (mut tx, rx) = oneshot::channel();
    let round = consensus_context.round;
    let context = context.child("propose").with_attribute("round", round);
    context.spawn(move |runtime_context| {
        async move {
            // Consensus abandons the request by dropping the receiver, which cancels the wait
            // for the parent and the build.
            let resolved = select! {
                _ = tx.closed() => {
                    debug!(reason = "consensus dropped receiver", "skipping proposal");
                    return;
                },
                resolved = checks => resolved,
            };
            let (parent, blocks, build_timer, metadata) = match resolved {
                // The boundary block is re-proposed as is. Staging it under this round lets the
                // relay broadcast and certification find it here.
                Resolved::Reuse(digest, block) => {
                    gates
                        .stage(
                            round,
                            digest,
                            block,
                            |digest| {
                                tx.send_lossy(digest);
                            },
                            "proposed boundary block",
                        )
                        .await;
                    return;
                }
                // Closing the receiver skips the view, which the voter nullifies by timeout.
                Resolved::Skip => return,
                Resolved::Build(parent, blocks, build_timer, metadata) => {
                    (parent, blocks, build_timer, metadata)
                }
            };

            let parent_commitment = consensus_context.parent.1;
            let build_request = application
                .propose(
                    (runtime_context.child("app_propose"), consensus_context),
                    parent,
                    blocks,
                    (),
                )
                .instrument(build_span());

            let built_block = select! {
                _ = tx.closed() => {
                    debug!(reason = "consensus dropped receiver", "skipping proposal");
                    return;
                },
                result = build_request => match result {
                    Some(block) => block,
                    None => {
                        debug!(
                            ?parent_commitment,
                            reason = "block building failed",
                            "skipping proposal"
                        );
                        return;
                    }
                },
            };

            // Only a build that yields a block is timed.
            build_timer.observe(&runtime_context);

            // The digest reaches consensus only once the relay broadcast and certification can
            // find the staged block.
            let (digest, block) = seal(built_block, metadata);
            gates
                .stage(
                    round,
                    digest,
                    block,
                    |digest| {
                        tx.send_lossy(digest);
                    },
                    "proposed block",
                )
                .await;
        }
        .instrument(span)
    });
    rx
}
