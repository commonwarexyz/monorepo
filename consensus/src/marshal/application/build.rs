//! The prepare and propose tasks shared by the marshal application wrappers.
//!
//! Each task runs the wrapper's proposal checks and then re-proposes the epoch boundary block,
//! declines a parent the marshal cannot build on, or builds on the fetched ancestry through the
//! application. A built block that marshal admits (see
//! [message sizes](crate::marshal#message-sizes)) is sealed into its staged form and staged for
//! the relay broadcast and certification before consensus hears of it. The tasks differ in the
//! application method they call and in their answer: a prepare answers a [`Handoff`] and
//! declines with [`Handoff::Wait`], and a propose answers the digest and declines by closing the
//! receiver.

use crate::{
    Application, Handoff,
    marshal::{
        ancestry::Ancestry,
        application::gates::Gates,
        core::{Mailbox, Variant},
    },
    simplex::types::Context,
};
use commonware_cryptography::{Digest, Digested, PublicKey, certificate::Scheme};
use commonware_macros::select;
use commonware_runtime::{Clock, Spawner, telemetry::metrics::histogram::Timer};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use std::future::Future;
use tracing::{Instrument as _, Span, debug};

/// The outcome of the marshal's proposal checks for a parent.
pub(crate) enum Resolved<D, S, A, M = ()> {
    /// The marshal re-proposes the epoch boundary block, whose digest is the first field.
    Reuse(D, S),
    /// The marshal cannot build on this parent.
    Skip,
    /// The parent is fetched and the application may build on its ancestry. The timer
    /// measures the application's build from this point. The metadata (the coding
    /// configuration, or unit for standard blocks) is passed to the sealing callback with
    /// the built block.
    Build(A, Timer, M),
}

/// Answers a prepare request for `consensus_context` from a task spawned from `context` and
/// instrumented with `span`.
///
/// `checks` resolves the parent. The epoch boundary block is re-proposed as is and answered
/// [`Handoff::Stage`], and a parent the marshal cannot build on answers [`Handoff::Wait`], in
/// both cases without the application. Otherwise `application` builds on the fetched ancestry
/// under the span `build_span` returns. A block that `marshal` does not admit answers
/// [`Handoff::Wait`]. Otherwise `seal` turns the block, with the metadata the checks resolved,
/// into the block's staged form and digest, which is answered under the application's decision.
/// The block is staged before its digest is sent. Dropping the receiver cancels the wait for the
/// parent and the build.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare<E, A, D, P, S, N, Fut, M, Seal, Z, V>(
    context: &E,
    application: &A,
    marshal: &Mailbox<Z, V>,
    gates: Gates<D, S>,
    consensus_context: Context<D, P>,
    checks: Fut,
    span: Span,
    build_span: impl FnOnce() -> Span + Send + 'static,
    seal: impl FnOnce(Digested<A::Block>, M) -> Seal + Send + 'static,
) -> oneshot::Receiver<Handoff<D>>
where
    E: Spawner + Clock,
    A: Application<E, Context = Context<D, P>, Input = ()>,
    D: Digest,
    P: PublicKey,
    S: Clone + Send + Sync + 'static,
    N: Ancestry<A::Block>,
    M: Send + 'static,
    Fut: Future<Output = Resolved<D, S, N, M>> + Send + 'static,
    Seal: Future<Output = (D, S)> + Send + 'static,
    Z: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    let mut application = application.clone();
    let marshal = marshal.clone();
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
            let (ancestry, timer, metadata) = match resolved {
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
                Resolved::Build(ancestry, timer, metadata) => (ancestry, timer, metadata),
            };

            let build = application
                .prepare(
                    (runtime_context.child("app_prepare"), consensus_context),
                    ancestry,
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

            // A block marshal would not admit is declined before it is sealed, so a coded block
            // is never erasure coded for nothing.
            if !marshal.admits(block.inner()).await {
                debug!(reason = "block exceeds size limit", "skipping prepare");
                tx.send_lossy(Handoff::Wait);
                return;
            }

            // The block is staged under the application's decision, and its digest reaches
            // consensus only once the relay broadcast and certification can find the block.
            let (digest, block) = seal(block, metadata).await;
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
/// marshal cannot build on, a build that produces no block, or a block that `marshal` does not
/// admit closes the receiver. Otherwise `application` builds on the fetched ancestry under the
/// span `build_span` returns, and `seal` turns the built block, with the metadata the checks
/// resolved, into the block's staged form and digest. The block is staged before its digest is
/// sent. Dropping the receiver cancels the wait for the parent and the build.
#[allow(clippy::too_many_arguments)]
pub(crate) fn propose<E, A, D, P, S, N, Fut, M, Seal, Z, V>(
    context: &E,
    application: &A,
    marshal: &Mailbox<Z, V>,
    gates: Gates<D, S>,
    consensus_context: Context<D, P>,
    checks: Fut,
    span: Span,
    build_span: impl FnOnce() -> Span + Send + 'static,
    seal: impl FnOnce(Digested<A::Block>, M) -> Seal + Send + 'static,
) -> oneshot::Receiver<D>
where
    E: Spawner + Clock,
    A: Application<E, Context = Context<D, P>, Input = ()>,
    D: Digest,
    P: PublicKey,
    S: Clone + Send + Sync + 'static,
    N: Ancestry<A::Block>,
    M: Send + 'static,
    Fut: Future<Output = Resolved<D, S, N, M>> + Send + 'static,
    Seal: Future<Output = (D, S)> + Send + 'static,
    Z: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    let mut application = application.clone();
    let marshal = marshal.clone();
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
            let (ancestor_stream, build_timer, metadata) = match resolved {
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
                Resolved::Build(ancestor_stream, build_timer, metadata) => {
                    (ancestor_stream, build_timer, metadata)
                }
            };

            let parent_commitment = consensus_context.parent.1;
            let build_request = application
                .propose(
                    (runtime_context.child("app_propose"), consensus_context),
                    ancestor_stream,
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

            // A block marshal would not admit is skipped before it is sealed, so a coded block
            // is never erasure coded for nothing.
            if !marshal.admits(built_block.inner()).await {
                debug!(reason = "block exceeds size limit", "skipping proposal");
                return;
            }

            // The digest reaches consensus only once the relay broadcast and certification can
            // find the staged block.
            let (digest, block) = seal(built_block, metadata).await;
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
