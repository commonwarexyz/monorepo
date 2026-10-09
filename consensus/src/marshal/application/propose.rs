//! The proposal task shared by the marshal application wrappers.

use crate::{
    Application,
    marshal::{
        ancestry::Ancestry,
        application::{
            gates::Gates,
            prepare::{BOUNDARY_BLOCK, Resolved},
        },
    },
    simplex::types::Context,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use rand_core::Rng;
use std::{future::Future, sync::Arc};
use tracing::{Instrument as _, Span, debug};

/// Answers a propose request for `consensus_context` from a task spawned from `context` and
/// instrumented with `span`.
///
/// `checks` resolves the parent. The epoch boundary block is re-proposed as is. A parent the
/// marshal cannot build on, or a build that produces no block, closes the receiver. Otherwise
/// `application` builds on the fetched ancestry under the span `build_span` returns, and
/// `seal` turns the built block, with the metadata the checks resolved, into the block's staged
/// form and identifier. The block is staged before its identifier is sent. Dropping the
/// receiver cancels the wait for the parent and the build.
#[allow(clippy::too_many_arguments)]
pub(crate) fn request<E, A, D, P, S, N, Fut, M>(
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
    N: Ancestry<A::Block>,
    M: Send + 'static,
    Fut: Future<Output = Resolved<D, S, N, M>> + Send + 'static,
{
    let mut application = application.clone();
    let (mut tx, rx) = oneshot::channel();
    let round = consensus_context.round;
    let context = context.child("propose").with_attribute("round", round);
    context.spawn(move |runtime_context| {
        async move {
            let resolved = select! {
                _ = tx.closed() => {
                    debug!(reason = "consensus dropped receiver", "skipping proposal");
                    return;
                },
                resolved = checks => resolved,
            };
            let (ancestor_stream, build_timer, metadata) = match resolved {
                Resolved::Reuse(id, block) => {
                    gates
                        .stage(
                            round,
                            id,
                            block,
                            |id| {
                                tx.send_lossy(id);
                            },
                            BOUNDARY_BLOCK,
                        )
                        .await;
                    return;
                }
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
            build_timer.observe(&runtime_context);

            let (id, block) = seal(built_block, metadata);
            gates
                .stage(
                    round,
                    id,
                    block,
                    |id| {
                        tx.send_lossy(id);
                    },
                    "proposed block",
                )
                .await;
        }
        .instrument(span)
    });
    rx
}
