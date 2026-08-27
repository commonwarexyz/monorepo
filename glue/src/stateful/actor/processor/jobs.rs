//! Verification and proposal jobs.
//!
//! A job is a chain of stages ([`super::stages`]), each a future over owned
//! inputs that resolves to what it learned. Between stages the
//! [`Processor`](super::Processor) steps the job synchronously; jobs never
//! touch the pending map, the anchor, or the replay table themselves, and
//! never watch for cancellation, which the processor's dispatch does.

use super::{PendingBatches, PendingDigest};
use crate::stateful::{Application, Input, Proposed, actor::core::Verification, db::Anchor};
use commonware_consensus::marshal::ancestry::BoxedAncestry;
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::metrics::histogram::Timer};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use rand_core::Rng;
use std::{collections::VecDeque, sync::Arc};
use tracing::Span;

/// Who asked for a job and how it is answered.
pub(super) enum Caller<B, I, P> {
    /// A verification, answered with a verdict.
    Verify(Verification),
    /// A proposal, answered with the built block.
    Propose {
        response: oneshot::Sender<Option<B>>,
        /// Taken when the `propose` stage is dispatched.
        input: Option<Input<I, P>>,
    },
}

impl<B, I, P> Caller<B, I, P> {
    /// Resolves once the caller drops its request.
    pub(super) async fn cancelled(&mut self) {
        match self {
            Self::Verify(verification) => verification.wait_for_cancellation().await,
            Self::Propose { response, .. } => response.closed().await,
        }
    }
}

pub(super) type CallerOf<A, E> = Caller<
    <A as Application<E>>::Block,
    <A as Application<E>>::Input,
    <A as Application<E>>::Provider,
>;

/// One request's state between stages.
pub(super) struct Job<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub(super) span: Span,
    pub(super) context: (E, A::Context),
    /// Ancestry cursor, positioned after the parent once it is fetched.
    pub(super) ancestry: BoxedAncestry<A::Block>,
    pub(super) caller: CallerOf<A, E>,
    /// The block under verification. Proposals have none.
    pub(super) candidate: Option<Arc<A::Block>>,
    /// The block whose state execution forks from.
    pub(super) parent: Option<Arc<A::Block>>,
    /// The anchor the current attempt is judged against.
    pub(super) anchor: Anchor<PendingDigest<A, E>>,
    /// Blocks still to replay before the parent's state exists, oldest first.
    /// Non-empty in the pool only while the job replays its front.
    pub(super) path: VecDeque<Arc<A::Block>>,
    /// Started when the job is scheduled, observed on a true verdict or a built block.
    pub(super) timer: Timer,
    /// Started when a rebuild begins, observed when its path is exhausted.
    pub(super) rebuild: Option<Timer>,
}

impl<E, A> Job<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub(super) const fn candidate(&self) -> &Arc<A::Block> {
        self.candidate
            .as_ref()
            .expect("the candidate was fetched before this step")
    }

    pub(super) const fn parent(&self) -> &Arc<A::Block> {
        self.parent
            .as_ref()
            .expect("the parent was fetched before this step")
    }

    pub(super) const fn is_proposal(&self) -> bool {
        matches!(self.caller, Caller::Propose { .. })
    }

    /// Answer a verification. Observes the timer on a true verdict.
    pub(super) fn answer(self, valid: bool) {
        let Caller::Verify(verification) = self.caller else {
            unreachable!("proposals are answered with a block")
        };
        if valid {
            self.timer.observe(&self.context.0);
        }
        verification.respond(valid);
    }

    /// Answer a proposal. Observes the timer when a block was built.
    pub(super) fn deliver(self, block: Option<A::Block>) {
        let Caller::Propose { response, .. } = self.caller else {
            unreachable!("verifications are answered with a verdict")
        };
        if block.is_some() {
            self.timer.observe(&self.context.0);
        }
        response.send_lossy(block);
    }
}

/// A finalization invalidated the batch mid-execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Stale;

/// What a stage resolved to.
pub(super) enum Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The caller dropped its request. Produced by dispatch, never by a stage.
    Cancelled,
    /// The block under verification, or `None` when the ancestry ended first.
    Candidate(Option<Arc<A::Block>>),
    /// The block to fork from, or `None` when the ancestry ended first.
    Parent(Option<Arc<A::Block>>),
    /// The digest of the canonical block at the candidate's height, or `None`
    /// when marshal does not have it.
    Canonical(Option<PendingDigest<A, E>>),
    /// The blocks between known state and the parent, oldest first. `None` is
    /// invalid ancestry.
    Walked(Option<Vec<Arc<A::Block>>>),
    /// `replay` executed the first block of the path.
    Replayed(Result<PendingBatches<A, E>, Stale>),
    /// `verify` executed the candidate. `Ok(None)` is a rejection.
    Verified(Result<Option<PendingBatches<A, E>>, Stale>),
    /// `propose` built a block. `Ok(None)` is a decline.
    Proposed(Result<Option<Proposed<A, E>>, Stale>),
}
