//! Verification and proposal jobs.
//!
//! A job is a chain of stages ([`super::stages`]), each a future over owned
//! inputs that resolves to an [`Outcome`]. Between stages the
//! [`Processor`](super::Processor) steps the job synchronously; jobs never
//! touch the pending map, the anchor, or the replay table themselves.

use super::{PendingBatches, PendingDigest};
use crate::stateful::{
    Application, Input, Proposed,
    actor::core::{Verification, WeakAncestry},
    db::Anchor,
};
use commonware_consensus::marshal::ancestry::BoxedAncestry;
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::metrics::histogram::Timer};
use commonware_utils::channel::{fallible::OneshotExt, oneshot};
use rand_core::Rng;
use std::{collections::VecDeque, sync::Arc};
use tracing::Span;

/// A verification request handed to a job.
///
/// The request carries a non-owning ancestry handle, so caller cancellation
/// releases the backing blocks even while the request waits in the mailbox.
/// Scheduling upgrades the handle to an independent owning cursor.
pub(in crate::stateful::actor) struct Request<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub(in crate::stateful::actor) span: Span,
    pub(in crate::stateful::actor) context: (E, A::Context),
    pub(in crate::stateful::actor) ancestry: WeakAncestry<A::Block>,
    pub(in crate::stateful::actor) verification: Verification,
}

/// Who asked for a job and how it is answered.
pub(super) enum Caller<B, I, P> {
    /// A verification, answered with a verdict.
    Verify(Verification),
    /// A proposal, answered with the built block.
    Propose {
        response: oneshot::Sender<Option<B>>,
        /// Taken by the `propose` stage.
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
    /// Ancestry cursor, positioned after the parent once `parent` completes.
    pub(super) ancestry: BoxedAncestry<A::Block>,
    pub(super) caller: CallerOf<A, E>,
    /// The block under verification, set by `candidate`. Proposals have none.
    pub(super) candidate: Option<Arc<A::Block>>,
    /// The block whose state execution forks from, set by `parent`.
    pub(super) parent: Option<Arc<A::Block>>,
    /// The anchor the current attempt is judged against.
    pub(super) anchor: Anchor<PendingDigest<A, E>>,
    /// Blocks still to replay before the parent's state exists, oldest first.
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
            .expect("the candidate stage ran before this one")
    }

    pub(super) const fn parent(&self) -> &Arc<A::Block> {
        self.parent
            .as_ref()
            .expect("the parent stage ran before this one")
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

/// Why a replay ended without its result.
///
/// Cancellation is reported here rather than as [`Outcome::Cancelled`] so the
/// owner's step releases the jobs parked on its replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    /// The ancestry or the replayed state is provably invalid.
    Invalid,
    /// A finalization invalidated the batch mid-execution.
    Stale,
    /// The caller dropped its request.
    Cancelled,
}

/// A finalization invalidated the batch mid-execution.
pub(super) struct Stale;

/// What a stage resolved to.
pub(super) enum Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The caller dropped its request.
    Cancelled,
    /// `candidate` fetched the block under verification into the job.
    Candidate,
    /// `parent` fetched the block to fork from into the job.
    Parent,
    /// The ancestry ended before the parent of a proposal.
    Declined,
    /// `canonical` compared the candidate with the canonical block at its height.
    Classified(bool),
    /// `walk` found the blocks between known state and the parent, oldest
    /// first. `None` is invalid ancestry.
    Walked(Option<Vec<Arc<A::Block>>>),
    /// `replay` executed the first block of the path.
    Replayed(Result<PendingBatches<A, E>, Failure>),
    /// `verify` executed the candidate. `Ok(None)` is a rejection.
    Verified(Result<Option<PendingBatches<A, E>>, Stale>),
    /// `propose` built a block. `Ok(None)` is a decline.
    Proposed(Result<Option<Proposed<A, E>>, Stale>),
}
