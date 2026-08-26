//! Verification and proposal jobs polled by the actor loop.
//!
//! A job is a chain of stages ([`super::stages`]), each a future over owned
//! inputs that resolves to an [`Outcome`]. Between stages the actor runs
//! [`Processor::step`](super::Processor::step); jobs never touch the pending
//! map, the anchor, or the replay table themselves. [`Handler`] owns the pool
//! the stages run in and answers verdict-only outcomes as soon as they
//! complete.

use super::{PendingBatches, PendingDigest, Processor};
use crate::stateful::{
    Application, Input, Proposed,
    actor::core::{Verification, WeakAncestry},
    db::Anchor,
};
use commonware_consensus::{
    Roundable,
    marshal::{
        ancestry::{BlockProvider, BoxedAncestry},
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
    types::Round,
};
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::metrics::histogram::Timer};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    futures::Pool,
};
use futures::FutureExt as _;
use rand_core::Rng;
use std::{collections::VecDeque, future::Future, sync::Arc};
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
pub(super) struct Carry<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub(super) span: Span,
    pub(super) context: (E, A::Context),
    /// Ancestry cursor, positioned after the parent once `acquire` completes.
    pub(super) ancestry: BoxedAncestry<A::Block>,
    pub(super) caller: CallerOf<A, E>,
    /// The block under verification, set by `acquire`. Proposals have none.
    pub(super) candidate: Option<Arc<A::Block>>,
    /// The block whose state execution forks from, set by `acquire`.
    pub(super) parent: Option<Arc<A::Block>>,
    /// The anchor the last lookup ran against.
    pub(super) anchor: Anchor<PendingDigest<A, E>>,
    /// Blocks still to replay before the parent's state exists, oldest first.
    pub(super) path: VecDeque<Arc<A::Block>>,
    /// Started when the job is scheduled, observed on a true verdict or a built block.
    pub(super) timer: Timer,
    /// Started when a rebuild begins, observed when its path is exhausted.
    pub(super) rebuild: Option<Timer>,
}

impl<E, A> Carry<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub(super) const fn candidate(&self) -> &Arc<A::Block> {
        self.candidate
            .as_ref()
            .expect("acquire sets the candidate of a verification")
    }

    pub(super) const fn parent(&self) -> &Arc<A::Block> {
        self.parent.as_ref().expect("acquire sets the parent")
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
    fn deliver(self, block: Option<A::Block>) {
        let Caller::Propose { response, .. } = self.caller else {
            unreachable!("verifications are answered with a verdict")
        };
        if block.is_some() {
            self.timer.observe(&self.context.0);
        }
        response.send_lossy(block);
    }
}

/// Why a stage ended without its result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    /// The ancestry or the replayed state is provably invalid.
    Invalid,
    /// A finalization invalidated the batch mid-execution.
    Stale,
    /// The caller dropped its request.
    Cancelled,
}

/// Why an execution stage ended without the application's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Interrupted {
    /// A finalization invalidated the batch mid-execution.
    Stale,
    /// The caller dropped its request.
    Cancelled,
}

/// How `candidate` ended.
pub(super) enum Fetched {
    /// The carry holds the candidate.
    Ready,
    /// The caller dropped its request.
    Cancelled,
}

/// How `parent` ended.
pub(super) enum Acquired {
    /// The carry holds the parent.
    Ready,
    /// The ancestry stream ended before the parent, which declines a proposal.
    Declined,
    /// The caller dropped its request.
    Cancelled,
}

/// The result a replay owner broadcasts to the jobs waiting on it.
pub(super) type ReplayResult = Result<(), Failure>;

/// What a stage resolved to.
pub(super) enum Outcome<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// `candidate` fetched the block under verification into the carry.
    Candidate(Fetched),
    /// `parent` fetched the block to fork from into the carry.
    Parent(Acquired),
    /// `classify` compared the candidate with the canonical block at its
    /// height. `None` is cancellation.
    Classified(Option<bool>),
    /// `walk` found the blocks between known state and the parent, oldest first.
    Walked(Result<Vec<Arc<A::Block>>, Failure>),
    /// `replay` executed the first block of the path.
    Replayed(Result<PendingBatches<A, E>, Failure>),
    /// `verify` executed the candidate. `Ok(None)` is a rejection.
    Verified(Result<Option<PendingBatches<A, E>>, Interrupted>),
    /// `propose` built a block. `Ok(None)` is a decline.
    Proposed(Result<Option<Proposed<A, E>>, Interrupted>),
    /// `wait` heard from the replay it waited on. `None` is the waiter's own
    /// cancellation.
    Woken(Option<ReplayResult>),
}

/// Verified state to retain once the actor can step.
pub(super) struct Insert<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub(super) digest: PendingDigest<A, E>,
    pub(super) parent: PendingDigest<A, E>,
    pub(super) round: Round,
    pub(super) merkleized: PendingBatches<A, E>,
}

/// Owns the job futures the actor loop polls alongside its own work.
pub(in crate::stateful::actor) struct Handler<E, A, S, V>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: MarshalVariant,
{
    marshal: MarshalMailbox<S, V>,
    jobs: Pool<(Carry<E, A>, Outcome<E, A>)>,
    /// Verified state whose verdict was already answered, awaiting retention.
    inserts: Vec<Insert<E, A>>,
    /// Completed stages awaiting a step.
    steps: Vec<(Carry<E, A>, Outcome<E, A>)>,
    /// Whether a proposal job is live.
    proposing: bool,
}

impl<E, A, S, V> Handler<E, A, S, V>
where
    E: Rng + Spawner + Metrics + Clock + 'static,
    A: Application<E>,
    S: Scheme + 'static,
    V: MarshalVariant<ApplicationBlock = A::Block> + 'static,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    pub(in crate::stateful::actor) fn new(marshal: MarshalMailbox<S, V>) -> Self {
        Self {
            marshal,
            jobs: Pool::default(),
            inserts: Vec::new(),
            steps: Vec::new(),
            proposing: false,
        }
    }

    pub(super) fn marshal(&self) -> MarshalMailbox<S, V> {
        self.marshal.clone()
    }

    /// Run a stage in the pool.
    pub(super) fn push(
        &mut self,
        job: impl Future<Output = (Carry<E, A>, Outcome<E, A>)> + Send + 'static,
    ) {
        self.jobs.push(job);
    }

    /// Whether a proposal job is live.
    pub(in crate::stateful::actor) const fn proposing(&self) -> bool {
        self.proposing
    }

    pub(super) fn start_proposal(&mut self) {
        assert!(!self.proposing, "the actor runs one proposal at a time");
        self.proposing = true;
    }

    /// Answer a proposal and retire its job.
    pub(super) fn deliver(&mut self, carry: Carry<E, A>, block: Option<A::Block>) {
        self.proposing = false;
        carry.deliver(block);
    }

    /// Retire a job whose caller dropped its request.
    pub(super) fn release(&mut self, carry: Carry<E, A>) {
        if carry.is_proposal() {
            self.proposing = false;
        }
    }

    /// Answers verdict-only outcomes right away and queues the rest for a step.
    fn admit(&mut self, (carry, outcome): (Carry<E, A>, Outcome<E, A>)) {
        match outcome {
            Outcome::Classified(Some(valid)) => carry.answer(valid),
            Outcome::Verified(Ok(None)) => carry.answer(false),
            // Caching is retention, not part of the verdict. The execution
            // matched the block's commitments on its own branch.
            Outcome::Verified(Ok(Some(merkleized))) => {
                let insert = Insert {
                    digest: carry.candidate().digest(),
                    parent: carry.parent().digest(),
                    round: carry.context.1.round(),
                    merkleized,
                };
                carry.answer(true);
                self.inserts.push(insert);
            }
            outcome => self.steps.push((carry, outcome)),
        }
    }

    /// Admits every job that has already finished, without waiting.
    pub(in crate::stateful::actor) fn complete_ready(&mut self) {
        while let Some(completed) = self.jobs.next_completed().now_or_never() {
            self.admit(completed);
        }
    }

    pub(in crate::stateful::actor) async fn next_completed(&mut self) {
        let completed = self.jobs.next_completed().await;
        self.admit(completed);
    }

    /// Runs `operation` while stepping the jobs that finish meanwhile. A step
    /// that needs the databases waits for the caller's next
    /// [`Processor::settle`].
    pub(in crate::stateful::actor) async fn drive<T>(
        &mut self,
        processor: &mut Processor<E, A>,
        operation: impl Future<Output = T>,
    ) -> T {
        futures::pin_mut!(operation);
        loop {
            let output = select! {
                output = &mut operation => Some(output),
                _ = self.next_completed() => None,
            };
            match output {
                Some(output) => break output,
                None => processor.settle(self, None),
            }
        }
    }

    /// Take the verified state whose verdicts were already answered.
    pub(super) fn take_inserts(&mut self) -> Vec<Insert<E, A>> {
        std::mem::take(&mut self.inserts)
    }

    /// Take the completed stages awaiting a step.
    pub(super) fn take_steps(&mut self) -> Vec<(Carry<E, A>, Outcome<E, A>)> {
        std::mem::take(&mut self.steps)
    }
}
