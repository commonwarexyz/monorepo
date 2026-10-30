//! Concurrent speculative requests for the processing loop.
//!
//! A verification, or a proposal whose parent state may be missing, becomes a [`Work`] that the
//! [`Handler`] polls alongside the actor's other duties. A request first acquires its blocks and
//! the missing path back to known state, then runs one execution step per missing block (see
//! [`Verifier::next`]), and finally answers its caller or, for a proposal, queues a build.
//! Maintenance pauses acquisition and waits only for the execution steps it cannot retain, so
//! unrelated requests keep progressing.

use super::{
    mailbox::{ProposalRequest, Verification, WeakAncestry},
    processing::Action,
};
use crate::stateful::{
    Application,
    actor::{
        BlockDigest,
        processor::{
            Disposition, ExecutionStep, FinalizationBoundary, PrepareBatchesError, Prepared,
            Verifier,
        },
    },
};
use commonware_consensus::marshal::{
    ancestry::BlockProvider,
    core::{Mailbox as MarshalMailbox, Variant},
};
use commonware_macros::select;
use commonware_runtime::{Clock, Supervisor};
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture, stream::FuturesUnordered};
use std::{
    collections::VecDeque,
    future::{Future, pending},
    pin::Pin,
    task::{Context, Poll, ready},
};
use tracing::{Instrument as _, Span, info_span};

/// A verification request that holds its caller's ancestry through a [`WeakAncestry`].
pub(super) struct VerificationRequest<E, A>
where
    A: Application<E>,
{
    pub(super) span: Span,
    pub(super) context: E,
    pub(super) ancestry: WeakAncestry<A::Block>,
    pub(super) verification: Verification,
}

/// A speculative request: a verification, or a proposal that recovers any missing parent state
/// before it builds.
pub(super) enum Request<E, A>
where
    A: Application<E>,
{
    Verify(VerificationRequest<E, A>),
    Recover(ProposalRequest<E, A>),
}

impl<E, A> Request<E, A>
where
    A: Application<E>,
{
    /// Returns whether the caller has dropped its response channel.
    pub(super) fn is_cancelled(&self) -> bool {
        match self {
            Self::Verify(request) => request.verification.is_cancelled(),
            Self::Recover(request) => request.proposal.is_cancelled(),
        }
    }

    /// Resolves once the caller drops its response channel.
    fn poll_cancelled(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match self {
            Self::Verify(request) => request.verification.poll_cancelled(cx),
            Self::Recover(request) => request.proposal.poll_cancelled(cx),
        }
    }

    /// Returns the runtime context the request was submitted with.
    const fn context(&self) -> &E {
        match self {
            Self::Verify(request) => &request.context,
            Self::Recover(request) => &request.context.0,
        }
    }

    /// Opens the span under which the request's blocks are processed.
    fn process_span(&self) -> Span {
        match self {
            Self::Verify(request) => info_span!(parent: &request.span, "stateful.actor.verify"),
            Self::Recover(request) => info_span!(parent: &request.span, "stateful.actor.recover"),
        }
    }

    /// Answers the request negatively: a verification votes `false` and a proposal declines.
    pub(super) fn reject(self) {
        match self {
            Self::Verify(request) => request.verification.respond(false),
            Self::Recover(request) => request.proposal.decline(),
        }
    }
}

/// The outcome of an acquisition or execution phase.
type PhaseResult<B> = Result<Prepared<B>, PrepareBatchesError>;

/// The current phase of a [`Work`].
enum Phase<E, A>
where
    A: Application<E>,
{
    /// Finished an execution step that maintenance parks until [`Handler::resume`].
    Ready { prepared: Prepared<A::Block> },
    /// Acquiring the request's blocks. `future` is `None` while maintenance pauses acquisition.
    Acquiring {
        future: Option<BoxFuture<'static, PhaseResult<A::Block>>>,
    },
    /// Running one execution step.
    Executing {
        step: ExecutionStep<BlockDigest<A, E>>,
        future: BoxFuture<'static, PhaseResult<A::Block>>,
    },
}

/// A request and its current phase. The request outlives each phase's future, so maintenance can
/// drop a paused acquisition and start a new one later.
struct Work<E, A>
where
    A: Application<E>,
{
    request: Option<Request<E, A>>,
    phase: Phase<E, A>,
}

// Polling pins only the boxed phase futures, so the request and phase metadata may move.
impl<E, A: Application<E>> Unpin for Work<E, A> {}

impl<E, A: Application<E>> Work<E, A> {
    /// Returns the execution step this work is running, if any.
    const fn step(&self) -> Option<ExecutionStep<BlockDigest<A, E>>> {
        match self.phase {
            Phase::Acquiring { .. } | Phase::Ready { .. } => None,
            Phase::Executing { step, .. } => Some(step),
        }
    }
}

/// A request whose current phase ended. `result` is `None` if its caller cancelled.
struct Completion<E, A>
where
    A: Application<E>,
{
    request: Request<E, A>,
    step: Option<ExecutionStep<BlockDigest<A, E>>>,
    result: Option<PhaseResult<A::Block>>,
}

impl<E, A: Application<E>> Future for Work<E, A> {
    type Output = Completion<E, A>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let work = self.get_mut();
        let step = work.step();

        // A caller's cancellation ends its work in any phase, including one whose future is
        // paused. The step is reported so a paused maintenance operation stops waiting for it.
        if work
            .request
            .as_mut()
            .expect("pending work must retain its request")
            .poll_cancelled(cx)
            .is_ready()
        {
            return Poll::Ready(Completion {
                request: work.request.take().unwrap(),
                step,
                result: None,
            });
        }

        // Parked work and paused acquisitions wait for `Handler::resume`. Any other phase ends
        // the work with its future's result.
        let result = match &mut work.phase {
            Phase::Ready { .. } | Phase::Acquiring { future: None } => return Poll::Pending,
            Phase::Acquiring {
                future: Some(future),
            }
            | Phase::Executing { future, .. } => ready!(future.as_mut().poll(cx)),
        };
        Poll::Ready(Completion {
            request: work.request.take().unwrap(),
            step,
            result: Some(result),
        })
    }
}

/// Which execution steps may start or continue during the actor's current operation.
enum Admission<D> {
    /// No maintenance is running, so every step is admitted.
    Open,
    /// A block is being finalized, and [`FinalizationBoundary::disposition`] classifies each step.
    Finalizing(FinalizationBoundary<D>),
    /// Pruning is running, and every step parks.
    Pruning,
}

impl<D: Copy + Eq + std::hash::Hash> Admission<D> {
    /// Classifies `step` under the current operation.
    fn disposition(&self, step: &ExecutionStep<D>) -> Disposition {
        match self {
            Self::Open => Disposition::Retain,
            Self::Finalizing(boundary) => boundary.disposition(step),
            Self::Pruning => Disposition::Park,
        }
    }
}

/// Runs speculative requests concurrently. Finished recoveries queue their builds for the actor,
/// and [`Handler::pause`] holds back execution steps that conflict with maintenance.
pub(super) struct Handler<E, A, V>
where
    A: Application<E>,
    V: Variant,
{
    /// Source of blocks for acquisition and for ancestry reads during execution.
    marshal: MarshalMailbox<A::SigningScheme, V>,
    /// Template for the application instance each execution step runs on.
    verifier: Verifier<E, A>,
    /// Runtime context for shared processing calls. A processing call outlives the requests
    /// that join it, so the context is the actor's.
    context: E,
    /// Every live request, in any phase.
    jobs: FuturesUnordered<Work<E, A>>,
    /// Which execution steps the actor's current operation admits.
    admission: Admission<BlockDigest<A, E>>,
}

impl<E, A, V> Handler<E, A, V>
where
    E: Supervisor + Clock,
    A: Application<E>,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<A::SigningScheme, V>: BlockProvider<Block = A::Block>,
{
    pub(super) fn new(
        marshal: MarshalMailbox<A::SigningScheme, V>,
        verifier: Verifier<E, A>,
        context: E,
    ) -> Self {
        Self {
            marshal,
            verifier,
            context,
            jobs: FuturesUnordered::new(),
            admission: Admission::Open,
        }
    }

    /// Returns the future that acquires `request`'s blocks, or `None` if its caller has cancelled
    /// or released its ancestry.
    fn acquisition(
        &self,
        request: &Request<E, A>,
    ) -> Option<BoxFuture<'static, PhaseResult<A::Block>>> {
        if request.is_cancelled() {
            return None;
        }

        // A verification reads the ancestry its caller still owns and recovers state for the
        // block's parent. A proposal owns its ancestry, and its first block is the parent to build
        // on.
        let (ancestry, verify) = match request {
            Request::Verify(request) => (request.ancestry.upgrade()?, true),
            Request::Recover(request) => (request.ancestry.clone(), false),
        };
        Some(
            self.verifier
                .prepare(
                    request.context().child("acquire"),
                    self.marshal.clone(),
                    ancestry,
                    verify,
                )
                .instrument(request.process_span())
                .boxed(),
        )
    }

    /// Starts acquiring `request`'s blocks, or drops the request if its caller has cancelled or
    /// released its ancestry.
    pub(super) fn schedule(&mut self, request: Request<E, A>) {
        assert!(matches!(self.admission, Admission::Open));
        let Some(future) = self.acquisition(&request) else {
            return;
        };
        self.jobs.push(Work {
            request: Some(request),
            phase: Phase::Acquiring {
                future: Some(future),
            },
        });
    }

    /// Handles every request whose current phase has already ended.
    pub(super) fn complete_ready(&mut self, actions: &mut VecDeque<Action<E, A>>) {
        while let Some(Some(result)) = self.jobs.next().now_or_never() {
            self.complete(result, actions);
        }
    }

    /// Waits for the next request's phase to end and handles it. Stays pending while no request is
    /// scheduled.
    pub(super) async fn complete_next(&mut self, actions: &mut VecDeque<Action<E, A>>) {
        let Some(result) = self.jobs.next().await else {
            return pending().await;
        };
        self.complete(result, actions);
    }

    /// Awaits `operation` while continuing to handle requests.
    pub(super) async fn drive<T>(
        &mut self,
        operation: impl Future<Output = T>,
        actions: &mut VecDeque<Action<E, A>>,
    ) -> T {
        futures::pin_mut!(operation);
        loop {
            select! {
                output = &mut operation => break output,
                _ = self.complete_next(actions) => {},
            }
        }
    }

    /// Pauses every acquisition and waits for each running execution step that the next
    /// maintenance operation does not retain.
    ///
    /// `boundary` is the block about to be finalized, or `None` for pruning. Finalization retains
    /// steps that descend from that block, pruning retains none, and [`Handler::resume`] restarts
    /// the paused acquisitions.
    pub(super) async fn pause(
        &mut self,
        boundary: Option<FinalizationBoundary<BlockDigest<A, E>>>,
        actions: &mut VecDeque<Action<E, A>>,
    ) {
        assert!(matches!(self.admission, Admission::Open));
        self.admission = boundary.map_or(Admission::Pruning, Admission::Finalizing);

        // Drop every acquisition future, keeping its request, and count the running steps that
        // maintenance must wait for. The count stays exact because a step starts only once its
        // parent's state is cached, so the completion of a retained step cannot make a counted
        // step retained.
        let mut pending = 0;
        for mut work in std::mem::take(&mut self.jobs) {
            match &mut work.phase {
                Phase::Ready { .. } => {}
                Phase::Acquiring { future } => *future = None,
                Phase::Executing { step, .. } => {
                    pending += usize::from(self.admission.disposition(step) != Disposition::Retain);
                }
            }
            self.jobs.push(work);
        }

        // Counted steps park or are rejected as they finish, and a counted step whose caller
        // cancels is dropped. Retained steps that finish meanwhile advance to their next step.
        while pending != 0 {
            let result = self
                .jobs
                .next()
                .await
                .expect("pending execution must remain scheduled");
            let selected = result
                .step
                .as_ref()
                .is_some_and(|step| self.admission.disposition(step) != Disposition::Retain);
            self.complete(result, actions);
            pending -= usize::from(selected);
        }
    }

    /// Reopens admission after maintenance. Parked requests advance from the state it left, and
    /// paused acquisitions restart unless their callers have gone.
    pub(super) fn resume(&mut self, actions: &mut VecDeque<Action<E, A>>) {
        assert!(!matches!(self.admission, Admission::Open));
        self.admission = Admission::Open;
        for work in std::mem::take(&mut self.jobs) {
            // A parked request kept the inputs of its finished step and selects its next step
            // directly.
            let mut work = match work {
                Work {
                    request,
                    phase: Phase::Ready { prepared },
                } => {
                    self.advance(
                        request.expect("ready request must be retained"),
                        prepared,
                        actions,
                    );
                    continue;
                }
                work => work,
            };

            // A paused acquisition starts over against the branch maintenance left, because the
            // state it was walking toward may have been applied or discarded since.
            if let Phase::Acquiring { future } = &mut work.phase {
                *future = self.acquisition(
                    work.request
                        .as_ref()
                        .expect("parked request must be retained"),
                );
                if future.is_none() {
                    continue;
                }
            }
            self.jobs.push(work);
        }
    }

    /// Handles a request whose phase ended: a cancelled request is dropped, a failed phase
    /// rejects it, a finished step is classified under the current admission, and an admitted
    /// request advances.
    fn complete(&mut self, completion: Completion<E, A>, actions: &mut VecDeque<Action<E, A>>) {
        let Completion {
            request,
            step,
            result,
        } = completion;

        // A cancelled request is dropped without a reply, and a failed phase rejects it.
        let Some(result) = result else {
            return;
        };
        let Ok(prepared) = result else {
            request.reject();
            return;
        };

        // Maintenance parks or rejects a finished step it does not retain. A retained step becomes
        // a compatible parent for steps that finish later in the same finalization.
        if let Some(step) = step {
            match self.admission.disposition(&step) {
                Disposition::Park => {
                    self.jobs.push(Work {
                        request: Some(request),
                        phase: Phase::Ready { prepared },
                    });
                    return;
                }
                Disposition::Reject => {
                    request.reject();
                    return;
                }
                Disposition::Retain => {
                    if let Admission::Finalizing(boundary) = &mut self.admission {
                        boundary.completed(&step);
                    }
                }
            }
        }
        self.advance(request, prepared, actions);
    }

    /// Starts the request's next execution step, or answers the request once no step remains.
    ///
    /// A next step that the current admission does not retain rejects the request.
    fn advance(
        &mut self,
        request: Request<E, A>,
        mut prepared: Prepared<A::Block>,
        actions: &mut VecDeque<Action<E, A>>,
    ) {
        if request.is_cancelled() {
            return;
        }

        // Each step gets its own clone of the application, so steps of different requests
        // execute concurrently and a processing call shared by several requests can outlive the
        // request that started it.
        if let Some((step, ancestry)) =
            self.verifier
                .next(request.context(), &self.marshal, &mut prepared)
        {
            if self.admission.disposition(&step) != Disposition::Retain {
                request.reject();
                return;
            }
            let span = request.process_span();
            let verifier = self.verifier.clone();
            let context = self.context.child("process");
            self.jobs.push(Work {
                request: Some(request),
                phase: Phase::Executing {
                    step,
                    future:
                        async move { verifier.process(context, ancestry).await.map(|()| prepared) }
                            .instrument(span)
                            .boxed(),
                },
            });
            return;
        }

        // Every step is done. A verification accepts, and a recovered proposal queues its build
        // with the ancestry it acquired.
        let ancestry = prepared.finish(request.context());
        match request {
            Request::Verify(request) => request.verification.respond(true),
            Request::Recover(mut request) => {
                request.ancestry = ancestry;
                actions.push_back(Action::Build(request));
            }
        }
    }
}
