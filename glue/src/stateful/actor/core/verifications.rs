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

/// A verification whose ancestry remains owned by its caller until work is admitted.
pub(super) struct VerificationRequest<E, A>
where
    A: Application<E>,
{
    pub(super) span: Span,
    pub(super) context: E,
    pub(super) ancestry: WeakAncestry<A::Block>,
    pub(super) verification: Verification,
}

/// Original inputs and response of an admitted speculative request.
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
    pub(super) fn is_cancelled(&self) -> bool {
        match self {
            Self::Verify(request) => request.verification.is_cancelled(),
            Self::Recover(request) => request.proposal.is_cancelled(),
        }
    }

    fn poll_cancelled(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match self {
            Self::Verify(request) => request.verification.poll_cancelled(cx),
            Self::Recover(request) => request.proposal.poll_cancelled(cx),
        }
    }

    const fn context(&self) -> &E {
        match self {
            Self::Verify(request) => &request.context,
            Self::Recover(request) => &request.context.0,
        }
    }

    fn process_span(&self) -> Span {
        match self {
            Self::Verify(request) => info_span!(parent: &request.span, "stateful.actor.verify"),
            Self::Recover(request) => info_span!(parent: &request.span, "stateful.actor.recover"),
        }
    }

    pub(super) fn reject(self) {
        match self {
            Self::Verify(request) => request.verification.respond(false),
            Self::Recover(request) => request.proposal.decline(),
        }
    }
}

type WorkResult<E, A> = (
    Verifier<E, A>,
    Result<Prepared<<A as Application<E>>::Block>, PrepareBatchesError>,
);

enum Phase<E, A>
where
    A: Application<E>,
{
    Ready {
        verifier: Verifier<E, A>,
        prepared: Prepared<A::Block>,
    },
    Acquiring {
        verifier: Option<Verifier<E, A>>,
        future: Option<BoxFuture<'static, Result<Prepared<A::Block>, PrepareBatchesError>>>,
    },
    Executing {
        step: ExecutionStep<BlockDigest<A, E>>,
        future: BoxFuture<'static, WorkResult<E, A>>,
    },
}

/// Owns a request independently of its replaceable acquisition or single-block execution.
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
    const fn step(&self) -> Option<ExecutionStep<BlockDigest<A, E>>> {
        match self.phase {
            Phase::Acquiring { .. } | Phase::Ready { .. } => None,
            Phase::Executing { step, .. } => Some(step),
        }
    }
}

struct Completion<E, A>
where
    A: Application<E>,
{
    request: Request<E, A>,
    step: Option<ExecutionStep<BlockDigest<A, E>>>,
    result: Option<WorkResult<E, A>>,
}

impl<E, A: Application<E>> Future for Work<E, A> {
    type Output = Completion<E, A>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let work = self.get_mut();
        let step = work.step();
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

        let result = match &mut work.phase {
            Phase::Ready { .. } => return Poll::Pending,
            Phase::Acquiring { verifier, future } => {
                let Some(future) = future else {
                    return Poll::Pending;
                };
                let result = ready!(future.as_mut().poll(cx));
                (
                    verifier
                        .take()
                        .expect("acquiring work must retain its verifier"),
                    result,
                )
            }
            Phase::Executing { future, .. } => ready!(future.as_mut().poll(cx)),
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
    Open,
    Finalizing(FinalizationBoundary<D>),
    Pruning,
}

impl<D: Copy + Eq + std::hash::Hash> Admission<D> {
    fn disposition(&self, step: &ExecutionStep<D>) -> Disposition {
        match self {
            Self::Open => Disposition::Retain,
            Self::Finalizing(boundary) => boundary.disposition(step),
            Self::Pruning => Disposition::Park,
        }
    }
}

/// Advances independently-polled requests while the actor owns their admission order.
pub(super) struct Handler<E, A, V>
where
    A: Application<E>,
    V: Variant,
{
    marshal: MarshalMailbox<A::SigningScheme, V>,
    jobs: FuturesUnordered<Work<E, A>>,
    admission: Admission<BlockDigest<A, E>>,
}

impl<E, A, V> Handler<E, A, V>
where
    E: Supervisor + Clock,
    A: Application<E>,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<A::SigningScheme, V>: BlockProvider<Block = A::Block>,
{
    pub(super) fn new(marshal: MarshalMailbox<A::SigningScheme, V>) -> Self {
        Self {
            marshal,
            jobs: FuturesUnordered::new(),
            admission: Admission::Open,
        }
    }

    fn acquisition(
        &self,
        verifier: &Verifier<E, A>,
        request: &Request<E, A>,
    ) -> Option<BoxFuture<'static, Result<Prepared<A::Block>, PrepareBatchesError>>> {
        if request.is_cancelled() {
            return None;
        }
        let (ancestry, verify) = match request {
            Request::Verify(request) => (request.ancestry.upgrade()?, true),
            Request::Recover(request) => (request.ancestry.clone(), false),
        };
        Some(
            verifier
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

    pub(super) fn schedule(&mut self, verifier: Verifier<E, A>, request: Request<E, A>) {
        assert!(matches!(self.admission, Admission::Open));
        let Some(future) = self.acquisition(&verifier, &request) else {
            return;
        };
        self.jobs.push(Work {
            request: Some(request),
            phase: Phase::Acquiring {
                verifier: Some(verifier),
                future: Some(future),
            },
        });
    }

    pub(super) fn complete_ready(&mut self, actions: &mut VecDeque<Action<E, A>>) {
        while let Some(Some(result)) = self.jobs.next().now_or_never() {
            self.complete(result, actions);
        }
    }

    pub(super) async fn complete_next(&mut self, actions: &mut VecDeque<Action<E, A>>) {
        let Some(result) = self.jobs.next().await else {
            return pending().await;
        };
        self.complete(result, actions);
    }

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

    /// Parks pure acquisition and lets read-bearing steps finish before conflicting maintenance.
    /// Compatible descendant execution remains admitted across finalization.
    pub(super) async fn pause(
        &mut self,
        boundary: Option<FinalizationBoundary<BlockDigest<A, E>>>,
        actions: &mut VecDeque<Action<E, A>>,
    ) {
        assert!(matches!(self.admission, Admission::Open));
        self.admission = boundary.map_or(Admission::Pruning, Admission::Finalizing);
        let mut pending = 0;
        for mut work in std::mem::take(&mut self.jobs) {
            match &mut work.phase {
                Phase::Ready { .. } => {}
                Phase::Acquiring { future, .. } => *future = None,
                Phase::Executing { step, .. } => {
                    pending += usize::from(self.admission.disposition(step) != Disposition::Retain);
                }
            }
            self.jobs.push(work);
        }

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

    /// Rechecks waiting requests against the branch left by maintenance.
    pub(super) fn resume(&mut self, actions: &mut VecDeque<Action<E, A>>) {
        assert!(!matches!(self.admission, Admission::Open));
        self.admission = Admission::Open;
        for work in std::mem::take(&mut self.jobs) {
            let mut work = match work {
                Work {
                    request,
                    phase: Phase::Ready { verifier, prepared },
                } => {
                    self.advance(
                        request.expect("ready request must be retained"),
                        verifier,
                        prepared,
                        actions,
                    );
                    continue;
                }
                work => work,
            };
            if let Phase::Acquiring { verifier, future } = &mut work.phase {
                *future = self.acquisition(
                    verifier.as_ref().expect("parked verifier must be retained"),
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

    fn complete(&mut self, completion: Completion<E, A>, actions: &mut VecDeque<Action<E, A>>) {
        let Completion {
            request,
            step,
            result,
        } = completion;
        let Some((verifier, result)) = result else {
            return;
        };
        let Ok(prepared) = result else {
            request.reject();
            return;
        };
        if let Some(step) = step {
            match self.admission.disposition(&step) {
                Disposition::Park => {
                    self.jobs.push(Work {
                        request: Some(request),
                        phase: Phase::Ready { verifier, prepared },
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
        self.advance(request, verifier, prepared, actions);
    }

    fn advance(
        &mut self,
        request: Request<E, A>,
        mut verifier: Verifier<E, A>,
        mut prepared: Prepared<A::Block>,
        actions: &mut VecDeque<Action<E, A>>,
    ) {
        if request.is_cancelled() {
            return;
        }
        if let Some((step, ancestry)) =
            verifier.next(request.context(), self.marshal.clone(), &mut prepared)
        {
            if self.admission.disposition(&step) != Disposition::Retain {
                request.reject();
                return;
            }
            let context = request.context().child("execute");
            let span = request.process_span();
            self.jobs.push(Work {
                request: Some(request),
                phase: Phase::Executing {
                    step,
                    future: async move {
                        let result = verifier
                            .process(&context, ancestry)
                            .await
                            .map(|()| prepared);
                        (verifier, result)
                    }
                    .instrument(span)
                    .boxed(),
                },
            });
            return;
        }

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
