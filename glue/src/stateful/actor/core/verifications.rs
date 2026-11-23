//! Concurrent speculative requests for the processing loop.
//!
//! A verification, or a proposal whose parent state may be missing, becomes a [`Work`] that the
//! [`Handler`] polls alongside the actor's other duties. A request first acquires its blocks and
//! the missing path back to known state, then runs one execution step per missing block (see
//! [`Verifier::next`]), and finally answers its caller or, for a proposal, queues a build.
//!
//! Requests keep running while the actor finalizes or prunes. A finalization on a competing
//! branch makes a request's step end with [`PrepareBatchesError::Stale`], and the request then
//! acquires its blocks again against the new branch anchor. Each such restart follows a
//! finalization, so a request restarts at most once per finalized block.

use super::{
    mailbox::{ProposalRequest, Verification, WeakAncestry},
    processing::Action,
};
use crate::stateful::{
    Application,
    actor::processor::{PrepareBatchesError, Prepared, Verifier},
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
    /// Acquiring the request's blocks.
    Acquiring {
        future: BoxFuture<'static, PhaseResult<A::Block>>,
    },
    /// Running one execution step.
    Executing {
        future: BoxFuture<'static, PhaseResult<A::Block>>,
    },
}

/// A request and its current phase. The request outlives each phase's future, so a stale request
/// can start a new acquisition.
struct Work<E, A>
where
    A: Application<E>,
{
    request: Option<Request<E, A>>,
    phase: Phase<E, A>,
}

// Polling pins only the boxed phase futures, so the request and phase metadata may move.
impl<E, A: Application<E>> Unpin for Work<E, A> {}

/// A request whose current phase ended. `result` is `None` if its caller cancelled.
struct Completion<E, A>
where
    A: Application<E>,
{
    request: Request<E, A>,
    result: Option<PhaseResult<A::Block>>,
}

impl<E, A: Application<E>> Future for Work<E, A> {
    type Output = Completion<E, A>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let work = self.get_mut();

        // A caller's cancellation ends its work in any phase.
        if work
            .request
            .as_mut()
            .expect("pending work must retain its request")
            .poll_cancelled(cx)
            .is_ready()
        {
            return Poll::Ready(Completion {
                request: work.request.take().unwrap(),
                result: None,
            });
        }

        let result = match &mut work.phase {
            Phase::Acquiring { future } | Phase::Executing { future } => {
                ready!(future.as_mut().poll(cx))
            }
        };
        Poll::Ready(Completion {
            request: work.request.take().unwrap(),
            result: Some(result),
        })
    }
}

/// Runs speculative requests concurrently. Finished recoveries queue their builds for the actor.
pub(super) struct Handler<E, A, V>
where
    A: Application<E>,
    V: Variant,
{
    /// Source of blocks for acquisition and for ancestry reads during execution.
    marshal: MarshalMailbox<A::SigningScheme, V>,
    /// Template for the application instance each execution step runs on.
    verifier: Verifier<E, A>,
    /// Runtime context for acquisition and shared processing. Shared processing may outlive
    /// any individual request, so it uses the actor's context.
    context: E,
    /// Every live request, in any phase.
    jobs: FuturesUnordered<Work<E, A>>,
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
                    self.context.child("acquire"),
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
        let Some(future) = self.acquisition(&request) else {
            return;
        };
        self.jobs.push(Work {
            request: Some(request),
            phase: Phase::Acquiring { future },
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

    /// Handles a request whose phase ended: a cancelled request is dropped, a stale one starts
    /// over, a failed one is rejected, and a finished one advances.
    fn complete(&mut self, completion: Completion<E, A>, actions: &mut VecDeque<Action<E, A>>) {
        let Completion { request, result } = completion;

        // A cancelled request is dropped without a reply.
        let Some(result) = result else {
            return;
        };
        let prepared = match result {
            Ok(prepared) => prepared,
            // The branch anchor moved past the state this request built on. Acquiring again
            // answers it from the canonical chain or replays it on the new anchor's state.
            Err(PrepareBatchesError::Stale) => {
                self.schedule(request);
                return;
            }
            Err(PrepareBatchesError::Invalid | PrepareBatchesError::Incomplete) => {
                request.reject();
                return;
            }
        };

        self.advance(request, prepared, actions);
    }

    /// Starts the request's next execution step, or answers the request once no step remains.
    fn advance(
        &mut self,
        request: Request<E, A>,
        mut prepared: Prepared<A::Block>,
        actions: &mut VecDeque<Action<E, A>>,
    ) {
        if request.is_cancelled() {
            return;
        }

        // Each processing call owns an application clone, so different blocks can execute
        // concurrently and a shared call can outlive the request that started it. A step joins
        // the block's processing as it starts, so it stays alive for that step even if every
        // other holder is dropped before the step is first polled.
        if let Some(ancestry) = self
            .verifier
            .next(&self.context, &self.marshal, &mut prepared)
        {
            let span = request.process_span();
            let processing = self
                .verifier
                .process(self.context.child("process"), ancestry);
            self.jobs.push(Work {
                request: Some(request),
                phase: Phase::Executing {
                    future: async move { processing.await.map(|()| prepared) }
                        .instrument(span)
                        .boxed(),
                },
            });
            return;
        }

        // Every step is done. A verification accepts, and a recovered proposal queues its build
        // with the ancestry it acquired.
        let ancestry = prepared.finish(&self.context);
        match request {
            Request::Verify(request) => request.verification.respond(true),
            Request::Recover(mut request) => {
                request.ancestry = ancestry;
                actions.push_back(Action::Build(request));
            }
        }
    }
}
