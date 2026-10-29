use crate::stateful::{
    Application,
    actor::{
        BlockDigest,
        core::mailbox::{Message, ProposalRequest, Verification, WeakAncestry},
        processor::{Disposition, Progress, Verifier},
    },
};
use commonware_consensus::marshal::{
    ancestry::BlockProvider,
    core::{Mailbox as MarshalMailbox, Variant},
};
use commonware_macros::select;
use commonware_runtime::{Clock, Supervisor};
use commonware_utils::{channel::oneshot, futures::Pool};
use futures::FutureExt as _;
use std::{collections::BTreeMap, future::Future};
use tracing::{Instrument as _, Span, info_span};

/// A caller-scoped verification request that can be deferred or restarted.
///
/// Restarting a request reuses its caller's ancestry without taking ownership of it.
pub(super) struct VerificationRequest<E, A>
where
    A: Application<E>,
{
    pub(super) span: Span,
    pub(super) context: E,
    pub(super) ancestry: WeakAncestry<A::Block>,
    pub(super) verification: Verification,
}

/// Caller requests whose speculative processing can be stopped and retried.
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

    pub(super) fn into_message(self) -> Message<E, A> {
        match self {
            Self::Verify(request) => Message::Verify(request),
            Self::Recover(request) => Message::Propose(request),
        }
    }

    pub(super) fn reject(self) {
        match self {
            Self::Verify(request) => request.verification.respond(false),
            Self::Recover(request) => request.proposal.decline(),
        }
    }
}

enum JobResult<E, A>
where
    A: Application<E>,
{
    Finished {
        id: u64,
        request: Request<E, A>,
        succeeded: Option<bool>,
    },
    Invalidated {
        id: u64,
        request: Request<E, A>,
    },
}

impl<E, A> JobResult<E, A>
where
    A: Application<E>,
{
    const fn id(&self) -> u64 {
        match self {
            Self::Finished { id, .. } | Self::Invalidated { id, .. } => *id,
        }
    }
}

struct JobControl<D: Copy> {
    invalidation: Option<oneshot::Sender<()>>,
    progress: Progress<D>,
}

/// Owns independently-polled verification and recovery requests and their cancellation handles.
pub(super) struct Handler<E, A, V>
where
    A: Application<E>,
    V: Variant,
{
    marshal: MarshalMailbox<A::SigningScheme, V>,
    jobs: Pool<'static, JobResult<E, A>>,
    controls: BTreeMap<u64, JobControl<BlockDigest<A, E>>>,
    next_id: u64,
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
            jobs: Pool::default(),
            controls: BTreeMap::new(),
            next_id: 0,
        }
    }

    /// Starts an attempt for `request` with `verifier`, or drops `request` if its caller has
    /// cancelled.
    pub(super) fn schedule(&mut self, mut verifier: Verifier<E, A>, mut request: Request<E, A>) {
        if request.is_cancelled() {
            return;
        }

        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("speculative request ID overflowed");
        let (invalidate, invalidated) = oneshot::channel();
        let progress = Progress::default();
        assert!(
            self.controls
                .insert(
                    id,
                    JobControl {
                        invalidation: Some(invalidate),
                        progress: progress.clone(),
                    },
                )
                .is_none()
        );

        let marshal = self.marshal.clone();
        let process = match &request {
            Request::Verify(request) => info_span!(parent: &request.span, "stateful.actor.verify"),
            Request::Recover(request) => {
                info_span!(parent: &request.span, "stateful.actor.recover")
            }
        };
        self.jobs.push(
            async move {
                select! {
                    _ = invalidated => JobResult::Invalidated { id, request },
                    succeeded = async {
                        match &mut request {
                            Request::Verify(request) => {
                                let ancestry = request.ancestry.upgrade()?;
                                select! {
                                    _ = request.verification.wait_for_cancellation() => None,
                                    valid = verifier.run(
                                        &request.context,
                                        marshal,
                                        ancestry,
                                        &progress,
                                    ) => Some(valid),
                                }
                            }
                            Request::Recover(request) => {
                                select! {
                                    _ = request.proposal.wait_for_cancellation() => None,
                                    ready = verifier.recover_parent(
                                        &request.context.0,
                                        marshal,
                                        &mut request.ancestry,
                                        &progress,
                                    ) => Some(ready),
                                }
                            }
                        }
                    } => JobResult::Finished { id, request, succeeded },
                }
            }
            .instrument(process),
        );
    }

    pub(super) fn complete_ready(&mut self) {
        while let Some(result) = self.jobs.next_completed().now_or_never() {
            self.handle(result);
        }
    }

    pub(super) async fn complete_next(&mut self) {
        let result = self.jobs.next_completed().await;
        self.handle(result);
    }

    /// Awaits `operation` while continuing to complete speculative attempts.
    pub(super) async fn drive<T>(&mut self, operation: impl Future<Output = T>) -> T {
        futures::pin_mut!(operation);
        loop {
            select! {
                output = &mut operation => break output,
                _ = self.complete_next() => {},
            }
        }
    }

    /// Stops every active attempt, waits for all of them to end, and returns the requests whose
    /// callers are still waiting.
    pub(super) async fn quiesce(&mut self) -> Vec<Request<E, A>> {
        let (retry, reject) = self.quiesce_where(|_| Disposition::Retry).await;
        assert!(reject.is_empty());
        retry
    }

    /// Stops every attempt that `disposition` does not retain and waits for those attempts to end.
    ///
    /// Returns the stopped requests to retry (excluding cancelled callers) and the requests to
    /// reject. An attempt that finished before observing the stop is handled the same way, and its
    /// result is discarded. Retained attempts keep running, and any that finish in the meantime
    /// complete normally.
    pub(super) async fn quiesce_where(
        &mut self,
        disposition: impl Fn(&Progress<BlockDigest<A, E>>) -> Disposition,
    ) -> (Vec<Request<E, A>>, Vec<Request<E, A>>) {
        let mut pending = BTreeMap::new();
        for (&id, control) in &mut self.controls {
            let disposition = disposition(&control.progress);
            if disposition == Disposition::Retain {
                continue;
            }
            assert!(control.invalidation.take().is_some());
            assert!(pending.insert(id, disposition).is_none());
        }

        let mut retry = Vec::with_capacity(pending.len());
        let mut reject = Vec::with_capacity(pending.len());
        while !pending.is_empty() {
            let result = self.jobs.next_completed().await;
            let id = result.id();
            let Some(disposition) = pending.remove(&id) else {
                self.handle(result);
                continue;
            };
            let control = self
                .controls
                .remove(&id)
                .expect("completed request must have an invalidation handle");
            assert!(control.invalidation.is_none());
            let request = match result {
                JobResult::Finished { request, .. } | JobResult::Invalidated { request, .. } => {
                    request
                }
            };
            match disposition {
                Disposition::Retain => {
                    unreachable!("retained request cannot be invalidated")
                }
                Disposition::Retry => {
                    if !request.is_cancelled() {
                        retry.push(request);
                    }
                }
                Disposition::Reject => reject.push(request),
            }
        }
        (retry, reject)
    }

    fn handle(&mut self, result: JobResult<E, A>) {
        let control = self
            .controls
            .remove(&result.id())
            .expect("completed request must have an invalidation handle");
        assert!(control.invalidation.is_some());
        let JobResult::Finished {
            request, succeeded, ..
        } = result
        else {
            panic!("request cannot finish through the actor loop after invalidation");
        };
        let Some(succeeded) = succeeded else {
            return;
        };
        match request {
            Request::Verify(request) => request.verification.respond(succeeded),
            Request::Recover(request) => {
                if succeeded {
                    let mailbox = request.retry_mailbox.clone();
                    mailbox(Message::Build(request));
                } else {
                    request.proposal.decline();
                }
            }
        }
    }
}
