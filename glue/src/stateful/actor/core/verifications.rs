use crate::stateful::{
    Application,
    actor::{
        core::mailbox::{Verification, WeakAncestry},
        processor::{Disposition, PendingDigest, VerificationProgress, Verifier},
    },
};
use commonware_consensus::marshal::{
    ancestry::BlockProvider,
    core::{Mailbox as MarshalMailbox, Variant},
};
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::{channel::oneshot, futures::Pool};
use futures::FutureExt as _;
use rand_core::Rng;
use std::{collections::BTreeMap, future::Future};
use tracing::{Instrument as _, Span, info_span};

/// A caller-scoped verification request that can be deferred or restarted.
///
/// The request retains the same non-owning ancestry handle while each active
/// attempt uses an independent cursor.
pub(super) struct Request<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub(super) span: Span,
    pub(super) context: (E, A::Context),
    pub(super) ancestry: WeakAncestry<A::Block>,
    pub(super) verification: Verification,
}

enum JobResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    Finished {
        id: u64,
        request: Request<E, A>,
        valid: Option<bool>,
    },
    Invalidated {
        id: u64,
        request: Request<E, A>,
    },
}

impl<E, A> JobResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
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
    progress: VerificationProgress<D>,
}

/// Owns independently-polled verification requests and their cancellation handles.
pub(super) struct Handler<E, A, S, V>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    marshal: MarshalMailbox<S, V>,
    jobs: Pool<JobResult<E, A>>,
    controls: BTreeMap<u64, JobControl<PendingDigest<A, E>>>,
    next_id: u64,
}

impl<E, A, S, V> Handler<E, A, S, V>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    pub(super) fn new(marshal: MarshalMailbox<S, V>) -> Self {
        Self {
            marshal,
            jobs: Pool::default(),
            controls: BTreeMap::new(),
            next_id: 0,
        }
    }

    pub(super) fn schedule(&mut self, mut verifier: Verifier<E, A>, mut request: Request<E, A>) {
        // Acquire an independent cursor for this active attempt. Canceled callers cannot provide
        // one, while queued requests remain non-owning.
        let Some(ancestry) = request.ancestry.acquire() else {
            return;
        };

        // Register the attempt before polling it so actor invalidation and progress share one
        // lifecycle.
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("verification request ID overflowed");
        let (invalidate, invalidated) = oneshot::channel();
        let progress = VerificationProgress::default();
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

        // Move only the independent cursor into active work. The original request returns with
        // its weak ancestry handle intact for completion or another attempt.
        let marshal = self.marshal.clone();
        let process = info_span!(parent: &request.span, "stateful.actor.verify");
        self.jobs.push(
            async move {
                select! {
                    _ = invalidated => JobResult::Invalidated { id, request },
                    valid = verifier.run(
                        &request.context.0,
                        marshal,
                        request.context.1.clone(),
                        ancestry,
                        &progress,
                        &mut request.verification,
                    ) => JobResult::Finished { id, request, valid },
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

    pub(super) async fn next_completed(&mut self) {
        let result = self.jobs.next_completed().await;
        self.handle(result);
    }

    pub(super) async fn drive<T>(&mut self, operation: impl Future<Output = T>) -> T {
        futures::pin_mut!(operation);
        loop {
            select! {
                output = &mut operation => break output,
                _ = self.next_completed() => {},
            }
        }
    }

    /// Cancels every active attempt and waits for verification work to stop.
    ///
    /// Pruning uses this full barrier because it can remove history needed by
    /// every branch. Live requests retain their ancestry and are returned for
    /// a new attempt.
    pub(super) async fn quiesce(&mut self) -> Vec<Request<E, A>> {
        let (retry, reject) = self.quiesce_where(|_| Disposition::Retry).await;
        assert!(reject.is_empty());
        retry
    }

    pub(super) async fn quiesce_where(
        &mut self,
        disposition: impl Fn(&VerificationProgress<PendingDigest<A, E>>) -> Disposition,
    ) -> (Vec<Request<E, A>>, Vec<Verification>) {
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
                .expect("completed verification must have an invalidation handle");
            assert!(control.invalidation.is_none());
            let request = match result {
                JobResult::Finished { request, .. } | JobResult::Invalidated { request, .. } => {
                    request
                }
            };
            match disposition {
                Disposition::Retain => {
                    unreachable!("retained verification cannot be invalidated")
                }
                Disposition::Retry => {
                    if !request.verification.is_cancelled() {
                        retry.push(request);
                    }
                }
                Disposition::Reject => reject.push(request.verification),
            }
        }
        (retry, reject)
    }

    fn handle(&mut self, result: JobResult<E, A>) {
        let control = self
            .controls
            .remove(&result.id())
            .expect("completed verification must have an invalidation handle");
        assert!(control.invalidation.is_some());
        let JobResult::Finished { request, valid, .. } = result else {
            panic!("verification cannot finish through the actor loop after invalidation");
        };
        if let Some(valid) = valid {
            request.verification.respond(valid);
        }
    }
}
