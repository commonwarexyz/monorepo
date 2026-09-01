//! Local block builds and custody checks run by the application.

use super::{DigestOf, Finished, VoterTypes};
use crate::{
    Automaton as _, Epochable as _,
    multimmit::{
        actors::voter::{
            tasks::{TaskError, TaskPermit},
            telemetry::TraceContext,
        },
        machine::{BuildId, BuildJob, CustodyCancellation, CustodyJob, Generation, Issued},
        types::{BlockRef, Context, TransactionBlockHeader},
    },
    types::Epoch,
};
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_runtime::{
    Clock as _, Error as RuntimeError, Spawner as _, Supervisor as _,
    telemetry::traces::TracedExt as _,
};
use commonware_utils::{channel::oneshot, futures::Pool};
use futures::FutureExt as _;
use std::{
    collections::BTreeMap,
    future::Future,
    mem,
    task::{self, Poll},
    time::SystemTime,
};
use tracing::{Instrument as _, Span, info_span};

/// One completed application job.
pub(crate) enum AppOutcome<D: Digest> {
    Built {
        started_at: SystemTime,
        id: BuildId,
        generation: Generation,
        parent: BlockRef<D>,
        result: Option<D>,
    },
    Custodied {
        id: BuildId,
        generation: Generation,
        header: TransactionBlockHeader<D>,
        verdict: Option<bool>,
    },
    CustodyCancelled {
        cancellation: CustodyCancellation,
    },
}

/// An application job as it returns from its task: its outcome, or a task failure.
pub(crate) type AppResult<D> = Result<AppOutcome<D>, RuntimeError>;

/// The cancellation state of one running custody check.
pub(crate) enum Custody {
    /// The check runs; sending on the channel cancels it.
    Running(oneshot::Sender<()>),
    /// The machine cancelled the check and awaits its cancellation completion.
    CancelRequested,
}

/// Runs local application jobs and collects their outcomes.
pub(crate) struct AppExecutor<T: VoterTypes> {
    automaton: T::Automaton,
    epoch: Epoch,
    jobs: Pool<'static, Finished<AppResult<DigestOf<T>>>>,
    /// Cancellation state of each running custody check, keyed by the machine's build identity.
    custody: BTreeMap<BuildId, Custody>,
}

impl<T: VoterTypes> AppExecutor<T> {
    pub(crate) fn new(automaton: T::Automaton, epoch: Epoch) -> Self {
        Self {
            automaton,
            epoch,
            jobs: Pool::default(),
            custody: BTreeMap::new(),
        }
    }

    /// Asks the application to build the block for one machine-issued production job.
    pub(crate) fn build(
        &mut self,
        runtime: &T::Context,
        permit: TaskPermit,
        job: &BuildJob<DigestOf<T>>,
        root: &Span,
    ) {
        let parent = job.parent();
        let context = Context::new(
            self.epoch,
            parent.chain(),
            parent.height().next(),
            parent.digest(),
        )
        .expect("build job has a non-genesis position");
        let (id, generation) = (job.issued().id(), job.issued().generation());
        let span = info_span!(
            "multimmit.voter.produce",
            epoch = self.epoch.get().traced(),
            chain = parent.chain().get().traced(),
            height = parent.height().next().get().traced()
        );
        let started_at = runtime.current();
        let mut automaton = self.automaton.clone();
        self.spawn(runtime, permit, "build", span, root, async move {
            let receiver = automaton.propose(context).await;
            let result = receiver.await.ok();
            AppOutcome::Built {
                started_at,
                id,
                generation,
                parent,
                result,
            }
        });
    }

    /// Validates and durably retains one locally prepared body before its header may be signed.
    pub(crate) fn custody(
        &mut self,
        runtime: &T::Context,
        permit: TaskPermit,
        job: &CustodyJob<DigestOf<T>>,
        root: &Span,
    ) {
        let (id, generation) = (job.issued().id(), job.issued().generation());
        let cancellation = CustodyCancellation::new(Issued::new(id, generation));
        let header = job.header().clone();
        let context = Context::from(&header);
        let commitment = header.body_digest();
        let (cancel, cancelled) = oneshot::channel();
        let previous = self.custody.insert(id, Custody::Running(cancel));
        assert!(previous.is_none(), "local custody identity is unique");
        let span = info_span!(
            "multimmit.voter.custody",
            epoch = header.epoch().get().traced(),
            chain = header.chain().get().traced(),
            height = header.height().get().traced(),
        );
        let mut automaton = self.automaton.clone();
        self.spawn(runtime, permit, "custody", span, root, async move {
            let custody = async {
                let receiver = automaton.verify(context, commitment).await;
                receiver.await.ok()
            };
            select! {
                verdict = custody => AppOutcome::Custodied {
                    id,
                    generation,
                    header,
                    verdict,
                },
                _ = cancelled => AppOutcome::CustodyCancelled { cancellation },
            }
        });
    }

    /// Spawns `job` under `span` while `permit` holds its capacity.
    fn spawn(
        &mut self,
        runtime: &T::Context,
        permit: TaskPermit,
        label: &'static str,
        span: Span,
        root: &Span,
        job: impl Future<Output = AppOutcome<DigestOf<T>>> + Send + 'static,
    ) {
        let trace = TraceContext::new(span.clone(), root.clone());
        let handle = runtime.child(label).spawn(move |_| job.instrument(span));
        self.jobs.push(async move {
            Finished {
                permit,
                trace,
                outcome: handle.await,
            }
        });
    }

    /// Cancels a running custody check.
    pub(crate) fn cancel(&mut self, id: BuildId) -> Result<(), TaskError> {
        let custody = self.custody.get_mut(&id).ok_or(TaskError::Accounting)?;
        if let Custody::Running(cancel) = mem::replace(custody, Custody::CancelRequested) {
            let _ = cancel.send(());
        }
        Ok(())
    }

    /// Returns whether the machine cancelled the custody check for `id`.
    pub(crate) fn cancel_requested(&self, id: BuildId) -> bool {
        matches!(self.custody.get(&id), Some(Custody::CancelRequested))
    }

    /// Forgets a finished custody check and returns its cancellation state.
    pub(crate) fn finish_custody(&mut self, id: BuildId) -> Result<Custody, TaskError> {
        self.custody.remove(&id).ok_or(TaskError::Accounting)
    }

    /// Polls for the next finished job.
    pub(crate) fn poll_completed(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Finished<AppResult<DigestOf<T>>>> {
        self.jobs.next_completed().poll_unpin(cx)
    }

    /// Cancels every running job and forgets their custody state.
    pub(crate) fn cancel_all(&mut self) {
        self.jobs.cancel_all();
        self.custody.clear();
    }
}
