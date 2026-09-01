//! The verifier: dispatches verification jobs to the strategy pools and forwards completions.

use super::{
    Config, Mailbox,
    mailbox::Message,
    metrics::{Metrics as ActorMetrics, VerificationKind},
    verify::verify,
    votes::VerifiedVotes,
};
use crate::{
    multimmit::{
        actors::{
            util::{Timing, WorkerPanicked, offload_timed},
            voter::{Completed, Completions},
        },
        machine::{VerificationCompletion, VerifyJob},
        scheme::bls12381_threshold::Scheme,
        types::Artifact,
    },
    types::Round,
};
use commonware_actor::mailbox;
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::traces::TracedExt as _};
use commonware_utils::{futures::Pool, sync::Mutex};
use rand_core::CryptoRng;
use std::{future::Future, marker::PhantomData, sync::Arc, time::SystemTime};
use tracing::{Span, debug_span, info_span};

/// One finished job with the span of the caller that issued it.
type VerifyResult<V, D> = (Span, Result<VerificationCompletion<V, D>, WorkerPanicked>);

/// Jobs in flight, completed in any order.
type VerifyResults<V, D> = Pool<'static, VerifyResult<V, D>>;

/// Why the verifier stopped the loop that drives it.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Fatal {
    #[error("verification job accounting exceeded its configured bound")]
    JobBound,
    /// Carries the span of the job whose worker panicked.
    #[error("verification worker panicked")]
    WorkerPanicked(Span),
    #[error("voter completion path closed")]
    VoterClosed,
}

/// One input the verifier serves.
pub(crate) enum Event<V: Variant, D: Digest> {
    /// A job message from the voter.
    Message(Message<V, D>),
    /// A finished job.
    Completed(VerifyResult<V, D>),
}

/// Runs machine-issued verification jobs on the configured strategy pools.
///
/// The verifier has no task of its own: the ingress loop owns it and serves its inputs ahead of
/// its own (see [`ingress::Actor::start`]).
///
/// [`ingress::Actor::start`]: crate::multimmit::actors::ingress::Actor::start
pub(crate) struct Verifier<E, H, P, V, T, C>
where
    E: Clock + CryptoRng + Metrics + Spawner,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
    C: Strategy,
{
    context: E,
    scheme: Arc<Scheme<P, V>>,
    verified_votes: Arc<Mutex<VerifiedVotes<V, H::Digest>>>,
    pub(super) strategy: T,
    pub(super) critical_strategy: C,
    inflight_jobs: usize,
    mailbox: mailbox::Receiver<Message<V, H::Digest>>,
    jobs: VerifyResults<V, H::Digest>,
    metrics: Arc<ActorMetrics>,
    _hasher: PhantomData<H>,
}

impl<E, H, P, V, T, C> Verifier<E, H, P, V, T, C>
where
    E: Clock + CryptoRng + Metrics + Spawner,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
    C: Strategy,
{
    /// Creates the verifier and its job mailbox.
    pub(crate) fn new(context: E, config: Config<P, V, T, C>) -> (Self, Mailbox<V, H::Digest>) {
        let metrics = Arc::new(ActorMetrics::new(&context));
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        (
            Self {
                context,
                verified_votes: Arc::new(Mutex::new(VerifiedVotes::new(
                    config.scheme.participants().as_ref().len(),
                ))),
                scheme: Arc::new(config.scheme),
                strategy: config.strategy,
                critical_strategy: config.critical_strategy,
                inflight_jobs: config.inflight_jobs.get(),
                mailbox: receiver,
                jobs: VerifyResults::default(),
                metrics,
                _hasher: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    /// Waits for the next input: a queued job message first, then a finished job.
    ///
    /// Returns `None` once the job mailbox closes.
    pub(crate) async fn next(&mut self) -> Option<Event<V, H::Digest>> {
        select! {
            message = self.mailbox.recv() => message.map(Event::Message),
            completion = self.jobs.next_completed() => Some(Event::Completed(completion)),
        }
    }

    /// Serves one input: submits a job, or delivers a finished one to `voter`.
    pub(crate) fn handle(
        &mut self,
        event: Event<V, H::Digest>,
        voter: &Completions<V, H::Digest>,
    ) -> Result<(), Fatal> {
        match event {
            Event::Message(Message::Verify {
                issued_at,
                span,
                round,
                job,
            }) => self.dispatch(span, round, job, issued_at),
            Event::Completed(completion) => deliver(voter, completion),
        }
    }

    /// Submits one job to the pool its items belong to.
    fn dispatch(
        &mut self,
        span: Span,
        round: Round,
        job: VerifyJob<V, H::Digest>,
        issued_at: SystemTime,
    ) -> Result<(), Fatal> {
        if self.jobs.len() >= self.inflight_jobs {
            return Err(Fatal::JobBound);
        }
        self.metrics.batch_size.observe(job.items().len() as f64);
        // The round waits on a view-critical verdict, so it executes on the pool reserved for view
        // work instead of queueing behind bulk header and availability jobs.
        if job.view_critical() {
            let strategy = self.critical_strategy.clone();
            let verification = self.verification(strategy, span, round, job, issued_at);
            self.jobs.push(verification);
        } else {
            let strategy = self.strategy.clone();
            let verification = self.verification(strategy, span, round, job, issued_at);
            self.jobs.push(verification);
        }
        Ok(())
    }

    /// Prepares one verification job for `strategy`.
    ///
    /// Submission waits for the first poll. The completion carries the caller's span so the voter
    /// can preserve trace causality.
    pub(super) fn verification<S: Strategy>(
        &self,
        strategy: S,
        span: Span,
        round: Round,
        job: VerifyJob<V, H::Digest>,
        issued_at: SystemTime,
    ) -> impl Future<Output = VerifyResult<V, H::Digest>> + Send + 'static {
        let kind = VerificationKind::of(&job);
        let worker = worker_span(&span, kind, round, &job);
        let timing = Timing {
            dispatch: self.metrics.verification_dispatch_wait.clone(),
            queue: self.metrics.kinds[kind].queue.clone(),
            issued_at,
        };
        let scheme = Arc::clone(&self.scheme);
        let verified_votes = Arc::clone(&self.verified_votes);
        let metrics = Arc::clone(&self.metrics);
        let context = self.context.child("verify");
        let operation = move |mut context: E, strategy: S| {
            let timer = metrics.kinds[kind].latency.timer(&context);
            let mut job = job;
            {
                let cache = verified_votes.lock();
                job.extend_known(|view| cache.known(view));
            }
            observe_transcripts(&metrics, &job);
            let completion = verify::<H, _, _>(&job, &mut context, &scheme, &strategy);
            verified_votes
                .lock()
                .record_job(&job, &completion, round, &metrics.verified_vote_lag);
            timer.observe(&context);
            completion
        };
        async move {
            let (_, outcome) = offload_timed(context, timing, strategy, 1, worker, operation).await;
            (span, outcome)
        }
    }
}

/// Opens the worker span of one job under `parent`.
///
/// Bulk jobs trace at debug level. Every other kind, including mixed jobs, may carry a vote or
/// certificate the round needs, so it traces at info level.
fn worker_span<V: Variant, D: Digest>(
    parent: &Span,
    kind: VerificationKind,
    round: Round,
    job: &VerifyJob<V, D>,
) -> Span {
    let pool = if job.view_critical() {
        "critical"
    } else {
        "bulk"
    };
    if kind == VerificationKind::Bulk {
        debug_span!(
            parent: parent,
            "multimmit.batcher.verify",
            kind = kind.label(),
            epoch = round.epoch().get().traced(),
            view = round.view().get().traced(),
            job = job.issued().id().get().traced(),
            items = job.items().len().traced(),
            pool,
        )
    } else {
        info_span!(
            parent: parent,
            "multimmit.batcher.verify",
            kind = kind.label(),
            epoch = round.epoch().get().traced(),
            view = round.view().get().traced(),
            job = job.issued().id().get().traced(),
            items = job.items().len().traced(),
            pool,
        )
    }
}

/// Observes the transcript size and cached votes of every certificate in `job`.
fn observe_transcripts<V: Variant, D: Digest>(metrics: &ActorMetrics, job: &VerifyJob<V, D>) {
    for item in job.items() {
        let signers = match item.artifact() {
            Artifact::Vqc(certificate) => certificate.tally().signers().count(),
            Artifact::Lqc(certificate) => certificate.tally().signers().count(),
            _ => continue,
        };
        metrics
            .certificate_transcript_messages
            .observe(signers as f64);
        metrics
            .certificate_known_messages
            .observe(item.known().len() as f64);
    }
}

/// Forwards one completion to the voter.
pub(super) fn deliver<V: Variant, D: Digest>(
    voter: &Completions<V, D>,
    (span, outcome): VerifyResult<V, D>,
) -> Result<(), Fatal> {
    let completion = match outcome {
        Ok(completion) => completion,
        Err(WorkerPanicked) => return Err(Fatal::WorkerPanicked(span)),
    };
    if voter.completed(Completed { span, completion }).accepted() {
        Ok(())
    } else {
        Err(Fatal::VoterClosed)
    }
}
