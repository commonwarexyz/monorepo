//! Routing of core capabilities to the runtime pieces that execute them.

use super::{
    AtRoot as _, DigestOf, Failure, Fatal, Hooks as _, RetentionBoundary, VoterTypes, live::Live,
    timers::TimeoutReason, verification::PendingVerification,
};
use crate::{
    Viewable as _,
    multimmit::{
        actors::{
            resolver::ResolveRequest,
            voter::{
                egress::Transmission,
                tasks::{TaskClass, TaskError, TaskPermit},
                telemetry::TraceContext,
            },
        },
        machine::{
            AppJob, Capabilities, Capability, CryptoJob, CustodyCancellation, DurableEffect,
            DurableJob, EffectId, Generation, Publication, ResolverCommand, SendRequest,
            SignRequest, StepError, TimerCommand, VerifyJob,
        },
        types::{Artifact, ViewProof},
    },
    types::{Participant, Round},
};
use commonware_p2p::{Blocker as _, Sender};
use commonware_runtime::{
    Clock as _,
    telemetry::{
        metrics::{GaugeExt as _, HistogramExt as _},
        traces::TracedExt as _,
    },
};
use commonware_utils::SystemTimeExt as _;
use std::sync::Arc;
use tracing::{Span, debug, info_span};

impl<T, S> Live<T, S>
where
    T: VoterTypes,
    S: Sender<PublicKey = T::PublicKey>,
{
    /// Executes core capabilities in order.
    pub(crate) fn execute_capabilities(
        &mut self,
        capabilities: Capabilities<T::Variant, DigestOf<T>>,
        root: &Span,
    ) -> Result<(), Failure> {
        for capability in capabilities {
            match capability {
                Capability::Verify(job) => self.verify(job, root)?,
                Capability::Quarantine(participants) => self.block_participants(&participants),
                Capability::Journal(directive) => self.persist(directive, root).at(root)?,
                Capability::Acknowledged {
                    retention,
                    forwarded_nullifications,
                } => self
                    .acknowledged(retention, forwarded_nullifications)
                    .at(root)?,
                Capability::Released(job) => self.execute_released(job, root).at(root)?,
                Capability::Retain(artifact) => self
                    .retain_served(&artifact, RetentionBoundary::Exposure)
                    .at(root)?,
                Capability::Retire(retired) => self.retire(&retired),
                Capability::Application(job) => self.execute_application(job, root).at(root)?,
                Capability::Crypto(job) => self.execute_crypto(job, root).at(root)?,
                Capability::Timer(command) => self.arm_timer(command, root),
                // Each chain plane and the own-chain DA task run on their own tasks; the voter
                // hands them the machine's command and never blocks on them.
                Capability::Validator(chain, command) => {
                    if let Some(plane) = self.chains.plane(chain) {
                        let _ = plane.command(command);
                    }
                }
                Capability::OwnChainDa(command) => {
                    if let Some(da) = self.chains.da() {
                        let _ = da.command(command);
                    }
                }
                Capability::Resolver(command) => self.execute_resolver(command, root).at(root)?,
            }
        }
        Ok(())
    }

    /// Schedules the verification of one machine-issued job.
    fn verify(
        &mut self,
        job: VerifyJob<T::Variant, DigestOf<T>>,
        root: &Span,
    ) -> Result<(), Failure> {
        let view = self.telemetry.round_view();
        let span = info_span!(
            parent: root,
            "multimmit.voter.verify",
            epoch = self.epoch.get().traced(),
            view = view.get().traced(),
            job = job.issued().id().get().traced(),
            items = job.items().len().traced(),
            verdicts = tracing::field::Empty
        );
        self.schedule_verification(PendingVerification {
            span,
            root: root.clone(),
            round: Round::new(self.epoch, view),
            job,
            queued_at: self.context.current(),
        })
    }

    /// Installs resolver custody and accounting released by one durable acknowledgement.
    fn acknowledged(
        &mut self,
        retention: Vec<Arc<Artifact<T::Variant, DigestOf<T>>>>,
        forwarded_nullifications: usize,
    ) -> Result<(), Fatal> {
        for artifact in retention {
            self.retain_served(&artifact, RetentionBoundary::Acknowledged)?;
        }
        self.telemetry
            .metrics
            .nullifications
            .inc_by(forwarded_nullifications as u64);
        Ok(())
    }

    /// Retires volatile publication attempts the machine discharged.
    fn retire(&mut self, retired: &[EffectId]) {
        self.egress.retire(retired);
        self.hooks.retired(retired);
        let _ = self
            .telemetry
            .metrics
            .publications
            .try_set(self.egress.len());
    }

    /// Executes one durable effect the machine released for execution.
    pub(crate) fn execute_released(
        &mut self,
        job: DurableJob<T::Variant, DigestOf<T>>,
        root: &Span,
    ) -> Result<(), Fatal> {
        let (issued, effect) = job.into_parts();
        let (id, generation) = (issued.id(), issued.generation());
        self.hooks.issued(id, generation, &effect);
        match effect {
            DurableEffect::Sign(effect) if effect.requests().len() == 1 => {
                let requests = Arc::clone(effect.shared());
                let request = &requests[0];
                // Signing detaches like assembly and recovery: the loop keeps draining ingress
                // while the critical pool signs, and the completion re-enters as a crypto result.
                let span = info_span!(
                    "multimmit.voter.sign",
                    epoch = self.epoch.get().traced(),
                    view = tracing::field::Empty,
                    id = id.get().traced(),
                    generation = generation.get().traced(),
                    kind = request.label(),
                    positions = tracing::field::Empty,
                    extensions = tracing::field::Empty,
                    certified_anchors = tracing::field::Empty
                );
                if let Some(view) = request.consensus_view() {
                    span.record("view", view.get().traced());
                }
                if let SignRequest::DaVote(vote) = request {
                    let now = self.context.current();
                    self.telemetry
                        .observe_da_vote_latency::<T::Hasher>(vote.header(), now);
                }
                self.telemetry.metrics.observe_sign_request(request, &span);
                let permit = self.reserve_crypto(TaskClass::LocalSigning, 1)?;
                self.crypto
                    .sign(permit, id, generation, requests, span, root);
            }
            DurableEffect::Sign(effect) => {
                let requests = Arc::clone(effect.shared());
                let workers = requests.len().max(1);
                let view = requests.first().and_then(SignRequest::consensus_view);
                let span = info_span!(
                    "multimmit.voter.sign.batch",
                    epoch = self.epoch.get().traced(),
                    view = tracing::field::Empty,
                    id = id.get().traced(),
                    generation = generation.get().traced(),
                    requests = requests.len().traced()
                );
                if let Some(view) = view {
                    span.record("view", view.get().traced());
                }
                let now = self.context.current();
                for request in requests.iter() {
                    if let SignRequest::DaVote(vote) = request {
                        self.telemetry
                            .observe_da_vote_latency::<T::Hasher>(vote.header(), now);
                    }
                }
                // The batch is all-or-nothing and order preserving; any failure is fatal before a
                // completion is constructed. Signatures are independent, so the batch fans out
                // across the critical pool.
                let permit = self.reserve_crypto(TaskClass::LocalSigning, workers)?;
                self.crypto
                    .sign_batch(permit, id, generation, requests, span, root);
            }
            DurableEffect::Publish(Publication::Broadcast(artifacts)) => {
                self.broadcast(id, generation, &artifacts)?;
            }
            DurableEffect::Publish(Publication::Propose(publication)) => {
                let transmission = self.egress.frame_proposal(&publication);
                self.install(id, generation, vec![transmission])?;
            }
            DurableEffect::Publish(Publication::Send(requests)) => {
                self.send(id, generation, &requests)?;
            }
        }
        Ok(())
    }

    /// Frames `artifacts` for every connected peer and installs them as one publication.
    fn broadcast(
        &mut self,
        id: EffectId,
        generation: Generation,
        artifacts: &[Arc<Artifact<T::Variant, DigestOf<T>>>],
    ) -> Result<(), Fatal> {
        let mut transmissions = Vec::with_capacity(artifacts.len());
        for artifact in artifacts {
            transmissions.push(self.frame(artifact, None)?);
        }
        self.install(id, generation, transmissions)
    }

    /// Frames each request's artifact for its recipient and installs them as one publication.
    fn send(
        &mut self,
        id: EffectId,
        generation: Generation,
        requests: &[SendRequest<T::Variant, DigestOf<T>>],
    ) -> Result<(), Fatal> {
        let mut transmissions = Vec::with_capacity(requests.len());
        for request in requests {
            let recipient = self.recipient(request.recipient())?;
            transmissions.push(self.frame(request.artifact(), Some(recipient))?);
        }
        self.install(id, generation, transmissions)
    }

    /// Returns the identity of committee member `participant`.
    fn recipient(&self, participant: Participant) -> Result<T::PublicKey, Fatal> {
        self.crypto
            .scheme()
            .participants()
            .get(participant.get() as usize)
            .cloned()
            .ok_or(Fatal::Step(StepError::UnauthorizedEffect))
    }

    fn execute_application(&mut self, job: AppJob<DigestOf<T>>, root: &Span) -> Result<(), Fatal> {
        match job {
            AppJob::Build(job) => {
                // Validation work never consumes this slot. The machine issues at most one build
                // at a time, so reserving it before spawning keeps local production bounded
                // without waiting.
                let permit = self.tasks.reserve_units(TaskClass::LocalBuild, 1)?;
                self.app.build(&self.context, permit, &job, root);
            }
            AppJob::Custody(job) => {
                let permit = self.tasks.reserve_units(TaskClass::LocalCustody, 1)?;
                self.app.custody(&self.context, permit, &job, root);
            }
            AppJob::CancelCustody(cancellation) => self.cancel_custody(cancellation)?,
        }
        Ok(())
    }

    fn arm_timer(&mut self, command: TimerCommand<DigestOf<T>>, root: &Span) {
        match command {
            TimerCommand::View(timer) => {
                debug!(view = timer.round().view().get(), "view timer armed");
                let now = self.context.current();
                let leader = self.leaders.leader(timer.round().view());
                let (deadline, reason) = if self.activity.is_active(leader, now) {
                    (
                        now.saturating_add_ext(timer.delay()),
                        TimeoutReason::Deadline,
                    )
                } else {
                    (now, TimeoutReason::InactiveLeader)
                };
                self.timers.arm_view(timer, deadline, reason);
            }
            TimerCommand::Production(timer) => {
                self.hooks.production_timer_armed(root);
                let deadline = self.context.current().saturating_add_ext(timer.delay());
                self.timers.arm_production(
                    timer,
                    deadline,
                    TraceContext::new(Span::current(), root.clone()),
                );
            }
        }
    }

    fn cancel_custody(&mut self, cancellation: CustodyCancellation) -> Result<(), Fatal> {
        if self.tasks.is_stale(cancellation.issued().generation()) {
            return Ok(());
        }
        self.app.cancel(cancellation.issued().id())?;
        Ok(())
    }

    fn execute_resolver(&mut self, command: ResolverCommand, root: &Span) -> Result<(), Fatal> {
        let feedback = match command {
            ResolverCommand::Resolve(job) => {
                let view = self.telemetry.round_view();
                let span = info_span!(
                    "multimmit.voter.resolve",
                    epoch = self.epoch.get().traced(),
                    view = view.get().traced(),
                    id = job.issued().id().get().traced(),
                    generation = job.issued().generation().get().traced()
                );
                self.resolver.resolve(ResolveRequest {
                    span,
                    root: root.clone(),
                    round: Round::new(self.epoch, view),
                    job,
                })
            }
            ResolverCommand::Cancel(job) => self.resolver.cancel(job),
            ResolverCommand::Reject(job) => self.resolver.reject(job),
            ResolverCommand::Prune(through) => self.resolver.prune(through),
        };
        if !feedback.accepted() {
            return Err(Fatal::Closed);
        }
        Ok(())
    }

    fn execute_crypto(
        &mut self,
        job: CryptoJob<T::Variant, DigestOf<T>>,
        root: &Span,
    ) -> Result<(), Fatal> {
        match job {
            CryptoJob::RecoverNullification(job) => {
                let round = job
                    .shares()
                    .first()
                    .expect("nullification recovery jobs contain a quorum")
                    .round();
                let span = info_span!(
                    "multimmit.voter.recover.nullification",
                    epoch = round.epoch().get().traced(),
                    view = round.view().get().traced(),
                    job = job.issued().id().get().traced(),
                    generation = job.issued().generation().get().traced()
                );
                let permit = self.reserve_crypto(TaskClass::CriticalAggregation, 1)?;
                self.crypto.recover_nullification(permit, job, span, root);
            }
            CryptoJob::AggregateVqc(job) => {
                let span = info_span!(
                    "multimmit.voter.aggregate.vqc",
                    epoch = self.epoch.get().traced(),
                    view = job.leader().view().get().traced(),
                    job = job.issued().id().get().traced(),
                    generation = job.issued().generation().get().traced()
                );
                let permit = self.reserve_crypto(TaskClass::CriticalAggregation, 1)?;
                self.crypto.aggregate(permit, job, span, root);
            }
            CryptoJob::AggregateLqc(job) => {
                let span = info_span!(
                    "multimmit.voter.aggregate.lqc",
                    epoch = self.epoch.get().traced(),
                    view = job.leader().view().get().traced(),
                    job = job.issued().id().get().traced(),
                    generation = job.issued().generation().get().traced()
                );
                let permit = self.reserve_crypto(TaskClass::CriticalAggregation, 1)?;
                self.crypto.aggregate(permit, job, span, root);
            }
        }
        Ok(())
    }

    /// Reserves worker and completion capacity for one local cryptographic operation.
    fn reserve_crypto(&mut self, class: TaskClass, units: usize) -> Result<TaskPermit, Fatal> {
        let permit = self.tasks.reserve_units(class, units)?;
        debug!(
            task = permit.id(),
            units,
            ?class,
            "reserved crypto task and completion"
        );
        Ok(permit)
    }

    /// Blocks the peers of participants the machine proved equivocated.
    fn block_participants(&mut self, participants: &[Participant]) {
        for signer in participants {
            let Some(peer) = self
                .crypto
                .scheme()
                .participants()
                .get((*signer).into())
                .cloned()
            else {
                continue;
            };
            self.blocked.inc();
            commonware_p2p::block!(self.blocker, peer, "authenticated equivocation");
        }
    }

    /// Reserves verification workers for `pending`, queueing it behind any job already waiting.
    fn schedule_verification(&mut self, pending: PendingVerification<T>) -> Result<(), Failure> {
        if !self.verification.is_empty() {
            self.enqueue_verification(pending)?;
            return self.schedule_pending_verifications();
        }
        if let Some(pending) = self.try_schedule_verification(pending)? {
            self.enqueue_verification(pending)?;
        }
        Ok(())
    }

    /// Reserves workers for `pending` and hands it to the verifier, or returns it when its task
    /// class is full.
    ///
    /// Errors are recorded on the job's own root, which may differ from the input being served.
    fn try_schedule_verification(
        &mut self,
        pending: PendingVerification<T>,
    ) -> Result<Option<PendingVerification<T>>, Failure> {
        let workers = pending.job.items().len().max(1);
        let critical = pending.job.view_critical();
        let class = if critical {
            TaskClass::CriticalVerification
        } else {
            TaskClass::BulkCrypto
        };
        let permit = match self.tasks.reserve_units(class, workers) {
            Ok(permit) => permit,
            Err(TaskError::ClassFull) => return Ok(Some(pending)),
            Err(error) => return Err((pending.root, error.into())),
        };
        let issued_at = self.context.current();
        let job = pending.job.issued().id();
        if self.verification_tasks.contains_key(&job) {
            let _ = self.finish_task(permit).at(&pending.root)?;
            return Err((pending.root, TaskError::Accounting.into()));
        }
        let wait = if critical {
            &self.telemetry.metrics.verification_wait_fast
        } else {
            &self.telemetry.metrics.verification_wait_bulk
        };
        wait.observe_between(pending.queued_at, issued_at);
        self.verification_tasks.insert(job, (permit, pending.root));
        if self
            .verifier
            .verify(pending.span, pending.round, pending.job, issued_at)
            .accepted()
        {
            return Ok(None);
        }

        let (permit, root) = self
            .verification_tasks
            .remove(&job)
            .expect("the dispatched job was just recorded");
        let _ = self.finish_task(permit).at(&root)?;
        Err((root, Fatal::VerificationClosed))
    }

    /// Queues `pending` until worker capacity frees.
    fn enqueue_verification(&mut self, pending: PendingVerification<T>) -> Result<(), Failure> {
        let urgency = pending.urgency();
        self.verification
            .push(pending, urgency)
            .map_err(|pending| (pending.root, TaskError::ClassFull.into()))
    }

    /// Tries every queued verification once, fast jobs first.
    pub(crate) fn schedule_pending_verifications(&mut self) -> Result<(), Failure> {
        let mut pass = self.verification.pass();
        while let Some(pending) = pass.next(&mut self.verification) {
            if let Some(pending) = self.try_schedule_verification(pending)? {
                pass.defer(&mut self.verification, pending);
            }
        }
        Ok(())
    }

    /// Makes one authenticated proof available after its local signature exposure floor.
    pub(crate) fn retain_served(
        &mut self,
        artifact: &Artifact<T::Variant, DigestOf<T>>,
        boundary: RetentionBoundary,
    ) -> Result<(), Fatal> {
        let Some(proof) = ViewProof::from_artifact(artifact) else {
            return Ok(());
        };
        self.retain(proof, boundary)
    }

    /// Seeds the resolver with the retention floor and every proof durable state still holds.
    pub(crate) fn seed_resolver(&mut self) -> Result<(), Fatal> {
        let (through, proofs) = self.machine.machine().resolver_seed();
        if !self.resolver.prune(through).accepted() {
            return Err(Fatal::Closed);
        }
        for proof in proofs {
            self.retain(proof, RetentionBoundary::Recovered)?;
        }
        Ok(())
    }

    fn retain(
        &mut self,
        proof: ViewProof<T::Variant, DigestOf<T>>,
        boundary: RetentionBoundary,
    ) -> Result<(), Fatal> {
        self.hooks.retained(&proof, boundary);
        if !self.resolver.retain(proof).accepted() {
            return Err(Fatal::Closed);
        }
        Ok(())
    }

    /// Frames one artifact publication.
    fn frame(
        &self,
        artifact: &Arc<Artifact<T::Variant, DigestOf<T>>>,
        recipient: Option<T::PublicKey>,
    ) -> Result<Transmission<T::PublicKey, DigestOf<T>>, Fatal> {
        self.egress
            .frame::<T::Hasher, T::Variant>(artifact, recipient)
            .ok_or(Fatal::Step(StepError::UnauthorizedEffect))
    }
}
