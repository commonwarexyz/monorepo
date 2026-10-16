//! Routing of core capabilities to the runtime pieces that execute them.

use super::{
    AtRoot as _, DigestOf, Failure, Fatal, Hooks as _, VoterTypes,
    live::Live,
    timers::instant,
    verification::{Dispatched, PendingVerification},
};
use crate::{
    multimmit::{
        actors::{
            resolver::ResolveRequest,
            voter::{
                egress::Transmission,
                tasks::{TaskClass, TaskError, TaskPermit},
            },
        },
        machine::{
            AppJob, Capabilities, Capability, CryptoJob, DurableEffect, DurableJob, EffectId,
            Generation, Publication, ResolverCommand, SignRequest, StepError, TimerCommand,
            VerifyJob,
        },
        types::Artifact,
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
                Capability::Acknowledged { retention } => self.acknowledged(retention).at(root)?,
                Capability::Released(job) => self.execute_released(job, root).at(root)?,
                Capability::Retain(artifact) => self.retain_served(&artifact).at(root)?,
                Capability::Retire(retired) => self.retire(&retired),
                Capability::Application(job) => self.execute_application(job).at(root)?,
                Capability::Crypto(job) => self.execute_crypto(job, root).at(root)?,
                Capability::Timer(command) => self.arm_timer(command),
                // Each chain plane runs on its own task; the voter hands it the machine's command
                // and never blocks on it.
                Capability::Chain(chain, command) => {
                    if let Some(plane) = self.chains.plane(chain) {
                        let _ = plane.command(command);
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

    /// Installs resolver custody released by one durable acknowledgement.
    fn acknowledged(
        &mut self,
        retention: Vec<Arc<Artifact<T::Variant, DigestOf<T>>>>,
    ) -> Result<(), Fatal> {
        for artifact in retention {
            self.retain_served(&artifact)?;
        }
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
            DurableEffect::Sign(effect) => {
                let requests = effect.into_requests();
                let workers = requests.len().max(1);
                // Signing detaches like assembly: the loop keeps draining ingress while the
                // critical pool signs, and the completion re-enters as a crypto result. The span
                // belongs to the round and follows from its cause, since a signature is often
                // reserved while an earlier one completes.
                let span = info_span!(
                    parent: self.telemetry.round_span(),
                    "multimmit.voter.sign",
                    epoch = self.epoch.get().traced(),
                    view = tracing::field::Empty,
                    id = id.get().traced(),
                    generation = generation.get().traced(),
                    kind = requests.first().map_or("empty", SignRequest::label),
                    requests = requests.len().traced()
                );
                if let Some(view) = requests.first().and_then(SignRequest::consensus_view) {
                    span.record("view", view.get().traced());
                }
                span.follows_from(Span::current());
                // The batch is all-or-nothing and order preserving; any failure is fatal before a
                // completion is constructed. Signatures are independent, so the batch fans out
                // across the critical pool.
                let permit = self.reserve_crypto(TaskClass::LocalSigning, workers)?;
                self.crypto
                    .sign(permit, id, generation, requests, span, root);
            }
            DurableEffect::Publish(Publication::Broadcast(artifacts)) => {
                self.broadcast(id, generation, &artifacts)?;
            }
            DurableEffect::Publish(Publication::Propose(publication)) => {
                let transmission = self.egress.frame_proposal(&publication);
                self.install(id, generation, vec![transmission])?;
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
            if matches!(artifact.as_ref(), Artifact::Update(_)) {
                self.telemetry
                    .metrics
                    .update_bytes
                    .observe(artifact.encoded_len() as f64);
            }
            transmissions.push(self.frame(artifact, None)?);
        }
        self.install(id, generation, transmissions)
    }

    /// Starts one application job under the current round's span.
    fn execute_application(&mut self, job: AppJob<DigestOf<T>>) -> Result<(), Fatal> {
        let round = self.round_span();
        match job {
            AppJob::Build(job) => {
                // Validation work never consumes this slot. The machine issues at most one build
                // at a time, so reserving it before spawning keeps local production bounded
                // without waiting.
                let permit = self.tasks.reserve_units(TaskClass::LocalBuild, 1)?;
                self.app.build(&self.context, permit, &job, &round);
            }
            AppJob::Custody(job) => {
                let permit = self.tasks.reserve_units(TaskClass::LocalCustody, 1)?;
                self.app.custody(&self.context, permit, &job, &round);
            }
            AppJob::Recall(header) => {
                let permit = self.tasks.reserve_units(TaskClass::LocalCustody, 1)?;
                self.app.recall(&self.context, permit, header, &round);
            }
        }
        Ok(())
    }

    fn arm_timer(&mut self, command: TimerCommand) {
        match command {
            TimerCommand::Arm { family, at } => {
                debug!(?family, at = at.millis(), "timer armed");
                self.timers.arm(family, instant(at));
            }
            TimerCommand::Cancel(family) => self.timers.cancel(family),
        }
    }

    fn execute_resolver(
        &mut self,
        command: ResolverCommand<DigestOf<T>>,
        root: &Span,
    ) -> Result<(), Fatal> {
        let feedback = match command {
            ResolverCommand::Resolve(job) => {
                let view = self.telemetry.round_view();
                let span = info_span!(
                    parent: root,
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
            ResolverCommand::SettleHeaders { chain, height } => {
                self.resolver.settle_headers(chain, height)
            }
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
        let kind = match &job {
            CryptoJob::AggregateVqc(_) => "vqc",
            CryptoJob::AggregateLqc(_) => "lqc",
        };
        let span = info_span!(
            "multimmit.voter.aggregate",
            epoch = self.epoch.get().traced(),
            view = job.view().get().traced(),
            kind,
            generation = job.issued().generation().get().traced()
        );
        let permit = self.reserve_crypto(TaskClass::CriticalAggregation, 1)?;
        self.crypto.aggregate(permit, job, span, root);
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
        self.verification_tasks
            .insert(job, Dispatched::new(&pending, permit));
        if self
            .verifier
            .verify(pending.span, pending.round, pending.job, issued_at)
            .accepted()
        {
            return Ok(None);
        }

        let Dispatched { permit, root, .. } = self
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

    /// Makes one authenticated artifact servable to peers.
    pub(crate) fn retain_served(
        &mut self,
        artifact: &Arc<Artifact<T::Variant, DigestOf<T>>>,
    ) -> Result<(), Fatal> {
        if !self.resolver.retain(Arc::clone(artifact)).accepted() {
            return Err(Fatal::Closed);
        }
        Ok(())
    }

    /// Seeds the resolver with the retention floor, every proof durable state still holds, and this
    /// node's latest votes.
    pub(crate) fn seed_resolver(&mut self) -> Result<(), Fatal> {
        let (through, artifacts) = self.machine.machine().resolver_seed();
        if !self.resolver.prune(through).accepted() {
            return Err(Fatal::Closed);
        }
        for artifact in artifacts {
            self.retain_served(&Arc::new(artifact))?;
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
