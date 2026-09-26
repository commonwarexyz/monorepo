//! The running voter: one loop that admits runtime inputs and drives the core.

use super::{
    AtRoot as _, DigestOf, Failure, Fatal, Finished, Hooks as _, Planes, VoterTypes,
    app::{AppExecutor, AppOutcome, AppResult, Custody},
    chains::ChainTasks,
    crypto::{CryptoExecutor, CryptoOutcome, CryptoResult},
    persist::Persistence,
    record_fatal,
    sources::{Arm, ObservedBatch, Probe, ReadinessCursor, RuntimeEvent, Source},
    timers::{ArmedProduction, Timers},
    verification::{PendingVerification, VerificationQueue},
};
use crate::{
    Epochable as _, Reporter as _,
    multimmit::{
        actors::{
            ingress, resolver, verifier,
            voter::{
                VoterLimits,
                egress::Egress,
                mailbox::{Completed, Inbox, Message, Observed, Query},
                tasks::{TaskError, TaskPermit, TaskReservations},
                telemetry::{
                    Correlation, PeerActivity, Telemetry, TraceContext, metrics::ViewProofKind,
                    round_timeout_span,
                },
            },
        },
        config::LeaderSchedule,
        machine::{
            BuildCompletion, Capabilities, CoreError, CoreState, CoreTurn, CryptoCompletion,
            CustodyCancellation, CustodyCompletion, EffectCompletion, Generation,
            IdentifiedArtifact, Input, InputTicket, Issued, JobId, PollResult, StepStatus,
            ViewTimer,
        },
        types::{Activity, Artifact},
    },
    types::{Epoch, Participant, Round, View},
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::Sender;
use commonware_runtime::{
    Clock as _, Spawner as _,
    telemetry::{
        metrics::{Counter, GaugeExt as _, Histogram, HistogramExt as _},
        traces::TracedExt as _,
    },
    utils::reschedule,
};
use commonware_utils::{SystemTimeExt as _, ordered::Quorum as _};
use std::{collections::BTreeMap, mem::size_of_val, sync::Arc, task::Poll};
use tracing::{Span, debug, debug_span, info_span};

/// An inspection query the voter accepted but has not answered.
pub(crate) enum PendingInspection<D: Digest> {
    /// Answered after at most one input that is already ready.
    Deferred(Query<D>),
    /// Answered on the next selection.
    Due(Query<D>),
}

/// Whether the voter keeps running after an input.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Disposition {
    Continue,
    Stop,
}

/// All state owned by one running voter.
pub(crate) struct Live<T: VoterTypes, S> {
    pub(crate) context: T::Context,
    pub(crate) machine: CoreState<T::Hasher, T::Variant>,
    /// Worker and completion permits of every task the voter runs.
    pub(crate) tasks: TaskReservations,
    pub(crate) epoch: Epoch,
    pub(crate) leaders: LeaderSchedule,
    pub(crate) participant: Option<Participant>,
    pub(crate) limits: VoterLimits,

    pub(crate) inbox: Inbox<T::PublicKey, T::Variant, DigestOf<T>>,
    /// A queued cohort that did not fit the last merged step; it leads the next one.
    pub(crate) carried_observation: Option<Observed<T::PublicKey, T::Variant, DigestOf<T>>>,
    /// Most artifacts one merged observation step may carry: the machine's verification batch.
    pub(crate) observation_batch: usize,
    pub(crate) pending_inspection: Option<PendingInspection<DigestOf<T>>>,

    pub(crate) persistence: Persistence<T::Hasher, T::Variant>,

    pub(crate) crypto: CryptoExecutor<T>,
    pub(crate) app: AppExecutor<T>,
    pub(crate) verification: VerificationQueue<PendingVerification<T>>,
    /// Verification jobs retain their affine permits until the verifier returns them.
    pub(crate) verification_tasks: BTreeMap<JobId, (TaskPermit, Span)>,
    pub(crate) timers: Timers<DigestOf<T>>,

    pub(crate) egress: Egress<T::PublicKey, DigestOf<T>>,
    pub(crate) relay: T::Relay,
    pub(crate) planes: Planes<S>,
    pub(crate) ingress: ingress::Mailbox,
    pub(crate) verifier: verifier::Mailbox<T::Variant, DigestOf<T>>,
    pub(crate) resolver: resolver::Mailbox<T::Variant, DigestOf<T>>,
    /// Blocks participants the machine proves equivocated.
    pub(crate) blocker: T::Blocker,
    /// Peers blocked for authenticated equivocation.
    pub(crate) blocked: Counter,
    pub(crate) reporter: T::Reporter,

    pub(crate) chains: ChainTasks<T>,

    pub(crate) telemetry: Telemetry<DigestOf<T>>,
    pub(crate) activity: PeerActivity,
    pub(crate) correlation: Correlation,
    pub(crate) hooks: T::Hooks,
}

impl<T, S> Live<T, S>
where
    T: VoterTypes,
    S: Sender<PublicKey = T::PublicKey>,
{
    /// Admits runtime inputs and drives the core until the runtime stops or a fatal error.
    pub(crate) async fn run(mut self) {
        let mut cursor = ReadinessCursor::default();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping voter");
            },
            event = self.next_event(&mut cursor) => {
                if let Some(event) = event {
                    match self.handle_runtime_burst(event, &mut cursor) {
                        Ok(Disposition::Continue) => {}
                        Ok(Disposition::Stop) => break,
                        Err((root, fatal)) => {
                            record_fatal(&self.telemetry.metrics, &root, &fatal);
                            break;
                        }
                    }
                }
                if let Err((root, fatal)) = self.drive_core_cycle().await {
                    record_fatal(&self.telemetry.metrics, &root, &fatal);
                    break;
                }
            },
        }
        self.shutdown_tasks();
    }

    /// Returns the current view's root span.
    pub(crate) fn round_span(&self) -> Span {
        self.telemetry.round_span().clone()
    }

    /// Applies one runtime input and then every other ready input that competes with it.
    ///
    /// Inputs of the first input's lane are skipped until an input of another lane arrives, so a
    /// busy lane cannot keep the core from seeing the others before it runs.
    pub(crate) fn handle_runtime_burst(
        &mut self,
        first: RuntimeEvent<T::PublicKey, T::Variant, DigestOf<T>>,
        cursor: &mut ReadinessCursor,
    ) -> Result<Disposition, Failure> {
        let mut next = Some(first);
        let mut first_lane = None;
        let mut competing_lanes = false;
        while let Some(event) = next {
            let lane = event.core_lane();
            if self.handle_runtime_event(event)? == Disposition::Stop {
                return Ok(Disposition::Stop);
            }
            let Some(lane) = lane else {
                break;
            };
            let initial = *first_lane.get_or_insert(lane);
            competing_lanes |= lane != initial;
            if self.pending_inspection.is_none()
                && let Poll::Ready(query) = self.poll_arm(Arm::Inspection, &mut Probe::Now)
            {
                cursor.advance_past(Source::Inspection);
                self.handle_runtime_event(query)?;
                break;
            }
            next = self.scan(cursor, (!competing_lanes).then_some(initial));
        }
        Ok(Disposition::Continue)
    }

    /// Applies one runtime input to the core.
    pub(crate) fn handle_runtime_event(
        &mut self,
        event: RuntimeEvent<T::PublicKey, T::Variant, DigestOf<T>>,
    ) -> Result<Disposition, Failure> {
        match event {
            RuntimeEvent::Persistence(output) => self.persisted(output)?,
            RuntimeEvent::PersistenceCapacity(result) => {
                result.at(self.telemetry.round_span())?;
            }
            RuntimeEvent::Application(finished) => self.application_completed(finished)?,
            RuntimeEvent::Crypto(finished) => self.crypto_completed(finished)?,
            RuntimeEvent::ChainTask(update) => {
                let root = self.round_span();
                root.in_scope(|| self.chain_update(update)).at(&root)?;
            }
            RuntimeEvent::ViewTimer => {
                let armed = self.timers.take_view().expect("armed timer fired");
                self.submit_view_timeout(armed.timer, armed.reason.as_str())
                    .at(self.telemetry.round_span())?;
            }
            RuntimeEvent::ProductionTimer => {
                let armed = self.timers.take_production().expect("armed timer fired");
                let root = armed.trace.root.clone();
                self.submit_production_timeout(armed).at(&root)?;
            }
            RuntimeEvent::Publication => self.publish_due().at(self.telemetry.round_span())?,
            RuntimeEvent::Heartbeat => {
                let now = self.context.current();
                self.timers
                    .set_heartbeat(now.saturating_add_ext(self.limits.heartbeat));
                self.telemetry.update_chains(&self.machine);
                self.telemetry.report_stall(now, self.limits.heartbeat);
            }
            RuntimeEvent::Verification(completed) => self.ingest_completed(completed)?,
            RuntimeEvent::Resolution(message) => self.ingest_message(message)?,
            RuntimeEvent::Inspection(query) => {
                debug_assert!(self.pending_inspection.is_none());
                self.pending_inspection = Some(PendingInspection::Deferred(query));
            }
            RuntimeEvent::Observation(observed) => {
                self.ingest_observed(observed)
                    .at(self.telemetry.round_span())?;
            }
            RuntimeEvent::InputClosed => return Ok(Disposition::Stop),
        }
        Ok(Disposition::Continue)
    }

    /// Serves staged inputs and at most one unit of machine work, then yields to other tasks.
    pub(crate) async fn drive_core_cycle(&mut self) -> Result<(), Failure> {
        self.hooks.cycle_started();
        let started = self.context.current();
        let mut yielded = false;
        loop {
            if !self.persistence.has_capacity() {
                break;
            }
            if self.persistence_receivable()
                && let Poll::Ready(completion) = self.poll_arm(Arm::Persistence, &mut Probe::Now)
            {
                self.handle_runtime_event(completion)?;
            }
            let span = self.round_span();
            let vote_build = &mut self.telemetry.vote_build;
            let action = span
                .in_scope(|| {
                    self.machine.next_action(|machine| {
                        // A pass the poll begins gets its span now, so the span covers the poll.
                        if !span.is_disabled() && machine.vote_build_due() {
                            let protocol = machine.profile().protocol();
                            vote_build.open(
                                Round::new(protocol.epoch(), machine.view()),
                                protocol.codec_config().extension_bound(),
                            );
                        }
                    })
                })
                .at(&span)?;
            match action {
                CoreTurn::YieldRequired => {
                    self.telemetry.record_busy(started, self.context.current());
                    reschedule().await;
                    yielded = true;
                    self.telemetry
                        .round_span()
                        .in_scope(|| self.machine.resume_after_yield())
                        .at(&span)?;
                    self.hooks.resumed();
                    break;
                }
                CoreTurn::Input(serviced) => {
                    self.hooks.serviced(&serviced);
                    if serviced.observed_items > 0 {
                        self.correlation
                            .admit_observations(
                                &self.telemetry.metrics,
                                serviced.transition.status(),
                                serviced.ticket,
                                serviced.observed_items,
                                serviced.final_chunk,
                            )
                            .at(&span)?;
                    }
                    let input = self.correlation.context(serviced.ticket).at(&span)?;
                    if let Some((source, kind)) = input.view_proof
                        && let StepStatus::ResolutionCompleted { admission } =
                            serviced.transition.status()
                    {
                        self.telemetry
                            .metrics
                            .admit_view_proof(source, kind, *admission);
                    }
                    let root = &input.root;
                    input.span.in_scope(|| {
                        self.hooks.dispatching(root, self.telemetry.round_view());
                        self.on_generation(self.machine.machine().generation())
                            .at(root)?;
                        if matches!(serviced.transition.status(), StepStatus::StaleCompletion) {
                            self.telemetry.metrics.stale.inc();
                        }
                        let (capabilities, activities) = serviced.transition.into_parts();
                        self.apply(capabilities, activities, root)
                    })?;
                    if serviced.final_chunk {
                        self.correlation.consumed(serviced.ticket).at(root)?;
                    }
                    let span = self.round_span();
                    span.in_scope(|| self.maybe_checkpoint()).at(&span)?;
                }
                CoreTurn::Work(work) => {
                    span.in_scope(|| self.dispatch_work(work, &span))?;
                    break;
                }
                CoreTurn::Idle => {
                    span.in_scope(|| self.maybe_checkpoint()).at(&span)?;
                    break;
                }
            }
        }
        if !yielded {
            self.telemetry.record_busy(started, self.context.current());
            reschedule().await;
        }
        Ok(())
    }

    fn dispatch_work(
        &mut self,
        work: PollResult<T::Variant, DigestOf<T>>,
        root: &Span,
    ) -> Result<(), Failure> {
        self.hooks.working(root, self.telemetry.round_view());
        let PollResult {
            capabilities,
            activities,
            vote_builds,
            ..
        } = work;
        self.telemetry.vote_build.observe(vote_builds);
        self.apply(capabilities, activities, root)?;
        self.maybe_checkpoint().at(root)
    }

    /// Executes one core step's capabilities, reports its activities, and refreshes progress.
    fn apply(
        &mut self,
        capabilities: Capabilities<T::Variant, DigestOf<T>>,
        activities: Vec<Activity<T::Variant, DigestOf<T>>>,
        root: &Span,
    ) -> Result<(), Failure> {
        self.execute_capabilities(capabilities, root)?;
        self.report_activities(activities);
        self.update_progress();
        Ok(())
    }

    /// Exports retention and progress gauges and moves the round span to the current view.
    pub(crate) fn update_progress(&mut self) {
        let now = self.context.current();
        self.telemetry
            .update_retention(&self.machine, self.persistence.ledger().events());
        let view = self
            .telemetry
            .update_progress(&self.machine, &self.tasks, now);
        let _ = self
            .telemetry
            .metrics
            .view_timer_armed
            .try_set(usize::from(self.timers.view_armed()));
        self.telemetry.refresh_round(view, now);
    }

    fn report_activities(&mut self, activities: Vec<Activity<T::Variant, DigestOf<T>>>) {
        for activity in activities {
            if let Activity::LeaderFinalized { fact } | Activity::LeaderFinalityUpdated { fact } =
                &activity
            {
                let _finality = info_span!(
                    "multimmit.voter.finality",
                    epoch = fact.round().epoch().get().traced(),
                    view = fact.round().view().get().traced(),
                    votes = fact.votes().traced(),
                    updated = matches!(&activity, Activity::LeaderFinalityUpdated { .. }),
                    settled_chains = fact
                        .settled()
                        .iter()
                        .filter(|settled| **settled)
                        .count()
                        .traced(),
                    extension_blocks = fact
                        .blocks()
                        .iter()
                        .zip(fact.proposed())
                        .map(|(block, proposed)| {
                            block.height().get().saturating_sub(proposed.get())
                        })
                        .fold(0u64, u64::saturating_add)
                        .traced(),
                );
            }
            let _ = self.reporter.report(activity);
        }
    }

    /// Stages one transition in the core and records the trace context that owns it.
    pub(crate) fn track_transition(
        &mut self,
        transition: impl FnOnce(&mut CoreState<T::Hasher, T::Variant>) -> Result<InputTicket, CoreError>,
        root: &Span,
    ) -> Result<InputTicket, Fatal> {
        let ticket = transition(&mut self.machine)?;
        self.correlation
            .track(ticket, TraceContext::new(Span::current(), root.clone()))?;
        Ok(ticket)
    }

    /// Stages one transition whose terminal errors belong to the round.
    pub(crate) fn track_in_round(
        &mut self,
        transition: impl FnOnce(&mut CoreState<T::Hasher, T::Variant>) -> Result<InputTicket, CoreError>,
    ) -> Result<InputTicket, Fatal> {
        let root = self.round_span();
        self.track_transition(transition, &root)
    }

    fn submit_view_timeout(&mut self, timer: ViewTimer, reason: &'static str) -> Result<(), Fatal> {
        let round = timer.round();
        let view = round.view();
        debug!(view = view.get(), reason, "view timer fired");
        self.telemetry.metrics.view_timeouts.inc();
        let span = round_timeout_span(self.telemetry.round_span(), round);
        span.record("reason", reason);
        span.in_scope(|| {
            self.track_in_round(|core| core.enqueue(Input::TimerFired(timer)))?;
            Ok(())
        })
    }

    fn submit_production_timeout(
        &mut self,
        armed: ArmedProduction<DigestOf<T>>,
    ) -> Result<(), Fatal> {
        let ArmedProduction { timer, trace, .. } = armed;
        self.telemetry.metrics.production_stalls.inc();
        let parent = timer.parent();
        let span = info_span!(
            parent: &trace.span,
            "multimmit.voter.production.timeout",
            epoch = self.epoch.get().traced(),
            chain = parent.chain().get().traced(),
            height = parent.height().get().traced()
        );
        span.in_scope(|| {
            self.track_transition(
                |core| core.enqueue(Input::ProductionTimerFired(timer)),
                &trace.root,
            )?;
            Ok(())
        })
    }

    /// Moves runtime work to a new process generation: cancels the previous generation's tasks
    /// and timers, then starts or reconfigures the chain tasks.
    fn on_generation(&mut self, generation: Generation) -> Result<(), Fatal> {
        if generation <= self.tasks.generation() {
            return Ok(());
        }
        self.clear_generation_runtime();
        self.timers.clear();
        self.tasks.advance_generation(generation)?;
        self.chains.enter(generation, &self.machine);
        Ok(())
    }

    /// Cancels actor-owned work and correlations tied to the current task generation.
    fn clear_generation_runtime(&mut self) {
        self.app.cancel_all();
        self.crypto.cancel_all();
        self.verification_tasks.clear();
        self.verification.clear();
    }

    /// Returns one affine capacity permit to the task ledger, or `false` when the permit was
    /// stale.
    ///
    /// Prior-generation permits are stale completions, not epoch failures.
    pub(crate) fn finish_task(&mut self, permit: TaskPermit) -> Result<bool, Fatal> {
        if self.tasks.is_stale(permit.generation()) {
            self.telemetry.metrics.stale.inc();
            return Ok(false);
        }
        match self.tasks.finish(permit) {
            Ok(()) => Ok(true),
            Err(TaskError::StaleGeneration | TaskError::UnknownPermit) => {
                self.telemetry.metrics.stale.inc();
                Ok(false)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Cancels every runtime task and releases its task accounting.
    pub(crate) fn shutdown_tasks(&mut self) {
        self.clear_generation_runtime();
        self.tasks.shutdown();
    }

    /// Commits one completed build or custody job to protocol state.
    fn application_completed(
        &mut self,
        finished: Finished<AppResult<DigestOf<T>>>,
    ) -> Result<(), Failure> {
        let Finished {
            permit,
            trace,
            outcome,
        } = finished;
        trace
            .span
            .in_scope(|| self.application_outcome(permit, &trace, outcome))
            .at(&trace.root)
    }

    fn application_outcome(
        &mut self,
        permit: TaskPermit,
        trace: &TraceContext,
        outcome: AppResult<DigestOf<T>>,
    ) -> Result<(), Fatal> {
        let Ok(outcome) = outcome else {
            if !self.finish_task(permit)? {
                return Ok(());
            }
            return Err(Fatal::Automaton);
        };
        match outcome {
            AppOutcome::Built {
                started_at,
                id,
                generation,
                parent,
                result,
            } => {
                if !self.finish_task(permit)? {
                    return Ok(());
                }
                let metrics = &self.telemetry.metrics;
                metrics
                    .build_latency
                    .observe_between(started_at, self.context.current());
                if result.is_some() {
                    metrics.builds.inc();
                } else {
                    metrics.build_declines.inc();
                }
                let completed = info_span!(parent: &trace.span, "multimmit.voter.produce.complete");
                completed.in_scope(|| {
                    let completion =
                        BuildCompletion::new(Issued::new(id, generation), parent, result);
                    self.track_transition(
                        |core| core.enqueue(Input::BlockBuilt(completion)),
                        &trace.root,
                    )?;
                    Ok(())
                })
            }
            AppOutcome::Custodied {
                id,
                generation,
                header,
                verdict,
            } => {
                let cancel_requested = self.app.cancel_requested(id);
                if !self.finish_task(permit)? {
                    return Ok(());
                }
                let custody = self.app.finish_custody(id)?;
                if matches!(custody, Custody::CancelRequested) != cancel_requested {
                    return Err(TaskError::Accounting.into());
                }
                if cancel_requested {
                    let cancellation = CustodyCancellation::new(Issued::new(id, generation));
                    self.track_transition(
                        |core| core.enqueue(Input::CustodyCancelled(cancellation)),
                        &trace.root,
                    )?;
                    return Ok(());
                }
                if verdict != Some(true) {
                    return Err(Fatal::Automaton);
                }
                let completed = info_span!(parent: &trace.span, "multimmit.voter.custody.complete");
                completed.in_scope(|| {
                    let completion = CustodyCompletion::new(Issued::new(id, generation), header);
                    self.track_transition(
                        |core| core.enqueue(Input::BlockCustodied(completion)),
                        &trace.root,
                    )?;
                    Ok(())
                })
            }
            AppOutcome::CustodyCancelled { cancellation } => {
                if !self.finish_task(permit)? {
                    return Ok(());
                }
                if matches!(
                    self.app.finish_custody(cancellation.issued().id())?,
                    Custody::Running(_)
                ) {
                    return Err(TaskError::Accounting.into());
                }
                self.track_transition(
                    |core| core.enqueue(Input::CustodyCancelled(cancellation)),
                    &trace.root,
                )?;
                Ok(())
            }
        }
    }

    /// Reconciles one finished cryptographic operation and admits its result.
    fn crypto_completed(
        &mut self,
        finished: Finished<CryptoResult<T::Variant, DigestOf<T>>>,
    ) -> Result<(), Failure> {
        let Finished {
            permit,
            trace,
            outcome,
        } = finished;
        let root = &trace.root;
        let Ok(outcome) = outcome else {
            if !self.finish_task(permit).at(root)? {
                return Ok(());
            }
            return Err((root.clone(), Fatal::CryptoTaskPanicked));
        };
        if !self.finish_task(permit).at(root)? {
            return Ok(());
        }
        let _span = trace.span.enter();
        match outcome.at(root)? {
            CryptoOutcome::Signed {
                id,
                generation,
                artifact,
            } => {
                self.track_transition(
                    |core| {
                        core.enqueue(Input::EffectCompleted(EffectCompletion::signed(
                            Issued::new(id, generation),
                            vec![artifact],
                        )))
                    },
                    root,
                )
                .at(root)?;
            }
            CryptoOutcome::SignedBatch {
                id,
                generation,
                artifacts,
            } => {
                self.track_transition(
                    |core| {
                        core.enqueue(Input::EffectCompleted(EffectCompletion::signed(
                            Issued::new(id, generation),
                            artifacts.into_iter().map(Arc::new).collect(),
                        )))
                    },
                    root,
                )
                .at(root)?;
            }
            CryptoOutcome::NullificationRecovered {
                started_at,
                completion,
            } => {
                self.telemetry
                    .metrics
                    .nullification_recovery_latency
                    .observe_between(started_at, self.context.current());
                self.track_transition(
                    |core| core.enqueue(Input::Crypto(CryptoCompletion::Nullification(completion))),
                    root,
                )
                .at(root)?;
            }
            CryptoOutcome::VqcAggregated { view, completion } => {
                let certificate = completion.certificate();
                self.record_qc(
                    view,
                    &self.telemetry.metrics.vqc_latency,
                    certificate.tally().deviations().len(),
                    certificate.encode_size(),
                );
                self.track_transition(
                    |core| core.enqueue(Input::Crypto(CryptoCompletion::Vqc(completion))),
                    root,
                )
                .at(root)?;
            }
            CryptoOutcome::LqcAggregated { view, completion } => {
                let certificate = completion.certificate();
                self.record_qc(
                    view,
                    &self.telemetry.metrics.lqc_latency,
                    certificate.tally().deviations().len(),
                    certificate.encode_size(),
                );
                self.track_transition(
                    |core| core.enqueue(Input::Crypto(CryptoCompletion::Lqc(completion))),
                    root,
                )
                .at(root)?;
            }
        }
        Ok(())
    }

    /// Records the formation latency, deviation count, and size of one local certificate.
    ///
    /// Formation latency is only meaningful to the view's leader.
    fn record_qc(&self, view: View, latency: &Histogram, deviations: usize, bytes: usize) {
        if self.participant == Some(self.leaders.leader(view)) {
            self.telemetry
                .observe_since_view_start(view, latency, self.context.current());
        }
        let metrics = &self.telemetry.metrics;
        metrics.qc_deviations.observe(deviations as f64);
        metrics.qc_bytes.observe(bytes as f64);
    }

    /// Ingests one verification completion from the verifier.
    fn ingest_completed(
        &mut self,
        completed: Completed<T::Variant, DigestOf<T>>,
    ) -> Result<(), Failure> {
        let Completed { span, completion } = completed;
        let _process = info_span!(parent: &span, "multimmit.voter.verify.process").entered();
        if self.tasks.is_stale(completion.issued().generation()) {
            self.telemetry.metrics.stale.inc();
            return Ok(());
        }
        let Some((permit, root)) = self.verification_tasks.remove(&completion.issued().id()) else {
            self.telemetry.metrics.stale.inc();
            return Ok(());
        };
        if !self.finish_task(permit).at(&root)? {
            return Ok(());
        }
        self.schedule_pending_verifications()?;
        span.record("verdicts", completion.verdicts().len().traced());
        self.track_transition(|core| core.enqueue(Input::Verified(completion)), &root)
            .at(&root)?;
        Ok(())
    }

    /// Stages one observed batch in the core and binds the view-proof kinds it carries.
    fn observe_network(
        &mut self,
        artifacts: Vec<IdentifiedArtifact<T::Variant, DigestOf<T>>>,
        artifact_bytes: usize,
    ) -> Result<(), Fatal> {
        let arrived_at = self.context.current();
        for identified in &artifacts {
            if let Artifact::TransactionBlock(block) = &identified.artifact {
                self.telemetry
                    .record_arrival(block.header().block_ref::<T::Hasher>(), arrived_at);
            }
        }
        let mut proof_kinds = artifacts
            .iter()
            .map(|identified| ViewProofKind::of(&identified.artifact))
            .collect::<Vec<_>>();
        // The ingress actor measured each artifact's encoded length at admission.
        let resident_bytes = artifacts
            .iter()
            .try_fold(artifact_bytes, |total, identified| {
                total.checked_add(identified.id.encode_size())
            })
            .and_then(|bytes| bytes.checked_add(size_of_val(proof_kinds.as_slice())))
            .ok_or(CoreError::CapacityOverflow)?;
        debug_assert_eq!(
            artifact_bytes,
            artifacts
                .iter()
                .map(|identified| identified.artifact.encoded_len())
                .sum::<usize>(),
            "the cohort's measured weight matches its artifacts"
        );
        proof_kinds.reverse();
        let ticket = self.track_in_round(|core| core.observe(artifacts, resident_bytes))?;
        self.correlation.observed(ticket, proof_kinds)?;
        Ok(())
    }

    /// Ingests one peer observation batch.
    fn ingest_observed(
        &mut self,
        batch: ObservedBatch<T::PublicKey, T::Variant, DigestOf<T>>,
    ) -> Result<(), Fatal> {
        let ObservedBatch {
            artifacts,
            spans,
            cohorts,
            forwarded_at,
            bytes,
        } = batch;
        let now = self.context.current();
        self.telemetry
            .metrics
            .observation_wait
            .observe_between(forwarded_at, now);
        for (source, _) in &artifacts {
            if let Some(participant) = self.crypto.scheme().participants().index(source) {
                self.activity.observe(participant, now);
            }
        }
        let artifacts = artifacts
            .into_iter()
            .map(|(_, artifact)| artifact)
            .collect();
        let observe = debug_span!(
            parent: self.telemetry.round_span(),
            "multimmit.voter.observe",
            epoch = self.epoch.get().traced(),
            view = self.telemetry.round_view().get().traced(),
            cohorts
        );
        for span in &spans {
            observe.follows_from(span.id());
        }
        observe.in_scope(|| self.observe_network(artifacts, bytes))?;
        if !self.ingress.consumed(cohorts).accepted() {
            return Err(Fatal::Closed);
        }
        Ok(())
    }

    /// Ingests one resolver completion.
    fn ingest_message(&mut self, message: Message<T::Variant, DigestOf<T>>) -> Result<(), Failure> {
        let Message::Resolution {
            span,
            root,
            round,
            completion,
        } = message;
        let kind = ViewProofKind::from(completion.proof());
        let resolved = info_span!(
            parent: &span,
            "multimmit.voter.resolve.complete",
            epoch = round.epoch().get().traced(),
            view = round.view().get().traced()
        );
        resolved
            .in_scope(|| {
                let ticket = self.track_transition(
                    |core| core.enqueue(Input::ResolutionCompleted(completion)),
                    &root,
                )?;
                self.correlation.resolved(ticket, kind)?;
                Ok::<_, Fatal>(())
            })
            .at(&root)
    }

    /// Answers one inspection query with the machine's current projection.
    pub(crate) fn answer_inspection(&self, query: Query<DigestOf<T>>) {
        let Query::Inspect { responder } = query;
        let _ = responder.send(self.machine.machine().inspect());
    }
}
