//! The running voter: one loop that admits runtime inputs and drives the core.

use super::{
    AtRoot as _, DigestOf, Failure, Fatal, Finished, Planes, VoterTypes,
    app::{AppExecutor, AppOutcome, AppResult},
    chains::ChainTasks,
    crypto::{CryptoExecutor, CryptoOutcome, CryptoResult},
    persist::Persistence,
    record_fatal,
    sources::{Arm, ObservedBatch, Probe, ReadinessCursor, RuntimeEvent, Source},
    timers::Timers,
    verification::{Dispatched, PendingVerification, Urgency, VerificationQueue},
};
use crate::{
    Reporter as _,
    multimmit::{
        actors::{
            ingress, resolver, verifier,
            voter::{
                VoterLimits,
                egress::Egress,
                mailbox::{Completed, Inbox, Message, Observed, Query},
                tasks::{TaskError, TaskPermit, TaskReservations},
                telemetry::{Correlation, Telemetry, TraceContext, metrics::ViewProofKind},
            },
        },
        machine::{
            BuildCompletion, Capabilities, CoreError, CoreState, CoreTurn, CryptoCompletion,
            CustodyCompletion, EffectCompletion, Generation, IdentifiedArtifact, Input,
            InputTicket, Issued, JobId, Now, PollResult, StepStatus, TimerFamily,
        },
        types::Activity,
    },
    types::{Epoch, Participant},
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::Sender;
use commonware_runtime::{
    Clock as _, Spawner as _,
    telemetry::{
        metrics::{Counter, GaugeExt as _, HistogramExt as _},
        traces::TracedExt as _,
    },
    utils::reschedule,
};
use commonware_utils::SystemTimeExt as _;
use std::{
    collections::BTreeMap,
    mem::size_of_val,
    task::Poll,
    time::{Duration, SystemTime},
};
use tracing::{Span, debug, debug_span, error, info_span};

/// An inspection query the voter accepted but has not answered.
pub(crate) enum PendingInspection<D: Digest> {
    /// Answered after at most one input that is already ready.
    Deferred(Query<D>),
    /// Answered on the next selection.
    Due(Query<D>),
}

/// Whether the voter keeps running after an input.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Continuation {
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
    pub(crate) participant: Option<Participant>,
    pub(crate) limits: VoterLimits,

    pub(crate) inbox: Inbox<T::Variant, DigestOf<T>>,
    /// A queued cohort that did not fit the last merged step; it leads the next one.
    pub(crate) carried_observation: Option<Observed<T::Variant, DigestOf<T>>>,
    /// Most artifacts one merged observation step may carry: the machine's verification batch.
    pub(crate) observation_batch: usize,
    pub(crate) pending_inspection: Option<PendingInspection<DigestOf<T>>>,

    pub(crate) persistence: Persistence<T::Hasher, T::Variant>,

    pub(crate) crypto: CryptoExecutor<T>,
    pub(crate) app: AppExecutor<T>,
    pub(crate) verification: VerificationQueue<PendingVerification<T>>,
    /// Verification jobs retain their affine permits until the verifier returns them.
    pub(crate) verification_tasks: BTreeMap<JobId, Dispatched>,
    pub(crate) timers: Timers,

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

    pub(crate) telemetry: Telemetry,
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
                        Ok(Continuation::Continue) => {}
                        Ok(Continuation::Stop) => break,
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

    /// Returns the machine clock reading: milliseconds since the Unix epoch.
    pub(crate) fn now(&self) -> Now {
        Now::from_millis(self.context.current().epoch_millis())
    }

    /// Applies one runtime input and then every other ready input that competes with it.
    ///
    /// Inputs of the first input's lane are skipped until an input of another lane arrives, so a
    /// busy lane cannot keep the core from seeing the others before it runs.
    pub(crate) fn handle_runtime_burst(
        &mut self,
        first: RuntimeEvent<T::Variant, DigestOf<T>>,
        cursor: &mut ReadinessCursor,
    ) -> Result<Continuation, Failure> {
        let mut next = Some(first);
        let mut first_lane = None;
        let mut competing_lanes = false;
        while let Some(event) = next {
            let lane = event.core_lane();
            if self.handle_runtime_event(event)? == Continuation::Stop {
                return Ok(Continuation::Stop);
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
        Ok(Continuation::Continue)
    }

    /// Applies one runtime input to the core.
    pub(crate) fn handle_runtime_event(
        &mut self,
        event: RuntimeEvent<T::Variant, DigestOf<T>>,
    ) -> Result<Continuation, Failure> {
        match event {
            RuntimeEvent::Persistence(output) => self.persisted(output)?,
            RuntimeEvent::PersistenceCapacity(result) => {
                result.at(self.telemetry.round_span())?;
            }
            RuntimeEvent::Application(finished) => self.application_completed(finished)?,
            RuntimeEvent::Crypto(finished) => self.crypto_completed(finished)?,
            RuntimeEvent::ChainTask(update) => {
                let root = self.round_span();
                root.in_scope(|| self.validated(update)).at(&root)?;
            }
            RuntimeEvent::Timer(family) => {
                self.fire_timer(family).at(self.telemetry.round_span())?;
            }
            RuntimeEvent::Publication => self.publish_due().at(self.telemetry.round_span())?,
            RuntimeEvent::Heartbeat => {
                let now = self.context.current();
                self.timers
                    .set_heartbeat(now.saturating_add_ext(self.limits.heartbeat));
                self.telemetry.update_chains(&self.machine);
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
            RuntimeEvent::InputClosed => return Ok(Continuation::Stop),
        }
        Ok(Continuation::Continue)
    }

    /// Serves staged inputs and at most one unit of machine work, then yields to other tasks.
    pub(crate) async fn drive_core_cycle(&mut self) -> Result<(), Failure> {
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
            let now = self.now();
            let turn_started = self.context.current();
            let action = span
                .in_scope(|| self.machine.next_action(now, |_| {}))
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
                    break;
                }
                CoreTurn::Input(serviced) => {
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
                        self.telemetry
                            .metrics
                            .service
                            .wait(serviced.lane, now.saturating_since(serviced.admitted));
                    }
                    let span = self.round_span();
                    span.in_scope(|| self.maybe_checkpoint()).at(&span)?;
                    self.telemetry
                        .metrics
                        .service
                        .input(serviced.kind, self.elapsed_since(turn_started));
                }
                CoreTurn::Work(work) => {
                    let driven = work.driven;
                    span.in_scope(|| self.dispatch_work(work, &span))?;
                    self.telemetry
                        .metrics
                        .service
                        .work(driven, self.elapsed_since(turn_started));
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
        let PollResult {
            capabilities,
            activities,
            ..
        } = work;
        self.apply(capabilities, activities, root)?;
        self.maybe_checkpoint().at(root)
    }

    /// Returns the wall time since `started`, zero when the clock stepped back.
    fn elapsed_since(&self, started: SystemTime) -> Duration {
        self.context
            .current()
            .duration_since(started)
            .unwrap_or_default()
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
            .update_retention(self.persistence.ledger().events());
        let view = self.telemetry.update_progress(&self.machine, &self.tasks);
        let _ = self
            .telemetry
            .metrics
            .view_timer_armed
            .try_set(usize::from(self.timers.armed(TimerFamily::View)));
        self.telemetry.refresh_round(view, now);
    }

    fn report_activities(&mut self, activities: Vec<Activity<T::Variant, DigestOf<T>>>) {
        for activity in activities {
            self.telemetry.metrics.record_activity(&activity);
            let _ = self.reporter.report(activity);
        }
    }

    /// Stages one transition in the core and records the trace context that owns it.
    ///
    /// The transition receives the machine clock reading the input is admitted at.
    pub(crate) fn track_transition(
        &mut self,
        transition: impl FnOnce(
            &mut CoreState<T::Hasher, T::Variant>,
            Now,
        ) -> Result<InputTicket, CoreError>,
        root: &Span,
    ) -> Result<InputTicket, Fatal> {
        let now = self.now();
        let ticket = transition(&mut self.machine, now)?;
        self.correlation
            .track(ticket, TraceContext::new(Span::current(), root.clone()))?;
        Ok(ticket)
    }

    /// Stages one transition whose terminal errors belong to the round.
    pub(crate) fn track_in_round(
        &mut self,
        transition: impl FnOnce(
            &mut CoreState<T::Hasher, T::Variant>,
            Now,
        ) -> Result<InputTicket, CoreError>,
    ) -> Result<InputTicket, Fatal> {
        let root = self.round_span();
        self.track_transition(transition, &root)
    }

    /// Disarms `family`'s due deadline and delivers its tick to the machine.
    fn fire_timer(&mut self, family: TimerFamily) -> Result<(), Fatal> {
        self.timers.cancel(family);
        debug!(?family, "timer fired");
        if family == TimerFamily::Liveness {
            self.telemetry.metrics.view_timeouts.inc();
        }
        let span = info_span!(
            parent: self.telemetry.round_span(),
            "multimmit.voter.timer",
            epoch = self.epoch.get().traced(),
            view = self.telemetry.round_view().get().traced(),
            family = ?family
        );
        span.in_scope(|| {
            self.track_in_round(|core, now| core.enqueue(Input::Tick(family), now))?;
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
        self.chains
            .enter(generation, &self.machine.machine().chain_progress());
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
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                if !self.finish_task(permit)? {
                    return Ok(());
                }
                error!(%error, "application task failed");
                return Err(Fatal::Automaton);
            }
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
                        |core, now| core.enqueue(Input::BlockBuilt(completion), now),
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
                if !self.finish_task(permit)? {
                    return Ok(());
                }
                if verdict != Some(true) {
                    error!(
                        chain = header.chain().get(),
                        height = header.height().get(),
                        ?verdict,
                        "application did not hold an own block in custody"
                    );
                    return Err(Fatal::Automaton);
                }
                let completed = info_span!(parent: &trace.span, "multimmit.voter.custody.complete");
                completed.in_scope(|| {
                    let completion = CustodyCompletion::new(Issued::new(id, generation), header);
                    self.track_transition(
                        |core, now| core.enqueue(Input::BlockCustodied(completion), now),
                        &trace.root,
                    )?;
                    Ok(())
                })
            }
            AppOutcome::Recalled { header, verdict } => {
                if !self.finish_task(permit)? {
                    return Ok(());
                }
                // A recall only lets the relay serve a body it lost in the restart; one the
                // application no longer holds is fetched by the peers that still need it.
                if verdict != Some(true) {
                    debug!(
                        chain = header.chain().get(),
                        height = header.height().get(),
                        "recalled own block is not held"
                    );
                }
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
        let input = match outcome.at(root)? {
            CryptoOutcome::Signed {
                id,
                generation,
                artifacts,
            } => Input::EffectCompleted(EffectCompletion::signed(
                Issued::new(id, generation),
                artifacts,
            )),
            CryptoOutcome::Aggregated { view, completion } => {
                let metrics = &self.telemetry.metrics;
                let (latency, size, bytes) = match &completion {
                    CryptoCompletion::Vqc(aggregated) => (
                        &metrics.vqc_latency,
                        &metrics.vqc_bytes,
                        aggregated.certificate().encode_size(),
                    ),
                    CryptoCompletion::Lqc(aggregated) => (
                        &metrics.lqc_latency,
                        &metrics.lqc_bytes,
                        aggregated.certificate().encode_size(),
                    ),
                };
                self.telemetry
                    .observe_since_view_start(view, latency, self.context.current());
                size.observe(bytes as f64);
                Input::Crypto(completion)
            }
        };
        self.track_transition(|core, now| core.enqueue(input, now), root)
            .at(root)?;
        Ok(())
    }

    /// Ingests one verification completion from the verifier.
    fn ingest_completed(&mut self, completed: Completed<DigestOf<T>>) -> Result<(), Failure> {
        let Completed { span, completion } = completed;
        let _process = info_span!(parent: &span, "multimmit.voter.verify.process").entered();
        if self.tasks.is_stale(completion.issued().generation()) {
            self.telemetry.metrics.stale.inc();
            return Ok(());
        }
        let Some(dispatched) = self.verification_tasks.remove(&completion.issued().id()) else {
            self.telemetry.metrics.stale.inc();
            return Ok(());
        };
        let Dispatched {
            permit,
            root,
            queued_at,
            urgency,
            updates,
        } = dispatched;
        let metrics = &self.telemetry.metrics;
        let dwell = match urgency {
            Urgency::Critical => &metrics.verification_dwell_fast,
            Urgency::Bulk => &metrics.verification_dwell_bulk,
        };
        dwell.observe_between(queued_at, self.context.current());
        // The lag is taken as the voter applies the verdicts, so time the job spent queued or
        // executing counts against it.
        let verdicts = completion.verdicts();
        let valid = |index: usize| verdicts.get(index).is_some_and(|verdict| verdict.valid());
        for lag in updates.lags(self.telemetry.round_view(), valid) {
            metrics.verified_vote_lag.observe(lag as f64);
        }
        if !self.finish_task(permit).at(&root)? {
            return Ok(());
        }
        self.schedule_pending_verifications()?;
        span.record("verdicts", completion.verdicts().len().traced());
        self.track_transition(
            |core, now| core.enqueue(Input::Verified(completion), now),
            &root,
        )
        .at(&root)?;
        Ok(())
    }

    /// Stages one observed batch in the core and binds the view-proof kinds it carries.
    fn observe_network(
        &mut self,
        artifacts: Vec<IdentifiedArtifact<T::Variant, DigestOf<T>>>,
        artifact_bytes: usize,
    ) -> Result<(), Fatal> {
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
        let ticket =
            self.track_in_round(|core, now| core.observe(artifacts, resident_bytes, now))?;
        self.correlation.observed(ticket, proof_kinds)?;
        Ok(())
    }

    /// Ingests one peer observation batch.
    fn ingest_observed(
        &mut self,
        batch: ObservedBatch<T::Variant, DigestOf<T>>,
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
        let kind = ViewProofKind::of(&completion.artifact().artifact);
        let resolved = info_span!(
            parent: &span,
            "multimmit.voter.resolve.complete",
            epoch = round.epoch().get().traced(),
            view = round.view().get().traced()
        );
        resolved
            .in_scope(|| {
                let ticket = self.track_transition(
                    |core, now| core.enqueue(Input::ResolutionCompleted(completion), now),
                    &root,
                )?;
                if let Some(kind) = kind {
                    self.correlation.resolved(ticket, kind)?;
                }
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
