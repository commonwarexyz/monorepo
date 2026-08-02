use super::*;

impl<E, H, P, V, A, R, F, T, S1, S2, S3> Driver<E, H, P, V, A, R, F, T, S1, S2, S3>
where
    E: Clock + Spawner + Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
    S1: Sender<PublicKey = P>,
    S2: Sender<PublicKey = P>,
    S3: Sender<PublicKey = P>,
{
    pub(super) fn execute_capabilities(
        &mut self,
        capabilities: Capabilities<V, H::Digest>,
    ) -> Result<(), Fatal> {
        for capability in capabilities {
            match capability {
                Capability::Durability(DurabilityCapability::Retire(retired)) => {
                    self.egress.retire(&retired);
                    #[cfg(test)]
                    if !retired.is_empty() {
                        self.test_hooks.record(TestEvent::Retired(retired));
                    }
                    let _ = self.metrics.publications.try_set(self.egress.len());
                }
                capability => self.execute_capability(capability)?,
            }
        }
        Ok(())
    }

    /// Returns one affine capacity permit to Core. Prior-generation permits are stale completions,
    /// not epoch failures.
    pub(super) fn finish_task(
        &mut self,
        permit: TaskPermit,
        terminal: TaskTerminal,
    ) -> Result<bool, Fatal> {
        if permit.generation() != self.core().task_generation() {
            self.metrics.stale.inc();
            return Ok(false);
        }
        match self.core_mut().finish_task(permit, terminal) {
            Ok(()) => Ok(true),
            Err(TaskError::StaleGeneration | TaskError::UnknownPermit) => {
                self.metrics.stale.inc();
                Ok(false)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn shutdown_tasks(&mut self) {
        self.jobs.cancel_all();
        self.crypto.cancel_all();
        self.verification_tasks.clear();
        self.pending_verifications.clear();
        self.pending_signs.clear();
        self.pending_applications.clear();
        self.pending_publication = None;
        reset_generation_runtime_correlations(
            &mut self.active_custody,
            &mut self.active_validations,
            &mut self.verification_sources,
        );
        self.core_mut().shutdown_tasks();
    }

    /// Routes one core capability to its runtime-owned executor.
    fn execute_capability(&mut self, capability: Capability<V, H::Digest>) -> Result<(), Fatal> {
        match capability {
            Capability::Verification(capability) => self.execute_verification(capability)?,
            Capability::Durability(capability) => self.execute_durability(capability)?,
            Capability::Producer(capability) => self.execute_producer(capability)?,
            Capability::Leader(capability) => self.execute_leader(capability)?,
            Capability::Resolver(capability) => self.execute_resolver(capability)?,
        }
        Ok(())
    }

    fn execute_verification(
        &mut self,
        capability: VerificationCapability<V, H::Digest>,
    ) -> Result<(), Fatal> {
        match capability {
            VerificationCapability::Verify(job) => {
                let sources = job
                    .items()
                    .iter()
                    .map(|item| {
                        if item.peer_attributed() {
                            self.verification_sources
                                .remove(&item.ticket().observation())
                                .map(Some)
                                .ok_or(StepError::CompletionMismatch)
                        } else {
                            Ok(None)
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let span = info_span!(
                    "multimmit.voter.verify",
                    epoch = self.protocol_epoch.get().traced(),
                    view = self.round_view.get().traced(),
                    job = job.id().get().traced()
                );
                self.schedule_verification(PendingVerification {
                    span,
                    round: Round::new(self.protocol_epoch, self.round_view),
                    job,
                    sources,
                })?;
            }
        }
        Ok(())
    }

    fn execute_durability(
        &mut self,
        capability: DurabilityCapability<V, H::Digest>,
    ) -> Result<(), Fatal> {
        match capability {
            DurabilityCapability::Persist(directive) => self.persist(directive)?,
            DurabilityCapability::Acknowledged {
                retention,
                forwarded_nullifications,
                #[cfg(test)]
                acknowledgement,
                #[cfg(test)]
                retirements,
            } => {
                for artifact in retention {
                    self.retain_served(
                        &artifact,
                        #[cfg(test)]
                        RetentionBoundary::Acknowledged(acknowledgement),
                    )?;
                }
                self.metrics
                    .forwarded_nullifications
                    .inc_by(forwarded_nullifications as u64);
                #[cfg(test)]
                self.test_hooks.record(TestEvent::Acknowledged {
                    ack: acknowledgement,
                    retired: retirements,
                });
            }
            DurabilityCapability::Released(job) => {
                let (id, generation, effect) = job.into_parts();
                #[cfg(test)]
                self.test_hooks.record_durable(id, generation, &effect);
                match effect {
                    DurableEffect::Sign(request) => {
                        // Signing detaches like assembly and recovery below: the loop keeps
                        // draining ingress while the compute pool signs, and the completion
                        // re-enters through the crypto pool arm.
                        let span = info_span!(
                            "multimmit.voter.sign",
                            epoch = self.protocol_epoch.get().traced(),
                            view = tracing::field::Empty,
                            id = id.get().traced(),
                            generation = generation.traced(),
                            kind = sign_request_kind(&request)
                        );
                        if let Some(view) = request.consensus_view() {
                            span.record("view", view.get().traced());
                        }
                        let timing = SigningTiming {
                            ready_to_sign_at: self.context.current(),
                            application: self
                                .take_application_timing(core::slice::from_ref(&request)),
                        };
                        let scheme = Arc::clone(&self.scheme);
                        let operation = move |_| {
                            sign_request(&scheme, &request).map(|artifact| CryptoOutcome::Signed {
                                id,
                                generation,
                                artifact: Arc::new(artifact),
                                timing,
                            })
                        };
                        self.spawn_crypto(TaskClass::LocalSigning, span, operation)?;
                    }
                    DurableEffect::SignBatch(requests) => {
                        let workers = requests.len().max(1);
                        let view = requests.first().and_then(SignRequest::consensus_view);
                        let span = info_span!(
                            "multimmit.voter.sign.batch",
                            epoch = self.protocol_epoch.get().traced(),
                            view = tracing::field::Empty,
                            id = id.get().traced(),
                            generation = generation.traced(),
                            requests = requests.len().traced()
                        );
                        if let Some(view) = view {
                            span.record("view", view.get().traced());
                        }
                        let timing = SigningTiming {
                            ready_to_sign_at: self.context.current(),
                            application: self.take_application_timing(&requests),
                        };
                        // The batch is all-or-nothing and order preserving; any failure is fatal
                        // before a completion is constructed. Signatures are independent, so the
                        // batch fans out across the compute pool.
                        let scheme = Arc::clone(&self.scheme);
                        let operation = move |strategy: T| {
                            strategy
                                .try_map_collect_vec(requests.iter(), |request| {
                                    sign_request(&scheme, request)
                                })
                                .map(|artifacts| CryptoOutcome::SignedBatch {
                                    id,
                                    generation,
                                    artifacts,
                                    timing,
                                })
                        };
                        self.spawn_crypto_units(TaskClass::LocalSigning, workers, span, operation)?;
                    }
                    DurableEffect::Broadcast(artifact) => {
                        let transmission = self.frame(&artifact, None)?;
                        self.install(id, generation, vec![transmission]);
                    }
                    DurableEffect::BroadcastBatch(artifacts) => {
                        let mut transmissions = Vec::with_capacity(artifacts.len());
                        for artifact in artifacts.iter() {
                            transmissions.push(self.frame(artifact, None)?);
                        }
                        self.install(id, generation, transmissions);
                    }
                    DurableEffect::Propose(publication) => {
                        let transmission = self.egress.frame_proposal(&publication);
                        self.install(id, generation, vec![transmission]);
                    }
                    DurableEffect::Send(request) => {
                        let Some(recipient) = self
                            .scheme
                            .participants()
                            .get(request.recipient().get() as usize)
                            .cloned()
                        else {
                            return Err(Fatal::Step(StepError::UnauthorizedEffect));
                        };
                        let transmission = self.frame(request.artifact(), Some(recipient))?;
                        self.install(id, generation, vec![transmission]);
                    }
                    DurableEffect::SendBatch(requests) => {
                        let mut transmissions = Vec::with_capacity(requests.len());
                        for request in requests.iter() {
                            let Some(recipient) = self
                                .scheme
                                .participants()
                                .get(request.recipient().get() as usize)
                                .cloned()
                            else {
                                return Err(Fatal::Step(StepError::UnauthorizedEffect));
                            };
                            transmissions.push(self.frame(request.artifact(), Some(recipient))?);
                        }
                        self.install(id, generation, transmissions);
                    }
                }
            }
            DurabilityCapability::Retire(_) => {
                unreachable!("retirement executes at the ordered capability boundary")
            }
        }
        Ok(())
    }

    fn execute_producer(
        &mut self,
        capability: ProducerCapability<V, H::Digest>,
    ) -> Result<(), Fatal> {
        match capability {
            ProducerCapability::ArmTimer(timer) => {
                let deadline = self.context.current().saturating_add_ext(timer.delay());
                self.production_timer = Some((timer, deadline, Span::current()));
            }
            ProducerCapability::Build(job) => self.spawn_build(&job)?,
            ProducerCapability::Custody(job) => self.spawn_custody(&job)?,
            ProducerCapability::CancelCustody(cancellation) => {
                self.cancel_custody(cancellation)?;
            }
            ProducerCapability::Validate(job) => self.schedule_validation(job)?,
            ProducerCapability::CancelValidations { chain, through } => {
                self.cancel_validations(chain, through);
            }
            // DA assembly runs on the compute pool and returns through a reserved completion.
            ProducerCapability::RecoverDa(job) => {
                let header = job
                    .votes()
                    .first()
                    .expect("DA recovery jobs contain a quorum")
                    .header();
                let span = info_span!(
                    "multimmit.voter.recover.da",
                    epoch = header.epoch().get().traced(),
                    chain = header.chain().get().traced(),
                    height = header.height().get().traced(),
                    job = job.id().get().traced(),
                    generation = job.generation().traced()
                );
                let scheme = Arc::clone(&self.scheme);
                let started_at = self.context.current();
                let (id, generation) = (job.id(), job.generation());
                let operation = move |strategy: T| {
                    scheme
                        .assemble_da_certificate_preverified(job.votes(), &strategy)
                        .map(|certificate| CryptoOutcome::DaRecovered {
                            started_at,
                            completion: DaRecoveryCompletion::new(id, generation, certificate),
                        })
                };
                self.spawn_crypto(TaskClass::CriticalAggregation, span, operation)?;
            }
        }
        Ok(())
    }

    fn execute_resolver(&mut self, capability: ResolverCapability) -> Result<(), Fatal> {
        match capability {
            ResolverCapability::Resolve(job) => {
                let span = info_span!(
                    "multimmit.voter.resolve",
                    epoch = self.protocol_epoch.get().traced(),
                    view = self.round_view.get().traced(),
                    id = job.id().get().traced(),
                    generation = job.generation().traced()
                );
                let round = Round::new(self.protocol_epoch, self.round_view);
                if !self
                    .resolver
                    .enqueue(resolver::Message::Resolve(ResolveRequest {
                        span,
                        round,
                        job,
                    }))
                    .accepted()
                {
                    return Err(Fatal::Closed);
                }
            }
            ResolverCapability::Cancel(job) => {
                if !self
                    .resolver
                    .enqueue(resolver::Message::Cancel { job })
                    .accepted()
                {
                    return Err(Fatal::Closed);
                }
            }
            ResolverCapability::Reject(job) => {
                if !self
                    .resolver
                    .enqueue(resolver::Message::Reject { job })
                    .accepted()
                {
                    return Err(Fatal::Closed);
                }
            }
            ResolverCapability::Prune(through) => {
                if !self
                    .resolver
                    .enqueue(resolver::Message::Prune { through })
                    .accepted()
                {
                    return Err(Fatal::Closed);
                }
            }
        }
        Ok(())
    }

    fn execute_leader(&mut self, capability: LeaderCapability<V, H::Digest>) -> Result<(), Fatal> {
        match capability {
            LeaderCapability::ArmTimer(timer) => {
                debug!(view = timer.round().view().get(), "view timer armed");
                let deadline = self.context.current().saturating_add_ext(timer.delay());
                self.view_timer = Some((timer, deadline));
            }
            LeaderCapability::RecoverNullification(job) => {
                let round = job
                    .shares()
                    .first()
                    .expect("nullification recovery jobs contain a quorum")
                    .round();
                let span = info_span!(
                    "multimmit.voter.recover.nullification",
                    epoch = round.epoch().get().traced(),
                    view = round.view().get().traced(),
                    job = job.id().get().traced(),
                    generation = job.generation().traced()
                );
                let scheme = Arc::clone(&self.scheme);
                let started_at = self.context.current();
                let (id, generation) = (job.id(), job.generation());
                let operation = move |strategy: T| {
                    scheme
                        .assemble_nullification_preverified(job.shares(), &strategy)
                        .map(|certificate| CryptoOutcome::NullificationRecovered {
                            started_at,
                            completion: NullificationRecoveryCompletion::new(
                                id,
                                generation,
                                certificate,
                            ),
                        })
                };
                self.spawn_crypto(TaskClass::CriticalAggregation, span, operation)?;
            }
            LeaderCapability::AggregateVqc(job) => {
                let span = info_span!(
                    "multimmit.voter.aggregate.vqc",
                    epoch = self.protocol_epoch.get().traced(),
                    view = job.leader().view().get().traced(),
                    job = job.id().get().traced(),
                    generation = job.generation().traced()
                );
                let scheme = Arc::clone(&self.scheme);
                let view = job.leader().view();
                let (id, generation) = (job.id(), job.generation());
                let operation = move |strategy: T| {
                    let messages = job.messages().collect::<Vec<_>>();
                    scheme
                        .assemble_vqc_preverified::<H, _>(
                            job.leader().clone(),
                            &messages,
                            &strategy,
                        )
                        .map(|certificate| CryptoOutcome::VqcAggregated {
                            view,
                            completion: Box::new(VqcAggregateCompletion::new(
                                id,
                                generation,
                                certificate,
                            )),
                        })
                };
                self.spawn_crypto(TaskClass::CriticalAggregation, span, operation)?;
            }
            LeaderCapability::AggregateLqc(job) => {
                let span = info_span!(
                    "multimmit.voter.aggregate.lqc",
                    epoch = self.protocol_epoch.get().traced(),
                    view = job.leader().view().get().traced(),
                    job = job.id().get().traced(),
                    generation = job.generation().traced()
                );
                let scheme = Arc::clone(&self.scheme);
                let view = job.leader().view();
                let (id, generation) = (job.id(), job.generation());
                let operation = move |strategy: T| {
                    let votes = job.votes().cloned().collect::<Vec<_>>();
                    scheme
                        .assemble_lqc_preverified::<H, _>(job.leader().clone(), &votes, &strategy)
                        .map(|certificate| CryptoOutcome::LqcAggregated {
                            view,
                            completion: Box::new(LqcAggregateCompletion::new(
                                id,
                                generation,
                                certificate,
                            )),
                        })
                };
                self.spawn_crypto(TaskClass::CriticalAggregation, span, operation)?;
            }
        }
        Ok(())
    }

    /// Runs one cryptographic operation and returns its originating span with the result.
    fn spawn_crypto(
        &mut self,
        class: TaskClass,
        span: Span,
        operation: impl FnOnce(T) -> Result<CryptoOutcome<V, H::Digest>, SchemeError> + Send + 'static,
    ) -> Result<(), Fatal> {
        self.spawn_crypto_units(class, 1, span, operation)
    }

    fn spawn_crypto_units(
        &mut self,
        class: TaskClass,
        units: usize,
        span: Span,
        operation: impl FnOnce(T) -> Result<CryptoOutcome<V, H::Digest>, SchemeError> + Send + 'static,
    ) -> Result<(), Fatal> {
        let permit = self.core_mut().reserve_task(class, units)?;
        debug!(
            task = permit.id(),
            units,
            ?class,
            "reserved crypto task and completion"
        );
        let operation = run_crypto_operation(self.strategy.clone(), span, operation);
        self.crypto.push(async move { (permit, operation.await) });
        Ok(())
    }

    /// Reserves the verification workers before the job can enter the batcher's retained queue.
    fn schedule_verification(
        &mut self,
        pending: PendingVerification<P, V, H::Digest>,
    ) -> Result<(), Fatal> {
        if !self.pending_verifications.is_empty() {
            self.enqueue_pending_verification(pending)?;
            return self.schedule_pending_verifications();
        }
        if let Some(pending) = self.try_schedule_verification(pending)? {
            self.enqueue_pending_verification(pending)?;
        }
        Ok(())
    }

    fn try_schedule_verification(
        &mut self,
        pending: PendingVerification<P, V, H::Digest>,
    ) -> Result<Option<PendingVerification<P, V, H::Digest>>, Fatal> {
        let workers = pending.job.items().len().max(1);
        let permit = match self.core_mut().reserve_task(TaskClass::BulkCrypto, workers) {
            Ok(permit) => permit,
            Err(TaskError::ClassFull) => return Ok(Some(pending)),
            Err(error) => return Err(error.into()),
        };
        let job = pending.job.id();
        if self.verification_tasks.contains_key(&job) {
            let _ = self.finish_task(permit, TaskTerminal::Cancelled)?;
            return Err(TaskError::Accounting.into());
        }
        self.verification_tasks.insert(job, permit);
        if self
            .batcher
            .enqueue(batcher::Message::Verify {
                span: pending.span,
                round: pending.round,
                job: pending.job,
                sources: pending.sources,
            })
            .accepted()
        {
            return Ok(None);
        }

        let permit = self
            .verification_tasks
            .remove(&job)
            .ok_or(TaskError::Accounting)?;
        let _ = self.finish_task(permit, TaskTerminal::Cancelled)?;
        Err(Fatal::Closed)
    }

    fn enqueue_pending_verification(
        &mut self,
        pending: PendingVerification<P, V, H::Digest>,
    ) -> Result<(), Fatal> {
        if self.pending_verifications.len() >= self.verification_queue_limit {
            return Err(TaskError::ClassFull.into());
        }
        self.pending_verifications.push_back(pending);
        Ok(())
    }

    pub(super) fn schedule_pending_verifications(&mut self) -> Result<(), Fatal> {
        let queued = self.pending_verifications.len();
        for _ in 0..queued {
            let pending = self
                .pending_verifications
                .pop_front()
                .expect("the pass length came from this queue");
            if let Some(pending) = self.try_schedule_verification(pending)? {
                self.pending_verifications.push_back(pending);
            }
        }
        Ok(())
    }

    fn take_application_timing(
        &mut self,
        requests: &[SignRequest<V, H::Digest>],
    ) -> Option<AppCompletionTiming> {
        for request in requests {
            let Some(key) = application_completion_key::<H, V>(request) else {
                continue;
            };
            let position = self
                .pending_applications
                .iter()
                .position(|(pending, _)| pending == &key);
            let Some(position) = position else {
                continue;
            };
            return Some(self.pending_applications.swap_remove(position).1);
        }
        None
    }

    /// Appends one exact barrier and stages its durability completion.
    ///
    /// Barriers pipeline: the journal appends behind in-flight syncs, and completions are
    /// acknowledged strictly in cursor order.
    fn persist(&mut self, directive: PersistDirective<V, H::Digest>) -> Result<(), Fatal> {
        let (job, staged_retention, release_after_enqueue, signed_publication) =
            directive.into_parts();
        let publication = signed_publication.and_then(|(sign, publication)| {
            let position = self
                .pending_signs
                .iter()
                .position(|timed| timed.id == sign)?;
            let timed = self.pending_signs.swap_remove(position);
            Some(TimedPublication {
                id: publication,
                at: timed.at,
            })
        });

        // A dedicated span makes each barrier's wall time (append, fsync, acknowledgement)
        // visible per round; staging stalls behind exactly this interval.
        let span = info_span!(
            "multimmit.voter.persist",
            epoch = self.protocol_epoch.get().traced(),
            view = self.round_view.get().traced(),
            barrier = job.id().get().traced(),
            events = job.events().len().traced()
        );
        #[cfg(test)]
        let barrier = job.id();
        match self.journal.try_append(span, job) {
            Ok(response) => {
                self.journal_responses.push_back(PendingJournal {
                    response,
                    publication,
                });
                Ok(())
            }
            Err(JournalAdmission::Full(_)) => Err(CoreError::SchedulerInvariant.into()),
            Err(JournalAdmission::Closed(_)) => Err(Fatal::Closed),
        }?;
        for artifact in staged_retention {
            self.retain_served(
                &artifact,
                #[cfg(test)]
                RetentionBoundary::Staged(barrier),
            )?;
        }
        for job in release_after_enqueue {
            self.execute_durability(DurabilityCapability::Released(job))?;
        }
        Ok(())
    }

    /// Applies bookkeeping and acknowledges a successfully synced journal barrier.
    pub(super) fn persistence_completed(
        &mut self,
        durable: JournalDurable<V, H::Digest>,
        publication: Option<TimedPublication>,
    ) -> Result<(), Fatal> {
        let JournalDurable {
            span,
            job,
            ack: completion,
        } = durable;
        self.events_since_checkpoint += job.events().len() as u64;
        #[cfg(test)]
        self.test_hooks.record(TestEvent::Acknowledged {
            ack: completion,
            retired: Vec::new(),
        });
        let ticket = self.track_transition(|core| core.persistence_completed(completion))?;
        self.input_spans
            .get_mut(&ticket)
            .ok_or(CoreError::SchedulerInvariant)?
            .span = span;
        self.input_spans
            .get_mut(&ticket)
            .ok_or(CoreError::SchedulerInvariant)?
            .publication = publication;

        Ok(())
    }

    /// Spawns the application build for one machine-issued production job.
    fn spawn_build(&mut self, job: &BuildJob<H::Digest>) -> Result<(), Fatal> {
        // Validation work never consumes this slot. The machine issues at most one build at a
        // time, so reserving it before spawning keeps local production bounded without waiting.
        let permit = self.core_mut().reserve_task(TaskClass::LocalBuild, 1)?;

        let parent = job.parent();
        let context = Context::new(
            self.protocol_epoch,
            parent.chain(),
            parent.height().next(),
            parent.digest(),
        )
        .expect("build job has a non-genesis position");
        let (id, generation) = (job.id(), job.generation());
        let span = info_span!(
            "multimmit.voter.produce",
            epoch = self.protocol_epoch.get().traced(),
            chain = parent.chain().get().traced(),
            height = parent.height().next().get().traced()
        );
        let started_at = self.context.current();
        let mut automaton = self.automaton.clone();
        let completion_span = span.clone();
        let handle = self.context.child("build").spawn(move |_| {
            async move {
                let receiver = automaton.propose(context).await;
                let result = receiver.await.ok();
                AppOutcome::Built {
                    started_at,
                    id,
                    generation,
                    parent,
                    result,
                }
            }
            .instrument(span)
        });
        self.jobs
            .push(async move { (permit, completion_span, handle.await) });
        Ok(())
    }

    /// Validates and durably retains one locally prepared body before its header may be signed.
    fn spawn_custody(&mut self, job: &CustodyJob<H::Digest>) -> Result<(), Fatal> {
        let permit = self.core_mut().reserve_task(TaskClass::LocalCustody, 1)?;
        let (id, generation) = (job.id(), job.generation());
        let cancellation = CustodyCancellation::new(id, generation);
        let header = job.header().clone();
        let context = Context::from(&header);
        let commitment = header.body_digest();
        let (cancel, cancelled) = oneshot::channel();
        let previous = self.active_custody.insert(id, Some(cancel));
        assert!(previous.is_none(), "local custody identity is unique");
        let span = info_span!(
            "multimmit.voter.custody",
            epoch = header.epoch().get().traced(),
            chain = header.chain().get().traced(),
            height = header.height().get().traced(),
        );
        let started_at = self.context.current();
        let mut automaton = self.automaton.clone();
        let completion_span = span.clone();
        let handle = self.context.child("custody").spawn(move |_| {
            async move {
                let custody = async {
                    let receiver = automaton.verify(context, commitment).await;
                    receiver.await.ok()
                };
                select! {
                    verdict = custody => AppOutcome::Custodied {
                        started_at,
                        id,
                        generation,
                        header,
                        verdict,
                    },
                    _ = cancelled => AppOutcome::CustodyCancelled { cancellation },
                }
            }
            .instrument(span)
        });
        self.jobs
            .push(async move { (permit, completion_span, handle.await) });
        Ok(())
    }

    /// Starts a validation within the global and per-producer application bounds.
    fn schedule_validation(&mut self, job: ValidationJob<V, H::Digest>) -> Result<(), Fatal> {
        if let Some(dispatch) = self.core_mut().schedule_validation(job)? {
            self.spawn_validation(dispatch)?;
        }
        Ok(())
    }

    /// Spawns the deterministic application check for one authenticated header.
    fn spawn_validation(
        &mut self,
        dispatch: crate::multimmit::machine::ValidationDispatch<V, H::Digest>,
    ) -> Result<(), Fatal> {
        let (permit, job) = dispatch.into_parts();
        let chain = job.block().header().chain().get();

        let (id, generation) = (job.id(), job.generation());
        let block = Arc::new(job.block().clone());
        let context = Context::from(block.header());
        let commitment = block.header().body_digest();
        let (cancel, cancelled) = oneshot::channel();
        let previous = self.active_validations.insert(id, Some(cancel));
        assert!(previous.is_none(), "producer application slot is occupied");
        let span = info_span!(
            "multimmit.voter.validate_block",
            epoch = self.protocol_epoch.get().traced(),
            chain = chain.traced(),
            height = block.header().height().get().traced()
        );
        let started_at = self.context.current();
        let mut automaton = self.automaton.clone();
        let completion_span = span.clone();
        let handle = self.context.child("validate").spawn(move |_| {
            async move {
                let validation = async {
                    let receiver = automaton.verify(context, commitment).await;
                    receiver.await.ok()
                };
                select! {
                    verdict = validation => AppOutcome::Validated {
                        started_at,
                        id,
                        generation,
                        block,
                        verdict,
                    },
                    _ = cancelled => AppOutcome::ValidationCancelled {
                        id,
                        chain: ChainId::new(chain),
                    },
                }
            }
            .instrument(span)
        });
        self.jobs
            .push(async move { (permit, completion_span, handle.await) });
        Ok(())
    }

    fn validation_finished(&mut self, chain: ChainId, id: ValidationId) -> Result<(), Fatal> {
        if self.active_validations.remove(&id).is_none() {
            return Err(TaskError::Accounting.into());
        }
        if let Some(dispatch) = self.core_mut().validation_finished(chain, id)? {
            self.spawn_validation(dispatch)?;
        }
        Ok(())
    }

    /// Commits one completed build or validation job to protocol state.
    pub(super) fn application_outcome(
        &mut self,
        permit: TaskPermit,
        span: &Span,
        outcome: Result<AppOutcome<V, H::Digest>, RuntimeError>,
    ) -> Result<(), Fatal> {
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(_) => {
                if !self.finish_task(permit, TaskTerminal::Panicked)? {
                    return Ok(());
                }
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
                if !self.finish_task(permit, TaskTerminal::Completed)? {
                    return Ok(());
                }
                let completed_at = self.context.current();
                self.metrics
                    .build_latency
                    .observe_between(started_at, completed_at);
                let application = result.map(|commitment| {
                    (
                        AppCompletionKey::Propose {
                            chain: parent.chain().get(),
                            parent: parent.digest(),
                            commitment,
                        },
                        AppCompletionTiming::Propose(completed_at),
                    )
                });
                if result.is_some() {
                    self.metrics.builds.inc();
                } else {
                    self.metrics.build_declines.inc();
                }
                let completed = info_span!(parent: span, "multimmit.voter.produce.complete");
                completed.in_scope(|| {
                    let completion = BuildCompletion::new(id, generation, parent, result);
                    let ticket =
                        self.track_transition(|core| core.producer_build_completed(completion))?;
                    self.track_application(ticket, application)
                })
            }
            AppOutcome::Custodied {
                started_at,
                id,
                generation,
                header,
                verdict,
            } => {
                let cancellation_requested = self
                    .active_custody
                    .get(&id)
                    .is_some_and(Option::is_none);
                let terminal = if cancellation_requested {
                    TaskTerminal::Cancelled
                } else if verdict == Some(true) {
                    TaskTerminal::Completed
                } else {
                    TaskTerminal::Failed
                };
                if !self.finish_task(permit, terminal)? {
                    return Ok(());
                }
                let active = self
                    .active_custody
                    .remove(&id)
                    .ok_or(TaskError::Accounting)?;
                if active.is_none() != cancellation_requested {
                    return Err(TaskError::Accounting.into());
                }
                if cancellation_requested {
                    let cancellation = CustodyCancellation::new(id, generation);
                    self.track_transition(|core| {
                        core.producer_custody_cancelled(cancellation)
                    })?;
                    return Ok(());
                }
                self.metrics
                    .custody_latency
                    .observe_between(started_at, self.context.current());
                if verdict != Some(true) {
                    return Err(Fatal::Automaton);
                }
                let completed = info_span!(parent: span, "multimmit.voter.custody.complete");
                completed.in_scope(|| {
                    let completion = CustodyCompletion::new(id, generation, header);
                    self.track_transition(|core| core.producer_custodied(completion))?;
                    Ok(())
                })
            }
            AppOutcome::CustodyCancelled { cancellation } => {
                if !self.finish_task(permit, TaskTerminal::Cancelled)? {
                    return Ok(());
                }
                let active = self
                    .active_custody
                    .remove(&cancellation.id())
                    .ok_or(TaskError::Accounting)?;
                if active.is_some() {
                    return Err(TaskError::Accounting.into());
                }
                self.track_transition(|core| core.producer_custody_cancelled(cancellation))?;
                Ok(())
            }
            AppOutcome::Validated {
                started_at,
                id,
                generation,
                block,
                verdict,
            } => {
                let terminal = if verdict.is_some() {
                    TaskTerminal::Completed
                } else {
                    TaskTerminal::Failed
                };
                if !self.finish_task(permit, terminal)? {
                    return Ok(());
                }
                let completed_at = self.context.current();
                self.metrics
                    .validation_latency
                    .observe_between(started_at, completed_at);
                self.validation_finished(block.header().chain(), id)?;

                let verdict = verdict.ok_or(Fatal::Automaton)?;
                let validity = if verdict {
                    BlockValidity::Valid
                } else {
                    self.metrics.invalid_blocks.inc();
                    BlockValidity::Invalid
                };
                let application = (validity == BlockValidity::Valid).then_some((
                    AppCompletionKey::Verify(block.header().digest::<H>()),
                    AppCompletionTiming::Verify(completed_at),
                ));
                let completed = info_span!(parent: span, "multimmit.voter.validate_block.complete");
                completed.in_scope(|| {
                    let completion = ValidationCompletion::new(id, generation, validity);
                    let ticket =
                        self.track_transition(|core| core.producer_validated(completion))?;
                    self.track_application(ticket, application)
                })
            }
            AppOutcome::ValidationCancelled { id, chain } => {
                if !self.finish_task(permit, TaskTerminal::Cancelled)? {
                    return Ok(());
                }
                self.validation_finished(chain, id)?;
                Ok(())
            }
        }
    }

    fn cancel_validations(&mut self, chain: ChainId, through: Height) {
        for id in self.core_mut().cancel_validations(chain, through) {
            let Some(cancel) = self.active_validations.get_mut(&id) else {
                continue;
            };
            if let Some(cancel) = cancel.take() {
                let _ = cancel.send(());
            }
        }
    }

    fn cancel_custody(&mut self, cancellation: CustodyCancellation) -> Result<(), Fatal> {
        if cancellation.generation() != self.core().task_generation() {
            return Ok(());
        }
        let Some(cancel) = self.active_custody.get_mut(&cancellation.id()) else {
            return Err(TaskError::Accounting.into());
        };
        if let Some(cancel) = cancel.take() {
            let _ = cancel.send(());
        }
        Ok(())
    }

    fn observe_sign_ready(&self, timing: SigningTiming) -> SystemTime {
        let sign_ready_at = self.context.current();
        self.metrics
            .ready_to_sign_latency
            .observe_between(timing.ready_to_sign_at, sign_ready_at);
        match timing.application {
            Some(AppCompletionTiming::Propose(completed_at)) => self
                .metrics
                .propose_to_sign_ready_latency
                .observe_between(completed_at, sign_ready_at),
            Some(AppCompletionTiming::Verify(completed_at)) => self
                .metrics
                .verify_to_sign_ready_latency
                .observe_between(completed_at, sign_ready_at),
            None => {}
        }
        sign_ready_at
    }

    /// Feeds one completed certificate assembly or recovery back into the machine.
    fn crypto_outcome(
        &mut self,
        outcome: Result<CryptoOutcome<V, H::Digest>, SchemeError>,
    ) -> Result<(), Fatal> {
        let outcome = outcome?;
        match outcome {
            CryptoOutcome::Signed {
                id,
                generation,
                artifact,
                timing,
            } => {
                let sign_ready_at = self.observe_sign_ready(timing);
                let ticket =
                    self.track_transition(|core| core.signing_completed(id, generation, artifact))?;
                self.track_signing(
                    ticket,
                    TimedSign {
                        id,
                        at: sign_ready_at,
                    },
                )
            }
            CryptoOutcome::SignedBatch {
                id,
                generation,
                artifacts,
                timing,
            } => {
                let sign_ready_at = self.observe_sign_ready(timing);
                let ticket = self.track_transition(|core| {
                    core.signing_batch_completed(id, generation, artifacts)
                })?;
                self.track_signing(
                    ticket,
                    TimedSign {
                        id,
                        at: sign_ready_at,
                    },
                )
            }
            CryptoOutcome::DaRecovered {
                started_at,
                completion,
            } => {
                self.metrics
                    .da_recovery_latency
                    .observe_between(started_at, self.context.current());
                self.track_transition(|core| core.producer_da_recovered(completion))?;
                Ok(())
            }
            CryptoOutcome::NullificationRecovered {
                started_at,
                completion,
            } => {
                self.metrics
                    .nullification_recovery_latency
                    .observe_between(started_at, self.context.current());
                self.track_transition(|core| core.leader_nullification_recovered(completion))?;
                Ok(())
            }
            CryptoOutcome::VqcAggregated { view, completion } => {
                self.observe_leader_latency(view, &self.metrics.vqc_latency);
                self.track_transition(|core| core.leader_vqc_aggregated(completion))?;
                Ok(())
            }
            CryptoOutcome::LqcAggregated { view, completion } => {
                self.observe_leader_latency(view, &self.metrics.lqc_latency);
                self.track_transition(|core| core.leader_lqc_aggregated(completion))?;
                Ok(())
            }
        }
    }

    /// Reconciles one crypto handle before admitting its typed completion.
    pub(super) fn crypto_completed(
        &mut self,
        permit: TaskPermit,
        span: &Span,
        outcome: Result<Result<CryptoOutcome<V, H::Digest>, SchemeError>, CryptoTaskPanicked>,
    ) -> Result<(), Fatal> {
        match outcome {
            Ok(outcome) => {
                let terminal = if outcome.is_ok() {
                    TaskTerminal::Completed
                } else {
                    TaskTerminal::Failed
                };
                if !self.finish_task(permit, terminal)? {
                    return Ok(());
                }
                span.in_scope(|| self.crypto_outcome(outcome))
            }
            Err(CryptoTaskPanicked) => {
                if !self.finish_task(permit, TaskTerminal::Panicked)? {
                    return Ok(());
                }
                Err(Fatal::CryptoTaskPanicked)
            }
        }
    }
}
