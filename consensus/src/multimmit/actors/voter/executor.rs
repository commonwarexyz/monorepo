use super::*;

impl<E, H, P, V, A, R, F, T, C, S1, S2, S3> Driver<E, H, P, V, A, R, F, T, C, S1, S2, S3>
where
    E: Clock + Spawner + Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
    C: Strategy,
    S1: Sender<PublicKey = P>,
    S2: Sender<PublicKey = P>,
    S3: Sender<PublicKey = P>,
{
    pub(super) fn execute_capabilities(
        &mut self,
        capabilities: Capabilities<V, H::Digest>,
        root: &Span,
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
                capability => self.execute_capability(capability, root)?,
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
        self.clear_generation_runtime();
        self.core_mut().shutdown_tasks();
    }

    /// Routes one core capability to its runtime-owned executor.
    fn execute_capability(
        &mut self,
        capability: Capability<V, H::Digest>,
        root: &Span,
    ) -> Result<(), Fatal> {
        match capability {
            Capability::Verification(capability) => self.execute_verification(capability, root)?,
            Capability::Durability(capability) => self.execute_durability(capability, root)?,
            Capability::Producer(capability) => self.execute_producer(capability, root)?,
            Capability::Leader(capability) => self.execute_leader(capability, root)?,
            Capability::Resolver(capability) => self.execute_resolver(capability, root)?,
        }
        Ok(())
    }

    fn execute_verification(
        &mut self,
        capability: VerificationCapability<V, H::Digest>,
        root: &Span,
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
                    job = job.id().get().traced(),
                    items = job.items().len().traced(),
                    verdicts = tracing::field::Empty
                );
                self.schedule_verification(PendingVerification {
                    span,
                    root: root.clone(),
                    round: Round::new(self.protocol_epoch, self.round_view),
                    job,
                    sources,
                    queued_at: self.context.current(),
                })?;
            }
        }
        Ok(())
    }

    fn execute_durability(
        &mut self,
        capability: DurabilityCapability<V, H::Digest>,
        root: &Span,
    ) -> Result<(), Fatal> {
        match capability {
            DurabilityCapability::Persist(directive) => self.persist(directive, root)?,
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
                        // draining ingress while the critical pool signs, and the completion
                        // re-enters through the crypto pool arm.
                        let span = info_span!(
                            "multimmit.voter.sign",
                            epoch = self.protocol_epoch.get().traced(),
                            view = tracing::field::Empty,
                            id = id.get().traced(),
                            generation = generation.traced(),
                            kind = sign_request_kind(&request),
                            positions = tracing::field::Empty,
                            extensions = tracing::field::Empty,
                            payloads = tracing::field::Empty,
                            certified_anchors = tracing::field::Empty
                        );
                        if let Some(view) = request.consensus_view() {
                            span.record("view", view.get().traced());
                        }
                        match &request {
                            SignRequest::DaVote(vote) => {
                                self.observe_da_vote_latency(vote.header());
                            }
                            SignRequest::Vote(vote) => {
                                let body = vote.body();
                                let positions = body
                                    .positions()
                                    .iter()
                                    .map(|position| u64::from(position.get()))
                                    .sum::<u64>();
                                let extensions = body
                                    .extensions()
                                    .iter()
                                    .map(|extension| extension.payloads().len() as u64)
                                    .sum::<u64>();
                                span.record("positions", positions.traced());
                                span.record("extensions", extensions.traced());
                                self.metrics.vote_extensions.observe(extensions as f64);
                                self.metrics.vote_positions.observe(positions as f64);
                                if positions == 0 && extensions == 0 {
                                    self.metrics.empty_votes.inc();
                                }
                            }
                            SignRequest::LeaderBlock(proposal) => {
                                let proposals = proposal.block().proposals();
                                let payloads = proposals
                                    .iter()
                                    .map(|chain| chain.len() as u64)
                                    .sum::<u64>();
                                let certified = proposals
                                    .iter()
                                    .filter(|chain| {
                                        matches!(
                                            chain.anchor(),
                                            crate::multimmit::types::Anchor::Certificate(_)
                                        )
                                    })
                                    .count() as u64;
                                span.record("payloads", payloads.traced());
                                span.record("certified_anchors", certified.traced());
                                self.metrics.proposal_payloads.observe(payloads as f64);
                                self.metrics
                                    .proposal_certified_anchors
                                    .observe(certified as f64);
                            }
                            _ => {}
                        }
                        let scheme = Arc::clone(&self.scheme);
                        let critical = self.critical_strategy.clone();
                        let operation = move |_| {
                            sign_request(&scheme, &request).map(|artifact| CryptoOutcome::Signed {
                                id,
                                generation,
                                artifact: Arc::new(artifact),
                            })
                        };
                        self.spawn_crypto(
                            critical,
                            TaskClass::LocalSigning,
                            span,
                            operation,
                            root,
                        )?;
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
                        for request in requests.iter() {
                            if let SignRequest::DaVote(vote) = request {
                                self.observe_da_vote_latency(vote.header());
                            }
                        }
                        // The batch is all-or-nothing and order preserving; any failure is fatal
                        // before a completion is constructed. Signatures are independent, so the
                        // batch fans out across the critical pool.
                        let scheme = Arc::clone(&self.scheme);
                        let critical = self.critical_strategy.clone();
                        let operation = move |strategy: C| {
                            strategy
                                .try_map_collect_vec(requests.iter(), |request| {
                                    sign_request(&scheme, request)
                                })
                                .map(|artifacts| CryptoOutcome::SignedBatch {
                                    id,
                                    generation,
                                    artifacts,
                                })
                        };
                        self.spawn_crypto_units(
                            critical,
                            TaskClass::LocalSigning,
                            workers,
                            span,
                            operation,
                            root,
                        )?;
                    }
                    DurableEffect::Broadcast(artifact) => {
                        let transmission = self.frame(&artifact, None)?;
                        self.install(id, generation, vec![transmission])?;
                    }
                    DurableEffect::BroadcastBatch(artifacts) => {
                        let mut transmissions = Vec::with_capacity(artifacts.len());
                        for artifact in artifacts.iter() {
                            transmissions.push(self.frame(artifact, None)?);
                        }
                        self.install(id, generation, transmissions)?;
                    }
                    DurableEffect::Propose(publication) => {
                        let transmission = self.egress.frame_proposal(&publication);
                        self.install(id, generation, vec![transmission])?;
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
                        self.install(id, generation, vec![transmission])?;
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
                        self.install(id, generation, transmissions)?;
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
        root: &Span,
    ) -> Result<(), Fatal> {
        match capability {
            ProducerCapability::ArmTimer(timer) => {
                #[cfg(test)]
                debug!(
                    test_root = root.id().map_or(0, |id| id.into_u64()),
                    "test production timer armed"
                );
                let deadline = self.context.current().saturating_add_ext(timer.delay());
                self.production_timer = Some((
                    timer,
                    deadline,
                    TraceContext {
                        span: Span::current(),
                        root: root.clone(),
                    },
                ));
            }
            ProducerCapability::Build(job) => self.spawn_build(&job, root)?,
            ProducerCapability::Custody(job) => self.spawn_custody(&job, root)?,
            ProducerCapability::CancelCustody(cancellation) => {
                self.cancel_custody(cancellation)?;
            }
            // The own-chain DA plane runs on its own task: central just routes authenticated
            // shares and anchor advances to it and never blocks on it.
            ProducerCapability::ForwardShare(share) => {
                if let Some(command) = &self.da_command {
                    let _ = command.enqueue(ChainCommand::Observe(share));
                }
            }
            ProducerCapability::AnchorAdvanced(height) => {
                if let Some(command) = &self.da_command {
                    let _ = command.enqueue(ChainCommand::AnchorAdvanced(height));
                }
            }
            // Each remote validator plane runs on its own per-chain task; central routes the block,
            // the certified anchor, and the durable choices to it and never blocks on it.
            ProducerCapability::ObserveBlock {
                id,
                observation,
                block,
                custodied,
            } => {
                let chain = block.header().chain().get() as usize;
                if let Some(command) = self.validator_commands.get(chain) {
                    let _ = command.enqueue(super::validator::ValidatorCommand::Observe {
                        id,
                        observation,
                        block,
                        custodied,
                    });
                }
            }
            ProducerCapability::ValidatorAnchor(anchor) => {
                let chain = anchor.chain().get() as usize;
                if let Some(command) = self.validator_commands.get(chain) {
                    let _ =
                        command.enqueue(super::validator::ValidatorCommand::AnchorAdvanced(anchor));
                }
            }
            ProducerCapability::ValidatorChosen { chain, choices } => {
                if let Some(command) = self.validator_commands.get(chain.get() as usize) {
                    let _ = command.enqueue(super::validator::ValidatorCommand::Chosen(choices));
                }
            }
        }
        Ok(())
    }

    fn execute_resolver(
        &mut self,
        capability: ResolverCapability,
        root: &Span,
    ) -> Result<(), Fatal> {
        let message = match capability {
            ResolverCapability::Resolve(job) => {
                let span = info_span!(
                    "multimmit.voter.resolve",
                    epoch = self.protocol_epoch.get().traced(),
                    view = self.round_view.get().traced(),
                    id = job.id().get().traced(),
                    generation = job.generation().traced()
                );
                let round = Round::new(self.protocol_epoch, self.round_view);
                resolver::Message::Resolve(ResolveRequest {
                    span,
                    root: root.clone(),
                    round,
                    job,
                })
            }
            ResolverCapability::Cancel(job) => resolver::Message::Cancel { job },
            ResolverCapability::Reject(job) => resolver::Message::Reject { job },
            ResolverCapability::Prune(through) => resolver::Message::Prune { through },
        };
        if !self.resolver.enqueue(message).accepted() {
            return Err(Fatal::Closed);
        }
        Ok(())
    }

    fn execute_leader(
        &mut self,
        capability: LeaderCapability<V, H::Digest>,
        root: &Span,
    ) -> Result<(), Fatal> {
        match capability {
            LeaderCapability::ArmTimer(timer) => {
                debug!(view = timer.round().view().get(), "view timer armed");
                let now = self.context.current();
                let (deadline, reason) =
                    if self.is_active(self.leaders.leader(timer.round().view())) {
                        (now.saturating_add_ext(timer.delay()), "deadline")
                    } else {
                        (now, "inactive_leader")
                    };
                self.view_timer = Some((timer, deadline, reason));
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
                let critical = self.critical_strategy.clone();
                let started_at = self.context.current();
                let (id, generation) = (job.id(), job.generation());
                let operation = move |strategy: C| {
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
                self.spawn_crypto(
                    critical,
                    TaskClass::CriticalAggregation,
                    span,
                    operation,
                    root,
                )?;
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
                let critical = self.critical_strategy.clone();
                let view = job.leader().view();
                let (id, generation) = (job.id(), job.generation());
                let operation = move |strategy: C| {
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
                self.spawn_crypto(
                    critical,
                    TaskClass::CriticalAggregation,
                    span,
                    operation,
                    root,
                )?;
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
                let critical = self.critical_strategy.clone();
                let view = job.leader().view();
                let operation = move |strategy: C| {
                    let votes = job.votes().cloned().collect::<Vec<_>>();
                    scheme
                        .assemble_lqc_preverified::<H, _>(job.leader().clone(), &votes, &strategy)
                        .and_then(|certificate| {
                            LqcAggregateCompletion::prepare::<H>(
                                &job,
                                certificate,
                                scheme.codec_config(),
                            )
                        })
                        .map(|completion| CryptoOutcome::LqcAggregated {
                            view,
                            completion: Box::new(completion),
                        })
                };
                self.spawn_crypto(
                    critical,
                    TaskClass::CriticalAggregation,
                    span,
                    operation,
                    root,
                )?;
            }
        }
        Ok(())
    }

    /// Blocks the peers a failed recovery attributed invalid data-availability shares to.
    ///
    /// Ingress rejects a share whose signer is not the peer that sent it, so a share's signer
    /// index names its authenticated source. The batcher owns peer blocking, so the attribution
    /// is routed there rather than duplicating that authority in the voter.
    pub(super) fn block_da_signers(&mut self, invalid: &[Participant]) -> Result<(), Fatal> {
        let peers = invalid
            .iter()
            .filter_map(|signer| self.scheme.participants().get((*signer).into()).cloned())
            .collect::<Vec<_>>();
        if peers.is_empty() {
            return Ok(());
        }
        if !self
            .batcher
            .enqueue(batcher::Message::Block { peers })
            .accepted()
        {
            return Err(Fatal::Closed);
        }
        Ok(())
    }

    /// Runs one cryptographic operation on `strategy` and returns its originating span with the
    /// result.
    ///
    /// The pool is the caller's choice rather than the class's: view-critical assembly and signing
    /// run on the critical pool, while data-availability recovery runs with the bulk verification
    /// it is paced by. A job's closure takes the pool it was submitted to, so a job cannot use one
    /// pool's threads while occupying the other's queue.
    fn spawn_crypto<S: Strategy>(
        &mut self,
        strategy: S,
        class: TaskClass,
        span: Span,
        operation: impl FnOnce(S) -> Result<CryptoOutcome<V, H::Digest>, SchemeError> + Send + 'static,
        root: &Span,
    ) -> Result<(), Fatal> {
        self.spawn_crypto_units(strategy, class, 1, span, operation, root)
    }

    fn spawn_crypto_units<S: Strategy>(
        &mut self,
        strategy: S,
        class: TaskClass,
        units: usize,
        span: Span,
        operation: impl FnOnce(S) -> Result<CryptoOutcome<V, H::Digest>, SchemeError> + Send + 'static,
        root: &Span,
    ) -> Result<(), Fatal> {
        let permit = self.core_mut().reserve_task(class, units)?;
        debug!(
            task = permit.id(),
            units,
            ?class,
            "reserved crypto task and completion"
        );
        let operation = run_crypto_operation(strategy, span, operation);
        let root = root.clone();
        self.crypto.push(async move {
            let (span, outcome) = operation.await;
            (permit, TraceContext { span, root }, outcome)
        });
        Ok(())
    }

    /// Reserves the verification workers before the job can enter the batcher's retained queue.
    ///
    /// View-critical jobs drain ahead of bulk header and availability work: the finalization
    /// path waits on vote and certificate verdicts, while bulk verdicts only feed eligibility.
    /// Fast arrivals are bounded by the committee's per-view message budget, so bulk work
    /// cannot starve.
    fn schedule_verification(
        &mut self,
        pending: PendingVerification<P, V, H::Digest>,
    ) -> Result<(), Fatal> {
        if !self.fast_verifications.is_empty() || !self.bulk_verifications.is_empty() {
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
        let class = if pending.view_critical() {
            TaskClass::CriticalVerification
        } else {
            TaskClass::BulkCrypto
        };
        let permit = match self.core_mut().reserve_task(class, workers) {
            Ok(permit) => permit,
            Err(TaskError::ClassFull) => return Ok(Some(pending)),
            Err(error) => return Err(error.into()),
        };
        let job = pending.job.id();
        if self.verification_tasks.contains_key(&job) {
            let _ = self.finish_task(permit, TaskTerminal::Cancelled)?;
            return Err(TaskError::Accounting.into());
        }
        let wait = if pending.view_critical() {
            &self.metrics.verification_wait_fast
        } else {
            &self.metrics.verification_wait_bulk
        };
        wait.observe_between(pending.queued_at, self.context.current());
        self.verification_tasks.insert(job, (permit, pending.root));
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

        let (permit, root) = self
            .verification_tasks
            .remove(&job)
            .ok_or(TaskError::Accounting)?;
        let _ = self.finish_task(permit, TaskTerminal::Cancelled)?;
        Err(Fatal::VerificationClosed { root })
    }

    fn enqueue_pending_verification(
        &mut self,
        pending: PendingVerification<P, V, H::Digest>,
    ) -> Result<(), Fatal> {
        let queued = self.fast_verifications.len() + self.bulk_verifications.len();
        if queued >= self.verification_queue_limit {
            return Err(TaskError::ClassFull.into());
        }
        if pending.view_critical() {
            self.fast_verifications.push_back(pending);
        } else {
            self.bulk_verifications.push_back(pending);
        }
        Ok(())
    }

    pub(super) fn schedule_pending_verifications(&mut self) -> Result<(), Fatal> {
        // Fast jobs lead, but the drain interleaves: after at most FAST_DRAIN fast jobs, one
        // bulk job is guaranteed a reservation attempt. View-critical artifacts are the most
        // forgeable class (self-certifying certificates skip the future-view gate before
        // verification), so an exhaustive fast drain would let one peer's forged certificate
        // stream starve header and availability verification entirely.
        const FAST_DRAIN: usize = 4;
        let mut fast = self.fast_verifications.len();
        let mut bulk = self.bulk_verifications.len();
        while fast > 0 || bulk > 0 {
            let lead = fast.min(FAST_DRAIN);
            for _ in 0..lead {
                let pending = self
                    .fast_verifications
                    .pop_front()
                    .expect("the pass length came from this queue");
                if let Some(pending) = self.try_schedule_verification(pending)? {
                    self.fast_verifications.push_back(pending);
                }
            }
            fast -= lead;
            if bulk > 0 {
                let pending = self
                    .bulk_verifications
                    .pop_front()
                    .expect("the pass length came from this queue");
                if let Some(pending) = self.try_schedule_verification(pending)? {
                    self.bulk_verifications.push_back(pending);
                }
                bulk -= 1;
            }
        }
        Ok(())
    }

    /// Appends one exact barrier and stages its durability completion.
    ///
    /// Barriers pipeline: the journal appends behind in-flight syncs, and completions are
    /// acknowledged strictly in cursor order.
    fn persist(
        &mut self,
        directive: PersistDirective<V, H::Digest>,
        root: &Span,
    ) -> Result<(), Fatal> {
        let (job, staged_retention, release_after_enqueue, _) = directive.into_parts();

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
                    root: root.clone(),
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
            self.execute_durability(DurabilityCapability::Released(job), root)?;
        }
        Ok(())
    }

    /// Applies bookkeeping and acknowledges a successfully synced journal barrier.
    pub(super) fn persistence_completed(
        &mut self,
        durable: JournalDurable<V, H::Digest>,
        root: &Span,
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
        let ticket = self.track_transition(|core| core.persistence_completed(completion), root)?;
        self.input_spans
            .get_mut(&ticket)
            .ok_or(CoreError::SchedulerInvariant)?
            .span = span;

        Ok(())
    }

    /// Spawns the application build for one machine-issued production job.
    fn spawn_build(&mut self, job: &BuildJob<H::Digest>, root: &Span) -> Result<(), Fatal> {
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
        let completion_context = TraceContext {
            span: span.clone(),
            root: root.clone(),
        };
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
            .push(async move { (permit, completion_context, handle.await) });
        Ok(())
    }

    /// Validates and durably retains one locally prepared body before its header may be signed.
    fn spawn_custody(&mut self, job: &CustodyJob<H::Digest>, root: &Span) -> Result<(), Fatal> {
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
        let mut automaton = self.automaton.clone();
        let completion_context = TraceContext {
            span: span.clone(),
            root: root.clone(),
        };
        let handle = self.context.child("custody").spawn(move |_| {
            async move {
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
            }
            .instrument(span)
        });
        self.jobs
            .push(async move { (permit, completion_context, handle.await) });
        Ok(())
    }

    /// Starts a validation within the global and per-producer application bounds.
    /// Commits one completed build or validation job to protocol state.
    pub(super) fn application_outcome(
        &mut self,
        permit: TaskPermit,
        context: &TraceContext,
        outcome: Result<AppOutcome<H::Digest>, RuntimeError>,
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
                if result.is_some() {
                    self.metrics.builds.inc();
                } else {
                    self.metrics.build_declines.inc();
                }
                let completed =
                    info_span!(parent: &context.span, "multimmit.voter.produce.complete");
                completed.in_scope(|| {
                    let completion = BuildCompletion::new(id, generation, parent, result);
                    self.track_transition(
                        |core| core.producer_build_completed(completion),
                        &context.root,
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
                let cancellation_requested =
                    self.active_custody.get(&id).is_some_and(Option::is_none);
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
                    self.track_transition(
                        |core| core.producer_custody_cancelled(cancellation),
                        &context.root,
                    )?;
                    return Ok(());
                }
                if verdict != Some(true) {
                    return Err(Fatal::Automaton);
                }
                let completed =
                    info_span!(parent: &context.span, "multimmit.voter.custody.complete");
                completed.in_scope(|| {
                    let completion = CustodyCompletion::new(id, generation, header);
                    self.track_transition(
                        |core| core.producer_custodied(completion),
                        &context.root,
                    )?;
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
                self.track_transition(
                    |core| core.producer_custody_cancelled(cancellation),
                    &context.root,
                )?;
                Ok(())
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

    /// Feeds one completed certificate assembly or recovery back into the machine.
    fn crypto_outcome(
        &mut self,
        outcome: Result<CryptoOutcome<V, H::Digest>, SchemeError>,
        root: &Span,
    ) -> Result<(), Fatal> {
        let outcome = outcome?;
        match outcome {
            CryptoOutcome::Signed {
                id,
                generation,
                artifact,
            } => {
                self.track_transition(
                    |core| core.signing_completed(id, generation, artifact),
                    root,
                )?;
                Ok(())
            }
            CryptoOutcome::SignedBatch {
                id,
                generation,
                artifacts,
            } => {
                self.track_transition(
                    |core| core.signing_batch_completed(id, generation, artifacts),
                    root,
                )?;
                Ok(())
            }
            CryptoOutcome::NullificationRecovered {
                started_at,
                completion,
            } => {
                self.metrics
                    .nullification_recovery_latency
                    .observe_between(started_at, self.context.current());
                self.track_transition(
                    |core| core.leader_nullification_recovered(completion),
                    root,
                )?;
                Ok(())
            }
            CryptoOutcome::VqcAggregated { view, completion } => {
                self.observe_leader_latency(view, &self.metrics.vqc_latency);
                self.metrics
                    .qc_deviations
                    .observe(completion.certificate().tally().deviations().len() as f64);
                self.metrics
                    .qc_bytes
                    .observe(completion.certificate().encode_size() as f64);
                self.track_transition(|core| core.leader_vqc_aggregated(completion), root)?;
                Ok(())
            }
            CryptoOutcome::LqcAggregated { view, completion } => {
                self.observe_leader_latency(view, &self.metrics.lqc_latency);
                self.metrics
                    .qc_deviations
                    .observe(completion.certificate().tally().deviations().len() as f64);
                self.metrics
                    .qc_bytes
                    .observe(completion.certificate().encode_size() as f64);
                self.track_transition(|core| core.leader_lqc_aggregated(completion), root)?;
                Ok(())
            }
        }
    }

    /// Reconciles one crypto handle before admitting its typed completion.
    pub(super) fn crypto_completed(
        &mut self,
        permit: TaskPermit,
        context: &TraceContext,
        outcome: CryptoOperationOutcome<V, H::Digest>,
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
                context
                    .span
                    .in_scope(|| self.crypto_outcome(outcome, &context.root))
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
