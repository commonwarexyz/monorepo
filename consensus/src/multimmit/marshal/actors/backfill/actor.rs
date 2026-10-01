//! The backfill actor: registers waiters, rechecks local custody, fetches from peers, validates
//! responses, stages blocks, and completes waiters.

use super::{
    BackfillSubscriber, Error,
    mailbox::{BackfillBridge, DeliveryReply, Incoming, Mailbox, Message},
    rechecks::{RecheckCompletion, Rechecks, local_value},
    registry::{Eviction, Registry, Removed},
    serve,
    staging::{Ready, Staging, StagingCompletion, StagingJob},
    validate::{self, Limits},
    verifications::{Verdict, Verification, Verifications},
    waiter::{BlockMode, Cancellation, FetchState, Reply, Resolved, Target, Waiter, in_epoch},
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        actors::util::gated,
        marshal::{
            actors::{
                catalog,
                metrics::{self, FetchReason},
            },
            bodies::Bodies,
            types::LqcVerifier,
            wire::BackfillKey,
        },
        types::{BlockRef, Body, CertificateId, CodecConfig, Lqc, TipRecord, TransactionBlock},
    },
    types::Epoch,
};
use commonware_actor::{Feedback, mailbox};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select_loop;
use commonware_resolver::{Delivery, Fetch, Outcome, Resolver};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::{channel::fallible::OneshotExt as _, futures::Pool};
use futures::future::Aborted;
use std::{
    collections::BTreeSet,
    num::NonZeroUsize,
    slice,
    sync::{Arc, mpsc::TryRecvError},
};
use tracing::{Instrument as _, Span, debug, info_span};

/// Configuration for the backfill actor.
pub(crate) struct Config<H: Hasher, V: Variant, B: Body<H>> {
    /// Epoch of every accepted proof, header and block.
    pub epoch: Epoch,
    /// Decode bounds for the epoch.
    pub codec: CodecConfig,
    /// Decode configuration for application bodies.
    pub body: B::Cfg,
    /// Maximum encoded size of one block.
    pub max_block_bytes: NonZeroUsize,
    /// Maximum size of one resolver value.
    pub max_value_bytes: NonZeroUsize,
    /// Catalog used for local rechecks, L-QC admission and block staging.
    pub catalog: catalog::Mailbox<H, V, B>,
    /// Body lookups across temporary and immutable custody.
    pub bodies: Bodies<H, V, B>,
    /// Serving mailbox that the bridge forwards peer requests to.
    pub serve: serve::Mailbox<H::Digest>,
    /// Capacity of the actor's mailbox.
    pub mailbox_size: NonZeroUsize,
    /// Maximum number of registered waiters, and of keys reserved for staging.
    pub max_pending: NonZeroUsize,
    /// Maximum number of concurrent local rechecks.
    pub max_rechecks: NonZeroUsize,
    /// Maximum number of concurrent staging requests.
    pub max_staging: NonZeroUsize,
}

fn response_process_span(parent: &Span, received: usize) -> Span {
    info_span!(
        parent: parent,
        "multimmit.marshal.resolver.fetch.response.process",
        received = received,
    )
}

fn response_stage_span(process: &Span, blocks: usize, bytes: u64) -> Span {
    info_span!(
        parent: process,
        "multimmit.marshal.resolver.fetch.response.stage",
        blocks = blocks,
        bytes = bytes,
    )
}

/// Resolves missing marshal artifacts from local custody, then from peers.
///
/// Each request becomes a waiter keyed by the peer-visible key it needs. The first waiter of a key
/// starts a local recheck; on a miss, every waiter of the key fetches under its own identity. A
/// validated response completes every waiter of its key that it satisfies, after staging blocks
/// in temporary custody when a waiter needs it and after verifying and admitting an L-QC.
pub(crate) struct Actor<E, H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    context: ContextCell<E>,
    limits: Limits<B::Cfg>,
    catalog: catalog::Mailbox<H, V, B>,
    bodies: Bodies<H, V, B>,
    receiver: mailbox::Receiver<Message<H, V, B>>,
    /// Whether every mailbox sender is gone; the actor then drains accepted work and stops.
    closed: bool,
    registry: Registry<H, V, B>,
    rechecks: Rechecks<H, V, B>,
    staging: Staging<H, V, B>,
    verifications: Verifications<H, V, B>,
    cancellations: Pool<'static, Cancellation<H::Digest>>,
    metrics: metrics::Backfill,
}

impl<E, H, V, B> Actor<E, H, V, B>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    B::Cfg: Send + 'static,
{
    /// Creates the actor, the bridge for the network `commonware_resolver` engine, and the
    /// mailbox for marshal.
    ///
    /// The bridge exists before the network engine that consumes it is built; start the actor
    /// with that engine's resolver. `context` is marshal's: the actor registers its metrics under
    /// `resolver` and its mailbox under `resolver_bridge`.
    pub(crate) fn new(
        context: &E,
        config: Config<H, V, B>,
    ) -> (Self, BackfillBridge<H, V, B>, Mailbox<H, V, B>) {
        let (sender, receiver) =
            mailbox::new(context.child("resolver_bridge"), config.mailbox_size);
        let context = context.child("resolver");
        let metrics = metrics::Backfill::new(&context);
        let actor = Self {
            context: ContextCell::new(context),
            limits: Limits {
                epoch: config.epoch,
                codec: config.codec,
                body: config.body,
                max_block_bytes: config.max_block_bytes.get(),
                max_value_bytes: config.max_value_bytes.get(),
            },
            catalog: config.catalog,
            bodies: config.bodies,
            receiver,
            closed: false,
            registry: Registry::new(config.max_pending.get()),
            rechecks: Rechecks::new(config.max_rechecks.get()),
            staging: Staging::new(config.max_staging.get(), config.max_pending.get()),
            verifications: Verifications::new(config.max_rechecks.get()),
            cancellations: Pool::default(),
            metrics,
        };
        (
            actor,
            BackfillBridge::new(sender.clone(), config.serve),
            Mailbox::new(sender),
        )
    }

    /// Starts the actor, fetching through `resolver` and verifying peer L-QCs with `verifier`.
    pub(crate) fn start<R, Q>(mut self, resolver: R, verifier: Q) -> Handle<Result<(), Error>>
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
        Q: LqcVerifier<H, V> + Clone,
    {
        spawn_cell!(self.context, self.run(resolver, verifier))
    }

    async fn run<R, Q>(mut self, mut resolver: R, verifier: Q) -> Result<(), Error>
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
        Q: LqcVerifier<H, V> + Clone,
    {
        select_loop! {
            self.context,
            on_start => {
                self.schedule();
                self.update_gauges();
                if self.closed && self.staging.is_idle() && self.verifications.is_empty() {
                    break;
                }
            },
            on_stopped => {
                debug!("backfill stopped");
            },
            completion = self.rechecks.next_completed() => {
                self.on_recheck(&mut resolver, completion)?;
            },
            completion = self.staging.next_completed() => {
                self.on_staged(&mut resolver, completion)?;
            },
            verification = self.verifications.next_completed() => {
                self.on_verified(&mut resolver, verification)?;
            },
            cancellation = self.cancellations.next_completed() => {
                self.on_canceled(&mut resolver, cancellation);
            },
            message = gated(!self.closed, self.receiver.recv()) => match message {
                Some(message) => self.on_message(&mut resolver, &verifier, message),
                None => self.closed = true,
            },
        }
        Ok(())
    }

    /// Starts queued rechecks and staging jobs while their slots are free.
    fn schedule(&mut self) {
        while let Some(key) = self.rechecks.next_queued() {
            let mut waiters = self.registry.waiters(&key);
            let first = waiters.next().expect("a queued recheck has waiters");
            let references = match &first.target {
                Target::Blocks(references) => Some(Arc::clone(references)),
                _ => None,
            };
            let recheck = info_span!(
                parent: &first.span,
                "multimmit.marshal.resolver.fetch.local_recheck",
                reason = ?first.reason,
            );
            for waiter in waiters {
                recheck.follows_from(waiter.span.id());
            }
            let catalog = self.catalog.clone();
            let bodies = self.bodies.clone();
            let max_value_bytes = self.limits.max_value_bytes;
            self.metrics.local_rechecks.inc();
            self.rechecks.start(
                key,
                async move {
                    let result =
                        local_value(catalog, bodies, key, references, max_value_bytes).await;
                    RecheckCompletion { key, result }
                }
                .instrument(recheck),
            );
        }
        let clock = self.context.as_present();
        let latency = &self.metrics.staging_latency;
        self.staging
            .schedule(&self.catalog, || latency.timer(clock));
    }

    fn update_gauges(&self) {
        self.metrics
            .rechecks(self.rechecks.active(), self.rechecks.queued());
        let staging = self.staging.load();
        self.metrics.staging(
            staging.active,
            staging.active_bytes,
            staging.queued,
            staging.queued_bytes,
        );
        self.metrics.pending(self.registry.len());
    }

    fn on_message<R, Q>(&mut self, resolver: &mut R, verifier: &Q, message: Message<H, V, B>)
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
        Q: LqcVerifier<H, V> + Clone,
    {
        match message {
            Message::Deliver(incoming) => {
                if let Some(next) = self.on_deliver(resolver, verifier, incoming) {
                    self.on_message(resolver, verifier, next);
                }
            }
            Message::Fetch {
                span,
                target,
                reply,
                reason,
            } => {
                let process = info_span!(
                    parent: &span,
                    "multimmit.marshal.resolver.process",
                    reason = ?reason,
                );
                let fetch = info_span!(
                    parent: &process,
                    "multimmit.marshal.resolver.fetch",
                    reason = ?reason,
                );
                process.in_scope(|| self.register(resolver, fetch, target, Some(reply), reason));
            }
            Message::CertifiedBlock { reference } => self.on_certified(resolver, reference),
            Message::RetireCertified { frontiers, reply } => {
                self.retire_certified(resolver, &frontiers);
                reply.send_lossy(Ok(()));
            }
            Message::AdmittedBlock {
                reference,
                block,
                reply,
            } => {
                reply.send_lossy(self.on_admitted_block(resolver, reference, block));
            }
            Message::AdmittedHistory {
                commitment,
                record,
                reply,
            } => {
                reply.send_lossy(self.on_admitted_history(resolver, commitment, record));
            }
        }
    }

    /// Validates a peer response, draining queued block responses into one staging job.
    ///
    /// Returns a message taken from the mailbox while draining, which the caller handles next.
    fn on_deliver<R, Q>(
        &mut self,
        resolver: &mut R,
        verifier: &Q,
        incoming: Incoming<H::Digest>,
    ) -> Option<Message<H, V, B>>
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
        Q: LqcVerifier<H, V> + Clone,
    {
        if !matches!(incoming.delivery.key, BackfillKey::ProducerBlock { .. }) {
            let process = response_process_span(&incoming.span, 1);
            let mut job = StagingJob::new();
            self.admit(resolver, verifier, incoming, &mut job, &process);
            if !job.is_empty() {
                let stage = response_stage_span(&process, job.blocks.len(), job.bytes);
                self.staging.queue(job, stage);
            }
            return None;
        }
        let mut deliveries = vec![incoming];
        let next = self.drain_block_deliveries(&mut deliveries);
        let process = response_process_span(&deliveries[0].span, deliveries.len());
        for incoming in deliveries.iter().skip(1) {
            process.follows_from(incoming.span.id());
        }
        let validate = info_span!(
            parent: &process,
            "multimmit.marshal.resolver.fetch.response.validate",
            received = deliveries.len(),
            valid = tracing::field::Empty,
            staged = tracing::field::Empty,
        );
        let guard = validate.enter();
        let mut job = StagingJob::new();
        let mut valid = 0usize;
        for incoming in deliveries {
            if self.admit(resolver, verifier, incoming, &mut job, &process) {
                valid += 1;
            }
        }
        validate.record("valid", valid);
        validate.record("staged", job.blocks.len());
        drop(guard);
        if !job.is_empty() {
            let stage = response_stage_span(&process, job.blocks.len(), job.bytes);
            self.staging.queue(job, stage);
        }
        next
    }

    /// Moves queued block responses into `deliveries`, up to the pending bound.
    ///
    /// Returns the first other message taken from the mailbox.
    fn drain_block_deliveries(
        &mut self,
        deliveries: &mut Vec<Incoming<H::Digest>>,
    ) -> Option<Message<H, V, B>> {
        while deliveries.len() < self.registry.capacity() {
            match self.receiver.try_recv() {
                Ok(Message::Deliver(incoming))
                    if matches!(incoming.delivery.key, BackfillKey::ProducerBlock { .. }) =>
                {
                    deliveries.push(incoming);
                }
                Ok(message) => return Some(message),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return None,
            }
        }
        None
    }

    /// Validates one peer response and completes its waiters, adds it to `job` for staging, or
    /// starts its L-QC verification. Returns whether the response was accepted.
    fn admit<R, Q>(
        &mut self,
        resolver: &mut R,
        verifier: &Q,
        incoming: Incoming<H::Digest>,
        job: &mut StagingJob<H, V, B>,
        process: &Span,
    ) -> bool
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
        Q: LqcVerifier<H, V> + Clone,
    {
        let Incoming {
            delivery,
            value,
            response,
            ..
        } = incoming;
        let key = delivery.key;
        if !self.registry.contains(&key) {
            self.respond(response, Outcome::Ignored);
            return false;
        }
        let bytes = u64::try_from(value.len()).unwrap_or(u64::MAX);
        let Some(resolved) = validate::decode::<H, V, B>(&self.limits, key, value) else {
            self.respond(response, Outcome::Invalid);
            return false;
        };
        if let Resolved::Lqc(id, proof) = &resolved {
            // A retry after the running verification finishes completes the key or tries
            // another peer; retiring it now would strand the waiters if the proof is invalid.
            if self.verifications.is_active(&key) || self.verifications.is_saturated() {
                self.respond(response, Outcome::Ambiguous);
                return false;
            }
            let (id, proof) = (*id, Arc::clone(proof));
            let ready = Ready {
                delivery,
                resolved,
                response,
            };
            self.verify(verifier, id, proof, ready, process);
            return true;
        }
        let stages = match &resolved {
            Resolved::Block(reference, _) => self.registry.waiters(&key).any(|waiter| {
                matches!(
                    &waiter.target,
                    Target::Block { reference: expected, mode } if expected == reference && mode.stages()
                )
            }),
            Resolved::Blocks(..) => {
                if !self
                    .registry
                    .waiters(&key)
                    .any(|waiter| waiter.target.accepts(&resolved))
                {
                    self.respond(response, Outcome::Invalid);
                    return false;
                }
                true
            }
            Resolved::Lqc(..) | Resolved::History(..) | Resolved::Headers(..) => false,
        };
        if !stages {
            let outcome = self.complete(resolver, Some(&delivery), resolved);
            self.respond(response, outcome);
            return true;
        }
        if self.staging.is_reserved(&key) {
            self.respond(response, Outcome::Ignored);
            return false;
        }
        if self.staging.is_saturated() {
            self.respond(response, Outcome::Ambiguous);
            return false;
        }
        if let (BackfillKey::ProducerBlocks { max_items, .. }, Resolved::Blocks(_, blocks)) =
            (key, &resolved)
        {
            self.metrics
                .range_received(usize::from(max_items.get()), blocks.len());
        }
        self.staging.reserve(key);
        job.push(
            Ready {
                delivery,
                resolved,
                response,
            },
            bytes,
        );
        true
    }

    /// Verifies the decoded peer L-QC `proof` of `ready` on the shared blocking pool, then admits
    /// it to the catalog.
    fn verify<Q: LqcVerifier<H, V> + Clone>(
        &mut self,
        verifier: &Q,
        id: CertificateId<H::Digest>,
        proof: Arc<Lqc<V, H::Digest>>,
        ready: Ready<H, V, B>,
        process: &Span,
    ) {
        let mut verifier = verifier.clone();
        let verified = Arc::clone(&proof);
        let span = process.clone();
        let task = self.context.child("verify").shared(true).spawn(move |_| {
            async move { verifier.verify(&verified).await.is_ok() }.instrument(span)
        });
        let catalog = self.catalog.clone();
        let key = ready.delivery.key;
        self.verifications.start(
            key,
            async move {
                let result = match task.await {
                    Ok(true) => catalog
                        .admit_lqc(proof.view(), id, proof)
                        .await
                        .map(|()| Verdict::Admitted)
                        .map_err(Error::from),
                    Ok(false) => Ok(Verdict::Invalid),
                    Err(error) => Err(Error::Verification(error)),
                };
                Verification { ready, result }
            }
            .instrument(process.clone()),
        );
    }

    fn on_verified<R>(
        &mut self,
        resolver: &mut R,
        verification: Verification<H, V, B>,
    ) -> Result<(), Error>
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
    {
        let Verification {
            ready:
                Ready {
                    delivery,
                    resolved,
                    response,
                },
            result,
        } = verification;
        if !self.verifications.finish(&delivery.key) {
            return Err(Error::Invalid("completed verification is not active"));
        }
        let outcome = match result? {
            Verdict::Admitted => self.complete(resolver, Some(&delivery), resolved),
            Verdict::Invalid => Outcome::Invalid,
        };
        self.respond(response, outcome);
        Ok(())
    }

    fn on_staged<R>(
        &mut self,
        resolver: &mut R,
        completion: StagingCompletion<H, V, B>,
    ) -> Result<(), Error>
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
    {
        let StagingCompletion { job, timer, result } = completion;
        timer.observe(self.context.as_present());
        self.staging.finish(&job)?;
        result?;
        for Ready {
            delivery,
            resolved,
            response,
        } in job.ready
        {
            let outcome = self.complete(resolver, Some(&delivery), resolved);
            self.respond(response, outcome);
        }
        Ok(())
    }

    fn on_recheck<R>(
        &mut self,
        resolver: &mut R,
        completion: Result<RecheckCompletion<H, V, B>, Aborted>,
    ) -> Result<(), Error>
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
    {
        let Ok(RecheckCompletion { key, result }) = completion else {
            return Ok(());
        };
        if !self.rechecks.finish(&key) {
            return Err(Error::Invalid("completed local recheck is not active"));
        }
        match result? {
            Some(resolved) => {
                self.complete(resolver, None, resolved);
            }
            None => {
                self.metrics.local_misses.inc();
                self.start_fetch(resolver, &key);
            }
        }
        Ok(())
    }

    fn on_canceled<R>(&mut self, resolver: &mut R, cancellation: Cancellation<H::Digest>)
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
    {
        if let Some(removed) = self.registry.remove(&cancellation.key, cancellation.id) {
            self.release(resolver, slice::from_ref(&removed));
        }
    }

    /// Registers a waiter for `target`, answered through `reply`.
    fn register<R>(
        &mut self,
        resolver: &mut R,
        span: Span,
        target: Target<H::Digest>,
        reply: Option<Reply<H, V, B>>,
        reason: FetchReason,
    ) where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
    {
        if reply.as_ref().is_some_and(Reply::is_closed) {
            return;
        }
        if !target.in_epoch(self.limits.codec.chains()) {
            if let Some(reply) = reply {
                reply.fail(Error::Invalid("producer chain is outside the epoch"));
            }
            return;
        }
        let key = target.key();
        if let Target::Block { reference, mode } = &target
            && !target.is_marker()
            && self.registry.has_marker(&key, reference)
        {
            let reference = *reference;
            let target = Target::Block {
                reference,
                mode: mode.merge_certified(),
            };
            let waiter = self.waiter(key, span, target, reply, reason);
            self.registry.replace_marker(&key, &reference, waiter);
            if !self.rechecks.contains(&key) {
                self.start_fetch(resolver, &key);
            }
            return;
        }
        if self.registry.is_full() {
            let Eviction { evicted, room } = self.registry.make_room(&target, reason);
            self.release(resolver, &evicted);
            for Removed { waiter, .. } in evicted {
                waiter.fail(Error::PendingFull);
            }
            if !room {
                if let Some(reply) = reply {
                    reply.fail(Error::PendingFull);
                }
                return;
            }
        }
        let waiter = self.waiter(key, span, target, reply, reason);
        self.registry.insert(key, waiter);
        if !self.rechecks.queue(key) {
            self.metrics.local_recheck_coalesced.inc();
        }
    }

    /// Builds a waiter under a fresh identity whose reply reports its caller's cancellation.
    fn waiter(
        &mut self,
        key: BackfillKey<H::Digest>,
        span: Span,
        target: Target<H::Digest>,
        reply: Option<Reply<H, V, B>>,
        reason: FetchReason,
    ) -> Waiter<H, V, B> {
        let id = self.registry.allocate();
        let reply =
            reply.map(|reply| reply.track(Cancellation { key, id }, &mut self.cancellations));
        Waiter {
            id,
            target,
            reply,
            span,
            reason,
            state: FetchState::Idle,
        }
    }

    /// Starts a network fetch for every idle waiter of `key` that fetches.
    fn start_fetch<R>(&mut self, resolver: &mut R, key: &BackfillKey<H::Digest>)
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
    {
        let mut closed = Vec::new();
        for waiter in self.registry.waiters_mut(key) {
            let Some(reason) = waiter.fetch_reason() else {
                continue;
            };
            waiter.state = FetchState::Fetching;
            self.metrics.request(reason);
            if let BackfillKey::ProducerBlocks { max_items, .. } = key {
                self.metrics.range_requested(usize::from(max_items.get()));
            }
            debug!(?key, ?reason, subscriber = ?waiter.id, "starting exact marshal fetch");
            let submit = info_span!(
                parent: &waiter.span,
                "multimmit.marshal.resolver.fetch.submit",
                reason = ?reason,
            );
            let feedback = submit.in_scope(|| {
                resolver.fetch(Fetch {
                    key: *key,
                    subscriber: waiter.id,
                    span: waiter.span.clone(),
                })
            });
            if feedback == Feedback::Closed {
                closed.push(waiter.id);
            }
        }
        for id in closed {
            if let Some(removed) = self.registry.remove(key, id) {
                self.release(resolver, slice::from_ref(&removed));
                removed.waiter.fail(Error::NetworkClosed);
            }
        }
    }

    /// Cancels the network fetches and rechecks that removed waiters no longer need.
    fn release<R>(&mut self, resolver: &mut R, removed: &[Removed<H, V, B>])
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
    {
        let mut fetching = BTreeSet::new();
        for Removed {
            key,
            waiter,
            emptied,
        } in removed
        {
            if waiter.state == FetchState::Fetching {
                fetching.insert(waiter.id);
            }
            if *emptied {
                self.rechecks.cancel(key);
            }
        }
        if !fetching.is_empty() {
            let _ = resolver.retain(move |_, subscriber| !fetching.contains(subscriber));
        }
    }

    /// Completes every waiter of the resolved key that `resolved` satisfies.
    ///
    /// For a peer `delivery`, returns [`Outcome::Complete`] when every delivered waiter that is
    /// still registered accepted the value, and [`Outcome::Ambiguous`] otherwise.
    fn complete<R>(
        &mut self,
        resolver: &mut R,
        delivery: Option<&Delivery<BackfillKey<H::Digest>, BackfillSubscriber>>,
        resolved: Resolved<H, V, B>,
    ) -> Outcome
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
    {
        // An authenticated body also proves its header, so header waiters complete without
        // another network response or durability fence. A single block carries its already
        // checked reference; a range's references are computed here.
        match &resolved {
            Resolved::Block(reference, block) => {
                self.complete_headers(resolver, *reference, block);
            }
            Resolved::Blocks(_, blocks) => {
                for block in blocks.as_slice() {
                    self.complete_headers(resolver, block.reference(), block);
                }
            }
            Resolved::Lqc(..) | Resolved::History(..) | Resolved::Headers(..) => {}
        }
        let key = resolved.key();
        let complete = delivery.is_none_or(|delivery| {
            delivery.subscribers.iter().all(|(subscriber, _)| {
                self.registry
                    .waiters(&key)
                    .find(|waiter| waiter.id == *subscriber)
                    .is_none_or(|waiter| waiter.target.accepts(&resolved))
            })
        });
        let removed = self.registry.take_accepting(&resolved);
        self.release(resolver, &removed);
        for Removed { waiter, .. } in removed {
            waiter.complete(&resolved);
        }
        if complete {
            Outcome::Complete
        } else {
            Outcome::Ambiguous
        }
    }

    /// Completes the header waiters of `reference` with the header of `block`, its body.
    fn complete_headers<R>(
        &mut self,
        resolver: &mut R,
        reference: BlockRef<H::Digest>,
        block: &TransactionBlock<H, B>,
    ) where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
    {
        if self
            .registry
            .contains(&BackfillKey::producer_headers(reference))
        {
            self.complete(
                resolver,
                None,
                Resolved::Headers(reference, Arc::new(vec![block.header().clone()])),
            );
        }
    }

    fn on_certified<R>(&mut self, resolver: &mut R, reference: BlockRef<H::Digest>)
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
    {
        if !in_epoch(&reference, self.limits.codec.chains()) {
            return;
        }
        let key = BackfillKey::producer_block(reference.chain(), reference.digest());
        let mut held = false;
        let mut promoted = false;
        for waiter in self.registry.waiters_mut(&key) {
            if let Target::Block {
                reference: expected,
                mode,
            } = &mut waiter.target
                && *expected == reference
            {
                held = true;
                let certified = mode.on_certified();
                promoted |= certified != *mode;
                *mode = certified;
            }
        }
        if promoted && !self.rechecks.contains(&key) {
            self.start_fetch(resolver, &key);
        }
        if !held && !self.registry.is_full() {
            let target = Target::Block {
                reference,
                mode: BlockMode::Certified,
            };
            self.register(resolver, Span::none(), target, None, FetchReason::Certified);
        }
    }

    fn retire_certified<R>(&mut self, resolver: &mut R, frontiers: &[BlockRef<H::Digest>])
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
    {
        let removed = self.registry.remove_where(|waiter| match &waiter.target {
            Target::Block {
                reference,
                mode: BlockMode::Certified,
            } => frontiers.iter().any(|frontier| {
                frontier.chain() == reference.chain() && frontier.height() >= reference.height()
            }),
            _ => false,
        });
        self.release(resolver, &removed);
    }

    fn on_admitted_block<R>(
        &mut self,
        resolver: &mut R,
        reference: BlockRef<H::Digest>,
        block: Arc<TransactionBlock<H, B>>,
    ) -> Result<(), Error>
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
    {
        if block.reference() != reference || block.header().epoch() != self.limits.epoch {
            return Err(Error::Invalid("admitted block identity mismatch"));
        }
        self.complete(
            resolver,
            None,
            Resolved::Block(reference, Arc::clone(&block)),
        );
        let ranges = self.registry.ranges_from(reference).collect::<Vec<_>>();
        let blocks = Arc::new(vec![block]);
        for key in ranges {
            self.complete(resolver, None, Resolved::Blocks(key, Arc::clone(&blocks)));
        }
        Ok(())
    }

    fn on_admitted_history<R>(
        &mut self,
        resolver: &mut R,
        commitment: H::Digest,
        record: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Error>
    where
        R: Resolver<Key = BackfillKey<H::Digest>, Subscriber = BackfillSubscriber>,
    {
        if record.commitment::<H>() != commitment {
            return Err(Error::Invalid("admitted history identity mismatch"));
        }
        self.complete(
            resolver,
            None,
            Resolved::History(commitment, Arc::new(vec![record])),
        );
        Ok(())
    }

    fn respond(&self, response: DeliveryReply, outcome: Outcome) {
        self.metrics.outcome(outcome);
        response.send(outcome);
    }
}
