//! The router: runs the public mailbox's staging, subscription, floor and hint work.
//!
//! Each request becomes a job (or a coalesced subscription) that outlives the caller, so a
//! dropped caller never cancels storage work or its follow-up notifications. At most
//! `max_jobs` jobs run at once. At the bound the router stops taking requests, which queue in
//! its mailbox; once that is full too, the public mailbox answers [`Error::Busy`] for staging
//! and floor installation, while block subscriptions wait for a subscription slot.

use super::subscriptions::{Event, Found, Origin, Subscriptions};
use crate::{
    Viewable as _,
    multimmit::{
        actors::util::{Completion, gated},
        marshal::{
            actors::{backfill, catalog, synchronizer},
            bodies::Bodies,
            mailbox::{Mailbox, Message, Request, SubscriptionSlot, SubscriptionSlots},
            relay::Staged,
            types::{Custody, Error, Floor, Reply},
        },
        types::{Activity, Artifact, BlockRef, Body, TransactionBlock},
    },
};
use commonware_actor::mailbox::{self as actor_mailbox, UnreliableReceiver};
use commonware_broadcast::buffered;
use commonware_cryptography::{Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    ContextCell, Handle, Metrics as RuntimeMetrics, Spawner, spawn_cell,
    telemetry::metrics::{Counter, Gauge, GaugeExt as _, MetricsExt as _},
};
use commonware_utils::{channel::fallible::OneshotExt as _, futures::Pool, sync::Mutex};
use futures::pin_mut;
use std::{future::Future, num::NonZeroUsize, sync::Arc};
use tracing::{Instrument as _, Span, debug_span, info_span};

/// The outcome of one router job; an error stops the router.
type JobResult = Result<(), Error>;

/// Router configuration.
pub(super) struct Config<E, H, V, B, P>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
    P: PublicKey,
{
    /// Runtime context of the router task.
    pub(super) context: E,
    /// Stages blocks, hint artifacts and subscribed blocks; also answers the public mailbox.
    pub(super) catalog: catalog::Mailbox<H, V, B>,
    /// Body lookups for the public mailbox.
    pub(super) bodies: Bodies<H, V, B>,
    /// Resolves subscribed blocks and hears of admitted ones; also answers the public mailbox.
    pub(super) backfill: backfill::Mailbox<H, V, B>,
    /// Receives consensus hints and floor installations.
    pub(super) synchronizer: synchronizer::Mailbox<V, H::Digest>,
    /// Buffered broadcast ingress, raced against backfill by block subscriptions.
    pub(super) broadcast: buffered::Mailbox<P, TransactionBlock<H, B>>,
    /// Capacity of the router's request queue.
    pub(super) mailbox_size: NonZeroUsize,
    /// Most jobs in flight.
    pub(super) max_jobs: NonZeroUsize,
    /// Most callers waiting for block subscriptions.
    pub(super) subscription_callers: NonZeroUsize,
    /// Blocks the public mailbox stages, kept for the relay when one exists.
    pub(super) staged: Option<Arc<Mutex<Staged<H, B>>>>,
}

/// Runs routed requests as bounded jobs and coalesced subscriptions.
pub(super) struct Actor<E, H, V, B, P>
where
    E: Spawner + RuntimeMetrics,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    P: PublicKey,
{
    context: ContextCell<E>,
    catalog: catalog::Mailbox<H, V, B>,
    backfill: backfill::Mailbox<H, V, B>,
    synchronizer: synchronizer::Mailbox<V, H::Digest>,
    broadcast: buffered::Mailbox<P, TransactionBlock<H, B>>,
    mailbox: UnreliableReceiver<Message<H, V, B>>,
    jobs: Pool<'static, JobResult>,
    subscriptions: Subscriptions<H, B>,
    max_jobs: usize,
    metrics: Metrics,
}

impl<E, H, V, B, P> Actor<E, H, V, B, P>
where
    E: Spawner + RuntimeMetrics,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    P: PublicKey,
{
    /// Creates the router and the public mailbox that feeds it.
    pub(super) fn new(config: Config<E, H, V, B, P>) -> (Self, Mailbox<H, V, B>) {
        let Config {
            context,
            catalog,
            bodies,
            backfill,
            synchronizer,
            broadcast,
            mailbox_size,
            max_jobs,
            subscription_callers,
            staged,
        } = config;
        let (sender, receiver) =
            actor_mailbox::new_unreliable(context.child("mailbox"), mailbox_size);
        let mailbox = Mailbox::new(
            sender,
            catalog.clone(),
            bodies,
            backfill.clone(),
            Arc::new(SubscriptionSlots::new(subscription_callers)),
            staged,
        );
        let router = Self {
            metrics: Metrics::new(&context),
            context: ContextCell::new(context),
            catalog,
            backfill,
            synchronizer,
            broadcast,
            mailbox: receiver,
            jobs: Pool::default(),
            subscriptions: Subscriptions::new(subscription_callers.get()),
            max_jobs: max_jobs.get(),
        };
        (router, mailbox)
    }

    /// Starts the router task.
    pub(super) fn start(mut self) -> Handle<Result<(), Error>> {
        spawn_cell!(self.context, self.run())
    }

    /// Serves requests until every public mailbox is dropped.
    ///
    /// Each turn waits for the first of: a finished job, a subscription event, a request (only
    /// below the job bound). A failed job stops the router.
    async fn run(mut self) -> Result<(), Error> {
        select_loop! {
            self.context,
            on_start => {
                let subscriptions = self.subscriptions.stats();
                self.metrics
                    .update(self.jobs.len(), subscriptions.blocks, subscriptions.callers);
                let receive = self.jobs.len() < self.max_jobs;
            },
            on_stopped => {},
            result = self.jobs.next_completed() => result?,
            event = self.subscriptions.next() => match event {
                Some(Event::Found(found)) => self.on_found(found),
                Some(Event::Settled(found)) => self.on_settled(found),
                None => {}
            },
            Some(message) = gated(receive, self.mailbox.recv()) else break => {
                self.drain(message);
            },
        }
        Ok(())
    }

    fn push(&mut self, job: impl Future<Output = JobResult> + Send + 'static) {
        self.jobs.push(job.instrument(Span::current()));
    }

    /// Dispatches a burst of requests bounded by the remaining job capacity.
    ///
    /// Dispatched work runs in its caller's span when the drain span is disabled.
    fn drain(&mut self, first: Message<H, V, B>) {
        let capacity = self.max_jobs.saturating_sub(self.jobs.len()).max(1);
        let drain = debug_span!(
            parent: None,
            "multimmit.marshal.router.drain",
            triggered_by = first.request.kind(),
            commands = tracing::field::Empty,
            hints = tracing::field::Empty,
        );
        let _guard = drain.enter();
        let mut commands = 0usize;
        let mut hints = 0u64;
        let mut next = Some(first);
        while let Some(message) = next {
            if let Some(id) = message.span.id() {
                drain.follows_from(id);
            }
            commands += 1;
            hints += u64::from(matches!(message.request, Request::Hint { .. }));
            let _origin = drain.is_disabled().then(|| message.span.enter());
            self.dispatch(message.request);
            next = (commands < capacity)
                .then(|| self.mailbox.try_recv().ok())
                .flatten();
        }
        drain.record("commands", commands);
        drain.record("hints", hints);
        self.metrics.hints(hints);
    }

    fn dispatch(&mut self, request: Request<H, V, B>) {
        match request {
            Request::Hint { activity } => self.on_hint(activity),
            Request::StageBlock { block, reply } => self.on_stage(block, reply),
            Request::SubscribeBlock {
                reference,
                reply,
                slot,
            } => self.on_subscribe(reference, reply, slot),
            Request::InstallFloor { floor, reply } => self.on_install_floor(floor, reply),
        }
    }

    /// Forwards a consensus hint.
    ///
    /// Hints are advisory: a full child mailbox may drop them and a closed child is reported by
    /// the supervisor, so enqueue results are ignored.
    fn on_hint(&mut self, activity: Activity<V, H::Digest>) {
        match activity {
            Activity::TransactionProposed { .. } => {}
            Activity::CommitmentsAccepted { commitments } => {
                let _ = self.synchronizer.commitments(commitments);
            }
            Activity::ProtocolAccepted {
                artifact_id,
                artifact,
            } => {
                if artifact.id::<H>() != artifact_id {
                    return;
                }
                match artifact.as_ref() {
                    Artifact::TransactionBlock(block) => {
                        let _ = self.synchronizer.header(block.header().clone());
                    }
                    Artifact::DaCertificate(certificate) => {
                        let _ = self.synchronizer.header(certificate.header().clone());
                        let _ = self.backfill.certified_block(certificate.block_ref::<H>());
                    }
                    Artifact::Lqc(proof) => {
                        let proof = Arc::new(proof.clone());
                        let id = proof.id::<H>();
                        let view = proof.view();
                        let catalog = self.catalog.clone();
                        let synchronizer = self.synchronizer.clone();
                        self.push(async move {
                            match catalog.stage_lqc(view, id, Arc::clone(&proof)).await {
                                Ok(()) => {}
                                // An L-QC the catalog rejects (such as one from another epoch)
                                // is only a hint, so it is dropped.
                                Err(error) if error.is_rejected() => return Ok(()),
                                Err(error) => return Err(error.into()),
                            }
                            synchronizer.trigger(id, proof).map_err(Error::from)
                        });
                    }
                    _ => {}
                }
            }
            Activity::HistoryAccepted {
                view,
                commitment,
                record,
            } => {
                if record.commitment::<H>() != commitment {
                    return;
                }
                let catalog = self.catalog.clone();
                let backfill = self.backfill.clone();
                self.push(async move {
                    match catalog
                        .stage_history(view, commitment, Arc::clone(&record))
                        .await
                    {
                        Ok(()) => {}
                        // A history record the catalog rejects is only a hint, so it is dropped.
                        Err(error) if error.is_rejected() => return Ok(()),
                        Err(error) => return Err(error.into()),
                    }
                    backfill
                        .admitted_history(commitment, record)
                        .await
                        .map_err(Error::from)
                });
            }
            Activity::LeaderFinalized { fact } | Activity::LeaderFinalityUpdated { fact } => {
                let _ = self.synchronizer.finality(fact);
            }
        }
    }

    /// Stages a block, replies with its custody completion, and tells backfill once it is
    /// durable.
    fn on_stage(&mut self, block: Arc<TransactionBlock<H, B>>, reply: Reply<Custody, Error>) {
        let reference = block.reference();
        let catalog = self.catalog.clone();
        let backfill = self.backfill.clone();
        self.push(async move {
            let custody = match catalog.stage_block(Arc::clone(&block)).await {
                Ok(custody) => custody,
                Err(error) => {
                    reply.send_lossy(Err(error.into()));
                    return Ok(());
                }
            };
            let (completion, token) = Completion::channel(|| Error::Closed);
            reply.send_lossy(Ok(token));
            let result = custody.wait().await.map_err(Error::from);
            // Catalog durability establishes custody; backfill notification is downstream
            // bookkeeping and must not extend the producer's custody fence.
            completion.send_lossy(result.clone());
            result?;
            backfill
                .admitted_block(reference, block)
                .await
                .map_err(Error::from)
        });
    }

    /// Joins or starts the subscription for `reference`, holding the caller's `slot` until the
    /// caller is dropped.
    ///
    /// The subscription races buffered broadcast ingress against backfill, falling back to the
    /// other when the first fails; only this race is abandoned when every caller leaves. The
    /// found block is then made durable custody by [`Self::on_found`], and callers are answered.
    fn on_subscribe(
        &mut self,
        reference: BlockRef<H::Digest>,
        reply: Reply<Arc<TransactionBlock<H, B>>, Error>,
        slot: SubscriptionSlot,
    ) {
        let broadcast = self.broadcast.clone();
        let backfill = self.backfill.clone();
        let race = async move {
            let received = broadcast.subscribe(reference.digest());
            let buffered = async move {
                received
                    .await
                    .ok()
                    .filter(|block| block.reference() == reference)
            };
            let resolved = backfill
                .subscribe_block(reference)
                .instrument(info_span!("multimmit.marshal.subscribe.resolve"));
            pin_mut!(buffered, resolved);
            let (block, origin) = select! {
                block = &mut buffered => match block {
                    Some(block) => (block, Origin::Buffer),
                    None => (resolved.await?, Origin::Backfill),
                },
                result = &mut resolved => match result {
                    Ok(block) => (block, Origin::Backfill),
                    Err(error) => match buffered.await {
                        Some(block) => (block, Origin::Buffer),
                        None => return Err(error.into()),
                    },
                },
            };
            Ok(Found {
                reference,
                block,
                origin,
                span: Span::current(),
            })
        }
        .instrument(Span::current());
        self.subscriptions.insert(reference, reply, slot, race);
    }

    /// Makes a found block durable custody, whether or not its callers remain.
    fn on_found(&mut self, found: Found<H, B>) {
        let catalog = self.catalog.clone();
        let reference = found.reference;
        let block = Arc::clone(&found.block);
        let custody = info_span!(parent: &found.span, "multimmit.marshal.subscribe.custody");
        self.subscriptions.settle(found, async move {
            Ok(catalog
                .admit_block(reference, block)
                .instrument(custody)
                .await?)
        });
    }

    /// Tells backfill about a block a subscription took from buffered ingress.
    ///
    /// This runs as a job once the block is durable custody, so it neither delays the callers
    /// nor depends on them staying.
    fn on_settled(&mut self, found: Found<H, B>) {
        // Backfill delivered its own blocks.
        if found.origin == Origin::Backfill {
            return;
        }
        let Found {
            reference, block, ..
        } = found;
        let backfill = self.backfill.clone();
        self.push(async move { Ok(backfill.admitted_block(reference, block).await?) });
    }

    /// Installs a floor and, once installed, lets backfill retire certified blocks below it.
    fn on_install_floor(&mut self, floor: Floor<V, H::Digest>, reply: Reply<(), Error>) {
        let synchronizer = self.synchronizer.clone();
        let backfill = self.backfill.clone();
        let frontiers = floor.emitted.clone();
        self.push(async move {
            let result = synchronizer.install_floor(floor).await;
            if result.is_ok() {
                backfill
                    .retire_certified(frontiers)
                    .await
                    .map_err(Error::from)?;
            }
            reply.send_lossy(result.map_err(Error::from));
            Ok(())
        });
    }
}

/// Router throughput and pressure.
struct Metrics {
    /// Reporter hints accepted from consensus. The observation rate the router must keep up with.
    hints: Counter,
    jobs: Gauge,
    subscriptions: Gauge,
    subscription_callers: Gauge,
}

impl Metrics {
    fn new(context: &impl RuntimeMetrics) -> Self {
        Self {
            hints: context.counter(
                "hints_total",
                "Reporter hints dispatched by the marshal router",
            ),
            jobs: context.gauge("pending_jobs", "Concurrent marshal router jobs"),
            subscriptions: context.gauge(
                "block_subscriptions",
                "Distinct producer blocks with a live subscription",
            ),
            subscription_callers: context.gauge(
                "block_subscription_callers",
                "Callers waiting for a producer-block subscription",
            ),
        }
    }

    /// Counts hints dispatched in one drain.
    fn hints(&self, hints: u64) {
        self.hints.inc_by(hints);
    }

    /// Publishes jobs in flight and subscription pressure.
    fn update(&self, jobs: usize, subscriptions: usize, callers: usize) {
        let _ = self.jobs.try_set(jobs);
        let _ = self.subscriptions.try_set(subscriptions);
        let _ = self.subscription_callers.try_set(callers);
    }
}
