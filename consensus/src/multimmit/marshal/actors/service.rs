//! Actor composition and public routing for Multimmit marshal.

use super::{
    broadcast,
    catalog::{self, CatalogClient},
    delivery, metrics, promoter, resolver,
    subscriptions::{Completion as SubscriptionCompletion, Subscriptions},
    synchronizer::{self, LqcVerifier},
};
use crate::{
    Reporter, Viewable as _,
    multimmit::{
        machine::Artifact,
        marshal::{
            config::Config,
            mailbox::{self, Command, Progress, Request},
            storage::scratch::{BlockScratch, HistoryScratch},
            types::Update,
            wire,
        },
        types::{BlockRef, TransactionBlock},
    },
};
use commonware_broadcast::buffered;
use commonware_codec::Codec;
use commonware_cryptography::{
    Digestible, Hasher, PublicKey, bls12381::primitives::variant::Variant,
};
use commonware_macros::select;
use commonware_resolver::Resolver;
use commonware_runtime::{Handle, Spawner};
use commonware_storage::{Context, translator::Translator};
use commonware_utils::{
    acknowledgement::Exact,
    futures::{AbortablePool, Pool},
};
use std::{
    future::{Future, pending},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tracing::{Instrument as _, Span, info_span};

/// Resolver-facing producer and consumer allocated before the network resolver is constructed.
pub type ResolverBridge<H, V, B> = resolver::Bridge<H, V, B>;

enum RouterEvent<J, S, R, C> {
    Job(J),
    Subscription(S),
    Subscriber(R),
    Command(C),
}

async fn next_router_event<J, S, R, C>(
    job: J,
    subscription: S,
    subscriber: R,
    command: C,
    receive: bool,
) -> RouterEvent<J::Output, S::Output, R::Output, C::Output>
where
    J: Future,
    S: Future,
    R: Future,
    C: Future,
{
    let command = async move {
        if receive {
            command.await
        } else {
            pending().await
        }
    };
    select! {
        result = job => RouterEvent::Job(result),
        result = subscription => RouterEvent::Subscription(result),
        result = subscriber => RouterEvent::Subscriber(result),
        result = command => RouterEvent::Command(result),
    }
}

type JobResult = Result<(), mailbox::Error>;

/// Open storage and allocate the resolver bridge before its network resolver exists.
pub struct Service<E, H, V, B, P>
where
    E: Context,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    P: PublicKey,
{
    context: E,
    catalog: CatalogClient<H, V, B>,
    catalog_handle: Handle<Result<(), catalog::Error>>,
    promoter: Option<promoter::Client<H, B>>,
    promoter_handle: Option<Handle<Result<(), promoter::Error>>>,
    delivery_commands: delivery::DeliveryReceiver<H, B>,
    resolver_endpoint: resolver::Endpoint<H, V, B>,
    resolver_config: resolver::Config<B::Cfg>,
    history_scratch: HistoryScratch<E, H>,
    block_scratch: BlockScratch<E, H::Digest>,
    broadcast: broadcast::Mailbox<P, TransactionBlock<H, B>>,
    router_capacity: NonZeroUsize,
    resolver_capacity: NonZeroUsize,
    max_resolved_block_bytes: NonZeroUsize,
    codec: crate::multimmit::config::CodecConfig,
    backfill_concurrency: NonZeroUsize,
    header_cache_capacity: NonZeroUsize,
    max_commit_outputs: NonZeroUsize,
    max_commit_block_bytes: NonZeroUsize,
    max_pending_acks: NonZeroUsize,
    max_delivery_bytes: NonZeroUsize,
    max_hot_block_bytes: NonZeroUsize,
}

/// Opens marshal-owned storage and returns the bridge used to construct the network resolver.
pub async fn open<E, T, H, V, B, P>(
    context: E,
    config: Config<T, V, B>,
    buffer: buffered::Mailbox<P, TransactionBlock<H, B>>,
) -> Result<(Service<E, H, V, B, P>, ResolverBridge<H, V, B>), mailbox::Error>
where
    E: Context + Spawner,
    T: Translator,
    H: Hasher<Digest = B::Digest>,
    V: Variant,
    B: Codec + Digestible,
    B::Cfg: Clone + Send + 'static,
    P: PublicKey,
{
    config.validate().map_err(mailbox::Error::failed)?;
    let router_capacity = config.catalog_mailbox_size;
    let resolver_capacity = config.resolver_mailbox_size;
    let max_resolved_block_bytes = config.resolver_max_value_bytes;
    let codec = config.codec_config;
    let backfill_concurrency = config.effective_backfill_concurrency();
    let max_commit_outputs = config.max_commit_outputs;
    let max_commit_block_bytes = config.max_commit_block_bytes;
    let header_cache_capacity = config.header_cache_capacity;
    let max_pending_acks = config.max_pending_acks;
    let max_delivery_bytes = config.max_delivery_bytes;
    let max_hot_block_bytes = config.max_hot_block_bytes;
    let resolver_config = resolver::Config::new(
        config.epoch,
        codec,
        config.body_codec_config.clone(),
        config.resolver_max_value_bytes,
    );
    let history_scratch = HistoryScratch::init(
        context.child("history_scratch"),
        config.archive.scratch(
            format!("{}_history_scratch", config.partition_prefix),
            config.chains.get() as usize,
        ),
    )
    .await
    .map_err(mailbox::Error::failed)?;
    let block_scratch = BlockScratch::init(
        context.child("block_scratch"),
        config
            .archive
            .scratch(format!("{}_block_scratch", config.partition_prefix), ()),
    )
    .await
    .map_err(mailbox::Error::failed)?;
    let (bridge, resolver_endpoint) = resolver::channel(
        context.child("resolver_bridge"),
        context.child("resolver_producer_bridge"),
        resolver_capacity,
    );
    let (delivery, delivery_commands) =
        delivery::channel(context.child("delivery").child("mailbox"));
    let (catalog, catalog_handle, promoter, promoter_handle) = config
        .spawn(context.child("storage"), delivery)
        .await
        .map_err(mailbox::Error::failed)?;
    Ok((
        Service {
            context,
            catalog,
            catalog_handle,
            promoter,
            promoter_handle,
            delivery_commands,
            resolver_endpoint,
            resolver_config,
            history_scratch,
            block_scratch,
            broadcast: broadcast::Mailbox::new(buffer),
            router_capacity,
            resolver_capacity,
            max_resolved_block_bytes,
            codec,
            backfill_concurrency,
            header_cache_capacity,
            max_commit_outputs,
            max_commit_block_bytes,
            max_pending_acks,
            max_delivery_bytes,
            max_hot_block_bytes,
        },
        bridge,
    ))
}

struct Router<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    catalog: CatalogClient<H, V, B>,
    bodies: promoter::Bodies<H, V, B>,
    resolver: resolver::Client<H, V, B>,
    synchronizer: synchronizer::Client<V, H::Digest>,
    commands: commonware_actor::mailbox::UnreliableReceiver<Command<H, V, B>>,
    jobs: Pool<JobResult>,
    subscriptions: Subscriptions<H, B>,
    subscription_completions: AbortablePool<SubscriptionCompletion<H, B>>,
    subscription_callers: Pool<BlockRef<H::Digest>>,
    max_pending: usize,
    metrics: metrics::Router,
}

impl<H, V, B> Router<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn push(&mut self, future: impl Future<Output = JobResult> + Send + 'static) {
        self.jobs.push(future.instrument(Span::current()));
    }

    fn dispatch(&mut self, command: Command<H, V, B>) {
        let span = info_span!(
            parent: &command.span,
            "multimmit.marshal.router.process",
            request = command.request.kind(),
        );
        let _guard = span.enter();
        let command = match command.request {
            Request::SubscribeBlock(reference, reply) => {
                let resolver = self.resolver.clone();
                let catalog = self.catalog.clone();
                let span = Span::current();
                self.subscriptions.insert(
                    reference,
                    reply,
                    &mut self.subscription_completions,
                    &mut self.subscription_callers,
                    async move {
                        let block = resolver
                            .subscribe_block(reference)
                            .await
                            .map_err(mailbox::Error::failed)?;
                        catalog
                            .admit_block(reference, Arc::clone(&block))
                            .await
                            .map_err(mailbox::Error::failed)?;
                        Ok(block)
                    }
                    .instrument(span),
                );
                return;
            }
            command => command,
        };
        match command {
            Request::Hint(activity) => match activity {
                crate::multimmit::types::Activity::ProtocolAccepted {
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
                            let _ = self.resolver.certified_block(certificate.block_ref::<H>());
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
                                    Err(catalog::Error::Invalid(_)) => return Ok(()),
                                    Err(error) => return Err(mailbox::Error::failed(error)),
                                }
                                synchronizer
                                    .trigger(id, proof)
                                    .map_err(mailbox::Error::failed)?;
                                Ok(())
                            });
                        }
                        _ => {}
                    }
                }
                crate::multimmit::types::Activity::HistoryAccepted {
                    view,
                    commitment,
                    record,
                } => {
                    if record.commitment::<H>() != commitment {
                        return;
                    }
                    let catalog = self.catalog.clone();
                    let resolver = self.resolver.clone();
                    self.push(async move {
                        match catalog
                            .stage_history(view, commitment, Arc::clone(&record))
                            .await
                        {
                            Ok(()) => {}
                            Err(catalog::Error::Invalid(_)) => return Ok(()),
                            Err(error) => return Err(mailbox::Error::failed(error)),
                        }
                        resolver
                            .admitted_history(commitment, record)
                            .await
                            .map_err(mailbox::Error::failed)?;
                        Ok(())
                    });
                }
                crate::multimmit::types::Activity::LeaderFinalized { .. } => {}
            },
            Request::StageBlock(block, reply) => {
                let reference = block.reference();
                let catalog = self.catalog.clone();
                let resolver = self.resolver.clone();
                self.push(async move {
                    let custody = match catalog.stage_block(Arc::clone(&block)).await {
                        Ok(custody) => custody,
                        Err(error) => {
                            drop(reply.send(Err(mailbox::Error::failed(error))));
                            return Ok(());
                        }
                    };
                    let (completion, token) = mailbox::Custody::channel();
                    drop(reply.send(Ok(token)));
                    let result = custody.wait().await.map_err(mailbox::Error::failed);
                    // Catalog durability establishes custody; resolver notification is downstream
                    // bookkeeping and must not extend the producer's custody fence.
                    drop(completion.send(result.clone()));
                    result?;
                    resolver
                        .admitted_block(reference, block)
                        .await
                        .map_err(mailbox::Error::failed)
                });
            }
            Request::GetCertificate(id, reply) => {
                let catalog = self.catalog.clone();
                self.push(async move {
                    drop(reply.send(catalog.lqc(id).await.map_err(mailbox::Error::failed)));
                    Ok(())
                });
            }
            Request::FetchCertificate(id, mut reply) => {
                let resolver = self.resolver.clone();
                self.push(async move {
                    select! {
                        result = resolver.lqc(metrics::FetchReason::Explicit, id) => {
                            drop(reply.send(result.map_err(mailbox::Error::failed)));
                        },
                        _ = reply.closed() => {},
                    }
                    Ok(())
                });
            }
            Request::GetBlock(reference, reply) => {
                let bodies = self.bodies.clone();
                self.push(async move {
                    drop(
                        reply.send(
                            bodies
                                .block(reference)
                                .await
                                .map_err(mailbox::Error::failed),
                        ),
                    );
                    Ok(())
                });
            }
            Request::FetchBlock(reference, mut reply) => {
                let resolver = self.resolver.clone();
                self.push(async move {
                    select! {
                        result = resolver.block(metrics::FetchReason::Explicit, reference) => {
                            drop(reply.send(result.map_err(mailbox::Error::failed)));
                        },
                        _ = reply.closed() => {},
                    }
                    Ok(())
                });
            }
            Request::SubscribeBlock(_, _) => unreachable!("subscriptions are dispatched above"),
            Request::InstallFloor(floor, mut reply) => {
                let synchronizer = self.synchronizer.clone();
                let resolver = self.resolver.clone();
                let frontiers = floor.emitted.clone();
                self.push(async move {
                    select! {
                        result = synchronizer.install_floor(floor) => {
                            if result.is_ok() {
                                resolver
                                    .retire_certified(frontiers)
                                    .await
                                    .map_err(mailbox::Error::failed)?;
                            }
                            drop(reply.send(result.map_err(mailbox::Error::failed)));
                        },
                        _ = reply.closed() => {},
                    }
                    Ok(())
                });
            }
            Request::Prune(request, reply) => {
                let catalog = self.catalog.clone();
                self.push(async move {
                    drop(
                        reply.send(
                            catalog
                                .prune(request.generation())
                                .await
                                .map_err(mailbox::Error::failed),
                        ),
                    );
                    Ok(())
                });
            }
            Request::Progress(reply) => {
                let catalog = self.catalog.clone();
                self.push(async move {
                    let result = catalog
                        .progress()
                        .await
                        .map(|progress| Progress {
                            generation: progress.generation,
                            floor: progress.floor,
                            committed: progress.committed,
                            acknowledged: progress.acknowledged,
                        })
                        .map_err(mailbox::Error::failed);
                    drop(reply.send(result));
                    Ok(())
                });
            }
        }
    }

    async fn run(mut self) -> Result<(), mailbox::Error> {
        loop {
            let (subscriptions, callers) = self.subscriptions.stats();
            self.metrics
                .update(self.jobs.len(), subscriptions, callers);
            let receive = self.jobs.len() < self.max_pending;
            match next_router_event(
                self.jobs.next_completed(),
                self.subscription_completions.next_completed(),
                self.subscription_callers.next_completed(),
                self.commands.recv(),
                receive,
            )
            .await
            {
                RouterEvent::Command(command) => {
                    let Some(command) = command else {
                        return Ok(());
                    };
                    self.dispatch(command);
                }
                RouterEvent::Job(result) => result?,
                RouterEvent::Subscription(Ok((reference, result))) => {
                    self.subscriptions.complete(reference, result);
                }
                RouterEvent::Subscription(Err(_)) => {}
                RouterEvent::Subscriber(reference) => self.subscriptions.retain_open(reference),
            }
        }
    }
}

fn child_result<T: std::fmt::Display>(
    role: &'static str,
    result: Result<Result<(), T>, commonware_runtime::Error>,
) -> Result<(), mailbox::Error> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(mailbox::Error::Failed(Arc::from(format!(
            "{role} failed: {error}"
        )))),
        Err(error) => Err(mailbox::Error::Failed(Arc::from(format!(
            "{role} runtime failed: {error}"
        )))),
    }
}

async fn promoter_result(
    handle: &mut Option<Handle<Result<(), promoter::Error>>>,
) -> Result<Result<(), promoter::Error>, commonware_runtime::Error> {
    match handle {
        Some(handle) => handle.await,
        None => pending().await,
    }
}

struct Children {
    catalog: Handle<Result<(), catalog::Error>>,
    promoter: Option<Handle<Result<(), promoter::Error>>>,
    resolver: Handle<Result<(), resolver::Error>>,
    synchronizer: Handle<Result<(), synchronizer::Error>>,
    delivery: Handle<Result<(), delivery::Error>>,
    router: Handle<Result<(), mailbox::Error>>,
}

impl Children {
    fn abort(&self) {
        self.catalog.abort();
        if let Some(promoter) = &self.promoter {
            promoter.abort();
        }
        self.resolver.abort();
        self.synchronizer.abort();
        self.delivery.abort();
        self.router.abort();
    }
}

impl Drop for Children {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Lifecycle owner for a running marshal service.
pub struct Running {
    task: Handle<Result<(), mailbox::Error>>,
    shutdown_requested: AtomicBool,
}

impl Running {
    /// Requests shutdown of the service and every child actor.
    pub fn abort(&self) {
        self.shutdown_requested.store(true, Ordering::Relaxed);
        self.task.abort();
    }

    /// Waits for the service to stop and returns its first component failure.
    pub async fn join(self) -> Result<(), mailbox::Error> {
        let shutdown_requested = self.shutdown_requested.load(Ordering::Relaxed);
        match self.task.await {
            Ok(result) => result,
            Err(commonware_runtime::Error::Closed | commonware_runtime::Error::Aborted)
                if shutdown_requested =>
            {
                Ok(())
            }
            Err(error) => Err(mailbox::Error::failed(error)),
        }
    }
}

impl<E, H, V, B, P> Service<E, H, V, B, P>
where
    E: Context + Spawner,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    B::Cfg: Send + 'static,
    P: PublicKey,
{
    #[cfg(test)]
    pub(in crate::multimmit::marshal) fn catalog(&self) -> CatalogClient<H, V, B> {
        self.catalog.clone()
    }

    /// Starts every actor after the caller has attached the resolver bridge to its transport.
    pub fn start<R, Q, A>(
        self,
        network: R,
        verifier: Q,
        application: A,
    ) -> (mailbox::Mailbox<H, V, B, P>, Running)
    where
        R: Resolver<Key = wire::Key<H::Digest>, Subscriber = resolver::Subscriber>,
        Q: LqcVerifier<H, V> + Clone,
        A: Reporter<Activity = Update<TransactionBlock<H, B>, Exact>>,
    {
        let bodies = promoter::Bodies::new(self.catalog.clone(), self.promoter.clone());
        let (resolver, resolver_handle) = resolver::spawn(
            self.context.child("resolver"),
            self.resolver_endpoint,
            network,
            verifier.clone(),
            self.resolver_config,
            self.catalog.clone(),
            bodies.clone(),
            self.resolver_capacity,
            self.backfill_concurrency,
        );
        let delivery_handle = delivery::spawn(
            self.context.child("delivery"),
            self.catalog.clone(),
            bodies.clone(),
            application,
            self.delivery_commands,
            delivery::Bounds {
                pending_acks: self.max_pending_acks,
                delivery_bytes: self.max_delivery_bytes,
                hot_block_bytes: self.max_hot_block_bytes,
            },
        );
        let (synchronizer, synchronizer_handle) = synchronizer::spawn(
            self.context.child("synchronizer"),
            self.resolver_capacity,
            self.catalog.clone(),
            resolver::CustodyFetcher::new(resolver.clone(), self.catalog.clone()),
            self.history_scratch,
            self.block_scratch,
            self.header_cache_capacity,
            verifier,
            self.codec,
            self.backfill_concurrency,
            self.max_commit_outputs,
            self.max_commit_block_bytes,
            self.max_resolved_block_bytes,
        );
        let router_context = self.context.child("router");
        let (mailbox, commands) = mailbox::channel(
            router_context.child("mailbox"),
            self.router_capacity,
            self.broadcast.clone(),
        );
        let metrics = metrics::Router::new(&router_context);
        let router = Router {
            catalog: self.catalog,
            bodies,
            resolver,
            synchronizer,
            commands,
            jobs: Pool::default(),
            subscriptions: Subscriptions::new(self.resolver_capacity.get()),
            subscription_completions: AbortablePool::default(),
            subscription_callers: Pool::default(),
            max_pending: self.resolver_capacity.get(),
            metrics,
        };
        let router_handle = router_context.shared(false).spawn(move |_| router.run());
        let mut children = Children {
            catalog: self.catalog_handle,
            promoter: self.promoter_handle,
            resolver: resolver_handle,
            synchronizer: synchronizer_handle,
            delivery: delivery_handle,
            router: router_handle,
        };
        let handle = self
            .context
            .child("supervisor")
            .shared(false)
            .spawn(move |_| async move {
                let result = select! {
                    result = &mut children.catalog => child_result("catalog", result),
                    result = promoter_result(&mut children.promoter) => child_result("promoter", result),
                    result = &mut children.resolver => child_result("resolver", result),
                    result = &mut children.synchronizer => child_result("synchronizer", result),
                    result = &mut children.delivery => child_result("delivery", result),
                    result = &mut children.router => child_result("router", result),
                };
                children.abort();
                result
            });
        (
            mailbox,
            Running {
                task: handle,
                shutdown_requested: AtomicBool::new(false),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{RouterEvent, next_router_event};
    use futures::executor::block_on;
    use std::future::{pending, ready};

    #[test]
    fn router_prefers_completed_work_to_ready_intake() {
        let event = block_on(next_router_event(
            ready(1),
            pending::<u8>(),
            pending::<u8>(),
            ready(3),
            true,
        ));
        assert!(matches!(event, RouterEvent::Job(1)));
    }
}
