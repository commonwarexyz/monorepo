use super::{
    cache,
    config::Config,
    ingress::{
        handler::Request,
        mailbox::{Mailbox, MailboxMessage},
    },
};
use crate::{
    marshal::{
        ingress::handler,
        store::{Blocks, Certificates},
        Update,
    },
    simplex::scheme::Scheme,
    types::{Epoch, Epocher, Height, Round, ViewDelta},
    Block, Reporter,
};
use commonware_actor::Actor as ActorTrait;
use commonware_broadcast::buffered;
use commonware_cryptography::{
    certificate::{Provider, Scheme as CertificateScheme},
    PublicKey,
};
use commonware_macros::select;
use commonware_parallel::Strategy;
use commonware_resolver::Resolver;
use commonware_runtime::{telemetry::metrics::status::GaugeExt, Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, mpsc, oneshot},
    futures::{AbortablePool, Aborter, OptionFuture},
    sequence::U64,
    Acknowledgement, BoxedError,
};
use pin_project::pin_project;
use prometheus_client::metrics::gauge::Gauge;
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, future::Future, marker::PhantomData, num::NonZeroUsize};
use thiserror::Error;
use tracing::info;

mod handlers;
mod storage;
mod sync;

/// The key used to store the last processed height in the metadata store.
const LATEST_KEY: U64 = U64::new(0xFF);

/// A pending acknowledgement from the application for processing a block at the contained height/commitment.
#[pin_project]
struct PendingAck<B: Block, A: Acknowledgement> {
    height: Height,
    commitment: B::Commitment,
    #[pin]
    receiver: A::Waiter,
}

impl<B: Block, A: Acknowledgement> Future for PendingAck<B, A> {
    type Output = <A::Waiter as Future>::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.project().receiver.poll(cx)
    }
}

/// A struct that holds multiple subscriptions for a block.
struct BlockSubscription<B: Block> {
    // The subscribers that are waiting for the block
    subscribers: Vec<oneshot::Sender<B>>,
    // Aborter that aborts the waiter future when dropped
    _aborter: Aborter,
}

/// Initialization data passed to the marshal actor at startup.
///
/// Holds the external dependencies that the actor needs to process messages:
/// the application reporter, the broadcast buffer, and the resolver.
pub struct Init<K, R, App, B>
where
    K: PublicKey,
    R: Send + 'static,
    App: Send + 'static,
    B: Block,
{
    /// The application that receives finalized blocks.
    pub application: App,
    /// The broadcast buffer for disseminating and retrieving blocks.
    pub buffer: buffered::Mailbox<K, B>,
    /// Receiver for resolver messages (produce/deliver requests from peers).
    pub resolver_rx: mpsc::Receiver<handler::Message<B>>,
    /// The resolver for fetching missing data from the network.
    pub resolver: R,
}

/// Fatal error from the marshal actor.
///
/// Returned from [`Actor::on_ingress`](ActorTrait::on_ingress) to signal an
/// unrecoverable failure that stops the actor without calling `on_shutdown`.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Metadata(#[from] metadata::Error),

    #[error("storage: {0}")]
    Storage(BoxedError),

    #[error("application: {0}")]
    Application(BoxedError),
}

/// The [Actor] is responsible for receiving uncertified blocks from the broadcast mechanism,
/// receiving notarizations and finalizations from consensus, and reconstructing a total order
/// of blocks.
///
/// The actor is designed to be used in a view-based model. Each view corresponds to a
/// potential block in the chain. The actor will only finalize a block if it has a
/// corresponding finalization.
///
/// The actor also provides a backfill mechanism for missing blocks. If the actor receives a
/// finalization for a block that is ahead of its current view, it will request the missing blocks
/// from its peers. This ensures that the actor can catch up to the rest of the network if it falls
/// behind.
pub struct Actor<E, B, P, FC, FB, ES, T, K, R, App, A = Exact>
where
    E: CryptoRngCore + Spawner + Metrics + Clock + Storage,
    B: Block,
    P: Provider<Scope = Epoch, Scheme: Scheme<B::Commitment>>,
    FC: Certificates<Commitment = B::Commitment, Scheme = P::Scheme>,
    FB: Blocks<Block = B>,
    ES: Epocher,
    T: Strategy,
    K: PublicKey,
    R: Resolver<Key = Request<B>, PublicKey = <P::Scheme as CertificateScheme>::PublicKey>,
    App: Reporter<Activity = Update<B, A>>,
    A: Acknowledgement,
{
    // Provider for epoch-specific signing schemes
    provider: P,
    // Epoch configuration
    epocher: ES,
    // Minimum number of views to retain temporary data after the application processes a block
    view_retention_timeout: ViewDelta,
    // Maximum number of blocks to repair at once
    max_repair: NonZeroUsize,
    // Codec configuration for block type
    block_codec_config: B::Cfg,
    // Strategy for parallel operations
    strategy: T,

    // Last view processed
    last_processed_round: Round,
    // Last height processed by the application
    last_processed_height: Height,
    // Pending application acknowledgement, if any
    pending_ack: OptionFuture<PendingAck<B, A>>,
    // Highest known finalized height
    tip: Height,
    // Outstanding subscriptions for blocks
    block_subscriptions: BTreeMap<B::Commitment, BlockSubscription<B>>,
    // Pool of waiter futures for block subscriptions
    waiters: AbortablePool<(B::Commitment, B)>,
    // Prunable cache
    cache: cache::Manager<E, B, P::Scheme>,
    // Metadata tracking application progress
    application_metadata: Metadata<E, U64, Height>,
    // Finalizations stored by height
    finalizations_by_height: FC,
    // Finalized blocks stored by height
    finalized_blocks: FB,
    // Latest height metric
    finalized_height: Gauge,
    // Latest processed height
    processed_height: Gauge,
    _phantom: PhantomData<fn(K, R, App)>,
}

impl<E, B, P, FC, FB, ES, T, K, R, App, A> Actor<E, B, P, FC, FB, ES, T, K, R, App, A>
where
    E: CryptoRngCore + Spawner + Metrics + Clock + Storage,
    B: Block,
    P: Provider<Scope = Epoch, Scheme: Scheme<B::Commitment>>,
    FC: Certificates<Commitment = B::Commitment, Scheme = P::Scheme>,
    FB: Blocks<Block = B>,
    ES: Epocher,
    T: Strategy,
    K: PublicKey,
    R: Resolver<Key = Request<B>, PublicKey = <P::Scheme as CertificateScheme>::PublicKey>,
    App: Reporter<Activity = Update<B, A>>,
    A: Acknowledgement,
{
    /// Create a new marshal actor.
    ///
    /// Returns the actor and the last processed height. The caller should use
    /// [`commonware_actor::service::ServiceBuilder`] to obtain the mailbox and
    /// start the actor.
    pub async fn init(
        context: E,
        finalizations_by_height: FC,
        finalized_blocks: FB,
        config: Config<B, P, ES, T>,
    ) -> (Self, Height) {
        // Initialize cache
        let prunable_config = cache::Config {
            partition_prefix: format!("{}-cache", config.partition_prefix),
            prunable_items_per_section: config.prunable_items_per_section,
            replay_buffer: config.replay_buffer,
            key_write_buffer: config.key_write_buffer,
            value_write_buffer: config.value_write_buffer,
            key_page_cache: config.page_cache.clone(),
        };
        let cache = cache::Manager::init(
            context.with_label("cache"),
            prunable_config,
            config.block_codec_config.clone(),
        )
        .await;

        // Initialize metadata tracking application progress
        let application_metadata = Metadata::init(
            context.with_label("application_metadata"),
            metadata::Config {
                partition: format!("{}-application-metadata", config.partition_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("failed to initialize application metadata");
        let last_processed_height = application_metadata
            .get(&LATEST_KEY)
            .copied()
            .unwrap_or(Height::zero());

        // Create metrics
        let finalized_height = Gauge::default();
        context.register(
            "finalized_height",
            "Finalized height of application",
            finalized_height.clone(),
        );
        let processed_height = Gauge::default();
        context.register(
            "processed_height",
            "Processed height of application",
            processed_height.clone(),
        );
        let _ = processed_height.try_set(last_processed_height.get());

        (
            Self {
                provider: config.provider,
                epocher: config.epocher,
                view_retention_timeout: config.view_retention_timeout,
                max_repair: config.max_repair,
                block_codec_config: config.block_codec_config,
                strategy: config.strategy,
                last_processed_round: Round::zero(),
                last_processed_height,
                pending_ack: None.into(),
                tip: Height::zero(),
                block_subscriptions: BTreeMap::new(),
                waiters: AbortablePool::default(),
                cache,
                application_metadata,
                finalizations_by_height,
                finalized_blocks,
                finalized_height,
                processed_height,
                _phantom: PhantomData,
            },
            last_processed_height,
        )
    }
}

impl<E, B, P, FC, FB, ES, T, K, R, App, A> ActorTrait<E>
    for Actor<E, B, P, FC, FB, ES, T, K, R, App, A>
where
    E: CryptoRngCore + Spawner + Metrics + Clock + Storage,
    B: Block,
    P: Provider<Scope = Epoch, Scheme: Scheme<B::Commitment>>,
    FC: Certificates<Commitment = B::Commitment, Scheme = P::Scheme>,
    FB: Blocks<Block = B>,
    ES: Epocher,
    T: Strategy,
    K: PublicKey,
    R: Resolver<Key = Request<B>, PublicKey = <P::Scheme as CertificateScheme>::PublicKey>,
    App: Reporter<Activity = Update<B, A>>,
    A: Acknowledgement,
{
    type Mailbox = Mailbox<P::Scheme, B>;
    type Ingress = MailboxMessage<P::Scheme, B>;
    type Error = Error;
    type Init = Init<K, R, App, B>;

    async fn on_startup(&mut self, _context: &mut E, init: &mut Self::Init) {
        // Get tip and send to application
        let tip = self.get_latest().await;
        if let Some((height, commitment, round)) = tip {
            init.application
                .report(Update::Tip(round, height, commitment))
                .await;
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        // Attempt to dispatch the next finalized block to the application, if it is ready.
        self.try_dispatch_block(&mut init.application).await;

        // Attempt to repair any gaps in the finalized blocks archive, if there are any.
        self.try_repair_gaps(&mut init.buffer, &mut init.resolver, &mut init.application)
            .await;
    }

    async fn preprocess(&mut self, _context: &mut E, _init: &mut Self::Init) {
        // Remove any dropped subscribers. If all subscribers dropped, abort the waiter.
        self.block_subscriptions.retain(|_, bs| {
            bs.subscribers.retain(|tx| !tx.is_closed());
            !bs.subscribers.is_empty()
        });
    }

    async fn on_external(
        &mut self,
        _context: &mut E,
        init: &mut Self::Init,
    ) -> Option<Self::Ingress> {
        loop {
            select! {
                result = self.waiters.next_completed() => {
                    let Ok((commitment, block)) = result else {
                        // Aborted future, try again
                        continue;
                    };
                    return Some(MailboxMessage::WaiterCompleted { commitment, block });
                },
                ack = &mut self.pending_ack => {
                    let PendingAck {
                        height,
                        commitment,
                        ..
                    } = self.pending_ack.take().expect("ack state must be present");
                    let result = ack.map_err(|e| BoxedError::from(format!("{e:?}")));
                    return Some(MailboxMessage::AckCompleted { height, commitment, result });
                },
                message = init.resolver_rx.recv() => {
                    return match message? {
                        handler::Message::Produce { key, response } => {
                            Some(MailboxMessage::ResolverProduce { key, response })
                        }
                        handler::Message::Deliver { key, value, response } => {
                            Some(MailboxMessage::ResolverDeliver { key, value, response })
                        }
                    };
                },
            }
        }
    }

    async fn on_ingress(
        &mut self,
        context: &mut E,
        init: &mut Self::Init,
        message: Self::Ingress,
    ) -> Result<(), Self::Error> {
        match message {
            MailboxMessage::GetInfo {
                identifier,
                response,
            } => {
                self.handle_get_info(identifier, response).await;
            }
            MailboxMessage::GetBlock {
                identifier,
                response,
            } => {
                self.handle_get_block(&mut init.buffer, identifier, response)
                    .await;
            }
            MailboxMessage::GetFinalization { height, response } => {
                let finalization = self.get_finalization_by_height(height).await;
                response.send_lossy(finalization);
            }
            MailboxMessage::HintFinalized { height, targets } => {
                self.handle_hint_finalized(&mut init.resolver, height, targets)
                    .await;
            }
            MailboxMessage::Subscribe {
                round,
                commitment,
                response,
            } => {
                self.handle_subscribe(
                    &mut init.buffer,
                    &mut init.resolver,
                    round,
                    commitment,
                    response,
                )
                .await;
            }
            MailboxMessage::Proposed { round, block } => {
                self.handle_proposed(&mut init.buffer, round, block).await;
            }
            MailboxMessage::Verified { round, block } => {
                self.cache_verified(round, block.commitment(), block).await;
            }
            MailboxMessage::SetFloor { height } => {
                self.handle_set_floor(&mut init.resolver, height).await?;
            }
            MailboxMessage::Prune { height } => {
                self.handle_prune(height).await?;
            }
            MailboxMessage::NotifyNotarization { notarization } => {
                self.handle_notarization(&mut init.buffer, &mut init.resolver, notarization)
                    .await;
            }
            MailboxMessage::NotifyFinalization { finalization } => {
                self.handle_finalization(
                    &mut init.application,
                    &mut init.buffer,
                    &mut init.resolver,
                    finalization,
                )
                .await;
            }
            MailboxMessage::WaiterCompleted { commitment, block } => {
                self.notify_subscribers(commitment, &block).await;
            }
            MailboxMessage::AckCompleted {
                height,
                commitment,
                result,
            } => {
                self.handle_ack_completed(
                    &mut init.application,
                    &mut init.resolver,
                    height,
                    commitment,
                    result,
                )
                .await?;
            }
            MailboxMessage::ResolverProduce { key, response } => {
                self.handle_resolver_produce(&mut init.buffer, key, response)
                    .await;
            }
            MailboxMessage::ResolverDeliver {
                key,
                value,
                response,
            } => match key {
                Request::Block(commitment) => {
                    self.deliver_block(
                        &mut init.application,
                        &mut init.buffer,
                        &mut init.resolver,
                        commitment,
                        value,
                        response,
                    )
                    .await;
                }
                Request::Finalized { height } => {
                    self.deliver_finalization(
                        context,
                        &mut init.application,
                        &mut init.buffer,
                        &mut init.resolver,
                        height,
                        value,
                        response,
                    )
                    .await;
                }
                Request::Notarized { round } => {
                    self.deliver_notarization(
                        context,
                        &mut init.application,
                        &mut init.buffer,
                        &mut init.resolver,
                        round,
                        value,
                        response,
                    )
                    .await;
                }
            },
        }
        Ok(())
    }

    async fn on_shutdown(&mut self, _context: &mut E, _init: &mut Self::Init) {
        info!("marshal actor shutting down");
    }
}
