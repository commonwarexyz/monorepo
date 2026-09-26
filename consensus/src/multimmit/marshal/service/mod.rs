//! Opening, starting and supervising a marshal.
//!
//! # Lifecycle
//!
//! 1. [`open`](fn@open) opens and recovers storage, starts the catalog (and the promoter), and
//!    returns the [`Service`] with the [`BackfillBridge`] the network resolver needs.
//! 2. The caller attaches the bridge to its resolver as consumer and producer.
//! 3. [`Service::start`] starts the remaining actors and returns the public [`Mailbox`] and the
//!    [`ServiceHandle`].
//! 4. [`ServiceHandle::abort`] stops every actor; [`ServiceHandle::join`] returns the first
//!    failure.
//!
//! # Examples
//!
//! ```rust,ignore
//! let (service, bridge) = marshal::open(context.child("marshal"), config, buffer).await?;
//! let (engine, resolver) = resolver::Engine::new(context.child("resolver"), resolver::Config {
//!     consumer: bridge.clone(),
//!     producer: bridge,
//!     ..
//! });
//! engine.start(network);
//! let (mailbox, mut running) = service.start(resolver, verifier, application);
//! mailbox.put_block(block).await?;
//! running.abort();
//! running.join().await?;
//! ```

mod router;
mod subscriptions;
mod supervisor;

use super::{
    actors::{
        backfill::{self, BackfillBridge, serve},
        delivery, synchronizer,
    },
    bodies::Bodies,
    config::{ActorBounds, Capacities, Config, Limits},
    mailbox::Mailbox,
    open::{self, OpenError, Opened},
    relay::{Relay, Staged},
    storage::scratch::{BlockScratch, HistoryScratch},
    types::{LqcVerifier, Update},
    wire,
};
use crate::{
    Reporter,
    multimmit::{
        config::max_outbox_effects,
        types::{Body, ChainId, CodecConfig, TransactionBlock},
    },
};
use commonware_broadcast::buffered;
use commonware_codec::Codec;
use commonware_cryptography::{
    Digestible, Hasher, PublicKey, bls12381::primitives::variant::Variant,
};
use commonware_resolver::Resolver;
use commonware_runtime::Spawner;
use commonware_storage::{Context, translator::Translator};
use commonware_utils::sync::Mutex;
use std::sync::Arc;
use supervisor::Children;
pub use supervisor::ServiceHandle;

/// An opened marshal whose remaining actors have not started.
pub struct Service<E, H, V, B, P>
where
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    P: PublicKey,
{
    context: E,
    storage: Opened<E, H, V, B>,
    delivery: delivery::Receiver<H, B>,
    bodies: Bodies<H, V, B>,
    backfill: backfill::Actor<E, H, V, B>,
    backfill_mailbox: backfill::Mailbox<H, V, B>,
    serve: serve::Actor<E, H, V, B>,
    history_scratch: HistoryScratch<E, H>,
    block_scratch: BlockScratch<E, H::Digest>,
    broadcast: buffered::Mailbox<P, TransactionBlock<H, B>>,
    staged: Option<Arc<Mutex<Staged<H, B>>>>,
    capacities: Capacities,
    limits: Limits,
    codec: CodecConfig,
    bounds: ActorBounds,
}

/// Opens marshal-owned storage and returns the bridge used to construct the network resolver.
///
/// `buffer` is the buffered broadcast ingress that block subscriptions race against backfill.
pub async fn open<E, T, H, V, B, P>(
    context: E,
    config: Config<T, V, B>,
    buffer: buffered::Mailbox<P, TransactionBlock<H, B>>,
) -> Result<(Service<E, H, V, B, P>, BackfillBridge<H, V, B>), OpenError>
where
    E: Context + Spawner,
    T: Translator,
    H: Hasher<Digest = B::Digest>,
    V: Variant,
    B: Codec + Digestible,
    B::Cfg: Clone + Send + 'static,
    P: PublicKey,
{
    let bounds = config.actor_bounds()?;
    let history_scratch = HistoryScratch::init(
        context.child("history_scratch"),
        config.archive.scratch(
            format!("{}_history_scratch", config.partition_prefix),
            config.codec_config,
        ),
    )
    .await?;
    let block_scratch = BlockScratch::init(
        context.child("block_scratch"),
        config
            .archive
            .scratch(format!("{}_block_scratch", config.partition_prefix), ()),
        config.archive.value_write_buffer.get(),
    )
    .await?;
    let (delivery_mailbox, delivery) =
        delivery::channel(context.child("delivery").child("mailbox"));
    let storage =
        open::storage(context.child("storage"), &config, &bounds, delivery_mailbox).await?;
    let promoter = storage
        .promoter
        .as_ref()
        .map(|promoter| promoter.mailbox.clone());
    let bodies = Bodies::new(storage.catalog.clone(), promoter);
    let (serve, serve_mailbox) = serve::Actor::new(
        &context,
        serve::Config {
            catalog: storage.catalog.clone(),
            bodies: bodies.clone(),
            max_block_bytes: config.limits.max_block_bytes,
            max_value_bytes: config.limits.resolver_max_value_bytes,
            mailbox_size: bounds.backfill_mailbox,
            max_pending: bounds.backfill_pending,
            max_active: bounds.serve_active,
        },
    );
    let (backfill, bridge, backfill_mailbox) = backfill::Actor::new(
        &context,
        backfill::Config {
            epoch: config.epoch(),
            codec: config.codec_config,
            body: config.body_codec_config.clone(),
            max_block_bytes: config.limits.max_block_bytes,
            max_value_bytes: config.limits.resolver_max_value_bytes,
            catalog: storage.catalog.clone(),
            bodies: bodies.clone(),
            serve: serve_mailbox,
            mailbox_size: bounds.backfill_mailbox,
            max_pending: bounds.backfill_pending,
            max_rechecks: bounds.serve_active,
            max_staging: bounds.serve_active,
        },
    );
    Ok((
        Service {
            context,
            storage,
            delivery,
            bodies,
            backfill,
            backfill_mailbox,
            serve,
            history_scratch,
            block_scratch,
            broadcast: buffer,
            staged: None,
            capacities: config.capacities,
            limits: config.limits,
            codec: config.codec_config,
            bounds,
        },
        bridge,
    ))
}

impl<E, H, V, B, P> Service<E, H, V, B, P>
where
    E: Context + Spawner,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    B::Cfg: Send + 'static,
    P: PublicKey,
{
    /// Returns a consensus [`Relay`](crate::Relay) that broadcasts blocks staged through this
    /// service's [`Mailbox`].
    ///
    /// The relay can broadcast any recently staged block the engine may still ask it to publish,
    /// counting blocks on this node's producer `chain` that a subscription returned: it keeps as
    /// many as an engine of this committee keeps publications awaiting acknowledgement. Without a
    /// relay, staging keeps no extra copy. Call before [`Self::start`]; later calls share the
    /// first call's settings.
    pub fn relay(&mut self, chain: Option<ChainId>) -> Relay<H, B, P> {
        let retention = max_outbox_effects(self.codec.participants());
        let staged = self
            .staged
            .get_or_insert_with(|| Arc::new(Mutex::new(Staged::new(retention, chain))));
        Relay::new(Arc::clone(staged), self.broadcast.clone())
    }

    /// Starts every actor after the caller has attached the resolver bridge to its transport.
    pub fn start<R, Q, A>(
        self,
        network: R,
        verifier: Q,
        application: A,
    ) -> (Mailbox<H, V, B>, ServiceHandle)
    where
        R: Resolver<Key = wire::BackfillKey<H::Digest>, Subscriber = backfill::BackfillSubscriber>,
        Q: LqcVerifier<H, V> + Clone,
        A: Reporter<Activity = Update<TransactionBlock<H, B>>>,
    {
        let Opened {
            catalog,
            catalog_handle,
            promoter,
            delivery_store,
        } = self.storage;
        let promoter_handle = promoter.map(|promoter| promoter.handle);
        let bodies = self.bodies;
        let backfill = self.backfill_mailbox;
        let serve_handle = self.serve.start();
        let backfill_handle = self.backfill.start(network, verifier.clone());
        let delivery_handle = delivery::Actor::new(delivery::Config {
            context: self.context.child("delivery"),
            store: delivery_store,
            catalog: catalog.clone(),
            bodies: bodies.clone(),
            application,
            mailbox: self.delivery,
            bounds: delivery::Bounds {
                pending_acks: self.capacities.max_pending_acks,
                delivery_bytes: self.limits.max_delivery_bytes,
                hot_block_bytes: self.limits.max_hot_block_bytes,
            },
        })
        .start();
        let (synchronizer, synchronizer_mailbox) = synchronizer::Actor::new(
            &self.context,
            synchronizer::Config {
                catalog: catalog.clone(),
                fetcher: synchronizer::CustodyFetcher::new(backfill.clone(), catalog.clone()),
                history_stack: self.history_scratch,
                block_stack: self.block_scratch,
                verifier,
                codec: self.codec,
                mailbox_size: self.bounds.synchronizer_mailbox,
                header_cache_capacity: self.capacities.header_cache_capacity,
                backfill_concurrency: self.bounds.synchronizer_fetches,
                max_commit_outputs: self.capacities.max_commit_outputs,
                max_commit_block_bytes: self.limits.max_commit_block_bytes,
                max_block_bytes: self.limits.max_block_bytes,
                max_value_bytes: self.limits.resolver_max_value_bytes,
            },
        );
        let synchronizer_handle = synchronizer.start();
        let (router, mailbox) = router::Actor::new(router::Config {
            context: self.context.child("router"),
            catalog,
            bodies,
            backfill,
            synchronizer: synchronizer_mailbox,
            broadcast: self.broadcast,
            mailbox_size: self.bounds.router_mailbox,
            max_jobs: self.bounds.router_jobs,
            subscription_callers: self.bounds.subscription_callers,
            staged: self.staged,
        });
        let children = Children {
            catalog: catalog_handle,
            promoter: promoter_handle,
            backfill: backfill_handle,
            serve: serve_handle,
            synchronizer: synchronizer_handle,
            delivery: delivery_handle,
            router: router.start(),
        };
        // The supervisor takes the service context itself, so stopping it also stops every task
        // an actor spawned beneath its own context.
        let task = self
            .context
            .shared(false)
            .spawn(move |_| children.supervise());
        (
            mailbox,
            ServiceHandle {
                task,
                shutdown_requested: false,
            },
        )
    }
}

#[cfg(test)]
mod fixtures {
    use super::Service;
    use crate::multimmit::{marshal::actors::catalog, types::Body};
    use commonware_cryptography::{Hasher, PublicKey, bls12381::primitives::variant::Variant};
    use commonware_storage::Context;

    impl<E, H, V, B, P> Service<E, H, V, B, P>
    where
        E: Context,
        H: Hasher,
        V: Variant,
        B: Body<H>,
        P: PublicKey,
    {
        /// Returns the running catalog's mailbox.
        pub(crate) fn catalog(&self) -> catalog::Mailbox<H, V, B> {
            self.storage.catalog.clone()
        }
    }
}
