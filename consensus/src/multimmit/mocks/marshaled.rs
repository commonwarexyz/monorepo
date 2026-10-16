//! A marshal per cluster engine, and the application glue that stages and verifies through it.
//!
//! A `Marshaled` slot runs a complete marshal service (buffered broadcast, backfill resolver,
//! catalog, delivery) next to its consensus engine. The engine's automaton stages each built
//! block before answering a proposal and answers a verification only once marshal holds the block
//! durably; its relay broadcasts staged blocks; its reporter feeds marshal. Every delivered output
//! is recorded in the slot's [`Deliveries`], which outlive restarts.

use crate::{
    Automaton, Relay,
    multimmit::{
        marshal::{
            self, ArchiveConfig, Config, Custody, Mailbox, OutputIndex, SchemeVerifier,
            ServiceHandle, Start, Update,
        },
        mocks::{Committee, MockApplication, MockBody},
        types::{BlockRef, ChainId, Context, TransactionBlock, TransactionBlockHeader},
    },
};
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::Variant, ed25519, sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::{Receiver, Sender, simulated::Oracle};
use commonware_parallel::Sequential;
use commonware_resolver::p2p;
use commonware_runtime::{
    Clock as _, Handle, Spawner as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{Acknowledgement as _, NZUsize, channel::oneshot, sync::Mutex};
use std::{collections::BTreeMap, future::Future, sync::Arc, time::Duration};

/// A producer block as the cluster's marshals hold it.
pub type ClusterBlock = TransactionBlock<Sha256, MockBody>;

/// A cluster slot's marshal ingress.
pub type ClusterMarshal<V> = Mailbox<Sha256, V, MockBody>;

type ClusterRelay = marshal::Relay<Sha256, MockBody, ed25519::PublicKey>;

/// Runs `future` until it completes or the requester drops `response`.
async fn or_canceled<R, T>(
    response: &mut oneshot::Sender<R>,
    future: impl Future<Output = T>,
) -> Option<T> {
    select! {
        _ = response.closed() => None,
        output = future => Some(output),
    }
}

/// The outputs one slot's marshal delivered, by canonical index, across every restart.
///
/// Recording checks that a redelivered index names the block delivered there before;
/// [`Cluster::assert_deliveries_agree`](super::cluster::Cluster::assert_deliveries_agree) checks
/// that the recorded indices are contiguous.
#[derive(Clone, Default)]
pub struct Deliveries {
    outputs: Arc<Mutex<BTreeMap<OutputIndex, BlockRef<Sha256Digest>>>>,
}

impl Deliveries {
    /// Returns every recorded output in index order.
    pub fn outputs(&self) -> Vec<(OutputIndex, BlockRef<Sha256Digest>)> {
        self.outputs
            .lock()
            .iter()
            .map(|(index, block)| (*index, *block))
            .collect()
    }

    /// Returns the highest recorded index.
    pub fn last(&self) -> Option<OutputIndex> {
        self.outputs
            .lock()
            .last_key_value()
            .map(|(index, _)| *index)
    }

    fn record(&self, index: OutputIndex, block: BlockRef<Sha256Digest>) {
        let mut outputs = self.outputs.lock();
        if let Some(previous) = outputs.get(&index) {
            assert_eq!(
                *previous, block,
                "output {index:?} was redelivered as another block"
            );
            return;
        }
        outputs.insert(index, block);
    }
}

impl crate::Reporter for Deliveries {
    type Activity = Update<ClusterBlock>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        self.record(update.index, update.block.reference());
        update.acknowledgement.acknowledge();
        Feedback::Ok
    }
}

/// The automaton of a cluster engine: [`MockApplication`]'s production and verification
/// policies, staged and verified through the slot's marshal when it runs one.
///
/// A proposal turns the application's commitment into a [`MockBody`], stages the block and
/// answers with the body digest once custody is durable. A verification answers the application's
/// verdict once marshal holds the named block durably, so a block whose body never arrives is
/// never verified (it can still be adopted).
pub struct ClusterApplication<V: Variant> {
    app: MockApplication,
    marshal: Option<(deterministic::Context, ClusterMarshal<V>)>,
}

impl<V: Variant> Clone for ClusterApplication<V> {
    fn clone(&self) -> Self {
        Self {
            app: self.app.clone(),
            marshal: self
                .marshal
                .as_ref()
                .map(|(context, marshal)| (context.child("application"), marshal.clone())),
        }
    }
}

impl<V: Variant> ClusterApplication<V> {
    /// Answers with `app` alone.
    pub const fn detached(app: MockApplication) -> Self {
        Self { app, marshal: None }
    }

    /// Stages and verifies through `marshal`, spawning each wait on `context`.
    pub const fn marshaled(
        app: MockApplication,
        context: deterministic::Context,
        marshal: ClusterMarshal<V>,
    ) -> Self {
        Self {
            app,
            marshal: Some((context, marshal)),
        }
    }
}

impl<V: Variant> Automaton for ClusterApplication<V> {
    type Context = Context<Sha256Digest>;
    type Digest = Sha256Digest;

    #[expect(
        clippy::async_yields_async,
        reason = "the Automaton contract returns a receiver for separately cancelable application work"
    )]
    fn propose(
        &mut self,
        context: Self::Context,
    ) -> impl Future<Output = oneshot::Receiver<Self::Digest>> + Send {
        let Self { mut app, marshal } = self.clone();
        async move {
            let delay = app.build_delay();
            let built = app.propose(context).await;
            let Some((runtime, marshal)) = marshal else {
                return built;
            };
            let (mut response, receiver) = oneshot::channel();
            runtime.child("propose").spawn(move |task| async move {
                if !delay.is_zero()
                    && or_canceled(&mut response, task.sleep(delay))
                        .await
                        .is_none()
                {
                    return;
                }
                let Some(Ok(commitment)) = or_canceled(&mut response, built).await else {
                    return;
                };
                let mut seed = [0; 8];
                seed.copy_from_slice(&commitment.as_ref()[..8]);
                let block = Arc::new(ClusterBlock::from_context(
                    context,
                    MockBody(u64::from_be_bytes(seed)),
                ));
                let payload = block.header().body_digest();
                let staged = or_canceled(&mut response, async {
                    let custody: Custody = marshal.stage_block(block).await?;
                    custody.wait().await
                })
                .await;
                if matches!(staged, Some(Ok(()))) {
                    let _ = response.send(payload);
                }
            });
            receiver
        }
    }

    #[expect(
        clippy::async_yields_async,
        reason = "the Automaton contract returns a receiver for separately cancelable application work"
    )]
    fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> impl Future<Output = oneshot::Receiver<bool>> + Send {
        let Self { mut app, marshal } = self.clone();
        async move {
            let verdict = app.verify(context, payload).await;
            let Some((runtime, marshal)) = marshal else {
                return verdict;
            };
            let (mut response, receiver) = oneshot::channel();
            runtime.child("verify").spawn(move |_| async move {
                let reference =
                    TransactionBlockHeader::from_context(context, payload).block_ref::<Sha256>();
                match or_canceled(&mut response, marshal.subscribe_block(reference)).await {
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        tracing::warn!(?reference, %error, "marshal subscription failed");
                        return;
                    }
                    None => return,
                }
                if let Some(Ok(valid)) = or_canceled(&mut response, verdict).await {
                    let _ = response.send(valid);
                }
            });
            receiver
        }
    }
}

/// The relay of a cluster engine: marshal's broadcast of staged blocks when the slot runs one.
#[derive(Clone, Default)]
pub struct ClusterBroadcast {
    relay: Option<ClusterRelay>,
}

impl Relay for ClusterBroadcast {
    type Digest = Sha256Digest;
    type PublicKey = ed25519::PublicKey;
    type Plan = ();

    fn broadcast(&mut self, digest: Self::Digest, (): Self::Plan) -> Feedback {
        self.relay
            .as_mut()
            .map_or(Feedback::Ok, |relay| relay.broadcast(digest, ()))
    }
}

/// One node's running marshal and the transports it runs over.
pub(crate) struct Marshaled<V: Variant> {
    pub(crate) mailbox: ClusterMarshal<V>,
    pub(crate) relay: ClusterBroadcast,
    service: ServiceHandle,
    resolver: Handle<()>,
    broadcast: Handle<()>,
}

impl<V: Variant> Marshaled<V> {
    /// Opens (or recovers) `partition`'s marshal for `identity` and starts it over the
    /// `bodies` broadcast and `backfill` resolver transports, with delivered outputs reported to
    /// `application`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn start(
        context: deterministic::Context,
        committee: &Committee<V>,
        oracle: &Oracle<ed25519::PublicKey, deterministic::Context>,
        identity: ed25519::PublicKey,
        chain: Option<ChainId>,
        partition: String,
        bodies: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        backfill: (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        application: impl crate::Reporter<Activity = Update<ClusterBlock>>,
    ) -> Self {
        let control = oracle.control(identity.clone());
        let (broadcast_engine, buffer) = buffered::Engine::new(
            context.child("broadcast"),
            buffered::Config {
                public_key: identity.clone(),
                mailbox_size: NZUsize!(1024),
                ingress_size: NZUsize!(1024),
                deque_size: 64,
                priority: false,
                codec_config: (),
                peer_provider: oracle.manager(),
                blocker: control.clone(),
                strategy: Sequential,
            },
        );
        let broadcast = broadcast_engine.start(bodies);
        let config = Config::new(
            Start::Genesis(committee.genesis().clone()),
            partition,
            committee.codec(),
            (),
            ArchiveConfig::new(
                TwoCap,
                CacheRef::from_pooler(&context, paged::page_size(4_096), NZUsize!(8)),
            ),
        );
        let (mut service, bridge) = marshal::open::<_, TwoCap, Sha256, V, MockBody, _>(
            context.child("marshal"),
            config,
            buffer,
        )
        .await
        .expect("marshal opens");
        let relay = ClusterBroadcast {
            relay: Some(service.relay(chain)),
        };
        let (resolver_engine, resolver) = p2p::Engine::new(
            context.child("backfill"),
            p2p::Config {
                peer_provider: oracle.manager(),
                blocker: control,
                consumer: bridge.clone(),
                producer: bridge,
                mailbox_size: NZUsize!(1024),
                me: Some(identity),
                timeout: Duration::from_millis(200),
                fetch_retry_timeout: Duration::from_millis(50),
                priority_requests: false,
                priority_responses: false,
            },
        );
        let resolver_handle = resolver_engine.start(backfill);
        let verifier = SchemeVerifier::new(
            context.child("lqc_verifier"),
            committee.verifier.clone(),
            Sequential,
        );
        let (mailbox, service) = service.start(resolver, verifier, application);
        Self {
            mailbox,
            relay,
            service,
            resolver: resolver_handle,
            broadcast,
        }
    }

    /// Aborts marshal and its transports.
    pub(crate) fn abort(&mut self) {
        self.service.abort();
        self.resolver.abort();
        self.broadcast.abort();
    }

    /// Waits for the aborted tasks to stop and returns marshal's first failure, if it failed
    /// before the abort.
    pub(crate) async fn join(self) -> Result<(), marshal::Error> {
        let result = self.service.join().await;
        let _ = self.resolver.await;
        let _ = self.broadcast.await;
        result
    }
}
