//! Implementation of an `authenticated` network.

#[stability(ALPHA)]
use super::config::{AttachmentConfig, GenericConfig};
use super::{
    actors::{attachment, dialer, listener, spawner, tracker},
    config::Config,
};
#[stability(ALPHA)]
use crate::PeerEndpoint;
use crate::{
    Address, AddressableManager, AddressableTrackedPeers, Blocker, Channel, Ingress,
    PeerSetSubscription, Provider, TrackedPeers,
    authenticated::{
        admission::{TcpAdmission, TcpAdmissionConfig},
        channels::{self, Channels},
        data::MAX_PAYLOAD_DATA_OVERHEAD,
        router,
    },
};
use commonware_cryptography::Signer;
use commonware_macros::{select, stability};
#[stability(ALPHA)]
use commonware_runtime::Scheduler;
use commonware_runtime::{
    Acceptor, BufferPooler, Clock, Connection, ContextCell, Dialer, Handle, Metrics, Quota,
    Resolver, Spawner, TcpEndpoint, TcpOrigin, spawn_cell,
};
use commonware_stream::encrypted::Config as StreamConfig;
use commonware_utils::{PlatformSend, ordered::Map, sync::Mutex, union};
use rand::{SeedableRng, rngs::StdRng, seq::IndexedRandom};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    sync::Arc,
};
use tracing::{debug, info};

struct TcpOracleState<C: commonware_cryptography::PublicKey> {
    sets: BTreeMap<u64, AddressableTrackedPeers<C>>,
    max_sets: usize,
}

/// Legacy TCP oracle that keeps origin admission synchronized with peer addresses.
pub struct Oracle<C: commonware_cryptography::PublicKey> {
    inner: tracker::Oracle<C>,
    updates: crate::authenticated::admission::TcpAdmissionUpdates<C>,
    state: Arc<Mutex<TcpOracleState<C>>>,
    #[cfg(test)]
    after_tracker_update: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl<C: commonware_cryptography::PublicKey> Clone for Oracle<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            updates: self.updates.clone(),
            state: self.state.clone(),
            #[cfg(test)]
            after_tracker_update: self.after_tracker_update.clone(),
        }
    }
}

impl<C: commonware_cryptography::PublicKey> fmt::Debug for Oracle<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Oracle").finish_non_exhaustive()
    }
}

impl<C: commonware_cryptography::PublicKey> Oracle<C> {
    fn refresh_admission(&self, state: &TcpOracleState<C>) {
        let mut latest_peer_ips = HashMap::new();
        for peers in state.sets.values() {
            for (peer, address) in &peers.secondary {
                latest_peer_ips.insert(peer.clone(), address.egress_ip());
            }
            for (peer, address) in &peers.primary {
                latest_peer_ips.insert(peer.clone(), address.egress_ip());
            }
        }

        let peer_ips = latest_peer_ips
            .into_iter()
            .map(|(peer, ip)| (peer, HashSet::from([ip])))
            .collect();
        self.updates.set(peer_ips);
    }
}

impl<C: commonware_cryptography::PublicKey> Provider for Oracle<C> {
    type PublicKey = C;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<C>> {
        self.inner.peer_set(id).await
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<C> {
        self.inner.subscribe().await
    }
}

impl<C: commonware_cryptography::PublicKey> AddressableManager for Oracle<C> {
    fn track<T>(&mut self, index: u64, peers: T) -> commonware_actor::Feedback
    where
        T: Into<AddressableTrackedPeers<C>> + PlatformSend,
    {
        let peers = peers.into();
        let mut state = self.state.lock();
        if state
            .sets
            .last_key_value()
            .is_some_and(|(last, _)| index <= *last)
        {
            return self.inner.track(index, peers);
        }

        state.sets.insert(index, peers.clone());
        while state.sets.len() > state.max_sets {
            state.sets.pop_first();
        }
        self.refresh_admission(&state);

        let feedback = self.inner.track(index, peers);
        #[cfg(test)]
        if let Some(hook) = &self.after_tracker_update {
            hook();
        }
        feedback
    }

    fn overwrite(&mut self, peers: Map<C, Address>) -> commonware_actor::Feedback {
        let mut state = self.state.lock();
        for tracked in state.sets.values_mut() {
            for (peer, address) in &peers {
                if let Some(existing) = tracked.primary.get_value_mut(peer) {
                    *existing = address.clone();
                }
                if let Some(existing) = tracked.secondary.get_value_mut(peer) {
                    *existing = address.clone();
                }
            }
        }
        self.refresh_admission(&state);

        let feedback = self.inner.overwrite(peers);
        #[cfg(test)]
        if let Some(hook) = &self.after_tracker_update {
            hook();
        }
        feedback
    }
}

impl<C: commonware_cryptography::PublicKey> Blocker for Oracle<C> {
    type PublicKey = C;

    #[allow(
        clippy::disallowed_methods,
        reason = "facade forwards the Blocker implementation without adding a second log"
    )]
    fn block(&mut self, public_key: C) -> commonware_actor::Feedback {
        self.inner.block(public_key)
    }
}

/// Endpoint-generic lookup network that only establishes outbound connections.
#[stability(ALPHA)]
pub struct DialOnlyNetwork<R, C, D>
where
    R: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    D: Dialer,
    D::Endpoint: PeerEndpoint,
{
    context: ContextCell<R>,
    cfg: GenericConfig<C>,
    dialer: D,
    channels: Channels<C::PublicKey>,
    tracker: tracker::Actor<R, C, D::Endpoint>,
    tracker_mailbox: tracker::Mailbox<C::PublicKey, D::Endpoint>,
    router: router::Actor<R, C::PublicKey>,
    router_mailbox: router::Mailbox<C::PublicKey>,
}

#[stability(ALPHA)]
impl<R, C, D> DialOnlyNetwork<R, C, D>
where
    R: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    D: Dialer,
    D::Endpoint: PeerEndpoint,
{
    /// Creates a lookup network without requiring an inbound transport capability.
    pub fn new(
        context: R,
        dialer: D,
        cfg: GenericConfig<C>,
    ) -> (Self, tracker::Oracle<C::PublicKey, D::Endpoint>) {
        let (tracker, tracker_mailbox, oracle) = tracker::Actor::new(
            context.child("tracker"),
            tracker::Config {
                crypto: cfg.stream.signing_key.clone(),
                mailbox_size: cfg.mailbox_size,
                tracked_peer_sets: cfg.tracked_peer_sets,
                peer_connection_cooldown: cfg.peer_connection_cooldown,
                block_duration: cfg.block_duration,
            },
        );
        let (router, router_mailbox, messenger) = router::Actor::new(
            context.child("router"),
            router::Config {
                mailbox_size: cfg.mailbox_size,
            },
        );
        let channels = Channels::new(
            messenger,
            cfg.stream
                .max_message_size
                .saturating_sub(MAX_PAYLOAD_DATA_OVERHEAD),
        );
        (
            Self {
                context: ContextCell::new(context),
                cfg,
                dialer,
                channels,
                tracker,
                tracker_mailbox,
                router,
                router_mailbox,
            },
            oracle,
        )
    }

    /// Registers an application channel.
    #[allow(clippy::type_complexity)]
    pub fn register(
        &mut self,
        channel: Channel,
        rate: Quota,
        backlog: usize,
    ) -> (
        channels::Sender<C::PublicKey, R>,
        channels::Receiver<C::PublicKey>,
    ) {
        let context = self
            .context
            .child("channel")
            .with_attribute("index", channel);
        self.channels.register(channel, rate, backlog, context)
    }

    /// Adds an explicitly supplied acceptor and inbound admission policy.
    pub const fn accepting<A, I>(
        self,
        acceptor: A,
        bind: A::Bind,
        admission: I,
        max_concurrent_handshakes: std::num::NonZeroU32,
    ) -> AcceptingNetwork<R, C, D, A, I>
    where
        A: Acceptor<Connection = D::Connection>,
        I: crate::authenticated::admission::InboundAdmission<
                C::PublicKey,
                <D::Connection as Connection>::Origin,
            >,
    {
        AcceptingNetwork {
            inner: self,
            acceptor,
            bind,
            admission,
            max_concurrent_handshakes,
        }
    }

    /// Starts the dial-only network.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(self) {
        let mut tracker_task = self.tracker.start();
        let mut router_task = self.router.start(self.channels);
        let (spawner, spawner_mailbox) = spawner::Actor::new(
            self.context.child("spawner"),
            spawner::Config {
                mailbox_size: self.cfg.mailbox_size,
                send_batch_size: self.cfg.send_batch_size,
                ping_frequency: self.cfg.ping_frequency,
            },
        );
        let mut spawner_task = spawner.start(self.tracker_mailbox.clone(), self.router_mailbox);
        let dialer = dialer::Actor::new(
            self.context.child("dialer"),
            self.dialer,
            dialer::Config {
                stream_cfg: self.cfg.stream,
                dial_timeout: self.cfg.dial_timeout,
                dial_frequency: self.cfg.dial_frequency,
                peer_connection_cooldown: self.cfg.peer_connection_cooldown,
            },
        );
        let mut dialer_task = dialer.start(self.tracker_mailbox, spawner_mailbox);
        let mut shutdown = self.context.stopped();
        select! {
            _ = &mut shutdown => debug!("context shutdown, stopping dial-only network"),
            result = &mut tracker_task => debug!(?result, "tracker stopped"),
            result = &mut router_task => debug!(?result, "router stopped"),
            result = &mut spawner_task => debug!(?result, "spawner stopped"),
            result = &mut dialer_task => debug!(?result, "dialer stopped"),
        }
    }
}

/// Endpoint-generic lookup network with inbound and outbound transport capabilities.
#[stability(ALPHA)]
pub struct AcceptingNetwork<R, C, D, A, I>
where
    R: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    D: Dialer,
    D::Endpoint: PeerEndpoint,
    A: Acceptor<Connection = D::Connection>,
    I: crate::authenticated::admission::InboundAdmission<
            C::PublicKey,
            <D::Connection as Connection>::Origin,
        >,
{
    inner: DialOnlyNetwork<R, C, D>,
    acceptor: A,
    bind: A::Bind,
    admission: I,
    max_concurrent_handshakes: std::num::NonZeroU32,
}

#[stability(ALPHA)]
impl<R, C, D, A, I> AcceptingNetwork<R, C, D, A, I>
where
    R: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    D: Dialer,
    D::Endpoint: PeerEndpoint,
    A: Acceptor<Connection = D::Connection>,
    I: crate::authenticated::admission::InboundAdmission<
            C::PublicKey,
            <D::Connection as Connection>::Origin,
        >,
{
    /// Registers an application channel.
    #[allow(clippy::type_complexity)]
    pub fn register(
        &mut self,
        channel: Channel,
        rate: Quota,
        backlog: usize,
    ) -> (
        channels::Sender<C::PublicKey, R>,
        channels::Receiver<C::PublicKey>,
    ) {
        self.inner.register(channel, rate, backlog)
    }

    /// Starts the accepting network.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.inner.context, self.run())
    }

    async fn run(self) {
        let mut tracker_task = self.inner.tracker.start();
        let mut router_task = self.inner.router.start(self.inner.channels);
        let (spawner, spawner_mailbox) = spawner::Actor::new(
            self.inner.context.child("spawner"),
            spawner::Config {
                mailbox_size: self.inner.cfg.mailbox_size,
                send_batch_size: self.inner.cfg.send_batch_size,
                ping_frequency: self.inner.cfg.ping_frequency,
            },
        );
        let mut spawner_task = spawner.start(
            self.inner.tracker_mailbox.clone(),
            self.inner.router_mailbox,
        );
        let (attachment, attachments) = attachment::Actor::new(
            self.inner.context.child("attachment"),
            self.inner.cfg.stream.clone(),
            self.admission,
            self.inner.cfg.mailbox_size,
            self.max_concurrent_handshakes,
        );
        let mut attachment_task =
            attachment.start_listener(self.inner.tracker_mailbox.clone(), spawner_mailbox.clone());
        let listener = listener::Actor::new(
            self.inner.context.child("listener"),
            self.acceptor,
            listener::Config { bind: self.bind },
        );
        let mut listener_task = listener.start(attachments);
        let dialer = dialer::Actor::new(
            self.inner.context.child("dialer"),
            self.inner.dialer,
            dialer::Config {
                stream_cfg: self.inner.cfg.stream,
                dial_timeout: self.inner.cfg.dial_timeout,
                dial_frequency: self.inner.cfg.dial_frequency,
                peer_connection_cooldown: self.inner.cfg.peer_connection_cooldown,
            },
        );
        let mut dialer_task = dialer.start(self.inner.tracker_mailbox, spawner_mailbox);
        let mut shutdown = self.inner.context.stopped();
        select! {
            _ = &mut shutdown => debug!("context shutdown, stopping accepting network"),
            result = &mut tracker_task => debug!(?result, "tracker stopped"),
            result = &mut router_task => debug!(?result, "router stopped"),
            result = &mut spawner_task => debug!(?result, "spawner stopped"),
            result = &mut attachment_task => debug!(?result, "attachment stopped"),
            result = &mut listener_task => debug!(?result, "listener stopped"),
            result = &mut dialer_task => debug!(?result, "dialer stopped"),
        }
    }
}

/// Authenticated network whose transport connections are supplied explicitly.
#[stability(ALPHA)]
pub struct AttachmentNetwork<
    E: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    N: Connection,
    A: crate::authenticated::admission::InboundAdmission<C::PublicKey, N::Origin>,
> {
    context: ContextCell<E>,
    mailbox_size: std::num::NonZeroUsize,
    send_batch_size: std::num::NonZeroUsize,
    ping_frequency: std::time::Duration,
    channels: Channels<C::PublicKey>,
    tracker: tracker::Actor<E, C>,
    tracker_mailbox: tracker::Mailbox<C::PublicKey>,
    router: router::Actor<E, C::PublicKey>,
    router_mailbox: router::Mailbox<C::PublicKey>,
    attachment: attachment::Actor<E, C, N, A>,
}

#[stability(ALPHA)]
impl<
    E: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    N: Connection,
    A: crate::authenticated::admission::InboundAdmission<C::PublicKey, N::Origin>,
> AttachmentNetwork<E, C, N, A>
{
    /// Creates a network and a handle for supplying transport connections.
    #[allow(
        clippy::type_complexity,
        reason = "the network, reachability oracle, and attachment handle are its construction interface"
    )]
    pub fn new(
        context: E,
        cfg: AttachmentConfig<C, A>,
    ) -> (
        Self,
        tracker::Oracle<C::PublicKey>,
        crate::authenticated::attachment::Attachments<N, C::PublicKey, A>,
    ) {
        let (tracker, tracker_mailbox, oracle) = tracker::Actor::new(
            context.child("tracker"),
            tracker::Config {
                crypto: cfg.stream.signing_key.clone(),
                mailbox_size: cfg.mailbox_size,
                tracked_peer_sets: cfg.tracked_peer_sets,
                peer_connection_cooldown: cfg.peer_connection_cooldown,
                block_duration: cfg.block_duration,
            },
        );
        let (router, router_mailbox, messenger) = router::Actor::new(
            context.child("router"),
            router::Config {
                mailbox_size: cfg.mailbox_size,
            },
        );
        let channels = Channels::new(
            messenger,
            cfg.stream
                .max_message_size
                .saturating_sub(MAX_PAYLOAD_DATA_OVERHEAD),
        );
        let (attachment, attachments) = attachment::Actor::new(
            context.child("attachment"),
            cfg.stream.clone(),
            cfg.admission,
            cfg.mailbox_size,
            cfg.max_concurrent_handshakes,
        );

        (
            Self {
                context: ContextCell::new(context),
                mailbox_size: cfg.mailbox_size,
                send_batch_size: cfg.send_batch_size,
                ping_frequency: cfg.ping_frequency,
                channels,
                tracker,
                tracker_mailbox,
                router,
                router_mailbox,
                attachment,
            },
            oracle,
            attachments,
        )
    }

    /// Registers an application channel.
    #[allow(clippy::type_complexity)]
    pub fn register(
        &mut self,
        channel: Channel,
        rate: Quota,
        backlog: usize,
    ) -> (
        channels::Sender<C::PublicKey, E>,
        channels::Receiver<C::PublicKey>,
    ) {
        let context = self
            .context
            .child("channel")
            .with_attribute("index", channel);
        self.channels.register(channel, rate, backlog, context)
    }

    /// Starts the tracker, router, peer spawner, and attachment actors.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(self) {
        let mut tracker_task = self.tracker.start();
        let mut router_task = self.router.start(self.channels);
        let (spawner, spawner_mailbox) = spawner::Actor::new(
            self.context.child("spawner"),
            spawner::Config {
                mailbox_size: self.mailbox_size,
                send_batch_size: self.send_batch_size,
                ping_frequency: self.ping_frequency,
            },
        );
        let mut spawner_task =
            spawner.start(self.tracker_mailbox.clone(), self.router_mailbox.clone());
        let mut attachment_task = self.attachment.start(self.tracker_mailbox, spawner_mailbox);
        let mut shutdown = self.context.stopped();

        info!("attachment network started");
        select! {
            _ = &mut shutdown => debug!("context shutdown, stopping network"),
            tracker = &mut tracker_task => debug!(?tracker, "tracker stopped, shutting down network"),
            router = &mut router_task => debug!(?router, "router stopped, shutting down network"),
            spawner = &mut spawner_task => debug!(?spawner, "spawner stopped, shutting down network"),
            attachment = &mut attachment_task => debug!(?attachment, "attachment actor stopped, shutting down network"),
        }
    }
}

/// Unique suffix for all messages signed in a stream.
const STREAM_SUFFIX: &[u8] = b"_STREAM";

pub(super) struct TcpDialer<D> {
    inner: D,
    selector: Mutex<StdRng>,
    allow_private_ips: bool,
    allow_dns: bool,
}

impl<D: CryptoRng> TcpDialer<D> {
    pub(super) fn new(mut inner: D, allow_private_ips: bool, allow_dns: bool) -> Self {
        let selector = Mutex::new(StdRng::from_rng(&mut inner));
        Self {
            inner,
            selector,
            allow_private_ips,
            allow_dns,
        }
    }
}

impl<D> Dialer for TcpDialer<D>
where
    D: Dialer<Endpoint = TcpEndpoint> + Resolver + CryptoRng,
{
    type Endpoint = Ingress;
    type Connection = D::Connection;

    fn supports(&self, endpoint: &Self::Endpoint) -> bool {
        if !endpoint.is_valid(self.allow_private_ips, self.allow_dns) {
            return false;
        }
        match endpoint {
            Ingress::Socket(_) => self
                .inner
                .supports(&endpoint.tcp_endpoint(self.allow_private_ips)),
            Ingress::Dns { .. } => true,
        }
    }

    async fn dial(
        &self,
        endpoint: &Self::Endpoint,
    ) -> Result<Self::Connection, commonware_runtime::Error> {
        let addresses: Vec<_> = endpoint
            .resolve_filtered(&self.inner, self.allow_private_ips)
            .await
            .map(Iterator::collect)
            .unwrap_or_default();
        let address = addresses
            .choose(&mut *self.selector.lock())
            .copied()
            .ok_or(commonware_runtime::Error::ConnectionFailed)?;
        self.inner.dial(&TcpEndpoint::Socket(address)).await
    }
}

/// Implementation of an `authenticated` network.
pub struct Network<
    E: Spawner
        + BufferPooler
        + Clock
        + CryptoRng
        + Resolver
        + Acceptor<Bind = std::net::SocketAddr>
        + Dialer<Endpoint = TcpEndpoint, Connection = <E as Acceptor>::Connection>
        + Metrics,
    C: Signer,
> where
    <E as Acceptor>::Connection: Connection<Origin = TcpOrigin>,
{
    context: ContextCell<E>,
    cfg: Config<C>,

    channels: Channels<C::PublicKey>,
    tracker: tracker::Actor<E, C>,
    tracker_mailbox: tracker::Mailbox<C::PublicKey>,
    router: router::Actor<E, C::PublicKey>,
    router_mailbox: router::Mailbox<C::PublicKey>,
    admission: TcpAdmission<E, C::PublicKey>,
}

impl<
    E: Spawner
        + BufferPooler
        + Clock
        + CryptoRng
        + Resolver
        + Acceptor<Bind = std::net::SocketAddr>
        + Dialer<Endpoint = TcpEndpoint, Connection = <E as Acceptor>::Connection>
        + Metrics,
    C: Signer,
> Network<E, C>
where
    <E as Acceptor>::Connection: Connection<Origin = TcpOrigin>,
{
    /// Create a new instance of an `authenticated` network.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Configuration for the network.
    ///
    /// # Returns
    ///
    /// * A tuple containing the network instance and the oracle that
    ///   can be used by a developer to configure which peers are authorized.
    pub fn new(context: E, cfg: Config<C>) -> (Self, Oracle<C::PublicKey>) {
        let max_sets = cfg.tracked_peer_sets.get();
        let (tracker, tracker_mailbox, tracker_oracle, eligibility) =
            tracker::Actor::with_eligibility(
                context.child("tracker"),
                tracker::Config {
                    crypto: cfg.crypto.clone(),
                    mailbox_size: cfg.mailbox_size,
                    tracked_peer_sets: cfg.tracked_peer_sets,
                    peer_connection_cooldown: cfg.peer_connection_cooldown,
                    block_duration: cfg.block_duration,
                },
            );
        let (router, router_mailbox, messenger) = router::Actor::new(
            context.child("router"),
            router::Config {
                mailbox_size: cfg.mailbox_size,
            },
        );
        let channels = Channels::new(messenger, cfg.max_message_size);
        let (admission, updates) = TcpAdmission::with_eligibility(
            context.child("admission"),
            TcpAdmissionConfig {
                allow_private_ips: cfg.allow_private_ips,
                require_registered_ip: !cfg.bypass_ip_check,
                allowed_handshake_rate_per_ip: cfg.allowed_handshake_rate_per_ip,
                allowed_handshake_rate_per_subnet: cfg.allowed_handshake_rate_per_subnet,
            },
            eligibility,
        );
        let oracle = Oracle {
            inner: tracker_oracle,
            updates,
            state: Arc::new(Mutex::new(TcpOracleState {
                sets: BTreeMap::new(),
                max_sets,
            })),
            #[cfg(test)]
            after_tracker_update: None,
        };

        (
            Self {
                context: ContextCell::new(context),
                cfg,

                channels,
                tracker,
                tracker_mailbox,
                router,
                router_mailbox,
                admission,
            },
            oracle,
        )
    }

    /// Register a new channel over the network.
    ///
    /// # Parameters
    ///
    /// * `channel` - Unique identifier for the channel.
    /// * `rate` - Rate at which messages can be received over the channel.
    /// * `backlog` - Maximum number of messages that can be queued on the channel before blocking.
    ///
    /// # Returns
    ///
    /// * A tuple containing the sender and receiver for the channel (how to communicate
    ///   with external peers on the network). It is safe to close either the sender or receiver
    ///   without impacting the ability to process messages on other channels.
    #[allow(clippy::type_complexity)]
    pub fn register(
        &mut self,
        channel: Channel,
        rate: Quota,
        backlog: usize,
    ) -> (
        channels::Sender<C::PublicKey, E>,
        channels::Receiver<C::PublicKey>,
    ) {
        let context = self
            .context
            .child("channel")
            .with_attribute("index", channel);
        self.channels.register(channel, rate, backlog, context)
    }

    /// Starts the network.
    ///
    /// After the network is started, it is not possible to add more channels.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(self) {
        // Start tracker
        let mut tracker_task = self.tracker.start();

        // Start router
        let mut router_task = self.router.start(self.channels);

        // Start spawner
        let (spawner, spawner_mailbox) = spawner::Actor::new(
            self.context.child("spawner"),
            spawner::Config {
                mailbox_size: self.cfg.mailbox_size,
                send_batch_size: self.cfg.send_batch_size,
                ping_frequency: self.cfg.ping_frequency,
            },
        );
        let mut spawner_task =
            spawner.start(self.tracker_mailbox.clone(), self.router_mailbox.clone());

        let stream_cfg = StreamConfig {
            signing_key: self.cfg.crypto,
            namespace: union(&self.cfg.namespace, STREAM_SUFFIX),
            max_message_size: self
                .cfg
                .max_message_size
                .saturating_add(MAX_PAYLOAD_DATA_OVERHEAD),
            synchrony_bound: self.cfg.synchrony_bound,
            max_handshake_age: self.cfg.max_handshake_age,
            handshake_timeout: self.cfg.handshake_timeout,
        };
        let (attachment, attachments) = attachment::Actor::new(
            self.context.child("attachment"),
            stream_cfg.clone(),
            self.admission,
            self.cfg.mailbox_size,
            self.cfg.max_concurrent_handshakes,
        );
        let mut attachment_task =
            attachment.start_listener(self.tracker_mailbox.clone(), spawner_mailbox.clone());

        // Start listener
        let listener = listener::Actor::new(
            self.context.child("listener"),
            self.context.child("acceptor"),
            listener::Config {
                bind: self.cfg.listen,
            },
        );
        let mut listener_task = listener.start(attachments);

        // Start dialer
        let dialer = dialer::Actor::new(
            self.context.child("dialer"),
            TcpDialer::new(
                self.context.child("transport_dialer"),
                self.cfg.allow_private_ips,
                self.cfg.allow_dns,
            ),
            dialer::Config {
                stream_cfg,
                dial_timeout: self.cfg.dial_timeout,
                dial_frequency: self.cfg.dial_frequency,
                peer_connection_cooldown: self.cfg.peer_connection_cooldown,
            },
        );
        let mut dialer_task = dialer.start(self.tracker_mailbox, spawner_mailbox);

        let mut shutdown = self.context.stopped();

        // If any task completes, the network should stop
        info!("network started");
        select! {
            _ = &mut shutdown => {
                debug!("context shutdown, stopping network");
            },
            tracker = &mut tracker_task => {
                debug!(?tracker, "tracker stopped, shutting down network");
            },
            router = &mut router_task => {
                debug!(?router, "router stopped, shutting down network");
            },
            spawner = &mut spawner_task => {
                debug!(?spawner, "spawner stopped, shutting down network");
            },
            listener = &mut listener_task => {
                debug!(?listener, "listener stopped, shutting down network");
            },
            attachment = &mut attachment_task => {
                debug!(?attachment, "attachment stopped, shutting down network");
            },
            dialer = &mut dialer_task => {
                debug!(?dialer, "dialer stopped, shutting down network");
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::admission::{InboundAdmission, Rejection};
    use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
    use commonware_runtime::{
        ConnectionInfo, Resolver, Runner as _, Supervisor as _, deterministic,
    };
    use commonware_utils::{NZUsize, hostname, sync::Mutex as TestMutex};
    use rand_core::{TryCryptoRng, TryRng};
    use std::{
        convert::Infallible,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{Arc as StdArc, Barrier},
        time::Duration,
    };

    struct RecordingTcpDialer {
        context: deterministic::Context,
        attempts: StdArc<TestMutex<Vec<TcpEndpoint>>>,
    }

    impl TryRng for RecordingTcpDialer {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            self.context.try_next_u32()
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.context.try_next_u64()
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            self.context.try_fill_bytes(dest)
        }
    }

    impl TryCryptoRng for RecordingTcpDialer {}

    impl Resolver for RecordingTcpDialer {
        async fn resolve(
            &self,
            _host: &str,
        ) -> Result<Vec<IpAddr>, commonware_runtime::Error> {
            Ok(vec![
                Ipv4Addr::new(8, 8, 8, 8).into(),
                Ipv4Addr::new(1, 1, 1, 1).into(),
            ])
        }
    }

    impl Dialer for RecordingTcpDialer {
        type Endpoint = TcpEndpoint;
        type Connection = <deterministic::Context as Dialer>::Connection;

        async fn dial(
            &self,
            endpoint: &Self::Endpoint,
        ) -> Result<Self::Connection, commonware_runtime::Error> {
            self.attempts.lock().push(endpoint.clone());
            Err(commonware_runtime::Error::ConnectionFailed)
        }
    }

    fn connection_info(remote: SocketAddr) -> ConnectionInfo<TcpOrigin> {
        ConnectionInfo {
            origin: Some(TcpOrigin { remote }),
            transport: "tcp",
        }
    }

    async fn assert_origin_accepted<E>(
        admission: &TcpAdmission<E, PublicKey>,
        peer: &PublicKey,
        remote: SocketAddr,
    ) where
        E: Clock + Metrics,
    {
        let info = connection_info(remote);
        let permit = admission
            .pre_auth(&info)
            .expect("registered origin should begin authentication");
        assert_eq!(admission.post_auth(permit, peer, &info).await, Ok(()));
    }

    fn assert_origin_rejected<E>(admission: &TcpAdmission<E, PublicKey>, remote: SocketAddr)
    where
        E: Clock + Metrics,
    {
        assert_eq!(
            admission.pre_auth(&connection_info(remote)),
            Err(Rejection::UnregisteredIp)
        );
    }

    #[test]
    fn tcp_dialer_selects_one_resolved_address_per_attempt() {
        deterministic::Runner::default().start(|context| async move {
            let attempts = StdArc::new(TestMutex::new(Vec::new()));
            let transport = RecordingTcpDialer {
                context: context.child("transport"),
                attempts: attempts.clone(),
            };
            let dialer = TcpDialer::new(transport, false, true);
            let endpoint = Ingress::Dns {
                host: hostname!("example.com"),
                port: 443,
            };

            assert!(matches!(
                dialer.dial(&endpoint).await,
                Err(commonware_runtime::Error::ConnectionFailed)
            ));
            let attempts = attempts.lock();
            assert_eq!(attempts.len(), 1);
            assert!(matches!(attempts[0], TcpEndpoint::Socket(_)));
        });
    }

    #[test]
    fn oracle_admission_uses_latest_address_across_retained_sets() {
        deterministic::Runner::default().start(|context| async move {
            let signer = PrivateKey::from_seed(0);
            let peer = PrivateKey::from_seed(1).public_key();
            let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
            let old_origin = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 1000));
            let new_origin = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 1000));
            let mut config = Config::test(signer, listen, 1024);
            config.tracked_peer_sets = NZUsize!(2);

            let (network, mut oracle) = Network::new(context.child("network"), config);
            let tracker_mailbox = network.tracker_mailbox.clone();
            network.tracker.start();
            let old_set = Map::try_from([(peer.clone(), Address::from(old_origin))]).unwrap();
            let new_set = Map::try_from([(peer.clone(), Address::from(new_origin))]).unwrap();
            oracle.track(0, old_set);
            oracle.track(1, new_set);
            assert!(tracker_mailbox.acceptable(peer.clone()).await);

            assert_origin_rejected(&network.admission, old_origin);
            assert_origin_accepted(&network.admission, &peer, new_origin).await;
        });
    }

    #[test]
    fn oracle_updates_admission_before_publishing_tracker_changes() {
        deterministic::Runner::default().start(|context| async move {
            let signer = PrivateKey::from_seed(3);
            let peer = PrivateKey::from_seed(4).public_key();
            let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
            let old_origin = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 1000));
            let new_origin = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 1000));
            let config = Config::test(signer, listen, 1024);

            let (network, mut oracle) = Network::new(context.child("network"), config);
            let tracker_mailbox = network.tracker_mailbox.clone();
            network.tracker.start();
            oracle.track(
                0,
                Map::try_from([(peer.clone(), Address::from(old_origin))]).unwrap(),
            );
            assert!(tracker_mailbox.acceptable(peer.clone()).await);

            let published = StdArc::new(Barrier::new(2));
            let release = StdArc::new(Barrier::new(2));
            oracle.after_tracker_update = Some(StdArc::new({
                let published = published.clone();
                let release = release.clone();
                move || {
                    published.wait();
                    release.wait();
                }
            }));
            let update = std::thread::spawn(move || {
                oracle.overwrite(
                    Map::try_from([(peer.clone(), Address::from(new_origin))]).unwrap(),
                )
            });

            published.wait();
            let reservation = tracker_mailbox
                .listen(PrivateKey::from_seed(4).public_key())
                .await;
            let old_origin_result = network.admission.pre_auth(&connection_info(old_origin));
            release.wait();
            assert!(update.join().unwrap().accepted());

            assert!(reservation.is_some());
            assert_eq!(old_origin_result, Err(Rejection::UnregisteredIp));
        });
    }

    #[test]
    fn oracle_admission_prefers_primary_address_within_set() {
        deterministic::Runner::default().start(|context| async move {
            let signer = PrivateKey::from_seed(0);
            let peer = PrivateKey::from_seed(1).public_key();
            let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
            let primary_origin = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 1000));
            let secondary_origin = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 2), 1000));
            let config = Config::test(signer, listen, 1024);

            let primary =
                Map::try_from([(peer.clone(), Address::from(primary_origin))]).unwrap();
            let secondary =
                Map::try_from([(peer.clone(), Address::from(secondary_origin))]).unwrap();
            let (network, mut oracle) = Network::new(context.child("network"), config);
            let tracker_mailbox = network.tracker_mailbox.clone();
            network.tracker.start();
            oracle.track(0, AddressableTrackedPeers::new(primary, secondary));
            assert!(tracker_mailbox.acceptable(peer.clone()).await);

            assert_origin_accepted(&network.admission, &peer, primary_origin).await;
            assert_origin_rejected(&network.admission, secondary_origin);
        });
    }

    #[test]
    fn oracle_admission_removes_unique_origin_while_peer_is_blocked() {
        deterministic::Runner::default().start(|context| async move {
            let signer = PrivateKey::from_seed(0);
            let peer = PrivateKey::from_seed(1).public_key();
            let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
            let origin = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 1000));
            let mut config = Config::test(signer, listen, 1024);
            config.block_duration = Duration::from_millis(100);
            let block_duration = config.block_duration;

            let (network, mut oracle) = Network::new(context.child("network"), config);
            let tracker_mailbox = network.tracker_mailbox.clone();
            network.tracker.start();
            let peers = Map::try_from([(peer.clone(), Address::from(origin))]).unwrap();
            oracle.track(0, peers);
            assert!(tracker_mailbox.acceptable(peer.clone()).await);
            assert_origin_accepted(&network.admission, &peer, origin).await;

            crate::block_peer(&mut oracle, peer.clone());
            assert!(!tracker_mailbox.acceptable(peer.clone()).await);
            assert_origin_rejected(&network.admission, origin);

            context
                .sleep(block_duration + Duration::from_millis(1))
                .await;
            assert!(tracker_mailbox.acceptable(peer.clone()).await);
            assert_origin_accepted(&network.admission, &peer, origin).await;
        });
    }

    #[test]
    fn oracle_admission_keeps_origin_shared_with_unblocked_peer() {
        deterministic::Runner::default().start(|context| async move {
            let signer = PrivateKey::from_seed(0);
            let blocked_peer = PrivateKey::from_seed(1).public_key();
            let eligible_peer = PrivateKey::from_seed(2).public_key();
            let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
            let origin = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 1000));
            let config = Config::test(signer, listen, 1024);

            let (network, mut oracle) = Network::new(context.child("network"), config);
            let tracker_mailbox = network.tracker_mailbox.clone();
            network.tracker.start();
            let peers = Map::try_from([
                (blocked_peer.clone(), Address::from(origin)),
                (eligible_peer.clone(), Address::from(origin)),
            ])
            .unwrap();
            oracle.track(0, peers);
            assert!(tracker_mailbox.acceptable(blocked_peer.clone()).await);
            assert!(tracker_mailbox.acceptable(eligible_peer.clone()).await);

            crate::block_peer(&mut oracle, blocked_peer.clone());
            assert!(!tracker_mailbox.acceptable(blocked_peer).await);
            assert!(tracker_mailbox.acceptable(eligible_peer.clone()).await);
            assert_origin_accepted(&network.admission, &eligible_peer, origin).await;
        });
    }
}
