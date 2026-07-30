//! Implementation of an `authenticated` network.

use super::{
    actors::{attachment, dialer, listener, spawner, tracker},
    config::{AttachmentConfig, Config},
};
use crate::{
    Channel,
    authenticated::{
        channels::{self, Channels},
        data::MAX_PAYLOAD_DATA_OVERHEAD,
        router,
    },
};
use commonware_cryptography::Signer;
use commonware_macros::select;
use commonware_runtime::{
    Acceptor, BufferPooler, Clock, Connection, ContextCell, Dialer, Handle, Metrics, Quota,
    Scheduler, TcpEndpoint, TcpOrigin, spawn_cell,
};
use commonware_stream::encrypted::Config as StreamConfig;
use commonware_utils::union;
use rand_core::CryptoRng;
use tracing::{debug, info};

/// Authenticated network whose transport connections are supplied explicitly.
pub struct AttachmentNetwork<
    E: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    N: Connection,
    A: attachment::PeerAdmission<C::PublicKey, N::Origin>,
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

impl<
    E: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    N: Connection,
    A: attachment::PeerAdmission<C::PublicKey, N::Origin>,
> AttachmentNetwork<E, C, N, A>
{
    /// Creates a network and a handle for supplying transport connections.
    pub fn new(
        context: E,
        cfg: AttachmentConfig<C, A>,
    ) -> (
        Self,
        tracker::Oracle<C::PublicKey>,
        attachment::Attachments<N, C::PublicKey>,
    ) {
        // Retain the tracker update sink required by the shared tracker implementation.
        let (listener, _updates) = listener::Mailbox::new();
        let (tracker, tracker_mailbox, oracle) = tracker::Actor::new(
            context.child("tracker"),
            tracker::Config {
                crypto: cfg.stream.signing_key.clone(),
                mailbox_size: cfg.mailbox_size,
                tracked_peer_sets: cfg.tracked_peer_sets,
                peer_connection_cooldown: cfg.peer_connection_cooldown,
                allow_private_ips: false,
                allow_dns: false,
                bypass_ip_check: true,
                listener,
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
        let mut attachment_task = self
            .attachment
            .start(self.tracker_mailbox, spawner_mailbox);
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

/// Implementation of an `authenticated` network.
pub struct Network<
    E: Scheduler
        + BufferPooler
        + Clock
        + CryptoRng
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
    listener: listener::Updates,
}

impl<
    E: Scheduler
        + BufferPooler
        + Clock
        + CryptoRng
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
    pub fn new(context: E, cfg: Config<C>) -> (Self, tracker::Oracle<C::PublicKey>) {
        let (listener_mailbox, listener) = listener::Mailbox::new();
        let (tracker, tracker_mailbox, oracle) = tracker::Actor::new(
            context.child("tracker"),
            tracker::Config {
                crypto: cfg.crypto.clone(),
                mailbox_size: cfg.mailbox_size,
                tracked_peer_sets: cfg.tracked_peer_sets,
                peer_connection_cooldown: cfg.peer_connection_cooldown,
                allow_private_ips: cfg.allow_private_ips,
                allow_dns: cfg.allow_dns,
                bypass_ip_check: cfg.bypass_ip_check,
                listener: listener_mailbox,
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

        (
            Self {
                context: ContextCell::new(context),
                cfg,

                channels,
                tracker,
                tracker_mailbox,
                router,
                router_mailbox,
                listener,
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

        // Start listener
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
        let listener = listener::Actor::new(
            self.context.child("listener"),
            listener::Config {
                address: self.cfg.listen,
                stream_cfg: stream_cfg.clone(),
                allow_private_ips: self.cfg.allow_private_ips,
                bypass_ip_check: self.cfg.bypass_ip_check,
                max_concurrent_handshakes: self.cfg.max_concurrent_handshakes,
                allowed_handshake_rate_per_ip: self.cfg.allowed_handshake_rate_per_ip,
                allowed_handshake_rate_per_subnet: self.cfg.allowed_handshake_rate_per_subnet,
            },
            self.listener,
        );
        let mut listener_task =
            listener.start(self.tracker_mailbox.clone(), spawner_mailbox.clone());

        // Start dialer
        let dialer = dialer::Actor::new(
            self.context.child("dialer"),
            dialer::Config {
                stream_cfg,
                dial_timeout: self.cfg.dial_timeout,
                dial_frequency: self.cfg.dial_frequency,
                peer_connection_cooldown: self.cfg.peer_connection_cooldown,
                allow_private_ips: self.cfg.allow_private_ips,
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
            dialer = &mut dialer_task => {
                debug!(?dialer, "dialer stopped, shutting down network");
            },
        }
    }
}
