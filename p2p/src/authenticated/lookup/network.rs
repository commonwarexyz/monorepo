//! Implementation of an `authenticated` network.

use super::{
    actors::{dialer, listener, spawner, tracker},
    config::Config,
};
use crate::{
    Channel,
    authenticated::{
        MAX_PAYLOAD_OVERHEAD,
        channels::{self, Channels},
        router,
    },
};
use commonware_cryptography::Signer;
use commonware_macros::select;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Network as RNetwork, Quota, Resolver,
    Spawner, spawn_cell,
};
use commonware_stream::encrypted::Config as StreamConfig;
use commonware_utils::union;
use rand_core::CryptoRng;
use tracing::{debug, info};

/// Unique suffix for all messages signed in a stream.
const STREAM_SUFFIX: &[u8] = b"_STREAM";

/// Implementation of an `authenticated` network.
pub struct Network<E: Spawner + BufferPooler + Clock + CryptoRng + RNetwork + Metrics, C: Signer> {
    context: ContextCell<E>,
    cfg: Config<C>,
    max_frame_size: u32,

    channels: Channels<C::PublicKey>,
    router_staging: Option<router::Staging<C::PublicKey>>,
    tracker: tracker::Actor<E, C>,
    tracker_mailbox: tracker::Mailbox<C::PublicKey>,
    listener: listener::Updates,
}

impl<E: Spawner + BufferPooler + Clock + CryptoRng + RNetwork + Resolver + Metrics, C: Signer>
    Network<E, C>
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
    ///
    /// # Panics
    ///
    /// Panics if [`Config::max_message_size`] plus [`MAX_PAYLOAD_OVERHEAD`] exceeds `u32::MAX`.
    pub fn new(context: E, cfg: Config<C>) -> (Self, tracker::Oracle<C::PublicKey>) {
        let max_frame_size = cfg
            .max_message_size
            .checked_add(MAX_PAYLOAD_OVERHEAD)
            .expect("maximum frame size overflow");
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
        let (messenger, router_staging) = router::Messenger::unbound(
            context.network_buffer_pool().clone(),
            context.child("router_staging"),
            cfg.mailbox_size,
        );
        let channels = Channels::new(messenger, cfg.max_message_size);

        (
            Self {
                context: ContextCell::new(context),
                cfg,
                max_frame_size,

                channels,
                router_staging: Some(router_staging),
                tracker,
                tracker_mailbox,
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
    /// * `rate` - Per-peer message quota for the channel. Inbound traffic from each connected peer
    ///   is paced independently. The returned sender applies the same quota independently to each
    ///   recipient.
    /// * `backlog` - Capacity of the channel's bounded inbound mailbox and its contribution to the
    ///   shared outbound router mailbox.
    ///
    /// # Backpressure
    ///
    /// All peer connections share the channel's inbound mailbox. Enqueueing never waits for
    /// capacity. When the mailbox is full, the arriving message is dropped and queued messages
    /// remain. There is no per-peer reservation or fairness.
    ///
    /// A synchronized burst can contribute up to `rate.burst_size()` messages per connected peer.
    /// To absorb one full burst from every peer, use
    /// [`backlog`](crate::authenticated::backlog) with the maximum number of connected peers. This
    /// sizing includes honest traffic since protocol events can synchronize honest senders. Also
    /// account for expected receiver stalls and ensure its drain rate can sustain aggregate ingress.
    /// No finite backlog can absorb sustained ingress above the drain rate.
    ///
    /// Outbound send invocations from all channels share one router mailbox. Each successful
    /// registration grows the pre-start staging mailbox by `backlog`. The final mailbox has the
    /// same capacity: [`Config::mailbox_size`] plus the sum of all registered backlogs. This
    /// capacity is pooled rather than reserved per channel, and each send uses one slot regardless
    /// of its number of recipients.
    ///
    /// For memory budgeting, the inbound queue can retain roughly `backlog * max_message_size`
    /// bytes, and this backlog also adds the same number of slots to the shared outbound queue, in
    /// addition to queue and allocator overhead.
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
        let registered = self.channels.register(channel, rate, backlog, context);
        self.channels.grow_staging(
            self.router_staging
                .as_mut()
                .expect("router staging mailbox missing"),
            self.context.child("router_staging"),
            self.cfg.mailbox_size,
        );
        registered
    }

    /// Starts the network.
    ///
    /// After the network is started, it is not possible to add more channels.
    /// Before the network starts, outbound content submissions use a staging mailbox bounded by
    /// [`Config::mailbox_size`] plus the sum of all registered channel backlogs. Accepted
    /// submissions are transferred to the equally sized final outbound router mailbox during this
    /// call before the router starts.
    pub fn start(mut self) -> Handle<()> {
        let (router, router_mailbox, _) = router::Actor::new(
            self.context.child("router"),
            router::Config {
                mailbox_size: self.channels.outbound_mailbox_size(self.cfg.mailbox_size),
            },
        );
        self.channels.bind(
            router_mailbox.clone(),
            self.router_staging
                .take()
                .expect("router staging mailbox missing"),
        );
        spawn_cell!(self.context, self.run(router, router_mailbox))
    }

    async fn run(
        self,
        router: router::Actor<E, C::PublicKey>,
        router_mailbox: router::Mailbox<C::PublicKey>,
    ) {
        // Start tracker
        let mut tracker_task = self.tracker.start();

        // Start router
        let mut router_task = router.start(self.channels);

        // Start spawner
        let (spawner, spawner_mailbox) = spawner::Actor::new(
            self.context.child("spawner"),
            spawner::Config {
                mailbox_size: self.cfg.mailbox_size,
                send_batch_size: self.cfg.send_batch_size,
                ping_frequency: self.cfg.ping_frequency,
            },
        );
        let mut spawner_task = spawner.start(self.tracker_mailbox.clone(), router_mailbox);

        // Start listener
        let stream_cfg = StreamConfig {
            signing_key: self.cfg.crypto,
            namespace: union(&self.cfg.namespace, STREAM_SUFFIX),
            max_message_size: self.max_frame_size,
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
