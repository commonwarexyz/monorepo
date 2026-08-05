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
        discovery::types::InfoVerifier,
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

/// Unique suffix for all messages signed by the tracker.
const TRACKER_SUFFIX: &[u8] = b"_TRACKER";

/// Unique suffix for all messages signed in a stream.
const STREAM_SUFFIX: &[u8] = b"_STREAM";

/// Implementation of an `authenticated` network.
pub struct Network<
    E: Spawner + BufferPooler + Clock + CryptoRng + RNetwork + Resolver + Metrics,
    C: Signer,
> {
    context: ContextCell<E>,
    cfg: Config<C>,
    max_frame_size: u32,

    channels: Channels<C::PublicKey>,
    tracker: tracker::Actor<E, C>,
    tracker_mailbox: tracker::Mailbox<C::PublicKey>,
    info_verifier: InfoVerifier<C::PublicKey>,
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
        let (tracker, tracker_mailbox, oracle, info_verifier) = tracker::Actor::new(
            context.child("tracker"),
            tracker::Config {
                crypto: cfg.crypto.clone(),
                namespace: union(&cfg.namespace, TRACKER_SUFFIX),
                address: cfg.dialable.clone(),
                bootstrappers: cfg.bootstrappers.clone(),
                allow_private_ips: cfg.allow_private_ips,
                allow_dns: cfg.allow_dns,
                synchrony_bound: cfg.synchrony_bound,
                mailbox_size: cfg.mailbox_size,
                tracked_peer_sets: cfg.tracked_peer_sets,
                peer_connection_cooldown: cfg.peer_connection_cooldown,
                peer_gossip_max_count: cfg.peer_gossip_max_count,
                max_peer_set_size: cfg.max_peer_set_size,
                dial_fail_limit: cfg.dial_fail_limit,
                block_duration: cfg.block_duration,
            },
        );
        let messenger = router::Messenger::unbound(context.network_buffer_pool().clone());
        let channels = Channels::new(messenger, cfg.max_message_size, cfg.max_peers);

        (
            Self {
                context: ContextCell::new(context),
                cfg,
                max_frame_size,

                channels,
                tracker,
                tracker_mailbox,
                info_verifier,
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
    /// # Backpressure
    ///
    /// All peer connections share the channel's inbound mailbox. Enqueueing never waits for
    /// capacity. When the mailbox is full, the arriving message is dropped and queued messages
    /// remain. There is no per-peer reservation or fairness.
    ///
    /// The mailbox holds one `rate.burst_size()` burst for each of the configured
    /// [`Config::max_peers`]. This includes honest traffic since protocol events can synchronize
    /// honest senders, but does not cover receiver stalls or sustained ingress above the
    /// receiver's drain rate.
    ///
    /// Outbound send invocations from all channels share one router mailbox. The final mailbox
    /// capacity is [`Config::mailbox_size`] plus every registered channel's derived inbound
    /// capacity. This capacity is pooled rather than reserved per channel, and each send uses one
    /// slot regardless of its number of recipients.
    ///
    /// The derived capacity budgets per-recipient quota bursts across at most
    /// [`Config::max_peers`] connected peers. It does not reserve space for arbitrary offline
    /// recipient identities, so bursts to those identities may be rejected under backpressure.
    ///
    /// For memory budgeting, each inbound queue can retain roughly `max_peers * burst_size *
    /// max_message_size` bytes, in addition to queue and allocator overhead.
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
    ) -> (
        channels::Sender<C::PublicKey, E>,
        channels::Receiver<C::PublicKey>,
    ) {
        let context = self
            .context
            .child("channel")
            .with_attribute("index", channel);
        self.channels.register(channel, rate, context)
    }

    /// Starts the network.
    ///
    /// After the network is started, it is not possible to add more channels.
    /// Registered senders are bound to the outbound router during this call; submissions made
    /// before it are accepted and dropped.
    pub fn start(mut self) -> Handle<()> {
        let (router, router_mailbox, _) = router::Actor::new(
            self.context.child("router"),
            router::Config {
                mailbox_size: self.channels.outbound_mailbox_size(self.cfg.mailbox_size),
                max_peers: self.cfg.max_peers,
            },
        );
        self.channels.bind(router_mailbox.clone());
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
                gossip_bit_vec_frequency: self.cfg.gossip_bit_vec_frequency,
                max_peer_set_size: self.cfg.max_peer_set_size,
                peer_gossip_max_count: self.cfg.peer_gossip_max_count,
                info_verifier: self.info_verifier,
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
                max_concurrent_handshakes: self.cfg.max_concurrent_handshakes,
                allowed_handshake_rate_per_ip: self.cfg.allowed_handshake_rate_per_ip,
                allowed_handshake_rate_per_subnet: self.cfg.allowed_handshake_rate_per_subnet,
            },
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
