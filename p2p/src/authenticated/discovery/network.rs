//! Implementation of an `authenticated` network.

use super::{
    Handshake,
    actors::{dialer, listener, spawner, tracker},
    config::Config,
};
use crate::{
    Channel,
    authenticated::{
        MAX_PAYLOAD_OVERHEAD,
        channels::{self, Channels},
        discovery::types::{Info, InfoVerifier},
        max_size, router,
    },
    sizing::max_retained_peers,
};
use commonware_macros::select;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Network as RNetwork, Quota, Resolver,
    Spawner, spawn_cell,
};
use commonware_stream::{Config as StreamConfig, utils::Timeout};
use commonware_utils::{SystemTimeExt, ordered::Set, union};
use rand_core::CryptoRng;
use std::sync::Arc;
use tracing::{debug, info};

/// Unique suffix for discovery tracker messages.
const TRACKER_SUFFIX: &[u8] = b"_TRACKER";

/// Unique suffix for stream authentication.
const STREAM_SUFFIX: &[u8] = b"_STREAM";

/// Unique suffix for signed discovery address records.
const IP_SUFFIX: &[u8] = b"_IP";

/// Implementation of an `authenticated` network.
pub struct Network<
    E: Spawner + BufferPooler + Clock + CryptoRng + RNetwork + Resolver + Metrics,
    H: Handshake,
> {
    context: ContextCell<E>,
    cfg: Config<H>,
    max_frame_size: u32,
    max_peer_set_size: u64,

    channels: Channels<H::PublicKey>,
    tracker: tracker::Actor<E, H::PublicKey>,
    tracker_mailbox: tracker::Mailbox<H::PublicKey>,
    info_verifier: InfoVerifier<H::PublicKey>,
}

impl<E: Spawner + BufferPooler + Clock + CryptoRng + RNetwork + Resolver + Metrics, H: Handshake>
    Network<E, H>
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
    /// Panics if the configured frame size exceeds the stream limit or capacity arithmetic overflows.
    pub fn new(context: E, cfg: Config<H>) -> (Self, tracker::Oracle<H::PublicKey>) {
        assert!(
            cfg.max_message_size <= max_size::<H>(),
            "maximum message size exceeds stream limit"
        );
        let max_frame_size = cfg
            .max_message_size
            .checked_add(MAX_PAYLOAD_OVERHEAD)
            .expect("maximum frame size overflow");
        let max_peer_set_size =
            u64::try_from(cfg.max_peers_per_set.get()).expect("maximum peers per set exceeds u64");

        // Bootstrappers persist outside the tracked peer-set window. Reserve capacity for each
        // distinct remote identity without folding them into the per-set limit.
        let local = cfg.handshake.public_key();
        let persistent_peers = Set::from_iter_dedup(
            cfg.bootstrappers
                .iter()
                .map(|(peer, _)| peer.clone())
                .filter(|peer| peer != &local),
        )
        .len();
        let max_retained_peers = max_retained_peers(
            cfg.max_peers_per_set,
            cfg.tracked_peer_sets,
            persistent_peers,
        );
        let ip_namespace = union(&union(&cfg.namespace, TRACKER_SUFFIX), IP_SUFFIX);
        let myself = Info::sign(
            local.clone(),
            &ip_namespace,
            cfg.dialable.clone(),
            context.current().epoch_millis(),
            |namespace, message| cfg.handshake.sign(namespace, message),
        );
        let info_verifier = Info::verifier(
            local,
            cfg.peer_gossip_max_count,
            cfg.synchrony_bound,
            ip_namespace,
        );
        let (tracker, tracker_mailbox, oracle) = tracker::Actor::new(
            context.child("tracker"),
            tracker::Config {
                myself,
                bootstrappers: cfg.bootstrappers.clone(),
                allow_private_ips: cfg.allow_private_ips,
                allow_dns: cfg.allow_dns,
                mailbox_size: cfg.mailbox_size,
                max_peers_per_set: cfg.max_peers_per_set.get(),
                tracked_peer_sets: cfg.tracked_peer_sets,
                peer_connection_cooldown: cfg.peer_connection_cooldown,
                peer_gossip_max_count: cfg.peer_gossip_max_count,
                dial_fail_limit: cfg.dial_fail_limit,
                block_duration: cfg.block_duration,
            },
        );
        let messenger = router::Messenger::unbound(context.network_buffer_pool().clone());
        let channels = Channels::new(messenger, cfg.max_message_size, max_retained_peers);

        (
            Self {
                context: ContextCell::new(context),
                cfg,
                max_frame_size,
                max_peer_set_size,

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
    /// The mailbox holds one quota burst for every identity allowed by the derived retained-peer
    /// bound. This includes honest traffic since protocol events can synchronize honest senders,
    /// but does not cover receiver stalls or sustained ingress above the receiver's drain rate.
    ///
    /// Outbound send invocations from all channels share one router mailbox. The final mailbox
    /// capacity is [`Config::mailbox_size`] plus every registered channel's derived inbound
    /// capacity. This capacity is pooled rather than reserved per channel, and each send uses one
    /// slot regardless of its number of recipients.
    ///
    /// The derived capacity budgets per-recipient quota bursts for every configured remote
    /// identity. It does not reserve space for arbitrary offline recipient identities, so bursts
    /// to those identities may be rejected under backpressure.
    ///
    /// For memory budgeting, multiply the derived retained-peer bound by the burst size and maximum
    /// message size, then add queue and allocator overhead.
    ///
    /// # Panics
    ///
    /// Panics if `channel` is already registered or if the derived channel or router mailbox
    /// capacity overflows.
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
        channels::Sender<H::PublicKey, E>,
        channels::Receiver<H::PublicKey>,
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
    ///
    /// # Panics
    ///
    /// Panics if adding the internal mailbox capacity to the registered channel capacities
    /// overflows.
    pub fn start(mut self) -> Handle<()> {
        // Size the router mailbox from the registered channels before binding their senders.
        // Submissions made before binding are accepted and dropped.
        let (router, router_mailbox) = router::Actor::new(
            self.context.child("router"),
            router::Config {
                mailbox_size: self.channels.outbound_mailbox_size(self.cfg.mailbox_size),
            },
        );
        self.channels.bind(router_mailbox.clone());
        spawn_cell!(self.context, self.run(router, router_mailbox))
    }

    async fn run(
        self,
        router: router::Actor<E, H::PublicKey>,
        router_mailbox: router::Mailbox<H::PublicKey>,
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
                max_peer_set_size: self.max_peer_set_size,
                peer_gossip_max_count: self.cfg.peer_gossip_max_count,
                info_verifier: self.info_verifier,
            },
        );
        let mut spawner_task = spawner.start(self.tracker_mailbox.clone(), router_mailbox);

        // Inbound and outbound connections share the same handshake policy.
        let stream = Arc::new(StreamConfig::new(
            Timeout::new(self.cfg.handshake, self.cfg.handshake_timeout),
            union(&self.cfg.namespace, STREAM_SUFFIX),
            self.max_frame_size,
        ));

        // Start listener
        let listener = listener::Actor::new(
            self.context.child("listener"),
            listener::Config {
                address: self.cfg.listen,
                stream: stream.clone(),
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
                stream,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ingress, Manager, authenticated::discovery::actors::peer};
    use commonware_codec::Encode;
    use commonware_cryptography::{Signer, ed25519::PrivateKey};
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use commonware_stream::encrypted::Handshake as StreamHandshake;
    use commonware_utils::NZUsize;
    use std::{net::SocketAddr, time::Duration};

    #[test]
    fn greeting_and_verifier_use_the_authenticated_identity_and_gossip_namespace() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            // Configure distinct local and remote identities.
            let signer = PrivateKey::from_seed(0);
            let peer_signer = PrivateKey::from_seed(1);
            let local = signer.public_key();
            let peer = peer_signer.public_key();
            let address = SocketAddr::from(([127, 0, 0, 1], 7000));
            let cfg = Config::local(
                StreamHandshake::new(signer.clone()),
                b"discovery-test",
                address,
                address,
                Vec::new(),
                NZUsize!(2),
                1024,
            );
            let timestamp = context.current().epoch_millis();
            let (network, mut oracle) = Network::new(context.child("network"), cfg);

            // Accept a peer record signed in the gossip namespace.
            let ingress = Ingress::from(address);
            let message = (ingress, timestamp).encode();
            let namespace = b"discovery-test_TRACKER_IP";
            let peer_info = Info {
                ingress: address.into(),
                timestamp,
                public_key: peer.clone(),
                signature: peer_signer.sign(namespace, &message),
            };
            assert!(
                network
                    .info_verifier
                    .validate(&context, &[peer_info])
                    .is_ok()
            );

            // Check that the greeting uses the handshake's identity and the gossip namespace.
            network.tracker.start();
            oracle.track(0, Set::try_from([local.clone(), peer.clone()]).unwrap());
            let _reservation = network.tracker_mailbox.listen(peer.clone()).await.unwrap();
            let (mailbox, _receiver) = peer::Mailbox::new(context.child("peer"), NZUsize!(1));
            let greeting = network
                .tracker_mailbox
                .connect(peer, mailbox, false)
                .await
                .unwrap();
            assert_eq!(greeting.public_key, local);
            assert_eq!(greeting.ingress, address.into());
            assert_eq!(greeting.timestamp, timestamp);
            assert_eq!(greeting.signature, signer.sign(namespace, &message));
        });
    }
}
