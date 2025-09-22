//! Implementation of an `authenticated` network.

use super::{
    actors::{dialer, listener, router, spawner, tracker},
    channels::{self, Channels},
    config::Config,
    types,
};
use crate::{authenticated::Mailbox, Channel};
use commonware_cryptography::Signer;
use commonware_macros::select;
use commonware_runtime::{Clock, Handle, Metrics, Network as RNetwork, Spawner};
use commonware_stream::public_key;
use commonware_utils::union;
use governor::{clock::ReasonablyRealtime, Quota};
use rand::{CryptoRng, Rng};
use tracing::{debug, info, warn};

/// Unique suffix for all messages signed by the tracker.
const TRACKER_SUFFIX: &[u8] = b"_TRACKER";

/// Unique suffix for all messages signed in a stream.
const STREAM_SUFFIX: &[u8] = b"_STREAM";

/// Implementation of an `authenticated` network.
pub struct Network<
    E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + RNetwork + Metrics,
    C: Signer,
> {
    context: E,
    cfg: Config<C>,

    channels: Channels<C::PublicKey>,
    tracker: tracker::Actor<E, C>,
    tracker_mailbox: Mailbox<tracker::Message<E, C::PublicKey>>,
    router: router::Actor<C::PublicKey>,
    router_mailbox: Mailbox<router::Message<C::PublicKey>>,
}

impl<E: Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + RNetwork + Metrics, C: Signer>
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
    pub fn new(context: E, cfg: Config<C>) -> (Self, tracker::Oracle<E, C::PublicKey>) {
        let (tracker, tracker_mailbox, oracle) = tracker::Actor::new(
            context.with_label("tracker"),
            tracker::Config {
                crypto: cfg.crypto.clone(),
                namespace: union(&cfg.namespace, TRACKER_SUFFIX),
                address: cfg.dialable,
                bootstrappers: cfg.bootstrappers.clone(),
                allow_private_ips: cfg.allow_private_ips,
                mailbox_size: cfg.mailbox_size,
                synchrony_bound: cfg.synchrony_bound,
                tracked_peer_sets: cfg.tracked_peer_sets,
                allowed_connection_rate_per_peer: cfg.allowed_connection_rate_per_peer,
                peer_gossip_max_count: cfg.peer_gossip_max_count,
                max_peer_set_size: cfg.max_peer_set_size,
                dial_fail_limit: cfg.dial_fail_limit,
            },
        );
        let (router, router_mailbox, messenger) = router::Actor::new(
            context.with_label("router"),
            router::Config {
                mailbox_size: cfg.mailbox_size,
            },
        );
        let channels = Channels::new(messenger, cfg.max_message_size);

        (
            Self {
                context,
                cfg,

                channels,
                tracker,
                tracker_mailbox,
                router,
                router_mailbox,
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
    pub fn register(
        &mut self,
        channel: Channel,
        rate: Quota,
        backlog: usize,
    ) -> (
        channels::Sender<C::PublicKey>,
        channels::Receiver<C::PublicKey>,
    ) {
        self.channels.register(channel, rate, backlog)
    }

    /// Starts the network.
    ///
    /// After the network is started, it is not possible to add more channels.
    pub fn start(mut self) -> Handle<()> {
        self.context.spawn_ref()(self.run())
    }

    async fn run(self) {
        // Start tracker
        let mut tracker_task = self
            .context
            .with_label("tracker")
            .spawn_child(|_| self.tracker.run());

        // Start router
        let mut router_task = self
            .context
            .with_label("router")
            .spawn_child(|_| self.router.run(self.channels));

        // Start spawner
        let (spawner, spawner_mailbox) = spawner::Actor::new(
            self.context.with_label("spawner"),
            spawner::Config {
                mailbox_size: self.cfg.mailbox_size,
                gossip_bit_vec_frequency: self.cfg.gossip_bit_vec_frequency,
                allowed_bit_vec_rate: self.cfg.allowed_bit_vec_rate,
                max_peer_set_size: self.cfg.max_peer_set_size,
                allowed_peers_rate: self.cfg.allowed_peers_rate,
                peer_gossip_max_count: self.cfg.peer_gossip_max_count,
            },
        );
        let tracker = self.tracker_mailbox.clone();
        let mut spawner_task = self
            .context
            .with_label("spawner")
            .spawn_child(move |_| spawner.run(tracker, self.router_mailbox.clone()));

        // Start listener
        let stream_cfg = public_key::Config {
            crypto: self.cfg.crypto,
            namespace: union(&self.cfg.namespace, STREAM_SUFFIX),
            max_message_size: self.cfg.max_message_size + types::MAX_PAYLOAD_DATA_OVERHEAD,
            synchrony_bound: self.cfg.synchrony_bound,
            max_handshake_age: self.cfg.max_handshake_age,
            handshake_timeout: self.cfg.handshake_timeout,
        };
        let listener = listener::Actor::new(
            self.context.with_label("listener"),
            listener::Config {
                address: self.cfg.listen,
                stream_cfg: stream_cfg.clone(),
                allowed_incoming_connection_rate: self.cfg.allowed_incoming_connection_rate,
            },
        );
        let tracker = self.tracker_mailbox.clone();
        let spawner = spawner_mailbox.clone();
        let mut listener_task = self
            .context
            .with_label("listener")
            .spawn_child(move |_| listener.run(tracker, spawner));

        // Start dialer
        let dialer = dialer::Actor::new(
            self.context.with_label("dialer"),
            dialer::Config {
                stream_cfg,
                dial_frequency: self.cfg.dial_frequency,
                query_frequency: self.cfg.query_frequency,
            },
        );
        let mut dialer_task = self
            .context
            .with_label("dialer")
            .spawn_child(move |_| dialer.run(self.tracker_mailbox, spawner_mailbox));
        info!("network started");

        // Wait for any actor to exit or the shutdown signal to be received.
        // Since each actor is spawned as a child, they will be aborted automatically.
        let mut shutdown = self.context.stopped();
        match select! {
            tracker = &mut tracker_task => {
                debug!("tracker exited");
                tracker
            },
            router = &mut router_task => {
                debug!("router exited");
                router
            },
            spawner = &mut spawner_task => {
                debug!("spawner exited");
                spawner
            },
            listener = &mut listener_task => {
                debug!("listener exited");
                listener
            },
            dialer = &mut dialer_task => {
                debug!("dialer exited");
                dialer
            },
            shutdown = &mut shutdown => {
                shutdown.map(|_| ())
            },
        } {
            Ok(()) => {
                debug!("shutdown signal received");
            }
            Err(err) => {
                warn!(error=?err, "actor exited abnormally");
            }
        }
    }
}
