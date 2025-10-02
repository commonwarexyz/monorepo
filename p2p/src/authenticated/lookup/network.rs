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
use commonware_stream::Config as StreamConfig;
use commonware_utils::union;
use futures::channel::mpsc;
use governor::{clock::ReasonablyRealtime, Quota};
use rand::{CryptoRng, Rng};
use tracing::{debug, info, warn};

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
    router: router::Actor<E, C::PublicKey>,
    router_mailbox: Mailbox<router::Message<C::PublicKey>>,
    registered_ip_updates: mpsc::Receiver<listener::Message>,
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
        let (registered_ip_sender, registered_ip_updates) =
            mpsc::channel::<listener::Message>(cfg.mailbox_size);
        let (tracker, tracker_mailbox, oracle) = tracker::Actor::new(
            context.with_label("tracker"),
            tracker::Config {
                crypto: cfg.crypto.clone(),
                address: cfg.dialable,
                mailbox_size: cfg.mailbox_size,
                tracked_peer_sets: cfg.tracked_peer_sets,
                allowed_connection_rate_per_peer: cfg.allowed_connection_rate_per_peer,
                allow_private_ips: cfg.allow_private_ips,
                registered_ips: Mailbox::new(registered_ip_sender),
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
                registered_ip_updates,
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
        let Self {
            context,
            cfg,
            channels,
            tracker,
            tracker_mailbox,
            router,
            router_mailbox,
            registered_ip_updates,
        } = self;

        // Start tracker
        let mut tracker_task = tracker.start();

        // Start router
        let mut router_task = router.start(channels);

        let Config {
            crypto,
            namespace,
            listen,
            dialable: _,
            allow_private_ips: _,
            max_message_size,
            mailbox_size,
            synchrony_bound,
            max_handshake_age,
            handshake_timeout,
            allowed_connection_rate_per_peer: _,
            max_concurrent_handshakes,
            allowed_handshake_rate_per_ip,
            allowed_handshake_rate_per_subnet,
            ping_frequency,
            allowed_ping_rate,
            dial_frequency,
            query_frequency,
            tracked_peer_sets: _,
        } = cfg;

        // Start spawner
        let (spawner, spawner_mailbox) = spawner::Actor::new(
            context.with_label("spawner"),
            spawner::Config {
                mailbox_size,
                ping_frequency,
                allowed_ping_rate,
            },
        );
        let mut spawner_task = spawner.start(tracker_mailbox.clone(), router_mailbox.clone());

        // Start listener
        let stream_cfg = StreamConfig {
            signing_key: crypto,
            namespace: union(&namespace, STREAM_SUFFIX),
            max_message_size: max_message_size + types::MAX_PAYLOAD_DATA_OVERHEAD,
            synchrony_bound,
            max_handshake_age,
            handshake_timeout,
        };
        let listener = listener::Actor::new(
            context.with_label("listener"),
            listener::Config {
                address: listen,
                stream_cfg: stream_cfg.clone(),
                max_concurrent_handshakes,
                allowed_handshake_rate_per_ip,
                allowed_handshake_rate_per_subnet,
            },
            registered_ip_updates,
        );
        let mut listener_task = listener.start(tracker_mailbox.clone(), spawner_mailbox.clone());

        // Start dialer
        let dialer = dialer::Actor::new(
            context.with_label("dialer"),
            dialer::Config {
                stream_cfg,
                dial_frequency,
                query_frequency,
            },
        );
        let mut dialer_task = dialer.start(tracker_mailbox, spawner_mailbox);

        // Wait for first actor to exit
        info!("network started");
        let err = select! {
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
        }
        .unwrap_err();

        // Log error
        warn!(error=?err, "network shutdown");
    }
}
