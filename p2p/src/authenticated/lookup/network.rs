//! Implementation of an `authenticated` network.

use super::{
    actors::{dialer, listener, router, spawner, tracker},
    channels::{self, Channels},
    config::Config,
    types,
};
use crate::{
    authenticated::{mailbox::UnboundedMailbox, Mailbox},
    Channel,
};
use commonware_cryptography::Signer;
use commonware_macros::select;
use commonware_runtime::{
    spawn_cell, Clock, ContextCell, Handle, Metrics, Network as RNetwork, Quota, Resolver, Spawner,
};
use commonware_stream::Config as StreamConfig;
use commonware_utils::union;
use futures::channel::mpsc;
use rand::{CryptoRng, Rng};
use std::{collections::HashSet, net::IpAddr};
use tracing::{debug, info};

/// Unique suffix for all messages signed in a stream.
const STREAM_SUFFIX: &[u8] = b"_STREAM";

/// Implementation of an `authenticated` network.
pub struct Network<E: Spawner + Clock + Rng + CryptoRng + RNetwork + Metrics, C: Signer> {
    context: ContextCell<E>,
    cfg: Config<C>,

    channels: Channels<C::PublicKey>,
    tracker: tracker::Actor<E, C>,
    tracker_mailbox: UnboundedMailbox<tracker::Message<C::PublicKey>>,
    router: router::Actor<E, C::PublicKey>,
    router_mailbox: Mailbox<router::Message<C::PublicKey>>,
    listener: mpsc::Receiver<HashSet<IpAddr>>,
}

impl<E: Spawner + Clock + Rng + CryptoRng + RNetwork + Resolver + Metrics, C: Signer>
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
    pub fn new(context: E, cfg: Config<C>) -> (Self, tracker::Oracle<C::PublicKey>) {
        let (listener_mailbox, listener) = Mailbox::<HashSet<IpAddr>>::new(cfg.mailbox_size);
        let (tracker, tracker_mailbox, oracle) = tracker::Actor::new(
            context.with_label("tracker"),
            tracker::Config {
                crypto: cfg.crypto.clone(),
                tracked_peer_sets: cfg.tracked_peer_sets,
                allowed_connection_rate_per_peer: cfg.allowed_connection_rate_per_peer,
                allow_private_ips: cfg.allow_private_ips,
                allow_dns: cfg.allow_dns,
                listener: listener_mailbox,
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
        let clock = self
            .context
            .with_label(&format!("channel_{channel}"))
            .take();
        self.channels.register(channel, rate, backlog, clock)
    }

    /// Starts the network.
    ///
    /// After the network is started, it is not possible to add more channels.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(self) {
        // Start tracker
        let mut tracker_task = self.tracker.start();

        // Start router
        let mut router_task = self.router.start(self.channels);

        // Start spawner
        let (spawner, spawner_mailbox) = spawner::Actor::new(
            self.context.with_label("spawner"),
            spawner::Config {
                mailbox_size: self.cfg.mailbox_size,
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
                .saturating_add(types::MAX_PAYLOAD_DATA_OVERHEAD),
            synchrony_bound: self.cfg.synchrony_bound,
            max_handshake_age: self.cfg.max_handshake_age,
            handshake_timeout: self.cfg.handshake_timeout,
        };
        let listener = listener::Actor::new(
            self.context.with_label("listener"),
            listener::Config {
                address: self.cfg.listen,
                stream_cfg: stream_cfg.clone(),
                allow_private_ips: self.cfg.allow_private_ips,
                attempt_unregistered_handshakes: self.cfg.attempt_unregistered_handshakes,
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
            self.context.with_label("dialer"),
            dialer::Config {
                stream_cfg,
                dial_frequency: self.cfg.dial_frequency,
                query_frequency: self.cfg.query_frequency,
                allow_private_ips: self.cfg.allow_private_ips,
            },
        );
        let mut dialer_task = dialer.start(self.tracker_mailbox, spawner_mailbox);

        let mut shutdown = self.context.stopped();

        // Wait for first actor to exit
        info!("network started");
        select! {
            _ = &mut shutdown => {
                debug!("context shutdown, stopping network");
            },
            tracker = &mut tracker_task => {
                panic!("tracker exited unexpectedly: {tracker:?}");
            },
            router = &mut router_task => {
                panic!("router exited unexpectedly: {router:?}");
            },
            spawner = &mut spawner_task => {
                panic!("spawner exited unexpectedly: {spawner:?}");
            },
            listener = &mut listener_task => {
                panic!("listener exited unexpectedly: {listener:?}");
            },
            dialer = &mut dialer_task => {
                panic!("dialer exited unexpectedly: {dialer:?}");
            },
        }
    }
}
