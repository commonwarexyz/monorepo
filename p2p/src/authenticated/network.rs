//! Implementation of an `authenticated` network.

use std::marker::PhantomData;

use super::{
    actors::{dialer, listener, router, spawner, tracker},
    channels::{self, Channels},
    config::Config,
    connection,
};
use commonware_cryptography::Scheme;
use commonware_runtime::{select, Clock, Listener, Network as RNetwork, Sink, Spawner, Stream};
use rand::{CryptoRng, Rng};
use tracing::info;

/// Implementation of an `authenticated` network.
pub struct Network<
    Si: Sink,
    St: Stream,
    L: Listener<Si, St>,
    E: Spawner + Clock + Rng + CryptoRng + RNetwork<L, Si, St>,
    C: Scheme,
> {
    context: E,
    cfg: Config<C>,

    channels: Channels,
    tracker: tracker::Actor<E, C>,
    tracker_mailbox: tracker::Mailbox<E>,
    router: router::Actor,
    router_mailbox: router::Mailbox,

    _phantom_si: PhantomData<Si>,
    _phantom_st: PhantomData<St>,
    _phantom_l: PhantomData<L>,
}

impl<
        Si: Sink,
        St: Stream,
        L: Listener<Si, St>,
        E: Spawner + Clock + Rng + CryptoRng + RNetwork<L, Si, St>,
        C: Scheme,
    > Network<Si, St, L, E, C>
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
    pub fn new(context: E, cfg: Config<C>) -> (Self, tracker::Oracle<E>) {
        let (tracker, tracker_mailbox, oracle) = tracker::Actor::new(
            context.clone(),
            tracker::Config {
                crypto: cfg.crypto.clone(),
                registry: cfg.registry.clone(),
                address: cfg.dialable,
                bootstrappers: cfg.bootstrappers.clone(),
                allow_private_ips: cfg.allow_private_ips,
                mailbox_size: cfg.mailbox_size,
                synchrony_bound: cfg.synchrony_bound,
                tracked_peer_sets: cfg.tracked_peer_sets,
                allowed_connection_rate_per_peer: cfg.allowed_connection_rate_per_peer,
                peer_gossip_max_count: cfg.peer_gossip_max_count,
            },
        );
        let (router, router_mailbox, messenger) = router::Actor::new(router::Config {
            registry: cfg.registry.clone(),
            mailbox_size: cfg.mailbox_size,
        });

        (
            Self {
                context,
                cfg,

                channels: Channels::new(messenger),
                tracker,
                tracker_mailbox,
                router,
                router_mailbox,

                _phantom_si: PhantomData,
                _phantom_st: PhantomData,
                _phantom_l: PhantomData,
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
    /// * `max_size` - Maximum size of a message that can be sent/received over the channel.
    /// * `backlog` - Maximum number of messages that can be queued on the channel before blocking.
    /// * `compression` - Optional compression level (using `zstd`) to use for messages on the channel.
    ///
    /// # Returns
    ///
    /// * A tuple containing the sender and receiver for the channel (how to communicate
    ///   with external peers on the network).
    pub fn register(
        &mut self,
        channel: u32,
        rate: governor::Quota,
        max_size: usize,
        backlog: usize,
        compression: Option<u8>,
    ) -> (channels::Sender, channels::Receiver) {
        self.channels
            .register(channel, rate, max_size, backlog, compression)
    }

    /// Starts the network.
    ///
    /// After the network is started, it is not possible to add more channels.
    pub async fn run(self) {
        // Start tracker
        let mut tracker_task = self.context.spawn(self.tracker.run());

        // Start router
        let mut router_task = self.context.spawn(self.router.run(self.channels));

        // Start spawner
        let (spawner, spawner_mailbox) = spawner::Actor::new(
            self.context.clone(),
            spawner::Config {
                registry: self.cfg.registry.clone(),
                mailbox_size: self.cfg.mailbox_size,
                gossip_bit_vec_frequency: self.cfg.gossip_bit_vec_frequency,
                allowed_bit_vec_rate: self.cfg.allowed_bit_vec_rate,
                allowed_peers_rate: self.cfg.allowed_peers_rate,
            },
        );
        let mut spawner_task = self
            .context
            .spawn(spawner.run(self.tracker_mailbox.clone(), self.router_mailbox));

        // Start listener
        let connection = connection::Config {
            crypto: self.cfg.crypto,
            max_frame_length: self.cfg.max_frame_length,
            synchrony_bound: self.cfg.synchrony_bound,
            max_handshake_age: self.cfg.max_handshake_age,
        };
        let listener = listener::Actor::new(
            self.context.clone(),
            listener::Config {
                address: self.cfg.listen,
                connection: connection.clone(),
                allowed_incoming_connectioned_rate: self.cfg.allowed_incoming_connection_rate,
            },
        );
        let mut listener_task = self
            .context
            .spawn(listener.run(self.tracker_mailbox.clone(), spawner_mailbox.clone()));

        // Start dialer
        let dialer = dialer::Actor::new(
            self.context.clone(),
            dialer::Config {
                registry: self.cfg.registry,
                connection,
                dial_frequency: self.cfg.dial_frequency,
                dial_rate: self.cfg.dial_rate,
            },
        );
        let mut dialer_task = self
            .context
            .spawn(dialer.run(self.tracker_mailbox, spawner_mailbox));

        // Wait for actors
        info!("network started");
        // TODO: use select with errors?
        let err = futures::try_join!(
            &mut tracker_task,
            &mut router_task,
            &mut spawner_task,
            &mut listener_task,
            &mut dialer_task,
        )
        .unwrap_err();

        // Ensure all tasks close
        tracker_task.abort();
        router_task.abort();
        spawner_task.abort();
        listener_task.abort();
        dialer_task.abort();

        // Log error
        info!(error=?err, "network shutdown")
    }
}
