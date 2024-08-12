//! Instance of a commonware-p2p network.

use crate::{
    actors::{dialer, listener, router, spawner, tracker},
    channels::{self, Channels},
    config::Config,
    connection,
    crypto::Crypto,
};
use tracing::info;

/// Instance of a commonware-p2p network.
pub struct Network<C: Crypto> {
    cfg: Config<C>,

    channels: Channels,
    tracker: tracker::Actor<C>,
    tracker_mailbox: tracker::Mailbox,
    router: router::Actor,
    router_mailbox: router::Mailbox,
}

impl<C: Crypto> Network<C> {
    /// Create a new instance of a commonware-p2p network.
    ///
    /// # Parameters
    ///
    /// * `cfg` - Configuration for the network.
    ///
    /// # Returns
    ///
    /// * A tuple containing the network instance and the oracle that
    ///   can be used by a developer to configure which peers are authorized.
    pub fn new(cfg: Config<C>) -> (Self, tracker::Oracle) {
        let (tracker, tracker_mailbox, oracle) = tracker::Actor::new(tracker::Config {
            crypto: cfg.crypto.clone(),
            registry: cfg.registry.clone(),
            address: cfg.address,
            bootstrappers: cfg.bootstrappers.clone(),
            allow_private_ips: cfg.allow_private_ips,
            mailbox_size: cfg.mailbox_size,
            tracked_peer_sets: cfg.tracked_peer_sets,
            allowed_connection_rate_per_peer: cfg.allowed_connection_rate_per_peer,
            peer_gossip_max_count: cfg.peer_gossip_max_count,
        });
        let (router, router_mailbox, messenger) = router::Actor::new(router::Config {
            registry: cfg.registry.clone(),
            mailbox_size: cfg.mailbox_size,
        });

        (
            Self {
                cfg,

                channels: Channels::new(messenger),
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
    /// * `max_size` - Maximum size of a message that can be sent/received over the channel.
    /// * `backlog` - Maximum number of messages that can be queued on the channel before blocking.
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
    ) -> (channels::Sender, channels::Receiver) {
        self.channels.register(channel, rate, max_size, backlog)
    }

    /// Starts the network.
    ///
    /// After the network is started, it is not possible to add more channels.
    pub async fn run(self) {
        // Start tracker
        let mut tracker_task = tokio::spawn(self.tracker.run());

        // Start router
        let mut router_task = tokio::spawn(self.router.run(self.channels));

        // Start spawner
        let (spawner, spawner_mailbox) = spawner::Actor::new(spawner::Config {
            registry: self.cfg.registry.clone(),
            mailbox_size: self.cfg.mailbox_size,
            gossip_bit_vec_frequency: self.cfg.gossip_bit_vec_frequency,
            allowed_bit_vec_rate: self.cfg.allowed_bit_vec_rate,
            allowed_peers_rate: self.cfg.allowed_peers_rate,
        });
        let mut spawner_task =
            tokio::spawn(spawner.run(self.tracker_mailbox.clone(), self.router_mailbox));

        // Start listener
        let connection = connection::Config {
            crypto: self.cfg.crypto,
            max_frame_length: self.cfg.max_frame_length,
            handshake_timeout: self.cfg.handshake_timeout,
            read_timeout: self.cfg.read_timeout,
            write_timeout: self.cfg.write_timeout,
            tcp_nodelay: self.cfg.tcp_nodelay,
        };
        let listener = listener::Actor::new(listener::Config {
            port: self.cfg.address.port(),
            connection: connection.clone(),
            allowed_incoming_connectioned_rate: self.cfg.allowed_incoming_connection_rate,
        });
        let mut listener_task =
            tokio::spawn(listener.run(self.tracker_mailbox.clone(), spawner_mailbox.clone()));

        // Start dialer
        let dialer = dialer::Actor::new(dialer::Config {
            registry: self.cfg.registry,
            connection,
            dial_frequency: self.cfg.dial_frequency,
            dial_rate: self.cfg.dial_rate,
        });
        let mut dialer_task = tokio::spawn(dialer.run(self.tracker_mailbox, spawner_mailbox));

        // Wait for actors
        info!("network started");
        let err = tokio::try_join!(
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
