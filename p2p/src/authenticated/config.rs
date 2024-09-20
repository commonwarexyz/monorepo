use commonware_cryptography::{PublicKey, Scheme};
use governor::Quota;
use prometheus_client::registry::Registry;
use std::{
    net::SocketAddr,
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Known peer and its accompanying address that will be dialed on startup.
pub type Bootstrapper = (PublicKey, SocketAddr);

/// Configuration for the peer-to-peer instance.
///
/// # Warning
/// It is recommended to synchronize this configuration across peers in the network (with the
/// exection of `crypto`, `registry`, `address`, `bootstrappers`, `allow_private_ips`, and `mailbox_size`).
/// If this is not sycnhronized, connections could be unnecessarily dropped, messages could be parsed incorrectly,
/// and/or peers will rate limit each other during normal operation.
#[derive(Clone)]
pub struct Config<C: Scheme> {
    /// Cryptographic primitives.
    pub crypto: C,

    /// Registry for prometheus metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// Address to listen on.
    pub listen: SocketAddr,

    /// Dialable address of the peer.
    pub dialable: SocketAddr,

    /// Peers dialed on startup.
    pub bootstrappers: Vec<Bootstrapper>,

    /// Whether or not to allow connections with private IP addresses.
    pub allow_private_ips: bool,

    /// Message backlog allowed for internal actors.
    ///
    /// When there are more messages in the mailbox than this value, any actor
    /// sending a message will be blocked until the mailbox is processed.
    pub mailbox_size: usize,

    /// Time into the future that a timestamp can be and still be considered valid.
    pub synchrony_bound: Duration,

    /// Duration after which a handshake message is considered stale.
    pub max_handshake_age: Duration,

    /// Quota for connection attempts per peer (incoming or outgoing).
    pub allowed_connection_rate_per_peer: Quota,

    /// Quota for incoming connections across all peers.
    pub allowed_incoming_connection_rate: Quota,

    /// Frequency to attempt to dial known addresses.
    pub dial_frequency: Duration,

    /// Quota for peers to dial.
    pub dial_rate: Quota,

    /// Number of peer sets to track.
    ///
    /// We will attempt to maintain connections to peers stored
    /// across all peer sets, not just the most recent. This allows
    /// us to continue serving requests to peers that have recently
    /// been evicted and/or to communicate with peers in a future
    /// set (if we, for example, are trying to do a reshare of a threshold
    /// key).
    pub tracked_peer_sets: usize,

    /// Frequency we gossip about known peers.
    ///
    /// If there is no other network activity, this message is used as a ping
    /// and should be sent more often than the read_timeout.
    pub gossip_bit_vec_frequency: Duration,

    /// Quota for bit vector messages a peer can send us.
    pub allowed_bit_vec_rate: Quota,

    /// Maximum number of peers we will send or consider valid when receiving in a single messsage.
    ///
    /// This is used to prevent malicious peers from sending us a large number of peers at one time (each
    /// of which requires a signature verification).
    pub peer_gossip_max_count: usize,

    /// Quota for peers messages a peer can send us.
    pub allowed_peers_rate: Quota,
}

impl<C: Scheme> Config<C> {
    /// Generates a configuration with reasonable defaults for usage in production.
    pub fn recommended(
        crypto: C,
        registry: Arc<Mutex<Registry>>,
        listen: SocketAddr,
        dialable: SocketAddr,
        bootstrappers: Vec<Bootstrapper>,
    ) -> Self {
        Self {
            crypto,
            registry,
            listen,
            dialable,
            bootstrappers,

            allow_private_ips: false,
            mailbox_size: 1_000,
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            allowed_connection_rate_per_peer: Quota::per_minute(NonZeroU32::new(1).unwrap()),
            allowed_incoming_connection_rate: Quota::per_second(NonZeroU32::new(256).unwrap()),
            dial_frequency: Duration::from_secs(60),
            dial_rate: Quota::per_minute(NonZeroU32::new(30).unwrap()),
            tracked_peer_sets: 4,
            gossip_bit_vec_frequency: Duration::from_secs(50),
            allowed_bit_vec_rate: Quota::per_second(NonZeroU32::new(2).unwrap()),
            peer_gossip_max_count: 32,
            allowed_peers_rate: Quota::per_second(NonZeroU32::new(2).unwrap()),
        }
    }

    /// Generates a configuration that minimizes peer discovery latency. This
    /// can be useful when running local demos.
    ///
    /// # Warning
    /// It is not recommended to use this configuration in production.
    pub fn aggressive(
        crypto: C,
        registry: Arc<Mutex<Registry>>,
        listen: SocketAddr,
        dialable: SocketAddr,
        bootstrappers: Vec<Bootstrapper>,
    ) -> Self {
        Self {
            crypto,
            registry,
            listen,
            dialable,
            bootstrappers,

            allow_private_ips: true,
            mailbox_size: 1_000,
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            allowed_connection_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
            allowed_incoming_connection_rate: Quota::per_second(NonZeroU32::new(256).unwrap()),
            dial_frequency: Duration::from_secs(5),
            dial_rate: Quota::per_second(NonZeroU32::new(30).unwrap()),
            tracked_peer_sets: 4,
            gossip_bit_vec_frequency: Duration::from_secs(5),
            allowed_bit_vec_rate: Quota::per_second(NonZeroU32::new(5).unwrap()),
            peer_gossip_max_count: 32,
            allowed_peers_rate: Quota::per_second(NonZeroU32::new(5).unwrap()),
        }
    }

    #[cfg(test)]
    pub fn test(
        crypto: C,
        registry: Arc<Mutex<Registry>>,
        listen: SocketAddr,
        dialable: SocketAddr,
        bootstrappers: Vec<Bootstrapper>,
    ) -> Self {
        Self {
            crypto,
            registry,
            listen,
            dialable,
            bootstrappers,

            allow_private_ips: true,
            mailbox_size: 1_000,
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            allowed_connection_rate_per_peer: Quota::per_second(NonZeroU32::new(1_024).unwrap()),
            allowed_incoming_connection_rate: Quota::per_second(NonZeroU32::new(1_024).unwrap()),
            dial_frequency: Duration::from_secs(1),
            dial_rate: Quota::per_second(NonZeroU32::new(1_024).unwrap()),
            tracked_peer_sets: 4,
            gossip_bit_vec_frequency: Duration::from_secs(1),
            allowed_bit_vec_rate: Quota::per_second(NonZeroU32::new(5).unwrap()),
            peer_gossip_max_count: 32,
            allowed_peers_rate: Quota::per_second(NonZeroU32::new(5).unwrap()),
        }
    }
}
