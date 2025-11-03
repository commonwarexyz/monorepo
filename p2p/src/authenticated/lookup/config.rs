use commonware_cryptography::Signer;
use commonware_utils::NZU32;
use governor::Quota;
use std::{net::SocketAddr, num::NonZeroU32, time::Duration};

/// Configuration for the peer-to-peer instance.
///
/// # Warning
/// It is recommended to synchronize this configuration across peers in the network (with the
/// exception of `crypto`, `listen`, `allow_private_ips`, and `mailbox_size`).
/// If this is not synchronized, connections could be unnecessarily dropped, messages could be parsed incorrectly,
/// and/or peers will rate limit each other during normal operation.
#[derive(Clone)]
pub struct Config<C: Signer> {
    /// Cryptographic primitives.
    pub crypto: C,

    /// Prefix for all signed messages to avoid replay attacks.
    pub namespace: Vec<u8>,

    /// Address to listen on.
    pub listen: SocketAddr,

    /// Whether or not to allow connections with private IP addresses.
    pub allow_private_ips: bool,

    /// Whether or not to attempt handshakes on incoming connections
    /// from unregistered IP addresses.
    pub attempt_unregistered_handshakes: bool,

    /// Maximum size allowed for messages over any connection.
    ///
    /// The actual size of the network message will be higher due to overhead from the protocol;
    /// this may include additional metadata, data from the codec, and/or cryptographic signatures.
    pub max_message_size: usize,

    /// Message backlog allowed for internal actors.
    ///
    /// When there are more messages in the mailbox than this value, any actor
    /// sending a message will be blocked until the mailbox is processed.
    pub mailbox_size: usize,

    /// Time into the future that a timestamp can be and still be considered valid.
    pub synchrony_bound: Duration,

    /// Duration after which a handshake message is considered stale.
    pub max_handshake_age: Duration,

    /// Timeout for the handshake process.
    ///
    /// This is often set to some value less than the connection read timeout to prevent
    /// unauthenticated peers from holding open connection.
    pub handshake_timeout: Duration,

    /// Quota for connection attempts per peer (incoming or outgoing).
    pub allowed_connection_rate_per_peer: Quota,

    /// Maximum number of concurrent handshake attempts allowed.
    pub max_concurrent_handshakes: NonZeroU32,

    /// Quota for handshake attempts originating from a single IP address.
    ///
    /// To cap the number of handshakes concurrently attempted for a single
    /// IP, set this to [Config::handshake_timeout].
    pub allowed_handshake_rate_per_ip: Quota,

    /// Quota for handshake attempts originating from a single IP subnet.
    pub allowed_handshake_rate_per_subnet: Quota,

    /// Frequency at which we send ping messages to peers.
    pub ping_frequency: Duration,

    /// Quota for ping messages received from a peer.
    pub allowed_ping_rate: Quota,

    /// Average frequency at which we make a single dial attempt across all peers.
    pub dial_frequency: Duration,

    /// Average frequency at which we will fetch a new list of dialable peers.
    ///
    /// This value also limits the rate at which we attempt to re-dial any single peer.
    pub query_frequency: Duration,

    /// Number of peer sets to track.
    ///
    /// We will attempt to maintain connections to peers stored
    /// across all peer sets, not just the most recent. This allows
    /// us to continue serving requests to peers that have recently
    /// been evicted and/or to communicate with peers in a future
    /// set (if we, for example, are trying to do a reshare of a threshold
    /// key).
    pub tracked_peer_sets: usize,
}

impl<C: Signer> Config<C> {
    /// Generates a configuration with reasonable defaults for usage in production.
    pub fn recommended(
        crypto: C,
        namespace: &[u8],
        listen: SocketAddr,
        max_message_size: usize,
    ) -> Self {
        Self {
            crypto,
            namespace: namespace.to_vec(),
            listen,

            allow_private_ips: false,
            attempt_unregistered_handshakes: false,
            max_message_size,
            mailbox_size: 1_000,
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(5),
            allowed_connection_rate_per_peer: Quota::per_minute(NZU32!(1)),
            max_concurrent_handshakes: NZU32!(512),
            allowed_handshake_rate_per_ip: Quota::with_period(Duration::from_secs(5)).unwrap(), // 1 concurrent handshake per IP
            allowed_handshake_rate_per_subnet: Quota::per_second(NZU32!(64)),
            ping_frequency: Duration::from_secs(50),
            allowed_ping_rate: Quota::per_minute(NZU32!(2)),
            dial_frequency: Duration::from_secs(1),
            query_frequency: Duration::from_secs(60),
            tracked_peer_sets: 4,
        }
    }

    /// Generates a configuration that minimizes peer discovery latency. This
    /// can be useful when running local demos.
    ///
    /// # Warning
    ///
    /// It is not recommended to use this configuration in production.
    pub fn local(crypto: C, namespace: &[u8], listen: SocketAddr, max_message_size: usize) -> Self {
        Self {
            crypto,
            namespace: namespace.to_vec(),
            listen,

            allow_private_ips: true,
            attempt_unregistered_handshakes: false,
            max_message_size,
            mailbox_size: 1_000,
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(5),
            allowed_connection_rate_per_peer: Quota::per_second(NZU32!(1)),
            max_concurrent_handshakes: NZU32!(1_024),
            allowed_handshake_rate_per_ip: Quota::per_second(NZU32!(16)), // 80 concurrent handshakes per IP
            allowed_handshake_rate_per_subnet: Quota::per_second(NZU32!(128)),
            ping_frequency: Duration::from_secs(5),
            allowed_ping_rate: Quota::per_second(NZU32!(2)),
            dial_frequency: Duration::from_millis(500),
            query_frequency: Duration::from_secs(30),
            tracked_peer_sets: 4,
        }
    }

    #[cfg(test)]
    pub fn test(crypto: C, listen: SocketAddr, max_message_size: usize) -> Self {
        Self {
            crypto,
            namespace: b"test_namespace".to_vec(),
            listen,

            allow_private_ips: true,
            attempt_unregistered_handshakes: false,
            max_message_size,
            mailbox_size: 1_000,
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(5),
            allowed_connection_rate_per_peer: Quota::per_second(NZU32!(4)),
            max_concurrent_handshakes: NZU32!(1_024),
            allowed_handshake_rate_per_ip: Quota::per_second(NZU32!(128)), // 640 concurrent handshakes per IP
            allowed_handshake_rate_per_subnet: Quota::per_second(NZU32!(256)),
            ping_frequency: Duration::from_secs(1),
            allowed_ping_rate: Quota::per_second(NZU32!(5)),
            dial_frequency: Duration::from_millis(200),
            query_frequency: Duration::from_secs(5),
            tracked_peer_sets: 4,
        }
    }
}
