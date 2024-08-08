use crate::crypto::{Crypto, PublicKey};
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
pub struct Config<C: Crypto> {
    /// Cryptographic primitives.
    pub crypto: C,

    /// Registry for prometheus metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// Dialable address of the peer.
    pub address: SocketAddr,

    /// Peers dialed on startup.
    pub bootstrappers: Vec<Bootstrapper>,

    /// Whether or not to allow connections with private IP addresses.
    pub allow_private_ips: bool,

    /// Message backlog allowed for internal actors.
    ///
    /// When there are more messages in the mailbox than this value, any actor
    /// sending a message will be blocked until the mailbox is processed.
    pub mailbox_size: usize,

    /// Maximum size used for all messages sent over the wire.
    ///
    /// We use this to prevent malicious peers from sending us large messages
    /// that would consume all of our memory.
    ///
    /// If a message is larger than this size, it will be chunked into parts
    /// of this size or smaller.
    ///
    /// If this value is not synchronized across all connected peers,
    /// chunks will be parsed incorrectly (any non-terminal chunk must be of ~this
    /// size).
    pub max_frame_length: usize,

    /// Duration after which to close the connection if the handshake is not completed.
    pub handshake_timeout: Duration,

    /// Duration after which to close the connection if no message is read.
    pub read_timeout: Duration,

    /// Duration after which to close the connection if a message cannot be written.
    pub write_timeout: Duration,

    /// Quota for connection attempts per peer (incoming or outgoing).
    pub allowed_connection_rate_per_peer: Quota,

    /// Quota for incoming connections across all peers.
    pub allowed_incoming_connection_rate: Quota,

    /// Frequency to attempt to dial known addresses.
    pub dial_frequency: Duration,

    /// Quota for peers to dial.
    pub dial_rate: Quota,

    /// Number of peer sets to keep in memory for handling peer requests.
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

    ///  Quota for peers messages a peer can send us.
    pub allowed_peers_rate: Quota,
}

impl<C: Crypto> Config<C> {
    /// Default produces a new configuration with reasonable defaults.
    pub fn default(
        crypto: C,
        registry: Arc<Mutex<Registry>>,
        address: SocketAddr,
        bootstrappers: Vec<Bootstrapper>,
        allow_private_ips: bool,
    ) -> Self {
        Self {
            crypto,
            registry,
            address,
            bootstrappers,
            allow_private_ips,

            mailbox_size: 1_000,
            max_frame_length: 1024 * 1024, // 1 MB
            handshake_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(30),
            allowed_connection_rate_per_peer: Quota::per_minute(NonZeroU32::new(1).unwrap()),
            allowed_incoming_connection_rate: Quota::per_second(NonZeroU32::new(256).unwrap()),
            dial_frequency: Duration::from_secs(60),
            dial_rate: Quota::per_second(NonZeroU32::new(30).unwrap()),
            tracked_peer_sets: 32,
            gossip_bit_vec_frequency: Duration::from_secs(50),
            allowed_bit_vec_rate: Quota::per_second(NonZeroU32::new(2).unwrap()),
            peer_gossip_max_count: 32,
            allowed_peers_rate: Quota::per_second(NonZeroU32::new(2).unwrap()),
        }
    }
}
