use crate::{
    Ingress,
    authenticated::{MAX_PAYLOAD_OVERHEAD, MAX_SIZE},
};
use commonware_cryptography::Signer;
use commonware_runtime::Quota;
use commonware_stream::encrypted::MAX_SIZE as STREAM_MAX_SIZE;
use commonware_utils::{AtMost, NZU32, NZUsize};
use std::{
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};

/// Known peer and its accompanying ingress address that will be dialed on startup.
pub type Bootstrapper<P> = (P, Ingress);

/// Configuration for the peer-to-peer instance.
///
/// # Warning
/// It is recommended to synchronize this configuration across peers in the network (with
/// the exception of `crypto`, `listen`, `bootstrappers`, `allow_private_ips`,
/// `max_peers_per_set`, `mailbox_size`, `send_batch_size`, and `dial_timeout`). If this is not
/// synchronized, connections could be unnecessarily dropped, messages could be parsed
/// incorrectly, and/or peers will rate limit each other during normal operation.
#[derive(Clone)]
pub struct Config<C: Signer> {
    /// Cryptographic primitives.
    pub crypto: C,

    /// Prefix for all signed messages to avoid replay attacks.
    pub namespace: Vec<u8>,

    /// Address to listen on.
    pub listen: SocketAddr,

    /// Dialable ingress address of the peer.
    pub dialable: Ingress,

    /// Peers dialed on startup.
    pub bootstrappers: Vec<Bootstrapper<C::PublicKey>>,

    /// Whether or not to allow DNS-based ingress addresses.
    ///
    /// When dialing a DNS-based address, the hostname is resolved and a random IP
    /// is selected from the results (shuffled for each dial attempt).
    pub allow_dns: bool,

    /// Whether or not to allow connections with private IP addresses.
    pub allow_private_ips: bool,

    /// Maximum size allowed for an application payload passed to a sender.
    ///
    /// Sending a larger payload panics. Output from wrappers such as codecs and multiplexers is
    /// part of the payload and counts toward this limit.
    ///
    /// Framing and transport overhead are added after this size check and do not count toward
    /// the limit, so the resulting network message will be larger.
    pub max_message_size: AtMost<NonZeroU32, MAX_SIZE>,

    /// Maximum number of distinct identities at one peer-set index, including the local identity.
    ///
    /// This applies to the deduplicated union of a peer set's primary and secondary identities.
    /// The local identity counts even when omitted from the registered set. Configure only this
    /// per-set value; do not multiply it or add bootstrappers separately. The network derives its
    /// retained identity bound by multiplying it by [`Config::tracked_peer_sets`] and adding the
    /// distinct configured bootstrappers other than the local identity. Tracking an oversized peer
    /// set panics.
    ///
    /// The derived bound sizes every application channel's inbound mailbox and its contribution
    /// to the shared outbound router mailbox. It also limits primary peer-set bit vectors decoded
    /// from the network.
    pub max_peers_per_set: NonZeroUsize,

    /// Capacity for internal actor mailboxes.
    ///
    /// This does not affect inbound application message capacity, which is derived from channel
    /// rate limits and [`Config::max_peers_per_set`].
    pub mailbox_size: NonZeroUsize,

    /// Maximum number of already-queued outbound messages to combine into one connection write.
    ///
    /// Set this to `1` to disable batching.
    pub send_batch_size: NonZeroUsize,

    /// Time into the future that a timestamp can be and still be considered valid.
    pub synchrony_bound: Duration,

    /// Duration after which a handshake message is considered stale.
    pub max_handshake_age: Duration,

    /// Timeout for the handshake process.
    ///
    /// This is often set to some value less than the connection read timeout to prevent
    /// unauthenticated peers from holding open connection.
    pub handshake_timeout: Duration,

    /// Timeout for an outbound dial attempt.
    ///
    /// This bounds address resolution, connection establishment, and the handshake so a
    /// peer reservation cannot be held indefinitely.
    pub dial_timeout: Duration,

    /// Minimum time between connection reservations for a single peer.
    pub peer_connection_cooldown: Duration,

    /// Maximum number of concurrent handshake attempts allowed.
    pub max_concurrent_handshakes: NonZeroU32,

    /// Quota for handshake attempts originating from a single IP address.
    ///
    /// To cap the number of handshakes concurrently attempted for a single
    /// IP, set this to [Config::handshake_timeout].
    pub allowed_handshake_rate_per_ip: Quota,

    /// Quota for handshake attempts originating from a single IP subnet.
    pub allowed_handshake_rate_per_subnet: Quota,

    /// Average frequency at which we make a single dial attempt across all peers.
    pub dial_frequency: Duration,

    /// Times that dialing a given peer should fail before asking for updated peer information for
    /// that peer.
    pub dial_fail_limit: usize,

    /// Number of peer sets to track.
    ///
    /// We will attempt to maintain connections to peers stored
    /// across all peer sets, not just the most recent. This allows
    /// us to continue serving requests to peers that have recently
    /// been evicted and/or to communicate with peers in a future
    /// set (if we, for example, are trying to do a reshare of a threshold
    /// key).
    pub tracked_peer_sets: NonZeroUsize,

    /// Frequency we gossip about known peers.
    ///
    /// If there is no other network activity, this message is used as a ping
    /// and should be sent more often than the read_timeout.
    ///
    /// This also determines the rate limit for incoming BitVec and Peers messages
    /// (one per half this frequency to account for jitter).
    pub gossip_bit_vec_frequency: Duration,

    /// Maximum number of peers we will send or consider valid when receiving in a single message.
    ///
    /// This is used to prevent malicious peers from sending us a large number of peers at one time (each
    /// of which requires a signature verification).
    pub peer_gossip_max_count: usize,

    /// Duration after which a blocked peer is allowed to reconnect.
    pub block_duration: Duration,
}

impl<C: Signer> Config<C> {
    /// Returns the encrypted-stream payload limit for this configuration.
    pub(super) fn max_frame_size(&self) -> AtMost<NonZeroU32, STREAM_MAX_SIZE> {
        AtMost!(self.max_message_size.get() + MAX_PAYLOAD_OVERHEAD)
    }

    /// Generates a configuration with reasonable defaults for usage in production.
    pub fn recommended(
        crypto: C,
        namespace: &[u8],
        listen: SocketAddr,
        dialable: impl Into<Ingress>,
        bootstrappers: Vec<Bootstrapper<C::PublicKey>>,
        max_peers_per_set: NonZeroUsize,
        max_message_size: AtMost<NonZeroU32, MAX_SIZE>,
    ) -> Self {
        Self {
            crypto,
            namespace: namespace.to_vec(),
            listen,
            dialable: dialable.into(),
            bootstrappers,
            allow_dns: true,

            allow_private_ips: false,
            max_message_size,
            max_peers_per_set,
            mailbox_size: NZUsize!(1_000),
            send_batch_size: NZUsize!(8),
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(5),
            dial_timeout: Duration::from_secs(15),
            peer_connection_cooldown: Duration::from_secs(60),
            max_concurrent_handshakes: NZU32!(512),
            allowed_handshake_rate_per_ip: Quota::with_period(Duration::from_secs(5)).unwrap(), // 1 concurrent handshake per IP
            allowed_handshake_rate_per_subnet: Quota::per_second(NZU32!(64)),
            dial_frequency: Duration::from_secs(1),
            dial_fail_limit: 2,
            tracked_peer_sets: NZUsize!(4),
            gossip_bit_vec_frequency: Duration::from_secs(50),
            peer_gossip_max_count: 32,
            block_duration: Duration::from_hours(4),
        }
    }

    /// Generates a configuration that minimizes peer discovery latency. This
    /// can be useful when running local demos.
    ///
    /// # Warning
    ///
    /// It is not recommended to use this configuration in production.
    pub fn local(
        crypto: C,
        namespace: &[u8],
        listen: SocketAddr,
        dialable: impl Into<Ingress>,
        bootstrappers: Vec<Bootstrapper<C::PublicKey>>,
        max_peers_per_set: NonZeroUsize,
        max_message_size: AtMost<NonZeroU32, MAX_SIZE>,
    ) -> Self {
        Self {
            crypto,
            namespace: namespace.to_vec(),
            listen,
            dialable: dialable.into(),
            bootstrappers,
            allow_dns: true,

            allow_private_ips: true,
            max_message_size,
            max_peers_per_set,
            mailbox_size: NZUsize!(1_000),
            send_batch_size: NZUsize!(8),
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(5),
            dial_timeout: Duration::from_secs(15),
            peer_connection_cooldown: Duration::from_secs(1),
            max_concurrent_handshakes: NZU32!(1_024),
            allowed_handshake_rate_per_ip: Quota::per_second(NZU32!(16)), // 80 concurrent handshakes per IP
            allowed_handshake_rate_per_subnet: Quota::per_second(NZU32!(128)),
            dial_frequency: Duration::from_millis(500),
            dial_fail_limit: 1,
            tracked_peer_sets: NZUsize!(4),
            gossip_bit_vec_frequency: Duration::from_secs(5),
            peer_gossip_max_count: 32,
            block_duration: Duration::from_hours(1),
        }
    }

    #[cfg(test)]
    pub fn test(
        crypto: C,
        listen: SocketAddr,
        bootstrappers: Vec<Bootstrapper<C::PublicKey>>,
        max_message_size: AtMost<NonZeroU32, MAX_SIZE>,
    ) -> Self {
        Self {
            crypto,
            namespace: b"test_namespace".to_vec(),
            listen,
            dialable: listen.into(),
            bootstrappers,
            allow_dns: true,

            allow_private_ips: true,
            max_message_size,
            max_peers_per_set: NZUsize!(32),
            mailbox_size: NZUsize!(1_000),
            send_batch_size: NZUsize!(8),
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(5),
            dial_timeout: Duration::from_secs(15),
            peer_connection_cooldown: Duration::from_millis(250),
            max_concurrent_handshakes: NZU32!(1_024),
            allowed_handshake_rate_per_ip: Quota::per_second(NZU32!(128)), // 640 concurrent handshakes per IP
            allowed_handshake_rate_per_subnet: Quota::per_second(NZU32!(256)),
            dial_frequency: Duration::from_millis(200),
            dial_fail_limit: 1,
            tracked_peer_sets: NZUsize!(4),
            gossip_bit_vec_frequency: Duration::from_secs(1),
            peer_gossip_max_count: 32,
            block_duration: Duration::from_mins(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::ed25519::PrivateKey;
    use commonware_utils::AtMost;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_max_message_size_config_is_compatible() {
        let config = Config::test(
            PrivateKey::from_seed(0),
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            Vec::new(),
            AtMost!(MAX_SIZE),
        );

        assert_eq!(config.max_message_size.get(), MAX_SIZE);
        assert_eq!(config.max_frame_size().get(), STREAM_MAX_SIZE);
    }
}
