use commonware_cryptography::PublicKey;
use commonware_p2p::PeerSetSubscription;

/// Configuration for the [super::Engine].
pub struct Config<P: PublicKey, MCfg> {
    /// The public key of the participant.
    pub public_key: P,

    /// The maximum size of the mailbox backlog.
    pub mailbox_size: usize,

    /// The maximum number of cached items per sender.
    pub deque_size: usize,

    /// Whether messages are sent over the network as priority.
    pub priority: bool,

    /// The configuration for the codec item.
    pub codec_config: MCfg,

    /// Subscription to peer set changes. Per-peer caches are freed when a
    /// peer leaves all tracked peer sets.
    pub peer_set_subscription: PeerSetSubscription<P>,
}
