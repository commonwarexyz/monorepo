use commonware_cryptography::PublicKey;
use commonware_p2p::Provider;
use std::num::NonZeroUsize;

/// Configuration for the [super::Engine].
pub struct Config<P: PublicKey, MCfg, D: Provider<PublicKey = P>> {
    /// The public key of the participant.
    pub public_key: P,

    /// The maximum size of the mailbox backlog.
    pub mailbox_size: NonZeroUsize,

    /// The maximum number of cached items per sender.
    pub deque_size: usize,

    /// Whether messages are sent over the network as priority.
    pub priority: bool,

    /// The configuration for the codec item.
    pub codec_config: MCfg,

    /// Provider for peer set changes (eviction follows latest primary; see [`buffered`](super)).
    pub peer_provider: D,
}
