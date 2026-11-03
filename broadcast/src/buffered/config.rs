use commonware_cryptography::PublicKey;
use commonware_p2p::{Blocker, Provider};
use commonware_parallel::Strategy;
use std::num::NonZeroUsize;

/// Configuration for the [super::Engine].
pub struct Config<P, MCfg, D, B, T>
where
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    T: Strategy,
{
    /// The public key of the participant.
    pub public_key: P,

    /// Capacity of the application inbox.
    ///
    /// Requests beyond this capacity wait in order. While in overflow, broadcasts with the same
    /// digest combine recipients and are handled once at the first broadcast's position, including
    /// cache updates and subscriber notifications. Canceled overflow requests are discarded.
    pub mailbox_size: NonZeroUsize,

    /// The maximum number of cached items per sender.
    pub deque_size: usize,

    /// Whether messages are sent over the network as priority.
    pub priority: bool,

    /// The configuration for the codec item.
    pub codec_config: MCfg,

    /// Provider for peer set changes (eviction follows the tracked primary sets; see
    /// [`buffered`](super)).
    pub peer_provider: D,

    /// Blocks peers whose messages fail to decode.
    pub blocker: B,

    /// Strategy for decoding inbound messages and computing their digests. Messages are cached in
    /// the order they finish decoding, which may differ from arrival order.
    pub strategy: T,
}
