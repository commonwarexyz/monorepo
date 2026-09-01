use commonware_cryptography::PublicKey;
use commonware_p2p::{Blocker, Provider};
use commonware_parallel::Strategy;
use std::num::NonZeroUsize;

/// Configuration for the [super::Engine].
pub struct Config<
    P: PublicKey,
    MCfg,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    T: Strategy,
> {
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

    /// Blocks peers whose messages fail to decode.
    pub blocker: B,

    /// Strategy for decoding inbound messages off the engine's event loop.
    ///
    /// Decoding embeds any validation the item's codec performs (for example, digest checks on
    /// large payloads), so a parallel strategy keeps that work from serializing behind the
    /// engine's other duties.
    pub strategy: T,
}
