use commonware_codec::Config as CodecCfg;
use commonware_utils::Array;

/// Configuration for the [`Engine`](super::Engine).
pub struct Config<Cfg: CodecCfg, P: Array> {
    /// The public key of the participant.
    pub public_key: P,

    /// The maximum size of the mailbox backlog.
    pub mailbox_size: usize,

    /// The maximum number of cached items per sender.
    pub deque_size: usize,

    /// Whether messages are sent over the network as priority.
    pub priority: bool,

    /// The configuration for the codec item.
    pub codec_config: Cfg,
}
