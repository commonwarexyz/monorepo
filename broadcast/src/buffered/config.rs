use commonware_utils::Array;

/// Configuration for the [`Engine`](super::Engine).
pub struct Config<C: Copy + Send + 'static, P: Array> {
    /// The public key of the participant.
    pub public_key: P,

    /// The maximum size of the mailbox backlog.
    pub mailbox_size: usize,

    /// The maximum number of cached items per sender.
    pub deque_size: usize,

    /// Whether messages are sent over the network as priority.
    pub priority: bool,

    /// The configuration for decoding messages.
    pub decode_config: C,
}
