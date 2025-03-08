use commonware_utils::Array;

/// Configuration for the [`Engine`](super::Engine).
pub struct Config<P: Array> {
    /// The cryptographic scheme used if the engine is a sequencer.
    pub public_key: P,

    /// The maximum size of the mailbox backlog.
    pub mailbox_size: usize,

    /// The maximum number of cached items per sender.
    pub cache_per_sender_size: usize,

    /// Whether messages are sent over the network as priority.
    pub priority: bool,
}
