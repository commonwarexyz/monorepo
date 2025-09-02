use crate::{
    broadcast::{Coordinator, Producer},
    Consumer,
};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_utils::Span;

/// Configuration for the broadcast resolver.
pub struct Config<
    P: PublicKey,
    D: Coordinator<PublicKey = P>,
    Key: Span,
    Con: Consumer<Key = Key, Value = Bytes, Failure = ()>,
    Pro: Producer<Key = Key>,
> {
    /// Manages the current set of peers
    pub coordinator: D,

    /// The consumer that gets notified when data is available
    pub consumer: Con,

    /// The producer that serves data requests
    pub producer: Pro,

    /// The maximum size of the mailbox backlog
    pub mailbox_size: usize,

    /// Whether requests are sent with priority over other network messages
    pub priority_requests: bool,

    /// Whether responses are sent with priority over other network messages
    pub priority_responses: bool,
}
