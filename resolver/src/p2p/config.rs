use crate::{p2p::Producer, Consumer};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_p2p::{Blocker, Manager};
use commonware_utils::Span;
use std::time::Duration;

/// Configuration for the peer actor.
pub struct Config<
    P: PublicKey,
    D: Manager<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    Key: Span,
    Con: Consumer<Key = Key, Value = Bytes, Failure = ()>,
    Pro: Producer<Key = Key>,
> {
    /// Manages the current set of peers
    pub manager: D,

    /// The blocker that will be used to block peers that send invalid responses
    pub blocker: B,

    /// The consumer that gets notified when data is available
    pub consumer: Con,

    /// The producer that serves data requests
    pub producer: Pro,

    /// The maximum size of the mailbox backlog
    pub mailbox_size: usize,

    /// Local identity of the participant (if any).
    pub me: Option<P>,

    /// Initial expected performance for new participants.
    pub initial: Duration,

    /// Timeout for requests.
    pub timeout: Duration,

    /// How long fetches remain in the pending queue before being retried
    pub fetch_retry_timeout: Duration,

    /// Whether requests are sent with priority over other network messages
    pub priority_requests: bool,

    /// Whether responses are sent with priority over other network messages
    pub priority_responses: bool,
}
