use crate::{
    p2p::{Coordinator, Producer},
    Consumer,
};
use bytes::Bytes;
use commonware_p2p::utils::requester;
use commonware_utils::Array;
use std::time::Duration;

/// Configuration for the peer actor.
pub struct Config<
    C: Array,
    D: Coordinator<PublicKey = C>,
    Key: Array,
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

    /// Configuration for the requester
    pub requester_config: requester::Config<C>,

    /// How long fetches remain in the pending queue before being retried
    pub fetch_retry_timeout: Duration,

    /// Whether requests are sent with priority over other network messages
    pub priority_requests: bool,

    /// Whether responses are sent with priority over other network messages
    pub priority_responses: bool,
}
