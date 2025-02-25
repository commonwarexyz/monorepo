use crate::{
    p2p::{Coordinator, Producer},
    Consumer,
};
use bytes::Bytes;
use commonware_cryptography::Scheme;
use commonware_p2p::utils::requester;
use commonware_utils::Array;
use std::time::Duration;

/// Configuration for the peer actor.
pub struct Config<
    C: Scheme,
    D: Coordinator<PublicKey = C::PublicKey>,
    Key: Array,
    Con: Consumer<Key = Key, Value = Bytes, Failure = ()>,
    Pro: Producer<Key = Key>,
> {
    pub crypto: C,
    pub coordinator: D,
    pub consumer: Con,
    pub producer: Pro,
    pub mailbox_size: usize,
    pub requester_config: requester::Config<C>,
    pub fetch_retry_timeout: Duration,
}
