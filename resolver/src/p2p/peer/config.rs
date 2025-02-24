use std::time::Duration;

use crate::{
    p2p::{Director, Producer, Value},
    Consumer,
};
use commonware_cryptography::{Array, Scheme};
use commonware_p2p::utils::requester;
use governor::Quota;

pub struct Config<
    C: Scheme,
    D: Director<PublicKey = C::PublicKey>,
    Key: Array,
    Con: Consumer<Key = Key, Value = Value, Failure = ()>,
    Pro: Producer<Key = Key, Value = Value>,
> {
    pub crypto: C,
    pub director: D,
    pub consumer: Con,
    pub producer: Pro,
    pub mailbox_size: usize,
    pub requester_config: requester::Config<C>,
    pub fetch_max_outstanding: usize,
    pub fetch_retry_timeout: Duration,

    // Incoming requests
    pub serve_concurrent: usize,
    pub rate_limit: Quota,
}
