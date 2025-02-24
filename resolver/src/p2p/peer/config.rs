use std::time::Duration;

use crate::{
    p2p::{Director, Producer, Value},
    Consumer,
};
use commonware_cryptography::Scheme;
use commonware_p2p::utils::requester;
use commonware_utils::Array;

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
    pub fetch_retry_timeout: Duration,
}
