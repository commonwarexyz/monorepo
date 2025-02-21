use crate::{p2p::Value, Consumer, Director, Producer};
use commonware_cryptography::{Array, Scheme};
use commonware_p2p::utils::requester;

pub struct Config<
    C: Scheme,
    D: Director<PublicKey = C::PublicKey>,
    Key: Array,
    Con: Consumer<Key = Key, Value = Value, FailureCode = ()>,
    Pro: Producer<Key = Key, Value = Value>,
> {
    pub crypto: C,
    pub director: D,
    pub consumer: Con,
    pub producer: Pro,
    pub mailbox_size: usize,
    pub requester_config: requester::Config<C>,
    pub fetch_concurrent: usize,
    pub serve_concurrent: usize,
}
