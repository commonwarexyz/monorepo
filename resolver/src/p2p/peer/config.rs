use crate::{Director, Key, Server};
use commonware_cryptography::Scheme;
use commonware_p2p::utils::requester;

pub struct Config<C: Scheme, K: Key, A: Server<Key = K>, D: Director<PublicKey = C::PublicKey>> {
    pub crypto: C,
    pub server: A,
    pub director: D,
    pub mailbox_size: usize,
    pub requester_config: requester::Config<C>,
    pub fetch_concurrent: usize,
    pub serve_concurrent: usize,
}
