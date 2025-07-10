use crate::p2p::{Endpoint, Originator};
use commonware_cryptography::Digest;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Config<D: Digest, O: Originator<D>, E: Endpoint<D>> {
    pub originator: O,
    pub endpoint: E,
    pub mailbox_size: usize,
    pub quorum: usize,
    pub priority_request: bool,
    pub priority_response: bool,
    pub _digest: PhantomData<D>,
}
