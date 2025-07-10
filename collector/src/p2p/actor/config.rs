use crate::p2p::{Handler, Monitor};

#[derive(Clone)]
pub struct Config<M: Monitor, H: Handler> {
    pub monitor: M,
    pub handler: H,
    pub mailbox_size: usize,
    pub quorum: usize,
    pub priority_request: bool,
    pub priority_response: bool,
}
