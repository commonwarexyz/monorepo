use crate::collection::{Endpoint, Originator};

#[derive(Clone)]
pub struct Config<O: Originator, E: Endpoint> {
    pub originator: O,
    pub endpoint: E,
    pub mailbox_size: usize,
    pub quorum: usize,
    pub priority_request: bool,
    pub priority_response: bool,
}
