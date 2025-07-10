use crate::{Handler, Monitor};

mod engine;
pub use engine::Engine;
mod ingress;
pub use ingress::{Mailbox, Message};

#[derive(Clone)]
pub struct Config<M: Monitor, H: Handler, RqC, RsC> {
    pub monitor: M,
    pub handler: H,

    pub mailbox_size: usize,

    pub priority_request: bool,
    pub request_codec: RqC,

    pub priority_response: bool,
    pub response_codec: RsC,
}
