//! Implementation of the [crate::Originator], [crate::Handler], and [crate::Monitor] traits for [commonware_p2p].

use crate::{Handler, Monitor};

mod engine;
pub use engine::Engine;
mod ingress;
pub use ingress::{Mailbox, Message};

/// Configuration for an [Engine].
#[derive(Clone)]
pub struct Config<M: Monitor, H: Handler, RqC, RsC> {
    /// The [Monitor] that will be notified when a response is collected.
    pub monitor: M,

    /// The [Handler] that will be used to process requests.
    pub handler: H,

    /// The size of the mailbox for sending and receiving messages.
    pub mailbox_size: usize,

    /// Whether or not to send requests with priority over other network messages.
    pub priority_request: bool,

    /// The [commonware_codec::Codec] configuration for requests.
    pub request_codec: RqC,

    /// Whether or not to send responses with priority over other network messages.
    pub priority_response: bool,

    /// The [commonware_codec::Codec] configuration for responses.
    pub response_codec: RsC,
}
