use crate::{Handler, Monitor};
use commonware_p2p::Blocker;
use std::num::NonZeroUsize;

/// Configuration for an [Engine](super::Engine).
#[derive(Clone)]
pub struct Config<B: Blocker, M: Monitor, H: Handler, RqC, RsC> {
    /// Blocks peers whose messages fail to decode.
    pub blocker: B,

    /// Receives each response the engine collects.
    pub monitor: M,

    /// Processes each request the engine receives.
    pub handler: H,

    /// Capacity of the engine's [inbox](super#backpressure).
    pub mailbox_size: NonZeroUsize,

    /// Whether requests are sent with priority over other network messages.
    pub priority_requests: bool,

    /// The [commonware_codec::Codec] configuration for decoding requests.
    pub request_codec_config: RqC,

    /// Whether responses are sent with priority over other network messages.
    pub priority_responses: bool,

    /// The [commonware_codec::Codec] configuration for decoding responses.
    pub response_codec_config: RsC,
}
