use crate::{Handler, Monitor};
use commonware_p2p::Blocker;
use std::num::NonZeroUsize;

/// Configuration for an [Engine](super::Engine).
#[derive(Clone)]
pub struct Config<B: Blocker, M: Monitor, H: Handler, RqC, RsC> {
    /// Blocks peers whose requests or responses fail to decode.
    pub blocker: B,

    /// Receives each response the engine collects.
    pub monitor: M,

    /// Processes each request the engine admits.
    pub handler: H,

    /// Capacity of the engine's inbox.
    ///
    /// The Backpressure section of the [module](super) docs describes what waits behind it.
    pub mailbox_size: NonZeroUsize,

    /// Maximum number of inbound requests awaiting a handler response across all peers.
    pub max_pending_requests: NonZeroUsize,

    /// Maximum number of requests from one peer that can await a handler response.
    ///
    /// A value at least as large as [Self::max_pending_requests] adds no further limit.
    pub max_pending_requests_per_peer: NonZeroUsize,

    /// Whether requests are sent with priority over other network messages.
    pub priority_requests: bool,

    /// The [commonware_codec::Codec] configuration for decoding requests.
    pub request_codec_config: RqC,

    /// Whether responses are sent with priority over other network messages.
    pub priority_responses: bool,

    /// The [commonware_codec::Codec] configuration for decoding responses.
    pub response_codec_config: RsC,
}
