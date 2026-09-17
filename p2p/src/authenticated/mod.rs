//! Communicate with a fixed set of authenticated peers.
//!
//! [discovery] operates under the assumption that peer addresses aren't known in
//! advance, and that they need to be discovered. Bootstrappers are used to
//! connect to the network and discover peers.
//!
//! [lookup] operates under the assumption that peer addresses are known in advance,
//! and that they can be looked up by their identifiers.

mod channels;
mod data;
pub use crate::sizing::peer_set_limit;
pub use data::{MAX_PAYLOAD_OVERHEAD, max_size};
pub(crate) mod dialing;
pub mod discovery;
pub mod lookup;
mod mailbox;
pub use mailbox::Mailbox;
mod relay;
mod router;

use std::time::Duration;

/// Settings shared by inbound and outbound stream establishment.
#[derive(Clone)]
pub(crate) struct StreamConfig<H> {
    /// Handshake used to authenticate and wrap a connection.
    pub handshake: H,
    /// Namespace for the stream handshake.
    pub namespace: Vec<u8>,
    /// Maximum stream message size, including p2p framing.
    pub max_message_size: u32,
    /// Maximum duration of a handshake attempt.
    pub handshake_timeout: Duration,
}
