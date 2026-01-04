//! Communicate with a fixed set of authenticated peers over encrypted connections.
//!
//! [discovery] operates under the assumption that peer addresses aren't known in
//! advance, and that they need to be discovered. Bootstrappers are used to
//! connect to the network and discover peers.
//!
//! [lookup] operates under the assumption that peer addresses are known in advance,
//! and that they can be looked up by their identifiers.

mod data;
pub mod discovery;
pub mod lookup;
mod mailbox;
pub use mailbox::Mailbox;
mod relay;

/// Result of checking if a peer is acceptable for an incoming connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Attempt {
    /// Peer is acceptable.
    Ok,
    /// Peer is explicitly blocked.
    Blocked,
    /// Peer is not in any tracked peer set (or failed other eligibility checks).
    Unregistered,
    /// Peer is already connected or has a pending connection.
    Reserved,
    /// Some expected data doesn't match (e.g., source IP doesn't match expected egress IP).
    Mismatch,
    /// Peer is ourselves.
    Myself,
}
