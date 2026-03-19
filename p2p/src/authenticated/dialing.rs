use commonware_cryptography::PublicKey;
use std::time::SystemTime;

/// Merges `b` into `a`, keeping the earliest time.
pub(crate) fn earliest(a: Option<SystemTime>, b: SystemTime) -> Option<SystemTime> {
    Some(a.map_or(b, |a| a.min(b)))
}

/// Result of checking whether a peer is dialable.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DialStatus {
    /// Peer can be dialed immediately.
    Now,
    /// Peer will become dialable at the given time.
    After(SystemTime),
    /// Peer is not dialable.
    Unavailable,
}

/// Result of attempting to reserve a peer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReserveResult {
    /// Reservation succeeded.
    Reserved,
    /// Reservation denied because not enough time has elapsed since the last reservation.
    RateLimited,
    /// Reservation denied for any other reason (already reserved, is self, etc.).
    Unavailable,
}

/// Dialable peers and the next time it is worth querying again.
#[derive(Clone, Debug)]
pub struct Dialable<C: PublicKey> {
    /// Peers that can be dialed immediately.
    pub peers: Vec<C>,

    /// Earliest known time at which another peer may become dialable.
    pub next_query_at: Option<SystemTime>,
}

impl<C: PublicKey> Default for Dialable<C> {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            next_query_at: None,
        }
    }
}
