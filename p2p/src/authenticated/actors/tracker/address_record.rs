use crate::authenticated::types::SignedPeerInfo;
use commonware_cryptography::Scheme;
use std::net::SocketAddr;

/// Represents information known about a peer's address.
#[derive(Clone)]
pub enum AddressRecord<C: Scheme> {
    /// Peer address is not yet known.
    /// Can be upgraded to `Discovered`.
    /// Tracks the number of peer sets this peer is part of.
    Unknown(usize),

    /// Provided during initialization.
    /// Can be upgraded to `Persistent`.
    Bootstrapper(SocketAddr),

    /// Discovered this peer's address from other peers.
    /// Tracks the number of peer sets this peer is part of.
    Discovered(usize, SignedPeerInfo<C>),

    /// Discovered this peer's address from other peers after it was bootstrapped.
    /// Will continuously be tracked.
    Persistent(SignedPeerInfo<C>),
}

impl<C: Scheme> AddressRecord<C> {
    /// Get the address of the peer.
    ///
    /// Returns None if the address is unknown.
    pub fn get_address(&self) -> Option<SocketAddr> {
        match &self {
            Self::Unknown(_) => None,
            Self::Bootstrapper(socket) => Some(*socket),
            Self::Discovered(_, peer_info) => Some(peer_info.socket),
            Self::Persistent(peer_info) => Some(peer_info.socket),
        }
    }

    /// Attempt to set the address of a discovered peer.
    ///
    /// Returns true if the update was successful.
    pub fn set_discovered(&mut self, peer_info: SignedPeerInfo<C>) -> bool {
        match self {
            Self::Unknown(count) => {
                // Upgrade to Discovered.
                *self = Self::Discovered(*count, peer_info);
                true
            }
            Self::Bootstrapper(_) => {
                // Upgrade to Persistent.
                *self = Self::Persistent(peer_info);
                true
            }
            Self::Discovered(count, past_info) => {
                // Ensure the new info is more recent.
                if past_info.timestamp >= peer_info.timestamp {
                    return false;
                }
                *self = Self::Discovered(*count, peer_info);
                true
            }
            Self::Persistent(past_info) => {
                // Ensure the new info is more recent.
                if past_info.timestamp >= peer_info.timestamp {
                    return false;
                }
                *self = Self::Persistent(peer_info);
                true
            }
        }
    }

    /// Check if the address is a discovered address.
    pub fn is_discovered(&self) -> bool {
        matches!(self, Self::Discovered(_, _) | Self::Persistent(_))
    }

    /// Increase the num
    pub fn increment(&mut self) {
        match self {
            Self::Unknown(count) | Self::Discovered(count, _) => {
                *count = count.checked_add(1).unwrap();
            }
            // Bootstrapper and Persistent are not incremented.
            _ => {}
        }
    }

    /// Decreases the count and returns true if the count is 0.
    pub fn decrement(&mut self) -> bool {
        match self {
            Self::Unknown(count) | Self::Discovered(count, _) => {
                *count = count.checked_sub(1).unwrap();
                *count == 0
            }
            // Bootstrapper and Persistent are not decremented.
            _ => false,
        }
    }
}
