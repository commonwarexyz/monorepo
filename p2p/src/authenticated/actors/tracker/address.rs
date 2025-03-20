use crate::authenticated::types::SignedPeerInfo;
use commonware_cryptography::Scheme;
use std::net::SocketAddr;

/// If the count for an `AddressRecord` is set to this value,
/// it is considered pinned and cannot be incremented or decremented.
const PINNED: usize = usize::MAX;

/// Represents information known about a peer's address.
#[derive(Clone)]
pub enum AddressRecord<C: Scheme> {
    /// Provided during initialization.
    /// Can be upgraded to `Discovered`.
    Bootstrapper(SocketAddr),

    /// Peer address is not yet known.
    /// Can be upgraded to `Discovered`.
    /// Tracks the number of peer sets this peer is part of.
    Unknown(usize),

    /// Discovered this peer's address from other peers.
    /// Tracks the number of peer sets this peer is part of.
    Discovered(usize, SignedPeerInfo<C>),
}

impl<C: Scheme> AddressRecord<C> {
    /// Get the address of the peer.
    ///
    /// Returns None if the address is unknown.
    pub fn get_address(&self) -> Option<SocketAddr> {
        match &self {
            Self::Bootstrapper(socket) => Some(*socket),
            Self::Discovered(_, peer_info) => Some(peer_info.socket),
            Self::Unknown(_) => None,
        }
    }

    /// Attempt to set the address of a discovered peer.
    ///
    /// Returns true if the update was successful.
    /// Panics if the address is a bootstrapper.
    pub fn set_discovered(&mut self, peer_info: SignedPeerInfo<C>) -> bool {
        let count = match self {
            Self::Unknown(count) => *count,
            Self::Discovered(count, past_info) => {
                if past_info.timestamp >= peer_info.timestamp {
                    return false;
                }
                *count
            }
            Self::Bootstrapper(_) => PINNED,
        };
        *self = Self::Discovered(count, peer_info);
        true
    }

    /// Check if the address is a discovered address.
    pub fn is_discovered(&self) -> bool {
        matches!(self, Self::Discovered(_, _))
    }

    /// Increase the num
    pub fn increment(&mut self) {
        if let Self::Unknown(count) | Self::Discovered(count, _) = self {
            // The address is already pinned.
            if *count == PINNED {
                return;
            }

            *count += 1;
        }
    }

    /// Decreases the count and returns true if the count is 0.
    pub fn decrement(&mut self) -> bool {
        if let Self::Unknown(count) | Self::Discovered(count, _) = self {
            if *count == PINNED {
                return false;
            }
            *count = count.checked_sub(1).unwrap();
            *count == 0
        } else {
            false
        }
    }
}
