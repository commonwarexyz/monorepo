use crate::authenticated::types::SignedPeerInfo;
use commonware_cryptography::Scheme;
use std::net::SocketAddr;

#[derive(Clone)]
pub enum Address<C: Scheme> {
    /// Provided during initialization
    Bootstrapper(SocketAddr),

    /// Not yet known
    Unknown,

    /// Learned from other peers
    Discovered(SignedPeerInfo<C>),
}

pub struct AddressCount<C: Scheme> {
    /// Address of the peer.
    /// If this is `None`, then the address of the peer is not (yet) known.
    pub address: Address<C>,

    /// Number of peer sets this peer is part of.
    /// If this is `usize::MAX`, then this is a bootstrapper address.
    pub count: usize,
}

impl<C: Scheme> AddressCount<C> {
    /// Create a new `AddressCount` with no address and a count of 1.
    pub fn new() -> Self {
        Self {
            address: Address::Unknown,
            count: 1,
        }
    }

    /// Get the address of the peer.
    pub fn get_address(&self) -> Option<SocketAddr> {
        match &self.address {
            Address::Bootstrapper(socket) => Some(*socket),
            Address::Discovered(info) => Some(info.info.socket),
            Address::Unknown => None,
        }
    }

    /// Create a bootstrapper address.
    pub fn new_bootstrapper(address: SocketAddr) -> Self {
        Self {
            address: Address::Bootstrapper(address),
            // Ensures that we never remove a bootstrapper (even
            // if not in any active set)
            count: usize::MAX,
        }
    }

    /// Set as a discovered address.
    pub fn set_discovered(&mut self, signed_peer_info: SignedPeerInfo<C>) -> bool {
        if let Address::Discovered(past) = &self.address {
            if past.info.timestamp >= signed_peer_info.info.timestamp {
                return false;
            }
        }
        self.address = Address::Discovered(signed_peer_info);
        true
    }

    /// Check if the address is a discovered address.
    pub fn has_discovered(&self) -> bool {
        matches!(self.address, Address::Discovered(_))
    }

    /// Increase the count.
    pub fn increment(&mut self) {
        if self.count == usize::MAX {
            return;
        }
        self.count += 1;
    }

    /// Decreases the count and returns true if the count is 0.
    pub fn decrement(&mut self) -> bool {
        if self.count == usize::MAX {
            return false;
        }
        self.count -= 1;
        self.count == 0
    }
}
