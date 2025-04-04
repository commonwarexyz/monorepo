use crate::authenticated::types::SignedPeerInfo;
use commonware_cryptography::Verifier;
use std::net::SocketAddr;

/// Represents information known about a peer's address.
#[derive(Clone)]
pub enum Record<C: Verifier> {
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

impl<C: Verifier> Record<C> {
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

    /// Get the peer information if available.
    pub fn get_peer_info(&self) -> Option<&SignedPeerInfo<C>> {
        match &self {
            Self::Unknown(_) => None,
            Self::Bootstrapper(_) => None,
            Self::Discovered(_, peer_info) => Some(peer_info),
            Self::Persistent(peer_info) => Some(peer_info),
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;
    use commonware_cryptography::{Secp256r1, Signer};
    use std::net::SocketAddr;

    // Helper function to create signed peer info
    fn create_signed_peer_info(timestamp: u64) -> SignedPeerInfo<Secp256r1> {
        let mut rng = rand::thread_rng();
        let mut c = Secp256r1::new(&mut rng);
        let socket = SocketAddr::from(([127, 0, 0, 1], 8080));
        let signature = c.sign(None, &(socket, timestamp).encode());
        SignedPeerInfo {
            socket,
            timestamp,
            public_key: c.public_key(),
            signature,
        }
    }

    #[test]
    fn test_unknown_to_discovered() {
        let mut record = Record::<Secp256r1>::Unknown(1);
        let peer_info = create_signed_peer_info(1000);
        assert!(record.set_discovered(peer_info.clone()));
        match record {
            Record::Discovered(count, info) => {
                assert_eq!(count, 1);
                assert_eq!(info.timestamp, 1000);
                assert_eq!(info.socket, peer_info.socket);
            }
            _ => panic!("Expected Discovered state"),
        }
    }

    #[test]
    fn test_bootstrapper_to_persistent() {
        let socket = SocketAddr::from(([127, 0, 0, 1], 8080));
        let mut record = Record::<Secp256r1>::Bootstrapper(socket);
        let peer_info = create_signed_peer_info(1000);
        assert!(record.set_discovered(peer_info.clone()));
        match record {
            Record::Persistent(info) => {
                assert_eq!(info.timestamp, 1000);
                assert_eq!(info.socket, socket);
            }
            _ => panic!("Expected Persistent state"),
        }
    }

    #[test]
    fn test_discovered_update_newer_timestamp() {
        let peer_info_old = create_signed_peer_info(1000);
        let mut record = Record::<Secp256r1>::Discovered(1, peer_info_old);
        let peer_info_new = create_signed_peer_info(2000);
        assert!(record.set_discovered(peer_info_new.clone()));
        match record {
            Record::Discovered(count, info) => {
                assert_eq!(count, 1);
                assert_eq!(info.timestamp, 2000);
            }
            _ => panic!("Expected Discovered state"),
        }
    }

    #[test]
    fn test_discovered_no_update_older_timestamp() {
        let peer_info_old = create_signed_peer_info(1000);
        let mut record = Record::<Secp256r1>::Discovered(1, peer_info_old.clone());
        let peer_info_older = create_signed_peer_info(500);
        assert!(!record.set_discovered(peer_info_older));
        match record {
            Record::Discovered(count, info) => {
                assert_eq!(count, 1);
                assert_eq!(info.timestamp, 1000);
            }
            _ => panic!("Expected Discovered state"),
        }
    }

    #[test]
    fn test_increment_decrement() {
        // Test Unknown state
        let mut record = Record::<Secp256r1>::Unknown(0);
        record.increment();
        assert!(matches!(record, Record::Unknown(1)));
        assert!(record.decrement());
        assert!(matches!(record, Record::Unknown(0)));

        // Test Discovered state
        let peer_info = create_signed_peer_info(1000);
        let mut record = Record::<Secp256r1>::Discovered(1, peer_info);
        record.increment();
        assert!(matches!(record, Record::Discovered(2, _)));
        assert!(!record.decrement());
        assert!(matches!(record, Record::Discovered(1, _)));
        assert!(record.decrement());
        assert!(matches!(record, Record::Discovered(0, _)));
    }

    #[test]
    fn test_get_address() {
        let socket = SocketAddr::from(([127, 0, 0, 1], 8080));

        let record = Record::<Secp256r1>::Bootstrapper(socket);
        assert_eq!(record.get_address(), Some(socket));

        let peer_info = create_signed_peer_info(1000);
        let record = Record::<Secp256r1>::Discovered(1, peer_info.clone());
        assert_eq!(record.get_address(), Some(peer_info.socket));

        let record = Record::<Secp256r1>::Unknown(1);
        assert_eq!(record.get_address(), None);
    }
}
