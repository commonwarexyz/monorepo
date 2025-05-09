use crate::authenticated::types::PeerInfo;
use commonware_cryptography::Verifier;
use std::net::SocketAddr;
use tracing::trace;

/// Represents information known about a peer's address.
#[derive(Clone, Debug, PartialEq)]
pub enum Address<C: Verifier> {
    /// Peer address is not yet known.
    /// Can be upgraded to `Discovered`.
    Unknown,

    /// Peer is the local node.
    Myself(PeerInfo<C>),

    /// Provided during initialization.
    /// Can be upgraded to `Persistent`.
    /// Will be tracked even if the peer is not part of any peer sets.
    Bootstrapper(SocketAddr),

    /// Discovered this peer's address from other peers.
    Discovered(PeerInfo<C>),

    /// Discovered this peer's address from other peers after it was originally a bootstrapper.
    /// Will be tracked even if the peer is not part of any peer sets.
    Persistent(PeerInfo<C>),

    /// Peer is blocked.
    /// We don't care to track its information.
    Blocked,
}

/// Represents a record of a peer's address and associated information.
#[derive(Clone, Debug, PartialEq)]
pub struct Record<C: Verifier> {
    /// Address state of the peer.
    address: Address<C>,

    /// Number of peer sets this peer is part of.
    sets: usize,
}

impl<C: Verifier> Record<C> {
    // ---------- Constructors ----------

    /// Create a new record with an unknown address.
    pub fn unknown() -> Self {
        Record {
            address: Address::Unknown,
            sets: 0,
        }
    }

    /// Create a new record with the local node's information.
    pub fn myself(peer_info: PeerInfo<C>) -> Self {
        Record {
            address: Address::Myself(peer_info),
            sets: 0,
        }
    }

    /// Create a new record with a bootstrapper address.
    pub fn bootstrapper(socket: SocketAddr) -> Self {
        Record {
            address: Address::Bootstrapper(socket),
            sets: 0,
        }
    }

    // ---------- Setters ----------

    /// Attempt to set the address of a discovered peer.
    ///
    /// Returns true if the update was successful.
    pub fn discover(&mut self, peer_info: PeerInfo<C>) -> bool {
        match &self.address {
            Address::Unknown => {
                // Upgrade to Discovered.
                self.address = Address::Discovered(peer_info);
                true
            }
            Address::Myself(_) => {
                // Do not update, we already have our own information.
                false
            }
            Address::Bootstrapper(_) => {
                // Upgrade to Persistent.
                self.address = Address::Persistent(peer_info);
                true
            }
            Address::Discovered(past_info) => {
                // Ensure the new info is more recent.
                let existing_ts = past_info.timestamp;
                let incoming_ts = peer_info.timestamp;
                if existing_ts >= incoming_ts {
                    trace!(peer = ?peer_info.public_key, ?existing_ts, ?incoming_ts, "peer discovery not updated");
                    return false;
                }
                self.address = Address::Discovered(peer_info);
                true
            }
            Address::Persistent(past_info) => {
                // Ensure the new info is more recent.
                let existing_ts = past_info.timestamp;
                let incoming_ts = peer_info.timestamp;
                if existing_ts >= incoming_ts {
                    trace!(peer = ?peer_info.public_key, ?existing_ts, ?incoming_ts, "peer discovery not updated");
                    return false;
                }
                self.address = Address::Persistent(peer_info);
                true
            }
            Address::Blocked => {
                // Blocked peers cannot be updated.
                false
            }
        }
    }

    /// Attempt to mark the peer as blocked.
    ///
    /// Returns true if the peer was newly blocked.
    /// Returns false if the peer was already blocked or is the local node (unblockable).
    pub fn block(&mut self) -> bool {
        match self.address {
            Address::Blocked | Address::Myself(_) => false,
            _ => {
                self.address = Address::Blocked;
                true
            }
        }
    }

    /// Increase the count of peer sets this peer is part of.
    pub fn increment(&mut self) {
        self.sets = self.sets.checked_add(1).unwrap();
    }

    /// Decrease the count of peer sets this peer is part of.
    ///
    /// Returns true if the record can be deleted. That is:
    /// - The count reaches zero
    /// - The peer is not a bootstrapper or the local node
    pub fn decrement(&mut self) -> bool {
        self.sets = self.sets.checked_sub(1).unwrap();
        if self.sets > 0 {
            return false;
        }
        match self.address {
            Address::Blocked | Address::Unknown | Address::Discovered(_) => true,
            Address::Myself(_) | Address::Bootstrapper(_) | Address::Persistent(_) => false,
        }
    }

    // ---------- Getters ----------

    /// Check if the peer is blocked.
    pub fn blocked(&self) -> bool {
        matches!(self.address, Address::Blocked)
    }

    /// Returns true if we don't need additional [`PeerInfo`] about this peer.
    ///
    /// Similar to `peer_info().is_some()`, but also include the `Blocked` case since we don't
    /// want to track blocked peers despite not recording their information.
    pub fn discovered(&self) -> bool {
        match self.address {
            Address::Unknown | Address::Bootstrapper(_) => false,
            Address::Myself(_)
            | Address::Blocked
            | Address::Discovered(_)
            | Address::Persistent(_) => true,
        }
    }

    /// Get the address of the peer if known.
    pub fn address(&self) -> Option<SocketAddr> {
        match &self.address {
            Address::Unknown => None,
            Address::Myself(peer_info) => Some(peer_info.socket),
            Address::Bootstrapper(socket) => Some(*socket),
            Address::Discovered(peer_info) => Some(peer_info.socket),
            Address::Persistent(peer_info) => Some(peer_info.socket),
            Address::Blocked => None,
        }
    }

    /// Get the peer information if known.
    pub fn peer_info(&self) -> Option<&PeerInfo<C>> {
        match &self.address {
            Address::Unknown => None,
            Address::Myself(peer_info) => Some(peer_info),
            Address::Bootstrapper(_) => None,
            Address::Discovered(peer_info) => Some(peer_info),
            Address::Persistent(peer_info) => Some(peer_info),
            Address::Blocked => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::types::PeerInfo;
    use commonware_codec::Encode;
    use commonware_cryptography::{Secp256r1, Signer, Verifier};
    use std::net::SocketAddr;

    // Helper function to create signed peer info
    fn create_peer_info<C: Signer + Verifier>(
        signer_seed: u64,
        socket: SocketAddr,
        timestamp: u64,
    ) -> PeerInfo<C> {
        let mut signer = C::from_seed(signer_seed);
        let signature = signer.sign(None, &(socket, timestamp).encode());
        PeerInfo {
            socket,
            timestamp,
            public_key: signer.public_key(),
            signature,
        }
    }

    // Common test values
    fn test_socket() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 8080))
    }

    // Helper function to assert equality of PeerInfo
    fn assert_peer_info_eq<C: Verifier>(info1: Option<&PeerInfo<C>>, info2: Option<&PeerInfo<C>>) {
        let (Some(info1), Some(info2)) = (info1, info2) else {
            assert!(info1.is_none() && info2.is_none());
            return;
        };
        assert_eq!(info1.socket, info2.socket);
        assert_eq!(info1.timestamp, info2.timestamp);
        assert_eq!(info1.public_key, info2.public_key);
        assert_eq!(info1.signature, info2.signature);
    }

    #[test]
    fn test_unknown_initial_state() {
        let record = Record::<Secp256r1>::unknown();
        assert!(matches!(record.address, Address::Unknown));
        assert_eq!(record.sets, 0);
        assert_eq!(record.address(), None);
        assert_peer_info_eq(record.peer_info(), None);
        assert!(!record.discovered());
        assert!(!record.blocked());
    }

    #[test]
    fn test_bootstrapper_initial_state() {
        let socket = test_socket();
        let record = Record::<Secp256r1>::bootstrapper(socket);
        assert!(matches!(record.address, Address::Bootstrapper(s) if s == socket));
        assert_eq!(record.sets, 0);
        assert_eq!(record.address(), Some(socket));
        assert_peer_info_eq(record.peer_info(), None);
        assert!(!record.discovered());
        assert!(!record.blocked());
    }

    #[test]
    fn test_unknown_to_discovered() {
        let socket = test_socket();
        let mut record = Record::<Secp256r1>::unknown();
        let peer_info: PeerInfo<Secp256r1> = create_peer_info(1, socket, 1000);

        assert!(record.discover(peer_info.clone()));
        assert_eq!(record.address(), Some(socket));
        assert!(record.discovered());
        assert!(matches!(&record.address, Address::Discovered(_)));
        assert_peer_info_eq(record.peer_info(), Some(&peer_info));
    }

    #[test]
    fn test_bootstrapper_to_persistent() {
        let socket = test_socket();
        let mut record = Record::<Secp256r1>::bootstrapper(socket);
        let peer_info: PeerInfo<Secp256r1> = create_peer_info(2, socket, 1000);

        assert!(record.discover(peer_info.clone()));
        assert_eq!(record.address(), Some(socket));
        assert!(record.discovered());
        assert!(matches!(&record.address, Address::Persistent(_)));
        assert_peer_info_eq(record.peer_info(), Some(&peer_info));
    }

    #[test]
    fn test_discovered_update_newer_timestamp() {
        let socket = test_socket();
        let mut record = Record::<Secp256r1>::unknown();
        let peer_info_old: PeerInfo<Secp256r1> = create_peer_info(3, socket, 1000);
        let peer_info_new: PeerInfo<Secp256r1> = create_peer_info(3, socket, 2000);

        assert!(record.discover(peer_info_old.clone())); // Unknown -> Discovered
        assert!(record.discover(peer_info_new.clone())); // Discovered -> Discovered (update)

        assert_eq!(record.address(), Some(socket));
        assert!(record.discovered());
        assert!(matches!(&record.address, Address::Discovered(_)));
        assert_peer_info_eq(record.peer_info(), Some(&peer_info_new));
    }

    #[test]
    fn test_persistent_update_newer_timestamp() {
        let socket = test_socket();
        let mut record = Record::<Secp256r1>::bootstrapper(socket);
        let peer_info_old: PeerInfo<Secp256r1> = create_peer_info(4, socket, 1000);
        let peer_info_new: PeerInfo<Secp256r1> = create_peer_info(4, socket, 2000);

        assert!(record.discover(peer_info_old.clone())); // Bootstrapper -> Persistent
        assert!(record.discover(peer_info_new.clone())); // Persistent -> Persistent (update)

        assert_eq!(record.address(), Some(socket));
        assert!(record.discovered());
        assert!(matches!(&record.address, Address::Persistent(_)));
        assert_peer_info_eq(record.peer_info(), Some(&peer_info_new));
    }

    #[test]
    fn test_discovered_no_update_older_or_equal_timestamp() {
        let socket = test_socket();
        let mut record = Record::<Secp256r1>::unknown();
        let peer_info_old: PeerInfo<Secp256r1> = create_peer_info(5, socket, 1000);
        let peer_info_older: PeerInfo<Secp256r1> = create_peer_info(5, socket, 500);
        let peer_info_equal: PeerInfo<Secp256r1> = create_peer_info(5, socket, 1000);

        assert!(record.discover(peer_info_old.clone())); // Unknown -> Discovered

        // Attempt update with older timestamp
        assert!(!record.discover(peer_info_older));
        assert_peer_info_eq(record.peer_info(), Some(&peer_info_old)); // Verify state hasn't changed

        // Attempt update with equal timestamp
        assert!(!record.discover(peer_info_equal));
        assert_peer_info_eq(record.peer_info(), Some(&peer_info_old)); // Verify state still hasn't changed

        // Final state check
        assert!(matches!(&record.address, Address::Discovered(_)));
    }

    #[test]
    fn test_persistent_no_update_older_or_equal_timestamp() {
        let socket = test_socket();
        let mut record = Record::<Secp256r1>::bootstrapper(socket);
        let peer_info_old: PeerInfo<Secp256r1> = create_peer_info(6, socket, 1000);
        let peer_info_older: PeerInfo<Secp256r1> = create_peer_info(6, socket, 500);
        let peer_info_equal: PeerInfo<Secp256r1> = create_peer_info(6, socket, 1000);

        assert!(record.discover(peer_info_old.clone())); // Bootstrapper -> Persistent

        // Attempt update with older timestamp
        assert!(!record.discover(peer_info_older));
        assert_peer_info_eq(record.peer_info(), Some(&peer_info_old)); // Verify state hasn't changed

        // Attempt update with equal timestamp
        assert!(!record.discover(peer_info_equal));
        assert_peer_info_eq(record.peer_info(), Some(&peer_info_old)); // Verify state still hasn't changed

        // Final state check
        assert!(matches!(&record.address, Address::Persistent(_)));
    }

    #[test]
    fn test_increment_decrement_removable() {
        let socket = test_socket();

        // Test Unknown state -> removable
        let mut record_unknown = Record::<Secp256r1>::unknown();
        assert_eq!(record_unknown.sets, 0);
        record_unknown.increment();
        record_unknown.increment();
        assert_eq!(record_unknown.sets, 2);
        assert!(!record_unknown.decrement());
        assert_eq!(record_unknown.sets, 1);
        assert!(record_unknown.decrement());
        assert_eq!(record_unknown.sets, 0);

        // Test Discovered state -> removable
        let peer_info: PeerInfo<Secp256r1> = create_peer_info(7, socket, 1000);
        let mut record_disc = Record::<Secp256r1>::unknown();
        record_disc.discover(peer_info.clone());
        assert_eq!(record_disc.sets, 0);
        record_disc.increment();
        record_disc.increment();
        assert_eq!(record_disc.sets, 2);
        assert!(!record_disc.decrement());
        assert_eq!(record_disc.sets, 1);
        assert!(record_disc.decrement());
        assert_eq!(record_disc.sets, 0);
    }

    #[test]
    fn test_increment_decrement_not_removable() {
        let socket = test_socket();

        // Test Bootstrapper state -> not removable
        let mut record_boot = Record::<Secp256r1>::bootstrapper(socket);
        assert_eq!(record_boot.sets, 0);
        record_boot.increment();
        record_boot.increment();
        assert_eq!(record_boot.sets, 2);
        assert!(!record_boot.decrement());
        assert_eq!(record_boot.sets, 1);
        assert!(!record_boot.decrement());
        assert_eq!(record_boot.sets, 0);

        // Test Persistent state -> not removable
        let peer_info: PeerInfo<Secp256r1> = create_peer_info(7, socket, 1000);
        let mut record_pers = Record::<Secp256r1>::bootstrapper(socket);
        record_pers.discover(peer_info);
        assert_eq!(record_pers.sets, 0);
        record_pers.increment();
        record_pers.increment();
        assert_eq!(record_pers.sets, 2);
        assert!(!record_pers.decrement());
        assert_eq!(record_pers.sets, 1);
        assert!(!record_pers.decrement());
        assert_eq!(record_pers.sets, 0);
    }

    #[test]
    #[should_panic]
    fn test_decrement_panics_at_zero() {
        let mut record = Record::<Secp256r1>::unknown();
        assert_eq!(record.sets, 0);
        // This call should decrement from 0, causing a panic due to checked_sub
        record.decrement();
    }

    #[test]
    fn test_address_all_states() {
        let socket = test_socket();
        let peer_info: PeerInfo<Secp256r1> = create_peer_info(8, socket, 1000);

        let record_unknown = Record::<Secp256r1>::unknown();
        assert_eq!(record_unknown.address(), None);

        let record_boot = Record::<Secp256r1>::bootstrapper(socket);
        assert_eq!(record_boot.address(), Some(socket));

        let mut record_disc = Record::<Secp256r1>::unknown();
        record_disc.discover(peer_info.clone());
        assert_eq!(record_disc.address(), Some(socket));

        let mut record_pers = Record::<Secp256r1>::bootstrapper(socket);
        record_pers.discover(peer_info);
        assert_eq!(record_pers.address(), Some(socket));

        let mut record_blocked = Record::<Secp256r1>::unknown();
        record_blocked.block();
        assert_eq!(record_blocked.address(), None);
    }

    #[test]
    fn test_peer_info_all_states() {
        let socket = test_socket();
        let peer_info: PeerInfo<Secp256r1> = create_peer_info(9, socket, 1000);

        let record_unknown = Record::<Secp256r1>::unknown();
        assert_peer_info_eq(record_unknown.peer_info(), None);

        let record_boot = Record::<Secp256r1>::bootstrapper(socket);
        assert_peer_info_eq(record_boot.peer_info(), None);

        let mut record_disc = Record::<Secp256r1>::unknown();
        record_disc.discover(peer_info.clone());
        assert_peer_info_eq(record_disc.peer_info(), Some(&peer_info));

        let mut record_pers = Record::<Secp256r1>::bootstrapper(socket);
        record_pers.discover(peer_info.clone());
        assert_peer_info_eq(record_pers.peer_info(), Some(&peer_info));

        let mut record_blocked = Record::<Secp256r1>::unknown();
        record_blocked.block();
        assert_peer_info_eq(record_blocked.peer_info(), None);
    }

    #[test]
    fn test_discovered_all_states() {
        let socket = test_socket();
        let peer_info: PeerInfo<Secp256r1> = create_peer_info(10, socket, 1000);

        let record_unknown = Record::<Secp256r1>::unknown();
        assert!(!record_unknown.discovered());

        let record_boot = Record::<Secp256r1>::bootstrapper(socket);
        assert!(!record_boot.discovered());

        let mut record_disc = Record::<Secp256r1>::unknown();
        record_disc.discover(peer_info.clone());
        assert!(record_disc.discovered());

        let mut record_pers = Record::<Secp256r1>::bootstrapper(socket);
        record_pers.discover(peer_info);
        assert!(record_pers.discovered());

        let mut record_blocked = Record::<Secp256r1>::unknown();
        record_blocked.block();
        assert!(record_blocked.discovered());
    }

    #[test]
    fn test_block() {
        let mut record = Record::<Secp256r1>::unknown();
        assert!(!record.blocked());
        record.block();
        assert!(record.blocked());
        assert!(matches!(record.address, Address::Blocked));

        // Attempting to set discovered on a blocked record should fail
        let socket = test_socket();
        let peer_info: PeerInfo<Secp256r1> = create_peer_info(11, socket, 1000);
        assert!(!record.discover(peer_info));
        assert!(record.blocked()); // Still blocked
        assert_peer_info_eq(record.peer_info(), None); // Info should not be set
    }
}
