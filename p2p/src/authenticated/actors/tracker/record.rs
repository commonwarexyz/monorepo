use crate::authenticated::types::PeerInfo;
use commonware_cryptography::Verifier;
use std::net::SocketAddr;
use tracing::trace;

/// Represents information known about a peer's address.
#[derive(Clone, Debug)]
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

/// Represents the connection status of a peer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Status {
    /// Initial state. The peer is not yet connected.
    /// Will be upgraded to [`Status::Reserved`] when a reservation is made.
    Inert,

    /// The peer connection is reserved by an actor that is attempting to establish a connection.
    /// Will either be upgraded to [`Status::Active`] or downgraded to [`Status::Inert`].
    Reserved,

    /// The peer is connected.
    /// Must return to [`Status::Inert`] after the connection is closed.
    Active,
}

/// Represents a record of a peer's address and associated information.
#[derive(Clone, Debug)]
pub struct Record<C: Verifier> {
    /// Address state of the peer.
    address: Address<C>,

    /// Connection status of the peer.
    status: Status,

    /// Number of peer sets this peer is part of.
    sets: usize,
}

/// Returns `true` if the new information is more recent than the existing one.
fn should_update<C: Verifier>(existing_ts: u64, info: &PeerInfo<C>) -> bool {
    // Ensure the new info is more recent.
    let incoming_ts = info.timestamp;
    if existing_ts >= incoming_ts {
        trace!(peer = ?info.public_key, ?existing_ts, ?incoming_ts, "peer discovery not updated");
        return false;
    }
    true
}

impl<C: Verifier> Record<C> {
    // ---------- Constructors ----------

    /// Create a new record with an unknown address.
    pub fn unknown() -> Self {
        Record {
            address: Address::Unknown,
            status: Status::Inert,
            sets: 0,
        }
    }

    /// Create a new record with the local node's information.
    pub fn myself(peer_info: PeerInfo<C>) -> Self {
        Record {
            address: Address::Myself(peer_info),
            status: Status::Inert,
            sets: 0,
        }
    }

    /// Create a new record with a bootstrapper address.
    pub fn bootstrapper(socket: SocketAddr) -> Self {
        Record {
            address: Address::Bootstrapper(socket),
            status: Status::Inert,
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
                if !should_update(past_info.timestamp, &peer_info) {
                    return false;
                }
                self.address = Address::Discovered(peer_info);
                true
            }
            Address::Persistent(past_info) => {
                if !should_update(past_info.timestamp, &peer_info) {
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
    pub fn decrement(&mut self) {
        self.sets = self.sets.checked_sub(1).unwrap();
    }

    /// Attempt to reserve the peer for connection.
    ///
    /// Returns `true` if the reservation was successful, `false` otherwise.
    pub fn reserve(&mut self) -> bool {
        match self.status {
            Status::Inert => {
                self.status = Status::Reserved;
                true
            }
            Status::Reserved => false,
            Status::Active => false,
        }
    }

    /// Marks the peer as connected. The peer must have the status [`Status::Reserved`].
    pub fn connect(&mut self) {
        assert!(self.status == Status::Reserved);
        self.status = Status::Active;
    }

    /// Releases any reservation on the peer.
    ///
    /// Returns the previous status of the peer.
    pub fn release(&mut self) -> Status {
        let prev = self.status;
        self.status = Status::Inert;
        prev
    }

    // ---------- Getters ----------

    /// Returns `true` if the record is blocked.
    pub fn blocked(&self) -> bool {
        matches!(self.address, Address::Blocked)
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

    /// Get the peer information if it is sharable. The information is considered sharable if it is
    /// known and we are connected to the peer.
    pub fn sharable_info(&self) -> Option<PeerInfo<C>> {
        match &self.address {
            Address::Unknown => None,
            Address::Myself(peer_info) => Some(peer_info),
            Address::Bootstrapper(_) => None,
            Address::Discovered(peer_info) => self.connected().then_some(peer_info),
            Address::Persistent(peer_info) => self.connected().then_some(peer_info),
            Address::Blocked => None,
        }
        .cloned()
    }

    // Returns `true` if the peer is connected.
    pub fn connected(&self) -> bool {
        matches!(self.status, Status::Active)
    }

    /// Returns `true` if the peer is reserved (or active).
    /// This is used to determine if we should attempt to reserve the peer again.
    pub fn reserved(&self) -> bool {
        matches!(self.status, Status::Reserved | Status::Active)
    }

    /// Returns `true` if we want to ask for updated peer information for this peer.
    pub fn want(&self) -> bool {
        // Ignore how many sets the peer is part of. If the peer is not in any sets, this function
        // is not called anyway.

        let connected = self.status == Status::Active;
        match self.address {
            Address::Unknown => true,
            Address::Myself(_) => false,
            Address::Bootstrapper(_) => true,
            Address::Discovered(_) => !connected,
            Address::Persistent(_) => !connected,
            Address::Blocked => false,
        }
    }

    /// Returns `true` if the record can safely be deleted.
    pub fn deletable(&self) -> bool {
        match self.address {
            Address::Myself(_) | Address::Bootstrapper(_) | Address::Persistent(_) => false,
            Address::Blocked | Address::Unknown | Address::Discovered(_) => {
                self.sets == 0 && self.status == Status::Inert
            }
        }
    }

    /// Returns `true` if the record is allowed to be used for connection.
    pub fn allowed(&self) -> bool {
        match self.address {
            Address::Blocked | Address::Myself(_) => false,
            Address::Bootstrapper(_) | Address::Persistent(_) => true,
            Address::Unknown | Address::Discovered(_) => self.sets > 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::types::PeerInfo;
    use commonware_codec::Encode;
    use commonware_cryptography::{Secp256r1, Signer};
    use std::net::SocketAddr;

    // Helper function to create signed peer info
    fn create_peer_info<S>(signer_seed: u64, socket: SocketAddr, timestamp: u64) -> PeerInfo<S>
    where
        S: Signer + Verifier,
        S::PublicKey: Clone + PartialEq + std::fmt::Debug,
        S::Signature: Clone + PartialEq + std::fmt::Debug,
    {
        let mut signer = S::from_seed(signer_seed);
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
    fn test_socket2() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 8081))
    }

    // Helper function to compare the contents of two PeerInfo instances
    fn peer_info_contents_are_equal<S: Verifier>(
        actual: &PeerInfo<S>,
        expected: &PeerInfo<S>,
    ) -> bool
    where
        S::PublicKey: PartialEq + std::fmt::Debug,
        S::Signature: PartialEq + std::fmt::Debug,
    {
        actual.socket == expected.socket
            && actual.timestamp == expected.timestamp
            && actual.public_key == expected.public_key
            && actual.signature == expected.signature
    }

    // Helper function to compare an Option<&PeerInfo<S>> with a &PeerInfo<S>
    fn compare_optional_peer_info<S: Verifier>(
        actual_opt: Option<&PeerInfo<S>>,
        expected: &PeerInfo<S>,
    ) -> bool
    where
        S::PublicKey: PartialEq + std::fmt::Debug,
        S::Signature: PartialEq + std::fmt::Debug,
    {
        if let Some(actual) = actual_opt {
            peer_info_contents_are_equal(actual, expected)
        } else {
            false
        }
    }

    #[test]
    fn test_unknown_initial_state() {
        let record = Record::<Secp256r1>::unknown();
        assert!(matches!(record.address, Address::Unknown));
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.sets, 0);
        assert_eq!(record.address(), None);
        assert!(record.sharable_info().is_none());
        assert!(!record.blocked());
        assert!(!record.connected());
        assert!(!record.reserved());
        assert!(record.want());
        assert!(record.deletable());
        assert!(!record.allowed());
    }

    #[test]
    fn test_myself_initial_state() {
        let my_info = create_peer_info::<Secp256r1>(0, test_socket(), 100);
        let record = Record::<Secp256r1>::myself(my_info.clone());
        assert!(
            matches!(&record.address, Address::Myself(info) if peer_info_contents_are_equal(info, &my_info))
        );
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.sets, 0);
        assert_eq!(record.address(), Some(my_info.socket));
        assert!(compare_optional_peer_info(
            record.sharable_info().as_ref(),
            &my_info
        ));
        assert!(!record.blocked());
        assert!(!record.connected());
        assert!(!record.reserved());
        assert!(!record.want());
        assert!(!record.deletable());
        assert!(!record.allowed());
    }

    #[test]
    fn test_bootstrapper_initial_state() {
        let socket = test_socket();
        let record = Record::<Secp256r1>::bootstrapper(socket);
        assert!(matches!(record.address, Address::Bootstrapper(s) if s == socket));
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.sets, 0);
        assert_eq!(record.address(), Some(socket));
        assert!(record.sharable_info().is_none());
        assert!(!record.blocked());
        assert!(!record.connected());
        assert!(!record.reserved());
        assert!(record.want());
        assert!(!record.deletable());
        assert!(record.allowed());
    }

    #[test]
    fn test_unknown_to_discovered() {
        let socket = test_socket();
        let mut record = Record::<Secp256r1>::unknown();
        let peer_info = create_peer_info::<Secp256r1>(1, socket, 1000);

        assert!(record.discover(peer_info.clone()));
        assert_eq!(record.address(), Some(socket));
        assert!(
            matches!(&record.address, Address::Discovered(info) if peer_info_contents_are_equal(info, &peer_info))
        );
        assert!(record.sharable_info().is_none()); // Not connected yet
    }

    #[test]
    fn test_bootstrapper_to_persistent() {
        let socket = test_socket();
        let mut record = Record::<Secp256r1>::bootstrapper(socket);
        let peer_info = create_peer_info::<Secp256r1>(2, socket, 1000);

        assert!(record.discover(peer_info.clone()));
        assert_eq!(record.address(), Some(socket));
        assert!(
            matches!(&record.address, Address::Persistent(info) if peer_info_contents_are_equal(info, &peer_info))
        );
        assert!(record.sharable_info().is_none()); // Not connected yet
    }

    #[test]
    fn test_discovered_update_newer_timestamp() {
        let socket = test_socket();
        let mut record = Record::<Secp256r1>::unknown();
        let peer_info_old = create_peer_info::<Secp256r1>(3, socket, 1000);
        let peer_info_new = create_peer_info::<Secp256r1>(3, socket, 2000); // Same PK, new timestamp

        assert!(record.discover(peer_info_old.clone()));
        assert!(record.discover(peer_info_new.clone()));

        assert_eq!(record.address(), Some(socket));
        assert!(
            matches!(&record.address, Address::Discovered(info) if peer_info_contents_are_equal(info, &peer_info_new))
        );
    }

    #[test]
    fn test_persistent_update_newer_timestamp() {
        let socket = test_socket();
        let mut record = Record::<Secp256r1>::bootstrapper(socket);
        let peer_info_old = create_peer_info::<Secp256r1>(4, socket, 1000);
        let peer_info_new = create_peer_info::<Secp256r1>(4, socket, 2000); // Same PK, new timestamp

        assert!(record.discover(peer_info_old.clone()));
        assert!(record.discover(peer_info_new.clone()));

        assert_eq!(record.address(), Some(socket));
        assert!(
            matches!(&record.address, Address::Persistent(info) if peer_info_contents_are_equal(info, &peer_info_new))
        );
    }

    #[test]
    fn test_discovered_no_update_older_or_equal_timestamp() {
        let socket = test_socket();
        let mut record = Record::<Secp256r1>::unknown();
        let peer_info_current = create_peer_info::<Secp256r1>(5, socket, 1000);
        let peer_info_older = create_peer_info::<Secp256r1>(5, socket, 500);
        let peer_info_equal = create_peer_info::<Secp256r1>(5, socket, 1000);

        assert!(record.discover(peer_info_current.clone()));

        assert!(!record.discover(peer_info_older));
        assert!(
            matches!(&record.address, Address::Discovered(info) if peer_info_contents_are_equal(info, &peer_info_current))
        );

        assert!(!record.discover(peer_info_equal));
        assert!(
            matches!(&record.address, Address::Discovered(info) if peer_info_contents_are_equal(info, &peer_info_current))
        );
    }

    #[test]
    fn test_persistent_no_update_older_or_equal_timestamp() {
        let socket = test_socket();
        let mut record = Record::<Secp256r1>::bootstrapper(socket);
        let peer_info_current = create_peer_info::<Secp256r1>(6, socket, 1000);
        let peer_info_older = create_peer_info::<Secp256r1>(6, socket, 500);
        let peer_info_equal = create_peer_info::<Secp256r1>(6, socket, 1000);

        assert!(record.discover(peer_info_current.clone()));

        assert!(!record.discover(peer_info_older));
        assert!(
            matches!(&record.address, Address::Persistent(info) if peer_info_contents_are_equal(info, &peer_info_current))
        );

        assert!(!record.discover(peer_info_equal));
        assert!(
            matches!(&record.address, Address::Persistent(info) if peer_info_contents_are_equal(info, &peer_info_current))
        );
    }

    #[test]
    fn test_discover_myself_and_blocked() {
        let my_info = create_peer_info::<Secp256r1>(0, test_socket(), 100);
        let mut record_myself = Record::myself(my_info.clone());
        let other_info = create_peer_info::<Secp256r1>(1, test_socket2(), 200);

        assert!(!record_myself.discover(other_info.clone()));
        assert!(
            matches!(&record_myself.address, Address::Myself(info) if peer_info_contents_are_equal(info, &my_info))
        );

        let mut record_blocked = Record::<Secp256r1>::unknown();
        assert!(record_blocked.block());
        assert!(!record_blocked.discover(other_info));
        assert!(matches!(record_blocked.address, Address::Blocked));
    }

    #[test]
    fn test_discover_with_different_public_key() {
        let socket = test_socket();
        let mut record = Record::<Secp256r1>::unknown();

        let peer_info_pk1_ts1000 = create_peer_info::<Secp256r1>(10, socket, 1000);
        let peer_info_pk2_ts2000 = create_peer_info::<Secp256r1>(11, socket, 2000); // Different PK (seed 11)

        assert!(record.discover(peer_info_pk1_ts1000.clone()));
        assert!(
            matches!(&record.address, Address::Discovered(info) if peer_info_contents_are_equal(info, &peer_info_pk1_ts1000))
        );

        assert!(
            record.discover(peer_info_pk2_ts2000.clone()),
            "Discover should succeed based on timestamp"
        );
        assert!(
            matches!(&record.address, Address::Discovered(info) if peer_info_contents_are_equal(info, &peer_info_pk2_ts2000))
        );
    }

    #[test]
    fn test_increment_decrement_deletable() {
        let mut record_unknown = Record::<Secp256r1>::unknown();
        record_unknown.increment();
        assert!(!record_unknown.deletable());
        record_unknown.decrement();
        assert!(record_unknown.deletable());

        let peer_info = create_peer_info::<Secp256r1>(7, test_socket(), 1000);
        let mut record_disc = Record::<Secp256r1>::unknown();
        assert!(record_disc.discover(peer_info));
        record_disc.increment();
        assert!(!record_disc.deletable());
        record_disc.decrement();
        assert!(record_disc.deletable());
    }

    #[test]
    fn test_increment_decrement_not_deletable() {
        let mut record_boot = Record::<Secp256r1>::bootstrapper(test_socket());
        record_boot.increment();
        assert!(!record_boot.deletable());
        record_boot.decrement();
        assert!(!record_boot.deletable());

        let peer_info = create_peer_info::<Secp256r1>(8, test_socket(), 1000);
        let mut record_pers = Record::<Secp256r1>::bootstrapper(test_socket());
        assert!(record_pers.discover(peer_info));
        record_pers.increment();
        assert!(!record_pers.deletable());
        record_pers.decrement();
        assert!(!record_pers.deletable());

        let my_info = create_peer_info::<Secp256r1>(0, test_socket(), 100);
        let mut record_myself = Record::myself(my_info);
        record_myself.increment();
        assert!(!record_myself.deletable());
        record_myself.decrement();
        assert!(!record_myself.deletable());
    }

    #[test]
    #[should_panic]
    fn test_decrement_panics_at_zero() {
        let mut record = Record::<Secp256r1>::unknown();
        record.decrement();
    }

    #[test]
    fn test_block_behavior() {
        let sample_peer_info = create_peer_info::<Secp256r1>(20, test_socket(), 1000);

        let mut record_unknown = Record::<Secp256r1>::unknown();
        assert_eq!(record_unknown.status, Status::Inert);
        assert!(record_unknown.block());
        assert!(record_unknown.blocked());
        assert!(matches!(record_unknown.address, Address::Blocked));
        assert_eq!(
            record_unknown.status,
            Status::Inert,
            "Status should remain Inert"
        );
        assert!(!record_unknown.block());
        assert!(!record_unknown.discover(sample_peer_info.clone()));
        assert!(record_unknown.address().is_none());
        assert!(record_unknown.sharable_info().is_none());

        let mut record_reserved = Record::<Secp256r1>::unknown();
        assert!(record_reserved.discover(sample_peer_info.clone()));
        assert!(record_reserved.reserve());
        assert_eq!(record_reserved.status, Status::Reserved);
        assert!(record_reserved.block());
        assert!(record_reserved.blocked());
        assert!(matches!(record_reserved.address, Address::Blocked));
        assert_eq!(
            record_reserved.status,
            Status::Reserved,
            "Status should remain Reserved"
        );

        let mut record_active = Record::<Secp256r1>::unknown();
        assert!(record_active.discover(sample_peer_info.clone()));
        assert!(record_active.reserve());
        record_active.connect();
        assert_eq!(record_active.status, Status::Active);
        assert!(record_active.block());
        assert!(record_active.blocked());
        assert!(matches!(record_active.address, Address::Blocked));
        assert_eq!(
            record_active.status,
            Status::Active,
            "Status should remain Active"
        );
    }

    #[test]
    fn test_block_myself_and_already_blocked() {
        let my_info = create_peer_info::<Secp256r1>(0, test_socket(), 100);
        let mut record_myself = Record::myself(my_info.clone());
        assert!(!record_myself.block());
        assert!(
            matches!(&record_myself.address, Address::Myself(info) if peer_info_contents_are_equal(info, &my_info))
        );

        let mut record_to_be_blocked = Record::<Secp256r1>::unknown();
        assert!(record_to_be_blocked.block());
        assert!(matches!(record_to_be_blocked.address, Address::Blocked));
        assert!(!record_to_be_blocked.block());
        assert!(matches!(record_to_be_blocked.address, Address::Blocked));
    }

    #[test]
    fn test_status_transitions_reserve_connect_release() {
        let mut record = Record::<Secp256r1>::unknown();

        assert_eq!(record.status, Status::Inert);
        assert!(record.reserve());
        assert_eq!(record.status, Status::Reserved);
        assert!(record.reserved());

        assert!(!record.reserve());
        assert_eq!(record.status, Status::Reserved);

        record.connect();
        assert_eq!(record.status, Status::Active);
        assert!(record.connected());
        assert!(record.reserved());

        assert!(!record.reserve());
        assert_eq!(record.status, Status::Active);

        assert_eq!(record.release(), Status::Active);
        assert_eq!(record.status, Status::Inert);
        assert!(!record.connected());
        assert!(!record.reserved());

        assert_eq!(record.release(), Status::Inert);
        assert_eq!(record.status, Status::Inert);

        assert!(record.reserve());
        assert_eq!(record.status, Status::Reserved);
        assert_eq!(record.release(), Status::Reserved);
        assert_eq!(record.status, Status::Inert);
    }

    #[test]
    #[should_panic(expected = "assertion failed: self.status == Status::Reserved")]
    fn test_connect_when_not_reserved_panics_from_inert() {
        let mut record = Record::<Secp256r1>::unknown();
        record.connect();
    }

    #[test]
    #[should_panic(expected = "assertion failed: self.status == Status::Reserved")]
    fn test_connect_when_active_panics() {
        let mut record = Record::<Secp256r1>::unknown();
        assert!(record.reserve());
        record.connect(); // Now Active
        record.connect();
    }

    #[test]
    fn test_sharable_info_logic() {
        let socket = test_socket();
        let peer_info_data = create_peer_info::<Secp256r1>(12, socket, 100);

        let record_unknown = Record::<Secp256r1>::unknown();
        assert!(record_unknown.sharable_info().is_none());

        let record_myself = Record::myself(peer_info_data.clone());
        assert!(compare_optional_peer_info(
            record_myself.sharable_info().as_ref(),
            &peer_info_data
        ));

        let record_boot = Record::<Secp256r1>::bootstrapper(socket);
        assert!(record_boot.sharable_info().is_none());

        let mut record_blocked = Record::<Secp256r1>::unknown();
        record_blocked.block();
        assert!(record_blocked.sharable_info().is_none());

        let mut record_disc = Record::<Secp256r1>::unknown();
        record_disc.discover(peer_info_data.clone());
        assert!(record_disc.sharable_info().is_none()); // Not connected
        assert!(record_disc.reserve());
        record_disc.connect(); // Now connected
        assert!(compare_optional_peer_info(
            record_disc.sharable_info().as_ref(),
            &peer_info_data
        ));
        record_disc.release();
        assert!(record_disc.sharable_info().is_none()); // Not connected anymore

        let mut record_pers = Record::<Secp256r1>::bootstrapper(socket);
        record_pers.discover(peer_info_data.clone());
        assert!(record_pers.sharable_info().is_none()); // Not connected
        assert!(record_pers.reserve());
        record_pers.connect(); // Now connected
        assert!(compare_optional_peer_info(
            record_pers.sharable_info().as_ref(),
            &peer_info_data
        ));
        record_pers.release();
        assert!(record_pers.sharable_info().is_none()); // Not connected anymore
    }

    #[test]
    fn test_connected_status() {
        let mut record = Record::<Secp256r1>::unknown();
        assert!(!record.connected());
        assert!(record.reserve());
        assert!(!record.connected());
        record.connect();
        assert!(record.connected());
        record.release();
        assert!(!record.connected());
    }

    #[test]
    fn test_reserved_status() {
        let mut record = Record::<Secp256r1>::unknown();
        assert!(!record.reserved());
        assert!(record.reserve());
        assert!(record.reserved());
        record.connect();
        assert!(record.reserved());
        record.release();
        assert!(!record.reserved());
    }

    #[test]
    fn test_want_logic() {
        let peer_info = create_peer_info::<Secp256r1>(13, test_socket(), 100);

        let record_unknown = Record::<Secp256r1>::unknown();
        assert!(record_unknown.want());

        let record_myself = Record::myself(peer_info.clone());
        assert!(!record_myself.want());

        let record_boot = Record::<Secp256r1>::bootstrapper(test_socket());
        assert!(record_boot.want());

        let mut record_blocked = Record::<Secp256r1>::unknown();
        record_blocked.block();
        assert!(!record_blocked.want());

        let mut record_disc = Record::<Secp256r1>::unknown();
        record_disc.discover(peer_info.clone());
        assert!(record_disc.want());
        assert!(record_disc.reserve());
        record_disc.connect();
        assert!(!record_disc.want());
        record_disc.release();
        assert!(record_disc.want());

        let mut record_pers = Record::<Secp256r1>::bootstrapper(test_socket());
        record_pers.discover(peer_info.clone());
        assert!(record_pers.want());
        assert!(record_pers.reserve());
        record_pers.connect();
        assert!(!record_pers.want());
        record_pers.release();
        assert!(record_pers.want());
    }

    #[test]
    fn test_deletable_logic() {
        let peer_info = create_peer_info::<Secp256r1>(14, test_socket(), 100);
        let peer_info2 = create_peer_info::<Secp256r1>(15, test_socket2(), 200);

        assert!(!Record::myself(peer_info.clone()).deletable());
        assert!(!Record::<Secp256r1>::bootstrapper(test_socket()).deletable());
        let mut record_pers = Record::<Secp256r1>::bootstrapper(test_socket());
        record_pers.discover(peer_info.clone());
        assert!(!record_pers.deletable());

        let mut record_unknown = Record::<Secp256r1>::unknown();
        assert!(record_unknown.deletable());
        record_unknown.increment();
        assert!(!record_unknown.deletable());
        record_unknown.decrement();
        assert!(record_unknown.deletable());
        assert!(record_unknown.reserve());
        assert!(!record_unknown.deletable());
        record_unknown.release();
        assert!(record_unknown.deletable());

        let mut record_disc = Record::<Secp256r1>::unknown();
        record_disc.discover(peer_info.clone());
        assert!(record_disc.deletable());
        record_disc.increment();
        assert!(!record_disc.deletable());
        record_disc.decrement();
        assert!(record_disc.deletable());
        assert!(record_disc.reserve());
        assert!(!record_disc.deletable());
        record_disc.release();
        assert!(record_disc.deletable());

        let mut record_blocked_from_unknown = Record::<Secp256r1>::unknown();
        record_blocked_from_unknown.block();
        assert_eq!(record_blocked_from_unknown.status, Status::Inert);
        assert!(record_blocked_from_unknown.deletable());
        record_blocked_from_unknown.increment();
        assert!(!record_blocked_from_unknown.deletable());
        record_blocked_from_unknown.decrement();
        assert!(record_blocked_from_unknown.deletable());

        let mut record_active_then_blocked = Record::<Secp256r1>::unknown();
        assert!(record_active_then_blocked.discover(peer_info2.clone()));
        assert!(record_active_then_blocked.reserve());
        record_active_then_blocked.connect();
        assert_eq!(record_active_then_blocked.sets, 0);
        assert_eq!(record_active_then_blocked.status, Status::Active);
        assert!(!record_active_then_blocked.deletable());

        record_active_then_blocked.block();
        assert!(record_active_then_blocked.blocked());
        assert_eq!(record_active_then_blocked.status, Status::Active);
        assert_eq!(record_active_then_blocked.sets, 0);
        assert!(!record_active_then_blocked.deletable());
    }

    #[test]
    fn test_allowed_logic() {
        let peer_info = create_peer_info::<Secp256r1>(16, test_socket(), 100);

        let mut record_blocked = Record::<Secp256r1>::unknown();
        record_blocked.block();
        assert!(!record_blocked.allowed());
        assert!(!Record::myself(peer_info.clone()).allowed());

        assert!(Record::<Secp256r1>::bootstrapper(test_socket()).allowed());
        let mut record_pers = Record::<Secp256r1>::bootstrapper(test_socket());
        record_pers.discover(peer_info.clone());
        assert!(record_pers.allowed());

        let mut record_unknown = Record::<Secp256r1>::unknown();
        assert!(!record_unknown.allowed());
        record_unknown.increment();
        assert!(record_unknown.allowed());
        record_unknown.decrement();
        assert!(!record_unknown.allowed());

        let mut record_disc = Record::<Secp256r1>::unknown();
        record_disc.discover(peer_info.clone());
        assert!(!record_disc.allowed());
        record_disc.increment();
        assert!(record_disc.allowed());
    }
}
