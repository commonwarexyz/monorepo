use crate::authenticated::discovery::types::Info;
use commonware_cryptography::PublicKey;
use std::net::SocketAddr;
use tracing::trace;

/// Represents information known about a peer's address.
#[derive(Clone, Debug)]
pub enum Address<C: PublicKey> {
    /// Peer address is not yet known.
    /// Can be upgraded to `Discovered`.
    Unknown,

    /// Peer is the local node.
    Myself(Info<C>),

    /// Address is provided during initialization.
    /// Can be upgraded to `Discovered`.
    Bootstrapper(SocketAddr),

    /// Discovered this peer's address from other peers.
    ///
    /// The `usize` indicates the number of times dialing this record has failed.
    Discovered(Info<C>, usize),

    /// Peer is blocked.
    /// We don't care to track its information.
    Blocked,
}

/// Represents the connection status of a peer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Status {
    /// Initial state. The peer is not yet connected.
    /// Will be upgraded to [Status::Reserved] when a reservation is made.
    Inert,

    /// The peer connection is reserved by an actor that is attempting to establish a connection.
    /// Will either be upgraded to [Status::Active] or downgraded to [Status::Inert].
    Reserved,

    /// The peer is connected.
    /// Must return to [Status::Inert] after the connection is closed.
    Active,
}

/// Represents a record of a peer's address and associated information.
#[derive(Clone, Debug)]
pub struct Record<C: PublicKey> {
    /// Address state of the peer.
    address: Address<C>,

    /// Connection status of the peer.
    status: Status,

    /// Number of peer sets this peer is part of.
    sets: usize,

    /// If `true`, the record should persist even if the peer is not part of any peer sets.
    persistent: bool,
}

impl<C: PublicKey> Record<C> {
    // ---------- Constructors ----------

    /// Create a new record with an unknown address.
    pub const fn unknown() -> Self {
        Self {
            address: Address::Unknown,
            status: Status::Inert,
            sets: 0,
            persistent: false,
        }
    }

    /// Create a new record with the local node's information.
    pub const fn myself(info: Info<C>) -> Self {
        Self {
            address: Address::Myself(info),
            status: Status::Inert,
            sets: 0,
            persistent: true,
        }
    }

    /// Create a new record with a bootstrapper address.
    pub const fn bootstrapper(socket: SocketAddr) -> Self {
        Self {
            address: Address::Bootstrapper(socket),
            status: Status::Inert,
            sets: 0,
            persistent: true,
        }
    }

    // ---------- Setters ----------

    /// Attempt to update the [Info] of a discovered peer.
    ///
    /// Returns true if the update was successful.
    pub fn update(&mut self, info: Info<C>) -> bool {
        match &self.address {
            Address::Myself(_) => false,
            Address::Blocked => false,
            Address::Unknown | Address::Bootstrapper(_) => {
                self.address = Address::Discovered(info, 0);
                true
            }
            Address::Discovered(prev, _) => {
                // Ensure the new info is more recent.
                let existing_ts = prev.timestamp;
                let incoming_ts = info.timestamp;
                if existing_ts >= incoming_ts {
                    let peer = info.public_key;
                    trace!(
                        ?peer,
                        ?existing_ts,
                        ?incoming_ts,
                        "peer discovery not updated"
                    );
                    return false;
                }
                self.address = Address::Discovered(info, 0);
                true
            }
        }
    }

    /// Attempt to mark the peer as blocked.
    ///
    /// Returns `true` if the peer was newly blocked.
    /// Returns `false` if the peer was already blocked or is the local node (unblockable).
    pub fn block(&mut self) -> bool {
        if matches!(self.address, Address::Blocked | Address::Myself(_)) {
            return false;
        }
        self.address = Address::Blocked;
        self.persistent = false;
        true
    }

    /// Increase the count of peer sets this peer is part of.
    pub const fn increment(&mut self) {
        self.sets = self.sets.checked_add(1).unwrap();
    }

    /// Decrease the count of peer sets this peer is part of.
    ///
    /// Returns `true` if the record can be deleted. That is:
    /// - The count reaches zero
    /// - The peer is not a bootstrapper or the local node
    pub const fn decrement(&mut self) {
        self.sets = self.sets.checked_sub(1).unwrap();
    }

    /// Attempt to reserve the peer for connection.
    ///
    /// Returns `true` if the reservation was successful, `false` otherwise.
    pub const fn reserve(&mut self) -> bool {
        if matches!(self.address, Address::Blocked | Address::Myself(_)) {
            return false;
        }
        if matches!(self.status, Status::Inert) {
            self.status = Status::Reserved;
            return true;
        }
        false
    }

    /// Marks the peer as connected.
    ///
    /// The peer must have the status [Status::Reserved].
    pub fn connect(&mut self) {
        assert!(matches!(self.status, Status::Reserved));
        self.status = Status::Active;
    }

    /// Releases any reservation on the peer.
    pub fn release(&mut self) {
        assert!(self.status != Status::Inert, "Cannot release an Inert peer");
        self.status = Status::Inert;
    }

    /// Indicate that there was a dial failure for this peer using the given `socket`, which is
    /// checked against the existing record to ensure that we correctly attribute the failure.
    pub fn dial_failure(&mut self, socket: SocketAddr) {
        if let Address::Discovered(info, fails) = &mut self.address {
            if info.socket == socket {
                *fails += 1;
            }
        }
    }

    /// Indicate that a dial succeeded for this peer.
    ///
    /// Due to race conditions, it's possible that we connected using a socket that is now ejected
    /// from the record. However, in this case, the record would already have the `fails` set to 0,
    /// so we can avoid checking against the socket.
    pub const fn dial_success(&mut self) {
        if let Address::Discovered(_, fails) = &mut self.address {
            *fails = 0;
        }
    }

    // ---------- Getters ----------

    /// Returns `true` if the record is blocked.
    pub const fn blocked(&self) -> bool {
        matches!(self.address, Address::Blocked)
    }

    /// Returns `true` if the record is dialable.
    ///
    /// A record is dialable if:
    /// - We have the socket address of the peer
    /// - It is not ourselves
    /// - We are not already connected
    pub fn dialable(&self) -> bool {
        self.status == Status::Inert
            && matches!(
                self.address,
                Address::Bootstrapper(_) | Address::Discovered(_, _)
            )
    }

    /// Returns `true` if the peer is listenable.
    ///
    /// A record is listenable if:
    /// - The peer is allowed
    /// - We are not already connected
    pub fn listenable(&self) -> bool {
        self.allowed() && self.status == Status::Inert
    }

    /// Return the socket of the peer, if known.
    pub const fn socket(&self) -> Option<SocketAddr> {
        match &self.address {
            Address::Unknown => None,
            Address::Myself(info) => Some(info.socket),
            Address::Bootstrapper(socket) => Some(*socket),
            Address::Discovered(info, _) => Some(info.socket),
            Address::Blocked => None,
        }
    }

    /// Get the peer information if it is sharable. The information is considered sharable if it is
    /// known and we are connected to the peer.
    pub fn sharable(&self) -> Option<Info<C>> {
        match &self.address {
            Address::Unknown => None,
            Address::Myself(info) => Some(info),
            Address::Bootstrapper(_) => None,
            Address::Discovered(info, _) => (self.status == Status::Active).then_some(info),
            Address::Blocked => None,
        }
        .cloned()
    }

    /// Returns `true` if the peer is reserved (or active).
    /// This is used to determine if we should attempt to reserve the peer again.
    pub const fn reserved(&self) -> bool {
        matches!(self.status, Status::Reserved | Status::Active)
    }

    /// Returns `true` if we want to ask for updated peer information for this peer.
    ///
    /// - Returns `false` for `Myself` and `Blocked` addresses.
    /// - Returns `true` for addresses for which we don't have peer info.
    /// - Returns true for addresses for which we do have peer info if-and-only-if we have failed to
    ///   dial at least `min_fails` times.
    pub fn want(&self, min_fails: usize) -> bool {
        // Ignore how many sets the peer is part of.
        // If the peer is not in any sets, this function is not called anyway.

        // Return true if we either:
        // - Don't have signed peer info
        // - Are not connected to the peer and have failed dialing it
        match self.address {
            Address::Myself(_) | Address::Blocked => false,
            Address::Unknown | Address::Bootstrapper(_) => true,
            Address::Discovered(_, fails) => self.status != Status::Active && fails >= min_fails,
        }
    }

    /// Returns `true` if the record can safely be deleted.
    pub const fn deletable(&self) -> bool {
        self.sets == 0 && !self.persistent && matches!(self.status, Status::Inert)
    }

    /// Returns `true` if the record is allowed to be used for connection.
    pub const fn allowed(&self) -> bool {
        match self.address {
            Address::Blocked | Address::Myself(_) => false,
            Address::Bootstrapper(_) | Address::Unknown | Address::Discovered(_, _) => {
                self.sets > 0 || self.persistent
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;
    use commonware_cryptography::{
        secp256r1::standard::{PrivateKey, PublicKey},
        PrivateKeyExt,
    };
    use std::net::SocketAddr;

    const NAMESPACE: &[u8] = b"test";

    // Helper function to create signed peer info for testing
    fn create_peer_info<S>(
        signer_seed: u64,
        socket: SocketAddr,
        timestamp: u64,
    ) -> Info<S::PublicKey>
    where
        S: PrivateKeyExt,
    {
        let signer = S::from_seed(signer_seed);
        let signature = signer.sign(NAMESPACE, &(socket, timestamp).encode());
        Info {
            socket,
            timestamp,
            public_key: signer.public_key(),
            signature,
        }
    }

    // Common test sockets
    fn test_socket() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 8080))
    }
    fn test_socket2() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 8081))
    }

    // Helper function to compare the contents of two Info instances
    fn peer_info_contents_are_equal<S: commonware_cryptography::PublicKey>(
        actual: &Info<S>,
        expected: &Info<S>,
    ) -> bool {
        actual.socket == expected.socket
            && actual.timestamp == expected.timestamp
            && actual.public_key == expected.public_key
            && actual.signature == expected.signature
    }

    // Helper function to compare an Option<&Info<S>> with a &Info<S>
    fn compare_optional_peer_info<S: commonware_cryptography::PublicKey>(
        actual_opt: Option<&Info<S>>,
        expected: &Info<S>,
    ) -> bool {
        actual_opt.is_some_and(|actual| peer_info_contents_are_equal(actual, expected))
    }

    #[test]
    fn test_unknown_initial_state() {
        let record = Record::<PublicKey>::unknown();
        assert!(matches!(record.address, Address::Unknown));
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.sets, 0);
        assert!(!record.persistent);
        assert_eq!(record.socket(), None);
        assert!(record.sharable().is_none());
        assert!(!record.blocked());
        assert!(!record.reserved());
        assert!(record.want(0), "Should want info for unknown peer");
        assert!(record.deletable());
        assert!(!record.allowed());
    }

    #[test]
    fn test_myself_initial_state() {
        let my_info = create_peer_info::<PrivateKey>(0, test_socket(), 100);
        let record = Record::<PublicKey>::myself(my_info.clone());
        assert!(
            matches!(&record.address, Address::Myself(info) if peer_info_contents_are_equal(info, &my_info))
        );
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.sets, 0);
        assert!(record.persistent);
        assert_eq!(record.socket(), Some(my_info.socket),);
        assert!(compare_optional_peer_info(
            record.sharable().as_ref(),
            &my_info
        ));
        assert!(!record.blocked());
        assert!(!record.reserved());
        assert!(!record.want(0), "Should not want info for myself");
        assert!(!record.deletable());
        assert!(!record.allowed());
    }

    #[test]
    fn test_bootstrapper_initial_state() {
        let socket = test_socket();
        let record = Record::<PublicKey>::bootstrapper(socket);
        assert!(matches!(record.address, Address::Bootstrapper(s) if s == socket));
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.sets, 0);
        assert!(record.persistent);
        assert_eq!(record.socket(), Some(socket));
        assert!(record.sharable().is_none());
        assert!(!record.blocked());
        assert!(!record.reserved());
        assert!(record.want(0), "Should want info for bootstrapper");
        assert!(!record.deletable());
        assert!(record.allowed());
    }

    #[test]
    fn test_unknown_to_discovered() {
        let socket = test_socket();
        let mut record = Record::<PublicKey>::unknown();
        let peer_info = create_peer_info::<PrivateKey>(1, socket, 1000);

        assert!(record.update(peer_info.clone()));
        assert_eq!(record.socket(), Some(socket));
        assert!(
            matches!(&record.address, Address::Discovered(info, 0) if peer_info_contents_are_equal(info, &peer_info)),
            "Address should be Discovered with 0 failures"
        );
        assert!(record.sharable().is_none(), "Info not sharable yet");
        assert!(!record.persistent);
    }

    #[test]
    fn test_bootstrapper_to_discovered() {
        let socket = test_socket();
        let mut record = Record::<PublicKey>::bootstrapper(socket);
        let peer_info = create_peer_info::<PrivateKey>(2, socket, 1000);

        assert!(record.persistent, "Should start as persistent");
        assert!(record.update(peer_info.clone()));
        assert_eq!(record.socket(), Some(socket));
        assert!(
            matches!(&record.address, Address::Discovered(info, 0) if peer_info_contents_are_equal(info, &peer_info)),
            "Address should be Discovered with 0 failures"
        );
        assert!(record.sharable().is_none());
        assert!(record.persistent, "Should remain persistent after update");
    }

    #[test]
    fn test_discovered_update_newer_timestamp() {
        let socket = test_socket();
        let mut record = Record::<PublicKey>::unknown();
        let peer_info_old = create_peer_info::<PrivateKey>(3, socket, 1000);
        let peer_info_new = create_peer_info::<PrivateKey>(3, socket, 2000);

        assert!(record.update(peer_info_old));
        assert!(record.update(peer_info_new.clone()));

        assert_eq!(record.socket(), Some(socket));
        assert!(
            matches!(&record.address, Address::Discovered(info, 0) if peer_info_contents_are_equal(info, &peer_info_new)),
            "Address should contain newer info"
        );
    }

    #[test]
    fn test_discovered_no_update_older_or_equal_timestamp() {
        let socket = test_socket();
        let mut record = Record::<PublicKey>::unknown();
        let peer_info_current = create_peer_info::<PrivateKey>(5, socket, 1000);
        let peer_info_older = create_peer_info::<PrivateKey>(5, socket, 500);
        let peer_info_equal = create_peer_info::<PrivateKey>(5, socket, 1000);

        assert!(record.update(peer_info_current.clone()));

        assert!(!record.update(peer_info_older));
        assert!(
            matches!(&record.address, Address::Discovered(info, 0) if peer_info_contents_are_equal(info, &peer_info_current)),
            "Address should not update with older info"
        );

        assert!(!record.update(peer_info_equal));
        assert!(
            matches!(&record.address, Address::Discovered(info, 0) if peer_info_contents_are_equal(info, &peer_info_current)),
            "Address should not update with equal timestamp info"
        );
    }

    #[test]
    fn test_update_myself_and_blocked() {
        let my_info = create_peer_info::<PrivateKey>(0, test_socket(), 100);
        let mut record_myself = Record::myself(my_info.clone());
        let other_info = create_peer_info::<PrivateKey>(1, test_socket2(), 200);
        let newer_my_info = create_peer_info::<PrivateKey>(0, test_socket(), 300);

        // Cannot update Myself record with other info or newer self info
        assert!(!record_myself.update(other_info.clone()));
        assert!(!record_myself.update(newer_my_info));
        assert!(
            matches!(&record_myself.address, Address::Myself(info) if peer_info_contents_are_equal(info, &my_info)),
            "Myself record should remain unchanged"
        );

        // Cannot update a Blocked record
        let mut record_blocked = Record::<PublicKey>::unknown();
        assert!(record_blocked.block());
        assert!(!record_blocked.update(other_info));
        assert!(matches!(record_blocked.address, Address::Blocked));
    }

    #[test]
    fn test_update_with_different_public_key() {
        // While unlikely in normal operation (update uses Info tied to a specific record),
        // the `update` method itself doesn't check the public key matches.
        let socket = test_socket();
        let mut record = Record::<PublicKey>::unknown();

        let peer_info_pk1_ts1000 = create_peer_info::<PrivateKey>(10, socket, 1000);
        let peer_info_pk2_ts2000 = create_peer_info::<PrivateKey>(11, socket, 2000);

        assert!(record.update(peer_info_pk1_ts1000.clone()));
        assert!(
            matches!(&record.address, Address::Discovered(info, 0) if peer_info_contents_are_equal(info, &peer_info_pk1_ts1000))
        );

        // Update should succeed based on newer timestamp, even if PK differs (though context matters)
        assert!(
            record.update(peer_info_pk2_ts2000.clone()),
            "Update should succeed based on newer timestamp"
        );
        assert!(
            matches!(&record.address, Address::Discovered(info, 0) if peer_info_contents_are_equal(info, &peer_info_pk2_ts2000))
        );
    }

    #[test]
    fn test_increment_decrement_and_deletable() {
        // Test Unknown (not persistent)
        let mut record_unknown = Record::<PublicKey>::unknown();
        assert!(record_unknown.deletable());
        record_unknown.increment(); // sets = 1
        assert!(!record_unknown.deletable());
        record_unknown.decrement(); // sets = 0
        assert!(record_unknown.deletable());

        // Test Discovered (not persistent)
        let peer_info = create_peer_info::<PrivateKey>(7, test_socket(), 1000);
        let mut record_disc = Record::<PublicKey>::unknown();
        assert!(record_disc.update(peer_info));
        assert!(record_disc.deletable());
        record_disc.increment(); // sets = 1
        assert!(!record_disc.deletable());
        record_disc.decrement(); // sets = 0
        assert!(record_disc.deletable());

        // Test Bootstrapper (persistent)
        let mut record_boot = Record::<PublicKey>::bootstrapper(test_socket());
        assert!(!record_boot.deletable()); // Persistent
        record_boot.increment(); // sets = 1
        assert!(!record_boot.deletable());
        record_boot.decrement(); // sets = 0
        assert!(!record_boot.deletable()); // Still persistent

        // Test Myself (persistent)
        let my_info = create_peer_info::<PrivateKey>(0, test_socket(), 100);
        let mut record_myself = Record::myself(my_info);
        assert!(!record_myself.deletable()); // Persistent
        record_myself.increment(); // sets = 1
        assert!(!record_myself.deletable());
        record_myself.decrement(); // sets = 0
        assert!(!record_myself.deletable()); // Still persistent
    }

    #[test]
    #[should_panic]
    fn test_decrement_panics_at_zero() {
        let mut record = Record::<PublicKey>::unknown();
        assert_eq!(record.sets, 0);
        record.decrement(); // Panics
    }

    #[test]
    fn test_block_behavior_and_persistence() {
        let sample_peer_info = create_peer_info::<PrivateKey>(20, test_socket(), 1000);

        // Block an Unknown record
        let mut record_unknown = Record::<PublicKey>::unknown();
        assert!(!record_unknown.persistent);
        assert!(record_unknown.block()); // Newly blocked
        assert!(record_unknown.blocked());
        assert!(matches!(record_unknown.address, Address::Blocked));
        assert_eq!(record_unknown.status, Status::Inert);
        assert!(!record_unknown.persistent, "Blocking sets persistent=false");
        assert!(!record_unknown.block()); // Already blocked

        // Block a Bootstrapper record (initially persistent)
        let mut record_boot = Record::<PublicKey>::bootstrapper(test_socket());
        assert!(record_boot.persistent);
        assert!(record_boot.block());
        assert!(record_boot.blocked());
        assert!(matches!(record_boot.address, Address::Blocked));
        assert!(!record_boot.persistent, "Blocking sets persistent=false");

        // Block a Discovered record (initially not persistent)
        let mut record_disc = Record::<PublicKey>::unknown();
        assert!(record_disc.update(sample_peer_info.clone()));
        assert!(!record_disc.persistent);
        assert!(record_disc.block());
        assert!(record_disc.blocked());
        assert!(matches!(record_disc.address, Address::Blocked));
        assert!(!record_disc.persistent);

        // Block a Discovered record that came from a Bootstrapper (initially persistent)
        let mut record_disc_from_boot = Record::<PublicKey>::bootstrapper(test_socket());
        assert!(record_disc_from_boot.update(sample_peer_info.clone()));
        assert!(record_disc_from_boot.persistent);
        assert!(record_disc_from_boot.block());
        assert!(record_disc_from_boot.blocked());
        assert!(matches!(record_disc_from_boot.address, Address::Blocked));
        assert!(
            !record_disc_from_boot.persistent,
            "Blocking sets persistent=false"
        );

        // Check status remains unchanged when blocking
        let mut record_reserved = Record::<PublicKey>::unknown();
        assert!(record_reserved.update(sample_peer_info.clone()));
        assert!(record_reserved.reserve());
        assert!(record_reserved.block());
        assert_eq!(record_reserved.status, Status::Reserved);

        let mut record_active = Record::<PublicKey>::unknown();
        assert!(record_active.update(sample_peer_info));
        assert!(record_active.reserve());
        record_active.connect();
        assert!(record_active.block());
        assert_eq!(record_active.status, Status::Active);
    }

    #[test]
    fn test_block_myself_and_already_blocked() {
        let my_info = create_peer_info::<PrivateKey>(0, test_socket(), 100);
        let mut record_myself = Record::myself(my_info.clone());
        assert!(!record_myself.block(), "Cannot block myself");
        assert!(
            matches!(&record_myself.address, Address::Myself(info) if peer_info_contents_are_equal(info, &my_info))
        );

        let mut record_to_be_blocked = Record::<PublicKey>::unknown();
        assert!(record_to_be_blocked.block());
        assert!(
            !record_to_be_blocked.block(),
            "Cannot block already blocked peer"
        );
        assert!(matches!(record_to_be_blocked.address, Address::Blocked));
    }

    #[test]
    fn test_status_transitions_reserve_connect_release() {
        let mut record = Record::<PublicKey>::unknown();

        assert_eq!(record.status, Status::Inert);
        assert!(record.reserve());
        assert_eq!(record.status, Status::Reserved);
        assert!(record.reserved());

        assert!(!record.reserve(), "Cannot re-reserve when Reserved");
        assert_eq!(record.status, Status::Reserved);

        record.connect();
        assert_eq!(record.status, Status::Active);
        assert!(record.reserved()); // reserved() is true for Active too

        assert!(!record.reserve(), "Cannot reserve when Active");
        assert_eq!(record.status, Status::Active);

        record.release(); // Release from Active
        assert_eq!(record.status, Status::Inert);
        assert!(!record.reserved());

        assert!(record.reserve()); // Reserve again
        assert_eq!(record.status, Status::Reserved);
        record.release(); // Release from Reserved
        assert_eq!(record.status, Status::Inert);
    }

    #[test]
    #[should_panic]
    fn test_connect_when_not_reserved_panics_from_inert() {
        let mut record = Record::<PublicKey>::unknown();
        record.connect(); // Should panic
    }

    #[test]
    #[should_panic]
    fn test_connect_when_active_panics() {
        let mut record = Record::<PublicKey>::unknown();
        assert!(record.reserve());
        record.connect();
        record.connect(); // Should panic
    }

    #[test]
    #[should_panic]
    fn test_release_when_inert_panics() {
        let mut record = Record::<PublicKey>::unknown();
        record.release(); // Should panic
    }

    #[test]
    fn test_sharable_logic() {
        let socket = test_socket();
        let peer_info_data = create_peer_info::<PrivateKey>(12, socket, 100);

        // Unknown: Not sharable
        let record_unknown = Record::<PublicKey>::unknown();
        assert!(record_unknown.sharable().is_none());

        // Myself: Sharable
        let record_myself = Record::myself(peer_info_data.clone());
        assert!(compare_optional_peer_info(
            record_myself.sharable().as_ref(),
            &peer_info_data
        ));

        // Bootstrapper (no Info yet): Not sharable
        let record_boot = Record::<PublicKey>::bootstrapper(socket);
        assert!(record_boot.sharable().is_none());

        // Blocked: Not sharable
        let mut record_blocked = Record::<PublicKey>::unknown();
        record_blocked.block();
        assert!(record_blocked.sharable().is_none());

        // Discovered but not Active: Not sharable
        let mut record_disc = Record::<PublicKey>::unknown();
        assert!(record_disc.update(peer_info_data.clone()));
        assert!(record_disc.sharable().is_none()); // Status Inert
        assert!(record_disc.reserve());
        assert!(record_disc.sharable().is_none()); // Status Reserved

        // Discovered and Active: Sharable
        record_disc.connect();
        assert!(compare_optional_peer_info(
            record_disc.sharable().as_ref(),
            &peer_info_data
        ));

        // Released after Active: Not sharable
        record_disc.release();
        assert!(record_disc.sharable().is_none());
    }

    #[test]
    fn test_reserved_status_check() {
        let mut record = Record::<PublicKey>::unknown();
        assert!(!record.reserved()); // Inert
        assert!(record.reserve());
        assert!(record.reserved()); // Reserved
        record.connect();
        assert!(record.reserved()); // Active
        record.release();
        assert!(!record.reserved()); // Inert again
    }

    #[test]
    fn test_dial_failure_and_dial_success() {
        let socket = test_socket();
        let peer_info = create_peer_info::<PrivateKey>(18, socket, 1000);
        let mut record = Record::<PublicKey>::unknown();

        // Cannot fail dial before discovered
        record.dial_failure(socket);
        assert!(matches!(record.address, Address::Unknown));

        // Discover
        assert!(record.update(peer_info));
        assert!(matches!(&record.address, Address::Discovered(_, 0)));

        // Fail dial 1
        record.dial_failure(socket);
        assert!(matches!(&record.address, Address::Discovered(_, 1)));

        // Fail dial 2
        record.dial_failure(socket);
        assert!(matches!(&record.address, Address::Discovered(_, 2)));

        // Fail dial for wrong socket
        record.dial_failure(test_socket2());
        assert!(
            matches!(&record.address, Address::Discovered(_, 2)),
            "Failure count should not change for wrong socket"
        );

        // Success resets failures
        record.dial_success();
        assert!(
            matches!(&record.address, Address::Discovered(_, 0)),
            "Failures should reset"
        );

        // Fail dial again
        record.dial_failure(socket);
        assert!(matches!(&record.address, Address::Discovered(_, 1)));
    }

    #[test]
    fn test_want_logic_with_min_fails() {
        let socket = test_socket();
        let peer_info = create_peer_info::<PrivateKey>(13, socket, 100);
        let min_fails = 2;

        // Unknown and Bootstrapper always want info
        assert!(Record::<PublicKey>::unknown().want(min_fails));
        assert!(Record::<PublicKey>::bootstrapper(socket).want(min_fails));

        // Myself and Blocked never want info
        assert!(!Record::myself(peer_info.clone()).want(min_fails));
        let mut blocked = Record::<PublicKey>::unknown();
        blocked.block();
        assert!(!blocked.want(min_fails));

        let mut record_disc = Record::<PublicKey>::unknown();
        assert!(record_disc.update(peer_info));

        // Status Inert
        assert!(
            !record_disc.want(min_fails),
            "Should not want when fails=0 < min_fails"
        );
        record_disc.dial_failure(socket); // fails = 1
        assert!(
            !record_disc.want(min_fails),
            "Should not want when fails=1 < min_fails"
        );
        record_disc.dial_failure(socket); // fails = 2
        assert!(
            record_disc.want(min_fails),
            "Should want when fails=2 >= min_fails"
        );

        // Status Reserved
        assert!(record_disc.reserve());
        assert!(
            record_disc.want(min_fails),
            "Should still want when Reserved and fails >= min_fails"
        );

        // Status Active
        record_disc.connect();
        assert!(!record_disc.want(min_fails), "Should not want when Active");

        // Status Inert again (after release)
        record_disc.release();
        assert!(record_disc.want(min_fails));

        // Reset failures
        record_disc.dial_success(); // Reset failures
        assert!(
            !record_disc.want(min_fails),
            "Should not want when Inert and fails=0"
        );
        record_disc.dial_failure(socket); // fails = 1
        assert!(!record_disc.want(min_fails));
        record_disc.dial_failure(socket); // fails = 2
        assert!(record_disc.want(min_fails));
    }

    #[test]
    fn test_deletable_logic_detailed() {
        let peer_info = create_peer_info::<PrivateKey>(14, test_socket(), 100);

        // Persistent records are never deletable regardless of sets count
        assert!(!Record::myself(peer_info.clone()).deletable());
        assert!(!Record::<PublicKey>::bootstrapper(test_socket()).deletable());
        let mut record_pers = Record::<PublicKey>::bootstrapper(test_socket());
        assert!(record_pers.update(peer_info));
        assert!(!record_pers.deletable());

        // Non-persistent records depend on sets count and status
        let mut record = Record::<PublicKey>::unknown(); // Not persistent
        assert_eq!(record.sets, 0);
        assert_eq!(record.status, Status::Inert);
        assert!(record.deletable()); // sets = 0, !persistent, Inert

        record.increment(); // sets = 1
        assert!(!record.deletable()); // sets != 0

        assert!(record.reserve()); // status = Reserved
        assert!(!record.deletable()); // status != Inert

        record.connect(); // status = Active
        assert!(!record.deletable()); // status != Inert

        record.release(); // status = Inert
        assert!(!record.deletable()); // sets != 0

        record.decrement(); // sets = 0
        assert!(record.deletable()); // sets = 0, !persistent, Inert

        // Blocking makes a record non-persistent, but deletability still depends on sets/status
        let mut record_blocked = Record::<PublicKey>::bootstrapper(test_socket());
        assert!(record_blocked.persistent);
        record_blocked.increment(); // sets = 1
        assert!(record_blocked.block());
        assert!(!record_blocked.persistent);
        assert!(!record_blocked.deletable()); // sets = 1
        record_blocked.decrement(); // sets = 0
        assert!(record_blocked.deletable()); // sets = 0, !persistent, Inert
    }

    #[test]
    fn test_allowed_logic_detailed() {
        let peer_info = create_peer_info::<PrivateKey>(16, test_socket(), 100);

        // Blocked and Myself are never allowed
        let mut record_blocked = Record::<PublicKey>::unknown();
        record_blocked.block();
        assert!(!record_blocked.allowed());
        assert!(!Record::myself(peer_info.clone()).allowed());

        // Persistent records (Bootstrapper, Myself before blocking) are allowed even with sets=0
        assert!(Record::<PublicKey>::bootstrapper(test_socket()).allowed());
        let mut record_pers = Record::<PublicKey>::bootstrapper(test_socket());
        assert!(record_pers.update(peer_info.clone()));
        assert!(record_pers.allowed());

        // Non-persistent records (Unknown, Discovered) require sets > 0
        let mut record_unknown = Record::<PublicKey>::unknown();
        assert!(!record_unknown.allowed()); // sets = 0, !persistent
        record_unknown.increment(); // sets = 1
        assert!(record_unknown.allowed()); // sets > 0
        record_unknown.decrement(); // sets = 0
        assert!(!record_unknown.allowed());

        let mut record_disc = Record::<PublicKey>::unknown();
        assert!(record_disc.update(peer_info));
        assert!(!record_disc.allowed()); // sets = 0, !persistent
        record_disc.increment(); // sets = 1
        assert!(record_disc.allowed()); // sets > 0
    }
}
