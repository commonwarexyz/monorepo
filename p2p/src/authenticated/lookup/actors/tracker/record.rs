use std::net::SocketAddr;

/// Represents information known about a peer's address.
#[derive(Clone, Debug)]
pub enum Address {
    /// Peer address is not yet known.
    /// Can be upgraded to `Known`.
    Unknown,

    /// Peer is the local node.
    Myself(SocketAddr),

    /// Address is provided during initialization.
    Known(SocketAddr),

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
pub struct Record {
    /// Address state of the peer.
    address: Address,

    /// Connection status of the peer.
    status: Status,

    /// Number of peer sets this peer is part of.
    sets: usize,

    /// If `true`, the record should persist even if the peer is not part of any peer sets.
    persistent: bool,
}

impl Record {
    // ---------- Constructors ----------

    /// Create a new record with an unknown address.
    pub fn unknown() -> Self {
        Record {
            address: Address::Unknown,
            status: Status::Inert,
            sets: 0,
            persistent: false,
        }
    }

    /// Create a new record with the local node's information.
    pub fn myself(socket: SocketAddr) -> Self {
        Record {
            address: Address::Myself(socket),
            status: Status::Inert,
            sets: 0,
            persistent: true,
        }
    }

    /// Create a new record with a bootstrapper address.
    pub fn bootstrapper(socket: SocketAddr) -> Self {
        Record {
            address: Address::Known(socket),
            status: Status::Inert,
            sets: 0,
            persistent: true,
        }
    }

    // ---------- Setters ----------

    pub fn update_address(&mut self, address: SocketAddr) {
        // TODO: what should we do if this peer is blocked?
        self.address = Address::Known(address);
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
    pub fn increment(&mut self) {
        self.sets = self.sets.checked_add(1).unwrap();
    }

    /// Decrease the count of peer sets this peer is part of.
    ///
    /// Returns `true` if the record can be deleted. That is:
    /// - The count reaches zero
    /// - The peer is not a bootstrapper or the local node
    pub fn decrement(&mut self) {
        self.sets = self.sets.checked_sub(1).unwrap();
    }

    /// Attempt to reserve the peer for connection.
    ///
    /// Returns `true` if the reservation was successful, `false` otherwise.
    pub fn reserve(&mut self) -> bool {
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
    /// The peer must have the status [`Status::Reserved`].
    pub fn connect(&mut self) {
        assert!(matches!(self.status, Status::Reserved));
        self.status = Status::Active;
    }

    /// Releases any reservation on the peer.
    pub fn release(&mut self) {
        assert!(self.status != Status::Inert, "Cannot release an Inert peer");
        self.status = Status::Inert;
    }

    // ---------- Getters ----------

    /// Returns `true` if the record is blocked.
    pub fn blocked(&self) -> bool {
        matches!(self.address, Address::Blocked)
    }

    /// Returns `true` if the record is dialable.
    ///
    /// A record is dialable if:
    /// - We have the socket address of the peer
    /// - It is not ourselves
    /// - We are not already connected
    pub fn dialable(&self) -> bool {
        self.status == Status::Inert && matches!(self.address, Address::Known(_))
    }

    /// Return the socket of the peer, if known.
    pub fn socket(&self) -> Option<SocketAddr> {
        match &self.address {
            Address::Unknown => None,
            Address::Myself(addr) => Some(*addr),
            Address::Known(addr) => Some(*addr),
            Address::Blocked => None,
        }
    }

    /// Returns `true` if the peer is reserved (or active).
    /// This is used to determine if we should attempt to reserve the peer again.
    pub fn reserved(&self) -> bool {
        matches!(self.status, Status::Reserved | Status::Active)
    }

    /// Returns `true` if the record can safely be deleted.
    pub fn deletable(&self) -> bool {
        self.sets == 0 && !self.persistent && matches!(self.status, Status::Inert)
    }

    /// Returns `true` if the record is allowed to be used for connection.
    pub fn allowed(&self) -> bool {
        match self.address {
            Address::Blocked | Address::Myself(_) => false,
            Address::Known(_) | Address::Unknown => self.sets > 0 || self.persistent,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::peer_info::PeerInfo;
    use commonware_codec::Encode;
    use commonware_cryptography::{secp256r1, PrivateKeyExt};
    use std::net::SocketAddr;

    // Helper function to create signed peer info for testing
    fn create_peer_info<S>(
        signer_seed: u64,
        socket: SocketAddr,
        timestamp: u64,
    ) -> PeerInfo<S::PublicKey>
    where
        S: PrivateKeyExt,
    {
        let signer = S::from_seed(signer_seed);
        let signature = signer.sign(None, &(socket, timestamp).encode());
        PeerInfo {
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

    #[test]
    fn test_unknown_initial_state() {
        let record = Record::unknown();
        assert!(matches!(record.address, Address::Unknown));
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.sets, 0);
        assert!(!record.persistent);
        assert_eq!(record.socket(), None);
        assert!(!record.blocked());
        assert!(!record.reserved());
        assert!(record.deletable());
        assert!(!record.allowed());
    }

    #[test]
    fn test_myself_initial_state() {
        let my_info = create_peer_info::<secp256r1::PrivateKey>(0, test_socket(), 100);
        let my_addr = test_socket();
        let record = Record::myself(my_addr);
        match record.address {
            Address::Myself(addr) => assert_eq!(addr, my_addr),
            _ => panic!("Expected Address::Myself"),
        }
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.sets, 0);
        assert!(record.persistent);
        assert_eq!(record.socket(), Some(my_info.socket),);
        assert!(!record.blocked());
        assert!(!record.reserved());
        assert!(!record.deletable());
        assert!(!record.allowed());
    }

    #[test]
    fn test_bootstrapper_initial_state() {
        let socket = test_socket();
        let record = Record::bootstrapper(socket);
        assert!(matches!(record.address, Address::Known(s) if s == socket));
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.sets, 0);
        assert!(record.persistent);
        assert_eq!(record.socket(), Some(socket));
        assert!(!record.blocked());
        assert!(!record.reserved());
        assert!(!record.deletable());
        assert!(record.allowed());
    }

    #[test]
    fn test_unknown_to_known() {
        let socket = test_socket();
        let mut record = Record::unknown();

        record.update_address(socket);
        assert_eq!(record.socket(), Some(socket));
        assert!(matches!(&record.address, Address::Known(got_socket) if *got_socket == socket));
        assert!(!record.persistent);
    }

    #[test]
    fn test_bootstrapper_to_known() {
        let socket = test_socket();
        let mut record = Record::bootstrapper(socket);

        assert!(record.persistent, "Should start as persistent");
        record.update_address(socket);
        assert_eq!(record.socket(), Some(socket));
        assert!(matches!(&record.address, Address::Known(got_socket) if *got_socket == socket));
        assert!(record.persistent, "Should remain persistent after update");
    }

    #[test]
    fn test_myself_blocked_to_known() {
        let addr = test_socket();
        let mut record = Record::myself(addr);
        record.block();
        assert!(!record.blocked(), "Can't block myself");
    }

    #[test]
    fn test_other_blocked_to_known() {
        let socket = test_socket();
        let mut record = Record::unknown();
        record.update_address(socket);
        assert!(matches!(&record.address, Address::Known(s) if *s == socket));

        // Block the record
        assert!(record.block());
        assert!(record.blocked());
        assert!(matches!(record.address, Address::Blocked));

        // Unblock and check it goes back to Known
        record.update_address(socket);
        assert_eq!(record.socket(), Some(socket));
        assert!(matches!(&record.address, Address::Known(s) if *s == socket));
    }

    #[test]
    fn test_increment_decrement_and_deletable() {
        // Test Unknown (not persistent)
        let mut record_unknown = Record::unknown();
        assert!(record_unknown.deletable());
        record_unknown.increment(); // sets = 1
        assert!(!record_unknown.deletable());
        record_unknown.decrement(); // sets = 0
        assert!(record_unknown.deletable());

        // Test Known (not persistent)
        let addr = test_socket();
        let mut record_disc = Record::unknown();
        record_disc.update_address(addr);
        assert!(record_disc.deletable());
        record_disc.increment(); // sets = 1
        assert!(!record_disc.deletable());
        record_disc.decrement(); // sets = 0
        assert!(record_disc.deletable());

        // Test Bootstrapper (persistent)
        let mut record_boot = Record::bootstrapper(addr);
        assert!(!record_boot.deletable()); // Persistent
        record_boot.increment(); // sets = 1
        assert!(!record_boot.deletable());
        record_boot.decrement(); // sets = 0
        assert!(!record_boot.deletable()); // Still persistent

        // Test Myself (persistent)
        let mut record_myself = Record::myself(addr);
        assert!(!record_myself.deletable()); // Persistent
        record_myself.increment(); // sets = 1
        assert!(!record_myself.deletable());
        record_myself.decrement(); // sets = 0
        assert!(!record_myself.deletable()); // Still persistent
    }

    #[test]
    #[should_panic]
    fn test_decrement_panics_at_zero() {
        let mut record = Record::unknown();
        assert_eq!(record.sets, 0);
        record.decrement(); // Panics
    }

    #[test]
    fn test_block_behavior_and_persistence() {
        let addr = test_socket();

        // Block an Unknown record
        let mut record_unknown = Record::unknown();
        assert!(!record_unknown.persistent);
        assert!(record_unknown.block()); // Newly blocked
        assert!(record_unknown.blocked());
        assert!(matches!(record_unknown.address, Address::Blocked));
        assert_eq!(record_unknown.status, Status::Inert);
        assert!(!record_unknown.persistent, "Blocking sets persistent=false");
        assert!(!record_unknown.block()); // Already blocked

        // Block a Bootstrapper record (initially persistent)
        let mut record_boot = Record::bootstrapper(test_socket());
        assert!(record_boot.persistent);
        assert!(record_boot.block());
        assert!(record_boot.blocked());
        assert!(matches!(record_boot.address, Address::Blocked));
        assert!(!record_boot.persistent, "Blocking sets persistent=false");

        // Block a Known record (initially not persistent)
        let mut record_disc = Record::unknown();
        record_disc.update_address(addr);
        assert!(!record_disc.persistent);
        assert!(record_disc.block());
        assert!(record_disc.blocked());
        assert!(matches!(record_disc.address, Address::Blocked));
        assert!(!record_disc.persistent);

        // Block a Known record that came from a Bootstrapper (initially persistent)
        let mut record_disc_from_boot = Record::bootstrapper(addr);
        record_disc_from_boot.update_address(addr);
        assert!(record_disc_from_boot.persistent);
        assert!(record_disc_from_boot.block());
        assert!(record_disc_from_boot.blocked());
        assert!(matches!(record_disc_from_boot.address, Address::Blocked));
        assert!(
            !record_disc_from_boot.persistent,
            "Blocking sets persistent=false"
        );

        // Check status remains unchanged when blocking
        let mut record_reserved = Record::unknown();
        record_reserved.update_address(addr);
        assert!(record_reserved.reserve());
        assert!(record_reserved.block());
        assert_eq!(record_reserved.status, Status::Reserved);

        let mut record_active = Record::unknown();
        record_active.update_address(addr);
        assert!(record_active.reserve());
        record_active.connect();
        assert!(record_active.block());
        assert_eq!(record_active.status, Status::Active);
    }

    #[test]
    fn test_block_myself_and_already_blocked() {
        let addr = test_socket();
        let mut record_myself = Record::myself(addr);
        assert!(!record_myself.block(), "Cannot block myself");
        assert!(matches!(&record_myself.address, Address::Myself(got_addr) if *got_addr == addr));

        let mut record_to_be_blocked = Record::unknown();
        assert!(record_to_be_blocked.block());
        assert!(
            !record_to_be_blocked.block(),
            "Cannot block already blocked peer"
        );
        assert!(matches!(record_to_be_blocked.address, Address::Blocked));
    }

    #[test]
    fn test_status_transitions_reserve_connect_release() {
        let mut record = Record::unknown();

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
        let mut record = Record::unknown();
        record.connect(); // Should panic
    }

    #[test]
    #[should_panic]
    fn test_connect_when_active_panics() {
        let mut record = Record::unknown();
        assert!(record.reserve());
        record.connect();
        record.connect(); // Should panic
    }

    #[test]
    #[should_panic]
    fn test_release_when_inert_panics() {
        let mut record = Record::unknown();
        record.release(); // Should panic
    }

    #[test]
    fn test_reserved_status_check() {
        let mut record = Record::unknown();
        assert!(!record.reserved()); // Inert
        assert!(record.reserve());
        assert!(record.reserved()); // Reserved
        record.connect();
        assert!(record.reserved()); // Active
        record.release();
        assert!(!record.reserved()); // Inert again
    }

    #[test]
    fn test_deletable_logic_detailed() {
        let addr = test_socket();

        // Persistent records are never deletable regardless of sets count
        assert!(!Record::myself(addr).deletable());
        assert!(!Record::bootstrapper(test_socket()).deletable());
        let mut record_pers = Record::bootstrapper(test_socket());
        record_pers.update_address(addr.clone());
        assert!(!record_pers.deletable());

        // Non-persistent records depend on sets count and status
        let mut record = Record::unknown(); // Not persistent
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
        let mut record_blocked = Record::bootstrapper(test_socket());
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
        let addr = test_socket();

        // Blocked and Myself are never allowed
        let mut record_blocked = Record::unknown();
        record_blocked.block();
        assert!(!record_blocked.allowed());
        assert!(!Record::myself(addr).allowed());

        // Persistent records (Bootstrapper, Myself before blocking) are allowed even with sets=0
        assert!(Record::bootstrapper(test_socket()).allowed());
        let mut record_pers = Record::bootstrapper(test_socket());
        record_pers.update_address(addr);
        assert!(record_pers.allowed());

        // Non-persistent records (Unknown, Discovered) require sets > 0
        let mut record_unknown = Record::unknown();
        assert!(!record_unknown.allowed()); // sets = 0, !persistent
        record_unknown.increment(); // sets = 1
        assert!(record_unknown.allowed()); // sets > 0
        record_unknown.decrement(); // sets = 0
        assert!(!record_unknown.allowed());

        let mut record_known = Record::unknown();
        record_known.update_address(addr);
        assert!(!record_known.allowed()); // sets = 0, !persistent
        record_known.increment(); // sets = 1
        assert!(record_known.allowed()); // sets > 0
    }
}
