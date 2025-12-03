use commonware_utils::IpAddrExt;
use std::net::SocketAddr;

/// Represents information known about a peer's address.
#[derive(Clone, Debug)]
pub enum Address {
    /// Peer is the local node.
    Myself,

    /// Address is provided when peer is registered.
    Known(SocketAddr),

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

    /// Create a new record with a known address.
    pub const fn known(socket: SocketAddr) -> Self {
        Self {
            address: Address::Known(socket),
            status: Status::Inert,
            sets: 0,
            persistent: false,
        }
    }

    /// Create a new record with the local node's information.
    pub const fn myself() -> Self {
        Self {
            address: Address::Myself,
            status: Status::Inert,
            sets: 0,
            persistent: true,
        }
    }

    // ---------- Setters ----------

    /// Update the record with a new address.
    pub const fn update(&mut self, socket: SocketAddr) {
        if matches!(self.address, Address::Myself | Address::Blocked) {
            return;
        }
        self.address = Address::Known(socket);
    }

    /// Attempt to mark the peer as blocked.
    ///
    /// Returns `true` if the peer was newly blocked.
    /// Returns `false` if the peer was already blocked or is the local node (unblockable).
    pub const fn block(&mut self) -> bool {
        if matches!(self.address, Address::Blocked | Address::Myself) {
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
    /// - The peer is not the local node
    pub const fn decrement(&mut self) {
        self.sets = self.sets.checked_sub(1).unwrap();
    }

    /// Attempt to reserve the peer for connection.
    ///
    /// Returns `true` if the reservation was successful, `false` otherwise.
    pub const fn reserve(&mut self) -> bool {
        if matches!(self.address, Address::Blocked | Address::Myself) {
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
    #[allow(unstable_name_collisions)]
    pub fn dialable(&self, allow_private_ips: bool) -> bool {
        match self.address {
            Address::Known(addr) => {
                self.status == Status::Inert && (allow_private_ips || addr.ip().is_global())
            }
            _ => false,
        }
    }

    /// Returns `true` if the peer is listenable.
    ///
    /// A record is listenable if:
    /// - The peer is allowed
    /// - We are not already connected
    pub fn listenable(&self, allow_private_ips: bool) -> bool {
        self.allowed(allow_private_ips) && self.status == Status::Inert
    }

    /// Return the socket of the peer, if known.
    pub const fn socket(&self) -> Option<SocketAddr> {
        match &self.address {
            Address::Myself => None,
            Address::Known(addr) => Some(*addr),
            Address::Blocked => None,
        }
    }

    /// Returns `true` if the peer is reserved (or active).
    /// This is used to determine if we should attempt to reserve the peer again.
    pub const fn reserved(&self) -> bool {
        matches!(self.status, Status::Reserved | Status::Active)
    }

    /// Returns `true` if the record can safely be deleted.
    pub const fn deletable(&self) -> bool {
        self.sets == 0 && !self.persistent && matches!(self.status, Status::Inert)
    }

    /// Returns `true` if the record is allowed to be used for connection.
    #[allow(unstable_name_collisions)]
    pub fn allowed(&self, allow_private_ips: bool) -> bool {
        match self.address {
            Address::Blocked | Address::Myself => false,
            Address::Known(addr) => {
                (self.sets > 0 || self.persistent) && (allow_private_ips || addr.ip().is_global())
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    // Common test sockets
    fn test_socket() -> SocketAddr {
        SocketAddr::from(([54, 12, 1, 9], 8080))
    }

    #[test]
    fn test_myself_initial_state() {
        let record = Record::myself();
        assert!(matches!(record.address, Address::Myself));
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.sets, 0);
        assert!(record.persistent);
        assert_eq!(record.socket(), None);
        assert!(!record.blocked());
        assert!(!record.reserved());
        assert!(!record.deletable());
        assert!(!record.allowed(false));
    }

    #[test]
    fn test_myself_blocked_to_known() {
        let mut record = Record::myself();
        record.block();
        assert!(!record.blocked(), "Can't block myself");
    }

    #[test]
    fn test_increment_decrement_and_deletable() {
        // Test Known (not persistent)
        let socket = test_socket();
        let mut record_known = Record::known(socket);
        assert!(record_known.deletable());
        record_known.increment(); // sets = 1
        assert!(!record_known.deletable());
        record_known.decrement(); // sets = 0
        assert!(record_known.deletable());

        // Test Myself (persistent)
        let mut record_myself = Record::myself();
        assert!(!record_myself.deletable()); // Persistent
        record_myself.increment(); // sets = 1
        assert!(!record_myself.deletable());
        record_myself.decrement(); // sets = 0
        assert!(!record_myself.deletable()); // Still persistent
    }

    #[test]
    #[should_panic]
    fn test_decrement_panics_at_zero() {
        let mut record = Record::known(test_socket());
        assert_eq!(record.sets, 0);
        record.decrement(); // Panics
    }

    #[test]
    fn test_block_behavior_and_persistence() {
        let socket = test_socket();

        // Block a Known record (initially not persistent)
        let mut record_known = Record::known(socket);
        assert!(!record_known.persistent);
        assert!(record_known.block());
        assert!(record_known.blocked());
        assert!(matches!(record_known.address, Address::Blocked));
        assert!(!record_known.persistent);

        // Check status remains unchanged when blocking
        let mut record_reserved = Record::known(socket);
        assert!(record_reserved.reserve());
        assert!(record_reserved.block());
        assert_eq!(record_reserved.status, Status::Reserved);

        let mut record_active = Record::known(socket);
        assert!(record_active.reserve());
        record_active.connect();
        assert!(record_active.block());
        assert_eq!(record_active.status, Status::Active);
    }

    #[test]
    fn test_block_myself_and_already_blocked() {
        let mut record_myself = Record::myself();
        assert!(!record_myself.block(), "Cannot block myself");
        assert!(matches!(&record_myself.address, Address::Myself));

        let mut record_to_be_blocked = Record::known(test_socket());
        assert!(record_to_be_blocked.block());
        assert!(
            !record_to_be_blocked.block(),
            "Cannot block already blocked peer"
        );
        assert!(matches!(record_to_be_blocked.address, Address::Blocked));
    }

    #[test]
    fn test_status_transitions_reserve_connect_release() {
        let mut record = Record::known(test_socket());

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
        let mut record = Record::known(test_socket());
        record.connect(); // Should panic
    }

    #[test]
    #[should_panic]
    fn test_connect_when_active_panics() {
        let mut record = Record::known(test_socket());
        assert!(record.reserve());
        record.connect();
        record.connect(); // Should panic
    }

    #[test]
    #[should_panic]
    fn test_release_when_inert_panics() {
        let mut record = Record::known(test_socket());
        record.release(); // Should panic
    }

    #[test]
    fn test_reserved_status_check() {
        let mut record = Record::known(test_socket());
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
        let socket = test_socket();

        // Persistent records are never deletable regardless of sets count
        assert!(!Record::myself().deletable());

        // Non-persistent records depend on sets count and status
        let mut record = Record::known(socket); // Not persistent
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
    }

    #[test]
    fn test_allowed_logic_detailed() {
        let socket = test_socket();

        // Blocked and Myself are never allowed
        let mut record_blocked = Record::known(socket);
        record_blocked.block();
        assert!(!record_blocked.allowed(false));
        assert!(!Record::myself().allowed(false));

        // Non-persistent records (Unknown, Known) require sets > 0
        let mut record_unknown = Record::known(socket);
        assert!(!record_unknown.allowed(false)); // sets = 0, !persistent
        assert!(!record_unknown.allowed(true)); // sets = 0, !persistent
        record_unknown.increment(); // sets = 1
        assert!(record_unknown.allowed(false)); // sets > 0
        assert!(record_unknown.allowed(true)); // sets > 0, allow_private_ips doesn't matter
        record_unknown.decrement(); // sets = 0
        assert!(!record_unknown.allowed(false));
        assert!(!record_unknown.allowed(true));

        let mut record_known = Record::known(socket);
        assert!(!record_known.allowed(false)); // sets = 0, !persistent
        assert!(!record_known.allowed(true)); // sets = 0, !persistent
        record_known.increment(); // sets = 1
        assert!(record_known.allowed(false)); // sets > 0
        assert!(record_known.allowed(true)); // sets > 0, allow_private_ips doesn't matter

        // Test private IPs only allowed if allow_private_ips is true
        let private_socket = SocketAddr::from(([10, 0, 0, 1], 8080));
        let mut record_private = Record::known(private_socket);
        record_private.increment(); // sets = 1
        assert!(
            !record_private.allowed(false),
            "Private IPs not allowed by default"
        );
        assert!(
            record_private.allowed(true),
            "Private IPs allowed when flag is true"
        );
    }
}
