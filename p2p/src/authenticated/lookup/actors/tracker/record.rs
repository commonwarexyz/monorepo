use crate::types::{self, Ingress};
use std::net::IpAddr;

/// Represents information known about a peer's address.
#[derive(Clone, Debug)]
pub enum Address {
    /// Peer is the local node.
    Myself,

    /// Address is provided when peer is registered.
    Known(types::Address),
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
    pub const fn known(addr: types::Address) -> Self {
        Self {
            address: Address::Known(addr),
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
    ///
    /// Returns `true` if the address was changed, `false` if unchanged or self.
    pub fn update(&mut self, addr: types::Address) -> bool {
        match &mut self.address {
            Address::Myself => false,
            Address::Known(existing) => {
                if *existing == addr {
                    return false;
                }
                *existing = addr;
                true
            }
        }
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
        if matches!(self.address, Address::Myself) {
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

    /// Returns `true` if this peer can be blocked.
    ///
    /// Only `Myself` cannot be blocked. Actual blocked status is tracked
    /// by the Directory via PrioritySet.
    pub const fn is_blockable(&self) -> bool {
        !matches!(self.address, Address::Myself)
    }

    /// Returns the number of peer sets this peer is part of.
    pub const fn sets(&self) -> usize {
        self.sets
    }

    /// Returns `true` if the record is dialable.
    ///
    /// A record is dialable if:
    /// - We have a known address of the peer
    /// - It is not ourselves
    /// - We are not already connected or reserved
    /// - The ingress address is allowed (DNS enabled, Socket IP is global or private IPs allowed)
    pub fn dialable(&self, allow_private_ips: bool, allow_dns: bool) -> bool {
        if self.status != Status::Inert {
            return false;
        }
        let ingress = match &self.address {
            Address::Known(addr) => addr.ingress(),
            Address::Myself => return false,
        };
        ingress.is_valid(allow_private_ips, allow_dns)
    }

    /// Returns `true` if this peer is acceptable (can accept an incoming connection from them).
    ///
    /// A peer is acceptable if:
    /// - The peer is eligible (in a peer set, not ourselves)
    /// - The source IP matches the expected egress IP for this peer (if not bypass_ip_check)
    /// - We are not already connected or reserved
    pub fn acceptable(&self, source_ip: IpAddr, bypass_ip_check: bool) -> bool {
        if !self.eligible() || self.status != Status::Inert {
            return false;
        }
        if bypass_ip_check {
            return true;
        }
        match &self.address {
            Address::Known(addr) => addr.egress_ip() == source_ip,
            Address::Myself => false,
        }
    }

    /// Return the ingress address for dialing, if known.
    pub fn ingress(&self) -> Option<Ingress> {
        match &self.address {
            Address::Myself => None,
            Address::Known(addr) => Some(addr.ingress()),
        }
    }

    /// Return the egress IP for filtering, if known.
    pub const fn egress_ip(&self) -> Option<IpAddr> {
        match &self.address {
            Address::Myself => None,
            Address::Known(addr) => Some(addr.egress_ip()),
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

    /// Returns `true` if this peer is eligible for connection.
    ///
    /// A peer is eligible if:
    /// - It is not ourselves
    /// - It is part of at least one peer set (or is persistent)
    pub const fn eligible(&self) -> bool {
        match &self.address {
            Address::Myself => false,
            Address::Known(_) => self.sets > 0 || self.persistent,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn test_socket() -> SocketAddr {
        SocketAddr::from(([54, 12, 1, 9], 8080))
    }

    fn test_address() -> types::Address {
        types::Address::Symmetric(test_socket())
    }

    #[test]
    fn test_myself_initial_state() {
        let record = Record::myself();
        assert!(matches!(record.address, Address::Myself));
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.sets, 0);
        assert!(record.persistent);
        assert!(record.ingress().is_none());
        assert!(!record.is_blockable());
        assert!(!record.reserved());
        assert!(!record.deletable());
        assert!(!record.eligible());
    }

    #[test]
    fn test_known_initial_state() {
        let record = Record::known(test_address());
        assert!(matches!(record.address, Address::Known(_)));
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.sets, 0);
        assert!(!record.persistent);
        assert!(record.ingress().is_some());
        assert!(record.is_blockable());
        assert!(!record.reserved());
        assert!(record.deletable());
        assert!(!record.eligible());
    }

    #[test]
    fn test_is_blockable() {
        // Myself is not blockable
        let record_myself = Record::myself();
        assert!(!record_myself.is_blockable());

        // Known peers are blockable
        let record_known = Record::known(test_address());
        assert!(record_known.is_blockable());
    }

    #[test]
    fn test_increment_decrement_and_deletable() {
        let mut record_known = Record::known(test_address());
        assert!(record_known.deletable());
        record_known.increment();
        assert!(!record_known.deletable());
        record_known.decrement();
        assert!(record_known.deletable());

        let mut record_myself = Record::myself();
        assert!(!record_myself.deletable());
        record_myself.increment();
        assert!(!record_myself.deletable());
        record_myself.decrement();
        assert!(!record_myself.deletable());
    }

    #[test]
    #[should_panic]
    fn test_decrement_panics_at_zero() {
        let mut record = Record::known(test_address());
        assert_eq!(record.sets, 0);
        record.decrement();
    }

    #[test]
    fn test_status_transitions_reserve_connect_release() {
        let mut record = Record::known(test_address());

        assert_eq!(record.status, Status::Inert);
        assert!(record.reserve());
        assert_eq!(record.status, Status::Reserved);
        assert!(record.reserved());

        assert!(!record.reserve(), "Cannot re-reserve when Reserved");
        assert_eq!(record.status, Status::Reserved);

        record.connect();
        assert_eq!(record.status, Status::Active);
        assert!(record.reserved());

        assert!(!record.reserve(), "Cannot reserve when Active");
        assert_eq!(record.status, Status::Active);

        record.release();
        assert_eq!(record.status, Status::Inert);
        assert!(!record.reserved());

        assert!(record.reserve());
        assert_eq!(record.status, Status::Reserved);
        record.release();
        assert_eq!(record.status, Status::Inert);
    }

    #[test]
    #[should_panic]
    fn test_connect_when_not_reserved_panics_from_inert() {
        let mut record = Record::known(test_address());
        record.connect();
    }

    #[test]
    #[should_panic]
    fn test_connect_when_active_panics() {
        let mut record = Record::known(test_address());
        assert!(record.reserve());
        record.connect();
        record.connect();
    }

    #[test]
    #[should_panic]
    fn test_release_when_inert_panics() {
        let mut record = Record::known(test_address());
        record.release();
    }

    #[test]
    fn test_reserved_status_check() {
        let mut record = Record::known(test_address());
        assert!(!record.reserved());
        assert!(record.reserve());
        assert!(record.reserved());
        record.connect();
        assert!(record.reserved());
        record.release();
        assert!(!record.reserved());
    }

    #[test]
    fn test_deletable_logic_detailed() {
        assert!(!Record::myself().deletable());

        let mut record = Record::known(test_address());
        assert_eq!(record.sets, 0);
        assert_eq!(record.status, Status::Inert);
        assert!(record.deletable());

        record.increment();
        assert!(!record.deletable());

        assert!(record.reserve());
        assert!(!record.deletable());

        record.connect();
        assert!(!record.deletable());

        record.release();
        assert!(!record.deletable());

        record.decrement();
        assert!(record.deletable());
    }

    #[test]
    fn test_eligible_logic() {
        // Myself is never eligible
        assert!(!Record::myself().eligible());

        // Known records are only eligible when in a peer set
        let mut record_known = Record::known(test_address());
        assert!(!record_known.eligible(), "Not eligible when sets=0");
        record_known.increment();
        assert!(record_known.eligible(), "Eligible when sets>0");
        record_known.decrement();
        assert!(!record_known.eligible(), "Not eligible when sets=0 again");
    }

    #[test]
    fn test_acceptable_checks_eligibility_status_and_ip() {
        use std::net::IpAddr;

        let egress_ip: IpAddr = [8, 8, 8, 8].into();
        let wrong_ip: IpAddr = [1, 2, 3, 4].into();
        let public_socket = SocketAddr::from(([8, 8, 8, 8], 8080));

        // Eligible, Inert, and correct IP - acceptable
        let mut record = Record::known(types::Address::Symmetric(public_socket));
        record.increment();
        assert!(
            record.acceptable(egress_ip, false),
            "Eligible, Inert, correct IP is acceptable"
        );

        // Correct everything but wrong IP - not acceptable
        assert!(
            !record.acceptable(wrong_ip, false),
            "Not acceptable when IP doesn't match"
        );

        // Not eligible (sets=0) - not acceptable
        let record_not_eligible = Record::known(types::Address::Symmetric(public_socket));
        assert!(
            !record_not_eligible.acceptable(egress_ip, false),
            "Not acceptable when not eligible"
        );

        // Already reserved - not acceptable
        let mut record_reserved = Record::known(types::Address::Symmetric(public_socket));
        record_reserved.increment();
        record_reserved.reserve();
        assert!(
            !record_reserved.acceptable(egress_ip, false),
            "Not acceptable when reserved"
        );

        // Already connected - not acceptable
        let mut record_connected = Record::known(types::Address::Symmetric(public_socket));
        record_connected.increment();
        record_connected.reserve();
        record_connected.connect();
        assert!(
            !record_connected.acceptable(egress_ip, false),
            "Not acceptable when connected"
        );
    }

    #[test]
    fn test_acceptable_bypass_ip_check() {
        let egress_ip: IpAddr = [8, 8, 8, 8].into();
        let wrong_ip: IpAddr = [1, 2, 3, 4].into();
        let public_socket = SocketAddr::from(([8, 8, 8, 8], 8080));

        // With bypass_ip_check=true, accepts even with wrong IP (skips IP check)
        let mut record = Record::known(types::Address::Symmetric(public_socket));
        record.increment();
        assert!(
            record.acceptable(wrong_ip, true),
            "Acceptable with wrong IP when bypass_ip_check=true"
        );

        // Still requires eligible (sets > 0), even with bypass_ip_check=true
        let record_not_eligible = Record::known(types::Address::Symmetric(public_socket));
        assert!(
            !record_not_eligible.acceptable(egress_ip, true),
            "Not acceptable when not eligible (sets=0), even with bypass_ip_check=true"
        );

        // Still not acceptable when reserved
        let mut record_reserved = Record::known(types::Address::Symmetric(public_socket));
        record_reserved.increment();
        record_reserved.reserve();
        assert!(
            !record_reserved.acceptable(egress_ip, true),
            "Not acceptable when reserved"
        );

        // Still not acceptable when connected
        let mut record_connected = Record::known(types::Address::Symmetric(public_socket));
        record_connected.increment();
        record_connected.reserve();
        record_connected.connect();
        assert!(
            !record_connected.acceptable(egress_ip, true),
            "Not acceptable when connected"
        );

        // Still not acceptable when myself
        let record_myself = Record::myself();
        assert!(
            !record_myself.acceptable(egress_ip, true),
            "Not acceptable when myself"
        );
    }

    #[test]
    fn test_dialable_checks_ingress_ip() {
        use std::net::IpAddr;
        use Ingress;

        // Public ingress, public egress - dialable
        let public_socket = SocketAddr::from(([8, 8, 8, 8], 8080));
        let record_public = Record::known(types::Address::Symmetric(public_socket));
        assert!(record_public.dialable(false, true));

        // Private ingress (Socket), public egress - NOT dialable when allow_private_ips=false
        let private_ingress =
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let public_egress = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 9090);
        let asymmetric_private_ingress = types::Address::Asymmetric {
            ingress: Ingress::Socket(private_ingress),
            egress: public_egress,
        };
        let record_private_ingress = Record::known(asymmetric_private_ingress);
        assert!(
            !record_private_ingress.dialable(false, true),
            "Should NOT be dialable when ingress Socket IP is private"
        );
        assert!(
            record_private_ingress.dialable(true, true),
            "Should be dialable when allow_private_ips=true"
        );

        // Public ingress (Socket), private egress - dialable (egress not checked for dialing)
        let public_ingress = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 8080);
        let private_egress =
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 9090);
        let asymmetric_private_egress = types::Address::Asymmetric {
            ingress: Ingress::Socket(public_ingress),
            egress: private_egress,
        };
        let record_private_egress = Record::known(asymmetric_private_egress);
        assert!(
            record_private_egress.dialable(false, true),
            "Should be dialable - egress IP is not checked for dialing"
        );

        // DNS ingress (no IP to check) - dialable (DNS private check happens at dial time)
        let dns_ingress = types::Address::Asymmetric {
            ingress: Ingress::Dns {
                host: commonware_utils::hostname!("example.com"),
                port: 8080,
            },
            egress: public_egress,
        };
        let record_dns = Record::known(dns_ingress);
        assert!(
            record_dns.dialable(false, true),
            "DNS ingress should be dialable (private check happens at resolution)"
        );
        assert!(
            !record_dns.dialable(false, false),
            "DNS ingress should NOT be dialable when allow_dns=false"
        );
    }
}
