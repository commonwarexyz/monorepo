use crate::{
    authenticated::dialing::{DialStatus, ReserveResult},
    types::{self, Ingress},
};
use commonware_runtime::Clock;
use commonware_utils::SystemTimeExt;
use rand::Rng;
use std::{
    net::IpAddr,
    time::{Duration, SystemTime},
};

/// Represents information known about a peer's address.
#[derive(Clone, Debug)]
pub enum Address {
    /// Peer is the local node.
    Myself,

    /// Peer may dial us from a registered source IP when not currently tracked.
    External(IpAddr),

    /// Address is provided when peer is tracked in a peer set.
    Known(types::Address),

    /// Peer is currently tracked, but also has an external fallback source IP.
    KnownExternal {
        address: types::Address,
        source_ip: IpAddr,
    },
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

    /// The earliest time we are willing to reserve this peer again.
    next_reservable_at: SystemTime,

    /// The earliest time we are willing to dial this peer.
    next_dial_at: SystemTime,
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
            next_reservable_at: SystemTime::UNIX_EPOCH,
            next_dial_at: SystemTime::UNIX_EPOCH,
        }
    }

    /// Create a new record with the local node's information.
    pub const fn myself() -> Self {
        Self {
            address: Address::Myself,
            status: Status::Inert,
            sets: 0,
            persistent: true,
            next_reservable_at: SystemTime::UNIX_EPOCH,
            next_dial_at: SystemTime::UNIX_EPOCH,
        }
    }

    /// Create a new record for an external fallback peer.
    pub const fn external(source_ip: IpAddr) -> Self {
        Self {
            address: Address::External(source_ip),
            status: Status::Inert,
            sets: 0,
            persistent: true,
            next_reservable_at: SystemTime::UNIX_EPOCH,
            next_dial_at: SystemTime::UNIX_EPOCH,
        }
    }

    // ---------- Setters ----------

    /// Update the tracked address for this record.
    ///
    /// Returns `true` if the tracked address changed and any live connection
    /// should be replaced immediately.
    pub fn update(&mut self, addr: types::Address) -> bool {
        match &mut self.address {
            Address::Myself => false,
            Address::External(source_ip) => {
                self.address = Address::KnownExternal {
                    address: addr,
                    source_ip: *source_ip,
                };
                true
            }
            Address::Known(existing) => {
                if *existing == addr {
                    return false;
                }
                *existing = addr;
                true
            }
            Address::KnownExternal { address, .. } => {
                if *address == addr {
                    return false;
                }
                *address = addr;
                true
            }
        }
    }

    /// Register or update the external fallback source IP for this record.
    pub fn register_external(&mut self, source_ip: IpAddr) {
        self.address = match &self.address {
            Address::Myself => Address::Myself,
            Address::External(_) => Address::External(source_ip),
            Address::Known(address) => Address::KnownExternal {
                address: address.clone(),
                source_ip,
            },
            Address::KnownExternal { address, .. } => Address::KnownExternal {
                address: address.clone(),
                source_ip,
            },
        };
        self.persistent = true;
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
    /// Checks that the peer is not ourselves, is currently inert, and that
    /// `next_reservable_at` has passed. On success, computes a jittered
    /// `next_dial_at` and sets `next_reservable_at` to `now + interval`.
    pub fn reserve(
        &mut self,
        context: &mut (impl Rng + Clock),
        interval: Duration,
    ) -> ReserveResult {
        if matches!(self.address, Address::Myself) || !matches!(self.status, Status::Inert) {
            return ReserveResult::Unavailable;
        }
        let now = context.current();
        if now < self.next_reservable_at {
            return ReserveResult::RateLimited;
        }
        self.status = Status::Reserved;
        self.next_reservable_at = now.saturating_add_ext(interval);
        self.next_dial_at = self.next_reservable_at.add_jittered(context, interval / 2);
        ReserveResult::Reserved
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

    /// Returns `true` if this record is for the local node.
    pub const fn is_myself(&self) -> bool {
        matches!(self.address, Address::Myself)
    }

    /// Returns the number of peer sets this peer is part of.
    pub const fn sets(&self) -> usize {
        self.sets
    }

    /// Check whether this record is dialable at the given time.
    ///
    /// Returns [DialStatus::Now] if the peer can be dialed immediately,
    /// [DialStatus::After] if it will become dialable at a future time,
    /// or [DialStatus::Unavailable] if it is not dialable at all.
    pub fn dialable(
        &self,
        now: SystemTime,
        allow_private_ips: bool,
        allow_dns: bool,
    ) -> DialStatus {
        if self.status != Status::Inert {
            return DialStatus::Unavailable;
        }
        if self.sets == 0 {
            return DialStatus::Unavailable;
        }
        let ingress = match &self.address {
            Address::Known(addr) => addr.ingress(),
            Address::KnownExternal { address, .. } => address.ingress(),
            Address::Myself | Address::External(_) => return DialStatus::Unavailable,
        };
        if !ingress.is_valid(allow_private_ips, allow_dns) {
            return DialStatus::Unavailable;
        }
        if self.next_dial_at > now {
            DialStatus::After(self.next_dial_at)
        } else {
            DialStatus::Now
        }
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
        if self.sets > 0 {
            match &self.address {
                Address::Known(addr) => addr.egress_ip() == source_ip,
                Address::KnownExternal { address, .. } => address.egress_ip() == source_ip,
                Address::Myself | Address::External(_) => false,
            }
        } else {
            match &self.address {
                Address::External(expected_ip) => *expected_ip == source_ip,
                Address::KnownExternal {
                    source_ip: expected_ip,
                    ..
                } => *expected_ip == source_ip,
                Address::Known(_) | Address::Myself => false,
            }
        }
    }

    /// Return the ingress address for dialing, if known.
    pub fn ingress(&self) -> Option<Ingress> {
        match &self.address {
            Address::Myself | Address::External(_) => None,
            Address::Known(addr) => Some(addr.ingress()),
            Address::KnownExternal { address, .. } => {
                if self.sets > 0 {
                    Some(address.ingress())
                } else {
                    None
                }
            }
        }
    }

    /// Return the egress IP for filtering, if known.
    pub const fn egress_ip(&self) -> Option<IpAddr> {
        match &self.address {
            Address::Myself => None,
            Address::External(source_ip) => Some(*source_ip),
            Address::Known(addr) => Some(addr.egress_ip()),
            Address::KnownExternal { address, source_ip } => {
                if self.sets > 0 {
                    Some(address.egress_ip())
                } else {
                    Some(*source_ip)
                }
            }
        }
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
            Address::External(_) | Address::Known(_) | Address::KnownExternal { .. } => {
                self.sets > 0 || self.persistent
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{deterministic, Runner};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::{Duration, SystemTime},
    };

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
        assert_eq!(record.status, Status::Inert);
        assert!(!record.deletable());
        assert!(!record.eligible());
    }

    #[test]
    fn test_external_initial_state() {
        let source_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let wrong_ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));

        // External-only records admit inbound connections from the configured
        // source IP, but they are never dialable.
        let record = Record::external(source_ip);
        assert!(matches!(record.address, Address::External(ip) if ip == source_ip));
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.sets, 0);
        assert!(record.persistent);
        assert!(record.ingress().is_none());
        assert_eq!(record.egress_ip(), Some(source_ip));
        assert!(record.is_blockable());
        assert!(!record.deletable());
        assert!(record.eligible());
        assert!(record.acceptable(source_ip, false));
        assert!(!record.acceptable(wrong_ip, false));
        assert!(record.acceptable(wrong_ip, true));
        assert!(matches!(
            record.dialable(SystemTime::UNIX_EPOCH, true, true),
            DialStatus::Unavailable
        ));
    }

    #[test]
    fn test_external_record_uses_tracked_address_while_in_peer_set() {
        let source_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let tracked = test_address();
        let tracked_ip = tracked.egress_ip();
        let mut record = Record::external(source_ip);

        // Registering a tracked address preserves the external fallback instead of
        // replacing it.
        assert!(record.update(tracked.clone()));
        assert!(matches!(
            record.address,
            Address::KnownExternal {
                ref address,
                source_ip: external_ip,
            } if *address == tracked && external_ip == source_ip
        ));
        assert!(record.ingress().is_none());
        assert_eq!(record.egress_ip(), Some(source_ip));

        // While tracked, the record behaves like a normal lookup peer.
        record.increment();
        assert_eq!(record.ingress(), Some(tracked.ingress()));
        assert_eq!(record.egress_ip(), Some(tracked_ip));
        assert!(record.acceptable(tracked_ip, false));
        assert!(!record.acceptable(source_ip, false));

        // Once the last tracked set is removed, the record falls back to the
        // external admission IP without any extra cleanup.
        record.decrement();
        assert!(record.ingress().is_none());
        assert_eq!(record.egress_ip(), Some(source_ip));
        assert!(record.acceptable(source_ip, false));
        assert!(!record.acceptable(tracked_ip, false));
    }

    #[test]
    fn test_known_external_updates_tracked_address_with_reconnect_signal() {
        let source_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let tracked_a = test_address();
        let tracked_b = types::Address::Symmetric(SocketAddr::from(([54, 12, 1, 10], 8081)));
        let mut record = Record::external(source_ip);

        // First tracked address registration records the tracked endpoint while
        // preserving the external fallback and requests a reconnect.
        assert!(record.update(tracked_a.clone()));
        record.increment();
        assert_eq!(record.ingress(), Some(tracked_a.ingress()));

        // Updating the tracked endpoint for an external-backed peer also
        // requests a reconnect, matching normal tracked-peer behavior.
        assert!(record.update(tracked_b.clone()));
        assert_eq!(record.ingress(), Some(tracked_b.ingress()));
        assert_eq!(record.egress_ip(), Some(tracked_b.egress_ip()));

        // If the peer becomes untracked again, the original external IP still
        // governs future inbound admissions.
        record.decrement();
        assert_eq!(record.ingress(), None);
        assert_eq!(record.egress_ip(), Some(source_ip));
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
        deterministic::Runner::default().start(|mut context| async move {
            let mut record = Record::known(test_address());

            assert_eq!(record.status, Status::Inert);
            assert_eq!(
                record.reserve(&mut context, Duration::ZERO),
                ReserveResult::Reserved
            );
            assert_eq!(record.status, Status::Reserved);

            assert_eq!(
                record.reserve(&mut context, Duration::ZERO),
                ReserveResult::Unavailable,
                "Cannot re-reserve when Reserved"
            );
            assert_eq!(record.status, Status::Reserved);

            record.connect();
            assert_eq!(record.status, Status::Active);

            assert_eq!(
                record.reserve(&mut context, Duration::ZERO),
                ReserveResult::Unavailable,
                "Cannot reserve when Active"
            );
            assert_eq!(record.status, Status::Active);

            record.release();
            assert_eq!(record.status, Status::Inert);

            assert_eq!(
                record.reserve(&mut context, Duration::ZERO),
                ReserveResult::Reserved
            );
            assert_eq!(record.status, Status::Reserved);
            record.release();
            assert_eq!(record.status, Status::Inert);
        });
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
        deterministic::Runner::default().start(|mut context| async move {
            let mut record = Record::known(test_address());
            assert_eq!(
                record.reserve(&mut context, Duration::ZERO),
                ReserveResult::Reserved
            );
            record.connect();
            record.connect();
        });
    }

    #[test]
    #[should_panic]
    fn test_release_when_inert_panics() {
        let mut record = Record::known(test_address());
        record.release();
    }

    #[test]
    fn test_deletable_logic_detailed() {
        deterministic::Runner::default().start(|mut context| async move {
            assert!(!Record::myself().deletable());

            let mut record = Record::known(test_address());
            assert_eq!(record.sets, 0);
            assert_eq!(record.status, Status::Inert);
            assert!(record.deletable());

            record.increment();
            assert!(!record.deletable());

            assert_eq!(
                record.reserve(&mut context, Duration::ZERO),
                ReserveResult::Reserved
            );
            assert!(!record.deletable());

            record.connect();
            assert!(!record.deletable());

            record.release();
            assert!(!record.deletable());

            record.decrement();
            assert!(record.deletable());
        });
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
        deterministic::Runner::default().start(|mut context| async move {
            use std::net::IpAddr;

            let egress_ip: IpAddr = [8, 8, 8, 8].into();
            let wrong_ip: IpAddr = [1, 2, 3, 4].into();
            let public_socket = SocketAddr::from(([8, 8, 8, 8], 8080));

            let mut record = Record::known(types::Address::Symmetric(public_socket));
            record.increment();
            assert!(record.acceptable(egress_ip, false));
            assert!(!record.acceptable(wrong_ip, false));

            let record_not_eligible = Record::known(types::Address::Symmetric(public_socket));
            assert!(!record_not_eligible.acceptable(egress_ip, false));

            let mut record_reserved = Record::known(types::Address::Symmetric(public_socket));
            record_reserved.increment();
            record_reserved.reserve(&mut context, Duration::ZERO);
            assert!(!record_reserved.acceptable(egress_ip, false));

            let mut record_connected = Record::known(types::Address::Symmetric(public_socket));
            record_connected.increment();
            record_connected.reserve(&mut context, Duration::ZERO);
            record_connected.connect();
            assert!(!record_connected.acceptable(egress_ip, false));
        });
    }

    #[test]
    fn test_acceptable_bypass_ip_check() {
        deterministic::Runner::default().start(|mut context| async move {
            use std::net::IpAddr;

            let egress_ip: IpAddr = [8, 8, 8, 8].into();
            let wrong_ip: IpAddr = [1, 2, 3, 4].into();
            let public_socket = SocketAddr::from(([8, 8, 8, 8], 8080));

            let mut record = Record::known(types::Address::Symmetric(public_socket));
            record.increment();
            assert!(record.acceptable(wrong_ip, true));

            let record_not_eligible = Record::known(types::Address::Symmetric(public_socket));
            assert!(!record_not_eligible.acceptable(egress_ip, true));

            let mut record_reserved = Record::known(types::Address::Symmetric(public_socket));
            record_reserved.increment();
            record_reserved.reserve(&mut context, Duration::ZERO);
            assert!(!record_reserved.acceptable(egress_ip, true));

            let mut record_connected = Record::known(types::Address::Symmetric(public_socket));
            record_connected.increment();
            record_connected.reserve(&mut context, Duration::ZERO);
            record_connected.connect();
            assert!(!record_connected.acceptable(egress_ip, true));

            assert!(!Record::myself().acceptable(egress_ip, true));
        });
    }

    #[test]
    fn test_reserve_sets_next_dial() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut record = Record::known(test_address());
            record.increment();
            let now = context.current();
            assert_eq!(record.dialable(now, true, true), DialStatus::Now);

            let interval = Duration::from_secs(1);
            assert_eq!(
                record.reserve(&mut context, interval),
                ReserveResult::Reserved
            );
            record.release();

            // Immediately after release, dialable returns After with jittered time.
            let status = record.dialable(now, true, true);
            match status {
                DialStatus::After(t) => {
                    assert!(t >= now + interval);
                    assert!(t <= now + interval * 2);
                }
                other => panic!("expected After, got {:?}", other),
            }
        });
    }

    #[test]
    fn test_reserve_rate_limited() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut record = Record::known(test_address());
            let interval = Duration::from_secs(5);

            assert_eq!(
                record.reserve(&mut context, interval),
                ReserveResult::Reserved
            );
            record.release();

            // Immediate re-reserve is rate-limited.
            assert_eq!(
                record.reserve(&mut context, interval),
                ReserveResult::RateLimited
            );

            // After interval elapses, reserve succeeds again.
            context.sleep(interval).await;
            assert_eq!(
                record.reserve(&mut context, interval),
                ReserveResult::Reserved
            );
        });
    }

    #[test]
    fn test_dialable_checks_ingress_ip() {
        use std::net::IpAddr;
        use Ingress;

        let now = SystemTime::UNIX_EPOCH;

        // Public ingress, public egress - dialable
        let public_socket = SocketAddr::from(([8, 8, 8, 8], 8080));
        let mut record_public = Record::known(types::Address::Symmetric(public_socket));
        record_public.increment();
        assert_eq!(record_public.dialable(now, false, true), DialStatus::Now);

        // Private ingress (Socket), public egress - NOT dialable when allow_private_ips=false
        let private_ingress =
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let public_egress = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 9090);
        let asymmetric_private_ingress = types::Address::Asymmetric {
            ingress: Ingress::Socket(private_ingress),
            egress: public_egress,
        };
        let mut record_private_ingress = Record::known(asymmetric_private_ingress);
        record_private_ingress.increment();
        assert_eq!(
            record_private_ingress.dialable(now, false, true),
            DialStatus::Unavailable
        );
        assert_eq!(
            record_private_ingress.dialable(now, true, true),
            DialStatus::Now
        );

        // Public ingress (Socket), private egress - dialable (egress not checked for dialing)
        let public_ingress = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 8080);
        let private_egress =
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 9090);
        let asymmetric_private_egress = types::Address::Asymmetric {
            ingress: Ingress::Socket(public_ingress),
            egress: private_egress,
        };
        let mut record_private_egress = Record::known(asymmetric_private_egress);
        record_private_egress.increment();
        assert_eq!(
            record_private_egress.dialable(now, false, true),
            DialStatus::Now
        );

        // DNS ingress (no IP to check) - dialable (DNS private check happens at dial time)
        let dns_ingress = types::Address::Asymmetric {
            ingress: Ingress::Dns {
                host: commonware_utils::hostname!("example.com"),
                port: 8080,
            },
            egress: public_egress,
        };
        let mut record_dns = Record::known(dns_ingress);
        record_dns.increment();
        assert_eq!(record_dns.dialable(now, false, true), DialStatus::Now);
        assert_eq!(
            record_dns.dialable(now, false, false),
            DialStatus::Unavailable
        );
    }
}
