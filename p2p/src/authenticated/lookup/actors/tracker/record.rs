use crate::{
    Advertisement, PeerEndpoint, Reachability,
    authenticated::dialing::{DialStatus, ReserveResult},
};
use commonware_runtime::Clock;
use commonware_utils::SystemTimeExt;
use rand_core::Rng;
use std::time::{Duration, SystemTime};

/// Represents information known about a peer's address.
#[derive(Clone, Debug)]
pub enum Address<E: PeerEndpoint> {
    /// Peer is the local node.
    Myself,

    /// Address is provided when peer is tracked.
    Known(Reachability<E>),

    /// Peer is authorized for an attached connection but has no dial endpoint.
    Undialable,
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
pub struct Record<E: PeerEndpoint> {
    /// Address state of the peer.
    address: Address<E>,

    /// Connection status of the peer.
    status: Status,

    /// If `true`, the reserved or active connection state was created before the latest address.
    stale_connection: bool,

    /// Number of primary peer sets this peer is part of.
    primary_sets: usize,

    /// Number of secondary peer sets this peer is part of.
    secondary_sets: usize,

    /// If `true`, the record should persist even if the peer is not part of any peer sets.
    persistent: bool,

    /// The earliest time we are willing to reserve this peer again.
    next_reservable_at: SystemTime,

    /// The earliest time we are willing to dial this peer.
    next_dial_at: SystemTime,
}

impl<E: PeerEndpoint> Record<E> {
    // ---------- Constructors ----------

    /// Create a new record with a known address.
    pub const fn known(reachability: Reachability<E>) -> Self {
        Self {
            address: Address::Known(reachability),
            status: Status::Inert,
            stale_connection: false,
            primary_sets: 0,
            secondary_sets: 0,
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
            stale_connection: false,
            primary_sets: 0,
            secondary_sets: 0,
            persistent: true,
            next_reservable_at: SystemTime::UNIX_EPOCH,
            next_dial_at: SystemTime::UNIX_EPOCH,
        }
    }

    /// Create a provisional record for a peer reached through an attached connection.
    pub const fn undialable() -> Self {
        Self {
            address: Address::Undialable,
            status: Status::Inert,
            stale_connection: false,
            primary_sets: 0,
            secondary_sets: 0,
            persistent: false,
            next_reservable_at: SystemTime::UNIX_EPOCH,
            next_dial_at: SystemTime::UNIX_EPOCH,
        }
    }

    // ---------- Setters ----------

    /// Update the record with a new address.
    ///
    /// Returns `true` if the address was changed, `false` if unchanged or self.
    pub fn update(&mut self, reachability: Reachability<E>) -> bool {
        match &mut self.address {
            Address::Myself => false,
            Address::Undialable => {
                self.address = Address::Known(reachability);
                if self.is_reserved_or_connected() {
                    self.stale_connection = true;
                }
                true
            }
            Address::Known(existing) => {
                if *existing == reachability {
                    return false;
                }
                *existing = reachability;
                if self.is_reserved_or_connected() {
                    self.stale_connection = true;
                }
                true
            }
        }
    }

    /// Increase the count of primary peer sets this peer is part of.
    pub const fn increment_primary(&mut self) {
        self.primary_sets = self.primary_sets.checked_add(1).unwrap();
    }

    /// Decrease the count of primary peer sets this peer is part of.
    pub const fn decrement_primary(&mut self) {
        self.primary_sets = self.primary_sets.checked_sub(1).unwrap();
    }

    /// Increase the count of secondary peer sets this peer is part of.
    pub const fn increment_secondary(&mut self) {
        self.secondary_sets = self.secondary_sets.checked_add(1).unwrap();
    }

    /// Decrease the count of secondary peer sets this peer is part of.
    pub const fn decrement_secondary(&mut self) {
        self.secondary_sets = self.secondary_sets.checked_sub(1).unwrap();
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
        self.stale_connection = false;
        self.next_reservable_at = now.saturating_add_ext(interval);
        self.next_dial_at = self.next_reservable_at.add_jittered(context, interval / 2);
        ReserveResult::Reserved
    }

    /// Marks the peer as connected.
    ///
    /// The peer must have the status [Status::Reserved].
    ///
    /// Returns `false` if the reservation was invalidated by an address change.
    pub fn connect(&mut self) -> bool {
        assert!(matches!(self.status, Status::Reserved));
        if self.stale_connection {
            return false;
        }
        self.status = Status::Active;
        if matches!(self.address, Address::Undialable) {
            self.persistent = true;
        }
        true
    }

    /// Releases any reservation on the peer.
    pub fn release(&mut self) {
        assert!(self.status != Status::Inert, "Cannot release an Inert peer");
        self.status = Status::Inert;
        self.stale_connection = false;
    }

    // ---------- Getters ----------

    /// Returns `true` if this peer can be blocked.
    ///
    /// Only `Myself` cannot be blocked. Actual blocked status is tracked
    /// by the Directory via PrioritySet.
    pub const fn is_blockable(&self) -> bool {
        !matches!(self.address, Address::Myself)
    }

    /// Returns `true` while a connection is reserved or active.
    pub const fn is_reserved_or_connected(&self) -> bool {
        !matches!(self.status, Status::Inert)
    }

    /// Returns `true` when reserved or active connection state should be torn down.
    pub const fn needs_teardown(&self) -> bool {
        self.is_reserved_or_connected() && (self.stale_connection || !self.eligible())
    }

    /// Returns the number of primary peer sets this peer is part of.
    pub const fn primary_sets(&self) -> usize {
        self.primary_sets
    }

    /// Returns the number of secondary peer sets this peer is part of.
    pub const fn secondary_sets(&self) -> usize {
        self.secondary_sets
    }

    /// Whether this peer should be dialed outbound (primary or persistent peers).
    ///
    /// Secondary peers remain eligible for inbound connections, but we reserve
    /// outbound dialing for primary peers and for persistent records
    /// that must stay dialable without a primary count.
    pub const fn is_outbound_target(&self) -> bool {
        self.primary_sets > 0 || self.persistent
    }

    /// Check whether this record is dialable at the given time.
    ///
    /// Returns [DialStatus::Now] if the peer can be dialed immediately,
    /// [DialStatus::After] if it will become dialable at a future time,
    /// or [DialStatus::Unavailable] if it is not dialable at all.
    pub fn dialable(&self, now: SystemTime) -> DialStatus {
        if self.status != Status::Inert || !self.is_outbound_target() {
            return DialStatus::Unavailable;
        }
        match &self.address {
            Address::Known(Reachability::Dialable(_)) => {}
            Address::Known(Reachability::OutboundOnly) => return DialStatus::Unavailable,
            Address::Myself | Address::Undialable => return DialStatus::Unavailable,
        }
        if self.next_dial_at > now {
            DialStatus::After(self.next_dial_at)
        } else {
            DialStatus::Now
        }
    }

    /// Returns `true` if this peer is eligible and has no active reservation or connection.
    pub const fn acceptable(&self) -> bool {
        self.eligible() && matches!(self.status, Status::Inert)
    }

    /// Returns the peer's advertised endpoints, if it can be dialed.
    pub fn advertisement(&self) -> Option<Advertisement<E>> {
        match &self.address {
            Address::Known(Reachability::Dialable(advertisement)) => Some(advertisement.clone()),
            Address::Known(Reachability::OutboundOnly) | Address::Myself | Address::Undialable => {
                None
            }
        }
    }

    /// Returns `true` if the record can safely be deleted.
    pub const fn deletable(&self) -> bool {
        self.primary_sets == 0
            && self.secondary_sets == 0
            && !self.persistent
            && matches!(self.status, Status::Inert)
    }

    /// Returns `true` if this peer is eligible for connection.
    ///
    /// A peer is eligible if:
    /// - It is not ourselves
    /// - It is part of at least one primary peer set, at least one secondary peer set, or
    ///   persistent
    pub const fn eligible(&self) -> bool {
        match &self.address {
            Address::Myself => false,
            Address::Known(_) => {
                self.primary_sets > 0 || self.secondary_sets > 0 || self.persistent
            }
            Address::Undialable => {
                self.primary_sets > 0
                    || self.secondary_sets > 0
                    || self.persistent
                    || matches!(self.status, Status::Reserved | Status::Active)
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner, deterministic};

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct Endpoint(&'static str);

    impl PeerEndpoint for Endpoint {}

    type TestRecord = Record<Endpoint>;

    fn dialable(endpoints: &[&'static str]) -> Reachability<Endpoint> {
        Reachability::Dialable(
            Advertisement::new(endpoints.iter().copied().map(Endpoint).collect()).unwrap(),
        )
    }

    fn known() -> TestRecord {
        Record::known(dialable(&["primary"]))
    }

    #[test]
    fn test_myself_initial_state() {
        let record = TestRecord::myself();
        assert!(matches!(record.address, Address::Myself));
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.primary_sets, 0);
        assert_eq!(record.secondary_sets, 0);
        assert!(record.persistent);
        assert!(record.advertisement().is_none());
        assert!(!record.is_blockable());
        assert!(!record.deletable());
        assert!(!record.eligible());
    }

    #[test]
    fn test_known_initial_state() {
        let record = known();
        assert!(matches!(record.address, Address::Known(_)));
        assert_eq!(record.status, Status::Inert);
        assert_eq!(record.primary_sets, 0);
        assert_eq!(record.secondary_sets, 0);
        assert!(!record.persistent);
        assert_eq!(
            record.advertisement().unwrap().endpoints(),
            &[Endpoint("primary")]
        );
        assert!(record.is_blockable());
        assert!(record.deletable());
        assert!(!record.eligible());
    }

    #[test]
    fn test_attached_peer_can_gain_reachability() {
        let mut record = TestRecord::undialable();
        let reachability = dialable(&["first", "second"]);
        assert!(record.update(reachability.clone()));
        assert_eq!(
            record.advertisement(),
            match reachability {
                Reachability::Dialable(advertisement) => Some(advertisement),
                Reachability::OutboundOnly => unreachable!(),
            }
        );
        assert!(!record.is_outbound_target());
    }

    #[test]
    fn test_is_blockable() {
        let record_myself = TestRecord::myself();
        assert!(!record_myself.is_blockable());

        let record_known = known();
        assert!(record_known.is_blockable());

        let record_undialable = TestRecord::undialable();
        assert!(record_undialable.is_blockable());
    }

    #[test]
    fn test_increment_decrement_and_deletable() {
        let mut record_known = known();
        assert!(record_known.deletable());
        record_known.increment_primary();
        assert_eq!(record_known.primary_sets(), 1);
        assert!(!record_known.deletable());
        record_known.decrement_primary();
        assert!(record_known.deletable());

        record_known.increment_secondary();
        assert_eq!(record_known.secondary_sets(), 1);
        assert!(!record_known.deletable());
        record_known.decrement_secondary();
        assert!(record_known.deletable());

        let mut record_myself = TestRecord::myself();
        assert!(!record_myself.deletable());
        record_myself.increment_primary();
        assert!(!record_myself.deletable());
        record_myself.decrement_primary();
        assert!(!record_myself.deletable());
    }

    #[test]
    #[should_panic]
    fn test_decrement_panics_at_zero() {
        let mut record = known();
        assert_eq!(record.primary_sets, 0);
        record.decrement_primary();
    }

    #[test]
    fn test_status_transitions_reserve_connect_release() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut record = known();

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

            assert!(record.connect());
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
    fn test_needs_teardown_after_losing_eligibility() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut record = known();
            record.increment_primary();

            assert!(!record.needs_teardown());
            assert!(!record.is_reserved_or_connected());
            assert_eq!(
                record.reserve(&mut context, Duration::ZERO),
                ReserveResult::Reserved
            );
            assert!(!record.needs_teardown());
            assert!(record.is_reserved_or_connected());

            record.decrement_primary();
            assert!(record.needs_teardown());
            assert!(record.is_reserved_or_connected());

            assert!(record.connect());
            assert!(record.needs_teardown());
            assert!(record.is_reserved_or_connected());

            record.release();
            assert!(!record.needs_teardown());
            assert!(!record.is_reserved_or_connected());
        });
    }

    #[test]
    fn test_reserved_connect_rejected_after_address_change() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut record = known();
            record.increment_primary();
            assert_eq!(
                record.reserve(&mut context, Duration::ZERO),
                ReserveResult::Reserved
            );

            assert!(record.update(dialable(&["replacement"])));
            assert!(record.needs_teardown());
            assert!(!record.connect());
            assert_eq!(record.status, Status::Reserved);

            record.release();
            assert!(!record.needs_teardown());
        });
    }

    #[test]
    #[should_panic]
    fn test_connect_when_not_reserved_panics_from_inert() {
        let mut record = known();
        record.connect();
    }

    #[test]
    #[should_panic]
    fn test_connect_when_active_panics() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut record = known();
            assert_eq!(
                record.reserve(&mut context, Duration::ZERO),
                ReserveResult::Reserved
            );
            assert!(record.connect());
            record.connect();
        });
    }

    #[test]
    #[should_panic]
    fn test_release_when_inert_panics() {
        let mut record = known();
        record.release();
    }

    #[test]
    fn test_deletable_logic_detailed() {
        deterministic::Runner::default().start(|mut context| async move {
            assert!(!TestRecord::myself().deletable());

            let mut record = known();
            assert_eq!(record.primary_sets, 0);
            assert_eq!(record.status, Status::Inert);
            assert!(record.deletable());

            record.increment_primary();
            assert!(!record.deletable());

            assert_eq!(
                record.reserve(&mut context, Duration::ZERO),
                ReserveResult::Reserved
            );
            assert!(!record.deletable());

            assert!(record.connect());
            assert!(!record.deletable());

            record.release();
            assert!(!record.deletable());

            record.decrement_primary();
            assert!(record.deletable());
        });
    }

    #[test]
    fn test_eligible_logic() {
        assert!(!TestRecord::myself().eligible());

        let mut record_known = known();
        assert!(!record_known.eligible(), "Not eligible when sets=0");
        record_known.increment_primary();
        assert!(record_known.eligible(), "Eligible when sets>0");
        record_known.decrement_primary();
        assert!(!record_known.eligible(), "Not eligible when sets=0 again");

        record_known.increment_secondary();
        assert!(record_known.eligible(), "Eligible when in a secondary set");

        let record_undialable = TestRecord::undialable();
        assert!(!record_undialable.eligible());
        assert!(!record_undialable.acceptable());
        assert!(record_undialable.advertisement().is_none());
    }

    #[test]
    fn test_acceptable_checks_eligibility_and_status() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut record = known();
            record.increment_primary();
            assert!(record.acceptable());

            let record_not_eligible = known();
            assert!(!record_not_eligible.acceptable());

            let mut record_reserved = known();
            record_reserved.increment_primary();
            record_reserved.reserve(&mut context, Duration::ZERO);
            assert!(!record_reserved.acceptable());

            let mut record_connected = known();
            record_connected.increment_primary();
            record_connected.reserve(&mut context, Duration::ZERO);
            record_connected.connect();
            assert!(!record_connected.acceptable());

            assert!(!TestRecord::myself().acceptable());
        });
    }

    #[test]
    fn test_reserve_sets_next_dial() {
        deterministic::Runner::default().start(|mut context| async move {
            let mut record = known();
            record.increment_primary();
            let now = context.current();
            assert_eq!(record.dialable(now), DialStatus::Now);

            let interval = Duration::from_secs(1);
            assert_eq!(
                record.reserve(&mut context, interval),
                ReserveResult::Reserved
            );
            record.release();

            let status = record.dialable(now);
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
            let mut record = known();
            let interval = Duration::from_secs(5);

            assert_eq!(
                record.reserve(&mut context, interval),
                ReserveResult::Reserved
            );
            record.release();

            assert_eq!(
                record.reserve(&mut context, interval),
                ReserveResult::RateLimited
            );

            context.sleep(interval).await;
            assert_eq!(
                record.reserve(&mut context, interval),
                ReserveResult::Reserved
            );
        });
    }

    #[test]
    fn test_dialable_requires_outbound_target_and_advertisement() {
        let now = SystemTime::UNIX_EPOCH;

        let mut secondary = Record::known(dialable(&["first", "second"]));
        secondary.increment_secondary();
        assert_eq!(secondary.dialable(now), DialStatus::Unavailable);
        assert_eq!(
            secondary.advertisement().unwrap().endpoints(),
            &[Endpoint("first"), Endpoint("second")]
        );

        secondary.increment_primary();
        assert_eq!(secondary.dialable(now), DialStatus::Now);

        let mut outbound_only = Record::known(Reachability::<Endpoint>::OutboundOnly);
        outbound_only.increment_primary();
        assert!(outbound_only.acceptable());
        assert_eq!(outbound_only.dialable(now), DialStatus::Unavailable);
        assert!(outbound_only.advertisement().is_none());

        assert!(outbound_only.update(dialable(&["replacement", "fallback"])));
        assert_eq!(outbound_only.dialable(now), DialStatus::Now);
        assert_eq!(
            outbound_only.advertisement().unwrap().endpoints(),
            &[Endpoint("replacement"), Endpoint("fallback")]
        );
    }
}
