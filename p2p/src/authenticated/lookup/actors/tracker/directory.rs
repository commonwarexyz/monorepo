use super::{Metadata, Reservation, metrics::Metrics, record::Record};
use crate::{
    Advertisement, PeerEndpoint, PeerSetUpdate, Reachability, ReachableTrackedPeers, TrackedPeers,
    authenticated::{
        dialing::{DialStatus, Dialable, ReserveResult, earliest},
        lookup::actors::tracker::ingress::Releaser,
    },
    utils::PeerSetsAtIndex as PeerSetsAtIndexBase,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{
    Clock, Metrics as RuntimeMetrics, Scheduler, telemetry::metrics::GaugeExt,
};
use commonware_utils::{PrioritySet, SystemTimeExt, ordered::Set};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, HashMap, HashSet, hash_map::Entry},
    num::NonZeroUsize,
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

/// Primary and secondary [`Set`] at one peer set index.
type PeerSetsAtIndex<C> = PeerSetsAtIndexBase<Set<C>, Set<C>>;

/// Configuration for the [Directory].
pub struct Config {
    /// The maximum number of peer sets to track.
    pub max_sets: NonZeroUsize,

    /// The cooldown between reservations for a given peer.
    pub peer_connection_cooldown: Duration,

    /// Duration after which a blocked peer is allowed to reconnect.
    pub block_duration: Duration,
}

/// Represents a collection of records for all peers.
pub struct Directory<R: Rng + Clock + RuntimeMetrics, C: PublicKey, E: PeerEndpoint> {
    context: R,

    // ---------- Configuration ----------
    /// The maximum number of peer sets to track.
    max_sets: NonZeroUsize,

    /// Duration after which a blocked peer is allowed to reconnect.
    block_duration: Duration,

    /// Minimum duration between reservations for a given peer.
    peer_connection_cooldown: Duration,

    // ---------- State ----------
    /// The records of all peers.
    peers: HashMap<C, Record<E>>,

    /// Primary and secondary peer sets indexed by peer set ID.
    peer_sets: BTreeMap<u64, PeerSetsAtIndex<C>>,

    /// Tracks blocked peers and their unblock time. This is the source of truth for
    /// whether a peer is blocked, persisting even if the peer record is deleted.
    blocked: PrioritySet<C, SystemTime>,

    // ---------- Message-Passing ----------
    /// The releaser for the tracker actor.
    releaser: Releaser<C, E>,

    // ---------- Metrics ----------
    /// The metrics for the records.
    metrics: Metrics<C>,
}

impl<R: Scheduler + Rng + Clock + RuntimeMetrics, C: PublicKey, E: PeerEndpoint>
    Directory<R, C, E>
{
    /// Create a new set of records using the given local node information.
    pub fn init(context: R, myself: C, cfg: Config, releaser: Releaser<C, E>) -> Self {
        // Create the list of peers and add myself.
        let mut peers = HashMap::new();
        peers.insert(myself, Record::myself());

        let metrics = Metrics::init(&context);
        let _ = metrics.tracked.try_set(peers.len() - 1); // Exclude self

        Self {
            context,
            max_sets: cfg.max_sets,
            block_duration: cfg.block_duration,
            peer_connection_cooldown: cfg.peer_connection_cooldown,
            peers,
            peer_sets: BTreeMap::new(),
            blocked: PrioritySet::new(),
            releaser,
            metrics,
        }
    }

    // ---------- Setters ----------

    /// Releases a peer.
    pub fn release(&mut self, metadata: Metadata<C>) {
        let peer = metadata.public_key();
        let Some(record) = self.peers.get_mut(peer) else {
            return;
        };
        record.release();
        self.metrics.connected.remove_by(peer);
        self.metrics.reserved.dec();
        self.delete_if_needed(peer);
    }

    /// Sets the status of a peer to `connected`.
    ///
    /// Returns `false` if the reservation was invalidated by an address change.
    ///
    /// # Panics
    ///
    /// Panics if the peer has no record or if the peer is not in the reserved state.
    pub fn connect(&mut self, peer: &C) -> bool {
        // Set the record as connected
        let record = self.peers.get_mut(peer).unwrap();
        if !record.connect() {
            return false;
        }
        let _ = self
            .metrics
            .connected
            .get_or_create_by(peer)
            .try_set(self.context.current().epoch_millis());
        true
    }

    /// Track new primary and secondary peer sets for the given index.
    ///
    /// Returns peers whose connection state should be torn down because they were removed from all
    /// tracked peer sets or had their address changed.
    ///
    /// Returns `None` if the index is invalid.
    pub fn track(&mut self, index: u64, peers: ReachableTrackedPeers<C, E>) -> Option<Set<C>> {
        // Check if peer set already exists
        if self.peer_sets.contains_key(&index) {
            warn!(index, "peer set already exists");
            return None;
        }

        // Ensure that peer set is monotonically increasing
        if let Some((last, _)) = self.peer_sets.last_key_value()
            && index <= *last
        {
            warn!(?index, ?last, "index must monotonically increase");
            return None;
        }

        // Create and store new primary peer set (all peers are tracked regardless of address
        // validity).
        let mut kill_peers = Vec::new();
        for (primary, addr) in &peers.primary {
            let record = match self.peers.entry(primary.clone()) {
                Entry::Occupied(entry) => {
                    let entry = entry.into_mut();
                    if entry.update(addr.clone()) {
                        self.metrics.updates.get_or_create_by(primary).inc();
                        if entry.is_reserved_or_connected() {
                            kill_peers.push(primary.clone());
                        }
                    }
                    entry
                }
                Entry::Vacant(entry) => {
                    self.metrics.tracked.inc();
                    entry.insert(Record::known(addr.clone()))
                }
            };
            record.increment_primary();
        }

        // Peers in both primary and secondary are stored as primary only.
        for (secondary, addr) in &peers.secondary {
            if peers.primary.position(secondary).is_some() {
                continue;
            }
            let record = match self.peers.entry(secondary.clone()) {
                Entry::Occupied(entry) => {
                    let entry = entry.into_mut();
                    if entry.update(addr.clone()) {
                        self.metrics.updates.get_or_create_by(secondary).inc();
                        if entry.is_reserved_or_connected() {
                            kill_peers.push(secondary.clone());
                        }
                    }
                    entry
                }
                Entry::Vacant(entry) => {
                    self.metrics.tracked.inc();
                    entry.insert(Record::known(addr.clone()))
                }
            };
            record.increment_secondary();
        }
        let secondary_set = Set::from_iter_dedup(
            peers
                .secondary
                .keys()
                .iter()
                .filter(|k| peers.primary.position(k).is_none())
                .cloned(),
        );
        let primary_keys_set = peers.primary.into_keys();
        self.peer_sets.insert(
            index,
            PeerSetsAtIndex {
                primary: primary_keys_set,
                secondary: secondary_set,
            },
        );

        // Remove oldest tracked peer sets if necessary.
        while self.peer_sets.len() > self.max_sets.get() {
            let (removed_index, sets) = self.peer_sets.pop_first().unwrap();
            debug!(index = removed_index, "removed oldest tracked peer sets");
            sets.primary.into_iter().for_each(|primary| {
                self.peers.get_mut(&primary).unwrap().decrement_primary();
                self.queue_if_needs_teardown(&primary, &mut kill_peers);
            });
            sets.secondary.into_iter().for_each(|secondary| {
                self.peers
                    .get_mut(&secondary)
                    .unwrap()
                    .decrement_secondary();
                self.queue_if_needs_teardown(&secondary, &mut kill_peers);
            });
        }

        Some(Set::from_iter_dedup(kill_peers))
    }

    /// Update a tracked peer's address.
    ///
    /// Returns `true` if the peer exists and the address actually changed.
    /// The caller should sever any existing connection to this peer since it
    /// was established to the old address.
    ///
    /// Returns `false` if the peer has no record, is ourselves, or the
    /// new address is identical to the existing one.
    pub fn overwrite(&mut self, peer: &C, reachability: Reachability<E>) -> bool {
        let Some(record) = self.peers.get_mut(peer) else {
            return false;
        };
        record.update(reachability)
    }

    /// Gets the peer set (primary and secondary) at the given index.
    pub fn get_peer_set(&self, index: &u64) -> Option<TrackedPeers<C>> {
        let entry = self.peer_sets.get(index)?;
        Some(TrackedPeers::new(
            entry.primary.clone(),
            entry.secondary.clone(),
        ))
    }

    /// Returns the latest peer set index.
    pub fn latest_set_index(&self) -> Option<u64> {
        self.peer_sets.keys().last().copied()
    }

    /// Returns a [`PeerSetUpdate`] for the latest peer set (by id), if any.
    pub fn latest_update(&self) -> Option<PeerSetUpdate<C>> {
        let index = self.latest_set_index()?;
        Some(PeerSetUpdate {
            index,
            latest: self.get_peer_set(&index).unwrap(),
            all: self.all(),
        })
    }

    /// Attempt to reserve a peer for the dialer.
    ///
    /// Returns `Some` on success, `None` otherwise.
    pub fn dial(&mut self, peer: &C) -> Option<(Reservation<C, E>, Advertisement<E>)> {
        let record = self.peers.get(peer)?;
        if !record.is_outbound_target() {
            return None;
        }
        let advertisement = record.advertisement()?;
        let reservation = self.reserve(Metadata::Dialer(peer.clone()))?;
        Some((reservation, advertisement))
    }

    /// Reserve a peer whose transport connection was established outside the dialer or listener.
    pub fn attach(&mut self, peer: C, metadata: Metadata<C>) -> Option<Reservation<C, E>> {
        if metadata.public_key() != &peer || self.is_blocked(&peer) {
            return None;
        }

        let inserted = !self.peers.contains_key(&peer);
        if inserted {
            self.metrics.tracked.inc();
            self.peers.insert(peer.clone(), Record::undialable());
        }
        let reservation = self.reserve_record(metadata);
        if reservation.is_none() && inserted {
            self.delete_if_needed(&peer);
        }
        reservation
    }

    /// Attempt to reserve a peer for the listener.
    ///
    /// Returns `Some` on success, `None` otherwise.
    pub fn listen(&mut self, peer: &C) -> Option<Reservation<C, E>> {
        if !self.acceptable(peer) {
            return None;
        }
        self.reserve(Metadata::Listener(peer.clone()))
    }

    /// Returns `true` if the peer is actively blocked (entry exists and has not expired).
    fn is_blocked(&self, peer: &C) -> bool {
        self.blocked
            .get(peer)
            .is_some_and(|t| t > self.context.current())
    }

    /// Attempt to block a peer for the configured duration, updating the metrics accordingly.
    ///
    /// Peers can be blocked even if they don't have a record yet. The block will be applied
    /// when they are later added to a peer set.
    pub fn block(&mut self, peer: &C) {
        // Already blocked
        if self.is_blocked(peer) {
            return;
        }

        // If record exists, check if it's blockable
        if let Some(record) = self.peers.get(peer)
            && !record.is_blockable()
        {
            return;
        }

        let blocked_until = self.context.current() + self.block_duration;
        self.blocked.put(peer.clone(), blocked_until);
        let _ = self
            .metrics
            .blocked
            .get_or_create_by(peer)
            .try_set(blocked_until.epoch_millis());
    }

    // ---------- Getters ----------

    /// Returns all peers across all tracked peer sets.
    ///
    /// Same overlap rule as each stored set and as [`crate::Provider::subscribe`] documents for
    /// [`PeerSetUpdate::all`]: a peer with any primary membership is listed only under `primary`,
    /// even if they also appear as secondary in another tracked set.
    pub fn all(&self) -> TrackedPeers<C> {
        let mut primary = Vec::new();
        let mut secondary = Vec::new();
        for (k, record) in &self.peers {
            if record.primary_sets() > 0 {
                primary.push(k.clone());
            } else if record.secondary_sets() > 0 {
                secondary.push(k.clone());
            }
        }
        TrackedPeers::new(
            Set::from_iter_dedup(primary),
            Set::from_iter_dedup(secondary),
        )
    }

    /// Returns true if the peer is eligible for connection.
    ///
    /// A peer is eligible if it is in a peer set, not blocked, and not ourselves.
    /// This does NOT check IP validity - that is done separately for dialing (ingress)
    /// and accepting (egress).
    pub fn eligible(&self, peer: &C) -> bool {
        !self.is_blocked(peer) && self.peers.get(peer).is_some_and(|r| r.eligible())
    }

    /// Returns peers eligible to begin inbound authentication.
    pub fn admissible(&self) -> HashSet<C> {
        self.peers
            .iter()
            .filter(|(peer, record)| !self.is_blocked(peer) && record.eligible())
            .map(|(peer, _)| peer.clone())
            .collect()
    }

    /// Returns dialable peers and the next time another peer may become dialable.
    pub fn dialable(&self) -> Dialable<C> {
        let now = self.context.current();
        let mut next_query_at: Option<SystemTime> = None;
        let mut peers = Vec::new();
        for (peer, record) in &self.peers {
            if let Some(blocked_until) = self.blocked.get(peer).filter(|t| *t > now) {
                next_query_at = earliest(next_query_at, blocked_until);
                continue;
            }
            match record.dialable(now) {
                DialStatus::Now => peers.push(peer.clone()),
                DialStatus::After(t) => {
                    next_query_at = earliest(next_query_at, t);
                }
                DialStatus::Unavailable => {}
            }
        }
        peers.sort();

        Dialable {
            peers,
            next_query_at,
        }
    }

    /// Returns true if this peer is acceptable (can accept an incoming connection from them).
    ///
    /// Origin and endpoint admission policies are enforced before this tracker is queried.
    pub fn acceptable(&self, peer: &C) -> bool {
        !self.is_blocked(peer) && self.peers.get(peer).is_some_and(Record::acceptable)
    }

    /// Unblock all peers whose block has expired.
    ///
    /// Returns `true` if any peers were unblocked.
    pub fn unblock_expired(&mut self) -> bool {
        let now = self.context.current();
        let mut any_unblocked = false;
        while let Some((_, &blocked_until)) = self.blocked.peek() {
            if blocked_until > now {
                break;
            }
            let (peer, _) = self.blocked.pop().unwrap();
            debug!(?peer, "unblocked peer");
            self.metrics.blocked.remove_by(&peer);
            any_unblocked = true;
        }

        any_unblocked
    }

    /// Waits until the next blocked peer should be unblocked.
    ///
    /// If no peers are blocked, this will never complete.
    pub async fn wait_for_unblock(&self) {
        match self.blocked.peek() {
            Some((_, &time)) => self.context.sleep_until(time).await,
            None => futures::future::pending().await,
        }
    }

    /// Returns the number of currently blocked peers.
    #[cfg(test)]
    pub fn blocked(&self) -> usize {
        self.blocked.len()
    }

    // --------- Helpers ----------

    /// Attempt to reserve a peer.
    ///
    /// Returns `Some(Reservation)` if the peer was successfully reserved, `None` otherwise.
    fn reserve(&mut self, metadata: Metadata<C>) -> Option<Reservation<C, E>> {
        let peer = metadata.public_key();

        // Not reservable (must be in a peer set)
        if !self.eligible(peer) {
            return None;
        }

        self.reserve_record(metadata)
    }

    fn reserve_record(&mut self, metadata: Metadata<C>) -> Option<Reservation<C, E>> {
        let peer = metadata.public_key();
        // Reserve
        let record = self.peers.get_mut(peer).unwrap();
        match record.reserve(&mut self.context, self.peer_connection_cooldown) {
            ReserveResult::Reserved => {
                self.metrics.reserved.inc();
                Some(Reservation::new(metadata, self.releaser.clone()))
            }
            ReserveResult::RateLimited => {
                self.metrics.limits.get_or_create_by(peer).inc();
                None
            }
            ReserveResult::Unavailable => None,
        }
    }

    /// Queue connection state for teardown if it is no longer valid, then delete inert records.
    ///
    /// Active peers need a kill signal. Reserved peers may not have registered a mailbox yet; in
    /// that case the actor kill path is a no-op and later Connect rejection or reservation release
    /// completes cleanup.
    fn queue_if_needs_teardown(&mut self, peer: &C, kill_peers: &mut Vec<C>) {
        if self
            .peers
            .get(peer)
            .is_some_and(|record| record.needs_teardown())
        {
            kill_peers.push(peer.clone());
        }
        self.delete_if_needed(peer);
    }

    /// Attempt to delete a record.
    fn delete_if_needed(&mut self, peer: &C) {
        let Some(record) = self.peers.get(peer) else {
            return;
        };
        if !record.deletable() {
            return;
        }

        // We don't decrement the blocked metric here because the block
        // persists in PrioritySet even after the record is deleted. The metric
        // is decremented in unblock_expired when the block actually expires.
        self.peers.remove(peer);
        self.metrics.tracked.dec();
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Advertisement, PeerEndpoint, Reachability, ReachableTrackedPeers,
        authenticated::lookup::actors::tracker::directory::Directory,
    };
    use commonware_actor::mailbox;
    use commonware_cryptography::{Signer, ed25519};
    use commonware_runtime::{Clock, Metrics as _, Runner, Supervisor as _, deterministic};
    use commonware_utils::{
        NZUsize, SystemTimeExt,
        ordered::{Map, Set},
    };
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct Endpoint(SocketAddr);

    impl PeerEndpoint for Endpoint {}

    fn advertisement(socket: SocketAddr) -> Advertisement<Endpoint> {
        Advertisement::new(vec![Endpoint(socket)]).unwrap()
    }

    fn dialable(socket: SocketAddr) -> Reachability<Endpoint> {
        Reachability::Dialable(advertisement(socket))
    }

    fn primary(
        map: Map<ed25519::PublicKey, Reachability<Endpoint>>,
    ) -> ReachableTrackedPeers<ed25519::PublicKey, Endpoint> {
        ReachableTrackedPeers::from(map)
    }

    fn metric_value(metrics: &str, name: &str, peer: &str) -> Option<i64> {
        metrics
            .lines()
            .find(|line| line.starts_with(&format!("{name}{{peer=\"{peer}\"}} ")))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<i64>().ok())
    }

    fn new_releaser<C: commonware_cryptography::PublicKey>(
        metrics: impl commonware_runtime::Metrics,
    ) -> super::Releaser<C, Endpoint> {
        let (tx, _rx) = mailbox::new(metrics, NZUsize!(1024));
        super::Releaser::new(tx)
    }

    #[test]
    fn test_rejected_attachment_does_not_retain_unknown_peer() {
        deterministic::Runner::default().start(|context| async move {
            let myself = ed25519::PrivateKey::from_seed(0).public_key();
            let peer = ed25519::PrivateKey::from_seed(1).public_key();
            let config = super::Config {
                max_sets: NZUsize!(1),
                peer_connection_cooldown: Duration::ZERO,
                block_duration: Duration::from_secs(100),
            };
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, myself, config, releaser);

            let reservation = directory
                .attach(peer.clone(), super::Metadata::Listener(peer.clone()))
                .expect("unknown peer should be provisionally reservable");
            let metadata = reservation.metadata().clone();
            std::mem::forget(reservation);
            directory.release(metadata);

            assert!(!directory.peers.contains_key(&peer));
        });
    }

    #[test]
    fn test_connected_attachment_retains_unknown_peer() {
        deterministic::Runner::default().start(|context| async move {
            let myself = ed25519::PrivateKey::from_seed(0).public_key();
            let peer = ed25519::PrivateKey::from_seed(1).public_key();
            let config = super::Config {
                max_sets: NZUsize!(1),
                peer_connection_cooldown: Duration::ZERO,
                block_duration: Duration::from_secs(100),
            };
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, myself, config, releaser);

            let reservation = directory
                .attach(peer.clone(), super::Metadata::Listener(peer.clone()))
                .expect("unknown peer should be provisionally reservable");
            let metadata = reservation.metadata().clone();
            std::mem::forget(reservation);
            assert!(directory.connect(&peer));
            directory.release(metadata);

            assert!(directory.peers.contains_key(&peer));
            assert!(directory.eligible(&peer));
        });
    }

    #[test]
    fn test_track_only_returns_live_peers_for_teardown() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(1),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let pk_2 = ed25519::PrivateKey::from_seed(2).public_key();
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1236);
        let pk_3 = ed25519::PrivateKey::from_seed(3).public_key();
        let addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1237);

        runtime.start(|context| async move {
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk, config, releaser);

            let kill_peers = directory
                .track(
                    0,
                    primary(
                        [
                            (pk_1.clone(), dialable(addr_1)),
                            (pk_2.clone(), dialable(addr_2)),
                        ]
                        .try_into()
                        .unwrap(),
                    ),
                )
                .unwrap();
            assert!(
                kill_peers.is_empty(),
                "No peers should need teardown on first set"
            );

            let kill_peers = directory
                .track(
                    1,
                    primary(
                        [
                            (pk_2.clone(), dialable(addr_2)),
                            (pk_3.clone(), dialable(addr_3)),
                        ]
                        .try_into()
                        .unwrap(),
                    ),
                )
                .unwrap();
            assert!(
                kill_peers.is_empty(),
                "Inert deleted records should not need teardown"
            );

            let kill_peers = directory
                .track(
                    2,
                    primary([(pk_3.clone(), dialable(addr_3))].try_into().unwrap()),
                )
                .unwrap();
            assert!(
                kill_peers.is_empty(),
                "Inert deleted records should not need teardown"
            );

            let kill_peers = directory
                .track(
                    3,
                    primary([(pk_3.clone(), dialable(addr_3))].try_into().unwrap()),
                )
                .unwrap();
            assert!(kill_peers.is_empty(), "No peers should be killed");
        });
    }

    #[test]
    fn test_track_kills_connected_peer_removed_from_sets() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(1),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let pk_2 = ed25519::PrivateKey::from_seed(2).public_key();
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1236);

        runtime.start(|context| async move {
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk, config, releaser);

            directory
                .track(
                    0,
                    primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
                )
                .unwrap();
            let reservation = directory.listen(&pk_1).expect("peer should reserve");
            directory.connect(&pk_1);

            let kill_peers = directory
                .track(
                    1,
                    primary([(pk_2.clone(), dialable(addr_2))].try_into().unwrap()),
                )
                .unwrap();

            assert_eq!(kill_peers, Set::try_from([pk_1.clone()]).unwrap());
            let record = directory.peers.get(&pk_1).unwrap();
            assert!(!record.deletable());
            directory.release(reservation.metadata().clone());
            assert!(!directory.peers.contains_key(&pk_1));
            assert_eq!(reservation.metadata().public_key(), &pk_1);
        });
    }

    #[test]
    fn test_secondary_sets_remain_until_eviction() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(2),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let primary_0 = ed25519::PrivateKey::from_seed(1).public_key();
        let primary_0_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let primary_1 = ed25519::PrivateKey::from_seed(2).public_key();
        let primary_1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1236);
        let primary_2 = ed25519::PrivateKey::from_seed(3).public_key();
        let primary_2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1237);
        let secondary_0 = ed25519::PrivateKey::from_seed(4).public_key();
        let secondary_0_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1238);
        let secondary_1 = ed25519::PrivateKey::from_seed(5).public_key();
        let secondary_1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1239);

        runtime.start(|context| async move {
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk, config, releaser);

            assert!(
                directory
                    .track(
                        0,
                        ReachableTrackedPeers::new(
                            [(primary_0, dialable(primary_0_addr))].try_into().unwrap(),
                            [(secondary_0.clone(), dialable(secondary_0_addr))]
                                .try_into()
                                .unwrap(),
                        ),
                    )
                    .is_some()
            );
            assert!(directory.eligible(&secondary_0));

            assert!(
                directory
                    .track(
                        1,
                        ReachableTrackedPeers::new(
                            [(primary_1, dialable(primary_1_addr))].try_into().unwrap(),
                            [(secondary_1.clone(), dialable(secondary_1_addr))]
                                .try_into()
                                .unwrap(),
                        ),
                    )
                    .is_some()
            );
            assert!(directory.eligible(&secondary_0));
            assert!(directory.eligible(&secondary_1));

            assert!(
                directory
                    .track(
                        2,
                        primary([(primary_2, dialable(primary_2_addr))].try_into().unwrap(),),
                    )
                    .is_some()
            );
            assert!(!directory.peers.contains_key(&secondary_0));
            assert!(directory.eligible(&secondary_1));
        });
    }

    #[test]
    fn test_track_overwrite() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let my_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let addr_4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1238);
        let pk_2 = ed25519::PrivateKey::from_seed(2).public_key();
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1236);
        let pk_3 = ed25519::PrivateKey::from_seed(3).public_key();
        let addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1237);

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk.clone(),
                config,
                new_releaser(context.child("releaser")),
            );

            directory.track(
                0,
                primary(
                    [
                        (pk_1.clone(), dialable(addr_1)),
                        (pk_2.clone(), dialable(addr_2)),
                    ]
                    .try_into()
                    .unwrap(),
                ),
            );
            assert!(
                directory
                    .peers
                    .get(&my_pk)
                    .unwrap()
                    .advertisement()
                    .is_none()
            );
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().advertisement(),
                Some(advertisement(addr_1))
            );
            assert_eq!(
                directory.peers.get(&pk_2).unwrap().advertisement(),
                Some(advertisement(addr_2))
            );
            assert!(!directory.peers.contains_key(&pk_3));
            assert_eq!(
                metric_value(
                    &context.encode(),
                    "directory_updates_total",
                    &pk_1.to_string()
                ),
                None
            );

            directory.track(
                1,
                primary([(pk_1.clone(), dialable(addr_4))].try_into().unwrap()),
            );
            assert!(
                directory
                    .peers
                    .get(&my_pk)
                    .unwrap()
                    .advertisement()
                    .is_none()
            );
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().advertisement(),
                Some(advertisement(addr_4))
            );
            assert_eq!(
                directory.peers.get(&pk_2).unwrap().advertisement(),
                Some(advertisement(addr_2))
            );
            assert!(!directory.peers.contains_key(&pk_3));
            assert_eq!(
                metric_value(
                    &context.encode(),
                    "directory_updates_total",
                    &pk_1.to_string()
                ),
                Some(1)
            );

            directory.track(
                2,
                primary([(my_pk.clone(), dialable(addr_3))].try_into().unwrap()),
            );
            assert!(
                directory
                    .peers
                    .get(&my_pk)
                    .unwrap()
                    .advertisement()
                    .is_none()
            );
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().advertisement(),
                Some(advertisement(addr_4))
            );
            assert_eq!(
                directory.peers.get(&pk_2).unwrap().advertisement(),
                Some(advertisement(addr_2))
            );
            assert!(!directory.peers.contains_key(&pk_3));

            let kill_peers = directory
                .track(
                    3,
                    primary([(my_pk.clone(), dialable(my_addr))].try_into().unwrap()),
                )
                .unwrap();
            assert!(kill_peers.is_empty());

            let kill_peers = directory
                .track(
                    4,
                    primary([(my_pk.clone(), dialable(addr_3))].try_into().unwrap()),
                )
                .unwrap();
            assert!(kill_peers.is_empty());

            let result = directory.track(
                0,
                primary(
                    [
                        (pk_1.clone(), dialable(addr_1)),
                        (pk_2.clone(), dialable(addr_2)),
                    ]
                    .try_into()
                    .unwrap(),
                ),
            );
            assert!(result.is_none());
        });
    }

    #[test]
    fn test_track_updates_metric_for_secondary_reachability_change() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1236);

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );

            directory
                .track(
                    0,
                    ReachableTrackedPeers::new(
                        Map::default(),
                        [(pk_1.clone(), dialable(addr_1))].try_into().unwrap(),
                    ),
                )
                .unwrap();
            assert_eq!(
                metric_value(
                    &context.encode(),
                    "directory_updates_total",
                    &pk_1.to_string()
                ),
                None
            );

            directory
                .track(
                    1,
                    ReachableTrackedPeers::new(
                        Map::default(),
                        [(pk_1.clone(), dialable(addr_2))].try_into().unwrap(),
                    ),
                )
                .unwrap();
            assert_eq!(
                metric_value(
                    &context.encode(),
                    "directory_updates_total",
                    &pk_1.to_string()
                ),
                Some(1)
            );
        });
    }

    #[test]
    fn test_track_primary_secondary_overlap_deduplicates() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let primary_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let secondary_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 2235);

        runtime.start(|context| async move {
            // Same pk in primary and secondary maps; deduplicated as primary only.
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk, config, releaser);

            let kill_peers = directory
                .track(
                    0,
                    ReachableTrackedPeers::new(
                        [(pk_1.clone(), dialable(primary_addr))].try_into().unwrap(),
                        [(pk_1.clone(), dialable(secondary_addr))]
                            .try_into()
                            .unwrap(),
                    ),
                )
                .unwrap();

            assert!(kill_peers.is_empty());
            assert_eq!(directory.latest_set_index(), Some(0));
            let peer_set = directory.get_peer_set(&0).unwrap();
            assert_eq!(peer_set.primary, [pk_1.clone()].try_into().unwrap());
            assert!(
                peer_set.secondary.is_empty(),
                "overlap peer is deduplicated as primary only"
            );
            assert!(directory.eligible(&pk_1));
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().advertisement(),
                Some(advertisement(primary_addr))
            );
            assert_eq!(directory.all().primary, [pk_1.clone()].try_into().unwrap());
            assert!(directory.all().secondary.is_empty());
            assert_eq!(directory.dialable().peers, vec![pk_1.clone()]);
            let rec = directory.peers.get(&pk_1).unwrap();
            assert_eq!(rec.primary_sets(), 1);
            assert_eq!(rec.secondary_sets(), 0);
        });
    }

    #[test]
    fn test_demotion_from_primary_to_secondary() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(2),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_x = ed25519::PrivateKey::from_seed(1).public_key();
        let pk_y = ed25519::PrivateKey::from_seed(2).public_key();
        let addr_x = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1000);
        let addr_y = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 2000);

        runtime.start(|context| async move {
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk, config, releaser);

            // Index 0: X is primary, Y is secondary.
            directory
                .track(
                    0,
                    ReachableTrackedPeers::new(
                        [(pk_x.clone(), dialable(addr_x))].try_into().unwrap(),
                        [(pk_y.clone(), dialable(addr_y))].try_into().unwrap(),
                    ),
                )
                .unwrap();
            assert_eq!(directory.peers.get(&pk_x).unwrap().primary_sets(), 1);
            assert_eq!(directory.peers.get(&pk_x).unwrap().secondary_sets(), 0);
            assert_eq!(directory.peers.get(&pk_y).unwrap().primary_sets(), 0);
            assert_eq!(directory.peers.get(&pk_y).unwrap().secondary_sets(), 1);

            // Index 1: X is demoted to secondary, Y is promoted to primary.
            directory
                .track(
                    1,
                    ReachableTrackedPeers::new(
                        [(pk_y.clone(), dialable(addr_y))].try_into().unwrap(),
                        [(pk_x.clone(), dialable(addr_x))].try_into().unwrap(),
                    ),
                )
                .unwrap();

            // Both indices are retained (max_sets=2).
            // X: primary in set 0, secondary in set 1.
            assert_eq!(directory.peers.get(&pk_x).unwrap().primary_sets(), 1);
            assert_eq!(directory.peers.get(&pk_x).unwrap().secondary_sets(), 1);
            // Y: secondary in set 0, primary in set 1.
            assert_eq!(directory.peers.get(&pk_y).unwrap().primary_sets(), 1);
            assert_eq!(directory.peers.get(&pk_y).unwrap().secondary_sets(), 1);

            // Aggregate view: both are primary (primary-wins across sets).
            let agg = directory.all();
            assert!(agg.primary.position(&pk_x).is_some());
            assert!(agg.primary.position(&pk_y).is_some());
            assert!(agg.secondary.is_empty());

            // Index 2: only Y is primary, X is secondary. This evicts index 0.
            directory
                .track(
                    2,
                    ReachableTrackedPeers::new(
                        [(pk_y.clone(), dialable(addr_y))].try_into().unwrap(),
                        [(pk_x.clone(), dialable(addr_x))].try_into().unwrap(),
                    ),
                )
                .unwrap();

            // Index 0 evicted. X lost its primary from index 0.
            // X: primary_sets=0, secondary_sets=2 (from indices 1 and 2).
            assert_eq!(directory.peers.get(&pk_x).unwrap().primary_sets(), 0);
            assert_eq!(directory.peers.get(&pk_x).unwrap().secondary_sets(), 2);
            // Y: primary_sets=2, secondary_sets=0 (secondary from index 0 was evicted).
            assert_eq!(directory.peers.get(&pk_y).unwrap().primary_sets(), 2);
            assert_eq!(directory.peers.get(&pk_y).unwrap().secondary_sets(), 0);

            // Aggregate: X is now purely secondary, Y is purely primary.
            let agg = directory.all();
            assert!(agg.primary.position(&pk_y).is_some());
            assert!(agg.secondary.position(&pk_x).is_some());
            assert!(agg.primary.position(&pk_x).is_none());
            assert!(agg.secondary.position(&pk_y).is_none());
        });
    }

    #[test]
    fn test_track_primary_wins_conflicting_overlap_when_updating_reachability() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::ZERO,
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let old_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let new_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 2235);

        runtime.start(|context| async move {
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk, config, releaser);

            let initial_kill = directory
                .track(
                    0,
                    primary([(pk_1.clone(), dialable(old_addr))].try_into().unwrap()),
                )
                .unwrap();
            assert!(initial_kill.is_empty());
            let reservation = directory.listen(&pk_1).expect("peer should reserve");
            directory.connect(&pk_1);

            let kill_peers = directory
                .track(
                    1,
                    ReachableTrackedPeers::new(
                        [(pk_1.clone(), dialable(new_addr))].try_into().unwrap(),
                        [(pk_1.clone(), dialable(old_addr))].try_into().unwrap(),
                    ),
                )
                .unwrap();

            assert_eq!(kill_peers, Set::try_from([pk_1.clone()]).unwrap());
            assert_eq!(directory.latest_set_index(), Some(1));
            assert_eq!(
                directory.get_peer_set(&1).unwrap().primary,
                [pk_1.clone()].try_into().unwrap()
            );
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().advertisement(),
                Some(advertisement(new_addr))
            );
            assert_eq!(directory.all().primary, [pk_1.clone()].try_into().unwrap());
            directory.release(reservation.metadata().clone());
            assert_eq!(directory.dialable().peers, vec![pk_1.clone()]);
            assert_eq!(directory.dial(&pk_1).unwrap().1, advertisement(new_addr));
        });
    }

    #[test]
    fn test_all_cross_index_primary_wins_for_overlap_peer() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_a = ed25519::PrivateKey::from_seed(31).public_key();
        let pk_b = ed25519::PrivateKey::from_seed(32).public_key();
        let pk_overlap = ed25519::PrivateKey::from_seed(33).public_key();
        let pk_sec = ed25519::PrivateKey::from_seed(34).public_key();

        let addr_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4001);
        let addr_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 4002);
        let addr_overlap_p = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 4003);
        let addr_overlap_s = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 5003);
        let addr_sec = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)), 4004);

        runtime.start(|context| async move {
            // pk_overlap: primary in set 0, secondary in set 1.
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk, config, releaser);

            assert!(
                directory
                    .track(
                        10,
                        primary(
                            [
                                (pk_a.clone(), dialable(addr_a)),
                                (pk_overlap.clone(), dialable(addr_overlap_p)),
                            ]
                            .try_into()
                            .unwrap(),
                        ),
                    )
                    .is_some()
            );
            assert!(
                directory
                    .track(
                        11,
                        ReachableTrackedPeers::new(
                            [(pk_b.clone(), dialable(addr_b))].try_into().unwrap(),
                            [
                                (pk_overlap.clone(), dialable(addr_overlap_s)),
                                (pk_sec.clone(), dialable(addr_sec)),
                            ]
                            .try_into()
                            .unwrap(),
                        ),
                    )
                    .is_some()
            );

            let agg = directory.all();
            assert!(
                agg.primary.position(&pk_overlap).is_some(),
                "any primary membership across tracked sets -> aggregate primary only"
            );
            assert!(
                agg.secondary.position(&pk_overlap).is_none(),
                "aggregate secondary must not duplicate keys that have a primary role somewhere"
            );
            assert!(
                agg.secondary.position(&pk_sec).is_some(),
                "peers who are only secondary across sets stay under aggregate secondary"
            );
        });
    }

    #[test]
    fn test_connected_metric_tracks_active_peers() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(1),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );
            directory
                .track(
                    0,
                    primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
                )
                .unwrap();

            let _reservation = directory.listen(&pk_1).expect("peer should reserve");
            let connected_at: i64 = context.current().epoch_millis().try_into().unwrap();
            directory.connect(&pk_1);

            context.sleep(Duration::from_secs(5)).await;

            let metrics = context.encode();
            assert_eq!(
                metric_value(&metrics, "directory_connected", &pk_1.to_string()),
                Some(connected_at)
            );

            directory.release(super::Metadata::Listener(pk_1.clone()));

            let metrics = context.encode();
            assert_eq!(
                metric_value(&metrics, "directory_connected", &pk_1.to_string()),
                None
            );
        });
    }

    #[test]
    fn test_blocked_peer_remains_blocked_on_update() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2235);

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk.clone(),
                config,
                new_releaser(context.child("releaser")),
            );

            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );
            directory.block(&pk_1);
            assert!(
                directory.blocked.contains(&pk_1),
                "Peer should be blocked after call to block"
            );
            // Reachability is preserved (blocking is tracked in PrioritySet)
            let record = directory.peers.get(&pk_1).unwrap();
            assert_eq!(
                record.advertisement(),
                Some(advertisement(addr_1)),
                "Record still has reachability (blocking is at Directory level)"
            );

            // Update the reachability while blocked
            directory.track(
                1,
                primary([(pk_1.clone(), dialable(addr_2))].try_into().unwrap()),
            );
            assert!(
                directory.blocked.contains(&pk_1),
                "Blocked peer should remain blocked after update"
            );
            // Reachability is updated
            let record = directory.peers.get(&pk_1).unwrap();
            assert_eq!(
                record.advertisement(),
                Some(advertisement(addr_2)),
                "Record has updated reachability"
            );

            // Advance time past block duration and unblock
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            // Verify the peer is unblocked with the updated reachability.
            assert!(
                !directory.blocked.contains(&pk_1),
                "Peer should be unblocked after expiry"
            );
            let record = directory.peers.get(&pk_1).unwrap();
            assert_eq!(
                record.advertisement(),
                Some(advertisement(addr_2)),
                "Unblocked peer should have the updated reachability"
            );
        });
    }

    #[test]
    fn test_multiple_endpoint_advertisement() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let preferred = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let fallback = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
        let advertisement =
            Advertisement::new(vec![Endpoint(preferred), Endpoint(fallback)]).unwrap();
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        runtime.start(|context| async move {
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk, config, releaser);

            let kill_peers = directory
                .track(
                    0,
                    primary(
                        [(pk_1.clone(), Reachability::Dialable(advertisement.clone()))]
                            .try_into()
                            .unwrap(),
                    ),
                )
                .unwrap();
            assert!(kill_peers.is_empty());
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().advertisement(),
                Some(advertisement.clone())
            );
            assert_eq!(directory.dial(&pk_1).unwrap().1, advertisement);
        });
    }

    #[test]
    fn test_outbound_only_peer_is_tracked_but_not_dialable() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let dialable_pk = ed25519::PrivateKey::from_seed(1).public_key();
        let outbound_only_pk = ed25519::PrivateKey::from_seed(2).public_key();
        let dialable_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        runtime.start(|context| async move {
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk, config, releaser);
            directory
                .track(
                    0,
                    primary(
                        [
                            (dialable_pk.clone(), dialable(dialable_addr)),
                            (outbound_only_pk.clone(), Reachability::OutboundOnly),
                        ]
                        .try_into()
                        .unwrap(),
                    ),
                )
                .unwrap();

            assert!(directory.eligible(&outbound_only_pk));
            assert!(directory.acceptable(&outbound_only_pk));
            assert_eq!(directory.dialable().peers, vec![dialable_pk]);
            assert!(directory.dial(&outbound_only_pk).is_none());
        });
    }

    #[test]
    fn test_unblock_expired() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );

            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );

            // Block the peer
            directory.block(&pk_1);

            // Verify peer is blocked
            assert_eq!(directory.blocked(), 1, "Should have one blocked peer");

            // Get first expiry time
            let first_expiry = directory
                .blocked
                .get(&pk_1)
                .expect("peer should be blocked");

            // unblock_expired should return false before expiry
            assert!(
                !directory.unblock_expired(),
                "No peers should be unblocked before expiry"
            );

            // Advance time past block duration
            context.sleep(block_duration + Duration::from_secs(1)).await;

            // Now unblock_expired should unblock the peer
            assert!(directory.unblock_expired(), "Should have unblocked a peer");

            // Verify no more blocked peers
            assert_eq!(directory.blocked(), 0, "No more blocked peers");

            // Re-block the peer and verify expiry time increased
            directory.block(&pk_1);
            assert_eq!(directory.blocked(), 1, "Should have one blocked peer again");

            let second_expiry = directory
                .blocked
                .get(&pk_1)
                .expect("peer should be blocked again");

            assert!(
                second_expiry > first_expiry,
                "Re-blocking should have a later expiry time"
            );
        });
    }

    #[test]
    fn test_unblock_expired_peer_removed_and_readded() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            max_sets: NZUsize!(1), // Only keep 1 set so we can evict peers
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let pk_2 = ed25519::PrivateKey::from_seed(2).public_key();
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1236);

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );

            // Initially no blocked peers
            assert!(
                directory.metrics.blocked.get_by(&pk_1).is_none(),
                "pk_1 should not be blocked initially"
            );

            // Add pk_1 and block it
            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );
            directory.block(&pk_1);
            assert!(directory.blocked.contains(&pk_1));
            assert!(
                directory.metrics.blocked.get_by(&pk_1).is_some(),
                "pk_1 should be marked blocked"
            );

            // Add a new set that evicts pk_1 (max_sets=1)
            // The blocked metric should remain since the block persists
            directory.track(
                1,
                primary([(pk_2.clone(), dialable(addr_2))].try_into().unwrap()),
            );
            assert!(
                !directory.peers.contains_key(&pk_1),
                "pk_1 should be removed"
            );
            assert!(
                directory.metrics.blocked.get_by(&pk_1).is_some(),
                "blocked metric should persist after peer removal"
            );

            // Re-add pk_1 - should still be blocked because block persists
            directory.track(
                2,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );
            assert!(
                directory.blocked.contains(&pk_1),
                "Re-added pk_1 should still be blocked"
            );
            assert!(
                directory.metrics.blocked.get_by(&pk_1).is_some(),
                "blocked metric should persist after re-add"
            );

            // Advance time past block duration
            context.sleep(block_duration + Duration::from_secs(1)).await;

            // Now unblock_expired should unblock pk_1
            assert!(directory.unblock_expired());
            assert!(
                !directory.blocked.contains(&pk_1),
                "pk_1 should no longer be blocked"
            );
            assert!(
                directory.metrics.blocked.get_by(&pk_1).is_none(),
                "blocked metric should be removed after unblock"
            );
        });
    }

    #[test]
    fn test_blocked_metric_multiple_peers() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let pk_2 = ed25519::PrivateKey::from_seed(2).public_key();
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1236);
        let pk_3 = ed25519::PrivateKey::from_seed(3).public_key();
        let addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1237);

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );

            // Add all peers
            directory.track(
                0,
                primary(
                    [
                        (pk_1.clone(), dialable(addr_1)),
                        (pk_2.clone(), dialable(addr_2)),
                        (pk_3.clone(), dialable(addr_3)),
                    ]
                    .try_into()
                    .unwrap(),
                ),
            );
            assert_eq!(directory.blocked(), 0);

            // Block all three peers
            directory.block(&pk_1);
            assert!(directory.metrics.blocked.get_by(&pk_1).is_some());
            directory.block(&pk_2);
            assert!(directory.metrics.blocked.get_by(&pk_2).is_some());
            directory.block(&pk_3);
            assert!(directory.metrics.blocked.get_by(&pk_3).is_some());
            assert_eq!(directory.blocked(), 3);

            // Blocking again should not change anything
            directory.block(&pk_1);
            assert!(directory.metrics.blocked.get_by(&pk_1).is_some());

            // Advance time and unblock all
            context.sleep(block_duration + Duration::from_secs(1)).await;
            assert!(directory.unblock_expired());
            assert!(directory.metrics.blocked.get_by(&pk_1).is_none());
            assert!(directory.metrics.blocked.get_by(&pk_2).is_none());
            assert!(directory.metrics.blocked.get_by(&pk_3).is_none());
            assert_eq!(directory.blocked(), 0);
        });
    }

    #[test]
    fn test_block_myself_no_panic_on_expiry() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk.clone(),
                config,
                new_releaser(context.child("releaser")),
            );

            // Blocking myself should be ignored (Myself is unblockable)
            directory.block(&my_pk);

            // Metrics should not have an entry for myself
            assert!(
                directory.metrics.blocked.get_by(&my_pk).is_none(),
                "Blocking myself should not create metric entry"
            );

            // No peers should be blocked
            assert_eq!(directory.blocked(), 0, "No peers should be blocked");

            // Advance time past block duration
            context.sleep(block_duration + Duration::from_secs(1)).await;

            // unblock_expired should not panic and return false
            assert!(!directory.unblock_expired(), "No peers should be unblocked");
        });
    }

    #[test]
    fn test_block_nonexistent_peer_then_add_to_set() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let unknown_pk = ed25519::PrivateKey::from_seed(99).public_key();
        let unknown_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );

            // Block a peer that doesn't exist yet
            directory.block(&unknown_pk);

            // Metrics should have an entry for the blocked peer
            assert!(
                directory.metrics.blocked.get_by(&unknown_pk).is_some(),
                "Blocking nonexistent peer should create metric entry"
            );

            // Peer should be blocked
            assert_eq!(directory.blocked(), 1, "One peer should be blocked");

            // Peer should not be in peers yet
            assert!(
                !directory.peers.contains_key(&unknown_pk),
                "Peer should not be in peers yet"
            );

            // Now track the peer in a set
            directory.track(
                0,
                primary(
                    [(unknown_pk.clone(), dialable(unknown_addr))]
                        .try_into()
                        .unwrap(),
                ),
            );

            // Peer should now be in peers and blocked
            assert!(
                directory.peers.contains_key(&unknown_pk),
                "Peer should be in peers after tracking"
            );
            assert!(
                directory.blocked.contains(&unknown_pk),
                "Peer should be blocked after tracking"
            );

            // Peer should not be eligible
            assert!(
                !directory.eligible(&unknown_pk),
                "Blocked peer should not be eligible"
            );

            // Advance time past block duration
            context.sleep(block_duration + Duration::from_secs(1)).await;

            // Unblock the peer
            directory.unblock_expired();

            // Metrics entry should be removed for the unblocked peer
            assert!(
                directory.metrics.blocked.get_by(&unknown_pk).is_none(),
                "Blocked metric should be removed after unblock"
            );

            // Peer should now be eligible
            assert!(
                directory.eligible(&unknown_pk),
                "Peer should be eligible after unblock"
            );
        });
    }

    #[test]
    fn test_block_peer_multiple_times() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let unknown_pk = ed25519::PrivateKey::from_seed(99).public_key();
        let registered_pk = ed25519::PrivateKey::from_seed(50).public_key();
        let registered_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5050);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );

            // Register a peer
            directory.track(
                0,
                primary(
                    [(registered_pk.clone(), dialable(registered_addr))]
                        .try_into()
                        .unwrap(),
                ),
            );
            assert!(
                directory.metrics.blocked.get_by(&registered_pk).is_none(),
                "Peer should not be blocked initially"
            );

            // Block tracked peer multiple times
            directory.block(&registered_pk);
            assert!(
                directory.metrics.blocked.get_by(&registered_pk).is_some(),
                "Tracked peer should be marked blocked"
            );

            directory.block(&registered_pk);
            assert!(
                directory.metrics.blocked.get_by(&registered_pk).is_some(),
                "Blocking same tracked peer twice should not change metric"
            );

            directory.block(&registered_pk);
            assert!(
                directory.metrics.blocked.get_by(&registered_pk).is_some(),
                "Blocking same tracked peer thrice should not change metric"
            );

            // Block a nonexistent peer multiple times
            directory.block(&unknown_pk);
            assert!(
                directory.metrics.blocked.get_by(&unknown_pk).is_some(),
                "Unknown peer should be marked blocked"
            );

            directory.block(&unknown_pk);
            assert!(
                directory.metrics.blocked.get_by(&unknown_pk).is_some(),
                "Blocking same nonexistent peer twice should not change metric"
            );

            directory.block(&unknown_pk);
            assert!(
                directory.metrics.blocked.get_by(&unknown_pk).is_some(),
                "Blocking same nonexistent peer thrice should not change metric"
            );
        });
    }

    #[test]
    fn test_blocked_peer_not_dialable() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );

            // Add peer to a set
            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );

            // Peer should be dialable before blocking
            assert!(
                directory.dialable().peers.contains(&pk_1),
                "Peer should be dialable before blocking"
            );

            // Block the peer
            directory.block(&pk_1);

            // Peer should NOT be dialable while blocked
            assert!(
                !directory.dialable().peers.contains(&pk_1),
                "Blocked peer should not be dialable"
            );

            // Advance time and unblock
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            // Peer should be dialable again after unblock
            assert!(
                directory.dialable().peers.contains(&pk_1),
                "Peer should be dialable after unblock"
            );
        });
    }

    #[test]
    fn test_reservation_rate_limits_redial() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let cooldown = Duration::from_secs(1);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: cooldown,
            block_duration: Duration::from_secs(100),
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );
            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );

            // First reservation succeeds.
            let reservation = directory.dial(&pk_1).expect("first dial should succeed");

            // Release the reservation.
            drop(reservation);
            directory.release(super::Metadata::Dialer(pk_1.clone()));

            // Immediate re-dial is rate-limited.
            assert!(
                directory.dial(&pk_1).is_none(),
                "should be rate-limited immediately after release"
            );
            assert!(
                !directory.dialable().peers.contains(&pk_1),
                "should not appear in dialable list during rate-limit window"
            );

            // After the jitter window (up to 2x interval), peer becomes dialable again.
            context.sleep(cooldown * 2).await;
            assert!(directory.dialable().peers.contains(&pk_1));
            let (_reservation, dial_advertisement) = directory
                .dial(&pk_1)
                .expect("should succeed after interval");
            assert_eq!(dial_advertisement, advertisement(addr_1));
        });
    }

    #[test]
    fn test_dialable_next_query_at_reflects_rate_limit() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let cooldown = Duration::from_secs(1);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: cooldown,
            block_duration: Duration::from_secs(100),
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );
            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );

            // Reserve and release.
            let reservation = directory.dial(&pk_1).expect("first dial should succeed");
            let reserved_at = context.current();
            drop(reservation);
            directory.release(super::Metadata::Dialer(pk_1.clone()));

            // next_query_at reflects the jittered next_dial_at (between 1x and 2x interval).
            let interval = cooldown;
            let dialable = directory.dialable();
            assert!(!dialable.peers.contains(&pk_1));
            let nqa = dialable.next_query_at.unwrap();
            assert!(nqa >= reserved_at + interval);
            assert!(nqa <= reserved_at + interval * 2);
        });
    }

    #[test]
    fn test_dialable_empty() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let cooldown = Duration::from_millis(200);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: cooldown,
            block_duration: Duration::from_secs(100),
        };

        runtime.start(|context| async move {
            let directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );

            let dialable = directory.dialable();
            assert!(dialable.peers.is_empty());
            assert_eq!(dialable.next_query_at, None);
        });
    }

    #[test]
    fn test_dialable_next_query_at_includes_blocked() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1234);
        let cooldown = Duration::from_millis(200);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: cooldown,
            block_duration: Duration::from_secs(3600),
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );
            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );

            // Block the only peer. No peers are immediately dialable, but
            // next_query_at should point to the blocked peer's unblock time
            // so the dialer knows when to re-check.
            directory.block(&pk_1);
            let dialable = directory.dialable();
            assert!(dialable.peers.is_empty());
            assert_eq!(
                dialable.next_query_at,
                Some(context.current() + Duration::from_secs(3600))
            );
        });
    }

    #[test]
    fn test_dialable_expired_block_without_unblock() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1234);
        let block_duration = Duration::from_secs(1);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(200),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );
            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );

            directory.block(&pk_1);
            assert!(directory.dialable().peers.is_empty());

            // Advance past the block expiry but do NOT call unblock_expired().
            context.sleep(block_duration + Duration::from_secs(1)).await;

            // The peer should still be dialable despite the stale block entry.
            let dialable = directory.dialable();
            assert!(
                dialable.peers.contains(&pk_1),
                "expired block should not prevent dialing"
            );
            assert_eq!(
                dialable.next_query_at, None,
                "expired block should not contribute a stale hint"
            );

            // Reservation should also succeed.
            directory
                .dial(&pk_1)
                .expect("expired block should not prevent reservation");
        });
    }

    #[test]
    fn test_reblock_after_expired_block_without_unblock() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1234);
        let block_duration = Duration::from_secs(1);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(200),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );
            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );

            directory.block(&pk_1);
            assert!(directory.dialable().peers.is_empty());

            // Advance past expiry without calling unblock_expired().
            context.sleep(block_duration + Duration::from_secs(1)).await;

            // Re-block should succeed despite stale entry.
            directory.block(&pk_1);
            assert!(
                directory.dialable().peers.is_empty(),
                "re-blocked peer should not be dialable"
            );
            assert!(
                directory.dial(&pk_1).is_none(),
                "re-blocked peer should not be reservable"
            );
        });
    }

    #[test]
    fn test_blocked_peer_not_acceptable() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );

            // Add peer to a set
            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );

            // Peer should be acceptable before blocking
            assert!(
                directory.acceptable(&pk_1),
                "Peer should be acceptable before blocking"
            );

            // Block the peer
            directory.block(&pk_1);

            // Peer should NOT be acceptable while blocked
            assert!(
                !directory.acceptable(&pk_1),
                "Blocked peer should not be acceptable"
            );

            // Advance time and unblock
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            // Peer should be acceptable again after unblock
            assert!(
                directory.acceptable(&pk_1),
                "Peer should be acceptable after unblock"
            );
        });
    }

    #[test]
    fn test_blocked_peer_not_eligible() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );

            // Add peer to a set
            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );

            // Peer should be eligible before blocking
            assert!(
                directory.eligible(&pk_1),
                "Peer should be eligible before blocking"
            );

            // Block the peer
            directory.block(&pk_1);

            // Peer should NOT be eligible while blocked
            assert!(
                !directory.eligible(&pk_1),
                "Blocked peer should not be eligible"
            );

            // Advance time and unblock
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            // Peer should be eligible again after unblock
            assert!(
                directory.eligible(&pk_1),
                "Peer should be eligible after unblock"
            );
        });
    }

    #[test]
    fn test_overwrite_basic() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 1236);

        runtime.start(|context| async move {
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk, config, releaser);

            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );

            assert_eq!(
                directory.peers.get(&pk_1).unwrap().advertisement(),
                Some(advertisement(addr_1))
            );

            let success = directory.overwrite(&pk_1, dialable(addr_2));
            assert!(success);
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().advertisement(),
                Some(advertisement(addr_2))
            );
        });
    }

    #[test]
    fn test_overwrite_untracked_peer() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);

        runtime.start(|context| async move {
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk, config, releaser);

            let success = directory.overwrite(&pk_1, dialable(addr_1));
            assert!(!success);
        });
    }

    #[test]
    fn test_overwrite_peer_not_in_set() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(1),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let pk_2 = ed25519::PrivateKey::from_seed(2).public_key();
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 1236);
        let addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)), 1237);

        runtime.start(|context| async move {
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk, config, releaser);

            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );
            directory.track(
                1,
                primary([(pk_2.clone(), dialable(addr_2))].try_into().unwrap()),
            );

            let success = directory.overwrite(&pk_1, dialable(addr_3));
            assert!(!success);
        });
    }

    #[test]
    fn test_overwrite_blocked_peer() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 1236);

        runtime.start(|context| async move {
            let mut directory = Directory::init(
                context.child("directory"),
                my_pk,
                config,
                new_releaser(context.child("releaser")),
            );

            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );
            directory.block(&pk_1);

            let success = directory.overwrite(&pk_1, dialable(addr_2));
            assert!(success);
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().advertisement(),
                Some(advertisement(addr_2))
            );

            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            assert_eq!(
                directory.peers.get(&pk_1).unwrap().advertisement(),
                Some(advertisement(addr_2))
            );
            assert!(directory.dialable().peers.contains(&pk_1));
        });
    }

    #[test]
    fn test_overwrite_myself() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);

        runtime.start(|context| async move {
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk.clone(), config, releaser);

            let success = directory.overwrite(&my_pk, dialable(addr_1));
            assert!(!success);
        });
    }

    #[test]
    fn test_overwrite_same_reachability() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let config = super::Config {
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);

        runtime.start(|context| async move {
            let releaser = new_releaser(context.child("releaser"));
            let mut directory = Directory::init(context, my_pk, config, releaser);

            directory.track(
                0,
                primary([(pk_1.clone(), dialable(addr_1))].try_into().unwrap()),
            );

            // First update with different reachability should succeed
            let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 1236);
            assert!(directory.overwrite(&pk_1, dialable(addr_2)));

            // Update with same reachability should return false (no change)
            assert!(!directory.overwrite(&pk_1, dialable(addr_2)));

            // Update with different reachability should succeed again
            let addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)), 1237);
            assert!(directory.overwrite(&pk_1, dialable(addr_3)));
        });
    }
}
