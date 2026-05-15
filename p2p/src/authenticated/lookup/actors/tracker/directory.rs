use super::{metrics::Metrics, record::Record, Metadata, Reservation};
use crate::{
    authenticated::{
        dialing::{earliest, DialStatus, Dialable, ReserveResult},
        lookup::actors::tracker::ingress::Releaser,
    },
    types::Address,
    utils::PeerSetsAtIndex as PeerSetsAtIndexBase,
    AddressableTrackedPeers, Ingress, PeerSetUpdate, TrackedPeers,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{telemetry::metrics::GaugeExt, Clock, Metrics as RuntimeMetrics, Spawner};
use commonware_utils::{ordered::Set, IpAddrExt, PrioritySet, SystemTimeExt};
use rand::Rng;
use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap, HashSet},
    net::IpAddr,
    num::NonZeroUsize,
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

/// Primary and secondary [`Set`] at one peer set index.
type PeerSetsAtIndex<C> = PeerSetsAtIndexBase<Set<C>, Set<C>>;

/// Configuration for the [Directory].
pub struct Config {
    /// Whether private IPs are connectable.
    pub allow_private_ips: bool,

    /// Whether DNS-based ingress addresses are allowed.
    pub allow_dns: bool,

    /// Whether to skip IP verification for incoming connections (allows unknown IPs).
    pub bypass_ip_check: bool,

    /// The maximum number of peer sets to track.
    pub max_sets: NonZeroUsize,

    /// The cooldown between reservations for a given peer.
    pub peer_connection_cooldown: Duration,

    /// Duration after which a blocked peer is allowed to reconnect.
    pub block_duration: Duration,
}

/// Represents a collection of records for all peers.
pub struct Directory<E: Rng + Clock + RuntimeMetrics, C: PublicKey> {
    context: E,

    // ---------- Configuration ----------
    /// The maximum number of peer sets to track.
    max_sets: NonZeroUsize,

    /// Whether private IPs are connectable.
    pub allow_private_ips: bool,

    /// Whether DNS-based ingress addresses are allowed.
    allow_dns: bool,

    /// Whether to skip IP verification for incoming connections (allows unknown IPs).
    bypass_ip_check: bool,

    /// Duration after which a blocked peer is allowed to reconnect.
    block_duration: Duration,

    /// Minimum duration between reservations for a given peer.
    peer_connection_cooldown: Duration,

    // ---------- State ----------
    /// The records of all peers.
    peers: HashMap<C, Record>,

    /// Primary and secondary peer sets indexed by peer set ID.
    peer_sets: BTreeMap<u64, PeerSetsAtIndex<C>>,

    /// Tracks blocked peers and their unblock time. This is the source of truth for
    /// whether a peer is blocked, persisting even if the peer record is deleted.
    blocked: PrioritySet<C, SystemTime>,

    // ---------- Message-Passing ----------
    /// The releaser for the tracker actor.
    releaser: Releaser<C>,

    // ---------- Metrics ----------
    /// The metrics for the records.
    metrics: Metrics<C>,
}

impl<E: Spawner + Rng + Clock + RuntimeMetrics, C: PublicKey> Directory<E, C> {
    /// Create a new set of records using the given local node information.
    pub fn init(context: E, myself: C, cfg: Config, releaser: Releaser<C>) -> Self {
        // Create the list of peers and add myself.
        let mut peers = HashMap::new();
        peers.insert(myself, Record::myself());

        let metrics = Metrics::init(&context);
        let _ = metrics.tracked.try_set(peers.len() - 1); // Exclude self

        Self {
            context,
            max_sets: cfg.max_sets,
            allow_private_ips: cfg.allow_private_ips,
            allow_dns: cfg.allow_dns,
            bypass_ip_check: cfg.bypass_ip_check,
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
    /// # Panics
    ///
    /// Panics if the peer has no record or if the peer is not in the reserved state.
    pub fn connect(&mut self, peer: &C) {
        // Set the record as connected
        let record = self.peers.get_mut(peer).unwrap();
        record.connect();
        let _ = self
            .metrics
            .connected
            .get_or_create_by(peer)
            .try_set(self.context.current().epoch_millis());
    }

    /// Track new primary and secondary peer sets for the given index.
    ///
    /// Returns the peers whose connections should be reset because they were
    /// removed from all tracked peer sets or had their address changed.
    ///
    /// Returns `None` if the index is invalid.
    pub fn track(&mut self, index: u64, peers: AddressableTrackedPeers<C>) -> Option<Set<C>> {
        // Check if peer set already exists
        if self.peer_sets.contains_key(&index) {
            warn!(index, "peer set already exists");
            return None;
        }

        // Ensure that peer set is monotonically increasing
        if let Some((last, _)) = self.peer_sets.last_key_value() {
            if index <= *last {
                warn!(?index, ?last, "index must monotonically increase");
                return None;
            }
        }

        // Create and store new primary peer set (all peers are tracked regardless of address
        // validity).
        let mut reset_peers = Vec::new();
        for (primary, addr) in &peers.primary {
            let record = match self.peers.entry(primary.clone()) {
                Entry::Occupied(entry) => {
                    let entry = entry.into_mut();
                    if entry.update(addr.clone()) {
                        self.metrics.updates.get_or_create_by(primary).inc();
                        reset_peers.push(primary.clone());
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
                        reset_peers.push(secondary.clone());
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
                let deleted = self.delete_if_needed(&primary);
                if deleted {
                    reset_peers.push(primary);
                }
            });
            sets.secondary.into_iter().for_each(|secondary| {
                self.peers
                    .get_mut(&secondary)
                    .unwrap()
                    .decrement_secondary();
                let deleted = self.delete_if_needed(&secondary);
                if deleted {
                    reset_peers.push(secondary);
                }
            });
        }

        Some(Set::from_iter_dedup(reset_peers))
    }

    /// Update a tracked peer's address.
    ///
    /// Returns `true` if the peer exists and the address actually changed.
    /// The caller should sever any existing connection to this peer since it
    /// was established to the old address.
    ///
    /// Returns `false` if the peer has no record, is ourselves, or the
    /// new address is identical to the existing one.
    pub fn overwrite(&mut self, peer: &C, address: Address) -> bool {
        let Some(record) = self.peers.get_mut(peer) else {
            return false;
        };
        record.update(address)
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
    pub fn dial(&mut self, peer: &C) -> Option<(Reservation<C>, Ingress)> {
        let record = self.peers.get(peer)?;
        if !record.is_outbound_target() {
            return None;
        }
        let ingress = record.ingress()?;
        let reservation = self.reserve(Metadata::Dialer(peer.clone()))?;
        Some((reservation, ingress))
    }

    /// Attempt to reserve a peer for the listener.
    ///
    /// Returns `Some` on success, `None` otherwise.
    pub fn listen(&mut self, peer: &C) -> Option<Reservation<C>> {
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
        if let Some(record) = self.peers.get(peer) {
            if !record.is_blockable() {
                return;
            }
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
            match record.dialable(now, self.allow_private_ips, self.allow_dns) {
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
    /// Checks eligibility (peer set membership), blocked status, egress IP match (if not bypass_ip_check),
    /// and connection status.
    pub fn acceptable(&self, peer: &C, source_ip: IpAddr) -> bool {
        !self.is_blocked(peer)
            && self
                .peers
                .get(peer)
                .is_some_and(|record| record.acceptable(source_ip, self.bypass_ip_check))
    }

    /// Return egress IPs we should listen for (accept incoming connections from).
    ///
    /// Only includes IPs from peers that are:
    /// - Currently eligible (not blocked, in a peer set)
    /// - Have a valid egress IP (global, or private IPs are allowed)
    pub fn listenable(&self) -> HashSet<IpAddr> {
        self.peers
            .iter()
            .filter(|(peer, r)| !self.is_blocked(peer) && r.eligible())
            .filter_map(|(_, r)| r.egress_ip())
            .filter(|ip| self.allow_private_ips || IpAddrExt::is_global(ip))
            .collect()
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
    fn reserve(&mut self, metadata: Metadata<C>) -> Option<Reservation<C>> {
        let peer = metadata.public_key();

        // Not reservable (must be in a peer set)
        if !self.eligible(peer) {
            return None;
        }

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

    /// Attempt to delete a record.
    ///
    /// Returns `true` if the record was deleted, `false` otherwise.
    fn delete_if_needed(&mut self, peer: &C) -> bool {
        let Some(record) = self.peers.get(peer) else {
            return false;
        };
        if !record.deletable() {
            return false;
        }

        // We don't decrement the blocked metric here because the block
        // persists in PrioritySet even after the record is deleted. The metric
        // is decremented in unblock_expired when the block actually expires.
        self.peers.remove(peer);
        self.metrics.tracked.dec();
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        authenticated::lookup::actors::tracker::directory::Directory,
        types::Address,
        AddressableTrackedPeers, Ingress,
    };
    use commonware_actor::mailbox;
    use commonware_cryptography::{ed25519, Signer};
    use commonware_runtime::{deterministic, Clock, Metrics as _, Runner, Supervisor as _};
    use commonware_utils::{
        hostname,
        ordered::{Map, Set},
        NZUsize, SystemTimeExt,
    };
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    fn addr(socket: SocketAddr) -> Address {
        Address::Symmetric(socket)
    }

    fn primary(
        map: Map<ed25519::PublicKey, Address>,
    ) -> AddressableTrackedPeers<ed25519::PublicKey> {
        AddressableTrackedPeers::from(map)
    }

    fn metric_value(metrics: &str, name: &str, peer: &str) -> Option<i64> {
        metrics
            .lines()
            .find(|line| line.starts_with(&format!("{name}{{peer=\"{peer}\"}} ")))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<i64>().ok())
    }

    #[test]
    fn test_track_return_value() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
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
            let mut directory = Directory::init(context, my_pk, config, releaser);

            let reset_peers = directory
                .track(
                    0,
                    primary(
                        [(pk_1.clone(), addr(addr_1)), (pk_2.clone(), addr(addr_2))]
                            .try_into()
                            .unwrap(),
                    ),
                )
                .unwrap();
            assert!(
                reset_peers.is_empty(),
                "No peers should be deleted on first set"
            );

            let reset_peers = directory
                .track(
                    1,
                    primary(
                        [(pk_2.clone(), addr(addr_2)), (pk_3.clone(), addr(addr_3))]
                            .try_into()
                            .unwrap(),
                    ),
                )
                .unwrap();
            assert_eq!(reset_peers.len(), 1, "One peer should be reset");
            assert!(
                reset_peers.position(&pk_1).is_some(),
                "Reset peer should be pk_1"
            );

            let reset_peers = directory
                .track(
                    2,
                    primary([(pk_3.clone(), addr(addr_3))].try_into().unwrap()),
                )
                .unwrap();
            assert_eq!(reset_peers.len(), 1, "One peer should be reset");
            assert!(
                reset_peers.position(&pk_2).is_some(),
                "Reset peer should be pk_2"
            );

            let reset_peers = directory
                .track(
                    3,
                    primary([(pk_3.clone(), addr(addr_3))].try_into().unwrap()),
                )
                .unwrap();
            assert!(reset_peers.is_empty(), "No peers should be reset");
        });
    }

    #[test]
    fn test_secondary_sets_remain_until_eviction() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
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
            let mut directory = Directory::init(context, my_pk, config, releaser);

            assert!(directory
                .track(
                    0,
                    AddressableTrackedPeers::new(
                        [(primary_0, addr(primary_0_addr))].try_into().unwrap(),
                        [(secondary_0.clone(), addr(secondary_0_addr))]
                            .try_into()
                            .unwrap(),
                    ),
                )
                .is_some());
            assert!(directory.eligible(&secondary_0));

            assert!(directory
                .track(
                    1,
                    AddressableTrackedPeers::new(
                        [(primary_1, addr(primary_1_addr))].try_into().unwrap(),
                        [(secondary_1.clone(), addr(secondary_1_addr))]
                            .try_into()
                            .unwrap(),
                    ),
                )
                .is_some());
            assert!(directory.eligible(&secondary_0));
            assert!(directory.eligible(&secondary_1));

            assert!(directory
                .track(
                    2,
                    primary([(primary_2, addr(primary_2_addr))].try_into().unwrap(),),
                )
                .is_some());
            assert!(!directory.peers.contains_key(&secondary_0));
            assert!(directory.eligible(&secondary_1));
        });
    }

    #[test]
    fn test_track_overwrite() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let my_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
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
            let mut directory =
                Directory::init(context.child("directory"), my_pk.clone(), config, releaser);

            directory.track(
                0,
                primary(
                    [(pk_1.clone(), addr(addr_1)), (pk_2.clone(), addr(addr_2))]
                        .try_into()
                        .unwrap(),
                ),
            );
            assert!(directory.peers.get(&my_pk).unwrap().ingress().is_none());
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().ingress(),
                Some(Ingress::Socket(addr_1))
            );
            assert_eq!(
                directory.peers.get(&pk_2).unwrap().ingress(),
                Some(Ingress::Socket(addr_2))
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
                primary([(pk_1.clone(), addr(addr_4))].try_into().unwrap()),
            );
            assert!(directory.peers.get(&my_pk).unwrap().ingress().is_none());
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().ingress(),
                Some(Ingress::Socket(addr_4))
            );
            assert_eq!(
                directory.peers.get(&pk_2).unwrap().ingress(),
                Some(Ingress::Socket(addr_2))
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
                primary([(my_pk.clone(), addr(addr_3))].try_into().unwrap()),
            );
            assert!(directory.peers.get(&my_pk).unwrap().ingress().is_none());
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().ingress(),
                Some(Ingress::Socket(addr_4))
            );
            assert_eq!(
                directory.peers.get(&pk_2).unwrap().ingress(),
                Some(Ingress::Socket(addr_2))
            );
            assert!(!directory.peers.contains_key(&pk_3));

            let reset_peers = directory
                .track(
                    3,
                    primary([(my_pk.clone(), addr(my_addr))].try_into().unwrap()),
                )
                .unwrap();
            assert_eq!(reset_peers.len(), 1);
            assert!(reset_peers.position(&pk_2).is_some());

            let reset_peers = directory
                .track(
                    4,
                    primary([(my_pk.clone(), addr(addr_3))].try_into().unwrap()),
                )
                .unwrap();
            assert_eq!(reset_peers.len(), 1);
            assert!(reset_peers.position(&pk_1).is_some());

            let result = directory.track(
                0,
                primary(
                    [(pk_1.clone(), addr(addr_1)), (pk_2.clone(), addr(addr_2))]
                        .try_into()
                        .unwrap(),
                ),
            );
            assert!(result.is_none());
        });
    }

    #[test]
    fn test_track_updates_metric_for_secondary_address_change() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1236);

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);

            directory
                .track(
                    0,
                    AddressableTrackedPeers::new(
                        Map::default(),
                        [(pk_1.clone(), addr(addr_1))].try_into().unwrap(),
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
                    AddressableTrackedPeers::new(
                        Map::default(),
                        [(pk_1.clone(), addr(addr_2))].try_into().unwrap(),
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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let primary_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let secondary_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 2235);

        runtime.start(|context| async move {
            // Same pk in primary and secondary maps; deduplicated as primary only.
            let mut directory = Directory::init(context, my_pk, config, releaser);

            let reset_peers = directory
                .track(
                    0,
                    AddressableTrackedPeers::new(
                        [(pk_1.clone(), addr(primary_addr))].try_into().unwrap(),
                        [(pk_1.clone(), addr(secondary_addr))].try_into().unwrap(),
                    ),
                )
                .unwrap();

            assert!(reset_peers.is_empty());
            assert_eq!(directory.latest_set_index(), Some(0));
            let peer_set = directory.get_peer_set(&0).unwrap();
            assert_eq!(peer_set.primary, [pk_1.clone()].try_into().unwrap());
            assert!(
                peer_set.secondary.is_empty(),
                "overlap peer is deduplicated as primary only"
            );
            assert!(directory.eligible(&pk_1));
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().ingress(),
                Some(Ingress::Socket(primary_addr))
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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(2),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_x = ed25519::PrivateKey::from_seed(1).public_key();
        let pk_y = ed25519::PrivateKey::from_seed(2).public_key();
        let addr_x = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1000);
        let addr_y = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 2000);

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, my_pk, config, releaser);

            // Index 0: X is primary, Y is secondary.
            directory
                .track(
                    0,
                    AddressableTrackedPeers::new(
                        [(pk_x.clone(), addr(addr_x))].try_into().unwrap(),
                        [(pk_y.clone(), addr(addr_y))].try_into().unwrap(),
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
                    AddressableTrackedPeers::new(
                        [(pk_y.clone(), addr(addr_y))].try_into().unwrap(),
                        [(pk_x.clone(), addr(addr_x))].try_into().unwrap(),
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
                    AddressableTrackedPeers::new(
                        [(pk_y.clone(), addr(addr_y))].try_into().unwrap(),
                        [(pk_x.clone(), addr(addr_x))].try_into().unwrap(),
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
    fn test_track_primary_wins_conflicting_overlap_when_updating_existing_address() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let old_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let new_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 2235);

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, my_pk, config, releaser);

            let initial_reset = directory
                .track(
                    0,
                    primary([(pk_1.clone(), addr(old_addr))].try_into().unwrap()),
                )
                .unwrap();
            assert!(initial_reset.is_empty());

            let reset_peers = directory
                .track(
                    1,
                    AddressableTrackedPeers::new(
                        [(pk_1.clone(), addr(new_addr))].try_into().unwrap(),
                        [(pk_1.clone(), addr(old_addr))].try_into().unwrap(),
                    ),
                )
                .unwrap();

            assert_eq!(reset_peers, Set::try_from([pk_1.clone()]).unwrap());
            assert_eq!(directory.latest_set_index(), Some(1));
            assert_eq!(
                directory.get_peer_set(&1).unwrap().primary,
                [pk_1.clone()].try_into().unwrap()
            );
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().ingress(),
                Some(Ingress::Socket(new_addr))
            );
            assert_eq!(directory.all().primary, [pk_1.clone()].try_into().unwrap());
            assert_eq!(directory.dialable().peers, vec![pk_1.clone()]);
            assert_eq!(directory.dial(&pk_1).unwrap().1, Ingress::Socket(new_addr));
            assert!(directory.listenable().contains(&new_addr.ip()));
            assert!(!directory.listenable().contains(&old_addr.ip()));
        });
    }

    #[test]
    fn test_all_cross_index_primary_wins_for_overlap_peer() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
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
            // pk_overlap: primary in set 0 (address addr_overlap_p), secondary in set 1 (addr_overlap_s).
            let mut directory = Directory::init(context, my_pk, config, releaser);

            assert!(directory
                .track(
                    10,
                    primary(
                        [
                            (pk_a.clone(), addr(addr_a)),
                            (pk_overlap.clone(), addr(addr_overlap_p)),
                        ]
                        .try_into()
                        .unwrap(),
                    ),
                )
                .is_some());
            assert!(directory
                .track(
                    11,
                    AddressableTrackedPeers::new(
                        [(pk_b.clone(), addr(addr_b))].try_into().unwrap(),
                        [
                            (pk_overlap.clone(), addr(addr_overlap_s)),
                            (pk_sec.clone(), addr(addr_sec)),
                        ]
                        .try_into()
                        .unwrap(),
                    ),
                )
                .is_some());

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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(1),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);
            directory
                .track(
                    0,
                    primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2235);

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk.clone(), config, releaser);

            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
            );
            directory.block(&pk_1);
            assert!(
                directory.blocked.contains(&pk_1),
                "Peer should be blocked after call to block"
            );
            // Address is preserved (blocking is tracked in PrioritySet)
            let record = directory.peers.get(&pk_1).unwrap();
            assert_eq!(
                record.ingress(),
                Some(Ingress::Socket(addr_1)),
                "Record still has address (blocking is at Directory level)"
            );

            // Update the address while blocked
            directory.track(
                1,
                primary([(pk_1.clone(), addr(addr_2))].try_into().unwrap()),
            );
            assert!(
                directory.blocked.contains(&pk_1),
                "Blocked peer should remain blocked after update"
            );
            // Address is updated
            let record = directory.peers.get(&pk_1).unwrap();
            assert_eq!(
                record.ingress(),
                Some(Ingress::Socket(addr_2)),
                "Record has updated address"
            );

            // Advance time past block duration and unblock
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            // Verify the peer is unblocked with the UPDATED address
            assert!(
                !directory.blocked.contains(&pk_1),
                "Peer should be unblocked after expiry"
            );
            let record = directory.peers.get(&pk_1).unwrap();
            assert_eq!(
                record.ingress(),
                Some(Ingress::Socket(addr_2)),
                "Unblocked peer should have the updated address"
            );
        });
    }

    #[test]
    fn test_asymmetric_addresses() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        // Create asymmetric address where ingress differs from egress
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let ingress_socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let egress_socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
        let asymmetric_addr = Address::Asymmetric {
            ingress: Ingress::Socket(ingress_socket),
            egress: egress_socket,
        };

        // Create another peer with DNS-based ingress
        let pk_2 = ed25519::PrivateKey::from_seed(2).public_key();
        let egress_socket_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 9090);
        let dns_addr = Address::Asymmetric {
            ingress: Ingress::Dns {
                host: hostname!("node.example.com"),
                port: 8080,
            },
            egress: egress_socket_2,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, my_pk.clone(), config, releaser);

            // Add set with asymmetric addresses
            let reset_peers = directory
                .track(
                    0,
                    primary(
                        [
                            (pk_1.clone(), asymmetric_addr.clone()),
                            (pk_2.clone(), dns_addr.clone()),
                        ]
                        .try_into()
                        .unwrap(),
                    ),
                )
                .unwrap();
            assert!(reset_peers.is_empty());

            // Verify peer 1 has correct ingress and egress
            let record_1 = directory.peers.get(&pk_1).unwrap();
            assert_eq!(
                record_1.ingress(),
                Some(Ingress::Socket(ingress_socket)),
                "Ingress should match the asymmetric address's ingress"
            );
            assert_eq!(
                record_1.egress_ip(),
                Some(egress_socket.ip()),
                "Egress IP should be from the egress socket"
            );

            // Verify peer 2 has DNS ingress and correct egress
            let record_2 = directory.peers.get(&pk_2).unwrap();
            assert_eq!(
                record_2.ingress(),
                Some(Ingress::Dns {
                    host: hostname!("node.example.com"),
                    port: 8080
                }),
                "Ingress should be DNS address"
            );
            assert_eq!(
                record_2.egress_ip(),
                Some(egress_socket_2.ip()),
                "Egress IP should be from the egress socket"
            );

            // Verify listenable() returns egress IPs for IP filtering
            let listenable = directory.listenable();
            assert!(
                listenable.contains(&egress_socket.ip()),
                "Listenable should contain peer 1's egress IP"
            );
            assert!(
                listenable.contains(&egress_socket_2.ip()),
                "Listenable should contain peer 2's egress IP"
            );
            assert!(
                !listenable.contains(&ingress_socket.ip()),
                "Listenable should NOT contain peer 1's ingress IP"
            );
        });
    }

    #[test]
    fn test_dns_addresses_registered_but_not_dialable_when_disabled() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);

        // DNS is disabled
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: false,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        // Create peers with different address types
        let pk_socket = ed25519::PrivateKey::from_seed(1).public_key();
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let socket_peer_addr = Address::Symmetric(socket_addr);

        let pk_dns = ed25519::PrivateKey::from_seed(2).public_key();
        let egress_socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9090);
        let dns_peer_addr = Address::Asymmetric {
            ingress: Ingress::Dns {
                host: hostname!("node.example.com"),
                port: 8080,
            },
            egress: egress_socket,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, my_pk, config, releaser);

            // Add set with both socket and DNS addresses
            let reset_peers = directory
                .track(
                    0,
                    primary(
                        [
                            (pk_socket.clone(), socket_peer_addr.clone()),
                            (pk_dns.clone(), dns_peer_addr.clone()),
                        ]
                        .try_into()
                        .unwrap(),
                    ),
                )
                .unwrap();
            assert!(reset_peers.is_empty());

            // Both peers should be in the peer set (for consistency)
            assert!(
                directory.peers.contains_key(&pk_socket),
                "Socket peer should be in the peer set"
            );
            assert!(
                directory.peers.contains_key(&pk_dns),
                "DNS peer should be in the peer set for consistency"
            );

            // Only socket peer should be dialable (DNS ingress invalid when disabled)
            let dialable = directory.dialable();
            assert_eq!(dialable.peers.len(), 1);
            assert_eq!(dialable.peers[0], pk_socket);
        });
    }

    #[test]
    fn test_private_egress_ip_in_peer_set_but_not_dialable_or_tracked() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);

        // Private IPs are NOT allowed
        let config = super::Config {
            allow_private_ips: false,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        // Create peer with public egress IP
        let pk_public = ed25519::PrivateKey::from_seed(1).public_key();
        let public_addr =
            Address::Symmetric(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 8080));

        // Create peer with private egress IP
        let pk_private = ed25519::PrivateKey::from_seed(2).public_key();
        let private_addr = Address::Symmetric(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8080,
        ));

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, my_pk, config, releaser);

            // Add set with both public and private egress IPs
            let reset_peers = directory
                .track(
                    0,
                    primary(
                        [
                            (pk_public.clone(), public_addr.clone()),
                            (pk_private.clone(), private_addr.clone()),
                        ]
                        .try_into()
                        .unwrap(),
                    ),
                )
                .unwrap();
            assert!(reset_peers.is_empty());

            // Both peers should be in the peer set (for consistency)
            assert!(
                directory.peers.contains_key(&pk_public),
                "Public peer should be in the peer set"
            );
            assert!(
                directory.peers.contains_key(&pk_private),
                "Private peer should be in the peer set for consistency"
            );

            // Only public peer should be dialable (private ingress IP not allowed)
            let dialable = directory.dialable();
            assert_eq!(dialable.peers.len(), 1);
            assert_eq!(dialable.peers[0], pk_public);

            // Verify listenable() only returns public IP (private IP excluded from filter)
            let listenable = directory.listenable();
            assert!(listenable.contains(&Ipv4Addr::new(8, 8, 8, 8).into()));
            assert!(!listenable.contains(&Ipv4Addr::new(10, 0, 0, 1).into()));
        });
    }

    #[test]
    fn test_listenable_ip_collision_eligible_wins() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        // Two peers with the same egress IP (simulating NAT scenario)
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let pk_2 = ed25519::PrivateKey::from_seed(2).public_key();
        let shared_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let addr_1 = Address::Symmetric(SocketAddr::new(shared_ip, 8080));
        let addr_2 = Address::Symmetric(SocketAddr::new(shared_ip, 8081));

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);

            // Add both peers with the same IP
            directory.track(
                0,
                primary(
                    [(pk_1.clone(), addr_1), (pk_2.clone(), addr_2)]
                        .try_into()
                        .unwrap(),
                ),
            );

            // Both peers eligible: IP should be in listenable set
            let listenable = directory.listenable();
            assert!(
                listenable.contains(&shared_ip),
                "IP should be listenable when both peers are eligible"
            );

            // Block one peer
            directory.block(&pk_1);

            // One eligible, one blocked: IP should still be listenable
            let listenable = directory.listenable();
            assert!(
                listenable.contains(&shared_ip),
                "IP should be listenable when at least one peer is eligible"
            );

            // Block the other peer
            directory.block(&pk_2);

            // Both blocked: IP should NOT be in listenable set
            let listenable = directory.listenable();
            assert!(
                !listenable.contains(&shared_ip),
                "IP should not be listenable when all peers are blocked"
            );
        });
    }

    #[test]
    fn test_unblock_expired() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);

            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
            );

            // Block the peer
            directory.block(&pk_1);

            // Verify peer is blocked and not listenable
            assert!(
                !directory.listenable().contains(&addr_1.ip()),
                "Blocked peer should not be listenable"
            );

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

            // Verify peer is now listenable
            assert!(
                directory.listenable().contains(&addr_1.ip()),
                "Unblocked peer should be listenable"
            );

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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(1), // Only keep 1 set so we can evict peers
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let pk_2 = ed25519::PrivateKey::from_seed(2).public_key();
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1236);

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);

            // Initially no blocked peers
            assert!(
                directory.metrics.blocked.get_by(&pk_1).is_none(),
                "pk_1 should not be blocked initially"
            );

            // Add pk_1 and block it
            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
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
                primary([(pk_2.clone(), addr(addr_2))].try_into().unwrap()),
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
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
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
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);

            // Add all peers
            directory.track(
                0,
                primary(
                    [
                        (pk_1.clone(), addr(addr_1)),
                        (pk_2.clone(), addr(addr_2)),
                        (pk_3.clone(), addr(addr_3)),
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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk.clone(), config, releaser);

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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);

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
                    [(unknown_pk.clone(), addr(unknown_addr))]
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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);

            // Register a peer
            directory.track(
                0,
                primary(
                    [(registered_pk.clone(), addr(registered_addr))]
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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);

            // Add peer to a set
            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let cooldown = Duration::from_secs(1);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: cooldown,
            block_duration: Duration::from_secs(100),
        };

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);
            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
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
            let (_reservation, ingress) = directory
                .dial(&pk_1)
                .expect("should succeed after interval");
            assert_eq!(ingress, Ingress::Socket(addr_1));
        });
    }

    #[test]
    fn test_dialable_next_query_at_reflects_rate_limit() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let cooldown = Duration::from_secs(1);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: cooldown,
            block_duration: Duration::from_secs(100),
        };

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);
            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let cooldown = Duration::from_millis(200);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: cooldown,
            block_duration: Duration::from_secs(100),
        };

        runtime.start(|context| async move {
            let directory = Directory::init(context.child("directory"), my_pk, config, releaser);

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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let cooldown = Duration::from_millis(200);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: cooldown,
            block_duration: Duration::from_secs(3600),
        };

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);
            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(1);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(200),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);
            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(1);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(200),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);
            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: true, // Bypass IP check to simplify test
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);

            // Add peer to a set
            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
            );

            // Peer should be acceptable before blocking
            assert!(
                directory.acceptable(&pk_1, addr_1.ip()),
                "Peer should be acceptable before blocking"
            );

            // Block the peer
            directory.block(&pk_1);

            // Peer should NOT be acceptable while blocked
            assert!(
                !directory.acceptable(&pk_1, addr_1.ip()),
                "Blocked peer should not be acceptable"
            );

            // Advance time and unblock
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            // Peer should be acceptable again after unblock
            assert!(
                directory.acceptable(&pk_1, addr_1.ip()),
                "Peer should be acceptable after unblock"
            );
        });
    }

    #[test]
    fn test_blocked_peer_not_listenable() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);

            // Add peer to a set
            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
            );

            // Peer's IP should be listenable before blocking
            assert!(
                directory.listenable().contains(&addr_1.ip()),
                "Peer's IP should be listenable before blocking"
            );

            // Block the peer
            directory.block(&pk_1);

            // Peer's IP should NOT be listenable while blocked
            assert!(
                !directory.listenable().contains(&addr_1.ip()),
                "Blocked peer's IP should not be listenable"
            );

            // Advance time and unblock
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            // Peer's IP should be listenable again after unblock
            assert!(
                directory.listenable().contains(&addr_1.ip()),
                "Peer's IP should be listenable after unblock"
            );
        });
    }

    #[test]
    fn test_blocked_peer_not_eligible() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);

            // Add peer to a set
            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
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
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 1236);

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, my_pk, config, releaser);

            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
            );

            assert_eq!(
                directory.peers.get(&pk_1).unwrap().ingress(),
                Some(Ingress::Socket(addr_1))
            );

            let success = directory.overwrite(&pk_1, addr(addr_2));
            assert!(success);
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().ingress(),
                Some(Ingress::Socket(addr_2))
            );
        });
    }

    #[test]
    fn test_overwrite_untracked_peer() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, my_pk, config, releaser);

            let success = directory.overwrite(&pk_1, addr(addr_1));
            assert!(!success);
        });
    }

    #[test]
    fn test_overwrite_peer_not_in_set() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
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
            let mut directory = Directory::init(context, my_pk, config, releaser);

            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
            );
            directory.track(
                1,
                primary([(pk_2.clone(), addr(addr_2))].try_into().unwrap()),
            );

            let success = directory.overwrite(&pk_1, addr(addr_3));
            assert!(!success);
        });
    }

    #[test]
    fn test_overwrite_blocked_peer() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 1236);

        runtime.start(|context| async move {
            let mut directory =
                Directory::init(context.child("directory"), my_pk, config, releaser);

            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
            );
            directory.block(&pk_1);

            let success = directory.overwrite(&pk_1, addr(addr_2));
            assert!(success);
            assert_eq!(
                directory.peers.get(&pk_1).unwrap().ingress(),
                Some(Ingress::Socket(addr_2))
            );

            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            assert_eq!(
                directory.peers.get(&pk_1).unwrap().ingress(),
                Some(Ingress::Socket(addr_2))
            );
            assert!(directory.dialable().peers.contains(&pk_1));
        });
    }

    #[test]
    fn test_overwrite_myself() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, my_pk.clone(), config, releaser);

            let success = directory.overwrite(&my_pk, addr(addr_1));
            assert!(!success);
        });
    }

    #[test]
    fn test_overwrite_same_address() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = mailbox::new(NZUsize!(1024));
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            bypass_ip_check: false,
            max_sets: NZUsize!(3),
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1235);

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, my_pk, config, releaser);

            directory.track(
                0,
                primary([(pk_1.clone(), addr(addr_1))].try_into().unwrap()),
            );

            // First update with different address should succeed
            let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 1236);
            assert!(directory.overwrite(&pk_1, addr(addr_2)));

            // Update with same address should return false (no change)
            assert!(!directory.overwrite(&pk_1, addr(addr_2)));

            // Update with different address should succeed again
            let addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)), 1237);
            assert!(directory.overwrite(&pk_1, addr(addr_3)));
        });
    }
}
