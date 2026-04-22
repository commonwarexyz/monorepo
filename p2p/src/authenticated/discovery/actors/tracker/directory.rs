use super::{bit_set::BitSet, metrics::Metrics, record::Record, Metadata, Reservation};
use crate::{
    authenticated::{
        dialing::{earliest, DialStatus, Dialable, ReserveResult},
        discovery::{
            actors::tracker::ingress::Releaser,
            types::{self, Info},
        },
    },
    utils::PeerSetsAtIndex as PeerSetsAtIndexBase,
    Ingress, PeerSetUpdate, TrackedPeers,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Metrics as RuntimeMetrics, Spawner};
use commonware_utils::{ordered::Set as OrderedSet, PrioritySet, SystemTimeExt};
use rand::{seq::IteratorRandom, Rng};
use std::{
    collections::{BTreeMap, HashMap},
    num::NonZeroUsize,
    ops::Deref,
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

/// Primary [`BitSet`] and secondary ordered [`OrderedSet`] at one peer set index.
type PeerSetsAtIndex<C> = PeerSetsAtIndexBase<BitSet<C>, OrderedSet<C>>;

/// Configuration for the [Directory].
pub struct Config {
    /// Whether private IPs are connectable.
    pub allow_private_ips: bool,

    /// Whether DNS-based ingress addresses are allowed.
    pub allow_dns: bool,

    /// The maximum number of peer sets to track.
    pub max_sets: NonZeroUsize,

    /// The minimum number of times we should fail to dial a peer before attempting to ask other
    /// peers for its peer info again.
    pub dial_fail_limit: usize,

    /// The cooldown between reservations for a given peer.
    pub peer_connection_cooldown: Duration,

    /// Duration after which a blocked peer is allowed to reconnect.
    pub block_duration: Duration,
}

/// Represents a collection of records for all peers.
pub struct Directory<E: Rng + Clock + RuntimeMetrics, C: PublicKey> {
    context: E,

    // ---------- Configuration ----------
    /// Whether private IPs are connectable.
    allow_private_ips: bool,

    /// Whether DNS-based ingress addresses are allowed.
    allow_dns: bool,

    /// The maximum number of peer sets to track.
    max_sets: NonZeroUsize,

    /// The minimum number of times we should fail to dial a peer before attempting to ask other
    /// peers for its peer info again.
    dial_fail_limit: usize,

    /// Duration after which a blocked peer is allowed to reconnect.
    block_duration: Duration,

    /// Minimum duration between reservations for a given peer.
    peer_connection_cooldown: Duration,

    // ---------- State ----------
    /// The records of all peers.
    peers: HashMap<C, Record<C>>,

    /// Primary and secondary peer sets indexed by peer set ID.
    ///
    /// Secondaries do not participate in BitVec knowledge gossip; they are stored as plain
    /// ordered sets (same type as [`TrackedPeers::secondary`]).
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
    /// Create a new set of records using the given bootstrappers and local node information.
    pub fn init(
        context: E,
        bootstrappers: Vec<(C, Ingress)>,
        myself: Info<C>,
        cfg: Config,
        releaser: Releaser<C>,
    ) -> Self {
        // Create the list of peers and add the bootstrappers.
        let mut peers = HashMap::new();
        for (peer, ingress) in bootstrappers {
            peers.insert(peer, Record::bootstrapper(ingress));
        }

        // Add myself to the list of peers.
        // Overwrites the entry if myself is also a bootstrapper.
        peers.insert(myself.public_key.clone(), Record::myself(myself));

        // Other initialization.
        // TODO(#1833): Metrics should use the post-start context
        let metrics = Metrics::init(context.clone());
        let _ = metrics.tracked.try_set(peers.len() - 1); // Exclude self

        Self {
            context,
            allow_private_ips: cfg.allow_private_ips,
            allow_dns: cfg.allow_dns,
            max_sets: cfg.max_sets,
            dial_fail_limit: cfg.dial_fail_limit,
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

        // If the reservation was taken by the dialer, record the failure.
        if let Metadata::Dialer(_, ingress) = &metadata {
            record.dial_failure(ingress);
        }

        // We may have to update the primary sets.
        let want = record.want(self.dial_fail_limit);
        for entry in self.peer_sets.values_mut() {
            entry.primary.update(peer, !want);
        }
        self.delete_if_needed(peer);
    }

    /// Sets the status of a peer to `connected`.
    ///
    /// # Panics
    ///
    /// Panics if the peer has no record or if the peer is not in the reserved state.
    pub fn connect(&mut self, peer: &C, dialer: bool) {
        // Set the record as connected
        let record = self.peers.get_mut(peer).unwrap();
        if dialer {
            record.dial_success();
        }
        record.connect();
        let _ = self
            .metrics
            .connected
            .get_or_create_by(peer)
            .try_set(self.context.current().epoch_millis());

        // We may have to update the primary sets.
        let want = record.want(self.dial_fail_limit);
        for entry in self.peer_sets.values_mut() {
            entry.primary.update(peer, !want);
        }
    }

    /// Using a list of (already-validated) peer information, update the records.
    pub fn update_peers(&mut self, infos: Vec<types::Info<C>>) {
        for info in infos {
            // Update peer address
            //
            // It is not safe to rate limit how many times this can happen
            // over some interval because a malicious peer may just replay
            // old IPs to prevent us from propagating a new one.
            let peer = info.public_key.clone();
            let Some(record) = self.peers.get_mut(&peer) else {
                continue;
            };
            if !record.update(info) {
                continue;
            }
            self.metrics
                .updates
                .get_or_create_by(&peer)
                .inc();

            // We may have to update the primary sets.
            let want = record.want(self.dial_fail_limit);
            for entry in self.peer_sets.values_mut() {
                entry.primary.update(&peer, !want);
            }
            debug!(?peer, "updated peer record");
        }
    }

    /// Track new primary and secondary peer sets for the given index.
    pub fn track(&mut self, index: u64, peers: TrackedPeers<C>) -> bool {
        // Check if peer set already exists
        if self.peer_sets.contains_key(&index) {
            warn!(index, "peer set already exists");
            return false;
        }

        // Ensure that peer set is monotonically increasing
        if let Some((last, _)) = self.peer_sets.last_key_value() {
            if index <= *last {
                warn!(?index, ?last, "index must monotonically increase");
                return false;
            }
        }

        // Peers in both primary and secondary are stored as primary only.
        let secondary_deduped: OrderedSet<C> = OrderedSet::from_iter_dedup(
            peers
                .secondary
                .iter()
                .filter(|s| peers.primary.position(s).is_none())
                .cloned(),
        );

        // Track each primary in `self.peers`, then set the BitVec knowledge slot by index.
        let mut primary_set = BitSet::new(peers.primary);
        for i in 0..primary_set.len() {
            let primary = primary_set[i].clone();
            let record = self.peers.entry(primary).or_insert_with(|| {
                self.metrics.tracked.inc();
                Record::unknown()
            });
            record.increment_primary();
            assert!(
                primary_set.update_at(i, !record.want(self.dial_fail_limit)),
                "index in 0..primary_set.len() must map to a knowledge bit"
            );
        }

        // Create and store new secondary peer set.
        for secondary in secondary_deduped.iter() {
            let record = self.peers.entry(secondary.clone()).or_insert_with(|| {
                self.metrics.tracked.inc();
                Record::unknown()
            });
            record.increment_secondary();
        }
        self.peer_sets.insert(
            index,
            PeerSetsAtIndex {
                primary: primary_set,
                secondary: secondary_deduped,
            },
        );

        // Remove oldest tracked peer sets if necessary.
        while self.peer_sets.len() > self.max_sets.get() {
            let (index, sets) = self.peer_sets.pop_first().unwrap();
            debug!(index, "removed oldest tracked peer sets");
            sets.primary.into_iter().for_each(|primary| {
                self.peers.get_mut(primary).unwrap().decrement_primary();
                self.delete_if_needed(primary);
            });
            sets.secondary.iter().for_each(|secondary| {
                self.peers.get_mut(secondary).unwrap().decrement_secondary();
                self.delete_if_needed(secondary);
            });
        }

        true
    }

    /// Gets the peer set (primary and secondary) at the given index.
    pub fn get_peer_set(&self, index: &u64) -> Option<TrackedPeers<C>> {
        let entry = self.peer_sets.get(index)?;
        Some(TrackedPeers::new(
            entry.primary.deref().clone(),
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
    pub fn dial(&mut self, peer: &C) -> Option<Reservation<C>> {
        let ingress = self.peers.get(peer)?.ingress()?.clone();
        self.reserve(Metadata::Dialer(peer.clone(), ingress))
    }

    /// Attempt to reserve a peer for the listener.
    ///
    /// Returns `Some` on success, `None` otherwise.
    pub fn listen(&mut self, peer: &C) -> Option<Reservation<C>> {
        self.reserve(Metadata::Listener(peer.clone()))
    }

    /// Returns a [types::BitVec] for a random peer set.
    pub fn get_random_bit_vec(&mut self) -> Option<types::BitVec> {
        let (&index, entry) = self.peer_sets.iter().choose(&mut self.context)?;
        Some(types::BitVec {
            index,
            bits: entry.primary.knowledge(),
        })
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
            OrderedSet::from_iter_dedup(primary),
            OrderedSet::from_iter_dedup(secondary),
        )
    }

    /// Returns the sharable information for a given peer.
    pub fn info(&self, peer: &C) -> Option<Info<C>> {
        self.peers.get(peer).and_then(|r| r.sharable())
    }

    /// Returns all available peer information for a given bit vector.
    ///
    /// Returns `None` if the bit vector is malformed.
    pub fn infos(&self, bit_vec: types::BitVec) -> Option<Vec<types::Info<C>>> {
        let Some(entry) = self.peer_sets.get(&bit_vec.index) else {
            // Don't consider unknown indices as errors, just ignore them.
            debug!(index = bit_vec.index, "requested peer set not found");
            return Some(vec![]);
        };

        // Ensure that the bit vector is the same size as the peer set
        if bit_vec.bits.len() != entry.primary.len() as u64 {
            debug!(
                index = bit_vec.index,
                expected = entry.primary.len(),
                actual = bit_vec.bits.len(),
                "bit vector length mismatch"
            );
            return None;
        }

        // Compile peers to send
        let peers: Vec<_> = bit_vec
            .bits
            .iter()
            .enumerate()
            .filter_map(|(i, b)| {
                let peer = (!b).then_some(&entry.primary[i])?; // Only consider peers that the requester wants
                let info = self.peers.get(peer).and_then(|r| r.sharable());
                // We may have information signed over a timestamp greater than the current time,
                // but within our synchrony bound. Avoid sharing this information as it could get us
                // blocked by other peers due to clock skew. Consider timestamps earlier than the
                // current time to be safe enough to share.
                info.filter(|i| i.timestamp <= self.context.current().epoch_millis())
            })
            .collect();

        Some(peers)
    }

    /// Returns true if the peer is eligible for connection.
    ///
    /// A peer is eligible if it is in a peer set (or is persistent), not blocked, and not ourselves.
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
    pub fn acceptable(&self, peer: &C) -> bool {
        !self.is_blocked(peer) && self.peers.get(peer).is_some_and(|r| r.acceptable())
    }

    /// Unblock all peers whose block has expired and update primary peer set knowledge bitmaps.
    pub fn unblock_expired(&mut self) {
        let now = self.context.current();
        while let Some((_, &blocked_until)) = self.blocked.peek() {
            if blocked_until > now {
                break;
            }
            let (peer, _) = self.blocked.pop().unwrap();
            debug!(?peer, "unblocked peer");
            self.metrics.blocked.remove_by(&peer);

            // Update primary-set knowledge (BitVec gossip); secondaries have no bitmap.
            if let Some(record) = self.peers.get(&peer) {
                let want = record.want(self.dial_fail_limit);
                for entry in self.peer_sets.values_mut() {
                    entry.primary.update(&peer, !want);
                }
            }
        }
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
                self.metrics
                    .limits
                    .get_or_create_by(peer)
                    .inc();
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
    use super::*;
    use crate::authenticated::{discovery::types, mailbox::UnboundedMailbox};
    use commonware_cryptography::{secp256r1::standard::PrivateKey, Signer};
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use commonware_utils::{
        bitmap::BitMap, ordered::Set as OrderedSet, NZUsize, SystemTimeExt, TryCollect,
    };
    use std::net::SocketAddr;

    const NAMESPACE: &[u8] = b"test";

    fn test_socket() -> SocketAddr {
        SocketAddr::from(([8, 8, 8, 8], 8080))
    }

    fn create_myself_info<S>(
        signer: &S,
        socket: SocketAddr,
        timestamp: u64,
    ) -> types::Info<S::PublicKey>
    where
        S: commonware_cryptography::Signer,
    {
        types::Info::sign(signer, NAMESPACE, socket, timestamp)
    }

    fn metric_value(metrics: &str, name: &str, peer: &str) -> Option<i64> {
        metrics
            .lines()
            .find(|line| line.starts_with(&format!("{name}{{peer=\"{peer}\"}} ")))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<i64>().ok())
    }

    #[test]
    fn test_block_myself_no_panic_on_expiry() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_pk = signer.public_key();
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = Config {
            allow_private_ips: false,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Blocking myself should be ignored (Myself is unblockable)
            directory.block(&my_pk);

            // Metrics should not have an entry for myself
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&my_pk)
                    .is_none(),
                "Blocking myself should not create metric entry"
            );

            // No peers should be blocked
            assert_eq!(directory.blocked(), 0, "No peers should be blocked");

            // Advance time past block duration
            context.sleep(block_duration + Duration::from_secs(1)).await;

            // unblock_expired should not panic
            directory.unblock_expired();
        });
    }

    #[test]
    fn test_secondary_sets_remain_until_eviction() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let config = Config {
            allow_private_ips: false,
            allow_dns: true,
            max_sets: NZUsize!(2),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };
        let primary_0 = PrivateKey::from_seed(1).public_key();
        let primary_1 = PrivateKey::from_seed(2).public_key();
        let primary_2 = PrivateKey::from_seed(3).public_key();
        let secondary_0 = PrivateKey::from_seed(4).public_key();
        let secondary_1 = PrivateKey::from_seed(5).public_key();

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, vec![], my_info, config, releaser);

            assert!(directory.track(
                0,
                TrackedPeers::new(
                    [primary_0].try_into().unwrap(),
                    [secondary_0.clone()].try_into().unwrap(),
                ),
            ));
            assert!(directory.eligible(&secondary_0));

            assert!(directory.track(
                1,
                TrackedPeers::new(
                    [primary_1].try_into().unwrap(),
                    [secondary_1.clone()].try_into().unwrap(),
                ),
            ));
            assert!(directory.eligible(&secondary_0));
            assert!(directory.eligible(&secondary_1));

            assert!(directory.track(
                2,
                TrackedPeers::from(OrderedSet::try_from([primary_2]).unwrap()),
            ));
            assert!(!directory.peers.contains_key(&secondary_0));
            assert!(directory.eligible(&secondary_1));
        });
    }

    #[test]
    fn test_track_primary_secondary_overlap_deduplicates() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let config = Config {
            allow_private_ips: false,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };
        let pk_a = PrivateKey::from_seed(1).public_key();
        let pk_b = PrivateKey::from_seed(2).public_key();
        let pk_c = PrivateKey::from_seed(3).public_key();

        runtime.start(|context| async move {
            // pk_b in both roles; pk_c secondary-only. pk_b is deduplicated as primary only.
            let mut directory = Directory::init(context, vec![], my_info, config, releaser);

            assert!(directory.track(
                0,
                TrackedPeers::new(
                    [pk_a.clone(), pk_b.clone()].try_into().unwrap(),
                    [pk_b.clone(), pk_c.clone()].try_into().unwrap(),
                ),
            ));

            let peer_set = directory.get_peer_set(&0).unwrap();
            assert_eq!(peer_set.secondary.len(), 1);
            assert!(peer_set.secondary.position(&pk_c).is_some());
            assert!(peer_set.secondary.position(&pk_b).is_none());

            assert_eq!(directory.peers.get(&pk_b).unwrap().primary_sets(), 1);
            assert_eq!(directory.peers.get(&pk_b).unwrap().secondary_sets(), 0);
            assert_eq!(directory.peers.get(&pk_c).unwrap().secondary_sets(), 1);

            let latest = directory.latest_update().unwrap();
            assert!(latest.latest.secondary.position(&pk_b).is_none());
            assert!(latest.latest.primary.position(&pk_b).is_some());

            let agg = directory.all();
            assert!(agg.primary.position(&pk_b).is_some());
            assert!(agg.secondary.position(&pk_b).is_none());
        });
    }

    #[test]
    fn test_demotion_from_primary_to_secondary() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let config = Config {
            allow_private_ips: false,
            allow_dns: true,
            max_sets: NZUsize!(2),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };
        let pk_x = PrivateKey::from_seed(1).public_key();
        let pk_y = PrivateKey::from_seed(2).public_key();

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, vec![], my_info, config, releaser);

            // Index 0: X is primary, Y is secondary.
            assert!(directory.track(
                0,
                TrackedPeers::new(
                    OrderedSet::try_from([pk_x.clone()]).unwrap(),
                    OrderedSet::try_from([pk_y.clone()]).unwrap(),
                ),
            ));
            assert_eq!(directory.peers.get(&pk_x).unwrap().primary_sets(), 1);
            assert_eq!(directory.peers.get(&pk_x).unwrap().secondary_sets(), 0);
            assert_eq!(directory.peers.get(&pk_y).unwrap().primary_sets(), 0);
            assert_eq!(directory.peers.get(&pk_y).unwrap().secondary_sets(), 1);

            // Index 1: X is demoted to secondary, Y is promoted to primary.
            assert!(directory.track(
                1,
                TrackedPeers::new(
                    OrderedSet::try_from([pk_y.clone()]).unwrap(),
                    OrderedSet::try_from([pk_x.clone()]).unwrap(),
                ),
            ));

            // Both indices retained (max_sets=2).
            assert_eq!(directory.peers.get(&pk_x).unwrap().primary_sets(), 1);
            assert_eq!(directory.peers.get(&pk_x).unwrap().secondary_sets(), 1);
            assert_eq!(directory.peers.get(&pk_y).unwrap().primary_sets(), 1);
            assert_eq!(directory.peers.get(&pk_y).unwrap().secondary_sets(), 1);

            // Aggregate: both are primary (primary-wins across sets).
            let agg = directory.all();
            assert!(agg.primary.position(&pk_x).is_some());
            assert!(agg.primary.position(&pk_y).is_some());
            assert!(agg.secondary.is_empty());

            // Index 2: only Y is primary, X is secondary. This evicts index 0.
            assert!(directory.track(
                2,
                TrackedPeers::new(
                    OrderedSet::try_from([pk_y.clone()]).unwrap(),
                    OrderedSet::try_from([pk_x.clone()]).unwrap(),
                ),
            ));

            // Index 0 evicted. X lost its primary from index 0.
            assert_eq!(directory.peers.get(&pk_x).unwrap().primary_sets(), 0);
            assert_eq!(directory.peers.get(&pk_x).unwrap().secondary_sets(), 2);
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
    fn test_all_cross_index_primary_wins_for_overlap_peer() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let config = Config {
            allow_private_ips: false,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };
        let pk_a = PrivateKey::from_seed(31).public_key();
        let pk_b = PrivateKey::from_seed(32).public_key();
        let pk_overlap = PrivateKey::from_seed(33).public_key();
        let pk_sec = PrivateKey::from_seed(34).public_key();

        runtime.start(|context| async move {
            // pk_overlap is a primary member in set 0 and listed again as secondary in set 1.
            let mut directory = Directory::init(context, vec![], my_info, config, releaser);

            assert!(directory.track(
                0,
                TrackedPeers::from(
                    OrderedSet::try_from([pk_a.clone(), pk_overlap.clone()]).unwrap(),
                ),
            ));
            assert!(directory.track(
                1,
                TrackedPeers::new(
                    [pk_b.clone()].try_into().unwrap(),
                    [pk_overlap.clone(), pk_sec.clone()].try_into().unwrap(),
                ),
            ));

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
    fn test_block_nonexistent_peer_then_add_to_set() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let unknown_pk = PrivateKey::from_seed(99).public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = Config {
            allow_private_ips: false,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Block a peer that doesn't exist yet
            directory.block(&unknown_pk);

            // Metrics should have an entry for the blocked peer
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&unknown_pk)
                    .is_some(),
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
            let peer_set: OrderedSet<_> = [unknown_pk.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));

            // Peer should now be in peers and blocked (via PrioritySet)
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
                directory
                    .metrics
                    .blocked
                    .get_by(&unknown_pk)
                    .is_none(),
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
    fn test_connected_metric_tracks_active_peers() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let config = Config {
            allow_private_ips: false,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration: Duration::from_secs(100),
        };

        let pk_1 = PrivateKey::from_seed(1).public_key();

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);
            let peer_set: OrderedSet<_> = [pk_1.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));

            let _reservation = directory.listen(&pk_1).expect("peer should reserve");
            let connected_at: i64 = context.current().epoch_millis().try_into().unwrap();
            directory.connect(&pk_1, false);

            context.sleep(Duration::from_secs(5)).await;

            let metrics = context.encode();
            assert_eq!(
                metric_value(&metrics, "connected", &pk_1.to_string()),
                Some(connected_at)
            );

            directory.release(Metadata::Listener(pk_1.clone()));

            let metrics = context.encode();
            assert_eq!(metric_value(&metrics, "connected", &pk_1.to_string()), None);
        });
    }

    #[test]
    fn test_block_peer_multiple_times() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let unknown_pk = PrivateKey::from_seed(99).public_key();
        let registered_pk = PrivateKey::from_seed(50).public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = Config {
            allow_private_ips: false,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Register a peer
            let peer_set: OrderedSet<_> =
                [registered_pk.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&registered_pk)
                    .is_none(),
                "Peer should not be blocked initially"
            );

            // Block tracked peer multiple times
            directory.block(&registered_pk);
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&registered_pk)
                    .is_some(),
                "Tracked peer should be marked blocked"
            );

            directory.block(&registered_pk);
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&registered_pk)
                    .is_some(),
                "Blocking same tracked peer twice should not change metric"
            );

            directory.block(&registered_pk);
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&registered_pk)
                    .is_some(),
                "Blocking same tracked peer thrice should not change metric"
            );

            // Block a nonexistent peer multiple times
            directory.block(&unknown_pk);
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&unknown_pk)
                    .is_some(),
                "Unknown peer should be marked blocked"
            );

            directory.block(&unknown_pk);
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&unknown_pk)
                    .is_some(),
                "Blocking same nonexistent peer twice should not change metric"
            );

            directory.block(&unknown_pk);
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&unknown_pk)
                    .is_some(),
                "Blocking same nonexistent peer thrice should not change metric"
            );
        });
    }

    #[test]
    fn test_blocked_peer_remains_blocked_on_update() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let peer_signer = PrivateKey::from_seed(1);
        let peer_pk = peer_signer.public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Add peer to a set
            let peer_set: OrderedSet<_> = [peer_pk.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));

            // Block the peer
            directory.block(&peer_pk);
            assert!(
                directory.blocked.contains(&peer_pk),
                "Peer should be blocked after call to block"
            );

            // Update with peer info while blocked
            let peer_info = types::Info::sign(&peer_signer, NAMESPACE, test_socket(), 200);
            directory.update_peers(vec![peer_info.clone()]);

            // Peer should still be blocked
            assert!(
                directory.blocked.contains(&peer_pk),
                "Peer should remain blocked after update"
            );

            // But info should be updated
            let record = directory.peers.get(&peer_pk).unwrap();
            assert!(
                record.ingress().is_some(),
                "Peer info should be updated while blocked"
            );

            // Advance time past block duration and unblock
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            // Verify the peer is unblocked with the updated info
            assert!(
                !directory.blocked.contains(&peer_pk),
                "Peer should be unblocked after expiry"
            );
            let record = directory.peers.get(&peer_pk).unwrap();
            assert!(
                record.ingress().is_some(),
                "Unblocked peer should have the updated info"
            );
        });
    }

    #[test]
    fn test_unblock_expired() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let peer_pk = PrivateKey::from_seed(1).public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Add peer to a set
            let peer_set: OrderedSet<_> = [peer_pk.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));

            // Block the peer
            directory.block(&peer_pk);
            assert!(directory.blocked.contains(&peer_pk));

            // Verify peer is blocked
            assert_eq!(directory.blocked(), 1, "Should have one blocked peer");

            // Get first expiry time
            let first_expiry = directory
                .blocked
                .get(&peer_pk)
                .expect("peer should be blocked");

            // unblock_expired should do nothing before expiry
            directory.unblock_expired();
            assert!(
                directory.blocked.contains(&peer_pk),
                "Peer should still be blocked before expiry"
            );

            // Advance time past block duration
            context.sleep(block_duration + Duration::from_secs(1)).await;

            // Now unblock_expired should unblock the peer
            directory.unblock_expired();
            assert!(
                !directory.blocked.contains(&peer_pk),
                "Peer should be unblocked after expiry"
            );

            // Verify no more blocked peers
            assert_eq!(directory.blocked(), 0, "No more blocked peers");

            // Re-block the peer and verify expiry time increased
            directory.block(&peer_pk);
            assert_eq!(directory.blocked(), 1, "Should have one blocked peer again");

            let second_expiry = directory
                .blocked
                .get(&peer_pk)
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
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let pk_1 = PrivateKey::from_seed(1).public_key();
        let pk_2 = PrivateKey::from_seed(2).public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(1), // Only keep 1 set so we can evict peers
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Initially no blocked peers
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&pk_1)
                    .is_none(),
                "pk_1 should not be blocked initially"
            );

            // Add pk_1 and block it
            let peer_set: OrderedSet<_> = [pk_1.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));
            directory.block(&pk_1);
            assert!(directory.blocked.contains(&pk_1));
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&pk_1)
                    .is_some(),
                "pk_1 should be marked blocked"
            );

            // Add a new set that evicts pk_1 (max_sets=1)
            // The blocked metric should remain since the block persists
            let peer_set_2: OrderedSet<_> = [pk_2.clone()].into_iter().try_collect().unwrap();
            directory.track(1, TrackedPeers::from(peer_set_2));
            assert!(
                !directory.peers.contains_key(&pk_1),
                "pk_1 should be removed"
            );
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&pk_1)
                    .is_some(),
                "blocked metric should persist after peer removal"
            );

            // Re-add pk_1 - should still be blocked because block persists
            let peer_set_3: OrderedSet<_> = [pk_1.clone()].into_iter().try_collect().unwrap();
            directory.track(2, TrackedPeers::from(peer_set_3));
            assert!(
                directory.blocked.contains(&pk_1),
                "Re-added pk_1 should still be blocked"
            );
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&pk_1)
                    .is_some(),
                "blocked metric should persist after re-add"
            );

            // Advance time past block duration
            context.sleep(block_duration + Duration::from_secs(1)).await;

            // Now unblock_expired should unblock pk_1
            directory.unblock_expired();
            assert!(
                !directory.blocked.contains(&pk_1),
                "pk_1 should no longer be blocked"
            );
            assert!(
                directory
                    .metrics
                    .blocked
                    .get_by(&pk_1)
                    .is_none(),
                "blocked metric should be removed after unblock"
            );
        });
    }

    #[test]
    fn test_blocked_metric_multiple_peers() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let pk_1 = PrivateKey::from_seed(1).public_key();
        let pk_2 = PrivateKey::from_seed(2).public_key();
        let pk_3 = PrivateKey::from_seed(3).public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Add all peers
            let peer_set: OrderedSet<_> = [pk_1.clone(), pk_2.clone(), pk_3.clone()]
                .into_iter()
                .try_collect()
                .unwrap();
            directory.track(0, TrackedPeers::from(peer_set));
            assert_eq!(directory.blocked(), 0);

            // Block all three peers
            directory.block(&pk_1);
            assert!(directory
                .metrics
                .blocked
                .get_by(&pk_1)
                .is_some());
            directory.block(&pk_2);
            assert!(directory
                .metrics
                .blocked
                .get_by(&pk_2)
                .is_some());
            directory.block(&pk_3);
            assert!(directory
                .metrics
                .blocked
                .get_by(&pk_3)
                .is_some());
            assert_eq!(directory.blocked(), 3);

            // Blocking again should not change anything
            directory.block(&pk_1);
            assert!(directory
                .metrics
                .blocked
                .get_by(&pk_1)
                .is_some());

            // Advance time and unblock all
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();
            assert!(directory
                .metrics
                .blocked
                .get_by(&pk_1)
                .is_none());
            assert!(directory
                .metrics
                .blocked
                .get_by(&pk_2)
                .is_none());
            assert!(directory
                .metrics
                .blocked
                .get_by(&pk_3)
                .is_none());
            assert_eq!(directory.blocked(), 0);
        });
    }

    #[test]
    fn test_blocked_peer_not_dialable() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let peer_signer = PrivateKey::from_seed(1);
        let peer_pk = peer_signer.public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Add peer to a set
            let peer_set: OrderedSet<_> = [peer_pk.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));

            // Update with peer info so it has a dialable address
            let peer_info = types::Info::sign(&peer_signer, NAMESPACE, test_socket(), 200);
            directory.update_peers(vec![peer_info]);

            // Peer should be dialable before blocking
            assert!(
                directory.dialable().peers.contains(&peer_pk),
                "Peer should be dialable before blocking"
            );

            // Block the peer
            directory.block(&peer_pk);

            // Peer should NOT be dialable while blocked
            assert!(
                !directory.dialable().peers.contains(&peer_pk),
                "Blocked peer should not be dialable"
            );

            // Advance time and unblock
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            // Peer should be dialable again after unblock
            assert!(
                directory.dialable().peers.contains(&peer_pk),
                "Peer should be dialable after unblock"
            );
        });
    }

    #[test]
    fn test_blocked_peer_not_acceptable() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let peer_signer = PrivateKey::from_seed(1);
        let peer_pk = peer_signer.public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Add peer to a set
            let peer_set: OrderedSet<_> = [peer_pk.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));

            // Update with peer info
            let peer_info = types::Info::sign(&peer_signer, NAMESPACE, test_socket(), 200);
            directory.update_peers(vec![peer_info]);

            // Peer should be acceptable before blocking
            assert!(
                directory.acceptable(&peer_pk),
                "Peer should be acceptable before blocking"
            );

            // Block the peer
            directory.block(&peer_pk);

            // Peer should NOT be acceptable while blocked
            assert!(
                !directory.acceptable(&peer_pk),
                "Blocked peer should not be acceptable"
            );

            // Advance time and unblock
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            // Peer should be acceptable again after unblock
            assert!(
                directory.acceptable(&peer_pk),
                "Peer should be acceptable after unblock"
            );
        });
    }

    #[test]
    fn test_blocked_peer_not_eligible() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let peer_pk = PrivateKey::from_seed(1).public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Add peer to a set
            let peer_set: OrderedSet<_> = [peer_pk.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));

            // Peer should be eligible before blocking
            assert!(
                directory.eligible(&peer_pk),
                "Peer should be eligible before blocking"
            );

            // Block the peer
            directory.block(&peer_pk);

            // Peer should NOT be eligible while blocked
            assert!(
                !directory.eligible(&peer_pk),
                "Blocked peer should not be eligible"
            );

            // Advance time and unblock
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            // Peer should be eligible again after unblock
            assert!(
                directory.eligible(&peer_pk),
                "Peer should be eligible after unblock"
            );
        });
    }

    #[test]
    fn test_blocked_peer_info_not_sharable() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let peer_signer = PrivateKey::from_seed(1);
        let peer_pk = peer_signer.public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Add peer to a set
            let peer_set: OrderedSet<_> = [peer_pk.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));

            // Update with peer info
            let peer_info = types::Info::sign(&peer_signer, NAMESPACE, test_socket(), 200);
            directory.update_peers(vec![peer_info]);

            // Reserve and connect to make peer Active (so info would be sharable)
            let reservation = directory.dial(&peer_pk);
            assert!(reservation.is_some(), "Should be able to dial peer");
            directory.connect(&peer_pk, true);

            // Verify info is sharable when connected
            assert!(
                directory.info(&peer_pk).is_some(),
                "Connected peer's info should be sharable"
            );

            // Block the peer - this should trigger disconnect (making status Inert)
            directory.block(&peer_pk);

            // Release the reservation to simulate the connection being killed
            directory.release(Metadata::Dialer(
                peer_pk.clone(),
                Ingress::Socket(test_socket()),
            ));

            // Now info should NOT be sharable (peer is Inert after block/disconnect)
            assert!(
                directory.info(&peer_pk).is_none(),
                "Blocked peer's info should not be sharable after disconnect"
            );

            // Advance time and unblock
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            // Info still not sharable because peer is not connected
            assert!(
                directory.info(&peer_pk).is_none(),
                "Unblocked but disconnected peer's info should not be sharable"
            );
        });
    }

    #[test]
    fn test_bootstrapper_remains_persistent_after_blocking() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let bootstrapper_pk = PrivateKey::from_seed(1).public_key();
        let bootstrapper_ingress = Ingress::Socket(SocketAddr::from(([1, 2, 3, 4], 8080)));
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            // Initialize with a bootstrapper
            let mut directory = Directory::init(
                context.clone(),
                vec![(bootstrapper_pk.clone(), bootstrapper_ingress)],
                my_info,
                config,
                releaser,
            );

            // Verify bootstrapper is not deletable (because it's persistent)
            let record = directory.peers.get(&bootstrapper_pk).unwrap();
            assert!(
                !record.deletable(),
                "Bootstrapper should not be deletable (persistent)"
            );

            // Block the bootstrapper
            directory.block(&bootstrapper_pk);
            assert!(
                directory.blocked.contains(&bootstrapper_pk),
                "Bootstrapper should be blocked"
            );

            // Verify bootstrapper is STILL not deletable after blocking
            // (blocking should NOT change persistence)
            let record = directory.peers.get(&bootstrapper_pk).unwrap();
            assert!(
                !record.deletable(),
                "Bootstrapper should still not be deletable after blocking"
            );

            // Advance time and unblock
            context.sleep(block_duration + Duration::from_secs(1)).await;
            directory.unblock_expired();

            // Verify bootstrapper is still not deletable after unblock
            let record = directory.peers.get(&bootstrapper_pk).unwrap();
            assert!(
                !record.deletable(),
                "Bootstrapper should remain not deletable after unblock"
            );
        });
    }

    #[test]
    fn test_infos_excludes_blocked_peers() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let peer_signer_1 = PrivateKey::from_seed(1);
        let peer_pk_1 = peer_signer_1.public_key();
        let peer_signer_2 = PrivateKey::from_seed(2);
        let peer_pk_2 = peer_signer_2.public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(100);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(100),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Add both peers to a set
            let peer_set: OrderedSet<_> = [peer_pk_1.clone(), peer_pk_2.clone()]
                .into_iter()
                .try_collect()
                .unwrap();
            directory.track(0, TrackedPeers::from(peer_set));

            // Update with peer info for both (use timestamp 0 to pass the epoch_millis filter)
            let peer_info_1 = types::Info::sign(&peer_signer_1, NAMESPACE, test_socket(), 0);
            let peer_info_2 = types::Info::sign(
                &peer_signer_2,
                NAMESPACE,
                SocketAddr::from(([9, 9, 9, 9], 9090)),
                0,
            );
            directory.update_peers(vec![peer_info_1, peer_info_2]);

            // Connect both peers to make them Active (sharable)
            let reservation_1 = directory.dial(&peer_pk_1);
            assert!(reservation_1.is_some());
            directory.connect(&peer_pk_1, true);

            let reservation_2 = directory.dial(&peer_pk_2);
            assert!(reservation_2.is_some());
            directory.connect(&peer_pk_2, true);

            // Create a bit vector requesting info for both peers (bits = false means "want info")
            let bit_vec = types::BitVec {
                index: 0,
                bits: BitMap::zeroes(2),
            };

            // Both peers' info should be returned
            let infos = directory.infos(bit_vec.clone()).unwrap();
            assert_eq!(infos.len(), 2, "Should have info for both peers");

            // Block peer 1 and release their connection
            directory.block(&peer_pk_1);
            directory.release(Metadata::Dialer(
                peer_pk_1.clone(),
                Ingress::Socket(test_socket()),
            ));

            // Now only peer 2's info should be returned (peer 1 is Inert after disconnect)
            let infos = directory.infos(bit_vec).unwrap();
            assert_eq!(
                infos.len(),
                1,
                "Should only have info for unblocked connected peer"
            );
            assert_eq!(
                infos[0].public_key, peer_pk_2,
                "Returned info should be for peer 2"
            );
        });
    }

    #[test]
    fn test_reservation_rate_limits_redial() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let peer_signer = PrivateKey::from_seed(1);
        let peer_pk = peer_signer.public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let cooldown = Duration::from_secs(1);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: cooldown,
            block_duration: Duration::from_secs(100),
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            let peer_set: OrderedSet<_> = [peer_pk.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));
            let peer_info = types::Info::sign(&peer_signer, NAMESPACE, test_socket(), 200);
            directory.update_peers(vec![peer_info]);

            let reservation = directory.dial(&peer_pk).expect("first dial should succeed");
            drop(reservation);
            directory.release(Metadata::Dialer(
                peer_pk.clone(),
                Ingress::Socket(test_socket()),
            ));

            assert!(
                directory.dial(&peer_pk).is_none(),
                "should be rate-limited immediately after release"
            );
            assert!(
                !directory.dialable().peers.contains(&peer_pk),
                "should not appear in dialable list during rate-limit window"
            );

            // After the jitter window (up to 2x interval), peer becomes dialable again.
            context.sleep(cooldown * 2).await;
            assert!(directory.dialable().peers.contains(&peer_pk));
            directory
                .dial(&peer_pk)
                .expect("should succeed after interval");
        });
    }

    #[test]
    fn test_dialable_next_query_at_reflects_rate_limit() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let peer_signer = PrivateKey::from_seed(1);
        let peer_pk = peer_signer.public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let cooldown = Duration::from_secs(1);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: cooldown,
            block_duration: Duration::from_secs(100),
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            let peer_set: OrderedSet<_> = [peer_pk.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));
            let peer_info = types::Info::sign(&peer_signer, NAMESPACE, test_socket(), 200);
            directory.update_peers(vec![peer_info]);

            let reservation = directory.dial(&peer_pk).expect("first dial should succeed");
            let reserved_at = context.current();
            drop(reservation);
            directory.release(Metadata::Dialer(
                peer_pk.clone(),
                Ingress::Socket(test_socket()),
            ));

            // next_query_at reflects the jittered next_dial_at (between 1x and 2x interval).
            let dialable = directory.dialable();
            assert!(!dialable.peers.contains(&peer_pk));
            let nqa = dialable.next_query_at.unwrap();
            assert!(nqa >= reserved_at + cooldown);
            assert!(nqa <= reserved_at + cooldown * 2);
        });
    }

    #[test]
    fn test_dialable_empty() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(200),
            block_duration: Duration::from_secs(100),
        };

        runtime.start(|context| async move {
            let directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            let dialable = directory.dialable();
            assert!(dialable.peers.is_empty());
            assert_eq!(dialable.next_query_at, None);
        });
    }

    #[test]
    fn test_dialable_next_query_at_includes_blocked() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let peer_signer = PrivateKey::from_seed(1);
        let peer_pk = peer_signer.public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(3600);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(200),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            let peer_set: OrderedSet<_> = [peer_pk.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));
            let peer_info = types::Info::sign(&peer_signer, NAMESPACE, test_socket(), 200);
            directory.update_peers(vec![peer_info]);

            directory.block(&peer_pk);
            let dialable = directory.dialable();
            assert!(dialable.peers.is_empty());
            assert_eq!(
                dialable.next_query_at,
                Some(context.current() + block_duration)
            );
        });
    }

    #[test]
    fn test_dialable_expired_block_without_unblock() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let peer_signer = PrivateKey::from_seed(1);
        let peer_pk = peer_signer.public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(1);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(200),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            let peer_set: OrderedSet<_> = [peer_pk.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));
            let peer_info = types::Info::sign(&peer_signer, NAMESPACE, test_socket(), 200);
            directory.update_peers(vec![peer_info]);

            directory.block(&peer_pk);
            assert!(directory.dialable().peers.is_empty());

            // Advance past the block expiry but do NOT call unblock_expired().
            context.sleep(block_duration + Duration::from_secs(1)).await;

            // The peer should still be dialable despite the stale block entry.
            let dialable = directory.dialable();
            assert!(
                dialable.peers.contains(&peer_pk),
                "expired block should not prevent dialing"
            );
            assert_eq!(
                dialable.next_query_at, None,
                "expired block should not contribute a stale hint"
            );

            // Reservation should also succeed.
            directory
                .dial(&peer_pk)
                .expect("expired block should not prevent reservation");
        });
    }

    #[test]
    fn test_reblock_after_expired_block_without_unblock() {
        let runtime = deterministic::Runner::default();
        let signer = PrivateKey::from_seed(0);
        let my_info = create_myself_info(&signer, test_socket(), 100);
        let peer_signer = PrivateKey::from_seed(1);
        let peer_pk = peer_signer.public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = Releaser::new(tx);
        let block_duration = Duration::from_secs(1);
        let config = Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: NZUsize!(3),
            dial_fail_limit: 1,
            peer_connection_cooldown: Duration::from_millis(200),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            let peer_set: OrderedSet<_> = [peer_pk.clone()].into_iter().try_collect().unwrap();
            directory.track(0, TrackedPeers::from(peer_set));
            let peer_info = types::Info::sign(&peer_signer, NAMESPACE, test_socket(), 200);
            directory.update_peers(vec![peer_info]);

            directory.block(&peer_pk);
            assert!(directory.dialable().peers.is_empty());

            // Advance past expiry without calling unblock_expired().
            context.sleep(block_duration + Duration::from_secs(1)).await;

            // Re-block should succeed despite stale entry.
            directory.block(&peer_pk);
            assert!(
                directory.dialable().peers.is_empty(),
                "re-blocked peer should not be dialable"
            );
            assert!(
                directory.dial(&peer_pk).is_none(),
                "re-blocked peer should not be reservable"
            );
        });
    }
}
