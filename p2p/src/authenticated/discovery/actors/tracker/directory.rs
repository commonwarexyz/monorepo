use super::{metrics::Metrics, record::Record, set::Set, Metadata, Reservation};
use crate::{
    authenticated::discovery::{
        actors::tracker::ingress::Releaser,
        metrics,
        types::{self, Info},
    },
    utils::blocked,
    Ingress,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{
    telemetry::metrics::status::GaugeExt, Clock, KeyedRateLimiter, Metrics as RuntimeMetrics,
    Quota, Spawner,
};
use commonware_utils::{ordered::Set as OrderedSet, SystemTimeExt, TryCollect};
use rand::{seq::IteratorRandom, Rng};
use std::{
    collections::{BTreeMap, HashMap},
    ops::Deref,
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

/// Configuration for the [Directory].
pub struct Config {
    /// Whether private IPs are connectable.
    pub allow_private_ips: bool,

    /// Whether DNS-based ingress addresses are allowed.
    pub allow_dns: bool,

    /// The maximum number of peer sets to track.
    pub max_sets: usize,

    /// The minimum number of times we should fail to dial a peer before attempting to ask other
    /// peers for its peer info again.
    pub dial_fail_limit: usize,

    /// The rate limit for allowing reservations per-peer.
    pub rate_limit: Quota,

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
    max_sets: usize,

    /// The minimum number of times we should fail to dial a peer before attempting to ask other
    /// peers for its peer info again.
    dial_fail_limit: usize,

    /// Duration after which a blocked peer is allowed to reconnect.
    block_duration: Duration,

    // ---------- State ----------
    /// The records of all peers.
    peers: HashMap<C, Record<C>>,

    /// The peer sets
    sets: BTreeMap<u64, Set<C>>,

    /// Rate limiter for connection attempts.
    rate_limiter: KeyedRateLimiter<C, E>,

    /// Tracks blocked peers and their unblock time. This is the source of truth for
    /// whether a peer is blocked, persisting even if the peer record is deleted.
    blocked: blocked::Queue<C>,

    // ---------- Message-Passing ----------
    /// The releaser for the tracker actor.
    releaser: Releaser<C>,

    // ---------- Metrics ----------
    /// The metrics for the records.
    metrics: Metrics,
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
        let rate_limiter = KeyedRateLimiter::hashmap_with_clock(cfg.rate_limit, context.clone());

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
            peers,
            sets: BTreeMap::new(),
            rate_limiter,
            blocked: blocked::Queue::new(),
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
        self.metrics.reserved.dec();

        // If the reservation was taken by the dialer, record the failure.
        if let Metadata::Dialer(_, ingress) = &metadata {
            record.dial_failure(ingress);
        }

        // We may have to update the sets.
        let want = record.want(self.dial_fail_limit);
        for set in self.sets.values_mut() {
            set.update(peer, !want);
        }
        self.delete_if_needed(peer);
    }

    /// Sets the status of a peer to `connected`.
    ///
    /// # Panics
    ///
    /// Panics if the peer is not tracked or if the peer is not in the reserved state.
    pub fn connect(&mut self, peer: &C, dialer: bool) {
        // Set the record as connected
        let record = self.peers.get_mut(peer).unwrap();
        if dialer {
            record.dial_success();
        }
        record.connect();

        // We may have to update the sets.
        let want = record.want(self.dial_fail_limit);
        for set in self.sets.values_mut() {
            set.update(peer, !want);
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
                .get_or_create(&metrics::Peer::new(&peer))
                .inc();

            // We may have to update the sets.
            let want = record.want(self.dial_fail_limit);
            for set in self.sets.values_mut() {
                set.update(&peer, !want);
            }
            debug!(?peer, "updated peer record");
        }
    }

    /// Stores a new peer set.
    pub fn add_set(&mut self, index: u64, peers: OrderedSet<C>) -> bool {
        // Check if peer set already exists
        if self.sets.contains_key(&index) {
            warn!(index, "peer set already exists");
            return false;
        }

        // Ensure that peer set is monotonically increasing
        if let Some((last, _)) = self.sets.last_key_value() {
            if index <= *last {
                warn!(?index, ?last, "index must monotonically increase");
                return false;
            }
        }

        // Create and store new peer set
        let mut set = Set::new(peers.clone());
        for peer in peers.iter() {
            let record = self.peers.entry(peer.clone()).or_insert_with(|| {
                self.metrics.tracked.inc();
                Record::unknown()
            });
            // If peer is blocked (from before they were removed), mark the new record
            if self.blocked.is_blocked(peer) {
                record.block();
            }
            record.increment();
            set.update(peer, !record.want(self.dial_fail_limit));
        }
        self.sets.insert(index, set);

        // Remove oldest entries if necessary
        while self.sets.len() > self.max_sets {
            let (index, set) = self.sets.pop_first().unwrap();
            debug!(index, "removed oldest peer set");
            set.into_iter().for_each(|peer| {
                self.peers.get_mut(peer).unwrap().decrement();
                self.delete_if_needed(peer);
            });
        }

        // Attempt to remove any old records from the rate limiter.
        // This is a best-effort attempt to prevent memory usage from growing indefinitely.
        //
        // We don't reduce the capacity of the rate limiter to avoid re-allocation on
        // future peer set additions.
        self.rate_limiter.retain_recent();

        true
    }

    /// Gets a peer set by index.
    pub fn get_set(&self, index: &u64) -> Option<&OrderedSet<C>> {
        self.sets.get(index).map(Deref::deref)
    }

    /// Returns the latest peer set index.
    pub fn latest_set_index(&self) -> Option<u64> {
        self.sets.keys().last().copied()
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
        let (&index, set) = self.sets.iter().choose(&mut self.context)?;
        Some(types::BitVec {
            index,
            bits: set.knowledge(),
        })
    }

    /// Attempt to block a peer for the configured duration, updating the metrics accordingly.
    pub fn block(&mut self, peer: &C) {
        // Only add to queue if the record can actually be blocked
        let Some(record) = self.peers.get_mut(peer) else {
            return;
        };
        if !record.block() {
            return;
        }
        let blocked_until = self.context.current() + self.block_duration;
        self.blocked.block(peer.clone(), blocked_until);
        self.metrics.blocked.inc();
    }

    // ---------- Getters ----------

    /// Returns all peers that are part of at least one peer set.
    pub fn tracked(&self) -> OrderedSet<C> {
        self.peers
            .iter()
            .filter(|(_, r)| r.sets() > 0)
            .map(|(k, _)| k.clone())
            .try_collect()
            .expect("HashMap keys are unique")
    }

    /// Returns the sharable information for a given peer.
    pub fn info(&self, peer: &C) -> Option<Info<C>> {
        self.peers.get(peer).and_then(|r| r.sharable())
    }

    /// Returns all available peer information for a given bit vector.
    ///
    /// Returns `None` if the bit vector is malformed.
    pub fn infos(&self, bit_vec: types::BitVec) -> Option<Vec<types::Info<C>>> {
        let Some(set) = self.sets.get(&bit_vec.index) else {
            // Don't consider unknown indices as errors, just ignore them.
            debug!(index = bit_vec.index, "requested peer set not found");
            return Some(vec![]);
        };

        // Ensure that the bit vector is the same size as the peer set
        if bit_vec.bits.len() != set.len() as u64 {
            debug!(
                index = bit_vec.index,
                expected = set.len(),
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
                let peer = (!b).then_some(&set[i])?; // Only consider peers that the requester wants
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
        self.peers.get(peer).is_some_and(|r| r.eligible())
    }

    /// Returns a vector of dialable peers. That is, unconnected peers for which we have an ingress.
    pub fn dialable(&self) -> Vec<C> {
        // Collect peers with known addresses
        let mut result: Vec<_> = self
            .peers
            .iter()
            .filter(|&(_, r)| r.dialable(self.allow_private_ips, self.allow_dns))
            .map(|(peer, _)| peer.clone())
            .collect();
        result.sort();
        result
    }

    /// Returns true if this peer is acceptable (can accept an incoming connection from them).
    pub fn acceptable(&self, peer: &C) -> bool {
        self.peers.get(peer).is_some_and(|r| r.acceptable())
    }

    /// Unblock all peers whose block has expired and update the knowledge bitmap.
    pub fn unblock_expired(&mut self) {
        let now = self.context.current();
        let unblocked = self.blocked.unblock_expired(now);

        // Update metrics and clear blocks on records
        for peer in unblocked {
            self.metrics.blocked.dec();
            if let Some(record) = self.peers.get_mut(&peer) {
                record.clear_expired_block();

                // Update the knowledge bitmap for this peer
                let want = record.want(self.dial_fail_limit);
                for set in self.sets.values_mut() {
                    set.update(&peer, !want);
                }
            }
        }
    }

    /// Get the next unblock deadline (earliest blocked_until time).
    ///
    /// Returns `None` if no peers are currently blocked.
    pub fn next_unblock_deadline(&self) -> Option<SystemTime> {
        self.blocked.next_deadline()
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

        // Already reserved
        let record = self.peers.get_mut(peer).unwrap();
        if record.reserved() {
            return None;
        }

        // Rate limit
        if self.rate_limiter.check_key(peer).is_err() {
            self.metrics
                .limits
                .get_or_create(&metrics::Peer::new(peer))
                .inc();
            return None;
        }

        // Reserve
        if record.reserve() {
            self.metrics.reserved.inc();
            return Some(Reservation::new(metadata, self.releaser.clone()));
        }
        None
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
        // persists in blocked::Queue even after the record is deleted. The metric
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
    use commonware_runtime::{deterministic, Clock, Runner};
    use commonware_utils::NZU32;
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
            max_sets: 3,
            dial_fail_limit: 1,
            rate_limit: Quota::per_second(NZU32!(10)),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Blocking myself should be ignored (Myself is unblockable)
            directory.block(&my_pk);

            // Metrics should not be incremented
            assert_eq!(
                directory.metrics.blocked.get(),
                0,
                "Blocking myself should not increment metric"
            );

            // No unblock deadline should be set
            assert!(
                directory.next_unblock_deadline().is_none(),
                "No deadline since nothing was blocked"
            );

            // Advance time past block duration
            context.sleep(block_duration + Duration::from_secs(1)).await;

            // unblock_expired should not panic
            directory.unblock_expired();
        });
    }

    #[test]
    fn test_block_nonexistent_peer_ignored() {
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
            max_sets: 3,
            dial_fail_limit: 1,
            rate_limit: Quota::per_second(NZU32!(10)),
            block_duration,
        };

        runtime.start(|context| async move {
            let mut directory = Directory::init(context.clone(), vec![], my_info, config, releaser);

            // Blocking a peer that doesn't exist should be ignored
            directory.block(&unknown_pk);

            // Metrics should not be incremented
            assert_eq!(
                directory.metrics.blocked.get(),
                0,
                "Blocking nonexistent peer should not increment metric"
            );

            // No unblock deadline should be set
            assert!(
                directory.next_unblock_deadline().is_none(),
                "No deadline since nothing was blocked"
            );

            // Advance time past block duration
            context.sleep(block_duration + Duration::from_secs(1)).await;

            // unblock_expired should not panic
            directory.unblock_expired();
        });
    }
}
