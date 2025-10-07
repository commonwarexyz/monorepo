use super::{metrics::Metrics, record::Record, Metadata, Reservation};
use crate::authenticated::lookup::{actors::tracker::ingress::Releaser, metrics};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Metrics as RuntimeMetrics, Spawner};
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore, Quota,
    RateLimiter,
};
use rand::Rng;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};
use tracing::debug;

/// Configuration for the [Directory].
pub struct Config {
    /// Whether private IPs are connectable.
    pub allow_private_ips: bool,

    /// The maximum number of peer sets to track.
    pub max_sets: usize,

    /// The rate limit for allowing reservations per-peer.
    pub rate_limit: Quota,
}

/// Represents a collection of records for all peers.
pub struct Directory<E: Rng + Clock + GClock + RuntimeMetrics, C: PublicKey> {
    // ---------- Configuration ----------
    /// The maximum number of peer sets to track.
    max_sets: usize,

    /// Whether private IPs are connectable.
    pub allow_private_ips: bool,

    // ---------- State ----------
    /// The records of all peers.
    peers: HashMap<C, Record>,

    /// The peer sets
    sets: BTreeMap<u64, Vec<C>>,

    /// Rate limiter for connection attempts.
    #[allow(clippy::type_complexity)]
    rate_limiter: RateLimiter<C, HashMapStateStore<C>, E, NoOpMiddleware<E::Instant>>,

    // ---------- Message-Passing ----------
    /// The releaser for the tracker actor.
    releaser: Releaser<C>,

    // ---------- Metrics ----------
    /// The metrics for the records.
    metrics: Metrics,
}

impl<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: PublicKey> Directory<E, C> {
    /// Create a new set of records using the given local node information.
    pub fn init(context: E, myself: (C, SocketAddr), cfg: Config, releaser: Releaser<C>) -> Self {
        // Create the list of peers and add myself.
        let mut peers = HashMap::new();
        peers.insert(myself.0, Record::myself(myself.1));

        // Other initialization.
        let rate_limiter = RateLimiter::hashmap_with_clock(cfg.rate_limit, &context);
        let metrics = Metrics::init(context.clone());
        metrics.tracked.set((peers.len() - 1) as i64); // Exclude self

        Self {
            max_sets: cfg.max_sets,
            allow_private_ips: cfg.allow_private_ips,
            peers,
            sets: BTreeMap::new(),
            rate_limiter,
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
        self.delete_if_needed(peer);
    }

    /// Sets the status of a peer to `connected`.
    ///
    /// # Panics
    ///
    /// Panics if the peer is not tracked or if the peer is not in the reserved state.
    pub fn connect(&mut self, peer: &C) {
        // Set the record as connected
        let record = self.peers.get_mut(peer).unwrap();
        record.connect();
    }

    /// Stores a new peer set.
    pub fn add_set(&mut self, index: u64, peers: Vec<(C, SocketAddr)>) -> Vec<C> {
        // Check if peer set already exists
        if self.sets.contains_key(&index) {
            debug!(index, "peer set already exists");
            return Vec::new();
        }

        // Ensure that peer set is monotonically increasing
        if let Some((last, _)) = self.sets.last_key_value() {
            if index <= *last {
                debug!(?index, ?last, "index must monotonically increase",);
                return Vec::new();
            }
        }

        // Create and store new peer set
        for (peer, addr) in &peers {
            let record = self.peers.entry(peer.clone()).or_insert_with(|| {
                self.metrics.tracked.inc();
                Record::known(*addr)
            });
            record.increment();
        }
        let peers: Vec<_> = peers.into_iter().map(|(peer, _)| peer).collect();
        self.sets.insert(index, peers);

        // Remove oldest entries if necessary
        let mut deleted_peers = Vec::new();
        while self.sets.len() > self.max_sets {
            let (index, set) = self.sets.pop_first().unwrap();
            debug!(index, "removed oldest peer set");
            set.into_iter().for_each(|peer| {
                self.peers.get_mut(&peer).unwrap().decrement();
                let deleted = self.delete_if_needed(&peer);
                if deleted {
                    deleted_peers.push(peer);
                }
            });
        }

        // Attempt to remove any old records from the rate limiter.
        // This is a best-effort attempt to prevent memory usage from growing indefinitely.
        self.rate_limiter.shrink_to_fit();
        deleted_peers
    }

    /// Attempt to reserve a peer for the dialer.
    ///
    /// Returns `Some` on success, `None` otherwise.
    pub fn dial(&mut self, peer: &C) -> Option<Reservation<C>> {
        let socket = self.peers.get(peer)?.socket()?;
        self.reserve(Metadata::Dialer(peer.clone(), socket))
    }

    /// Attempt to reserve a peer for the listener.
    ///
    /// Returns `Some` on success, `None` otherwise.
    pub fn listen(&mut self, peer: &C) -> Option<Reservation<C>> {
        self.reserve(Metadata::Listener(peer.clone()))
    }

    /// Attempt to block a peer, updating the metrics accordingly.
    pub fn block(&mut self, peer: &C) {
        if self.peers.get_mut(peer).is_some_and(|r| r.block()) {
            self.metrics.blocked.inc();
        }
    }

    // ---------- Getters ----------

    /// Returns true if the peer is able to be connected to.
    pub fn allowed(&self, peer: &C) -> bool {
        self.peers
            .get(peer)
            .is_some_and(|r| r.allowed(self.allow_private_ips))
    }

    /// Returns a vector of dialable peers. That is, unconnected peers for which we have a socket.
    pub fn dialable(&self) -> Vec<C> {
        // Collect peers with known addresses
        let mut result: Vec<_> = self
            .peers
            .iter()
            .filter(|&(_, r)| r.dialable(self.allow_private_ips))
            .map(|(peer, _)| peer.clone())
            .collect();
        result.sort();
        result
    }

    /// Returns true if the peer is listenable.
    pub fn listenable(&self, peer: &C) -> bool {
        self.peers
            .get(peer)
            .is_some_and(|r| r.listenable(self.allow_private_ips))
    }

    /// Return all registered IP addresses.
    pub fn registered(&self) -> HashSet<IpAddr> {
        // Using `.allowed()` here excludes any peers that are still connected but no longer
        // part of a peer set (and will be dropped shortly).
        self.peers
            .values()
            .filter(|r| r.allowed(self.allow_private_ips))
            .filter_map(|r| r.socket().map(|s| s.ip()))
            .collect()
    }

    // --------- Helpers ----------

    /// Attempt to reserve a peer.
    ///
    /// Returns `Some(Reservation)` if the peer was successfully reserved, `None` otherwise.
    fn reserve(&mut self, metadata: Metadata<C>) -> Option<Reservation<C>> {
        let peer = metadata.public_key();

        // Not reservable
        if !self.allowed(peer) {
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
        if record.blocked() {
            self.metrics.blocked.dec();
        }
        self.peers.remove(peer);
        self.metrics.tracked.dec();
        true
    }
}

#[cfg(test)]
mod tests {
    use crate::authenticated::{
        lookup::actors::tracker::directory::Directory, mailbox::UnboundedMailbox,
    };
    use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::NZU32;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_add_set_return_value() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let my_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            max_sets: 1,
            rate_limit: governor::Quota::per_second(NZU32!(10)),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let pk_2 = ed25519::PrivateKey::from_seed(2).public_key();
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1236);
        let pk_3 = ed25519::PrivateKey::from_seed(3).public_key();
        let addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1237);

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, (my_pk, my_addr), config, releaser);

            let deleted =
                directory.add_set(0, vec![(pk_1.clone(), addr_1), (pk_2.clone(), addr_2)]);
            assert!(
                deleted.is_empty(),
                "No peers should be deleted on first set"
            );

            let deleted =
                directory.add_set(1, vec![(pk_2.clone(), addr_2), (pk_3.clone(), addr_3)]);
            assert_eq!(deleted.len(), 1, "One peer should be deleted");
            assert!(deleted.contains(&pk_1), "Deleted peer should be pk_1");

            let deleted = directory.add_set(2, vec![(pk_3.clone(), addr_3)]);
            assert_eq!(deleted.len(), 1, "One peer should be deleted");
            assert!(deleted.contains(&pk_2), "Deleted peer should be pk_2");

            let deleted = directory.add_set(3, vec![(pk_3.clone(), addr_3)]);
            assert!(deleted.is_empty(), "No peers should be deleted");
        });
    }
}
