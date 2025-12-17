use super::{metrics::Metrics, record::Record, Metadata, Reservation};
use crate::authenticated::lookup::{actors::tracker::ingress::Releaser, metrics};
use commonware_cryptography::PublicKey;
use commonware_runtime::{
    telemetry::metrics::status::GaugeExt, Clock, KeyedRateLimiter, Metrics as RuntimeMetrics,
    Quota, Spawner,
};
use commonware_utils::{
    ordered::{Map, Set},
    TryCollect,
};
use rand::Rng;
use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};
use tracing::{debug, warn};

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
pub struct Directory<E: Rng + Clock + RuntimeMetrics, C: PublicKey> {
    // ---------- Configuration ----------
    /// The maximum number of peer sets to track.
    max_sets: usize,

    /// Whether private IPs are connectable.
    pub allow_private_ips: bool,

    // ---------- State ----------
    /// The records of all peers.
    peers: HashMap<C, Record>,

    /// The peer sets
    sets: BTreeMap<u64, Set<C>>,

    /// Rate limiter for connection attempts.
    rate_limiter: KeyedRateLimiter<C, E>,

    // ---------- Message-Passing ----------
    /// The releaser for the tracker actor.
    releaser: Releaser<C>,

    // ---------- Metrics ----------
    /// The metrics for the records.
    metrics: Metrics,
}

impl<E: Spawner + Rng + Clock + RuntimeMetrics, C: PublicKey> Directory<E, C> {
    /// Create a new set of records using the given local node information.
    pub fn init(context: E, myself: C, cfg: Config, releaser: Releaser<C>) -> Self {
        // Create the list of peers and add myself.
        let mut peers = HashMap::new();
        peers.insert(myself, Record::myself());

        // Other initialization.
        let rate_limiter = KeyedRateLimiter::hashmap_with_clock(cfg.rate_limit, context.clone());

        let metrics = Metrics::init(context);
        let _ = metrics.tracked.try_set(peers.len() - 1); // Exclude self

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
    pub fn add_set(&mut self, index: u64, peers: Map<C, SocketAddr>) -> Option<Vec<C>> {
        // Check if peer set already exists
        if self.sets.contains_key(&index) {
            warn!(index, "peer set already exists");
            return None;
        }

        // Ensure that peer set is monotonically increasing
        if let Some((last, _)) = self.sets.last_key_value() {
            if index <= *last {
                warn!(?index, ?last, "index must monotonically increase");
                return None;
            }
        }

        // Create and store new peer set
        for (peer, addr) in &peers {
            let record = match self.peers.entry(peer.clone()) {
                Entry::Occupied(entry) => {
                    let entry = entry.into_mut();
                    entry.update(*addr);
                    entry
                }
                Entry::Vacant(entry) => {
                    self.metrics.tracked.inc();
                    entry.insert(Record::known(*addr))
                }
            };
            record.increment();
        }
        self.sets.insert(index, peers.into_keys());

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
        Some(deleted_peers)
    }

    /// Gets a peer set by index.
    pub fn get_set(&self, index: &u64) -> Option<&Set<C>> {
        self.sets.get(index)
    }

    /// Returns the latest peer set index.
    pub fn latest_set_index(&self) -> Option<u64> {
        self.sets.keys().last().copied()
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

    /// Returns all peers that are part of at least one peer set.
    pub fn tracked(&self) -> Set<C> {
        self.peers
            .iter()
            .filter(|(_, r)| r.sets() > 0)
            .map(|(k, _)| k.clone())
            .try_collect()
            .expect("HashMap keys are unique")
    }

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
    use commonware_cryptography::{ed25519, Signer};
    use commonware_runtime::{deterministic, Quota, Runner};
    use commonware_utils::NZU32;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_add_set_return_value() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            max_sets: 1,
            rate_limit: Quota::per_second(NZU32!(10)),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let pk_2 = ed25519::PrivateKey::from_seed(2).public_key();
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1236);
        let pk_3 = ed25519::PrivateKey::from_seed(3).public_key();
        let addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1237);

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, my_pk, config, releaser);

            let deleted = directory
                .add_set(
                    0,
                    [(pk_1.clone(), addr_1), (pk_2.clone(), addr_2)]
                        .try_into()
                        .unwrap(),
                )
                .unwrap();
            assert!(
                deleted.is_empty(),
                "No peers should be deleted on first set"
            );

            let deleted = directory
                .add_set(
                    1,
                    [(pk_2.clone(), addr_2), (pk_3.clone(), addr_3)]
                        .try_into()
                        .unwrap(),
                )
                .unwrap();
            assert_eq!(deleted.len(), 1, "One peer should be deleted");
            assert!(deleted.contains(&pk_1), "Deleted peer should be pk_1");

            let deleted = directory
                .add_set(2, [(pk_3.clone(), addr_3)].try_into().unwrap())
                .unwrap();
            assert_eq!(deleted.len(), 1, "One peer should be deleted");
            assert!(deleted.contains(&pk_2), "Deleted peer should be pk_2");

            let deleted = directory
                .add_set(3, [(pk_3.clone(), addr_3)].try_into().unwrap())
                .unwrap();
            assert!(deleted.is_empty(), "No peers should be deleted");
        });
    }

    #[test]
    fn test_add_set_update_address() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let my_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            max_sets: 3,
            rate_limit: Quota::per_second(NZU32!(10)),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let addr_4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1238);
        let pk_2 = ed25519::PrivateKey::from_seed(2).public_key();
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1236);
        let pk_3 = ed25519::PrivateKey::from_seed(3).public_key();
        let addr_3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1237);

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, my_pk.clone(), config, releaser);

            directory.add_set(
                0,
                [(pk_1.clone(), addr_1), (pk_2.clone(), addr_2)]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(directory.peers.get(&my_pk).unwrap().socket(), None);
            assert_eq!(directory.peers.get(&pk_1).unwrap().socket(), Some(addr_1));
            assert_eq!(directory.peers.get(&pk_2).unwrap().socket(), Some(addr_2));
            assert!(!directory.peers.contains_key(&pk_3));

            // Update address
            directory.add_set(1, [(pk_1.clone(), addr_4)].try_into().unwrap());
            assert_eq!(directory.peers.get(&my_pk).unwrap().socket(), None);
            assert_eq!(directory.peers.get(&pk_1).unwrap().socket(), Some(addr_4));
            assert_eq!(directory.peers.get(&pk_2).unwrap().socket(), Some(addr_2));
            assert!(!directory.peers.contains_key(&pk_3));

            // Ignore update to me
            directory.add_set(2, [(my_pk.clone(), addr_3)].try_into().unwrap());
            assert_eq!(directory.peers.get(&my_pk).unwrap().socket(), None);
            assert_eq!(directory.peers.get(&pk_1).unwrap().socket(), Some(addr_4));
            assert_eq!(directory.peers.get(&pk_2).unwrap().socket(), Some(addr_2));
            assert!(!directory.peers.contains_key(&pk_3));

            // Ensure tracking works for static peers
            let deleted = directory
                .add_set(3, [(my_pk.clone(), my_addr)].try_into().unwrap())
                .unwrap();
            assert_eq!(deleted.len(), 1);
            assert!(deleted.contains(&pk_2));

            // Ensure tracking works for dynamic peers
            let deleted = directory
                .add_set(4, [(my_pk.clone(), addr_3)].try_into().unwrap())
                .unwrap();
            assert_eq!(deleted.len(), 1);
            assert!(deleted.contains(&pk_1));

            // Attempt to add an old peer set
            let deleted = directory.add_set(
                0,
                [(pk_1.clone(), addr_1), (pk_2.clone(), addr_2)]
                    .try_into()
                    .unwrap(),
            );
            assert!(deleted.is_none());
        });
    }

    #[test]
    fn test_blocked_peer_remains_blocked_on_update() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            max_sets: 3,
            rate_limit: Quota::per_second(NZU32!(10)),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2235);

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, my_pk.clone(), config, releaser);

            directory.add_set(0, [(pk_1.clone(), addr_1)].try_into().unwrap());
            directory.block(&pk_1);
            let record = directory.peers.get(&pk_1).unwrap();
            assert!(
                record.blocked(),
                "Peer should be blocked after call to block"
            );
            assert_eq!(
                record.socket(),
                None,
                "Blocked peer should not have a socket"
            );

            directory.add_set(1, [(pk_1.clone(), addr_2)].try_into().unwrap());
            let record = directory.peers.get(&pk_1).unwrap();
            assert!(
                record.blocked(),
                "Blocked peer should remain blocked after update"
            );
            assert_eq!(
                record.socket(),
                None,
                "Blocked peer should not regain its socket"
            );
        });
    }
}
