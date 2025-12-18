use super::{metrics::Metrics, record::Record, Metadata, Reservation};
use crate::{
    authenticated::lookup::{actors::tracker::ingress::Releaser, metrics},
    types::Address,
    Ingress,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{
    telemetry::metrics::status::GaugeExt, Clock, KeyedRateLimiter, Metrics as RuntimeMetrics,
    Quota, Spawner,
};
use commonware_utils::{
    ordered::{Map, Set},
    IpAddrExt, TryCollect,
};
use rand::Rng;
use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap, HashSet},
    net::IpAddr,
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

    /// Whether DNS-based ingress addresses are allowed.
    allow_dns: bool,

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
            allow_dns: cfg.allow_dns,
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
    pub fn add_set(&mut self, index: u64, peers: Map<C, Address>) -> Option<Vec<C>> {
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

        // Create and store new peer set (all peers are tracked regardless of address validity)
        for (peer, addr) in &peers {
            let record = match self.peers.entry(peer.clone()) {
                Entry::Occupied(entry) => {
                    let entry = entry.into_mut();
                    entry.update(addr.clone());
                    entry
                }
                Entry::Vacant(entry) => {
                    self.metrics.tracked.inc();
                    entry.insert(Record::known(addr.clone()))
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
    pub fn dial(&mut self, peer: &C) -> Option<(Reservation<C>, Ingress)> {
        let ingress = self.peers.get(peer)?.ingress()?;
        let reservation = self.reserve(Metadata::Dialer(peer.clone()))?;
        Some((reservation, ingress))
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

    /// Returns true if the peer is eligible for connection.
    ///
    /// A peer is eligible if it is in a peer set, not blocked, and not ourselves.
    /// This does NOT check IP validity - that is done separately for dialing (ingress)
    /// and accepting (egress).
    pub fn eligible(&self, peer: &C) -> bool {
        self.peers.get(peer).is_some_and(|r| r.eligible())
    }

    /// Returns a vector of dialable peers. That is, unconnected peers for which we have a socket.
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
    ///
    /// Checks eligibility (peer set membership), egress IP match, and connection status.
    pub fn acceptable(&self, peer: &C, source_ip: IpAddr) -> bool {
        self.peers
            .get(peer)
            .is_some_and(|r| r.acceptable(source_ip))
    }

    /// Return egress IPs we should listen for (accept incoming connections from).
    ///
    /// Only includes IPs from peers that are:
    /// - Eligible (in a peer set, not blocked, not ourselves)
    /// - Have a valid egress IP (global, or private IPs are allowed)
    pub fn listenable(&self) -> HashSet<IpAddr> {
        self.peers
            .values()
            .filter(|r| r.eligible())
            .filter_map(|r| r.egress_ip())
            .filter(|ip| self.allow_private_ips || IpAddrExt::is_global(ip))
            .collect()
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
    use crate::{
        authenticated::{lookup::actors::tracker::directory::Directory, mailbox::UnboundedMailbox},
        types::Address,
        Ingress,
    };
    use commonware_cryptography::{ed25519, Signer};
    use commonware_runtime::{deterministic, Quota, Runner};
    use commonware_utils::{hostname, NZU32};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn addr(socket: SocketAddr) -> Address {
        Address::Symmetric(socket)
    }

    #[test]
    fn test_add_set_return_value() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
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
                    [(pk_1.clone(), addr(addr_1)), (pk_2.clone(), addr(addr_2))]
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
                    [(pk_2.clone(), addr(addr_2)), (pk_3.clone(), addr(addr_3))]
                        .try_into()
                        .unwrap(),
                )
                .unwrap();
            assert_eq!(deleted.len(), 1, "One peer should be deleted");
            assert!(deleted.contains(&pk_1), "Deleted peer should be pk_1");

            let deleted = directory
                .add_set(2, [(pk_3.clone(), addr(addr_3))].try_into().unwrap())
                .unwrap();
            assert_eq!(deleted.len(), 1, "One peer should be deleted");
            assert!(deleted.contains(&pk_2), "Deleted peer should be pk_2");

            let deleted = directory
                .add_set(3, [(pk_3.clone(), addr(addr_3))].try_into().unwrap())
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
            allow_dns: true,
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
                [(pk_1.clone(), addr(addr_1)), (pk_2.clone(), addr(addr_2))]
                    .try_into()
                    .unwrap(),
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

            directory.add_set(1, [(pk_1.clone(), addr(addr_4))].try_into().unwrap());
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

            directory.add_set(2, [(my_pk.clone(), addr(addr_3))].try_into().unwrap());
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

            let deleted = directory
                .add_set(3, [(my_pk.clone(), addr(my_addr))].try_into().unwrap())
                .unwrap();
            assert_eq!(deleted.len(), 1);
            assert!(deleted.contains(&pk_2));

            let deleted = directory
                .add_set(4, [(my_pk.clone(), addr(addr_3))].try_into().unwrap())
                .unwrap();
            assert_eq!(deleted.len(), 1);
            assert!(deleted.contains(&pk_1));

            let deleted = directory.add_set(
                0,
                [(pk_1.clone(), addr(addr_1)), (pk_2.clone(), addr(addr_2))]
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
            allow_dns: true,
            max_sets: 3,
            rate_limit: Quota::per_second(NZU32!(10)),
        };

        let pk_1 = ed25519::PrivateKey::from_seed(1).public_key();
        let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1235);
        let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2235);

        runtime.start(|context| async move {
            let mut directory = Directory::init(context, my_pk.clone(), config, releaser);

            directory.add_set(0, [(pk_1.clone(), addr(addr_1))].try_into().unwrap());
            directory.block(&pk_1);
            let record = directory.peers.get(&pk_1).unwrap();
            assert!(
                record.blocked(),
                "Peer should be blocked after call to block"
            );
            assert!(
                record.ingress().is_none(),
                "Blocked peer should not have an ingress"
            );

            directory.add_set(1, [(pk_1.clone(), addr(addr_2))].try_into().unwrap());
            let record = directory.peers.get(&pk_1).unwrap();
            assert!(
                record.blocked(),
                "Blocked peer should remain blocked after update"
            );
            assert!(
                record.ingress().is_none(),
                "Blocked peer should not regain its ingress"
            );
        });
    }

    #[test]
    fn test_asymmetric_addresses() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = super::Releaser::new(tx);
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: true,
            max_sets: 3,
            rate_limit: Quota::per_second(NZU32!(10)),
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
            let deleted = directory
                .add_set(
                    0,
                    [
                        (pk_1.clone(), asymmetric_addr.clone()),
                        (pk_2.clone(), dns_addr.clone()),
                    ]
                    .try_into()
                    .unwrap(),
                )
                .unwrap();
            assert!(deleted.is_empty());

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

            // Verify registered() returns egress IPs for IP filtering
            let registered = directory.listenable();
            assert!(
                registered.contains(&egress_socket.ip()),
                "Registered should contain peer 1's egress IP"
            );
            assert!(
                registered.contains(&egress_socket_2.ip()),
                "Registered should contain peer 2's egress IP"
            );
            assert!(
                !registered.contains(&ingress_socket.ip()),
                "Registered should NOT contain peer 1's ingress IP"
            );
        });
    }

    #[test]
    fn test_dns_addresses_tracked_but_not_dialable_when_disabled() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = super::Releaser::new(tx);

        // DNS is disabled
        let config = super::Config {
            allow_private_ips: true,
            allow_dns: false,
            max_sets: 3,
            rate_limit: Quota::per_second(NZU32!(10)),
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
            let deleted = directory
                .add_set(
                    0,
                    [
                        (pk_socket.clone(), socket_peer_addr.clone()),
                        (pk_dns.clone(), dns_peer_addr.clone()),
                    ]
                    .try_into()
                    .unwrap(),
                )
                .unwrap();
            assert!(deleted.is_empty());

            // Both peers should be tracked (for peer set consistency)
            assert!(
                directory.peers.contains_key(&pk_socket),
                "Socket peer should be tracked"
            );
            assert!(
                directory.peers.contains_key(&pk_dns),
                "DNS peer should be tracked for peer set consistency"
            );

            // Only socket peer should be dialable (DNS ingress invalid when disabled)
            let dialable = directory.dialable();
            assert_eq!(dialable.len(), 1);
            assert_eq!(dialable[0], pk_socket);
        });
    }

    #[test]
    fn test_private_egress_ip_tracked_but_not_dialable_or_registered() {
        let runtime = deterministic::Runner::default();
        let my_pk = ed25519::PrivateKey::from_seed(0).public_key();
        let (tx, _rx) = UnboundedMailbox::new();
        let releaser = super::Releaser::new(tx);

        // Private IPs are NOT allowed
        let config = super::Config {
            allow_private_ips: false,
            allow_dns: true,
            max_sets: 3,
            rate_limit: Quota::per_second(NZU32!(10)),
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
            let deleted = directory
                .add_set(
                    0,
                    [
                        (pk_public.clone(), public_addr.clone()),
                        (pk_private.clone(), private_addr.clone()),
                    ]
                    .try_into()
                    .unwrap(),
                )
                .unwrap();
            assert!(deleted.is_empty());

            // Both peers should be tracked (for peer set consistency)
            assert!(
                directory.peers.contains_key(&pk_public),
                "Public peer should be tracked"
            );
            assert!(
                directory.peers.contains_key(&pk_private),
                "Private peer should be tracked for peer set consistency"
            );

            // Only public peer should be dialable (private ingress IP not allowed)
            let dialable = directory.dialable();
            assert_eq!(dialable.len(), 1);
            assert_eq!(dialable[0], pk_public);

            // Verify registered() only returns public IP (private IP excluded from filter)
            let registered = directory.listenable();
            assert!(registered.contains(&Ipv4Addr::new(8, 8, 8, 8).into()));
            assert!(!registered.contains(&Ipv4Addr::new(10, 0, 0, 1).into()));
        });
    }
}
