use super::{metrics::Metrics, record::Record, Metadata, Reservation};
use crate::authenticated::lookup::metrics;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Metrics as RuntimeMetrics, Spawner};
use futures::channel::mpsc;
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore, Quota,
    RateLimiter,
};
use rand::Rng;
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
};
use tracing::debug;

/// Configuration for the [`Directory`].
pub struct Config {
    /// The maximum number of peer sets to track.
    pub mailbox_size: usize,

    /// The maximum number of peer sets to track.
    pub max_sets: usize,

    /// The rate limit for allowing reservations per-peer.
    pub rate_limit: Quota,
}

/// Represents a collection of records for all peers.
pub struct Directory<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: PublicKey> {
    context: E,

    // ---------- Configuration ----------
    /// The maximum number of peer sets to track.
    max_sets: usize,

    // ---------- State ----------
    /// The records of all peers.
    peers: HashMap<C, Record>,

    /// The peer sets
    sets: BTreeMap<u64, Vec<C>>,

    /// Rate limiter for connection attempts.
    #[allow(clippy::type_complexity)]
    rate_limiter: RateLimiter<C, HashMapStateStore<C>, E, NoOpMiddleware<E::Instant>>,

    // ---------- Released Reservations Queue ----------
    /// Sender for releasing reservations.
    sender: mpsc::Sender<Metadata<C>>,

    /// Receiver for releasing reservations.
    receiver: mpsc::Receiver<Metadata<C>>,

    // ---------- Metrics ----------
    /// The metrics for the records.
    metrics: Metrics,
}

impl<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: PublicKey> Directory<E, C> {
    /// Create a new set of records using the given bootstrappers and local node information.
    pub fn init(
        context: E,
        bootstrappers: Vec<(C, SocketAddr)>,
        myself: (C, SocketAddr),
        cfg: Config,
    ) -> Self {
        // Create the list of peers and add the bootstrappers.
        let mut peers = HashMap::new();
        for (peer, socket) in bootstrappers {
            peers.insert(peer, Record::bootstrapper(socket));
        }

        // Add myself to the list of peers.
        // Overwrites the entry if myself is also a bootstrapper.
        peers.insert(myself.0, Record::myself(myself.1));
        let rate_limiter = RateLimiter::hashmap_with_clock(cfg.rate_limit, &context);

        // Other initialization.
        let metrics = Metrics::init(context.clone());
        metrics.tracked.set((peers.len() - 1) as i64); // Exclude self
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);

        Self {
            context,
            max_sets: cfg.max_sets,
            peers,
            sets: BTreeMap::new(),
            rate_limiter,
            sender,
            receiver,
            metrics,
        }
    }

    /// Process all messages in the release queue.
    pub fn process_releases(&mut self) {
        // For each message in the queue...
        while let Ok(Some(metadata)) = self.receiver.try_next() {
            let peer = metadata.public_key();
            let Some(record) = self.peers.get_mut(peer) else {
                continue;
            };
            record.release();
            self.metrics.reserved.dec();

            self.delete_if_needed(peer);
        }
    }

    // ---------- Setters ----------

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

    /// Sets the peer's address. No-op if the peer is not tracked.
    pub fn update_address(&mut self, peer: &C, address: SocketAddr) {
        let Some(record) = self.peers.get_mut(peer) else {
            debug!(?peer, "peer not tracked");
            return;
        };
        record.update_address(address);
        self.metrics
            .updates
            .get_or_create(&metrics::Peer::new(peer))
            .inc();
    }

    /// Stores a new peer set.
    pub fn add_set(&mut self, index: u64, peers: Vec<C>) {
        // Check if peer set already exists
        if self.sets.contains_key(&index) {
            debug!(index, "peer set already exists");
            return;
        }

        // Ensure that peer set is monotonically increasing
        if let Some((last, _)) = self.sets.last_key_value() {
            if index <= *last {
                debug!(?index, ?last, "index must monotonically increase",);
                return;
            }
        }

        // Create and store new peer set
        for peer in &peers {
            let record = self.peers.entry(peer.clone()).or_insert_with(|| {
                self.metrics.tracked.inc();
                Record::unknown()
            });
            record.increment();
        }
        self.sets.insert(index, peers);

        // Remove oldest entries if necessary
        while self.sets.len() > self.max_sets {
            let (index, set) = self.sets.pop_first().unwrap();
            debug!(index, "removed oldest peer set");
            set.into_iter().for_each(|peer| {
                self.peers.get_mut(&peer).unwrap().decrement();
                self.delete_if_needed(&peer);
            });
        }

        // Attempt to remove any old records from the rate limiter.
        // This is a best-effort attempt to prevent memory usage from growing indefinitely.
        self.rate_limiter.shrink_to_fit();
    }

    /// Returns a vector of dialable peers. That is, unconnected peers for which we have a socket.
    pub fn dialable(&self) -> Vec<C> {
        // Collect peers with known addresses
        let mut result: Vec<_> = self
            .peers
            .iter()
            .filter(|&(_, r)| r.dialable())
            .map(|(peer, _)| peer.clone())
            .collect();
        result.sort();
        result
    }

    /// Attempt to reserve a peer for the dialer.
    ///
    /// Returns `Some` on success, `None` otherwise.
    pub fn dial(&mut self, peer: &C) -> Option<Reservation<E, C>> {
        let socket = self.peers.get(peer)?.socket()?;
        self.reserve(Metadata::Dialer(peer.clone(), socket))
    }

    /// Attempt to reserve a peer for the listener.
    ///
    /// Returns `Some` on success, `None` otherwise.
    pub fn listen(&mut self, peer: &C) -> Option<Reservation<E, C>> {
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
        self.peers.get(peer).is_some_and(|r| r.allowed())
    }

    // --------- Helpers ----------

    /// Attempt to reserve a peer.
    ///
    /// Returns `Some(Reservation)` if the peer was successfully reserved, `None` otherwise.
    fn reserve(&mut self, metadata: Metadata<C>) -> Option<Reservation<E, C>> {
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
            return Some(Reservation::new(
                self.context.clone(),
                metadata,
                self.sender.clone(),
            ));
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
