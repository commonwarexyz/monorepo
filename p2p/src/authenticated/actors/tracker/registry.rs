use super::{
    metrics::Metrics,
    record::{Record, Status},
    set::Set,
    Reservation,
};
use crate::authenticated::{
    metrics,
    types::{self, PeerInfo},
};
use commonware_cryptography::Verifier;
use commonware_runtime::{Clock, Metrics as RuntimeMetrics, Spawner};
use commonware_utils::SystemTimeExt;
use futures::channel::mpsc;
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore, Quota,
    RateLimiter,
};
use rand::{
    seq::{IteratorRandom, SliceRandom},
    Rng,
};
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
};
use tracing::debug;

/// Represents a collection of records for all peers.
pub struct Registry<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: Verifier> {
    context: E,

    // ---------- Configuration ----------
    /// The maximum number of peer sets to track.
    max_sets: usize,

    // ---------- State ----------
    /// The records of all peers.
    peers: HashMap<C::PublicKey, Record<C>>,

    /// The peer sets
    sets: BTreeMap<u64, Set<C::PublicKey>>,

    /// Rate limiter for connection attempts.
    #[allow(clippy::type_complexity)]
    rate_limiter:
        RateLimiter<C::PublicKey, HashMapStateStore<C::PublicKey>, E, NoOpMiddleware<E::Instant>>,

    // ---------- Released Reservations Queue ----------
    /// Sender for releasing reservations.
    sender: mpsc::Sender<C::PublicKey>,

    /// Receiver for releasing reservations.
    receiver: mpsc::Receiver<C::PublicKey>,

    // ---------- Metrics ----------
    /// The metrics for the records.
    metrics: Metrics,
}

impl<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: Verifier> Registry<E, C> {
    /// Create a new set of records using the given bootstrappers and local node information.
    pub fn init(
        context: E,
        bootstrappers: Vec<(C::PublicKey, SocketAddr)>,
        myself: PeerInfo<C>,
        rate_limit: Quota,
        mailbox_size: usize,
        max_sets: usize,
    ) -> Self {
        let mut peers = HashMap::new();
        for (peer, socket) in bootstrappers {
            peers.insert(peer, Record::bootstrapper(socket));
        }
        // Overwrites the entry if myself is also a bootstrapper.
        peers.insert(myself.public_key.clone(), Record::myself(myself));
        let rate_limiter = RateLimiter::hashmap_with_clock(rate_limit, &context);
        let metrics = Metrics::init(context.clone());
        let (sender, receiver) = mpsc::channel(mailbox_size);
        Self {
            context,
            max_sets,
            peers,
            sets: BTreeMap::new(),
            rate_limiter,
            sender,
            receiver,
            metrics,
        }
    }

    /// Process all messages in the release queue.
    pub fn flush(&mut self) {
        // For each message in the queue...
        while let Ok(Some(peer)) = self.receiver.try_next() {
            // Release the reservation and remove the record if needed.
            if let Some(record) = self.peers.get_mut(&peer) {
                match record.release() {
                    Status::Inert => 0,
                    Status::Reserved => self.metrics.reserved.dec(),
                    Status::Active => self.metrics.connected.dec(),
                };
                self.delete_if_needed(&peer);
            };
        }
    }

    // ---------- Setters ----------

    pub fn connect(&mut self, peer: &C::PublicKey) {
        self.peers.get_mut(peer).unwrap().connect();
        self.metrics.connected.inc();
    }

    pub fn update_peers(&mut self, infos: Vec<types::PeerInfo<C>>) {
        for info in infos {
            // Update peer address
            //
            // It is not safe to rate limit how many times this can happen
            // over some interval because a malicious peer may just replay
            // old IPs to prevent us from propagating a new one.
            let peer = info.public_key.clone();
            if !self
                .peers
                .get_mut(&info.public_key)
                .is_some_and(|r| r.discover(info))
            {
                continue;
            }
            self.metrics
                .updates
                .get_or_create(&metrics::Peer::new(&peer))
                .inc();

            // Update peer set knowledge
            let want = self.peers.get(&peer).unwrap().want();
            for set in self.sets.values_mut() {
                set.set_to(&peer, !want);
            }
            debug!(?peer, "updated peer record");
        }
    }

    /// Stores a new peer set.
    pub fn add_set(&mut self, index: u64, peers: Vec<C::PublicKey>) {
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
        let mut set = Set::new(peers.clone());
        for peer in peers.iter() {
            self.try_insert(peer, Record::unknown());
            let record = self.peers.get_mut(peer).unwrap();
            record.increment();
            set.set_to(peer, !record.want());
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
    }

    /// Returns a shuffled list of peers that we have a known address for and were able to reserve.
    pub fn reserve_dialable(&mut self) -> Vec<(SocketAddr, Reservation<E, C::PublicKey>)> {
        // Collect peers with known addresses
        let result: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(peer, record)| record.address().map(|addr| (peer.clone(), addr)))
            .collect();

        // Attempt to reserve each peer
        let mut result: Vec<_> = result
            .into_iter()
            .filter_map(|(peer, addr)| self.reserve(&peer).map(|res| (addr, res)))
            .collect();

        // Shuffle to prevent starvation
        result.shuffle(&mut self.context);
        result
    }

    /// Returns a [`types::BitVec`] for a random peer set.
    pub fn get_random_bit_vec(&mut self) -> Option<types::BitVec> {
        let (&index, set) = self.sets.iter().choose(&mut self.context)?;
        Some(types::BitVec {
            index,
            bits: set.knowledge(),
        })
    }

    pub fn try_insert(&mut self, peer: &C::PublicKey, record: Record<C>) -> bool {
        if self.peers.contains_key(peer) {
            return false;
        }
        self.peers.insert(peer.clone(), record);
        self.metrics.tracked.inc();
        true
    }

    /// Attempt to delete a record.
    ///
    /// Returns `true` if the record was deleted, `false` otherwise.
    pub fn delete_if_needed(&mut self, peer: &C::PublicKey) -> bool {
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

    /// Attempt to reserve a peer.
    ///
    /// Returns `Some(Reservation)` if the peer was successfully reserved, `None` otherwise.
    pub fn reserve(&mut self, peer: &C::PublicKey) -> Option<Reservation<E, C::PublicKey>> {
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
                peer.clone(),
                self.sender.clone(),
            ));
        }
        None
    }

    /// Attempt to block a peer.
    ///
    /// Returns `true` if the peer was newly blocked, `false` otherwise.
    pub fn block(&mut self, peer: &C::PublicKey) -> bool {
        let Some(record) = self.peers.get_mut(peer) else {
            return false;
        };
        if record.block() {
            self.metrics.blocked.inc();
            return true;
        }
        false
    }

    // ---------- Getters ----------

    /// Returns the sharable information for a given peer.
    pub fn info(&self, peer: &C::PublicKey) -> Option<PeerInfo<C>> {
        self.peers.get(peer).and_then(|r| r.sharable_info())
    }

    /// Returns all available peer information for a given bit vector.
    ///
    /// Returns `None` if the bit vector is malformed.
    pub fn infos(&self, bit_vec: types::BitVec) -> Option<Vec<types::PeerInfo<C>>> {
        let Some(set) = self.sets.get(&bit_vec.index) else {
            // Don't consider unknown indices as errors, just ignore them.
            debug!(index = bit_vec.index, "requested peer set not found");
            return Some(vec![]);
        };

        // Ensure that the bit vector is the same size as the peer set
        if bit_vec.bits.len() != set.len() {
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
                let info = self.peers.get(peer).and_then(|r| r.sharable_info());
                // We may have information signed over a timestamp greater than the current time,
                // but within our synchrony bound. Avoid sharing this information as it could get us
                // blocked by other peers due to clock skew. Consider timestamps earlier than the
                // current time to be safe enough to share.
                info.filter(|i| i.timestamp <= self.context.current().epoch_millis())
            })
            .collect();

        Some(peers)
    }

    /// Returns true if the peer is able to be connected to.
    pub fn allowed(&self, peer: &C::PublicKey) -> bool {
        self.peers.get(peer).is_some_and(|r| r.allowed())
    }
}
