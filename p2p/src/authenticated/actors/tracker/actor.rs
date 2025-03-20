use super::address::AddressCount;
pub use super::{
    address::Address,
    ingress::{Mailbox, Message, Oracle, Reservation},
    Config, Error,
};
use crate::authenticated::{
    ip, metrics,
    types::{self, SignedPeerInfo},
};
use bitvec::prelude::*;
use commonware_codec::Codec;
use commonware_cryptography::Scheme;
use commonware_runtime::{Clock, Handle, Metrics, Spawner};
use commonware_utils::{union, Array, SystemTimeExt};
use futures::{channel::mpsc, StreamExt};
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore,
    RateLimiter,
};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use rand::{
    prelude::{IteratorRandom, SliceRandom},
    Rng,
};
use std::time::Duration;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
};
use tracing::{debug, trace};

// Bytes to add to the namespace to prevent replay attacks.
const NAMESPACE_SUFFIX_IP: &[u8] = b"_IP";

struct PeerSet<P: Array> {
    index: u64,
    sorted: Vec<P>,
    order: HashMap<P, usize>,
    knowledge: BitVec<u8, Lsb0>,
    msg: types::BitVec,
}

impl<P: Array> PeerSet<P> {
    fn new(index: u64, mut peers: Vec<P>) -> Self {
        // Insert peers in sorted order
        peers.sort();
        let mut order = HashMap::new();
        for (idx, peer) in peers.iter().enumerate() {
            order.insert(peer.clone(), idx);
        }

        // Create bit vector
        let knowledge = BitVec::repeat(false, peers.len());

        // Create message
        let msg = types::BitVec {
            index,
            bits: knowledge.clone().into(),
        };

        Self {
            index,
            sorted: peers,
            order,
            knowledge,
            msg,
        }
    }

    fn found(&mut self, peer: P) -> bool {
        if let Some(idx) = self.order.get(&peer) {
            self.knowledge.set(*idx, true);
            return true;
        }
        false
    }

    fn update_msg(&mut self) {
        self.msg = types::BitVec {
            index: self.index,
            bits: self.knowledge.clone().into(),
        };
    }

    fn msg(&self) -> types::BitVec {
        self.msg.clone()
    }
}

pub struct Actor<E: Spawner + Rng + GClock + Metrics, C: Scheme> {
    context: E,

    crypto: C,
    ip_namespace: Vec<u8>,
    allow_private_ips: bool,
    synchrony_bound: Duration,
    tracked_peer_sets: usize,
    peer_gossip_max_count: usize,

    sender: mpsc::Sender<Message<E, C>>,
    receiver: mpsc::Receiver<Message<E, C>>,
    peers: BTreeMap<C::PublicKey, AddressCount<C>>,
    sets: BTreeMap<u64, PeerSet<C::PublicKey>>,
    #[allow(clippy::type_complexity)]
    connections_rate_limiter:
        RateLimiter<C::PublicKey, HashMapStateStore<C::PublicKey>, E, NoOpMiddleware<E::Instant>>,
    connections: HashSet<C::PublicKey>,

    tracked_peers: Gauge,
    reserved_connections: Gauge,
    rate_limited_connections: Family<metrics::Peer, Counter>,
    updated_peers: Family<metrics::Peer, Counter>,

    ip_signature: types::SignedPeerInfo<C>,
}

impl<E: Spawner + Rng + Clock + GClock + Metrics, C: Scheme> Actor<E, C> {
    #[allow(clippy::type_complexity)]
    pub fn new(context: E, mut cfg: Config<C>) -> (Self, Mailbox<E, C>, Oracle<E, C>) {
        // Construct IP signature
        let timestamp = context.current().epoch_millis();
        let ip_namespace = union(&cfg.namespace, NAMESPACE_SUFFIX_IP);
        let peer_info = types::PeerInfo {
            socket: cfg.address,
            timestamp,
        };
        let signature = cfg.crypto.sign(Some(&ip_namespace), &peer_info.encode());
        let ip_signature = types::SignedPeerInfo {
            info: peer_info,
            public_key: cfg.crypto.public_key(),
            signature,
        };

        // Register bootstrappers
        let mut peers = BTreeMap::new();
        for (peer, address) in cfg.bootstrappers.into_iter() {
            if peer == cfg.crypto.public_key() {
                continue;
            }
            peers.insert(peer, AddressCount::new_bootstrapper(address));
        }

        // Configure peer set
        let mut tracked_peer_sets = cfg.tracked_peer_sets;
        if tracked_peer_sets == 0 {
            tracked_peer_sets = 1
        };
        let sets: BTreeMap<u64, PeerSet<C::PublicKey>> = BTreeMap::new();

        // Construct channels
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);

        // Create connections
        let connections_rate_limiter =
            RateLimiter::hashmap_with_clock(cfg.allowed_connection_rate_per_peer, &context);

        // Create metrics
        let tracked_peers = Gauge::default();
        let reserved_connections = Gauge::default();
        let rate_limited_connections = Family::<metrics::Peer, Counter>::default();
        let updated_peers = Family::<metrics::Peer, Counter>::default();
        context.register("tracked_peers", "tracked peers", tracked_peers.clone());
        context.register(
            "reservations",
            "number of reserved connections",
            reserved_connections.clone(),
        );
        context.register(
            "rate_limited_connections",
            "number of rate limited connections",
            rate_limited_connections.clone(),
        );
        context.register(
            "updated_peers",
            "number of peer records updated",
            updated_peers.clone(),
        );

        (
            Self {
                context,
                crypto: cfg.crypto,
                ip_namespace,
                allow_private_ips: cfg.allow_private_ips,
                synchrony_bound: cfg.synchrony_bound,
                tracked_peer_sets,
                peer_gossip_max_count: cfg.peer_gossip_max_count,

                ip_signature,

                sender: sender.clone(),
                receiver,
                peers,
                sets,

                connections_rate_limiter,
                connections: HashSet::new(),

                tracked_peers,
                reserved_connections,
                rate_limited_connections,
                updated_peers,
            },
            Mailbox::new(sender.clone()),
            Oracle::new(sender),
        )
    }

    /// Returns whether a peer is not us and in one of the known peer sets.
    fn allowed(&self, peer: &C::PublicKey) -> bool {
        if *peer == self.crypto.public_key() {
            return false;
        }
        for set in self.sets.values() {
            if set.order.contains_key(peer) {
                return true;
            }
        }
        false
    }

    /// Stores a new peer set and increments peer counters.
    fn store_peer_set(&mut self, index: u64, peers: Vec<C::PublicKey>) {
        // Check if peer set already exists
        if self.sets.contains_key(&index) {
            debug!(index, "peer set already exists");
            return;
        }

        // Ensure that peer set is monotonically increasing
        match self.sets.keys().last() {
            Some(last) if index <= *last => {
                debug!(
                    index,
                    last, "peer set index must be monotonically increasing"
                );
                return;
            }
            _ => {}
        }

        // Create and store new peer set
        let set = PeerSet::new(index, peers.clone());
        self.sets.insert(index, set);

        // Update stored counters
        let set = self.sets.get_mut(&index).unwrap();
        for peer in peers.iter() {
            if let Some(address) = self.peers.get_mut(peer) {
                address.increment();
                if address.has_discovered() {
                    set.found(peer.clone());
                }
            } else {
                self.peers.insert(peer.clone(), AddressCount::new());
            }
        }

        // Add self
        set.found(self.crypto.public_key());

        // Update bit vector now that we have changed it
        set.update_msg();

        // Remove oldest entries if necessary
        while self.sets.len() > self.tracked_peer_sets {
            let (index, set) = self.sets.pop_first().unwrap();
            debug!(index, "removed oldest peer set");

            // Iterate over peer set and decrement counts
            for peer in set.order.keys() {
                if let Some(address) = self.peers.get_mut(peer) {
                    if address.decrement() {
                        self.peers.remove(peer);
                    }
                }
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn handle_dialable(&mut self) -> Vec<(C::PublicKey, SocketAddr, Reservation<E, C>)> {
        // Collect unreserved peers
        let available_peers: Vec<_> = self
            .peers
            .keys()
            .filter(|peer| !self.connections.contains(*peer))
            .cloned()
            .collect();

        // Iterate over available peers
        let mut reserved = Vec::new();
        for peer in available_peers {
            // Reserve the connection
            let reservation = match self.reserve(peer.clone()) {
                Some(reservation) => reservation,
                None => continue, // can happen if rate limited
            };

            // Grab address
            if let Some(address) = self.peers.get(&peer).unwrap().get_address() {
                reserved.push((peer, address, reservation));
            };
        }
        reserved
    }

    fn handle_peer(&mut self, peer: &C::PublicKey, signed_peer_info: SignedPeerInfo<C>) -> bool {
        // Check if peer is authorized
        if !self.allowed(peer) {
            return false;
        }

        // Update peer address
        //
        // It is not safe to rate limit how many times this can happen
        // over some interval because a malicious peer may just replay
        // old IPs to prevent us from propagating a new one.
        let record = self.peers.get_mut(peer).unwrap();
        let wire_time = signed_peer_info.info.timestamp;
        if !record.set_discovered(signed_peer_info) {
            trace!(?peer, wire_time, "stored peer newer");
            return false;
        }
        self.updated_peers
            .get_or_create(&metrics::Peer::new(peer))
            .inc();

        // Update peer set knowledge
        for set in self.sets.values_mut() {
            if set.found(peer.clone()) {
                set.update_msg();
            }
        }
        true
    }

    fn handle_peers(&mut self, peers: Vec<types::SignedPeerInfo<C>>) -> Result<(), Error> {
        // Ensure there aren't too many peers sent
        if peers.len() > self.peer_gossip_max_count {
            return Err(Error::TooManyPeers(peers.len()));
        }

        // We allow peers to be sent in any order when responding to a bit vector (allows
        // for selecting a random subset of peers when there are too many) and allow
        // for duplicates (no need to create an additional set to check this)
        let mut updated = false;
        for peer in peers {
            // Check if address is well formatted
            let address = peer.info.socket;

            // Check if IP is allowed
            let ip = address.ip();
            if !ip::is_global(ip) && !self.allow_private_ips {
                return Err(Error::PrivateIPsNotAllowed(ip));
            }

            // Check if peer is us
            if peer.public_key == self.crypto.public_key() {
                return Err(Error::ReceivedSelf);
            }

            // If any signature is invalid, disconnect from the peer
            if !C::verify(
                Some(&self.ip_namespace),
                &peer.info.encode(),
                &peer.public_key,
                &peer.signature,
            ) {
                return Err(Error::InvalidSignature);
            }

            // If any timestamp is too far into the future, disconnect from the peer
            if Duration::from_millis(peer.info.timestamp)
                > self.context.current().epoch() + self.synchrony_bound
            {
                return Err(Error::InvalidSignature);
            }

            // Attempt to update peer record
            let public_key = peer.public_key.clone();
            if self.handle_peer(&public_key, peer) {
                debug!(peer = ?public_key, "updated peer record");
                updated = true;
            }
        }

        // Update messages for bit vectors
        if updated {
            for set in self.sets.values_mut() {
                set.update_msg();
            }
        }
        Ok(())
    }

    fn handle_bit_vec(
        &mut self,
        bit_vec: types::BitVec,
    ) -> Result<Option<Vec<types::SignedPeerInfo<C>>>, Error> {
        // Ensure we have the peerset requested
        let set = match self.sets.get(&bit_vec.index) {
            Some(set) => set,
            None => {
                debug!(index = bit_vec.index, "requested peer set not found");
                return Ok(None);
            }
        };

        // Parse bit vector bytes
        let bits: BitVec<u8, Lsb0> = BitVec::from_vec(bit_vec.bits);

        // Ensure bit vector is the correct length
        let required_bytes = (set.order.len() / 8 + 1) * 8;
        if bits.len() != required_bytes {
            return Err(Error::BitVecLengthMismatch(required_bytes, bits.len()));
        }

        // Compile peers to send
        let mut peers = Vec::new();
        for (order, bit) in bits.iter().enumerate() {
            // Check if we have exhausted our known peers
            let peer = match set.sorted.get(order) {
                Some(peer) => peer,
                None => {
                    if *bit {
                        return Err(Error::BitVecExtraBit);
                    }

                    // It is ok if the bit vector is smaller than the peer set but
                    // there should never be bits in these positions.
                    continue;
                }
            };

            // Check if the peer already knows of this peer
            if *bit {
                continue;
            }

            // Add the peer to the list if its address is known
            if *peer == self.crypto.public_key() {
                peers.push(self.ip_signature.clone());
                continue;
            }
            let signed_peer_info = match self.peers.get(peer) {
                Some(AddressCount {
                    address: Address::Discovered(signed_peer_info),
                    ..
                }) => signed_peer_info,
                _ => continue,
            };
            peers.push(signed_peer_info.clone());
        }

        // Return None if no peers to send
        if peers.is_empty() {
            return Ok(None);
        }

        // If we have collected more peers than we can send, randomly
        // select a subset to send (this increases the likelihood that
        // the recipient will hear about different peers from different sources)
        if peers.len() > self.peer_gossip_max_count {
            peers.shuffle(&mut self.context);
            peers.truncate(self.peer_gossip_max_count);
        }
        Ok(Some(peers))
    }

    fn reserve(&mut self, peer: C::PublicKey) -> Option<Reservation<E, C>> {
        // Check if we are already reserved
        if self.connections.contains(&peer) {
            return None;
        }

        // Determine if we've tried to connect to this peer too many times
        //
        // This could happen if we open a connection and then it is immediately closed by
        // the peer. We don't want to keep trying to connect to the peer in this case.
        if self.connections_rate_limiter.check_key(&peer).is_err() {
            self.rate_limited_connections
                .get_or_create(&metrics::Peer::new(&peer))
                .inc();
            return None;
        }

        // Reserve the connection
        self.connections.insert(peer.clone());
        self.reserved_connections.inc();
        Some(Reservation::new(
            self.context.clone(),
            peer,
            Mailbox::new(self.sender.clone()),
        ))
    }

    pub fn start(mut self) -> Handle<()> {
        self.context.spawn_ref()(self.run())
    }

    async fn run(mut self) {
        while let Some(msg) = self.receiver.next().await {
            match msg {
                Message::Construct {
                    public_key,
                    mut peer,
                } => {
                    // Kill if peer is not authorized
                    if !self.peers.contains_key(&public_key) {
                        peer.kill().await;
                        continue;
                    }

                    // Select a random peer set (we want to learn about all peers in
                    // our tracked sets)
                    let set = match self.sets.values().choose(&mut self.context) {
                        Some(set) => set,
                        None => {
                            debug!("no peer sets available");
                            continue;
                        }
                    };

                    // Send bit vector if stored
                    let _ = peer.bit_vec(set.msg()).await;
                }
                Message::BitVec { bit_vec, mut peer } => {
                    let result = self.handle_bit_vec(bit_vec);
                    if let Err(e) = result {
                        debug!(error = ?e, "failed to handle bit vector");
                        peer.kill().await;
                        continue;
                    }
                    if let Some(peers) = result.unwrap() {
                        peer.peers(peers).await;
                    }
                }
                Message::Peers { peers, mut peer } => {
                    // Consider new peer signatures
                    let result = self.handle_peers(peers);
                    if let Err(e) = result {
                        debug!(error = ?e, "failed to handle peers");
                        peer.kill().await;
                        continue;
                    }

                    // We will never add/remove tracked peers here, so we
                    // don't need to update the gauge.
                }
                Message::Dialable { peers } => {
                    // Fetch dialable peers
                    let mut dialable = self.handle_dialable();

                    // Shuffle to prevent starvation
                    dialable.shuffle(&mut self.context);

                    // Inform dialer of dialable peers
                    let _ = peers.send(dialable);

                    // Shrink to fit rate limiter
                    self.connections_rate_limiter.shrink_to_fit();
                }
                Message::Register { index, peers } => {
                    self.store_peer_set(index, peers);
                    self.tracked_peers.set(self.peers.len() as i64);
                }
                Message::Reserve { peer, reservation } => {
                    // Get latest peer set
                    if self.allowed(&peer) {
                        // Because dropping the reservation will release the connection,
                        // we don't need to worry about the case that this fails.
                        let _ = reservation.send(self.reserve(peer));
                    } else {
                        debug!(?peer, "peer not authorized to connect");
                        let _ = reservation.send(None);
                    }
                }
                Message::Release { peer } => {
                    self.connections.remove(&peer);
                    self.reserved_connections.dec();
                }
            }
        }
        debug!("tracker shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::{actors::peer, config::Bootstrapper};
    use commonware_cryptography::Ed25519;
    use commonware_runtime::{deterministic::Executor, Clock, Runner};
    use governor::Quota;
    use std::net::{IpAddr, Ipv4Addr};
    use std::num::NonZeroU32;
    use std::time::Duration;

    fn test_config<C: Scheme>(
        crypto: C,
        bootstrappers: Vec<Bootstrapper<C::PublicKey>>,
    ) -> Config<C> {
        Config {
            crypto,
            namespace: b"test_namespace".to_vec(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            bootstrappers,
            allow_private_ips: true,
            mailbox_size: 32,
            synchrony_bound: Duration::from_secs(10),
            tracked_peer_sets: 2,
            allowed_connection_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
            peer_gossip_max_count: 32,
        }
    }

    #[test]
    fn test_reserve_peer() {
        // Create actor
        let (executor, context, _) = Executor::default();
        let cfg = test_config(Ed25519::from_seed(0), Vec::new());
        executor.start(async move {
            // Run actor in background
            let actor_context = context.with_label("actor");
            let (actor, mut mailbox, mut oracle) = Actor::new(actor_context.clone(), cfg);
            actor_context.spawn(|_| actor.run());

            // Create peer
            let peer = Ed25519::from_seed(1).public_key();

            // Attempt to reserve peer before allowed
            let reservation = mailbox.reserve(peer.clone()).await;
            assert!(reservation.is_none());

            // Register and reserve peer
            oracle.register(0, vec![peer.clone()]).await;
            let reservation = mailbox.reserve(peer.clone()).await;
            assert!(reservation.is_some());

            // Attempt to re-register peer that is already reserved
            let failed_reservation = mailbox.reserve(peer.clone()).await;
            assert!(failed_reservation.is_none());

            // Release peer
            {
                let _ = reservation.unwrap();
            }

            // Eventually reserve peer again (async release)
            loop {
                let reservation = mailbox.reserve(peer.clone()).await;
                if reservation.is_some() {
                    break;
                }
                context.sleep(Duration::from_millis(10)).await;
            }
        });
    }

    #[test]
    fn test_bit_vec() {
        // Create actor
        let (executor, context, _) = Executor::default();
        let peer0 = Ed25519::from_seed(0);
        let cfg = test_config(peer0.clone(), Vec::new());
        executor.start(async move {
            // Run actor in background
            let actor_context = context.with_label("actor");
            let (actor, mut mailbox, mut oracle) = Actor::new(actor_context.clone(), cfg);
            let ip_namespace = actor.ip_namespace.clone();
            actor_context.spawn(|_| actor.run());

            // Create peers
            let mut peer1_signer = Ed25519::from_seed(1);
            let peer1 = peer1_signer.public_key();
            let peer2 = Ed25519::from_seed(2).public_key();
            let peer3 = Ed25519::from_seed(3).public_key();

            // Request bit vector with unallowed peer
            let (peer_mailbox, mut peer_receiver) = peer::Mailbox::test();
            mailbox.construct(peer1.clone(), peer_mailbox.clone()).await;
            let msg = peer_receiver.next().await.unwrap();
            assert!(matches!(msg, peer::Message::Kill));

            // Find sorted indices
            let mut peers = vec![
                peer0.public_key(),
                peer1.clone(),
                peer2.clone(),
                peer3.clone(),
            ];
            peers.sort();
            let me_idx = peers
                .iter()
                .position(|peer| peer == &peer0.public_key())
                .unwrap();
            let peer1_idx = peers.iter().position(|peer| peer == &peer1).unwrap();

            // Register some peers
            oracle.register(0, peers).await;

            // Request bit vector
            mailbox.construct(peer1.clone(), peer_mailbox.clone()).await;
            let msg = peer_receiver.next().await.unwrap();
            let bit_vec = match msg {
                peer::Message::BitVec { bit_vec } => bit_vec,
                _ => panic!("unexpected message"),
            };
            assert!(bit_vec.index == 0);
            let bits: BitVec<u8, Lsb0> = BitVec::from_vec(bit_vec.bits);
            for (idx, bit) in bits.iter().enumerate() {
                if idx == me_idx {
                    assert!(*bit);
                } else {
                    assert!(!*bit);
                }
            }

            // Provide peer address
            let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
            let peer_info = types::PeerInfo {
                socket,
                timestamp: 0,
            };
            let signature = peer1_signer.sign(Some(&ip_namespace), &peer_info.encode());
            let peers = vec![types::SignedPeerInfo {
                info: peer_info,
                public_key: peer1.clone(),
                signature,
            }];
            mailbox.peers(peers, peer_mailbox.clone()).await;

            // Request bit vector again
            mailbox.construct(peer1.clone(), peer_mailbox.clone()).await;
            let msg = peer_receiver.next().await.unwrap();
            let bit_vec = match msg {
                peer::Message::BitVec { bit_vec } => bit_vec,
                _ => panic!("unexpected message"),
            };
            assert!(bit_vec.index == 0);
            let bits: BitVec<u8, Lsb0> = BitVec::from_vec(bit_vec.bits);
            for (idx, bit) in bits.iter().enumerate() {
                if idx == me_idx || idx == peer1_idx {
                    assert!(*bit);
                } else {
                    assert!(!*bit);
                }
            }

            // Register new peers
            oracle.register(1, vec![peer2.clone(), peer3]).await;

            // Request bit vector until both indexes returned
            let mut index_0_returned = false;
            let mut index_1_returned = false;
            while !index_0_returned || !index_1_returned {
                mailbox.construct(peer1.clone(), peer_mailbox.clone()).await; // peer1 still allowed
                let msg = peer_receiver.next().await.unwrap();
                let bit_vec = match msg {
                    peer::Message::BitVec { bit_vec } => bit_vec,
                    _ => panic!("unexpected message"),
                };
                let bits: BitVec<u8, Lsb0> = BitVec::from_vec(bit_vec.bits);
                match bit_vec.index {
                    0 => {
                        for (idx, bit) in bits.iter().enumerate() {
                            if idx == me_idx || idx == peer1_idx {
                                assert!(*bit);
                            } else {
                                assert!(!*bit);
                            }
                        }
                        index_0_returned = true
                    }
                    1 => {
                        for bit in bits.iter() {
                            assert!(!*bit);
                        }
                        index_1_returned = true
                    }
                    _ => panic!("unexpected index"),
                };
            }

            // Register some peers
            oracle.register(2, vec![peer2.clone()]).await;

            // Ensure peer1 has been evicted from the peer tracker and should die
            mailbox.construct(peer1, peer_mailbox.clone()).await;
            let msg = peer_receiver.next().await.unwrap();
            assert!(matches!(msg, peer::Message::Kill));

            // Wait for valid sets to be returned
            let mut index_1_returned = false;
            let mut index_2_returned = false;
            while !index_1_returned || !index_2_returned {
                mailbox.construct(peer2.clone(), peer_mailbox.clone()).await; // peer1 no longer allowed
                let msg = peer_receiver.next().await.unwrap();
                let bit_vec = match msg {
                    peer::Message::BitVec { bit_vec } => bit_vec,
                    _ => panic!("unexpected message"),
                };
                let bits: BitVec<u8, Lsb0> = BitVec::from_vec(bit_vec.bits);
                match bit_vec.index {
                    1 => {
                        for bit in bits.iter() {
                            assert!(!*bit);
                        }
                        index_1_returned = true
                    }
                    2 => {
                        for bit in bits.iter() {
                            assert!(!*bit);
                        }
                        index_2_returned = true
                    }
                    _ => panic!("unexpected index"),
                };
            }
        });
    }
}
