pub use super::{
    address::{socket_from_payload, socket_peer_payload, wire_peer_payload, Address, Signature},
    ingress::{Mailbox, Message, Oracle, Reservation},
    Config, Error,
};
use crate::{
    crypto::{Crypto, PublicKey},
    ip,
    metrics::{self, Peer},
    wire,
};
use bitvec::prelude::*;
use governor::DefaultKeyedRateLimiter;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use rand::{seq::SliceRandom, thread_rng};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
};
use tokio::sync::mpsc;
use tracing::{debug, trace};

const DST: &[u8] = b"_COMMONWARE_P2P_IP_";

struct PeerSet {
    index: u64,
    order: HashMap<PublicKey, usize>,
    knowldege: BitVec<u8, Lsb0>,
    msg: wire::BitVec,
}

impl PeerSet {
    fn new(index: u64, mut peers: Vec<PublicKey>) -> Self {
        // Insert peers in sorted order
        peers.sort();
        let mut order = HashMap::new();
        for (idx, peer) in peers.iter().enumerate() {
            order.insert(peer.clone(), idx);
        }

        // Create bit vector
        let knowldege = BitVec::repeat(false, peers.len());

        // Create message
        let msg = wire::BitVec {
            index,
            bits: knowldege.clone().into(),
        };

        Self {
            index,
            order,
            knowldege,
            msg,
        }
    }

    fn found(&mut self, peer: PublicKey) -> bool {
        if let Some(idx) = self.order.get(&peer) {
            self.knowldege.set(*idx, true);
            return true;
        }
        false
    }

    fn update_msg(&mut self) {
        self.msg = wire::BitVec {
            index: self.index,
            bits: self.knowldege.clone().into(),
        };
    }

    fn msg(&self) -> wire::BitVec {
        self.msg.clone()
    }
}

struct AddressCount {
    address: Option<Address>,
    count: usize,
}

impl AddressCount {
    fn new() -> Self {
        Self {
            address: None,
            count: 1,
        }
    }
    fn new_config(address: SocketAddr) -> Self {
        Self {
            address: Some(Address::Config(address)),
            // Ensures that we never remove a bootstrapper (even
            // if not in any active set)
            count: usize::MAX,
        }
    }
    fn new_network(address: Signature) -> Self {
        Self {
            address: Some(Address::Network(address)),
            count: 1,
        }
    }
    fn update(&mut self, address: Signature) -> bool {
        if let Some(Address::Network(past)) = &self.address {
            if past.peer.timestamp >= address.peer.timestamp {
                return false;
            }
        }
        self.address = Some(Address::Network(address));
        true
    }
    fn has_network(&self) -> bool {
        matches!(self.address, Some(Address::Network(_)))
    }
    fn increment(&mut self) {
        if self.count == usize::MAX {
            return;
        }
        self.count += 1;
    }
    fn decrement(&mut self) -> bool {
        if self.count == usize::MAX {
            return false;
        }
        self.count -= 1;
        self.count == 0
    }
}

pub struct Actor<C: Crypto> {
    crypto: C,
    allow_private_ips: bool,
    tracked_peer_sets: usize,
    peer_gossip_max_count: usize,

    sender: mpsc::Sender<Message>,
    receiver: mpsc::Receiver<Message>,
    peers: HashMap<PublicKey, AddressCount>,
    sets: BTreeMap<u64, PeerSet>,
    connections_rate_limiter: DefaultKeyedRateLimiter<PublicKey>,
    connections: HashSet<PublicKey>,

    tracked_peers: Gauge,
    reserved_connections: Gauge,
    rate_limited_connections: Family<metrics::Peer, Counter>,

    ip_signature: wire::Peer,
}

impl<C: Crypto> Actor<C> {
    pub fn new(mut cfg: Config<C>) -> (Self, Mailbox, Oracle) {
        // Construct IP signature
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to get current time")
            .as_secs();
        let (socket_bytes, payload_bytes) = socket_peer_payload(&cfg.address, current_time);
        let ip_signature = cfg.crypto.sign(DST, &payload_bytes);
        let ip_signature = wire::Peer {
            socket: socket_bytes,
            timestamp: current_time,
            signature: Some(wire::Signature {
                public_key: cfg.crypto.me(),
                signature: ip_signature,
            }),
        };

        // Register bootstrappers
        let mut peers = HashMap::new();
        for (peer, address) in cfg.bootstrappers.into_iter() {
            if peer == cfg.crypto.me() {
                continue;
            }
            peers.insert(peer, AddressCount::new_config(address));
        }

        // Configure peer set
        let mut tracked_peer_sets = cfg.tracked_peer_sets;
        if tracked_peer_sets == 0 {
            tracked_peer_sets = 1
        };
        let sets: BTreeMap<u64, PeerSet> = BTreeMap::new();

        // Construct channels
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);

        // Create connections
        let connections_rate_limiter =
            DefaultKeyedRateLimiter::keyed(cfg.allowed_connection_rate_per_peer);

        // Create metrics
        let tracked_peers = Gauge::default();
        let reserved_connections = Gauge::default();
        let rate_limited_connections = Family::<metrics::Peer, Counter>::default();
        {
            let mut registry = cfg.registry.lock().unwrap();
            registry.register("tracked_peers", "tracked peers", tracked_peers.clone());
            registry.register(
                "connections",
                "number of connections",
                reserved_connections.clone(),
            );
            registry.register(
                "rate_limited_connections",
                "number of rate limited connections",
                rate_limited_connections.clone(),
            );
        }

        (
            Self {
                crypto: cfg.crypto,
                allow_private_ips: cfg.allow_private_ips,
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
            },
            Mailbox::new(sender.clone()),
            Oracle::new(sender),
        )
    }

    /// Returns whether a peer is not us and in one of the known peer sets.
    fn allowed(&self, peer: &PublicKey) -> bool {
        if *peer == self.crypto.me() {
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
    fn store_peer_set(&mut self, index: u64, peers: Vec<PublicKey>) {
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
                if address.has_network() {
                    set.found(peer.clone());
                }
            } else {
                self.peers.insert(peer.clone(), AddressCount::new());
            }
        }
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

    fn handle_dialable(&mut self) -> Vec<(PublicKey, SocketAddr, Reservation)> {
        // Collect unreserved peers
        let unreserved_peers: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(peer, address)| {
                if !self.connections.contains(peer) {
                    Some((peer.clone(), address.clone()))
                } else {
                    None
                }
            })
            .collect();

        // Iterate over available peers
        let mut reserved = Vec::new();
        for (peer, address) in unreserved_peers {
            // Reserve the connection
            let reservation = match self.reserve(peer.clone()) {
                Some(reservation) => reservation,
                None => continue, // can happen if rate limited
            };

            // Grab address
            let address = match &address.address {
                Some(Address::Network(signature)) => signature.addr,
                Some(Address::Config(address)) => *address,
                None => continue,
            };
            reserved.push((peer.clone(), address, reservation));
        }
        reserved
    }

    fn handle_peer(&mut self, peer: PublicKey, address: Signature) -> bool {
        // Check if peer is authorized
        if !self.allowed(&peer) {
            return false;
        }

        // Update peer address
        let record = self.peers.get_mut(&peer).unwrap();
        if !record.update(address) {
            return false;
        }

        // Update peer set knowledge
        for set in self.sets.values_mut() {
            if set.found(peer.clone()) {
                set.update_msg();
            }
        }
        true
    }

    fn handle_peers(&mut self, peers: wire::Peers) -> Result<(), Error> {
        // Ensure there aren't too many peers sent
        let peers_len = peers.peers.len();
        if peers_len > self.peer_gossip_max_count {
            return Err(Error::TooManyPeers(peers_len));
        }

        // We allow peers to be sent in any order when responding to a bit vector (allows
        // for selecting a random subset of peers when there are too many) and allow
        // for duplicates (no need to create an additional set to check this)
        let mut updated = false;
        for peer in peers.peers {
            // Check if address is well formatted
            let address = socket_from_payload(&peer)?;

            // Check if IP is allowed
            let ip = address.ip();
            if !ip::is_global(ip) && !self.allow_private_ips {
                return Err(Error::PrivateIPsNotAllowed(ip));
            }

            // Check if peer is signed
            let signature = peer.signature.as_ref().ok_or(Error::PeerUnsigned)?;

            // Check if public key is well-formatted and if peer is us
            let public_key = &signature.public_key;
            if !C::validate(public_key) {
                return Err(Error::InvalidPublicKey);
            }
            if public_key == &self.crypto.me() {
                return Err(Error::ReceivedSelf);
            }

            // If any signature is invalid, disconnect from the peer
            let payload = wire_peer_payload(&peer);
            if !C::verify(DST, &payload, public_key, &signature.signature) {
                return Err(Error::InvalidSignature);
            }

            // Attempt to update peer record
            if self.handle_peer(
                peer,
                Address::Network(Signature {
                    addr: address,
                    peer: peer.clone(),
                }),
            ) {
                debug!(peer = hex::encode(public_key), "updated peer record");
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

    fn handle_bit_vec(&self, bit_vec: wire::BitVec) -> Result<Option<wire::Peers>, Error> {
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
        let required_bytes = (set.len() / 8 + 1) * 8;
        if bits.len() != required_bytes {
            return Err(Error::BitVecLengthMismatch(required_bytes, bits.len()));
        }

        // Compile peers to send
        let mut peers = Vec::new();
        let mut set_iter = set.iter();
        for bit in bits.iter() {
            // Check if we have exhausted our known peers
            let peer = match set_iter.next() {
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

            // Add the peer to the list if its address is unknown
            if *peer == self.crypto.me() {
                peers.push(self.ip_signature.clone());
                continue;
            }
            if let Some(Address::Network(signature)) = self.peers.get(peer) {
                peers.push(signature.peer.clone());
            }
        }

        // Return None if no peers to send
        if peers.is_empty() {
            return Ok(None);
        }

        // If we have collected more peers than we can send, randomly
        // select a subset to send (this increases the likelihood that
        // the recipient will hear about different peers from different sources)
        if peers.len() > self.peer_gossip_max_count {
            peers.shuffle(&mut thread_rng());
            peers.truncate(self.peer_gossip_max_count);
        }
        Ok(Some(wire::Peers { peers }))
    }

    fn reserve(&mut self, peer: PublicKey) -> Option<Reservation> {
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
        }

        // Reserve the connection
        self.connections.insert(peer.clone());
        self.reserved_connections.inc();
        Some(Reservation::new(peer, Mailbox::new(self.sender.clone())))
    }

    pub async fn run(mut self) {
        // TODO: make connection set updates a higher priority than
        // messaages we receive over the wire (add separate mpsc)
        while let Some(msg) = self.receiver.recv().await {
            match msg {
                Message::Construct { public_key, peer } => {
                    // Get latest peer set
                    let latest = match self.sets.last_key_value() {
                        Some((_, set)) => set,
                        None => {
                            debug!("no peer sets available");
                            peer.kill().await;
                            continue;
                        }
                    };

                    // Kill if peer is not authorized
                    if !latest.contains(&public_key) {
                        peer.kill().await;
                        continue;
                    }

                    // Send bit vector if stored
                    if let Some(bit_vec) = self.bit_vec.clone() {
                        let _ = peer.bit_vec(bit_vec).await;
                    }
                }
                Message::BitVec { bit_vec, peer } => {
                    let result = self.handle_bit_vec(bit_vec).await;
                    if let Err(e) = result {
                        debug!(error = ?e, "failed to handle bit vector");
                        peer.kill().await;
                        continue;
                    }
                    if let Some(peers) = result.unwrap() {
                        peer.peers(peers).await;
                    }
                }
                Message::Peers { peers, peer } => {
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
                    let _ = peers.send(self.handle_dialable());

                    // Shirnk to fit rate limiter
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
                        debug!(peer = hex::encode(&peer), "peer not authorized to connect");
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
    use crate::actors::peer;
    use crate::{config::Bootstrapper, crypto::ed25519};
    use governor::Quota;
    use std::net::{IpAddr, Ipv4Addr};
    use std::num::NonZeroU32;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::time;

    fn test_config<C: Crypto>(crypto: C, bootstrappers: Vec<Bootstrapper>) -> Config<C> {
        Config {
            crypto,
            registry: Arc::new(Mutex::new(prometheus_client::registry::Registry::default())),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            bootstrappers,
            allow_private_ips: true,
            mailbox_size: 32,
            tracked_peer_sets: 32,
            allowed_connection_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
            peer_gossip_max_count: 32,
        }
    }

    #[tokio::test]
    async fn test_reserve_peer() {
        // Create actor
        let cfg = test_config(ed25519::insecure_signer(0), Vec::new());
        let (actor, mailbox, oracle) = Actor::new(cfg);

        // Run actor in background
        tokio::spawn(async move {
            actor.run().await;
        });

        // Create peer
        let peer = ed25519::insecure_signer(1).me();

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
            time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn test_bit_vec() {
        // Create actor
        let cfg = test_config(ed25519::insecure_signer(0), Vec::new());
        let (actor, mailbox, oracle) = Actor::new(cfg);

        // Run actor in background
        tokio::spawn(async move {
            actor.run().await;
        });

        // Create peers
        let mut peer1_signer = ed25519::insecure_signer(1);
        let peer1 = peer1_signer.me();
        let peer2 = ed25519::insecure_signer(2).me();
        let peer3 = ed25519::insecure_signer(3).me();

        // Request bit vector with unallowed peer
        let (peer_mailbox, mut peer_receiver) = peer::Mailbox::test();
        mailbox.construct(peer1.clone(), peer_mailbox.clone()).await;
        let msg = peer_receiver.recv().await.unwrap();
        assert!(matches!(msg, peer::Message::Kill));

        // Register some peers
        oracle
            .register(0, vec![peer1.clone(), peer2.clone(), peer3.clone()])
            .await;

        // Request bit vector
        mailbox.construct(peer1.clone(), peer_mailbox.clone()).await;
        let msg = peer_receiver.recv().await.unwrap();
        let bit_vec = match msg {
            peer::Message::BitVec { bit_vec } => bit_vec,
            _ => panic!("unexpected message"),
        };
        assert!(bit_vec.index == 0);
        let bits: BitVec<u8, Lsb0> = BitVec::from_vec(bit_vec.bits);
        for bit in bits.iter() {
            assert!(!*bit);
        }

        // Provide peer address
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (socket_bytes, payload_bytes) = socket_peer_payload(&socket, 0);
        let ip_signature = peer1_signer.sign(DST, &payload_bytes);
        let peers = wire::Peers {
            peers: vec![wire::Peer {
                socket: socket_bytes,
                timestamp: 0,
                signature: Some(wire::Signature {
                    public_key: peer1.clone(),
                    signature: ip_signature,
                }),
            }],
        };
        mailbox.peers(peers, peer_mailbox.clone()).await;

        // Request bit vector again
        mailbox.construct(peer1, peer_mailbox.clone()).await;
        let msg = peer_receiver.recv().await.unwrap();
        let bit_vec = match msg {
            peer::Message::BitVec { bit_vec } => bit_vec,
            _ => panic!("unexpected message"),
        };
        assert!(bit_vec.index == 0);
        let bits: BitVec<u8, Lsb0> = BitVec::from_vec(bit_vec.bits);
        for (idx, bit) in bits.iter().enumerate() {
            if idx == 1 {
                // peer1 is the second peer in the bit vector (sorted by public key)
                assert!(*bit);
            } else {
                assert!(!*bit);
            }
        }

        // Register new peers
        oracle.register(1, vec![peer2.clone(), peer3.clone()]).await;

        // Request bit vector again
        mailbox.construct(peer2, peer_mailbox.clone()).await; // peer1 no longer allowed
        let msg = peer_receiver.recv().await.unwrap();
        let bit_vec = match msg {
            peer::Message::BitVec { bit_vec } => bit_vec,
            _ => panic!("unexpected message"),
        };
        assert!(bit_vec.index == 1);
        let bits: BitVec<u8, Lsb0> = BitVec::from_vec(bit_vec.bits);
        for bit in bits.iter() {
            assert!(!*bit);
        }
    }
}
