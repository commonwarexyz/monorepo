use super::{
    ingress::{Mailbox, Message, Oracle, Reservation},
    metrics::Metrics,
    record::Record,
    set::Set,
    Config, Error,
};
use crate::authenticated::{ip, metrics, types};
use commonware_cryptography::Scheme;
use commonware_runtime::{Clock, Handle, Metrics as RuntimeMetrics, Spawner};
use commonware_utils::{union, SystemTimeExt};
use futures::{channel::mpsc, StreamExt};
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore,
    RateLimiter,
};
use rand::{
    prelude::{IteratorRandom, SliceRandom},
    Rng,
};
use std::{cmp::max, time::Duration};
use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
};
use tracing::debug;

// Bytes to add to the namespace to prevent replay attacks.
const NAMESPACE_SUFFIX_IP: &[u8] = b"_IP";

/// The tracker actor that manages peer discovery and connection reservations.
pub struct Actor<E: Spawner + Rng + GClock + RuntimeMetrics, C: Scheme> {
    context: E,

    // ---------- Configuration ----------
    crypto: C,
    ip_namespace: Vec<u8>,
    allow_private_ips: bool,
    synchrony_bound: Duration,
    tracked_peer_sets: usize,
    max_peer_set_size: usize,
    peer_gossip_max_count: usize,

    // ---------- Message-Passing ----------
    sender: mpsc::Sender<Message<E, C>>,
    receiver: mpsc::Receiver<Message<E, C>>,

    // ---------- State ----------
    /// Tracks peer sets based on the index of the set.
    sets: BTreeMap<u64, Set<C::PublicKey>>,

    /// Tracks peer information, including:
    /// - How many peer sets they are part of
    /// - Their known [`SocketAddr`]
    /// - Whether they are blocked
    ///
    /// This map does not track whether we are connected to the peer or not.
    peers: BTreeMap<C::PublicKey, Record<C>>,

    /// Tracks currently reserved connections.
    ///
    /// Inserts upon the peer sending a `Reserve` message.
    /// Removes upon the peer sending a `Release` message.
    reserved: HashSet<C::PublicKey>,

    /// The rate-limiter used to limit the connection-attempt rate per peer.
    #[allow(clippy::type_complexity)]
    connections_rate_limiter:
        RateLimiter<C::PublicKey, HashMapStateStore<C::PublicKey>, E, NoOpMiddleware<E::Instant>>,

    /// Metrics for this actor.
    metrics: Metrics,
}

impl<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: Scheme> Actor<E, C> {
    /// Create a new tracker [`Actor`] from the given `context` and `cfg`.
    #[allow(clippy::type_complexity)]
    pub fn new(context: E, mut cfg: Config<C>) -> (Self, Mailbox<E, C>, Oracle<E, C>) {
        // Initialization
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        let connections_rate_limiter =
            RateLimiter::hashmap_with_clock(cfg.allowed_connection_rate_per_peer, &context);
        let metrics = Metrics::init(context.clone());

        // Register bootstrappers
        let mut peers = BTreeMap::new();
        for (peer, address) in cfg.bootstrappers.into_iter() {
            peers.insert(peer, Record::bootstrapper(address));
        }

        // Register self; overwrites the entry if I am listed as a bootstrapper
        let socket = cfg.address;
        let timestamp = context.current().epoch_millis();
        let ip_namespace = union(&cfg.namespace, NAMESPACE_SUFFIX_IP);
        let local_info = types::PeerInfo::sign(&mut cfg.crypto, &ip_namespace, socket, timestamp);
        peers.insert(cfg.crypto.public_key(), Record::myself(local_info));

        (
            Self {
                context,

                // Configuration
                crypto: cfg.crypto,
                ip_namespace,
                allow_private_ips: cfg.allow_private_ips,
                synchrony_bound: cfg.synchrony_bound,
                tracked_peer_sets: max(1, cfg.tracked_peer_sets),
                max_peer_set_size: cfg.max_peer_set_size,
                peer_gossip_max_count: cfg.peer_gossip_max_count,

                // Message-Passing
                sender: sender.clone(),
                receiver,

                // State
                peers,
                sets: BTreeMap::new(),
                connections_rate_limiter,
                reserved: HashSet::new(),
                metrics,
            },
            Mailbox::new(sender.clone()),
            Oracle::new(sender),
        )
    }

    /// Returns whether a peer is all of the following:
    /// - In a peer set
    /// - Not blocked
    /// - Not us
    fn allowed(&self, peer: &C::PublicKey) -> bool {
        let invalid =
            *peer == self.crypto.public_key() || self.peers.get(peer).is_none_or(|r| r.blocked());
        !invalid
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

        // Ensure that peer set is not too large.
        // Panic since there is no way to recover from this.
        assert!(
            peers.len() <= self.max_peer_set_size,
            "peer set is too large: {} > {}",
            peers.len(),
            self.max_peer_set_size
        );

        // Create and store new peer set
        let set = Set::new(index, peers.clone());
        self.sets.insert(index, set);

        // Update stored counters
        let set = self.sets.get_mut(&index).unwrap();
        for peer in peers.iter() {
            let record = self.peers.entry(peer.clone()).or_insert(Record::unknown());
            record.increment();
            if record.discovered() {
                set.found(peer);
            }
        }

        // Remove oldest entries if necessary
        while self.sets.len() > self.tracked_peer_sets {
            let (index, set) = self.sets.pop_first().unwrap();
            debug!(index, "removed oldest peer set");

            // Iterate over peer set and decrement counts
            for peer in set.order.keys() {
                if let Some(record) = self.peers.get_mut(peer) {
                    if record.decrement() {
                        self.peers.remove(peer);
                    }
                }
            }
        }

        // Update metrics
        self.metrics.tracked.set(self.peers.len() as i64);
        let blocked = self.peers.values().filter(|r| r.blocked()).count();
        self.metrics.blocked.set(blocked as i64);
    }

    /// Returns a list of peers that we have a known address for and were able to successfully reserve.
    #[allow(clippy::type_complexity)]
    fn handle_dialable(&mut self) -> Vec<(C::PublicKey, SocketAddr, Reservation<E, C>)> {
        // Collect peers with known addresses
        let peers: Vec<(C::PublicKey, SocketAddr)> = self
            .peers
            .iter()
            .filter_map(|(peer, record)| record.address().map(|addr| (peer.clone(), addr)))
            .collect();

        // Return all peers that we got a reservation for
        peers
            .into_iter()
            .filter_map(|(peer, addr)| self.reserve(peer.clone()).map(|res| (peer, addr, res)))
            .collect()
    }

    /// Handle an incoming list of peer information.
    ///
    /// Returns an error if the list itself or any entries can be considered malformed.
    fn handle_peers(&mut self, infos: Vec<types::PeerInfo<C>>) -> Result<(), Error> {
        // Ensure there aren't too many peers sent
        if infos.len() > self.peer_gossip_max_count {
            return Err(Error::TooManyPeers(infos.len()));
        }

        // We allow peers to be sent in any order when responding to a bit vector (allows
        // for selecting a random subset of peers when there are too many) and allow
        // for duplicates (no need to create an additional set to check this)
        for info in infos {
            // Check if IP is allowed
            if !self.allow_private_ips && !ip::is_global(info.socket.ip()) {
                return Err(Error::PrivateIPsNotAllowed(info.socket.ip()));
            }

            // Check if peer is us
            if info.public_key == self.crypto.public_key() {
                return Err(Error::ReceivedSelf);
            }

            // If any timestamp is too far into the future, disconnect from the peer
            if Duration::from_millis(info.timestamp)
                > self.context.current().epoch() + self.synchrony_bound
            {
                return Err(Error::SynchronyBound);
            }

            // Ignore irrelevant peers
            if !self.allowed(&info.public_key) {
                continue;
            }

            // If any signature is invalid, disconnect from the peer
            if !info.verify(&self.ip_namespace) {
                return Err(Error::InvalidSignature);
            }

            // Update peer address
            //
            // It is not safe to rate limit how many times this can happen
            // over some interval because a malicious peer may just replay
            // old IPs to prevent us from propagating a new one.
            let record = self.peers.get_mut(&info.public_key).unwrap();
            let public_key = info.public_key.clone();
            if !record.discover(info) {
                continue;
            }
            self.metrics
                .updates
                .get_or_create(&metrics::Peer::new(&public_key))
                .inc();

            // Update peer set knowledge
            for set in self.sets.values_mut() {
                set.found(&public_key);
            }
            debug!(peer = ?public_key, "updated peer record");
        }

        Ok(())
    }

    /// Handle an incoming bit vector from a peer.
    fn handle_bit_vec(&mut self, bit_vec: types::BitVec) -> Result<Vec<types::PeerInfo<C>>, Error> {
        // Ensure we have the peerset requested
        let Some(set) = self.sets.get(&bit_vec.index) else {
            // Don't consider unknown indices as errors, just ignore them.
            debug!(index = bit_vec.index, "requested peer set not found");
            return Ok(vec![]);
        };

        // Ensure that the bit vector is the same size as the peer set
        if bit_vec.bits.len() != set.sorted.len() {
            return Err(Error::BitVecLengthMismatch(
                set.sorted.len(),
                bit_vec.bits.len(),
            ));
        }

        // Compile peers to send
        let mut peers: Vec<_> = bit_vec
            .bits
            .iter()
            .enumerate()
            .filter(|(_, bit)| !bit) // Only consider peers that the requester has not discovered
            .filter_map(|(i, _)| {
                let peer = set.sorted.get(i).expect("invalid index"); // len checked above
                self.peers.get(peer).and_then(|r| r.peer_info().cloned())
            })
            .collect();

        // If we have collected more peers than we can send, randomly
        // select a subset to send (this increases the likelihood that
        // the recipient will hear about different peers from different sources)
        if peers.len() > self.peer_gossip_max_count {
            peers.shuffle(&mut self.context);
            peers.truncate(self.peer_gossip_max_count);
        }
        Ok(peers)
    }

    /// Attempt to reserve a connection to a peer, returning a [`Reservation`] if successful.
    ///
    /// Will return `None` in any of the following cases:
    /// - The peer is already reserved.
    /// - The peer is not [`Self::allowed`].
    /// - The peer has been rate-limited for connection attempts.
    fn reserve(&mut self, peer: C::PublicKey) -> Option<Reservation<E, C>> {
        // Check if we are already reserved
        if self.reserved.contains(&peer) {
            return None;
        }

        // Check if peer is invalid or blocked
        if !self.allowed(&peer) {
            return None;
        }

        // Determine if we've tried to connect to this peer too many times
        //
        // This could happen if we open a connection and then it is immediately closed by
        // the peer. We don't want to keep trying to connect to the peer in this case.
        if self.connections_rate_limiter.check_key(&peer).is_err() {
            self.metrics
                .limits
                .get_or_create(&metrics::Peer::new(&peer))
                .inc();
            return None;
        }

        // Reserve the connection
        self.reserved.insert(peer.clone());
        self.metrics.reserved.set(self.reserved.len() as i64);
        Some(Reservation::new(
            self.context.with_label("reservation"),
            peer,
            Mailbox::new(self.sender.clone()),
        ))
    }

    /// Start the actor and run it in the background.
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
                    if !self.allowed(&public_key) {
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
                    let bitvec = types::BitVec {
                        index: set.index,
                        bits: set.knowledge.clone(),
                    };
                    let _ = peer.bit_vec(bitvec).await;
                }
                Message::BitVec { bit_vec, mut peer } => match self.handle_bit_vec(bit_vec) {
                    Err(e) => {
                        debug!(error = ?e, "failed to handle bit vector");
                        peer.kill().await;
                        continue;
                    }
                    Ok(peers) => {
                        if !peers.is_empty() {
                            peer.peers(peers).await;
                        }
                    }
                },
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
                }
                Message::Reserve {
                    public_key,
                    reservation,
                } => {
                    // Because dropping the reservation will release the connection,
                    // we don't need to worry about the case that this fails.
                    let _ = reservation.send(self.reserve(public_key));
                }
                Message::Release { public_key } => {
                    self.reserved.remove(&public_key);
                    self.metrics.reserved.set(self.reserved.len() as i64);
                }
                Message::Block { public_key } => {
                    // Block the peer
                    let updated = self.peers.get_mut(&public_key).is_some_and(|r| r.block());

                    // Update metrics
                    if updated {
                        let blocked = self.peers.values().filter(|r| r.blocked()).count();
                        self.metrics.blocked.set(blocked as i64);
                    }

                    // We don't have to kill the peer now. It will be sent a `Kill` message the next
                    // time it sends the `Construct` message to the tracker.
                }
            }
        }
        debug!("tracker shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authenticated::{actors::peer, config::Bootstrapper, types},
        Blocker,
    };
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{
        ed25519::{self, PublicKey},
        Ed25519, Signer, Verifier,
    };
    use commonware_runtime::{deterministic, Clock, Runner};
    use commonware_utils::{BitVec as UtilsBitVec, NZU32};
    use governor::Quota;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use types::PeerInfo;

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
            allowed_connection_rate_per_peer: Quota::per_second(NZU32!(1)),
            peer_gossip_max_count: 5,
            max_peer_set_size: 1 << 16,
        }
    }

    fn create_signer_and_pk(seed: u64) -> (Ed25519, PublicKey) {
        let signer = Ed25519::from_seed(seed);
        let pk = signer.public_key();
        (signer, pk)
    }

    fn create_custom_peer_info(
        signer: &mut Ed25519,
        ip_namespace: &[u8],
        socket_addr: SocketAddr,
        timestamp: u64,
        target_pk_override: Option<PublicKey>, // The public key embedded in the PeerInfo, if different from signer's.
        is_signature_invalid: bool,
    ) -> PeerInfo<Ed25519> {
        let peer_info_pk = target_pk_override.unwrap_or_else(|| signer.public_key());
        let mut signature = signer.sign(Some(ip_namespace), &(socket_addr, timestamp).encode());

        if is_signature_invalid && !signature.as_ref().is_empty() {
            let mut sig_bytes = signature.encode();
            sig_bytes[0] = sig_bytes[0].wrapping_add(1);
            signature = ed25519::Signature::decode(sig_bytes).unwrap();
        }

        PeerInfo {
            socket: socket_addr,
            timestamp,
            public_key: peer_info_pk,
            signature,
        }
    }

    struct TestHarness<C: Verifier> {
        #[allow(dead_code)]
        actor_handle: Handle<()>,
        mailbox: Mailbox<deterministic::Context, Ed25519>,
        oracle: Oracle<deterministic::Context, Ed25519>,
        ip_namespace: Vec<u8>,
        tracker_pk: C::PublicKey,
        synchrony_bound: Duration,
    }

    fn setup_tracker_actor(
        runner_context: deterministic::Context,
        cfg: Config<Ed25519>,
    ) -> TestHarness<Ed25519> {
        let tracker_pk = cfg.crypto.public_key();
        let synchrony_bound = cfg.synchrony_bound;
        // cfg is moved into Actor::new
        let (actor, mailbox, oracle) = Actor::new(runner_context.clone(), cfg);
        let ip_namespace = actor.ip_namespace.clone(); // Clone before actor is moved
        let actor_handle = runner_context.spawn(|_| actor.run());

        TestHarness {
            actor_handle,
            mailbox,
            oracle,
            ip_namespace,
            tracker_pk,
            synchrony_bound,
        }
    }

    #[test]
    fn test_handle_peers_too_many_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut cfg = test_config(Ed25519::from_seed(0), Vec::new());
            let pgmc = 2;
            cfg.peer_gossip_max_count = pgmc;
            let TestHarness {
                mut mailbox,
                ip_namespace,
                ..
            } = setup_tracker_actor(context.clone(), cfg);

            let (mut s1_signer, _pk1) = create_signer_and_pk(1);
            let (_s2_signer, pk2) = create_signer_and_pk(2);
            let (_s3_signer, pk3) = create_signer_and_pk(3);
            let (_s4_signer, pk4) = create_signer_and_pk(4);

            let (peer_mailbox_s1, mut peer_receiver_s1) = peer::Mailbox::test();

            let infos = vec![
                create_custom_peer_info(
                    &mut s1_signer,
                    &ip_namespace,
                    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1002),
                    context.current().epoch_millis(),
                    Some(pk2),
                    false,
                ),
                create_custom_peer_info(
                    &mut s1_signer,
                    &ip_namespace,
                    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1003),
                    context.current().epoch_millis(),
                    Some(pk3),
                    false,
                ),
                create_custom_peer_info(
                    &mut s1_signer,
                    &ip_namespace,
                    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1004),
                    context.current().epoch_millis(),
                    Some(pk4),
                    false,
                ),
            ];
            assert!(
                infos.len() > pgmc,
                "Test setup error: infos.len() is not greater than peer_gossip_max_count"
            );

            mailbox.peers(infos, peer_mailbox_s1.clone()).await;

            match peer_receiver_s1.next().await {
                Some(peer::Message::Kill) => { /* Expected: peer sending too many infos is killed */
                }
                _ => panic!("Expected peer to be killed"),
            }
        });
    }

    #[test]
    fn test_handle_peers_private_ip_disallowed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut cfg = test_config(Ed25519::from_seed(0), Vec::new());
            cfg.allow_private_ips = false;
            let TestHarness { mut mailbox, ip_namespace, .. } = setup_tracker_actor(context.clone(), cfg);

            let (_, _pk1) = create_signer_and_pk(1);
            let (mut s2_signer, pk2) = create_signer_and_pk(2);

            let private_socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
            let peer_info_private_ip = create_custom_peer_info(&mut s2_signer, &ip_namespace, private_socket, context.current().epoch_millis(), Some(pk2), false);

            let (peer_mailbox_s1, mut peer_receiver_s1) = peer::Mailbox::test();
            mailbox.peers(vec![peer_info_private_ip], peer_mailbox_s1.clone()).await;

            match peer_receiver_s1.next().await {
                Some(peer::Message::Kill) => { /* Expected: peer sending disallowed private IP info is killed */ }
                _ => panic!("Expected peer to be killed due to private IP"),
            }
        });
    }

    #[test]
    fn test_handle_peers_synchrony_bound() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness { mut mailbox, ip_namespace, synchrony_bound, .. } = setup_tracker_actor(context.clone(), cfg);

            let (_, _pk1) = create_signer_and_pk(1);
            let (mut s2_signer, pk2) = create_signer_and_pk(2);

            let far_future_timestamp = context.current().epoch_millis() + synchrony_bound.as_millis() as u64 + 1000;
            let peer_info_future_ts = create_custom_peer_info(&mut s2_signer, &ip_namespace, SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1002), far_future_timestamp, Some(pk2), false);

            let (peer_mailbox_s1, mut peer_receiver_s1) = peer::Mailbox::test();
            mailbox.peers(vec![peer_info_future_ts], peer_mailbox_s1.clone()).await;

            match peer_receiver_s1.next().await {
                Some(peer::Message::Kill) => { /* Expected: peer sending info with timestamp too far in future is killed */ }
                _ => panic!("Expected peer to be killed due to synchrony bound"),
            }
        });
    }

    #[test]
    fn test_handle_peers_invalid_signature() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness { mut mailbox, mut oracle, ip_namespace, .. } = setup_tracker_actor(context.clone(), cfg);

            let (_, pk1) = create_signer_and_pk(1);
            let (mut s2_signer, pk2) = create_signer_and_pk(2);

            oracle.register(0, vec![pk1.clone(), pk2.clone()]).await;

            let peer_info_bad_sig = create_custom_peer_info(
                &mut s2_signer, &ip_namespace, SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1002), context.current().epoch_millis(), Some(pk2), true
            );

            let (peer_mailbox_s1, mut peer_receiver_s1) = peer::Mailbox::test();
            mailbox.peers(vec![peer_info_bad_sig], peer_mailbox_s1.clone()).await;

            match peer_receiver_s1.next().await {
                Some(peer::Message::Kill) => { /* Expected: peer sending info with invalid signature is killed */ }
                _ => panic!("Expected peer to be killed due to invalid signature"),
            }
        });
    }

    #[test]
    fn test_handle_bit_vec_length_mismatch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness { mut mailbox, mut oracle, tracker_pk, .. } = setup_tracker_actor(context.clone(), cfg);

            let (_s1_signer, pk1) = create_signer_and_pk(1);
            let (_s2_signer, pk2) = create_signer_and_pk(2);

            oracle.register(0, vec![tracker_pk.clone(), pk1.clone(), pk2.clone()]).await; // Set size is 3

            let (peer_mailbox_s1, mut peer_receiver_s1) = peer::Mailbox::test();
            let invalid_bit_vec = types::BitVec {
                index: 0,
                bits: UtilsBitVec::ones(2), // Expected length 3 2
            };

            mailbox.bit_vec(invalid_bit_vec, peer_mailbox_s1.clone()).await;

            match peer_receiver_s1.next().await {
                Some(peer::Message::Kill) => { /* Expected: peer sending bitvec with mismatched length is killed */ }
                _ => panic!("Expected peer to be killed due to bitvec length mismatch"),
            }
        });
    }

    #[test]
    fn test_handle_bit_vec_index_not_found() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness { mut mailbox, ..} = setup_tracker_actor(context.clone(), cfg);

            let (peer_mailbox_s1, mut peer_receiver_s1) = peer::Mailbox::test();
            let bit_vec_unknown_index = types::BitVec {
                index: 99,
                bits: UtilsBitVec::ones(1),
            };

            mailbox.bit_vec(bit_vec_unknown_index, peer_mailbox_s1.clone()).await;

            let result = futures::future::select(
                Box::pin(peer_receiver_s1.next()),
                Box::pin(context.sleep(Duration::from_millis(50)))
            ).await;

            match result {
                futures::future::Either::Left((Some(msg), _)) => {
                    if matches!(msg, peer::Message::Kill) {
                        panic!("Peer was killed for an unknown bitvec index; expected graceful ignore.");
                    }
                     // If it sends Peers(empty_vec) that's acceptable.
                    if let peer::Message::Peers(p) = msg {
                        assert!(p.is_empty(), "Expected empty peers list if any for unknown index");
                    }
                }
                futures::future::Either::Left((None, _)) => { panic!("Peer mailbox channel closed unexpectedly"); }
                futures::future::Either::Right((_, _)) => { /* Timeout: No message sent, which is acceptable behavior */ }
            }
        });
    }

    #[test]
    fn test_block_peer_standard_behavior() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                tracker_pk,
                ..
            } = setup_tracker_actor(context.clone(), cfg);

            let (_s1_signer, pk1) = create_signer_and_pk(1);
            oracle
                .register(0, vec![tracker_pk.clone(), pk1.clone()])
                .await;
            context.sleep(Duration::from_millis(10)).await; // Allow register to process

            oracle.block(pk1.clone()).await;
            context.sleep(Duration::from_millis(10)).await; // Allow block message to process

            let (peer_mailbox_pk1, mut peer_receiver_pk1) = peer::Mailbox::test();
            mailbox
                .construct(pk1.clone(), peer_mailbox_pk1.clone())
                .await;

            match peer_receiver_pk1.next().await {
                Some(peer::Message::Kill) => { /* Expected: blocked peer is killed on Construct */ }
                _ => panic!("Expected blocked peer to be killed on Construct",),
            }

            // Additionally, check dialable (though pk1 needs an address for this to be meaningful)
            // For simplicity, we focus on the `Construct` behavior which implies `allowed()` is false.
            let dialable_peers = mailbox.dialable().await;
            assert!(
                !dialable_peers.iter().any(|(p, _, _)| p == &pk1),
                "Blocked peer should not be dialable"
            );
        });
    }

    #[test]
    fn test_block_peer_already_blocked_is_noop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                tracker_pk,
                ..
            } = setup_tracker_actor(context.clone(), cfg);

            let (_s1_signer, pk1) = create_signer_and_pk(1);
            oracle
                .register(0, vec![tracker_pk.clone(), pk1.clone()])
                .await;
            context.sleep(Duration::from_millis(10)).await;

            oracle.block(pk1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;
            oracle.block(pk1.clone()).await; // Block again
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox_pk1, mut peer_receiver_pk1) = peer::Mailbox::test();
            mailbox
                .construct(pk1.clone(), peer_mailbox_pk1.clone())
                .await;
            assert!(
                matches!(peer_receiver_pk1.next().await, Some(peer::Message::Kill)),
                "Peer should remain killed after being blocked multiple times"
            );
        });
    }

    #[test]
    fn test_block_peer_non_existent_is_noop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness { mut oracle, .. } = setup_tracker_actor(context.clone(), cfg);

            let (_s1_signer, pk_non_existent) = create_signer_and_pk(100);

            oracle.block(pk_non_existent).await;
            context.sleep(Duration::from_millis(10)).await;
            // Test passes if no panic or error occurs.
        });
    }

    #[test]
    fn test_handle_peers_learns_unknown_peer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                ip_namespace,
                tracker_pk,
                ..
            } = setup_tracker_actor(context.clone(), cfg);

            let (_, pk1) = create_signer_and_pk(1);
            let (mut s2_signer, pk2) = create_signer_and_pk(2);

            // pk2 is initially unknown
            oracle
                .register(0, vec![tracker_pk.clone(), pk1.clone()])
                .await;
            context.sleep(Duration::from_millis(10)).await;

            let pk2_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 2002);
            let pk2_timestamp = context.current().epoch_millis();
            let pk2_info = create_custom_peer_info(
                &mut s2_signer,
                &ip_namespace,
                pk2_addr,
                pk2_timestamp,
                Some(pk2.clone()),
                false,
            );

            // Verify tracker learned pk2:
            // Register a new set that includes pk2.
            // Have pk1 send a BitVec for this new set, with pk2's bit as FALSE.
            // Tracker should respond with PeerInfo for pk2.
            let mut set1 = vec![tracker_pk.clone(), pk1.clone(), pk2.clone()];
            set1.sort();
            oracle.register(1, set1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox_s1, mut peer_receiver_s1) = peer::Mailbox::test();
            // s1 (reporter) sends info about pk2
            mailbox
                .peers(vec![pk2_info.clone()], peer_mailbox_s1.clone())
                .await;
            context.sleep(Duration::from_millis(10)).await;

            // Assume pk1 (sender of BitVec) knows itself and the tracker in this new set.
            // The bit for pk2 remains false in pk1's knowledge for set1.
            let mut bv = UtilsBitVec::zeroes(set1.len());
            let idx_tracker_in_set1 = set1.iter().position(|p| p == &tracker_pk).unwrap();
            let idx_pk1_in_set1 = set1.iter().position(|p| p == &pk1).unwrap();
            bv.set(idx_tracker_in_set1);
            bv.set(idx_pk1_in_set1);

            mailbox
                .bit_vec(
                    types::BitVec { index: 1, bits: bv },
                    peer_mailbox_s1.clone(),
                )
                .await;

            match peer_receiver_s1.next().await {
                Some(peer::Message::Peers(received_peers_info)) => {
                    assert_eq!(
                        received_peers_info.len(),
                        1,
                        "Expected to receive info specifically for pk2"
                    );
                    let received_pk2_info = &received_peers_info[0];
                    assert_eq!(
                        received_pk2_info.public_key, pk2,
                        "Public key mismatch for learned peer"
                    );
                    assert_eq!(
                        received_pk2_info.socket, pk2_addr,
                        "Socket address mismatch for learned peer"
                    );
                    assert_eq!(
                        received_pk2_info.timestamp, pk2_timestamp,
                        "Timestamp mismatch for learned peer"
                    );
                }
                _ => panic!("pk1 did not receive expected PeerInfo for pk2"),
            }
        });
    }

    #[test]
    fn test_handle_peers_rejects_older_info_for_known_peer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(Ed25519::from_seed(0), Vec::new());
            let ts_current = cfg.synchrony_bound.as_millis() as u64;
            let ts_old = ts_current / 2;
            let TestHarness {
                mut mailbox,
                mut oracle,
                ip_namespace,
                tracker_pk,
                ..
            } = setup_tracker_actor(context.clone(), cfg);

            let (_, pk1) = create_signer_and_pk(1);
            let (mut s2_signer, pk2) = create_signer_and_pk(2);

            let peer_set_0_peers = vec![tracker_pk.clone(), pk1.clone(), pk2.clone()];
            oracle.register(0, peer_set_0_peers.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let pk2_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 2002);

            let pk2_info_initial = create_custom_peer_info(
                &mut s2_signer,
                &ip_namespace,
                pk2_addr,
                ts_current,
                Some(pk2.clone()),
                false,
            );
            let (peer_mailbox_s1, mut peer_receiver_s1) = peer::Mailbox::test();
            mailbox
                .peers(vec![pk2_info_initial.clone()], peer_mailbox_s1.clone())
                .await;
            context.sleep(Duration::from_millis(10)).await;

            let pk2_info_older = create_custom_peer_info(
                &mut s2_signer,
                &ip_namespace,
                pk2_addr,
                ts_old,
                Some(pk2.clone()),
                false,
            );
            mailbox
                .peers(vec![pk2_info_older], peer_mailbox_s1.clone())
                .await; // Send older info
            context.sleep(Duration::from_millis(10)).await;

            // Verify tracker still has the initial (newer) info.
            // pk1 sends a BitVec for set 0, indicating it doesn't know pk2's info (to prompt a response).
            let mut sorted_set0_peers = peer_set_0_peers.clone();
            sorted_set0_peers.sort();
            let mut knowledge_for_set0 = UtilsBitVec::zeroes(sorted_set0_peers.len());
            let idx_tracker_in_set0 = sorted_set0_peers
                .iter()
                .position(|p| p == &tracker_pk)
                .unwrap();
            let idx_pk1_in_set0 = sorted_set0_peers.iter().position(|p| p == &pk1).unwrap();
            knowledge_for_set0.set(idx_tracker_in_set0);
            knowledge_for_set0.set(idx_pk1_in_set0);

            let bit_vec_from_pk1 = types::BitVec {
                index: 0,
                bits: knowledge_for_set0,
            };
            mailbox
                .bit_vec(bit_vec_from_pk1, peer_mailbox_s1.clone())
                .await;

            match peer_receiver_s1.next().await {
                Some(peer::Message::Peers(received_peers_info)) => {
                    assert_eq!(
                        received_peers_info.len(),
                        1,
                        "Expected to receive info only for pk2"
                    );
                    let received_pk2_info = &received_peers_info[0];
                    assert_eq!(received_pk2_info.public_key, pk2);
                    assert_eq!(
                        received_pk2_info.timestamp, ts_current,
                        "Timestamp should be the initial (newer) one, not the older one."
                    );
                }
                _ => panic!("pk1 did not receive PeerInfo as expected"),
            }
        });
    }

    #[test]
    fn test_reserve_peer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // context needs to be mut for sleep
            let cfg = test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_tracker_actor(context.clone(), cfg);

            let (_peer_signer, peer_pk) = create_signer_and_pk(1);

            // Attempt to reserve an unknown peer
            let reservation = mailbox.reserve(peer_pk.clone()).await;
            assert!(reservation.is_none(), "Should not reserve unknown peer");

            // Register the peer
            oracle.register(0, vec![peer_pk.clone()]).await;

            // Attempt to reserve the now known peer
            let reservation = mailbox.reserve(peer_pk.clone()).await;
            assert!(reservation.is_some(), "Should reserve known peer");

            // Cannot reserve the same peer again
            let failed_reservation = mailbox.reserve(peer_pk.clone()).await;
            assert!(failed_reservation.is_none(), "Should not re-reserve");

            // Release by dropping
            drop(reservation.unwrap());

            // Sleep to avoid rate-limiting
            context.sleep(Duration::from_millis(1_000)).await;

            let reservation_after_release = mailbox.reserve(peer_pk.clone()).await;
            assert!(
                reservation_after_release.is_some(),
                "Failed to reserve peer again after release"
            );
        });
    }

    #[test]
    fn test_bit_vec() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // context needs to be mut
            let peer0_signer = Ed25519::from_seed(0);
            let cfg = test_config(peer0_signer.clone(), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                ip_namespace,
                tracker_pk,
                ..
            } = setup_tracker_actor(context.clone(), cfg);

            let (mut peer1_signer, peer1_pk) = create_signer_and_pk(1);
            let (_peer2_signer, peer2_pk) = create_signer_and_pk(2);
            let (_peer3_signer, peer3_pk) = create_signer_and_pk(3);

            let (peer_mailbox_for_pk1, mut peer_receiver_for_pk1) = peer::Mailbox::test();
            mailbox
                .construct(peer1_pk.clone(), peer_mailbox_for_pk1.clone())
                .await;
            assert!(
                matches!(
                    peer_receiver_for_pk1.next().await,
                    Some(peer::Message::Kill)
                ),
                "Unallowed peer should be killed"
            );

            let mut initial_peers_set0 = vec![
                tracker_pk.clone(),
                peer1_pk.clone(),
                peer2_pk.clone(),
                peer3_pk.clone(),
            ];
            initial_peers_set0.sort();

            let me_idx_in_set0 = initial_peers_set0
                .iter()
                .position(|p| p == &tracker_pk)
                .unwrap();
            let peer1_idx_in_set0 = initial_peers_set0
                .iter()
                .position(|p| p == &peer1_pk)
                .unwrap();

            oracle.register(0, initial_peers_set0.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            mailbox
                .construct(peer1_pk.clone(), peer_mailbox_for_pk1.clone())
                .await;
            let bit_vec_set0 = match peer_receiver_for_pk1.next().await.unwrap() {
                peer::Message::BitVec(bv) => bv,
                _ => panic!("Expected BitVec"),
            };
            assert_eq!(bit_vec_set0.index, 0);
            assert_eq!(bit_vec_set0.bits.len(), initial_peers_set0.len());
            for (idx, bit) in bit_vec_set0.bits.iter().enumerate() {
                assert_eq!(
                    bit,
                    idx == me_idx_in_set0,
                    "Mismatch in initial BitVec for set 0 at index {}",
                    idx
                );
            }

            let socket_peer1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1001);
            let timestamp_peer1 = context.current().epoch_millis();
            let peer1_info = create_custom_peer_info(
                &mut peer1_signer,
                &ip_namespace,
                socket_peer1,
                timestamp_peer1,
                Some(peer1_pk.clone()),
                false,
            );

            mailbox
                .peers(vec![peer1_info], peer_mailbox_for_pk1.clone())
                .await;
            context.sleep(Duration::from_millis(10)).await;

            mailbox
                .construct(peer1_pk.clone(), peer_mailbox_for_pk1.clone())
                .await;
            let bit_vec_set0_updated = match peer_receiver_for_pk1.next().await.unwrap() {
                peer::Message::BitVec(bv) => bv,
                _ => panic!("Expected BitVec after update"),
            };
            assert_eq!(bit_vec_set0_updated.index, 0);
            for (idx, bit) in bit_vec_set0_updated.bits.iter().enumerate() {
                assert_eq!(
                    bit,
                    idx == me_idx_in_set0 || idx == peer1_idx_in_set0,
                    "Mismatch in updated BitVec for set 0 at index {}",
                    idx
                );
            }

            let set1_peers = vec![peer2_pk.clone(), peer3_pk.clone()];
            oracle.register(1, set1_peers.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let mut index_0_returned = false;
            let mut index_1_returned = false;
            for _ in 0..10 {
                if index_0_returned && index_1_returned {
                    break;
                }
                mailbox
                    .construct(peer1_pk.clone(), peer_mailbox_for_pk1.clone())
                    .await;
                let bit_vec_rand = match peer_receiver_for_pk1.next().await.unwrap() {
                    peer::Message::BitVec(bv) => bv,
                    _ => panic!("Expected BitVec"),
                };
                match bit_vec_rand.index {
                    0 => {
                        index_0_returned = true;
                    }
                    1 => {
                        for bit in bit_vec_rand.bits.iter() {
                            assert!(!bit);
                        } // Tracker knows no one in set1 initially
                        index_1_returned = true;
                    }
                    other_idx => panic!("Unexpected index {} returned", other_idx),
                };
            }
            assert!(
                index_0_returned && index_1_returned,
                "Both set indices (0,1) should have been returned for peer1"
            );

            let set2_peers = vec![peer2_pk.clone()];
            oracle.register(2, set2_peers.clone()).await; // Evicts set 0
            context.sleep(Duration::from_millis(10)).await;

            mailbox
                .construct(peer1_pk.clone(), peer_mailbox_for_pk1.clone())
                .await; // peer1_pk was only in set 0
            assert!(
                matches!(
                    peer_receiver_for_pk1.next().await,
                    Some(peer::Message::Kill)
                ),
                "Peer1 (only in evicted set 0) should be killed"
            );

            let (peer_mailbox_for_pk2, mut peer_receiver_for_pk2) = peer::Mailbox::test();
            let mut index_1_returned_for_p2 = false;
            let mut index_2_returned_for_p2 = false;
            for _ in 0..10 {
                if index_1_returned_for_p2 && index_2_returned_for_p2 {
                    break;
                }
                mailbox
                    .construct(peer2_pk.clone(), peer_mailbox_for_pk2.clone())
                    .await; // peer2_pk is in set 1 and 2
                let bit_vec_rand_p2 = match peer_receiver_for_pk2.next().await.unwrap() {
                    peer::Message::BitVec(bv) => bv,
                    _ => panic!("Expected BitVec for peer2"),
                };
                match bit_vec_rand_p2.index {
                    1 => {
                        index_1_returned_for_p2 = true;
                    }
                    2 => {
                        index_2_returned_for_p2 = true;
                    }
                    other_idx => {
                        panic!("Unexpected index {} for peer2 (expected 1 or 2)", other_idx)
                    }
                }
            }
            assert!(
                index_1_returned_for_p2 && index_2_returned_for_p2,
                "Both active set indices (1,2) should have been seen for peer2"
            );
        });
    }
}
