use super::{
    directory::{self, Directory},
    ingress::{Mailbox, Message, Oracle},
    Config, Error,
};
use crate::authenticated::{ip, types};
use commonware_cryptography::Scheme;
use commonware_runtime::{Clock, Handle, Metrics as RuntimeMetrics, Spawner};
use commonware_utils::{union, SystemTimeExt};
use futures::{channel::mpsc, StreamExt};
use governor::clock::Clock as GClock;
use rand::{seq::SliceRandom, Rng};
use std::time::Duration;
use tracing::debug;

// Bytes to add to the namespace to prevent replay attacks.
const NAMESPACE_SUFFIX_IP: &[u8] = b"_IP";

/// The tracker actor that manages peer discovery and connection reservations.
pub struct Actor<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: Scheme> {
    context: E,

    // ---------- Configuration ----------
    /// For signing and verifying messages.
    crypto: C,

    /// The namespace used to sign and verify [`types::PeerInfo`] messages.
    ip_namespace: Vec<u8>,

    /// Whether to allow private IPs.
    allow_private_ips: bool,

    /// The time bound for synchrony. Messages with timestamps greater than this far into the
    /// future will be considered malformed.
    synchrony_bound: Duration,

    /// The maximum number of peers in a set.
    max_peer_set_size: usize,

    /// The maximum number of [`types::PeerInfo`] allowable in a single message.
    peer_gossip_max_count: usize,

    // ---------- Message-Passing ----------
    /// The mailbox for the actor.
    receiver: mpsc::Receiver<Message<E, C>>,

    // ---------- State ----------
    /// Tracks peer sets and peer connectivity information.
    directory: Directory<E, C>,
}

impl<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: Scheme> Actor<E, C> {
    /// Create a new tracker [`Actor`] from the given `context` and `cfg`.
    pub fn new(context: E, mut cfg: Config<C>) -> (Self, Mailbox<E, C>, Oracle<E, C>) {
        // Sign my own information
        let socket = cfg.address;
        let timestamp = context.current().epoch_millis();
        let ip_namespace = union(&cfg.namespace, NAMESPACE_SUFFIX_IP);
        let myself = types::PeerInfo::sign(&mut cfg.crypto, &ip_namespace, socket, timestamp);

        // General initialization
        let directory_cfg = directory::Config {
            mailbox_size: cfg.mailbox_size,
            max_sets: cfg.tracked_peer_sets,
            dial_fail_limit: cfg.dial_fail_limit,
            rate_limit: cfg.allowed_connection_rate_per_peer,
        };
        let directory = Directory::init(context.clone(), cfg.bootstrappers, myself, directory_cfg);
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);

        (
            Self {
                context,
                crypto: cfg.crypto,
                ip_namespace,
                allow_private_ips: cfg.allow_private_ips,
                synchrony_bound: cfg.synchrony_bound,
                max_peer_set_size: cfg.max_peer_set_size,
                peer_gossip_max_count: cfg.peer_gossip_max_count,
                receiver,
                directory,
            },
            Mailbox::new(sender.clone()),
            Oracle::new(sender),
        )
    }

    /// Handle an incoming list of peer information.
    ///
    /// Returns an error if the list itself or any entries can be considered malformed.
    fn validate(&mut self, infos: &Vec<types::PeerInfo<C>>) -> Result<(), Error> {
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

            // If any signature is invalid, disconnect from the peer
            if !info.verify(&self.ip_namespace) {
                return Err(Error::InvalidSignature);
            }
        }

        Ok(())
    }

    /// Start the actor and run it in the background.
    pub fn start(mut self) -> Handle<()> {
        self.context.spawn_ref()(self.run())
    }

    async fn run(mut self) {
        while let Some(msg) = self.receiver.next().await {
            self.directory.process_releases();
            match msg {
                Message::Register { index, peers } => {
                    // Ensure that peer set is not too large.
                    // Panic since there is no way to recover from this.
                    let len = peers.len();
                    let max = self.max_peer_set_size;
                    assert!(len <= max, "peer set too large: {} > {}", len, max);

                    self.directory.add_set(index, peers);
                }
                Message::Connect {
                    public_key,
                    dialer,
                    mut peer,
                } => {
                    // Kill if peer is not authorized
                    if !self.directory.allowed(&public_key) {
                        peer.kill().await;
                        continue;
                    }

                    // Mark the record as connected
                    self.directory.connect(&public_key, dialer);

                    // Proactively send our own info to the peer
                    let info = self.directory.info(&self.crypto.public_key()).unwrap();
                    let _ = peer.peers(vec![info]).await;
                }
                Message::Construct {
                    public_key,
                    mut peer,
                } => {
                    // Kill if peer is not authorized
                    if !self.directory.allowed(&public_key) {
                        peer.kill().await;
                        continue;
                    }

                    if let Some(bit_vec) = self.directory.get_random_bit_vec() {
                        let _ = peer.bit_vec(bit_vec).await;
                    } else {
                        debug!("no peer sets available");
                    };
                }
                Message::BitVec { bit_vec, mut peer } => {
                    let Some(mut infos) = self.directory.infos(bit_vec) else {
                        peer.kill().await;
                        continue;
                    };

                    // Truncate to a random selection of peers if we have too many infos
                    let max = self.peer_gossip_max_count;
                    if infos.len() > max {
                        infos.partial_shuffle(&mut self.context, max);
                        infos.truncate(max);
                    }

                    // Send the info
                    if !infos.is_empty() {
                        peer.peers(infos).await;
                    }
                }
                Message::Peers { peers, mut peer } => {
                    if let Err(e) = self.validate(&peers) {
                        debug!(error = ?e, "failed to handle peers");
                        peer.kill().await;
                        continue;
                    }
                    self.directory.update_peers(peers);
                }
                Message::Dialable { responder } => {
                    let _ = responder.send(self.directory.dialable());
                }
                Message::Dial {
                    public_key,
                    reservation,
                } => {
                    let _ = reservation.send(self.directory.dial(&public_key));
                }
                Message::Listen {
                    public_key,
                    reservation,
                } => {
                    let _ = reservation.send(self.directory.listen(&public_key));
                }
                Message::Block { public_key } => {
                    // Block the peer
                    self.directory.block(&public_key);

                    // We don't have to kill the peer now. It will be sent a `Kill` message the next
                    // time it sends the `Connect` or `Construct` message to the tracker.
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
        authenticated::{
            actors::{peer, tracker},
            config::Bootstrapper,
            types,
        },
        Blocker,
        // Blocker is implicitly available via oracle.block() due to Oracle implementing crate::Blocker
    };
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{
        ed25519::{self, PublicKey},
        Ed25519,
        Signer, // Verifier is not directly used in this test module's scope
    };
    use commonware_runtime::{
        deterministic::{self, Context},
        Clock, Runner,
    };
    use commonware_utils::{BitVec as UtilsBitVec, NZU32};
    use futures::future::Either;
    use governor::Quota;
    use std::time::Duration;
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, SocketAddr},
    };
    use types::PeerInfo;

    // Test Configuration Setup
    fn default_test_config<C: Scheme>(
        crypto: C,
        bootstrappers: Vec<Bootstrapper<C::PublicKey>>,
    ) -> Config<C> {
        Config {
            crypto,
            namespace: b"test_tracker_actor_namespace".to_vec(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            bootstrappers,
            allow_private_ips: true,
            mailbox_size: 32,
            synchrony_bound: Duration::from_secs(10),
            tracked_peer_sets: 2,
            allowed_connection_rate_per_peer: Quota::per_second(NZU32!(5)),
            peer_gossip_max_count: 5,
            max_peer_set_size: 128,
            dial_fail_limit: 1,
        }
    }

    // Helper to create Ed25519 signer and public key
    fn new_signer_and_pk(seed: u64) -> (Ed25519, PublicKey) {
        let signer = Ed25519::from_seed(seed);
        let pk = signer.public_key();
        (signer, pk)
    }

    // Helper to create PeerInfo
    fn new_peer_info(
        signer: &mut Ed25519,
        ip_namespace: &[u8],
        socket: SocketAddr,
        timestamp: u64,
        target_pk_override: Option<PublicKey>,
        make_sig_invalid: bool,
    ) -> PeerInfo<Ed25519> {
        let peer_info_pk = target_pk_override.unwrap_or_else(|| signer.public_key());
        let mut signature = signer.sign(Some(ip_namespace), &(socket, timestamp).encode());

        if make_sig_invalid && !signature.as_ref().is_empty() {
            let mut sig_bytes = signature.encode();
            sig_bytes[0] = sig_bytes[0].wrapping_add(1);
            signature = ed25519::Signature::decode(sig_bytes).unwrap();
        }

        PeerInfo {
            socket,
            timestamp,
            public_key: peer_info_pk,
            signature,
        }
    }

    // Mock a connection to a peer by reserving it as if it had dialed us and the `peer` actor had
    // sent an initialization.
    async fn connect_to_peer(
        mailbox: &mut tracker::Mailbox<Context, Ed25519>,
        peer: &PublicKey,
        peer_mailbox: &peer::Mailbox<Ed25519>,
        peer_receiver: &mut mpsc::Receiver<peer::Message<Ed25519>>,
    ) -> tracker::Reservation<Context, PublicKey> {
        let res = mailbox
            .listen(peer.clone())
            .await
            .expect("reservation failed");
        let dialer = false;
        mailbox
            .connect(peer.clone(), dialer, peer_mailbox.clone())
            .await;
        let response = peer_receiver
            .next()
            .await
            .expect("no response after initialization");
        assert!(matches!(response, peer::Message::Peers(_)));
        res
    }

    // Test Harness
    struct TestHarness {
        #[allow(dead_code)]
        actor_handle: Handle<()>,
        mailbox: Mailbox<deterministic::Context, Ed25519>,
        oracle: Oracle<deterministic::Context, Ed25519>,
        ip_namespace: Vec<u8>,
        tracker_pk: PublicKey,
        tracker_signer: Ed25519,
        cfg: Config<Ed25519>, // Store cloned config for access to its values
    }

    fn setup_actor(
        runner_context: deterministic::Context,
        cfg_to_clone: Config<Ed25519>, // Pass by value to allow cloning
    ) -> TestHarness {
        let tracker_signer = cfg_to_clone.crypto.clone();
        let tracker_pk = tracker_signer.public_key();
        let ip_namespace_base = cfg_to_clone.namespace.clone();
        let stored_cfg = cfg_to_clone.clone(); // Clone for storing in harness

        // Actor::new takes ownership, so clone again if cfg_to_clone is needed later
        let (actor, mailbox, oracle) = Actor::new(runner_context.clone(), cfg_to_clone);
        let ip_namespace = union(&ip_namespace_base, super::NAMESPACE_SUFFIX_IP);
        let actor_handle = runner_context.spawn(|_| actor.run());

        TestHarness {
            actor_handle,
            mailbox,
            oracle,
            ip_namespace,
            tracker_pk,
            tracker_signer,
            cfg: stored_cfg,
        }
    }

    #[test]
    #[should_panic(expected = "peer set too large")]
    fn test_register_peer_set_too_large() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut oracle,
                cfg,
                mut mailbox,
                ..
            } = setup_actor(context.clone(), cfg_initial);
            let too_many_peers: Vec<PublicKey> = (1..=(cfg.max_peer_set_size + 1) as u64)
                .map(|i| new_signer_and_pk(i).1)
                .collect();
            oracle.register(0, too_many_peers).await;
            // Ensure the message is processed causing the panic
            let _ = mailbox.dialable().await;
        });
    }

    #[test]
    fn test_connect_unauthorized_peer_is_killed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness { mut mailbox, .. } = setup_actor(context.clone(), cfg);

            let (_unauth_signer, unauth_pk) = new_signer_and_pk(1);
            let (peer_mailbox, mut peer_receiver) = peer::Mailbox::test();

            // Connect as listener
            mailbox
                .connect(unauth_pk.clone(), false, peer_mailbox.clone())
                .await;
            assert!(
                matches!(peer_receiver.next().await, Some(peer::Message::Kill)),
                "Unauthorized peer should be killed on Connect"
            );

            // Connect as dialer
            mailbox.connect(unauth_pk, true, peer_mailbox).await;
            assert!(
                matches!(peer_receiver.next().await, Some(peer::Message::Kill)),
                "Unauthorized peer should be killed on Connect"
            );
        });
    }

    #[test]
    fn test_connect_authorized_peer_receives_tracker_info() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                tracker_pk,
                cfg,
                ip_namespace,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_auth_signer, auth_pk) = new_signer_and_pk(1);
            oracle
                .register(0, vec![tracker_pk.clone(), auth_pk.clone()])
                .await;
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox, mut peer_receiver) = peer::Mailbox::test();

            let _res = mailbox.listen(auth_pk.clone()).await.unwrap();
            mailbox
                .connect(auth_pk.clone(), false, peer_mailbox.clone())
                .await;

            match peer_receiver.next().await {
                Some(peer::Message::Peers(infos)) => {
                    assert_eq!(infos.len(), 1);
                    let tracker_info = &infos[0];
                    assert_eq!(tracker_info.public_key, tracker_pk);
                    assert_eq!(tracker_info.socket, cfg.address);
                    assert!(tracker_info.verify(&ip_namespace));
                }
                _ => panic!("Expected Peers message with tracker info"),
            }
        });
    }

    #[test]
    fn test_construct_no_sets_registered() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (_boot_signer, boot_pk) = new_signer_and_pk(99);
            let boot_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9999);
            let cfg_with_boot =
                default_test_config(Ed25519::from_seed(0), vec![(boot_pk.clone(), boot_addr)]);
            let TestHarness {
                mailbox: mut new_mailbox,
                ..
            } = setup_actor(context.clone(), cfg_with_boot);

            let (peer_mailbox, mut peer_receiver) = peer::Mailbox::test();
            new_mailbox
                .construct(boot_pk.clone(), peer_mailbox.clone())
                .await;

            match futures::future::select(
                Box::pin(peer_receiver.next()),
                Box::pin(context.sleep(Duration::from_millis(50))),
            )
            .await
            {
                Either::Left((Some(_), _)) => {
                    panic!("Expected no message on Construct with no sets",)
                }
                Either::Left((None, _)) => panic!("Peer mailbox closed unexpectedly"),
                Either::Right(_) => { /* Timeout: Correctly no message sent */ }
            }
        });
    }

    #[test]
    fn test_handle_peers_received_self() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                ip_namespace,
                tracker_pk,
                mut tracker_signer,
                cfg,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_, pk1) = new_signer_and_pk(1);
            oracle
                .register(0, vec![tracker_pk.clone(), pk1.clone()])
                .await;
            context.sleep(Duration::from_millis(10)).await;

            let self_info = new_peer_info(
                &mut tracker_signer,
                &ip_namespace,
                cfg.address,
                context.current().epoch_millis(),
                Some(tracker_pk.clone()),
                false,
            );

            let (peer_mailbox_s1, mut peer_receiver_s1) = peer::Mailbox::test();
            mailbox
                .peers(vec![self_info], peer_mailbox_s1.clone())
                .await;

            assert!(
                matches!(peer_receiver_s1.next().await, Some(peer::Message::Kill)),
                "Peer should be killed for sending tracker's own info"
            );
        });
    }

    #[test]
    fn test_handle_bit_vec_for_unknown_index_sends_no_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                tracker_pk,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_, pk1) = new_signer_and_pk(1);
            oracle.register(0, vec![tracker_pk, pk1.clone()]).await;
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox_pk1, mut peer_receiver_pk1) = peer::Mailbox::test();
            let bit_vec_unknown_idx = types::BitVec {
                index: 99,
                bits: UtilsBitVec::ones(1),
            };

            let _r1 = connect_to_peer(
                &mut mailbox,
                &pk1,
                &peer_mailbox_pk1,
                &mut peer_receiver_pk1,
            )
            .await;

            // Peer lets us know it received a bit vector
            mailbox
                .bit_vec(bit_vec_unknown_idx, peer_mailbox_pk1.clone())
                .await;

            // No message is sent back to the peer
            assert!(peer_receiver_pk1.try_next().is_err());
        });
    }

    #[test]
    fn test_block_peer_standard_behavior() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                tracker_pk,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_s1_signer, pk1) = new_signer_and_pk(1);
            oracle
                .register(0, vec![tracker_pk.clone(), pk1.clone()])
                .await;
            context.sleep(Duration::from_millis(10)).await;

            oracle.block(pk1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox_pk1, mut peer_receiver_pk1) = peer::Mailbox::test();
            mailbox
                .construct(pk1.clone(), peer_mailbox_pk1.clone())
                .await;

            assert!(matches!(
                peer_receiver_pk1.next().await,
                Some(peer::Message::Kill)
            ));

            let dialable_peers = mailbox.dialable().await;
            assert!(!dialable_peers.iter().any(|peer| peer == &pk1));
        });
    }

    #[test]
    fn test_block_peer_already_blocked_is_noop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                tracker_pk,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_s1_signer, pk1) = new_signer_and_pk(1);
            oracle
                .register(0, vec![tracker_pk.clone(), pk1.clone()])
                .await;
            context.sleep(Duration::from_millis(10)).await;

            oracle.block(pk1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;
            oracle.block(pk1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox_pk1, mut peer_receiver_pk1) = peer::Mailbox::test();
            mailbox
                .construct(pk1.clone(), peer_mailbox_pk1.clone())
                .await;
            assert!(matches!(
                peer_receiver_pk1.next().await,
                Some(peer::Message::Kill)
            ));
        });
    }

    #[test]
    fn test_block_peer_non_existent_is_noop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness { mut oracle, .. } = setup_actor(context.clone(), cfg_initial);

            let (_s1_signer, pk_non_existent) = new_signer_and_pk(100);

            oracle.block(pk_non_existent).await;
            context.sleep(Duration::from_millis(10)).await;
        });
    }

    #[test]
    fn test_handle_peers_learns_unknown_peer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                ip_namespace,
                tracker_pk,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_, pk1) = new_signer_and_pk(1);
            let (mut s2_signer, pk2) = new_signer_and_pk(2);

            oracle
                .register(0, vec![tracker_pk.clone(), pk1.clone()])
                .await;
            context.sleep(Duration::from_millis(10)).await;

            let pk2_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 2002);
            let pk2_timestamp = context.current().epoch_millis();
            let pk2_info = new_peer_info(
                &mut s2_signer,
                &ip_namespace,
                pk2_addr,
                pk2_timestamp,
                Some(pk2.clone()),
                false,
            );

            let mut set1 = vec![tracker_pk.clone(), pk1.clone(), pk2.clone()];
            set1.sort();
            oracle.register(1, set1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox_s1, mut peer_receiver_s1) = peer::Mailbox::test();
            let (peer_mailbox_s2, mut peer_receiver_s2) = peer::Mailbox::test();
            mailbox
                .peers(vec![pk2_info.clone()], peer_mailbox_s1.clone())
                .await;
            context.sleep(Duration::from_millis(10)).await;

            let _r1 =
                connect_to_peer(&mut mailbox, &pk1, &peer_mailbox_s1, &mut peer_receiver_s1).await;
            let _r2 =
                connect_to_peer(&mut mailbox, &pk2, &peer_mailbox_s2, &mut peer_receiver_s2).await;

            // Act as if pk1 received a bit vector where pk2 is not known.
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
                    assert_eq!(received_peers_info.len(), 1);
                    let received_pk2_info = &received_peers_info[0];
                    assert_eq!(received_pk2_info.public_key, pk2);
                    assert_eq!(received_pk2_info.socket, pk2_addr);
                    assert_eq!(received_pk2_info.timestamp, pk2_timestamp);
                }
                _ => panic!("pk1 did not receive expected PeerInfo for pk2",),
            }
        });
    }

    #[test]
    fn test_handle_peers_rejects_older_info_for_known_peer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                ip_namespace,
                tracker_pk,
                cfg,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let ts_new = context.current().epoch_millis();
            let ts_old = ts_new.saturating_sub(cfg.synchrony_bound.as_millis() as u64 / 2);

            let (_, pk1) = new_signer_and_pk(1);
            let (mut s2_signer, pk2) = new_signer_and_pk(2);

            let peer_set_0_peers = vec![tracker_pk.clone(), pk1.clone(), pk2.clone()];
            oracle.register(0, peer_set_0_peers.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let pk2_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 2002);
            let pk2_info_initial = new_peer_info(
                &mut s2_signer,
                &ip_namespace,
                pk2_addr,
                ts_new,
                Some(pk2.clone()),
                false,
            );

            let (peer_mailbox_s1, mut peer_receiver_s1) = peer::Mailbox::test();
            let _r1 =
                connect_to_peer(&mut mailbox, &pk1, &peer_mailbox_s1, &mut peer_receiver_s1).await;

            // Connect to pk2
            let (peer_mailbox_s2, mut peer_receiver_s2) = peer::Mailbox::test();
            let _r2 =
                connect_to_peer(&mut mailbox, &pk2, &peer_mailbox_s2, &mut peer_receiver_s2).await;

            mailbox
                .peers(vec![pk2_info_initial.clone()], peer_mailbox_s1.clone())
                .await;
            context.sleep(Duration::from_millis(10)).await;

            let pk2_info_older = new_peer_info(
                &mut s2_signer,
                &ip_namespace,
                pk2_addr,
                ts_old,
                Some(pk2.clone()),
                false,
            );
            mailbox
                .peers(vec![pk2_info_older], peer_mailbox_s1.clone())
                .await;
            context.sleep(Duration::from_millis(10)).await;

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
                    assert_eq!(received_peers_info.len(), 1);
                    let received_pk2_info = &received_peers_info[0];
                    assert_eq!(received_pk2_info.public_key, pk2);
                    assert_eq!(received_pk2_info.timestamp, ts_new);
                }
                _ => panic!("pk1 did not receive PeerInfo as expected"),
            }
        });
    }

    #[test]
    fn test_listen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_peer_signer, peer_pk) = new_signer_and_pk(1);

            let reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation.is_none());

            oracle.register(0, vec![peer_pk.clone()]).await;
            context.sleep(Duration::from_millis(10)).await; // Allow register to process

            let reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation.is_some());

            let failed_reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(failed_reservation.is_none());

            drop(reservation.unwrap());
            context.sleep(Duration::from_millis(1_010)).await; // Allow release and rate limit to pass

            let reservation_after_release = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation_after_release.is_some());
        });
    }

    #[test]
    fn test_dialable_message() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (_boot_signer, boot_pk) = new_signer_and_pk(99);
            let boot_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9000);
            let cfg_initial =
                default_test_config(Ed25519::from_seed(0), vec![(boot_pk.clone(), boot_addr)]);
            let TestHarness { mut mailbox, .. } = setup_actor(context.clone(), cfg_initial);

            let dialable_peers = mailbox.dialable().await;
            assert_eq!(dialable_peers.len(), 1);
            assert_eq!(dialable_peers[0], boot_pk);
        });
    }

    #[test]
    fn test_dial_message() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (_boot_signer, boot_pk) = new_signer_and_pk(99);
            let boot_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9000);
            let cfg_initial =
                default_test_config(Ed25519::from_seed(0), vec![(boot_pk.clone(), boot_addr)]);

            let TestHarness { mut mailbox, .. } = setup_actor(context.clone(), cfg_initial);

            let reservation = mailbox.dial(boot_pk.clone()).await;
            assert!(reservation.is_some());
            if let Some(res) = reservation {
                match res.metadata() {
                    crate::authenticated::actors::tracker::Metadata::Dialer(pk, addr) => {
                        assert_eq!(pk, &boot_pk);
                        assert_eq!(*addr, boot_addr);
                    }
                    _ => panic!("Expected Dialer metadata"),
                }
            }

            let (_unknown_signer, unknown_pk) = new_signer_and_pk(100);
            let no_reservation = mailbox.dial(unknown_pk).await;
            assert!(no_reservation.is_none());
        });
    }

    #[test]
    fn test_validate_kill_on_too_many() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut cfg = default_test_config(Ed25519::from_seed(0), Vec::new());
            let max_gossip = 2;
            cfg.peer_gossip_max_count = max_gossip;
            let TestHarness {
                mut mailbox,
                ip_namespace,
                ..
            } = setup_actor(context.clone(), cfg);

            let (mut s1, _pk1) = new_signer_and_pk(1);
            let (_s2, pk2) = new_signer_and_pk(2);
            let (_s3, pk3) = new_signer_and_pk(3);
            let (_s4, pk4) = new_signer_and_pk(4);

            let (peer_mailbox, mut peer_receiver) = peer::Mailbox::test();
            let infos = vec![
                new_peer_info(
                    &mut s1,
                    &ip_namespace,
                    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1002),
                    context.current().epoch_millis(),
                    Some(pk2),
                    false,
                ),
                new_peer_info(
                    &mut s1,
                    &ip_namespace,
                    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1003),
                    context.current().epoch_millis(),
                    Some(pk3),
                    false,
                ),
                new_peer_info(
                    &mut s1,
                    &ip_namespace,
                    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1004),
                    context.current().epoch_millis(),
                    Some(pk4),
                    false,
                ),
            ];
            assert!(infos.len() > max_gossip);
            mailbox.peers(infos, peer_mailbox.clone()).await;
            assert!(matches!(
                peer_receiver.next().await,
                Some(peer::Message::Kill)
            ));
        });
    }

    #[test]
    fn test_validate_kill_on_private_ip_disallowed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut cfg = default_test_config(Ed25519::from_seed(0), Vec::new());
            cfg.allow_private_ips = false;
            let TestHarness {
                mut mailbox,
                ip_namespace,
                ..
            } = setup_actor(context.clone(), cfg);

            let (mut s2, pk2) = new_signer_and_pk(2);
            let private_socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
            let info = new_peer_info(
                &mut s2,
                &ip_namespace,
                private_socket,
                context.current().epoch_millis(),
                Some(pk2),
                false,
            );

            let (peer_mailbox, mut peer_receiver) = peer::Mailbox::test();
            mailbox.peers(vec![info], peer_mailbox.clone()).await;
            assert!(matches!(
                peer_receiver.next().await,
                Some(peer::Message::Kill)
            ));
        });
    }

    #[test]
    fn test_validate_kill_on_synchrony_bound() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                ip_namespace,
                cfg,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (mut s2, pk2) = new_signer_and_pk(2);
            let far_future_ts =
                context.current().epoch_millis() + cfg.synchrony_bound.as_millis() as u64 + 1000;
            let info = new_peer_info(
                &mut s2,
                &ip_namespace,
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1002),
                far_future_ts,
                Some(pk2),
                false,
            );

            let (peer_mailbox, mut peer_receiver) = peer::Mailbox::test();
            mailbox.peers(vec![info], peer_mailbox.clone()).await;
            assert!(matches!(
                peer_receiver.next().await,
                Some(peer::Message::Kill)
            ));
        });
    }

    #[test]
    fn test_validate_kill_on_invalid_signature() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                ip_namespace,
                tracker_pk,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_, pk1) = new_signer_and_pk(1);
            let (mut s2, pk2) = new_signer_and_pk(2);
            oracle.register(0, vec![tracker_pk, pk1, pk2.clone()]).await;
            context.sleep(Duration::from_millis(10)).await;

            let info = new_peer_info(
                &mut s2,
                &ip_namespace,
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1002),
                context.current().epoch_millis(),
                Some(pk2),
                true,
            );

            let (peer_mailbox, mut peer_receiver) = peer::Mailbox::test();
            mailbox.peers(vec![info], peer_mailbox.clone()).await;
            assert!(matches!(
                peer_receiver.next().await,
                Some(peer::Message::Kill)
            ));
        });
    }

    #[test]
    fn test_bitvec_kill_on_length_mismatch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                tracker_pk,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_s1, pk1) = new_signer_and_pk(1);
            let (_s2, pk2) = new_signer_and_pk(2);
            oracle
                .register(0, vec![tracker_pk, pk1.clone(), pk2.clone()])
                .await;
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox, mut peer_receiver) = peer::Mailbox::test();
            let invalid_bit_vec = types::BitVec {
                index: 0,
                bits: UtilsBitVec::ones(2),
            };
            mailbox.bit_vec(invalid_bit_vec, peer_mailbox.clone()).await;
            assert!(matches!(
                peer_receiver.next().await,
                Some(peer::Message::Kill)
            ));
        });
    }

    #[test]
    fn test_bit_vec_comprehensive() {
        // Combines and clarifies parts of the old test_bit_vec
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(Ed25519::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                ip_namespace,
                tracker_pk,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (mut peer1_s, peer1_pk) = new_signer_and_pk(1);
            let (_peer2_s, peer2_pk) = new_signer_and_pk(2);

            // --- Initial Construct for unauthorized peer ---
            let (peer_mailbox1, mut peer_receiver1) = peer::Mailbox::test();
            mailbox
                .construct(peer1_pk.clone(), peer_mailbox1.clone())
                .await;
            assert!(
                matches!(peer_receiver1.next().await, Some(peer::Message::Kill)),
                "Unauthorized peer killed on Construct"
            );

            // --- Register set 0, then Construct for authorized peer1 ---
            let mut set0_peers = vec![tracker_pk.clone(), peer1_pk.clone(), peer2_pk.clone()];
            set0_peers.sort(); // Directory expects sorted, Oracle also benefits
            oracle.register(0, set0_peers.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let _r1 =
                connect_to_peer(&mut mailbox, &peer1_pk, &peer_mailbox1, &mut peer_receiver1).await;

            mailbox
                .construct(peer1_pk.clone(), peer_mailbox1.clone())
                .await;
            let bit_vec0 = match peer_receiver1.next().await {
                Some(peer::Message::BitVec(bv)) => bv,
                _ => panic!("Expected BitVec for set 0"),
            };
            assert_eq!(bit_vec0.index, 0);
            assert_eq!(bit_vec0.bits.len(), set0_peers.len());
            let tracker_idx_s0 = set0_peers.iter().position(|p| p == &tracker_pk).unwrap();
            assert!(
                bit_vec0.bits.get(tracker_idx_s0).unwrap(),
                "Tracker should know itself in set 0"
            );

            // --- Peer1 sends its info, tracker learns it, Construct reflects this ---
            let peer1_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1001);
            let peer1_ts = context.current().epoch_millis();
            let peer1_info = new_peer_info(
                &mut peer1_s,
                &ip_namespace,
                peer1_addr,
                peer1_ts,
                Some(peer1_pk.clone()),
                false,
            );
            mailbox.peers(vec![peer1_info], peer_mailbox1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            mailbox
                .construct(peer1_pk.clone(), peer_mailbox1.clone())
                .await;
            let bit_vec0_updated = match peer_receiver1.next().await {
                Some(peer::Message::BitVec(bv)) => bv,
                _ => panic!("Expected updated BitVec for set 0"),
            };
            let peer1_idx_s0 = set0_peers.iter().position(|p| p == &peer1_pk).unwrap();
            assert!(bit_vec0_updated.bits.get(tracker_idx_s0).unwrap());
            assert!(
                bit_vec0_updated.bits.get(peer1_idx_s0).unwrap(),
                "Tracker should know peer1 in set 0 after Peers msg"
            );

            // --- Peer1 sends BitVec for set 0, indicating it only knows tracker ---
            // Tracker should respond with PeerInfo for peer1_pk (as it just learned it)
            let mut peer1_knowledge_s0 = UtilsBitVec::zeroes(set0_peers.len());
            peer1_knowledge_s0.set(tracker_idx_s0); // Peer1 knows tracker
            mailbox
                .bit_vec(
                    types::BitVec {
                        index: 0,
                        bits: peer1_knowledge_s0,
                    },
                    peer_mailbox1.clone(),
                )
                .await;

            match peer_receiver1.next().await {
                Some(peer::Message::Peers(infos)) => {
                    assert_eq!(infos.len(), 1, "Expected 1 PeerInfo (for peer1)");
                    assert_eq!(infos[0].public_key, peer1_pk);
                    assert_eq!(infos[0].socket, peer1_addr);
                }
                _ => panic!("Expected Peers message from tracker"),
            }

            // --- Set eviction and peer killing ---
            let (_peer3_s, peer3_pk) = new_signer_and_pk(3);
            let mut set1_peers = vec![tracker_pk.clone(), peer2_pk.clone()]; // New set without peer1
            set1_peers.sort();
            oracle.register(1, set1_peers.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let mut set2_peers = vec![tracker_pk.clone(), peer3_pk.clone()]; // Another new set without peer1
            set2_peers.sort();
            oracle.register(2, set2_peers.clone()).await; // This should evict set 0 (max_sets = 2)
            context.sleep(Duration::from_millis(10)).await;

            // Peer1 was only in set 0, which is now evicted.
            // Construct for peer1 should now result in Kill because it's not in any active tracked set.
            mailbox
                .construct(peer1_pk.clone(), peer_mailbox1.clone())
                .await;
            assert!(
                matches!(peer_receiver1.next().await, Some(peer::Message::Kill)),
                "Peer1 should be killed after its only set was evicted"
            );

            // Peer2 is in set1 (still active)
            let (peer_mailbox2, mut peer_receiver2) = peer::Mailbox::test();
            let _r2 =
                connect_to_peer(&mut mailbox, &peer2_pk, &peer_mailbox2, &mut peer_receiver2).await;

            // Run this several times since the bitvec given may have index 1 or 2.
            let mut indices = HashSet::new();
            for _ in 0..100 {
                mailbox
                    .construct(peer2_pk.clone(), peer_mailbox2.clone())
                    .await;
                let Some(peer::Message::BitVec(bv)) = peer_receiver2.next().await else {
                    panic!("Unexpected message type");
                };
                indices.insert(bv.index);
            }
            assert!(indices.contains(&1));
            assert!(indices.contains(&2));
            assert_eq!(indices.len(), 2);
        });
    }
}
