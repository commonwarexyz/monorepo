use super::{
    directory::{self, Directory},
    ingress::{Mailbox, Message, Oracle},
    Config,
};
use crate::authenticated::PeerInfo;
use commonware_cryptography::Signer;
use commonware_runtime::{Clock, Handle, Metrics as RuntimeMetrics, Spawner};
use commonware_utils::{union, SystemTimeExt};
use futures::{channel::mpsc, StreamExt};
use governor::clock::Clock as GClock;
use rand::Rng;
use tracing::debug;

// Bytes to add to the namespace to prevent replay attacks.
const NAMESPACE_SUFFIX_IP: &[u8] = b"_IP";

/// The tracker actor that manages peer discovery and connection reservations.
pub struct Actor<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: Signer> {
    context: E,

    // ---------- Configuration ----------
    /// For signing and verifying messages.
    crypto: C,

    /// The maximum number of peers in a set.
    max_peer_set_size: usize,

    // ---------- Message-Passing ----------
    /// The mailbox for the actor.
    receiver: mpsc::Receiver<Message<E, C::PublicKey>>,

    // ---------- State ----------
    /// Tracks peer sets and peer connectivity information.
    directory: Directory<E, C::PublicKey>,
}

impl<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: Signer> Actor<E, C> {
    /// Create a new tracker [`Actor`] from the given `context` and `cfg`.
    #[allow(clippy::type_complexity)]
    pub fn new(
        context: E,
        cfg: Config<C>,
    ) -> (Self, Mailbox<E, C::PublicKey>, Oracle<E, C::PublicKey>) {
        // Sign my own information
        let socket = cfg.address;
        let timestamp = context.current().epoch_millis();
        let ip_namespace = union(&cfg.namespace, NAMESPACE_SUFFIX_IP);
        let myself = PeerInfo::sign(&cfg.crypto, &ip_namespace, socket, timestamp);

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
                max_peer_set_size: cfg.max_peer_set_size,
                receiver,
                directory,
            },
            Mailbox::new(sender.clone()),
            Oracle::new(sender),
        )
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
                    // TODO danlaine: do we need to send the peer anything here?
                    let _info = self.directory.info(&self.crypto.public_key()).unwrap();
                    // let _ = peer.peers(vec![info]).await;
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
            self,
            lookup::{actors::peer, config::Bootstrapper},
        },
        Blocker,
        // Blocker is implicitly available via oracle.block() due to Oracle implementing crate::Blocker
    };
    use commonware_cryptography::PrivateKeyExt as _;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_runtime::{
        deterministic::{self},
        Clock, Runner,
    };
    use commonware_utils::NZU32;
    use governor::Quota;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    // Test Configuration Setup
    fn default_test_config<C: Signer>(
        crypto: C,
        bootstrappers: Vec<Bootstrapper<C::PublicKey>>,
    ) -> Config<C> {
        Config {
            crypto,
            namespace: b"test_tracker_actor_namespace".to_vec(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            bootstrappers,
            mailbox_size: 32,
            tracked_peer_sets: 2,
            allowed_connection_rate_per_peer: Quota::per_second(NZU32!(5)),
            max_peer_set_size: 128,
            dial_fail_limit: 1,
        }
    }

    // Helper to create Ed25519 signer and public key
    fn new_signer_and_pk(seed: u64) -> (PrivateKey, PublicKey) {
        let signer = PrivateKey::from_seed(seed);
        let pk = signer.public_key();
        (signer, pk)
    }

    // // Helper to create PeerInfo
    // fn new_peer_info(
    //     signer: &mut PrivateKey,
    //     ip_namespace: &[u8],
    //     socket: SocketAddr,
    //     timestamp: u64,
    //     target_pk_override: Option<PublicKey>,
    //     make_sig_invalid: bool,
    // ) -> PeerInfo<PublicKey> {
    //     let peer_info_pk = target_pk_override.unwrap_or_else(|| signer.public_key());
    //     let mut signature = signer.sign(Some(ip_namespace), &(socket, timestamp).encode());

    //     if make_sig_invalid && !signature.as_ref().is_empty() {
    //         let mut sig_bytes = signature.encode();
    //         sig_bytes[0] = sig_bytes[0].wrapping_add(1);
    //         signature = Signature::decode(sig_bytes).unwrap();
    //     }

    //     PeerInfo {
    //         socket,
    //         timestamp,
    //         public_key: peer_info_pk,
    //         signature,
    //     }
    // }

    // // Mock a connection to a peer by reserving it as if it had dialed us and the `peer` actor had
    // // sent an initialization.
    // async fn connect_to_peer(
    //     mailbox: &mut tracker::Mailbox<Context, PublicKey>,
    //     peer: &PublicKey,
    //     peer_mailbox: &authenticated::Mailbox,
    //     peer_receiver: &mut mpsc::Receiver<peer::Message>,
    // ) -> tracker::Reservation<Context, PublicKey> {
    //     let res = mailbox
    //         .listen(peer.clone())
    //         .await
    //         .expect("reservation failed");
    //     let dialer = false;
    //     mailbox
    //         .connect(peer.clone(), dialer, peer_mailbox.clone())
    //         .await;
    //     let response = peer_receiver
    //         .next()
    //         .await
    //         .expect("no response after initialization");
    //     // TODO danlaine: what response do we expect here?
    //     // assert!(matches!(response, peer::Message::Peers(_)));
    //     res
    // }

    // Test Harness
    struct TestHarness {
        #[allow(dead_code)]
        actor_handle: Handle<()>,
        mailbox: Mailbox<deterministic::Context, PublicKey>,
        oracle: Oracle<deterministic::Context, PublicKey>,
        cfg: Config<PrivateKey>, // Store cloned config for access to its values
    }

    fn setup_actor(
        runner_context: deterministic::Context,
        cfg_to_clone: Config<PrivateKey>, // Pass by value to allow cloning
    ) -> TestHarness {
        let stored_cfg = cfg_to_clone.clone(); // Clone for storing in harness

        // Actor::new takes ownership, so clone again if cfg_to_clone is needed later
        let (actor, mailbox, oracle) = Actor::new(runner_context.clone(), cfg_to_clone);
        let actor_handle = runner_context.spawn(|_| actor.run());

        TestHarness {
            actor_handle,
            mailbox,
            oracle,
            cfg: stored_cfg,
        }
    }

    #[test]
    #[should_panic(expected = "peer set too large")]
    fn test_register_peer_set_too_large() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
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
            let cfg = default_test_config(PrivateKey::from_seed(0), Vec::new());
            let TestHarness { mut mailbox, .. } = setup_actor(context.clone(), cfg);

            let (_unauth_signer, unauth_pk) = new_signer_and_pk(1);
            let (peer_mailbox, mut peer_receiver) = authenticated::Mailbox::test();

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

    // #[test]
    // fn test_connect_authorized_peer_receives_tracker_info() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
    //         let TestHarness {
    //             mut mailbox,
    //             mut oracle,
    //             tracker_pk,
    //             cfg,
    //             ip_namespace,
    //             ..
    //         } = setup_actor(context.clone(), cfg_initial);

    //         let (_auth_signer, auth_pk) = new_signer_and_pk(1);
    //         oracle
    //             .register(0, vec![tracker_pk.clone(), auth_pk.clone()])
    //             .await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         let (peer_mailbox, mut peer_receiver) = authenticated::Mailbox::test();

    //         let _res = mailbox.listen(auth_pk.clone()).await.unwrap();
    //         mailbox
    //             .connect(auth_pk.clone(), false, peer_mailbox.clone())
    //             .await;

    //         match peer_receiver.next().await {
    //             Some(peer::Message::Peers(infos)) => {
    //                 assert_eq!(infos.len(), 1);
    //                 let tracker_info = &infos[0];
    //                 assert_eq!(tracker_info.public_key, tracker_pk);
    //                 assert_eq!(tracker_info.socket, cfg.address);
    //                 assert!(tracker_info.verify(&ip_namespace));
    //             }
    //             _ => panic!("Expected Peers message with tracker info"),
    //         }
    //     });
    // }

    // #[test]
    // fn test_construct_no_sets_registered() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let (_boot_signer, boot_pk) = new_signer_and_pk(99);
    //         let boot_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9999);
    //         let cfg_with_boot =
    //             default_test_config(PrivateKey::from_seed(0), vec![(boot_pk.clone(), boot_addr)]);
    //         let TestHarness {
    //             mailbox: mut new_mailbox,
    //             ..
    //         } = setup_actor(context.clone(), cfg_with_boot);

    //         let (peer_mailbox, mut peer_receiver) = authenticated::Mailbox::test();
    //         new_mailbox
    //             .construct(boot_pk.clone(), peer_mailbox.clone())
    //             .await;

    //         match futures::future::select(
    //             Box::pin(peer_receiver.next()),
    //             Box::pin(context.sleep(Duration::from_millis(50))),
    //         )
    //         .await
    //         {
    //             Either::Left((Some(_), _)) => {
    //                 panic!("Expected no message on Construct with no sets",)
    //             }
    //             Either::Left((None, _)) => panic!("Peer mailbox closed unexpectedly"),
    //             Either::Right(_) => { /* Timeout: Correctly no message sent */ }
    //         }
    //     });
    // }

    // #[test]
    // fn test_handle_peers_received_self() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
    //         let TestHarness {
    //             mut mailbox,
    //             mut oracle,
    //             ip_namespace,
    //             tracker_pk,
    //             mut tracker_signer,
    //             cfg,
    //             ..
    //         } = setup_actor(context.clone(), cfg_initial);

    //         let (_, pk1) = new_signer_and_pk(1);
    //         oracle
    //             .register(0, vec![tracker_pk.clone(), pk1.clone()])
    //             .await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         let self_info = new_peer_info(
    //             &mut tracker_signer,
    //             &ip_namespace,
    //             cfg.address,
    //             context.current().epoch_millis(),
    //             Some(tracker_pk.clone()),
    //             false,
    //         );

    //         let (peer_mailbox_s1, mut peer_receiver_s1) = authenticated::Mailbox::test();
    //         mailbox
    //             .peers(vec![self_info], peer_mailbox_s1.clone())
    //             .await;

    //         assert!(
    //             matches!(peer_receiver_s1.next().await, Some(peer::Message::Kill)),
    //             "Peer should be killed for sending tracker's own info"
    //         );
    //     });
    // }

    // #[test]
    // fn test_handle_bit_vec_for_unknown_index_sends_no_peers() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
    //         let TestHarness {
    //             mut mailbox,
    //             mut oracle,
    //             tracker_pk,
    //             ..
    //         } = setup_actor(context.clone(), cfg_initial);

    //         let (_, pk1) = new_signer_and_pk(1);
    //         oracle.register(0, vec![tracker_pk, pk1.clone()]).await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         let (peer_mailbox_pk1, mut peer_receiver_pk1) = authenticated::Mailbox::test();
    //         let bit_vec_unknown_idx = types::BitVec {
    //             index: 99,
    //             bits: UtilsBitVec::ones(1),
    //         };

    //         let _r1 = connect_to_peer(
    //             &mut mailbox,
    //             &pk1,
    //             &peer_mailbox_pk1,
    //             &mut peer_receiver_pk1,
    //         )
    //         .await;

    //         // Peer lets us know it received a bit vector
    //         mailbox
    //             .bit_vec(bit_vec_unknown_idx, peer_mailbox_pk1.clone())
    //             .await;

    //         // No message is sent back to the peer
    //         assert!(peer_receiver_pk1.try_next().is_err());
    //     });
    // }

    // #[test]
    // fn test_block_peer_standard_behavior() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
    //         let TestHarness {
    //             mut mailbox,
    //             mut oracle,
    //             tracker_pk,
    //             ..
    //         } = setup_actor(context.clone(), cfg_initial);

    //         let (_s1_signer, pk1) = new_signer_and_pk(1);
    //         oracle
    //             .register(0, vec![tracker_pk.clone(), pk1.clone()])
    //             .await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         oracle.block(pk1.clone()).await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         let (peer_mailbox_pk1, mut peer_receiver_pk1) = authenticated::Mailbox::test();
    //         mailbox
    //             .construct(pk1.clone(), peer_mailbox_pk1.clone())
    //             .await;

    //         assert!(matches!(
    //             peer_receiver_pk1.next().await,
    //             Some(peer::Message::Kill)
    //         ));

    //         let dialable_peers = mailbox.dialable().await;
    //         assert!(!dialable_peers.iter().any(|peer| peer == &pk1));
    //     });
    // }

    // #[test]
    // fn test_block_peer_already_blocked_is_noop() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
    //         let TestHarness {
    //             mut mailbox,
    //             mut oracle,
    //             tracker_pk,
    //             ..
    //         } = setup_actor(context.clone(), cfg_initial);

    //         let (_s1_signer, pk1) = new_signer_and_pk(1);
    //         oracle
    //             .register(0, vec![tracker_pk.clone(), pk1.clone()])
    //             .await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         oracle.block(pk1.clone()).await;
    //         context.sleep(Duration::from_millis(10)).await;
    //         oracle.block(pk1.clone()).await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         let (peer_mailbox_pk1, mut peer_receiver_pk1) = authenticated::Mailbox::test();
    //         mailbox
    //             .construct(pk1.clone(), peer_mailbox_pk1.clone())
    //             .await;
    //         assert!(matches!(
    //             peer_receiver_pk1.next().await,
    //             Some(peer::Message::Kill)
    //         ));
    //     });
    // }

    #[test]
    fn test_block_peer_non_existent_is_noop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
            let TestHarness { mut oracle, .. } = setup_actor(context.clone(), cfg_initial);

            let (_s1_signer, pk_non_existent) = new_signer_and_pk(100);

            oracle.block(pk_non_existent).await;
            context.sleep(Duration::from_millis(10)).await;
        });
    }

    // #[test]
    // fn test_handle_peers_learns_unknown_peer() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
    //         let TestHarness {
    //             mut mailbox,
    //             mut oracle,
    //             ip_namespace,
    //             tracker_pk,
    //             ..
    //         } = setup_actor(context.clone(), cfg_initial);

    //         let (_, pk1) = new_signer_and_pk(1);
    //         let (mut s2_signer, pk2) = new_signer_and_pk(2);

    //         oracle
    //             .register(0, vec![tracker_pk.clone(), pk1.clone()])
    //             .await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         let pk2_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 2002);
    //         let pk2_timestamp = context.current().epoch_millis();
    //         let pk2_info = new_peer_info(
    //             &mut s2_signer,
    //             &ip_namespace,
    //             pk2_addr,
    //             pk2_timestamp,
    //             Some(pk2.clone()),
    //             false,
    //         );

    //         let mut set1 = vec![tracker_pk.clone(), pk1.clone(), pk2.clone()];
    //         set1.sort();
    //         oracle.register(1, set1.clone()).await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         let (peer_mailbox_s1, mut peer_receiver_s1) = authenticated::Mailbox::test();
    //         let (peer_mailbox_s2, mut peer_receiver_s2) = authenticated::Mailbox::test();
    //         mailbox
    //             .peers(vec![pk2_info.clone()], peer_mailbox_s1.clone())
    //             .await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         let _r1 =
    //             connect_to_peer(&mut mailbox, &pk1, &peer_mailbox_s1, &mut peer_receiver_s1).await;
    //         let _r2 =
    //             connect_to_peer(&mut mailbox, &pk2, &peer_mailbox_s2, &mut peer_receiver_s2).await;

    //         // Act as if pk1 received a bit vector where pk2 is not known.
    //         let mut bv = UtilsBitVec::zeroes(set1.len());
    //         let idx_tracker_in_set1 = set1.iter().position(|p| p == &tracker_pk).unwrap();
    //         let idx_pk1_in_set1 = set1.iter().position(|p| p == &pk1).unwrap();
    //         bv.set(idx_tracker_in_set1);
    //         bv.set(idx_pk1_in_set1);
    //         mailbox
    //             .bit_vec(
    //                 types::BitVec { index: 1, bits: bv },
    //                 peer_mailbox_s1.clone(),
    //             )
    //             .await;
    //         match peer_receiver_s1.next().await {
    //             Some(peer::Message::Peers(received_peers_info)) => {
    //                 assert_eq!(received_peers_info.len(), 1);
    //                 let received_pk2_info = &received_peers_info[0];
    //                 assert_eq!(received_pk2_info.public_key, pk2);
    //                 assert_eq!(received_pk2_info.socket, pk2_addr);
    //                 assert_eq!(received_pk2_info.timestamp, pk2_timestamp);
    //             }
    //             _ => panic!("pk1 did not receive expected PeerInfo for pk2",),
    //         }
    //     });
    // }

    // #[test]
    // fn test_handle_peers_rejects_older_info_for_known_peer() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
    //         let TestHarness {
    //             mut mailbox,
    //             mut oracle,
    //             ip_namespace,
    //             tracker_pk,
    //             cfg,
    //             ..
    //         } = setup_actor(context.clone(), cfg_initial);

    //         let ts_new = context.current().epoch_millis();
    //         let ts_old = ts_new.saturating_sub(cfg.synchrony_bound.as_millis() as u64 / 2);

    //         let (_, pk1) = new_signer_and_pk(1);
    //         let (mut s2_signer, pk2) = new_signer_and_pk(2);

    //         let peer_set_0_peers = vec![tracker_pk.clone(), pk1.clone(), pk2.clone()];
    //         oracle.register(0, peer_set_0_peers.clone()).await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         let pk2_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 2002);
    //         let pk2_info_initial = new_peer_info(
    //             &mut s2_signer,
    //             &ip_namespace,
    //             pk2_addr,
    //             ts_new,
    //             Some(pk2.clone()),
    //             false,
    //         );

    //         let (peer_mailbox_s1, mut peer_receiver_s1) = authenticated::Mailbox::test();
    //         let _r1 =
    //             connect_to_peer(&mut mailbox, &pk1, &peer_mailbox_s1, &mut peer_receiver_s1).await;

    //         // Connect to pk2
    //         let (peer_mailbox_s2, mut peer_receiver_s2) = authenticated::Mailbox::test();
    //         let _r2 =
    //             connect_to_peer(&mut mailbox, &pk2, &peer_mailbox_s2, &mut peer_receiver_s2).await;

    //         mailbox
    //             .peers(vec![pk2_info_initial.clone()], peer_mailbox_s1.clone())
    //             .await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         let pk2_info_older = new_peer_info(
    //             &mut s2_signer,
    //             &ip_namespace,
    //             pk2_addr,
    //             ts_old,
    //             Some(pk2.clone()),
    //             false,
    //         );
    //         mailbox
    //             .peers(vec![pk2_info_older], peer_mailbox_s1.clone())
    //             .await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         let mut sorted_set0_peers = peer_set_0_peers.clone();
    //         sorted_set0_peers.sort();
    //         let mut knowledge_for_set0 = UtilsBitVec::zeroes(sorted_set0_peers.len());
    //         let idx_tracker_in_set0 = sorted_set0_peers
    //             .iter()
    //             .position(|p| p == &tracker_pk)
    //             .unwrap();
    //         let idx_pk1_in_set0 = sorted_set0_peers.iter().position(|p| p == &pk1).unwrap();
    //         knowledge_for_set0.set(idx_tracker_in_set0);
    //         knowledge_for_set0.set(idx_pk1_in_set0);

    //         let bit_vec_from_pk1 = types::BitVec {
    //             index: 0,
    //             bits: knowledge_for_set0,
    //         };
    //         mailbox
    //             .bit_vec(bit_vec_from_pk1, peer_mailbox_s1.clone())
    //             .await;

    //         match peer_receiver_s1.next().await {
    //             Some(peer::Message::Peers(received_peers_info)) => {
    //                 assert_eq!(received_peers_info.len(), 1);
    //                 let received_pk2_info = &received_peers_info[0];
    //                 assert_eq!(received_pk2_info.public_key, pk2);
    //                 assert_eq!(received_pk2_info.timestamp, ts_new);
    //             }
    //             _ => panic!("pk1 did not receive PeerInfo as expected"),
    //         }
    //     });
    // }

    #[test]
    fn test_listen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
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
                default_test_config(PrivateKey::from_seed(0), vec![(boot_pk.clone(), boot_addr)]);
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
                default_test_config(PrivateKey::from_seed(0), vec![(boot_pk.clone(), boot_addr)]);

            let TestHarness { mut mailbox, .. } = setup_actor(context.clone(), cfg_initial);

            let reservation = mailbox.dial(boot_pk.clone()).await;
            assert!(reservation.is_some());
            if let Some(res) = reservation {
                match res.metadata() {
                    crate::authenticated::lookup::actors::tracker::Metadata::Dialer(pk, addr) => {
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

    // #[test]
    // fn test_validate_kill_on_too_many() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let mut cfg = default_test_config(PrivateKey::from_seed(0), Vec::new());
    //         let max_gossip = 2;
    //         cfg.peer_gossip_max_count = max_gossip;
    //         let TestHarness {
    //             mut mailbox,
    //             ip_namespace,
    //             ..
    //         } = setup_actor(context.clone(), cfg);

    //         let (mut s1, _pk1) = new_signer_and_pk(1);
    //         let (_s2, pk2) = new_signer_and_pk(2);
    //         let (_s3, pk3) = new_signer_and_pk(3);
    //         let (_s4, pk4) = new_signer_and_pk(4);

    //         let (peer_mailbox, mut peer_receiver) = authenticated::Mailbox::test();
    //         let infos = vec![
    //             new_peer_info(
    //                 &mut s1,
    //                 &ip_namespace,
    //                 SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1002),
    //                 context.current().epoch_millis(),
    //                 Some(pk2),
    //                 false,
    //             ),
    //             new_peer_info(
    //                 &mut s1,
    //                 &ip_namespace,
    //                 SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1003),
    //                 context.current().epoch_millis(),
    //                 Some(pk3),
    //                 false,
    //             ),
    //             new_peer_info(
    //                 &mut s1,
    //                 &ip_namespace,
    //                 SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1004),
    //                 context.current().epoch_millis(),
    //                 Some(pk4),
    //                 false,
    //             ),
    //         ];
    //         assert!(infos.len() > max_gossip);
    //         mailbox.peers(infos, peer_mailbox.clone()).await;
    //         assert!(matches!(
    //             peer_receiver.next().await,
    //             Some(peer::Message::Kill)
    //         ));
    //     });
    // }

    // #[test]
    // fn test_validate_kill_on_private_ip_disallowed() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let mut cfg = default_test_config(PrivateKey::from_seed(0), Vec::new());
    //         cfg.allow_private_ips = false;
    //         let TestHarness {
    //             mut mailbox,
    //             ip_namespace,
    //             ..
    //         } = setup_actor(context.clone(), cfg);

    //         let (mut s2, pk2) = new_signer_and_pk(2);
    //         let private_socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
    //         let info = new_peer_info(
    //             &mut s2,
    //             &ip_namespace,
    //             private_socket,
    //             context.current().epoch_millis(),
    //             Some(pk2),
    //             false,
    //         );

    //         let (peer_mailbox, mut peer_receiver) = authenticated::Mailbox::test();
    //         mailbox.peers(vec![info], peer_mailbox.clone()).await;
    //         assert!(matches!(
    //             peer_receiver.next().await,
    //             Some(peer::Message::Kill)
    //         ));
    //     });
    // }

    // #[test]
    // fn test_validate_kill_on_synchrony_bound() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
    //         let TestHarness {
    //             mut mailbox,
    //             ip_namespace,
    //             cfg,
    //             ..
    //         } = setup_actor(context.clone(), cfg_initial);

    //         let (mut s2, pk2) = new_signer_and_pk(2);
    //         let far_future_ts =
    //             context.current().epoch_millis() + cfg.synchrony_bound.as_millis() as u64 + 1000;
    //         let info = new_peer_info(
    //             &mut s2,
    //             &ip_namespace,
    //             SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1002),
    //             far_future_ts,
    //             Some(pk2),
    //             false,
    //         );

    //         let (peer_mailbox, mut peer_receiver) = authenticated::Mailbox::test();
    //         mailbox.peers(vec![info], peer_mailbox.clone()).await;
    //         assert!(matches!(
    //             peer_receiver.next().await,
    //             Some(peer::Message::Kill)
    //         ));
    //     });
    // }

    // #[test]
    // fn test_validate_kill_on_invalid_signature() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
    //         let TestHarness {
    //             mut mailbox,
    //             mut oracle,
    //             ip_namespace,
    //             tracker_pk,
    //             ..
    //         } = setup_actor(context.clone(), cfg_initial);

    //         let (_, pk1) = new_signer_and_pk(1);
    //         let (mut s2, pk2) = new_signer_and_pk(2);
    //         oracle.register(0, vec![tracker_pk, pk1, pk2.clone()]).await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         let info = new_peer_info(
    //             &mut s2,
    //             &ip_namespace,
    //             SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1002),
    //             context.current().epoch_millis(),
    //             Some(pk2),
    //             true,
    //         );

    //         let (peer_mailbox, mut peer_receiver) = authenticated::Mailbox::test();
    //         mailbox.peers(vec![info], peer_mailbox.clone()).await;
    //         assert!(matches!(
    //             peer_receiver.next().await,
    //             Some(peer::Message::Kill)
    //         ));
    //     });
    // }

    // #[test]
    // fn test_bitvec_kill_on_length_mismatch() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
    //         let TestHarness {
    //             mut mailbox,
    //             mut oracle,
    //             tracker_pk,
    //             ..
    //         } = setup_actor(context.clone(), cfg_initial);

    //         let (_s1, pk1) = new_signer_and_pk(1);
    //         let (_s2, pk2) = new_signer_and_pk(2);
    //         oracle
    //             .register(0, vec![tracker_pk, pk1.clone(), pk2.clone()])
    //             .await;
    //         context.sleep(Duration::from_millis(10)).await;

    //         let (peer_mailbox, mut peer_receiver) = authenticated::Mailbox::test();
    //         let invalid_bit_vec = types::BitVec {
    //             index: 0,
    //             bits: UtilsBitVec::ones(2),
    //         };
    //         mailbox.bit_vec(invalid_bit_vec, peer_mailbox.clone()).await;
    //         assert!(matches!(
    //             peer_receiver.next().await,
    //             Some(peer::Message::Kill)
    //         ));
    //     });
    // }
}
