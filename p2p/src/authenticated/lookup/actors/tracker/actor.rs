use super::{
    directory::{self, Directory},
    ingress::{Mailbox, Message, Oracle},
    Config,
};
use commonware_cryptography::Signer;
use commonware_runtime::{Clock, Handle, Metrics as RuntimeMetrics, Spawner};
use futures::{channel::mpsc, StreamExt};
use governor::clock::Clock as GClock;
use rand::Rng;
use tracing::debug;

/// The tracker actor that manages peer discovery and connection reservations.
pub struct Actor<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: Signer> {
    context: E,

    // ---------- Configuration ----------
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
        let myself = (cfg.crypto.public_key(), cfg.address);

        // General initialization
        let directory_cfg = directory::Config {
            mailbox_size: cfg.mailbox_size,
            max_sets: cfg.tracked_peer_sets,
            rate_limit: cfg.allowed_connection_rate_per_peer,
        };
        let directory = Directory::init(context.clone(), myself, directory_cfg);
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);

        (
            Self {
                context,
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
                    mut peer,
                } => {
                    // Kill if peer is not authorized
                    if !self.directory.allowed(&public_key) {
                        peer.kill().await;
                        continue;
                    }

                    // Mark the record as connected
                    self.directory.connect(&public_key);

                    // TODO danlaine: do we need to send the peer anything here?
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
        authenticated::lookup::actors::peer,
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
    fn default_test_config<C: Signer>(crypto: C) -> Config<C> {
        Config {
            crypto,
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            mailbox_size: 32,
            tracked_peer_sets: 2,
            allowed_connection_rate_per_peer: Quota::per_second(NZU32!(5)),
            max_peer_set_size: 128,
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
            let cfg_initial = default_test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mut oracle,
                cfg,
                mut mailbox,
                ..
            } = setup_actor(context.clone(), cfg_initial);
            let too_many_peers: Vec<(PublicKey, SocketAddr)> = (1..=(cfg.max_peer_set_size + 1)
                as u64)
                .map(|i| {
                    (
                        new_signer_and_pk(i).1,
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                    )
                })
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
            let cfg = default_test_config(PrivateKey::from_seed(0));
            let TestHarness { mut mailbox, .. } = setup_actor(context.clone(), cfg);

            let (_unauth_signer, unauth_pk) = new_signer_and_pk(1);
            let (peer_mailbox, mut peer_receiver) = peer::Mailbox::test();

            // Connect as listener
            mailbox.connect(unauth_pk.clone(), peer_mailbox).await;
            assert!(
                matches!(peer_receiver.next().await, Some(peer::Message::Kill)),
                "Unauthorized peer should be killed on Connect"
            );
        });
    }

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
            let cfg_initial = default_test_config(PrivateKey::from_seed(0));
            let TestHarness { mut oracle, .. } = setup_actor(context.clone(), cfg_initial);

            let (_s1_signer, pk_non_existent) = new_signer_and_pk(100);

            oracle.block(pk_non_existent).await;
            context.sleep(Duration::from_millis(10)).await;
        });
    }

    #[test]
    fn test_listen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_peer_signer, peer_pk) = new_signer_and_pk(1);
            let peer_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8080);

            let reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation.is_none());

            oracle.register(0, vec![(peer_pk.clone(), peer_addr)]).await;
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
            let cfg_initial = default_test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);
            oracle.register(0, vec![(boot_pk.clone(), boot_addr)]).await;

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
            let cfg_initial = default_test_config(PrivateKey::from_seed(0));

            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            oracle.register(0, vec![(boot_pk.clone(), boot_addr)]).await;

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
}
