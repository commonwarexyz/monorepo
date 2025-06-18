use super::{
    directory::{self, Directory},
    ingress::{Mailbox, Message, Oracle},
    Config,
};
use crate::authenticated::lookup::actors::{peer, tracker::ingress::Releaser};
use commonware_cryptography::Signer;
use commonware_runtime::{Clock, Handle, Metrics as RuntimeMetrics, Spawner};
use futures::{channel::mpsc, StreamExt};
use governor::clock::Clock as GClock;
use rand::Rng;
use std::collections::HashMap;
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

    /// Maps a peer's public key to its mailbox.
    /// Set when a peer connects and cleared when it is blocked or released.
    mailboxes: HashMap<C::PublicKey, peer::Mailbox>,
}

impl<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: Signer> Actor<E, C> {
    /// Create a new tracker [Actor] from the given `context` and `cfg`.
    #[allow(clippy::type_complexity)]
    pub fn new(
        context: E,
        cfg: Config<C>,
    ) -> (Self, Mailbox<E, C::PublicKey>, Oracle<E, C::PublicKey>) {
        // General initialization
        let directory_cfg = directory::Config {
            max_sets: cfg.tracked_peer_sets,
            rate_limit: cfg.allowed_connection_rate_per_peer,
            allow_private_ips: cfg.allow_private_ips,
        };

        // Create the mailboxes
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        let mailbox = Mailbox::new(sender.clone());
        let releaser = Releaser::new(sender.clone());
        let oracle = Oracle::new(sender);

        // Create the directory
        let myself = (cfg.crypto.public_key(), cfg.address);
        let directory = Directory::init(context.clone(), myself, directory_cfg, releaser);

        (
            Self {
                context,
                max_peer_set_size: cfg.max_peer_set_size,
                receiver,
                directory,
                mailboxes: HashMap::new(),
            },
            mailbox,
            oracle,
        )
    }

    /// Start the actor and run it in the background.
    pub fn start(mut self) -> Handle<()> {
        self.context.spawn_ref()(self.run())
    }

    async fn run(mut self) {
        while let Some(msg) = self.receiver.next().await {
            match msg {
                Message::Register { index, peers } => {
                    // Ensure that peer set is not too large.
                    // Panic since there is no way to recover from this.
                    let len = peers.len();
                    let max = self.max_peer_set_size;
                    assert!(len <= max, "peer set too large: {} > {}", len, max);

                    // If we deleted peers, release them.
                    for peer in self.directory.add_set(index, peers) {
                        if let Some(mut mailbox) = self.mailboxes.remove(&peer) {
                            mailbox.kill().await;
                        }
                    }
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
                    self.mailboxes.insert(public_key, peer);
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

                    // Kill the peer if we're connected to it.
                    if let Some(mut peer) = self.mailboxes.remove(&public_key) {
                        peer.kill().await;
                    }
                }
                Message::Release { metadata } => {
                    // Clear the peer handle if it exists
                    self.mailboxes.remove(metadata.public_key());

                    // Release the peer
                    self.directory.release(metadata);
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
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        PrivateKeyExt as _, Signer,
    };
    use commonware_runtime::{
        deterministic::{self},
        Clock, Runner,
    };
    use commonware_utils::NZU32;
    use governor::Quota;
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    // Test Configuration Setup
    fn default_test_config<C: Signer>(crypto: C) -> Config<C> {
        Config {
            crypto,
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            mailbox_size: 32,
            tracked_peer_sets: 2,
            allowed_connection_rate_per_peer: Quota::per_second(NZU32!(5)),
            max_peer_set_size: 128,
            allow_private_ips: true,
        }
    }

    // Helper to create Ed25519 signer and public key
    fn new_signer_and_pk(seed: u64) -> (PrivateKey, PublicKey) {
        let signer = PrivateKey::from_seed(seed);
        let pk = signer.public_key();
        (signer, pk)
    }

    // Test Harness
    struct TestHarness {
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
        runner_context.spawn(|_| actor.run());

        TestHarness {
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

    #[test]
    fn test_block_peer_standard_behavior() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_, pk) = new_signer_and_pk(1);
            let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1001);
            oracle.register(0, vec![(pk.clone(), addr)]).await;
            context.sleep(Duration::from_millis(10)).await;

            let dialable_peers = mailbox.dialable().await;
            assert!(dialable_peers.iter().any(|peer| peer == &pk));

            oracle.block(pk.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let dialable_peers = mailbox.dialable().await;
            assert!(!dialable_peers.iter().any(|peer| peer == &pk));
        });
    }

    #[test]
    fn test_block_peer_already_blocked_is_noop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_, pk1) = new_signer_and_pk(1);
            let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1001);
            oracle.register(0, vec![(pk1.clone(), addr)]).await;
            context.sleep(Duration::from_millis(10)).await;

            oracle.block(pk1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let dialable_peers = mailbox.dialable().await;
            assert!(!dialable_peers.iter().any(|peer| peer == &pk1));

            oracle.block(pk1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let dialable_peers = mailbox.dialable().await;
            assert!(!dialable_peers.iter().any(|peer| peer == &pk1));
        });
    }

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

    #[test]
    fn test_block_clears_peer_mailbox_and_only_kills_once() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // 1) Setup actor
            let cfg = default_test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg);

            // 2) Register & connect an authorized peer
            let (_peer_signer, peer_pk) = new_signer_and_pk(1);
            let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
            oracle.register(0, vec![(peer_pk.clone(), peer_addr)]).await;
            // let the register take effect
            context.sleep(Duration::from_millis(10)).await;

            let reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation.is_some());

            let (peer_mailbox, mut peer_rx) = peer::Mailbox::test();
            mailbox.connect(peer_pk.clone(), peer_mailbox).await;

            // 3) Block it → should see exactly one Kill
            oracle.block(peer_pk.clone()).await;
            context.sleep(Duration::from_millis(10)).await;
            assert!(
                matches!(peer_rx.next().await, Some(peer::Message::Kill)),
                "connected peer must be killed on first Block"
            );

            // 4) Block again → mailbox was removed, so no new Kill
            oracle.block(peer_pk.clone()).await;
            context.sleep(Duration::from_millis(10)).await;
            assert!(
                peer_rx.next().await.is_none(),
                "no kill after handle has been cleared"
            );
        });
    }

    #[test]
    fn test_register_disconnects_removed_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (my_sk, my_pk) = new_signer_and_pk(0);
            let my_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9000);

            let pk_1 = new_signer_and_pk(1).1;
            let addr_1 = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9001);
            let pk_2 = new_signer_and_pk(2).1;
            let addr_2 = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9002);

            let mut cfg = default_test_config(my_sk);
            cfg.tracked_peer_sets = 1;

            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg);

            // Register set with myself and one other peer
            oracle
                .register(0, vec![(my_pk.clone(), my_addr), (pk_1.clone(), addr_1)])
                .await;
            // let the register take effect
            context.sleep(Duration::from_millis(10)).await;

            // Mark peer as connected
            let reservation = mailbox.listen(pk_1.clone()).await;
            assert!(reservation.is_some());

            let (peer_mailbox, mut peer_rx) = peer::Mailbox::test();
            mailbox.connect(my_pk.clone(), peer_mailbox).await;

            // Register another set which doesn't include first peer
            oracle.register(1, vec![(pk_2.clone(), addr_2)]).await;
            // let the register take effect

            // The first peer should be have received a kill message because its
            // peer set was removed because `tracked_peer_sets` is 1.
            assert!(matches!(peer_rx.next().await, Some(peer::Message::Kill)),)
        });
    }
}
