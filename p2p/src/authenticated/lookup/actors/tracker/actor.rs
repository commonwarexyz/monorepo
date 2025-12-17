use super::{
    directory::{self, Directory},
    ingress::{Message, Oracle},
    Config,
};
use crate::authenticated::{
    lookup::actors::{peer, tracker::ingress::Releaser},
    mailbox::UnboundedMailbox,
    Mailbox,
};
use commonware_cryptography::Signer;
use commonware_macros::select_loop;
use commonware_runtime::{
    spawn_cell, Clock, ContextCell, Handle, Metrics as RuntimeMetrics, Spawner,
};
use commonware_utils::ordered::Set;
use futures::{channel::mpsc, StreamExt};
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};
use tracing::debug;

/// The tracker actor that manages peer discovery and connection reservations.
pub struct Actor<E: Spawner + Rng + Clock + RuntimeMetrics, C: Signer> {
    context: ContextCell<E>,

    // ---------- Message-Passing ----------
    /// The unbounded mailbox for the actor.
    ///
    /// We use this to support sending a [`Message::Release`] message to the actor
    /// during [`Drop`]. While this channel is unbounded, it is practically bounded by
    /// the number of peers we can connect to at one time.
    receiver: mpsc::UnboundedReceiver<Message<C::PublicKey>>,

    /// The mailbox for the listener.
    listener: Mailbox<HashSet<IpAddr>>,

    // ---------- State ----------
    /// Tracks peer sets and peer connectivity information.
    directory: Directory<E, C::PublicKey>,

    /// Maps a peer's public key to its mailbox.
    /// Set when a peer connects and cleared when it is blocked or released.
    mailboxes: HashMap<C::PublicKey, Mailbox<peer::Message>>,

    /// Subscribers to peer set updates.
    #[allow(clippy::type_complexity)]
    subscribers: Vec<mpsc::UnboundedSender<(u64, Set<C::PublicKey>, Set<C::PublicKey>)>>,
}

impl<E: Spawner + Rng + Clock + RuntimeMetrics, C: Signer> Actor<E, C> {
    /// Create a new tracker [Actor] from the given `context` and `cfg`.
    #[allow(clippy::type_complexity)]
    pub fn new(
        context: E,
        cfg: Config<C>,
    ) -> (
        Self,
        UnboundedMailbox<Message<C::PublicKey>>,
        Oracle<C::PublicKey>,
    ) {
        // General initialization
        let directory_cfg = directory::Config {
            max_sets: cfg.tracked_peer_sets,
            rate_limit: cfg.allowed_connection_rate_per_peer,
            allow_private_ips: cfg.allow_private_ips,
        };

        // Create the mailboxes
        let (mailbox, receiver) = UnboundedMailbox::new();
        let oracle = Oracle::new(mailbox.clone());
        let releaser = Releaser::new(mailbox.clone());

        // Create the directory
        let directory = Directory::init(
            context.with_label("directory"),
            cfg.crypto.public_key(),
            directory_cfg,
            releaser,
        );

        (
            Self {
                context: ContextCell::new(context),
                receiver,
                directory,
                listener: cfg.listener,
                mailboxes: HashMap::new(),
                subscribers: Vec::new(),
            },
            mailbox,
            oracle,
        )
    }

    /// Start the actor and run it in the background.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping tracker");
            },
            msg = self.receiver.next() => {
                let Some(msg) = msg else {
                    debug!("mailbox closed, stopping tracker");
                    break;
                };
                self.handle_msg(msg).await;
            }
        }
    }

    /// Handle a [`Message`].
    async fn handle_msg(&mut self, msg: Message<C::PublicKey>) {
        match msg {
            Message::Register { index, peers } => {
                // If we are no longer interested in a peer, release them.
                let peer_keys: Set<C::PublicKey> = peers.keys().clone();
                let Some(deleted) = self.directory.add_set(index, peers) else {
                    return;
                };
                for peer in deleted {
                    if let Some(mut mailbox) = self.mailboxes.remove(&peer) {
                        mailbox.kill().await;
                    }
                }

                // Send the updated registered IP addresses to the listener.
                let _ = self.listener.send(self.directory.registered()).await;

                // Notify all subscribers about the new peer set
                self.subscribers.retain(|subscriber| {
                    subscriber
                        .unbounded_send((index, peer_keys.clone(), self.directory.tracked()))
                        .is_ok()
                });
            }
            Message::PeerSet { index, responder } => {
                // Send the peer set at the given index.
                let _ = responder.send(self.directory.get_set(&index).cloned());
            }
            Message::Subscribe { responder } => {
                // Create a new subscription channel
                let (sender, receiver) = mpsc::unbounded();

                // Send the latest peer set immediately
                if let Some(latest_set_id) = self.directory.latest_set_index() {
                    let latest_set = self.directory.get_set(&latest_set_id).cloned().unwrap();
                    sender
                        .unbounded_send((latest_set_id, latest_set, self.directory.tracked()))
                        .ok();
                }
                self.subscribers.push(sender);

                // Return the receiver to the caller
                let _ = responder.send(receiver);
            }
            Message::Connect {
                public_key,
                mut peer,
            } => {
                // Kill if peer is not authorized
                if !self.directory.allowed(&public_key) {
                    peer.kill().await;
                    return;
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
            Message::Listenable {
                public_key,
                responder,
            } => {
                let _ = responder.send(self.directory.listenable(&public_key));
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

                // Send the updated registered IP addresses to the listener.
                let _ = self.listener.send(self.directory.registered()).await;
            }
            Message::Release { metadata } => {
                // Clear the peer handle if it exists
                self.mailboxes.remove(metadata.public_key());

                // Release the peer
                self.directory.release(metadata);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authenticated::lookup::actors::peer,
        Blocker,
        Manager,
        // Blocker is implicitly available via oracle.block() due to Oracle implementing crate::Blocker
    };
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_runtime::{
        deterministic::{self},
        Clock, Quota, Runner,
    };
    use commonware_utils::NZU32;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    // Test Configuration Setup
    fn default_test_config<C: Signer>(crypto: C) -> (Config<C>, mpsc::Receiver<HashSet<IpAddr>>) {
        let (registered_ips_sender, registered_ips_receiver) = Mailbox::new(1);
        (
            Config {
                crypto,
                tracked_peer_sets: 2,
                allowed_connection_rate_per_peer: Quota::per_second(NZU32!(5)),
                allow_private_ips: true,
                listener: registered_ips_sender,
            },
            registered_ips_receiver,
        )
    }

    // Helper to create Ed25519 signer and public key
    fn new_signer_and_pk(seed: u64) -> (PrivateKey, PublicKey) {
        let signer = PrivateKey::from_seed(seed);
        let pk = signer.public_key();
        (signer, pk)
    }

    // Test Harness
    struct TestHarness {
        mailbox: UnboundedMailbox<Message<PublicKey>>,
        oracle: Oracle<PublicKey>,
    }

    fn setup_actor(
        runner_context: deterministic::Context,
        cfg_to_clone: Config<PrivateKey>, // Pass by value to allow cloning
    ) -> TestHarness {
        // Actor::new takes ownership, so clone again if cfg_to_clone is needed later
        let (actor, mailbox, oracle) = Actor::new(runner_context, cfg_to_clone);
        actor.start();

        TestHarness { mailbox, oracle }
    }

    #[test]
    fn test_connect_unauthorized_peer_is_killed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (cfg, _) = default_test_config(PrivateKey::from_seed(0));
            let TestHarness { mut mailbox, .. } = setup_actor(context.clone(), cfg);

            let (_unauth_signer, unauth_pk) = new_signer_and_pk(1);
            let (peer_mailbox, mut peer_receiver) = Mailbox::new(1);

            // Connect as listener
            mailbox.connect(unauth_pk.clone(), peer_mailbox);
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
            let (cfg_initial, _) = default_test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_, pk) = new_signer_and_pk(1);
            let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1001);
            oracle
                .update(0, [(pk.clone(), addr)].try_into().unwrap())
                .await;
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
            let (cfg_initial, _) = default_test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_, pk1) = new_signer_and_pk(1);
            let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1001);
            oracle
                .update(0, [(pk1.clone(), addr)].try_into().unwrap())
                .await;
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
            let (cfg_initial, _) = default_test_config(PrivateKey::from_seed(0));
            let TestHarness { mut oracle, .. } = setup_actor(context.clone(), cfg_initial);

            let (_s1_signer, pk_non_existent) = new_signer_and_pk(100);

            oracle.block(pk_non_existent).await;
            context.sleep(Duration::from_millis(10)).await;
        });
    }

    #[test]
    fn test_listenable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (peer_signer, peer_pk) = new_signer_and_pk(1);
            let peer_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1001);
            let (_peer_signer2, peer_pk2) = new_signer_and_pk(2);
            let peer_addr2 = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1002);
            let (_peer_signer3, peer_pk3) = new_signer_and_pk(3);
            let (cfg_initial, _) = default_test_config(peer_signer);
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            // None listenable because not registered
            assert!(!mailbox.listenable(peer_pk.clone()).await);
            assert!(!mailbox.listenable(peer_pk2.clone()).await);
            assert!(!mailbox.listenable(peer_pk3.clone()).await);

            oracle
                .update(
                    0,
                    [(peer_pk.clone(), peer_addr), (peer_pk2.clone(), peer_addr2)]
                        .try_into()
                        .unwrap(),
                )
                .await;
            context.sleep(Duration::from_millis(10)).await;

            // Not listenable because self
            assert!(!mailbox.listenable(peer_pk).await);
            // Listenable because registered
            assert!(mailbox.listenable(peer_pk2).await);
            // Not listenable because not registered
            assert!(!mailbox.listenable(peer_pk3).await);
        });
    }

    #[test]
    fn test_listen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (cfg_initial, _) = default_test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_peer_signer, peer_pk) = new_signer_and_pk(1);
            let peer_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8080);

            let reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation.is_none());

            oracle
                .update(0, [(peer_pk.clone(), peer_addr)].try_into().unwrap())
                .await;
            context.sleep(Duration::from_millis(10)).await; // Allow register to process

            assert!(mailbox.listenable(peer_pk.clone()).await);

            let reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation.is_some());

            assert!(!mailbox.listenable(peer_pk.clone()).await);

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
            let (cfg_initial, _) = default_test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);
            oracle
                .update(0, [(boot_pk.clone(), boot_addr)].try_into().unwrap())
                .await;

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
            let (cfg_initial, _) = default_test_config(PrivateKey::from_seed(0));

            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            oracle
                .update(0, [(boot_pk.clone(), boot_addr)].try_into().unwrap())
                .await;

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
            let (cfg, _) = default_test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg);

            // 2) Register & connect an authorized peer
            let (_peer_signer, peer_pk) = new_signer_and_pk(1);
            let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
            oracle
                .update(0, [(peer_pk.clone(), peer_addr)].try_into().unwrap())
                .await;
            // let the register take effect
            context.sleep(Duration::from_millis(10)).await;

            let reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation.is_some());

            let (peer_mailbox, mut peer_rx) = Mailbox::new(1);
            mailbox.connect(peer_pk.clone(), peer_mailbox);

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
            let addr_2 = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 9002);

            let (mut cfg, mut listener_receiver) = default_test_config(my_sk);
            cfg.tracked_peer_sets = 1;

            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg);

            // Register set with myself and one other peer
            oracle
                .update(
                    0,
                    [(my_pk.clone(), my_addr), (pk_1.clone(), addr_1)]
                        .try_into()
                        .unwrap(),
                )
                .await;
            // let the register take effect
            context.sleep(Duration::from_millis(10)).await;

            // Wait for a listener update
            let registered_ips = listener_receiver.next().await.unwrap();
            assert!(registered_ips.contains(&my_addr.ip()));
            assert!(registered_ips.contains(&addr_1.ip()));
            assert!(!registered_ips.contains(&addr_2.ip()));

            // Mark peer as connected
            let reservation = mailbox.listen(pk_1.clone()).await;
            assert!(reservation.is_some());

            let (peer_mailbox, mut peer_rx) = Mailbox::new(1);
            mailbox.connect(my_pk.clone(), peer_mailbox);

            // Register another set which doesn't include first peer
            oracle
                .update(1, [(pk_2.clone(), addr_2)].try_into().unwrap())
                .await;

            // Wait for a listener update
            let registered_ips = listener_receiver.next().await.unwrap();
            assert!(!registered_ips.contains(&my_addr.ip()));
            assert!(!registered_ips.contains(&addr_1.ip()));
            assert!(registered_ips.contains(&addr_2.ip()));

            // The first peer should be have received a kill message because its
            // peer set was removed because `tracked_peer_sets` is 1.
            assert!(matches!(peer_rx.next().await, Some(peer::Message::Kill)),)
        });
    }
}
