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
use commonware_utils::{
    channel::{
        fallible::{AsyncFallibleExt, FallibleExt},
        mpsc,
    },
    ordered::Set,
};
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
            allow_dns: cfg.allow_dns,
            bypass_ip_check: cfg.bypass_ip_check,
            block_duration: cfg.block_duration,
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
            _ = self.directory.wait_for_unblock() => {
                if self.directory.unblock_expired() {
                    self.listener
                        .0
                        .send_lossy(self.directory.listenable())
                        .await;
                }
            },
            Some(msg) = self.receiver.recv() else {
                debug!("mailbox closed, stopping tracker");
                break;
            } => {
                self.handle_msg(msg).await;
            },
        }
    }

    /// Handle a [`Message`].
    async fn handle_msg(&mut self, msg: Message<C::PublicKey>) {
        match msg {
            Message::Register { index, peers } => {
                // Identify peers that were added or had their addresses changed.
                let peer_keys: Set<C::PublicKey> = peers.keys().clone();
                let Some((deleted, changed)) = self.directory.add_set(index, peers) else {
                    return;
                };

                // Kill connections for peers no longer in any tracked peer set.
                for peer in deleted {
                    if let Some(mut mailbox) = self.mailboxes.remove(&peer) {
                        mailbox.kill().await;
                    }
                }

                // Kill connections for peers whose addresses changed. These connections
                // were established with the old address and should be replaced with a connection
                // to the new address.
                for peer in changed {
                    if let Some(mut mailbox) = self.mailboxes.remove(&peer) {
                        mailbox.kill().await;
                    }
                }

                // Send the updated listenable IPs to the listener.
                self.listener
                    .0
                    .send_lossy(self.directory.listenable())
                    .await;

                // Notify all subscribers about the new peer set
                self.subscribers.retain(|subscriber| {
                    subscriber.send_lossy((index, peer_keys.clone(), self.directory.tracked()))
                });
            }
            Message::Overwrite { peers } => {
                let mut any_changed = false;
                for (public_key, address) in peers {
                    // Update the peer address.
                    if !self.directory.overwrite(&public_key, address) {
                        continue;
                    }
                    any_changed = true;

                    // Kill the existing connection since it was established to the old address.
                    if let Some(mut peer) = self.mailboxes.remove(&public_key) {
                        peer.kill().await;
                    }
                }

                // Send the updated listenable IPs to the listener (if any changes occurred).
                if any_changed {
                    self.listener
                        .0
                        .send_lossy(self.directory.listenable())
                        .await;
                }
            }
            Message::PeerSet { index, responder } => {
                // Send the peer set at the given index.
                let _ = responder.send(self.directory.get_set(&index).cloned());
            }
            Message::Subscribe { responder } => {
                // Create a new subscription channel
                let (sender, receiver) = mpsc::unbounded_channel();

                // Send the latest peer set immediately
                if let Some(latest_set_id) = self.directory.latest_set_index() {
                    let latest_set = self.directory.get_set(&latest_set_id).cloned().unwrap();
                    sender.send_lossy((latest_set_id, latest_set, self.directory.tracked()));
                }
                self.subscribers.push(sender);

                // Return the receiver to the caller
                let _ = responder.send(receiver);
            }
            Message::Connect {
                public_key,
                mut peer,
            } => {
                // Kill if peer is not eligible (not in a peer set)
                if !self.directory.eligible(&public_key) {
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
            Message::Acceptable {
                public_key,
                source_ip,
                responder,
            } => {
                let _ = responder.send(self.directory.acceptable(&public_key, source_ip));
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

                // Send the updated listenable IPs to the listener.
                self.listener
                    .0
                    .send_lossy(self.directory.listenable())
                    .await;
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
    use crate::{authenticated::lookup::actors::peer, AddressableManager, Blocker, Ingress};
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
    fn test_config<C: Signer>(
        crypto: C,
        bypass_ip_check: bool,
    ) -> (Config<C>, mpsc::Receiver<HashSet<IpAddr>>) {
        let (registered_ips_sender, registered_ips_receiver) = Mailbox::new(1);
        (
            Config {
                crypto,
                tracked_peer_sets: 2,
                allowed_connection_rate_per_peer: Quota::per_second(NZU32!(5)),
                allow_private_ips: true,
                allow_dns: true,
                bypass_ip_check,
                listener: registered_ips_sender,
                block_duration: Duration::from_secs(100),
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
            let (cfg, _) = test_config(PrivateKey::from_seed(0), false);
            let TestHarness { mut mailbox, .. } = setup_actor(context.clone(), cfg);

            let (_unauth_signer, unauth_pk) = new_signer_and_pk(1);
            let (peer_mailbox, mut peer_receiver) = Mailbox::new(1);

            // Connect as listener
            mailbox.connect(unauth_pk.clone(), peer_mailbox);
            assert!(
                matches!(peer_receiver.recv().await, Some(peer::Message::Kill)),
                "Unauthorized peer should be killed on Connect"
            );
        });
    }

    #[test]
    fn test_block_peer_standard_behavior() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (cfg_initial, _) = test_config(PrivateKey::from_seed(0), false);
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_, pk) = new_signer_and_pk(1);
            let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1001);
            oracle
                .track(0, [(pk.clone(), addr.into())].try_into().unwrap())
                .await;
            context.sleep(Duration::from_millis(10)).await;

            let dialable_peers = mailbox.dialable().await;
            assert!(dialable_peers.iter().any(|peer| peer == &pk));

            crate::block_peer(&mut oracle, pk.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let dialable_peers = mailbox.dialable().await;
            assert!(!dialable_peers.iter().any(|peer| peer == &pk));
        });
    }

    #[test]
    fn test_block_peer_already_blocked_is_noop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (cfg_initial, _) = test_config(PrivateKey::from_seed(0), false);
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_, pk1) = new_signer_and_pk(1);
            let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1001);
            oracle
                .track(0, [(pk1.clone(), addr.into())].try_into().unwrap())
                .await;
            context.sleep(Duration::from_millis(10)).await;

            crate::block_peer(&mut oracle, pk1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let dialable_peers = mailbox.dialable().await;
            assert!(!dialable_peers.iter().any(|peer| peer == &pk1));

            crate::block_peer(&mut oracle, pk1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let dialable_peers = mailbox.dialable().await;
            assert!(!dialable_peers.iter().any(|peer| peer == &pk1));
        });
    }

    #[test]
    fn test_block_peer_non_existent_is_noop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (cfg_initial, _) = test_config(PrivateKey::from_seed(0), false);
            let TestHarness { mut oracle, .. } = setup_actor(context.clone(), cfg_initial);

            let (_s1_signer, pk_non_existent) = new_signer_and_pk(100);

            crate::block_peer(&mut oracle, pk_non_existent).await;
            context.sleep(Duration::from_millis(10)).await;
        });
    }

    #[test]
    fn test_listenable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (peer_signer, peer_pk) = new_signer_and_pk(1);
            let peer_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 1001);
            let (_peer_signer2, peer_pk2) = new_signer_and_pk(2);
            let peer_addr2 = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), 1002);
            let (_peer_signer3, peer_pk3) = new_signer_and_pk(3);
            let peer_addr3 = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 3).into(), 1003);
            let (cfg_initial, _) = test_config(peer_signer, false);
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            // None acceptable because not registered
            assert!(!mailbox.acceptable(peer_pk.clone(), peer_addr.ip()).await);
            assert!(!mailbox.acceptable(peer_pk2.clone(), peer_addr2.ip()).await);
            assert!(!mailbox.acceptable(peer_pk3.clone(), peer_addr3.ip()).await);

            oracle
                .track(
                    0,
                    [
                        (peer_pk.clone(), peer_addr.into()),
                        (peer_pk2.clone(), peer_addr2.into()),
                    ]
                    .try_into()
                    .unwrap(),
                )
                .await;
            context.sleep(Duration::from_millis(10)).await;

            // Not acceptable because self
            assert!(!mailbox.acceptable(peer_pk, peer_addr.ip()).await);
            // Acceptable because registered with correct IP
            assert!(mailbox.acceptable(peer_pk2.clone(), peer_addr2.ip()).await);
            // Not acceptable with wrong IP
            assert!(!mailbox.acceptable(peer_pk2, peer_addr.ip()).await);
            // Not acceptable because not registered
            assert!(!mailbox.acceptable(peer_pk3, peer_addr3.ip()).await);
        });
    }

    #[test]
    fn test_acceptable_bypass_ip_check() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (peer_signer, peer_pk) = new_signer_and_pk(1);
            let peer_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 1001);
            let (_peer_signer2, peer_pk2) = new_signer_and_pk(2);
            let peer_addr2 = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), 1002);
            let (_peer_signer3, peer_pk3) = new_signer_and_pk(3);
            let peer_addr3 = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 3).into(), 1003);

            // Create a tracker with bypass_ip_check=true (skips IP verification)
            let (cfg, _) = test_config(peer_signer, true);
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg);

            // Unknown peer is NOT acceptable (bypass_ip_check only skips IP check)
            assert!(
                !mailbox.acceptable(peer_pk3.clone(), peer_addr3.ip()).await,
                "Unknown peer should not be acceptable"
            );

            oracle
                .track(
                    0,
                    [
                        (peer_pk.clone(), peer_addr.into()),
                        (peer_pk2.clone(), peer_addr2.into()),
                    ]
                    .try_into()
                    .unwrap(),
                )
                .await;
            context.sleep(Duration::from_millis(10)).await;

            // With bypass_ip_check=true, registered peer with wrong IP is acceptable
            assert!(
                mailbox.acceptable(peer_pk2.clone(), peer_addr.ip()).await,
                "Registered peer with wrong IP should be acceptable with bypass_ip_check=true"
            );

            // Self is still not acceptable
            assert!(
                !mailbox.acceptable(peer_pk.clone(), peer_addr.ip()).await,
                "Self should not be acceptable"
            );

            // Block peer_pk2 and verify it's not acceptable
            crate::block_peer(&mut oracle, peer_pk2.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            assert!(
                !mailbox.acceptable(peer_pk2.clone(), peer_addr2.ip()).await,
                "Blocked peer should not be acceptable"
            );
        });
    }

    #[test]
    fn test_listen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (cfg_initial, _) = test_config(PrivateKey::from_seed(0), false);
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
                .track(0, [(peer_pk.clone(), peer_addr.into())].try_into().unwrap())
                .await;
            context.sleep(Duration::from_millis(10)).await; // Allow register to process

            assert!(mailbox.acceptable(peer_pk.clone(), peer_addr.ip()).await);

            let reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation.is_some());

            assert!(!mailbox.acceptable(peer_pk.clone(), peer_addr.ip()).await);

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
            let (cfg_initial, _) = test_config(PrivateKey::from_seed(0), false);
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);
            oracle
                .track(0, [(boot_pk.clone(), boot_addr.into())].try_into().unwrap())
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
            let (cfg_initial, _) = test_config(PrivateKey::from_seed(0), false);

            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            oracle
                .track(0, [(boot_pk.clone(), boot_addr.into())].try_into().unwrap())
                .await;

            let result = mailbox.dial(boot_pk.clone()).await;
            assert!(result.is_some());
            if let Some((res, ingress)) = result {
                match res.metadata() {
                    crate::authenticated::lookup::actors::tracker::Metadata::Dialer(pk) => {
                        assert_eq!(pk, &boot_pk);
                    }
                    _ => panic!("Expected Dialer metadata"),
                }
                assert_eq!(ingress, Ingress::Socket(boot_addr));
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
            let (cfg, _) = test_config(PrivateKey::from_seed(0), false);
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg);

            // 2) Register & connect an authorized peer
            let (_peer_signer, peer_pk) = new_signer_and_pk(1);
            let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
            oracle
                .track(0, [(peer_pk.clone(), peer_addr.into())].try_into().unwrap())
                .await;
            // let the register take effect
            context.sleep(Duration::from_millis(10)).await;

            let reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation.is_some());

            let (peer_mailbox, mut peer_rx) = Mailbox::new(1);
            mailbox.connect(peer_pk.clone(), peer_mailbox);

            // 3) Block it → should see exactly one Kill
            crate::block_peer(&mut oracle, peer_pk.clone()).await;
            context.sleep(Duration::from_millis(10)).await;
            assert!(
                matches!(peer_rx.recv().await, Some(peer::Message::Kill)),
                "connected peer must be killed on first Block"
            );

            // 4) Block again → mailbox was removed, so no new Kill
            crate::block_peer(&mut oracle, peer_pk.clone()).await;
            context.sleep(Duration::from_millis(10)).await;
            assert!(
                peer_rx.recv().await.is_none(),
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

            let (mut cfg, mut listener_receiver) = test_config(my_sk, false);
            cfg.tracked_peer_sets = 1;

            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg);

            // Register set with myself and one other peer
            oracle
                .track(
                    0,
                    [
                        (my_pk.clone(), my_addr.into()),
                        (pk_1.clone(), addr_1.into()),
                    ]
                    .try_into()
                    .unwrap(),
                )
                .await;
            // let the register take effect
            context.sleep(Duration::from_millis(10)).await;

            // Wait for a listener update
            let registered_ips = listener_receiver.recv().await.unwrap();
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
                .track(1, [(pk_2.clone(), addr_2.into())].try_into().unwrap())
                .await;

            // Wait for a listener update
            let registered_ips = listener_receiver.recv().await.unwrap();
            assert!(!registered_ips.contains(&my_addr.ip()));
            assert!(!registered_ips.contains(&addr_1.ip()));
            assert!(registered_ips.contains(&addr_2.ip()));

            // The first peer should be have received a kill message because its
            // peer set was removed because `tracked_peer_sets` is 1.
            assert!(matches!(peer_rx.recv().await, Some(peer::Message::Kill)),)
        });
    }

    #[test]
    fn test_overwrite_triggers_listener() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (my_sk, my_pk) = new_signer_and_pk(0);
            let my_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9000);

            let pk_1 = new_signer_and_pk(1).1;
            let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 9001);
            let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 9002);

            let (cfg, mut listener_receiver) = test_config(my_sk, false);
            let TestHarness { mut oracle, .. } = setup_actor(context.clone(), cfg);

            oracle
                .track(
                    0,
                    [
                        (my_pk.clone(), my_addr.into()),
                        (pk_1.clone(), addr_1.into()),
                    ]
                    .try_into()
                    .unwrap(),
                )
                .await;

            let registered_ips = listener_receiver.recv().await.unwrap();
            assert!(registered_ips.contains(&addr_1.ip()));
            assert!(!registered_ips.contains(&addr_2.ip()));

            oracle
                .overwrite([(pk_1.clone(), addr_2.into())].try_into().unwrap())
                .await;

            let registered_ips = listener_receiver.recv().await.unwrap();
            assert!(!registered_ips.contains(&addr_1.ip()));
            assert!(registered_ips.contains(&addr_2.ip()));
        });
    }

    #[test]
    fn test_overwrite_via_oracle() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (cfg, _) = test_config(PrivateKey::from_seed(0), false);
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg);

            let (_, pk) = new_signer_and_pk(1);
            let addr_1 = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1001);
            let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1002);

            oracle
                .track(0, [(pk.clone(), addr_1.into())].try_into().unwrap())
                .await;
            context.sleep(Duration::from_millis(10)).await;

            let result = mailbox.dial(pk.clone()).await;
            assert!(result.is_some());
            let (_, ingress) = result.unwrap();
            assert_eq!(ingress, Ingress::Socket(addr_1));

            oracle
                .overwrite([(pk.clone(), addr_2.into())].try_into().unwrap())
                .await;

            context.sleep(Duration::from_millis(1010)).await;

            let result = mailbox.dial(pk.clone()).await;
            assert!(result.is_some());
            let (_, ingress) = result.unwrap();
            assert_eq!(ingress, Ingress::Socket(addr_2));
        });
    }

    #[test]
    fn test_overwrite_blocked_peer_not_in_listenable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (my_sk, my_pk) = new_signer_and_pk(0);
            let my_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 9000);

            let pk_1 = new_signer_and_pk(1).1;
            let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 9001);
            let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 9002);

            let (cfg, mut listener_receiver) = test_config(my_sk, false);
            let TestHarness { mut oracle, .. } = setup_actor(context.clone(), cfg);

            oracle
                .track(
                    0,
                    [
                        (my_pk.clone(), my_addr.into()),
                        (pk_1.clone(), addr_1.into()),
                    ]
                    .try_into()
                    .unwrap(),
                )
                .await;

            let registered_ips = listener_receiver.recv().await.unwrap();
            assert!(registered_ips.contains(&addr_1.ip()));

            crate::block_peer(&mut oracle, pk_1.clone()).await;
            let registered_ips = listener_receiver.recv().await.unwrap();
            assert!(!registered_ips.contains(&addr_1.ip()));

            oracle
                .overwrite([(pk_1.clone(), addr_2.into())].try_into().unwrap())
                .await;

            let registered_ips = listener_receiver.recv().await.unwrap();
            assert!(!registered_ips.contains(&addr_1.ip()));
            assert!(!registered_ips.contains(&addr_2.ip()));
        });
    }

    #[test]
    fn test_overwrite_untracked_peer_silently_ignored() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (cfg, _) = test_config(PrivateKey::from_seed(0), false);
            let TestHarness { mut oracle, .. } = setup_actor(context.clone(), cfg);

            let (_, pk) = new_signer_and_pk(1);
            let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1001);

            // Untracked peer is silently skipped (no error, no effect)
            oracle
                .overwrite([(pk, addr.into())].try_into().unwrap())
                .await;
        });
    }

    #[test]
    fn test_overwrite_changes_acceptable_ip() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pk_1 = new_signer_and_pk(1).1;
            let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 9001);
            let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 9002);

            let (cfg, _) = test_config(PrivateKey::from_seed(0), false);
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg);

            oracle
                .track(0, [(pk_1.clone(), addr_1.into())].try_into().unwrap())
                .await;
            context.sleep(Duration::from_millis(10)).await;

            assert!(mailbox.acceptable(pk_1.clone(), addr_1.ip()).await);
            assert!(!mailbox.acceptable(pk_1.clone(), addr_2.ip()).await);

            oracle
                .overwrite([(pk_1.clone(), addr_2.into())].try_into().unwrap())
                .await;

            assert!(!mailbox.acceptable(pk_1.clone(), addr_1.ip()).await);
            assert!(mailbox.acceptable(pk_1.clone(), addr_2.ip()).await);
        });
    }

    #[test]
    fn test_overwrite_severs_existing_connection() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (cfg, _) = test_config(PrivateKey::from_seed(0), false);
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg);

            let (_, pk) = new_signer_and_pk(1);
            let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1001);
            let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 1002);

            oracle
                .track(0, [(pk.clone(), addr_1.into())].try_into().unwrap())
                .await;
            context.sleep(Duration::from_millis(10)).await;

            // Establish connection
            let reservation = mailbox.listen(pk.clone()).await;
            assert!(reservation.is_some());

            let (peer_mailbox, mut peer_rx) = Mailbox::new(1);
            mailbox.connect(pk.clone(), peer_mailbox);

            // Update address - should kill the connection
            oracle
                .overwrite([(pk.clone(), addr_2.into())].try_into().unwrap())
                .await;

            // Peer should receive kill message
            assert!(matches!(peer_rx.recv().await, Some(peer::Message::Kill)));
        });
    }

    #[test]
    fn test_add_set_severs_connection_on_address_change() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (cfg, mut listener_receiver) = test_config(PrivateKey::from_seed(0), false);
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg);

            let (_, pk) = new_signer_and_pk(1);
            let addr_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1001);
            let addr_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 1002);

            // Register peer set with peer at address A
            oracle
                .track(0, [(pk.clone(), addr_a.into())].try_into().unwrap())
                .await;
            let registered_ips = listener_receiver.recv().await.unwrap();
            assert!(registered_ips.contains(&addr_a.ip()));

            // Establish connection to peer
            let reservation = mailbox.listen(pk.clone()).await;
            assert!(reservation.is_some());

            let (peer_mailbox, mut peer_rx) = Mailbox::new(1);
            mailbox.connect(pk.clone(), peer_mailbox);

            // Register new peer set with same peer at address B
            oracle
                .track(1, [(pk.clone(), addr_b.into())].try_into().unwrap())
                .await;

            // Peer should receive Kill message (connection severed due to address change)
            assert!(matches!(peer_rx.recv().await, Some(peer::Message::Kill)));

            // Verify listenable IPs updated to new address
            let registered_ips = listener_receiver.recv().await.unwrap();
            assert!(!registered_ips.contains(&addr_a.ip()));
            assert!(registered_ips.contains(&addr_b.ip()));
        });
    }

    #[test]
    fn test_overwrite_batch_mixed_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (cfg, mut listener_receiver) = test_config(PrivateKey::from_seed(0), false);
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg);

            let (_, pk_tracked) = new_signer_and_pk(1);
            let (_, pk_unchanged) = new_signer_and_pk(2);
            let (_, pk_untracked) = new_signer_and_pk(3);

            let addr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1001);
            let addr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 1002);
            let addr_unchanged = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)), 1003);

            // Register some peers
            oracle
                .track(
                    0,
                    [
                        (pk_tracked.clone(), addr_1.into()),
                        (pk_unchanged.clone(), addr_unchanged.into()),
                    ]
                    .try_into()
                    .unwrap(),
                )
                .await;
            let _ = listener_receiver.recv().await.unwrap();

            // Establish connection to pk_tracked
            let reservation = mailbox.listen(pk_tracked.clone()).await;
            assert!(reservation.is_some());
            let (tracked_mailbox, mut tracked_rx) = Mailbox::new(1);
            mailbox.connect(pk_tracked.clone(), tracked_mailbox);

            // Establish connection to pk_unchanged
            let reservation = mailbox.listen(pk_unchanged.clone()).await;
            assert!(reservation.is_some());
            let (unchanged_mailbox, mut unchanged_rx) = Mailbox::new(1);
            mailbox.connect(pk_unchanged.clone(), unchanged_mailbox);

            // Call overwrite with mix of tracked+changed, tracked+unchanged, and untracked peers
            oracle
                .overwrite(
                    [
                        (pk_tracked.clone(), addr_2.into()),
                        (pk_unchanged.clone(), addr_unchanged.into()),
                        (pk_untracked.clone(), addr_1.into()),
                    ]
                    .try_into()
                    .unwrap(),
                )
                .await;

            // Only tracked+changed peer (pk_tracked) gets killed
            assert!(matches!(tracked_rx.recv().await, Some(peer::Message::Kill)));

            // Unchanged peer should NOT receive kill - verify the receiver has no pending messages
            // We use try_recv to check without blocking
            assert!(
                unchanged_rx.try_recv().is_err(),
                "Unchanged peer should not receive kill"
            );
        });
    }
}
