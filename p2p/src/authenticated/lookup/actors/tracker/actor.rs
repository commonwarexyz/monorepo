use super::{
    Config, Metadata,
    directory::{self, Directory},
    ingress::{Mailbox, Message, Oracle},
};
use crate::{
    PeerEndpoint, PeerSetUpdate,
    authenticated::{
        admission::PeerEligibility,
        lookup::actors::{peer, tracker::ingress::Releaser},
    },
};
use commonware_actor::mailbox;
use commonware_cryptography::Signer;
use commonware_macros::{select_loop, stability};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics as RuntimeMetrics, Scheduler, spawn_cell,
};
use commonware_utils::channel::{fallible::FallibleExt, mpsc};
use rand_core::Rng;
use std::collections::HashMap;
use tracing::debug;

/// The tracker actor that manages peer discovery and connection reservations.
pub struct Actor<
    R: Scheduler + Rng + Clock + RuntimeMetrics,
    C: Signer,
    E: PeerEndpoint = crate::Ingress,
> {
    context: ContextCell<R>,

    // ---------- Message-Passing ----------
    /// The mailbox for the actor.
    ///
    /// We use this to support sending a [`Message::Release`] message to the actor
    /// during [`Drop`].
    receiver: mailbox::Receiver<Message<C::PublicKey, E>>,

    // ---------- State ----------
    /// Tracks peer sets and peer connectivity information.
    directory: Directory<R, C::PublicKey, E>,

    /// Maps a peer's public key to its mailbox.
    /// Set when a peer connects and cleared when it is blocked or released.
    mailboxes: HashMap<C::PublicKey, peer::Mailbox>,

    /// Subscribers to peer set updates.
    subscribers: Vec<mpsc::UnboundedSender<PeerSetUpdate<C::PublicKey>>>,

    /// Identity-only snapshot consumed by transport-specific inbound admission.
    eligibility: PeerEligibility<C::PublicKey>,
}

impl<R: Scheduler + Rng + Clock + RuntimeMetrics, C: Signer, E: PeerEndpoint> Actor<R, C, E> {
    /// Create a new tracker [Actor] from the given `context` and `cfg`.
    #[allow(clippy::type_complexity)]
    #[stability(ALPHA)]
    pub fn new(
        context: R,
        cfg: Config<C>,
    ) -> (Self, Mailbox<C::PublicKey, E>, Oracle<C::PublicKey, E>) {
        let (actor, mailbox, oracle, _) = Self::with_eligibility(context, cfg);
        (actor, mailbox, oracle)
    }

    #[allow(
        clippy::type_complexity,
        reason = "the returned handles are the actor's construction interface"
    )]
    pub(crate) fn with_eligibility(
        context: R,
        cfg: Config<C>,
    ) -> (
        Self,
        Mailbox<C::PublicKey, E>,
        Oracle<C::PublicKey, E>,
        PeerEligibility<C::PublicKey>,
    ) {
        // General initialization
        let directory_cfg = directory::Config {
            max_sets: cfg.tracked_peer_sets,
            peer_connection_cooldown: cfg.peer_connection_cooldown,
            block_duration: cfg.block_duration,
        };

        // Create the mailboxes
        let (sender, receiver) = mailbox::new(context.child("mailbox"), cfg.mailbox_size);
        let oracle = Oracle::new(sender.clone());
        let releaser = Releaser::new(sender.clone());
        let eligibility = PeerEligibility::default();

        // Create the directory
        let directory = Directory::init(
            context.child("directory"),
            cfg.crypto.public_key(),
            directory_cfg,
            releaser,
        );

        (
            Self {
                context: ContextCell::new(context),
                receiver,
                directory,
                mailboxes: HashMap::new(),
                subscribers: Vec::new(),
                eligibility: eligibility.clone(),
            },
            Mailbox::new(sender),
            oracle,
            eligibility,
        )
    }

    /// Start the actor and run it in the background.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping tracker");
            },
            _ = self.directory.wait_for_unblock() => {
                if self.directory.unblock_expired() {
                    self.refresh_eligibility();
                }
            },
            Some(msg) = self.receiver.recv() else {
                debug!("mailbox closed, stopping tracker");
                break;
            } => {
                self.handle_msg(msg);
            },
        }
    }

    /// Handle a [`Message`].
    fn handle_msg(&mut self, msg: Message<C::PublicKey, E>) {
        match msg {
            Message::Register { index, peers } => {
                // Identify peers whose connection state should be torn down.
                let Some(kill_peers) = self.directory.track(index, peers) else {
                    return;
                };

                // Kill active peers no longer in any tracked peer set or whose addresses changed.
                for peer in kill_peers {
                    self.kill_peer(&peer);
                }
                self.refresh_eligibility();

                // Notify all subscribers about the new peer set
                let update = self
                    .directory
                    .latest_update()
                    .expect("latest update missing after successful track");
                self.subscribers
                    .retain(|subscriber| subscriber.send_lossy(update.clone()));
            }
            Message::Overwrite { peers } => {
                for (public_key, address) in peers {
                    // Update the peer address.
                    if !self.directory.overwrite(&public_key, address) {
                        continue;
                    }
                    // Kill the existing connection since it was established to the old address.
                    self.kill_peer(&public_key);
                }
            }
            Message::PeerSet { index, responder } => {
                let _ = responder.send(self.directory.get_peer_set(&index));
            }
            Message::Subscribe { responder } => {
                // Create a new subscription channel
                let (sender, receiver) = mpsc::unbounded_channel();

                // Send the latest peer set immediately
                if let Some(update) = self.directory.latest_update() {
                    sender.send_lossy(update);
                }
                self.subscribers.push(sender);

                // Return the receiver to the caller
                let _ = responder.send(receiver);
            }
            Message::Connect { public_key, peer } => {
                // Kill if peer is not eligible
                if !self.directory.eligible(&public_key) {
                    peer.kill();
                    return;
                }

                // Promote the reservation unless it was invalidated before Connect arrived.
                if !self.directory.connect(&public_key) {
                    peer.kill();
                    return;
                }
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
            Message::Attach {
                public_key,
                inbound,
                reservation,
            } => {
                let metadata = if inbound {
                    Metadata::Listener(public_key.clone())
                } else {
                    Metadata::Dialer(public_key.clone())
                };
                let _ = reservation.send(self.directory.attach(public_key, metadata));
            }
            Message::Acceptable {
                public_key,
                responder,
            } => {
                let _ = responder.send(self.directory.acceptable(&public_key));
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
                self.refresh_eligibility();

                // Kill the peer if we're connected to it
                self.kill_peer(&public_key);
            }
            Message::Release { metadata } => {
                self.release(metadata);
            }
        }
    }

    fn release(&mut self, metadata: Metadata<C::PublicKey>) {
        self.mailboxes.remove(metadata.public_key());
        self.directory.release(metadata);
    }

    fn kill_peer(&mut self, public_key: &C::PublicKey) {
        if let Some(peer) = self.mailboxes.remove(public_key) {
            peer.kill();
        }
    }

    fn refresh_eligibility(&self) {
        self.eligibility.set(self.directory.admissible());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Advertisement, PeerEndpoint, Provider, Reachability, ReachabilityManager,
        ReachableTrackedPeers, authenticated::lookup::actors::peer,
    };
    use commonware_cryptography::{
        Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{
        Clock, Runner, Supervisor as _,
        deterministic::{self},
    };
    use commonware_utils::{
        NZUsize,
        ordered::{Map, Set},
    };
    use futures::{FutureExt, StreamExt};
    use std::time::Duration;

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct Endpoint(u16);

    impl PeerEndpoint for Endpoint {}

    fn dialable(endpoint: Endpoint) -> Reachability<Endpoint> {
        Reachability::Dialable(Advertisement::new(vec![endpoint]).unwrap())
    }

    fn primary(
        peers: impl IntoIterator<Item = (PublicKey, Reachability<Endpoint>)>,
    ) -> Map<PublicKey, Reachability<Endpoint>> {
        Map::from_iter_dedup(peers)
    }

    // Test Configuration Setup
    fn test_config<C: Signer>(crypto: C) -> Config<C> {
        Config {
            crypto,
            mailbox_size: NZUsize!(1024),
            tracked_peer_sets: NZUsize!(2),
            peer_connection_cooldown: Duration::from_millis(200),
            block_duration: Duration::from_secs(100),
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
        mailbox: Mailbox<PublicKey, Endpoint>,
        oracle: Oracle<PublicKey, Endpoint>,
    }

    fn setup_actor(
        runner_context: deterministic::Context,
        cfg_to_clone: Config<PrivateKey>, // Pass by value to allow cloning
    ) -> TestHarness {
        // Actor::new takes ownership, so clone again if cfg_to_clone is needed later
        let (actor, mailbox, oracle) = Actor::<_, _, Endpoint>::new(runner_context, cfg_to_clone);
        actor.start();

        TestHarness { mailbox, oracle }
    }

    #[test]
    fn test_connect_unauthorized_peer_is_killed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(PrivateKey::from_seed(0));
            let TestHarness { mailbox, .. } = setup_actor(context.child("actor"), cfg);

            let (_unauth_signer, unauth_pk) = new_signer_and_pk(1);
            let (peer_mailbox, mut peer_receiver) = peer::Mailbox::new(NZUsize!(1));

            // Connect as listener
            let _ = mailbox.connect(unauth_pk.clone(), peer_mailbox);
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
            let cfg_initial = test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg_initial);

            let (_, pk) = new_signer_and_pk(1);
            oracle.track(0, primary([(pk.clone(), dialable(Endpoint(1001)))]));
            context.sleep(Duration::from_millis(10)).await;

            let dialable = mailbox.dialable().await;
            assert!(dialable.peers.iter().any(|peer| peer == &pk));

            crate::block_peer(&mut oracle, pk.clone());
            context.sleep(Duration::from_millis(10)).await;

            let dialable = mailbox.dialable().await;
            assert!(!dialable.peers.iter().any(|peer| peer == &pk));
        });
    }

    #[test]
    fn test_block_peer_already_blocked_is_noop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg_initial);

            let (_, pk1) = new_signer_and_pk(1);
            oracle.track(0, primary([(pk1.clone(), dialable(Endpoint(1001)))]));
            context.sleep(Duration::from_millis(10)).await;

            crate::block_peer(&mut oracle, pk1.clone());
            context.sleep(Duration::from_millis(10)).await;

            let dialable = mailbox.dialable().await;
            assert!(!dialable.peers.iter().any(|peer| peer == &pk1));

            crate::block_peer(&mut oracle, pk1.clone());
            context.sleep(Duration::from_millis(10)).await;

            let dialable = mailbox.dialable().await;
            assert!(!dialable.peers.iter().any(|peer| peer == &pk1));
        });
    }

    #[test]
    fn test_block_peer_non_existent_is_noop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = test_config(PrivateKey::from_seed(0));
            let TestHarness { mut oracle, .. } = setup_actor(context.child("actor"), cfg_initial);

            let (_s1_signer, pk_non_existent) = new_signer_and_pk(100);

            crate::block_peer(&mut oracle, pk_non_existent);
            context.sleep(Duration::from_millis(10)).await;
        });
    }

    #[test]
    fn test_acceptable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (peer_signer, peer_pk) = new_signer_and_pk(1);
            let (_peer_signer2, peer_pk2) = new_signer_and_pk(2);
            let (_peer_signer3, peer_pk3) = new_signer_and_pk(3);
            let cfg_initial = test_config(peer_signer);
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg_initial);

            // None acceptable because not registered
            assert!(!mailbox.acceptable(peer_pk.clone()).await);
            assert!(!mailbox.acceptable(peer_pk2.clone()).await);
            assert!(!mailbox.acceptable(peer_pk3.clone()).await);

            oracle.track(
                0,
                primary([
                    (peer_pk.clone(), dialable(Endpoint(1001))),
                    (peer_pk2.clone(), dialable(Endpoint(1002))),
                ]),
            );
            context.sleep(Duration::from_millis(10)).await;

            // Not acceptable because self
            assert!(!mailbox.acceptable(peer_pk).await);
            // Acceptable because registered
            assert!(mailbox.acceptable(peer_pk2.clone()).await);
            // Not acceptable because not registered
            assert!(!mailbox.acceptable(peer_pk3).await);
        });
    }

    #[test]
    fn test_outbound_only_peer_is_acceptable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (peer_signer, peer_pk) = new_signer_and_pk(1);
            let (_peer_signer2, peer_pk2) = new_signer_and_pk(2);
            let (_peer_signer3, peer_pk3) = new_signer_and_pk(3);

            let cfg = test_config(peer_signer);
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            // Unknown peers are not acceptable.
            assert!(
                !mailbox.acceptable(peer_pk3.clone()).await,
                "Unknown peer should not be acceptable"
            );

            oracle.track(
                0,
                primary([
                    (peer_pk.clone(), dialable(Endpoint(1001))),
                    (peer_pk2.clone(), Reachability::OutboundOnly),
                ]),
            );
            context.sleep(Duration::from_millis(10)).await;

            // Outbound-only peers may still establish inbound connections.
            assert!(
                mailbox.acceptable(peer_pk2.clone()).await,
                "outbound-only peer should be acceptable"
            );

            // Self is still not acceptable
            assert!(
                !mailbox.acceptable(peer_pk.clone()).await,
                "Self should not be acceptable"
            );

            // Block peer_pk2 and verify it's not acceptable
            crate::block_peer(&mut oracle, peer_pk2.clone());
            context.sleep(Duration::from_millis(10)).await;

            assert!(
                !mailbox.acceptable(peer_pk2.clone()).await,
                "Blocked peer should not be acceptable"
            );
        });
    }

    #[test]
    fn test_listen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg_initial);

            let (_peer_signer, peer_pk) = new_signer_and_pk(1);
            let reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation.is_none());

            oracle.track(0, primary([(peer_pk.clone(), dialable(Endpoint(8080)))]));
            context.sleep(Duration::from_millis(10)).await; // Allow register to process

            assert!(mailbox.acceptable(peer_pk.clone()).await);

            let reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation.is_some());

            assert!(!mailbox.acceptable(peer_pk.clone()).await);

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
            let cfg_initial = test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg_initial);
            oracle.track(0, primary([(boot_pk.clone(), dialable(Endpoint(9000)))]));

            let dialable = mailbox.dialable().await;
            assert_eq!(dialable.peers.len(), 1);
            assert_eq!(dialable.peers[0], boot_pk);
        });
    }

    #[test]
    fn test_dial_message() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (_boot_signer, boot_pk) = new_signer_and_pk(99);
            let boot_endpoint = Endpoint(9000);
            let cfg_initial = test_config(PrivateKey::from_seed(0));

            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg_initial);

            oracle.track(
                0,
                primary([(boot_pk.clone(), dialable(boot_endpoint.clone()))]),
            );

            let result = mailbox.dial(boot_pk.clone()).await;
            assert!(result.is_some());
            if let Some((res, advertisement)) = result {
                match res.metadata() {
                    crate::authenticated::lookup::actors::tracker::Metadata::Dialer(pk) => {
                        assert_eq!(pk, &boot_pk);
                    }
                    _ => panic!("Expected Dialer metadata"),
                }
                assert_eq!(advertisement.endpoints(), &[boot_endpoint]);
            }

            let (_unknown_signer, unknown_pk) = new_signer_and_pk(100);
            let no_reservation = mailbox.dial(unknown_pk).await;
            assert!(no_reservation.is_none());
        });
    }

    #[test]
    fn test_secondary_peers_are_acceptable_but_not_primary_or_dialable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            let mut subscription = oracle.subscribe().await;

            let (_primary_signer, primary_pk) = new_signer_and_pk(1);
            let (_secondary_signer, secondary_pk) = new_signer_and_pk(2);

            oracle.track(
                0,
                ReachableTrackedPeers::new(
                    primary([(primary_pk.clone(), dialable(Endpoint(9001)))]),
                    primary([(secondary_pk.clone(), Reachability::OutboundOnly)]),
                ),
            );

            let update = subscription.recv().await.unwrap();
            assert_eq!(update.index, 0);
            assert_eq!(update.latest.primary.len(), 1);
            assert!(update.latest.primary.position(&primary_pk).is_some());
            assert!(update.latest.primary.position(&secondary_pk).is_none());
            assert_eq!(
                update.latest.secondary,
                Set::try_from([secondary_pk.clone()]).unwrap()
            );
            assert_eq!(update.all.primary, update.latest.primary);
            assert_eq!(
                update.all.secondary,
                Set::try_from([secondary_pk.clone()]).unwrap()
            );

            let dialable = mailbox.dialable().await;
            assert!(dialable.peers.iter().any(|peer| peer == &primary_pk));
            assert!(!dialable.peers.iter().any(|peer| peer == &secondary_pk));
            assert!(mailbox.dial(secondary_pk.clone()).await.is_none());
            assert!(mailbox.acceptable(secondary_pk).await);
        });
    }

    #[test]
    fn test_overlapping_primary_secondary_no_duplicate_in_subscription() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Duplicate key across primary/secondary maps; deduplicated as primary only.
            let cfg = test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            let mut subscription = oracle.subscribe().await;

            let (_signer, pk) = new_signer_and_pk(1);
            oracle.track(
                0,
                ReachableTrackedPeers::new(
                    primary([(pk.clone(), dialable(Endpoint(9001)))]),
                    primary([(pk.clone(), Reachability::OutboundOnly)]),
                ),
            );

            let update = subscription.recv().await.unwrap();
            assert_eq!(update.index, 0);
            assert_eq!(update.latest.primary.len(), 1);
            assert!(update.latest.primary.position(&pk).is_some());
            assert!(
                update.latest.secondary.is_empty(),
                "overlap peer is deduplicated as primary only"
            );
            assert_eq!(update.all.primary, update.latest.primary);
            assert!(
                update.all.secondary.is_empty(),
                "aggregate secondary excludes keys that are primary"
            );

            let dialable = mailbox.dialable().await;
            assert!(dialable.peers.iter().any(|peer| peer == &pk));
            assert!(mailbox.acceptable(pk).await);
        });
    }

    #[test]
    fn test_block_clears_peer_mailbox_and_only_kills_once() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // 1) Setup actor
            let cfg = test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            // 2) Register & connect an authorized peer
            let (_peer_signer, peer_pk) = new_signer_and_pk(1);
            oracle.track(0, primary([(peer_pk.clone(), dialable(Endpoint(12345)))]));
            // let the register take effect
            context.sleep(Duration::from_millis(10)).await;

            let reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation.is_some());

            let (peer_mailbox, mut peer_rx) = peer::Mailbox::new(NZUsize!(1));
            let _ = mailbox.connect(peer_pk.clone(), peer_mailbox);

            // 3) Block it → should see exactly one Kill
            crate::block_peer(&mut oracle, peer_pk.clone());
            context.sleep(Duration::from_millis(10)).await;
            assert!(
                matches!(peer_rx.next().await, Some(peer::Message::Kill)),
                "connected peer must be killed on first Block"
            );

            // 4) Block again → mailbox was removed, so no new Kill
            crate::block_peer(&mut oracle, peer_pk.clone());
            context.sleep(Duration::from_millis(10)).await;
            assert!(
                !matches!(
                    peer_rx.next().now_or_never(),
                    Some(Some(peer::Message::Kill))
                ),
                "no kill after handle has been cleared"
            );
        });
    }

    #[test]
    fn test_register_disconnects_removed_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (my_sk, my_pk) = new_signer_and_pk(0);

            let pk_1 = new_signer_and_pk(1).1;
            let pk_2 = new_signer_and_pk(2).1;

            let mut cfg = test_config(my_sk);
            cfg.tracked_peer_sets = NZUsize!(1);

            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            // Register set with myself and one other peer
            oracle.track(
                0,
                primary([
                    (my_pk.clone(), dialable(Endpoint(9000))),
                    (pk_1.clone(), dialable(Endpoint(9001))),
                ]),
            );
            // let the register take effect
            context.sleep(Duration::from_millis(10)).await;

            assert!(!mailbox.acceptable(my_pk).await);
            assert!(mailbox.acceptable(pk_1.clone()).await);
            assert!(!mailbox.acceptable(pk_2.clone()).await);

            // Mark peer as connected
            let reservation = mailbox.listen(pk_1.clone()).await;
            assert!(reservation.is_some());

            let (peer_mailbox, mut peer_rx) = peer::Mailbox::new(NZUsize!(1));
            let _ = mailbox.connect(pk_1.clone(), peer_mailbox);

            // Register another set which doesn't include first peer
            oracle.track(1, primary([(pk_2.clone(), dialable(Endpoint(9002)))]));

            assert!(!mailbox.acceptable(pk_1.clone()).await);
            assert!(mailbox.acceptable(pk_2).await);

            // The first peer should have received a kill message because its
            // peer set was removed when `tracked_peer_sets` is 1.
            assert!(matches!(peer_rx.next().await, Some(peer::Message::Kill)),)
        });
    }

    #[test]
    fn test_register_keeps_connected_peer_present_across_rollover() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (my_sk, _) = new_signer_and_pk(0);
            let pk_1 = new_signer_and_pk(1).1;
            let pk_2 = new_signer_and_pk(2).1;

            let mut cfg = test_config(my_sk);
            cfg.tracked_peer_sets = NZUsize!(1);
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            oracle.track(
                0,
                primary([(pk_1.clone(), dialable(Endpoint(9001)))]),
            );
            assert!(mailbox.acceptable(pk_1.clone()).await);
            assert!(!mailbox.acceptable(pk_2.clone()).await);

            let reservation = mailbox
                .listen(pk_1.clone())
                .await
                .expect("peer should reserve");
            let (peer_mailbox, mut peer_rx) = peer::Mailbox::new(NZUsize!(1));
            let _ = mailbox.connect(pk_1.clone(), peer_mailbox);

            oracle.track(
                1,
                primary([
                    (pk_1.clone(), dialable(Endpoint(9001))),
                    (pk_2.clone(), dialable(Endpoint(9002))),
                ]),
            );
            assert!(mailbox.acceptable(pk_2).await);

            assert!(
                !matches!(peer_rx.next().now_or_never(), Some(Some(peer::Message::Kill))),
                "connected peer present in the new set should not be killed when the old set rolls off"
            );
            assert_eq!(reservation.metadata().public_key(), &pk_1);
        });
    }

    #[test]
    fn test_reserved_removed_peer_rejected_on_connect() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (my_sk, _) = new_signer_and_pk(0);
            let pk_1 = new_signer_and_pk(1).1;
            let pk_2 = new_signer_and_pk(2).1;

            let mut cfg = test_config(my_sk);
            cfg.tracked_peer_sets = NZUsize!(1);
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            oracle.track(0, primary([(pk_1.clone(), dialable(Endpoint(9001)))]));
            assert!(mailbox.acceptable(pk_1.clone()).await);
            assert!(!mailbox.acceptable(pk_2.clone()).await);

            let reservation = mailbox
                .listen(pk_1.clone())
                .await
                .expect("peer should reserve");
            assert_eq!(reservation.metadata().public_key(), &pk_1);

            oracle.track(1, primary([(pk_2.clone(), dialable(Endpoint(9002)))]));
            assert!(!mailbox.acceptable(pk_1.clone()).await);
            assert!(mailbox.acceptable(pk_2).await);

            let (peer_mailbox, mut peer_rx) = peer::Mailbox::new(NZUsize!(1));
            let _ = mailbox.connect(pk_1.clone(), peer_mailbox);
            assert!(
                matches!(peer_rx.next().await, Some(peer::Message::Kill)),
                "connect rejection is signaled by killing the peer"
            );
        });
    }

    #[test]
    fn test_reserved_peer_killed_on_connect_after_tracked_address_change() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (my_sk, _) = new_signer_and_pk(0);
            let pk = new_signer_and_pk(1).1;
            let endpoint_a = Endpoint(1001);
            let endpoint_b = Endpoint(1002);

            let mut cfg = test_config(my_sk);
            cfg.tracked_peer_sets = NZUsize!(2);
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            oracle.track(0, primary([(pk.clone(), dialable(endpoint_a.clone()))]));

            let (reservation, advertisement) =
                mailbox.dial(pk.clone()).await.expect("peer should reserve");
            assert_eq!(reservation.metadata().public_key(), &pk);
            assert_eq!(advertisement.endpoints(), &[endpoint_a]);

            oracle.track(1, primary([(pk.clone(), dialable(endpoint_b))]));

            let (peer_mailbox, mut peer_rx) = peer::Mailbox::new(NZUsize!(1));
            let _ = mailbox.connect(pk.clone(), peer_mailbox);
            assert!(
                matches!(peer_rx.next().await, Some(peer::Message::Kill)),
                "connect rejection is signaled by killing the peer"
            );
        });
    }

    #[test]
    fn test_reserved_peer_killed_on_connect_after_overwrite() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (my_sk, _) = new_signer_and_pk(0);
            let pk = new_signer_and_pk(1).1;
            let endpoint_a = Endpoint(1001);

            let cfg = test_config(my_sk);
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            oracle.track(0, primary([(pk.clone(), dialable(endpoint_a.clone()))]));

            let (reservation, advertisement) =
                mailbox.dial(pk.clone()).await.expect("peer should reserve");
            assert_eq!(reservation.metadata().public_key(), &pk);
            assert_eq!(advertisement.endpoints(), &[endpoint_a]);

            oracle.overwrite(primary([(pk.clone(), dialable(Endpoint(1002)))]));

            let (peer_mailbox, mut peer_rx) = peer::Mailbox::new(NZUsize!(1));
            let _ = mailbox.connect(pk.clone(), peer_mailbox);
            assert!(
                matches!(peer_rx.next().await, Some(peer::Message::Kill)),
                "connect rejection is signaled by killing the peer"
            );
        });
    }

    #[test]
    fn test_outbound_only_peer_remains_acceptable_after_overwrite() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (my_sk, _) = new_signer_and_pk(0);
            let pk = new_signer_and_pk(1).1;

            let cfg = test_config(my_sk);
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            oracle.track(0, primary([(pk.clone(), dialable(Endpoint(1001)))]));
            assert!(mailbox.acceptable(pk.clone()).await);

            oracle.overwrite(primary([(pk.clone(), Reachability::OutboundOnly)]));

            assert!(mailbox.acceptable(pk.clone()).await);
            assert!(mailbox.dial(pk.clone()).await.is_none());
            let reservation = mailbox.listen(pk).await;
            assert!(reservation.is_some());
        });
    }

    #[test]
    fn test_overwrite_updates_advertisement() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (my_sk, my_pk) = new_signer_and_pk(0);

            let pk_1 = new_signer_and_pk(1).1;

            let cfg = test_config(my_sk);
            let TestHarness {
                mailbox,
                mut oracle,
            } = setup_actor(context.child("actor"), cfg);

            oracle.track(
                0,
                primary([
                    (my_pk, dialable(Endpoint(9000))),
                    (pk_1.clone(), dialable(Endpoint(9001))),
                ]),
            );

            oracle.overwrite(primary([(pk_1.clone(), dialable(Endpoint(9002)))]));
            let (_, advertisement) = mailbox.dial(pk_1).await.unwrap();
            assert_eq!(advertisement.endpoints(), &[Endpoint(9002)]);
        });
    }

    #[test]
    fn test_overwrite_via_oracle() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            let (_, pk) = new_signer_and_pk(1);
            oracle.track(0, primary([(pk.clone(), dialable(Endpoint(1001)))]));
            context.sleep(Duration::from_millis(10)).await;

            let result = mailbox.dial(pk.clone()).await;
            assert!(result.is_some());
            let (_, advertisement) = result.unwrap();
            assert_eq!(advertisement.endpoints(), &[Endpoint(1001)]);

            oracle.overwrite(primary([(pk.clone(), dialable(Endpoint(1002)))]));

            context.sleep(Duration::from_millis(1010)).await;

            let result = mailbox.dial(pk.clone()).await;
            assert!(result.is_some());
            let (_, advertisement) = result.unwrap();
            assert_eq!(advertisement.endpoints(), &[Endpoint(1002)]);
        });
    }

    #[test]
    fn test_overwrite_blocked_peer_remains_unacceptable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (my_sk, my_pk) = new_signer_and_pk(0);

            let pk_1 = new_signer_and_pk(1).1;

            let cfg = test_config(my_sk);
            let TestHarness {
                mailbox,
                mut oracle,
            } = setup_actor(context.child("actor"), cfg);

            oracle.track(
                0,
                primary([
                    (my_pk, dialable(Endpoint(9000))),
                    (pk_1.clone(), dialable(Endpoint(9001))),
                ]),
            );

            crate::block_peer(&mut oracle, pk_1.clone());
            assert!(!mailbox.acceptable(pk_1.clone()).await);

            oracle.overwrite(primary([(pk_1.clone(), dialable(Endpoint(9002)))]));

            assert!(!mailbox.acceptable(pk_1).await);
        });
    }

    #[test]
    fn test_overwrite_untracked_peer_silently_ignored() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(PrivateKey::from_seed(0));
            let TestHarness { mut oracle, .. } = setup_actor(context.child("actor"), cfg);

            let (_, pk) = new_signer_and_pk(1);
            // Peer not in the directory is silently skipped (no error, no effect)
            oracle.overwrite(primary([(pk, dialable(Endpoint(1001)))]));
        });
    }

    #[test]
    fn test_overwrite_preserves_acceptability() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pk_1 = new_signer_and_pk(1).1;

            let cfg = test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            oracle.track(0, primary([(pk_1.clone(), dialable(Endpoint(9001)))]));
            context.sleep(Duration::from_millis(10)).await;

            assert!(mailbox.acceptable(pk_1.clone()).await);

            oracle.overwrite(primary([(pk_1.clone(), dialable(Endpoint(9002)))]));

            assert!(mailbox.acceptable(pk_1).await);
        });
    }

    #[test]
    fn test_overwrite_severs_existing_connection() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            let (_, pk) = new_signer_and_pk(1);
            oracle.track(0, primary([(pk.clone(), dialable(Endpoint(1001)))]));
            context.sleep(Duration::from_millis(10)).await;

            // Establish connection
            let reservation = mailbox.listen(pk.clone()).await;
            assert!(reservation.is_some());

            let (peer_mailbox, mut peer_rx) = peer::Mailbox::new(NZUsize!(1));
            let _ = mailbox.connect(pk.clone(), peer_mailbox);

            // Update address - should kill the connection
            oracle.overwrite(primary([(pk.clone(), dialable(Endpoint(1002)))]));

            // Peer should receive kill message
            assert!(matches!(peer_rx.next().await, Some(peer::Message::Kill)));
        });
    }

    #[test]
    fn test_add_set_severs_connection_on_address_change() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            let (_, pk) = new_signer_and_pk(1);
            // Register peer set with peer at address A
            oracle.track(0, primary([(pk.clone(), dialable(Endpoint(1001)))]));

            // Establish connection to peer
            let reservation = mailbox.listen(pk.clone()).await;
            assert!(reservation.is_some());

            let (peer_mailbox, mut peer_rx) = peer::Mailbox::new(NZUsize!(1));
            let _ = mailbox.connect(pk.clone(), peer_mailbox);

            // Register new peer set with same peer at address B
            oracle.track(1, primary([(pk.clone(), dialable(Endpoint(1002)))]));

            // Peer should receive Kill message (connection severed due to address change)
            assert!(matches!(peer_rx.next().await, Some(peer::Message::Kill)));

            drop(reservation);
            context.sleep(Duration::from_millis(210)).await;
            let (_, advertisement) = mailbox.dial(pk).await.unwrap();
            assert_eq!(advertisement.endpoints(), &[Endpoint(1002)]);
        });
    }

    #[test]
    fn test_overwrite_batch_mixed_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config(PrivateKey::from_seed(0));
            let TestHarness {
                mailbox,
                mut oracle,
                ..
            } = setup_actor(context.child("actor"), cfg);

            let (_, pk_tracked) = new_signer_and_pk(1);
            let (_, pk_unchanged) = new_signer_and_pk(2);
            let (_, pk_untracked) = new_signer_and_pk(3);

            // Register some peers
            oracle.track(
                0,
                primary([
                    (pk_tracked.clone(), dialable(Endpoint(1001))),
                    (pk_unchanged.clone(), dialable(Endpoint(1003))),
                ]),
            );

            // Establish connection to pk_tracked
            let reservation = mailbox.listen(pk_tracked.clone()).await;
            assert!(reservation.is_some());
            let (tracked_mailbox, mut tracked_rx) = peer::Mailbox::new(NZUsize!(1));
            let _ = mailbox.connect(pk_tracked.clone(), tracked_mailbox);

            // Establish connection to pk_unchanged
            let reservation = mailbox.listen(pk_unchanged.clone()).await;
            assert!(reservation.is_some());
            let (unchanged_mailbox, mut unchanged_rx) = peer::Mailbox::new(NZUsize!(1));
            let _ = mailbox.connect(pk_unchanged.clone(), unchanged_mailbox);

            // Call overwrite with mix of tracked+changed, tracked+unchanged, and unknown peers
            oracle.overwrite(primary([
                (pk_tracked.clone(), dialable(Endpoint(1002))),
                (pk_unchanged.clone(), dialable(Endpoint(1003))),
                (pk_untracked.clone(), dialable(Endpoint(1001))),
            ]));

            // Only tracked+changed peer (pk_tracked) gets killed
            assert!(matches!(tracked_rx.next().await, Some(peer::Message::Kill)));

            // Unchanged peer should NOT receive kill - verify the receiver has no pending messages.
            assert!(
                !matches!(
                    unchanged_rx.next().now_or_never(),
                    Some(Some(peer::Message::Kill))
                ),
                "Unchanged peer should not receive kill"
            );
        });
    }
}
