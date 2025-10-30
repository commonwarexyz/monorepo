use super::{
    directory::{self, Directory},
    ingress::{Message, Oracle},
    Config,
};
use crate::authenticated::{
    discovery::{
        actors::tracker::ingress::Releaser,
        types::{self, Info, InfoVerifier},
    },
    mailbox::UnboundedMailbox,
};
use commonware_cryptography::Signer;
use commonware_runtime::{
    spawn_cell, Clock, ContextCell, Handle, Metrics as RuntimeMetrics, Spawner,
};
use commonware_utils::{set::Ordered, union, SystemTimeExt};
use futures::{channel::mpsc, StreamExt};
use governor::clock::Clock as GClock;
use rand::{seq::SliceRandom, Rng};
use tracing::debug;

// Bytes to add to the namespace to prevent replay attacks.
const NAMESPACE_SUFFIX_IP: &[u8] = b"_IP";

/// The tracker actor that manages peer discovery and connection reservations.
pub struct Actor<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: Signer> {
    context: ContextCell<E>,

    // ---------- Configuration ----------
    /// For signing and verifying messages.
    crypto: C,

    /// The maximum number of peers in a set.
    max_peer_set_size: u64,

    /// The maximum number of [types::Info] allowable in a single message.
    peer_gossip_max_count: usize,

    // ---------- Message-Passing ----------
    /// The unbounded mailbox for the actor.
    ///
    /// We use this to support sending a [`Message::Release`] message to the actor
    /// during [`Drop`]. While this channel is unbounded, it is practically bounded by
    /// the number of peers we can connect to at one time.
    receiver: mpsc::UnboundedReceiver<Message<C::PublicKey>>,

    // ---------- State ----------
    /// Tracks peer sets and peer connectivity information.
    directory: Directory<E, C::PublicKey>,

    /// Subscribers to peer set updates.
    #[allow(clippy::type_complexity)]
    subscribers: Vec<mpsc::UnboundedSender<(u64, Ordered<C::PublicKey>, Ordered<C::PublicKey>)>>,
}

impl<E: Spawner + Rng + Clock + GClock + RuntimeMetrics, C: Signer> Actor<E, C> {
    /// Create a new tracker [Actor] from the given `context` and `cfg`.
    #[allow(clippy::type_complexity)]
    pub fn new(
        context: E,
        cfg: Config<C>,
    ) -> (
        Self,
        UnboundedMailbox<Message<C::PublicKey>>,
        Oracle<C::PublicKey>,
        InfoVerifier<C::PublicKey>,
    ) {
        // Sign my own information
        let socket = cfg.address;
        let timestamp = context.current().epoch_millis();
        let ip_namespace = union(&cfg.namespace, NAMESPACE_SUFFIX_IP);
        let myself = types::Info::sign(&cfg.crypto, &ip_namespace, socket, timestamp);

        // General initialization
        let directory_cfg = directory::Config {
            max_sets: cfg.tracked_peer_sets,
            dial_fail_limit: cfg.dial_fail_limit,
            rate_limit: cfg.allowed_connection_rate_per_peer,
        };

        // Create the mailboxes
        let (mailbox, receiver) = UnboundedMailbox::new();
        let oracle = Oracle::new(mailbox.clone());
        let releaser = Releaser::new(mailbox.clone());

        // Create the directory
        let directory = Directory::init(
            context.with_label("directory"),
            cfg.bootstrappers,
            myself,
            directory_cfg,
            releaser,
        );

        // Create peer validator
        let info_verifier = Info::verifier(
            cfg.crypto.public_key(),
            cfg.allow_private_ips,
            cfg.peer_gossip_max_count,
            cfg.synchrony_bound,
            ip_namespace,
        );

        (
            Self {
                context: ContextCell::new(context),
                crypto: cfg.crypto,
                max_peer_set_size: cfg.max_peer_set_size,
                peer_gossip_max_count: cfg.peer_gossip_max_count,
                receiver,
                directory,
                subscribers: Vec::new(),
            },
            mailbox,
            oracle,
            info_verifier,
        )
    }

    /// Start the actor and run it in the background.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
        while let Some(msg) = self.receiver.next().await {
            self.handle_msg(msg).await;
        }
        debug!("tracker shutdown");
    }

    /// Handle a [`Message`].
    async fn handle_msg(&mut self, msg: Message<C::PublicKey>) {
        match msg {
            Message::Register { index, peers } => {
                // Ensure that peer set is not too large.
                // Panic since there is no way to recover from this.
                let len = peers.len();
                let max = self.max_peer_set_size;
                assert!(len as u64 <= max, "peer set too large: {len} > {max}");
                self.directory.add_set(index, peers.clone());

                // Notify all subscribers about the new peer set
                self.subscribers.retain(|subscriber| {
                    subscriber
                        .unbounded_send((index, peers.clone(), self.directory.tracked()))
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
                dialer,
                mut peer,
            } => {
                // Kill if peer is not authorized
                if !self.directory.allowed(&public_key) {
                    peer.kill().await;
                    return;
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
                    return;
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
                    return;
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
            Message::Peers { peers } => {
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

                // We don't have to kill the peer now. It will be sent a `Kill` message the next
                // time it sends the `Connect` or `Construct` message to the tracker.
            }
            Message::Release { metadata } => {
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
        authenticated::{
            discovery::{
                actors::{peer, tracker},
                config::Bootstrapper,
                types,
            },
            Mailbox,
        },
        Blocker,
        Manager,
        // Blocker is implicitly available via oracle.block() due to Oracle implementing crate::Blocker
    };
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey, Signature},
        PrivateKeyExt as _, Signer,
    };
    use commonware_runtime::{deterministic, Clock, Runner};
    use commonware_utils::{bitmap::BitMap, set::Ordered, NZU32};
    use futures::future::Either;
    use governor::Quota;
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };
    use types::Info;

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
            allow_private_ips: true,
            synchrony_bound: Duration::from_secs(10),
            tracked_peer_sets: 2,
            allowed_connection_rate_per_peer: Quota::per_second(NZU32!(5)),
            peer_gossip_max_count: 5,
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

    // Helper to create Info
    fn new_peer_info(
        signer: &mut PrivateKey,
        ip_namespace: &[u8],
        socket: SocketAddr,
        timestamp: u64,
        target_pk_override: Option<PublicKey>,
        make_sig_invalid: bool,
    ) -> Info<PublicKey> {
        let peer_info_pk = target_pk_override.unwrap_or_else(|| signer.public_key());
        let mut signature = signer.sign(Some(ip_namespace), &(socket, timestamp).encode());

        if make_sig_invalid && !signature.as_ref().is_empty() {
            let mut sig_bytes = signature.encode();
            sig_bytes[0] = sig_bytes[0].wrapping_add(1);
            signature = Signature::decode(sig_bytes).unwrap();
        }

        Info {
            socket,
            timestamp,
            public_key: peer_info_pk,
            signature,
        }
    }

    // Mock a connection to a peer by reserving it as if it had dialed us and the `peer` actor had
    // sent an initialization.
    async fn connect_to_peer(
        mailbox: &mut UnboundedMailbox<Message<PublicKey>>,
        peer: &PublicKey,
        peer_mailbox: &Mailbox<peer::Message<PublicKey>>,
        peer_receiver: &mut mpsc::Receiver<peer::Message<PublicKey>>,
    ) -> tracker::Reservation<PublicKey> {
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
        mailbox: UnboundedMailbox<Message<PublicKey>>,
        oracle: Oracle<PublicKey>,
        ip_namespace: Vec<u8>,
        tracker_pk: PublicKey,
        cfg: Config<PrivateKey>, // Store cloned config for access to its values
    }

    fn setup_actor(
        runner_context: deterministic::Context,
        cfg_to_clone: Config<PrivateKey>, // Pass by value to allow cloning
    ) -> TestHarness {
        let tracker_signer = cfg_to_clone.crypto.clone();
        let tracker_pk = tracker_signer.public_key();
        let ip_namespace_base = cfg_to_clone.namespace.clone();
        let stored_cfg = cfg_to_clone.clone(); // Clone for storing in harness

        // Actor::new takes ownership, so clone again if cfg_to_clone is needed later
        let (actor, mailbox, oracle, _) = Actor::new(runner_context, cfg_to_clone);
        let ip_namespace = union(&ip_namespace_base, super::NAMESPACE_SUFFIX_IP);
        actor.start();

        TestHarness {
            mailbox,
            oracle,
            ip_namespace,
            tracker_pk,
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
            let too_many_peers: Ordered<PublicKey> = (1..=cfg.max_peer_set_size + 1)
                .map(|i| new_signer_and_pk(i).1)
                .collect();
            oracle.update(0, too_many_peers).await;
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
            let (peer_mailbox, mut peer_receiver) = Mailbox::new(1);

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
            let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
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
                .update(0, Ordered::from([tracker_pk.clone(), auth_pk.clone()]))
                .await;
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox, mut peer_receiver) = Mailbox::new(1);

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
                default_test_config(PrivateKey::from_seed(0), vec![(boot_pk.clone(), boot_addr)]);
            let TestHarness {
                mailbox: mut new_mailbox,
                ..
            } = setup_actor(context.clone(), cfg_with_boot);

            let (peer_mailbox, mut peer_receiver) = Mailbox::new(1);
            new_mailbox.construct(boot_pk.clone(), peer_mailbox.clone());

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
    fn test_handle_bit_vec_for_unknown_index_sends_no_peers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                tracker_pk,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_, pk1) = new_signer_and_pk(1);
            oracle
                .update(0, Ordered::from([tracker_pk, pk1.clone()]))
                .await;
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox_pk1, mut peer_receiver_pk1) = Mailbox::new(1);
            let bit_vec_unknown_idx = types::BitVec {
                index: 99,
                bits: BitMap::ones(1),
            };

            let _r1 = connect_to_peer(
                &mut mailbox,
                &pk1,
                &peer_mailbox_pk1,
                &mut peer_receiver_pk1,
            )
            .await;

            // Peer lets us know it received a bit vector
            mailbox.bit_vec(bit_vec_unknown_idx, peer_mailbox_pk1.clone());

            // No message is sent back to the peer
            assert!(peer_receiver_pk1.try_next().is_err());
        });
    }

    #[test]
    fn test_block_peer_standard_behavior() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                tracker_pk,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_s1_signer, pk1) = new_signer_and_pk(1);
            oracle
                .update(0, Ordered::from([tracker_pk.clone(), pk1.clone()]))
                .await;
            context.sleep(Duration::from_millis(10)).await;

            oracle.block(pk1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox_pk1, mut peer_receiver_pk1) = Mailbox::new(1);
            mailbox.construct(pk1.clone(), peer_mailbox_pk1.clone());

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
            let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                tracker_pk,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_s1_signer, pk1) = new_signer_and_pk(1);
            oracle
                .update(0, Ordered::from([tracker_pk.clone(), pk1.clone()]))
                .await;
            context.sleep(Duration::from_millis(10)).await;

            oracle.block(pk1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;
            oracle.block(pk1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox_pk1, mut peer_receiver_pk1) = Mailbox::new(1);
            mailbox.construct(pk1.clone(), peer_mailbox_pk1.clone());
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
            let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
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
            let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
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
                .update(0, Ordered::from([tracker_pk.clone(), pk1.clone()]))
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

            let set1 = Ordered::from([tracker_pk.clone(), pk1.clone(), pk2.clone()]);
            oracle.update(1, set1.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox_s1, mut peer_receiver_s1) = Mailbox::new(1);
            let (peer_mailbox_s2, mut peer_receiver_s2) = Mailbox::new(1);
            mailbox.peers(vec![pk2_info.clone()]);
            context.sleep(Duration::from_millis(10)).await;

            let _r1 =
                connect_to_peer(&mut mailbox, &pk1, &peer_mailbox_s1, &mut peer_receiver_s1).await;
            let _r2 =
                connect_to_peer(&mut mailbox, &pk2, &peer_mailbox_s2, &mut peer_receiver_s2).await;

            // Act as if pk1 received a bit vector where pk2 is not known.
            let mut bv = BitMap::zeroes(set1.len() as u64);
            let idx_tracker_in_set1 = set1.iter().position(|p| p == &tracker_pk).unwrap();
            let idx_pk1_in_set1 = set1.iter().position(|p| p == &pk1).unwrap();
            bv.set(idx_tracker_in_set1 as u64, true);
            bv.set(idx_pk1_in_set1 as u64, true);
            mailbox.bit_vec(
                types::BitVec { index: 1, bits: bv },
                peer_mailbox_s1.clone(),
            );
            match peer_receiver_s1.next().await {
                Some(peer::Message::Peers(received_peers_info)) => {
                    assert_eq!(received_peers_info.len(), 1);
                    let received_pk2_info = &received_peers_info[0];
                    assert_eq!(received_pk2_info.public_key, pk2);
                    assert_eq!(received_pk2_info.socket, pk2_addr);
                    assert_eq!(received_pk2_info.timestamp, pk2_timestamp);
                }
                _ => panic!("pk1 did not receive expected Info for pk2",),
            }
        });
    }

    #[test]
    fn test_handle_peers_rejects_older_info_for_known_peer() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                ip_namespace,
                tracker_pk,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let ts_new = context.current().epoch_millis();
            let ts_old = ts_new.saturating_sub(100);

            let (_, pk1) = new_signer_and_pk(1);
            let (mut s2_signer, pk2) = new_signer_and_pk(2);

            let peer_set_0_peers = Ordered::from([tracker_pk.clone(), pk1.clone(), pk2.clone()]);
            oracle.update(0, peer_set_0_peers.clone()).await;
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

            let (peer_mailbox_s1, mut peer_receiver_s1) = Mailbox::new(1);
            let _r1 =
                connect_to_peer(&mut mailbox, &pk1, &peer_mailbox_s1, &mut peer_receiver_s1).await;

            // Connect to pk2
            let (peer_mailbox_s2, mut peer_receiver_s2) = Mailbox::new(1);
            let _r2 =
                connect_to_peer(&mut mailbox, &pk2, &peer_mailbox_s2, &mut peer_receiver_s2).await;

            mailbox.peers(vec![pk2_info_initial.clone()]);
            context.sleep(Duration::from_millis(10)).await;

            let pk2_info_older = new_peer_info(
                &mut s2_signer,
                &ip_namespace,
                pk2_addr,
                ts_old,
                Some(pk2.clone()),
                false,
            );
            mailbox.peers(vec![pk2_info_older]);
            context.sleep(Duration::from_millis(10)).await;

            let mut knowledge_for_set0 = BitMap::zeroes(peer_set_0_peers.len() as u64);
            let idx_tracker_in_set0 = peer_set_0_peers.position(&tracker_pk).unwrap();
            let idx_pk1_in_set0 = peer_set_0_peers.position(&pk1).unwrap();
            knowledge_for_set0.set(idx_tracker_in_set0 as u64, true);
            knowledge_for_set0.set(idx_pk1_in_set0 as u64, true);

            let bit_vec_from_pk1 = types::BitVec {
                index: 0,
                bits: knowledge_for_set0,
            };
            mailbox.bit_vec(bit_vec_from_pk1, peer_mailbox_s1.clone());

            match peer_receiver_s1.next().await {
                Some(peer::Message::Peers(received_peers_info)) => {
                    assert_eq!(received_peers_info.len(), 1);
                    let received_pk2_info = &received_peers_info[0];
                    assert_eq!(received_pk2_info.public_key, pk2);
                    assert_eq!(received_pk2_info.timestamp, ts_new);
                }
                _ => panic!("pk1 did not receive Info as expected"),
            }
        });
    }

    #[test]
    fn test_listenable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (peer_signer, peer_pk) = new_signer_and_pk(0);
            let (_peer_signer2, peer_pk2) = new_signer_and_pk(1);
            let (_peer_signer3, peer_pk3) = new_signer_and_pk(2);
            let cfg_initial = default_test_config(peer_signer, Vec::new());
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
                .update(0, Ordered::from([peer_pk.clone(), peer_pk2.clone()]))
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
            let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_peer_signer, peer_pk) = new_signer_and_pk(1);

            let reservation = mailbox.listen(peer_pk.clone()).await;
            assert!(reservation.is_none());

            oracle.update(0, Ordered::from([peer_pk.clone()])).await;
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
                    crate::authenticated::discovery::actors::tracker::Metadata::Dialer(
                        pk,
                        addr,
                    ) => {
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
    fn test_bitvec_kill_on_length_mismatch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
            let TestHarness {
                mut mailbox,
                mut oracle,
                tracker_pk,
                ..
            } = setup_actor(context.clone(), cfg_initial);

            let (_s1, pk1) = new_signer_and_pk(1);
            let (_s2, pk2) = new_signer_and_pk(2);
            oracle
                .update(0, Ordered::from([tracker_pk, pk1.clone(), pk2.clone()]))
                .await;
            context.sleep(Duration::from_millis(10)).await;

            let (peer_mailbox, mut peer_receiver) = Mailbox::new(1);
            let invalid_bit_vec = types::BitVec {
                index: 0,
                bits: BitMap::ones(2),
            };
            mailbox.bit_vec(invalid_bit_vec, peer_mailbox.clone());
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
            let cfg_initial = default_test_config(PrivateKey::from_seed(0), Vec::new());
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
            let (peer_mailbox1, mut peer_receiver1) = Mailbox::new(1);
            mailbox.construct(peer1_pk.clone(), peer_mailbox1.clone());
            assert!(
                matches!(peer_receiver1.next().await, Some(peer::Message::Kill)),
                "Unauthorized peer killed on Construct"
            );

            // --- Register set 0, then Construct for authorized peer1 ---
            let set0_peers =
                Ordered::from([tracker_pk.clone(), peer1_pk.clone(), peer2_pk.clone()]);
            oracle.update(0, set0_peers.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let _r1 =
                connect_to_peer(&mut mailbox, &peer1_pk, &peer_mailbox1, &mut peer_receiver1).await;

            mailbox.construct(peer1_pk.clone(), peer_mailbox1.clone());
            let bit_vec0 = match peer_receiver1.next().await {
                Some(peer::Message::BitVec(bv)) => bv,
                _ => panic!("Expected BitVec for set 0"),
            };
            assert_eq!(bit_vec0.index, 0);
            assert_eq!(bit_vec0.bits.len(), set0_peers.len() as u64);
            let tracker_idx_s0 = set0_peers.iter().position(|p| p == &tracker_pk).unwrap();
            assert!(
                bit_vec0.bits.get(tracker_idx_s0 as u64),
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
            mailbox.peers(vec![peer1_info]);
            context.sleep(Duration::from_millis(10)).await;

            mailbox.construct(peer1_pk.clone(), peer_mailbox1.clone());
            let bit_vec0_updated = match peer_receiver1.next().await {
                Some(peer::Message::BitVec(bv)) => bv,
                _ => panic!("Expected updated BitVec for set 0"),
            };
            let peer1_idx_s0 = set0_peers.iter().position(|p| p == &peer1_pk).unwrap();
            assert!(bit_vec0_updated.bits.get(tracker_idx_s0 as u64));
            assert!(
                bit_vec0_updated.bits.get(peer1_idx_s0 as u64),
                "Tracker should know peer1 in set 0 after Peers msg"
            );

            // --- Peer1 sends BitVec for set 0, indicating it only knows tracker ---
            // Tracker should respond with Info for peer1_pk (as it just learned it)
            let mut peer1_knowledge_s0 = BitMap::zeroes(set0_peers.len() as u64);
            peer1_knowledge_s0.set(tracker_idx_s0 as u64, true); // Peer1 knows tracker
            mailbox.bit_vec(
                types::BitVec {
                    index: 0,
                    bits: peer1_knowledge_s0,
                },
                peer_mailbox1.clone(),
            );

            match peer_receiver1.next().await {
                Some(peer::Message::Peers(infos)) => {
                    assert_eq!(infos.len(), 1, "Expected 1 Info (for peer1)");
                    assert_eq!(infos[0].public_key, peer1_pk);
                    assert_eq!(infos[0].socket, peer1_addr);
                }
                _ => panic!("Expected Peers message from tracker"),
            }

            // --- Set eviction and peer killing ---
            let (_peer3_s, peer3_pk) = new_signer_and_pk(3);
            let set1_peers = Ordered::from([tracker_pk.clone(), peer2_pk.clone()]); // New set without peer1
            oracle.update(1, set1_peers.clone()).await;
            context.sleep(Duration::from_millis(10)).await;

            let set2_peers = Ordered::from([tracker_pk.clone(), peer3_pk.clone()]); // Another new set without peer1
            oracle.update(2, set2_peers.clone()).await; // This should evict set 0 (max_sets = 2)
            context.sleep(Duration::from_millis(10)).await;

            // Peer1 was only in set 0, which is now evicted.
            // Construct for peer1 should now result in Kill because it's not in any active tracked set.
            mailbox.construct(peer1_pk.clone(), peer_mailbox1.clone());
            assert!(
                matches!(peer_receiver1.next().await, Some(peer::Message::Kill)),
                "Peer1 should be killed after its only set was evicted"
            );

            // Peer2 is in set1 (still active)
            let (peer_mailbox2, mut peer_receiver2) = Mailbox::new(1);
            let _r2 =
                connect_to_peer(&mut mailbox, &peer2_pk, &peer_mailbox2, &mut peer_receiver2).await;

            // Run this several times since the bitvec given may have index 1 or 2.
            let mut indices = HashSet::new();
            for _ in 0..100 {
                mailbox.construct(peer2_pk.clone(), peer_mailbox2.clone());
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
