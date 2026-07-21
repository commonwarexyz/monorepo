//! Transport-neutral peer management for DKG.

use commonware_actor::Feedback;
use commonware_consensus::types::Epoch;
use commonware_cryptography::PublicKey;
use commonware_p2p::{
    Address, AddressableManager as P2pAddressableManager, AddressableTrackedPeers,
    Manager as P2pManager, Provider, TrackedPeers,
};
use commonware_utils::ordered::{Map, Set};
use std::{convert::Infallible, fmt, future::Future};
use thiserror::Error;

/// Interface for activating the peers used by a DKG epoch.
pub trait Manager: Provider {
    /// Error returned when a peer set cannot be activated.
    ///
    /// DKG actors stop when this error is returned. Implementations MUST retry
    /// transient failures before returning an error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Activates `peers` for `epoch`.
    ///
    /// The returned [`Feedback`] is exposed for callers that need it. DKG
    /// actors preserve the key-only manager's fire-and-forget contract and do
    /// not interpret it.
    fn track(
        &mut self,
        epoch: Epoch,
        peers: TrackedPeers<Self::PublicKey>,
    ) -> impl Future<Output = Result<Feedback, Self::Error>> + Send;
}

impl<M: P2pManager> Manager for M {
    type Error = Infallible;

    async fn track(
        &mut self,
        epoch: Epoch,
        peers: TrackedPeers<Self::PublicKey>,
    ) -> Result<Feedback, Self::Error> {
        Ok(P2pManager::track(self, epoch.get(), peers))
    }
}

/// Supplies stable, epoch-scoped addresses for DKG participants.
///
/// [`addresses`](Self::addresses) returns the address snapshot used while `epoch`
/// is active. The requested keys are the epoch's dealers, players, and next
/// players. Every requested key MUST be present. The provider may return
/// unrelated entries, which are ignored.
///
/// For a given epoch and requested key, every honest node MUST return the same
/// [`Address`]. Repeated calls MUST remain stable across restarts and duplicate
/// probe or orchestrator registrations.
///
/// The snapshot for epoch `E` MUST be locked before honest nodes propose or
/// verify the final block of `E - 1`, because that boundary announces the peer
/// roles activated in `E`. A participant first announced as a next player in
/// [`EpochInfo`] for `E` MUST already have an address in snapshot `E`, allowing it to
/// connect during `E`, one epoch before it becomes a player.
///
/// An address update submitted during epoch `E` takes effect only in snapshot
/// `E + 1`. Implementations MUST NOT expose the update through a later call for
/// epoch `E`. Mid-epoch [`commonware_p2p::AddressableManager::overwrite`] is
/// outside the DKG contract and MUST NOT mutate addresses for the active DKG
/// peer set. The next [`Manager::track`] applies the changed snapshot at the
/// epoch boundary, allowing lookup to replace stale connections.
///
/// [`EpochInfo`]: crate::dkg::types::EpochInfo
pub trait AddressProvider: Clone + Send + 'static {
    /// Public key type used to identify peers.
    type PublicKey: PublicKey;

    /// Error returned when an address snapshot cannot be loaded.
    ///
    /// DKG actors stop and do not retry address resolution when this error is
    /// returned. Implementations MUST retry transient failures internally.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns the address snapshot for the requested peers in `epoch`.
    fn addresses(
        &mut self,
        epoch: Epoch,
        peers: Set<Self::PublicKey>,
    ) -> impl Future<Output = Result<Map<Self::PublicKey, Address>, Self::Error>> + Send;
}

/// Adapts an addressable peer manager to DKG's key-only peer sets.
#[derive(Clone)]
pub struct AddressableManager<M, A> {
    manager: M,
    addresses: A,
}

impl<M, A> AddressableManager<M, A> {
    /// Creates an addressable DKG peer manager.
    pub const fn new(manager: M, addresses: A) -> Self {
        Self { manager, addresses }
    }
}

impl<M, A> fmt::Debug for AddressableManager<M, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddressableManager").finish_non_exhaustive()
    }
}

impl<M, A> Provider for AddressableManager<M, A>
where
    M: P2pAddressableManager,
    A: AddressProvider<PublicKey = M::PublicKey>,
{
    type PublicKey = M::PublicKey;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
        self.manager.peer_set(id).await
    }

    async fn subscribe(&mut self) -> commonware_p2p::PeerSetSubscription<Self::PublicKey> {
        self.manager.subscribe().await
    }
}

/// Error returned while activating an addressable DKG peer set.
#[derive(Debug, Error)]
pub enum AddressablePeerSetError<P: PublicKey, E: std::error::Error + 'static> {
    /// The address provider failed to load the epoch snapshot.
    #[error("address provider failed: {0}")]
    Provider(#[source] E),
    /// The epoch snapshot omitted a requested peer.
    #[error("address provider omitted peer {0:?}")]
    MissingAddress(P),
}

impl<M, A> Manager for AddressableManager<M, A>
where
    M: P2pAddressableManager,
    A: AddressProvider<PublicKey = M::PublicKey>,
{
    type Error = AddressablePeerSetError<M::PublicKey, A::Error>;

    async fn track(
        &mut self,
        epoch: Epoch,
        peers: TrackedPeers<Self::PublicKey>,
    ) -> Result<Feedback, Self::Error> {
        let requested = peers.clone().union();
        let addresses = self
            .addresses
            .addresses(epoch, requested)
            .await
            .map_err(AddressablePeerSetError::Provider)?;

        let primary = resolve(&peers.primary, &addresses)?;
        let secondary = resolve(&peers.secondary, &addresses)?;
        let peers = AddressableTrackedPeers::new(primary, secondary);

        Ok(self.manager.track(epoch.get(), peers))
    }
}

fn resolve<P: PublicKey, E: std::error::Error + 'static>(
    peers: &Set<P>,
    addresses: &Map<P, Address>,
) -> Result<Map<P, Address>, AddressablePeerSetError<P, E>> {
    let resolved = peers
        .iter()
        .map(|peer| {
            addresses
                .get_value(peer)
                .cloned()
                .map(|address| (peer.clone(), address))
                .ok_or_else(|| AddressablePeerSetError::MissingAddress(peer.clone()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Map::from_iter_dedup(resolved))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_macros::test_traced;
    use commonware_p2p::{
        PeerSetSubscription, Receiver as _, Recipients, Sender as _, authenticated::lookup,
    };
    use commonware_runtime::{
        Clock as _, Quota, Runner as _, Spawner as _, Supervisor as _, deterministic,
    };
    use commonware_utils::{NZU32, channel::mpsc, sync::Mutex};
    use futures::executor::block_on;
    use std::{
        convert::Infallible,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    type PublicKey = ed25519::PublicKey;
    type Tracked = Arc<Mutex<Vec<(u64, TrackedPeers<PublicKey>)>>>;
    type AddressableTracked = Arc<Mutex<Vec<(u64, AddressableTrackedPeers<PublicKey>)>>>;
    type Calls = Arc<Mutex<Vec<(Epoch, Set<PublicKey>)>>>;

    #[derive(Clone, Debug)]
    struct TestManager {
        feedback: Feedback,
        tracked: Tracked,
        addressable: AddressableTracked,
    }

    impl TestManager {
        fn new(feedback: Feedback) -> Self {
            Self {
                feedback,
                tracked: Arc::default(),
                addressable: Arc::default(),
            }
        }
    }

    impl Provider for TestManager {
        type PublicKey = PublicKey;

        async fn peer_set(&mut self, _id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
            None
        }

        async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
            let (_, receiver) = mpsc::unbounded_channel();
            receiver
        }
    }

    impl P2pManager for TestManager {
        fn track<R>(&mut self, id: u64, peers: R) -> Feedback
        where
            R: Into<TrackedPeers<Self::PublicKey>> + Send,
        {
            self.tracked.lock().push((id, peers.into()));
            self.feedback
        }
    }

    #[derive(Clone, Debug)]
    struct AddressableTestManager(TestManager);

    impl Provider for AddressableTestManager {
        type PublicKey = PublicKey;

        async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
            self.0.peer_set(id).await
        }

        async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
            self.0.subscribe().await
        }
    }

    impl P2pAddressableManager for AddressableTestManager {
        fn track<R>(&mut self, id: u64, peers: R) -> Feedback
        where
            R: Into<AddressableTrackedPeers<Self::PublicKey>> + Send,
        {
            self.0.addressable.lock().push((id, peers.into()));
            self.0.feedback
        }

        fn overwrite(&mut self, _peers: Map<Self::PublicKey, Address>) -> Feedback {
            self.0.feedback
        }
    }

    #[derive(Clone, Debug, Error, PartialEq, Eq)]
    #[error("provider failed")]
    struct ProviderFailed;

    #[derive(Clone)]
    struct TestAddressProvider {
        result: Result<Map<PublicKey, Address>, ProviderFailed>,
        calls: Calls,
    }

    impl AddressProvider for TestAddressProvider {
        type PublicKey = PublicKey;
        type Error = ProviderFailed;

        async fn addresses(
            &mut self,
            epoch: Epoch,
            peers: Set<Self::PublicKey>,
        ) -> Result<Map<Self::PublicKey, Address>, Self::Error> {
            self.calls.lock().push((epoch, peers));
            self.result.clone()
        }
    }

    fn key(seed: u8) -> PublicKey {
        ed25519::PrivateKey::from_seed(seed.into()).public_key()
    }

    fn address(port: u16) -> Address {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port).into()
    }

    fn peers() -> (TrackedPeers<PublicKey>, [PublicKey; 4]) {
        let keys = [key(1), key(2), key(3), key(4)];
        let peers = TrackedPeers::new(
            Set::from_iter_dedup([keys[0].clone(), keys[1].clone()]),
            Set::from_iter_dedup([keys[1].clone(), keys[2].clone()]),
        );
        (peers, keys)
    }

    #[test]
    fn key_only_feedback_is_preserved() {
        let (peers, _) = peers();
        for feedback in [Feedback::Ok, Feedback::Backoff, Feedback::Closed] {
            let mut manager = TestManager::new(feedback);
            assert_eq!(
                block_on(Manager::track(&mut manager, Epoch::new(7), peers.clone())),
                Ok(feedback)
            );
            assert_eq!(manager.tracked.lock()[0], (7, peers.clone()));
        }
    }

    #[test]
    fn addressable_mapping_preserves_roles_and_ignores_extras() {
        let (peers, keys) = peers();
        let addresses = Map::from_iter_dedup([
            (keys[0].clone(), address(1)),
            (keys[1].clone(), address(2)),
            (keys[2].clone(), address(3)),
            (keys[3].clone(), address(4)),
        ]);
        let calls: Calls = Arc::default();
        let provider = TestAddressProvider {
            result: Ok(addresses),
            calls: calls.clone(),
        };
        let inner = TestManager::new(Feedback::Ok);
        let tracked = inner.addressable.clone();
        let mut manager = AddressableManager::new(AddressableTestManager(inner), provider);

        let feedback =
            block_on(Manager::track(&mut manager, Epoch::new(9), peers.clone())).unwrap();
        assert_eq!(feedback, Feedback::Ok);

        assert_eq!(
            calls.lock().as_slice(),
            &[(Epoch::new(9), peers.clone().union())]
        );
        let tracked = tracked.lock();
        assert_eq!(tracked[0].0, 9);
        assert_eq!(tracked[0].1.primary.keys(), &peers.primary);
        assert_eq!(tracked[0].1.secondary.keys(), &peers.secondary);
        assert_eq!(tracked[0].1.primary.get_value(&keys[0]), Some(&address(1)));
        assert_eq!(tracked[0].1.primary.get_value(&keys[1]), Some(&address(2)));
        assert_eq!(
            tracked[0].1.secondary.get_value(&keys[1]),
            Some(&address(2))
        );
        assert_eq!(
            tracked[0].1.secondary.get_value(&keys[2]),
            Some(&address(3))
        );
    }

    #[test]
    fn addressable_errors_prevent_registration() {
        let (peers, keys) = peers();

        let inner = TestManager::new(Feedback::Ok);
        let tracked = inner.addressable.clone();
        let mut manager = AddressableManager::new(
            AddressableTestManager(inner),
            TestAddressProvider {
                result: Err(ProviderFailed),
                calls: Arc::default(),
            },
        );
        assert!(matches!(
            block_on(Manager::track(&mut manager, Epoch::new(1), peers.clone())),
            Err(AddressablePeerSetError::Provider(ProviderFailed))
        ));
        assert!(tracked.lock().is_empty());

        let inner = TestManager::new(Feedback::Ok);
        let tracked = inner.addressable.clone();
        let mut manager = AddressableManager::new(
            AddressableTestManager(inner),
            TestAddressProvider {
                result: Ok(Map::from_iter_dedup([(keys[0].clone(), address(1))])),
                calls: Arc::default(),
            },
        );
        assert!(matches!(
            block_on(Manager::track(&mut manager, Epoch::new(1), peers.clone())),
            Err(AddressablePeerSetError::MissingAddress(_))
        ));
        assert!(tracked.lock().is_empty());

        let addresses = Map::from_iter_dedup(
            peers
                .clone()
                .union()
                .into_iter()
                .enumerate()
                .map(|(index, peer)| (peer, address(index as u16 + 1))),
        );
        let mut manager = AddressableManager::new(
            AddressableTestManager(TestManager::new(Feedback::Closed)),
            TestAddressProvider {
                result: Ok(addresses),
                calls: Arc::default(),
            },
        );
        let feedback = block_on(Manager::track(&mut manager, Epoch::new(1), peers)).unwrap();
        assert_eq!(feedback, Feedback::Closed);
    }

    #[test]
    fn repeated_and_consecutive_epochs_use_their_snapshots() {
        #[derive(Clone)]
        struct EpochProvider {
            calls: Calls,
        }

        impl AddressProvider for EpochProvider {
            type PublicKey = PublicKey;
            type Error = Infallible;

            async fn addresses(
                &mut self,
                epoch: Epoch,
                peers: Set<Self::PublicKey>,
            ) -> Result<Map<Self::PublicKey, Address>, Self::Error> {
                self.calls.lock().push((epoch, peers.clone()));
                let port = if epoch == Epoch::new(4) { 4 } else { 5 };
                Ok(Map::from_iter_dedup(
                    peers.into_iter().map(|peer| (peer, address(port))),
                ))
            }
        }

        let (peers, _) = peers();
        let inner = TestManager::new(Feedback::Ok);
        let tracked = inner.addressable.clone();
        let calls: Calls = Arc::default();
        let mut manager = AddressableManager::new(
            AddressableTestManager(inner),
            EpochProvider {
                calls: calls.clone(),
            },
        );

        for epoch in [Epoch::new(4), Epoch::new(4), Epoch::new(5)] {
            block_on(Manager::track(&mut manager, epoch, peers.clone())).unwrap();
        }

        let requested = peers.union();
        assert_eq!(
            calls.lock().as_slice(),
            &[
                (Epoch::new(4), requested.clone()),
                (Epoch::new(4), requested.clone()),
                (Epoch::new(5), requested),
            ]
        );
        let tracked = tracked.lock();
        assert_eq!(tracked[0].1.primary.values(), tracked[1].1.primary.values());
        assert_ne!(tracked[1].1.primary.values(), tracked[2].1.primary.values());
    }

    #[test_traced]
    fn lookup_secondary_dials_primary_and_receives_response() {
        let executor = deterministic::Runner::timed(std::time::Duration::from_secs(10));
        executor.start(|context| async move {
            let dealer = ed25519::PrivateKey::from_seed(10);
            let participant = ed25519::PrivateKey::from_seed(11);
            let dealer_key = dealer.public_key();
            let participant_key = participant.public_key();
            let dealer_socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6100);
            let participant_socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6101);
            let addresses = Map::from_iter_dedup([
                (dealer_key.clone(), Address::Symmetric(dealer_socket)),
                (
                    participant_key.clone(),
                    Address::Asymmetric {
                        ingress: participant_socket.into(),
                        egress: participant_socket,
                    },
                ),
            ]);
            let peers = TrackedPeers::new(
                Set::from_iter_dedup([dealer_key.clone()]),
                Set::from_iter_dedup([participant_key.clone()]),
            );

            let (mut dealer_network, dealer_oracle) = lookup::Network::new(
                context.child("dealer"),
                lookup::Config::local(
                    dealer,
                    b"_COMMONWARE_GLUE_DKG_LOOKUP_TEST",
                    dealer_socket,
                    1024,
                ),
            );
            let (mut participant_network, participant_oracle) = lookup::Network::new(
                context.child("participant"),
                lookup::Config::local(
                    participant,
                    b"_COMMONWARE_GLUE_DKG_LOOKUP_TEST",
                    participant_socket,
                    1024,
                ),
            );
            let (mut dealer_sender, mut dealer_receiver) =
                dealer_network.register(0, Quota::per_second(NZU32!(100)), 16);
            let (mut participant_sender, mut participant_receiver) =
                participant_network.register(0, Quota::per_second(NZU32!(100)), 16);

            let provider = |addresses| TestAddressProvider {
                result: Ok(addresses),
                calls: Arc::default(),
            };
            let mut dealer_manager =
                AddressableManager::new(dealer_oracle, provider(addresses.clone()));
            let mut participant_manager =
                AddressableManager::new(participant_oracle, provider(addresses));
            Manager::track(&mut dealer_manager, Epoch::new(3), peers.clone())
                .await
                .unwrap();
            Manager::track(&mut participant_manager, Epoch::new(3), peers)
                .await
                .unwrap();

            dealer_network.start();
            participant_network.start();

            let request_sender = context.child("request_sender").spawn({
                let dealer_key = dealer_key.clone();
                move |context| async move {
                    loop {
                        participant_sender.send(
                            Recipients::One(dealer_key.clone()),
                            b"request".to_vec(),
                            true,
                        );
                        context.sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            });

            let (sender, request) = dealer_receiver.recv().await.unwrap();
            request_sender.abort();
            assert_eq!(sender, participant_key);
            assert_eq!(request.as_ref(), b"request");

            let response_sender = context.child("response_sender").spawn({
                let participant_key = participant_key.clone();
                move |context| async move {
                    loop {
                        dealer_sender.send(
                            Recipients::One(participant_key.clone()),
                            b"response".to_vec(),
                            true,
                        );
                        context.sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            });

            let (sender, response) = participant_receiver.recv().await.unwrap();
            response_sender.abort();
            assert_eq!(sender, dealer_key);
            assert_eq!(response.as_ref(), b"response");
        });
    }
}
