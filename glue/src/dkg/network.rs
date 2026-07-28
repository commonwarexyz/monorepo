//! Transport-neutral peer management for DKG.
//!
//! DKG peer identities are key-only in every ceremony artifact and wire
//! message. Transports that need more than a public key to dial a peer (like
//! [`commonware_p2p::authenticated::lookup`]) require an epoch-scoped
//! [`Directory`] carried in-band by [`EpochInfo`]: the final block of each
//! epoch embeds the next epoch's directory, so the same certificate-backed
//! artifact that names the committee also says how to reach it.
//!
//! Activation never consults application state. A node beginning state sync
//! initially holds only a certified [`EpochInfo`] (from
//! [`probe`](crate::dkg::probe) or the persisted
//! [`state_sync::Plan`](crate::dkg::state_sync::Plan)) and no synced state to
//! resolve addresses from, so [`Manager::track`] consumes only the peer set
//! and the directory embedded in that artifact. State-backed hooks
//! ([`ParticipantsProvider`](crate::dkg::ParticipantsProvider)) are consulted
//! only while building or verifying an epoch's final block, when the node is
//! fully synced.
//!
//! [`EpochInfo`]: crate::dkg::types::EpochInfo

use bytes::Buf;
use commonware_actor::Feedback;
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, Write};
use commonware_consensus::types::Epoch;
use commonware_cryptography::PublicKey;
use commonware_p2p::{
    Address, AddressableManager as P2pAddressableManager, AddressableTrackedPeers,
    Manager as P2pManager, Provider, TrackedPeers,
};
use commonware_utils::ordered::{Map, Set};
use std::{convert::Infallible, fmt, fmt::Debug};
use thiserror::Error;

/// Epoch-scoped reachability data for DKG participants, carried in-band by
/// [`EpochInfo`](crate::dkg::types::EpochInfo).
///
/// A directory is consensus data: the proposer of an epoch's final block embeds
/// the next epoch's directory in the epoch artifact and every verifier rebuilds
/// and compares it, so all honest nodes agree on one directory per epoch. It is
/// also the only reachability source used during recovery: restart and
/// state-sync entry activate peers from the artifact alone, without consulting
/// application state.
///
/// A directory MUST contain exactly the peers of its epoch (dealers, players,
/// and next players).
pub trait Directory<P: PublicKey>:
    Clone + Debug + PartialEq + Eq + Send + Sync + 'static + Read + Write + EncodeSize
{
    /// Returns whether the directory contains exactly `peers`.
    fn matches(&self, peers: &Set<P>) -> bool;
}

/// Key-only directory for transports that dial by public key alone.
impl<P: PublicKey> Directory<P> for () {
    fn matches(&self, _: &Set<P>) -> bool {
        true
    }
}

/// Address directory for transports that dial by [`Address`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Addresses<P: PublicKey>(Map<P, Address>);

impl<P: PublicKey> Addresses<P> {
    /// Returns the address recorded for `peer`, if any.
    pub fn get(&self, peer: &P) -> Option<&Address> {
        self.0.get_value(peer)
    }

    /// Returns the inner address map.
    pub fn into_inner(self) -> Map<P, Address> {
        self.0
    }
}

impl<P: PublicKey> From<Map<P, Address>> for Addresses<P> {
    fn from(addresses: Map<P, Address>) -> Self {
        Self(addresses)
    }
}

impl<P: PublicKey> FromIterator<(P, Address)> for Addresses<P> {
    fn from_iter<I: IntoIterator<Item = (P, Address)>>(iter: I) -> Self {
        Self(Map::from_iter_dedup(iter))
    }
}

impl<P: PublicKey> Write for Addresses<P> {
    fn write(&self, writer: &mut impl bytes::BufMut) {
        self.0.write(writer);
    }
}

impl<P: PublicKey> EncodeSize for Addresses<P> {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl<P: PublicKey> Read for Addresses<P> {
    /// Number of address entries accepted by the decoder.
    ///
    /// When decoding an [`EpochInfo`](crate::dkg::types::EpochInfo), this bound
    /// must accept the union of its dealers, players, and next players and
    /// reject larger directories.
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(Map::read_cfg(buf, &(*cfg, (), ()))?))
    }
}

impl<P: PublicKey> Directory<P> for Addresses<P> {
    fn matches(&self, peers: &Set<P>) -> bool {
        self.0.len() == peers.len() && peers.iter().all(|peer| self.0.get_value(peer).is_some())
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey> arbitrary::Arbitrary<'_> for Addresses<P>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
    }
}

/// Interface for activating the peers used by a DKG epoch.
pub trait Manager: Provider {
    /// In-band reachability data consumed when activating an epoch.
    type Directory: Directory<Self::PublicKey>;

    /// Error returned when a peer set cannot be activated.
    ///
    /// DKG actors stop when this error is returned.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Activates `peers` for `epoch` using the epoch's `directory`.
    ///
    /// The returned [`Feedback`] is exposed for callers that need it. DKG
    /// actors preserve the key-only manager's fire-and-forget contract and do
    /// not interpret it.
    fn track(
        &mut self,
        epoch: Epoch,
        peers: TrackedPeers<Self::PublicKey>,
        directory: &Self::Directory,
    ) -> Result<Feedback, Self::Error>;
}

impl<M: P2pManager> Manager for M {
    type Directory = ();
    type Error = Infallible;

    fn track(
        &mut self,
        epoch: Epoch,
        peers: TrackedPeers<Self::PublicKey>,
        _directory: &Self::Directory,
    ) -> Result<Feedback, Self::Error> {
        Ok(P2pManager::track(self, epoch.get(), peers))
    }
}

/// Adapts an addressable peer manager to DKG's key-only peer sets.
///
/// Activation resolves each tracked peer through the epoch's in-band
/// [`Addresses`] directory, preserving primary and secondary roles. Because the
/// directory arrives with the epoch artifact, restart and state-sync entry use
/// the same epoch-scoped addresses as an uninterrupted node, with no
/// out-of-band registry access.
#[derive(Clone)]
pub struct AddressableManager<M> {
    manager: M,
}

impl<M> AddressableManager<M> {
    /// Creates an addressable DKG peer manager.
    pub const fn new(manager: M) -> Self {
        Self { manager }
    }
}

impl<M> fmt::Debug for AddressableManager<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddressableManager").finish_non_exhaustive()
    }
}

impl<M> Provider for AddressableManager<M>
where
    M: P2pAddressableManager,
{
    type PublicKey = M::PublicKey;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
        self.manager.peer_set(id).await
    }

    async fn subscribe(&mut self) -> commonware_p2p::PeerSetSubscription<Self::PublicKey> {
        self.manager.subscribe().await
    }
}

/// The epoch directory omitted a tracked peer.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("epoch directory omitted peer {0:?}")]
pub struct MissingAddress<P: PublicKey>(pub P);

impl<M> Manager for AddressableManager<M>
where
    M: P2pAddressableManager,
{
    type Directory = Addresses<M::PublicKey>;
    type Error = MissingAddress<M::PublicKey>;

    fn track(
        &mut self,
        epoch: Epoch,
        peers: TrackedPeers<Self::PublicKey>,
        directory: &Self::Directory,
    ) -> Result<Feedback, Self::Error> {
        let primary = resolve(&peers.primary, directory)?;
        let secondary = resolve(&peers.secondary, directory)?;
        let peers = AddressableTrackedPeers::new(primary, secondary);

        Ok(self.manager.track(epoch.get(), peers))
    }
}

fn resolve<P: PublicKey>(
    peers: &Set<P>,
    directory: &Addresses<P>,
) -> Result<Map<P, Address>, MissingAddress<P>> {
    let resolved = peers
        .iter()
        .map(|peer| {
            directory
                .get(peer)
                .cloned()
                .map(|address| (peer.clone(), address))
                .ok_or_else(|| MissingAddress(peer.clone()))
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
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    type PublicKey = ed25519::PublicKey;
    type Tracked = Arc<Mutex<Vec<(u64, TrackedPeers<PublicKey>)>>>;
    type AddressableTracked = Arc<Mutex<Vec<(u64, AddressableTrackedPeers<PublicKey>)>>>;

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
                Manager::track(&mut manager, Epoch::new(7), peers.clone(), &()),
                Ok(feedback)
            );
            assert_eq!(manager.tracked.lock()[0], (7, peers.clone()));
        }
    }

    #[test]
    fn key_only_directory_matches_any_peer_set() {
        let (peers, _) = peers();
        assert!(Directory::matches(&(), &peers.union()));
    }

    #[test]
    fn addresses_requires_exact_peer_set() {
        let (peers, keys) = peers();
        let directory =
            Addresses::from_iter([(keys[0].clone(), address(1)), (keys[1].clone(), address(2))]);
        assert!(directory.matches(&peers.primary));
        assert!(!directory.matches(&peers.union()));
        assert!(!directory.matches(&Set::from_iter_dedup([keys[0].clone()])));
    }

    #[test]
    fn addressable_mapping_preserves_roles() {
        let (peers, keys) = peers();
        let directory = Addresses::from_iter([
            (keys[0].clone(), address(1)),
            (keys[1].clone(), address(2)),
            (keys[2].clone(), address(3)),
        ]);
        let inner = TestManager::new(Feedback::Ok);
        let tracked = inner.addressable.clone();
        let mut manager = AddressableManager::new(AddressableTestManager(inner));

        let feedback =
            Manager::track(&mut manager, Epoch::new(9), peers.clone(), &directory).unwrap();
        assert_eq!(feedback, Feedback::Ok);

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
    fn missing_address_prevents_registration() {
        let (peers, keys) = peers();

        let inner = TestManager::new(Feedback::Ok);
        let tracked = inner.addressable.clone();
        let mut manager = AddressableManager::new(AddressableTestManager(inner));
        let directory = Addresses::from_iter([(keys[0].clone(), address(1))]);
        assert_eq!(
            Manager::track(&mut manager, Epoch::new(1), peers.clone(), &directory),
            Err(MissingAddress(keys[1].clone()))
        );
        assert!(tracked.lock().is_empty());

        let directory = peers
            .clone()
            .union()
            .into_iter()
            .enumerate()
            .map(|(index, peer)| (peer, address(index as u16 + 1)))
            .collect::<Addresses<_>>();
        let mut manager =
            AddressableManager::new(AddressableTestManager(TestManager::new(Feedback::Closed)));
        let feedback = Manager::track(&mut manager, Epoch::new(1), peers, &directory).unwrap();
        assert_eq!(feedback, Feedback::Closed);
    }

    #[test]
    fn consecutive_epochs_use_their_directories() {
        let (peers, _) = peers();
        let directory_for = |port: u16| {
            peers
                .clone()
                .union()
                .into_iter()
                .map(|peer| (peer, address(port)))
                .collect::<Addresses<_>>()
        };

        let inner = TestManager::new(Feedback::Ok);
        let tracked = inner.addressable.clone();
        let mut manager = AddressableManager::new(AddressableTestManager(inner));

        for (epoch, port) in [(4, 4), (4, 4), (5, 5)] {
            Manager::track(
                &mut manager,
                Epoch::new(epoch),
                peers.clone(),
                &directory_for(port),
            )
            .unwrap();
        }

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
            let directory = Addresses::from_iter([
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

            let mut dealer_manager = AddressableManager::new(dealer_oracle);
            let mut participant_manager = AddressableManager::new(participant_oracle);
            Manager::track(
                &mut dealer_manager,
                Epoch::new(3),
                peers.clone(),
                &directory,
            )
            .unwrap();
            Manager::track(&mut participant_manager, Epoch::new(3), peers, &directory).unwrap();

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

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;
    use commonware_cryptography::ed25519;

    commonware_conformance::conformance_tests! {
        CodecConformance<Addresses<ed25519::PublicKey>>,
    }
}
