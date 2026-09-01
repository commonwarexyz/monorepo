//! Bounded fair ingress lanes.

use super::IngressLimits;
use crate::{
    multimmit::{machine::IdentifiedArtifact, types::Artifact, wire::Plane},
    types::{Attributable as _, Participant},
};
use commonware_cryptography::{Digest, PublicKey, bls12381::primitives::variant::Variant};
use std::{
    collections::{HashMap, VecDeque, hash_map::Entry as MapEntry},
    iter::once,
    time::SystemTime,
};

/// Why one decoded message was dropped before verification.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum DropReason {
    /// The destination lane reached its item or byte bound.
    Lane,
    /// The sending peer exceeded its item or byte share in the destination lane.
    Peer,
}

/// The destination lane for one decoded artifact.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum LaneId {
    /// The global latency-sensitive consensus lane.
    Consensus,
    /// The certificate plane lane.
    Certificate,
    /// One producer-chain data lane.
    Data(usize),
}

impl LaneId {
    /// Returns the plane whose traffic this lane buffers.
    pub(super) const fn plane(self) -> Plane {
        match self {
            Self::Consensus => Plane::Consensus,
            Self::Certificate => Plane::Certificate,
            Self::Data(_) => Plane::Data,
        }
    }
}

/// One buffered artifact and its canonical encoded length, measured once at admission.
pub(super) struct Entry<V: Variant, D: Digest> {
    artifact: IdentifiedArtifact<V, D>,
    bytes: usize,
}

impl<V: Variant, D: Digest> Entry<V, D> {
    fn new(artifact: IdentifiedArtifact<V, D>) -> Self {
        let bytes = artifact.artifact.encoded_len();
        Self { artifact, bytes }
    }
}

/// An indivisible parent+proposal pair or one artifact.
pub(super) struct Group<V: Variant, D: Digest> {
    first: Entry<V, D>,
    second: Option<Box<Entry<V, D>>>,
    /// When the network message carrying the group arrived at the ingress actor.
    received_at: SystemTime,
}

impl<V: Variant, D: Digest> Group<V, D> {
    pub(super) fn one(artifact: IdentifiedArtifact<V, D>, received_at: SystemTime) -> Self {
        Self {
            first: Entry::new(artifact),
            second: None,
            received_at,
        }
    }

    pub(super) fn pair(
        [first, second]: [IdentifiedArtifact<V, D>; 2],
        received_at: SystemTime,
    ) -> Self {
        Self {
            first: Entry::new(first),
            second: Some(Box::new(Entry::new(second))),
            received_at,
        }
    }

    pub(super) const fn len(&self) -> usize {
        if self.second.is_some() { 2 } else { 1 }
    }

    /// Returns the signer of every data-availability vote in the group.
    ///
    /// Every entry is read, so the sender check holds whatever the wire bundles.
    pub(super) fn da_vote_signers(&self) -> impl Iterator<Item = Participant> + '_ {
        once(&self.first)
            .chain(self.second.as_deref())
            .filter_map(|entry| match &entry.artifact.artifact {
                Artifact::DaVote(vote) => Some(vote.signer()),
                _ => None,
            })
    }

    const fn bytes(&self) -> usize {
        match &self.second {
            Some(second) => self.first.bytes.saturating_add(second.bytes),
            None => self.first.bytes,
        }
    }

    /// Pairs each entry with `peer` in observation order, parent first.
    ///
    /// Only a pair clones `peer`; a single artifact takes it.
    fn into_selected<P: PublicKey>(self, peer: P) -> impl Iterator<Item = Selected<P, V, D>> {
        let Self {
            first,
            second,
            received_at,
        } = self;
        let (first_peer, second) = match second {
            Some(second) => (peer.clone(), Some((*second, peer))),
            None => (peer, None),
        };
        once((first, first_peer))
            .chain(second)
            .map(move |(entry, peer)| Selected {
                artifact: entry.artifact,
                peer,
                bytes: entry.bytes,
                received_at,
            })
    }
}

/// One ingress selection and its authenticated source.
#[derive(Debug)]
pub(super) struct Selected<P: PublicKey, V: Variant, D: Digest> {
    pub(super) artifact: IdentifiedArtifact<V, D>,
    pub(super) peer: P,
    /// The artifact's canonical encoded length, measured once at admission.
    pub(super) bytes: usize,
    /// When the network message carrying the artifact arrived at the ingress actor.
    pub(super) received_at: SystemTime,
}

/// The artifacts of one plane selected into one observation cohort.
pub(super) struct Cohort<P: PublicKey, V: Variant, D: Digest> {
    /// The plane every selected artifact arrived on.
    pub(super) plane: Plane,
    /// The selected artifacts in observation order.
    pub(super) selected: Vec<Selected<P, V, D>>,
}

/// One peer's buffered groups in one lane, with their item and byte totals.
struct PeerLane<V: Variant, D: Digest> {
    groups: VecDeque<Group<V, D>>,
    items: usize,
    bytes: usize,
}

/// One lane's per-peer buffers, served round-robin across the peers in `ready`.
struct Lane<P: PublicKey, V: Variant, D: Digest> {
    peers: HashMap<P, PeerLane<V, D>>,
    ready: VecDeque<P>,
    items: usize,
    bytes: usize,
}

impl<P: PublicKey, V: Variant, D: Digest> Lane<P, V, D> {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            ready: VecDeque::new(),
            items: 0,
            bytes: 0,
        }
    }
}

/// Bounded per-plane and per-chain ingress buffers with deterministic fair flushing.
///
/// Lanes bound retained items and bytes per lane and per peer. Flushing rotates across consensus,
/// certificate, and data traffic. Data selections rotate across producer chains.
pub(super) struct Lanes<P: PublicKey, V: Variant, D: Digest> {
    consensus: Lane<P, V, D>,
    certificates: Lane<P, V, D>,
    data: Vec<Lane<P, V, D>>,
    items: usize,
    next_plane: Plane,
    next_chain: usize,
    peer_items: usize,
    peer_bytes: usize,
    limits: IngressLimits,
}

impl<P: PublicKey, V: Variant, D: Digest> Lanes<P, V, D> {
    pub(super) fn new(chains: usize, participants: usize, limits: IngressLimits) -> Self {
        let (peer_items, peer_bytes) = limits.peer_share(participants);
        Self {
            consensus: Lane::new(),
            certificates: Lane::new(),
            data: (0..chains).map(|_| Lane::new()).collect(),
            items: 0,
            next_plane: Plane::Consensus,
            next_chain: 0,
            peer_items,
            peer_bytes,
            limits,
        }
    }

    /// Returns the number of buffered artifacts across all lanes.
    pub(super) const fn items(&self) -> usize {
        self.items
    }

    fn lane_mut(&mut self, lane: LaneId) -> &mut Lane<P, V, D> {
        match lane {
            LaneId::Consensus => &mut self.consensus,
            LaneId::Certificate => &mut self.certificates,
            LaneId::Data(chain) => &mut self.data[chain],
        }
    }

    /// Atomically buffers one ordered group of decoded artifacts or reports why it was dropped.
    pub(super) fn push_group(
        &mut self,
        lane: LaneId,
        peer: P,
        group: Group<V, D>,
    ) -> Result<(), DropReason> {
        let bytes = group.bytes();
        let items = group.len();
        let limits = self.limits;
        let peer_items = self.peer_items;
        let peer_bytes = self.peer_bytes;
        let target = self.lane_mut(lane);
        let (buffered_items, buffered_bytes) = target
            .peers
            .get(&peer)
            .map_or((0, 0), |buffered| (buffered.items, buffered.bytes));
        if target.items.saturating_add(items) > limits.lane_items.get()
            || target.bytes.saturating_add(bytes) > limits.lane_bytes.get()
        {
            return Err(DropReason::Lane);
        }
        if buffered_items.saturating_add(items) > peer_items
            || buffered_bytes.saturating_add(bytes) > peer_bytes
        {
            return Err(DropReason::Peer);
        }

        let buffered = match target.peers.entry(peer) {
            MapEntry::Occupied(buffered) => buffered.into_mut(),
            MapEntry::Vacant(vacant) => {
                target.ready.push_back(vacant.key().clone());
                vacant.insert(PeerLane {
                    groups: VecDeque::new(),
                    items: 0,
                    bytes: 0,
                })
            }
        };
        buffered.items += items;
        buffered.bytes += bytes;
        buffered.groups.push_back(group);
        target.items += items;
        target.bytes += bytes;
        self.items += items;
        Ok(())
    }

    fn pop(&mut self, lane: LaneId) -> Option<(P, Group<V, D>)> {
        let target = self.lane_mut(lane);
        let peer = target.ready.pop_front()?;
        let buffered = target
            .peers
            .get_mut(&peer)
            .expect("ready peers retain a queue");
        let group = buffered.groups.pop_front().expect("ready peers have work");
        let items = group.len();
        buffered.items -= items;
        buffered.bytes -= group.bytes();
        target.items -= items;
        target.bytes -= group.bytes();
        if buffered.groups.is_empty() {
            target.peers.remove(&peer);
        } else {
            target.ready.push_back(peer.clone());
        }
        self.items -= items;
        Some((peer, group))
    }

    fn pop_data(&mut self) -> Option<(P, Group<V, D>)> {
        let chains = self.data.len();
        if chains == 0 {
            return None;
        }

        for _ in 0..chains {
            let chain = self.next_chain;
            self.next_chain = (self.next_chain + 1) % chains;
            if let Some(selected) = self.pop(LaneId::Data(chain)) {
                return Some(selected);
            }
        }

        None
    }

    fn next_ready_plane(&mut self) -> Option<Plane> {
        for plane in self.next_plane.rotation() {
            let ready = match plane {
                Plane::Consensus => self.consensus.items > 0,
                Plane::Certificate => self.certificates.items > 0,
                Plane::Data => self.data.iter().any(|lane| lane.items > 0),
            };
            if ready {
                self.next_plane = plane.next();
                return Some(plane);
            }
        }

        None
    }

    /// Selects up to `budget` artifacts from a single plane for one observation cohort.
    ///
    /// Each cohort holds one plane's artifacts. View-critical cohorts are also capped at
    /// [`IngressLimits::view_cohort_items`] to keep view-critical work separate from large data
    /// batches. Consecutive flushes rotate across planes, and data selections rotate across
    /// producer chains. Returns `None` when nothing is selected.
    pub(super) fn flush(&mut self, budget: usize) -> Option<Cohort<P, V, D>> {
        let plane = self.next_ready_plane()?;
        let budget = if plane.view_critical() {
            budget.min(self.limits.view_cohort_items.get())
        } else {
            budget
        };
        let mut selected = Vec::new();
        while selected.len() < budget {
            let popped = match plane {
                Plane::Consensus => self.pop(LaneId::Consensus),
                Plane::Certificate => self.pop(LaneId::Certificate),
                Plane::Data => self.pop_data(),
            };
            let Some((peer, group)) = popped else {
                break;
            };
            selected.extend(group.into_selected(peer));
        }
        (!selected.is_empty()).then_some(Cohort { plane, selected })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            mocks::Committee,
            types::{Artifact, Attestation, ChainId, NoVote},
        },
        types::{Epoch, Round, View},
    };
    use commonware_codec::types::lazy::Lazy;
    use commonware_cryptography::{
        Hasher as _, Sha256, Signer as _,
        bls12381::primitives::variant::MinPk,
        ed25519::{PrivateKey as Ed25519PrivateKey, PublicKey as Ed25519PublicKey},
        sha256::Digest as Sha256Digest,
    };
    use commonware_math::algebra::Additive as _;
    use commonware_utils::{Participant, TestRng, test_rng};
    use rand_core::Rng as _;
    use std::{num::NonZeroUsize, time::SystemTime};

    const EPOCH: SystemTime = SystemTime::UNIX_EPOCH;

    impl<P: PublicKey, V: Variant, D: Digest> PartialEq<Artifact<V, D>> for Selected<P, V, D> {
        fn eq(&self, other: &Artifact<V, D>) -> bool {
            self.artifact.artifact == *other
        }
    }

    impl<P: PublicKey, V: Variant, D: Digest> PartialEq<Selected<P, V, D>> for Artifact<V, D> {
        fn eq(&self, other: &Selected<P, V, D>) -> bool {
            *self == other.artifact.artifact
        }
    }

    fn limits() -> IngressLimits {
        IngressLimits {
            cohort_items: NonZeroUsize::new(16).unwrap(),
            lane_items: NonZeroUsize::new(4).unwrap(),
            ..IngressLimits::TEST
        }
    }

    /// Flushes one cohort and returns its selections, or none when every lane is empty.
    fn flushed(
        lanes: &mut Lanes<Ed25519PublicKey, MinPk, Sha256Digest>,
        budget: usize,
    ) -> Vec<Selected<Ed25519PublicKey, MinPk, Sha256Digest>> {
        lanes
            .flush(budget)
            .map_or_else(Vec::new, |cohort| cohort.selected)
    }

    fn committee() -> Committee<MinPk> {
        Committee::builder(21, 6).build()
    }

    fn peer(index: u8) -> Ed25519PublicKey {
        Ed25519PrivateKey::from_seed(u64::from(index)).public_key()
    }

    fn identified(
        artifact: Artifact<MinPk, Sha256Digest>,
    ) -> IdentifiedArtifact<MinPk, Sha256Digest> {
        artifact.identify::<Sha256>(&mut Vec::new())
    }

    #[test]
    fn flush_serves_every_saturated_lane_within_a_bound() {
        const SERVICE_BOUND: usize = 16;
        const ROUNDS: usize = SERVICE_BOUND * 3;

        let committee = committee();
        let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, limits());

        let block0 = Artifact::TransactionBlock(
            committee.signed_block(ChainId::new(0), Sha256::hash(&[b"block zero"])),
        );
        let block1 = Artifact::TransactionBlock(
            committee.signed_block(ChainId::new(1), Sha256::hash(&[b"block one"])),
        );
        let novote = Artifact::NoVote(committee.novote(Participant::new(2), View::new(1)));
        let nullification = Artifact::Nullification(committee.nullification(View::new(1)));
        let sources = [
            ("consensus", LaneId::Consensus, peer(0), novote),
            ("certificate", LaneId::Certificate, peer(1), nullification),
            ("data chain 0", LaneId::Data(0), peer(2), block0),
            ("data chain 1", LaneId::Data(1), peer(3), block1),
        ];
        for (_, lane, source, artifact) in &sources {
            lanes
                .push_group(
                    *lane,
                    source.clone(),
                    Group::one(identified(artifact.clone()), EPOCH),
                )
                .unwrap();
        }

        let mut last_service = [None; 4];
        let mut service_count = [0; 4];
        for round in 0..ROUNDS {
            let cohort = flushed(&mut lanes, 1);
            assert_eq!(cohort.len(), 1, "saturated lanes always have work");
            let artifact = &cohort[0];
            let source = sources
                .iter()
                .position(|(_, _, _, expected)| expected == artifact)
                .expect("selection preserves the admitted artifact identity");
            let name = sources[source].0;

            if let Some(previous) = last_service[source] {
                assert!(
                    round - previous <= SERVICE_BOUND,
                    "{name} waited {} rounds",
                    round - previous
                );
            }
            last_service[source] = Some(round);
            service_count[source] += 1;

            let (_, lane, peer, artifact) = &sources[source];
            lanes
                .push_group(
                    *lane,
                    peer.clone(),
                    Group::one(identified(artifact.clone()), EPOCH),
                )
                .unwrap();
            assert_eq!(lanes.items(), sources.len());
        }

        let starved = last_service
            .iter()
            .enumerate()
            .filter_map(|(source, service)| service.is_none().then_some(sources[source].0))
            .collect::<Vec<_>>();
        assert!(
            starved.is_empty(),
            "sources starved: {}",
            starved.join(", ")
        );

        for (source, last_service) in last_service.into_iter().enumerate() {
            let name = sources[source].0;
            let last_service = last_service.expect("starvation checked above");
            assert!(
                ROUNDS - last_service <= SERVICE_BOUND,
                "{name} received no service in the final {SERVICE_BOUND} rounds"
            );
            assert!(
                service_count[source] >= ROUNDS / SERVICE_BOUND,
                "{name} was not served repeatedly"
            );
        }
    }

    #[test]
    fn flush_rotates_the_first_data_chain() {
        let committee = committee();
        let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, limits());
        let block0 = Artifact::TransactionBlock(
            committee.signed_block(ChainId::new(0), Sha256::hash(&[b"rot zero"])),
        );
        let block1 = Artifact::TransactionBlock(
            committee.signed_block(ChainId::new(1), Sha256::hash(&[b"rot one"])),
        );

        lanes
            .push_group(
                LaneId::Data(0),
                peer(0),
                Group::one(identified(block0.clone()), EPOCH),
            )
            .unwrap();
        assert_eq!(flushed(&mut lanes, 16), vec![block0.clone()]);

        // The cursor advanced past chain zero, so an equal backlog starts at chain one.
        lanes
            .push_group(
                LaneId::Data(0),
                peer(0),
                Group::one(identified(block0.clone()), EPOCH),
            )
            .unwrap();
        lanes
            .push_group(
                LaneId::Data(1),
                peer(1),
                Group::one(identified(block1.clone()), EPOCH),
            )
            .unwrap();
        assert_eq!(flushed(&mut lanes, 16), vec![block1, block0]);
    }

    #[test]
    fn flush_selects_a_single_plane_per_cohort() {
        let committee = committee();
        let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, limits());
        let novote = Artifact::NoVote(committee.novote(Participant::new(2), View::new(1)));
        let nullification = Artifact::Nullification(committee.nullification(View::new(1)));
        let block = Artifact::TransactionBlock(
            committee.signed_block(ChainId::new(0), Sha256::hash(&[b"pp"])),
        );

        lanes
            .push_group(
                LaneId::Consensus,
                peer(0),
                Group::one(identified(novote.clone()), EPOCH),
            )
            .unwrap();
        lanes
            .push_group(
                LaneId::Certificate,
                peer(1),
                Group::one(identified(nullification.clone()), EPOCH),
            )
            .unwrap();
        lanes
            .push_group(
                LaneId::Data(0),
                peer(2),
                Group::one(identified(block.clone()), EPOCH),
            )
            .unwrap();

        // One buffered plane per cohort, in rotation order, regardless of budget headroom.
        for (plane, artifact) in [
            (Plane::Consensus, novote),
            (Plane::Certificate, nullification),
            (Plane::Data, block),
        ] {
            let cohort = lanes.flush(16).expect("a plane is buffered");
            assert_eq!(cohort.plane, plane);
            assert_eq!(cohort.selected, vec![artifact]);
        }
        assert!(lanes.flush(16).is_none());
    }

    #[test]
    fn flush_without_budget_selects_no_cohort() {
        let committee = committee();
        let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, limits());
        lanes
            .push_group(
                LaneId::Consensus,
                peer(0),
                Group::one(
                    identified(Artifact::NoVote(
                        committee.novote(Participant::new(2), View::new(1)),
                    )),
                    EPOCH,
                ),
            )
            .unwrap();

        // An empty selection is never forwarded, and the buffered group stays for the next flush.
        assert!(lanes.flush(0).is_none());
        assert_eq!(lanes.items(), 1);
        assert_eq!(
            lanes
                .flush(16)
                .expect("the group is still buffered")
                .selected
                .len(),
            1
        );
    }

    #[test]
    fn view_plane_cohorts_are_capped() {
        let committee = committee();
        let mut bounds = limits();
        bounds.lane_items = NonZeroUsize::new(16).unwrap();
        let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, bounds);
        for signer in 0..6usize {
            let novote =
                Artifact::NoVote(committee.novote(Participant::from_usize(signer), View::new(1)));
            lanes
                .push_group(
                    LaneId::Consensus,
                    peer(signer as u8),
                    Group::one(identified(novote), EPOCH),
                )
                .unwrap();
        }

        // The cohort budget does not lift the view-plane cap; the remainder follows in the
        // next rotation.
        assert_eq!(
            flushed(&mut lanes, 16).len(),
            bounds.view_cohort_items.get()
        );
        assert_eq!(flushed(&mut lanes, 16).len(), 2);
        assert!(flushed(&mut lanes, 16).is_empty());
    }

    #[test]
    fn push_enforces_lane_and_peer_bounds() {
        let committee = committee();
        let novote = Artifact::NoVote(committee.novote(Participant::new(0), View::new(1)));
        let mut bounds = limits();
        bounds.lane_bytes = NonZeroUsize::new(novote.encoded_len() * 2).unwrap();
        let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, bounds);

        lanes
            .push_group(
                LaneId::Consensus,
                peer(0),
                Group::one(identified(novote.clone()), EPOCH),
            )
            .unwrap();
        assert_eq!(
            lanes.push_group(
                LaneId::Consensus,
                peer(0),
                Group::one(identified(novote.clone()), EPOCH),
            ),
            Err(DropReason::Peer)
        );
        lanes
            .push_group(
                LaneId::Consensus,
                peer(1),
                Group::one(identified(novote.clone()), EPOCH),
            )
            .unwrap();
        assert_eq!(
            lanes.push_group(
                LaneId::Consensus,
                peer(2),
                Group::one(identified(novote.clone()), EPOCH),
            ),
            Err(DropReason::Lane)
        );

        // Draining the lane restores peer budgets exactly.
        assert_eq!(flushed(&mut lanes, 16).len(), 2);
        lanes
            .push_group(
                LaneId::Consensus,
                peer(0),
                Group::one(identified(novote), EPOCH),
            )
            .unwrap();
    }

    #[test]
    fn replaying_faulty_peer_cannot_take_the_correct_peers_lane_share() {
        let committee = committee();
        let replay = Artifact::NoVote(committee.novote(Participant::new(0), View::new(1)));
        let correct = Artifact::NoVote(committee.novote(Participant::new(1), View::new(1)));
        let mut bounds = limits();
        bounds.lane_items = NonZeroUsize::new(4).unwrap();
        let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, bounds);

        lanes
            .push_group(
                LaneId::Consensus,
                peer(0),
                Group::one(identified(replay.clone()), EPOCH),
            )
            .unwrap();
        lanes
            .push_group(
                LaneId::Consensus,
                peer(0),
                Group::one(identified(replay.clone()), EPOCH),
            )
            .unwrap();
        assert_eq!(
            lanes.push_group(
                LaneId::Consensus,
                peer(0),
                Group::one(identified(replay), EPOCH),
            ),
            Err(DropReason::Peer),
            "one of at most f faulty identities exhausted its lane share",
        );
        lanes
            .push_group(
                LaneId::Consensus,
                peer(1),
                Group::one(identified(correct.clone()), EPOCH),
            )
            .expect("a correct identity retains admission capacity");

        let first = flushed(&mut lanes, 1);
        let second = flushed(&mut lanes, 1);
        assert!(
            first == vec![correct.clone()] || second == vec![correct],
            "the correct peer was not served within one f+1 peer rotation",
        );
    }

    #[test]
    fn push_group_is_ordered_and_atomic_at_every_bound() {
        let committee = committee();
        let first = Artifact::NoVote(committee.novote(Participant::new(0), View::new(1)));
        let second = Artifact::NoVote(committee.novote(Participant::new(1), View::new(1)));
        let group_bytes = first.encoded_len() + second.encoded_len();

        let mut ordered: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, limits());
        ordered
            .push_group(
                LaneId::Consensus,
                peer(0),
                Group::pair(
                    [identified(first.clone()), identified(second.clone())],
                    EPOCH,
                ),
            )
            .unwrap();
        assert_eq!(
            flushed(&mut ordered, 2),
            vec![first.clone(), second.clone()]
        );

        let cases = [
            (
                {
                    let mut bounds = limits();
                    bounds.lane_items = NonZeroUsize::new(1).unwrap();
                    bounds
                },
                DropReason::Lane,
            ),
            (
                {
                    let mut bounds = limits();
                    bounds.lane_bytes = NonZeroUsize::new(group_bytes - 1).unwrap();
                    bounds
                },
                DropReason::Lane,
            ),
            (
                {
                    let mut bounds = limits();
                    bounds.lane_bytes = NonZeroUsize::new((group_bytes - 1) * 2).unwrap();
                    bounds
                },
                DropReason::Peer,
            ),
        ];

        for (bounds, expected) in cases {
            let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, bounds);
            assert_eq!(
                lanes.push_group(
                    LaneId::Consensus,
                    peer(0),
                    Group::pair(
                        [identified(first.clone()), identified(second.clone())],
                        EPOCH
                    ),
                ),
                Err(expected),
            );
            assert_eq!(lanes.items(), 0);
            assert!(flushed(&mut lanes, 2).is_empty());
        }
    }

    #[test]
    fn exact_proposal_group_bound_admits_both_artifacts_atomically() {
        let committee = committee();
        let parent = committee.vqc(View::new(1));
        let block = committee.leader_block_with_parent(View::new(2), &parent);
        let parent = Artifact::Vqc(parent);
        let block = Artifact::LeaderBlock(block);
        let group_bytes = parent.encoded_len() + block.encoded_len();
        let mut bounds = limits();
        bounds.lane_bytes = NonZeroUsize::new(group_bytes * 2).unwrap();
        let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, bounds);

        lanes
            .push_group(
                LaneId::Consensus,
                peer(0),
                Group::pair(
                    [identified(parent.clone()), identified(block.clone())],
                    EPOCH,
                ),
            )
            .unwrap();
        assert_eq!(flushed(&mut lanes, 2), vec![parent, block]);
    }

    const CHAINS: usize = 4;
    const PEERS: usize = 4;

    fn artifact(marker: u8) -> Artifact<MinPk, Sha256Digest> {
        let novote = NoVote::new(
            Round::new(Epoch::new(1), View::new(u64::from(marker) + 1)),
            Attestation::new(
                Participant::new(u32::from(marker % 8)),
                Lazy::from(<MinPk as Variant>::Signature::zero()),
            ),
        )
        .expect("live view is valid");
        Artifact::NoVote(novote)
    }

    fn exercise_lanes(input: &[u8]) {
        let peers: Vec<Ed25519PublicKey> = (0..PEERS as u64)
            .map(|seed| Ed25519PrivateKey::from_seed(seed).public_key())
            .collect();
        let mut bounds = limits();
        bounds.cohort_items = NonZeroUsize::new(4).unwrap();
        bounds.lane_items = NonZeroUsize::new(3).unwrap();
        bounds.lane_bytes = NonZeroUsize::new(4096).unwrap();
        let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> =
            Lanes::new(CHAINS, PEERS, bounds);

        let mut buffered = 0usize;

        for chunk in input.as_chunks::<3>().0 {
            let (op, a, b) = (chunk[0], chunk[1], chunk[2]);
            match op % 3 {
                0 => {
                    let lane = match a % 6 {
                        0 => LaneId::Consensus,
                        1 => LaneId::Certificate,
                        chain => LaneId::Data(usize::from(chain - 2) % CHAINS),
                    };
                    let peer = peers[usize::from(b) % PEERS].clone();
                    let artifact = artifact(b);
                    let artifact = artifact.identify::<Sha256>(&mut Vec::new());
                    if lanes
                        .push_group(lane, peer, Group::one(artifact, SystemTime::UNIX_EPOCH))
                        .is_ok()
                    {
                        buffered += 1;
                    }
                }
                1 => {
                    let peer = peers[usize::from(b) % PEERS].clone();
                    let artifacts = [artifact(b), artifact(b.wrapping_add(1))]
                        .map(|artifact| artifact.identify::<Sha256>(&mut Vec::new()));
                    if lanes
                        .push_group(
                            LaneId::Consensus,
                            peer,
                            Group::pair(artifacts, SystemTime::UNIX_EPOCH),
                        )
                        .is_ok()
                    {
                        buffered += 2;
                    }
                }
                _ => {
                    let budget = usize::from(a % 8);
                    let cohort = flushed(&mut lanes, budget);
                    assert!(
                        cohort.len() <= budget.saturating_add(1),
                        "flush split a group"
                    );
                    buffered -= cohort.len();
                }
            }

            assert_eq!(lanes.items(), buffered, "lane accounting diverged");
        }

        // Every buffered artifact drains, in bounded cohorts.
        loop {
            let cohort = flushed(&mut lanes, bounds.cohort_items.get());
            if cohort.is_empty() {
                break;
            }
            assert!(cohort.len() <= bounds.cohort_items.get().saturating_add(1));
            buffered -= cohort.len();
        }
        assert_eq!(buffered, 0, "artifacts were lost or duplicated");
        assert_eq!(lanes.items(), 0);
    }

    #[test]
    fn exercises_random_schedules() {
        let mut rng: TestRng = test_rng();
        for _ in 0..64 {
            let mut input = vec![0u8; 3 * 64];
            rng.fill_bytes(&mut input);
            exercise_lanes(&input);
        }
    }
}
