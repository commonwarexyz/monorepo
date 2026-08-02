//! Bounded fair ingress lanes.

use super::{Drop, IngressLimits};
#[cfg(test)]
use crate::multimmit::machine::Artifact;
use crate::multimmit::machine::IdentifiedArtifact;
use commonware_cryptography::{Digest, PublicKey, bls12381::primitives::variant::Variant};
use commonware_utils::N5f1;
use std::collections::{HashMap, VecDeque};

/// The destination lane for one decoded artifact.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum LaneId {
    /// The global latency-sensitive consensus lane.
    Consensus,
    /// The certificate catch-up lane.
    Certificate,
    /// One producer-chain data lane.
    Data(usize),
}

#[derive(Copy, Clone)]
enum Plane {
    Consensus,
    Certificate,
    Data,
}

pub(super) struct Group<V: Variant, D: Digest> {
    first: IdentifiedArtifact<V, D>,
    second: Option<Box<IdentifiedArtifact<V, D>>>,
    bytes: usize,
}

impl<V: Variant, D: Digest> Group<V, D> {
    pub(super) fn one(artifact: IdentifiedArtifact<V, D>) -> Self {
        let bytes = artifact.1.encoded_len();
        Self {
            first: artifact,
            second: None,
            bytes,
        }
    }

    pub(super) fn pair([first, second]: [IdentifiedArtifact<V, D>; 2]) -> Self {
        let bytes = first.1.encoded_len().saturating_add(second.1.encoded_len());
        Self {
            first,
            second: Some(Box::new(second)),
            bytes,
        }
    }

    pub(super) const fn len(&self) -> usize {
        if self.second.is_some() { 2 } else { 1 }
    }

    const fn bytes(&self) -> usize {
        self.bytes
    }
}

/// One ingress selection and its authenticated source.
#[derive(Debug)]
pub(super) struct Selected<P: PublicKey, V: Variant, D: Digest> {
    pub(super) artifact: IdentifiedArtifact<V, D>,
    pub(super) peer: P,
}

#[cfg(test)]
impl<P: PublicKey, V: Variant, D: Digest> PartialEq<Artifact<V, D>> for Selected<P, V, D> {
    fn eq(&self, other: &Artifact<V, D>) -> bool {
        self.artifact.1 == *other
    }
}

#[cfg(test)]
impl<P: PublicKey, V: Variant, D: Digest> PartialEq<Selected<P, V, D>> for Artifact<V, D> {
    fn eq(&self, other: &Selected<P, V, D>) -> bool {
        *self == other.artifact.1
    }
}

struct PeerLane<V: Variant, D: Digest> {
    groups: VecDeque<Group<V, D>>,
    items: usize,
    bytes: usize,
}

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

/// Bounded per-class and per-chain ingress buffers with deterministic fair flushing.
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
        let fault_domains = N5f1::f_plus_one(participants) as usize;
        Self {
            consensus: Lane::new(),
            certificates: Lane::new(),
            data: (0..chains).map(|_| Lane::new()).collect(),
            items: 0,
            next_plane: Plane::Consensus,
            next_chain: 0,
            peer_items: limits.lane_items.get() / fault_domains,
            peer_bytes: limits.lane_bytes.get() / fault_domains,
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
    ) -> Result<(), Drop> {
        self.push_inner(lane, peer, group)
    }

    fn push_inner(&mut self, lane: LaneId, peer: P, group: Group<V, D>) -> Result<(), Drop> {
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
            return Err(Drop::Lane);
        }
        if buffered_items.saturating_add(items) > peer_items
            || buffered_bytes.saturating_add(bytes) > peer_bytes
        {
            return Err(Drop::Peer);
        }

        if !target.peers.contains_key(&peer) {
            target.ready.push_back(peer.clone());
        }
        let buffered = target.peers.entry(peer).or_insert_with(|| PeerLane {
            groups: VecDeque::new(),
            items: 0,
            bytes: 0,
        });
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

    fn pop_next(&mut self) -> Option<(P, Group<V, D>)> {
        for _ in 0..3 {
            let plane = self.next_plane;
            let selected = match plane {
                Plane::Consensus => {
                    self.next_plane = Plane::Certificate;
                    self.pop(LaneId::Consensus)
                }
                Plane::Certificate => {
                    self.next_plane = Plane::Data;
                    self.pop(LaneId::Certificate)
                }
                Plane::Data => {
                    self.next_plane = Plane::Consensus;
                    self.pop_data()
                }
            };
            if selected.is_some() {
                return selected;
            }
        }

        None
    }

    /// Selects up to `budget` artifacts and authenticated sources for one observation cohort.
    pub(super) fn flush(&mut self, budget: usize) -> Vec<Selected<P, V, D>> {
        let mut cohort = Vec::new();
        while cohort.len() < budget {
            let Some((peer, group)) = self.pop_next() else {
                break;
            };
            match group.second {
                Some(second) => {
                    cohort.push(Selected {
                        artifact: group.first,
                        peer: peer.clone(),
                    });
                    cohort.push(Selected {
                        artifact: *second,
                        peer,
                    });
                }
                None => cohort.push(Selected {
                    artifact: group.first,
                    peer,
                }),
            }
        }
        cohort
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::{config::Limits, mocks::Committee};
    use commonware_cryptography::{
        Hasher as _, Sha256,
        bls12381::primitives::variant::MinPk,
        ed25519::{PrivateKey as Ed25519PrivateKey, PublicKey as Ed25519PublicKey},
        sha256::Digest as Sha256Digest,
    };
    use std::{num::NonZeroUsize, time::Duration};

    fn limits() -> IngressLimits {
        IngressLimits {
            cohort_items: NonZeroUsize::new(16).unwrap(),
            lane_items: NonZeroUsize::new(4).unwrap(),
            lane_bytes: NonZeroUsize::new(64 * 1024).unwrap(),
            inflight_jobs: NonZeroUsize::new(2).unwrap(),
            coalesce: Duration::ZERO,
        }
    }

    fn committee() -> Committee<MinPk> {
        Committee::new(21, 6, Limits::new(2, 1).unwrap())
    }

    fn peer(index: u8) -> Ed25519PublicKey {
        use commonware_cryptography::Signer as _;
        Ed25519PrivateKey::from_seed(u64::from(index)).public_key()
    }

    fn identified(
        artifact: Artifact<MinPk, Sha256Digest>,
    ) -> IdentifiedArtifact<MinPk, Sha256Digest> {
        (artifact.id::<Sha256>(), artifact)
    }

    #[test]
    fn flush_serves_every_saturated_lane_within_a_bound() {
        const SERVICE_BOUND: usize = 16;
        const ROUNDS: usize = SERVICE_BOUND * 3;

        let committee = committee();
        let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, limits());

        let block0 =
            Artifact::TransactionBlock(committee.signed_block(0, Sha256::hash(&[b"block zero"])));
        let block1 =
            Artifact::TransactionBlock(committee.signed_block(1, Sha256::hash(&[b"block one"])));
        let novote = Artifact::NoVote(committee.novote(2, 1));
        let nullification = Artifact::Nullification(committee.nullification(1));
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
                    Group::one(identified(artifact.clone())),
                )
                .unwrap();
        }

        let mut last_service = [None; 4];
        let mut service_count = [0; 4];
        for round in 0..ROUNDS {
            let cohort = lanes.flush(1);
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
                    Group::one(identified(artifact.clone())),
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
        let block0 =
            Artifact::TransactionBlock(committee.signed_block(0, Sha256::hash(&[b"rot zero"])));
        let block1 =
            Artifact::TransactionBlock(committee.signed_block(1, Sha256::hash(&[b"rot one"])));

        lanes
            .push_group(
                LaneId::Data(0),
                peer(0),
                Group::one(identified(block0.clone())),
            )
            .unwrap();
        assert_eq!(lanes.flush(16), vec![block0.clone()]);

        // The cursor advanced past chain zero, so an equal backlog starts at chain one.
        lanes
            .push_group(
                LaneId::Data(0),
                peer(0),
                Group::one(identified(block0.clone())),
            )
            .unwrap();
        lanes
            .push_group(
                LaneId::Data(1),
                peer(1),
                Group::one(identified(block1.clone())),
            )
            .unwrap();
        assert_eq!(lanes.flush(16), vec![block1, block0]);
    }

    #[test]
    fn push_enforces_lane_and_peer_bounds() {
        let committee = committee();
        let novote = Artifact::NoVote(committee.novote(0, 1));
        let mut bounds = limits();
        bounds.lane_bytes = NonZeroUsize::new(novote.encoded_len() * 2).unwrap();
        let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, bounds);

        lanes
            .push_group(
                LaneId::Consensus,
                peer(0),
                Group::one(identified(novote.clone())),
            )
            .unwrap();
        assert_eq!(
            lanes.push_group(
                LaneId::Consensus,
                peer(0),
                Group::one(identified(novote.clone())),
            ),
            Err(Drop::Peer)
        );
        lanes
            .push_group(
                LaneId::Consensus,
                peer(1),
                Group::one(identified(novote.clone())),
            )
            .unwrap();
        assert_eq!(
            lanes.push_group(
                LaneId::Consensus,
                peer(2),
                Group::one(identified(novote.clone())),
            ),
            Err(Drop::Lane)
        );

        // Draining the lane restores peer budgets exactly.
        assert_eq!(lanes.flush(16).len(), 2);
        lanes
            .push_group(LaneId::Consensus, peer(0), Group::one(identified(novote)))
            .unwrap();
    }

    #[test]
    fn replaying_faulty_peer_cannot_take_the_correct_peers_lane_share() {
        let committee = committee();
        let replay = Artifact::NoVote(committee.novote(0, 1));
        let correct = Artifact::NoVote(committee.novote(1, 1));
        let mut bounds = limits();
        bounds.lane_items = NonZeroUsize::new(4).unwrap();
        let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, bounds);

        lanes
            .push_group(
                LaneId::Consensus,
                peer(0),
                Group::one(identified(replay.clone())),
            )
            .unwrap();
        lanes
            .push_group(
                LaneId::Consensus,
                peer(0),
                Group::one(identified(replay.clone())),
            )
            .unwrap();
        assert_eq!(
            lanes.push_group(LaneId::Consensus, peer(0), Group::one(identified(replay)),),
            Err(Drop::Peer),
            "one of at most f faulty identities exhausted its lane share",
        );
        lanes
            .push_group(
                LaneId::Consensus,
                peer(1),
                Group::one(identified(correct.clone())),
            )
            .expect("a correct identity retains admission capacity");

        let first = lanes.flush(1);
        let second = lanes.flush(1);
        assert!(
            first == vec![correct.clone()] || second == vec![correct],
            "the correct peer was not served within one f+1 peer rotation",
        );
    }

    #[test]
    fn push_group_is_ordered_and_atomic_at_every_bound() {
        let committee = committee();
        let first = Artifact::NoVote(committee.novote(0, 1));
        let second = Artifact::NoVote(committee.novote(1, 1));
        let group_bytes = first.encoded_len() + second.encoded_len();

        let mut ordered: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, limits());
        ordered
            .push_group(
                LaneId::Consensus,
                peer(0),
                Group::pair([identified(first.clone()), identified(second.clone())]),
            )
            .unwrap();
        assert_eq!(ordered.flush(2), vec![first.clone(), second.clone()]);

        let cases = [
            (
                {
                    let mut bounds = limits();
                    bounds.lane_items = NonZeroUsize::new(1).unwrap();
                    bounds
                },
                Drop::Lane,
            ),
            (
                {
                    let mut bounds = limits();
                    bounds.lane_bytes = NonZeroUsize::new(group_bytes - 1).unwrap();
                    bounds
                },
                Drop::Lane,
            ),
            (
                {
                    let mut bounds = limits();
                    bounds.lane_bytes = NonZeroUsize::new((group_bytes - 1) * 2).unwrap();
                    bounds
                },
                Drop::Peer,
            ),
        ];

        for (bounds, expected) in cases {
            let mut lanes: Lanes<Ed25519PublicKey, MinPk, Sha256Digest> = Lanes::new(6, 6, bounds);
            assert_eq!(
                lanes.push_group(
                    LaneId::Consensus,
                    peer(0),
                    Group::pair([identified(first.clone()), identified(second.clone())]),
                ),
                Err(expected),
            );
            assert_eq!(lanes.items(), 0);
            assert!(lanes.flush(2).is_empty());
        }
    }

    #[test]
    fn exact_proposal_group_bound_admits_both_artifacts_atomically() {
        let committee = committee();
        let parent = committee.vqc(1);
        let block = committee.leader_block_with_parent(2, &parent);
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
                Group::pair([identified(parent.clone()), identified(block.clone())]),
            )
            .unwrap();
        assert_eq!(lanes.flush(2), vec![parent, block]);
    }
}
