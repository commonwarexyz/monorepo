//! Twins campaigns for Multimmit.
//!
//! Each Byzantine participant runs as two independently scheduled halves that share its exact key
//! material and threshold shares but keep separate machines, storage, applications, actor trees,
//! and production policy. The simulated network owns the participant's single endpoint per plane
//! and splits it: a router decides which half receives each inbound message, and a forwarder decides
//! which honest peers see each half's outbound message. Honest nodes therefore attribute both
//! halves to one participant with one committee weight, and no production code is weakened to make
//! that possible.
//!
//! The placement gate covers every Byzantine identity at `n=6, f=1` and every nonempty placement
//! within the fault bound at `n=11, f=2`. Every case uses real twin engines to selectively disclose
//! verified
//! attack-prefix traffic, produce conflicting authenticated headers, and recover honest progress in
//! a fair suffix. A separate delivery pump holds, reorders, and duplicates exact authenticated
//! artifacts before entering a fair suffix. The pump owns all stateful awaits, so cancellation of a
//! consumer receive cannot lose a held frame or skip a delivery phase.

use crate::{
    Epochable as _, Heightable as _, Viewable as _,
    multimmit::{
        actors::wire::{
            CertificateMessage, ConsensusMessage, DataMessage, Envelope, EnvelopeConfig,
        },
        config::{CodecConfig, LeaderSchedule, Limits},
        machine::{Artifact, ArtifactId, ArtifactKind},
        mocks::{
            Committee,
            cluster::{Cluster, ClusterOptions, link_all},
        },
        scheme::bls12381_threshold::Scheme,
        types::{
            Anchor, ChainId, ChainProposal, DaVote, Height, LeaderBlock, SignedLeaderBlock,
            SignedTransactionBlock, TransactionBlockHeader, Vote, genesis_tip_commitment,
        },
    },
    twins::{RoundScenario, Scenario},
    types::{Attributable as _, Epoch, Participant, Round, TermLength, View},
};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk, ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_group, test_traced};
use commonware_p2p::{
    Manager as _, Provider as _, Receiver as _, Recipients, Sender as _,
    simulated::{Sender as SimulatedSender, SplitOrigin, SplitTarget},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Runner as _, Spawner as _, Supervisor as _, deterministic, iobuf::IoBuf,
};
use commonware_utils::{Faults as _, N5f1, channel::mpsc, ordered::Set, sync::Mutex};
use std::{collections::BTreeMap, fmt::Debug, sync::Arc, time::Duration};

/// Committee size for Twins campaigns.
const PARTICIPANTS: u32 = 6;

/// Committee size for the complete two-Byzantine campaign.
const LARGE_PARTICIPANTS: u32 = 11;

/// Each shard contains one singleton and five unordered pairs at `n=11, f=2`.
const F2_PLACEMENT_SHARDS: usize = LARGE_PARTICIPANTS as usize;

/// Scripted adversarial rounds before the fair synchronous suffix.
const ROUNDS: usize = 2;

/// Every scripted round is one view, so a round index is a view index.
const TERM: TermLength = TermLength::ONE;

const FAIR_SUFFIX_VIEW: View = View::new(3);
const CENSORSHIP_VIEW: View = View::new(1);
const CENSORSHIP_DEADLINE_VIEW: View = View::new(2);

type NetworkSender = SimulatedSender<ed25519::PublicKey, deterministic::Context>;

/// One held first-half delivery awaiting its scripted reordering.
struct ReorderedDelivery {
    message: commonware_p2p::Message<ed25519::PublicKey>,
    artifact: DeliveryArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeliveryArtifact {
    source: ed25519::PublicKey,
    signer: Participant,
    view: View,
    kind: ArtifactKind,
    id: ArtifactId<Sha256Digest>,
}

#[derive(Clone, Debug)]
struct ConsensusTransmission {
    origin: SplitOrigin,
    artifact: DeliveryArtifact,
    broadcast_recipients: Option<Vec<ed25519::PublicKey>>,
}

#[derive(Clone, Debug)]
struct ProducerArtifact {
    signer: Participant,
    chain: u32,
    height: u64,
    header: TransactionBlockHeader<Sha256Digest>,
    id: ArtifactId<Sha256Digest>,
}

#[derive(Default)]
struct InclusionEvents {
    blocks: Vec<(usize, SignedTransactionBlock<MinPk, Sha256Digest>)>,
    da_votes: Vec<(usize, DaVote<MinPk, Sha256Digest>)>,
    proposals: Vec<(usize, SignedLeaderBlock<MinPk, Sha256Digest>)>,
    votes: Vec<(usize, Vote<MinPk, Sha256Digest>)>,
}

#[derive(Clone)]
struct InclusionTrace {
    events: Arc<Mutex<InclusionEvents>>,
    epoch: Epoch,
    codec: CodecConfig,
    verifier: Scheme<ed25519::PublicKey, MinPk>,
}

impl InclusionTrace {
    fn new(fixture: &Committee<MinPk>) -> Self {
        Self {
            events: Arc::new(Mutex::new(InclusionEvents::default())),
            epoch: fixture.config.epoch(),
            codec: fixture.codec(),
            verifier: fixture.verifier.clone(),
        }
    }

    fn record(&self, source: usize, plane: u64, bytes: &[u8]) -> bool {
        match plane {
            0 => self.record_data(source, bytes),
            1 => {
                self.record_consensus(source, bytes);
                false
            }
            _ => false,
        }
    }

    fn record_data(&self, source: usize, bytes: &[u8]) -> bool {
        let Ok(bounds) = self.codec.encoded_bounds::<MinPk, Sha256Digest>() else {
            return false;
        };
        let Ok(envelope) = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
            bytes,
            &EnvelopeConfig {
                max_frame_bytes: bounds.max_data_frame_bytes(),
                epoch: self.epoch,
                payload: (),
            },
        ) else {
            return false;
        };
        let mut events = self.events.lock();
        match envelope.into_payload() {
            DataMessage::Block(block) if self.verifier.verify_transaction_block(&block) => {
                assert_eq!(block.signer(), Participant::from_usize(source));
                events.blocks.push((source, block));
                false
            }
            DataMessage::DaVote(vote) if self.verifier.verify_da_vote(&vote) => {
                assert_eq!(vote.signer(), Participant::from_usize(source));
                events.da_votes.push((source, vote));
                true
            }
            _ => false,
        }
    }

    fn record_consensus(&self, source: usize, bytes: &[u8]) {
        let Ok(bounds) = self.codec.encoded_bounds::<MinPk, Sha256Digest>() else {
            return;
        };
        let Ok(envelope) = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
            bytes,
            &EnvelopeConfig {
                max_frame_bytes: bounds.max_consensus_frame_bytes(),
                epoch: self.epoch,
                payload: self.codec,
            },
        ) else {
            return;
        };
        let mut events = self.events.lock();
        match envelope.into_payload() {
            ConsensusMessage::Proposal { block, .. }
                if self.verifier.verify_leader_block(&block, &Sequential) =>
            {
                assert_eq!(block.signer(), Participant::from_usize(source));
                events.proposals.push((source, *block));
            }
            ConsensusMessage::Vote(vote) if self.verifier.verify_vote(&vote) => {
                assert_eq!(vote.signer(), Participant::from_usize(source));
                events.votes.push((source, vote));
            }
            _ => {}
        }
    }

    fn block_from(&self, source: usize) -> Option<SignedTransactionBlock<MinPk, Sha256Digest>> {
        self.events
            .lock()
            .blocks
            .iter()
            .find(|(sender, _)| *sender == source)
            .map(|(_, block)| block.clone())
    }

    fn da_voters(&self, header: &TransactionBlockHeader<Sha256Digest>) -> Vec<usize> {
        let mut voters = self
            .events
            .lock()
            .da_votes
            .iter()
            .filter(|(_, vote)| vote.header() == header)
            .map(|(source, _)| *source)
            .collect::<Vec<_>>();
        voters.sort_unstable();
        voters.dedup();
        voters
    }

    fn votes_for(&self, leader: Sha256Digest) -> Vec<(usize, Vote<MinPk, Sha256Digest>)> {
        let mut votes = BTreeMap::new();
        for (source, vote) in &self.events.lock().votes {
            if vote.body().leader() == leader {
                votes.entry(*source).or_insert_with(|| vote.clone());
            }
        }
        votes.into_iter().collect()
    }

    fn proposal_at(&self, view: View) -> Option<SignedLeaderBlock<MinPk, Sha256Digest>> {
        self.events
            .lock()
            .proposals
            .iter()
            .find(|(_, proposal)| proposal.view() == view)
            .map(|(_, proposal)| proposal.clone())
    }
}

#[derive(Debug, Default)]
struct DeliveryEvents {
    held: Option<DeliveryArtifact>,
    reordered: Option<DeliveryArtifact>,
    duplicated: Option<DeliveryArtifact>,
    fair: Option<DeliveryArtifact>,
}

/// Exact protocol artifacts selected by one deterministic delivery script.
#[derive(Clone, Default)]
struct DeliveryScript(Arc<Mutex<DeliveryEvents>>);

impl DeliveryScript {
    fn record_held(&self, artifact: DeliveryArtifact) {
        let mut events = self.0.lock();
        assert!(
            events.held.replace(artifact).is_none(),
            "one artifact is held"
        );
    }

    fn record_delivery(&self, event: DeliveryEvent, artifact: DeliveryArtifact) {
        let mut events = self.0.lock();
        let slot = match event {
            DeliveryEvent::Reordered => &mut events.reordered,
            DeliveryEvent::Duplicated => &mut events.duplicated,
            DeliveryEvent::Fair => &mut events.fair,
        };
        assert!(
            slot.replace(artifact).is_none(),
            "delivery event is recorded once"
        );
    }

    fn is_complete(&self) -> bool {
        let events = self.0.lock();
        events.held.is_some()
            && events.reordered.is_some()
            && events.duplicated.is_some()
            && events.fair.is_some()
    }

    fn assert_complete(&self, source: &ed25519::PublicKey, signer: Participant) {
        let events = self.0.lock();
        let held = events.held.as_ref().expect("prefix artifact was held");
        let reordered = events
            .reordered
            .as_ref()
            .expect("a distinct prefix artifact was delivered first");
        let duplicated = events
            .duplicated
            .as_ref()
            .expect("the held artifact was delivered twice");
        let fair = events
            .fair
            .as_ref()
            .expect("a fair-suffix artifact was delivered");

        for artifact in [held, reordered, duplicated, fair] {
            assert_eq!(&artifact.source, source, "authenticated source is exact");
            assert_eq!(artifact.signer, signer, "protocol signer is exact");
        }
        assert!(
            held.view < FAIR_SUFFIX_VIEW,
            "held artifact is from the prefix"
        );
        assert!(
            reordered.view < FAIR_SUFFIX_VIEW,
            "reordered artifact is from the prefix"
        );
        assert_ne!(
            held.id, reordered.id,
            "two distinct artifacts are reordered"
        );
        assert_eq!(held, duplicated, "the exact held artifact is duplicated");
        assert!(
            fair.view >= FAIR_SUFFIX_VIEW,
            "fair artifact is from the suffix"
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum DeliveryEvent {
    Reordered,
    Duplicated,
    Fair,
}

#[derive(Clone)]
struct DeliveryPlan {
    script: DeliveryScript,
    source: ed25519::PublicKey,
    signer: Participant,
    fair_view: View,
    epoch: Epoch,
    codec: CodecConfig,
    verifier: Scheme<ed25519::PublicKey, MinPk>,
}

impl DeliveryPlan {
    fn identify(
        &self,
        message: &commonware_p2p::Message<ed25519::PublicKey>,
    ) -> Option<DeliveryArtifact> {
        if message.0 != self.source {
            return None;
        }
        let artifact = identify_consensus(
            message.0.clone(),
            message.1.as_ref(),
            self.epoch,
            self.codec,
            &self.verifier,
        )?;
        (artifact.signer == self.signer).then_some(artifact)
    }
}

#[derive(Clone)]
struct RotationProbe {
    source: ed25519::PublicKey,
    seen: Arc<Mutex<Vec<IoBuf>>>,
}

impl RotationProbe {
    fn new(source: ed25519::PublicKey) -> Self {
        Self {
            source,
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn observe(&self, message: &commonware_p2p::Message<ed25519::PublicKey>) {
        if message.0 == self.source {
            self.seen.lock().push(message.1.clone());
        }
    }

    fn saw(&self, marker: &[u8]) -> bool {
        self.seen
            .lock()
            .iter()
            .any(|message| message.as_ref() == marker)
    }
}

struct PumpItem<E> {
    result: Result<commonware_p2p::Message<ed25519::PublicKey>, E>,
    event: Option<(DeliveryEvent, DeliveryArtifact)>,
}

enum PumpState {
    Hold,
    Reorder(Box<ReorderedDelivery>),
    FairSuffix,
    Fair,
}

/// A receiver backed by a dedicated pump that owns every stateful network await.
struct ScriptedReceiver<E> {
    receiver: mpsc::UnboundedReceiver<PumpItem<E>>,
    script: Option<DeliveryScript>,
}

impl<E> Debug for ScriptedReceiver<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScriptedReceiver")
            .finish_non_exhaustive()
    }
}

impl<E> ScriptedReceiver<E>
where
    E: Debug + std::error::Error + Send + Sync + 'static,
{
    fn scripted<R>(
        context: deterministic::Context,
        inner: R,
        plan: DeliveryPlan,
        probe: RotationProbe,
    ) -> Self
    where
        R: commonware_p2p::Receiver<Error = E, PublicKey = ed25519::PublicKey>,
    {
        Self::pump(context, inner, Some(plan), Some(probe))
    }

    fn fair<R>(context: deterministic::Context, inner: R) -> Self
    where
        R: commonware_p2p::Receiver<Error = E, PublicKey = ed25519::PublicKey>,
    {
        Self::pump(context, inner, None, None)
    }

    fn pump<R>(
        context: deterministic::Context,
        mut inner: R,
        plan: Option<DeliveryPlan>,
        probe: Option<RotationProbe>,
    ) -> Self
    where
        R: commonware_p2p::Receiver<Error = E, PublicKey = ed25519::PublicKey>,
    {
        let (sender, receiver) = mpsc::unbounded_channel();
        let script = plan.as_ref().map(|plan| plan.script.clone());
        context.spawn(move |_| async move {
            let mut state = if plan.is_some() {
                PumpState::Hold
            } else {
                PumpState::Fair
            };

            loop {
                let message = match inner.recv().await {
                    Ok(message) => message,
                    Err(error) => {
                        let _ = sender.send(PumpItem {
                            result: Err(error),
                            event: None,
                        });
                        return;
                    }
                };
                if let Some(probe) = &probe {
                    probe.observe(&message);
                }

                let identified = plan.as_ref().and_then(|plan| plan.identify(&message));
                match (&mut state, identified) {
                    (PumpState::Hold, Some(artifact))
                        if artifact.view < plan.as_ref().unwrap().fair_view =>
                    {
                        plan.as_ref().unwrap().script.record_held(artifact.clone());
                        state =
                            PumpState::Reorder(Box::new(ReorderedDelivery { message, artifact }));
                    }
                    (PumpState::Reorder(reordered), Some(artifact))
                        if artifact.view < plan.as_ref().unwrap().fair_view
                            && artifact.id != reordered.artifact.id =>
                    {
                        let held = reordered.message.clone();
                        let held_artifact = reordered.artifact.clone();
                        let deliveries = [
                            (message, Some((DeliveryEvent::Reordered, artifact))),
                            (held.clone(), None),
                            (held, Some((DeliveryEvent::Duplicated, held_artifact))),
                        ];
                        for (message, event) in deliveries {
                            if sender
                                .send(PumpItem {
                                    result: Ok(message),
                                    event,
                                })
                                .is_err()
                            {
                                return;
                            }
                        }
                        state = PumpState::FairSuffix;
                    }
                    (PumpState::FairSuffix, Some(artifact))
                        if artifact.view >= plan.as_ref().unwrap().fair_view =>
                    {
                        if sender
                            .send(PumpItem {
                                result: Ok(message),
                                event: Some((DeliveryEvent::Fair, artifact)),
                            })
                            .is_err()
                        {
                            return;
                        }
                        state = PumpState::Fair;
                    }
                    _ => {
                        if sender
                            .send(PumpItem {
                                result: Ok(message),
                                event: None,
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
        });

        Self { receiver, script }
    }
}

impl<E> commonware_p2p::Receiver for ScriptedReceiver<E>
where
    E: Debug + std::error::Error + Send + Sync + 'static,
{
    type Error = E;
    type PublicKey = ed25519::PublicKey;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Self::Error> {
        let item = self
            .receiver
            .recv()
            .await
            .expect("delivery pump remains live while its receiver is live");
        if let (Some(script), Some((event, artifact))) = (&self.script, item.event) {
            script.record_delivery(event, artifact);
        }
        item.result
    }
}

fn identify_consensus(
    source: ed25519::PublicKey,
    bytes: &[u8],
    epoch: Epoch,
    codec: CodecConfig,
    verifier: &Scheme<ed25519::PublicKey, MinPk>,
) -> Option<DeliveryArtifact> {
    let bounds = codec.encoded_bounds::<MinPk, Sha256Digest>().ok()?;
    let payload = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
        bytes,
        &EnvelopeConfig {
            max_frame_bytes: bounds.max_consensus_frame_bytes(),
            epoch,
            payload: codec,
        },
    )
    .ok()?
    .into_payload();
    let artifact = match payload {
        ConsensusMessage::Proposal { block, .. } => {
            verifier
                .verify_leader_block(&block, &Sequential)
                .then_some(())?;
            Artifact::LeaderBlock(*block)
        }
        ConsensusMessage::Vote(vote) => {
            verifier.verify_vote(&vote).then_some(())?;
            Artifact::Vote(vote)
        }
        ConsensusMessage::NoVote(vote) => {
            verifier.verify_novote(&vote).then_some(())?;
            Artifact::NoVote(vote)
        }
        ConsensusMessage::Nullify(nullify) => {
            verifier.verify_nullify(&nullify).then_some(())?;
            Artifact::Nullify(nullify)
        }
    };
    Some(DeliveryArtifact {
        source,
        signer: artifact.signer()?,
        view: artifact.view()?,
        kind: artifact.kind(),
        id: artifact.id::<Sha256>(),
    })
}

fn identify_producer(
    bytes: &[u8],
    epoch: Epoch,
    codec: CodecConfig,
    verifier: &Scheme<ed25519::PublicKey, MinPk>,
) -> Option<ProducerArtifact> {
    let bounds = codec.encoded_bounds::<MinPk, Sha256Digest>().ok()?;
    let payload = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
        bytes,
        &EnvelopeConfig {
            max_frame_bytes: bounds.max_data_frame_bytes(),
            epoch,
            payload: (),
        },
    )
    .ok()?
    .into_payload();
    let DataMessage::Block(block) = payload else {
        return None;
    };
    verifier.verify_transaction_block(&block).then_some(())?;

    let header = block.header().clone();
    let chain = header.chain().get();
    let height = header.height().get();
    let artifact = Artifact::TransactionBlock(block);
    Some(ProducerArtifact {
        signer: artifact.signer()?,
        chain,
        height,
        header,
        id: artifact.id::<Sha256>(),
    })
}

fn identify_producer_consequence(
    bytes: &[u8],
    epoch: Epoch,
    codec: CodecConfig,
    verifier: &Scheme<ed25519::PublicKey, MinPk>,
) -> Option<TransactionBlockHeader<Sha256Digest>> {
    let bounds = codec.encoded_bounds::<MinPk, Sha256Digest>().ok()?;
    let payload = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
        bytes,
        &EnvelopeConfig {
            max_frame_bytes: bounds.max_data_frame_bytes(),
            epoch,
            payload: (),
        },
    )
    .ok()?
    .into_payload();
    match payload {
        DataMessage::DaVote(vote) if verifier.verify_da_vote(&vote) => Some(vote.header().clone()),
        DataMessage::DaCertificate(certificate) if verifier.verify_da_certificate(&certificate) => {
            Some(certificate.header().clone())
        }
        _ => None,
    }
}

fn route_producer_consequence(
    blocks: &[(SplitOrigin, ProducerArtifact)],
    header: &TransactionBlockHeader<Sha256Digest>,
) -> Option<SplitTarget> {
    let emitted_by = |origin| {
        blocks
            .iter()
            .any(|(candidate, block)| *candidate == origin && block.header == *header)
    };

    match (
        emitted_by(SplitOrigin::Primary),
        emitted_by(SplitOrigin::Secondary),
    ) {
        (true, true) => Some(SplitTarget::Both),
        (true, false) => Some(SplitTarget::Primary),
        (false, true) => Some(SplitTarget::Secondary),
        (false, false) => None,
    }
}

#[test]
fn producer_consequences_follow_the_exact_twin_header() {
    let epoch = Epoch::new(1);
    let chain = ChainId::new(0);
    let height = Height::new(1);
    let parent = Sha256::hash(&[b"parent"]);
    let primary =
        TransactionBlockHeader::new(epoch, chain, height, parent, Sha256::hash(&[b"primary"]))
            .unwrap();
    let secondary =
        TransactionBlockHeader::new(epoch, chain, height, parent, Sha256::hash(&[b"secondary"]))
            .unwrap();
    let producer = |header: TransactionBlockHeader<Sha256Digest>, id: &[u8]| ProducerArtifact {
        signer: Participant::new(0),
        chain: header.chain().get(),
        height: header.height().get(),
        header,
        id: ArtifactId::new(Sha256::hash(&[id])),
    };
    let blocks = [
        (
            SplitOrigin::Primary,
            producer(primary.clone(), b"primary id"),
        ),
        (
            SplitOrigin::Secondary,
            producer(secondary.clone(), b"secondary id"),
        ),
    ];

    assert_eq!(
        route_producer_consequence(&blocks, &primary),
        Some(SplitTarget::Primary)
    );
    assert_eq!(
        route_producer_consequence(&blocks, &secondary),
        Some(SplitTarget::Secondary)
    );
}

struct TwinSlots {
    primary: usize,
    secondary: usize,
    traffic: Arc<Mutex<Vec<ConsensusTransmission>>>,
    producer_blocks: Arc<Mutex<Vec<(SplitOrigin, ProducerArtifact)>>>,
}

impl TwinSlots {
    fn assert_selective_disclosure(
        &self,
        byzantine: usize,
        scenario: &Scenario,
        identities: &[ed25519::PublicKey],
    ) {
        let traffic = self.traffic.lock();
        for origin in [SplitOrigin::Primary, SplitOrigin::Secondary] {
            let transmission = traffic
                .iter()
                .find(|transmission| {
                    transmission.origin == origin
                        && transmission.artifact.signer == Participant::from_usize(byzantine)
                        && transmission.artifact.view < FAIR_SUFFIX_VIEW
                        && transmission.broadcast_recipients.is_some()
                })
                .unwrap_or_else(|| {
                    panic!("{origin:?} emitted a signature-verified broadcast in the attack prefix")
                });
            let (primary, secondary) =
                scenario.partitions(transmission.artifact.view, TERM, identities);
            let expected = match origin {
                SplitOrigin::Primary => primary,
                SplitOrigin::Secondary => secondary,
            };
            let actual = transmission
                .broadcast_recipients
                .as_ref()
                .expect("broadcast recipient set was recorded");
            assert_eq!(
                transmission.artifact.source, identities[byzantine],
                "the authenticated endpoint and protocol signer identify one participant"
            );
            assert_eq!(actual, &expected, "the exact scripted mask is installed");
            assert!(
                actual.len() < identities.len(),
                "attack-prefix disclosure excludes at least one participant"
            );
        }
    }

    fn has_producer_equivocation(&self, cluster: &Cluster<MinPk>, byzantine: usize) -> bool {
        let blocks = self.producer_blocks.lock();
        let transmitted = blocks.iter().any(|(left_origin, left)| {
            *left_origin == SplitOrigin::Primary
                && left.signer == Participant::from_usize(byzantine)
                && blocks.iter().any(|(right_origin, right)| {
                    *right_origin == SplitOrigin::Secondary
                        && right.signer == left.signer
                        && right.chain == left.chain
                        && right.height == left.height
                        && right.id != left.id
                })
        });
        drop(blocks);
        if transmitted {
            return true;
        }

        let headers = |slot| {
            cluster
                .app(slot)
                .log()
                .lock()
                .builds
                .iter()
                .map(|(context, commitment)| {
                    TransactionBlockHeader::new(
                        context.epoch(),
                        context.chain(),
                        context.height(),
                        context.parent(),
                        *commitment,
                    )
                    .expect("the application builds only live producer heights")
                })
                .collect::<Vec<_>>()
        };
        let primary = headers(self.primary);
        let secondary = headers(self.secondary);
        let chain = ChainId::new(byzantine as u32);
        primary.iter().any(|left| {
            left.chain() == chain
                && secondary.iter().any(|right| {
                    right.chain() == left.chain()
                        && right.height() == left.height()
                        && right.digest::<Sha256>() != left.digest::<Sha256>()
                })
        })
    }

    fn assert_producer_equivocation(&self, cluster: &Cluster<MinPk>, byzantine: usize) {
        assert!(
            self.has_producer_equivocation(cluster, byzantine),
            "both halves built conflicting headers at one producer-chain position"
        );
    }
}

/// Returns the view a scripted round runs at.
///
/// Round `r` runs at view `r + 1`; view zero is synthetic genesis.
const fn round_view(round: usize) -> View {
    View::new(round as u64 + 1)
}

/// Returns the leader schedule that makes each scripted round's view elect that round's leader.
///
/// The generator picks a leader per round; Multimmit elects `schedule[view % n]`. Placing each
/// round's leader at its view's slot honors the scenario exactly, and the remaining slots keep
/// their round-robin participants so later views stay well defined.
fn schedule_for(scenario: &Scenario, participants: usize) -> LeaderSchedule {
    let mut order: Vec<Participant> = (0..participants).map(Participant::from_usize).collect();
    for (round, scripted) in scenario.rounds().iter().enumerate() {
        let slot = (round_view(round).get() as usize) % participants;
        order[slot] = Participant::from_usize(scripted.leader());
    }
    LeaderSchedule::round_robin(participants)
        .clone_with(order)
        .expect("scenario leaders are committee members")
}

/// Returns the view a plane message belongs to, if the plane is view-scoped.
///
/// Data-plane traffic is chain-scoped, so it carries no view and is never split by round.
fn message_view(plane: u64, bytes: &[u8], epoch: Epoch, codec: CodecConfig) -> Option<View> {
    let Ok(bounds) = codec.encoded_bounds::<MinPk, Sha256Digest>() else {
        return None;
    };
    match plane {
        1 => {
            let envelope = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &EnvelopeConfig {
                    max_frame_bytes: bounds.max_consensus_frame_bytes(),
                    epoch,
                    payload: codec,
                },
            )
            .ok()?;
            Some(match envelope.into_payload() {
                ConsensusMessage::Proposal { block, .. } => block.view(),
                ConsensusMessage::Vote(vote) => vote.view(),
                ConsensusMessage::NoVote(vote) => vote.view(),
                ConsensusMessage::Nullify(nullify) => nullify.view(),
            })
        }
        2 => {
            let envelope = Envelope::<CertificateMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &EnvelopeConfig {
                    max_frame_bytes: bounds.max_certificate_frame_bytes(),
                    epoch,
                    payload: codec,
                },
            )
            .ok()?;
            Some(match envelope.into_payload() {
                CertificateMessage::Nullification(nullification) => nullification.view(),
                CertificateMessage::Vqc(certificate) => certificate.view(),
                CertificateMessage::Lqc(certificate) => certificate.view(),
            })
        }
        _ => {
            // Reject malformed data-plane bytes the same way the batcher would, without
            // attributing them to a view.
            let _ = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &EnvelopeConfig {
                    max_frame_bytes: bounds.max_data_frame_bytes(),
                    epoch,
                    payload: (),
                },
            );
            None
        }
    }
}

fn participant_mask(participants: impl IntoIterator<Item = usize>) -> u64 {
    participants
        .into_iter()
        .fold(0u64, |mask, participant| mask | (1 << participant))
}

/// Two explicit view-scoped masks exercise selective disclosure before full synchrony.
fn placement_scenario(participants: usize) -> Scenario {
    assert!(participants >= 4, "the placement scenario needs four roles");
    assert!(
        participants <= u64::BITS as usize,
        "participant masks fit in u64"
    );
    let all = participant_mask(0..participants);
    let without = |participant: usize| all & !(1u64 << participant);

    Scenario::new(vec![
        RoundScenario::new(0, without(participants - 1), without(0)),
        RoundScenario::new(0, without(participants / 2), without(1)),
    ])
}

fn restrict_recipients(
    recipients: &Recipients<ed25519::PublicKey>,
    mask: &[ed25519::PublicKey],
) -> Option<Recipients<ed25519::PublicKey>> {
    let contains = |identity: &ed25519::PublicKey| mask.contains(identity);
    match recipients {
        Recipients::All => Some(Recipients::Some(mask.to_vec())),
        Recipients::Some(identities) => {
            let identities = identities
                .iter()
                .filter(|identity| contains(identity))
                .cloned()
                .collect::<Vec<_>>();
            (!identities.is_empty()).then_some(Recipients::Some(identities))
        }
        Recipients::One(identity) => contains(identity).then(|| Recipients::One(identity.clone())),
    }
}

async fn launch_halves<S, R>(
    cluster: &mut Cluster<MinPk>,
    byzantine: usize,
    primary: Vec<(S, R)>,
    secondary: Vec<(S, R)>,
    labels: [&'static str; 2],
) -> (usize, usize)
where
    S: commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
    R: commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
{
    let primary_slot = cluster.reserve_slot("primary");
    let secondary_slot = cluster.reserve_slot("secondary");
    let mut primary = primary.into_iter();
    let mut secondary = secondary.into_iter();
    cluster
        .launch_with(
            primary_slot,
            byzantine,
            Some(labels[0]),
            primary.next().expect("primary data plane"),
            primary.next().expect("primary consensus plane"),
            primary.next().expect("primary certificate plane"),
            primary.next().expect("primary resolver plane"),
        )
        .await;
    cluster
        .launch_with(
            secondary_slot,
            byzantine,
            Some(labels[1]),
            secondary.next().expect("secondary data plane"),
            secondary.next().expect("secondary consensus plane"),
            secondary.next().expect("secondary certificate plane"),
            secondary.next().expect("secondary resolver plane"),
        )
        .await;
    assert!(primary.next().is_none(), "exactly four primary planes");
    assert!(secondary.next().is_none(), "exactly four secondary planes");
    (primary_slot, secondary_slot)
}

async fn launch_scenario_twins(
    context: &deterministic::Context,
    cluster: &mut Cluster<MinPk>,
    byzantine: usize,
    scenario: &Scenario,
    labels: [&'static str; 2],
) -> TwinSlots {
    let identities: Arc<[ed25519::PublicKey]> = cluster.identities().into();
    let fixture = cluster.fixture();
    let epoch = fixture.config.epoch();
    let codec = fixture.codec();
    let verifier = fixture.verifier;
    let byzantine_identity = identities[byzantine].clone();
    let traffic = Arc::new(Mutex::new(Vec::new()));
    let producer_blocks = Arc::new(Mutex::new(Vec::new()));
    let mut primary = Vec::new();
    let mut secondary = Vec::new();

    for plane in 0..4u64 {
        let (sender, receiver) = cluster.tap(byzantine, plane).await;
        let forward_scenario = scenario.clone();
        let forward_identities = identities.clone();
        let forward_verifier = verifier.clone();
        let forward_identity = byzantine_identity.clone();
        let forward_traffic = traffic.clone();
        let forward_producer_blocks = producer_blocks.clone();
        let forwarder = move |origin: SplitOrigin,
                              recipients: &Recipients<ed25519::PublicKey>,
                              message: &IoBuf| {
            if plane == 0
                && let Some(artifact) =
                    identify_producer(message.as_ref(), epoch, codec, &forward_verifier)
            {
                forward_producer_blocks.lock().push((origin, artifact));
            }
            let consensus = (plane == 1)
                .then(|| {
                    identify_consensus(
                        forward_identity.clone(),
                        message.as_ref(),
                        epoch,
                        codec,
                        &forward_verifier,
                    )
                })
                .flatten();
            let Some(view) = message_view(plane, message.as_ref(), epoch, codec) else {
                return Some(recipients.clone());
            };
            let (primary, secondary) =
                forward_scenario.partitions(view, TERM, forward_identities.as_ref());
            let restricted = restrict_recipients(
                recipients,
                match origin {
                    SplitOrigin::Primary => primary,
                    SplitOrigin::Secondary => secondary,
                }
                .as_ref(),
            );
            if let Some(artifact) = consensus {
                let broadcast_recipients =
                    matches!(recipients, Recipients::All).then(|| match &restricted {
                        Some(Recipients::Some(recipients)) => recipients.clone(),
                        Some(Recipients::One(recipient)) => vec![recipient.clone()],
                        Some(Recipients::All) => {
                            unreachable!("recipient restriction makes broadcasts explicit")
                        }
                        None => Vec::new(),
                    });
                forward_traffic.lock().push(ConsensusTransmission {
                    origin,
                    artifact,
                    broadcast_recipients,
                });
            }
            restricted
        };

        let route_scenario = scenario.clone();
        let route_identities = identities.clone();
        let route_verifier = verifier.clone();
        let route_producer_blocks = producer_blocks.clone();
        let router = move |(sender, message): &(ed25519::PublicKey, IoBuf)| {
            if plane == 0
                && let Some(header) =
                    identify_producer_consequence(message.as_ref(), epoch, codec, &route_verifier)
                && let Some(target) =
                    route_producer_consequence(&route_producer_blocks.lock(), &header)
            {
                return target;
            }
            let Some(view) = message_view(plane, message.as_ref(), epoch, codec) else {
                return SplitTarget::Both;
            };
            route_scenario.route(view, TERM, sender, route_identities.as_ref())
        };

        let (sender_primary, sender_secondary) = sender.split_with(forwarder);
        let (receiver_primary, receiver_secondary) = receiver.split_with(
            context.child("twin_split").with_attribute("plane", plane),
            router,
        );
        primary.push((sender_primary, receiver_primary));
        secondary.push((sender_secondary, receiver_secondary));
    }

    let (primary, secondary) = Box::pin(launch_halves(
        cluster, byzantine, primary, secondary, labels,
    ))
    .await;
    TwinSlots {
        primary,
        secondary,
        traffic,
        producer_blocks,
    }
}

async fn launch_traced_honest(
    cluster: &mut Cluster<MinPk>,
    honest: &[usize],
    trace: &InclusionTrace,
) {
    for participant in 0..PARTICIPANTS as usize {
        assert_eq!(
            cluster.reserve_slot(""),
            participant,
            "committee storage slots stay in participant order"
        );
    }

    for &participant in honest {
        let mut planes = Vec::new();
        for plane in 0..4u64 {
            let (sender, receiver) = cluster.tap(participant, plane).await;
            let trace = trace.clone();
            let forwarder = move |origin: SplitOrigin,
                                  recipients: &Recipients<ed25519::PublicKey>,
                                  message: &IoBuf| {
                if message_view(plane, message.as_ref(), trace.epoch, trace.codec)
                    .is_some_and(|view| view > CENSORSHIP_DEADLINE_VIEW)
                {
                    return None;
                }
                if origin == SplitOrigin::Primary
                    && trace.record(participant, plane, message.as_ref())
                {
                    return None;
                }
                Some(recipients.clone())
            };
            let (sender, _unused) = sender.split_with(forwarder);
            planes.push((sender, receiver));
        }
        let mut planes = planes.into_iter();
        Box::pin(cluster.launch_with(
            participant,
            participant,
            None,
            planes.next().expect("honest data plane"),
            planes.next().expect("honest consensus plane"),
            planes.next().expect("honest certificate plane"),
            planes.next().expect("honest resolver plane"),
        ))
        .await;
        assert!(planes.next().is_none(), "exactly four honest planes");
    }
}

fn censorship_proposal(
    fixture: &Committee<MinPk>,
    junk: Option<Sha256Digest>,
) -> SignedLeaderBlock<MinPk, Sha256Digest> {
    let view = CENSORSHIP_VIEW;
    let codec = fixture.codec();
    let genesis = fixture.config.genesis();
    let proposals = genesis
        .tips()
        .iter()
        .enumerate()
        .map(|(chain, tip)| {
            let payloads = if chain == 0 {
                junk.iter().copied().collect()
            } else {
                Vec::new()
            };
            ChainProposal::new(
                tip.chain(),
                Anchor::Tip(*tip),
                payloads,
                codec.pipeline_depth(),
            )
            .expect("Byzantine proposal remains structurally valid")
        })
        .collect();
    let block = LeaderBlock::new(
        Round::new(fixture.config.epoch(), view),
        genesis.vqc(),
        genesis_tip_commitment::<Sha256>(genesis),
        proposals,
        codec,
    )
    .expect("Byzantine proposal remains structurally valid");
    fixture.signers[1]
        .sign_leader_block(block)
        .expect("participant one is the view-one leader")
}

fn send_consensus(
    sender: &mut NetworkSender,
    recipients: Vec<ed25519::PublicKey>,
    epoch: Epoch,
    message: ConsensusMessage<MinPk, Sha256Digest>,
) {
    let frame = IoBuf::from(Envelope::new(epoch, message).encode());
    assert_eq!(
        sender.send(Recipients::Some(recipients.clone()), frame, true),
        recipients,
        "every selected recipient accepts the authenticated Byzantine frame"
    );
}

fn vote_counts_for(
    vote: &Vote<MinPk, Sha256Digest>,
    leader: &SignedLeaderBlock<MinPk, Sha256Digest>,
    target: &TransactionBlockHeader<Sha256Digest>,
) -> bool {
    let chain = target.chain().get() as usize;
    let proposal = &leader.block().proposals()[chain];
    let anchor = proposal.anchor().block_ref::<Sha256>();
    if target.parent() != anchor.digest() || target.height().get() != anchor.height().get() + 1 {
        return false;
    }

    let position = vote.body().positions()[chain].get() as usize;
    if position == 1 {
        return proposal.payloads().first() == Some(&target.body_digest());
    }
    if position != 0 {
        return false;
    }
    vote.body().extensions()[chain].payloads().first() == Some(&target.body_digest())
}

fn proposal_extends(
    proposal: &SignedLeaderBlock<MinPk, Sha256Digest>,
    target: &TransactionBlockHeader<Sha256Digest>,
) -> bool {
    let chain = target.chain().get() as usize;
    let chain_proposal = &proposal.block().proposals()[chain];
    let anchor = chain_proposal.anchor().block_ref::<Sha256>();
    let target_ref = target.block_ref::<Sha256>();
    if anchor == target_ref {
        return true;
    }
    target.parent() == anchor.digest()
        && target.height().get() == anchor.height().get() + 1
        && chain_proposal.payloads().first() == Some(&target.body_digest())
}

async fn launch_scripted_honest(
    context: &deterministic::Context,
    cluster: &mut Cluster<MinPk>,
    honest: &[usize],
    scripted_node: usize,
    plan: &DeliveryPlan,
    probe: &RotationProbe,
) {
    for participant in 0..PARTICIPANTS as usize {
        assert_eq!(
            cluster.reserve_slot(""),
            participant,
            "committee storage slots stay in participant order"
        );
    }

    for &participant in honest {
        let mut planes = Vec::new();
        for plane in 0..4u64 {
            let (sender, receiver) = cluster.tap(participant, plane).await;
            let receiver = if participant == scripted_node && plane == 1 {
                ScriptedReceiver::scripted(
                    context
                        .child("scripted_delivery")
                        .with_attribute("participant", participant)
                        .with_attribute("plane", plane),
                    receiver,
                    plan.clone(),
                    probe.clone(),
                )
            } else {
                ScriptedReceiver::fair(
                    context
                        .child("fair_delivery")
                        .with_attribute("participant", participant)
                        .with_attribute("plane", plane),
                    receiver,
                )
            };
            planes.push((sender, receiver));
        }
        let mut planes = planes.into_iter();
        cluster
            .launch_with(
                participant,
                participant,
                None,
                planes.next().expect("honest data plane"),
                planes.next().expect("honest consensus plane"),
                planes.next().expect("honest certificate plane"),
                planes.next().expect("honest resolver plane"),
            )
            .await;
        assert!(planes.next().is_none(), "exactly four honest planes");
    }
}

async fn wait_twin_equivocation(
    context: &deterministic::Context,
    cluster: &mut Cluster<MinPk>,
    twins: &TwinSlots,
    byzantine: usize,
) {
    for _ in 0..600 {
        if twins.has_producer_equivocation(cluster, byzantine) {
            break;
        }
        context.sleep(Duration::from_millis(10)).await;
        cluster.refresh();
    }
    twins.assert_producer_equivocation(cluster, byzantine);
}

fn twin_labels(index: usize) -> [&'static str; 2] {
    match index {
        0 => ["twin_a_primary", "twin_a_secondary"],
        1 => ["twin_b_primary", "twin_b_secondary"],
        _ => panic!("the bounded placement matrix has at most two Byzantine identities"),
    }
}

async fn run_placement_case(
    context: &deterministic::Context,
    participants: u32,
    byzantine: &[usize],
    seed: u64,
) {
    assert!(
        !byzantine.is_empty() && byzantine.len() <= N5f1::max_faults(participants) as usize,
        "the case uses a nonempty placement within the declared fault budget"
    );
    let mut distinct = byzantine.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        byzantine.len(),
        "Byzantine placements are disjoint"
    );

    let participants = participants as usize;
    let scenario = placement_scenario(participants);
    assert_eq!(scenario.rounds().len(), ROUNDS);
    let mut cluster = Cluster::<MinPk>::new(
        context,
        ClusterOptions {
            n: participants as u32,
            seed,
            extras: 0,
            leaders: Some(schedule_for(&scenario, participants)),
            quota: None,
            latency: None,
            jitter: None,
            production: None,
            view_retention: None,
        },
    )
    .await;
    let honest = (0..participants)
        .filter(|participant| !byzantine.contains(participant))
        .collect::<Vec<_>>();
    for &participant in &honest {
        cluster.start_one(participant).await;
    }

    let mut twins = Vec::with_capacity(byzantine.len());
    for (index, &participant) in byzantine.iter().enumerate() {
        twins.push(
            Box::pin(launch_scenario_twins(
                context,
                &mut cluster,
                participant,
                &scenario,
                twin_labels(index),
            ))
            .await,
        );
    }

    let mut running = honest.clone();
    running.extend(
        twins
            .iter()
            .flat_map(|slots| [slots.primary, slots.secondary]),
    );
    cluster.await_ready(&running).await;
    cluster.wait_view(&honest, round_view(ROUNDS), 3600).await;
    let identities = cluster.identities();
    for (&participant, slots) in byzantine.iter().zip(&twins) {
        slots.assert_selective_disclosure(participant, &scenario, &identities);
    }

    cluster.produce_once();
    cluster.wait_produced(&honest, 1, 600).await;
    for (&participant, slots) in byzantine.iter().zip(&twins) {
        wait_twin_equivocation(context, &mut cluster, slots, participant).await;
    }

    cluster.observe_finality(&honest).await;
    require_fair_suffix_progress(&mut cluster, &honest, 2).await;
}

fn f2_placements() -> Vec<Vec<usize>> {
    let participants = LARGE_PARTICIPANTS as usize;
    let mut placements = Vec::with_capacity(participants + participants * (participants - 1) / 2);

    placements.extend((0..participants).map(|participant| vec![participant]));
    for left in 0..participants {
        for right in left + 1..participants {
            placements.push(vec![left, right]);
        }
    }

    assert_eq!(placements.len(), 11 + 55);
    placements
}

fn run_f2_placement_shard(shard: usize) {
    assert!(shard < F2_PLACEMENT_SHARDS);
    let cases = f2_placements()
        .into_iter()
        .enumerate()
        .filter(|(ordinal, _)| ordinal % F2_PLACEMENT_SHARDS == shard)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 6, "every shard has equal work");

    for (ordinal, byzantine) in cases {
        let executor = deterministic::Runner::timed(Duration::from_secs(900));
        executor.start(move |context| async move {
            Box::pin(run_placement_case(
                &context,
                LARGE_PARTICIPANTS,
                &byzantine,
                920 + ordinal as u64,
            ))
            .await;
        });
    }
}

async fn require_fair_suffix_progress(cluster: &mut Cluster<MinPk>, honest: &[usize], height: u64) {
    cluster.produce_once();
    cluster.wait_produced(honest, height, 600).await;
    let chains = honest.iter().map(|index| *index as u32).collect::<Vec<_>>();
    cluster.wait_finalized(honest, &chains, height, 3600).await;
    cluster.observe_finality(honest).await;
}

async fn rotate_byzantine_peer(
    context: &deterministic::Context,
    cluster: &mut Cluster<MinPk>,
    honest: &[usize],
    attacker: &mut NetworkSender,
    target: &ed25519::PublicKey,
    probe: &RotationProbe,
) {
    let identities = cluster.identities();
    let honest_identities = honest
        .iter()
        .map(|index| identities[*index].clone())
        .collect::<Vec<_>>();
    let mut manager = cluster.oracle().manager();
    assert!(
        manager
            .track(1, Set::from_iter_dedup(honest_identities))
            .accepted(),
        "Byzantine peer is rotated out"
    );
    let removed = manager
        .peer_set(1)
        .await
        .expect("removed peer set is installed");
    assert!(
        removed.union().position(&probe.source).is_none(),
        "Byzantine identity is absent from the installed peer set"
    );

    let removed_marker = vec![0xa5; 32];
    assert_eq!(
        attacker.send(
            Recipients::One(target.clone()),
            IoBuf::from(removed_marker.clone()),
            true,
        ),
        vec![target.clone()],
        "local submission remains accepted while the authenticated source is untracked"
    );
    cluster.produce_once();
    cluster.wait_produced(honest, 2, 600).await;
    context.sleep(Duration::from_millis(10)).await;
    assert!(
        !probe.saw(&removed_marker),
        "traffic from the rotated-out identity is not delivered"
    );
    cluster.observe_finality(honest).await;

    assert!(
        manager
            .track(2, Set::from_iter_dedup(identities.clone()))
            .accepted(),
        "Byzantine peer is rotated back in"
    );
    let restored = manager
        .peer_set(2)
        .await
        .expect("restored peer set is installed");
    assert!(
        restored.union().position(&probe.source).is_some(),
        "Byzantine identity is present after rotation"
    );
    link_all(cluster.oracle(), &identities).await;
    let restored_marker = vec![0x5a; 32];
    assert_eq!(
        attacker.send(
            Recipients::One(target.clone()),
            IoBuf::from(restored_marker.clone()),
            true,
        ),
        vec![target.clone()],
        "the restored endpoint submits authenticated traffic"
    );
    for _ in 0..100 {
        if probe.saw(&restored_marker) {
            break;
        }
        context.sleep(Duration::from_millis(1)).await;
    }
    assert!(
        probe.saw(&restored_marker),
        "traffic is observed after the peer is re-added"
    );
    cluster.observe_finality(honest).await;
}

#[derive(Debug)]
struct ControlledReceiver {
    messages: mpsc::UnboundedReceiver<commonware_p2p::Message<ed25519::PublicKey>>,
    taken: mpsc::UnboundedSender<()>,
}

impl commonware_p2p::Receiver for ControlledReceiver {
    type Error = std::io::Error;
    type PublicKey = ed25519::PublicKey;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Self::Error> {
        let message = self
            .messages
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("controlled receiver closed"))?;
        let _ = self.taken.send(());
        Ok(message)
    }
}

async fn cancel_pending_recv(
    context: &deterministic::Context,
    receiver: &mut ScriptedReceiver<std::io::Error>,
) {
    select! {
        result = receiver.recv() => panic!("scripted receive unexpectedly completed: {result:?}"),
        _ = context.sleep(Duration::from_millis(1)) => {},
    }
}

#[test_traced]
fn scripted_receiver_survives_cancelled_receives() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let fixture = Committee::<MinPk>::new(979, PARTICIPANTS, Limits::new(2, 1).unwrap());
        let source = fixture.identities[1].clone();
        let signer = Participant::new(1);
        let script = DeliveryScript::default();
        let plan = DeliveryPlan {
            script: script.clone(),
            source: source.clone(),
            signer,
            fair_view: FAIR_SUFFIX_VIEW,
            epoch: fixture.config.epoch(),
            codec: fixture.codec(),
            verifier: fixture.verifier.clone(),
        };
        let frame = |payload: ConsensusMessage<MinPk, Sha256Digest>| {
            IoBuf::from(Envelope::new(fixture.config.epoch(), payload).encode())
        };
        let held = frame(ConsensusMessage::NoVote(fixture.novote(1, 1)));
        let reordered = frame(ConsensusMessage::Nullify(fixture.nullify(1, 2)));
        let fair = frame(ConsensusMessage::Nullify(fixture.nullify(1, 3)));
        let (sender, messages) = mpsc::unbounded_channel();
        let (taken, mut acknowledgements) = mpsc::unbounded_channel();
        let inner = ControlledReceiver { messages, taken };
        let probe = RotationProbe::new(fixture.identities[5].clone());
        let mut receiver = ScriptedReceiver::scripted(
            context.child("cancellation_safe_delivery"),
            inner,
            plan,
            probe,
        );

        cancel_pending_recv(&context, &mut receiver).await;
        sender.send((source.clone(), held.clone())).unwrap();
        acknowledgements.recv().await.unwrap();
        cancel_pending_recv(&context, &mut receiver).await;

        sender.send((source.clone(), reordered.clone())).unwrap();
        acknowledgements.recv().await.unwrap();
        assert_eq!(receiver.recv().await.unwrap().1, reordered);
        assert_eq!(receiver.recv().await.unwrap().1, held);
        assert_eq!(receiver.recv().await.unwrap().1, held);

        cancel_pending_recv(&context, &mut receiver).await;
        sender.send((source.clone(), fair.clone())).unwrap();
        acknowledgements.recv().await.unwrap();
        assert_eq!(receiver.recv().await.unwrap().1, fair);
        script.assert_complete(&source, signer);
    });
}

#[test_group("slow")]
#[test_traced]
fn well_disseminated_block_survives_byzantine_leader_censorship() {
    let executor = deterministic::Runner::timed(Duration::from_secs(60));
    executor.start(|context| async move {
        const PRODUCER: usize = 0;
        const BYZANTINE: usize = 1;

        let honest = (0..PARTICIPANTS as usize)
            .filter(|participant| *participant != BYZANTINE)
            .collect::<Vec<_>>();
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                n: PARTICIPANTS,
                seed: 990,
                extras: 0,
                leaders: None,
                quota: None,
                latency: None,
                jitter: None,
                production: Some(Duration::from_millis(10)),
                view_retention: None,
            },
        )
        .await;
        let fixture = cluster.fixture();
        let trace = InclusionTrace::new(&fixture);
        Box::pin(launch_traced_honest(&mut cluster, &honest, &trace)).await;

        let mut byzantine_planes = Vec::new();
        for plane in 0..4u64 {
            byzantine_planes.push(cluster.tap(BYZANTINE, plane).await);
        }
        cluster.await_ready(&honest).await;

        cluster.app(PRODUCER).permit_builds(1);
        let mut target = None;
        for _ in 0..80 {
            context.sleep(Duration::from_millis(5)).await;
            cluster.observe_finality(&honest).await;
            let Some(block) = trace.block_from(PRODUCER) else {
                continue;
            };
            let voters = trace.da_voters(block.header());
            if honest
                .iter()
                .all(|participant| voters.contains(participant))
            {
                target = Some(block);
                break;
            }
        }
        let target =
            target.expect("every honest engine DA-votes the target before view-one voting");
        let target_header = target.header();
        let target_ref = target_header.block_ref::<Sha256>();
        assert_eq!(target_header.chain().get(), PRODUCER as u32);
        assert_eq!(target_header.height().get(), 1);
        for &participant in &honest {
            assert_eq!(
                cluster.inspect(participant).await.unwrap().view(),
                CENSORSHIP_VIEW,
                "the well-disseminated block precedes every view-one vote"
            );
        }

        let primary_junk = Sha256::hash(&[b"primary junk"]);
        let secondary_junk = Sha256::hash(&[b"secondary junk"]);
        let primary = censorship_proposal(&fixture, Some(primary_junk));
        let secondary = censorship_proposal(&fixture, Some(secondary_junk));
        let primary_digest = primary.block().digest::<Sha256>();
        let secondary_digest = secondary.block().digest::<Sha256>();
        assert_ne!(primary_digest, secondary_digest, "the leader equivocates");
        for (proposal, junk) in [(&primary, primary_junk), (&secondary, secondary_junk)] {
            assert!(fixture.verifier.verify_leader_block(proposal, &Sequential));
            let chain = &proposal.block().proposals()[PRODUCER];
            assert_eq!(chain.anchor().height().get(), 0, "the proposal is stale");
            assert_eq!(chain.payloads(), &[junk], "the proposal carries junk");
            assert_ne!(
                junk,
                target_header.body_digest(),
                "the honest block is omitted"
            );
        }

        let identities = cluster.identities();
        let primary_voters = &honest[..4];
        send_consensus(
            &mut byzantine_planes[1].0,
            primary_voters
                .iter()
                .map(|participant| identities[*participant].clone())
                .collect(),
            fixture.config.epoch(),
            ConsensusMessage::Proposal {
                parent: None,
                block: Box::new(primary.clone()),
            },
        );

        let mut supporting = Vec::new();
        for _ in 0..80 {
            context.sleep(Duration::from_millis(5)).await;
            supporting = trace
                .votes_for(primary_digest)
                .into_iter()
                .filter(|(source, _)| primary_voters.contains(source))
                .collect();
            if supporting.len() == primary_voters.len() {
                break;
            }
        }
        assert_eq!(supporting.len(), fixture.codec().da_quorum());
        assert!(
            supporting
                .iter()
                .all(|(_, vote)| vote_counts_for(vote, &primary, target_header)),
            "every correct primary vote independently counts for the omitted block"
        );
        for &participant in &honest {
            let inspection = cluster.inspect(participant).await.unwrap();
            assert!(
                inspection.finality_floor() < CENSORSHIP_VIEW,
                "four votes do not cross the view-one finality floor"
            );
            assert!(
                inspection.chain_progress()[PRODUCER].finalized() < target_ref.height(),
                "four votes establish support but cannot finalize the omitted block"
            );
        }

        let equivocation_observer = primary_voters[0];
        send_consensus(
            &mut byzantine_planes[1].0,
            vec![identities[equivocation_observer].clone()],
            fixture.config.epoch(),
            ConsensusMessage::Proposal {
                parent: None,
                block: Box::new(secondary.clone()),
            },
        );
        let secondary_id = Artifact::LeaderBlock(secondary).id::<Sha256>();
        for _ in 0..50 {
            context.sleep(Duration::from_millis(5)).await;
            if cluster
                .inspect(equivocation_observer)
                .await
                .unwrap()
                .ready_artifacts()
                .contains(&secondary_id)
            {
                break;
            }
        }
        assert!(
            cluster
                .inspect(equivocation_observer)
                .await
                .unwrap()
                .ready_artifacts()
                .contains(&secondary_id),
            "an honest engine authenticates the leader's pre-finality equivocation"
        );

        let byzantine_vote = fixture.vote(BYZANTINE, &primary);
        assert!(fixture.verifier.verify_vote(&byzantine_vote));
        assert!(!vote_counts_for(&byzantine_vote, &primary, target_header));
        assert_eq!(supporting.len() + 1, fixture.codec().view_quorum());
        send_consensus(
            &mut byzantine_planes[1].0,
            honest
                .iter()
                .map(|participant| identities[*participant].clone())
                .collect(),
            fixture.config.epoch(),
            ConsensusMessage::Vote(byzantine_vote),
        );

        let mut deadline = None;
        for _ in 0..600 {
            context.sleep(Duration::from_millis(10)).await;
            cluster.observe_finality(&honest).await;
            let mut inspections = Vec::with_capacity(honest.len());
            for &participant in &honest {
                inspections.push(cluster.inspect(participant).await.unwrap());
            }
            if inspections.iter().all(|inspection| {
                inspection
                    .finality()
                    .iter()
                    .any(|fact| fact.round().view() == CENSORSHIP_DEADLINE_VIEW)
            }) {
                deadline = Some(inspections);
                break;
            }
        }
        let inspections = deadline.expect("every honest engine observes the next finalized leader");

        let next_proposal = trace
            .proposal_at(CENSORSHIP_DEADLINE_VIEW)
            .expect("the correct view-two leader proposes");
        assert!(
            proposal_extends(&next_proposal, target_header),
            "the independently reconstructed view-two proposal safely extends the target"
        );
        let deadline_digest = next_proposal.block().digest::<Sha256>();
        let deadline_votes = trace.votes_for(deadline_digest);
        assert_eq!(
            deadline_votes
                .iter()
                .filter(|(source, _)| honest.contains(source))
                .count(),
            fixture.codec().view_quorum(),
            "the exact next-view n-f pool is the paper deadline"
        );
        for inspection in &inspections {
            assert!(
                inspection.finality_floor() >= CENSORSHIP_VIEW,
                "the next-view L-QC crosses the censored view's finality floor"
            );
            assert!(
                inspection.chain_progress()[PRODUCER].finalized() >= target_ref.height(),
                "the next-view L-QC finalizes the well-disseminated block"
            );
        }
    });
}

#[test_group("slow")]
#[test_traced]
fn every_f1_byzantine_placement_selectively_discloses_and_equivocates() {
    for byzantine in 0..PARTICIPANTS as usize {
        let executor = deterministic::Runner::timed(Duration::from_secs(900));
        executor.start(move |context| async move {
            run_placement_case(&context, PARTICIPANTS, &[byzantine], 900 + byzantine as u64).await;
        });
    }
}

#[test_group("slow")]
#[test_traced]
fn faulty_twin_exit_after_equivocation_does_not_fail_campaign() {
    let executor = deterministic::Runner::timed(Duration::from_secs(900));
    executor.start(|context| async move {
        run_placement_case(&context, LARGE_PARTICIPANTS, &[0, 1], 931).await;
    });
}

macro_rules! f2_placement_shards {
    ($($name:ident => $shard:expr),+ $(,)?) => {
        $(
            #[test_group("slow")]
            #[test_traced]
            fn $name() {
                run_f2_placement_shard($shard);
            }
        )+
    };
}

f2_placement_shards! {
    every_f2_byzantine_placement_shard_00 => 0,
    every_f2_byzantine_placement_shard_01 => 1,
    every_f2_byzantine_placement_shard_02 => 2,
    every_f2_byzantine_placement_shard_03 => 3,
    every_f2_byzantine_placement_shard_04 => 4,
    every_f2_byzantine_placement_shard_05 => 5,
    every_f2_byzantine_placement_shard_06 => 6,
    every_f2_byzantine_placement_shard_07 => 7,
    every_f2_byzantine_placement_shard_08 => 8,
    every_f2_byzantine_placement_shard_09 => 9,
    every_f2_byzantine_placement_shard_10 => 10,
}

#[test_group("slow")]
#[test_traced]
fn scripted_delivery_and_peer_rotation_recover_to_fairness() {
    let executor = deterministic::Runner::timed(Duration::from_secs(900));
    executor.start(|context| async move {
        let scenario = placement_scenario(PARTICIPANTS as usize);
        let byzantine = PARTICIPANTS as usize - 1;
        let honest = (0..PARTICIPANTS as usize)
            .filter(|index| *index != byzantine)
            .collect::<Vec<_>>();
        let scripted_node = honest[0];
        let source_node = honest[1];
        let script = DeliveryScript::default();
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                n: PARTICIPANTS,
                seed: 980,
                extras: 0,
                leaders: Some(schedule_for(&scenario, PARTICIPANTS as usize)),
                quota: None,
                latency: None,
                jitter: None,
                production: None,
                view_retention: None,
            },
        )
        .await;
        let fixture = cluster.fixture();
        let source = cluster.identity(source_node);
        let byzantine_identity = cluster.identity(byzantine);
        let plan = DeliveryPlan {
            script: script.clone(),
            source: source.clone(),
            signer: Participant::from_usize(source_node),
            fair_view: FAIR_SUFFIX_VIEW,
            epoch: fixture.config.epoch(),
            codec: fixture.codec(),
            verifier: fixture.verifier,
        };
        let probe = RotationProbe::new(byzantine_identity);

        launch_scripted_honest(
            &context,
            &mut cluster,
            &honest,
            scripted_node,
            &plan,
            &probe,
        )
        .await;
        let (mut attacker, _receiver) = cluster.tap(byzantine, 1).await;
        cluster.await_ready(&honest).await;

        cluster.produce_once();
        cluster.wait_produced(&honest, 1, 600).await;
        cluster.wait_view(&honest, round_view(ROUNDS), 3600).await;
        for _ in 0..600 {
            if script.is_complete() {
                break;
            }
            context.sleep(Duration::from_millis(10)).await;
            cluster.observe_finality(&honest).await;
        }
        script.assert_complete(&source, Participant::from_usize(source_node));

        let scripted_identity = cluster.identity(scripted_node);
        rotate_byzantine_peer(
            &context,
            &mut cluster,
            &honest,
            &mut attacker,
            &scripted_identity,
            &probe,
        )
        .await;
        cluster.observe_finality(&honest).await;
        require_fair_suffix_progress(&mut cluster, &honest, 3).await;
    });
}

#[test_traced]
fn twin_halves_equivocate_without_extra_weight() {
    // A fully connected split: both halves see every honest peer in every view, so honest nodes
    // observe conflicting artifacts signed by one participant.
    let executor = deterministic::Runner::timed(Duration::from_secs(900));
    executor.start(|context| async move {
        let byzantine = PARTICIPANTS as usize - 1;
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                n: PARTICIPANTS,
                seed: 950,
                extras: 0,
                leaders: None,
                quota: None,
                latency: None,
                jitter: None,
                production: None,
                view_retention: None,
            },
        )
        .await;

        let honest: Vec<usize> = (0..PARTICIPANTS as usize)
            .filter(|index| *index != byzantine)
            .collect();
        for &index in &honest {
            cluster.start_one(index).await;
        }

        let mut primary = Vec::new();
        let mut secondary = Vec::new();
        for plane in 0..4u64 {
            let (sender, receiver) = cluster.tap(byzantine, plane).await;
            let (sender_primary, sender_secondary) = sender
                .split_with(|_, recipients: &Recipients<_>, _: &_| Some(recipients.clone()));
            let (receiver_primary, receiver_secondary) = receiver.split_with(
                context.child("equivocate_split").with_attribute("plane", plane),
                |_: &(ed25519::PublicKey, IoBuf)| SplitTarget::Both,
            );
            primary.push((sender_primary, receiver_primary));
            secondary.push((sender_secondary, receiver_secondary));
        }

        let (primary_slot, secondary_slot) = launch_halves(
            &mut cluster,
            byzantine,
            primary,
            secondary,
            ["equivocator_primary", "equivocator_secondary"],
        )
        .await;

        cluster.await_ready(&honest).await;
        cluster.produce();
        let mut producers = honest.clone();
        producers.extend([primary_slot, secondary_slot]);
        cluster.wait_produced(&producers, 1, 600).await;
        cluster.stop_producing();

        // Both halves produce for the same chain from the same opportunity, so their bodies
        // conflict at one height. Honest chains still make finality progress without
        // compromising agreement.
        let honest_chains = honest.iter().map(|index| *index as u32).collect::<Vec<_>>();
        cluster
            .wait_finalized(&honest, &honest_chains, 1, 3600)
            .await;
        cluster.observe_finality(&honest).await;

        // Both halves must have produced once, and their salts make the bodies conflict at one
        // chain height under one participant's signature.
        let primary_built = cluster.app(primary_slot).log().lock().built;
        let secondary_built = cluster.app(secondary_slot).log().lock().built;
        assert!(
            primary_built > 0 && secondary_built > 0,
            "expected both halves to produce conflicting blocks (primary={primary_built}, secondary={secondary_built})"
        );
    });
}
