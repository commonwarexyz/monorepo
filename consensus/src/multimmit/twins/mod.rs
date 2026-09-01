//! Twins campaigns for Multimmit.
//!
//! Each Byzantine participant runs as two independently scheduled halves that share its key
//! material and threshold shares but keep separate machines, storage, applications, actor trees,
//! and production policy. The simulated network owns the participant's single endpoint per plane
//! and splits it: a router decides which half receives each inbound message, and a forwarder decides
//! which honest peers see each half's outbound message. Honest nodes therefore attribute both
//! halves to one participant with one committee weight, and no production code is weakened to make
//! that possible.
//!
//! The placement gate covers every Byzantine identity at `n=6, f=1` and every nonempty placement
//! within the fault bound at `n=11, f=2`. Every case uses real twin engines to produce conflicting
//! authenticated headers and exercise selective attack-prefix disclosure until honest observers
//! quarantine the shared identity or the execution enters a fair suffix. A separate delivery pump
//! holds, reorders, and duplicates authenticated artifacts before entering a fair suffix. The pump
//! owns all stateful awaits, so cancellation of a consumer receive cannot lose a held frame or skip
//! a delivery phase.

pub(crate) mod randomized;
#[cfg(test)]
mod scripted;

use crate::{
    Epochable as _, Heightable as _, Viewable as _,
    multimmit::{
        Planes,
        config::LeaderSchedule,
        mocks::cluster::{Cluster, ClusterOptions, LaunchSpec},
        scheme::bls12381_threshold::Scheme,
        types::{Artifact, ArtifactId, ArtifactKind, ChainId, CodecConfig, TransactionBlockHeader},
        wire::{CertificateMessage, ConsensusMessage, DataMessage, Envelope, EnvelopeConfig},
    },
    twins::{RoundScenario, Scenario},
    types::{Epoch, Participant, TermLength, View},
};
use commonware_codec::{Copying, Decode as _};
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::MinPk, ed25519, sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::{
    Recipients,
    simulated::{SplitOrigin, SplitTarget},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Runner as _, Spawner as _, Supervisor as _, deterministic, iobuf::IoBuf,
};
use commonware_utils::{Faults as _, N5f1, channel::mpsc, sync::Mutex};
use std::{collections::BTreeMap, fmt::Debug, future::Future, sync::Arc, time::Duration};
#[cfg(test)]
use {crate::types::Height, commonware_cryptography::Hasher as _};

/// Committee size for Twins campaigns.
const PARTICIPANTS: u32 = 6;

/// Committee size for the complete two-Byzantine campaign.
const LARGE_PARTICIPANTS: u32 = 11;

/// Every scripted round is one view, so a round index is a view index.
const TERM: TermLength = TermLength::ONE;

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

/// One network frame as a plane receiver yields it.
type Frame<E> = Result<commonware_p2p::Message<ed25519::PublicKey>, E>;

/// Carries the frames a delivery pump releases, each with its tag, to its receiver.
type PumpSender<E, T> = mpsc::UnboundedSender<(Frame<E>, T)>;

/// Decides which network frames a [`PumpedReceiver`] releases, in what order, and when.
trait PumpStrategy<E>: Send + 'static {
    /// What the pump records about each frame it releases.
    type Tag: Send + 'static;
    /// The receiving side's record of the frames the engine takes.
    type Observer: Send + 'static;

    /// Returns the receiving side's record.
    fn observer(&self) -> Self::Observer;

    /// Receives from `inner` and releases frames to `output` until either side closes.
    fn pump<R>(
        self,
        context: deterministic::Context,
        inner: R,
        output: PumpSender<E, Self::Tag>,
    ) -> impl Future<Output = ()> + Send
    where
        R: commonware_p2p::Receiver<Error = E, PublicKey = ed25519::PublicKey>;

    /// Records that the engine took `frame`, released with `tag`.
    fn taken(observer: &Self::Observer, frame: &Frame<E>, tag: Self::Tag);
}

/// A plane receiver backed by a dedicated pump task that owns every stateful network await.
///
/// A cancelled receive therefore cannot lose a held frame or skip a delivery phase.
struct PumpedReceiver<E, S: PumpStrategy<E>> {
    frames: mpsc::UnboundedReceiver<(Frame<E>, S::Tag)>,
    observer: S::Observer,
}

impl<E, S> PumpedReceiver<E, S>
where
    E: Debug + std::error::Error + Send + Sync + 'static,
    S: PumpStrategy<E>,
{
    /// Spawns `strategy`'s pump over `inner` on `context`.
    fn spawn<R>(context: deterministic::Context, inner: R, strategy: S) -> Self
    where
        R: commonware_p2p::Receiver<Error = E, PublicKey = ed25519::PublicKey>,
    {
        let (output, frames) = mpsc::unbounded_channel();
        let observer = strategy.observer();
        context.spawn(move |context| strategy.pump(context, inner, output));
        Self { frames, observer }
    }
}

impl<E, S: PumpStrategy<E>> Debug for PumpedReceiver<E, S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PumpedReceiver")
            .finish_non_exhaustive()
    }
}

impl<E, S> commonware_p2p::Receiver for PumpedReceiver<E, S>
where
    E: Debug + std::error::Error + Send + Sync + 'static,
    S: PumpStrategy<E>,
{
    type Error = E;
    type PublicKey = ed25519::PublicKey;

    async fn recv(&mut self) -> Frame<E> {
        let (frame, tag) = self
            .frames
            .recv()
            .await
            .expect("delivery pump remains live while its receiver is live");
        S::taken(&self.observer, &frame, tag);
        frame
    }
}

fn identify_consensus(
    source: ed25519::PublicKey,
    bytes: &[u8],
    epoch: Epoch,
    codec: CodecConfig,
    verifier: &Scheme<ed25519::PublicKey, MinPk>,
) -> Option<DeliveryArtifact> {
    let bounds = codec.encoded_bounds::<MinPk, Sha256Digest>()?;
    let payload = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
        Copying(bytes),
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
    let bounds = codec.encoded_bounds::<MinPk, Sha256Digest>()?;
    let payload = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
        Copying(bytes),
        &EnvelopeConfig {
            max_frame_bytes: bounds.max_data_frame_bytes(),
            epoch,
            payload: codec,
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
    let bounds = codec.encoded_bounds::<MinPk, Sha256Digest>()?;
    let payload = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
        Copying(bytes),
        &EnvelopeConfig {
            max_frame_bytes: bounds.max_data_frame_bytes(),
            epoch,
            payload: codec,
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

    /// Returns how many of `byzantine`'s broadcasts reached a strict, nonempty subset of
    /// `identities`.
    ///
    /// # Panics
    ///
    /// Panics unless every recorded transmission is signed by and sent from `byzantine`, and every
    /// broadcast reached exactly the recipients `scenario` assigns to its half.
    fn count_selective_broadcasts(
        &self,
        byzantine: usize,
        scenario: &Scenario,
        identities: &[ed25519::PublicKey],
    ) -> usize {
        self.traffic
            .lock()
            .iter()
            .filter(|transmission| {
                assert_eq!(
                    transmission.artifact.signer,
                    Participant::from_usize(byzantine)
                );
                assert_eq!(transmission.artifact.source, identities[byzantine]);
                let (primary, secondary) =
                    scenario.partitions(transmission.artifact.view, TERM, identities);
                let expected = match transmission.origin {
                    SplitOrigin::Primary => primary,
                    SplitOrigin::Secondary => secondary,
                };
                if let Some(actual) = &transmission.broadcast_recipients {
                    assert_eq!(
                        actual, &expected,
                        "actual recipients honor the sampled twin mask"
                    );
                }
                transmission
                    .broadcast_recipients
                    .as_ref()
                    .is_some_and(|recipients| {
                        !recipients.is_empty() && recipients.len() < identities.len()
                    })
            })
            .count()
    }
}

/// Returns the view a plane message belongs to, if the plane is view-scoped.
///
/// Data-plane traffic is chain-scoped, so it carries no view and is never split by round.
fn message_view(plane: u64, bytes: &[u8], epoch: Epoch, codec: CodecConfig) -> Option<View> {
    let bounds = codec.encoded_bounds::<MinPk, Sha256Digest>()?;
    match plane {
        1 => {
            let envelope = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                Copying(bytes),
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
                Copying(bytes),
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
            // Reject malformed data-plane bytes the same way the ingress actor would, without
            // attributing them to a view.
            let _ = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                Copying(bytes),
                &EnvelopeConfig {
                    max_frame_bytes: bounds.max_data_frame_bytes(),
                    epoch,
                    payload: codec,
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
    for (slot, planes, label) in [
        (primary_slot, primary, labels[0]),
        (secondary_slot, secondary, labels[1]),
    ] {
        let [data, consensus, certificates, resolver]: [(S, R); 4] = planes
            .try_into()
            .unwrap_or_else(|_| panic!("exactly four twin planes"));
        cluster
            .launch_over(
                LaunchSpec::new(slot).signer(byzantine).label(label),
                Planes {
                    data,
                    consensus,
                    certificates,
                    resolver,
                },
            )
            .await;
    }
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

fn twin_labels(index: usize) -> [&'static str; 2] {
    match index {
        0 => ["twin_a_primary", "twin_a_secondary"],
        1 => ["twin_b_primary", "twin_b_secondary"],
        _ => panic!("the bounded placement matrix has at most two Byzantine identities"),
    }
}
