//! Bounded decode-and-identify jobs for one network plane.

use super::lanes::{Group, LaneId};
use crate::multimmit::{
    actors::util::offload,
    types::{Artifact, CertificateId, CodecConfig},
    wire::{CertificateMessage, ConsensusMessage, DataMessage, Envelope, EnvelopeConfig, Plane},
};
use commonware_codec::{Decode as _, EncodeSize as _, Write as _};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use commonware_p2p::Receiver;
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, IoBuf};
use commonware_utils::futures::Pool;
use futures::FutureExt as _;
use std::time::SystemTime;
use tracing::Span;

/// Why one received frame was dropped before reaching a lane.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum InvalidIngress {
    /// The frame failed bounded decoding for its plane.
    Decode,
    /// A proposal attached a parent certificate other than the one its block references.
    ProposalParent,
}

/// The outcome of decoding and identifying one received frame.
#[allow(
    clippy::large_enum_variant,
    reason = "most frames are ready; boxing the group would allocate once per frame"
)]
pub(super) enum IngressOutcome<P, V: Variant, D: Digest> {
    /// A decoded and identified group, ready for its lane.
    Ready {
        peer: P,
        lane: LaneId,
        group: Group<V, D>,
    },
    /// A frame dropped before reaching a lane.
    Invalid { reason: InvalidIngress },
    /// The decode worker panicked.
    Panicked,
}

/// Decode-and-identify jobs of one plane, completed in any order.
pub(super) type IngressResults<P, V, D> = Pool<'static, IngressOutcome<P, V, D>>;

/// Owns bounded decode-and-identify jobs across cancellation of the network select.
pub(super) struct IngressReceiver<E, R: Receiver, H: Hasher, V: Variant, S> {
    context: E,
    pub(super) receiver: R,
    plane: Plane,
    config: EnvelopeConfig<CodecConfig>,
    strategy: S,
    pub(super) jobs: IngressResults<R::PublicKey, V, H::Digest>,
    capacity: usize,
    pub(super) closed: bool,
}

impl<E: Clock, R: Receiver, H: Hasher, V: Variant, S: Strategy> IngressReceiver<E, R, H, V, S> {
    /// Creates a receiver that runs at most `capacity` decodes of `plane` frames at once.
    pub(super) fn new(
        context: E,
        receiver: R,
        plane: Plane,
        config: EnvelopeConfig<CodecConfig>,
        strategy: S,
        capacity: usize,
    ) -> Self {
        Self {
            context,
            receiver,
            plane,
            config,
            strategy,
            jobs: Pool::default(),
            capacity,
            closed: false,
        }
    }

    /// Returns the next completed decode, receiving more frames while capacity allows.
    ///
    /// Returns `None` once the network receiver is closed and every owned job has completed.
    pub(super) async fn recv(&mut self) -> Option<IngressOutcome<R::PublicKey, V, H::Digest>> {
        loop {
            if self.closed {
                if self.jobs.is_empty() {
                    return None;
                }
                return Some(self.jobs.next_completed().await);
            }
            if self.jobs.len() >= self.capacity {
                return Some(self.jobs.next_completed().await);
            }
            select! {
                prepared = self.jobs.next_completed() => return Some(prepared),
                received = self.receiver.recv() => {
                    let Ok((peer, bytes)) = received else {
                        self.closed = true;
                        continue;
                    };
                    let received_at = self.context.current();
                    let config = self.config.clone();
                    let plane = self.plane;
                    let strategy = self.strategy.clone();
                    let weight = bytes.len();
                    self.jobs.push(async move {
                        let (_, outcome) = offload(strategy, weight, Span::none(), move |_| {
                            prepare::<H, V, _>(plane, peer, bytes, &config, received_at)
                        })
                        .await;
                        outcome.unwrap_or(IngressOutcome::Panicked)
                    });
                },
            }
        }
    }

    /// Returns a decode that has already completed, without receiving more frames.
    pub(super) fn try_completed(&mut self) -> Option<IngressOutcome<R::PublicKey, V, H::Digest>> {
        self.jobs.next_completed().now_or_never()
    }
}

/// Checks contextual frame constraints and identifies an entire atomic ingress group.
fn prepare<H: Hasher, V: Variant, P>(
    plane: Plane,
    peer: P,
    bytes: IoBuf,
    config: &EnvelopeConfig<CodecConfig>,
    received_at: SystemTime,
) -> IngressOutcome<P, V, H::Digest> {
    match plane {
        Plane::Consensus => prepare_consensus::<H, V, P>(peer, bytes, config, received_at),
        Plane::Certificate => prepare_certificate::<H, V, P>(peer, bytes, config, received_at),
        Plane::Data => prepare_data::<H, V, P>(peer, bytes, config, received_at),
    }
}

/// Decodes one consensus-plane frame, checking that an attached parent is the referenced one.
fn prepare_consensus<H: Hasher, V: Variant, P>(
    peer: P,
    bytes: IoBuf,
    config: &EnvelopeConfig<CodecConfig>,
    received_at: SystemTime,
) -> IngressOutcome<P, V, H::Digest> {
    let Ok(envelope) = Envelope::<ConsensusMessage<V, H::Digest>>::decode_cfg(bytes, config) else {
        return IngressOutcome::Invalid {
            reason: InvalidIngress::Decode,
        };
    };
    let mut scratch = Vec::new();
    let artifact = match envelope.into_payload() {
        ConsensusMessage::Proposal {
            parent: Some(parent),
            block,
        } => {
            let certificate = *parent;
            scratch.reserve(certificate.encode_size());
            certificate.write(&mut scratch);
            if CertificateId::from_canonical::<H>(&scratch) != block.block().parent() {
                return IngressOutcome::Invalid {
                    reason: InvalidIngress::ProposalParent,
                };
            }
            let parent = Artifact::Vqc(certificate).identify_from_canonical_encoding::<H>(&scratch);
            let block = Artifact::LeaderBlock(*block).identify::<H>(&mut scratch);
            return IngressOutcome::Ready {
                peer,
                lane: LaneId::Consensus,
                group: Group::pair([parent, block], received_at),
            };
        }
        ConsensusMessage::Proposal {
            parent: None,
            block,
        } => Artifact::LeaderBlock(*block),
        ConsensusMessage::Vote(vote) => Artifact::Vote(vote),
        ConsensusMessage::NoVote(vote) => Artifact::NoVote(vote),
        ConsensusMessage::Nullify(nullify) => Artifact::Nullify(nullify),
    };
    IngressOutcome::Ready {
        peer,
        lane: LaneId::Consensus,
        group: Group::one(artifact.identify::<H>(&mut scratch), received_at),
    }
}

/// Decodes one certificate-plane frame.
fn prepare_certificate<H: Hasher, V: Variant, P>(
    peer: P,
    bytes: IoBuf,
    config: &EnvelopeConfig<CodecConfig>,
    received_at: SystemTime,
) -> IngressOutcome<P, V, H::Digest> {
    let Ok(envelope) = Envelope::<CertificateMessage<V, H::Digest>>::decode_cfg(bytes, config)
    else {
        return IngressOutcome::Invalid {
            reason: InvalidIngress::Decode,
        };
    };
    let artifact = envelope.into_payload().into_artifact();
    IngressOutcome::Ready {
        peer,
        lane: LaneId::Certificate,
        group: Group::one(artifact.identify::<H>(&mut Vec::new()), received_at),
    }
}

/// Decodes one data-plane frame into the lane of its producer chain.
fn prepare_data<H: Hasher, V: Variant, P>(
    peer: P,
    bytes: IoBuf,
    config: &EnvelopeConfig<CodecConfig>,
    received_at: SystemTime,
) -> IngressOutcome<P, V, H::Digest> {
    let Ok(envelope) = Envelope::<DataMessage<V, H::Digest>>::decode_cfg(bytes, config) else {
        return IngressOutcome::Invalid {
            reason: InvalidIngress::Decode,
        };
    };
    let message = envelope.into_payload();
    // Decoding rejected chains outside the epoch codec profile.
    let lane = LaneId::Data(message.chain().get() as usize);
    IngressOutcome::Ready {
        peer,
        lane,
        group: Group::one(
            message.into_artifact().identify::<H>(&mut Vec::new()),
            received_at,
        ),
    }
}
