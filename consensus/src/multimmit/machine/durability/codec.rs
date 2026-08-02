//! Versioned encoding for Multimmit's durable snapshot and journal envelopes.

use super::{
    BarrierAck, BarrierId, BlockPublication, COMPONENT_EVENT_VERSION, CertificatePublication,
    Change, ComponentPayload, Cursor, DURABILITY_SCHEMA_VERSION, DaVoteRequest, DomainEvent,
    DurableComponent, DurableEffect, DurableState, EffectId, ExitPublication, JournalPrefix,
    OBLIGATIONS_VERSION, ORDERING_SNAPSHOT_VERSION, ObligationId, ObligationsSnapshot,
    OwnMessagePublication, PUBLICATION_OUTBOX_VERSION, ProposalPublication, ProposalRequest,
    PublicationDischarge, PublicationKind, PublicationObligation, PublicationOutbox, Role,
    SIGNING_RESERVATIONS_VERSION, SendRequest, SignRequest, SigningReservations, Snapshot,
    SnapshotEnvelope, VIEW_SNAPSHOT_VERSION, ViewNullification, ViewSlotSnapshot, ViewSnapshot,
    ViewStance, ViewTransition, VotePublication, VoteRequest,
};
use crate::{
    multimmit::{
        config::CodecConfig,
        machine::{Artifact, ArtifactBatch, ArtifactId, Profile},
        types::{
            DaCertificate, DaVote, LeaderBlock, Lqc, NoVote, Nullification, Nullify,
            ProposalParent, SignedLeaderBlock, SignedTransactionBlock, TransactionBlockHeader,
            Vote, VoteBody, Vqc,
        },
    },
    types::{Epoch, Height, Participant, Round, View},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Decode, Encode, EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc};

/// Bounds used to decode one acknowledged machine snapshot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SnapshotCodecConfig {
    event: DomainEventCodecConfig,
    chains: usize,
    max_artifacts: usize,
    max_view_slots: usize,
    max_outbox: usize,
    max_component_bytes: usize,
    max_pending_barriers: usize,
}

impl SnapshotCodecConfig {
    /// Derives snapshot decoding bounds from the immutable machine profile.
    pub fn from_profile<H: Hasher, V: Variant>(profile: &Profile<H, V>) -> Self {
        let resources = profile.resources();
        Self {
            event: DomainEventCodecConfig::from_profile(profile),
            chains: profile.protocol().codec_config().chains(),
            max_artifacts: resources.max_cached_artifacts(),
            max_view_slots: usize::try_from(profile.view_retention().get() + 1)
                .expect("validated view retention fits usize"),
            max_outbox: resources.max_outbox_effects(),
            max_component_bytes: resources
                .max_artifact_bytes()
                .saturating_mul(resources.max_cached_artifacts()),
            max_pending_barriers: resources.max_outbox_effects(),
        }
    }

    /// Returns a conservative allocation ceiling for one metadata-wrapped snapshot.
    ///
    /// Artifact-bearing effects dominate the encoding. The bound permits every durable effect to
    /// carry a full artifact batch, every artifact-indexed projection to reach its configured
    /// limit, all four component payloads, and fixed bookkeeping for each bounded entry.
    pub(crate) const fn max_checkpoint_blob_size(self) -> NonZeroUsize {
        let artifact_slots = self
            .max_artifacts
            .saturating_mul(self.max_outbox.saturating_add(8))
            .saturating_add(2);
        let artifact_bytes = self.event.max_artifact_bytes.saturating_mul(artifact_slots);
        let component_bytes = self.max_component_bytes.saturating_mul(4);
        let bounded_entries = artifact_slots
            .saturating_add(self.max_outbox)
            .saturating_add(self.max_view_slots)
            .saturating_add(self.max_pending_barriers)
            .saturating_add(self.chains);
        let bookkeeping = bounded_entries.saturating_mul(256);
        NonZeroUsize::new(
            artifact_bytes
                .saturating_add(component_bytes)
                .saturating_add(bookkeeping)
                .saturating_add(4096),
        )
        .expect("checkpoint bound includes fixed overhead")
    }
}

/// Bounds used to decode one self-contained safety-journal event.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DomainEventCodecConfig {
    protocol: CodecConfig,
    max_artifact_bytes: usize,
    max_artifacts: usize,
    max_retired_effects: usize,
}

impl DomainEventCodecConfig {
    /// Derives journal decoding bounds from the immutable machine profile.
    pub const fn from_profile<H: Hasher, V: Variant>(profile: &Profile<H, V>) -> Self {
        let resources = profile.resources();
        Self {
            protocol: profile.protocol().codec_config(),
            max_artifact_bytes: resources.max_artifact_bytes(),
            // A durable batch is either one item per producer chain or the two timeout
            // messages. The cache bound describes total live residency, not one event.
            max_artifacts: if profile.protocol().codec_config().chains() < 2 {
                2
            } else {
                profile.protocol().codec_config().chains()
            },
            max_retired_effects: resources.max_outbox_effects(),
        }
    }

    /// Returns a conservative payload ceiling for one change accepted by this codec.
    fn max_change_size(self) -> usize {
        let artifact_bytes = self
            .max_artifact_bytes
            .saturating_add(16)
            .saturating_mul(self.max_artifacts);
        let retirement_bytes = u64::MAX
            .encode_size()
            .saturating_mul(self.max_retired_effects)
            .saturating_mul(2);
        artifact_bytes
            .saturating_add(retirement_bytes)
            .saturating_add(256)
    }

    /// Returns a conservative encoded ceiling for one event accepted by this codec.
    pub(crate) fn max_encoded_size(self) -> usize {
        self.max_change_size().saturating_add(64)
    }

    #[cfg(test)]
    pub(crate) const fn new(
        protocol: CodecConfig,
        max_artifact_bytes: usize,
        max_artifacts: usize,
        max_retired_effects: usize,
    ) -> Self {
        Self {
            protocol,
            max_artifact_bytes,
            max_artifacts,
            max_retired_effects,
        }
    }
}

impl<V: Variant, D: Digest> Write for DomainEvent<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        DURABILITY_SCHEMA_VERSION.write(buf);
        self.epoch.write(buf);
        self.cursor.0.write(buf);
        durable_component_tag(self.component()).write(buf);
        COMPONENT_EVENT_VERSION.write(buf);
        self.change.encode_size().write(buf);
        self.change.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for DomainEvent<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        require_version(u8::read(buf)?, DURABILITY_SCHEMA_VERSION)?;
        let epoch = Epoch::read(buf)?;
        let cursor = Cursor(u64::read(buf)?);
        let component = read_durable_component(buf)?;
        require_version(u8::read(buf)?, COMPONENT_EVENT_VERSION)?;
        let max_payload = config.max_change_size();
        let payload_len = usize::read_cfg(buf, &RangeCfg::from(0..=max_payload))?;
        if buf.remaining() < payload_len {
            return Err(Error::EndOfBuffer);
        }
        let mut payload = buf.copy_to_bytes(payload_len);
        let change = Change::read_cfg(&mut payload, config)?;
        if payload.has_remaining() {
            return Err(Error::ExtraData(payload.remaining()));
        }
        if change.component() != component {
            return Err(Error::Invalid(
                "consensus::multimmit::machine::DomainEvent",
                "component owner does not match payload",
            ));
        }
        Ok(Self {
            epoch,
            cursor,
            change,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for DomainEvent<V, D> {
    fn encode_size(&self) -> usize {
        DURABILITY_SCHEMA_VERSION.encode_size()
            + self.epoch.encode_size()
            + self.cursor.0.encode_size()
            + 1
            + COMPONENT_EVENT_VERSION.encode_size()
            + self.change.encode_size().encode_size()
            + self.change.encode_size()
    }
}

impl<V: Variant, D: Digest> Write for Change<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::GenerationAdvanced(generation) => {
                0u8.write(buf);
                generation.write(buf);
            }
            Self::OutboxQueued { id, effect } => {
                3u8.write(buf);
                id.0.write(buf);
                effect.write(buf);
            }
            Self::SignedArtifact {
                sign,
                publication,
                artifact,
            } => {
                4u8.write(buf);
                sign.0.write(buf);
                publication.0.write(buf);
                artifact.write(buf);
            }
            Self::SignedArtifactBatch {
                sign,
                publication,
                artifacts,
            } => {
                5u8.write(buf);
                sign.0.write(buf);
                publication.0.write(buf);
                write_artifacts(artifacts, buf);
            }
            Self::ArtifactCreated {
                publication,
                artifact,
            } => {
                6u8.write(buf);
                publication.0.write(buf);
                artifact.write(buf);
            }
            Self::ViewCertificateCreated { artifact } => {
                7u8.write(buf);
                artifact.write(buf);
            }
            Self::ArtifactForwarded {
                publication,
                retired,
                artifact,
            } => {
                8u8.write(buf);
                publication.0.write(buf);
                retired.write(buf);
                artifact.write(buf);
            }
            Self::ViewAdvanced { proof, retired } => {
                9u8.write(buf);
                proof.get().write(buf);
                retired.write(buf);
            }
            Self::FinalityFloorAdvanced {
                proof,
                retired,
                publication_retired,
            } => {
                11u8.write(buf);
                proof.write(buf);
                retired.write(buf);
                publication_retired.write(buf);
            }
            Self::DaCertificateAdvanced {
                publication,
                retired,
                artifact,
            } => {
                12u8.write(buf);
                publication.write(buf);
                retired.write(buf);
                artifact.write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> Read for Change<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::GenerationAdvanced(u64::read(buf)?)),
            3 => Ok(Self::OutboxQueued {
                id: EffectId::read(buf)?,
                effect: Box::new(DurableEffect::read_cfg(buf, config)?),
            }),
            4 => Ok(Self::SignedArtifact {
                sign: EffectId::read(buf)?,
                publication: EffectId::read(buf)?,
                artifact: Arc::new(Artifact::read_cfg(buf, config)?),
            }),
            5 => Ok(Self::SignedArtifactBatch {
                sign: EffectId::read(buf)?,
                publication: EffectId::read(buf)?,
                artifacts: read_artifacts(buf, config.max_artifacts, config)?,
            }),
            6 => Ok(Self::ArtifactCreated {
                publication: EffectId::read(buf)?,
                artifact: Arc::new(Artifact::read_cfg(buf, config)?),
            }),
            7 => Ok(Self::ViewCertificateCreated {
                artifact: Arc::new(Artifact::read_cfg(buf, config)?),
            }),
            8 => Ok(Self::ArtifactForwarded {
                publication: EffectId::read(buf)?,
                retired: Vec::read_cfg(buf, &(RangeCfg::from(0..=config.max_retired_effects), ()))?,
                artifact: Arc::new(Artifact::read_cfg(buf, config)?),
            }),
            9 => Ok(Self::ViewAdvanced {
                proof: ArtifactId::new(D::read(buf)?),
                retired: Vec::read_cfg(buf, &(RangeCfg::from(0..=config.max_retired_effects), ()))?,
            }),
            11 => Ok(Self::FinalityFloorAdvanced {
                proof: Arc::new(Artifact::read_cfg(buf, config)?),
                retired: Vec::read_cfg(buf, &(RangeCfg::from(0..=config.max_retired_effects), ()))?,
                publication_retired: Vec::read_cfg(
                    buf,
                    &(RangeCfg::from(0..=config.max_retired_effects), ()),
                )?,
            }),
            12 => {
                let publication = Option::read(buf)?;
                Ok(Self::DaCertificateAdvanced {
                    publication,
                    retired: Vec::read_cfg(
                        buf,
                        &(RangeCfg::from(0..=config.max_retired_effects), ()),
                    )?,
                    artifact: Arc::new(Artifact::read_cfg(buf, config)?),
                })
            }
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for Change<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::GenerationAdvanced(generation) => generation.encode_size(),
            Self::OutboxQueued { id, effect } => id.0.encode_size() + effect.encode_size(),
            Self::SignedArtifact {
                sign,
                publication,
                artifact,
            } => sign.0.encode_size() + publication.0.encode_size() + artifact.encode_size(),
            Self::SignedArtifactBatch {
                sign,
                publication,
                artifacts,
            } => sign.0.encode_size() + publication.0.encode_size() + artifacts_size(artifacts),
            Self::ArtifactCreated {
                publication,
                artifact,
            } => publication.0.encode_size() + artifact.encode_size(),
            Self::ArtifactForwarded {
                publication,
                retired,
                artifact,
            } => publication.0.encode_size() + retired.encode_size() + artifact.encode_size(),
            Self::ViewCertificateCreated { artifact } => artifact.encode_size(),
            Self::ViewAdvanced { proof, retired } => {
                proof.get().encode_size() + retired.encode_size()
            }
            Self::FinalityFloorAdvanced {
                proof,
                retired,
                publication_retired,
            } => proof.encode_size() + retired.encode_size() + publication_retired.encode_size(),
            Self::DaCertificateAdvanced {
                publication,
                retired,
                artifact,
            } => publication.encode_size() + retired.encode_size() + artifact.encode_size(),
        }
    }
}

impl Write for PublicationKind {
    fn write(&self, buf: &mut impl BufMut) {
        let tag = match self {
            Self::Broadcast => 0u8,
            Self::BroadcastBatch => 1,
            Self::Propose => 2,
            Self::Send => 3,
            Self::SendBatch => 4,
        };
        tag.write(buf);
    }
}

impl Read for PublicationKind {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Broadcast),
            1 => Ok(Self::BroadcastBatch),
            2 => Ok(Self::Propose),
            3 => Ok(Self::Send),
            4 => Ok(Self::SendBatch),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for PublicationKind {
    fn encode_size(&self) -> usize {
        1
    }
}

fn write_obligation_id<F>(id: &ObligationId<F>, buf: &mut impl BufMut) {
    id.effect.write(buf);
    id.item.write(buf);
}

fn read_obligation_id<F>(buf: &mut impl Buf) -> Result<ObligationId<F>, Error> {
    Ok(ObligationId::new(EffectId::read(buf)?, u32::read(buf)?))
}

impl Write for PublicationDischarge {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::BlockCertifiedAtLeast { id, chain, height } => {
                0u8.write(buf);
                write_obligation_id(id, buf);
                chain.get().write(buf);
                height.write(buf);
            }
            Self::VoteCertifiedAtLeast { id, chain, height } => {
                1u8.write(buf);
                write_obligation_id(id, buf);
                chain.get().write(buf);
                height.write(buf);
            }
            Self::CertificateSupersededAbove { id, chain, height } => {
                2u8.write(buf);
                write_obligation_id(id, buf);
                chain.get().write(buf);
                height.write(buf);
            }
            Self::ExitReplacedAfter { id, view } => {
                3u8.write(buf);
                write_obligation_id(id, buf);
                view.write(buf);
            }
            Self::ViewRetired { id, view } => {
                4u8.write(buf);
                write_obligation_id(id, buf);
                view.write(buf);
            }
        }
    }
}

impl Read for PublicationDischarge {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::BlockCertifiedAtLeast {
                id: read_obligation_id::<BlockPublication>(buf)?,
                chain: crate::multimmit::types::ChainId::new(u32::read(buf)?),
                height: Height::read(buf)?,
            }),
            1 => Ok(Self::VoteCertifiedAtLeast {
                id: read_obligation_id::<VotePublication>(buf)?,
                chain: crate::multimmit::types::ChainId::new(u32::read(buf)?),
                height: Height::read(buf)?,
            }),
            2 => Ok(Self::CertificateSupersededAbove {
                id: read_obligation_id::<CertificatePublication>(buf)?,
                chain: crate::multimmit::types::ChainId::new(u32::read(buf)?),
                height: Height::read(buf)?,
            }),
            3 => Ok(Self::ExitReplacedAfter {
                id: read_obligation_id::<ExitPublication>(buf)?,
                view: View::read(buf)?,
            }),
            4 => Ok(Self::ViewRetired {
                id: read_obligation_id::<OwnMessagePublication>(buf)?,
                view: View::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for PublicationDischarge {
    fn encode_size(&self) -> usize {
        let identity = 8 + 4;
        1 + identity
            + match self {
                Self::BlockCertifiedAtLeast { chain, height, .. }
                | Self::VoteCertifiedAtLeast { chain, height, .. }
                | Self::CertificateSupersededAbove { chain, height, .. } => {
                    chain.get().encode_size() + height.encode_size()
                }
                Self::ExitReplacedAfter { view, .. } | Self::ViewRetired { view, .. } => {
                    view.encode_size()
                }
            }
    }
}

impl Write for PublicationObligation {
    fn write(&self, buf: &mut impl BufMut) {
        self.effect.write(buf);
        self.kind.write(buf);
        self.discharges.len().write(buf);
        for discharge in self.discharges.iter() {
            discharge.write(buf);
        }
    }
}

impl Read for PublicationObligation {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_items: &Self::Cfg) -> Result<Self, Error> {
        let effect = EffectId::read(buf)?;
        let kind = PublicationKind::read(buf)?;
        let discharges = Vec::read_cfg(buf, &(RangeCfg::from(1..=*max_items), ()))?;
        Ok(Self::new(effect, kind, discharges))
    }
}

impl EncodeSize for PublicationObligation {
    fn encode_size(&self) -> usize {
        self.effect.encode_size()
            + self.kind.encode_size()
            + self.discharges.len().encode_size()
            + self
                .discharges
                .iter()
                .map(EncodeSize::encode_size)
                .sum::<usize>()
    }
}

impl Write for ObligationsSnapshot {
    fn write(&self, buf: &mut impl BufMut) {
        self.obligations.write(buf);
    }
}

impl Read for ObligationsSnapshot {
    type Cfg = (usize, usize);

    fn read_cfg(
        buf: &mut impl Buf,
        (max_obligations, max_items): &Self::Cfg,
    ) -> Result<Self, Error> {
        let obligations = read_unique_map(buf, *max_obligations, |buf| {
            Ok((
                EffectId::read(buf)?,
                PublicationObligation::read_cfg(buf, max_items)?,
            ))
        })?;
        Ok(Self { obligations })
    }
}

impl EncodeSize for ObligationsSnapshot {
    fn encode_size(&self) -> usize {
        self.obligations.encode_size()
    }
}

impl<V: Variant, D: Digest> Write for DurableEffect<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Sign(request) => {
                0u8.write(buf);
                request.write(buf);
            }
            Self::SignBatch(requests) => {
                1u8.write(buf);
                requests.len().write(buf);
                for request in requests.iter() {
                    request.write(buf);
                }
            }
            Self::Broadcast(artifact) => {
                2u8.write(buf);
                artifact.write(buf);
            }
            Self::BroadcastBatch(artifacts) => {
                3u8.write(buf);
                write_artifacts(artifacts, buf);
            }
            Self::Propose(publication) => {
                4u8.write(buf);
                publication.block.write(buf);
                publication.parent.write(buf);
                publication.attach_parent.write(buf);
            }
            Self::Send(request) => {
                5u8.write(buf);
                request.recipient.write(buf);
                request.artifact.write(buf);
            }
            Self::SendBatch(requests) => {
                7u8.write(buf);
                requests.len().write(buf);
                for request in requests.iter() {
                    request.recipient.write(buf);
                    request.artifact.write(buf);
                }
            }
        }
    }
}

impl<V: Variant, D: Digest> Read for DurableEffect<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Sign(SignRequest::read_cfg(buf, config)?)),
            1 => {
                let count = usize::read_cfg(buf, &RangeCfg::exact(2))?;
                let mut requests = Vec::with_capacity(count);
                for _ in 0..count {
                    requests.push(SignRequest::read_cfg(buf, config)?);
                }
                Ok(Self::SignBatch(requests.into()))
            }
            2 => Ok(Self::Broadcast(Arc::new(Artifact::read_cfg(buf, config)?))),
            3 => Ok(Self::BroadcastBatch(read_artifacts(
                buf,
                config.max_artifacts,
                config,
            )?)),
            4 => Ok(Self::Propose(ProposalPublication {
                block: Arc::new(SignedLeaderBlock::read_cfg(buf, &config.protocol)?),
                parent: ProposalParent::read_cfg(buf, &config.protocol)?,
                attach_parent: bool::read(buf)?,
            })),
            5 => Ok(Self::Send(SendRequest {
                recipient: Participant::read(buf)?,
                artifact: Arc::new(Artifact::read_cfg(buf, config)?),
            })),
            7 => {
                let count = usize::read_cfg(buf, &RangeCfg::from(1..=config.protocol.chains()))?;
                let mut requests = Vec::with_capacity(count);
                for _ in 0..count {
                    requests.push(SendRequest {
                        recipient: Participant::read(buf)?,
                        artifact: Arc::new(Artifact::read_cfg(buf, config)?),
                    });
                }
                Ok(Self::SendBatch(requests.into()))
            }
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for DurableEffect<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Sign(request) => request.encode_size(),
            Self::SignBatch(requests) => {
                requests.len().encode_size()
                    + requests.iter().map(EncodeSize::encode_size).sum::<usize>()
            }
            Self::Broadcast(artifact) => artifact.encode_size(),
            Self::BroadcastBatch(artifacts) => artifacts_size(artifacts),
            Self::Propose(publication) => {
                publication.block.encode_size()
                    + publication.parent.encode_size()
                    + publication.attach_parent.encode_size()
            }
            Self::Send(request) => request.recipient.encode_size() + request.artifact.encode_size(),
            Self::SendBatch(requests) => {
                requests.len().encode_size()
                    + requests
                        .iter()
                        .map(|request| {
                            request.recipient.encode_size() + request.artifact.encode_size()
                        })
                        .sum::<usize>()
            }
        }
    }
}

impl<V: Variant, D: Digest> Write for SignRequest<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::TransactionBlock(header) => {
                0u8.write(buf);
                header.write(buf);
            }
            Self::DaVote(request) => {
                1u8.write(buf);
                request.block().write(buf);
            }
            Self::LeaderBlock(request) => {
                2u8.write(buf);
                request.block.write(buf);
                request.parent.write(buf);
                request.attach_parent.write(buf);
            }
            Self::Vote(request) => {
                3u8.write(buf);
                request.body().write(buf);
            }
            Self::NoVote { round } => {
                4u8.write(buf);
                round.write(buf);
            }
            Self::Nullify { round } => {
                5u8.write(buf);
                round.write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> Read for SignRequest<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::TransactionBlock(TransactionBlockHeader::read(buf)?)),
            1 => Ok(Self::DaVote(DaVoteRequest::new(Arc::new(
                SignedTransactionBlock::read_cfg(buf, &())?,
            )))),
            2 => Ok(Self::LeaderBlock(ProposalRequest {
                block: LeaderBlock::read_cfg(buf, &config.protocol)?,
                parent: ProposalParent::read_cfg(buf, &config.protocol)?,
                attach_parent: bool::read(buf)?,
            })),
            3 => Ok(Self::Vote(VoteRequest::new(VoteBody::read_cfg(
                buf,
                &config.protocol,
            )?))),
            4 => Ok(Self::NoVote {
                round: Round::read(buf)?,
            }),
            5 => Ok(Self::Nullify {
                round: Round::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for SignRequest<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::TransactionBlock(header) => header.encode_size(),
            Self::DaVote(request) => request.block().encode_size(),
            Self::LeaderBlock(request) => {
                request.block.encode_size()
                    + request.parent.encode_size()
                    + request.attach_parent.encode_size()
            }
            Self::Vote(request) => request.body().encode_size(),
            Self::NoVote { round } | Self::Nullify { round } => round.encode_size(),
        }
    }
}

impl<V: Variant, D: Digest> Read for ProposalParent<Arc<Vqc<V, D>>> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Genesis),
            1 => Ok(Self::Exact(Arc::new(Vqc::read_cfg(buf, config)?))),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<V: Variant, D: Digest> Write for ProposalParent<Arc<Vqc<V, D>>> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Genesis => 0u8.write(buf),
            Self::Exact(parent) => {
                1u8.write(buf);
                parent.write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for ProposalParent<Arc<Vqc<V, D>>> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Genesis => 0,
            Self::Exact(parent) => parent.encode_size(),
        }
    }
}

fn write_artifacts<V: Variant, D: Digest>(artifacts: &ArtifactBatch<V, D>, buf: &mut impl BufMut) {
    artifacts.len().write(buf);
    for artifact in artifacts.iter() {
        artifact.write(buf);
    }
}

fn read_artifacts<V: Variant, D: Digest>(
    buf: &mut impl Buf,
    max: usize,
    config: &DomainEventCodecConfig,
) -> Result<ArtifactBatch<V, D>, Error> {
    let artifacts = read_items(buf, max, |buf| {
        Artifact::read_cfg(buf, config).map(Arc::new)
    })?;
    Ok(artifacts.into())
}

fn artifacts_size<V: Variant, D: Digest>(artifacts: &ArtifactBatch<V, D>) -> usize {
    artifacts.len().encode_size()
        + artifacts
            .iter()
            .map(|item| item.encode_size())
            .sum::<usize>()
}

impl<V: Variant, D: Digest> Write for Artifact<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        let tag: u8 = match self {
            Self::TransactionBlock(_) => 0,
            Self::DaVote(_) => 1,
            Self::DaCertificate(_) => 2,
            Self::LeaderBlock(_) => 3,
            Self::Vote(_) => 4,
            Self::NoVote(_) => 5,
            Self::Nullify(_) => 6,
            Self::Nullification(_) => 7,
            Self::Vqc(_) => 8,
            Self::Lqc(_) => 9,
        };
        tag.write(buf);
        self.encoded_len().write(buf);
        match self {
            Self::TransactionBlock(value) => value.write(buf),
            Self::DaVote(value) => value.write(buf),
            Self::DaCertificate(value) => value.write(buf),
            Self::LeaderBlock(value) => value.write(buf),
            Self::Vote(value) => value.write(buf),
            Self::NoVote(value) => value.write(buf),
            Self::Nullify(value) => value.write(buf),
            Self::Nullification(value) => value.write(buf),
            Self::Vqc(value) => value.write(buf),
            Self::Lqc(value) => value.write(buf),
        }
    }
}

impl<V: Variant, D: Digest> Read for Artifact<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        let tag = u8::read(buf)?;
        let size = read_count(buf, config.max_artifact_bytes)?;
        if buf.remaining() < size {
            return Err(Error::EndOfBuffer);
        }
        let mut item = buf.copy_to_bytes(size);
        let artifact = match tag {
            0 => Self::TransactionBlock(SignedTransactionBlock::read(&mut item)?),
            1 => Self::DaVote(DaVote::read(&mut item)?),
            2 => Self::DaCertificate(DaCertificate::read(&mut item)?),
            3 => Self::LeaderBlock(SignedLeaderBlock::read_cfg(&mut item, &config.protocol)?),
            4 => Self::Vote(Vote::read_cfg(&mut item, &config.protocol)?),
            5 => Self::NoVote(NoVote::read(&mut item)?),
            6 => Self::Nullify(Nullify::read(&mut item)?),
            7 => Self::Nullification(Nullification::read(&mut item)?),
            8 => Self::Vqc(Vqc::read_cfg(&mut item, &config.protocol)?),
            9 => Self::Lqc(Lqc::read_cfg(&mut item, &config.protocol)?),
            tag => return Err(Error::InvalidEnum(tag)),
        };
        if item.has_remaining() {
            return Err(Error::ExtraData(item.remaining()));
        }
        Ok(artifact)
    }
}

impl<V: Variant, D: Digest> EncodeSize for Artifact<V, D> {
    fn encode_size(&self) -> usize {
        1 + self.encoded_len().encode_size() + self.encoded_len()
    }
}

impl Write for EffectId {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for EffectId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self(u64::read(buf)?))
    }
}

impl EncodeSize for EffectId {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl<D: Digest> Write for ArtifactId<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.get().write(buf);
    }
}

impl<D: Digest> Read for ArtifactId<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self::new(D::read(buf)?))
    }
}

impl<D: Digest> EncodeSize for ArtifactId<D> {
    fn encode_size(&self) -> usize {
        self.get().encode_size()
    }
}

fn read_count(buf: &mut impl Buf, max: usize) -> Result<usize, Error> {
    usize::read_cfg(buf, &RangeCfg::from(0..=max))
}

const fn require_version(actual: u8, expected: u8) -> Result<(), Error> {
    if actual != expected {
        return Err(Error::InvalidEnum(actual));
    }
    Ok(())
}

const fn durable_component_tag(component: DurableComponent) -> u8 {
    match component {
        DurableComponent::Da => 0,
        DurableComponent::View => 1,
        DurableComponent::Ordering => 2,
        DurableComponent::Durability => 3,
        DurableComponent::PublicationOutbox => 7,
    }
}

fn read_durable_component(buf: &mut impl Buf) -> Result<DurableComponent, Error> {
    match u8::read(buf)? {
        0 => Ok(DurableComponent::Da),
        1 => Ok(DurableComponent::View),
        2 => Ok(DurableComponent::Ordering),
        3 => Ok(DurableComponent::Durability),
        7 => Ok(DurableComponent::PublicationOutbox),
        tag => Err(Error::InvalidEnum(tag)),
    }
}

fn read_items<B: Buf, T>(
    buf: &mut B,
    max: usize,
    mut read: impl FnMut(&mut B) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    let count = read_count(buf, max)?;
    let mut items = Vec::with_capacity(count.min(buf.remaining()));
    for _ in 0..count {
        items.push(read(buf)?);
    }
    Ok(items)
}

fn read_unique_map<B: Buf, K: Ord, T>(
    buf: &mut B,
    max: usize,
    mut read: impl FnMut(&mut B) -> Result<(K, T), Error>,
) -> Result<BTreeMap<K, T>, Error> {
    let count = read_count(buf, max)?;
    let mut map = BTreeMap::new();
    for _ in 0..count {
        let (key, value) = read(buf)?;
        if map.insert(key, value).is_some() {
            return Err(Error::Invalid(
                "consensus::multimmit::machine::Snapshot",
                "duplicate map key",
            ));
        }
    }
    Ok(map)
}

impl<V: Variant, D: Digest> Write for PublicationOutbox<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.entries.write(buf);
    }
}

impl<V: Variant, D: Digest> Write for SigningReservations<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.entries.write(buf);
    }
}

impl<V: Variant, D: Digest> EncodeSize for SigningReservations<V, D> {
    fn encode_size(&self) -> usize {
        self.entries.encode_size()
    }
}

impl<V: Variant, D: Digest> Read for SigningReservations<V, D> {
    type Cfg = (usize, DomainEventCodecConfig);

    fn read_cfg(buf: &mut impl Buf, (max_entries, event): &Self::Cfg) -> Result<Self, Error> {
        let entries = BTreeMap::read_cfg(buf, &(RangeCfg::from(0..=*max_entries), ((), *event)))?;
        Self::from_entries(entries).ok_or(Error::Invalid(
            "consensus::multimmit::machine::SigningReservations",
            "owner contains a network-publication effect",
        ))
    }
}

impl<V: Variant, D: Digest> EncodeSize for PublicationOutbox<V, D> {
    fn encode_size(&self) -> usize {
        self.version.encode_size() + self.entries.encode_size()
    }
}

impl<V: Variant, D: Digest> Read for PublicationOutbox<V, D> {
    type Cfg = (usize, DomainEventCodecConfig);

    fn read_cfg(buf: &mut impl Buf, (max_entries, event): &Self::Cfg) -> Result<Self, Error> {
        require_version(u8::read(buf)?, PUBLICATION_OUTBOX_VERSION)?;
        let entries = BTreeMap::read_cfg(buf, &(RangeCfg::from(0..=*max_entries), ((), *event)))?;
        Self::from_entries(entries).ok_or(Error::Invalid(
            "consensus::multimmit::machine::PublicationOutbox",
            "owner contains a signing effect",
        ))
    }
}

impl Write for ComponentPayload {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.bytes.len().write(buf);
        buf.put_slice(&self.bytes);
    }
}

impl EncodeSize for ComponentPayload {
    fn encode_size(&self) -> usize {
        self.version.encode_size() + self.bytes.len().encode_size() + self.bytes.len()
    }
}

impl Read for ComponentPayload {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_bytes: &Self::Cfg) -> Result<Self, Error> {
        let version = u8::read(buf)?;
        let len = usize::read_cfg(buf, &RangeCfg::from(0..=*max_bytes))?;
        if buf.remaining() < len {
            return Err(Error::EndOfBuffer);
        }
        let bytes = Arc::<[u8]>::from(buf.copy_to_bytes(len).as_ref());
        Ok(Self { version, bytes })
    }
}

impl<V: Variant, D: Digest> Write for ViewSnapshot<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.slots.len().write(buf);
        for (view, slot) in &self.slots {
            view.write(buf);
            slot.write(buf);
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for ViewSnapshot<V, D> {
    fn encode_size(&self) -> usize {
        self.slots.len().encode_size()
            + self
                .slots
                .iter()
                .map(|(view, slot)| view.encode_size() + slot.encode_size())
                .sum::<usize>()
    }
}

impl<V: Variant, D: Digest> Read for ViewSnapshot<V, D> {
    type Cfg = (usize, CodecConfig);

    fn read_cfg(buf: &mut impl Buf, (max_slots, protocol): &Self::Cfg) -> Result<Self, Error> {
        let slots = read_unique_map(buf, *max_slots, |buf| {
            Ok((View::read(buf)?, ViewSlotSnapshot::read_cfg(buf, protocol)?))
        })?;
        Ok(Self { slots })
    }
}

impl<V: Variant, D: Digest> Write for ViewSlotSnapshot<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self.transition {
            ViewTransition::Active => 0u8.write(buf),
            ViewTransition::Exited(proof) => {
                1u8.write(buf);
                proof.write(buf);
            }
        }
        match &self.stance {
            ViewStance::Unchosen => 0u8.write(buf),
            ViewStance::Voted(body) => {
                1u8.write(buf);
                body.write(buf);
            }
            ViewStance::NoVoted => 2u8.write(buf),
        }
        match self.nullification {
            ViewNullification::Unsigned => 0u8.write(buf),
            ViewNullification::Signed => 1u8.write(buf),
        }
        self.proposal.is_some().write(buf);
        if let Some(proposal) = &self.proposal {
            proposal.write(buf);
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for ViewSlotSnapshot<V, D> {
    fn encode_size(&self) -> usize {
        let transition = match self.transition {
            ViewTransition::Active => 1,
            ViewTransition::Exited(proof) => 1 + proof.encode_size(),
        };
        let stance = match &self.stance {
            ViewStance::Unchosen | ViewStance::NoVoted => 1,
            ViewStance::Voted(body) => 1 + body.encode_size(),
        };
        transition
            + stance
            + 1
            + self.proposal.is_some().encode_size()
            + self.proposal.as_ref().map_or(0, EncodeSize::encode_size)
    }
}

impl<V: Variant, D: Digest> Read for ViewSlotSnapshot<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, protocol: &Self::Cfg) -> Result<Self, Error> {
        let transition = match u8::read(buf)? {
            0 => ViewTransition::Active,
            1 => ViewTransition::Exited(ArtifactId::read(buf)?),
            tag => return Err(Error::InvalidEnum(tag)),
        };
        let stance = match u8::read(buf)? {
            0 => ViewStance::Unchosen,
            1 => ViewStance::Voted(VoteBody::read_cfg(buf, protocol)?),
            2 => ViewStance::NoVoted,
            tag => return Err(Error::InvalidEnum(tag)),
        };
        let nullification = match u8::read(buf)? {
            0 => ViewNullification::Unsigned,
            1 => ViewNullification::Signed,
            tag => return Err(Error::InvalidEnum(tag)),
        };
        let proposal = if bool::read(buf)? {
            Some(LeaderBlock::read_cfg(buf, protocol)?)
        } else {
            None
        };
        Ok(Self {
            transition,
            stance,
            nullification,
            proposal,
        })
    }
}

impl Write for BarrierAck {
    fn write(&self, buf: &mut impl BufMut) {
        self.barrier.get().write(buf);
        self.generation.write(buf);
        self.cursor.get().write(buf);
    }
}

impl EncodeSize for BarrierAck {
    fn encode_size(&self) -> usize {
        self.barrier.get().encode_size()
            + self.generation.encode_size()
            + self.cursor.get().encode_size()
    }
}

impl Read for BarrierAck {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self::new(
            BarrierId::new(u64::read(buf)?),
            u64::read(buf)?,
            Cursor(u64::read(buf)?),
        ))
    }
}

impl Write for JournalPrefix {
    fn write(&self, buf: &mut impl BufMut) {
        self.version.write(buf);
        self.generation.write(buf);
        self.acknowledged.get().write(buf);
        self.pending.write(buf);
    }
}

impl EncodeSize for JournalPrefix {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.generation.encode_size()
            + self.acknowledged.get().encode_size()
            + self.pending.encode_size()
    }
}

impl Read for JournalPrefix {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_pending: &Self::Cfg) -> Result<Self, Error> {
        let version = u8::read(buf)?;
        let generation = u64::read(buf)?;
        let acknowledged = Cursor(u64::read(buf)?);
        let pending = Vec::read_cfg(buf, &(RangeCfg::from(0..=*max_pending), ()))?;
        Self::restore(version, generation, acknowledged, pending)
            .map_err(journal_prefix_codec_error)
    }
}

impl Write for SnapshotEnvelope {
    fn write(&self, buf: &mut impl BufMut) {
        self.ordering.write(buf);
        self.signing_reservations.write(buf);
        self.view.write(buf);
        self.obligations.write(buf);
        self.journal.write(buf);
    }
}

impl EncodeSize for SnapshotEnvelope {
    fn encode_size(&self) -> usize {
        self.ordering.encode_size()
            + self.signing_reservations.encode_size()
            + self.view.encode_size()
            + self.obligations.encode_size()
            + self.journal.encode_size()
    }
}

impl Read for SnapshotEnvelope {
    type Cfg = SnapshotCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        let ordering = ComponentPayload::read_cfg(buf, &config.max_component_bytes)?;
        let signing_reservations = ComponentPayload::read_cfg(buf, &config.max_component_bytes)?;
        let view = ComponentPayload::read_cfg(buf, &config.max_component_bytes)?;
        let obligations = ComponentPayload::read_cfg(buf, &config.max_component_bytes)?;
        if ordering.version != ORDERING_SNAPSHOT_VERSION
            || signing_reservations.version != SIGNING_RESERVATIONS_VERSION
            || view.version != VIEW_SNAPSHOT_VERSION
            || obligations.version != OBLIGATIONS_VERSION
        {
            return Err(Error::Invalid(
                "consensus::multimmit::machine::Snapshot",
                "unsupported component snapshot version",
            ));
        }
        Ok(Self {
            ordering,
            signing_reservations,
            view,
            obligations,
            journal: JournalPrefix::read_cfg(buf, &config.max_pending_barriers)?,
        })
    }
}

const fn journal_prefix_codec_error(_: ()) -> Error {
    Error::Invalid(
        "consensus::multimmit::machine::Snapshot",
        "invalid journal prefix state",
    )
}

impl<V: Variant, D: Digest> Write for Snapshot<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        DURABILITY_SCHEMA_VERSION.write(buf);
        self.epoch.write(buf);
        self.role.write(buf);
        self.state.write(buf);
        self.envelope.write(buf);
    }
}

impl<V: Variant, D: Digest> EncodeSize for Snapshot<V, D> {
    fn encode_size(&self) -> usize {
        DURABILITY_SCHEMA_VERSION.encode_size()
            + self.epoch.encode_size()
            + self.role.encode_size()
            + self.state.encode_size()
            + self.envelope.encode_size()
    }
}

impl<V: Variant, D: Digest> Read for Snapshot<V, D> {
    type Cfg = SnapshotCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        require_version(u8::read(buf)?, DURABILITY_SCHEMA_VERSION)?;
        let epoch = Epoch::read(buf)?;
        let role = Role::read(buf)?;
        let mut state = DurableState::read_cfg(buf, config)?;
        let envelope = SnapshotEnvelope::read_cfg(buf, config)?;
        let max_signing_reservations =
            config
                .max_outbox
                .checked_sub(state.outbox.len())
                .ok_or(Error::Invalid(
                    "consensus::multimmit::machine::Snapshot",
                    "durable effect owners exceed configured bound",
                ))?;
        let signing_reservations = SigningReservations::decode_cfg(
            envelope.signing_reservations.bytes(),
            &(max_signing_reservations, config.event),
        )?;
        if signing_reservations.encode().as_ref() != envelope.signing_reservations.bytes() {
            return Err(Error::Invalid(
                "consensus::multimmit::machine::SigningReservations",
                "component payload is not canonical",
            ));
        }
        state.signing_reservations = signing_reservations;
        let obligations = if envelope.obligations.bytes().is_empty() {
            ObligationsSnapshot::default()
        } else {
            let obligations = ObligationsSnapshot::decode_cfg(
                envelope.obligations.bytes(),
                &(state.outbox.len(), config.max_artifacts),
            )?;
            if obligations.encode().as_ref() != envelope.obligations.bytes() {
                return Err(Error::Invalid(
                    "consensus::multimmit::machine::ObligationsSnapshot",
                    "component payload is not canonical",
                ));
            }
            obligations
        };
        state.obligations = obligations.obligations;
        let view = ViewSnapshot::decode_cfg(
            envelope.view.bytes(),
            &(config.max_view_slots, config.event.protocol),
        )?;
        if !view.structurally_valid(epoch) || view.encode().as_ref() != envelope.view.bytes() {
            return Err(Error::Invalid(
                "consensus::multimmit::machine::ViewSnapshot",
                "component payload is not canonical",
            ));
        }
        Ok(Self {
            epoch,
            role,
            state,
            view,
            envelope,
        })
    }
}

impl Write for Role {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Observer => 0u8.write(buf),
            Self::Validator(participant) => {
                1u8.write(buf);
                participant.get().write(buf);
            }
        }
    }
}

impl Read for Role {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Observer),
            1 => Ok(Self::Validator(Participant::new(u32::read(buf)?))),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Role {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Observer => 0,
            Self::Validator(participant) => participant.get().encode_size(),
        }
    }
}

impl<V: Variant, D: Digest> Write for DurableState<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.view.write(buf);
        self.produced_blocks.write(buf);
        self.produced_height.write(buf);
        self.generation.write(buf);
        self.cursor.get().write(buf);
        self.certified_tips.write(buf);
        self.da_safety_heights.write(buf);
        self.retired_view.write(buf);
        self.signing_floor.write(buf);
        self.proposal_anchor.write(buf);
        self.proposal_nullified_through.write(buf);
        self.local.write(buf);
        self.outbox.write(buf);
        self.forwarded_vqcs.write(buf);
        self.forwarded_nullifications.write(buf);
        self.exits.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for DurableState<V, D> {
    type Cfg = SnapshotCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        let view = View::read(buf)?;
        let produced_blocks = u64::read(buf)?;
        let produced_height = Height::read(buf)?;
        let generation = u64::read(buf)?;
        let cursor = Cursor(u64::read(buf)?);
        let certified_tips = Vec::read_cfg(buf, &(RangeCfg::exact(config.chains), ()))?;
        let da_safety_heights = Vec::read_cfg(buf, &(RangeCfg::exact(config.chains), ()))?;
        let retired_view = View::read(buf)?;
        let signing_floor = Option::<Artifact<V, D>>::read_cfg(buf, &config.event)?.map(Arc::new);
        let proposal_anchor = Option::<Artifact<V, D>>::read_cfg(buf, &config.event)?.map(Arc::new);
        let proposal_nullified_through = View::read(buf)?;
        let local = read_unique_map(buf, config.max_artifacts, |buf| {
            Ok((
                ArtifactId::read(buf)?,
                Arc::new(Artifact::read_cfg(buf, &config.event)?),
            ))
        })?;
        let outbox = PublicationOutbox::read_cfg(buf, &(config.max_outbox, config.event))?;
        let forwarded_vqcs = read_forwarded(buf, config)?;
        let forwarded_nullifications = read_forwarded(buf, config)?;
        let exits = read_unique_map(buf, config.max_artifacts, |buf| {
            Ok((
                View::read(buf)?,
                Arc::new(Artifact::read_cfg(buf, &config.event)?),
            ))
        })?;
        Ok(Self {
            view,
            produced_blocks,
            produced_height,
            generation,
            cursor,
            certified_tips,
            da_safety_heights,
            retired_view,
            signing_floor,
            proposal_anchor,
            proposal_nullified_through,
            local,
            signing_reservations: SigningReservations::default(),
            outbox,
            obligations: BTreeMap::new(),
            forwarded_vqcs,
            forwarded_nullifications,
            exits,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for DurableState<V, D> {
    fn encode_size(&self) -> usize {
        self.view.encode_size()
            + self.produced_blocks.encode_size()
            + self.produced_height.encode_size()
            + self.generation.encode_size()
            + self.cursor.get().encode_size()
            + self.certified_tips.encode_size()
            + self.da_safety_heights.encode_size()
            + self.retired_view.encode_size()
            + self.signing_floor.encode_size()
            + self.proposal_anchor.encode_size()
            + self.proposal_nullified_through.encode_size()
            + self.local.encode_size()
            + self.outbox.encode_size()
            + self.forwarded_vqcs.encode_size()
            + self.forwarded_nullifications.encode_size()
            + self.exits.encode_size()
    }
}

fn read_forwarded<V: Variant, D: Digest>(
    buf: &mut impl Buf,
    config: &SnapshotCodecConfig,
) -> Result<BTreeMap<View, Arc<Artifact<V, D>>>, Error> {
    read_unique_map(buf, config.max_artifacts, |buf| {
        Ok((
            View::read(buf)?,
            Arc::new(Artifact::read_cfg(buf, &config.event)?),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::{
        config::Limits,
        types::{BlockRef, ChainId, Height},
    };
    #[cfg(feature = "arbitrary")]
    use crate::{
        multimmit::{
            config::Config,
            machine::{Machine, ResourceLimits, Tuning},
            types::{
                Anchor, Attestation, CertificateId, ChainProposal, EpochGenesis, Extension,
                Position, Tally, ThresholdShare,
            },
        },
        types::ViewDelta,
    };
    #[cfg(feature = "arbitrary")]
    use arbitrary::Arbitrary;
    #[cfg(feature = "arbitrary")]
    use commonware_codec::conformance::generate_value;
    use commonware_codec::{Decode, DecodeExt, Encode};
    #[cfg(feature = "arbitrary")]
    use commonware_conformance::Conformance;
    #[cfg(feature = "arbitrary")]
    use commonware_cryptography::bls12381::primitives::ops::aggregate;
    #[cfg(feature = "arbitrary")]
    use commonware_cryptography::bls12381::primitives::variant::MinPk;
    use commonware_cryptography::{
        Hasher, Sha256,
        bls12381::{
            certificate::threshold::Certificate as ThresholdCertificate,
            primitives::{
                group::{Private, Scalar},
                ops::sign_message,
                variant::MinSig,
            },
        },
        sha256::Digest as Sha256Digest,
    };
    type Event = DomainEvent<MinSig, Sha256Digest>;
    #[cfg(feature = "arbitrary")]
    type ConformanceArtifact<V> = Arc<Artifact<V, Sha256Digest>>;

    fn digest(label: &[u8]) -> Sha256Digest {
        Sha256::hash(&[label])
    }

    fn config(max_retired_effects: usize) -> DomainEventCodecConfig {
        DomainEventCodecConfig::new(
            CodecConfig::new(2, 2, Limits::new(2, 1).unwrap()).unwrap(),
            4096,
            4,
            max_retired_effects,
        )
    }

    fn snapshot_config() -> SnapshotCodecConfig {
        SnapshotCodecConfig {
            event: config(16),
            chains: 2,
            max_artifacts: 16,
            max_view_slots: 16,
            max_outbox: 16,
            max_component_bytes: 4096,
            max_pending_barriers: 16,
        }
    }

    fn context(change: Change<MinSig, Sha256Digest>) -> Event {
        Event::new(Epoch::new(7), Cursor(3), change)
    }

    fn block(chain: u32, height: u64) -> BlockRef<Sha256Digest> {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            digest(&height.to_be_bytes()),
        )
    }

    fn proof(view: u64) -> Arc<Artifact<MinSig, Sha256Digest>> {
        let private = Private::new(Scalar::from_u64(view + 1));
        Arc::new(Artifact::Nullification(
            Nullification::new(
                Round::new(Epoch::new(7), View::new(view)),
                ThresholdCertificate::new(sign_message::<MinSig>(
                    &private,
                    b"_COMMONWARE_CONSENSUS_MULTIMMIT_DURABILITY_CODEC_TEST_CERTIFICATE",
                    &view.to_be_bytes(),
                )),
            )
            .unwrap(),
        ))
    }

    fn obligation(effect: u64) -> PublicationObligation {
        let effect = EffectId(effect);
        PublicationObligation::new(
            effect,
            PublicationKind::BroadcastBatch,
            vec![PublicationDischarge::BlockCertifiedAtLeast {
                id: ObligationId::new(effect, 0),
                chain: ChainId::new(0),
                height: Height::new(3),
            }],
        )
    }

    fn snapshot<V: Variant>(seed: u64) -> Snapshot<V, Sha256Digest> {
        let mut state =
            DurableState::new(vec![block(0, seed + 1), block(1, seed + 2)], Height::zero());
        state.cursor = Cursor(3);
        state.generation = seed + 1;
        state.signing_reservations.insert(
            EffectId(2),
            DurableEffect::Sign(SignRequest::Nullify {
                round: Round::new(Epoch::new(7), View::new(seed + 1)),
            }),
        );
        Snapshot::from_state_for_test::<Sha256>(Epoch::new(7), Role::Observer, state)
    }

    #[test]
    fn round_trips_changes_and_effects() {
        let events = [
            context(Change::GenerationAdvanced(9)),
            context(Change::FinalityFloorAdvanced {
                proof: proof(3),
                retired: vec![EffectId(1)],
                publication_retired: vec![EffectId(2)],
            }),
            context(Change::OutboxQueued {
                id: EffectId(5),
                effect: Box::new(DurableEffect::Sign(SignRequest::Nullify {
                    round: Round::new(Epoch::new(7), View::new(3)),
                })),
            }),
        ];

        for event in events {
            let encoded = event.encode();
            assert_eq!(Event::decode_cfg(encoded, &config(4)).unwrap(), event);
        }
    }

    #[test]
    fn round_trips_publication_obligation_rows_and_legacy_shapes() {
        let rows = [
            (
                PublicationKind::Broadcast,
                PublicationDischarge::BlockCertifiedAtLeast {
                    id: ObligationId::new(EffectId(1), 0),
                    chain: ChainId::new(0),
                    height: Height::new(3),
                },
            ),
            (
                PublicationKind::Send,
                PublicationDischarge::VoteCertifiedAtLeast {
                    id: ObligationId::new(EffectId(2), 0),
                    chain: ChainId::new(1),
                    height: Height::new(4),
                },
            ),
            (
                PublicationKind::Broadcast,
                PublicationDischarge::CertificateSupersededAbove {
                    id: ObligationId::new(EffectId(3), 0),
                    chain: ChainId::new(0),
                    height: Height::new(5),
                },
            ),
            (
                PublicationKind::Broadcast,
                PublicationDischarge::ExitReplacedAfter {
                    id: ObligationId::new(EffectId(4), 0),
                    view: View::new(6),
                },
            ),
            (
                PublicationKind::Propose,
                PublicationDischarge::ViewRetired {
                    id: ObligationId::new(EffectId(5), 0),
                    view: View::new(7),
                },
            ),
        ];

        for (index, (kind, discharge)) in rows.into_iter().enumerate() {
            let obligation =
                PublicationObligation::new(EffectId(index as u64 + 1), kind, vec![discharge]);
            assert_eq!(
                PublicationObligation::decode_cfg(obligation.encode(), &1).unwrap(),
                obligation
            );
        }

        for kind in [
            PublicationKind::Broadcast,
            PublicationKind::BroadcastBatch,
            PublicationKind::Propose,
            PublicationKind::Send,
            PublicationKind::SendBatch,
        ] {
            assert_eq!(PublicationKind::decode(kind.encode()).unwrap(), kind);
        }
    }

    #[test]
    fn rejects_unknown_tag_and_trailing_data() {
        let event = context(Change::GenerationAdvanced(9));
        let mut unknown = event.encode().to_vec();
        let tag = DURABILITY_SCHEMA_VERSION.encode_size() + Epoch::new(7).encode_size() + 8;
        unknown[tag] = u8::MAX;
        assert!(matches!(
            Event::decode_cfg(unknown.as_slice(), &config(4)),
            Err(Error::InvalidEnum(u8::MAX))
        ));

        let mut trailing = event.encode().to_vec();
        trailing.push(0);
        assert!(matches!(
            Event::decode_cfg(trailing.as_slice(), &config(4)),
            Err(Error::ExtraData(1))
        ));

        let mut unsupported = event.encode().to_vec();
        unsupported[0] = u8::MAX;
        assert!(matches!(
            Event::decode_cfg(unsupported.as_slice(), &config(4)),
            Err(Error::InvalidEnum(u8::MAX))
        ));

        let mut unsupported_version = event.encode().to_vec();
        unsupported_version[0] = DURABILITY_SCHEMA_VERSION.wrapping_add(1);
        assert!(matches!(
            Event::decode_cfg(unsupported_version.as_slice(), &config(4)),
            Err(Error::InvalidEnum(version))
                if version == DURABILITY_SCHEMA_VERSION.wrapping_add(1)
        ));
    }

    #[test]
    fn rejects_removed_durability_tags() {
        for tag in [1, 2, 10, 13] {
            assert!(matches!(
                Change::<MinSig, Sha256Digest>::decode_cfg(&[tag][..], &config(4)),
                Err(Error::InvalidEnum(actual)) if actual == tag
            ));
        }
    }

    #[test]
    fn rejects_removed_publication_tags_without_renumbering_send_batch() {
        assert!(matches!(
            PublicationKind::decode(&[5][..]),
            Err(Error::InvalidEnum(5))
        ));
        assert!(matches!(
            DurableEffect::<MinSig, Sha256Digest>::decode_cfg(&[6][..], &config(4)),
            Err(Error::InvalidEnum(6))
        ));
        assert_eq!(PublicationKind::SendBatch.encode(), &[4][..]);

        let effect = DurableEffect::SendBatch(Arc::from([SendRequest {
            recipient: Participant::new(1),
            artifact: proof(3),
        }]));
        let encoded = effect.encode();
        assert_eq!(encoded[0], 7);
        assert_eq!(
            DurableEffect::<MinSig, Sha256Digest>::decode_cfg(encoded, &config(4)).unwrap(),
            effect
        );
    }

    #[test]
    fn rejects_removed_component_tags_without_renumbering_publication_outbox() {
        let component = DURABILITY_SCHEMA_VERSION.encode_size() + Epoch::new(7).encode_size() + 8;
        let base = context(Change::GenerationAdvanced(9)).encode().to_vec();
        assert_eq!(base[component], 3);
        for tag in 4..=6 {
            let mut encoded = base.clone();
            encoded[component] = tag;
            assert!(matches!(
                Event::decode_cfg(encoded.as_slice(), &config(4)),
                Err(Error::InvalidEnum(actual)) if actual == tag
            ));
        }

        let event = context(Change::OutboxQueued {
            id: EffectId(5),
            effect: Box::new(DurableEffect::Sign(SignRequest::Nullify {
                round: Round::new(Epoch::new(7), View::new(3)),
            })),
        });
        let encoded = event.encode();
        assert_eq!(encoded[component], 7);
        assert_eq!(Event::decode_cfg(encoded, &config(4)).unwrap(), event);
    }

    #[test]
    fn rejects_other_durability_schema() {
        assert_eq!(DURABILITY_SCHEMA_VERSION, 0);
        for unsupported in [1, 2, u8::MAX] {
            let mut event = context(Change::GenerationAdvanced(9)).encode().to_vec();
            event[0] = unsupported;
            assert!(matches!(
                Event::decode_cfg(event.as_slice(), &config(4)),
                Err(Error::InvalidEnum(version)) if version == unsupported
            ));

            let mut snapshot = snapshot::<MinSig>(9).encode().to_vec();
            snapshot[0] = unsupported;
            assert!(matches!(
                Snapshot::<MinSig, Sha256Digest>::decode_cfg(
                    snapshot.as_slice(),
                    &snapshot_config()
                ),
                Err(Error::InvalidEnum(version)) if version == unsupported
            ));
        }
    }

    #[test]
    fn proposal_parent_tags_are_exhaustive() {
        let protocol = config(4).protocol;

        let mut genesis = &[0u8][..];
        assert_eq!(
            ProposalParent::<Arc<Vqc<MinSig, Sha256Digest>>>::read_cfg(&mut genesis, &protocol,)
                .unwrap(),
            ProposalParent::Genesis
        );

        let mut exact_without_certificate = &[1u8][..];
        assert!(matches!(
            ProposalParent::<Arc<Vqc<MinSig, Sha256Digest>>>::read_cfg(
                &mut exact_without_certificate,
                &protocol,
            ),
            Err(Error::EndOfBuffer)
        ));

        let mut unknown = &[2u8][..];
        assert!(matches!(
            ProposalParent::<Arc<Vqc<MinSig, Sha256Digest>>>::read_cfg(&mut unknown, &protocol,),
            Err(Error::InvalidEnum(2))
        ));
    }

    #[test]
    fn rejects_bounded_vectors_before_allocating_items() {
        let event = context(Change::FinalityFloorAdvanced {
            proof: proof(3),
            retired: vec![EffectId(1), EffectId(2)],
            publication_retired: Vec::new(),
        });
        assert!(matches!(
            Event::decode_cfg(event.encode(), &config(1)),
            Err(Error::InvalidLength(2))
        ));
    }

    #[test]
    fn event_ceiling_includes_maximal_retirement_vectors() {
        let max_retired = 128;
        let config = DomainEventCodecConfig::new(
            CodecConfig::new(2, 2, Limits::new(2, 1).unwrap()).unwrap(),
            1,
            2,
            max_retired,
        );
        let retired = (0..max_retired)
            .map(|offset| EffectId(u64::MAX - offset as u64))
            .collect::<Vec<_>>();
        let event = context(Change::ViewAdvanced {
            proof: ArtifactId::new(digest(b"retirement ceiling")),
            retired,
        });
        let encoded = event.encode();

        assert!(encoded.len() <= config.max_encoded_size());
        assert_eq!(Event::decode_cfg(encoded, &config).unwrap(), event);
    }

    #[test]
    fn recovers_signing_reservations_from_component_payload() {
        let snapshot = snapshot::<MinSig>(9);
        let encoded = snapshot.encode();
        assert_eq!(encoded[0], DURABILITY_SCHEMA_VERSION);

        let recovered = Snapshot::decode_cfg(encoded.clone(), &snapshot_config()).unwrap();
        assert_eq!(recovered, snapshot);
        assert_eq!(recovered.state.outbox.version(), PUBLICATION_OUTBOX_VERSION);
        assert!(recovered.outbox().is_empty());
        assert!(matches!(
            recovered.state.signing_reservations.get(&EffectId(2)),
            Some(DurableEffect::Sign(SignRequest::Nullify { .. }))
        ));

        let unsupported = DURABILITY_SCHEMA_VERSION.wrapping_add(1);
        let mut unsupported_version = encoded.to_vec();
        unsupported_version[0] = unsupported;
        assert!(matches!(
            Snapshot::<MinSig, Sha256Digest>::decode_cfg(
                unsupported_version.as_slice(),
                &snapshot_config()
            ),
            Err(Error::InvalidEnum(version)) if version == unsupported
        ));
    }

    #[test]
    fn recovers_nonempty_versioned_publication_outbox() {
        let mut snapshot = snapshot::<MinSig>(9);
        snapshot.state.outbox.insert(
            EffectId(1),
            DurableEffect::BroadcastBatch(Vec::<Arc<Artifact<MinSig, Sha256Digest>>>::new().into()),
        );
        snapshot.envelope = SnapshotEnvelope::current(&snapshot.state, &snapshot.view);

        let recovered = Snapshot::decode_cfg(snapshot.encode(), &snapshot_config()).unwrap();
        assert_eq!(recovered, snapshot);
        assert_eq!(recovered.state.outbox.version(), PUBLICATION_OUTBOX_VERSION);
        assert!(matches!(
            recovered.outbox().get(&EffectId(1)),
            Some(DurableEffect::BroadcastBatch(artifacts)) if artifacts.is_empty()
        ));
    }

    #[test]
    fn obligation_component_round_trips_active_rows() {
        let mut snapshot = snapshot::<MinSig>(9);
        snapshot.state.outbox.insert(
            EffectId(3),
            DurableEffect::BroadcastBatch(Vec::<Arc<Artifact<MinSig, Sha256Digest>>>::new().into()),
        );
        snapshot
            .state
            .obligations
            .insert(EffectId(3), obligation(3));
        snapshot.envelope = SnapshotEnvelope::current(&snapshot.state, &snapshot.view);

        let recovered =
            Snapshot::<MinSig, Sha256Digest>::decode_cfg(snapshot.encode(), &snapshot_config())
                .unwrap();
        assert_eq!(recovered, snapshot);
        assert_eq!(recovered.state.obligations[&EffectId(3)], obligation(3));
    }

    #[test]
    fn obligation_component_rejects_unbounded_rows() {
        let mut unbounded = snapshot::<MinSig>(9);
        unbounded
            .state
            .obligations
            .insert(EffectId(3), obligation(3));
        unbounded.envelope = SnapshotEnvelope::current(&unbounded.state, &unbounded.view);
        assert!(matches!(
            Snapshot::<MinSig, Sha256Digest>::decode_cfg(unbounded.encode(), &snapshot_config()),
            Err(Error::InvalidLength(1))
        ));
    }

    #[test]
    fn durable_state_body_excludes_obligation_owner() {
        let snapshot = snapshot::<MinSig>(9);
        let mut state = snapshot.state;
        let encoded = state.encode();

        state.obligations.insert(EffectId(3), obligation(3));
        assert_eq!(state.encode(), encoded);
    }

    #[test]
    fn effect_owners_reject_rows_of_the_wrong_kind() {
        let event = config(4);
        let signing: DurableEffect<MinSig, Sha256Digest> =
            DurableEffect::Sign(SignRequest::Nullify {
                round: Round::new(Epoch::new(7), View::new(3)),
            });
        let publication =
            DurableEffect::BroadcastBatch(Vec::<Arc<Artifact<MinSig, Sha256Digest>>>::new().into());

        let signing_entries = BTreeMap::from([(EffectId(1), publication)]);
        let signing_payload = signing_entries.encode();
        assert!(matches!(
            SigningReservations::<MinSig, Sha256Digest>::decode_cfg(signing_payload, &(4, event)),
            Err(Error::Invalid(
                "consensus::multimmit::machine::SigningReservations",
                "owner contains a network-publication effect"
            ))
        ));

        let outbox_entries = BTreeMap::from([(EffectId(1), signing)]);
        let outbox = PublicationOutbox {
            version: PUBLICATION_OUTBOX_VERSION,
            entries: outbox_entries,
        };
        assert!(matches!(
            PublicationOutbox::<MinSig, Sha256Digest>::decode_cfg(outbox.encode(), &(4, event)),
            Err(Error::Invalid(
                "consensus::multimmit::machine::PublicationOutbox",
                "owner contains a signing effect"
            ))
        ));
    }

    #[test]
    fn signing_component_uses_remaining_effect_bound() {
        let mut snapshot = snapshot::<MinSig>(9);
        snapshot.state.outbox.insert(
            EffectId(1),
            DurableEffect::BroadcastBatch(Vec::<Arc<Artifact<MinSig, Sha256Digest>>>::new().into()),
        );
        snapshot.envelope = SnapshotEnvelope::current(&snapshot.state, &snapshot.view);
        let mut config = snapshot_config();
        config.max_outbox = 1;

        assert!(matches!(
            Snapshot::<MinSig, Sha256Digest>::decode_cfg(snapshot.encode(), &config),
            Err(Error::InvalidLength(1))
        ));
    }

    #[test]
    fn signing_component_rejects_trailing_bytes() {
        let mut snapshot = snapshot::<MinSig>(9);
        let mut bytes = snapshot.envelope.signing_reservations.bytes().to_vec();
        bytes.push(0);
        snapshot.envelope.signing_reservations =
            ComponentPayload::new(SIGNING_RESERVATIONS_VERSION, bytes);

        assert!(matches!(
            Snapshot::<MinSig, Sha256Digest>::decode_cfg(snapshot.encode(), &snapshot_config()),
            Err(Error::ExtraData(1))
        ));
    }

    #[test]
    fn barrier_ack_and_prefix_require_exact_order() {
        let pending = vec![
            BarrierAck::new(BarrierId(7), 4, Cursor(2)),
            BarrierAck::new(BarrierId(8), 4, Cursor(3)),
        ];
        let prefix = JournalPrefix::restore(0, 4, Cursor(1), pending).unwrap();
        assert_eq!(prefix.pending().len(), 2);
        assert!(
            JournalPrefix::restore(
                0,
                4,
                Cursor(1),
                vec![BarrierAck::new(BarrierId(8), 5, Cursor(2))]
            )
            .is_err()
        );
        assert!(
            JournalPrefix::restore(
                0,
                4,
                Cursor(1),
                vec![
                    BarrierAck::new(BarrierId(7), 4, Cursor(2)),
                    BarrierAck::new(BarrierId(9), 4, Cursor(3)),
                ]
            )
            .is_err()
        );
    }

    #[cfg(feature = "arbitrary")]
    fn generated<T: for<'a> Arbitrary<'a>>(seed: u64) -> T {
        generate_value(seed)
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_artifact<V: Variant>(seed: u64, arm: u64) -> Arc<Artifact<V, Sha256Digest>>
    where
        V::Signature: for<'a> Arbitrary<'a>,
    {
        Arc::new(match arm % 10 {
            0 => Artifact::TransactionBlock(generated(seed)),
            1 => Artifact::DaVote(generated(seed)),
            2 => Artifact::DaCertificate(generated(seed)),
            3 => Artifact::LeaderBlock(generated(seed)),
            4 => Artifact::Vote(generated(seed)),
            5 => Artifact::NoVote(generated(seed)),
            6 => Artifact::Nullify(generated(seed)),
            7 => Artifact::Nullification(generated(seed)),
            8 => Artifact::Vqc(generated(seed)),
            9 => Artifact::Lqc(generated(seed)),
            _ => unreachable!("artifact arm is reduced modulo the complete union"),
        })
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_parent<V: Variant>(seed: u64) -> ProposalParent<Arc<Vqc<V, Sha256Digest>>>
    where
        V::Signature: for<'a> Arbitrary<'a>,
    {
        if seed.is_multiple_of(2) {
            ProposalParent::Genesis
        } else {
            ProposalParent::Exact(Arc::new(generated(seed)))
        }
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_sign_request<V: Variant>(seed: u64) -> SignRequest<V, Sha256Digest>
    where
        V::Signature: for<'a> Arbitrary<'a>,
    {
        match seed % 6 {
            0 => SignRequest::TransactionBlock(generated(seed)),
            1 => SignRequest::DaVote(DaVoteRequest::new(Arc::new(generated(seed)))),
            2 => SignRequest::LeaderBlock(ProposalRequest::new(
                generated(seed),
                conformance_parent(seed),
                seed.is_multiple_of(2),
            )),
            3 => SignRequest::Vote(VoteRequest::new(generated(seed))),
            4 => SignRequest::NoVote {
                round: generated(seed),
            },
            5 => SignRequest::Nullify {
                round: generated(seed),
            },
            _ => unreachable!("sign-request arm is reduced modulo the complete union"),
        }
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_timeout_artifacts<V: Variant>(seed: u64) -> ArtifactBatch<V, Sha256Digest>
    where
        V::Signature: for<'a> Arbitrary<'a>,
    {
        let round = Round::new(Epoch::new(7), View::new(seed % 128 + 1));
        let signer = Participant::new((seed % 6) as u32);
        vec![
            Arc::new(Artifact::NoVote(
                NoVote::new(
                    round,
                    Attestation::new(signer, generated::<V::Signature>(seed).into()),
                )
                .unwrap(),
            )),
            Arc::new(Artifact::Nullify(
                Nullify::new(
                    round,
                    ThresholdShare::new(
                        signer,
                        generated::<V::Signature>(seed.wrapping_add(1)).into(),
                    ),
                )
                .unwrap(),
            )),
        ]
        .into()
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_outbox_effect<V: Variant>(seed: u64, lane: u64) -> DurableEffect<V, Sha256Digest>
    where
        V::Signature: for<'a> Arbitrary<'a>,
    {
        match lane {
            0..=5 => DurableEffect::Sign(conformance_sign_request(lane)),
            6 => {
                let round = generated(seed);
                DurableEffect::SignBatch(
                    vec![
                        SignRequest::NoVote { round },
                        SignRequest::Nullify { round },
                    ]
                    .into(),
                )
            }
            7 | 12 => DurableEffect::Broadcast(conformance_artifact(seed, 7)),
            8 => DurableEffect::BroadcastBatch(conformance_timeout_artifacts(seed)),
            9 => DurableEffect::Propose(ProposalPublication::new(
                Arc::new(generated(seed)),
                conformance_parent(seed),
                seed.is_multiple_of(2),
            )),
            10 => DurableEffect::Send(SendRequest::new(
                Participant::new((seed % 6) as u32),
                conformance_artifact(seed, 1),
            )),
            11 => DurableEffect::SendBatch(
                vec![
                    SendRequest::new(
                        Participant::new((seed % 6) as u32),
                        conformance_artifact(seed, 1),
                    ),
                    SendRequest::new(
                        Participant::new((seed.wrapping_add(1) % 6) as u32),
                        conformance_artifact(seed.wrapping_add(1), 1),
                    ),
                ]
                .into(),
            ),
            _ => unreachable!("outbox lane is reduced modulo the reachable set"),
        }
    }

    #[cfg(feature = "arbitrary")]
    impl<V: Variant> DomainEvent<V, Sha256Digest>
    where
        V::Signature: for<'a> Arbitrary<'a>,
    {
        pub(crate) fn conformance(seed: u64, cursor: Cursor) -> Self {
            let lane = seed / 10 % 13;
            let retired = || vec![EffectId(lane + 1), EffectId(lane + 2)];
            let change = match seed % 10 {
                0 => Change::GenerationAdvanced(seed),
                1 => Change::OutboxQueued {
                    id: EffectId(seed + 1),
                    effect: Box::new(conformance_outbox_effect(seed, lane)),
                },
                2 => Change::SignedArtifact {
                    sign: EffectId(seed + 1),
                    publication: EffectId(seed + 2),
                    artifact: conformance_artifact(seed, lane % 7),
                },
                3 => Change::SignedArtifactBatch {
                    sign: EffectId(seed + 1),
                    publication: EffectId(seed + 2),
                    artifacts: conformance_timeout_artifacts(seed),
                },
                4 => Change::ArtifactCreated {
                    publication: EffectId(seed + 1),
                    artifact: conformance_artifact(
                        seed,
                        if lane.is_multiple_of(2) { 2 } else { 9 },
                    ),
                },
                5 => Change::DaCertificateAdvanced {
                    publication: (!lane.is_multiple_of(2)).then_some(EffectId(seed + 1)),
                    retired: retired(),
                    artifact: conformance_artifact(seed, 2),
                },
                6 => Change::ViewCertificateCreated {
                    artifact: conformance_artifact(seed, 7 + lane % 2),
                },
                7 => Change::ArtifactForwarded {
                    publication: EffectId(seed + 1),
                    retired: retired(),
                    artifact: conformance_artifact(seed, 7 + lane % 2),
                },
                8 => Change::ViewAdvanced {
                    proof: ArtifactId::new(generated(seed)),
                    retired: retired(),
                },
                9 => Change::FinalityFloorAdvanced {
                    proof: conformance_artifact(seed, 9),
                    retired: retired(),
                    publication_retired: vec![EffectId(seed + 3)],
                },
                _ => unreachable!("change arm is reduced modulo the complete union"),
            };
            Self::new(Epoch::new(7), cursor, change)
        }
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_protocol_config() -> CodecConfig {
        CodecConfig::new(6, 6, Limits::new(2, 2).unwrap()).unwrap()
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_event_config() -> DomainEventCodecConfig {
        DomainEventCodecConfig::new(conformance_protocol_config(), 1024 * 1024, 16, 16)
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_snapshot_config() -> SnapshotCodecConfig {
        SnapshotCodecConfig {
            event: conformance_event_config(),
            chains: 6,
            max_artifacts: 16,
            max_view_slots: 16,
            max_outbox: 16,
            max_component_bytes: 1024 * 1024,
            max_pending_barriers: 16,
        }
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_profile<V: Variant>(role: Role) -> Profile<Sha256, V> {
        let epoch = Epoch::new(7);
        let tips = (0..6).map(|chain| block(chain, 0)).collect();
        let genesis = EpochGenesis::new(
            epoch,
            digest(b"leader genesis"),
            CertificateId::new(digest(b"vqc genesis")),
            CertificateId::new(digest(b"lqc genesis")),
            tips,
        )
        .unwrap();
        let protocol = Config::new(
            epoch,
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_CONFORMANCE",
            6,
            (0..6).map(Participant::new).collect(),
            Limits::new(2, 2).unwrap(),
            genesis,
        )
        .unwrap();
        let resources = ResourceLimits::new(
            NonZeroUsize::new(1024 * 1024).unwrap(),
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(2).unwrap(),
            2,
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(16).unwrap(),
            NonZeroUsize::new(16).unwrap(),
        );
        Profile::with_limits(
            protocol,
            role,
            Tuning {
                view_retention: ViewDelta::new(1),
                ..Tuning::default()
            },
            resources,
        )
        .unwrap()
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_leader<V: Variant>(
        profile: &Profile<Sha256, V>,
    ) -> LeaderBlock<V, Sha256Digest> {
        let protocol = profile.protocol();
        let round = Round::new(protocol.epoch(), View::new(1));
        let proposals = protocol
            .genesis()
            .tips()
            .iter()
            .enumerate()
            .map(|(chain, tip)| {
                ChainProposal::new(
                    ChainId::new(u32::try_from(chain).unwrap()),
                    Anchor::Tip(*tip),
                    Vec::new(),
                    protocol.codec_config().pipeline_depth(),
                )
                .unwrap()
            })
            .collect();
        LeaderBlock::new(
            round,
            protocol.genesis().vqc(),
            digest(b"conformance leader history"),
            proposals,
            protocol.codec_config(),
        )
        .unwrap()
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_finality_pair<V: Variant>(
        seed: u64,
        profile: &Profile<Sha256, V>,
    ) -> (ConformanceArtifact<V>, ConformanceArtifact<V>)
    where
        V::Signature: for<'a> Arbitrary<'a>,
    {
        let leader = conformance_leader(profile);
        let protocol = profile.protocol().codec_config();
        let vote = VoteBody::for_leader::<Sha256, V>(
            &leader,
            vec![Position::new(0); protocol.chains()],
            (0..protocol.chains()).map(|_| Extension::empty()).collect(),
            protocol,
        )
        .unwrap();
        let tally = Tally::from_votes::<V, Sha256, _>(
            &leader,
            (0..protocol.view_quorum())
                .map(|signer| (Participant::from_usize(signer), vote.clone())),
            protocol,
        )
        .unwrap();
        let lqc = Lqc::new(
            leader,
            tally,
            generated::<aggregate::Signature<V>>(seed),
            protocol,
        )
        .unwrap();
        let vqc = lqc.derive_vqc(protocol).unwrap();
        (Arc::new(Artifact::Lqc(lqc)), Arc::new(Artifact::Vqc(vqc)))
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_header(seed: u64, chain: ChainId) -> TransactionBlockHeader<Sha256Digest> {
        TransactionBlockHeader::new(
            Epoch::new(7),
            chain,
            Height::new(seed % 16 + 1),
            digest(b"conformance producer parent"),
            Sha256::hash(&[b"conformance payload", &seed.to_be_bytes()]),
        )
        .unwrap()
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_publication<V: Variant>(
        seed: u64,
        profile: &Profile<Sha256, V>,
    ) -> DurableEffect<V, Sha256Digest>
    where
        V::Signature: for<'a> Arbitrary<'a>,
    {
        let signer = match profile.role() {
            Role::Validator(signer) => signer,
            Role::Observer => Participant::new(0),
        };
        match seed % 7 {
            0 => {
                let header = conformance_header(seed, ChainId::new(0));
                let artifact = Arc::new(Artifact::TransactionBlock(SignedTransactionBlock::new(
                    header,
                    Attestation::new(signer, generated::<V::Signature>(seed).into()),
                )));
                DurableEffect::Broadcast(artifact)
            }
            1 => {
                let header = conformance_header(seed, ChainId::new(0));
                let artifact = Arc::new(Artifact::DaCertificate(DaCertificate::new(
                    header,
                    ThresholdCertificate::new(generated::<V::Signature>(seed)),
                )));
                DurableEffect::Broadcast(artifact)
            }
            2 => {
                let artifact = Arc::new(Artifact::Nullification(
                    Nullification::new(
                        Round::new(Epoch::new(7), View::new(1)),
                        ThresholdCertificate::new(generated::<V::Signature>(seed)),
                    )
                    .unwrap(),
                ));
                DurableEffect::Broadcast(artifact)
            }
            3 => {
                let round = Round::new(Epoch::new(7), View::new(1));
                let artifacts: Arc<[_]> = vec![
                    Arc::new(Artifact::NoVote(
                        NoVote::new(
                            round,
                            Attestation::new(signer, generated::<V::Signature>(seed).into()),
                        )
                        .unwrap(),
                    )),
                    Arc::new(Artifact::Nullify(
                        Nullify::new(
                            round,
                            ThresholdShare::new(
                                signer,
                                generated::<V::Signature>(seed.wrapping_add(1)).into(),
                            ),
                        )
                        .unwrap(),
                    )),
                ]
                .into();
                DurableEffect::BroadcastBatch(artifacts)
            }
            4 => {
                let block = conformance_leader(profile);
                let signed = Arc::new(SignedLeaderBlock::new(
                    block,
                    Attestation::new(signer, generated::<V::Signature>(seed).into()),
                ));
                DurableEffect::Propose(ProposalPublication::new(
                    signed,
                    ProposalParent::Genesis,
                    false,
                ))
            }
            5 => {
                let header = conformance_header(seed, ChainId::new(0));
                let artifact = Arc::new(Artifact::DaVote(DaVote::new(
                    header,
                    ThresholdShare::new(signer, generated::<V::Signature>(seed).into()),
                )));
                DurableEffect::Send(SendRequest::new(Participant::new(0), artifact))
            }
            6 => {
                let mut requests = Vec::new();
                for item in 0..2 {
                    let chain = ChainId::new(item);
                    let header = conformance_header(seed.wrapping_add(u64::from(item)), chain);
                    let artifact = Arc::new(Artifact::DaVote(DaVote::new(
                        header,
                        ThresholdShare::new(
                            signer,
                            generated::<V::Signature>(seed.wrapping_add(u64::from(item))).into(),
                        ),
                    )));
                    requests.push(SendRequest::new(Participant::new(item), artifact));
                }
                DurableEffect::SendBatch(requests.into())
            }
            _ => unreachable!("publication lane is reduced modulo the reachable set"),
        }
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_snapshot<V: Variant>(
        seed: u64,
    ) -> (Profile<Sha256, V>, Snapshot<V, Sha256Digest>)
    where
        V::Signature: for<'a> Arbitrary<'a>,
    {
        let lane = seed % 7;
        let role = if seed % 16 == 1 || lane == 4 {
            Role::Validator(Participant::new(1))
        } else if lane >= 3 {
            Role::Validator(Participant::new(0))
        } else if seed.is_multiple_of(4) {
            Role::Observer
        } else {
            Role::Validator(Participant::new(0))
        };
        let profile = conformance_profile::<V>(role);
        let epoch = profile.protocol().epoch();
        let round = Round::new(epoch, View::new(1));
        let mut state =
            DurableState::new(profile.protocol().genesis().tips().to_vec(), Height::zero());
        state.generation = seed + 1;
        state.cursor = Cursor(8);

        match seed % 4 {
            1 => {
                state.signing_reservations.insert(
                    EffectId(1),
                    DurableEffect::Sign(SignRequest::NoVote { round }),
                );
                state.signing_reservations.insert(
                    EffectId(2),
                    DurableEffect::Sign(SignRequest::Nullify { round }),
                );
            }
            2 => {
                let protocol = conformance_protocol_config();
                let body = VoteBody::new(
                    round,
                    generated(seed.wrapping_add(1)),
                    vec![Position::new(0); protocol.chains()],
                    (0..protocol.chains())
                        .map(|_| Extension::new(Vec::new(), protocol.extension_bound()).unwrap())
                        .collect(),
                    protocol,
                )
                .unwrap();
                state.signing_reservations.insert(
                    EffectId(1),
                    DurableEffect::Sign(SignRequest::Vote(VoteRequest::new(body))),
                );
            }
            3 => {
                state.signing_reservations.insert(
                    EffectId(1),
                    DurableEffect::SignBatch(
                        vec![
                            SignRequest::NoVote { round },
                            SignRequest::Nullify { round },
                        ]
                        .into(),
                    ),
                );
            }
            _ => {}
        }

        let proof = Arc::new(Artifact::Nullification(
            Nullification::new(
                round,
                ThresholdCertificate::new(generated(seed.wrapping_add(2))),
            )
            .unwrap(),
        ));
        let publication = EffectId(5);
        let effect = conformance_publication(seed, &profile);
        let obligation = Machine::<Sha256, V>::new(profile.clone())
            .publication_obligation(publication, &effect)
            .unwrap();
        state.outbox.insert(publication, effect);
        state.obligations.insert(publication, obligation);

        if seed.is_multiple_of(16) {
            let (floor, anchor) = conformance_finality_pair(seed, &profile);
            state.view = View::new(2);
            state.retired_view = View::new(1);
            state.signing_floor = Some(floor);
            state.proposal_anchor = Some(Arc::clone(&anchor));
            state.proposal_nullified_through = View::new(1);
            state
                .forwarded_vqcs
                .insert(View::new(1), Arc::clone(&anchor));
            state.local.insert(anchor.id::<Sha256>(), anchor);
        } else if seed.is_multiple_of(2) {
            state.view = View::new(2);
            state
                .forwarded_nullifications
                .insert(round.view(), Arc::clone(&proof));
            state.exits.insert(round.view(), proof);
        }

        if seed % 16 == 1 {
            let block = conformance_leader(&profile);
            let artifact = Arc::new(Artifact::LeaderBlock(SignedLeaderBlock::new(
                block,
                Attestation::new(Participant::new(1), generated::<V::Signature>(seed).into()),
            )));
            state.local.insert(artifact.id::<Sha256>(), artifact);
        }

        let snapshot = Snapshot::from_state_for_test::<Sha256>(epoch, role, state);
        snapshot.validate(&profile).unwrap();
        (profile, snapshot)
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_snapshot_bytes<V: Variant>(seed: u64) -> Vec<u8>
    where
        V::Signature: for<'a> Arbitrary<'a>,
    {
        let (profile, snapshot) = conformance_snapshot::<V>(seed);
        let encoded = snapshot.encode();
        let decoded =
            Snapshot::decode_cfg(encoded.clone(), &conformance_snapshot_config()).unwrap();
        assert_eq!(decoded, snapshot);
        decoded.validate(&profile).unwrap();
        encoded.to_vec()
    }

    #[cfg(feature = "arbitrary")]
    const fn artifact_arm<V: Variant>(artifact: &Artifact<V, Sha256Digest>) -> u16 {
        1 << match artifact {
            Artifact::TransactionBlock(_) => 0,
            Artifact::DaVote(_) => 1,
            Artifact::DaCertificate(_) => 2,
            Artifact::LeaderBlock(_) => 3,
            Artifact::Vote(_) => 4,
            Artifact::NoVote(_) => 5,
            Artifact::Nullify(_) => 6,
            Artifact::Nullification(_) => 7,
            Artifact::Vqc(_) => 8,
            Artifact::Lqc(_) => 9,
        }
    }

    #[cfg(feature = "arbitrary")]
    const fn sign_request_arm<V: Variant>(request: &SignRequest<V, Sha256Digest>) -> u8 {
        1 << match request {
            SignRequest::TransactionBlock(_) => 0,
            SignRequest::DaVote(_) => 1,
            SignRequest::LeaderBlock(_) => 2,
            SignRequest::Vote(_) => 3,
            SignRequest::NoVote { .. } => 4,
            SignRequest::Nullify { .. } => 5,
        }
    }

    #[cfg(feature = "arbitrary")]
    fn effect_arms<V: Variant>(effect: &DurableEffect<V, Sha256Digest>, requests: &mut u8) -> u8 {
        if let DurableEffect::Sign(request) = effect {
            *requests |= sign_request_arm(request);
            return 1;
        }
        if let DurableEffect::SignBatch(batch) = effect {
            for request in batch.iter() {
                *requests |= sign_request_arm(request);
            }
            return 1 << 1;
        }
        if matches!(effect, DurableEffect::Broadcast(_)) {
            return 1 << 2;
        }
        if matches!(effect, DurableEffect::BroadcastBatch(_)) {
            return 1 << 3;
        }
        if matches!(effect, DurableEffect::Propose(_)) {
            return 1 << 4;
        }
        if matches!(effect, DurableEffect::Send(_)) {
            return 1 << 5;
        }
        if matches!(effect, DurableEffect::SendBatch(_)) {
            return 1 << 6;
        }
        unreachable!("conformance generates only reachable effects")
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn generated_events_cover_every_reachable_union_arm() {
        let mut changes = 0u16;
        let mut effects = 0u8;
        let mut requests = 0u8;
        let mut view_certificates = 0u16;
        let mut forwarded = 0u16;
        for seed in 0..128 {
            match DomainEvent::<MinPk, Sha256Digest>::conformance(seed, Cursor(seed + 1)).change() {
                Change::GenerationAdvanced(_) => changes |= 1 << 0,
                Change::OutboxQueued { effect, .. } => {
                    changes |= 1 << 1;
                    effects |= effect_arms(effect, &mut requests);
                }
                Change::SignedArtifact { .. } => changes |= 1 << 2,
                Change::SignedArtifactBatch { .. } => changes |= 1 << 3,
                Change::ArtifactCreated { .. } => changes |= 1 << 4,
                Change::DaCertificateAdvanced { .. } => changes |= 1 << 5,
                Change::ViewCertificateCreated { artifact } => {
                    changes |= 1 << 6;
                    view_certificates |= artifact_arm(artifact);
                }
                Change::ArtifactForwarded { artifact, .. } => {
                    changes |= 1 << 7;
                    forwarded |= artifact_arm(artifact);
                }
                Change::ViewAdvanced { .. } => changes |= 1 << 8,
                Change::FinalityFloorAdvanced { .. } => changes |= 1 << 9,
            }
        }
        assert_eq!(changes, 0b11_1111_1111);
        assert_eq!(effects, 0b0111_1111);
        assert_eq!(requests, 0b11_1111);
        assert_eq!(view_certificates, (1 << 7) | (1 << 8));
        assert_eq!(forwarded, (1 << 7) | (1 << 8));
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn generated_snapshots_cover_checkpoint_unions() {
        let mut roles = 0u8;
        let mut effects = 0u8;
        let mut requests = 0u8;
        let mut stances = 0u8;
        let mut nullifications = 0u8;
        let mut transitions = 0u8;
        let mut proposals = 0u8;
        let mut publication_kinds = 0u8;
        let mut publication_discharges = 0u8;
        let mut state_owners = 0u8;
        for seed in 0..128 {
            let (profile, snapshot) = conformance_snapshot::<MinPk>(seed);
            roles |= match snapshot.role {
                Role::Observer => 1,
                Role::Validator(_) => 1 << 1,
            };
            for effect in snapshot.state.signing_reservations.values() {
                effects |= effect_arms(effect, &mut requests);
            }
            for (id, effect) in snapshot.state.outbox.iter() {
                effects |= effect_arms(effect, &mut requests);
                let obligation = &snapshot.state.obligations[id];
                publication_kinds |= 1
                    << match obligation.kind() {
                        PublicationKind::Broadcast => 0,
                        PublicationKind::BroadcastBatch => 1,
                        PublicationKind::Propose => 2,
                        PublicationKind::Send => 3,
                        PublicationKind::SendBatch => 4,
                    };
                for discharge in obligation.discharges() {
                    publication_discharges |= 1
                        << match discharge {
                            PublicationDischarge::BlockCertifiedAtLeast { .. } => 0,
                            PublicationDischarge::VoteCertifiedAtLeast { .. } => 1,
                            PublicationDischarge::CertificateSupersededAbove { .. } => 2,
                            PublicationDischarge::ExitReplacedAfter { .. } => 3,
                            PublicationDischarge::ViewRetired { .. } => 4,
                        };
                }
                assert!(!obligation.discharges().is_empty());
                assert!(obligation.matches_payload(effect));
            }
            for slot in snapshot.view.slots.values() {
                stances |= 1
                    << match slot.stance {
                        ViewStance::Unchosen => 0,
                        ViewStance::Voted(_) => 1,
                        ViewStance::NoVoted => 2,
                    };
                nullifications |= 1
                    << match slot.nullification {
                        ViewNullification::Unsigned => 0,
                        ViewNullification::Signed => 1,
                    };
                transitions |= 1
                    << match slot.transition {
                        ViewTransition::Active => 0,
                        ViewTransition::Exited(_) => 1,
                    };
                proposals |= 1 << usize::from(slot.proposal.is_some());
            }
            state_owners |= u8::from(snapshot.state.signing_floor.is_some());
            state_owners |= u8::from(snapshot.state.proposal_anchor.is_some()) << 1;
            state_owners |= u8::from(!snapshot.state.local.is_empty()) << 2;
            state_owners |= u8::from(!snapshot.state.forwarded_vqcs.is_empty()) << 3;
            assert!(snapshot.envelope.journal.pending().is_empty());
            snapshot.validate(&profile).unwrap();
        }
        assert_eq!(roles, 0b11);
        assert_eq!(effects, 0b111_1111);
        assert_eq!(requests, 0b11_1000);
        assert_eq!(stances, 0b111);
        assert_eq!(nullifications, 0b11);
        assert_eq!(transitions, 0b11);
        assert_eq!(proposals, 0b11);
        assert_eq!(publication_kinds, 0b1_1111);
        assert_eq!(publication_discharges, 0b1_1111);
        assert_eq!(state_owners, 0b1111);
    }

    #[cfg(feature = "arbitrary")]
    struct SnapshotMinPkConformance;
    #[cfg(feature = "arbitrary")]
    struct SnapshotMinSigConformance;

    #[cfg(feature = "arbitrary")]
    impl Conformance for SnapshotMinPkConformance {
        async fn commit(seed: u64) -> Vec<u8> {
            conformance_snapshot_bytes::<MinPk>(seed)
        }
    }

    #[cfg(feature = "arbitrary")]
    impl Conformance for SnapshotMinSigConformance {
        async fn commit(seed: u64) -> Vec<u8> {
            conformance_snapshot_bytes::<MinSig>(seed)
        }
    }

    #[cfg(feature = "arbitrary")]
    commonware_conformance::conformance_tests! {
        SnapshotMinPkConformance => 128,
        SnapshotMinSigConformance => 128,
    }
}
