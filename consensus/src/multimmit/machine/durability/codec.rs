//! Encoding for Multimmit's durable snapshot and journal events.
//!
//! A [`Snapshot`] encodes as the schema version, epoch, role, and every durable state field. A
//! [`DomainEvent`] encodes as the schema version, epoch, cursor, and change. Every value is
//! self-delimiting and bounded by its decoding config, so the journal record frame is the only
//! length prefix.

use super::{
    BatchId, Change, Cursor, DURABILITY_SCHEMA_VERSION, Discharge, DischargeKind, DomainEvent,
    DurableEffect, DurableState, EffectId, OutboxEntry, Proposal, ProposalParent,
    ProposalPublication, ProposalRequest, Publication, SendRequest, SignEffect, SignRequest,
    Snapshot,
};
use crate::{
    multimmit::{
        config::{Profile, Role},
        machine::{job::Generation, scheduler::DA_VOTE_RUN},
        types::{
            Artifact, ArtifactBatch, ArtifactId, ArtifactKind, ChainId, CodecConfig, DaCertificate,
            DaVote, Lqc, NoVote, Nullification, Nullify, SignedLeaderBlock, SignedTransactionBlock,
            TransactionBlockHeader, Vote, VoteBody, Vqc, each_artifact,
        },
    },
    types::{Epoch, Height, Participant, Round, View},
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::{collections::BTreeMap, sync::Arc};

/// Bounds used to decode one acknowledged machine snapshot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct SnapshotCodecConfig {
    event: DomainEventCodecConfig,
    chains: usize,
    max_artifacts: usize,
    max_outbox: usize,
}

impl SnapshotCodecConfig {
    /// Derives snapshot decoding bounds from the immutable machine profile.
    pub(crate) const fn from_profile<D: Digest>(profile: &Profile<D>) -> Self {
        let resources = profile.resources();
        Self {
            event: DomainEventCodecConfig::from_profile(profile),
            chains: profile.codec().chains(),
            max_artifacts: resources.max_cached_artifacts(),
            max_outbox: resources.max_outbox_effects(),
        }
    }

    /// Returns the bound for one map of durably retained artifacts.
    fn artifact_map_cfg(self) -> (RangeCfg<usize>, ((), DomainEventCodecConfig)) {
        (RangeCfg::from(0..=self.max_artifacts), ((), self.event))
    }
}

/// Ceiling on the bytes one artifact adds beyond its canonical encoding inside a change: its kind
/// tag and, in a send batch, its recipient.
const ARTIFACT_OVERHEAD_BYTES: usize = 16;

/// Most retirement lists one change carries: a finality floor advance retires signing requests
/// and publications.
const RETIREMENT_LISTS: usize = 2;

/// Ceiling on a change's tag, identifiers, digests, and list length prefixes.
const CHANGE_FIXED_BYTES: usize = 256;

/// Ceiling on an event's schema version, epoch, and cursor.
const EVENT_HEADER_BYTES: usize = 64;

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
    pub(crate) const fn from_profile<D: Digest>(profile: &Profile<D>) -> Self {
        let resources = profile.resources();
        Self {
            protocol: profile.codec(),
            max_artifact_bytes: resources.max_artifact_bytes(),
            // A durable batch is either the two timeout messages or a DA-vote run of up to
            // DA_VOTE_RUN consecutive blocks per producer chain. The cache bound describes total
            // live residency, not one event.
            max_artifacts: {
                let run = profile.codec().chains().saturating_mul(DA_VOTE_RUN);
                if run < 2 { 2 } else { run }
            },
            max_retired_effects: resources.max_outbox_effects(),
        }
    }

    /// Returns a conservative payload ceiling for one change accepted by this codec.
    fn max_change_size(self) -> usize {
        let artifact_bytes = self
            .max_artifact_bytes
            .saturating_add(ARTIFACT_OVERHEAD_BYTES)
            .saturating_mul(self.max_artifacts);
        let retirement_bytes = u64::MAX
            .encode_size()
            .saturating_mul(self.max_retired_effects)
            .saturating_mul(RETIREMENT_LISTS);
        artifact_bytes
            .saturating_add(retirement_bytes)
            .saturating_add(CHANGE_FIXED_BYTES)
    }

    /// Returns a conservative encoded ceiling for one event accepted by this codec.
    pub(crate) fn max_encoded_size(self) -> usize {
        self.max_change_size().saturating_add(EVENT_HEADER_BYTES)
    }

    /// Returns the bound for one retired-effect list.
    fn retired_cfg(self) -> (RangeCfg<usize>, ()) {
        (RangeCfg::from(0..=self.max_retired_effects), ())
    }

    /// Returns the bound for a non-empty batch of artifacts, requests, or sends.
    fn batch_cfg(self) -> (RangeCfg<usize>, Self) {
        (RangeCfg::from(1..=self.max_artifacts), self)
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
        self.cursor.write(buf);
        self.change.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for DomainEvent<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        require_version(u8::read(buf)?)?;
        Ok(Self {
            epoch: Epoch::read(buf)?,
            cursor: Cursor::read(buf)?,
            change: Change::read_cfg(buf, config)?,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for DomainEvent<V, D> {
    fn encode_size(&self) -> usize {
        DURABILITY_SCHEMA_VERSION.encode_size()
            + self.epoch.encode_size()
            + self.cursor.encode_size()
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
                1u8.write(buf);
                id.write(buf);
                effect.write(buf);
            }
            Self::SignedArtifacts {
                sign,
                publication,
                artifacts,
            } => {
                2u8.write(buf);
                sign.write(buf);
                publication.write(buf);
                artifacts.as_ref().write(buf);
            }
            Self::ViewCertificateCreated { artifact } => {
                3u8.write(buf);
                artifact.write(buf);
            }
            Self::ArtifactForwarded {
                publication,
                retired_publications,
                artifact,
            } => {
                4u8.write(buf);
                publication.write(buf);
                retired_publications.write(buf);
                artifact.write(buf);
            }
            Self::ViewAdvanced {
                proof,
                floor,
                retired_publications,
            } => {
                5u8.write(buf);
                proof.write(buf);
                floor.write(buf);
                retired_publications.write(buf);
            }
            Self::FinalityFloorAdvanced {
                proof,
                retired_signing,
                retired_publications,
            } => {
                6u8.write(buf);
                proof.write(buf);
                retired_signing.write(buf);
                retired_publications.write(buf);
            }
            Self::DaCertificateAdvanced {
                publication,
                retired_publications,
                artifact,
            } => {
                7u8.write(buf);
                publication.write(buf);
                retired_publications.write(buf);
                artifact.write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> Read for Change<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        let change = match u8::read(buf)? {
            0 => Self::GenerationAdvanced(Generation::read(buf)?),
            1 => Self::OutboxQueued {
                id: EffectId::read(buf)?,
                effect: Box::new(DurableEffect::read_cfg(buf, config)?),
            },
            2 => Self::SignedArtifacts {
                sign: EffectId::read(buf)?,
                publication: EffectId::read(buf)?,
                artifacts: read_batch(buf, config)?,
            },
            3 => Self::ViewCertificateCreated {
                artifact: Arc::read_cfg(buf, config)?,
            },
            4 => Self::ArtifactForwarded {
                publication: EffectId::read(buf)?,
                retired_publications: Vec::read_cfg(buf, &config.retired_cfg())?,
                artifact: Arc::read_cfg(buf, config)?,
            },
            5 => Self::ViewAdvanced {
                proof: ArtifactId::read(buf)?,
                floor: View::read(buf)?,
                retired_publications: Vec::read_cfg(buf, &config.retired_cfg())?,
            },
            6 => Self::FinalityFloorAdvanced {
                proof: Arc::read_cfg(buf, config)?,
                retired_signing: Vec::read_cfg(buf, &config.retired_cfg())?,
                retired_publications: Vec::read_cfg(buf, &config.retired_cfg())?,
            },
            7 => Self::DaCertificateAdvanced {
                publication: Option::read(buf)?,
                retired_publications: Vec::read_cfg(buf, &config.retired_cfg())?,
                artifact: Arc::read_cfg(buf, config)?,
            },
            tag => return Err(Error::InvalidEnum(tag)),
        };
        Ok(change)
    }
}

impl<V: Variant, D: Digest> EncodeSize for Change<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::GenerationAdvanced(generation) => generation.encode_size(),
            Self::OutboxQueued { id, effect } => id.encode_size() + effect.encode_size(),
            Self::SignedArtifacts {
                sign,
                publication,
                artifacts,
            } => sign.encode_size() + publication.encode_size() + artifacts.as_ref().encode_size(),
            Self::ViewCertificateCreated { artifact } => artifact.encode_size(),
            Self::ArtifactForwarded {
                publication,
                retired_publications,
                artifact,
            } => {
                publication.encode_size()
                    + retired_publications.encode_size()
                    + artifact.encode_size()
            }
            Self::ViewAdvanced {
                proof,
                floor,
                retired_publications,
            } => proof.encode_size() + floor.encode_size() + retired_publications.encode_size(),
            Self::FinalityFloorAdvanced {
                proof,
                retired_signing,
                retired_publications,
            } => {
                proof.encode_size()
                    + retired_signing.encode_size()
                    + retired_publications.encode_size()
            }
            Self::DaCertificateAdvanced {
                publication,
                retired_publications,
                artifact,
            } => {
                publication.encode_size()
                    + retired_publications.encode_size()
                    + artifact.encode_size()
            }
        }
    }
}

impl Write for DischargeKind {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::BlockCertifiedAtLeast { chain, height } => {
                0u8.write(buf);
                chain.write(buf);
                height.write(buf);
            }
            Self::VoteCertifiedAtLeast { chain, height } => {
                1u8.write(buf);
                chain.write(buf);
                height.write(buf);
            }
            Self::CertificateSupersededAbove { chain, height } => {
                2u8.write(buf);
                chain.write(buf);
                height.write(buf);
            }
            Self::ExitReplacedAfter { view } => {
                3u8.write(buf);
                view.write(buf);
            }
            Self::ViewRetired { view } => {
                4u8.write(buf);
                view.write(buf);
            }
        }
    }
}

impl Read for DischargeKind {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::BlockCertifiedAtLeast {
                chain: ChainId::read(buf)?,
                height: Height::read(buf)?,
            }),
            1 => Ok(Self::VoteCertifiedAtLeast {
                chain: ChainId::read(buf)?,
                height: Height::read(buf)?,
            }),
            2 => Ok(Self::CertificateSupersededAbove {
                chain: ChainId::read(buf)?,
                height: Height::read(buf)?,
            }),
            3 => Ok(Self::ExitReplacedAfter {
                view: View::read(buf)?,
            }),
            4 => Ok(Self::ViewRetired {
                view: View::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for DischargeKind {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::BlockCertifiedAtLeast { chain, height }
            | Self::VoteCertifiedAtLeast { chain, height }
            | Self::CertificateSupersededAbove { chain, height } => {
                chain.encode_size() + height.encode_size()
            }
            Self::ExitReplacedAfter { view } | Self::ViewRetired { view } => view.encode_size(),
        }
    }
}

impl Write for Discharge {
    fn write(&self, buf: &mut impl BufMut) {
        self.item.write(buf);
        self.until.write(buf);
    }
}

impl Read for Discharge {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self::new(u32::read(buf)?, DischargeKind::read(buf)?))
    }
}

impl EncodeSize for Discharge {
    fn encode_size(&self) -> usize {
        self.item.encode_size() + self.until.encode_size()
    }
}

impl<V: Variant, D: Digest> Write for OutboxEntry<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.publication.write(buf);
        self.discharges.as_ref().write(buf);
    }
}

impl<V: Variant, D: Digest> Read for OutboxEntry<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        let publication = Publication::read_cfg(buf, config)?;
        // Each discharge ends one distinct item of the publication.
        let items = match &publication {
            Publication::Broadcast(artifacts) => artifacts.len(),
            Publication::Send(requests) => requests.len(),
            Publication::Propose(_) => 1,
        };
        let discharges = Vec::read_cfg(buf, &(RangeCfg::from(1..=items), ()))?;
        Ok(Self::new(publication, discharges))
    }
}

impl<V: Variant, D: Digest> EncodeSize for OutboxEntry<V, D> {
    fn encode_size(&self) -> usize {
        self.publication.encode_size() + self.discharges.as_ref().encode_size()
    }
}

impl<V: Variant, D: Digest> Write for DurableEffect<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Sign(effect) => {
                0u8.write(buf);
                effect.write(buf);
            }
            Self::Publish(publication) => {
                1u8.write(buf);
                publication.write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> Read for DurableEffect<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Sign(SignEffect::read_cfg(buf, config)?)),
            1 => Ok(Self::Publish(Publication::read_cfg(buf, config)?)),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for DurableEffect<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Sign(effect) => effect.encode_size(),
            Self::Publish(publication) => publication.encode_size(),
        }
    }
}

impl<V: Variant, D: Digest> Write for SignEffect<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.requests.as_ref().write(buf);
    }
}

impl<V: Variant, D: Digest> Read for SignEffect<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self::new(Vec::read_cfg(buf, &config.batch_cfg())?.into()))
    }
}

impl<V: Variant, D: Digest> EncodeSize for SignEffect<V, D> {
    fn encode_size(&self) -> usize {
        self.requests.as_ref().encode_size()
    }
}

impl<V: Variant, D: Digest> Write for Publication<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Broadcast(artifacts) => {
                0u8.write(buf);
                artifacts.as_ref().write(buf);
            }
            Self::Propose(publication) => {
                1u8.write(buf);
                publication.write(buf);
            }
            Self::Send(requests) => {
                2u8.write(buf);
                requests.as_ref().write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> Read for Publication<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Broadcast(read_batch(buf, config)?)),
            1 => Ok(Self::Propose(ProposalPublication::read_cfg(
                buf,
                &config.protocol,
            )?)),
            // A send publishes the votes of one DA-vote signing choice, so it carries a run of
            // consecutive heights per producer chain, not a single vote per chain.
            2 => Ok(Self::Send(Vec::read_cfg(buf, &config.batch_cfg())?.into())),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for Publication<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Broadcast(artifacts) => artifacts.as_ref().encode_size(),
            Self::Propose(publication) => publication.encode_size(),
            Self::Send(requests) => requests.as_ref().encode_size(),
        }
    }
}

impl<V: Variant, D: Digest, B: Write> Write for Proposal<V, D, B> {
    fn write(&self, buf: &mut impl BufMut) {
        self.block.write(buf);
        self.parent.write(buf);
        self.attach_parent.write(buf);
    }
}

impl<V: Variant, D: Digest, B: Read<Cfg = CodecConfig>> Read for Proposal<V, D, B> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self::new(
            B::read_cfg(buf, config)?,
            ProposalParent::read_cfg(buf, config)?,
            bool::read(buf)?,
        ))
    }
}

impl<V: Variant, D: Digest, B: EncodeSize> EncodeSize for Proposal<V, D, B> {
    fn encode_size(&self) -> usize {
        self.block.encode_size() + self.parent.encode_size() + self.attach_parent.encode_size()
    }
}

impl<V: Variant, D: Digest> Write for SendRequest<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.recipient.write(buf);
        self.artifact.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for SendRequest<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            recipient: Participant::read(buf)?,
            artifact: Arc::read_cfg(buf, config)?,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for SendRequest<V, D> {
    fn encode_size(&self) -> usize {
        self.recipient.encode_size() + self.artifact.encode_size()
    }
}

impl<V: Variant, D: Digest> Write for SignRequest<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::TransactionBlock(header) => {
                0u8.write(buf);
                header.write(buf);
            }
            Self::DaVote(block) => {
                1u8.write(buf);
                block.write(buf);
            }
            Self::LeaderBlock(request) => {
                2u8.write(buf);
                request.write(buf);
            }
            Self::Vote(body) => {
                3u8.write(buf);
                body.write(buf);
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
            1 => Ok(Self::DaVote(Arc::<SignedTransactionBlock<V, D>>::read(
                buf,
            )?)),
            2 => Ok(Self::LeaderBlock(ProposalRequest::read_cfg(
                buf,
                &config.protocol,
            )?)),
            3 => Ok(Self::Vote(VoteBody::read_cfg(buf, &config.protocol)?)),
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
            Self::DaVote(block) => block.encode_size(),
            Self::LeaderBlock(request) => request.encode_size(),
            Self::Vote(body) => body.encode_size(),
            Self::NoVote { round } | Self::Nullify { round } => round.encode_size(),
        }
    }
}

impl<V: Variant, D: Digest> Read for ProposalParent<Arc<Vqc<V, D>>> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Genesis),
            1 => Ok(Self::Exact(Arc::read_cfg(buf, config)?)),
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

/// Reads a non-empty batch of artifacts.
fn read_batch<V: Variant, D: Digest>(
    buf: &mut impl Buf,
    config: &DomainEventCodecConfig,
) -> Result<ArtifactBatch<V, D>, Error> {
    Ok(Vec::read_cfg(buf, &config.batch_cfg())?.into())
}

impl<V: Variant, D: Digest> Write for Artifact<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        (self.kind() as u8).write(buf);
        each_artifact!(self, value => value.write(buf));
    }
}

impl<V: Variant, D: Digest> Read for Artifact<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        let protocol = &config.protocol;
        let artifact = match ArtifactKind::try_from(u8::read(buf)?)? {
            ArtifactKind::TransactionBlock => {
                Self::TransactionBlock(SignedTransactionBlock::read(buf)?)
            }
            ArtifactKind::DaVote => Self::DaVote(DaVote::read(buf)?),
            ArtifactKind::DaCertificate => Self::DaCertificate(DaCertificate::read(buf)?),
            ArtifactKind::LeaderBlock => {
                Self::LeaderBlock(SignedLeaderBlock::read_cfg(buf, protocol)?)
            }
            ArtifactKind::Vote => Self::Vote(Vote::read_cfg(buf, protocol)?),
            ArtifactKind::NoVote => Self::NoVote(NoVote::read(buf)?),
            ArtifactKind::Nullify => Self::Nullify(Nullify::read(buf)?),
            ArtifactKind::Nullification => Self::Nullification(Nullification::read(buf)?),
            ArtifactKind::Vqc => Self::Vqc(Vqc::read_cfg(buf, protocol)?),
            ArtifactKind::Lqc => Self::Lqc(Lqc::read_cfg(buf, protocol)?),
        };
        Ok(artifact)
    }
}

impl<V: Variant, D: Digest> EncodeSize for Artifact<V, D> {
    fn encode_size(&self) -> usize {
        1 + self.encoded_len()
    }
}

impl Write for Generation {
    fn write(&self, buf: &mut impl BufMut) {
        self.get().write(buf);
    }
}

impl Read for Generation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self::new(u64::read(buf)?))
    }
}

impl EncodeSize for Generation {
    fn encode_size(&self) -> usize {
        self.get().encode_size()
    }
}

impl Write for Cursor {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for Cursor {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self(u64::read(buf)?))
    }
}

impl EncodeSize for Cursor {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl Write for BatchId {
    fn write(&self, buf: &mut impl BufMut) {
        self.get().write(buf);
    }
}

impl Read for BatchId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self::new(u64::read(buf)?))
    }
}

impl EncodeSize for BatchId {
    fn encode_size(&self) -> usize {
        self.get().encode_size()
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

/// Rejects any schema version other than [`DURABILITY_SCHEMA_VERSION`].
const fn require_version(version: u8) -> Result<(), Error> {
    if version != DURABILITY_SCHEMA_VERSION {
        return Err(Error::InvalidEnum(version));
    }
    Ok(())
}

impl<V: Variant, D: Digest> Write for Snapshot<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        DURABILITY_SCHEMA_VERSION.write(buf);
        self.epoch.write(buf);
        self.role.write(buf);
        self.state.write(buf);
    }
}

impl<V: Variant, D: Digest> EncodeSize for Snapshot<V, D> {
    fn encode_size(&self) -> usize {
        DURABILITY_SCHEMA_VERSION.encode_size()
            + self.epoch.encode_size()
            + self.role.encode_size()
            + self.state.encode_size()
    }
}

impl<V: Variant, D: Digest> Read for Snapshot<V, D> {
    type Cfg = SnapshotCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        require_version(u8::read(buf)?)?;
        Ok(Self {
            epoch: Epoch::read(buf)?,
            role: Role::read(buf)?,
            state: DurableState::read_cfg(buf, config)?,
        })
    }
}

impl Write for Role {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Observer => 0u8.write(buf),
            Self::Validator(participant) => {
                1u8.write(buf);
                participant.write(buf);
            }
        }
    }
}

impl Read for Role {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Observer),
            1 => Ok(Self::Validator(Participant::read(buf)?)),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Role {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Observer => 0,
            Self::Validator(participant) => participant.encode_size(),
        }
    }
}

impl<V: Variant, D: Digest> Write for DurableState<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.view.write(buf);
        self.produced_blocks.write(buf);
        self.produced_height.write(buf);
        self.generation.write(buf);
        self.cursor.write(buf);
        self.certified_tips.write(buf);
        self.da_safety_heights.write(buf);
        self.retired_view.write(buf);
        self.signing_floor.write(buf);
        self.proposal_anchor.write(buf);
        self.proposal_nullified_through.write(buf);
        self.local.write(buf);
        self.signing_reservations.write(buf);
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
        let generation = Generation::read(buf)?;
        let cursor = Cursor::read(buf)?;
        let certified_tips = Vec::read_cfg(buf, &(RangeCfg::exact(config.chains), ()))?;
        let da_safety_heights = Vec::read_cfg(buf, &(RangeCfg::exact(config.chains), ()))?;
        let retired_view = View::read(buf)?;
        let signing_floor = Option::read_cfg(buf, &config.event)?;
        let proposal_anchor = Option::read_cfg(buf, &config.event)?;
        let proposal_nullified_through = View::read(buf)?;
        let local = BTreeMap::read_cfg(buf, &config.artifact_map_cfg())?;
        // Signing reservations and publications share one outbox bound.
        let signing_reservations: BTreeMap<_, _> = BTreeMap::read_cfg(
            buf,
            &(RangeCfg::from(0..=config.max_outbox), ((), config.event)),
        )?;
        let outbox = BTreeMap::read_cfg(
            buf,
            &(
                RangeCfg::from(0..=config.max_outbox - signing_reservations.len()),
                ((), config.event),
            ),
        )?;
        let forwarded_vqcs = BTreeMap::read_cfg(buf, &config.artifact_map_cfg())?;
        let forwarded_nullifications = BTreeMap::read_cfg(buf, &config.artifact_map_cfg())?;
        let exits = BTreeMap::read_cfg(buf, &config.artifact_map_cfg())?;
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
            signing_reservations,
            outbox,
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
            + self.cursor.encode_size()
            + self.certified_tips.encode_size()
            + self.da_safety_heights.encode_size()
            + self.retired_view.encode_size()
            + self.signing_floor.encode_size()
            + self.proposal_anchor.encode_size()
            + self.proposal_nullified_through.encode_size()
            + self.local.encode_size()
            + self.signing_reservations.encode_size()
            + self.outbox.encode_size()
            + self.forwarded_vqcs.encode_size()
            + self.forwarded_nullifications.encode_size()
            + self.exits.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "arbitrary")]
    use crate::multimmit::config::ResourceLimits;
    #[cfg(feature = "arbitrary")]
    use crate::multimmit::machine::view::{ViewStance, ViewTransition};
    use crate::{
        Epochable as _,
        multimmit::{
            config::{Role, Tuning},
            mocks::Committee,
            types::{Attestation, BlockRef, ChainId, PathLimits},
        },
        types::Height,
    };
    #[cfg(feature = "arbitrary")]
    use crate::{
        multimmit::{
            config::Protocol,
            machine::reducer::machine::Machine,
            types::{
                Anchor, CertificateId, ChainProposal, DigestedLeader, EpochGenesis, Extension,
                LeaderBlock, Position, Tally, ThresholdShare,
            },
        },
        types::ViewDelta,
    };
    #[cfg(feature = "arbitrary")]
    use arbitrary::Arbitrary;
    #[cfg(feature = "arbitrary")]
    use commonware_codec::conformance::generate_value;
    use commonware_codec::{Copying, Decode, DecodeExt, Encode};
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
    #[cfg(feature = "arbitrary")]
    use std::num::NonZeroUsize;
    type Event = DomainEvent<MinSig, Sha256Digest>;
    #[cfg(feature = "arbitrary")]
    type ConformanceArtifact<V> = Arc<Artifact<V, Sha256Digest>>;

    fn digest(label: &[u8]) -> Sha256Digest {
        Sha256::hash(&[label])
    }

    fn config(max_retired_effects: usize) -> DomainEventCodecConfig {
        DomainEventCodecConfig::new(
            CodecConfig::new(2, 2, PathLimits::new(2, 1).unwrap()).unwrap(),
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
            max_outbox: 16,
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

    fn entry(view: u64) -> OutboxEntry<MinSig, Sha256Digest> {
        OutboxEntry::new(
            Publication::broadcast(proof(view)),
            vec![Discharge::new(
                0,
                DischargeKind::ExitReplacedAfter {
                    view: View::new(view),
                },
            )],
        )
    }

    fn snapshot<V: Variant>(seed: u64) -> Snapshot<V, Sha256Digest> {
        let mut state =
            DurableState::new(vec![block(0, seed + 1), block(1, seed + 2)], Height::zero());
        state.cursor = Cursor(3);
        state.generation = Generation::new(seed + 1);
        state.signing_reservations.insert(
            EffectId(2),
            SignEffect::one(SignRequest::Nullify {
                round: Round::new(Epoch::new(7), View::new(seed + 1)),
            }),
        );
        Snapshot::new(Epoch::new(7), Role::Observer, state)
    }

    #[test]
    fn artifact_kind_rejects_out_of_range_tags() {
        for tag in 0..=9u8 {
            assert_eq!(
                ArtifactKind::try_from(tag).map(|kind| kind as u8).ok(),
                Some(tag)
            );
        }
        for tag in [10, u8::MAX] {
            assert!(matches!(
                ArtifactKind::try_from(tag),
                Err(Error::InvalidEnum(rejected)) if rejected == tag
            ));
        }
    }

    #[test]
    fn round_trips_changes_and_effects() {
        let events = [
            context(Change::GenerationAdvanced(Generation::new(9))),
            context(Change::FinalityFloorAdvanced {
                proof: proof(3),
                retired_signing: vec![EffectId(1)],
                retired_publications: vec![EffectId(2)],
            }),
            context(Change::OutboxQueued {
                id: EffectId(5),
                effect: Box::new(DurableEffect::sign(SignRequest::Nullify {
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
    fn round_trips_multi_da_sign_batch() {
        let requests = (0..3)
            .map(|seed| {
                let header = TransactionBlockHeader::new(
                    Epoch::new(7),
                    ChainId::new(seed % 2),
                    Height::new(seed as u64 + 1),
                    digest(b"batch parent"),
                    digest(&seed.to_be_bytes()),
                )
                .unwrap();
                let private = Private::new(Scalar::from_u64(seed as u64 + 1));
                let signature = sign_message::<MinSig>(
                    &private,
                    b"_COMMONWARE_CONSENSUS_MULTIMMIT_DURABILITY_CODEC_TEST_ATTESTATION",
                    &seed.to_be_bytes(),
                );
                SignRequest::DaVote(Arc::new(SignedTransactionBlock::new(
                    header,
                    Attestation::new(Participant::new(seed), signature.into()),
                )))
            })
            .collect::<Vec<_>>();
        let event = context(Change::OutboxQueued {
            id: EffectId(5),
            effect: Box::new(DurableEffect::Sign(SignEffect::new(requests.into()))),
        });

        assert_eq!(
            Event::decode_cfg(event.encode(), &config(4)).unwrap(),
            event
        );
    }

    #[test]
    fn profile_bounds_admit_a_full_da_vote_run_batch() {
        let committee = Committee::<MinSig>::builder(7, 1).build();
        let profile: Profile<Sha256Digest> =
            Profile::new::<MinSig>(committee.config, Role::Observer, Tuning::default()).unwrap();
        let chains = profile.codec().chains();
        let config = DomainEventCodecConfig::from_profile(&profile);
        assert_eq!(config.max_artifacts, chains * DA_VOTE_RUN);

        // Every chain contributes a full run: the largest batch the reducer can reserve.
        let requests = (0..chains * DA_VOTE_RUN)
            .map(|seed: usize| {
                let header = TransactionBlockHeader::new(
                    profile.protocol().epoch(),
                    ChainId::new((seed % chains) as u32),
                    Height::new((seed / chains) as u64 + 1),
                    digest(b"run parent"),
                    digest(&seed.to_be_bytes()),
                )
                .unwrap();
                let private = Private::new(Scalar::from_u64(seed as u64 + 1));
                let signature = sign_message::<MinSig>(
                    &private,
                    b"_COMMONWARE_CONSENSUS_MULTIMMIT_DURABILITY_CODEC_TEST_ATTESTATION",
                    &seed.to_be_bytes(),
                );
                SignRequest::DaVote(Arc::new(SignedTransactionBlock::new(
                    header,
                    Attestation::new(Participant::new((seed % chains) as u32), signature.into()),
                )))
            })
            .collect::<Vec<_>>();
        let event = Event::new(
            profile.protocol().epoch(),
            Cursor(3),
            Change::OutboxQueued {
                id: EffectId(5),
                effect: Box::new(DurableEffect::Sign(SignEffect::new(requests.into()))),
            },
        );
        assert_eq!(Event::decode_cfg(event.encode(), &config).unwrap(), event);
    }

    #[test]
    fn round_trips_outbox_entries_and_discharge_kinds() {
        let kinds = [
            DischargeKind::BlockCertifiedAtLeast {
                chain: ChainId::new(0),
                height: Height::new(3),
            },
            DischargeKind::VoteCertifiedAtLeast {
                chain: ChainId::new(1),
                height: Height::new(4),
            },
            DischargeKind::CertificateSupersededAbove {
                chain: ChainId::new(0),
                height: Height::new(5),
            },
            DischargeKind::ExitReplacedAfter { view: View::new(6) },
            DischargeKind::ViewRetired { view: View::new(7) },
        ];
        for (tag, until) in kinds.into_iter().enumerate() {
            let discharge = Discharge::new(u32::try_from(tag).unwrap(), until);
            let encoded = discharge.encode();
            assert_eq!(usize::from(encoded[discharge.item().encode_size()]), tag);
            assert_eq!(Discharge::decode(encoded).unwrap(), discharge);
        }

        let entry = entry(3);
        assert_eq!(
            OutboxEntry::decode_cfg(entry.encode(), &config(4)).unwrap(),
            entry
        );
    }

    #[test]
    fn rejects_unknown_tag_and_trailing_data() {
        let event = context(Change::GenerationAdvanced(Generation::new(9)));
        let mut unknown = event.encode().to_vec();
        let tag = DURABILITY_SCHEMA_VERSION.encode_size() + Epoch::new(7).encode_size() + 8;
        unknown[tag] = u8::MAX;
        assert!(matches!(
            Event::decode_cfg(unknown, &config(4)),
            Err(Error::InvalidEnum(u8::MAX))
        ));

        let mut trailing = event.encode().to_vec();
        trailing.push(0);
        assert!(matches!(
            Event::decode_cfg(trailing, &config(4)),
            Err(Error::ExtraData(1))
        ));

        let mut unsupported = event.encode().to_vec();
        unsupported[0] = u8::MAX;
        assert!(matches!(
            Event::decode_cfg(unsupported, &config(4)),
            Err(Error::InvalidEnum(u8::MAX))
        ));

        let mut unsupported_version = event.encode().to_vec();
        unsupported_version[0] = DURABILITY_SCHEMA_VERSION.wrapping_add(1);
        assert!(matches!(
            Event::decode_cfg(unsupported_version, &config(4)),
            Err(Error::InvalidEnum(version))
                if version == DURABILITY_SCHEMA_VERSION.wrapping_add(1)
        ));
    }

    #[test]
    fn rejects_other_durability_schema() {
        assert_eq!(DURABILITY_SCHEMA_VERSION, 0);
        for unsupported in [1, 2, u8::MAX] {
            let mut event = context(Change::GenerationAdvanced(Generation::new(9)))
                .encode()
                .to_vec();
            event[0] = unsupported;
            assert!(matches!(
                Event::decode_cfg(event, &config(4)),
                Err(Error::InvalidEnum(version)) if version == unsupported
            ));

            let mut snapshot = snapshot::<MinSig>(9).encode().to_vec();
            snapshot[0] = unsupported;
            assert!(matches!(
                Snapshot::<MinSig, Sha256Digest>::decode_cfg(
                    snapshot,
                    &snapshot_config()
                ),
                Err(Error::InvalidEnum(version)) if version == unsupported
            ));
        }
    }

    #[test]
    fn proposal_parent_tags_are_exhaustive() {
        let protocol = config(4).protocol;

        let mut genesis = Copying(&[0u8]);
        assert_eq!(
            ProposalParent::<Arc<Vqc<MinSig, Sha256Digest>>>::read_cfg(&mut genesis, &protocol,)
                .unwrap(),
            ProposalParent::Genesis
        );

        let mut exact_without_certificate = Copying(&[1u8]);
        assert!(matches!(
            ProposalParent::<Arc<Vqc<MinSig, Sha256Digest>>>::read_cfg(
                &mut exact_without_certificate,
                &protocol,
            ),
            Err(Error::EndOfBuffer)
        ));

        let mut unknown = Copying(&[2u8]);
        assert!(matches!(
            ProposalParent::<Arc<Vqc<MinSig, Sha256Digest>>>::read_cfg(&mut unknown, &protocol,),
            Err(Error::InvalidEnum(2))
        ));
    }

    #[test]
    fn rejects_bounded_vectors_before_allocating_items() {
        let event = context(Change::FinalityFloorAdvanced {
            proof: proof(3),
            retired_signing: vec![EffectId(1), EffectId(2)],
            retired_publications: Vec::new(),
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
            CodecConfig::new(2, 2, PathLimits::new(2, 1).unwrap()).unwrap(),
            1,
            2,
            max_retired,
        );
        let retired = (0..max_retired)
            .map(|offset| EffectId(u64::MAX - offset as u64))
            .collect::<Vec<_>>();
        let event = context(Change::ViewAdvanced {
            proof: ArtifactId::new(digest(b"retirement ceiling")),
            floor: View::new(u64::MAX),
            retired_publications: retired,
        });
        let encoded = event.encode();

        assert!(encoded.len() <= config.max_encoded_size());
        assert_eq!(Event::decode_cfg(encoded, &config).unwrap(), event);
    }

    #[test]
    fn change_and_effect_tags_are_dense() {
        let round = Round::new(Epoch::new(7), View::new(3));
        let changes = [
            Change::GenerationAdvanced(Generation::new(9)),
            Change::OutboxQueued {
                id: EffectId(5),
                effect: Box::new(DurableEffect::sign(SignRequest::Nullify { round })),
            },
            Change::SignedArtifacts {
                sign: EffectId(1),
                publication: EffectId(2),
                artifacts: vec![proof(3)].into(),
            },
            Change::ViewCertificateCreated { artifact: proof(3) },
            Change::ArtifactForwarded {
                publication: EffectId(2),
                retired_publications: Vec::new(),
                artifact: proof(3),
            },
            Change::ViewAdvanced {
                proof: ArtifactId::new(digest(b"exit")),
                floor: View::new(1),
                retired_publications: Vec::new(),
            },
            Change::FinalityFloorAdvanced {
                proof: proof(3),
                retired_signing: Vec::new(),
                retired_publications: Vec::new(),
            },
            Change::DaCertificateAdvanced {
                publication: None,
                retired_publications: Vec::new(),
                artifact: proof(3),
            },
        ];
        for (tag, change) in changes.iter().enumerate() {
            let encoded = change.encode();
            assert_eq!(usize::from(encoded[0]), tag);
            assert_eq!(&Change::decode_cfg(encoded, &config(4)).unwrap(), change);
        }
        let next = changes.len() as u8;
        assert!(matches!(
            Change::<MinSig, Sha256Digest>::decode_cfg(Copying(&[next]), &config(4)),
            Err(Error::InvalidEnum(tag)) if tag == next
        ));

        let effects = [
            DurableEffect::sign(SignRequest::Nullify { round }),
            DurableEffect::broadcast(proof(3)),
        ];
        for (tag, effect) in effects.into_iter().enumerate() {
            let encoded = effect.encode();
            assert_eq!(usize::from(encoded[0]), tag);
            assert_eq!(
                DurableEffect::<MinSig, Sha256Digest>::decode_cfg(encoded, &config(4)).unwrap(),
                effect
            );
        }
        assert!(matches!(
            DurableEffect::<MinSig, Sha256Digest>::decode_cfg(Copying(&[2]), &config(4)),
            Err(Error::InvalidEnum(2))
        ));

        // Propose (tag 1) needs a signed leader block and is covered by the conformance events.
        let publications = [
            (0, Publication::broadcast(proof(3))),
            (
                2,
                Publication::Send(Arc::from([SendRequest::new(Participant::new(1), proof(3))])),
            ),
        ];
        for (tag, publication) in publications {
            let encoded = publication.encode();
            assert_eq!(encoded[0], tag);
            assert_eq!(
                Publication::<MinSig, Sha256Digest>::decode_cfg(encoded, &config(4)).unwrap(),
                publication
            );
        }
        assert!(matches!(
            Publication::<MinSig, Sha256Digest>::decode_cfg(Copying(&[3]), &config(4)),
            Err(Error::InvalidEnum(3))
        ));
    }

    #[test]
    fn snapshot_round_trips_every_state_field() {
        let mut snapshot = snapshot::<MinSig>(9);
        snapshot.state.outbox.insert(EffectId(3), entry(3));
        snapshot
            .state
            .forwarded_nullifications
            .insert(View::new(1), proof(1));
        snapshot.state.exits.insert(View::new(1), proof(1));
        let encoded = snapshot.encode();
        assert_eq!(encoded[0], DURABILITY_SCHEMA_VERSION);
        assert_eq!(encoded.len(), snapshot.encode_size());

        let recovered = Snapshot::decode_cfg(encoded, &snapshot_config()).unwrap();
        assert_eq!(recovered, snapshot);
        assert!(matches!(
            recovered
                .state
                .signing_reservations
                .get(&EffectId(2))
                .map(SignEffect::requests),
            Some([SignRequest::Nullify { .. }])
        ));
        assert_eq!(recovered.outbox().get(&EffectId(3)), Some(&entry(3)));
    }

    #[test]
    fn outbox_entries_bound_discharges_by_publication_items() {
        let entry = entry(3);
        let discharge = entry.discharges()[0];
        let overfull = OutboxEntry::new(entry.publication().clone(), vec![discharge, discharge]);
        assert!(matches!(
            OutboxEntry::<MinSig, Sha256Digest>::decode_cfg(overfull.encode(), &config(4)),
            Err(Error::InvalidLength(2))
        ));
    }

    #[test]
    fn snapshot_bounds_reservations_and_publications_together() {
        let mut snapshot = snapshot::<MinSig>(9);
        snapshot.state.outbox.insert(EffectId(1), entry(3));
        let mut config = snapshot_config();
        config.max_outbox = 1;

        assert!(matches!(
            Snapshot::<MinSig, Sha256Digest>::decode_cfg(snapshot.encode(), &config),
            Err(Error::InvalidLength(1))
        ));
    }

    #[test]
    fn snapshot_rejects_trailing_bytes() {
        let mut encoded = snapshot::<MinSig>(9).encode().to_vec();
        encoded.push(0);
        assert!(matches!(
            Snapshot::<MinSig, Sha256Digest>::decode_cfg(encoded, &snapshot_config()),
            Err(Error::ExtraData(1))
        ));
    }

    #[test]
    fn snapshot_rejects_unsorted_maps() {
        let mut snapshot = snapshot::<MinSig>(9);
        let state = &mut snapshot.state;
        state.exits.insert(View::new(1), proof(1));
        state.exits.insert(View::new(2), proof(2));
        let encoded = snapshot.encode().to_vec();
        // Exits encode last: a length prefix, then two equal-size entries in ascending order.
        let entry = View::new(1).encode_size() + proof(1).encode_size();
        let second = encoded.len() - entry;
        let first = second - entry;
        let mut swapped = encoded[..first].to_vec();
        swapped.extend_from_slice(&encoded[second..]);
        swapped.extend_from_slice(&encoded[first..second]);
        assert!(matches!(
            Snapshot::<MinSig, Sha256Digest>::decode_cfg(swapped, &snapshot_config()),
            Err(Error::Invalid(_, "Keys must ascend"))
        ));
    }

    #[test]
    fn signing_choices_and_publications_reject_empty_batches() {
        for (tag, publication) in [(0u8, None), (1, Some(0u8)), (1, Some(2))] {
            // An empty list follows the effect tag, and the publication tag when there is one.
            let mut encoded = vec![tag];
            encoded.extend(publication);
            encoded.push(0);
            assert!(matches!(
                DurableEffect::<MinSig, Sha256Digest>::decode_cfg(encoded, &config(4)),
                Err(Error::InvalidLength(0))
            ));
        }
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
            1 => SignRequest::DaVote(Arc::new(generated(seed))),
            2 => SignRequest::LeaderBlock(ProposalRequest::new(
                generated(seed),
                conformance_parent(seed),
                seed.is_multiple_of(2),
            )),
            3 => SignRequest::Vote(generated(seed)),
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
            0..=5 => DurableEffect::sign(conformance_sign_request(lane)),
            6 => {
                let round = generated(seed);
                DurableEffect::Sign(SignEffect::new(
                    vec![
                        SignRequest::NoVote { round },
                        SignRequest::Nullify { round },
                    ]
                    .into(),
                ))
            }
            7 | 12 => DurableEffect::broadcast(conformance_artifact(seed, 7)),
            8 => {
                DurableEffect::Publish(Publication::Broadcast(conformance_timeout_artifacts(seed)))
            }
            9 => DurableEffect::Publish(Publication::Propose(ProposalPublication::new(
                Arc::new(generated(seed)),
                conformance_parent(seed),
                seed.is_multiple_of(2),
            ))),
            10 => DurableEffect::Publish(Publication::Send(Arc::from([SendRequest::new(
                Participant::new((seed % 6) as u32),
                conformance_artifact(seed, 1),
            )]))),
            11 => DurableEffect::Publish(Publication::Send(
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
            )),
            _ => unreachable!("outbox lane is reduced modulo the reachable set"),
        }
    }

    #[cfg(feature = "arbitrary")]
    impl<V: Variant> DomainEvent<V, Sha256Digest>
    where
        V::Signature: for<'a> Arbitrary<'a>,
    {
        pub(crate) fn conformance(seed: u64, cursor: Cursor) -> Self {
            let lane = seed / 8 % 13;
            let retired = || vec![EffectId(lane + 1), EffectId(lane + 2)];
            let change = match seed % 8 {
                0 => Change::GenerationAdvanced(Generation::new(seed)),
                1 => Change::OutboxQueued {
                    id: EffectId(seed + 1),
                    effect: Box::new(conformance_outbox_effect(seed, lane)),
                },
                2 => Change::SignedArtifacts {
                    sign: EffectId(seed + 1),
                    publication: EffectId(seed + 2),
                    artifacts: if lane.is_multiple_of(2) {
                        Arc::from([conformance_artifact(seed, lane % 7)])
                    } else {
                        conformance_timeout_artifacts(seed)
                    },
                },
                3 => Change::DaCertificateAdvanced {
                    publication: (!lane.is_multiple_of(2)).then_some(EffectId(seed + 1)),
                    retired_publications: retired(),
                    artifact: conformance_artifact(seed, 2),
                },
                4 => Change::ViewCertificateCreated {
                    artifact: conformance_artifact(seed, 7 + lane % 2),
                },
                5 => Change::ArtifactForwarded {
                    publication: EffectId(seed + 1),
                    retired_publications: retired(),
                    artifact: conformance_artifact(seed, 7 + lane % 2),
                },
                6 => Change::ViewAdvanced {
                    proof: ArtifactId::new(generated(seed)),
                    floor: View::new(seed),
                    retired_publications: retired(),
                },
                7 => Change::FinalityFloorAdvanced {
                    proof: conformance_artifact(seed, 9),
                    retired_signing: retired(),
                    retired_publications: vec![EffectId(seed + 3)],
                },
                _ => unreachable!("change arm is reduced modulo the complete union"),
            };
            Self::new(Epoch::new(7), cursor, change)
        }
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_protocol_config() -> CodecConfig {
        CodecConfig::new(6, 6, PathLimits::new(2, 2).unwrap()).unwrap()
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
            max_outbox: 16,
        }
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_profile(role: Role) -> Profile<Sha256Digest> {
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
        let protocol = Protocol::new(
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_CONFORMANCE",
            6,
            (0..6).map(Participant::new).collect(),
            PathLimits::new(2, 2).unwrap(),
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
        profile: &Profile<Sha256Digest>,
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
        profile: &Profile<Sha256Digest>,
    ) -> (ConformanceArtifact<V>, ConformanceArtifact<V>)
    where
        V::Signature: for<'a> Arbitrary<'a>,
    {
        let leader = conformance_leader(profile);
        let protocol = profile.codec();
        let vote = VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(&leader),
            vec![Position::new(0); protocol.chains()],
            (0..protocol.chains()).map(|_| Extension::empty()).collect(),
            protocol,
        )
        .unwrap();
        let tally = Tally::from_votes(
            DigestedLeader::new::<Sha256>(&leader),
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
        profile: &Profile<Sha256Digest>,
    ) -> Publication<V, Sha256Digest>
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
                Publication::broadcast(artifact)
            }
            1 => {
                // Only a chain's producer aggregates and broadcasts that chain's DA certificates.
                let chain = profile
                    .protocol()
                    .producer_chain(signer)
                    .expect("the DA certificate lane publishes as a producer");
                let header = conformance_header(seed, chain);
                let artifact = Arc::new(Artifact::DaCertificate(DaCertificate::new(
                    header,
                    ThresholdCertificate::new(generated::<V::Signature>(seed)),
                )));
                Publication::broadcast(artifact)
            }
            2 => {
                let artifact = Arc::new(Artifact::Nullification(
                    Nullification::new(
                        Round::new(Epoch::new(7), View::new(1)),
                        ThresholdCertificate::new(generated::<V::Signature>(seed)),
                    )
                    .unwrap(),
                ));
                Publication::broadcast(artifact)
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
                Publication::Broadcast(artifacts)
            }
            4 => {
                let block = conformance_leader(profile);
                let signed = Arc::new(SignedLeaderBlock::new(
                    block,
                    Attestation::new(signer, generated::<V::Signature>(seed).into()),
                ));
                Publication::Propose(ProposalPublication::new(
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
                Publication::Send(Arc::from([SendRequest::new(Participant::new(0), artifact)]))
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
                Publication::Send(requests.into())
            }
            _ => unreachable!("publication lane is reduced modulo the reachable set"),
        }
    }

    #[cfg(feature = "arbitrary")]
    fn conformance_snapshot<V: Variant>(
        seed: u64,
    ) -> (Profile<Sha256Digest>, Snapshot<V, Sha256Digest>)
    where
        V::Signature: for<'a> Arbitrary<'a>,
    {
        let lane = seed % 7;
        // Every publication lane binds its author. Only the transaction-block and nullification
        // lanes carry an artifact an observer may broadcast; the timeout, proposal, DA-certificate,
        // and DA-vote lanes each demand the validator identity that authorizes them.
        let role = if seed % 16 == 1 || lane == 4 {
            Role::Validator(Participant::new(1))
        } else if matches!(lane, 0 | 2) && seed.is_multiple_of(4) {
            Role::Observer
        } else {
            Role::Validator(Participant::new(0))
        };
        let profile = conformance_profile(role);
        let epoch = profile.protocol().epoch();
        let round = Round::new(epoch, View::new(1));
        let mut state =
            DurableState::new(profile.protocol().genesis().tips().to_vec(), Height::zero());
        state.generation = Generation::new(seed + 1);
        state.cursor = Cursor(8);

        match seed % 4 {
            1 => {
                state
                    .signing_reservations
                    .insert(EffectId(1), SignEffect::one(SignRequest::NoVote { round }));
                state
                    .signing_reservations
                    .insert(EffectId(2), SignEffect::one(SignRequest::Nullify { round }));
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
                state
                    .signing_reservations
                    .insert(EffectId(1), SignEffect::one(SignRequest::Vote(body)));
            }
            3 => {
                state.signing_reservations.insert(
                    EffectId(1),
                    SignEffect::new(
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
        let publication = conformance_publication(seed, &profile);
        let discharges = Machine::<Sha256, V>::new(profile.clone())
            .discharges(&publication)
            .unwrap();
        state
            .outbox
            .insert(EffectId(5), OutboxEntry::new(publication, discharges));

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

        let snapshot = Snapshot::new(epoch, role, state);
        snapshot.validate::<Sha256>(&profile).unwrap();
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
        decoded.validate::<Sha256>(&profile).unwrap();
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
    fn publication_arm<V: Variant>(publication: &Publication<V, Sha256Digest>) -> u8 {
        match publication {
            Publication::Broadcast(artifacts) if artifacts.len() == 1 => 1 << 2,
            Publication::Broadcast(_) => 1 << 3,
            Publication::Propose(_) => 1 << 4,
            Publication::Send(requests) if requests.len() == 1 => 1 << 5,
            Publication::Send(_) => 1 << 6,
        }
    }

    #[cfg(feature = "arbitrary")]
    fn sign_arms<V: Variant>(effect: &SignEffect<V, Sha256Digest>, requests: &mut u8) -> u8 {
        for request in effect.requests() {
            *requests |= sign_request_arm(request);
        }
        if effect.requests().len() == 1 {
            1
        } else {
            1 << 1
        }
    }

    #[cfg(feature = "arbitrary")]
    fn effect_arms<V: Variant>(effect: &DurableEffect<V, Sha256Digest>, requests: &mut u8) -> u8 {
        match effect {
            DurableEffect::Sign(effect) => sign_arms(effect, requests),
            DurableEffect::Publish(publication) => publication_arm(publication),
        }
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn generated_events_cover_every_reachable_union_arm() {
        let mut changes = 0u16;
        let mut effects = 0u8;
        let mut requests = 0u8;
        let mut signed = 0u8;
        let mut view_certificates = 0u16;
        let mut forwarded = 0u16;
        for seed in 0..128 {
            match DomainEvent::<MinPk, Sha256Digest>::conformance(seed, Cursor(seed + 1)).change() {
                Change::GenerationAdvanced(_) => changes |= 1 << 0,
                Change::OutboxQueued { effect, .. } => {
                    changes |= 1 << 1;
                    effects |= effect_arms(effect, &mut requests);
                }
                Change::SignedArtifacts { artifacts, .. } => {
                    changes |= 1 << 2;
                    signed |= if artifacts.len() == 1 { 1 } else { 1 << 1 };
                }
                Change::DaCertificateAdvanced { .. } => changes |= 1 << 3,
                Change::ViewCertificateCreated { artifact } => {
                    changes |= 1 << 4;
                    view_certificates |= artifact_arm(artifact);
                }
                Change::ArtifactForwarded { artifact, .. } => {
                    changes |= 1 << 5;
                    forwarded |= artifact_arm(artifact);
                }
                Change::ViewAdvanced { .. } => changes |= 1 << 6,
                Change::FinalityFloorAdvanced { .. } => changes |= 1 << 7,
            }
        }
        assert_eq!(changes, 0b1111_1111);
        assert_eq!(signed, 0b11);
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
                effects |= sign_arms(effect, &mut requests);
            }
            for entry in snapshot.state.outbox.values() {
                publication_kinds |= publication_arm(entry.publication()) >> 2;
                for discharge in entry.discharges() {
                    publication_discharges |= 1
                        << match discharge.until() {
                            DischargeKind::BlockCertifiedAtLeast { .. } => 0,
                            DischargeKind::VoteCertifiedAtLeast { .. } => 1,
                            DischargeKind::CertificateSupersededAbove { .. } => 2,
                            DischargeKind::ExitReplacedAfter { .. } => 3,
                            DischargeKind::ViewRetired { .. } => 4,
                        };
                }
                assert!(entry.consistent());
            }
            let view = snapshot.validate::<Sha256>(&profile).unwrap();
            for slot in view.slots.values() {
                stances |= 1
                    << match slot.stance {
                        ViewStance::Unchosen => 0,
                        ViewStance::Voted(_) => 1,
                        ViewStance::NoVoted => 2,
                    };
                nullifications |= 1 << u8::from(slot.nullified());
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
        }
        assert_eq!(roles, 0b11);
        assert_eq!(effects, 0b11);
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
