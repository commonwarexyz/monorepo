//! Encoding for Multimmit's durable snapshot and journal events.
//!
//! A [`Snapshot`] encodes as the schema version, epoch, role, and every durable state field. A
//! [`DomainEvent`] encodes as the schema version, epoch, cursor, and change. Every value is
//! self-delimiting and bounded by its decoding config before anything is allocated, so the journal
//! record frame is the only length prefix.

use super::{
    Acceptance, BatchId, Change, Cursor, DURABILITY_SCHEMA_VERSION, Discharge, DischargeKind,
    DomainEvent, DurableEffect, DurableState, EffectId, Emission, OutboxEntry, Proposal,
    ProposalParent, Publication, RetentionRoot, SignEffect, SignRequest, Snapshot, UpdateRequest,
    VoteWatermark,
};
use crate::{
    multimmit::{
        config::{Profile, Role},
        machine::job::Generation,
        types::{
            Artifact, ArtifactBatch, ArtifactId, ArtifactKind, CertificateId, ChainChange, ChainId,
            ChainSet, CodecConfig, Floor, HistoryRecord, Lqc, Resolution, SignedLeaderBlock,
            SignedTransactionBlock, TransactionBlockHeader, VoteContent, VoteUpdate, Vqc,
            each_artifact,
        },
    },
    types::{Epoch, Height, Participant, View},
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Most artifacts one publication batch carries.
///
/// A signing choice signs one subject and a forwarded certificate travels alone, so a batch stays
/// far below this bound.
pub(crate) const MAX_BATCH_ARTIFACTS: usize = 16;

/// Ceiling on the bytes one artifact adds beyond its canonical encoding inside a change: its kind
/// tag, an acceptance flag, and a length prefix.
const ARTIFACT_OVERHEAD_BYTES: usize = 16;

/// Most retirement lists one change carries: a retention advance retires signing requests and
/// publications.
const RETIREMENT_LISTS: usize = 2;

/// Ceiling on a change's tag, identifiers, digests, resolution, and list length prefixes.
const CHANGE_FIXED_BYTES: usize = 256;

/// Ceiling on an event's schema version, epoch, and cursor.
const EVENT_HEADER_BYTES: usize = 64;

/// Ceiling on one encoded chain reference beyond its digest: a chain index and a height varint.
const BLOCK_REF_OVERHEAD_BYTES: usize = 16;

/// Bounds used to decode one self-contained safety-journal event.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DomainEventCodecConfig {
    protocol: CodecConfig,
    max_artifact_bytes: usize,
    max_retired_effects: usize,
    max_accepted: usize,
    max_ancestors: usize,
}

impl DomainEventCodecConfig {
    /// Derives journal decoding bounds from the immutable machine profile.
    ///
    /// One acceptance batch holds at most every chain's tip-lead window. The ancestors a view
    /// entry retains become durable artifact references, so the artifact cache bounds them.
    pub(crate) fn from_profile<D: Digest>(profile: &Profile<D>) -> Self {
        let resources = profile.resources();
        let window = usize::try_from(profile.height_window()).unwrap_or(usize::MAX);
        Self {
            protocol: profile.codec(),
            max_artifact_bytes: resources.max_artifact_bytes(),
            max_retired_effects: resources.max_outbox_effects(),
            max_accepted: profile.codec().chains().saturating_mul(window).max(1),
            max_ancestors: resources.max_cached_artifacts(),
        }
    }

    /// Returns the bounds of an event whose artifacts encode in at most `max_artifact_bytes`,
    /// retiring at most `max_retired_effects` effects, accepting at most `max_accepted` headers,
    /// and retaining at most `max_ancestors` entry-chain ancestors.
    #[cfg(test)]
    pub(crate) const fn new(
        protocol: CodecConfig,
        max_artifact_bytes: usize,
        max_retired_effects: usize,
        max_accepted: usize,
        max_ancestors: usize,
    ) -> Self {
        Self {
            protocol,
            max_artifact_bytes,
            max_retired_effects,
            max_accepted,
            max_ancestors,
        }
    }

    /// Returns a conservative payload ceiling for one change accepted by this codec.
    fn max_change_size<D: Digest>(self) -> usize {
        let artifact = self
            .max_artifact_bytes
            .saturating_add(ARTIFACT_OVERHEAD_BYTES);
        let artifacts = artifact.saturating_mul(
            MAX_BATCH_ARTIFACTS
                .max(self.max_accepted)
                .max(self.max_ancestors),
        );
        let retirements = u64::MAX
            .encode_size()
            .saturating_mul(self.max_retired_effects)
            .saturating_mul(RETIREMENT_LISTS);
        let base = D::SIZE
            .saturating_add(BLOCK_REF_OVERHEAD_BYTES)
            .saturating_mul(self.protocol.chains());
        artifacts
            .saturating_add(retirements)
            .saturating_add(base)
            .saturating_add(CHANGE_FIXED_BYTES)
    }

    /// Returns a conservative encoded ceiling for one event accepted by this codec.
    pub(crate) fn max_encoded_size<D: Digest>(self) -> usize {
        self.max_change_size::<D>()
            .saturating_add(EVENT_HEADER_BYTES)
    }

    /// Returns the bound for one retired-effect list.
    fn retired_cfg(self) -> (RangeCfg<usize>, ()) {
        (RangeCfg::from(0..=self.max_retired_effects), ())
    }

    /// Returns the bound for a non-empty batch of artifacts or signing requests.
    fn batch_cfg(self) -> (RangeCfg<usize>, Self) {
        (RangeCfg::from(1..=MAX_BATCH_ARTIFACTS), self)
    }

    /// Returns the bound for one vector holding exactly one entry per chain.
    const fn per_chain_cfg(self) -> (RangeCfg<usize>, ()) {
        (RangeCfg::exact(self.protocol.chains()), ())
    }
}

/// Bounds used to decode one acknowledged machine snapshot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct SnapshotCodecConfig {
    event: DomainEventCodecConfig,
    max_artifacts: usize,
    max_outbox: usize,
    max_forwarded: usize,
}

impl SnapshotCodecConfig {
    /// Derives snapshot decoding bounds from the immutable machine profile.
    ///
    /// Every per-view map and every chain's accepted headers retain artifacts in the artifact
    /// cache, so the cache capacity bounds each of them.
    pub(crate) fn from_profile<D: Digest>(profile: &Profile<D>) -> Self {
        let resources = profile.resources();
        Self {
            event: DomainEventCodecConfig::from_profile(profile),
            max_artifacts: resources.max_cached_artifacts(),
            max_outbox: resources.max_outbox_effects(),
            max_forwarded: resources.max_forwarded_certificates(),
        }
    }

    /// Returns the bounds of a snapshot.
    #[cfg(test)]
    pub(crate) const fn new(
        event: DomainEventCodecConfig,
        max_artifacts: usize,
        max_outbox: usize,
        max_forwarded: usize,
    ) -> Self {
        Self {
            event,
            max_artifacts,
            max_outbox,
            max_forwarded,
        }
    }

    /// Returns the bound for one retained-artifact map or per-view map.
    fn map_cfg<K, V>(self, key: K, value: V) -> (RangeCfg<usize>, (K, V)) {
        (RangeCfg::from(0..=self.max_artifacts), (key, value))
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
            Self::Accepted { blocks } => {
                3u8.write(buf);
                blocks.write(buf);
            }
            Self::EmissionResolved { view, record, by } => {
                4u8.write(buf);
                view.write(buf);
                record.write(buf);
                by.write(buf);
            }
            Self::ArtifactForwarded {
                publication,
                artifact,
            } => {
                5u8.write(buf);
                publication.write(buf);
                artifact.write(buf);
            }
            Self::ViewEntered {
                proof,
                ancestors,
                retired_publications,
            } => {
                6u8.write(buf);
                proof.write(buf);
                ancestors.write(buf);
                retired_publications.write(buf);
            }
            Self::CertificateCreated { artifact } => {
                7u8.write(buf);
                artifact.write(buf);
            }
            Self::RetentionAdvanced {
                floor,
                root,
                retired_signing,
                retired_publications,
            } => {
                8u8.write(buf);
                floor.write(buf);
                root.write(buf);
                retired_signing.write(buf);
                retired_publications.write(buf);
            }
            Self::Anchored {
                floor,
                retired_signing,
                retired_publications,
            } => {
                9u8.write(buf);
                floor.write(buf);
                retired_signing.write(buf);
                retired_publications.write(buf);
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
            3 => Self::Accepted {
                blocks: Vec::read_cfg(buf, &(RangeCfg::from(1..=config.max_accepted), ()))?,
            },
            4 => Self::EmissionResolved {
                view: View::read(buf)?,
                record: HistoryRecord::read_cfg(buf, &config.protocol)?,
                by: Resolution::read(buf)?,
            },
            5 => Self::ArtifactForwarded {
                publication: EffectId::read(buf)?,
                artifact: Arc::read_cfg(buf, config)?,
            },
            6 => Self::ViewEntered {
                proof: ArtifactId::read(buf)?,
                ancestors: Vec::read_cfg(
                    buf,
                    &(RangeCfg::from(0..=config.max_ancestors), *config),
                )?,
                retired_publications: Vec::read_cfg(buf, &config.retired_cfg())?,
            },
            7 => Self::CertificateCreated {
                artifact: Arc::read_cfg(buf, config)?,
            },
            8 => Self::RetentionAdvanced {
                floor: View::read(buf)?,
                root: RetentionRoot::read_cfg(buf, config)?,
                retired_signing: Vec::read_cfg(buf, &config.retired_cfg())?,
                retired_publications: Vec::read_cfg(buf, &config.retired_cfg())?,
            },
            9 => Self::Anchored {
                floor: Arc::read_cfg(buf, config)?,
                retired_signing: Vec::read_cfg(buf, &config.retired_cfg())?,
                retired_publications: Vec::read_cfg(buf, &config.retired_cfg())?,
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
            Self::Accepted { blocks } => blocks.encode_size(),
            Self::EmissionResolved { view, record, by } => {
                view.encode_size() + record.encode_size() + by.encode_size()
            }
            Self::ArtifactForwarded {
                publication,
                artifact,
            } => publication.encode_size() + artifact.encode_size(),
            Self::ViewEntered {
                proof,
                ancestors,
                retired_publications,
            } => proof.encode_size() + ancestors.encode_size() + retired_publications.encode_size(),
            Self::CertificateCreated { artifact } => artifact.encode_size(),
            Self::RetentionAdvanced {
                floor,
                root,
                retired_signing,
                retired_publications,
            } => {
                floor.encode_size()
                    + root.encode_size()
                    + retired_signing.encode_size()
                    + retired_publications.encode_size()
            }
            Self::Anchored {
                floor,
                retired_signing,
                retired_publications,
            } => {
                floor.encode_size()
                    + retired_signing.encode_size()
                    + retired_publications.encode_size()
            }
        }
    }
}

impl<V: Variant, D: Digest> Write for Acceptance<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Full(block) => {
                0u8.write(buf);
                block.write(buf);
            }
            Self::Adopted(header) => {
                1u8.write(buf);
                header.write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> Read for Acceptance<V, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Full(Arc::<SignedTransactionBlock<V, D>>::read(buf)?)),
            1 => Ok(Self::Adopted(TransactionBlockHeader::read(buf)?)),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for Acceptance<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Full(block) => block.encode_size(),
            Self::Adopted(header) => header.encode_size(),
        }
    }
}

impl<D: Digest> Write for Resolution<D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Determined => 0u8.write(buf),
            Self::Pinned { view, lqc } => {
                1u8.write(buf);
                view.write(buf);
                lqc.write(buf);
            }
        }
    }
}

impl<D: Digest> Read for Resolution<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Determined),
            1 => Ok(Self::Pinned {
                view: View::read(buf)?,
                lqc: CertificateId::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<D: Digest> EncodeSize for Resolution<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Determined => 0,
            Self::Pinned { view, lqc } => view.encode_size() + lqc.encode_size(),
        }
    }
}

impl<D: Digest> Write for Emission<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.record.write(buf);
        self.by.write(buf);
    }
}

impl<D: Digest> Read for Emission<D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            record: HistoryRecord::read_cfg(buf, &config.protocol)?,
            by: Resolution::read(buf)?,
        })
    }
}

impl<D: Digest> EncodeSize for Emission<D> {
    fn encode_size(&self) -> usize {
        self.record.encode_size() + self.by.encode_size()
    }
}

impl<D: Digest> Write for RetentionRoot<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.vqc.write(buf);
        self.record.write(buf);
    }
}

impl<D: Digest> Read for RetentionRoot<D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            vqc: CertificateId::read(buf)?,
            record: HistoryRecord::read_cfg(buf, &config.protocol)?,
        })
    }
}

impl<D: Digest> EncodeSize for RetentionRoot<D> {
    fn encode_size(&self) -> usize {
        self.vqc.encode_size() + self.record.encode_size()
    }
}

impl<D: Digest> Write for VoteWatermark<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.seq.write(buf);
        self.tips.write(buf);
        self.declared.write(buf);
        self.declared_at.write(buf);
        self.final_content.write(buf);
    }
}

impl<D: Digest> Read for VoteWatermark<D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        let seq = u32::read(buf)?;
        let tips = Vec::read_cfg(buf, &config.per_chain_cfg())?;
        let declared = ChainSet::read_cfg(buf, &config.protocol.chains())?;
        // One declaration height per declared chain.
        let declared_at = Vec::read_cfg(buf, &(RangeCfg::exact(declared.len()), ()))?;
        let final_content = Option::<VoteContent<D>>::read_cfg(buf, &config.protocol)?;
        Ok(Self {
            seq,
            tips,
            declared,
            declared_at,
            final_content,
        })
    }
}

impl<D: Digest> EncodeSize for VoteWatermark<D> {
    fn encode_size(&self) -> usize {
        self.seq.encode_size()
            + self.tips.encode_size()
            + self.declared.encode_size()
            + self.declared_at.encode_size()
            + self.final_content.encode_size()
    }
}

impl Write for DischargeKind {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::HeaderBelowHstar { chain, height } => {
                0u8.write(buf);
                chain.write(buf);
                height.write(buf);
            }
            Self::UpdateSuperseded { view, seq } => {
                1u8.write(buf);
                view.write(buf);
                seq.write(buf);
            }
            Self::ExitReplacedAfter { view } => {
                2u8.write(buf);
                view.write(buf);
            }
            Self::ViewUnread { view } => {
                3u8.write(buf);
                view.write(buf);
            }
        }
    }
}

impl Read for DischargeKind {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::HeaderBelowHstar {
                chain: ChainId::read(buf)?,
                height: Height::read(buf)?,
            }),
            1 => Ok(Self::UpdateSuperseded {
                view: View::read(buf)?,
                seq: u32::read(buf)?,
            }),
            2 => Ok(Self::ExitReplacedAfter {
                view: View::read(buf)?,
            }),
            3 => Ok(Self::ViewUnread {
                view: View::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for DischargeKind {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::HeaderBelowHstar { chain, height } => chain.encode_size() + height.encode_size(),
            Self::UpdateSuperseded { view, seq } => view.encode_size() + seq.encode_size(),
            Self::ExitReplacedAfter { view } | Self::ViewUnread { view } => view.encode_size(),
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
        let items = publication.items();
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
        }
    }
}

impl<V: Variant, D: Digest> Read for Publication<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Broadcast(read_batch(buf, config)?)),
            1 => Ok(Self::Propose(Proposal::read_cfg(buf, &config.protocol)?)),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for Publication<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Broadcast(artifacts) => artifacts.as_ref().encode_size(),
            Self::Propose(publication) => publication.encode_size(),
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

impl<V: Variant, D: Digest, B: Read<Cfg = ()>> Read for Proposal<V, D, B> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self::new(
            B::read(buf)?,
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

impl<D: Digest> Write for UpdateRequest<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.content.write(buf);
        self.seq.write(buf);
        self.changes.write(buf);
    }
}

impl<D: Digest> Read for UpdateRequest<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self::new(
            VoteContent::read_cfg(buf, config)?,
            u32::read(buf)?,
            Vec::<ChainChange<D>>::read_cfg(buf, &(RangeCfg::from(0..=config.chains()), *config))?,
        ))
    }
}

impl<D: Digest> EncodeSize for UpdateRequest<D> {
    fn encode_size(&self) -> usize {
        self.content.encode_size() + self.seq.encode_size() + self.changes.encode_size()
    }
}

impl<V: Variant, D: Digest> Write for SignRequest<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::TransactionBlock(header) => {
                0u8.write(buf);
                header.write(buf);
            }
            Self::LeaderBlock(request) => {
                1u8.write(buf);
                request.write(buf);
            }
            Self::Update(request) => {
                2u8.write(buf);
                request.write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> Read for SignRequest<V, D> {
    type Cfg = DomainEventCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::TransactionBlock(TransactionBlockHeader::read(buf)?)),
            1 => Ok(Self::LeaderBlock(Proposal::read_cfg(
                buf,
                &config.protocol,
            )?)),
            2 => Ok(Self::Update(UpdateRequest::read_cfg(
                buf,
                &config.protocol,
            )?)),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for SignRequest<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::TransactionBlock(header) => header.encode_size(),
            Self::LeaderBlock(request) => request.encode_size(),
            Self::Update(request) => request.encode_size(),
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
            ArtifactKind::LeaderBlock => Self::LeaderBlock(SignedLeaderBlock::read(buf)?),
            ArtifactKind::Update => Self::Update(VoteUpdate::read_cfg(buf, protocol)?),
            ArtifactKind::Vqc => Self::Vqc(Vqc::read_cfg(buf, protocol)?),
            ArtifactKind::Lqc => Self::Lqc(Lqc::read_cfg(buf, protocol)?),
            ArtifactKind::Floor => Self::Floor(Floor::read_cfg(buf, protocol)?),
        };
        if artifact.encoded_len() > config.max_artifact_bytes {
            return Err(Error::Invalid(
                "Artifact",
                "exceeds the artifact byte ceiling",
            ));
        }
        Ok(artifact)
    }
}

impl<V: Variant, D: Digest> EncodeSize for Artifact<V, D> {
    fn encode_size(&self) -> usize {
        1 + self.encoded_len()
    }
}

/// Implements the codec of an identifier that encodes as its `u64` value.
macro_rules! u64_codec {
    ($($id:ty),* $(,)?) => {$(
        impl Write for $id {
            fn write(&self, buf: &mut impl BufMut) {
                self.get().write(buf);
            }
        }

        impl Read for $id {
            type Cfg = ();

            fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
                Ok(Self::new(u64::read(buf)?))
            }
        }

        impl EncodeSize for $id {
            fn encode_size(&self) -> usize {
                self.get().encode_size()
            }
        }
    )*};
}

u64_codec!(Generation, Cursor, BatchId, EffectId);

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
        self.generation.write(buf);
        self.cursor.write(buf);
        self.retired_view.write(buf);
        self.root.write(buf);
        self.accepted.write(buf);
        self.origin.write(buf);
        self.produced.write(buf);
        self.leader_blocks.write(buf);
        self.notarised.write(buf);
        self.watermark.write(buf);
        self.last_final.0.write(buf);
        self.last_final.1.write(buf);
        self.anchored_tag.write(buf);
        self.emission.write(buf);
        self.local.write(buf);
        self.signing_reservations.write(buf);
        self.outbox.write(buf);
        self.forwarded_vqcs.write(buf);
        self.exits.write(buf);
        self.ancestors.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for DurableState<V, D> {
    type Cfg = SnapshotCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        let event = config.event;
        let view = View::read(buf)?;
        let generation = Generation::read(buf)?;
        let cursor = Cursor::read(buf)?;
        let retired_view = View::read(buf)?;
        let root = Option::<RetentionRoot<D>>::read_cfg(buf, &event)?;
        let accepted = Vec::read_cfg(
            buf,
            &(
                RangeCfg::exact(event.protocol.chains()),
                config.map_cfg((), ()),
            ),
        )?;
        let origin = Vec::read_cfg(buf, &event.per_chain_cfg())?;
        let produced = Height::read(buf)?;
        let leader_blocks = BTreeMap::read_cfg(buf, &config.map_cfg((), ((), ())))?;
        let notarised = BTreeMap::read_cfg(buf, &config.map_cfg((), ()))?;
        let watermark = BTreeMap::read_cfg(buf, &config.map_cfg((), event))?;
        let last_final = (
            View::read(buf)?,
            Vec::read_cfg(buf, &event.per_chain_cfg())?,
        );
        let anchored_tag = Option::<View>::read(buf)?;
        let emission = BTreeMap::read_cfg(buf, &config.map_cfg((), event))?;
        let local = BTreeMap::read_cfg(buf, &config.map_cfg((), event))?;
        // Signing reservations and publications share one outbox bound.
        let signing_reservations: BTreeMap<_, _> =
            BTreeMap::read_cfg(buf, &(RangeCfg::from(0..=config.max_outbox), ((), event)))?;
        let outbox = BTreeMap::read_cfg(
            buf,
            &(
                RangeCfg::from(0..=config.max_outbox - signing_reservations.len()),
                ((), event),
            ),
        )?;
        let forwarded_vqcs = BTreeMap::<View, BTreeSet<CertificateId<D>>>::read_cfg(
            buf,
            &(
                RangeCfg::from(0..=config.max_forwarded),
                ((), (RangeCfg::from(1..=config.max_forwarded), ())),
            ),
        )?;
        if forwarded_vqcs.values().map(BTreeSet::len).sum::<usize>() > config.max_forwarded {
            return Err(Error::Invalid(
                "DurableState",
                "forwarded certificates exceed their bound",
            ));
        }
        let exits = BTreeMap::read_cfg(buf, &config.map_cfg((), event))?;
        let ancestors = BTreeMap::read_cfg(buf, &config.map_cfg((), event))?;
        Ok(Self {
            view,
            generation,
            cursor,
            retired_view,
            root,
            accepted,
            origin,
            produced,
            leader_blocks,
            notarised,
            watermark,
            last_final,
            anchored_tag,
            emission,
            local,
            signing_reservations,
            outbox,
            forwarded_vqcs,
            exits,
            ancestors,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for DurableState<V, D> {
    fn encode_size(&self) -> usize {
        self.view.encode_size()
            + self.generation.encode_size()
            + self.cursor.encode_size()
            + self.retired_view.encode_size()
            + self.root.encode_size()
            + self.accepted.encode_size()
            + self.origin.encode_size()
            + self.produced.encode_size()
            + self.leader_blocks.encode_size()
            + self.notarised.encode_size()
            + self.watermark.encode_size()
            + self.last_final.0.encode_size()
            + self.last_final.1.encode_size()
            + self.anchored_tag.encode_size()
            + self.emission.encode_size()
            + self.local.encode_size()
            + self.signing_reservations.encode_size()
            + self.outbox.encode_size()
            + self.forwarded_vqcs.encode_size()
            + self.exits.encode_size()
            + self.ancestors.encode_size()
    }
}

#[cfg(test)]
mod tests;
