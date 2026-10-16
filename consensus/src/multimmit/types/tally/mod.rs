//! Compact, reversible transcripts of the `n - f` vote contents a quorum certificate signs.
//!
//! A tally names its signers by bitmap and stores one reference entry, the content of a
//! designated reference signer. Every other signer whose content differs carries a [`Deviation`]:
//! the fields and chain tips by which it differs. In the common case every voter endorses the same
//! tips, so a tally is a bitmap and one entry.
//!
//! A [`VoteTally`] (L-QC) holds votes for one leader block, final or not. A [`FinalTally`] (V-QC)
//! holds final votes of one view for any leader block or none, plus the [`ResolutionPath`]s that
//! connect tips above the V-QC's base down to the base height.
//!
//! The reference signer is the lowest signer whose entry is the most common, and every encoding
//! is the unique canonical transcript of its entries, so a certificate's identifier names its
//! content.

mod build;
#[cfg(test)]
mod tests;

use super::{
    BlockRef, ChainSet, Endorsement, Error, VoteContent,
    bounds::{
        block_ref_size, checked_sum, encoded_len, encoded_vec, max_index_width, signers_size,
    },
};
use crate::{
    multimmit::types::CodecConfig,
    types::{Attributable, Participant, Round},
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, certificate::Signers};

/// The per-signer part of a vote content that a tally records.
///
/// A [`VoteTally`] fixes the leader, so its entries leave it `None`; a [`FinalTally`] fixes
/// finality, so its entries are all final.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Entry<D: Digest> {
    pub(crate) leader: Option<D>,
    pub(crate) final_: bool,
    pub(crate) endorsement: Endorsement<D>,
}

/// Which certificate a tally belongs to, and so which entry fields it fixes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Kind {
    /// Votes for one leader block: the leader is fixed and finality varies.
    Vote,
    /// Final votes of one view: finality is fixed and the leader varies.
    Final,
}

const FLIP_FINAL: u8 = 1 << 0;
const DECLARED: u8 = 1 << 1;
const LEADER: u8 = 1 << 2;

/// How one signer's entry differs from a tally's reference entry.
///
/// Each present field differs from the reference: `leader` replaces the reference leader,
/// `flip_final` negates its finality, `declared` is the symmetric difference from the reference's
/// declared chains, and `tips` replaces the reference tips of the chains it names, in ascending
/// chain order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Deviation<D: Digest> {
    signer: Participant,
    leader: Option<Option<D>>,
    flip_final: bool,
    declared: Option<ChainSet>,
    tips: Vec<BlockRef<D>>,
}

impl<D: Digest> Deviation<D> {
    /// Returns the participant whose entry is described.
    pub const fn signer(&self) -> Participant {
        self.signer
    }

    /// Returns the signer's leader when it differs from the reference.
    pub const fn leader(&self) -> Option<Option<D>> {
        self.leader
    }

    /// Returns whether the signer's finality differs from the reference.
    pub const fn flips_final(&self) -> bool {
        self.flip_final
    }

    /// Returns the symmetric difference of the signer's declared chains from the reference.
    pub const fn declared(&self) -> Option<&ChainSet> {
        self.declared.as_ref()
    }

    /// Returns the tips that replace the reference tips, in ascending chain order.
    pub fn tips(&self) -> &[BlockRef<D>] {
        &self.tips
    }

    const fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.flip_final {
            flags |= FLIP_FINAL;
        }
        if self.declared.is_some() {
            flags |= DECLARED;
        }
        if self.leader.is_some() {
            flags |= LEADER;
        }
        flags
    }

    fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            max_index_width(codec.participants())?,
            1,
            1 + D::SIZE,
            ChainSet::encoded_size(codec.chains()),
            encoded_vec(codec.chains(), block_ref_size::<D>(codec)?)?,
        ])
    }
}

impl<D: Digest> Attributable for Deviation<D> {
    fn signer(&self) -> Participant {
        self.signer
    }
}

impl<D: Digest> Write for Deviation<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.signer.write(buf);
        self.flags().write(buf);
        if let Some(leader) = &self.leader {
            leader.write(buf);
        }
        if let Some(declared) = &self.declared {
            declared.write(buf);
        }
        self.tips.write(buf);
    }
}

impl<D: Digest> EncodeSize for Deviation<D> {
    fn encode_size(&self) -> usize {
        self.signer.encode_size()
            + 1
            + self.leader.as_ref().map_or(0, EncodeSize::encode_size)
            + self.declared.as_ref().map_or(0, EncodeSize::encode_size)
            + self.tips.encode_size()
    }
}

impl<D: Digest> Read for Deviation<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let signer = Participant::read(buf)?;
        let flags = u8::read(buf)?;
        if flags & !(FLIP_FINAL | DECLARED | LEADER) != 0 {
            return Err(CodecError::Invalid("Deviation", "unknown flags"));
        }
        let leader = (flags & LEADER != 0)
            .then(|| Option::<D>::read(buf))
            .transpose()?;
        let declared = (flags & DECLARED != 0)
            .then(|| ChainSet::read_cfg(buf, &config.chains()))
            .transpose()?;
        let tips = Vec::<BlockRef<D>>::read_cfg(buf, &(RangeCfg::from(0..=config.chains()), ()))?;
        Ok(Self {
            signer,
            leader,
            flip_final: flags & FLIP_FINAL != 0,
            declared,
            tips,
        })
    }
}

/// The signers, reference, and deviations shared by both tallies.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Core<D: Digest> {
    signers: Signers,
    reference_signer: Participant,
    reference: Entry<D>,
    deviations: Vec<Deviation<D>>,
}

impl<D: Digest> Core<D> {
    fn write(&self, kind: Kind, buf: &mut impl BufMut) {
        self.signers.write(buf);
        self.reference_signer.write(buf);
        match kind {
            Kind::Vote => self.reference.final_.write(buf),
            Kind::Final => self.reference.leader.write(buf),
        }
        self.reference.endorsement.write(buf);
        self.deviations.write(buf);
    }

    fn encode_size(&self, kind: Kind) -> usize {
        self.signers.encode_size()
            + self.reference_signer.encode_size()
            + match kind {
                Kind::Vote => self.reference.final_.encode_size(),
                Kind::Final => self.reference.leader.encode_size(),
            }
            + self.reference.endorsement.encode_size()
            + self.deviations.encode_size()
    }

    fn read(kind: Kind, buf: &mut impl Buf, config: CodecConfig) -> Result<Self, CodecError> {
        let signers = Signers::read_cfg(buf, &config.participants())?;
        let reference_signer = Participant::read(buf)?;
        let (leader, final_) = match kind {
            Kind::Vote => (None, bool::read(buf)?),
            Kind::Final => (Option::<D>::read(buf)?, true),
        };
        let endorsement = Endorsement::read_cfg(buf, &config)?;
        let deviations =
            Vec::<Deviation<D>>::read_cfg(buf, &(RangeCfg::from(0..config.view_quorum()), config))?;
        let core = Self {
            signers,
            reference_signer,
            reference: Entry {
                leader,
                final_,
                endorsement,
            },
            deviations,
        };
        core.validate(kind, config)
            .map_err(|error| CodecError::Wrapped("Tally", error.into()))?;
        Ok(core)
    }

    fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        let deviations = codec.view_quorum() - 1;
        checked_sum(&[
            signers_size(codec.participants())?,
            max_index_width(codec.participants())?,
            1 + D::SIZE,
            Endorsement::<D>::max_encode_size(codec)?,
            encoded_len(deviations)?,
            deviations.checked_mul(Deviation::<D>::max_encode_size(codec)?)?,
        ])
    }
}

/// The compact transcript of an L-QC: `n - f` votes for one leader block, final or not.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VoteTally<D: Digest>(Core<D>);

impl<D: Digest> VoteTally<D> {
    /// Returns the signers.
    pub const fn signers(&self) -> &Signers {
        &self.0.signers
    }

    /// Returns the signer whose content is the reference.
    pub const fn reference_signer(&self) -> Participant {
        self.0.reference_signer
    }

    /// Returns the deviations in signer order.
    pub fn deviations(&self) -> &[Deviation<D>] {
        &self.0.deviations
    }

    /// Rebuilds every signer's vote content for the leader block with digest `leader` in `round`,
    /// in signer order.
    pub fn contents(&self, round: Round, leader: D) -> Vec<(Participant, VoteContent<D>)> {
        self.0.contents(round, Some(leader))
    }

    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        Core::<D>::max_encode_size(codec)
    }
}

impl<D: Digest> Write for VoteTally<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(Kind::Vote, buf);
    }
}

impl<D: Digest> EncodeSize for VoteTally<D> {
    fn encode_size(&self) -> usize {
        self.0.encode_size(Kind::Vote)
    }
}

impl<D: Digest> Read for VoteTally<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        Core::read(Kind::Vote, buf, *config).map(Self)
    }
}

/// Payload hashes rebuilding the headers above one object at a V-QC's base height.
///
/// Header `k` (from one) is `(epoch, chain, from.height + k, parent, payloads[k - 1])`, where the
/// parent of the first is `from` and of every later header is the one below it. A V-QC records a
/// path for every tip above its base, and a tip endorses window blocks only when its path starts
/// at the base itself.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolutionPath<D: Digest> {
    from: BlockRef<D>,
    payloads: Vec<D>,
}

impl<D: Digest> ResolutionPath<D> {
    /// Creates a path of at least one and at most `D + 2N` headers above `from`.
    pub fn new(from: BlockRef<D>, payloads: Vec<D>, config: CodecConfig) -> Result<Self, Error> {
        let path = Self { from, payloads };
        path.validate(config)?;
        Ok(path)
    }

    const fn validate(&self, config: CodecConfig) -> Result<(), Error> {
        if self.from.chain().index() >= config.chains() {
            return Err(Error::Chain);
        }
        if self.payloads.is_empty() || self.payloads.len() > config.window().max_tip_lead() as usize
        {
            return Err(Error::Window);
        }
        if self
            .from
            .height()
            .get()
            .checked_add(self.payloads.len() as u64)
            .is_none()
        {
            return Err(Error::HeightOverflow);
        }
        Ok(())
    }

    /// Returns the object at the base height the path starts from.
    pub const fn from(&self) -> BlockRef<D> {
        self.from
    }

    /// Returns the body digests of the rebuilt headers, lowest first.
    pub fn payloads(&self) -> &[D] {
        &self.payloads
    }
}

impl<D: Digest> Write for ResolutionPath<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.from.write(buf);
        self.payloads.write(buf);
    }
}

impl<D: Digest> EncodeSize for ResolutionPath<D> {
    fn encode_size(&self) -> usize {
        self.from.encode_size() + self.payloads.encode_size()
    }
}

impl<D: Digest> Read for ResolutionPath<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let from = BlockRef::read(buf)?;
        let bound = RangeCfg::from(1..=config.window().max_tip_lead() as usize);
        let payloads = Vec::<D>::read_cfg(buf, &(bound, ()))?;
        Self::new(from, payloads, *config)
            .map_err(|error| CodecError::Wrapped("ResolutionPath", error.into()))
    }
}

/// The compact transcript of a V-QC: `n - f` final votes of one view, with the resolution paths
/// of tips above the base.
///
/// Decoding checks the transcript is canonical. Whether the paths resolve every tip above the
/// base, and nothing else, depends on the base, which the V-QC's parent chain fixes; the machine
/// checks it when admitting the V-QC.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FinalTally<D: Digest> {
    core: Core<D>,
    paths: Vec<ResolutionPath<D>>,
}

impl<D: Digest> FinalTally<D> {
    /// Returns the signers.
    pub const fn signers(&self) -> &Signers {
        &self.core.signers
    }

    /// Returns the signer whose content is the reference.
    pub const fn reference_signer(&self) -> Participant {
        self.core.reference_signer
    }

    /// Returns the deviations in signer order.
    pub fn deviations(&self) -> &[Deviation<D>] {
        &self.core.deviations
    }

    /// Returns the resolution paths in ascending order.
    pub fn paths(&self) -> &[ResolutionPath<D>] {
        &self.paths
    }

    /// Rebuilds every signer's final vote content in `round`, in signer order.
    pub fn contents(&self, round: Round) -> Vec<(Participant, VoteContent<D>)> {
        self.core.contents(round, None)
    }

    fn validate_paths(&self, config: CodecConfig) -> Result<(), Error> {
        if self.paths.len() > max_paths(config) {
            return Err(Error::Window);
        }
        if self.paths.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::Transcript);
        }
        self.paths.iter().try_for_each(|path| path.validate(config))
    }
}

/// Returns the most resolution paths one V-QC may carry: one per recorded tip.
fn max_paths(config: CodecConfig) -> usize {
    config.view_quorum().saturating_mul(config.chains())
}

impl<D: Digest> Write for FinalTally<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.core.write(Kind::Final, buf);
        self.paths.write(buf);
    }
}

impl<D: Digest> EncodeSize for FinalTally<D> {
    fn encode_size(&self) -> usize {
        self.core.encode_size(Kind::Final) + self.paths.encode_size()
    }
}

impl<D: Digest> Read for FinalTally<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let core = Core::read(Kind::Final, buf, *config)?;
        let paths = Vec::<ResolutionPath<D>>::read_cfg(
            buf,
            &(RangeCfg::from(0..=max_paths(*config)), *config),
        )?;
        let tally = Self { core, paths };
        tally
            .validate_paths(*config)
            .map_err(|error| CodecError::Wrapped("FinalTally", error.into()))?;
        Ok(tally)
    }
}
