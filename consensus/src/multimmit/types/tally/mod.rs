//! Compact, reversible vote transcripts used by Multimmit quorum certificates.
//!
//! A [`Tally`] represents every vote for one leader block by a signer bit. Votes at every
//! proposal tip that carry the tally's reference extensions need nothing more; any other vote
//! carries a [`Deviation`] naming its lower positions and replacement extensions.
//!
//! `compress` builds the canonical tally from expanded votes, and `expand` reconstructs each
//! signer's vote and checks that a decoded tally is canonical.

mod compress;
mod expand;
#[cfg(test)]
mod tests;

use super::{
    Ballot, ChainId, Error, Extension, Position, VoteBody,
    bounds::{
        checked_product, checked_sum, encoded_index_sum, encoded_len, encoded_vec,
        largest_index_width_sum, signers_size,
    },
};
use crate::{
    multimmit::types::{CodecConfig, LeaderBlock},
    types::{Attributable, Round},
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{
    Digest, bls12381::primitives::variant::Variant, certificate::Signers,
};
use commonware_utils::Participant;
use core::num::NonZeroUsize;

/// One non-standard position in a compact vote tally.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PositionDeviation {
    chain: ChainId,
    position: Position,
}

impl PositionDeviation {
    /// Creates a position deviation for `chain`.
    pub const fn new(chain: ChainId, position: Position) -> Self {
        Self { chain, position }
    }

    /// Returns the affected chain.
    pub const fn chain(&self) -> ChainId {
        self.chain
    }

    /// Returns the reported position.
    pub const fn position(&self) -> Position {
        self.position
    }
}

impl Write for PositionDeviation {
    fn write(&self, writer: &mut impl BufMut) {
        self.chain.write(writer);
        self.position.write(writer);
    }
}

impl Read for PositionDeviation {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            chain: ReadExt::read(reader)?,
            position: ReadExt::read(reader)?,
        })
    }
}

impl EncodeSize for PositionDeviation {
    fn encode_size(&self) -> usize {
        self.chain.encode_size() + self.position.encode_size()
    }
}

/// One chain's replacement for a tally's reference extension.
///
/// A replacement either clears the chain's extension or names one of the tally's extension
/// paths by one-based index. The encoding writes a cleared chain as index zero.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExtensionDeviation {
    chain: ChainId,
    extension: Option<NonZeroUsize>,
}

impl ExtensionDeviation {
    /// Creates an extension replacement for `chain`: `None` clears the chain, and `Some(index)`
    /// selects the one-based extension path `index`.
    pub const fn new(chain: ChainId, extension: Option<NonZeroUsize>) -> Self {
        Self { chain, extension }
    }

    /// Returns the affected chain.
    pub const fn chain(&self) -> ChainId {
        self.chain
    }

    /// Returns the one-based replacement path index, or `None` when this chain is cleared.
    pub const fn extension(&self) -> Option<NonZeroUsize> {
        self.extension
    }

    /// Returns the encoded path index, where zero clears the chain.
    fn encoded_extension(&self) -> usize {
        self.extension.map_or(0, NonZeroUsize::get)
    }
}

impl Write for ExtensionDeviation {
    fn write(&self, writer: &mut impl BufMut) {
        self.chain.write(writer);
        self.encoded_extension().write(writer);
    }
}

impl Read for ExtensionDeviation {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, bound: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            chain: ReadExt::read(reader)?,
            extension: NonZeroUsize::new(usize::read_cfg(reader, &RangeCfg::from(0..=*bound))?),
        })
    }
}

impl EncodeSize for ExtensionDeviation {
    fn encode_size(&self) -> usize {
        self.chain.encode_size() + self.encoded_extension().encode_size()
    }
}

/// The fields by which one vote differs from a tally's standard vote.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Deviation {
    signer: Participant,
    positions: Vec<PositionDeviation>,
    extensions: Vec<ExtensionDeviation>,
}

impl Deviation {
    /// Creates a deviation record.
    pub(crate) const fn new(
        signer: Participant,
        positions: Vec<PositionDeviation>,
        extensions: Vec<ExtensionDeviation>,
    ) -> Self {
        Self {
            signer,
            positions,
            extensions,
        }
    }

    /// Returns the participant whose vote is described.
    pub const fn signer(&self) -> Participant {
        self.signer
    }

    /// Returns the positions below the corresponding proposal tips.
    pub fn positions(&self) -> &[PositionDeviation] {
        &self.positions
    }

    /// Returns extension replacements in chain order. Omitted chains use the tally reference.
    pub fn extensions(&self) -> &[ExtensionDeviation] {
        &self.extensions
    }

    /// Decodes a deviation whose extension indices address at most `paths` extension paths.
    fn decode_with_paths(
        reader: &mut impl Buf,
        config: CodecConfig,
        paths: usize,
    ) -> Result<Self, CodecError> {
        let signer = ReadExt::read(reader)?;
        let positions =
            Vec::<PositionDeviation>::read_cfg(reader, &(RangeCfg::from(0..=config.chains()), ()))?;
        let extensions = Vec::<ExtensionDeviation>::read_cfg(
            reader,
            &(RangeCfg::from(0..=config.chains()), paths),
        )?;
        Ok(Self::new(signer, positions, extensions))
    }
}

impl Attributable for Deviation {
    fn signer(&self) -> Participant {
        self.signer
    }
}

impl Write for Deviation {
    fn write(&self, writer: &mut impl BufMut) {
        self.signer.write(writer);
        self.positions.write(writer);
        self.extensions.write(writer);
    }
}

impl EncodeSize for Deviation {
    fn encode_size(&self) -> usize {
        self.signer.encode_size() + self.positions.encode_size() + self.extensions.encode_size()
    }
}

/// A compact tally of complete votes for one leader block.
///
/// Votes at every proposal tip and carrying `reference_extensions` are represented by one signer
/// bit. Only lower positions or a different extension vector require a [`Deviation`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Tally<D: Digest> {
    reference_extensions: Vec<Extension<D>>,
    signers: Signers,
    deviations: Vec<Deviation>,
    extension_paths: Vec<Extension<D>>,
}

impl<D: Digest> Tally<D> {
    /// Returns the standard extension vector shared by the compact tally.
    pub fn reference_extensions(&self) -> &[Extension<D>] {
        &self.reference_extensions
    }

    /// Returns the distinct nonempty replacement paths in lexical order.
    ///
    /// Deviation indices are one-based.
    pub fn extension_paths(&self) -> &[Extension<D>] {
        &self.extension_paths
    }

    /// Returns the participants whose complete votes are represented.
    pub const fn signers(&self) -> &Signers {
        &self.signers
    }

    /// Returns the non-standard vote records in signer order.
    pub fn deviations(&self) -> &[Deviation] {
        &self.deviations
    }

    /// Returns the payloads a deviation's replacement selects: empty when it clears the chain.
    fn extension(&self, path: Option<NonZeroUsize>) -> Result<&[D], Error> {
        let Some(path) = path else {
            return Ok(&[]);
        };
        self.extension_paths
            .get(path.get() - 1)
            .map(Extension::payloads)
            .ok_or(Error::Transcript)
    }

    /// Decodes a tally and checks that it is the canonical transcript for `leader`.
    pub(crate) fn decode_for_leader<V: Variant>(
        reader: &mut impl Buf,
        leader: &LeaderBlock<V, D>,
        config: CodecConfig,
    ) -> Result<Self, CodecError> {
        let reference_extensions = Vec::<Extension<D>>::read_cfg(
            reader,
            &(RangeCfg::exact(config.chains()), config.extension_bound()),
        )?;
        let signers = Signers::read_cfg(reader, &config.participants())?;
        let max_paths = config
            .chains()
            .checked_mul(config.participants())
            .ok_or(CodecError::Invalid("Tally", "too many paths"))?;
        let extension_paths = Vec::<Extension<D>>::read_cfg(
            reader,
            &(RangeCfg::from(0..=max_paths), config.extension_bound()),
        )?;
        let deviation_count = usize::read_cfg(reader, &RangeCfg::from(0..=config.participants()))?;
        let mut deviations = Vec::with_capacity(deviation_count.min(reader.remaining()));
        for _ in 0..deviation_count {
            deviations.push(Deviation::decode_with_paths(
                reader,
                config,
                extension_paths.len(),
            )?);
        }
        let tally = Self {
            reference_extensions,
            signers,
            deviations,
            extension_paths,
        };
        tally
            .validate(leader, config)
            .map_err(|error| CodecError::Wrapped("Tally", error.into()))?;
        Ok(tally)
    }

    /// Returns the largest encoding of a tally of `votes` votes under `codec`, less the signer
    /// indices of its deviations.
    pub(in crate::multimmit::types) fn max_encode_size_without_signer_indices(
        codec: CodecConfig,
        votes: usize,
    ) -> Option<usize> {
        let chains = codec.chains();
        let extension = Extension::<D>::max_encode_size(codec)?;
        let position_deviation = checked_sum(&[
            encoded_len(chains)?,
            encoded_index_sum(chains)?,
            checked_product(chains, encoded_len(codec.pipeline_depth() - 1)?)?,
        ])?;
        // A reference comes from one vote, leaving at most (votes - 1) replacements per chain.
        let replaced = if codec.extension_bound() == 0 {
            0
        } else {
            votes.saturating_sub(1)
        };
        let paths = checked_product(replaced, chains)?;
        let replacements = checked_sum(&[
            encoded_len(chains)? - 1,
            encoded_index_sum(chains)?,
            checked_product(chains, encoded_len(paths)?)?,
        ])?;
        checked_sum(&[
            encoded_vec(chains, extension)?,
            signers_size(codec.participants())?,
            encoded_vec(paths, extension)?,
            encoded_len(votes)?,
            checked_product(votes, checked_sum(&[position_deviation, 1])?)?,
            checked_product(replaced, replacements)?,
        ])
    }

    /// Returns the largest encoding of a tally of `votes` votes under `codec`.
    pub(in crate::multimmit::types) fn max_encode_size(
        codec: CodecConfig,
        votes: usize,
    ) -> Option<usize> {
        checked_sum(&[
            Self::max_encode_size_without_signer_indices(codec, votes)?,
            largest_index_width_sum(codec.participants(), votes)?,
        ])
    }
}

impl<D: Digest> Write for Tally<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.reference_extensions.write(writer);
        self.signers.write(writer);
        self.extension_paths.write(writer);
        self.deviations.write(writer);
    }
}

impl<D: Digest> EncodeSize for Tally<D> {
    fn encode_size(&self) -> usize {
        self.reference_extensions.encode_size()
            + self.signers.encode_size()
            + self.extension_paths.encode_size()
            + self.deviations.encode_size()
    }
}

/// A complete vote for another leader block in the same view.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConflictingVote<D: Digest> {
    signer: Participant,
    ballot: Ballot<D>,
}

impl<D: Digest> ConflictingVote<D> {
    /// Creates a conflicting vote record for `signer`'s `ballot`.
    ///
    /// The ballot is checked against `config` again, since it may have been built under another
    /// epoch's limits.
    pub fn new(signer: Participant, ballot: Ballot<D>, config: CodecConfig) -> Result<Self, Error> {
        if usize::from(signer) >= config.participants() {
            return Err(Error::Participants);
        }
        ballot.validate(config)?;
        Ok(Self { signer, ballot })
    }

    /// Returns the signer.
    pub const fn signer(&self) -> Participant {
        self.signer
    }

    /// Returns the signer's ballot for the other leader block.
    pub const fn ballot(&self) -> &Ballot<D> {
        &self.ballot
    }

    /// Returns the other leader-block digest.
    pub const fn leader(&self) -> D {
        self.ballot.leader()
    }

    /// Returns every reported chain position.
    pub fn positions(&self) -> &[Position] {
        self.ballot.positions()
    }

    /// Returns every reported chain extension.
    pub fn extensions(&self) -> &[Extension<D>] {
        self.ballot.extensions()
    }

    /// Reconstructs the signed vote body using the V-QC's round.
    pub fn vote_body(&self, round: Round) -> Result<VoteBody<D>, Error> {
        VoteBody::from_ballot(round, self.ballot.clone())
    }
}

impl<D: Digest> Attributable for ConflictingVote<D> {
    fn signer(&self) -> Participant {
        self.signer
    }
}

impl<D: Digest> Write for ConflictingVote<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signer.write(writer);
        self.ballot.write(writer);
    }
}

impl<D: Digest> EncodeSize for ConflictingVote<D> {
    fn encode_size(&self) -> usize {
        self.signer.encode_size() + self.ballot.encode_size()
    }
}

impl<D: Digest> Read for ConflictingVote<D> {
    type Cfg = CodecConfig;

    fn read_cfg(reader: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let signer: Participant = ReadExt::read(reader)?;
        // The decoded ballot is already within `config`, so only the signer needs checking.
        let ballot = Ballot::read_cfg(reader, config)?;
        if usize::from(signer) >= config.participants() {
            return Err(CodecError::Wrapped(
                "ConflictingVote",
                Error::Participants.into(),
            ));
        }
        Ok(Self { signer, ballot })
    }
}
