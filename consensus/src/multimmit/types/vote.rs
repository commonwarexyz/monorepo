//! Raw vote and view-message protocol objects.

use super::{
    Attestation, DigestedLeader, Error, LeaderBlock, Position, ThresholdShare,
    bounds::{
        MAX_U64_VARINT_SIZE, checked_product, checked_sum, encoded_len, encoded_vec,
        max_index_width,
    },
};
use crate::{
    Epochable, Viewable,
    multimmit::types::CodecConfig,
    types::{Attributable, Epoch, Participant, Round, View},
};
use bytes::BufMut;
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, FixedSize as _, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use core::fmt;
use std::sync::Arc;

/// A bounded sequence of application commitments extending one voted position.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Extension<D: Digest> {
    payloads: Vec<D>,
}

impl<D: Digest> fmt::Debug for Extension<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Extension")
            .field("payload_count", &self.payloads.len())
            .finish()
    }
}

impl<D: Digest> Extension<D> {
    /// Creates an extension within `extension_bound`.
    pub fn new(payloads: Vec<D>, extension_bound: usize) -> Result<Self, Error> {
        if payloads.len() > extension_bound {
            return Err(Error::ExtensionLength);
        }

        Ok(Self { payloads })
    }

    /// Creates an empty extension.
    pub const fn empty() -> Self {
        Self {
            payloads: Vec::new(),
        }
    }

    /// Returns the extension's application commitments in path order.
    pub fn payloads(&self) -> &[D] {
        &self.payloads
    }

    /// Returns the number of commitments in the extension.
    pub const fn len(&self) -> usize {
        self.payloads.len()
    }

    /// Returns whether the extension is empty.
    pub const fn is_empty(&self) -> bool {
        self.payloads.is_empty()
    }

    /// Returns the largest encoding of an extension under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        encoded_vec(codec.extension_bound(), D::SIZE)
    }
}

impl<D: Digest> Write for Extension<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.payloads.write(buf);
    }
}

impl<D: Digest> Read for Extension<D> {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, extension_bound: &usize) -> Result<Self, CodecError> {
        let payloads = Vec::<D>::read_cfg(buf, &(RangeCfg::from(0..=*extension_bound), ()))?;

        Self::new(payloads, *extension_bound)
            .map_err(|error| CodecError::Wrapped("Extension", error.into()))
    }
}

impl<D: Digest> EncodeSize for Extension<D> {
    fn encode_size(&self) -> usize {
        self.payloads.encode_size()
    }
}

/// One voter's choice for a leader block: its digest plus one position and one extension per
/// producer chain.
///
/// A ballot is always within the epoch's codec limits. Whether its positions fit a particular
/// leader block's proposals is checked against that block by [`VoteBody::for_leader`] and
/// [`VoteBody::valid_for`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ballot<D: Digest> {
    leader: D,
    positions: Arc<[Position]>,
    extensions: Arc<[Extension<D>]>,
}

impl<D: Digest> Ballot<D> {
    /// Creates a ballot spanning every producer chain within `limits`.
    pub fn new(
        leader: D,
        positions: Vec<Position>,
        extensions: Vec<Extension<D>>,
        limits: CodecConfig,
    ) -> Result<Self, Error> {
        let ballot = Self {
            leader,
            positions: positions.into(),
            extensions: extensions.into(),
        };
        ballot.validate(limits)?;
        Ok(ballot)
    }

    /// Returns the voted-for leader-block digest.
    pub const fn leader(&self) -> D {
        self.leader
    }

    /// Returns one position per producer chain in chain order.
    pub fn positions(&self) -> &[Position] {
        &self.positions
    }

    /// Returns one extension per producer chain in chain order.
    pub fn extensions(&self) -> &[Extension<D>] {
        &self.extensions
    }

    /// Checks the chain count, positions, and extensions against `limits`.
    pub(super) fn validate(&self, limits: CodecConfig) -> Result<(), Error> {
        if self.positions.len() != limits.chains() || self.extensions.len() != limits.chains() {
            return Err(Error::ChainCount);
        }
        if self
            .positions
            .iter()
            .any(|position| position.get() as usize > limits.pipeline_depth())
        {
            return Err(Error::Position);
        }
        if self
            .extensions
            .iter()
            .any(|extension| extension.len() > limits.extension_bound())
        {
            return Err(Error::ExtensionLength);
        }
        Ok(())
    }

    /// Returns whether every position and extension fits `leader`'s proposals.
    fn fits<V: Variant>(&self, leader: &LeaderBlock<V, D>) -> bool {
        paths_valid_for(leader, &self.positions, &self.extensions)
    }

    /// Returns the largest encoding of a ballot under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        let chains = codec.chains();
        checked_sum(&[
            D::SIZE,
            encoded_vec(chains, encoded_len(codec.pipeline_depth())?)?,
            encoded_vec(chains, Extension::<D>::max_encode_size(codec)?)?,
        ])
    }
}

impl<D: Digest> Write for Ballot<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.leader.write(buf);
        self.positions().write(buf);
        self.extensions().write(buf);
    }
}

impl<D: Digest> Read for Ballot<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        let leader = D::read(buf)?;
        let exact_chains = RangeCfg::exact(limits.chains());
        let positions = Vec::<Position>::read_cfg(buf, &(exact_chains, ()))?;
        let extensions =
            Vec::<Extension<D>>::read_cfg(buf, &(exact_chains, limits.extension_bound()))?;
        Self::new(leader, positions, extensions, *limits)
            .map_err(|error| CodecError::Wrapped("Ballot", error.into()))
    }
}

impl<D: Digest> EncodeSize for Ballot<D> {
    fn encode_size(&self) -> usize {
        self.leader.encode_size() + self.positions().encode_size() + self.extensions().encode_size()
    }
}

/// The subject of one Multimmit participation vote: a ballot cast in a live round.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VoteBody<D: Digest> {
    round: Round,
    ballot: Ballot<D>,
}

impl<D: Digest> VoteBody<D> {
    /// Creates a structurally bounded vote body spanning every producer chain.
    ///
    /// Use [`Self::for_leader`] when the leader block is available so positions are also checked
    /// against their corresponding proposal lengths.
    pub fn new(
        round: Round,
        leader: D,
        positions: Vec<Position>,
        extensions: Vec<Extension<D>>,
        limits: CodecConfig,
    ) -> Result<Self, Error> {
        let body = Self {
            round,
            ballot: Ballot {
                leader,
                positions: positions.into(),
                extensions: extensions.into(),
            },
        };
        body.validate(limits)?;
        Ok(body)
    }

    /// Casts an already bounded `ballot` in `round`.
    pub(crate) fn from_ballot(round: Round, ballot: Ballot<D>) -> Result<Self, Error> {
        if round.view().is_zero() {
            return Err(Error::GenesisView);
        }
        Ok(Self { round, ballot })
    }

    /// Creates a vote body for `leader` and checks every proposal-relative position.
    pub fn for_leader<V: Variant>(
        leader: DigestedLeader<'_, V, D>,
        positions: Vec<Position>,
        extensions: Vec<Extension<D>>,
        limits: CodecConfig,
    ) -> Result<Self, Error> {
        let block = leader.block();
        let body = Self::new(
            block.round(),
            leader.digest(),
            positions,
            extensions,
            limits,
        )?;
        if !body.ballot.fits(block) {
            return Err(Error::Position);
        }
        Ok(body)
    }

    /// Returns whether this body votes for `leader` in its round and all positions fit its
    /// proposals.
    pub fn valid_for<V: Variant>(&self, leader: DigestedLeader<'_, V, D>) -> bool {
        self.round == leader.block().round()
            && self.ballot.leader == leader.digest()
            && self.ballot.fits(leader.block())
    }

    /// Returns the vote's round.
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Returns the ballot cast by this vote.
    pub const fn ballot(&self) -> &Ballot<D> {
        &self.ballot
    }

    /// Returns the voted-for leader-block digest.
    pub const fn leader(&self) -> D {
        self.ballot.leader
    }

    /// Returns one position per producer chain in chain order.
    pub fn positions(&self) -> &[Position] {
        self.ballot.positions()
    }

    /// Returns one extension per producer chain in chain order.
    pub fn extensions(&self) -> &[Extension<D>] {
        self.ballot.extensions()
    }

    pub(crate) fn validate(&self, limits: CodecConfig) -> Result<(), Error> {
        if self.round.view().is_zero() {
            return Err(Error::GenesisView);
        }
        self.ballot.validate(limits)
    }

    /// Returns the largest encoding of a vote body under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            checked_product(2, MAX_U64_VARINT_SIZE)?,
            Ballot::<D>::max_encode_size(codec)?,
        ])
    }
}

pub(super) fn paths_valid_for<V: Variant, D: Digest>(
    leader: &LeaderBlock<V, D>,
    positions: &[Position],
    extensions: &[Extension<D>],
) -> bool {
    if positions.len() != leader.proposals().len() || positions.len() != extensions.len() {
        return false;
    }

    positions
        .iter()
        .zip(extensions)
        .zip(leader.proposals())
        .all(|((position, extension), proposal)| {
            if position.get() as usize > proposal.len() {
                return false;
            }

            proposal
                .anchor()
                .height()
                .get()
                .checked_add(u64::from(position.get()))
                .and_then(|height| height.checked_add(extension.len() as u64))
                .is_some()
        })
}

impl<D: Digest> Epochable for VoteBody<D> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<D: Digest> Viewable for VoteBody<D> {
    fn view(&self) -> View {
        self.round.view()
    }
}

impl<D: Digest> Write for VoteBody<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.ballot.write(buf);
    }
}

impl<D: Digest> Read for VoteBody<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        let round = Round::read(buf)?;
        let ballot = Ballot::read_cfg(buf, limits)?;
        Self::from_ballot(round, ballot)
            .map_err(|error| CodecError::Wrapped("VoteBody", error.into()))
    }
}

impl<D: Digest> EncodeSize for VoteBody<D> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.ballot.encode_size()
    }
}

/// One attributed vote over a complete vote body.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Vote<V: Variant, D: Digest> {
    body: VoteBody<D>,
    attestation: Attestation<V>,
}

impl<V: Variant, D: Digest> Vote<V, D> {
    /// Creates an unverified attributed vote.
    pub const fn new(body: VoteBody<D>, attestation: Attestation<V>) -> Self {
        Self { body, attestation }
    }

    /// Returns the complete participation subject.
    pub const fn body(&self) -> &VoteBody<D> {
        &self.body
    }

    /// Returns the vote attestation.
    pub const fn attestation(&self) -> &Attestation<V> {
        &self.attestation
    }

    /// Returns the largest encoding of a vote under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            VoteBody::<D>::max_encode_size(codec)?,
            max_index_width(codec.participants())?,
            V::Signature::SIZE,
        ])
    }
}

impl<V: Variant, D: Digest> Epochable for Vote<V, D> {
    fn epoch(&self) -> Epoch {
        self.body.epoch()
    }
}

impl<V: Variant, D: Digest> Attributable for Vote<V, D> {
    fn signer(&self) -> Participant {
        self.attestation.signer()
    }
}

impl<V: Variant, D: Digest> Viewable for Vote<V, D> {
    fn view(&self) -> View {
        self.body.view()
    }
}

impl<V: Variant, D: Digest> Write for Vote<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.body.write(buf);
        self.attestation.write(buf);
    }
}

impl<V: Variant, D: Digest> Read for Vote<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self::new(
            VoteBody::read_cfg(buf, limits)?,
            Attestation::read(buf)?,
        ))
    }
}

impl<V: Variant, D: Digest> EncodeSize for Vote<V, D> {
    fn encode_size(&self) -> usize {
        self.body.encode_size() + self.attestation.encode_size()
    }
}

/// A signed abstention used to complete a V-QC's accounted-message quorum.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NoVote<V: Variant> {
    round: Round,
    attestation: Attestation<V>,
}

impl<V: Variant> NoVote<V> {
    /// Creates an attributed abstention for a live round.
    ///
    /// This constructor does not verify the signature.
    pub fn new(round: Round, attestation: Attestation<V>) -> Result<Self, Error> {
        if round.view().is_zero() {
            return Err(Error::GenesisView);
        }

        Ok(Self { round, attestation })
    }

    /// Returns the abstention's round.
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Returns the abstention attestation.
    pub const fn attestation(&self) -> &Attestation<V> {
        &self.attestation
    }

    /// Returns the largest encoding of a novote under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            checked_product(2, MAX_U64_VARINT_SIZE)?,
            max_index_width(codec.participants())?,
            V::Signature::SIZE,
        ])
    }
}

impl<V: Variant> Epochable for NoVote<V> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<V: Variant> Attributable for NoVote<V> {
    fn signer(&self) -> Participant {
        self.attestation.signer()
    }
}

impl<V: Variant> Viewable for NoVote<V> {
    fn view(&self) -> View {
        self.round.view()
    }
}

impl<V: Variant> Write for NoVote<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.attestation.write(buf);
    }
}

impl<V: Variant> Read for NoVote<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Self::new(Round::read(buf)?, Attestation::read(buf)?)
            .map_err(|error| CodecError::Wrapped("NoVote", error.into()))
    }
}

impl<V: Variant> EncodeSize for NoVote<V> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.attestation.encode_size()
    }
}

/// A signed request to nullify a live round.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nullify<V: Variant> {
    round: Round,
    share: ThresholdShare<V>,
}

impl<V: Variant> Nullify<V> {
    /// Creates an attributed nullification request for a live round.
    ///
    /// This constructor does not verify the signature.
    pub fn new(round: Round, share: ThresholdShare<V>) -> Result<Self, Error> {
        if round.view().is_zero() {
            return Err(Error::GenesisView);
        }

        Ok(Self { round, share })
    }

    /// Returns the nullification request's round.
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Returns the nullification threshold share.
    pub const fn share(&self) -> &ThresholdShare<V> {
        &self.share
    }

    /// Returns the largest encoding of a nullify share under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            checked_product(2, MAX_U64_VARINT_SIZE)?,
            max_index_width(codec.participants())?,
            V::Signature::SIZE,
        ])
    }
}

impl<V: Variant> Epochable for Nullify<V> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<V: Variant> Attributable for Nullify<V> {
    fn signer(&self) -> Participant {
        self.share.signer()
    }
}

impl<V: Variant> Viewable for Nullify<V> {
    fn view(&self) -> View {
        self.round.view()
    }
}

impl<V: Variant> Write for Nullify<V> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.share.write(buf);
    }
}

impl<V: Variant> Read for Nullify<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Self::new(Round::read(buf)?, ThresholdShare::read(buf)?)
            .map_err(|error| CodecError::Wrapped("Nullify", error.into()))
    }
}

impl<V: Variant> EncodeSize for Nullify<V> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.share.encode_size()
    }
}

/// A fully attributed but cryptographically unverified vote or abstention.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ViewMessage<V: Variant, D: Digest> {
    /// A complete vote.
    Vote(Vote<V, D>),
    /// A complete signed abstention.
    NoVote(NoVote<V>),
}

impl<V: Variant, D: Digest> Epochable for ViewMessage<V, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::Vote(vote) => vote.epoch(),
            Self::NoVote(no_vote) => no_vote.epoch(),
        }
    }
}

impl<V: Variant, D: Digest> Attributable for ViewMessage<V, D> {
    fn signer(&self) -> Participant {
        match self {
            Self::Vote(vote) => vote.signer(),
            Self::NoVote(no_vote) => no_vote.signer(),
        }
    }
}

impl<V: Variant, D: Digest> Viewable for ViewMessage<V, D> {
    fn view(&self) -> View {
        match self {
            Self::Vote(vote) => vote.view(),
            Self::NoVote(no_vote) => no_vote.view(),
        }
    }
}

impl<V: Variant, D: Digest> Write for ViewMessage<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Vote(vote) => {
                0u8.write(buf);
                vote.write(buf);
            }
            Self::NoVote(no_vote) => {
                1u8.write(buf);
                no_vote.write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> Read for ViewMessage<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Vote(Vote::read_cfg(buf, limits)?)),
            1 => Ok(Self::NoVote(NoVote::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for ViewMessage<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Vote(vote) => vote.encode_size(),
            Self::NoVote(no_vote) => no_vote.encode_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::types::{Anchor, BlockRef, CertificateId, ChainId, ChainProposal, PathLimits},
        types::Height,
    };
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{Hasher, Sha256, bls12381::primitives::variant::MinSig, sha256};

    fn digest(label: &[u8]) -> sha256::Digest {
        Sha256::hash(&[label])
    }

    fn codec_config() -> CodecConfig {
        CodecConfig::new(2, 2, PathLimits::new(2, 1).unwrap()).unwrap()
    }

    fn leader() -> LeaderBlock<MinSig, sha256::Digest> {
        let limits = codec_config();
        let proposals = [2usize, 1]
            .into_iter()
            .enumerate()
            .map(|(index, payload_count)| {
                let chain = ChainId::new(index as u32);
                let anchor = Anchor::Tip(BlockRef::new(chain, Height::zero(), digest(b"anchor")));
                let payloads = (0..payload_count)
                    .map(|payload| digest(&payload.to_be_bytes()))
                    .collect();
                ChainProposal::new(chain, anchor, payloads, limits.pipeline_depth()).unwrap()
            })
            .collect();

        LeaderBlock::new(
            Round::new(Epoch::new(7), View::new(1)),
            CertificateId::new(digest(b"parent")),
            digest(b"history"),
            proposals,
            limits,
        )
        .unwrap()
    }

    #[test]
    fn extension_codec_enforces_bound() {
        let extension = Extension::new(vec![digest(b"payload")], 1).unwrap();
        assert_eq!(
            Extension::<sha256::Digest>::decode_cfg(extension.encode(), &1).unwrap(),
            extension
        );
        assert_eq!(
            Extension::new(vec![digest(b"1"), digest(b"2")], 1).unwrap_err(),
            Error::ExtensionLength
        );
    }

    #[test]
    fn vote_body_checks_positions_against_leader() {
        let leader = leader();
        let limits = codec_config();
        let extensions = vec![Extension::empty(), Extension::empty()];

        let valid = VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(&leader),
            vec![Position::new(2), Position::new(1)],
            extensions.clone(),
            limits,
        )
        .unwrap();
        assert!(valid.valid_for(DigestedLeader::new::<Sha256>(&leader)));

        assert_eq!(
            VoteBody::for_leader(
                DigestedLeader::new::<Sha256>(&leader),
                vec![Position::new(3), Position::new(1)],
                extensions,
                limits
            )
            .unwrap_err(),
            Error::Position
        );

        assert_eq!(
            VoteBody::new(
                leader.round(),
                leader.digest::<Sha256>(),
                vec![Position::new(3), Position::new(0)],
                vec![Extension::empty(), Extension::empty()],
                limits,
            )
            .unwrap_err(),
            Error::Position
        );
    }

    #[test]
    fn decode_errors_keep_the_protocol_source() {
        let encoded = (
            Epoch::new(7),
            View::new(1),
            digest(b"leader"),
            vec![Position::new(3), Position::new(0)],
            vec![Extension::<sha256::Digest>::empty(), Extension::empty()],
        )
            .encode();
        let error = VoteBody::<sha256::Digest>::decode_cfg(encoded, &codec_config()).unwrap_err();
        let CodecError::Wrapped(context, source) = error else {
            panic!("expected a wrapped protocol error, got {error:?}");
        };
        assert_eq!(context, "Ballot");
        assert_eq!(source.downcast_ref::<Error>(), Some(&Error::Position));
    }

    #[test]
    fn ballot_checks_codec_limits_and_encodes_after_the_round() {
        let limits = codec_config();
        let leader = digest(b"leader");
        assert_eq!(
            Ballot::new(
                leader,
                vec![Position::new(0)],
                vec![Extension::empty()],
                limits
            )
            .unwrap_err(),
            Error::ChainCount
        );
        assert_eq!(
            Ballot::new(
                leader,
                vec![Position::new(3), Position::new(0)],
                vec![Extension::empty(); 2],
                limits,
            )
            .unwrap_err(),
            Error::Position
        );
        let long = Extension::new(vec![digest(b"1"), digest(b"2")], 2).unwrap();
        assert_eq!(
            Ballot::new(
                leader,
                vec![Position::new(0); 2],
                vec![long, Extension::empty()],
                limits,
            )
            .unwrap_err(),
            Error::ExtensionLength
        );

        let ballot = Ballot::new(
            leader,
            vec![Position::new(1), Position::new(0)],
            vec![Extension::empty(); 2],
            limits,
        )
        .unwrap();
        assert_eq!(
            Ballot::<sha256::Digest>::decode_cfg(ballot.encode(), &limits).unwrap(),
            ballot
        );
        let round = Round::new(Epoch::new(7), View::new(1));
        let body = VoteBody::from_ballot(round, ballot.clone()).unwrap();
        let mut expected = round.encode().to_vec();
        expected.extend_from_slice(&ballot.encode());
        assert_eq!(body.encode().as_ref(), expected.as_slice());
        assert_eq!(
            VoteBody::from_ballot(Round::new(Epoch::new(7), View::zero()), ballot).unwrap_err(),
            Error::GenesisView
        );
    }

    #[test]
    fn digested_leader_binds_the_voted_digest() {
        let leader = leader();
        let digested = DigestedLeader::new::<Sha256>(&leader);
        assert_eq!(digested.digest(), leader.digest::<Sha256>());
        let body = VoteBody::for_leader(
            digested,
            vec![Position::new(2), Position::new(1)],
            vec![Extension::empty(), Extension::empty()],
            codec_config(),
        )
        .unwrap();
        assert_eq!(body.leader(), digested.digest());
        assert!(body.valid_for(digested));
        assert!(!body.valid_for(DigestedLeader::with_digest(&leader, digest(b"other"))));
    }

    #[test]
    fn vote_body_rejects_wrong_chain_count() {
        let leader = leader();
        assert_eq!(
            VoteBody::new(
                leader.round(),
                leader.digest::<Sha256>(),
                vec![Position::new(0)],
                vec![Extension::empty()],
                codec_config(),
            )
            .unwrap_err(),
            Error::ChainCount
        );
    }

    #[test]
    fn vote_body_rejects_extension_height_overflow() {
        let limits = codec_config();
        let proposals = (0..limits.chains())
            .map(|index| {
                let chain = ChainId::new(index as u32);
                ChainProposal::<MinSig, _>::new(
                    chain,
                    Anchor::Tip(BlockRef::new(
                        chain,
                        Height::new(u64::MAX),
                        digest(b"anchor"),
                    )),
                    Vec::new(),
                    limits.pipeline_depth(),
                )
                .unwrap()
            })
            .collect();
        let leader = LeaderBlock::new(
            Round::new(Epoch::new(7), View::new(1)),
            CertificateId::new(digest(b"parent")),
            digest(b"history"),
            proposals,
            limits,
        )
        .unwrap();
        let extensions = vec![
            Extension::new(vec![digest(b"next")], limits.extension_bound()).unwrap(),
            Extension::empty(),
        ];

        assert_eq!(
            VoteBody::for_leader(
                DigestedLeader::new::<Sha256>(&leader),
                vec![Position::new(0); limits.chains()],
                extensions,
                limits
            )
            .unwrap_err(),
            Error::Position
        );
    }

    #[test]
    fn vote_body_codec_round_trips_structural_bounds() {
        let leader = leader();
        let limits = codec_config();
        let body = VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(&leader),
            vec![Position::new(1), Position::new(0)],
            vec![
                Extension::new(vec![digest(b"extension")], 1).unwrap(),
                Extension::empty(),
            ],
            limits,
        )
        .unwrap();

        let decoded = VoteBody::<sha256::Digest>::decode_cfg(body.encode(), &limits).unwrap();
        assert_eq!(decoded, body);
        assert!(decoded.valid_for(DigestedLeader::new::<Sha256>(&leader)));

        let encoded_vectors = (
            body.epoch(),
            body.view(),
            body.leader(),
            body.positions().to_vec(),
            body.extensions().to_vec(),
        )
            .encode();
        assert_eq!(body.encode(), encoded_vectors);

        let cloned = body.clone();
        assert!(core::ptr::eq(body.positions(), cloned.positions()));
        assert!(core::ptr::eq(body.extensions(), cloned.extensions()));
        drop(body);
        assert_eq!(cloned.encode(), decoded.encode());
    }
}
