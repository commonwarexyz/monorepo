//! Raw vote and view-message protocol objects.

use super::{Attestation, Error, LeaderBlock, Position, ThresholdShare};
use crate::{
    Epochable, Viewable,
    multimmit::config::CodecConfig,
    types::{Attributable, Epoch, Participant, Round, View},
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use core::{
    fmt,
    hash::{Hash, Hasher as CoreHasher},
};

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
            return Err(Error::Length("vote extension"));
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
            .map_err(|_| CodecError::Invalid("Extension", "extension exceeds bound"))
    }
}

impl<D: Digest> EncodeSize for Extension<D> {
    fn encode_size(&self) -> usize {
        self.payloads.encode_size()
    }
}

/// The complete, exact subject of one Multimmit participation vote.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VoteBody<D: Digest> {
    round: Round,
    leader: D,
    positions: Vec<Position>,
    extensions: Vec<Extension<D>>,
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
            leader,
            positions,
            extensions,
        };
        body.validate(limits)?;
        Ok(body)
    }

    /// Creates a vote body for `leader` and checks every proposal-relative position.
    pub fn for_leader<H: Hasher<Digest = D>, V: Variant>(
        leader: &LeaderBlock<V, D>,
        positions: Vec<Position>,
        extensions: Vec<Extension<D>>,
        limits: CodecConfig,
    ) -> Result<Self, Error> {
        let body = Self::new(
            leader.round(),
            leader.digest::<H>(),
            positions,
            extensions,
            limits,
        )?;

        if !body.positions_valid_for(leader) {
            return Err(Error::Length("vote position"));
        }

        Ok(body)
    }

    /// Returns whether this body identifies `leader` and all positions fit its proposals.
    pub fn valid_for<H: Hasher<Digest = D>, V: Variant>(&self, leader: &LeaderBlock<V, D>) -> bool {
        self.valid_for_digest(leader, leader.digest::<H>())
    }

    /// Returns the vote's round.
    pub const fn round(&self) -> Round {
        self.round
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

    pub(crate) fn validate(&self, limits: CodecConfig) -> Result<(), Error> {
        if self.round.view().is_zero() {
            return Err(Error::GenesisView);
        }
        if self.positions.len() != limits.chains() || self.extensions.len() != limits.chains() {
            return Err(Error::Length("vote chains"));
        }
        if self
            .positions
            .iter()
            .any(|position| position.get() as usize > limits.pipeline_depth())
        {
            return Err(Error::Length("vote position"));
        }
        if self
            .extensions
            .iter()
            .any(|extension| extension.len() > limits.extension_bound())
        {
            return Err(Error::Length("vote extension"));
        }
        Ok(())
    }

    fn positions_valid_for<V: Variant>(&self, leader: &LeaderBlock<V, D>) -> bool {
        paths_valid_for(leader, &self.positions, &self.extensions)
    }

    pub(crate) fn valid_for_digest<V: Variant>(
        &self,
        leader: &LeaderBlock<V, D>,
        digest: D,
    ) -> bool {
        self.round == leader.round() && self.leader == digest && self.positions_valid_for(leader)
    }
}

pub(crate) fn paths_valid_for<V: Variant, D: Digest>(
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
        self.round.epoch().write(buf);
        self.round.view().write(buf);
        self.leader.write(buf);
        self.positions.write(buf);
        self.extensions.write(buf);
    }
}

impl<D: Digest> Read for VoteBody<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, limits: &Self::Cfg) -> Result<Self, CodecError> {
        let epoch = Epoch::read(buf)?;
        let view = View::read(buf)?;
        let leader = D::read(buf)?;
        let exact_chains = RangeCfg::from(limits.chains()..=limits.chains());
        let positions = Vec::<Position>::read_cfg(buf, &(exact_chains, ()))?;
        let extensions =
            Vec::<Extension<D>>::read_cfg(buf, &(exact_chains, limits.extension_bound()))?;

        Self::new(
            Round::new(epoch, view),
            leader,
            positions,
            extensions,
            *limits,
        )
        .map_err(|_| CodecError::Invalid("VoteBody", "invalid vote body"))
    }
}

impl<D: Digest> EncodeSize for VoteBody<D> {
    fn encode_size(&self) -> usize {
        self.round.epoch().encode_size()
            + self.round.view().encode_size()
            + self.leader.encode_size()
            + self.positions.encode_size()
            + self.extensions.encode_size()
    }
}

/// One attributed vote over a complete vote body.
#[derive(Clone, Debug)]
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
}

impl<V: Variant, D: Digest> PartialEq for Vote<V, D> {
    fn eq(&self, other: &Self) -> bool {
        self.body == other.body && self.attestation == other.attestation
    }
}

impl<V: Variant, D: Digest> Eq for Vote<V, D> {}

impl<V: Variant, D: Digest> Hash for Vote<V, D> {
    fn hash<H: CoreHasher>(&self, state: &mut H) {
        self.body.hash(state);
        self.attestation.hash(state);
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
#[derive(Clone, Debug)]
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
}

impl<V: Variant> PartialEq for NoVote<V> {
    fn eq(&self, other: &Self) -> bool {
        self.round == other.round && self.attestation == other.attestation
    }
}

impl<V: Variant> Eq for NoVote<V> {}

impl<V: Variant> Hash for NoVote<V> {
    fn hash<H: CoreHasher>(&self, state: &mut H) {
        self.round.hash(state);
        self.attestation.hash(state);
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
        self.round.epoch().write(buf);
        self.round.view().write(buf);
        self.attestation.write(buf);
    }
}

impl<V: Variant> Read for NoVote<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let epoch = Epoch::read(buf)?;
        let view = View::read(buf)?;

        Self::new(Round::new(epoch, view), Attestation::read(buf)?)
            .map_err(|_| CodecError::Invalid("NoVote", "view zero is synthetic"))
    }
}

impl<V: Variant> EncodeSize for NoVote<V> {
    fn encode_size(&self) -> usize {
        self.round.epoch().encode_size()
            + self.round.view().encode_size()
            + self.attestation.encode_size()
    }
}

/// A signed request to nullify a live round.
#[derive(Clone, Debug)]
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
}

impl<V: Variant> PartialEq for Nullify<V> {
    fn eq(&self, other: &Self) -> bool {
        self.round == other.round && self.share == other.share
    }
}

impl<V: Variant> Eq for Nullify<V> {}

impl<V: Variant> Hash for Nullify<V> {
    fn hash<H: CoreHasher>(&self, state: &mut H) {
        self.round.hash(state);
        self.share.hash(state);
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
        self.round.epoch().write(buf);
        self.round.view().write(buf);
        self.share.write(buf);
    }
}

impl<V: Variant> Read for Nullify<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let epoch = Epoch::read(buf)?;
        let view = View::read(buf)?;

        Self::new(Round::new(epoch, view), ThresholdShare::read(buf)?)
            .map_err(|_| CodecError::Invalid("Nullify", "view zero is synthetic"))
    }
}

impl<V: Variant> EncodeSize for Nullify<V> {
    fn encode_size(&self) -> usize {
        self.round.epoch().encode_size()
            + self.round.view().encode_size()
            + self.share.encode_size()
    }
}

/// A fully attributed but cryptographically unverified vote or abstention.
#[derive(Clone, Debug)]
pub enum ViewMessage<V: Variant, D: Digest> {
    /// A complete vote.
    Vote(Vote<V, D>),
    /// A complete signed abstention.
    NoVote(NoVote<V>),
}

impl<V: Variant, D: Digest> PartialEq for ViewMessage<V, D> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Vote(left), Self::Vote(right)) => left == right,
            (Self::NoVote(left), Self::NoVote(right)) => left == right,
            _ => false,
        }
    }
}

impl<V: Variant, D: Digest> Eq for ViewMessage<V, D> {}

impl<V: Variant, D: Digest> Hash for ViewMessage<V, D> {
    fn hash<H: CoreHasher>(&self, state: &mut H) {
        match self {
            Self::Vote(vote) => {
                0u8.hash(state);
                vote.hash(state);
            }
            Self::NoVote(no_vote) => {
                1u8.hash(state);
                no_vote.hash(state);
            }
        }
    }
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
    use crate::multimmit::{
        config::Limits,
        types::{Anchor, BlockRef, CertificateId, ChainId, ChainProposal, Height},
    };
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinSig, sha256};

    fn digest(label: &[u8]) -> sha256::Digest {
        Sha256::hash(&[label])
    }

    fn codec_config() -> CodecConfig {
        CodecConfig::new(2, 2, Limits::new(2, 1).unwrap()).unwrap()
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
            Error::Length("vote extension")
        );
    }

    #[test]
    fn vote_body_checks_positions_against_leader() {
        let leader = leader();
        let limits = codec_config();
        let extensions = vec![Extension::empty(), Extension::empty()];

        let valid = VoteBody::for_leader::<Sha256, _>(
            &leader,
            vec![Position::new(2), Position::new(1)],
            extensions.clone(),
            limits,
        )
        .unwrap();
        assert!(valid.valid_for::<Sha256, _>(&leader));

        assert_eq!(
            VoteBody::for_leader::<Sha256, _>(
                &leader,
                vec![Position::new(3), Position::new(1)],
                extensions,
                limits,
            )
            .unwrap_err(),
            Error::Length("vote position")
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
            Error::Length("vote position")
        );
    }

    #[test]
    fn vote_body_rejects_extension_height_overflow() {
        let limits = codec_config();
        let proposals = (0..limits.chains())
            .map(|index| {
                let chain = ChainId::new(index as u32);
                ChainProposal::new(
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
            VoteBody::for_leader::<Sha256, MinSig>(
                &leader,
                vec![Position::new(0); limits.chains()],
                extensions,
                limits,
            )
            .unwrap_err(),
            Error::Length("vote position")
        );
    }

    #[test]
    fn vote_body_codec_round_trips_structural_bounds() {
        let leader = leader();
        let limits = codec_config();
        let body = VoteBody::for_leader::<Sha256, _>(
            &leader,
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
        assert!(decoded.valid_for::<Sha256, _>(&leader));
    }
}
