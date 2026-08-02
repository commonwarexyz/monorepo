//! Compact, reversible vote transcripts used by Multimmit quorum certificates.

use super::{ChainId, Error, Extension, LeaderBlock, Position, VoteBody, vote::paths_valid_for};
use crate::{
    multimmit::config::CodecConfig,
    types::{Attributable, Round},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{
    Digest, Hasher, bls12381::primitives::variant::Variant, certificate::Signers,
};
use commonware_utils::Participant;
use std::collections::BTreeMap;

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

/// The fields by which one vote differs from a tally's standard vote.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Deviation<D: Digest> {
    signer: Participant,
    positions: Vec<PositionDeviation>,
    extensions: Option<Vec<Extension<D>>>,
}

impl<D: Digest> Deviation<D> {
    /// Creates a deviation record.
    pub(crate) const fn new(
        signer: Participant,
        positions: Vec<PositionDeviation>,
        extensions: Option<Vec<Extension<D>>>,
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

    /// Returns a replacement extension vector, or `None` when the tally reference is used.
    pub fn extensions(&self) -> Option<&[Extension<D>]> {
        self.extensions.as_deref()
    }
}

impl<D: Digest> Attributable for Deviation<D> {
    fn signer(&self) -> Participant {
        self.signer
    }
}

impl<D: Digest> Write for Deviation<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signer.write(writer);
        self.positions.write(writer);
        self.extensions.write(writer);
    }
}

impl<D: Digest> EncodeSize for Deviation<D> {
    fn encode_size(&self) -> usize {
        self.signer.encode_size() + self.positions.encode_size() + self.extensions.encode_size()
    }
}

impl<D: Digest> Deviation<D> {
    fn read_cfg(reader: &mut impl Buf, config: CodecConfig) -> Result<Self, CodecError> {
        let signer = ReadExt::read(reader)?;
        let positions =
            Vec::<PositionDeviation>::read_cfg(reader, &(RangeCfg::from(0..=config.chains()), ()))?;
        let extensions = Option::<Vec<Extension<D>>>::read_cfg(
            reader,
            &(RangeCfg::exact(config.chains()), config.extension_bound()),
        )?;
        Ok(Self::new(signer, positions, extensions))
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
    deviations: Vec<Deviation<D>>,
}

impl<D: Digest> Tally<D> {
    /// Builds the canonical tally for a collection of complete votes.
    pub fn from_votes<V, H, I>(
        leader: &LeaderBlock<V, D>,
        votes: I,
        config: CodecConfig,
    ) -> Result<Self, Error>
    where
        V: Variant,
        H: Hasher<Digest = D>,
        I: IntoIterator<Item = (Participant, VoteBody<D>)>,
    {
        let mut votes: Vec<_> = votes.into_iter().collect();
        votes.sort_by_key(|(signer, _)| *signer);
        if votes.is_empty() {
            return Err(Error::Quorum);
        }
        if leader.proposals().len() != config.chains() {
            return Err(Error::Context);
        }
        if votes.windows(2).any(|pair| pair[0].0 == pair[1].0)
            || votes
                .iter()
                .any(|(signer, _)| usize::from(*signer) >= config.participants())
            || votes.iter().any(|(_, body)| {
                body.positions().len() != config.chains()
                    || body.extensions().len() != config.chains()
            })
        {
            return Err(Error::Participants);
        }
        if votes
            .iter()
            .any(|(_, body)| !body.valid_for::<H, V>(leader))
        {
            return Err(Error::Transcript);
        }

        let reference_extensions = canonical_reference(leader, &votes);
        let mut deviations = Vec::new();
        for (signer, body) in &votes {
            let positions = body
                .positions()
                .iter()
                .zip(leader.proposals())
                .enumerate()
                .filter(|(_, (position, proposal))| {
                    position.get() < proposal.payloads().len() as u32
                })
                .map(|(chain, (position, _))| {
                    PositionDeviation::new(ChainId::new(chain as u32), *position)
                })
                .collect::<Vec<_>>();
            let extensions = (body.extensions() != reference_extensions.as_slice())
                .then(|| body.extensions().to_vec());
            if positions.is_empty() && extensions.is_none() {
                continue;
            }
            deviations.push(Deviation::new(*signer, positions, extensions));
        }

        let signers = Signers::from(
            config.participants(),
            votes.iter().map(|(signer, _)| *signer),
        );
        Ok(Self {
            reference_extensions,
            signers,
            deviations,
        })
    }

    /// Returns the standard extension vector shared by the compact tally.
    pub fn reference_extensions(&self) -> &[Extension<D>] {
        &self.reference_extensions
    }

    /// Returns the participants whose complete votes are represented.
    pub const fn signers(&self) -> &Signers {
        &self.signers
    }

    /// Returns the non-standard vote records in signer order.
    pub fn deviations(&self) -> &[Deviation<D>] {
        &self.deviations
    }

    /// Expands one signer's exact vote body.
    pub fn vote<V, H>(
        &self,
        leader: &LeaderBlock<V, D>,
        signer: Participant,
        config: CodecConfig,
    ) -> Result<VoteBody<D>, Error>
    where
        V: Variant,
        H: Hasher<Digest = D>,
    {
        if leader.proposals().len() != config.chains()
            || self.reference_extensions.len() != config.chains()
            || self.signers.len() != config.participants()
        {
            return Err(Error::Context);
        }
        if !self.signers.iter().any(|candidate| candidate == signer) {
            return Err(Error::Participants);
        }

        let mut positions = leader
            .proposals()
            .iter()
            .map(|proposal| Position::new(proposal.payloads().len() as u32))
            .collect::<Vec<_>>();
        let mut extensions = self.reference_extensions.clone();
        if let Ok(index) = self
            .deviations
            .binary_search_by_key(&signer, Deviation::signer)
        {
            let deviation = &self.deviations[index];
            for position in &deviation.positions {
                let Some(current) = positions.get_mut(position.chain.get() as usize) else {
                    return Err(Error::Transcript);
                };
                *current = position.position;
            }
            if let Some(replacement) = &deviation.extensions {
                extensions.clone_from(replacement);
            }
        }

        VoteBody::for_leader::<H, V>(leader, positions, extensions, config)
    }

    pub(crate) fn validate<V: Variant>(
        &self,
        leader: &LeaderBlock<V, D>,
        config: CodecConfig,
    ) -> Result<(), Error> {
        if self.reference_extensions.len() != config.chains()
            || self
                .reference_extensions
                .iter()
                .any(|extension| extension.len() > config.extension_bound())
            || self.signers.len() != config.participants()
            || self.signers.count() == 0
        {
            return Err(Error::Transcript);
        }
        if self
            .deviations
            .windows(2)
            .any(|pair| pair[0].signer >= pair[1].signer)
        {
            return Err(Error::Transcript);
        }

        for deviation in &self.deviations {
            if !self.signers.iter().any(|signer| signer == deviation.signer)
                || deviation.positions.is_empty() && deviation.extensions.is_none()
                || deviation
                    .positions
                    .windows(2)
                    .any(|pair| pair[0].chain >= pair[1].chain)
            {
                return Err(Error::Transcript);
            }
            for position in &deviation.positions {
                let Some(proposal) = leader.proposals().get(position.chain.get() as usize) else {
                    return Err(Error::Transcript);
                };
                if position.position.get() >= proposal.payloads().len() as u32 {
                    return Err(Error::Transcript);
                }
            }
            if let Some(extensions) = &deviation.extensions
                && (extensions.len() != config.chains()
                    || extensions == &self.reference_extensions
                    || extensions
                        .iter()
                        .any(|extension| extension.len() > config.extension_bound()))
            {
                return Err(Error::Transcript);
            }
        }

        let expanded = self
            .signers
            .iter()
            .map(|signer| {
                let mut positions = leader
                    .proposals()
                    .iter()
                    .map(|proposal| Position::new(proposal.payloads().len() as u32))
                    .collect::<Vec<_>>();
                let mut extensions = self.reference_extensions.clone();
                if let Ok(index) = self
                    .deviations
                    .binary_search_by_key(&signer, Deviation::signer)
                {
                    let deviation = &self.deviations[index];
                    for position in &deviation.positions {
                        positions[position.chain.get() as usize] = position.position;
                    }
                    if let Some(replacement) = &deviation.extensions {
                        extensions.clone_from(replacement);
                    }
                }
                (signer, positions, extensions)
            })
            .collect::<Vec<_>>();
        if expanded
            .iter()
            .any(|(_, positions, extensions)| !paths_valid_for(leader, positions, extensions))
        {
            return Err(Error::Transcript);
        }
        if canonical_reference_parts(leader, &expanded) != self.reference_extensions {
            return Err(Error::Transcript);
        }
        Ok(())
    }
}

impl<D: Digest> Write for Tally<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.reference_extensions.write(writer);
        self.signers.write(writer);
        self.deviations.write(writer);
    }
}

impl<D: Digest> EncodeSize for Tally<D> {
    fn encode_size(&self) -> usize {
        self.reference_extensions.encode_size()
            + self.signers.encode_size()
            + self.deviations.encode_size()
    }
}

impl<D: Digest> Tally<D> {
    pub(crate) fn read_cfg<V: Variant>(
        reader: &mut impl Buf,
        leader: &LeaderBlock<V, D>,
        config: CodecConfig,
    ) -> Result<Self, CodecError> {
        let reference_extensions = Vec::<Extension<D>>::read_cfg(
            reader,
            &(
                RangeCfg::from(config.chains()..=config.chains()),
                config.extension_bound(),
            ),
        )?;
        let signers = Signers::read_cfg(reader, &config.participants())?;
        let deviation_count = usize::read_cfg(reader, &RangeCfg::from(0..=config.participants()))?;
        let mut deviations = Vec::with_capacity(deviation_count.min(reader.remaining()));
        for _ in 0..deviation_count {
            deviations.push(Deviation::read_cfg(reader, config)?);
        }
        let tally = Self {
            reference_extensions,
            signers,
            deviations,
        };
        tally
            .validate(leader, config)
            .map_err(|_| CodecError::Invalid("Tally", "non-canonical transcript"))?;
        Ok(tally)
    }
}

/// A complete vote for another leader block in the same view.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConflictingVote<D: Digest> {
    signer: Participant,
    leader: D,
    positions: Vec<Position>,
    extensions: Vec<Extension<D>>,
}

impl<D: Digest> ConflictingVote<D> {
    /// Creates a complete conflicting vote record.
    pub fn new(
        signer: Participant,
        leader: D,
        positions: Vec<Position>,
        extensions: Vec<Extension<D>>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
        if usize::from(signer) >= config.participants()
            || positions.len() != config.chains()
            || positions
                .iter()
                .any(|position| position.get() as usize > config.pipeline_depth())
            || extensions.len() != config.chains()
            || extensions
                .iter()
                .any(|extension| extension.len() > config.extension_bound())
        {
            return Err(Error::Transcript);
        }
        Ok(Self {
            signer,
            leader,
            positions,
            extensions,
        })
    }

    /// Returns the signer.
    pub const fn signer(&self) -> Participant {
        self.signer
    }

    /// Returns the other leader-block digest.
    pub const fn leader(&self) -> D {
        self.leader
    }

    /// Returns every reported chain position.
    pub fn positions(&self) -> &[Position] {
        &self.positions
    }

    /// Returns every reported chain extension.
    pub fn extensions(&self) -> &[Extension<D>] {
        &self.extensions
    }

    /// Reconstructs the exact signed vote body using the V-QC's round.
    pub fn vote_body(&self, round: Round, config: CodecConfig) -> Result<VoteBody<D>, Error> {
        VoteBody::new(
            round,
            self.leader,
            self.positions.clone(),
            self.extensions.clone(),
            config,
        )
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
        self.leader.write(writer);
        self.positions.write(writer);
        self.extensions.write(writer);
    }
}

impl<D: Digest> EncodeSize for ConflictingVote<D> {
    fn encode_size(&self) -> usize {
        self.signer.encode_size()
            + self.leader.encode_size()
            + self.positions.encode_size()
            + self.extensions.encode_size()
    }
}

impl<D: Digest> Read for ConflictingVote<D> {
    type Cfg = CodecConfig;

    fn read_cfg(reader: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let signer = ReadExt::read(reader)?;
        let leader = D::read(reader)?;
        let positions = Vec::<Position>::read_cfg(
            reader,
            &(RangeCfg::from(config.chains()..=config.chains()), ()),
        )?;
        let extensions = Vec::<Extension<D>>::read_cfg(
            reader,
            &(
                RangeCfg::from(config.chains()..=config.chains()),
                config.extension_bound(),
            ),
        )?;
        Self::new(signer, leader, positions, extensions, *config)
            .map_err(|_| CodecError::Invalid("ConflictingVote", "invalid vote record"))
    }
}

fn canonical_reference<V: Variant, D: Digest>(
    leader: &LeaderBlock<V, D>,
    votes: &[(Participant, VoteBody<D>)],
) -> Vec<Extension<D>> {
    let parts = votes
        .iter()
        .map(|(signer, body)| {
            (
                *signer,
                body.positions().to_vec(),
                body.extensions().to_vec(),
            )
        })
        .collect::<Vec<_>>();
    canonical_reference_parts(leader, &parts)
}

type ExpandedVote<D> = (Participant, Vec<Position>, Vec<Extension<D>>);

fn canonical_reference_parts<V: Variant, D: Digest>(
    leader: &LeaderBlock<V, D>,
    votes: &[ExpandedVote<D>],
) -> Vec<Extension<D>> {
    let mut standard_candidates = BTreeMap::<Vec<Extension<D>>, usize>::new();
    let mut all_candidates = BTreeMap::<Vec<Extension<D>>, usize>::new();
    for (_, positions, extensions) in votes {
        *all_candidates.entry(extensions.clone()).or_default() += 1;
        let at_tips = positions
            .iter()
            .zip(leader.proposals())
            .all(|(position, proposal)| position.get() == proposal.payloads().len() as u32);
        if at_tips {
            *standard_candidates.entry(extensions.clone()).or_default() += 1;
        }
    }

    let candidates = if standard_candidates.is_empty() {
        all_candidates
    } else {
        standard_candidates
    };
    candidates
        .into_iter()
        .max_by(|(left_value, left_count), (right_value, right_count)| {
            left_count
                .cmp(right_count)
                .then_with(|| right_value.encode().cmp(&left_value.encode()))
        })
        .map(|(extensions, _)| extensions)
        .expect("a tally always contains at least one vote")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            config::Limits,
            types::{Anchor, BlockRef, CertificateId, ChainId, ChainProposal, Height},
        },
        types::{Epoch, Round, View},
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{Hasher, Sha256, bls12381::primitives::variant::MinSig, sha256};
    use proptest::{collection::vec as prop_vec, prelude::*};

    fn digest(marker: u64) -> sha256::Digest {
        Sha256::hash(&[&marker.to_be_bytes()])
    }

    fn config() -> CodecConfig {
        CodecConfig::new(6, 6, Limits::new(2, 1).unwrap()).unwrap()
    }

    fn leader() -> LeaderBlock<MinSig, sha256::Digest> {
        let config = config();
        let proposals = (0..config.chains())
            .map(|index| {
                let chain = ChainId::new(index as u32);
                ChainProposal::new(
                    chain,
                    Anchor::Tip(BlockRef::new(chain, Height::zero(), digest(index as u64))),
                    vec![digest(100 + index as u64)],
                    config.pipeline_depth(),
                )
                .unwrap()
            })
            .collect();
        LeaderBlock::new(
            Round::new(Epoch::new(3), View::new(4)),
            CertificateId::new(digest(201)),
            digest(202),
            proposals,
            config,
        )
        .unwrap()
    }

    proptest! {
        #[test]
        fn compact_tally_round_trips_every_exact_vote(
            positions in prop_vec(prop_vec(0u32..=1, 6), 6),
            extension_flags in prop_vec(prop_vec(any::<bool>(), 6), 6),
            count in 1usize..=6,
        ) {
            let config = config();
            let leader = leader();
            let votes = (0..count)
                .map(|signer| {
                    let extensions = extension_flags[signer]
                        .iter()
                        .enumerate()
                        .map(|(chain, present)| {
                            let payloads = present.then(|| digest(1_000 + (signer * 6 + chain) as u64));
                            Extension::new(payloads.into_iter().collect(), config.extension_bound()).unwrap()
                        })
                        .collect();
                    let body = VoteBody::for_leader::<Sha256, MinSig>(
                        &leader,
                        positions[signer].iter().copied().map(Position::new).collect(),
                        extensions,
                        config,
                    )
                    .unwrap();
                    (Participant::from_usize(signer), body)
                })
                .collect::<Vec<_>>();
            let tally = Tally::from_votes::<MinSig, Sha256, _>(
                &leader,
                votes.iter().cloned(),
                config,
            )
            .unwrap();

            for (signer, expected) in &votes {
                prop_assert_eq!(
                    tally.vote::<MinSig, Sha256>(&leader, *signer, config).unwrap(),
                    expected.clone(),
                );
            }
            let mut encoded = tally.encode();
            let decoded = Tally::read_cfg(&mut encoded, &leader, config).unwrap();
            prop_assert!(!encoded.has_remaining());
            prop_assert_eq!(decoded, tally);
        }
    }

    #[test]
    fn reference_prefers_most_common_standard_vote_then_canonical_bytes() {
        let config = config();
        let leader = leader();
        let empty = vec![Extension::empty(); config.chains()];
        let mut carried = empty.clone();
        carried[0] = Extension::new(vec![digest(300)], config.extension_bound()).unwrap();
        let positions = vec![Position::new(1); config.chains()];
        let votes = [empty, carried.clone(), carried.clone()]
            .into_iter()
            .enumerate()
            .map(|(signer, extensions)| {
                (
                    Participant::from_usize(signer),
                    VoteBody::for_leader::<Sha256, MinSig>(
                        &leader,
                        positions.clone(),
                        extensions,
                        config,
                    )
                    .unwrap(),
                )
            });
        let tally = Tally::from_votes::<MinSig, Sha256, _>(&leader, votes, config).unwrap();
        assert_eq!(tally.reference_extensions(), carried);
    }

    #[test]
    fn reference_tie_breaks_by_canonical_bytes() {
        let config = CodecConfig::new(6, 6, Limits::new(2, 2).unwrap()).unwrap();
        let leader = leader();
        let positions = vec![Position::new(1); config.chains()];
        let mut short = vec![Extension::empty(); config.chains()];
        short[0] = Extension::new(vec![digest(900)], config.extension_bound()).unwrap();
        let mut long = vec![Extension::empty(); config.chains()];
        long[0] = Extension::new(vec![digest(1), digest(2)], config.extension_bound()).unwrap();
        let votes = [long, short.clone()]
            .into_iter()
            .enumerate()
            .map(|(signer, extensions)| {
                (
                    Participant::from_usize(signer),
                    VoteBody::for_leader::<Sha256, MinSig>(
                        &leader,
                        positions.clone(),
                        extensions,
                        config,
                    )
                    .unwrap(),
                )
            });

        let tally = Tally::from_votes::<MinSig, Sha256, _>(&leader, votes, config).unwrap();
        assert_eq!(tally.reference_extensions(), short);
    }

    #[test]
    fn validation_rejects_noncanonical_reference() {
        let config = config();
        let leader = leader();
        let body = VoteBody::for_leader::<Sha256, MinSig>(
            &leader,
            vec![Position::new(1); config.chains()],
            vec![Extension::empty(); config.chains()],
            config,
        )
        .unwrap();
        let mut tally =
            Tally::from_votes::<MinSig, Sha256, _>(&leader, [(Participant::new(0), body)], config)
                .unwrap();
        let original = tally.reference_extensions.clone();
        tally.reference_extensions[0] =
            Extension::new(vec![digest(400)], config.extension_bound()).unwrap();
        tally.deviations.push(Deviation::new(
            Participant::new(0),
            Vec::new(),
            Some(original),
        ));
        assert_eq!(tally.validate(&leader, config), Err(Error::Transcript));
        let mut encoded = tally.encode();
        assert!(Tally::read_cfg(&mut encoded, &leader, config).is_err());
    }

    #[test]
    fn validation_rejects_expanded_height_overflow() {
        let config = config();
        let proposals = (0..config.chains())
            .map(|index| {
                let chain = ChainId::new(index as u32);
                let height = if index == 0 {
                    Height::new(u64::MAX)
                } else {
                    Height::zero()
                };
                ChainProposal::new(
                    chain,
                    Anchor::<MinSig, _>::Tip(BlockRef::new(chain, height, digest(index as u64))),
                    Vec::new(),
                    config.pipeline_depth(),
                )
                .unwrap()
            })
            .collect();
        let leader = LeaderBlock::new(
            Round::new(Epoch::new(3), View::new(4)),
            CertificateId::new(digest(201)),
            digest(202),
            proposals,
            config,
        )
        .unwrap();
        let mut reference_extensions = vec![Extension::empty(); config.chains()];
        reference_extensions[0] =
            Extension::new(vec![digest(300)], config.extension_bound()).unwrap();
        let tally = Tally {
            reference_extensions,
            signers: Signers::from(config.participants(), [Participant::new(0)]),
            deviations: Vec::new(),
        };

        assert_eq!(tally.validate(&leader, config), Err(Error::Transcript));
        let mut encoded = tally.encode();
        assert!(Tally::read_cfg(&mut encoded, &leader, config).is_err());
    }

    #[test]
    fn expanding_untrusted_tally_never_indexes_an_unchecked_chain() {
        let config = config();
        let leader = leader();
        let mut tally = Tally {
            reference_extensions: vec![Extension::empty(); config.chains()],
            signers: Signers::from(config.participants(), [Participant::new(0)]),
            deviations: vec![Deviation::new(
                Participant::new(0),
                vec![PositionDeviation::new(
                    ChainId::new(u32::MAX),
                    Position::new(0),
                )],
                None,
            )],
        };

        assert_eq!(
            tally.vote::<MinSig, Sha256>(&leader, Participant::new(0), config),
            Err(Error::Transcript)
        );
        tally.signers = Signers::from(config.participants() + 1, [Participant::new(0)]);
        assert_eq!(
            tally.vote::<MinSig, Sha256>(&leader, Participant::new(0), config),
            Err(Error::Context)
        );
    }
}
