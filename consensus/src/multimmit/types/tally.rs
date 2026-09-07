//! Compact, reversible vote transcripts used by Multimmit quorum certificates.

use super::{ChainId, Error, Extension, LeaderBlock, Position, VoteBody, vote::paths_valid_for};
use crate::{
    multimmit::config::CodecConfig,
    types::{Attributable, Round},
};
use bytes::BufMut;
use commonware_codec::{
    Buf, Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write,
};
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

/// One chain's replacement for a tally's reference extension.
///
/// An empty replacement clears the reference extension for this chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExtensionDeviation<D: Digest> {
    chain: ChainId,
    extension: Extension<D>,
}

impl<D: Digest> ExtensionDeviation<D> {
    /// Creates an extension replacement for `chain`.
    pub const fn new(chain: ChainId, extension: Extension<D>) -> Self {
        Self { chain, extension }
    }

    /// Returns the affected chain.
    pub const fn chain(&self) -> ChainId {
        self.chain
    }

    /// Returns the replacement extension.
    pub const fn extension(&self) -> &Extension<D> {
        &self.extension
    }
}

impl<D: Digest> Write for ExtensionDeviation<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chain.write(writer);
        self.extension.write(writer);
    }
}

impl<D: Digest> Read for ExtensionDeviation<D> {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, bound: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            chain: ReadExt::read(reader)?,
            extension: Extension::read_cfg(reader, bound)?,
        })
    }
}

impl<D: Digest> EncodeSize for ExtensionDeviation<D> {
    fn encode_size(&self) -> usize {
        self.chain.encode_size() + self.extension.encode_size()
    }
}

/// The fields by which one vote differs from a tally's standard vote.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Deviation<D: Digest> {
    signer: Participant,
    positions: Vec<PositionDeviation>,
    extensions: Vec<ExtensionDeviation<D>>,
}

impl<D: Digest> Deviation<D> {
    /// Creates a deviation record.
    pub(crate) const fn new(
        signer: Participant,
        positions: Vec<PositionDeviation>,
        extensions: Vec<ExtensionDeviation<D>>,
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
    pub fn extensions(&self) -> &[ExtensionDeviation<D>] {
        &self.extensions
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
        let extensions = Vec::<ExtensionDeviation<D>>::read_cfg(
            reader,
            &(
                RangeCfg::from(0..=config.chains()),
                config.extension_bound(),
            ),
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

        let reference_extensions = canonical_reference(
            leader,
            votes
                .iter()
                .map(|(_, body)| (body.positions(), body.extensions())),
        );
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
            let extensions = body
                .extensions()
                .iter()
                .zip(&reference_extensions)
                .enumerate()
                .filter(|(_, (extension, reference))| extension != reference)
                .map(|(chain, (extension, _))| {
                    ExtensionDeviation::new(ChainId::new(chain as u32), extension.clone())
                })
                .collect::<Vec<_>>();
            if positions.is_empty() && extensions.is_empty() {
                continue;
            }
            deviations.push(Deviation::new(*signer, positions, extensions));
        }

        let signers = Signers::new(
            config
                .participants()
                .try_into()
                .map_err(|_| Error::Participants)?,
            votes.iter().map(|(signer, _)| *signer),
        )
        .map_err(|_| Error::Participants)?;
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
        let (positions, extensions) = self.vote_parts(leader, signer, config)?;
        VoteBody::for_leader::<H, V>(leader, positions, extensions, config)
    }

    pub(crate) fn vote_with_leader_digest<V: Variant>(
        &self,
        leader: &LeaderBlock<V, D>,
        leader_digest: D,
        signer: Participant,
        config: CodecConfig,
    ) -> Result<VoteBody<D>, Error> {
        let (positions, extensions) = self.vote_parts(leader, signer, config)?;
        VoteBody::for_leader_digest(leader, leader_digest, positions, extensions, config)
    }

    fn vote_parts<V: Variant>(
        &self,
        leader: &LeaderBlock<V, D>,
        signer: Participant,
        config: CodecConfig,
    ) -> Result<(Vec<Position>, Vec<Extension<D>>), Error> {
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
            for replacement in &deviation.extensions {
                let Some(current) = extensions.get_mut(replacement.chain.get() as usize) else {
                    return Err(Error::Transcript);
                };
                current.clone_from(&replacement.extension);
            }
        }

        Ok((positions, extensions))
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
                || deviation.positions.is_empty() && deviation.extensions.is_empty()
                || deviation
                    .positions
                    .windows(2)
                    .any(|pair| pair[0].chain >= pair[1].chain)
                || deviation
                    .extensions
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
            for replacement in &deviation.extensions {
                let Some(reference) = self
                    .reference_extensions
                    .get(replacement.chain.get() as usize)
                else {
                    return Err(Error::Transcript);
                };
                if replacement.extension == *reference
                    || replacement.extension.len() > config.extension_bound()
                {
                    return Err(Error::Transcript);
                }
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
                    for replacement in &deviation.extensions {
                        extensions[replacement.chain.get() as usize]
                            .clone_from(&replacement.extension);
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
        if canonical_reference(
            leader,
            expanded
                .iter()
                .map(|(_, positions, extensions)| (positions.as_slice(), extensions.as_slice())),
        ) != self.reference_extensions
        {
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

fn canonical_reference<'a, V: Variant, D: Digest>(
    leader: &LeaderBlock<V, D>,
    votes: impl IntoIterator<Item = (&'a [Position], &'a [Extension<D>])>,
) -> Vec<Extension<D>> {
    let mut standard_candidates = BTreeMap::<Vec<Extension<D>>, usize>::new();
    let mut all_candidates = BTreeMap::<Vec<Extension<D>>, usize>::new();
    for (positions, extensions) in votes {
        *all_candidates.entry(extensions.to_vec()).or_default() += 1;
        let at_tips = positions
            .iter()
            .zip(leader.proposals())
            .all(|(position, proposal)| position.get() == proposal.payloads().len() as u32);
        if at_tips {
            *standard_candidates.entry(extensions.to_vec()).or_default() += 1;
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
            machine::algebra::{FinalTips, VqcExtraction},
            mocks::Committee,
            types::{
                Anchor, BlockRef, CertificateId, ChainId, ChainProposal, Height, Lqc, ViewMessage,
                Vqc,
            },
        },
        types::{Epoch, Round, View},
    };
    use bytes::{Buf as _, BytesMut};
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{
        Hasher, Sha256,
        bls12381::primitives::variant::{MinPk, MinSig},
        sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
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
    fn decoding_rejects_noncanonical_extension_deviations() {
        let config = config();
        let leader = leader();
        let extension = Extension::new(vec![digest(300)], config.extension_bound()).unwrap();
        let body = VoteBody::for_leader::<Sha256, MinSig>(
            &leader,
            vec![Position::new(1); config.chains()],
            vec![extension.clone(); config.chains()],
            config,
        )
        .unwrap();
        let tally = Tally::from_votes::<MinSig, Sha256, _>(
            &leader,
            (0..3).map(|signer| (Participant::new(signer), body.clone())),
            config,
        )
        .unwrap();
        let clear = |chain| ExtensionDeviation::new(ChainId::new(chain), Extension::empty());
        for replacements in [
            vec![],
            vec![clear(0), clear(0)],
            vec![clear(1), clear(0)],
            vec![clear(config.chains() as u32)],
            vec![clear(u32::MAX)],
            vec![ExtensionDeviation::new(ChainId::new(0), extension)],
            vec![
                clear(0),
                ExtensionDeviation::new(ChainId::new(1), tally.reference_extensions[1].clone()),
            ],
            vec![ExtensionDeviation::new(
                ChainId::new(0),
                Extension::new(vec![digest(400), digest(401)], 2).unwrap(),
            )],
        ] {
            let mut malformed = tally.clone();
            malformed
                .deviations
                .push(Deviation::new(Participant::new(0), vec![], replacements));
            assert_eq!(malformed.validate(&leader, config), Err(Error::Transcript));
            assert!(Tally::read_cfg(&mut malformed.encode(), &leader, config).is_err());
        }

        let mut valid = tally;
        valid
            .deviations
            .push(Deviation::new(Participant::new(0), vec![], vec![clear(0)]));
        assert_eq!(
            Tally::read_cfg(&mut valid.encode(), &leader, config).unwrap(),
            valid
        );
        assert!(
            valid
                .vote::<MinSig, Sha256>(&leader, Participant::new(0), config)
                .unwrap()
                .extensions()[0]
                .is_empty()
        );
    }

    #[test]
    fn decoding_bounds_extension_deviation_counts_and_payloads() {
        let config = config();
        let prefix = || {
            let mut bytes = BytesMut::new();
            Participant::new(0).write(&mut bytes);
            Vec::<PositionDeviation>::new().write(&mut bytes);
            bytes
        };
        let mut bytes = prefix();
        (config.chains() + 1).write(&mut bytes);
        assert!(matches!(
            Deviation::<sha256::Digest>::read_cfg(&mut bytes.freeze(), config),
            Err(CodecError::InvalidLength(_))
        ));

        let mut bytes = prefix();
        1usize.write(&mut bytes);
        ChainId::new(0).write(&mut bytes);
        (config.extension_bound() + 1).write(&mut bytes);
        assert!(matches!(
            Deviation::<sha256::Digest>::read_cfg(&mut bytes.freeze(), config),
            Err(CodecError::InvalidLength(_))
        ));
        let disabled = CodecConfig::new(6, 6, Limits::new(2, 0).unwrap()).unwrap();
        let mut bytes = prefix();
        1usize.write(&mut bytes);
        ChainId::new(0).write(&mut bytes);
        1usize.write(&mut bytes);
        assert!(matches!(
            Deviation::<sha256::Digest>::read_cfg(&mut bytes.freeze(), disabled),
            Err(CodecError::InvalidLength(_))
        ));
    }

    fn certificate_extension_deviations<V: Variant>() {
        for chains in [6, 128] {
            let committee = Committee::<V>::new_with_namespace(
                11,
                b"_COMMONWARE_CONSENSUS_SPARSE_TALLY_TEST",
                chains as u32,
                Limits::new(2, 1).unwrap(),
            );
            let config = committee.codec();
            let signed_leader = committee.leader_block(1);
            let leader = signed_leader.block();
            for changed in [0, 1, chains] {
                for (populated, clear) in [(false, false), (true, false), (true, true)] {
                    let reference = (0..chains)
                        .map(|chain| {
                            if populated {
                                Extension::new(vec![digest(chain as u64)], 1).unwrap()
                            } else {
                                Extension::empty()
                            }
                        })
                        .collect::<Vec<_>>();
                    let votes = (0..config.view_quorum())
                        .map(|signer| {
                            let mut extensions = reference.clone();
                            if signer >= config.view_quorum() - 2 {
                                for (chain, extension) in
                                    extensions.iter_mut().enumerate().rev().take(changed)
                                {
                                    *extension = if clear {
                                        Extension::empty()
                                    } else {
                                        Extension::new(vec![digest(1000 + chain as u64)], 1)
                                            .unwrap()
                                    };
                                }
                            }
                            let body = VoteBody::for_leader::<Sha256, V>(
                                leader,
                                vec![Position::new(0); chains],
                                extensions,
                                config,
                            )
                            .unwrap();
                            committee.signers[signer].sign_vote(body).unwrap()
                        })
                        .collect::<Vec<_>>();
                    let certificate = committee
                        .verifier
                        .assemble_lqc::<Sha256, _>(leader.clone(), &votes, &Sequential)
                        .unwrap();
                    let encoded = certificate.encode();
                    assert_eq!(encoded.len(), certificate.encode_size());
                    let decoded =
                        Lqc::<V, sha256::Digest>::decode_cfg(encoded.clone(), &config).unwrap();
                    assert_eq!(decoded, certificate);
                    assert!(
                        committee
                            .verifier
                            .verify_lqc::<_, Sha256, _>(&mut test_rng(), &decoded, &Sequential)
                            .is_some()
                    );
                    assert_eq!(decoded.tally().reference_extensions(), reference);
                    if changed > 0 {
                        let mut tampered = decoded.tally().clone();
                        tampered.deviations[0].extensions[0].extension =
                            Extension::new(vec![digest(10_000)], 1).unwrap();
                        let tampered = Lqc::new(
                            leader.clone(),
                            tampered,
                            decoded.signature().unwrap().clone(),
                            config,
                        )
                        .unwrap();
                        assert!(
                            committee
                                .verifier
                                .verify_lqc::<_, Sha256, _>(&mut test_rng(), &tampered, &Sequential)
                                .is_none()
                        );
                    }
                    for vote in &votes {
                        let expanded = decoded
                            .tally()
                            .vote::<V, Sha256>(leader, vote.signer(), config)
                            .unwrap();
                        assert_eq!(expanded.encode(), vote.body().encode());
                        assert_eq!(
                            decoded
                                .tally()
                                .vote_with_leader_digest(
                                    leader,
                                    leader.digest::<Sha256>(),
                                    vote.signer(),
                                    config
                                )
                                .unwrap(),
                            expanded
                        );
                    }
                    assert_eq!(
                        FinalTips::from_lqc::<Sha256, V>(&decoded, config).unwrap(),
                        FinalTips::from_pool::<Sha256, V, _>(
                            leader,
                            votes.iter().map(|vote| (vote.signer(), vote.body())),
                            config
                        )
                        .unwrap()
                    );
                    let messages = votes
                        .iter()
                        .cloned()
                        .map(ViewMessage::Vote)
                        .collect::<Vec<_>>();
                    let vqc = committee
                        .verifier
                        .assemble_vqc::<Sha256, _>(leader.clone(), &messages, &Sequential)
                        .unwrap();
                    let decoded_vqc =
                        Vqc::<V, sha256::Digest>::decode_cfg(vqc.encode(), &config).unwrap();
                    assert_eq!(decoded_vqc, vqc);
                    assert!(
                        committee
                            .verifier
                            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &decoded_vqc, &Sequential)
                            .is_some()
                    );
                    assert_eq!(
                        VqcExtraction::new::<Sha256, V>(&decoded_vqc, config)
                            .unwrap()
                            .into_parts()
                            .0,
                        VqcExtraction::from_votes::<Sha256, V>(
                            leader,
                            leader.digest::<Sha256>(),
                            votes.iter().map(|vote| (vote.signer(), vote.body())),
                            config
                        )
                        .unwrap()
                        .into_parts()
                        .0,
                    );

                    let tally = certificate.tally();
                    assert!(
                        tally
                            .deviations()
                            .iter()
                            .all(|deviation| deviation.extensions().len() == changed)
                    );
                    let mut dense = BytesMut::new();
                    tally.reference_extensions.write(&mut dense);
                    tally.signers.write(&mut dense);
                    tally.deviations.len().write(&mut dense);
                    for deviation in &tally.deviations {
                        deviation.signer.write(&mut dense);
                        deviation.positions.write(&mut dense);
                        Some(
                            votes[usize::from(deviation.signer)]
                                .body()
                                .extensions()
                                .to_vec(),
                        )
                        .write(&mut dense);
                    }
                    let old_size = encoded.len() - tally.encode_size() + dense.len();
                    let old_vqc_size = vqc.encode_size() - tally.encode_size() + dense.len();
                    eprintln!(
                        "{} chains={chains} populated={populated} changed={changed} clear={clear}: LQC {old_size}->{} VQC {old_vqc_size}->{}",
                        core::any::type_name::<V>(),
                        encoded.len(),
                        vqc.encode_size()
                    );
                    match changed {
                        0 => assert_eq!(encoded.len(), old_size),
                        1 => assert!(encoded.len() < old_size),
                        _ => assert_eq!(encoded.len(), old_size + 2 * (chains - 1)),
                    }
                    let bounds = config.encoded_bounds::<V, sha256::Digest>().unwrap();
                    assert!(encoded.len() <= bounds.max_artifact_bytes());
                    assert!(vqc.encode_size() <= bounds.max_artifact_bytes());
                }
            }
        }
    }

    #[test]
    fn sparse_certificates_preserve_signatures_tips_and_measure_sizes() {
        certificate_extension_deviations::<MinPk>();
        certificate_extension_deviations::<MinSig>();
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
        tally.reference_extensions[0] =
            Extension::new(vec![digest(400)], config.extension_bound()).unwrap();
        tally.deviations.push(Deviation::new(
            Participant::new(0),
            Vec::new(),
            vec![ExtensionDeviation::new(ChainId::new(0), Extension::empty())],
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
            signers: Signers::new(
                config.participants().try_into().unwrap(),
                [Participant::new(0)],
            )
            .unwrap(),
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
            signers: Signers::new(
                config.participants().try_into().unwrap(),
                [Participant::new(0)],
            )
            .unwrap(),
            deviations: vec![Deviation::new(
                Participant::new(0),
                vec![PositionDeviation::new(
                    ChainId::new(u32::MAX),
                    Position::new(0),
                )],
                Vec::new(),
            )],
        };

        assert_eq!(
            tally.vote::<MinSig, Sha256>(&leader, Participant::new(0), config),
            Err(Error::Transcript)
        );
        tally.deviations[0].positions.clear();
        tally.deviations[0].extensions.push(ExtensionDeviation::new(
            ChainId::new(u32::MAX),
            Extension::empty(),
        ));
        assert_eq!(
            tally.vote::<MinSig, Sha256>(&leader, Participant::new(0), config),
            Err(Error::Transcript)
        );
        tally.signers = Signers::new((config.participants() + 1).try_into().unwrap(), [Participant::new(0)]).unwrap();
        assert_eq!(
            tally.vote::<MinSig, Sha256>(&leader, Participant::new(0), config),
            Err(Error::Context)
        );
    }
}
