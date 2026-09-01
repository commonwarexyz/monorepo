//! Aggregate and recovered certificates for Multimmit.

use super::{
    Ballot, BlockRef, CertificateId, ConflictingVote, Error, LeaderBlock, Tally,
    TransactionBlockHeader,
    bounds::{
        MAX_U64_VARINT_SIZE, VARINT_BOUNDARIES, checked_product, checked_sum, encoded_len,
        largest_index_width_sum, signers_size,
    },
    canonical_digest,
};
#[cfg(not(target_arch = "wasm32"))]
use super::{DigestedLeader, VoteBody};
#[cfg(not(target_arch = "wasm32"))]
use crate::types::Participant;
use crate::{
    Epochable, Heightable, Viewable,
    multimmit::types::CodecConfig,
    types::{Epoch, Height, Round, View},
};
use bytes::BufMut;
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, FixedSize as _, RangeCfg, Read, ReadExt, Write,
    types::lazy::Lazy,
};
use commonware_cryptography::{
    Digest, Hasher,
    bls12381::{
        certificate::threshold,
        primitives::{ops::aggregate, variant::Variant},
    },
    certificate::Signers,
};

/// A recovered data-availability threshold signature over one block header.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DaCertificate<V: Variant, D: Digest> {
    header: TransactionBlockHeader<D>,
    certificate: threshold::Certificate<V>,
}

impl<V: Variant, D: Digest> DaCertificate<V, D> {
    pub(crate) const fn new(
        header: TransactionBlockHeader<D>,
        certificate: threshold::Certificate<V>,
    ) -> Self {
        Self {
            header,
            certificate,
        }
    }

    /// Returns the certified transaction-block header.
    pub const fn header(&self) -> &TransactionBlockHeader<D> {
        &self.header
    }

    /// Returns the recovered threshold certificate.
    pub const fn certificate(&self) -> &threshold::Certificate<V> {
        &self.certificate
    }

    /// Returns the certified block as a compact chain reference.
    pub fn block_ref<H: Hasher<Digest = D>>(&self) -> BlockRef<D> {
        self.header.block_ref::<H>()
    }

    /// Returns the largest encoding of a data-availability certificate under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            TransactionBlockHeader::<D>::max_encode_size(codec)?,
            V::Signature::SIZE,
        ])
    }
}

impl<V: Variant, D: Digest> Epochable for DaCertificate<V, D> {
    fn epoch(&self) -> Epoch {
        self.header.epoch()
    }
}

impl<V: Variant, D: Digest> Heightable for DaCertificate<V, D> {
    fn height(&self) -> Height {
        self.header.height()
    }
}

impl<V: Variant, D: Digest> Write for DaCertificate<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.header.write(writer);
        self.certificate.write(writer);
    }
}

impl<V: Variant, D: Digest> EncodeSize for DaCertificate<V, D> {
    fn encode_size(&self) -> usize {
        self.header.encode_size() + self.certificate.encode_size()
    }
}

impl<V: Variant, D: Digest> Read for DaCertificate<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let header = ReadExt::read(reader)?;
        let certificate = ReadExt::read(reader)?;
        Ok(Self::new(header, certificate))
    }
}

/// A recovered threshold signature authorizing a view skip.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nullification<V: Variant> {
    round: Round,
    certificate: threshold::Certificate<V>,
}

impl<V: Variant> Nullification<V> {
    pub(crate) fn new(round: Round, certificate: threshold::Certificate<V>) -> Result<Self, Error> {
        if round.view().is_zero() {
            return Err(Error::GenesisView);
        }
        Ok(Self { round, certificate })
    }

    /// Returns the nullified round.
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Returns the recovered threshold certificate.
    pub const fn certificate(&self) -> &threshold::Certificate<V> {
        &self.certificate
    }

    /// Returns the largest encoding of a nullification.
    pub(super) fn max_encode_size() -> Option<usize> {
        checked_sum(&[checked_product(2, MAX_U64_VARINT_SIZE)?, V::Signature::SIZE])
    }
}

impl<V: Variant> Epochable for Nullification<V> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<V: Variant> Viewable for Nullification<V> {
    fn view(&self) -> View {
        self.round.view()
    }
}

impl<V: Variant> Write for Nullification<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.certificate.write(writer);
    }
}

impl<V: Variant> EncodeSize for Nullification<V> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.certificate.encode_size()
    }
}

impl<V: Variant> Read for Nullification<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let round = Round::read(reader)?;
        let certificate = ReadExt::read(reader)?;
        Self::new(round, certificate)
            .map_err(|error| CodecError::Wrapped("Nullification", error.into()))
    }
}

/// A view quorum certificate over votes and novotes from `n-f..=n` participants.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Vqc<V: Variant, D: Digest> {
    leader: LeaderBlock<V, D>,
    tally: Tally<D>,
    novoters: Signers,
    conflicting: Vec<ConflictingVote<D>>,
    signature: Lazy<aggregate::Signature<V>>,
}

impl<V: Variant, D: Digest> Vqc<V, D> {
    pub(crate) fn new(
        leader: LeaderBlock<V, D>,
        tally: Tally<D>,
        novoters: Signers,
        conflicting: Vec<ConflictingVote<D>>,
        signature: aggregate::Signature<V>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
        let certificate = Self {
            leader,
            tally,
            novoters,
            conflicting,
            signature: signature.into(),
        };
        certificate.validate(config)?;
        Ok(certificate)
    }

    /// Returns the unsigned designated leader block.
    pub const fn leader(&self) -> &LeaderBlock<V, D> {
        &self.leader
    }

    /// Returns the compact complete votes for the designated leader.
    pub const fn tally(&self) -> &Tally<D> {
        &self.tally
    }

    /// Returns participants contributing a novote.
    pub const fn novoters(&self) -> &Signers {
        &self.novoters
    }

    /// Returns complete votes for other leader blocks in the same view.
    pub fn conflicting_votes(&self) -> &[ConflictingVote<D>] {
        &self.conflicting
    }

    /// Returns the decoded aggregate authenticating the complete view messages.
    pub fn signature(&self) -> Option<&aggregate::Signature<V>> {
        self.signature.get()
    }

    /// Returns the identifier used by leader blocks to reference this V-QC.
    pub fn id<H: Hasher<Digest = D>>(&self) -> CertificateId<D> {
        CertificateId::new(canonical_digest::<H>(self))
    }

    pub(crate) fn validate(&self, config: CodecConfig) -> Result<(), Error> {
        self.leader.validate(config)?;
        self.tally.validate(&self.leader, config)?;
        validate_vqc_participants(&self.tally, &self.novoters, &self.conflicting, config)
    }

    /// Rebuilds the vote of every tallied signer, in signer order.
    ///
    /// `leader_digest` is the digest of [`Self::leader`], which the caller derives once.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn expand_votes(
        &self,
        leader_digest: D,
        config: CodecConfig,
    ) -> Result<Vec<(Participant, VoteBody<D>)>, Error> {
        expand_tally(&self.leader, &self.tally, leader_digest, config)
    }

    /// Rebuilds the vote of every conflicting signer, in signer order.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn conflicting_bodies(&self) -> Result<Vec<(Participant, VoteBody<D>)>, Error> {
        let round = self.leader.round();
        self.conflicting
            .iter()
            .map(|vote| Ok((vote.signer(), vote.vote_body(round)?)))
            .collect()
    }

    /// Returns the largest encoding of a V-QC under `codec`.
    ///
    /// Fewer tallied votes leave more conflicting votes, and varint widths step at fixed
    /// boundaries, so the size is evaluated at every tallied-vote count where it can peak.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        let participants = codec.participants();
        let maximum = codec.vqc_max_messages();
        let leader = LeaderBlock::<V, D>::max_encode_size(codec)?;
        let conflicting_vote = Ballot::<D>::max_encode_size(codec)?;
        // Tally deviations and conflicting votes name distinct signers.
        let signer_indices = largest_index_width_sum(participants, maximum)?;
        let novoters = signers_size(participants)?;
        let mut largest = 0;
        for votes in vqc_candidates(codec.designation_quorum(), maximum, codec.chains()) {
            let conflicting = maximum - votes;
            let candidate = checked_sum(&[
                leader,
                Tally::<D>::max_encode_size_without_signer_indices(codec, votes)?,
                signer_indices,
                novoters,
                encoded_len(conflicting)?,
                checked_product(conflicting, conflicting_vote)?,
                V::Signature::SIZE,
            ])?;
            largest = largest.max(candidate);
        }
        Some(largest)
    }
}

/// Rebuilds the vote of every signer `tally` attests for `leader`, in signer order.
#[cfg(not(target_arch = "wasm32"))]
fn expand_tally<V: Variant, D: Digest>(
    leader: &LeaderBlock<V, D>,
    tally: &Tally<D>,
    leader_digest: D,
    config: CodecConfig,
) -> Result<Vec<(Participant, VoteBody<D>)>, Error> {
    tally
        .signers()
        .iter()
        .map(|signer| {
            let body = tally.vote(
                DigestedLeader::with_digest(leader, leader_digest),
                signer,
                config,
            )?;
            Ok((signer, body))
        })
        .collect()
}

impl<V: Variant, D: Digest> Epochable for Vqc<V, D> {
    fn epoch(&self) -> Epoch {
        self.leader.epoch()
    }
}

impl<V: Variant, D: Digest> Viewable for Vqc<V, D> {
    fn view(&self) -> View {
        self.leader.view()
    }
}

/// Returns the tallied-vote counts between `minimum` and `maximum` at which a V-QC's size can
/// peak.
fn vqc_candidates(minimum: usize, maximum: usize, chains: usize) -> Vec<usize> {
    let mut candidates = vec![minimum, maximum];
    for boundary in VARINT_BOUNDARIES {
        candidates.extend([boundary.saturating_sub(1), boundary]);
        // Path table counts and indices widen after (votes - 1) * chains crosses a boundary.
        let path_boundary = boundary.div_ceil(chains) + 1;
        candidates.extend([path_boundary - 1, path_boundary]);
        if maximum >= boundary {
            candidates.extend([maximum - boundary, maximum - boundary + 1]);
        }
    }
    candidates.retain(|candidate| (*candidate >= minimum) && (*candidate <= maximum));
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

impl<V: Variant, D: Digest> Write for Vqc<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.leader.write(writer);
        self.tally.write(writer);
        self.novoters.write(writer);
        self.conflicting.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Variant, D: Digest> EncodeSize for Vqc<V, D> {
    fn encode_size(&self) -> usize {
        self.leader.encode_size()
            + self.tally.encode_size()
            + self.novoters.encode_size()
            + self.conflicting.encode_size()
            + self.signature.encode_size()
    }
}

impl<V: Variant, D: Digest> Read for Vqc<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(reader: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let leader = LeaderBlock::<V, D>::read_cfg(reader, config)?;
        let tally = Tally::decode_for_leader(reader, &leader, *config)?;
        let novoters = Signers::read_cfg(reader, &config.participants())?;
        let conflicting = Vec::<ConflictingVote<D>>::read_cfg(
            reader,
            &(RangeCfg::from(0..=config.vqc_max_messages()), *config),
        )?;
        let signature = Lazy::<aggregate::Signature<V>>::read(reader)?;
        validate_vqc_participants(&tally, &novoters, &conflicting, *config)
            .map_err(|error| CodecError::Wrapped("Vqc", error.into()))?;
        Ok(Self {
            leader,
            tally,
            novoters,
            conflicting,
            signature,
        })
    }
}

/// A leader quorum certificate over exactly `n-f` votes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Lqc<V: Variant, D: Digest> {
    leader: LeaderBlock<V, D>,
    tally: Tally<D>,
    signature: Lazy<aggregate::Signature<V>>,
}

impl<V: Variant, D: Digest> Lqc<V, D> {
    pub(crate) fn new(
        leader: LeaderBlock<V, D>,
        tally: Tally<D>,
        signature: aggregate::Signature<V>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
        let certificate = Self {
            leader,
            tally,
            signature: signature.into(),
        };
        certificate.validate(config)?;
        Ok(certificate)
    }

    /// Returns the finalized unsigned leader block.
    pub const fn leader(&self) -> &LeaderBlock<V, D> {
        &self.leader
    }

    /// Returns the compact complete-vote transcript.
    pub const fn tally(&self) -> &Tally<D> {
        &self.tally
    }

    /// Returns the decoded aggregate, or `None` if its group element is malformed.
    pub fn signature(&self) -> Option<&aggregate::Signature<V>> {
        self.signature.get()
    }

    /// Returns the identifier of this L-QC.
    pub fn id<H: Hasher<Digest = D>>(&self) -> CertificateId<D> {
        CertificateId::new(canonical_digest::<H>(self))
    }

    pub(crate) fn validate(&self, config: CodecConfig) -> Result<(), Error> {
        self.leader.validate(config)?;
        self.tally.validate(&self.leader, config)?;
        validate_signers(self.tally.signers(), config)
    }

    /// Rebuilds the vote of every tallied signer, in signer order.
    ///
    /// `leader_digest` is the digest of [`Self::leader`], which the caller derives once.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn expand_votes(
        &self,
        leader_digest: D,
        config: CodecConfig,
    ) -> Result<Vec<(Participant, VoteBody<D>)>, Error> {
        expand_tally(&self.leader, &self.tally, leader_digest, config)
    }

    /// Returns whether a V-QC carries this exact all-vote transcript and aggregate.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn equivalent_vqc(&self, certificate: &Vqc<V, D>) -> bool {
        let Some(signature) = self.signature() else {
            return false;
        };
        certificate.leader() == &self.leader
            && certificate.tally() == &self.tally
            && certificate.novoters().count() == 0
            && certificate.conflicting_votes().is_empty()
            && certificate.signature() == Some(signature)
    }

    /// Derives the equivalent all-vote V-QC without re-aggregating signatures.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn derive_vqc(&self, config: CodecConfig) -> Result<Vqc<V, D>, Error> {
        let signature = self.signature().cloned().ok_or(Error::Transcript)?;
        Vqc::new(
            self.leader.clone(),
            self.tally.clone(),
            Signers::new(
                config
                    .participants()
                    .try_into()
                    .map_err(|_| Error::Participants)?,
                [],
            )
            .map_err(|_| Error::Participants)?,
            Vec::new(),
            signature,
            config,
        )
    }

    /// Returns the largest encoding of an L-QC under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            LeaderBlock::<V, D>::max_encode_size(codec)?,
            Tally::<D>::max_encode_size(codec, codec.view_quorum())?,
            V::Signature::SIZE,
        ])
    }
}

impl<V: Variant, D: Digest> Epochable for Lqc<V, D> {
    fn epoch(&self) -> Epoch {
        self.leader.epoch()
    }
}

impl<V: Variant, D: Digest> Viewable for Lqc<V, D> {
    fn view(&self) -> View {
        self.leader.view()
    }
}

impl<V: Variant, D: Digest> Write for Lqc<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.leader.write(writer);
        self.tally.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Variant, D: Digest> EncodeSize for Lqc<V, D> {
    fn encode_size(&self) -> usize {
        self.leader.encode_size() + self.tally.encode_size() + self.signature.encode_size()
    }
}

impl<V: Variant, D: Digest> Read for Lqc<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(reader: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let leader = LeaderBlock::<V, D>::read_cfg(reader, config)?;
        let tally = Tally::decode_for_leader(reader, &leader, *config)?;
        let signature = Lazy::<aggregate::Signature<V>>::read(reader)?;
        validate_signers(tally.signers(), *config)
            .map_err(|error| CodecError::Wrapped("Lqc", error.into()))?;
        Ok(Self {
            leader,
            tally,
            signature,
        })
    }
}

/// Checks that an L-QC tally names exactly a view quorum of the committee.
fn validate_signers(signers: &Signers, config: CodecConfig) -> Result<(), Error> {
    if signers.len() != config.participants() || signers.count() != config.view_quorum() {
        return Err(Error::Quorum);
    }
    Ok(())
}

fn validate_vqc_participants<D: Digest>(
    tally: &Tally<D>,
    novoters: &Signers,
    conflicting: &[ConflictingVote<D>],
    config: CodecConfig,
) -> Result<(), Error> {
    if tally.signers().count() < config.designation_quorum()
        || novoters.len() != config.participants()
        || conflicting
            .windows(2)
            .any(|pair| pair[0].signer() >= pair[1].signer())
    {
        return Err(Error::Quorum);
    }

    let mut accounted = vec![false; config.participants()];
    for signer in tally.signers().iter().chain(novoters.iter()) {
        let index = usize::from(signer);
        if accounted[index] {
            return Err(Error::Participants);
        }
        accounted[index] = true;
    }
    for vote in conflicting {
        let index = usize::from(vote.signer());
        if index >= accounted.len() || accounted[index] {
            return Err(Error::Participants);
        }
        accounted[index] = true;
    }
    let accounted = accounted.into_iter().filter(|accounted| *accounted).count();
    if !(config.view_quorum()..=config.vqc_max_messages()).contains(&accounted) {
        return Err(Error::Quorum);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::types::{
        Anchor, ChainId, ChainProposal, Extension, PathLimits, Position,
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinSig, sha256::Digest as Sha256Digest,
    };

    fn digest(marker: u64) -> Sha256Digest {
        Sha256::hash(&[&marker.to_be_bytes()])
    }

    fn config() -> CodecConfig {
        CodecConfig::new(6, 6, PathLimits::new(2, 1).unwrap()).unwrap()
    }

    fn leader(parent: u64) -> LeaderBlock<MinSig, Sha256Digest> {
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
            CertificateId::new(digest(parent)),
            digest(300),
            proposals,
            config,
        )
        .unwrap()
    }

    fn body(leader: &LeaderBlock<MinSig, Sha256Digest>, position: u32) -> VoteBody<Sha256Digest> {
        let config = config();
        VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(leader),
            vec![Position::new(position); config.chains()],
            vec![Extension::empty(); config.chains()],
            config,
        )
        .unwrap()
    }

    #[test]
    fn vqc_expansions_list_designated_votes_in_signer_order_and_conflicts_apart() {
        let config = config();
        let designated = leader(201);
        let conflicting = leader(202);
        let votes = [(4, 1), (1, 0), (0, 1), (2, 0)]
            .map(|(signer, position)| (Participant::new(signer), body(&designated, position)));
        let tally = Tally::from_votes(
            DigestedLeader::new::<Sha256>(&designated),
            votes.iter().cloned(),
            config,
        )
        .unwrap();
        let conflict = body(&conflicting, 0);
        let certificate = Vqc::new(
            designated.clone(),
            tally,
            Signers::new(u32::try_from(config.participants()).unwrap(), []).unwrap(),
            vec![
                ConflictingVote::new(Participant::new(3), conflict.ballot().clone(), config)
                    .unwrap(),
            ],
            aggregate::Signature::<MinSig>::zero(),
            config,
        )
        .unwrap();

        let mut expected = votes.to_vec();
        expected.sort_by_key(|(signer, _)| *signer);
        assert_eq!(
            certificate
                .expand_votes(designated.digest::<Sha256>(), config)
                .unwrap(),
            expected
        );
        assert_eq!(
            certificate.conflicting_bodies().unwrap(),
            vec![(Participant::new(3), conflict)]
        );
        // The tally binds the designated leader: expanding it for another leader's digest does
        // not reproduce the designated votes.
        assert!(
            certificate
                .expand_votes(conflicting.digest::<Sha256>(), config)
                .map_or(true, |votes| votes != expected)
        );
    }

    #[test]
    fn lqc_expansion_lists_every_vote_in_signer_order() {
        let config = config();
        let finalized = leader(201);
        let votes = [5, 3, 0, 1, 2].map(|signer| (Participant::new(signer), body(&finalized, 1)));
        let tally = Tally::from_votes(
            DigestedLeader::new::<Sha256>(&finalized),
            votes.iter().cloned(),
            config,
        )
        .unwrap();
        let certificate = Lqc::new(
            finalized.clone(),
            tally,
            aggregate::Signature::<MinSig>::zero(),
            config,
        )
        .unwrap();

        let mut expected = votes.to_vec();
        expected.sort_by_key(|(signer, _)| *signer);
        assert_eq!(
            certificate
                .expand_votes(finalized.digest::<Sha256>(), config)
                .unwrap(),
            expected
        );
    }
}
