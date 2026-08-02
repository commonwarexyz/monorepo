//! Aggregate and recovered certificates for Multimmit.

use super::{
    BlockRef, CertificateId, ConflictingVote, Error, LeaderBlock, Tally, TransactionBlockHeader,
};
use crate::{
    Epochable, Heightable, Viewable,
    multimmit::config::CodecConfig,
    types::{Epoch, Height, Round, View},
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write, types::lazy::Lazy,
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
        self.round.epoch().write(writer);
        self.round.view().write(writer);
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
        let epoch = Epoch::read(reader)?;
        let view = View::read(reader)?;
        let round = Round::new(epoch, view);
        if round.view().is_zero() {
            return Err(CodecError::Invalid("Nullification", "view zero is genesis"));
        }
        let certificate = ReadExt::read(reader)?;
        Ok(Self { round, certificate })
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
        CertificateId::new(H::hash(&[self.encode().as_ref()]))
    }

    pub(crate) fn validate(&self, config: CodecConfig) -> Result<(), Error> {
        validate_vqc_parts(
            &self.leader,
            &self.tally,
            &self.novoters,
            &self.conflicting,
            config,
        )
    }
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
        let tally = Tally::read_cfg(reader, &leader, *config)?;
        let novoters = Signers::read_cfg(reader, &config.participants())?;
        let conflicting = Vec::<ConflictingVote<D>>::read_cfg(
            reader,
            &(RangeCfg::from(0..=config.vqc_max_messages()), *config),
        )?;
        let signature = Lazy::<aggregate::Signature<V>>::read(reader)?;
        validate_vqc_parts(&leader, &tally, &novoters, &conflicting, *config)
            .map_err(|_| CodecError::Invalid("Vqc", "invalid compact transcript"))?;
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

    /// Returns the identifier of this exact L-QC.
    pub fn id<H: Hasher<Digest = D>>(&self) -> CertificateId<D> {
        CertificateId::new(H::hash(&[self.encode().as_ref()]))
    }

    fn validate_structure(&self, config: CodecConfig) -> Result<(), Error> {
        self.leader.validate(config)?;
        self.tally.validate(&self.leader, config)?;
        validate_signers(self.tally.signers(), config, config.view_quorum())
    }

    pub(crate) fn validate(&self, config: CodecConfig) -> Result<(), Error> {
        self.validate_structure(config)
    }

    /// Returns whether a V-QC carries this exact all-vote transcript and aggregate.
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
    pub(crate) fn derive_vqc(&self, config: CodecConfig) -> Result<Vqc<V, D>, Error> {
        let signature = self.signature().cloned().ok_or(Error::Transcript)?;
        Vqc::new(
            self.leader.clone(),
            self.tally.clone(),
            Signers::from(config.participants(), []),
            Vec::new(),
            signature,
            config,
        )
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
        let tally = Tally::read_cfg(reader, &leader, *config)?;
        let signature = Lazy::<aggregate::Signature<V>>::read(reader)?;
        tally
            .validate(&leader, *config)
            .and_then(|()| validate_signers(tally.signers(), *config, config.view_quorum()))
            .map_err(|_| CodecError::Invalid("Lqc", "invalid compact transcript"))?;
        Ok(Self {
            leader,
            tally,
            signature,
        })
    }
}

fn validate_signers(signers: &Signers, config: CodecConfig, expected: usize) -> Result<(), Error> {
    if signers.len() != config.participants() || signers.count() != expected {
        return Err(Error::Quorum);
    }
    Ok(())
}

fn validate_vqc_parts<V: Variant, D: Digest>(
    leader: &LeaderBlock<V, D>,
    tally: &Tally<D>,
    novoters: &Signers,
    conflicting: &[ConflictingVote<D>],
    config: CodecConfig,
) -> Result<(), Error> {
    leader.validate(config)?;
    tally.validate(leader, config)?;
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
