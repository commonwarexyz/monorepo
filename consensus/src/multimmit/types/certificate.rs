//! Aggregate quorum certificates for Multimmit.

use super::{
    CertificateId, Error, FinalTally, LeaderBlock, VoteContent, VoteTally, bounds::checked_sum,
};
use crate::{
    Epochable, Viewable,
    multimmit::types::CodecConfig,
    types::{Epoch, Participant, Round, View},
};
use bytes::BufMut;
use commonware_codec::{
    Buf, Encode as _, EncodeSize, Error as CodecError, FixedSize as _, Read, ReadExt, Write,
    types::lazy::Lazy,
};
use commonware_cryptography::{
    Digest, Hasher,
    bls12381::primitives::{ops::aggregate, variant::Variant},
};

/// A view quorum certificate: exactly `n - f` final votes of one view and the V-QC of the previous
/// view it extends.
///
/// Every view yields at least one V-QC. If at least `n - 3f` recorded votes are for one leader
/// block, the V-QC designates it and its parent must be the parent that leader block names.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Vqc<V: Variant, D: Digest> {
    round: Round,
    parent: CertificateId<D>,
    tally: FinalTally<D>,
    signature: Lazy<aggregate::Signature<V>>,
}

impl<V: Variant, D: Digest> Vqc<V, D> {
    /// Creates a V-QC within `config`'s byte ceiling. The signature is not verified.
    pub fn new(
        round: Round,
        parent: CertificateId<D>,
        tally: FinalTally<D>,
        signature: aggregate::Signature<V>,
        config: CodecConfig,
    ) -> Result<Self, Error> {
        if round.view().is_zero() {
            return Err(Error::GenesisView);
        }
        let certificate = Self {
            round,
            parent,
            tally,
            signature: signature.into(),
        };
        if certificate.encode_size() > config.max_vqc_bytes() {
            return Err(Error::Size);
        }
        Ok(certificate)
    }

    /// Returns the certified round.
    pub const fn round(&self) -> Round {
        self.round
    }

    /// Returns the identifier of the parent V-QC.
    pub const fn parent(&self) -> CertificateId<D> {
        self.parent
    }

    /// Returns the compact final-vote transcript.
    pub const fn tally(&self) -> &FinalTally<D> {
        &self.tally
    }

    /// Returns the decoded aggregate, or `None` if its group element is malformed.
    pub fn signature(&self) -> Option<&aggregate::Signature<V>> {
        self.signature.get()
    }

    /// Rebuilds every recorded final vote, in signer order.
    pub fn contents(&self) -> Vec<(Participant, VoteContent<D>)> {
        self.tally.contents(self.round)
    }

    /// Returns the identifier leader blocks and child V-QCs use to reference this V-QC.
    pub fn id<H: Hasher<Digest = D>>(&self) -> CertificateId<D> {
        CertificateId::from_canonical::<H>(&self.encode())
    }

    /// Returns the largest encoding of a V-QC under `codec`.
    pub(super) const fn max_encode_size(codec: CodecConfig) -> usize {
        codec.max_vqc_bytes()
    }
}

impl<V: Variant, D: Digest> Epochable for Vqc<V, D> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<V: Variant, D: Digest> Viewable for Vqc<V, D> {
    fn view(&self) -> View {
        self.round.view()
    }
}

impl<V: Variant, D: Digest> Write for Vqc<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.parent.write(buf);
        self.tally.write(buf);
        self.signature.write(buf);
    }
}

impl<V: Variant, D: Digest> EncodeSize for Vqc<V, D> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.parent.encode_size()
            + self.tally.encode_size()
            + self.signature.encode_size()
    }
}

impl<V: Variant, D: Digest> Read for Vqc<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let round = Round::read(buf)?;
        if round.view().is_zero() {
            return Err(CodecError::Wrapped("Vqc", Error::GenesisView.into()));
        }
        let parent = CertificateId::read(buf)?;
        let tally = FinalTally::read_cfg(buf, config)?;
        let signature = Lazy::read(buf)?;
        let certificate = Self {
            round,
            parent,
            tally,
            signature,
        };
        if certificate.encode_size() > config.max_vqc_bytes() {
            return Err(CodecError::Wrapped("Vqc", Error::Size.into()));
        }
        Ok(certificate)
    }
}

/// A leader quorum certificate: exactly `n - f` votes, final or not, for one leader block.
///
/// Together with the [`HistoryRecord`](super::HistoryRecord) opening the leader block's history
/// commitment, an L-QC proves that every correct log contains the opened tips.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Lqc<V: Variant, D: Digest> {
    leader: LeaderBlock<D>,
    tally: VoteTally<D>,
    signature: Lazy<aggregate::Signature<V>>,
}

impl<V: Variant, D: Digest> Lqc<V, D> {
    /// Creates an L-QC. The signature is not verified.
    pub fn new(
        leader: LeaderBlock<D>,
        tally: VoteTally<D>,
        signature: aggregate::Signature<V>,
    ) -> Self {
        Self {
            leader,
            tally,
            signature: signature.into(),
        }
    }

    /// Returns the finalized leader block.
    pub const fn leader(&self) -> &LeaderBlock<D> {
        &self.leader
    }

    /// Returns the compact vote transcript.
    pub const fn tally(&self) -> &VoteTally<D> {
        &self.tally
    }

    /// Returns the decoded aggregate, or `None` if its group element is malformed.
    pub fn signature(&self) -> Option<&aggregate::Signature<V>> {
        self.signature.get()
    }

    /// Rebuilds every recorded vote, in signer order.
    pub fn contents<H: Hasher<Digest = D>>(&self) -> Vec<(Participant, VoteContent<D>)> {
        self.tally
            .contents(self.leader.round(), self.leader.digest::<H>())
    }

    /// Returns the identifier of this L-QC.
    pub fn id<H: Hasher<Digest = D>>(&self) -> CertificateId<D> {
        CertificateId::from_canonical::<H>(&self.encode())
    }

    /// Returns the largest encoding of an L-QC under `codec`.
    pub(super) fn max_encode_size(codec: CodecConfig) -> Option<usize> {
        checked_sum(&[
            LeaderBlock::<D>::max_encode_size()?,
            VoteTally::<D>::max_encode_size(codec)?,
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
    fn write(&self, buf: &mut impl BufMut) {
        self.leader.write(buf);
        self.tally.write(buf);
        self.signature.write(buf);
    }
}

impl<V: Variant, D: Digest> EncodeSize for Lqc<V, D> {
    fn encode_size(&self) -> usize {
        self.leader.encode_size() + self.tally.encode_size() + self.signature.encode_size()
    }
}

impl<V: Variant, D: Digest> Read for Lqc<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            leader: LeaderBlock::read(buf)?,
            tally: VoteTally::read_cfg(buf, config)?,
            signature: Lazy::read(buf)?,
        })
    }
}
