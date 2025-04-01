use commonware_codec::{Codec, Error, Reader, SizedCodec, Writer};
use commonware_cryptography::{
    bls12381::primitives::{group::Signature, poly::PartialSignature},
    Digest,
};

use super::View;

#[derive(Clone, Debug, PartialEq)]
pub enum Voter<D: Digest> {
    Notarize(Notarize<D>),
    Notarization(Notarization<D>),
    Nullify(Nullify),
    Nullification(Nullification),
    Finalize(Finalize<D>),
    Finalization(Finalization<D>),
}

impl<D: Digest> Codec for Voter<D> {
    fn write(&self, writer: &mut impl Writer) {
        match self {
            Voter::Notarize(v) => {
                writer.write_u8(0);
                v.write(writer);
            }
            Voter::Notarization(v) => {
                writer.write_u8(1);
                v.write(writer);
            }
            Voter::Nullify(v) => {
                writer.write_u8(2);
                v.write(writer);
            }
            Voter::Nullification(v) => {
                writer.write_u8(3);
                v.write(writer);
            }
            Voter::Finalize(v) => {
                writer.write_u8(4);
                v.write(writer);
            }
            Voter::Finalization(v) => {
                writer.write_u8(5);
                v.write(writer);
            }
        }
    }

    fn len_encoded(&self) -> usize {
        (match self {
            Voter::Notarize(v) => Codec::len_encoded(v),
            Voter::Notarization(v) => Codec::len_encoded(v),
            Voter::Nullify(v) => Codec::len_encoded(v),
            Voter::Nullification(v) => Codec::len_encoded(v),
            Voter::Finalize(v) => Codec::len_encoded(v),
            Voter::Finalization(v) => Codec::len_encoded(v),
        }) + 1
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let tag = reader.read_u8()?;
        match tag {
            0 => {
                let v = Notarize::read(reader)?;
                Ok(Voter::Notarize(v))
            }
            1 => {
                let v = Notarization::read(reader)?;
                Ok(Voter::Notarization(v))
            }
            2 => {
                let v = Nullify::read(reader)?;
                Ok(Voter::Nullify(v))
            }
            3 => {
                let v = Nullification::read(reader)?;
                Ok(Voter::Nullification(v))
            }
            4 => {
                let v = Finalize::read(reader)?;
                Ok(Voter::Finalize(v))
            }
            5 => {
                let v = Finalization::read(reader)?;
                Ok(Voter::Finalization(v))
            }
            _ => Err(Error::Invalid(
                "consensus::threshold_simplex::Voter",
                "Invalid type",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Proposal<D: Digest> {
    pub view: u64,
    pub parent: u64,
    pub payload: D,
}

impl<D: Digest> Codec for Proposal<D> {
    fn write(&self, writer: &mut impl Writer) {
        self.view.write(writer);
        self.parent.write(writer);
        self.payload.write(writer)
    }

    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let view = u64::read(reader)?;
        let parent = u64::read(reader)?;
        let payload = D::read(reader)?;
        Ok(Proposal {
            view,
            parent,
            payload,
        })
    }
}

impl<D: Digest> SizedCodec for Proposal<D> {
    const LEN_ENCODED: usize = u64::LEN_ENCODED + u64::LEN_ENCODED + D::LEN_ENCODED;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Notarize<D: Digest> {
    pub proposal: Proposal<D>,
    pub proposal_signature: PartialSignature,
    pub seed_signature: PartialSignature,
}

impl<D: Digest> Codec for Notarize<D> {
    fn write(&self, writer: &mut impl Writer) {
        self.proposal.write(writer);
        self.proposal_signature.write(writer);
        self.seed_signature.write(writer);
    }

    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let proposal_signature = PartialSignature::read(reader)?;
        let seed_signature = PartialSignature::read(reader)?;
        Ok(Notarize {
            proposal,
            proposal_signature,
            seed_signature,
        })
    }
}

impl<D: Digest> SizedCodec for Notarize<D> {
    const LEN_ENCODED: usize =
        Proposal::<D>::LEN_ENCODED + PartialSignature::LEN_ENCODED + PartialSignature::LEN_ENCODED;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Notarization<D: Digest> {
    pub proposal: Proposal<D>,
    pub proposal_signature: Signature,
    pub seed_signature: Signature,
}

impl<D: Digest> Codec for Notarization<D> {
    fn write(&self, writer: &mut impl Writer) {
        self.proposal.write(writer);
        self.proposal_signature.write(writer);
        self.seed_signature.write(writer)
    }

    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let proposal_signature = Signature::read(reader)?;
        let seed_signature = Signature::read(reader)?;
        Ok(Notarization {
            proposal,
            proposal_signature,
            seed_signature,
        })
    }
}

impl<D: Digest> SizedCodec for Notarization<D> {
    const LEN_ENCODED: usize =
        Proposal::<D>::LEN_ENCODED + Signature::LEN_ENCODED + Signature::LEN_ENCODED;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Nullify {
    pub view: u64,
    pub proposal_signature: PartialSignature,
    pub seed_signature: PartialSignature,
}

impl Codec for Nullify {
    fn write(&self, writer: &mut impl Writer) {
        self.view.write(writer);
        self.proposal_signature.write(writer);
        self.seed_signature.write(writer);
    }

    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let view = u64::read(reader)?;
        let proposal_signature = PartialSignature::read(reader)?;
        let seed_signature = PartialSignature::read(reader)?;
        Ok(Nullify {
            view,
            proposal_signature,
            seed_signature,
        })
    }
}

impl SizedCodec for Nullify {
    const LEN_ENCODED: usize =
        u64::LEN_ENCODED + PartialSignature::LEN_ENCODED + PartialSignature::LEN_ENCODED;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Nullification {
    pub view: u64,
    pub view_signature: Signature,
    pub seed_signature: Signature,
}

impl Codec for Nullification {
    fn write(&self, writer: &mut impl Writer) {
        self.view.write(writer);
        self.view_signature.write(writer);
        self.seed_signature.write(writer);
    }

    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let view = u64::read(reader)?;
        let view_signature = Signature::read(reader)?;
        let seed_signature = Signature::read(reader)?;
        Ok(Nullification {
            view,
            view_signature,
            seed_signature,
        })
    }
}

impl SizedCodec for Nullification {
    const LEN_ENCODED: usize = u64::LEN_ENCODED + Signature::LEN_ENCODED + Signature::LEN_ENCODED;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Finalize<D: Digest> {
    pub proposal: Proposal<D>,
    pub proposal_signature: Signature,
}

impl<D: Digest> Codec for Finalize<D> {
    fn write(&self, writer: &mut impl Writer) {
        self.proposal.write(writer);
        self.proposal_signature.write(writer);
    }

    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let proposal_signature = Signature::read(reader)?;
        Ok(Finalize {
            proposal,
            proposal_signature,
        })
    }
}

impl<D: Digest> SizedCodec for Finalize<D> {
    const LEN_ENCODED: usize = Proposal::<D>::LEN_ENCODED + Signature::LEN_ENCODED;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Finalization<D: Digest> {
    pub proposal: Proposal<D>,
    pub proposal_signature: Signature,
    pub seed_signature: Signature,
}

impl<D: Digest> Codec for Finalization<D> {
    fn write(&self, writer: &mut impl Writer) {
        self.proposal.write(writer);
        self.proposal_signature.write(writer);
        self.seed_signature.write(writer);
    }

    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let proposal_signature = Signature::read(reader)?;
        let seed_signature = Signature::read(reader)?;
        Ok(Finalization {
            proposal,
            proposal_signature,
            seed_signature,
        })
    }
}

impl<D: Digest> SizedCodec for Finalization<D> {
    const LEN_ENCODED: usize =
        Proposal::<D>::LEN_ENCODED + Signature::LEN_ENCODED + Signature::LEN_ENCODED;
}

#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub id: u64,
    pub notarizations: Vec<u64>,
    pub nullifications: Vec<u64>,
}

impl Codec for Request {
    fn write(&self, writer: &mut impl Writer) {
        self.id.write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }

    fn len_encoded(&self) -> usize {
        Codec::len_encoded(&self.id)
            + self.notarizations.len_encoded()
            + self.nullifications.len_encoded()
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let id = u64::read(reader)?;
        let notarizations = Vec::<u64>::read(reader)?;
        let nullifications = Vec::<u64>::read(reader)?;
        Ok(Request {
            id,
            notarizations,
            nullifications,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Response<D: Digest> {
    pub id: u64,
    pub notarizations: Vec<Notarization<D>>,
    pub nullifications: Vec<Nullification>,
}

impl<D: Digest> Codec for Response<D> {
    fn write(&self, writer: &mut impl Writer) {
        self.id.write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }

    fn len_encoded(&self) -> usize {
        Codec::len_encoded(&self.id)
            + self.notarizations.len_encoded()
            + self.nullifications.len_encoded()
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let id = u64::read(reader)?;
        let notarizations = Vec::<Notarization<D>>::read(reader)?;
        let nullifications = Vec::<Nullification>::read(reader)?;
        Ok(Response {
            id,
            notarizations,
            nullifications,
        })
    }
}

pub fn view_message(view: View) -> Vec<u8> {
    View::encode(&view)
}
