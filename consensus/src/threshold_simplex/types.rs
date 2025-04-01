use bytes::Bytes;
use commonware_codec::{Codec, Error, Reader, SizedCodec, Writer};
use commonware_cryptography::{
    bls12381::primitives::poly::{PartialSignature, Signature},
    Digest,
};

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
                writer.write_u8(0)?;
                v.encode(writer)
            }
            Voter::Notarization(v) => {
                writer.write_u8(1)?;
                v.encode(writer)
            }
            Voter::Nullify(v) => {
                writer.write_u8(2)?;
                v.encode(writer)
            }
            Voter::Nullification(v) => {
                writer.write_u8(3)?;
                v.encode(writer)
            }
            Voter::Finalize(v) => {
                writer.write_u8(4)?;
                v.encode(writer)
            }
            Voter::Finalization(v) => {
                writer.write_u8(5)?;
                v.encode(writer)
            }
        }
    }

    fn len_encoded(&self) -> usize {
        (match self {
            Payload::BitVec(bitvec) => bitvec.len_encoded(),
            Payload::Peers(peers) => peers.len_encoded(),
            Payload::Data(data) => data.len_encoded(),
        }) + 1
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let tag = reader.read_u8()?;
        match tag {
            0 => Ok(Voter::Notarize(Notarize::decode(reader)?)),
            1 => Ok(Voter::Notarization(Notarization::decode(reader)?)),
            2 => Ok(Voter::Nullify(Nullify::decode(reader)?)),
            3 => Ok(Voter::Nullification(Nullification::decode(reader)?)),
            4 => Ok(Voter::Finalize(Finalize::decode(reader)?)),
            5 => Ok(Voter::Finalization(Finalization::decode(reader)?)),
            _ => Err(Error::InvalidTag(tag)),
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
        self.proposal.write(writer)?;
        self.proposal_signature.write(writer)?;
        self.seed_signature.write(writer)
    }

    fn len_encoded(&self) -> usize {
        self.proposal.len_encoded()
            + self.proposal_signature.len_encoded()
            + self.seed_signature.len_encoded()
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

#[derive(Clone, Debug, PartialEq)]
pub struct Nullify {
    pub view: u64,
    pub proposal_signature: PartialSignature,
    pub seed_signature: PartialSignature,
}

impl Codec for Nullify {
    fn write(&self, writer: &mut impl Writer) {
        writer.write_u64(self.view)?;
        self.proposal_signature.write(writer)?;
        self.seed_signature.write(writer)
    }

    fn len_encoded(&self) -> usize {
        8 + self.proposal_signature.len_encoded() + self.seed_signature.len_encoded()
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let view = reader.read_u64()?;
        let proposal_signature = PartialSignature::read(reader)?;
        let seed_signature = PartialSignature::read(reader)?;
        Ok(Nullify {
            view,
            proposal_signature,
            seed_signature,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Nullification {
    pub view: u64,
    pub view_signature: Signature,
    pub seed_signature: Signature,
}

impl Codec for Nullification {
    fn write(&self, writer: &mut impl Writer) {
        writer.write_u64(self.view)?;
        self.view_signature.write(writer)?;
        self.seed_signature.write(writer)
    }

    fn len_encoded(&self) -> usize {
        8 + self.view_signature.len_encoded() + self.seed_signature.len_encoded()
    }

    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        let view = reader.read_u64()?;
        let view_signature = Signature::read(reader)?;
        let seed_signature = Signature::read(reader)?;
        Ok(Nullification {
            view,
            view_signature,
            seed_signature,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Finalize<D: Digest> {
    pub proposal: Proposal<D>,
    pub proposal_signature: Signature,
}

impl<D: Digest> Codec for Finalize<D> {
    fn write(&self, writer: &mut impl Writer) {
        self.proposal.write(writer)?;
        self.proposal_signature.write(writer)
    }

    fn len_encoded(&self) -> usize {
        self.proposal.len_encoded() + self.proposal_signature.len_encoded()
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

#[derive(Clone, Debug, PartialEq)]
pub struct Finalization<D: Digest> {
    pub proposal: Proposal<D>,
    pub proposal_signature: Signature,
    pub seed_signature: Signature,
}

impl<D: Digest> Codec for Finalization<D> {
    fn write(&self, writer: &mut impl Writer) {
        self.proposal.write(writer)?;
        self.proposal_signature.write(writer)?;
        self.seed_signature.write(writer)
    }

    fn len_encoded(&self) -> usize {
        self.proposal.len_encoded()
            + self.proposal_signature.len_encoded()
            + self.seed_signature.len_encoded()
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

#[derive(Clone, Debug, PartialEq)]
pub enum Backfiller<D: Digest> {
    Request(Request),
    Response(Response<D>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub id: u64,
    pub notarizations: Vec<u64>,
    pub nullifications: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Response<D: Digest> {
    pub id: u64,
    pub notarizations: Vec<Notarization<D>>,
    pub nullifications: Vec<Nullification>,
}
