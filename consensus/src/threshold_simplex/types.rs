use super::{notarize_namespace, View};
use commonware_codec::{Codec, Error, Reader, SizedCodec, Writer};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Public, Signature},
        ops::{
            aggregate_signatures, aggregate_verify_multiple_messages, partial_verify_message,
            partial_verify_multiple_messages,
        },
        poly::{PartialSignature, Poly},
    },
    hash, sha256, Digest,
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

// TODO: add versioning to Voter and all other types?
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

impl<D: Digest> Proposal<D> {
    pub fn new(view: u64, parent: u64, payload: D) -> Self {
        Proposal {
            view,
            parent,
            payload,
        }
    }

    pub fn digest(&self) -> sha256::Digest {
        hash(&self.encode())
    }
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

impl<D: Digest> Notarize<D> {
    pub fn new(
        proposal: Proposal<D>,
        proposal_signature: PartialSignature,
        seed_signature: PartialSignature,
    ) -> Self {
        Notarize {
            proposal,
            proposal_signature,
            seed_signature,
        }
    }

    pub fn verify(
        &self,
        identity: &Poly<Public>,
        public_key_index: Option<u32>,
        notarize_namespace: &[u8],
        seed_namespace: &[u8],
    ) -> bool {
        let public_key_index = public_key_index.unwrap_or(self.proposal_signature.index);
        let notarize_message = self.encode();
        let notarize_message = (Some(notarize_namespace), notarize_message.as_ref());
        let seed_message = view_message(self.proposal.view);
        let seed_message = (Some(seed_namespace), seed_message.as_ref());
        partial_verify_multiple_messages(
            identity,
            public_key_index,
            &[notarize_message, seed_message],
            &[self.proposal_signature.clone(), self.seed_signature.clone()],
        )
        .is_ok()
    }
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

impl<D: Digest> Notarization<D> {
    pub fn new(
        proposal: Proposal<D>,
        proposal_signature: Signature,
        seed_signature: Signature,
    ) -> Self {
        Notarization {
            proposal,
            proposal_signature,
            seed_signature,
        }
    }

    // TODO: modify threshold funcs to allow references
    pub fn verify(
        &self,
        public_key: &Public,
        notarize_namespace: &[u8],
        seed_namespace: &[u8],
    ) -> bool {
        let notarize_message = self.proposal.encode();
        let notarize_message = (Some(notarize_namespace), notarize_message.as_ref());
        let seed_message = view_message(self.proposal.view);
        let seed_message = (Some(seed_namespace), seed_message.as_ref());
        let signature = aggregate_signatures(&[self.proposal_signature, self.seed_signature]);
        aggregate_verify_multiple_messages(
            public_key,
            &[notarize_message, seed_message],
            &signature,
            1,
        )
        .is_ok()
    }
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
    pub view_signature: PartialSignature,
    pub seed_signature: PartialSignature,
}

impl Nullify {
    pub fn new(
        view: u64,
        view_signature: PartialSignature,
        seed_signature: PartialSignature,
    ) -> Self {
        Nullify {
            view,
            view_signature,
            seed_signature,
        }
    }

    pub fn verify(
        &self,
        identity: &Poly<Public>,
        public_key_index: Option<u32>,
        nullify_namespace: &[u8],
        seed_namespace: &[u8],
    ) -> bool {
        let public_key_index = public_key_index.unwrap_or(self.view_signature.index);
        let view_message = view_message(self.view);
        let nullify_message = (Some(nullify_namespace), view_message.as_ref());
        let seed_message = (Some(seed_namespace), view_message.as_ref());
        partial_verify_multiple_messages(
            identity,
            public_key_index,
            &[nullify_message, seed_message],
            &[self.view_signature.clone(), self.seed_signature.clone()],
        )
        .is_ok()
    }
}

impl Codec for Nullify {
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
        let view_signature = PartialSignature::read(reader)?;
        let seed_signature = PartialSignature::read(reader)?;
        Ok(Nullify {
            view,
            view_signature,
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

impl Nullification {
    pub fn new(view: u64, view_signature: Signature, seed_signature: Signature) -> Self {
        Nullification {
            view,
            view_signature,
            seed_signature,
        }
    }

    pub fn verify(
        &self,
        public_key: &Public,
        nullify_namespace: &[u8],
        seed_namespace: &[u8],
    ) -> bool {
        let view_message = view_message(self.view);
        let nullify_message = (Some(nullify_namespace), view_message.as_ref());
        let seed_message = (Some(seed_namespace), view_message.as_ref());
        let signature = aggregate_signatures(&[self.view_signature, self.seed_signature]);
        aggregate_verify_multiple_messages(
            public_key,
            &[nullify_message, seed_message],
            &signature,
            1,
        )
        .is_ok()
    }
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
    pub proposal_signature: PartialSignature,
}

impl<D: Digest> Finalize<D> {
    pub fn new(proposal: Proposal<D>, proposal_signature: PartialSignature) -> Self {
        Finalize {
            proposal,
            proposal_signature,
        }
    }

    pub fn verify(
        &self,
        identity: &Poly<Public>,
        public_key_index: Option<u32>,
        finalize_namespace: &[u8],
    ) -> bool {
        if let Some(public_key_index) = public_key_index {
            if public_key_index != self.proposal_signature.index {
                return false;
            }
        }
        let message = self.proposal.encode();
        partial_verify_message(
            identity,
            Some(finalize_namespace),
            &message,
            &self.proposal_signature,
        )
        .is_ok()
    }
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
        let proposal_signature = PartialSignature::read(reader)?;
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

impl<D: Digest> Finalization<D> {
    pub fn new(
        proposal: Proposal<D>,
        proposal_signature: Signature,
        seed_signature: Signature,
    ) -> Self {
        Finalization {
            proposal,
            proposal_signature,
            seed_signature,
        }
    }

    pub fn verify(
        &self,
        public_key: &Public,
        finalize_namespace: &[u8],
        seed_namespace: &[u8],
    ) -> bool {
        let finalize_message = self.proposal.encode();
        let finalize_message = (Some(finalize_namespace), finalize_message.as_ref());
        let seed_message = view_message(self.proposal.view);
        let seed_message = (Some(seed_namespace), seed_message.as_ref());
        let signature = aggregate_signatures(&[self.proposal_signature, self.seed_signature]);
        aggregate_verify_multiple_messages(
            public_key,
            &[finalize_message, seed_message],
            &signature,
            1,
        )
        .is_ok()
    }
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

impl Request {
    pub fn new(id: u64, notarizations: Vec<u64>, nullifications: Vec<u64>) -> Self {
        Request {
            id,
            notarizations,
            nullifications,
        }
    }
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

impl<D: Digest> Response<D> {
    pub fn new(
        id: u64,
        notarizations: Vec<Notarization<D>>,
        nullifications: Vec<Nullification>,
    ) -> Self {
        Response {
            id,
            notarizations,
            nullifications,
        }
    }

    pub fn verify(
        &self,
        public_key: &Public,
        notarize_namespace: &[u8],
        seed_namespace: &[u8],
    ) -> bool {
        // TODO: ensure notarizations and nullifications are unique
        // TODO: use single aggregate signature for all notarizations and nullifications verification (need to be
        // sure to only include unique notarizations and nullifications and seeds to avoid attack)
        for notarization in &self.notarizations {
            if !notarization.verify(public_key, notarize_namespace, seed_namespace) {
                return false;
            }
        }
        for nullification in &self.nullifications {
            if !nullification.verify(public_key, notarize_namespace, seed_namespace) {
                return false;
            }
        }
        true
    }
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
        // TODO: limit size of notarizations and nullifications read (to avoid runaway memory allocation for improerly
        // provide "len" encoding)
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
