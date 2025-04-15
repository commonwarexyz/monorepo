use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, FixedSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Public, Signature},
        ops::{
            aggregate_signatures, aggregate_verify_multiple_messages, partial_verify_message,
            partial_verify_multiple_messages,
        },
        poly::{PartialSignature, Poly},
    },
    Digest,
};
use commonware_utils::union;

/// View is a monotonically increasing counter that represents the current focus of consensus.
pub type View = u64;

/// Context is a collection of metadata from consensus about a given payload.
#[derive(Clone)]
pub struct Context<D: Digest> {
    /// Current view of consensus.
    pub view: View,

    /// Parent the payload is built on.
    ///
    /// If there is a gap between the current view and the parent view, the participant
    /// must possess a nullification for each discarded view to safely vote on the proposed
    /// payload (any view without a nullification may eventually be finalized and skipping
    /// it would result in a fork).
    pub parent: (View, D),
}

pub trait Viewable {
    fn view(&self) -> View;
}

pub trait Attributable {
    fn signer(&self) -> u32;
}

pub const SEED_SUFFIX: &[u8] = b"_SEED";
pub const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
pub const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
pub const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

pub fn seed_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, SEED_SUFFIX)
}

pub fn notarize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

pub fn nullify_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

pub fn finalize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
}

#[derive(Clone, Debug, PartialEq)]
pub enum Voter<D: Digest> {
    Notarize(Notarize<D>),
    Notarization(Notarization<D>),
    Nullify(Nullify),
    Nullification(Nullification),
    Finalize(Finalize<D>),
    Finalization(Finalization<D>),
}

impl<D: Digest> Write for Voter<D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Voter::Notarize(v) => {
                0u8.write(writer);
                v.write(writer);
            }
            Voter::Notarization(v) => {
                1u8.write(writer);
                v.write(writer);
            }
            Voter::Nullify(v) => {
                2u8.write(writer);
                v.write(writer);
            }
            Voter::Nullification(v) => {
                3u8.write(writer);
                v.write(writer);
            }
            Voter::Finalize(v) => {
                4u8.write(writer);
                v.write(writer);
            }
            Voter::Finalization(v) => {
                5u8.write(writer);
                v.write(writer);
            }
        }
    }
}

impl<D: Digest> EncodeSize for Voter<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Voter::Notarize(v) => v.encode_size(),
            Voter::Notarization(v) => v.encode_size(),
            Voter::Nullify(v) => v.encode_size(),
            Voter::Nullification(v) => v.encode_size(),
            Voter::Finalize(v) => v.encode_size(),
            Voter::Finalization(v) => v.encode_size(),
        }
    }
}

impl<D: Digest> Read for Voter<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
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

impl<D: Digest> Viewable for Voter<D> {
    fn view(&self) -> View {
        match self {
            Voter::Notarize(v) => v.view(),
            Voter::Notarization(v) => v.view(),
            Voter::Nullify(v) => v.view(),
            Voter::Nullification(v) => v.view(),
            Voter::Finalize(v) => v.view(),
            Voter::Finalization(v) => v.view(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Proposal<D: Digest> {
    pub view: View,
    pub parent: View,
    pub payload: D,
}

impl<D: Digest> Proposal<D> {
    pub fn new(view: View, parent: View, payload: D) -> Self {
        Proposal {
            view,
            parent,
            payload,
        }
    }
}

impl<D: Digest> Write for Proposal<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.view.write(writer);
        self.parent.write(writer);
        self.payload.write(writer)
    }
}

impl<D: Digest> Read for Proposal<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = View::read(reader)?;
        let parent = View::read(reader)?;
        let payload = D::read(reader)?;
        Ok(Proposal {
            view,
            parent,
            payload,
        })
    }
}

impl<D: Digest> FixedSize for Proposal<D> {
    const SIZE: usize = View::SIZE + View::SIZE + D::SIZE;
}

impl<D: Digest> Viewable for Proposal<D> {
    fn view(&self) -> View {
        self.view
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
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
        let notarize_message = self.proposal.encode();
        let notarize_message = (Some(notarize_namespace), notarize_message.as_ref());
        let seed_message = view_message(self.proposal.view);
        let seed_message = (Some(seed_namespace), seed_message.as_ref());
        partial_verify_multiple_messages(
            identity,
            public_key_index,
            &[notarize_message, seed_message],
            [&self.proposal_signature, &self.seed_signature],
        )
        .is_ok()
    }
}

impl<D: Digest> Attributable for Notarize<D> {
    fn signer(&self) -> u32 {
        self.proposal_signature.index
    }
}

impl<D: Digest> Viewable for Notarize<D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<D: Digest> Write for Notarize<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.proposal_signature.write(writer);
        self.seed_signature.write(writer);
    }
}

impl<D: Digest> Read for Notarize<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let proposal_signature = PartialSignature::read(reader)?;
        let seed_signature = PartialSignature::read(reader)?;
        if proposal_signature.index != seed_signature.index {
            return Err(Error::Invalid("notarize", "mismatched signatures"));
        }
        Ok(Notarize {
            proposal,
            proposal_signature,
            seed_signature,
        })
    }
}

impl<D: Digest> FixedSize for Notarize<D> {
    const SIZE: usize = Proposal::<D>::SIZE + PartialSignature::SIZE + PartialSignature::SIZE;
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
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

impl<D: Digest> Viewable for Notarization<D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<D: Digest> Write for Notarization<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.proposal_signature.write(writer);
        self.seed_signature.write(writer)
    }
}

impl<D: Digest> Read for Notarization<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
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

impl<D: Digest> FixedSize for Notarization<D> {
    const SIZE: usize = Proposal::<D>::SIZE + Signature::SIZE + Signature::SIZE;
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Nullify {
    pub view: View,
    pub view_signature: PartialSignature,
    pub seed_signature: PartialSignature,
}

impl Nullify {
    pub fn new(
        view: View,
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
            [&self.view_signature, &self.seed_signature],
        )
        .is_ok()
    }
}

impl Attributable for Nullify {
    fn signer(&self) -> u32 {
        self.view_signature.index
    }
}

impl Viewable for Nullify {
    fn view(&self) -> View {
        self.view
    }
}

impl Write for Nullify {
    fn write(&self, writer: &mut impl BufMut) {
        self.view.write(writer);
        self.view_signature.write(writer);
        self.seed_signature.write(writer);
    }
}

impl Read for Nullify {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = View::read(reader)?;
        let view_signature = PartialSignature::read(reader)?;
        let seed_signature = PartialSignature::read(reader)?;
        if view_signature.index != seed_signature.index {
            return Err(Error::Invalid("nullify", "mismatched signatures"));
        }
        Ok(Nullify {
            view,
            view_signature,
            seed_signature,
        })
    }
}

impl FixedSize for Nullify {
    const SIZE: usize = View::SIZE + PartialSignature::SIZE + PartialSignature::SIZE;
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Nullification {
    pub view: View,
    pub view_signature: Signature,
    pub seed_signature: Signature,
}

impl Nullification {
    pub fn new(view: View, view_signature: Signature, seed_signature: Signature) -> Self {
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

impl Viewable for Nullification {
    fn view(&self) -> View {
        self.view
    }
}

impl Write for Nullification {
    fn write(&self, writer: &mut impl BufMut) {
        self.view.write(writer);
        self.view_signature.write(writer);
        self.seed_signature.write(writer);
    }
}

impl Read for Nullification {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = View::read(reader)?;
        let view_signature = Signature::read(reader)?;
        let seed_signature = Signature::read(reader)?;
        Ok(Nullification {
            view,
            view_signature,
            seed_signature,
        })
    }
}

impl FixedSize for Nullification {
    const SIZE: usize = View::SIZE + Signature::SIZE + Signature::SIZE;
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
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

impl<D: Digest> Attributable for Finalize<D> {
    fn signer(&self) -> u32 {
        self.proposal_signature.index
    }
}

impl<D: Digest> Viewable for Finalize<D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<D: Digest> Write for Finalize<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.proposal_signature.write(writer);
    }
}

impl<D: Digest> Read for Finalize<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let proposal_signature = PartialSignature::read(reader)?;
        Ok(Finalize {
            proposal,
            proposal_signature,
        })
    }
}

impl<D: Digest> FixedSize for Finalize<D> {
    const SIZE: usize = Proposal::<D>::SIZE + PartialSignature::SIZE;
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
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

impl<D: Digest> Viewable for Finalization<D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<D: Digest> Write for Finalization<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.proposal_signature.write(writer);
        self.seed_signature.write(writer);
    }
}

impl<D: Digest> Read for Finalization<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
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

impl<D: Digest> FixedSize for Finalization<D> {
    const SIZE: usize = Proposal::<D>::SIZE + Signature::SIZE + Signature::SIZE;
}

#[derive(Clone, Debug, PartialEq)]
pub enum Backfiller<D: Digest> {
    Request(Request),
    Response(Response<D>),
}

impl<D: Digest> Write for Backfiller<D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Backfiller::Request(v) => {
                0u8.write(writer);
                v.write(writer);
            }
            Backfiller::Response(v) => {
                1u8.write(writer);
                v.write(writer);
            }
        }
    }
}

impl<D: Digest> EncodeSize for Backfiller<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Backfiller::Request(v) => v.encode_size(),
            Backfiller::Response(v) => v.encode_size(),
        }
    }
}

impl<D: Digest> Read<usize> for Backfiller<D> {
    fn read_cfg(reader: &mut impl Buf, cfg: &usize) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = Request::read_cfg(reader, cfg)?;
                Ok(Backfiller::Request(v))
            }
            1 => {
                let v = Response::<D>::read_cfg(reader, cfg)?;
                Ok(Backfiller::Response(v))
            }
            _ => Err(Error::Invalid(
                "consensus::threshold_simplex::Backfiller",
                "Invalid type",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub id: View,
    pub notarizations: Vec<View>,
    pub nullifications: Vec<View>,
}

impl Request {
    pub fn new(id: View, notarizations: Vec<View>, nullifications: Vec<View>) -> Self {
        Request {
            id,
            notarizations,
            nullifications,
        }
    }
}

impl Write for Request {
    fn write(&self, writer: &mut impl BufMut) {
        self.id.write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl EncodeSize for Request {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.notarizations.encode_size() + self.nullifications.encode_size()
    }
}

impl Read<usize> for Request {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let id = View::read(reader)?;
        let notarizations = Vec::<View>::read_range(reader, ..=*max_len)?;
        let nullifications = Vec::<View>::read_range(reader, ..=*max_len)?;
        Ok(Request {
            id,
            notarizations,
            nullifications,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Response<D: Digest> {
    pub id: View,
    pub notarizations: Vec<Notarization<D>>,
    pub nullifications: Vec<Nullification>,
}

impl<D: Digest> Response<D> {
    pub fn new(
        id: View,
        notarizations: Vec<Notarization<D>>,
        nullifications: Vec<Nullification>,
    ) -> Self {
        Response {
            id,
            notarizations,
            nullifications,
        }
    }
}

impl<D: Digest> Write for Response<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.id.write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl<D: Digest> EncodeSize for Response<D> {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.notarizations.encode_size() + self.nullifications.encode_size()
    }
}

impl<D: Digest> Read<usize> for Response<D> {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let id = View::read(reader)?;
        let notarizations = Vec::<Notarization<D>>::read_range(reader, ..=*max_len)?;
        let nullifications = Vec::<Nullification>::read_range(reader, ..=*max_len)?;
        Ok(Response {
            id,
            notarizations,
            nullifications,
        })
    }
}

pub fn view_message(view: View) -> Vec<u8> {
    View::encode(&view).into()
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum Activity<D: Digest> {
    Notarize(Notarize<D>),
    Notarization(Notarization<D>),
    Nullify(Nullify),
    Nullification(Nullification),
    Finalize(Finalize<D>),
    Finalization(Finalization<D>),
    ConflictingNotarize(ConflictingNotarize<D>),
    ConflictingFinalize(ConflictingFinalize<D>),
    NullifyFinalize(NullifyFinalize<D>),
}

impl<D: Digest> Write for Activity<D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Activity::Notarize(v) => {
                0u8.write(writer);
                v.write(writer);
            }
            Activity::Notarization(v) => {
                1u8.write(writer);
                v.write(writer);
            }
            Activity::Nullify(v) => {
                2u8.write(writer);
                v.write(writer);
            }
            Activity::Nullification(v) => {
                3u8.write(writer);
                v.write(writer);
            }
            Activity::Finalize(v) => {
                4u8.write(writer);
                v.write(writer);
            }
            Activity::Finalization(v) => {
                5u8.write(writer);
                v.write(writer);
            }
            Activity::ConflictingNotarize(v) => {
                6u8.write(writer);
                v.write(writer);
            }
            Activity::ConflictingFinalize(v) => {
                7u8.write(writer);
                v.write(writer);
            }
            Activity::NullifyFinalize(v) => {
                8u8.write(writer);
                v.write(writer);
            }
        }
    }
}

impl<D: Digest> EncodeSize for Activity<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Activity::Notarize(v) => v.encode_size(),
            Activity::Notarization(v) => v.encode_size(),
            Activity::Nullify(v) => v.encode_size(),
            Activity::Nullification(v) => v.encode_size(),
            Activity::Finalize(v) => v.encode_size(),
            Activity::Finalization(v) => v.encode_size(),
            Activity::ConflictingNotarize(v) => v.encode_size(),
            Activity::ConflictingFinalize(v) => v.encode_size(),
            Activity::NullifyFinalize(v) => v.encode_size(),
        }
    }
}

impl<D: Digest> Read for Activity<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = Notarize::read(reader)?;
                Ok(Activity::Notarize(v))
            }
            1 => {
                let v = Notarization::read(reader)?;
                Ok(Activity::Notarization(v))
            }
            2 => {
                let v = Nullify::read(reader)?;
                Ok(Activity::Nullify(v))
            }
            3 => {
                let v = Nullification::read(reader)?;
                Ok(Activity::Nullification(v))
            }
            4 => {
                let v = Finalize::read(reader)?;
                Ok(Activity::Finalize(v))
            }
            5 => {
                let v = Finalization::read(reader)?;
                Ok(Activity::Finalization(v))
            }
            6 => {
                let v = ConflictingNotarize::read(reader)?;
                Ok(Activity::ConflictingNotarize(v))
            }
            7 => {
                let v = ConflictingFinalize::read(reader)?;
                Ok(Activity::ConflictingFinalize(v))
            }
            8 => {
                let v = NullifyFinalize::read(reader)?;
                Ok(Activity::NullifyFinalize(v))
            }
            _ => Err(Error::Invalid(
                "consensus::threshold_simplex::Activity",
                "Invalid type",
            )),
        }
    }
}

impl<D: Digest> Viewable for Activity<D> {
    fn view(&self) -> View {
        match self {
            Activity::Notarize(v) => v.view(),
            Activity::Notarization(v) => v.view(),
            Activity::Nullify(v) => v.view(),
            Activity::Nullification(v) => v.view(),
            Activity::Finalize(v) => v.view(),
            Activity::Finalization(v) => v.view(),
            Activity::ConflictingNotarize(v) => v.view(),
            Activity::ConflictingFinalize(v) => v.view(),
            Activity::NullifyFinalize(v) => v.view(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConflictingNotarize<D: Digest> {
    pub proposal_1: Proposal<D>,
    pub signature_1: PartialSignature,
    pub proposal_2: Proposal<D>,
    pub signature_2: PartialSignature,
}

impl<D: Digest> ConflictingNotarize<D> {
    pub fn new(
        proposal_1: Proposal<D>,
        signature_1: PartialSignature,
        proposal_2: Proposal<D>,
        signature_2: PartialSignature,
    ) -> Self {
        ConflictingNotarize {
            proposal_1,
            signature_1,
            proposal_2,
            signature_2,
        }
    }

    pub fn verify(
        &self,
        identity: &Poly<Public>,
        public_key_index: Option<u32>,
        notarize_namespace: &[u8],
    ) -> bool {
        let public_key_index = public_key_index.unwrap_or(self.signature_1.index);
        let notarize_message_1 = self.proposal_1.encode();
        let notarize_message_1 = (Some(notarize_namespace), notarize_message_1.as_ref());
        let notarize_message_2 = self.proposal_2.encode();
        let notarize_message_2 = (Some(notarize_namespace), notarize_message_2.as_ref());
        partial_verify_multiple_messages(
            identity,
            public_key_index,
            &[notarize_message_1, notarize_message_2],
            [&self.signature_1, &self.signature_2],
        )
        .is_ok()
    }
}

impl<D: Digest> Attributable for ConflictingNotarize<D> {
    fn signer(&self) -> u32 {
        self.signature_1.index
    }
}

impl<D: Digest> Viewable for ConflictingNotarize<D> {
    fn view(&self) -> View {
        self.proposal_1.view()
    }
}

impl<D: Digest> Write for ConflictingNotarize<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal_1.write(writer);
        self.signature_1.write(writer);
        self.proposal_2.write(writer);
        self.signature_2.write(writer);
    }
}

impl<D: Digest> Read for ConflictingNotarize<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal_1 = Proposal::read(reader)?;
        let signature_1 = PartialSignature::read(reader)?;
        let proposal_2 = Proposal::read(reader)?;
        let signature_2 = PartialSignature::read(reader)?;
        if proposal_1.view != proposal_2.view {
            return Err(Error::Invalid("conflicting_notarize", "mismatched views"));
        }
        if signature_1.index != signature_2.index {
            return Err(Error::Invalid(
                "conflicting_notarize",
                "mismatched signatures",
            ));
        }
        Ok(ConflictingNotarize {
            proposal_1,
            signature_1,
            proposal_2,
            signature_2,
        })
    }
}

impl<D: Digest> FixedSize for ConflictingNotarize<D> {
    const SIZE: usize =
        Proposal::<D>::SIZE + PartialSignature::SIZE + Proposal::<D>::SIZE + PartialSignature::SIZE;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConflictingFinalize<D: Digest> {
    pub proposal_1: Proposal<D>,
    pub signature_1: PartialSignature,
    pub proposal_2: Proposal<D>,
    pub signature_2: PartialSignature,
}

impl<D: Digest> ConflictingFinalize<D> {
    pub fn new(
        proposal_1: Proposal<D>,
        signature_1: PartialSignature,
        proposal_2: Proposal<D>,
        signature_2: PartialSignature,
    ) -> Self {
        ConflictingFinalize {
            proposal_1,
            signature_1,
            proposal_2,
            signature_2,
        }
    }

    pub fn verify(
        &self,
        identity: &Poly<Public>,
        public_key_index: Option<u32>,
        finalize_namespace: &[u8],
    ) -> bool {
        let public_key_index = public_key_index.unwrap_or(self.signature_1.index);
        let finalize_message_1 = self.proposal_1.encode();
        let finalize_message_1 = (Some(finalize_namespace), finalize_message_1.as_ref());
        let finalize_message_2 = self.proposal_2.encode();
        let finalize_message_2 = (Some(finalize_namespace), finalize_message_2.as_ref());
        partial_verify_multiple_messages(
            identity,
            public_key_index,
            &[finalize_message_1, finalize_message_2],
            [&self.signature_1, &self.signature_2],
        )
        .is_ok()
    }
}

impl<D: Digest> Attributable for ConflictingFinalize<D> {
    fn signer(&self) -> u32 {
        self.signature_1.index
    }
}

impl<D: Digest> Viewable for ConflictingFinalize<D> {
    fn view(&self) -> View {
        self.proposal_1.view()
    }
}

impl<D: Digest> Write for ConflictingFinalize<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal_1.write(writer);
        self.signature_1.write(writer);
        self.proposal_2.write(writer);
        self.signature_2.write(writer);
    }
}

impl<D: Digest> Read for ConflictingFinalize<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal_1 = Proposal::read(reader)?;
        let signature_1 = PartialSignature::read(reader)?;
        let proposal_2 = Proposal::read(reader)?;
        let signature_2 = PartialSignature::read(reader)?;
        if proposal_1.view != proposal_2.view {
            return Err(Error::Invalid("conflicting_finalize", "mismatched views"));
        }
        if signature_1.index != signature_2.index {
            return Err(Error::Invalid(
                "conflicting_finalize",
                "mismatched signatures",
            ));
        }
        Ok(ConflictingFinalize {
            proposal_1,
            signature_1,
            proposal_2,
            signature_2,
        })
    }
}

impl<D: Digest> FixedSize for ConflictingFinalize<D> {
    const SIZE: usize =
        Proposal::<D>::SIZE + PartialSignature::SIZE + Proposal::<D>::SIZE + PartialSignature::SIZE;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NullifyFinalize<D: Digest> {
    pub proposal: Proposal<D>,
    pub view_signature: PartialSignature,
    pub finalize_signature: PartialSignature,
}

impl<D: Digest> NullifyFinalize<D> {
    pub fn new(
        proposal: Proposal<D>,
        view_signature: PartialSignature,
        finalize_signature: PartialSignature,
    ) -> Self {
        NullifyFinalize {
            proposal,
            view_signature,
            finalize_signature,
        }
    }

    pub fn verify(
        &self,
        identity: &Poly<Public>,
        public_key_index: Option<u32>,
        nullify_namespace: &[u8],
        finalize_namespace: &[u8],
    ) -> bool {
        let public_key_index = public_key_index.unwrap_or(self.view_signature.index);
        let nullify_message = view_message(self.proposal.view);
        let nullify_message = (Some(nullify_namespace), nullify_message.as_ref());
        let finalize_message = self.proposal.encode();
        let finalize_message = (Some(finalize_namespace), finalize_message.as_ref());
        partial_verify_multiple_messages(
            identity,
            public_key_index,
            &[nullify_message, finalize_message],
            [&self.view_signature, &self.finalize_signature],
        )
        .is_ok()
    }
}

impl<D: Digest> Attributable for NullifyFinalize<D> {
    fn signer(&self) -> u32 {
        self.view_signature.index
    }
}

impl<D: Digest> Viewable for NullifyFinalize<D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<D: Digest> Write for NullifyFinalize<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.view_signature.write(writer);
        self.finalize_signature.write(writer);
    }
}

impl<D: Digest> Read for NullifyFinalize<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let view_signature = PartialSignature::read(reader)?;
        let finalize_signature = PartialSignature::read(reader)?;
        if view_signature.index != finalize_signature.index {
            return Err(Error::Invalid("nullify_finalize", "mismatched signatures"));
        }
        Ok(NullifyFinalize {
            proposal,
            view_signature,
            finalize_signature,
        })
    }
}

impl<D: Digest> FixedSize for NullifyFinalize<D> {
    const SIZE: usize = Proposal::<D>::SIZE + PartialSignature::SIZE + PartialSignature::SIZE;
}
