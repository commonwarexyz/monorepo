use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{Digest, Verifier};
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

pub trait Attributable<V: Verifier> {
    fn signer(&self) -> V::PublicKey;
}

pub const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
pub const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
pub const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

pub fn view_message(view: View) -> Vec<u8> {
    View::encode(&view).into()
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
pub enum Voter<V: Verifier, D: Digest> {
    Notarize(Notarize<V, D>),
    Notarization(Notarization<V, D>),
    Nullify(Nullify<V>),
    Nullification(Nullification<V>),
    Finalize(Finalize<V>),
    Finalization(Finalization<V, D>),
}

impl<V: Verifier, D: Digest> Write for Voter<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Voter::Notarize(notarize) => {
                0u8.write(writer);
                notarize.write(writer);
            }
            Voter::Notarization(notarization) => {
                1u8.write(writer);
                notarization.write(writer);
            }
            Voter::Nullify(nullify) => {
                2u8.write(writer);
                nullify.write(writer);
            }
            Voter::Nullification(nullification) => {
                3u8.write(writer);
                nullification.write(writer);
            }
            Voter::Finalize(finalize) => {
                4u8.write(writer);
                finalize.write(writer);
            }
            Voter::Finalization(finalization) => {
                5u8.write(writer);
                finalization.write(writer);
            }
        }
    }
}

impl<V: Verifier, D: Digest> Read<usize> for Voter<V, D> {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let tag = u8::read(reader)?;
        match tag {
            0 => Ok(Voter::Notarize(Notarize::<V, D>::read(reader)?)),
            1 => Ok(Voter::Notarization(Notarization::<V, D>::read_cfg(
                reader, max_len,
            )?)),
            2 => Ok(Voter::Nullify(Nullify::<V>::read(reader)?)),
            3 => Ok(Voter::Nullification(Nullification::<V>::read_cfg(
                reader, max_len,
            )?)),
            4 => Ok(Voter::Finalize(Finalize::<V>::read(reader)?)),
            5 => Ok(Voter::Finalization(Finalization::<V, D>::read_cfg(
                reader, max_len,
            )?)),
            _ => Err(Error::Invalid("consensus::simplex::Voter", "Invalid type")),
        }
    }
}

impl<V: Verifier, D: Digest> EncodeSize for Voter<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Voter::Notarize(notarize) => notarize.encode_size(),
            Voter::Notarization(notarization) => notarization.encode_size(),
            Voter::Nullify(nullify) => nullify.encode_size(),
            Voter::Nullification(nullification) => nullification.encode_size(),
            Voter::Finalize(finalize) => finalize.encode_size(),
            Voter::Finalization(finalization) => finalization.encode_size(),
        }
    }
}

impl<V: Verifier, D: Digest> Viewable for Voter<V, D> {
    fn view(&self) -> View {
        match self {
            Voter::Notarize(notarize) => notarize.view(),
            Voter::Notarization(notarization) => notarization.view(),
            Voter::Nullify(nullify) => nullify.view(),
            Voter::Nullification(nullification) => nullification.view(),
            Voter::Finalize(finalize) => finalize.view(),
            Voter::Finalization(finalization) => finalization.view(),
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
        Self {
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
        self.payload.write(writer);
    }
}

impl<D: Digest> Read for Proposal<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = View::read_cfg(reader, &())?;
        let parent = View::read_cfg(reader, &())?;
        let payload = D::read_cfg(reader, &())?;
        Ok(Self {
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature<V: Verifier> {
    pub public_key: V::PublicKey,
    pub signature: V::Signature,
}

impl<V: Verifier> Signature<V> {
    pub fn new(public_key: V::PublicKey, signature: V::Signature) -> Self {
        Self {
            public_key,
            signature,
        }
    }
}

impl<V: Verifier> Write for Signature<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.public_key.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Verifier> Read for Signature<V> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let public_key = V::PublicKey::read(reader)?;
        let signature = V::Signature::read(reader)?;
        Ok(Self {
            public_key,
            signature,
        })
    }
}

impl<V: Verifier> FixedSize for Signature<V> {
    const SIZE: usize = V::PublicKey::SIZE + V::Signature::SIZE;
}

impl<V: Verifier> Attributable<V> for Signature<V> {
    fn signer(&self) -> V::PublicKey {
        self.public_key
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Notarize<V: Verifier, D: Digest> {
    pub proposal: Proposal<D>,
    pub signature: Signature<V>,
}

impl<V: Verifier, D: Digest> Notarize<V, D> {
    pub fn new(proposal: Proposal<D>, signature: Signature<V>) -> Self {
        Self {
            proposal,
            signature,
        }
    }
}

impl<V: Verifier, D: Digest> Write for Notarize<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Verifier, D: Digest> Read for Notarize<V, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::<D>::read_cfg(reader, &())?;
        let signature = Signature::<V>::read_cfg(reader, &())?;
        Ok(Self {
            proposal,
            signature,
        })
    }
}

impl<V: Verifier, D: Digest> FixedSize for Notarize<V, D> {
    const SIZE: usize = Proposal::<D>::SIZE + Signature::<V>::SIZE;
}

impl<V: Verifier, D: Digest> Viewable for Notarize<V, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<V: Verifier, D: Digest> Attributable<V> for Notarize<V, D> {
    fn signer(&self) -> V::PublicKey {
        self.signature.signer()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Notarization<V: Verifier, D: Digest> {
    pub proposal: Proposal<D>,
    pub signatures: Vec<Signature<V>>,
}

impl<V: Verifier, D: Digest> Notarization<V, D> {
    pub fn new(proposal: Proposal<D>, signatures: Vec<Signature<V>>) -> Self {
        Self {
            proposal,
            signatures,
        }
    }
}

impl<V: Verifier, D: Digest> Write for Notarization<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.signatures.write(writer);
    }
}

impl<V: Verifier, D: Digest> Read<usize> for Notarization<V, D> {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let proposal = Proposal::<D>::read(reader)?;
        let signatures = Vec::<Signature<V>>::read_range(reader, ..=*max_len)?;
        Ok(Self {
            proposal,
            signatures,
        })
    }
}

impl<V: Verifier, D: Digest> EncodeSize for Notarization<V, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.signatures.encode_size()
    }
}

impl<V: Verifier, D: Digest> Viewable for Notarization<V, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nullify<V: Verifier> {
    pub view: View,
    pub signature: Signature<V>,
}

impl<V: Verifier> Nullify<V> {
    pub fn new(view: View, signature: Signature<V>) -> Self {
        Self { view, signature }
    }
}

impl<V: Verifier> Write for Nullify<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.view.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Verifier> Read for Nullify<V> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = View::read(reader)?;
        let signature = Signature::<V>::read(reader)?;
        Ok(Self { view, signature })
    }
}

impl<V: Verifier> FixedSize for Nullify<V> {
    const SIZE: usize = View::SIZE + Signature::<V>::SIZE;
}

impl<V: Verifier> Viewable for Nullify<V> {
    fn view(&self) -> View {
        self.view
    }
}

impl<V: Verifier> Attributable<V> for Nullify<V> {
    fn signer(&self) -> V::PublicKey {
        self.signature.signer()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nullification<V: Verifier> {
    pub view: View,
    pub signatures: Vec<Signature<V>>,
}

impl<V: Verifier> Nullification<V> {
    pub fn new(view: View, signatures: Vec<Signature<V>>) -> Self {
        Self { view, signatures }
    }
}

impl<V: Verifier> Write for Nullification<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.view.write(writer);
        self.signatures.write(writer);
    }
}

impl<V: Verifier> Read<usize> for Nullification<V> {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let view = View::read(reader)?;
        let signatures = Vec::<Signature<V>>::read_range(reader, ..=*max_len)?;
        Ok(Self { view, signatures })
    }
}

impl<V: Verifier> EncodeSize for Nullification<V> {
    fn encode_size(&self) -> usize {
        self.view.encode_size() + self.signatures.encode_size()
    }
}

impl<V: Verifier> Viewable for Nullification<V> {
    fn view(&self) -> View {
        self.view
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Finalize<V: Verifier> {
    pub view: View,
    pub signature: Signature<V>,
}

impl<V: Verifier> Finalize<V> {
    pub fn new(view: View, signature: Signature<V>) -> Self {
        Self { view, signature }
    }
}

impl<V: Verifier> Write for Finalize<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.view.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Verifier> Read for Finalize<V> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = View::read(reader)?;
        let signature = Signature::<V>::read(reader)?;
        Ok(Self { view, signature })
    }
}

impl<V: Verifier> FixedSize for Finalize<V> {
    const SIZE: usize = View::SIZE + Signature::<V>::SIZE;
}

impl<V: Verifier> Viewable for Finalize<V> {
    fn view(&self) -> View {
        self.view
    }
}

impl<V: Verifier> Attributable<V> for Finalize<V> {
    fn signer(&self) -> V::PublicKey {
        self.signature.signer()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Finalization<V: Verifier, D: Digest> {
    pub proposal: Proposal<D>,
    pub signatures: Vec<Signature<V>>,
}

impl<V: Verifier, D: Digest> Finalization<V, D> {
    pub fn new(proposal: Proposal<D>, signatures: Vec<Signature<V>>) -> Self {
        Self {
            proposal,
            signatures,
        }
    }
}

impl<V: Verifier, D: Digest> Write for Finalization<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.signatures.write(writer);
    }
}

impl<V: Verifier, D: Digest> Read<usize> for Finalization<V, D> {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let proposal = Proposal::<D>::read(reader)?;
        let signatures = Vec::<Signature<V>>::read_range(reader, ..=*max_len)?;
        Ok(Self {
            proposal,
            signatures,
        })
    }
}

impl<V: Verifier, D: Digest> EncodeSize for Finalization<V, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.signatures.encode_size()
    }
}

impl<V: Verifier, D: Digest> Viewable for Finalization<V, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Backfiller<V: Verifier, D: Digest> {
    Request(Request),
    Response(Response<V, D>),
}

impl<V: Verifier, D: Digest> Write for Backfiller<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Backfiller::Request(request) => {
                0u8.write(writer);
                request.write(writer);
            }
            Backfiller::Response(response) => {
                1u8.write(writer);
                response.write(writer);
            }
        }
    }
}

impl<V: Verifier, D: Digest> Read<usize> for Backfiller<V, D> {
    fn read_cfg(reader: &mut impl Buf, cfg: &usize) -> Result<Self, Error> {
        let tag = u8::read(reader)?;
        match tag {
            0 => Ok(Backfiller::Request(Request::read_cfg(reader, cfg)?)),
            1 => Ok(Backfiller::Response(Response::<V, D>::read_cfg(
                reader, cfg,
            )?)),
            _ => Err(Error::Invalid(
                "consensus::simplex::Backfiller",
                "Invalid type",
            )),
        }
    }
}

impl<V: Verifier, D: Digest> EncodeSize for Backfiller<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Backfiller::Request(request) => request.encode_size(),
            Backfiller::Response(response) => response.encode_size(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub id: u64,
    pub notarizations: Vec<View>,
    pub nullifications: Vec<View>,
}

impl Request {
    pub fn new(id: u64, notarizations: Vec<View>, nullifications: Vec<View>) -> Self {
        Self {
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

impl Read<usize> for Request {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let id = u64::read(reader)?;
        let notarizations = Vec::<View>::read_range(reader, ..=*max_len)?;
        let remaining = max_len - notarizations.len();
        let nullifications = Vec::<View>::read_range(reader, ..=remaining)?;
        Ok(Self {
            id,
            notarizations,
            nullifications,
        })
    }
}

impl EncodeSize for Request {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.notarizations.encode_size() + self.nullifications.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Response<V: Verifier, D: Digest> {
    pub id: u64,
    pub notarizations: Vec<Notarization<V, D>>,
    pub nullifications: Vec<Nullification<V>>,
}

impl<V: Verifier, D: Digest> Response<V, D> {
    pub fn new(
        id: u64,
        notarizations: Vec<Notarization<V, D>>,
        nullifications: Vec<Nullification<V>>,
    ) -> Self {
        Self {
            id,
            notarizations,
            nullifications,
        }
    }
}

impl<V: Verifier, D: Digest> Write for Response<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.id.write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl<V: Verifier, D: Digest> Read<usize> for Response<V, D> {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let id = u64::read(reader)?;
        let notarizations = Vec::<Notarization<V, D>>::read_range(reader, ..=*max_len)?;
        let remaining = max_len - notarizations.len();
        let nullifications = Vec::<Nullification<V>>::read_range(reader, ..=remaining)?;
        Ok(Self {
            id,
            notarizations,
            nullifications,
        })
    }
}

impl<V: Verifier, D: Digest> EncodeSize for Response<V, D> {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.notarizations.encode_size() + self.nullifications.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum Activity {}
