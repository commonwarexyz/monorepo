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
pub enum Voter<D: Digest> {}

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

#[derive(Clone, Debug, PartialEq)]
pub enum Backfiller<D: Digest> {}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum Activity {}
