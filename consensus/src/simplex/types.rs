use std::collections::HashSet;

use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, FixedSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{Digest, Scheme, Verifier};
use commonware_utils::{quorum, union, Array};

use crate::Supervisor;

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

pub fn threshold<P: Array>(validators: &[P]) -> (u32, u32) {
    let len = validators.len() as u32;
    let threshold = quorum(len).expect("not enough validators for a quorum");
    (threshold, len)
}

#[derive(Clone, Debug, PartialEq)]
pub enum Voter<V: Verifier, D: Digest> {
    Notarize(Notarize<V, D>),
    Notarization(Notarization<V, D>),
    Nullify(Nullify<V>),
    Nullification(Nullification<V>),
    Finalize(Finalize<V, D>),
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

    pub fn verify(&self, notarize_namespace: &[u8]) -> bool {
        let message = self.proposal.encode();
        V::verify(
            Some(&notarize_namespace),
            &message,
            self.signature.public_key,
            self.signature.signature,
        )
    }

    pub fn sign<S: Scheme<PublicKey = V::PublicKey, Signature = V::Signature>>(
        scheme: &mut S,
        proposal: Proposal<D>,
        notarize_namespace: &[u8],
    ) -> Self {
        let message = proposal.encode();
        let signature = scheme.sign(Some(&notarize_namespace), &message);
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

    pub fn verify<S: Supervisor<Index = View, PublicKey = V::PublicKey>>(
        &self,
        notarize_namespace: &[u8],
    ) -> bool {
        let Some(validators) = S::validators(self.proposal.view) else {
            return false;
        };
        let (threshold, count) = threshold(validators);
        if self.signatures.len() < threshold as usize {
            return false;
        }
        if self.signatures.len() > count as usize {
            return false;
        }
        let mut seen = HashSet::new();
        let message = self.proposal.encode();
        for signature in &self.signatures {
            if !seen.insert(signature.public_key) {
                return false;
            }
            if !V::verify(
                Some(&notarize_namespace),
                &message,
                signature.public_key,
                signature.signature,
            ) {
                return false;
            }
        }
        true
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

    pub fn verify(&self, nullify_namespace: &[u8]) -> bool {
        let message = view_message(self.view);
        V::verify(
            Some(&nullify_namespace),
            &message,
            self.signature.public_key,
            self.signature.signature,
        )
    }

    pub fn sign<S: Scheme<PublicKey = V::PublicKey, Signature = V::Signature>>(
        scheme: &mut S,
        view: View,
        nullify_namespace: &[u8],
    ) -> Self {
        let message = view_message(view);
        let signature = scheme.sign(Some(&nullify_namespace), &message);
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

    pub fn verify<S: Supervisor<Index = View, PublicKey = V::PublicKey>>(
        &self,
        nullify_namespace: &[u8],
    ) -> bool {
        let Some(validators) = S::validators(self.view) else {
            return false;
        };
        let (threshold, count) = threshold(validators);
        if self.signatures.len() < threshold as usize {
            return false;
        }
        if self.signatures.len() > count as usize {
            return false;
        }
        let mut seen = HashSet::new();
        let message = view_message(self.view);
        for signature in &self.signatures {
            if !seen.insert(signature.public_key) {
                return false;
            }
            if !V::verify(
                Some(&nullify_namespace),
                &message,
                signature.public_key,
                signature.signature,
            ) {
                return false;
            }
        }
        true
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
pub struct Finalize<V: Verifier, D: Digest> {
    pub proposal: Proposal<D>,
    pub signature: Signature<V>,
}

impl<V: Verifier, D: Digest> Finalize<V, D> {
    pub fn new(proposal: Proposal<D>, signature: Signature<V>) -> Self {
        Self {
            proposal,
            signature,
        }
    }

    pub fn verify(&self, finalize_namespace: &[u8]) -> bool {
        let message = self.proposal.encode();
        V::verify(
            Some(&finalize_namespace),
            &message,
            self.signature.public_key,
            self.signature.signature,
        )
    }

    pub fn sign<S: Scheme<PublicKey = V::PublicKey, Signature = V::Signature>>(
        scheme: &mut S,
        proposal: Proposal<D>,
        finalize_namespace: &[u8],
    ) -> Self {
        let message = proposal.encode();
        let signature = scheme.sign(Some(&finalize_namespace), &message);
        Self {
            proposal,
            signature,
        }
    }
}

impl<V: Verifier, D: Digest> Write for Finalize<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.view.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Verifier, D> Read for Finalize<V, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::<D>::read(reader)?;
        let signature = Signature::<V>::read(reader)?;
        Ok(Self {
            proposal,
            signature,
        })
    }
}

impl<V: Verifier, D> FixedSize for Finalize<V, D> {
    const SIZE: usize = Proposal::<D>::SIZE + Signature::<V>::SIZE;
}

impl<V: Verifier, D: Digest> Viewable for Finalize<V, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<V: Verifier, D: Digest> Attributable<V> for Finalize<V, D> {
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

    pub fn verify<S: Supervisor<Index = View, PublicKey = V::PublicKey>>(
        &self,
        finalize_namespace: &[u8],
    ) -> bool {
        let Some(validators) = S::validators(self.proposal.view) else {
            return false;
        };
        let (threshold, count) = threshold(validators);
        if self.signatures.len() < threshold as usize {
            return false;
        }
        if self.signatures.len() > count as usize {
            return false;
        }
        let mut seen = HashSet::new();
        let message = self.proposal.encode();
        for signature in &self.signatures {
            if !seen.insert(signature.public_key) {
                return false;
            }
            if !V::verify(
                Some(&finalize_namespace),
                &message,
                signature.public_key,
                signature.signature,
            ) {
                return false;
            }
        }
        true
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
pub enum Activity<V: Verifier, D: Digest> {
    Notarize(Notarize<V, D>),
    Notarization(Notarization<V, D>),
    Nullify(Nullify<V>),
    Nullification(Nullification<V>),
    Finalize(Finalize<V, D>),
    Finalization(Finalization<V, D>),
    ConflictingNotarize(ConflictingNotarize<V, D>),
    ConflictingFinalize(ConflictingFinalize<V, D>),
    NullifyFinalize(NullifyFinalize<V, D>),
}

impl<V: Verifier, D: Digest> Write for Activity<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Activity::Notarize(notarize) => {
                0u8.write(writer);
                notarize.write(writer);
            }
            Activity::Notarization(notarization) => {
                1u8.write(writer);
                notarization.write(writer);
            }
            Activity::Nullify(nullify) => {
                2u8.write(writer);
                nullify.write(writer);
            }
            Activity::Nullification(nullification) => {
                3u8.write(writer);
                nullification.write(writer);
            }
            Activity::Finalize(finalize) => {
                4u8.write(writer);
                finalize.write(writer);
            }
            Activity::Finalization(finalization) => {
                5u8.write(writer);
                finalization.write(writer);
            }
            Activity::ConflictingNotarize(conflicting_notarize) => {
                6u8.write(writer);
                conflicting_notarize.write(writer);
            }
            Activity::ConflictingFinalize(conflicting_finalize) => {
                7u8.write(writer);
                conflicting_finalize.write(writer);
            }
            Activity::NullifyFinalize(nullify_finalize) => {
                8u8.write(writer);
                nullify_finalize.write(writer);
            }
        }
    }
}

impl<V: Verifier, D: Digest> Read<usize> for Activity<V, D> {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let tag = u8::read(reader)?;
        match tag {
            0 => Ok(Activity::Notarize(Notarize::<V, D>::read_cfg(
                reader, max_len,
            )?)),
            1 => Ok(Activity::Notarization(Notarization::<V, D>::read_cfg(
                reader, max_len,
            )?)),
            2 => Ok(Activity::Nullify(Nullify::<V>::read_cfg(reader, max_len)?)),
            3 => Ok(Activity::Nullification(Nullification::<V>::read_cfg(
                reader, max_len,
            )?)),
            4 => Ok(Activity::Finalize(Finalize::<V>::read_cfg(
                reader, max_len,
            )?)),
            5 => Ok(Activity::Finalization(Finalization::<V, D>::read_cfg(
                reader, max_len,
            )?)),
            6 => Ok(Activity::ConflictingNotarize(
                ConflictingNotarize::<V, D>::read_cfg(reader, max_len)?,
            )),
            7 => Ok(Activity::ConflictingFinalize(
                ConflictingFinalize::<V, D>::read_cfg(reader, max_len)?,
            )),
            8 => Ok(Activity::NullifyFinalize(
                NullifyFinalize::<V, D>::read_cfg(reader, max_len)?,
            )),
            _ => Err(Error::Invalid(
                "consensus::simplex::Activity",
                "Invalid type",
            )),
        }
    }
}

impl<V: Verifier, D: Digest> EncodeSize for Activity<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Activity::Notarize(notarize) => notarize.encode_size(),
            Activity::Notarization(notarization) => notarization.encode_size(),
            Activity::Nullify(nullify) => nullify.encode_size(),
            Activity::Nullification(nullification) => nullification.encode_size(),
            Activity::Finalize(finalize) => finalize.encode_size(),
            Activity::Finalization(finalization) => finalization.encode_size(),
            Activity::ConflictingNotarize(conflicting_notarize) => {
                conflicting_notarize.encode_size()
            }
            Activity::ConflictingFinalize(conflicting_finalize) => {
                conflicting_finalize.encode_size()
            }
            Activity::NullifyFinalize(nullify_finalize) => nullify_finalize.encode_size(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct ConflictingNotarize<V: Verifier, D: Digest> {
    pub notarize_1: Notarize<V, D>,
    pub notarize_2: Notarize<V, D>,
}

impl<V: Verifier, D: Digest> ConflictingNotarize<V, D> {
    pub fn new(notarize_1: Notarize<V, D>, notarize_2: Notarize<V, D>) -> Self {
        Self {
            notarize_1,
            notarize_2,
        }
    }

    pub fn verify(&self, notarize_namespace: &[u8]) -> bool {
        self.notarize_1.verify(notarize_namespace) && self.notarize_2.verify(notarize_namespace)
    }
}

impl<V: Verifier, D: Digest> Write for ConflictingNotarize<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.notarize_1.write(writer);
        self.notarize_2.write(writer);
    }
}

impl<V: Verifier, D: Digest> Read for ConflictingNotarize<V, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let notarize_1 = Notarize::<V, D>::read(reader)?;
        let notarize_2 = Notarize::<V, D>::read(reader)?;
        if notarize_1.view() != notarize_2.view() {
            return Err(Error::Invalid(
                "consensus::simplex::ConflictingNotarize",
                "notarizes must have the same view",
            ));
        }
        if notarize_1.signer() != notarize_2.signer() {
            return Err(Error::Invalid(
                "consensus::simplex::ConflictingNotarize",
                "notarizes must have the same public key",
            ));
        }
        Ok(Self {
            notarize_1,
            notarize_2,
        })
    }
}

impl<V: Verifier, D: Digest> FixedSize for ConflictingNotarize<V, D> {
    const SIZE: usize = Notarize::<V, D>::SIZE + Notarize::<V, D>::SIZE;
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct ConflictingFinalize<V: Verifier, D: Digest> {
    pub finalize_1: Finalize<V, D>,
    pub finalize_2: Finalize<V, D>,
}

impl<V: Verifier, D: Digest> ConflictingFinalize<V, D> {
    pub fn new(finalize_1: Finalize<V, D>, finalize_2: Finalize<V, D>) -> Self {
        Self {
            finalize_1,
            finalize_2,
        }
    }

    pub fn verify(&self, finalize_namespace: &[u8]) -> bool {
        self.finalize_1.verify(finalize_namespace) && self.finalize_2.verify(finalize_namespace)
    }
}

impl<V: Verifier, D: Digest> Write for ConflictingFinalize<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.finalize_1.write(writer);
        self.finalize_2.write(writer);
    }
}

impl<V: Verifier, D: Digest> Read for ConflictingFinalize<V, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let finalize_1 = Finalize::<V, D>::read(reader)?;
        let finalize_2 = Finalize::<V, D>::read(reader)?;
        if finalize_1.view() != finalize_2.view() {
            return Err(Error::Invalid(
                "consensus::simplex::ConflictingFinalize",
                "finalizes must have the same view",
            ));
        }
        if finalize_1.signer() != finalize_2.signer() {
            return Err(Error::Invalid(
                "consensus::simplex::ConflictingFinalize",
                "finalizes must have the same public key",
            ));
        }
        Ok(Self {
            finalize_1,
            finalize_2,
        })
    }
}

impl<V: Verifier, D: Digest> FixedSize for ConflictingFinalize<V, D> {
    const SIZE: usize =
        Proposal::<D>::SIZE + Signature::<V>::SIZE + Proposal::<D>::SIZE + Signature::<V>::SIZE;
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct NullifyFinalize<V: Verifier, D: Digest> {
    pub nullify: Nullify<V>,
    pub finalize: Finalize<V, D>,
}

impl<V: Verifier, D: Digest> NullifyFinalize<V, D> {
    pub fn new(nullify: Nullify<V>, finalize: Finalize<V>) -> Self {
        Self { nullify, finalize }
    }

    pub fn verify(&self, nullify_namespace: &[u8], finalize_namespace: &[u8]) -> bool {
        self.nullify.verify(nullify_namespace) && self.finalize.verify(finalize_namespace)
    }
}

impl<V: Verifier, D: Digest> Write for NullifyFinalize<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.nullify.write(writer);
        self.finalize.write(writer);
    }
}

impl<V: Verifier, D: Digest> Read for NullifyFinalize<V, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let nullify = Nullify::<V>::read(reader)?;
        let finalize = Finalize::<V>::read(reader)?;
        if nullify.view() != finalize.view() {
            return Err(Error::Invalid(
                "consensus::simplex::NullifyFinalize",
                "nullification and finalization must have the same view",
            ));
        }
        if nullify.signer() != finalize.signer() {
            return Err(Error::Invalid(
                "consensus::simplex::NullifyFinalize",
                "nullification and finalization must have the same public key",
            ));
        }
        Ok(Self { nullify, finalize })
    }
}

impl<V: Verifier, D: Digest> FixedSize for NullifyFinalize<V, D> {
    const SIZE: usize = Nullify::<V>::SIZE + Finalize::<V>::SIZE;
}
