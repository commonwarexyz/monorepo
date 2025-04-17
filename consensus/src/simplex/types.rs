use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, FixedSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{Digest, Scheme, Verifier};
use commonware_utils::{quorum, union, Array};

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

const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

#[inline]
fn view_message(view: View) -> Vec<u8> {
    View::encode(&view).into()
}

#[inline]
fn notarize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

#[inline]
fn nullify_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

#[inline]
fn finalize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
}

#[inline]
pub fn threshold<P: Array>(validators: &[P]) -> (u32, u32) {
    let len = validators.len() as u32;
    let threshold = quorum(len).expect("not enough validators for a quorum");
    (threshold, len)
}

#[derive(Clone, Debug, PartialEq)]
pub enum Voter<S: Array, D: Digest> {
    Notarize(Notarize<S, D>),
    Notarization(Notarization<S, D>),
    Nullify(Nullify<S>),
    Nullification(Nullification<S>),
    Finalize(Finalize<S, D>),
    Finalization(Finalization<S, D>),
}

impl<S: Array, D: Digest> Write for Voter<S, D> {
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

impl<S: Array, D: Digest> Read<usize> for Voter<S, D> {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let tag = u8::read(reader)?;
        match tag {
            0 => Ok(Voter::Notarize(Notarize::<S, D>::read(reader)?)),
            1 => Ok(Voter::Notarization(Notarization::<S, D>::read_cfg(
                reader, max_len,
            )?)),
            2 => Ok(Voter::Nullify(Nullify::<S>::read(reader)?)),
            3 => Ok(Voter::Nullification(Nullification::<S>::read_cfg(
                reader, max_len,
            )?)),
            4 => Ok(Voter::Finalize(Finalize::<S, D>::read(reader)?)),
            5 => Ok(Voter::Finalization(Finalization::<S, D>::read_cfg(
                reader, max_len,
            )?)),
            _ => Err(Error::Invalid("consensus::simplex::Voter", "Invalid type")),
        }
    }
}

impl<S: Array, D: Digest> EncodeSize for Voter<S, D> {
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

impl<S: Array, D: Digest> Viewable for Voter<S, D> {
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
pub struct Signature<S: Array> {
    pub public_key: u32,
    pub signature: S,
}

impl<S: Array> Signature<S> {
    pub fn new(public_key: u32, signature: S) -> Self {
        Self {
            public_key,
            signature,
        }
    }
}

impl<S: Array> Write for Signature<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.public_key.write(writer);
        self.signature.write(writer);
    }
}

impl<S: Array> Read for Signature<S> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let public_key = u32::read(reader)?;
        let signature = S::read(reader)?;
        Ok(Self {
            public_key,
            signature,
        })
    }
}

impl<S: Array> FixedSize for Signature<S> {
    const SIZE: usize = u32::SIZE + S::SIZE;
}

impl<S: Array> Attributable for Signature<S> {
    fn signer(&self) -> u32 {
        self.public_key
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Notarize<S: Array, D: Digest> {
    pub proposal: Proposal<D>,
    pub signature: Signature<S>,
}

impl<S: Array, D: Digest> Notarize<S, D> {
    pub fn new(proposal: Proposal<D>, signature: Signature<S>) -> Self {
        Self {
            proposal,
            signature,
        }
    }

    pub fn verify<P: Array, V: Verifier<PublicKey = P, Signature = S>>(
        &self,
        namespace: &[u8],
        public_key: &P,
    ) -> bool {
        let notarize_namespace = notarize_namespace(namespace);
        let message = self.proposal.encode();
        V::verify(
            Some(notarize_namespace.as_ref()),
            &message,
            public_key,
            &self.signature.signature,
        )
    }

    pub fn sign<C: Scheme<Signature = S>>(
        namespace: &[u8],
        scheme: &mut C,
        public_key_index: u32,
        proposal: Proposal<D>,
    ) -> Self {
        let notarize_namespace = notarize_namespace(namespace);
        let message = proposal.encode();
        let signature = scheme.sign(Some(notarize_namespace.as_ref()), &message);
        Self {
            proposal,
            signature: Signature::new(public_key_index, signature),
        }
    }
}

impl<S: Array, D: Digest> Write for Notarize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.signature.write(writer);
    }
}

impl<S: Array, D: Digest> Read for Notarize<S, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::<D>::read_cfg(reader, &())?;
        let signature = Signature::<S>::read_cfg(reader, &())?;
        Ok(Self {
            proposal,
            signature,
        })
    }
}

impl<S: Array, D: Digest> FixedSize for Notarize<S, D> {
    const SIZE: usize = Proposal::<D>::SIZE + Signature::<S>::SIZE;
}

impl<S: Array, D: Digest> Viewable for Notarize<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<S: Array, D: Digest> Attributable for Notarize<S, D> {
    fn signer(&self) -> u32 {
        self.signature.signer()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Notarization<S: Array, D: Digest> {
    pub proposal: Proposal<D>,
    pub signatures: Vec<Signature<S>>,
}

impl<S: Array, D: Digest> Notarization<S, D> {
    pub fn new(proposal: Proposal<D>, mut signatures: Vec<Signature<S>>) -> Self {
        signatures.sort_by_key(|s| s.public_key);
        Self {
            proposal,
            signatures,
        }
    }

    // TODO(#755): Use `commonware-cryptography::Specification`
    pub fn verify<P: Array, V: Verifier<PublicKey = P, Signature = S>>(
        &self,
        namespace: &[u8],
        participants: &[P],
    ) -> bool {
        // Get allowed signers
        let (threshold, count) = threshold(participants);
        if self.signatures.len() < threshold as usize {
            return false;
        }
        if self.signatures.len() > count as usize {
            return false;
        }

        // Verify signatures
        let notarize_namespace = notarize_namespace(namespace);
        let mut last_seen = None;
        let message = self.proposal.encode();
        for signature in &self.signatures {
            // Ensure this isn't a duplicate (and the signatures are sorted)
            if let Some(last_seen) = last_seen {
                if last_seen >= signature.public_key {
                    return false;
                }
            }
            last_seen = Some(signature.public_key);

            // Get public key
            let Some(public_key) = participants.get(signature.public_key as usize) else {
                return false;
            };

            // Verify signature
            if !V::verify(
                Some(notarize_namespace.as_ref()),
                &message,
                public_key,
                &signature.signature,
            ) {
                return false;
            }
        }
        true
    }
}

impl<S: Array, D: Digest> Write for Notarization<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.signatures.write(writer);
    }
}

impl<S: Array, D: Digest> Read<usize> for Notarization<S, D> {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let proposal = Proposal::<D>::read(reader)?;
        let signatures = Vec::<Signature<S>>::read_range(reader, ..=*max_len)?;
        Ok(Self {
            proposal,
            signatures,
        })
    }
}

impl<S: Array, D: Digest> EncodeSize for Notarization<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.signatures.encode_size()
    }
}

impl<S: Array, D: Digest> Viewable for Notarization<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nullify<S: Array> {
    pub view: View,
    pub signature: Signature<S>,
}

impl<S: Array> Nullify<S> {
    pub fn new(view: View, signature: Signature<S>) -> Self {
        Self { view, signature }
    }

    pub fn verify<P: Array, V: Verifier<PublicKey = P, Signature = S>>(
        &self,
        namespace: &[u8],
        public_key: &P,
    ) -> bool {
        let nullify_namespace = nullify_namespace(namespace);
        let message = view_message(self.view);
        V::verify(
            Some(nullify_namespace.as_ref()),
            &message,
            public_key,
            &self.signature.signature,
        )
    }

    pub fn sign<C: Scheme<Signature = S>>(
        namespace: &[u8],
        scheme: &mut C,
        public_key_index: u32,
        view: View,
    ) -> Self {
        let nullify_namespace = nullify_namespace(namespace);
        let message = view_message(view);
        let signature = scheme.sign(Some(nullify_namespace.as_ref()), &message);
        Self {
            view,
            signature: Signature::new(public_key_index, signature),
        }
    }
}

impl<S: Array> Write for Nullify<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.view.write(writer);
        self.signature.write(writer);
    }
}

impl<S: Array> Read for Nullify<S> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = View::read(reader)?;
        let signature = Signature::<S>::read(reader)?;
        Ok(Self { view, signature })
    }
}

impl<S: Array> FixedSize for Nullify<S> {
    const SIZE: usize = View::SIZE + Signature::<S>::SIZE;
}

impl<S: Array> Viewable for Nullify<S> {
    fn view(&self) -> View {
        self.view
    }
}

impl<S: Array> Attributable for Nullify<S> {
    fn signer(&self) -> u32 {
        self.signature.signer()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nullification<S: Array> {
    pub view: View,
    pub signatures: Vec<Signature<S>>,
}

impl<S: Array> Nullification<S> {
    pub fn new(view: View, mut signatures: Vec<Signature<S>>) -> Self {
        signatures.sort_by_key(|s| s.public_key);
        Self { view, signatures }
    }

    pub fn verify<P: Array, V: Verifier<PublicKey = P, Signature = S>>(
        &self,
        namespace: &[u8],
        participants: &[P],
    ) -> bool {
        // Get allowed signers
        let (threshold, count) = threshold(participants);
        if self.signatures.len() < threshold as usize {
            return false;
        }
        if self.signatures.len() > count as usize {
            return false;
        }

        // Verify signatures
        let nullify_namespace = nullify_namespace(namespace);
        let mut last_seen = None;
        let message = view_message(self.view);
        for signature in &self.signatures {
            // Ensure this isn't a duplicate (and the signatures are sorted)
            if let Some(last_seen) = last_seen {
                if last_seen >= signature.public_key {
                    return false;
                }
            }
            last_seen = Some(signature.public_key);

            // Get public key
            let Some(public_key) = participants.get(signature.public_key as usize) else {
                return false;
            };

            // Verify signature
            if !V::verify(
                Some(nullify_namespace.as_ref()),
                &message,
                public_key,
                &signature.signature,
            ) {
                return false;
            }
        }
        true
    }
}

impl<S: Array> Write for Nullification<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.view.write(writer);
        self.signatures.write(writer);
    }
}

impl<S: Array> Read<usize> for Nullification<S> {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let view = View::read(reader)?;
        let signatures = Vec::<Signature<S>>::read_range(reader, ..=*max_len)?;
        Ok(Self { view, signatures })
    }
}

impl<S: Array> EncodeSize for Nullification<S> {
    fn encode_size(&self) -> usize {
        self.view.encode_size() + self.signatures.encode_size()
    }
}

impl<S: Array> Viewable for Nullification<S> {
    fn view(&self) -> View {
        self.view
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Finalize<S: Array, D: Digest> {
    pub proposal: Proposal<D>,
    pub signature: Signature<S>,
}

impl<S: Array, D: Digest> Finalize<S, D> {
    pub fn new(proposal: Proposal<D>, signature: Signature<S>) -> Self {
        Self {
            proposal,
            signature,
        }
    }

    pub fn verify<P: Array, V: Verifier<PublicKey = P, Signature = S>>(
        &self,
        namespace: &[u8],
        public_key: &P,
    ) -> bool {
        let finalize_namespace = finalize_namespace(namespace);
        let message = self.proposal.encode();
        V::verify(
            Some(finalize_namespace.as_ref()),
            &message,
            public_key,
            &self.signature.signature,
        )
    }

    pub fn sign<C: Scheme<Signature = S>>(
        namespace: &[u8],
        scheme: &mut C,
        public_key_index: u32,
        proposal: Proposal<D>,
    ) -> Self {
        let finalize_namespace = finalize_namespace(namespace);
        let message = proposal.encode();
        let signature = scheme.sign(Some(finalize_namespace.as_ref()), &message);
        Self {
            proposal,
            signature: Signature::new(public_key_index, signature),
        }
    }
}

impl<S: Array, D: Digest> Write for Finalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.signature.write(writer);
    }
}

impl<S: Array, D: Digest> Read for Finalize<S, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::<D>::read(reader)?;
        let signature = Signature::<S>::read(reader)?;
        Ok(Self {
            proposal,
            signature,
        })
    }
}

impl<S: Array, D: Digest> FixedSize for Finalize<S, D> {
    const SIZE: usize = Proposal::<D>::SIZE + Signature::<S>::SIZE;
}

impl<S: Array, D: Digest> Viewable for Finalize<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<S: Array, D: Digest> Attributable for Finalize<S, D> {
    fn signer(&self) -> u32 {
        self.signature.signer()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Finalization<S: Array, D: Digest> {
    pub proposal: Proposal<D>,
    pub signatures: Vec<Signature<S>>,
}

impl<S: Array, D: Digest> Finalization<S, D> {
    pub fn new(proposal: Proposal<D>, mut signatures: Vec<Signature<S>>) -> Self {
        signatures.sort_by_key(|s| s.public_key);
        Self {
            proposal,
            signatures,
        }
    }

    pub fn verify<P: Array, V: Verifier<PublicKey = P, Signature = S>>(
        &self,
        namespace: &[u8],
        participants: &[P],
    ) -> bool {
        // Get allowed signers
        let (threshold, count) = threshold(participants);
        if self.signatures.len() < threshold as usize {
            return false;
        }
        if self.signatures.len() > count as usize {
            return false;
        }

        // Verify signatures
        let finalize_namespace = finalize_namespace(namespace);
        let mut last_seen = None;
        let message = self.proposal.encode();
        for signature in &self.signatures {
            // Ensure this isn't a duplicate (and the signatures are sorted)
            if let Some(last_seen) = last_seen {
                if last_seen >= signature.public_key {
                    return false;
                }
            }
            last_seen = Some(signature.public_key);

            // Get public key
            let Some(public_key) = participants.get(signature.public_key as usize) else {
                return false;
            };

            // Verify signature
            if !V::verify(
                Some(finalize_namespace.as_ref()),
                &message,
                public_key,
                &signature.signature,
            ) {
                return false;
            }
        }
        true
    }
}

impl<S: Array, D: Digest> Write for Finalization<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.signatures.write(writer);
    }
}

impl<S: Array, D: Digest> Read<usize> for Finalization<S, D> {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let proposal = Proposal::<D>::read(reader)?;
        let signatures = Vec::<Signature<S>>::read_range(reader, ..=*max_len)?;
        Ok(Self {
            proposal,
            signatures,
        })
    }
}

impl<S: Array, D: Digest> EncodeSize for Finalization<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.signatures.encode_size()
    }
}

impl<S: Array, D: Digest> Viewable for Finalization<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Backfiller<S: Array, D: Digest> {
    Request(Request),
    Response(Response<S, D>),
}

impl<S: Array, D: Digest> Write for Backfiller<S, D> {
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

impl<S: Array, D: Digest> Read<(usize, usize)> for Backfiller<S, D> {
    fn read_cfg(reader: &mut impl Buf, cfg: &(usize, usize)) -> Result<Self, Error> {
        let tag = u8::read(reader)?;
        match tag {
            0 => Ok(Backfiller::Request(Request::read_cfg(reader, &cfg.0)?)),
            1 => Ok(Backfiller::Response(Response::<S, D>::read_cfg(
                reader, cfg,
            )?)),
            _ => Err(Error::Invalid(
                "consensus::simplex::Backfiller",
                "Invalid type",
            )),
        }
    }
}

impl<S: Array, D: Digest> EncodeSize for Backfiller<S, D> {
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
pub struct Response<S: Array, D: Digest> {
    pub id: u64,
    pub notarizations: Vec<Notarization<S, D>>,
    pub nullifications: Vec<Nullification<S>>,
}

impl<S: Array, D: Digest> Response<S, D> {
    pub fn new(
        id: u64,
        notarizations: Vec<Notarization<S, D>>,
        nullifications: Vec<Nullification<S>>,
    ) -> Self {
        Self {
            id,
            notarizations,
            nullifications,
        }
    }
}

impl<S: Array, D: Digest> Write for Response<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.id.write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl<S: Array, D: Digest> Read<(usize, usize)> for Response<S, D> {
    fn read_cfg(reader: &mut impl Buf, max_len: &(usize, usize)) -> Result<Self, Error> {
        let id = u64::read(reader)?;
        let notarizations =
            Vec::<Notarization<S, D>>::read_cfg(reader, &(..=max_len.0, max_len.1))?;
        let remaining = max_len.0 - notarizations.len();
        let nullifications = Vec::<Nullification<S>>::read_cfg(reader, &(..=remaining, max_len.1))?;
        Ok(Self {
            id,
            notarizations,
            nullifications,
        })
    }
}

impl<S: Array, D: Digest> EncodeSize for Response<S, D> {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.notarizations.encode_size() + self.nullifications.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum Activity<S: Array, D: Digest> {
    Notarize(Notarize<S, D>),
    Notarization(Notarization<S, D>),
    Nullify(Nullify<S>),
    Nullification(Nullification<S>),
    Finalize(Finalize<S, D>),
    Finalization(Finalization<S, D>),
    ConflictingNotarize(ConflictingNotarize<S, D>),
    ConflictingFinalize(ConflictingFinalize<S, D>),
    NullifyFinalize(NullifyFinalize<S, D>),
}

impl<S: Array, D: Digest> Write for Activity<S, D> {
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

impl<S: Array, D: Digest> Read<usize> for Activity<S, D> {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let tag = u8::read(reader)?;
        match tag {
            0 => Ok(Activity::Notarize(Notarize::<S, D>::read(reader)?)),
            1 => Ok(Activity::Notarization(Notarization::<S, D>::read_cfg(
                reader, max_len,
            )?)),
            2 => Ok(Activity::Nullify(Nullify::<S>::read(reader)?)),
            3 => Ok(Activity::Nullification(Nullification::<S>::read_cfg(
                reader, max_len,
            )?)),
            4 => Ok(Activity::Finalize(Finalize::<S, D>::read(reader)?)),
            5 => Ok(Activity::Finalization(Finalization::<S, D>::read_cfg(
                reader, max_len,
            )?)),
            6 => Ok(Activity::ConflictingNotarize(
                ConflictingNotarize::<S, D>::read(reader)?,
            )),
            7 => Ok(Activity::ConflictingFinalize(
                ConflictingFinalize::<S, D>::read(reader)?,
            )),
            8 => Ok(Activity::NullifyFinalize(NullifyFinalize::<S, D>::read(
                reader,
            )?)),
            _ => Err(Error::Invalid(
                "consensus::simplex::Activity",
                "Invalid type",
            )),
        }
    }
}

impl<S: Array, D: Digest> EncodeSize for Activity<S, D> {
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

impl<S: Array, D: Digest> Viewable for Activity<S, D> {
    fn view(&self) -> View {
        match self {
            Activity::Notarize(notarize) => notarize.view(),
            Activity::Notarization(notarization) => notarization.view(),
            Activity::Nullify(nullify) => nullify.view(),
            Activity::Nullification(nullification) => nullification.view(),
            Activity::Finalize(finalize) => finalize.view(),
            Activity::Finalization(finalization) => finalization.view(),
            Activity::ConflictingNotarize(conflicting_notarize) => conflicting_notarize.view(),
            Activity::ConflictingFinalize(conflicting_finalize) => conflicting_finalize.view(),
            Activity::NullifyFinalize(nullify_finalize) => nullify_finalize.view(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct ConflictingNotarize<S: Array, D: Digest> {
    pub notarize_1: Notarize<S, D>,
    pub notarize_2: Notarize<S, D>,
}

impl<S: Array, D: Digest> ConflictingNotarize<S, D> {
    pub fn new(notarize_1: Notarize<S, D>, notarize_2: Notarize<S, D>) -> Self {
        Self {
            notarize_1,
            notarize_2,
        }
    }

    pub fn verify<P: Array, V: Verifier<PublicKey = P, Signature = S>>(
        &self,
        namespace: &[u8],
        public_key: &P,
    ) -> bool {
        self.notarize_1.verify::<P, V>(namespace, public_key)
            && self.notarize_2.verify::<P, V>(namespace, public_key)
    }
}

impl<S: Array, D: Digest> Write for ConflictingNotarize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.notarize_1.write(writer);
        self.notarize_2.write(writer);
    }
}

impl<S: Array, D: Digest> Read for ConflictingNotarize<S, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let notarize_1 = Notarize::<S, D>::read(reader)?;
        let notarize_2 = Notarize::<S, D>::read(reader)?;
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

impl<S: Array, D: Digest> FixedSize for ConflictingNotarize<S, D> {
    const SIZE: usize = Notarize::<S, D>::SIZE + Notarize::<S, D>::SIZE;
}

impl<S: Array, D: Digest> Viewable for ConflictingNotarize<S, D> {
    fn view(&self) -> View {
        self.notarize_1.view()
    }
}

impl<S: Array, D: Digest> Attributable for ConflictingNotarize<S, D> {
    fn signer(&self) -> u32 {
        self.notarize_1.signer()
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct ConflictingFinalize<S: Array, D: Digest> {
    pub finalize_1: Finalize<S, D>,
    pub finalize_2: Finalize<S, D>,
}

impl<S: Array, D: Digest> ConflictingFinalize<S, D> {
    pub fn new(finalize_1: Finalize<S, D>, finalize_2: Finalize<S, D>) -> Self {
        Self {
            finalize_1,
            finalize_2,
        }
    }

    pub fn verify<P: Array, V: Verifier<PublicKey = P, Signature = S>>(
        &self,
        namespace: &[u8],
        public_key: &P,
    ) -> bool {
        self.finalize_1.verify::<P, V>(namespace, public_key)
            && self.finalize_2.verify::<P, V>(namespace, public_key)
    }
}

impl<S: Array, D: Digest> Write for ConflictingFinalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.finalize_1.write(writer);
        self.finalize_2.write(writer);
    }
}

impl<S: Array, D: Digest> Read for ConflictingFinalize<S, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let finalize_1 = Finalize::<S, D>::read(reader)?;
        let finalize_2 = Finalize::<S, D>::read(reader)?;
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

impl<S: Array, D: Digest> FixedSize for ConflictingFinalize<S, D> {
    const SIZE: usize =
        Proposal::<D>::SIZE + Signature::<S>::SIZE + Proposal::<D>::SIZE + Signature::<S>::SIZE;
}

impl<S: Array, D: Digest> Viewable for ConflictingFinalize<S, D> {
    fn view(&self) -> View {
        self.finalize_1.view()
    }
}

impl<S: Array, D: Digest> Attributable for ConflictingFinalize<S, D> {
    fn signer(&self) -> u32 {
        self.finalize_1.signer()
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct NullifyFinalize<S: Array, D: Digest> {
    pub nullify: Nullify<S>,
    pub finalize: Finalize<S, D>,
}

impl<S: Array, D: Digest> NullifyFinalize<S, D> {
    pub fn new(nullify: Nullify<S>, finalize: Finalize<S, D>) -> Self {
        Self { nullify, finalize }
    }

    pub fn verify<P: Array, V: Verifier<PublicKey = P, Signature = S>>(
        &self,
        namespace: &[u8],
        public_key: &P,
    ) -> bool {
        self.nullify.verify::<P, V>(namespace, public_key)
            && self.finalize.verify::<P, V>(namespace, public_key)
    }
}

impl<S: Array, D: Digest> Write for NullifyFinalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.nullify.write(writer);
        self.finalize.write(writer);
    }
}

impl<S: Array, D: Digest> Read for NullifyFinalize<S, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let nullify = Nullify::<S>::read(reader)?;
        let finalize = Finalize::<S, D>::read(reader)?;
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

impl<S: Array, D: Digest> FixedSize for NullifyFinalize<S, D> {
    const SIZE: usize = Nullify::<S>::SIZE + Finalize::<S, D>::SIZE;
}

impl<S: Array, D: Digest> Viewable for NullifyFinalize<S, D> {
    fn view(&self) -> View {
        self.nullify.view()
    }
}

impl<S: Array, D: Digest> Attributable for NullifyFinalize<S, D> {
    fn signer(&self) -> u32 {
        self.nullify.signer()
    }
}
