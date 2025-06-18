//! Types used in [crate::simplex].

use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, Encode, EncodeSize, Error, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_cryptography::{Digest, Signature as CSignature, Signer, Verifier};
use commonware_utils::{quorum, union};

/// View is a monotonically increasing counter that represents the current focus of consensus.
pub type View = u64;

/// Context is a collection of metadata from consensus about a given payload.
/// It provides information about the current view and the parent payload that new proposals are built on.
#[derive(Clone)]
pub struct Context<D: Digest> {
    /// Current view (round) of consensus.
    pub view: View,

    /// Parent the payload is built on.
    ///
    /// If there is a gap between the current view and the parent view, the participant
    /// must possess a nullification for each discarded view to safely vote on the proposed
    /// payload (any view without a nullification may eventually be finalized and skipping
    /// it would result in a fork).
    pub parent: (View, D),
}

/// Viewable is a trait that provides access to the view (round) number.
/// Any consensus message or object that is associated with a specific view should implement this.
pub trait Viewable {
    /// Returns the view associated with this object.
    fn view(&self) -> View;
}

/// Attributable is a trait that provides access to the signer index.
/// This is used to identify which participant signed a given message.
pub trait Attributable {
    /// Returns the index of the signer (validator) who produced this message.
    fn signer(&self) -> u32;
}

// Constants for domain separation in signature verification
// These are used to prevent cross-protocol attacks and message-type confusion
pub const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
pub const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
pub const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

/// Creates a message to be signed containing just the view number
#[inline]
pub fn view_message(view: View) -> Vec<u8> {
    View::encode(&view).into()
}

/// Creates a namespace for notarize messages by appending the NOTARIZE_SUFFIX
#[inline]
pub fn notarize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

/// Creates a namespace for nullify messages by appending the NULLIFY_SUFFIX
#[inline]
pub fn nullify_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

/// Creates a namespace for finalize messages by appending the FINALIZE_SUFFIX
#[inline]
pub fn finalize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
}

/// Calculates the quorum threshold for a set of validators
/// Returns (threshold, len) where threshold is the minimum number of validators
/// required for a quorum, and len is the total number of validators
#[inline]
pub fn threshold<P>(validators: &[P]) -> (u32, u32) {
    let len = validators.len() as u32;
    let threshold = quorum(len);
    (threshold, len)
}

/// Voter represents all possible message types that can be sent by validators
/// in the consensus protocol.
#[derive(Clone, Debug, PartialEq)]
pub enum Voter<S: CSignature, D: Digest> {
    /// A single validator notarize over a proposal
    Notarize(Notarize<S, D>),
    /// An aggregated set of validator notarizes that meets quorum
    Notarization(Notarization<S, D>),
    /// A single validator nullify to skip the current view (usually when leader is unresponsive)
    Nullify(Nullify<S>),
    /// An aggregated set of validator nullifies that meets quorum
    Nullification(Nullification<S>),
    /// A single validator finalize over a proposal
    Finalize(Finalize<S, D>),
    /// An aggregated set of validator finalizes that meets quorum
    Finalization(Finalization<S, D>),
}

impl<S: CSignature, D: Digest> Write for Voter<S, D> {
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

impl<S: CSignature, D: Digest> Read for Voter<S, D> {
    type Cfg = usize;

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

impl<S: CSignature, D: Digest> EncodeSize for Voter<S, D> {
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

impl<S: CSignature, D: Digest> Viewable for Voter<S, D> {
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

/// Proposal represents a proposed block in the protocol.
/// It includes the view number, the parent view, and the actual payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Proposal<D: Digest> {
    /// The view (round) in which this proposal is made
    pub view: View,
    /// The view of the parent proposal that this one builds upon
    pub parent: View,
    /// The actual payload/content of the proposal (typically a digest of the block data)
    pub payload: D,
}

impl<D: Digest> Proposal<D> {
    /// Creates a new proposal with the specified view, parent view, and payload.
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
        UInt(self.view).write(writer);
        UInt(self.parent).write(writer);
        self.payload.write(writer);
    }
}

impl<D: Digest> Read for Proposal<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = UInt::read_cfg(reader, &())?.into();
        let parent = UInt::read_cfg(reader, &())?.into();
        let payload = D::read_cfg(reader, &())?;
        Ok(Self {
            view,
            parent,
            payload,
        })
    }
}

impl<D: Digest> EncodeSize for Proposal<D> {
    fn encode_size(&self) -> usize {
        UInt(self.view).encode_size() + UInt(self.parent).encode_size() + self.payload.encode_size()
    }
}

impl<D: Digest> Viewable for Proposal<D> {
    fn view(&self) -> View {
        self.view
    }
}

/// Signature represents a validator's cryptographic signature with their identifier.
/// This combines the validator's public key index with their actual signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature<S: CSignature> {
    /// Index of the validator's public key in the validator set
    pub public_key: u32,
    /// The cryptographic signature produced by the validator
    pub signature: S,
}

impl<S: CSignature> Signature<S> {
    /// Creates a new signature with the given public key index and signature data.
    pub fn new(public_key: u32, signature: S) -> Self {
        Self {
            public_key,
            signature,
        }
    }
}

impl<S: CSignature> Write for Signature<S> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.public_key).write(writer);
        self.signature.write(writer);
    }
}

impl<S: CSignature> Read for Signature<S> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let public_key = UInt::read(reader)?.into();
        let signature = S::read(reader)?;
        Ok(Self {
            public_key,
            signature,
        })
    }
}

impl<S: CSignature> EncodeSize for Signature<S> {
    fn encode_size(&self) -> usize {
        UInt(self.public_key).encode_size() + self.signature.encode_size()
    }
}

impl<S: CSignature> Attributable for Signature<S> {
    fn signer(&self) -> u32 {
        self.public_key
    }
}

/// Notarize represents a validator's notarize over a proposal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Notarize<S: CSignature, D: Digest> {
    /// The proposal that is being notarized
    pub proposal: Proposal<D>,
    /// The validator's signature
    pub signature: Signature<S>,
}

impl<S: CSignature, D: Digest> Notarize<S, D> {
    /// Creates a new notarize with the given proposal and signature.
    pub fn new(proposal: Proposal<D>, signature: Signature<S>) -> Self {
        Self {
            proposal,
            signature,
        }
    }

    /// Verifies the signature on this notarize using the provided verifier.
    ///
    /// This ensures that the notarize was actually produced by the claimed validator.
    pub fn verify<K: Verifier<Signature = S>>(&self, namespace: &[u8], public_key: &K) -> bool {
        let notarize_namespace = notarize_namespace(namespace);
        let message = self.proposal.encode();
        public_key.verify(
            Some(notarize_namespace.as_ref()),
            &message,
            &self.signature.signature,
        )
    }

    /// Creates a new signed notarize using the provided cryptographic scheme.
    pub fn sign<C: Signer<Signature = S>>(
        namespace: &[u8],
        signer: &mut C,
        public_key_index: u32,
        proposal: Proposal<D>,
    ) -> Self {
        let notarize_namespace = notarize_namespace(namespace);
        let message = proposal.encode();
        let signature = signer.sign(Some(notarize_namespace.as_ref()), &message);
        Self {
            proposal,
            signature: Signature::new(public_key_index, signature),
        }
    }
}

impl<S: CSignature, D: Digest> Write for Notarize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.signature.write(writer);
    }
}

impl<S: CSignature, D: Digest> Read for Notarize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::<D>::read_cfg(reader, &())?;
        let signature = Signature::<S>::read_cfg(reader, &())?;
        Ok(Self {
            proposal,
            signature,
        })
    }
}

impl<S: CSignature, D: Digest> EncodeSize for Notarize<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.signature.encode_size()
    }
}

impl<S: CSignature, D: Digest> Viewable for Notarize<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<S: CSignature, D: Digest> Attributable for Notarize<S, D> {
    fn signer(&self) -> u32 {
        self.signature.signer()
    }
}

/// Notarization represents an aggregated set of notarizes that meets the quorum threshold.
/// It includes the proposal and the set of signatures from validators.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Notarization<S: CSignature, D: Digest> {
    /// The proposal that has been notarized
    pub proposal: Proposal<D>,
    /// The set of signatures from validators (must meet quorum threshold)
    pub signatures: Vec<Signature<S>>,
}

impl<S: CSignature, D: Digest> Notarization<S, D> {
    /// Creates a new notarization with the given proposal and set of signatures.
    ///
    /// # Warning
    ///
    /// The signatures must be sorted by the public key index.
    pub fn new(proposal: Proposal<D>, signatures: Vec<Signature<S>>) -> Self {
        Self {
            proposal,
            signatures,
        }
    }

    /// Verifies all signatures in this notarization using the provided verifier.
    ///
    /// This ensures that:
    /// 1. There are at least threshold valid signatures
    /// 2. All signatures are valid
    /// 3. All signers are in the validator set
    ///
    /// In `read_cfg`, we ensure that the signatures are sorted by public key index and are unique.
    pub fn verify<K: Verifier<Signature = S>>(&self, namespace: &[u8], participants: &[K]) -> bool {
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
        let message = self.proposal.encode();
        for signature in &self.signatures {
            // Get public key
            let Some(public_key) = participants.get(signature.public_key as usize) else {
                return false;
            };

            // Verify signature
            if !public_key.verify(
                Some(notarize_namespace.as_ref()),
                &message,
                &signature.signature,
            ) {
                return false;
            }
        }
        true
    }
}

impl<S: CSignature, D: Digest> Write for Notarization<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.signatures.write(writer);
    }
}

impl<S: CSignature, D: Digest> Read for Notarization<S, D> {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let proposal = Proposal::<D>::read(reader)?;
        let signatures = Vec::<Signature<S>>::read_range(reader, ..=*max_len)?;

        // Ensure the signatures are sorted by public key index and are unique
        for i in 1..signatures.len() {
            if signatures[i - 1].public_key >= signatures[i].public_key {
                return Err(Error::Invalid(
                    "consensus::simplex::Notarization",
                    "Signatures are not sorted by public key index",
                ));
            }
        }
        Ok(Self {
            proposal,
            signatures,
        })
    }
}

impl<S: CSignature, D: Digest> EncodeSize for Notarization<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.signatures.encode_size()
    }
}

impl<S: CSignature, D: Digest> Viewable for Notarization<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

/// Nullify represents a validator's nullify to skip the current view.
/// This is typically used when the leader is unresponsive or fails to propose a valid block.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nullify<S: CSignature> {
    /// The view to be nullified (skipped)
    pub view: View,
    /// The validator's signature on the view
    pub signature: Signature<S>,
}

impl<S: CSignature> Nullify<S> {
    /// Creates a new nullify with the given view and signature.
    pub fn new(view: View, signature: Signature<S>) -> Self {
        Self { view, signature }
    }

    /// Verifies the signature on this nullify using the provided verifier.
    pub fn verify<K: Verifier<Signature = S>>(&self, namespace: &[u8], public_key: &K) -> bool {
        let nullify_namespace = nullify_namespace(namespace);
        let message = view_message(self.view);
        public_key.verify(
            Some(nullify_namespace.as_ref()),
            &message,
            &self.signature.signature,
        )
    }

    /// Creates a new signed nullify using the provided cryptographic scheme.
    pub fn sign<C: Signer<Signature = S>>(
        namespace: &[u8],
        signer: &mut C,
        public_key_index: u32,
        view: View,
    ) -> Self {
        let nullify_namespace = nullify_namespace(namespace);
        let message = view_message(view);
        let signature = signer.sign(Some(nullify_namespace.as_ref()), &message);
        Self {
            view,
            signature: Signature::new(public_key_index, signature),
        }
    }
}

impl<S: CSignature> Write for Nullify<S> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.view).write(writer);
        self.signature.write(writer);
    }
}

impl<S: CSignature> Read for Nullify<S> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = UInt::read(reader)?.into();
        let signature = Signature::<S>::read(reader)?;
        Ok(Self { view, signature })
    }
}

impl<S: CSignature> EncodeSize for Nullify<S> {
    fn encode_size(&self) -> usize {
        UInt(self.view).encode_size() + self.signature.encode_size()
    }
}

impl<S: CSignature> Viewable for Nullify<S> {
    fn view(&self) -> View {
        self.view
    }
}

impl<S: CSignature> Attributable for Nullify<S> {
    fn signer(&self) -> u32 {
        self.signature.signer()
    }
}

/// Nullification represents an aggregated set of nullifies that meets the quorum threshold.
/// When a view is nullified, the consensus moves to the next view.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nullification<S: CSignature> {
    /// The view that has been nullified
    pub view: View,
    /// The set of signatures from validators (must meet quorum threshold)
    pub signatures: Vec<Signature<S>>,
}

impl<S: CSignature> Nullification<S> {
    /// Creates a new nullification with the given view and set of signatures.
    ///
    /// # Warning
    ///
    /// The signatures must be sorted by the public key index.
    pub fn new(view: View, signatures: Vec<Signature<S>>) -> Self {
        Self { view, signatures }
    }

    /// Verifies all signatures in this nullification using the provided verifier.
    ///
    /// Similar to Notarization::verify, ensures quorum of valid signatures from validators.
    pub fn verify<K: Verifier<Signature = S>>(&self, namespace: &[u8], participants: &[K]) -> bool {
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
        let message = view_message(self.view);
        for signature in &self.signatures {
            // Get public key
            let Some(public_key) = participants.get(signature.public_key as usize) else {
                return false;
            };

            // Verify signature
            if !public_key.verify(
                Some(nullify_namespace.as_ref()),
                &message,
                &signature.signature,
            ) {
                return false;
            }
        }
        true
    }
}

impl<S: CSignature> Write for Nullification<S> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.view).write(writer);
        self.signatures.write(writer);
    }
}

impl<S: CSignature> Read for Nullification<S> {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let view = UInt::read(reader)?.into();
        let signatures = Vec::<Signature<S>>::read_range(reader, ..=*max_len)?;

        // Ensure the signatures are sorted by public key index and are unique
        for i in 1..signatures.len() {
            if signatures[i - 1].public_key >= signatures[i].public_key {
                return Err(Error::Invalid(
                    "consensus::simplex::Nullification",
                    "Signatures are not sorted by public key index",
                ));
            }
        }
        Ok(Self { view, signatures })
    }
}

impl<S: CSignature> EncodeSize for Nullification<S> {
    fn encode_size(&self) -> usize {
        UInt(self.view).encode_size() + self.signatures.encode_size()
    }
}

impl<S: CSignature> Viewable for Nullification<S> {
    fn view(&self) -> View {
        self.view
    }
}

/// Finalize represents a validator's finalize over a proposal.
/// This happens after a proposal has been notarized, confirming it as the canonical block
/// for this view.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Finalize<S: CSignature, D: Digest> {
    /// The proposal to be finalized
    pub proposal: Proposal<D>,
    /// The validator's signature on the proposal
    pub signature: Signature<S>,
}

impl<S: CSignature, D: Digest> Finalize<S, D> {
    /// Creates a new finalize with the given proposal and signature.
    pub fn new(proposal: Proposal<D>, signature: Signature<S>) -> Self {
        Self {
            proposal,
            signature,
        }
    }

    /// Verifies the signature on this finalize using the provided verifier.
    pub fn verify<K: Verifier<Signature = S>>(&self, namespace: &[u8], public_key: &K) -> bool {
        let finalize_namespace = finalize_namespace(namespace);
        let message = self.proposal.encode();
        public_key.verify(
            Some(finalize_namespace.as_ref()),
            &message,
            &self.signature.signature,
        )
    }

    /// Creates a new signed finalize using the provided cryptographic scheme.
    pub fn sign<C: Signer<Signature = S>>(
        namespace: &[u8],
        signer: &mut C,
        public_key_index: u32,
        proposal: Proposal<D>,
    ) -> Self {
        let finalize_namespace = finalize_namespace(namespace);
        let message = proposal.encode();
        let signature = signer.sign(Some(finalize_namespace.as_ref()), &message);
        Self {
            proposal,
            signature: Signature::new(public_key_index, signature),
        }
    }
}

impl<S: CSignature, D: Digest> Write for Finalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.signature.write(writer);
    }
}

impl<S: CSignature, D: Digest> Read for Finalize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::<D>::read(reader)?;
        let signature = Signature::<S>::read(reader)?;
        Ok(Self {
            proposal,
            signature,
        })
    }
}

impl<S: CSignature, D: Digest> EncodeSize for Finalize<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.signature.encode_size()
    }
}

impl<S: CSignature, D: Digest> Viewable for Finalize<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<S: CSignature, D: Digest> Attributable for Finalize<S, D> {
    fn signer(&self) -> u32 {
        self.signature.signer()
    }
}

/// Finalization represents an aggregated set of finalizes that meets the quorum threshold.
/// When a proposal is finalized, it becomes the canonical block for its view.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Finalization<S: CSignature, D: Digest> {
    /// The proposal that has been finalized
    pub proposal: Proposal<D>,
    /// The set of signatures from validators (must meet quorum threshold)
    pub signatures: Vec<Signature<S>>,
}

impl<S: CSignature, D: Digest> Finalization<S, D> {
    /// Creates a new finalization with the given proposal and set of signatures.
    ///
    /// # Warning
    ///
    /// The signatures must be sorted by the public key index.
    pub fn new(proposal: Proposal<D>, signatures: Vec<Signature<S>>) -> Self {
        Self {
            proposal,
            signatures,
        }
    }

    /// Verifies all signatures in this finalization using the provided verifier.
    ///
    /// Similar to Notarization::verify, ensures quorum of valid signatures from validators.
    pub fn verify<V: Verifier<Signature = S>>(&self, namespace: &[u8], participants: &[V]) -> bool {
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
        let message = self.proposal.encode();
        for signature in &self.signatures {
            // Get public key
            let Some(public_key) = participants.get(signature.public_key as usize) else {
                return false;
            };

            // Verify signature
            if !public_key.verify(
                Some(finalize_namespace.as_ref()),
                &message,
                &signature.signature,
            ) {
                return false;
            }
        }
        true
    }
}

impl<S: CSignature, D: Digest> Write for Finalization<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.signatures.write(writer);
    }
}

impl<S: CSignature, D: Digest> Read for Finalization<S, D> {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let proposal = Proposal::<D>::read(reader)?;
        let signatures = Vec::<Signature<S>>::read_range(reader, ..=*max_len)?;

        // Ensure the signatures are sorted by public key index and are unique
        for i in 1..signatures.len() {
            if signatures[i - 1].public_key >= signatures[i].public_key {
                return Err(Error::Invalid(
                    "consensus::simplex::Finalization",
                    "Signatures are not sorted by public key index",
                ));
            }
        }
        Ok(Self {
            proposal,
            signatures,
        })
    }
}

impl<S: CSignature, D: Digest> EncodeSize for Finalization<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.signatures.encode_size()
    }
}

impl<S: CSignature, D: Digest> Viewable for Finalization<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

/// Backfiller is a message type for requesting and receiving missing consensus artifacts.
/// This is used to synchronize validators that have fallen behind or just joined the network.
#[derive(Clone, Debug, PartialEq)]
pub enum Backfiller<S: CSignature, D: Digest> {
    /// Request for missing notarizations and nullifications
    Request(Request),
    /// Response containing requested notarizations and nullifications
    Response(Response<S, D>),
}

impl<S: CSignature, D: Digest> Write for Backfiller<S, D> {
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

impl<S: CSignature, D: Digest> Read for Backfiller<S, D> {
    type Cfg = (usize, usize);

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

impl<S: CSignature, D: Digest> EncodeSize for Backfiller<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Backfiller::Request(request) => request.encode_size(),
            Backfiller::Response(response) => response.encode_size(),
        }
    }
}

/// Request is a message to request missing notarizations and nullifications.
/// This is used by validators who need to catch up with the consensus state.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    /// Unique identifier for this request (used to match responses)
    pub id: u64,
    /// Views for which notarizations are requested
    pub notarizations: Vec<View>,
    /// Views for which nullifications are requested
    pub nullifications: Vec<View>,
}

impl Request {
    /// Creates a new request for missing notarizations and nullifications.
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
        UInt(self.id).write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl Read for Request {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let id = UInt::read(reader)?.into();
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
        UInt(self.id).encode_size()
            + self.notarizations.encode_size()
            + self.nullifications.encode_size()
    }
}

/// Response is a message containing the requested notarizations and nullifications.
/// This is sent in response to a Request message.
#[derive(Clone, Debug, PartialEq)]
pub struct Response<S: CSignature, D: Digest> {
    /// Identifier matching the original request
    pub id: u64,
    /// Notarizations for the requested views
    pub notarizations: Vec<Notarization<S, D>>,
    /// Nullifications for the requested views
    pub nullifications: Vec<Nullification<S>>,
}

impl<S: CSignature, D: Digest> Response<S, D> {
    /// Creates a new response with the given id, notarizations, and nullifications.
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

impl<S: CSignature, D: Digest> Write for Response<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.id).write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl<S: CSignature, D: Digest> Read for Response<S, D> {
    type Cfg = (usize, usize);

    fn read_cfg(reader: &mut impl Buf, (total, max_sigs): &(usize, usize)) -> Result<Self, Error> {
        let id = UInt::read(reader)?.into();
        let notarizations =
            Vec::<Notarization<S, D>>::read_cfg(reader, &((..=total).into(), *max_sigs))?;
        let rem = total - notarizations.len();
        let nullifications =
            Vec::<Nullification<S>>::read_cfg(reader, &((..=rem).into(), *max_sigs))?;
        Ok(Self {
            id,
            notarizations,
            nullifications,
        })
    }
}

impl<S: CSignature, D: Digest> EncodeSize for Response<S, D> {
    fn encode_size(&self) -> usize {
        UInt(self.id).encode_size()
            + self.notarizations.encode_size()
            + self.nullifications.encode_size()
    }
}

/// Activity represents all possible activities that can occur in the consensus protocol.
/// This includes both regular consensus messages and fault evidence.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum Activity<S: CSignature, D: Digest> {
    /// A single notarize over a proposal
    Notarize(Notarize<S, D>),
    /// An aggregated set of validator notarizes that meets quorum
    Notarization(Notarization<S, D>),
    /// A single validator nullify to skip the current view
    Nullify(Nullify<S>),
    /// An aggregated set of validator nullifies that meets quorum
    Nullification(Nullification<S>),
    /// A single validator finalize over a proposal
    Finalize(Finalize<S, D>),
    /// An aggregated set of validator finalizes that meets quorum
    Finalization(Finalization<S, D>),
    /// Evidence of a validator sending conflicting notarizes (Byzantine behavior)
    ConflictingNotarize(ConflictingNotarize<S, D>),
    /// Evidence of a validator sending conflicting finalizes (Byzantine behavior)
    ConflictingFinalize(ConflictingFinalize<S, D>),
    /// Evidence of a validator sending both nullify and finalize for the same view (Byzantine behavior)
    NullifyFinalize(NullifyFinalize<S, D>),
}

impl<S: CSignature, D: Digest> Write for Activity<S, D> {
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

impl<S: CSignature, D: Digest> Read for Activity<S, D> {
    type Cfg = usize;

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

impl<S: CSignature, D: Digest> EncodeSize for Activity<S, D> {
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

impl<S: CSignature, D: Digest> Viewable for Activity<S, D> {
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

/// ConflictingNotarize represents evidence of a Byzantine validator sending conflicting notarizes.
/// This is used to prove that a validator has equivocated (voted for different proposals in the same view).
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct ConflictingNotarize<S: CSignature, D: Digest> {
    /// The view in which the conflict occurred
    pub view: View,
    /// The parent view of the first conflicting proposal
    pub parent_1: View,
    /// The payload of the first conflicting proposal
    pub payload_1: D,
    /// The signature on the first conflicting proposal
    pub signature_1: Signature<S>,
    /// The parent view of the second conflicting proposal
    pub parent_2: View,
    /// The payload of the second conflicting proposal
    pub payload_2: D,
    /// The signature on the second conflicting proposal
    pub signature_2: Signature<S>,
}

impl<S: CSignature, D: Digest> ConflictingNotarize<S, D> {
    /// Creates a new conflicting notarize evidence from two conflicting notarizes.
    pub fn new(notarize_1: Notarize<S, D>, notarize_2: Notarize<S, D>) -> Self {
        assert_eq!(notarize_1.view(), notarize_2.view());
        assert_eq!(notarize_1.signer(), notarize_2.signer());
        Self {
            view: notarize_1.view(),
            parent_1: notarize_1.proposal.parent,
            payload_1: notarize_1.proposal.payload,
            signature_1: notarize_1.signature,
            parent_2: notarize_2.proposal.parent,
            payload_2: notarize_2.proposal.payload,
            signature_2: notarize_2.signature,
        }
    }

    /// Reconstructs the original notarizes from this evidence.
    pub fn notarizes(&self) -> (Notarize<S, D>, Notarize<S, D>) {
        (
            Notarize::new(
                Proposal::new(self.view, self.parent_1, self.payload_1),
                self.signature_1.clone(),
            ),
            Notarize::new(
                Proposal::new(self.view, self.parent_2, self.payload_2),
                self.signature_2.clone(),
            ),
        )
    }

    /// Verifies that both conflicting signatures are valid, proving Byzantine behavior.
    pub fn verify<V: Verifier<Signature = S>>(&self, namespace: &[u8], public_key: &V) -> bool {
        let (notarize_1, notarize_2) = self.notarizes();
        notarize_1.verify(namespace, public_key) && notarize_2.verify(namespace, public_key)
    }
}

impl<S: CSignature, D: Digest> Write for ConflictingNotarize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.view).write(writer);
        UInt(self.parent_1).write(writer);
        self.payload_1.write(writer);
        self.signature_1.write(writer);
        UInt(self.parent_2).write(writer);
        self.payload_2.write(writer);
        self.signature_2.write(writer);
    }
}

impl<S: CSignature, D: Digest> Read for ConflictingNotarize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = UInt::read(reader)?.into();
        let parent_1 = UInt::read(reader)?.into();
        let payload_1 = D::read_cfg(reader, &())?;
        let signature_1 = Signature::<S>::read(reader)?;
        let parent_2 = UInt::read(reader)?.into();
        let payload_2 = D::read_cfg(reader, &())?;
        let signature_2 = Signature::<S>::read(reader)?;
        if signature_1.signer() != signature_2.signer() {
            return Err(Error::Invalid(
                "consensus::simplex::ConflictingNotarize",
                "notarizes must have the same public key",
            ));
        }
        Ok(Self {
            view,
            parent_1,
            payload_1,
            signature_1,
            parent_2,
            payload_2,
            signature_2,
        })
    }
}

impl<S: CSignature, D: Digest> EncodeSize for ConflictingNotarize<S, D> {
    fn encode_size(&self) -> usize {
        UInt(self.view).encode_size()
            + UInt(self.parent_1).encode_size()
            + self.payload_1.encode_size()
            + self.signature_1.encode_size()
            + UInt(self.parent_2).encode_size()
            + self.payload_2.encode_size()
            + self.signature_2.encode_size()
    }
}

impl<S: CSignature, D: Digest> Viewable for ConflictingNotarize<S, D> {
    fn view(&self) -> View {
        self.view
    }
}

impl<S: CSignature, D: Digest> Attributable for ConflictingNotarize<S, D> {
    fn signer(&self) -> u32 {
        self.signature_1.signer()
    }
}

/// ConflictingFinalize represents evidence of a Byzantine validator sending conflicting finalizes.
/// Similar to ConflictingNotarize, but for finalizes.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct ConflictingFinalize<S: CSignature, D: Digest> {
    /// The view in which the conflict occurred
    pub view: View,
    /// The parent view of the first conflicting proposal
    pub parent_1: View,
    /// The payload of the first conflicting proposal
    pub payload_1: D,
    /// The signature on the first conflicting proposal
    pub signature_1: Signature<S>,
    /// The parent view of the second conflicting proposal
    pub parent_2: View,
    /// The payload of the second conflicting proposal
    pub payload_2: D,
    /// The signature on the second conflicting proposal
    pub signature_2: Signature<S>,
}

impl<S: CSignature, D: Digest> ConflictingFinalize<S, D> {
    /// Creates a new conflicting finalize evidence from two conflicting finalizes.
    pub fn new(finalize_1: Finalize<S, D>, finalize_2: Finalize<S, D>) -> Self {
        assert_eq!(finalize_1.view(), finalize_2.view());
        assert_eq!(finalize_1.signer(), finalize_2.signer());
        Self {
            view: finalize_1.view(),
            parent_1: finalize_1.proposal.parent,
            payload_1: finalize_1.proposal.payload,
            signature_1: finalize_1.signature,
            parent_2: finalize_2.proposal.parent,
            payload_2: finalize_2.proposal.payload,
            signature_2: finalize_2.signature,
        }
    }

    /// Reconstructs the original finalize from this evidence.
    pub fn finalizes(&self) -> (Finalize<S, D>, Finalize<S, D>) {
        (
            Finalize::new(
                Proposal::new(self.view, self.parent_1, self.payload_1),
                self.signature_1.clone(),
            ),
            Finalize::new(
                Proposal::new(self.view, self.parent_2, self.payload_2),
                self.signature_2.clone(),
            ),
        )
    }

    /// Verifies that both conflicting signatures are valid, proving Byzantine behavior.
    pub fn verify<V: Verifier<Signature = S>>(&self, namespace: &[u8], public_key: &V) -> bool {
        let (finalize_1, finalize_2) = self.finalizes();
        finalize_1.verify(namespace, public_key) && finalize_2.verify(namespace, public_key)
    }
}

impl<S: CSignature, D: Digest> Write for ConflictingFinalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.view).write(writer);
        UInt(self.parent_1).write(writer);
        self.payload_1.write(writer);
        self.signature_1.write(writer);
        UInt(self.parent_2).write(writer);
        self.payload_2.write(writer);
        self.signature_2.write(writer);
    }
}

impl<S: CSignature, D: Digest> Read for ConflictingFinalize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = UInt::read(reader)?.into();
        let parent_1 = UInt::read(reader)?.into();
        let payload_1 = D::read_cfg(reader, &())?;
        let signature_1 = Signature::<S>::read(reader)?;
        let parent_2 = UInt::read(reader)?.into();
        let payload_2 = D::read_cfg(reader, &())?;
        let signature_2 = Signature::<S>::read(reader)?;
        if signature_1.signer() != signature_2.signer() {
            return Err(Error::Invalid(
                "consensus::simplex::ConflictingFinalize",
                "finalizes must have the same public key",
            ));
        }
        Ok(Self {
            view,
            parent_1,
            payload_1,
            signature_1,
            parent_2,
            payload_2,
            signature_2,
        })
    }
}

impl<S: CSignature, D: Digest> EncodeSize for ConflictingFinalize<S, D> {
    fn encode_size(&self) -> usize {
        UInt(self.view).encode_size()
            + UInt(self.parent_1).encode_size()
            + self.payload_1.encode_size()
            + self.signature_1.encode_size()
            + UInt(self.parent_2).encode_size()
            + self.payload_2.encode_size()
            + self.signature_2.encode_size()
    }
}

impl<S: CSignature, D: Digest> Viewable for ConflictingFinalize<S, D> {
    fn view(&self) -> View {
        self.view
    }
}

impl<S: CSignature, D: Digest> Attributable for ConflictingFinalize<S, D> {
    fn signer(&self) -> u32 {
        self.signature_1.signer()
    }
}

/// NullifyFinalize represents evidence of a Byzantine validator sending both a nullify and finalize
/// for the same view, which is contradictory behavior (a validator should either try to skip a view OR
/// finalize a proposal, not both).
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct NullifyFinalize<S: CSignature, D: Digest> {
    /// The proposal that the validator tried to finalize
    pub proposal: Proposal<D>,
    /// The signature on the nullify
    pub view_signature: Signature<S>,
    /// The signature on the finalize
    pub finalize_signature: Signature<S>,
}

impl<S: CSignature, D: Digest> NullifyFinalize<S, D> {
    /// Creates a new nullify-finalize evidence from a nullify and a finalize.
    pub fn new(nullify: Nullify<S>, finalize: Finalize<S, D>) -> Self {
        assert_eq!(nullify.view(), finalize.view());
        assert_eq!(nullify.signer(), finalize.signer());
        Self {
            proposal: finalize.proposal,
            view_signature: nullify.signature,
            finalize_signature: finalize.signature,
        }
    }

    /// Verifies that both the nullify and finalize signatures are valid, proving Byzantine behavior.
    pub fn verify<V: Verifier<Signature = S>>(&self, namespace: &[u8], public_key: &V) -> bool {
        let nullify = Nullify::new(self.proposal.view(), self.view_signature.clone());
        let finalize = Finalize::new(self.proposal.clone(), self.finalize_signature.clone());
        nullify.verify(namespace, public_key) && finalize.verify(namespace, public_key)
    }
}

impl<S: CSignature, D: Digest> Write for NullifyFinalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.view_signature.write(writer);
        self.finalize_signature.write(writer);
    }
}

impl<S: CSignature, D: Digest> Read for NullifyFinalize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::<D>::read(reader)?;
        let view_signature = Signature::<S>::read(reader)?;
        let finalize_signature = Signature::<S>::read(reader)?;
        if view_signature.signer() != finalize_signature.signer() {
            return Err(Error::Invalid(
                "consensus::simplex::NullifyFinalize",
                "nullification and finalization must have the same public key",
            ));
        }
        Ok(Self {
            proposal,
            view_signature,
            finalize_signature,
        })
    }
}

impl<S: CSignature, D: Digest> EncodeSize for NullifyFinalize<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size()
            + self.view_signature.encode_size()
            + self.finalize_signature.encode_size()
    }
}

impl<S: CSignature, D: Digest> Viewable for NullifyFinalize<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<S: CSignature, D: Digest> Attributable for NullifyFinalize<S, D> {
    fn signer(&self) -> u32 {
        self.view_signature.signer()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey, Signature},
        sha256::Digest as Sha256Digest,
        PrivateKeyExt as _,
    };

    const NAMESPACE: &[u8] = b"test";

    // Helper function to create a sample digest
    fn sample_digest(v: u8) -> Sha256Digest {
        Sha256Digest::from([v; 32]) // Simple fixed digest for testing
    }

    fn sample_scheme(v: u64) -> PrivateKey {
        PrivateKey::from_seed(v)
    }

    #[test]
    fn test_proposal_encode_decode() {
        let proposal = Proposal::new(10, 5, sample_digest(1));
        let encoded = proposal.encode();
        let decoded = Proposal::<Sha256Digest>::decode(encoded).unwrap();
        assert_eq!(proposal, decoded);
    }

    #[test]
    fn test_notarize_encode_decode() {
        let mut scheme = sample_scheme(0);
        let proposal = Proposal::new(10, 5, sample_digest(1));
        let notarize = Notarize::sign(NAMESPACE, &mut scheme, 0, proposal);
        let encoded = notarize.encode();
        let decoded = Notarize::<Signature, Sha256Digest>::decode(encoded).unwrap();
        assert_eq!(notarize, decoded);
        assert!(decoded.verify::<PublicKey>(NAMESPACE, &scheme.public_key()));
    }

    #[test]
    fn test_notarization_encode_decode() {
        let mut scheme_1 = sample_scheme(0);
        let mut scheme_2 = sample_scheme(1);
        let proposal = Proposal::new(10, 5, sample_digest(1));
        let notarize_1 = Notarize::sign(NAMESPACE, &mut scheme_1, 0, proposal.clone());
        let notarize_2 = Notarize::sign(NAMESPACE, &mut scheme_2, 1, proposal.clone());
        let signatures = vec![notarize_1.signature.clone(), notarize_2.signature.clone()];
        let notarization = Notarization::new(proposal.clone(), signatures.clone());
        let encoded = notarization.encode();
        let decoded =
            Notarization::<Signature, Sha256Digest>::decode_cfg(encoded, &usize::MAX).unwrap();
        assert_eq!(notarization, decoded);
        assert!(
            decoded.verify::<PublicKey>(NAMESPACE, &[scheme_1.public_key(), scheme_2.public_key()])
        );
    }

    #[test]
    fn test_nullify_encode_decode() {
        let mut scheme = sample_scheme(0);
        let nullify = Nullify::sign(NAMESPACE, &mut scheme, 0, 10);
        let encoded = nullify.encode();
        let decoded = Nullify::<Signature>::decode(encoded).unwrap();
        assert_eq!(nullify, decoded);
        assert!(decoded.verify::<PublicKey>(NAMESPACE, &scheme.public_key()));
    }

    #[test]
    fn test_nullification_encode_decode() {
        let mut scheme_1 = sample_scheme(0);
        let mut scheme_2 = sample_scheme(1);
        let nullify_1 = Nullify::sign(NAMESPACE, &mut scheme_1, 0, 10);
        let nullify_2 = Nullify::sign(NAMESPACE, &mut scheme_2, 1, 10);
        let signatures = vec![nullify_1.signature.clone(), nullify_2.signature.clone()];
        let nullification = Nullification::new(10, signatures.clone());
        let encoded = nullification.encode();
        let decoded = Nullification::<Signature>::decode_cfg(encoded, &usize::MAX).unwrap();
        assert_eq!(nullification, decoded);
        assert!(
            decoded.verify::<PublicKey>(NAMESPACE, &[scheme_1.public_key(), scheme_2.public_key()])
        );
    }

    #[test]
    fn test_finalize_encode_decode() {
        let mut scheme = sample_scheme(0);
        let proposal = Proposal::new(10, 5, sample_digest(1));
        let finalize = Finalize::sign(NAMESPACE, &mut scheme, 0, proposal);
        let encoded = finalize.encode();
        let decoded = Finalize::<Signature, Sha256Digest>::decode(encoded).unwrap();
        assert_eq!(finalize, decoded);
    }

    #[test]
    fn test_finalization_encode_decode() {
        let mut scheme_1 = sample_scheme(0);
        let mut scheme_2 = sample_scheme(1);
        let proposal = Proposal::new(10, 5, sample_digest(1));
        let finalize_1 = Finalize::sign(NAMESPACE, &mut scheme_1, 0, proposal.clone());
        let finalize_2 = Finalize::sign(NAMESPACE, &mut scheme_2, 1, proposal.clone());
        let signatures = vec![finalize_1.signature.clone(), finalize_2.signature.clone()];
        let finalization = Finalization::new(proposal.clone(), signatures.clone());
        let encoded = finalization.encode();
        let decoded =
            Finalization::<Signature, Sha256Digest>::decode_cfg(encoded, &usize::MAX).unwrap();
        assert_eq!(finalization, decoded);
        assert!(
            decoded.verify::<PublicKey>(NAMESPACE, &[scheme_1.public_key(), scheme_2.public_key()])
        );
    }

    #[test]
    fn test_backfiller_encode_decode() {
        let request = Request::new(1, vec![10, 11], vec![12, 13]);
        let backfiller = Backfiller::Request::<Signature, Sha256Digest>(request.clone());
        let encoded = backfiller.encode();
        let decoded =
            Backfiller::<Signature, Sha256Digest>::decode_cfg(encoded, &(usize::MAX, usize::MAX))
                .unwrap();
        assert!(matches!(decoded, Backfiller::Request(r) if r == request));
    }

    #[test]
    fn test_request_encode_decode() {
        let request = Request::new(1, vec![10, 11], vec![12, 13]);
        let encoded = request.encode();
        let decoded = Request::decode_cfg(encoded, &usize::MAX).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn test_response_encode_decode() {
        let mut scheme = sample_scheme(0);
        let proposal = Proposal::new(10, 5, sample_digest(1));
        let notarize = Notarize::sign(NAMESPACE, &mut scheme, 0, proposal.clone());
        let notarization = Notarization::new(proposal.clone(), vec![notarize.signature.clone()]);
        let response = Response::new(1, vec![notarization], vec![]);
        let encoded = response.encode();
        let decoded =
            Response::<Signature, Sha256Digest>::decode_cfg(encoded, &(usize::MAX, usize::MAX))
                .unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_conflicting_notarize_encode_decode() {
        let mut scheme = sample_scheme(0);
        let proposal1 = Proposal::new(10, 5, sample_digest(1));
        let proposal2 = Proposal::new(10, 6, sample_digest(2));
        let notarize1 = Notarize::sign(NAMESPACE, &mut scheme, 0, proposal1.clone());
        let notarize2 = Notarize::sign(NAMESPACE, &mut scheme, 0, proposal2.clone());
        let conflicting = ConflictingNotarize::new(notarize1, notarize2);
        let encoded = conflicting.encode();
        let decoded = ConflictingNotarize::<Signature, Sha256Digest>::decode(encoded).unwrap();
        assert_eq!(conflicting, decoded);
        assert!(conflicting.verify::<PublicKey>(NAMESPACE, &scheme.public_key()));
    }

    #[test]
    fn test_conflicting_finalize_encode_decode() {
        let mut scheme = sample_scheme(0);
        let proposal1 = Proposal::new(10, 5, sample_digest(1));
        let proposal2 = Proposal::new(10, 6, sample_digest(2));
        let finalize1 = Finalize::sign(NAMESPACE, &mut scheme, 0, proposal1.clone());
        let finalize2 = Finalize::sign(NAMESPACE, &mut scheme, 0, proposal2.clone());
        let conflicting = ConflictingFinalize::new(finalize1, finalize2);
        let encoded = conflicting.encode();
        let decoded = ConflictingFinalize::<Signature, Sha256Digest>::decode(encoded).unwrap();
        assert_eq!(conflicting, decoded);
        assert!(conflicting.verify::<PublicKey>(NAMESPACE, &scheme.public_key()));
    }

    #[test]
    fn test_nullify_finalize_encode_decode() {
        let mut scheme = sample_scheme(0);
        let proposal = Proposal::new(10, 5, sample_digest(1));
        let nullify = Nullify::sign(NAMESPACE, &mut scheme, 1, 10);
        let finalize = Finalize::sign(NAMESPACE, &mut scheme, 1, proposal.clone());
        let nullify_finalize = NullifyFinalize::new(nullify, finalize);
        let encoded = nullify_finalize.encode();
        let decoded = NullifyFinalize::<Signature, Sha256Digest>::decode(encoded).unwrap();
        assert_eq!(nullify_finalize, decoded);
        assert!(nullify_finalize.verify::<PublicKey>(NAMESPACE, &scheme.public_key()));
    }

    #[test]
    fn test_notarize_verify_wrong_namespace() {
        let mut scheme = sample_scheme(0);
        let proposal = Proposal::new(10, 5, sample_digest(1));
        let notarize = Notarize::sign(NAMESPACE, &mut scheme, 0, proposal);

        // Verify with wrong namespace - should fail
        assert!(!notarize.verify::<PublicKey>(b"wrong_namespace", &scheme.public_key()));
    }

    #[test]
    fn test_notarize_verify_wrong_public_key() {
        let mut scheme1 = sample_scheme(0);
        let scheme2 = sample_scheme(1); // Different key
        let proposal = Proposal::new(10, 5, sample_digest(1));
        let notarize = Notarize::sign(NAMESPACE, &mut scheme1, 0, proposal);

        // Verify with wrong public key - should fail
        assert!(!notarize.verify::<PublicKey>(NAMESPACE, &scheme2.public_key()));
    }

    #[test]
    fn test_notarization_verify_insufficient_signatures() {
        let mut scheme_1 = sample_scheme(0);
        let mut scheme_2 = sample_scheme(1);
        let proposal = Proposal::new(10, 5, sample_digest(1));
        let notarize_1 = Notarize::sign(NAMESPACE, &mut scheme_1, 0, proposal.clone());
        let notarize_2 = Notarize::sign(NAMESPACE, &mut scheme_2, 1, proposal.clone());

        // Create a notarization with only 2 signatures
        let signatures = vec![notarize_1.signature.clone(), notarize_2.signature.clone()];
        let notarization = Notarization::new(proposal.clone(), signatures);

        // Create a validator set of 4, which needs 3 signatures for quorum
        let validators = vec![
            scheme_1.public_key(),
            scheme_2.public_key(),
            sample_scheme(2).public_key(),
            sample_scheme(3).public_key(),
        ];

        // Should fail because we only have 2 signatures but need 3 for quorum
        assert!(!notarization.verify::<PublicKey>(NAMESPACE, &validators));
    }

    #[test]
    fn test_notarization_verify_invalid_validator_index() {
        let mut scheme_1 = sample_scheme(0);
        let scheme_2 = sample_scheme(1);
        let proposal = Proposal::new(10, 5, sample_digest(1));

        // Create notarize with invalid public key index (3, which is out of bounds)
        let notarize_1 = Notarize::sign(NAMESPACE, &mut scheme_1, 0, proposal.clone());
        let invalid_sig =
            super::Signature::new(3, scheme_2.sign(Some(NAMESPACE), &proposal.encode()));

        // Create a notarization with an invalid signature (refers to index 3, but there are only 2 validators)
        let signatures = vec![notarize_1.signature.clone(), invalid_sig];
        let notarization = Notarization::new(proposal.clone(), signatures);

        // Create a validator set of 2
        let validators = vec![scheme_1.public_key(), scheme_2.public_key()];

        // Should fail because the second signature refers to an invalid validator index
        assert!(!notarization.verify::<PublicKey>(NAMESPACE, &validators));
    }

    #[test]
    fn test_conflicting_notarize_detection() {
        let mut scheme = sample_scheme(0);

        // Create two different proposals for the same view
        let proposal1 = Proposal::new(10, 5, sample_digest(1));
        let proposal2 = Proposal::new(10, 6, sample_digest(2)); // Different parent

        // Create notarizes for both proposals from the same validator
        let notarize1 = Notarize::sign(NAMESPACE, &mut scheme, 0, proposal1.clone());
        let notarize2 = Notarize::sign(NAMESPACE, &mut scheme, 0, proposal2.clone());

        // Create conflict evidence
        let conflict = ConflictingNotarize::new(notarize1, notarize2);

        // Verify the evidence is valid - both signatures should be valid
        assert!(conflict.verify::<PublicKey>(NAMESPACE, &scheme.public_key()));

        // Now create invalid evidence
        let mut scheme2 = sample_scheme(1);
        let invalid_notarize = Notarize::sign(NAMESPACE, &mut scheme2, 1, proposal1.clone());

        // This will compile but should fail verification since the signatures are from different validators
        let (_, n2) = conflict.notarizes();
        let invalid_conflict = ConflictingNotarize {
            view: n2.view(),
            parent_1: n2.proposal.parent,
            payload_1: n2.proposal.payload,
            signature_1: n2.signature,
            parent_2: invalid_notarize.proposal.parent,
            payload_2: invalid_notarize.proposal.payload,
            signature_2: invalid_notarize.signature,
        };

        // Verify should fail with either key because the signatures are from different validators
        assert!(!invalid_conflict.verify::<PublicKey>(NAMESPACE, &scheme.public_key()));
        assert!(!invalid_conflict.verify::<PublicKey>(NAMESPACE, &scheme2.public_key()));
    }

    #[test]
    fn test_nullify_finalize_detection() {
        let mut scheme = sample_scheme(0);
        let view = 10;

        // Create a nullify for view 10
        let nullify = Nullify::sign(NAMESPACE, &mut scheme, 0, view);

        // Create a finalize for the same view
        let proposal = Proposal::new(view, 5, sample_digest(1));
        let finalize = Finalize::sign(NAMESPACE, &mut scheme, 0, proposal.clone());

        // Create nullify+finalize evidence
        let conflict = NullifyFinalize::new(nullify, finalize);

        // Verify the evidence is valid
        assert!(conflict.verify::<PublicKey>(NAMESPACE, &scheme.public_key()));

        // Now create invalid evidence with different validators
        let mut scheme2 = sample_scheme(1);
        let nullify2 = Nullify::sign(NAMESPACE, &mut scheme2, 1, view);
        let finalize2 = Finalize::sign(NAMESPACE, &mut scheme2, 1, proposal);

        // This will compile but verification with wrong key should fail
        let conflict2 = NullifyFinalize::new(nullify2, finalize2);
        assert!(!conflict2.verify::<PublicKey>(NAMESPACE, &scheme.public_key()));
        // Wrong key
    }

    #[test]
    fn test_nullification_invalid_signatures() {
        let mut scheme_1 = sample_scheme(0);
        let mut scheme_2 = sample_scheme(1);

        // Create nullify for view 10
        let nullify_1 = Nullify::sign(NAMESPACE, &mut scheme_1, 0, 10);
        let nullify_2 = Nullify::sign(NAMESPACE, &mut scheme_2, 1, 10);

        // Create a nullification with valid signatures
        let signatures = vec![nullify_1.signature.clone(), nullify_2.signature.clone()];
        let nullification = Nullification::new(10, signatures);

        // Create a validator set of 2
        let validators = vec![scheme_1.public_key(), scheme_2.public_key()];

        // Valid verification
        assert!(nullification.verify::<PublicKey>(NAMESPACE, &validators));

        // Create a nullification with tampered signature
        let tampered_sig =
            super::Signature::new(2, scheme_1.sign(Some(NAMESPACE), &nullify_1.encode()));

        let invalid_signatures = vec![nullify_1.signature.clone(), tampered_sig];
        let invalid_nullification = Nullification::new(10, invalid_signatures);

        // Verification should fail with tampered signature
        assert!(!invalid_nullification.verify::<PublicKey>(NAMESPACE, &validators));
    }
}
