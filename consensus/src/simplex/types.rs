use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, FixedSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{Digest, Scheme, Verifier};
use commonware_utils::{quorum, union, Array};

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
const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

/// Creates a message to be signed containing just the view number
#[inline]
fn view_message(view: View) -> Vec<u8> {
    View::encode(&view).into()
}

/// Creates a namespace for notarize messages by appending the NOTARIZE_SUFFIX
#[inline]
fn notarize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

/// Creates a namespace for nullify messages by appending the NULLIFY_SUFFIX
#[inline]
fn nullify_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

/// Creates a namespace for finalize messages by appending the FINALIZE_SUFFIX
#[inline]
fn finalize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
}

/// Calculates the quorum threshold for a set of validators
/// Returns (threshold, len) where threshold is the minimum number of validators
/// required for a quorum, and len is the total number of validators
#[inline]
pub fn threshold<P: Array>(validators: &[P]) -> (u32, u32) {
    let len = validators.len() as u32;
    let threshold = quorum(len).expect("not enough validators for a quorum");
    (threshold, len)
}

/// Voter represents all possible message types that can be sent by validators
/// in the consensus protocol.
#[derive(Clone, Debug, PartialEq)]
pub enum Voter<S: Array, D: Digest> {
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

/// Signature represents a validator's cryptographic signature with their identifier.
/// This combines the validator's public key index with their actual signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature<S: Array> {
    /// Index of the validator's public key in the validator set
    pub public_key: u32,
    /// The cryptographic signature produced by the validator
    pub signature: S,
}

impl<S: Array> Signature<S> {
    /// Creates a new signature with the given public key index and signature data.
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

/// Notarize represents a validator's notarize over a proposal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Notarize<S: Array, D: Digest> {
    /// The proposal that is being notarized
    pub proposal: Proposal<D>,
    /// The validator's signature
    pub signature: Signature<S>,
}

impl<S: Array, D: Digest> Notarize<S, D> {
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

    /// Creates a new signed notarize using the provided cryptographic scheme.
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

/// Notarization represents an aggregated set of notarizes that meets the quorum threshold.
/// It includes the proposal and the set of signatures from validators.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Notarization<S: Array, D: Digest> {
    /// The proposal that has been notarized
    pub proposal: Proposal<D>,
    /// The set of signatures from validators (must meet quorum threshold)
    pub signatures: Vec<Signature<S>>,
}

impl<S: Array, D: Digest> Notarization<S, D> {
    /// Creates a new notarization with the given proposal and set of signatures.
    /// The signatures are sorted by the public key index for deterministic ordering.
    pub fn new(proposal: Proposal<D>, mut signatures: Vec<Signature<S>>) -> Self {
        signatures.sort_by_key(|s| s.public_key);
        Self {
            proposal,
            signatures,
        }
    }

    /// Verifies all signatures in this notarization using the provided verifier.
    ///
    /// This ensures that:
    /// 1. There are at least threshold valid signatures
    /// 2. No duplicate signers
    /// 3. All signatures are valid
    /// 4. All signers are in the validator set
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

/// Nullify represents a validator's nullify to skip the current view.
/// This is typically used when the leader is unresponsive or fails to propose a valid block.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nullify<S: Array> {
    /// The view to be nullified (skipped)
    pub view: View,
    /// The validator's signature on the view
    pub signature: Signature<S>,
}

impl<S: Array> Nullify<S> {
    /// Creates a new nullify with the given view and signature.
    pub fn new(view: View, signature: Signature<S>) -> Self {
        Self { view, signature }
    }

    /// Verifies the signature on this nullify using the provided verifier.
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

    /// Creates a new signed nullify using the provided cryptographic scheme.
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

/// Nullification represents an aggregated set of nullifies that meets the quorum threshold.
/// When a view is nullified, the consensus moves to the next view.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Nullification<S: Array> {
    /// The view that has been nullified
    pub view: View,
    /// The set of signatures from validators (must meet quorum threshold)
    pub signatures: Vec<Signature<S>>,
}

impl<S: Array> Nullification<S> {
    /// Creates a new nullification with the given view and set of signatures.
    /// The signatures are sorted by the public key index for deterministic ordering.
    pub fn new(view: View, mut signatures: Vec<Signature<S>>) -> Self {
        signatures.sort_by_key(|s| s.public_key);
        Self { view, signatures }
    }

    /// Verifies all signatures in this nullification using the provided verifier.
    ///
    /// Similar to Notarization::verify, ensures quorum of valid signatures from validators.
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

/// Finalize represents a validator's finalize over a proposal.
/// This happens after a proposal has been notarized, confirming it as the canonical block
/// for this view.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Finalize<S: Array, D: Digest> {
    /// The proposal to be finalized
    pub proposal: Proposal<D>,
    /// The validator's signature on the proposal
    pub signature: Signature<S>,
}

impl<S: Array, D: Digest> Finalize<S, D> {
    /// Creates a new finalize with the given proposal and signature.
    pub fn new(proposal: Proposal<D>, signature: Signature<S>) -> Self {
        Self {
            proposal,
            signature,
        }
    }

    /// Verifies the signature on this finalize using the provided verifier.
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

    /// Creates a new signed finalize using the provided cryptographic scheme.
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

/// Finalization represents an aggregated set of finalizes that meets the quorum threshold.
/// When a proposal is finalized, it becomes the canonical block for its view.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Finalization<S: Array, D: Digest> {
    /// The proposal that has been finalized
    pub proposal: Proposal<D>,
    /// The set of signatures from validators (must meet quorum threshold)
    pub signatures: Vec<Signature<S>>,
}

impl<S: Array, D: Digest> Finalization<S, D> {
    /// Creates a new finalization with the given proposal and set of signatures.
    /// The signatures are sorted by the public key index for deterministic ordering.
    pub fn new(proposal: Proposal<D>, mut signatures: Vec<Signature<S>>) -> Self {
        signatures.sort_by_key(|s| s.public_key);
        Self {
            proposal,
            signatures,
        }
    }

    /// Verifies all signatures in this finalization using the provided verifier.
    ///
    /// Similar to Notarization::verify, ensures quorum of valid signatures from validators.
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

/// Backfiller is a message type for requesting and receiving missing consensus artifacts.
/// This is used to synchronize validators that have fallen behind or just joined the network.
#[derive(Clone, Debug, PartialEq)]
pub enum Backfiller<S: Array, D: Digest> {
    /// Request for missing notarizations and nullifications
    Request(Request),
    /// Response containing requested notarizations and nullifications
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

/// Response is a message containing the requested notarizations and nullifications.
/// This is sent in response to a Request message.
#[derive(Clone, Debug, PartialEq)]
pub struct Response<S: Array, D: Digest> {
    /// Identifier matching the original request
    pub id: u64,
    /// Notarizations for the requested views
    pub notarizations: Vec<Notarization<S, D>>,
    /// Nullifications for the requested views
    pub nullifications: Vec<Nullification<S>>,
}

impl<S: Array, D: Digest> Response<S, D> {
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

/// Activity represents all possible activities that can occur in the consensus protocol.
/// This includes both regular consensus messages and fault evidence.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum Activity<S: Array, D: Digest> {
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

/// ConflictingNotarize represents evidence of a Byzantine validator sending conflicting notarizes.
/// This is used to prove that a validator has equivocated (voted for different proposals in the same view).
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct ConflictingNotarize<S: Array, D: Digest> {
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

impl<S: Array, D: Digest> ConflictingNotarize<S, D> {
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
    pub fn verify<P: Array, V: Verifier<PublicKey = P, Signature = S>>(
        &self,
        namespace: &[u8],
        public_key: &P,
    ) -> bool {
        let (notarize_1, notarize_2) = self.notarizes();
        notarize_1.verify::<P, V>(namespace, public_key)
            && notarize_2.verify::<P, V>(namespace, public_key)
    }
}

impl<S: Array, D: Digest> Write for ConflictingNotarize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.view.write(writer);
        self.parent_1.write(writer);
        self.payload_1.write(writer);
        self.signature_1.write(writer);
        self.parent_2.write(writer);
        self.payload_2.write(writer);
        self.signature_2.write(writer);
    }
}

impl<S: Array, D: Digest> Read for ConflictingNotarize<S, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = View::read(reader)?;
        let parent_1 = View::read(reader)?;
        let payload_1 = D::read_cfg(reader, &())?;
        let signature_1 = Signature::<S>::read(reader)?;
        let parent_2 = View::read(reader)?;
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

impl<S: Array, D: Digest> FixedSize for ConflictingNotarize<S, D> {
    const SIZE: usize = View::SIZE
        + View::SIZE
        + D::SIZE
        + Signature::<S>::SIZE
        + View::SIZE
        + D::SIZE
        + Signature::<S>::SIZE;
}

impl<S: Array, D: Digest> Viewable for ConflictingNotarize<S, D> {
    fn view(&self) -> View {
        self.view
    }
}

impl<S: Array, D: Digest> Attributable for ConflictingNotarize<S, D> {
    fn signer(&self) -> u32 {
        self.signature_1.signer()
    }
}

/// ConflictingFinalize represents evidence of a Byzantine validator sending conflicting finalizes.
/// Similar to ConflictingNotarize, but for finalizes.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct ConflictingFinalize<S: Array, D: Digest> {
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

impl<S: Array, D: Digest> ConflictingFinalize<S, D> {
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
    pub fn verify<P: Array, V: Verifier<PublicKey = P, Signature = S>>(
        &self,
        namespace: &[u8],
        public_key: &P,
    ) -> bool {
        let (finalize_1, finalize_2) = self.finalizes();
        finalize_1.verify::<P, V>(namespace, public_key)
            && finalize_2.verify::<P, V>(namespace, public_key)
    }
}

impl<S: Array, D: Digest> Write for ConflictingFinalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.view.write(writer);
        self.parent_1.write(writer);
        self.payload_1.write(writer);
        self.signature_1.write(writer);
        self.parent_2.write(writer);
        self.payload_2.write(writer);
        self.signature_2.write(writer);
    }
}

impl<S: Array, D: Digest> Read for ConflictingFinalize<S, D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = View::read(reader)?;
        let parent_1 = View::read(reader)?;
        let payload_1 = D::read_cfg(reader, &())?;
        let signature_1 = Signature::<S>::read(reader)?;
        let parent_2 = View::read(reader)?;
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

impl<S: Array, D: Digest> FixedSize for ConflictingFinalize<S, D> {
    const SIZE: usize = View::SIZE
        + View::SIZE
        + D::SIZE
        + Signature::<S>::SIZE
        + View::SIZE
        + D::SIZE
        + Signature::<S>::SIZE;
}

impl<S: Array, D: Digest> Viewable for ConflictingFinalize<S, D> {
    fn view(&self) -> View {
        self.view
    }
}

impl<S: Array, D: Digest> Attributable for ConflictingFinalize<S, D> {
    fn signer(&self) -> u32 {
        self.signature_1.signer()
    }
}

/// NullifyFinalize represents evidence of a Byzantine validator sending both a nullify and finalize
/// for the same view, which is contradictory behavior (a validator should either try to skip a view OR
/// finalize a proposal, not both).
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct NullifyFinalize<S: Array, D: Digest> {
    /// The proposal that the validator tried to finalize
    pub proposal: Proposal<D>,
    /// The signature on the nullify
    pub view_signature: Signature<S>,
    /// The signature on the finalize
    pub finalize_signature: Signature<S>,
}

impl<S: Array, D: Digest> NullifyFinalize<S, D> {
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
    pub fn verify<P: Array, V: Verifier<PublicKey = P, Signature = S>>(
        &self,
        namespace: &[u8],
        public_key: &P,
    ) -> bool {
        let nullify = Nullify::new(self.proposal.view(), self.view_signature.clone());
        let finalize = Finalize::new(self.proposal.clone(), self.finalize_signature.clone());
        nullify.verify::<P, V>(namespace, public_key)
            && finalize.verify::<P, V>(namespace, public_key)
    }
}

impl<S: Array, D: Digest> Write for NullifyFinalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.view_signature.write(writer);
        self.finalize_signature.write(writer);
    }
}

impl<S: Array, D: Digest> Read for NullifyFinalize<S, D> {
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

impl<S: Array, D: Digest> FixedSize for NullifyFinalize<S, D> {
    const SIZE: usize = Proposal::<D>::SIZE + Signature::<S>::SIZE + Signature::<S>::SIZE;
}

impl<S: Array, D: Digest> Viewable for NullifyFinalize<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

impl<S: Array, D: Digest> Attributable for NullifyFinalize<S, D> {
    fn signer(&self) -> u32 {
        self.view_signature.signer()
    }
}
