//! Types used in [`threshold_simplex`](crate::threshold_simplex).

use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, Encode, EncodeSize, Error, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{Public, Share, Signature},
        ops::{
            aggregate_signatures, aggregate_verify_multiple_messages, partial_sign_message,
            partial_verify_message, partial_verify_multiple_messages, verify_message,
        },
        poly::{PartialSignature, Poly},
    },
    Digest,
};
use commonware_utils::union;

/// View is a monotonically increasing counter that represents the current focus of consensus.
/// Each View corresponds to a round in the consensus protocol where validators attempt to agree
/// on a block to commit.
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

/// Seedable is a trait that provides access to the seed associated with a message.
pub trait Seedable {
    /// Returns the seed associated with this object.
    fn seed(&self) -> Seed;
}

// Constants for domain separation in signature verification
// These are used to prevent cross-protocol attacks and message-type confusion
const SEED_SUFFIX: &[u8] = b"_SEED";
const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

/// Creates a message to be signed containing just the view number
#[inline]
fn view_message(view: View) -> Vec<u8> {
    View::encode(&view).into()
}

/// Creates a namespace for seed messages by appending the SEED_SUFFIX
/// The seed is used for leader election and randomness generation
#[inline]
fn seed_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, SEED_SUFFIX)
}

/// Creates a namespace for notarize messages by appending the NOTARIZE_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
fn notarize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

/// Creates a namespace for nullify messages by appending the NULLIFY_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
fn nullify_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

/// Creates a namespace for finalize messages by appending the FINALIZE_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
fn finalize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
}

/// Voter represents all possible message types that can be sent by validators
/// in the consensus protocol.
#[derive(Clone, Debug, PartialEq)]
pub enum Voter<D: Digest> {
    /// A single validator notarize over a proposal
    Notarize(Notarize<D>),
    /// A recovered threshold signature for a notarization
    Notarization(Notarization<D>),
    /// A single validator nullify to skip the current view (usually when leader is unresponsive)
    Nullify(Nullify),
    /// A recovered threshold signature for a nullification
    Nullification(Nullification),
    /// A single validator finalize over a proposal
    Finalize(Finalize<D>),
    /// A recovered threshold signature for a finalization
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

/// Proposal represents a proposed block in the protocol.
/// It includes the view number, the parent view, and the actual payload (typically a digest of block data).
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
        Proposal {
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
        self.payload.write(writer)
    }
}

impl<D: Digest> Read for Proposal<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = UInt::read(reader)?.into();
        let parent = UInt::read(reader)?.into();
        let payload = D::read(reader)?;
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

/// Notarize represents a validator's vote to notarize a proposal.
/// In threshold_simplex, it contains a partial signature on the proposal and a partial signature for the seed.
/// The seed is used for leader election and as a source of randomness.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Notarize<D: Digest> {
    /// The proposal that is being notarized
    pub proposal: Proposal<D>,
    /// The validator's partial signature on the proposal
    pub proposal_signature: PartialSignature,
    /// The validator's partial signature on the seed (for leader election/randomness)
    pub seed_signature: PartialSignature,
}

impl<D: Digest> Notarize<D> {
    /// Creates a new notarize with the given proposal and signatures.
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

    /// Verifies the signatures on this notarize using BLS threshold verification.
    ///
    /// This ensures that:
    /// 1. The notarize signature is valid for the claimed proposal
    /// 2. The seed signature is valid for the view
    /// 3. Both signatures are from the same signer
    pub fn verify(&self, namespace: &[u8], identity: &Poly<Public>) -> bool {
        let notarize_namespace = notarize_namespace(namespace);
        let notarize_message = self.proposal.encode();
        let notarize_message = (Some(notarize_namespace.as_ref()), notarize_message.as_ref());
        let seed_namespace = seed_namespace(namespace);
        let seed_message = view_message(self.proposal.view);
        let seed_message = (Some(seed_namespace.as_ref()), seed_message.as_ref());
        partial_verify_multiple_messages(
            identity,
            self.signer(),
            &[notarize_message, seed_message],
            [&self.proposal_signature, &self.seed_signature],
        )
        .is_ok()
    }

    /// Creates a new signed notarize using BLS threshold signatures.
    pub fn sign(namespace: &[u8], share: &Share, proposal: Proposal<D>) -> Self {
        let notarize_namespace = notarize_namespace(namespace);
        let proposal_message = proposal.encode();
        let proposal_signature =
            partial_sign_message(share, Some(notarize_namespace.as_ref()), &proposal_message);
        let seed_namespace = seed_namespace(namespace);
        let seed_message = view_message(proposal.view);
        let seed_signature =
            partial_sign_message(share, Some(seed_namespace.as_ref()), &seed_message);
        Notarize::new(proposal, proposal_signature, seed_signature)
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
            return Err(Error::Invalid(
                "consensus::threshold_simplex::Notarize",
                "mismatched signatures",
            ));
        }
        Ok(Notarize {
            proposal,
            proposal_signature,
            seed_signature,
        })
    }
}

impl<D: Digest> EncodeSize for Notarize<D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size()
            + self.proposal_signature.encode_size()
            + self.seed_signature.encode_size()
    }
}

/// Notarization represents a recovered threshold signature certifying a proposal.
/// When a proposal is notarized, it means at least 2f+1 validators have voted for it.
/// The threshold signatures provide compact verification compared to collecting individual signatures.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Notarization<D: Digest> {
    /// The proposal that has been notarized
    pub proposal: Proposal<D>,
    /// The recovered threshold signature on the proposal
    pub proposal_signature: Signature,
    /// The recovered threshold signature on the seed (for leader election/randomness)
    pub seed_signature: Signature,
}

impl<D: Digest> Notarization<D> {
    /// Creates a new notarization with the given proposal and aggregated signatures.
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

    /// Verifies the threshold signatures on this notarization.
    ///
    /// This ensures that:
    /// 1. The notarization signature is a valid threshold signature for the proposal
    /// 2. The seed signature is a valid threshold signature for the view
    pub fn verify(&self, namespace: &[u8], public_key: &Public) -> bool {
        let notarize_namespace = notarize_namespace(namespace);
        let notarize_message = self.proposal.encode();
        let notarize_message = (Some(notarize_namespace.as_ref()), notarize_message.as_ref());
        let seed_namespace = seed_namespace(namespace);
        let seed_message = view_message(self.proposal.view);
        let seed_message = (Some(seed_namespace.as_ref()), seed_message.as_ref());
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

impl<D: Digest> EncodeSize for Notarization<D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size()
            + self.proposal_signature.encode_size()
            + self.seed_signature.encode_size()
    }
}

impl<D: Digest> Seedable for Notarization<D> {
    fn seed(&self) -> Seed {
        Seed::new(self.view(), self.seed_signature)
    }
}

/// Nullify represents a validator's vote to skip the current view.
/// This is typically used when the leader is unresponsive or fails to propose a valid block.
/// It contains partial signatures for the view and seed.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Nullify {
    /// The view to be nullified (skipped)
    pub view: View,
    /// The validator's partial signature on the view
    pub view_signature: PartialSignature,
    /// The validator's partial signature on the seed (for leader election/randomness)
    pub seed_signature: PartialSignature,
}

impl Nullify {
    /// Creates a new nullify with the given view and signatures.
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

    /// Verifies the signatures on this nullify using BLS threshold verification.
    ///
    /// This ensures that:
    /// 1. The view signature is valid for the given view
    /// 2. The seed signature is valid for the view
    /// 3. Both signatures are from the same signer
    pub fn verify(&self, namespace: &[u8], identity: &Poly<Public>) -> bool {
        let nullify_namespace = nullify_namespace(namespace);
        let view_message = view_message(self.view);
        let nullify_message = (Some(nullify_namespace.as_ref()), view_message.as_ref());
        let seed_namespace = seed_namespace(namespace);
        let seed_message = (Some(seed_namespace.as_ref()), view_message.as_ref());
        partial_verify_multiple_messages(
            identity,
            self.signer(),
            &[nullify_message, seed_message],
            [&self.view_signature, &self.seed_signature],
        )
        .is_ok()
    }

    /// Creates a new signed nullify using BLS threshold signatures.
    pub fn sign(namespace: &[u8], share: &Share, view: View) -> Self {
        let nullify_namespace = nullify_namespace(namespace);
        let view_message = view_message(view);
        let view_signature =
            partial_sign_message(share, Some(nullify_namespace.as_ref()), &view_message);
        let seed_namespace = seed_namespace(namespace);
        let seed_signature =
            partial_sign_message(share, Some(seed_namespace.as_ref()), &view_message);
        Nullify::new(view, view_signature, seed_signature)
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
        UInt(self.view).write(writer);
        self.view_signature.write(writer);
        self.seed_signature.write(writer);
    }
}

impl Read for Nullify {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = UInt::read(reader)?.into();
        let view_signature = PartialSignature::read(reader)?;
        let seed_signature = PartialSignature::read(reader)?;
        if view_signature.index != seed_signature.index {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::Nullify",
                "mismatched signatures",
            ));
        }
        Ok(Nullify {
            view,
            view_signature,
            seed_signature,
        })
    }
}

impl EncodeSize for Nullify {
    fn encode_size(&self) -> usize {
        UInt(self.view).encode_size()
            + self.view_signature.encode_size()
            + self.seed_signature.encode_size()
    }
}

/// Nullification represents a recovered threshold signature to skip a view.
/// When a view is nullified, the consensus moves to the next view without finalizing a block.
/// The threshold signatures provide compact verification compared to collecting individual signatures.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Nullification {
    /// The view that has been nullified
    pub view: View,
    /// The recovered threshold signature on the view
    pub view_signature: Signature,
    /// The recovered threshold signature on the seed (for leader election/randomness)
    pub seed_signature: Signature,
}

impl Nullification {
    /// Creates a new nullification with the given view and aggregated signatures.
    pub fn new(view: View, view_signature: Signature, seed_signature: Signature) -> Self {
        Nullification {
            view,
            view_signature,
            seed_signature,
        }
    }

    /// Verifies the threshold signatures on this nullification.
    ///
    /// This ensures that:
    /// 1. The view signature is a valid threshold signature for the view
    /// 2. The seed signature is a valid threshold signature for the view
    pub fn verify(&self, namespace: &[u8], public_key: &Public) -> bool {
        let nullify_namespace = nullify_namespace(namespace);
        let view_message = view_message(self.view);
        let nullify_message = (Some(nullify_namespace.as_ref()), view_message.as_ref());
        let seed_namespace = seed_namespace(namespace);
        let seed_message = (Some(seed_namespace.as_ref()), view_message.as_ref());
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
        UInt(self.view).write(writer);
        self.view_signature.write(writer);
        self.seed_signature.write(writer);
    }
}

impl Read for Nullification {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = UInt::read(reader)?.into();
        let view_signature = Signature::read(reader)?;
        let seed_signature = Signature::read(reader)?;
        Ok(Nullification {
            view,
            view_signature,
            seed_signature,
        })
    }
}

impl EncodeSize for Nullification {
    fn encode_size(&self) -> usize {
        UInt(self.view).encode_size()
            + self.view_signature.encode_size()
            + self.seed_signature.encode_size()
    }
}

impl Seedable for Nullification {
    fn seed(&self) -> Seed {
        Seed::new(self.view(), self.seed_signature)
    }
}

/// Finalize represents a validator's vote to finalize a proposal.
/// This happens after a proposal has been notarized, confirming it as the canonical block for this view.
/// It contains a partial signature on the proposal.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Finalize<D: Digest> {
    /// The proposal to be finalized
    pub proposal: Proposal<D>,
    /// The validator's partial signature on the proposal
    pub proposal_signature: PartialSignature,
}

impl<D: Digest> Finalize<D> {
    /// Creates a new finalize with the given proposal and signature.
    pub fn new(proposal: Proposal<D>, proposal_signature: PartialSignature) -> Self {
        Finalize {
            proposal,
            proposal_signature,
        }
    }

    /// Verifies the signature on this finalize using BLS threshold verification.
    ///
    /// This ensures that the signature is valid for the given proposal.
    pub fn verify(&self, namespace: &[u8], identity: &Poly<Public>) -> bool {
        let finalize_namespace = finalize_namespace(namespace);
        let message = self.proposal.encode();
        partial_verify_message(
            identity,
            Some(finalize_namespace.as_ref()),
            &message,
            &self.proposal_signature,
        )
        .is_ok()
    }

    /// Creates a new signed finalize using BLS threshold signatures.
    pub fn sign(namespace: &[u8], share: &Share, proposal: Proposal<D>) -> Self {
        let finalize_namespace = finalize_namespace(namespace);
        let message = proposal.encode();
        let proposal_signature =
            partial_sign_message(share, Some(finalize_namespace.as_ref()), &message);
        Finalize::new(proposal, proposal_signature)
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

impl<D: Digest> EncodeSize for Finalize<D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.proposal_signature.encode_size()
    }
}

/// Finalization represents a recovered threshold signature to finalize a proposal.
/// When a proposal is finalized, it becomes the canonical block for its view.
/// The threshold signatures provide compact verification compared to collecting individual signatures.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Finalization<D: Digest> {
    /// The proposal that has been finalized
    pub proposal: Proposal<D>,
    /// The recovered threshold signature on the proposal
    pub proposal_signature: Signature,
    /// The recovered threshold signature on the seed (for leader election/randomness)
    pub seed_signature: Signature,
}

impl<D: Digest> Finalization<D> {
    /// Creates a new finalization with the given proposal and aggregated signatures.
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

    /// Verifies the threshold signatures on this finalization.
    ///
    /// This ensures that:
    /// 1. The proposal signature is a valid threshold signature for the proposal
    /// 2. The seed signature is a valid threshold signature for the view
    pub fn verify(&self, namespace: &[u8], public_key: &Public) -> bool {
        let finalize_namespace = finalize_namespace(namespace);
        let finalize_message = self.proposal.encode();
        let finalize_message = (Some(finalize_namespace.as_ref()), finalize_message.as_ref());
        let seed_namespace = seed_namespace(namespace);
        let seed_message = view_message(self.proposal.view);
        let seed_message = (Some(seed_namespace.as_ref()), seed_message.as_ref());
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

impl<D: Digest> EncodeSize for Finalization<D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size()
            + self.proposal_signature.encode_size()
            + self.seed_signature.encode_size()
    }
}

impl<D: Digest> Seedable for Finalization<D> {
    fn seed(&self) -> Seed {
        Seed::new(self.view(), self.seed_signature)
    }
}

/// Backfiller is a message type for requesting and receiving missing consensus artifacts.
/// This is used to synchronize validators that have fallen behind or just joined the network.
#[derive(Clone, Debug, PartialEq)]
pub enum Backfiller<D: Digest> {
    /// Request for missing notarizations and nullifications
    Request(Request),
    /// Response containing requested notarizations and nullifications
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
        Request {
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

impl EncodeSize for Request {
    fn encode_size(&self) -> usize {
        UInt(self.id).encode_size()
            + self.notarizations.encode_size()
            + self.nullifications.encode_size()
    }
}

impl Read<usize> for Request {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let id = UInt::read(reader)?.into();
        let notarizations = Vec::<View>::read_range(reader, ..=*max_len)?;
        let remaining = max_len - notarizations.len();
        let nullifications = Vec::<View>::read_range(reader, ..=remaining)?;
        Ok(Request {
            id,
            notarizations,
            nullifications,
        })
    }
}

/// Response is a message containing the requested notarizations and nullifications.
/// This is sent in response to a Request message.
#[derive(Clone, Debug, PartialEq)]
pub struct Response<D: Digest> {
    /// Identifier matching the original request
    pub id: u64,
    /// Notarizations for the requested views
    pub notarizations: Vec<Notarization<D>>,
    /// Nullifications for the requested views
    pub nullifications: Vec<Nullification>,
}

impl<D: Digest> Response<D> {
    /// Creates a new response with the given id, notarizations, and nullifications.
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
}

impl<D: Digest> Write for Response<D> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.id).write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl<D: Digest> EncodeSize for Response<D> {
    fn encode_size(&self) -> usize {
        UInt(self.id).encode_size()
            + self.notarizations.encode_size()
            + self.nullifications.encode_size()
    }
}

impl<D: Digest> Read<usize> for Response<D> {
    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let id = UInt::read(reader)?.into();
        let notarizations = Vec::<Notarization<D>>::read_range(reader, ..=*max_len)?;
        let remaining = max_len - notarizations.len();
        let nullifications = Vec::<Nullification>::read_range(reader, ..=remaining)?;
        Ok(Response {
            id,
            notarizations,
            nullifications,
        })
    }
}

/// Activity represents all possible activities that can occur in the consensus protocol.
/// This includes both regular consensus messages and fault evidence.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum Activity<D: Digest> {
    /// A single validator notarize over a proposal
    Notarize(Notarize<D>),
    /// A threshold signature for a notarization
    Notarization(Notarization<D>),
    /// A single validator nullify to skip the current view
    Nullify(Nullify),
    /// A threshold signature for a nullification
    Nullification(Nullification),
    /// A single validator finalize over a proposal
    Finalize(Finalize<D>),
    /// A threshold signature for a finalization
    Finalization(Finalization<D>),
    /// Evidence of a validator sending conflicting notarizes (Byzantine behavior)
    ConflictingNotarize(ConflictingNotarize<D>),
    /// Evidence of a validator sending conflicting finalizes (Byzantine behavior)
    ConflictingFinalize(ConflictingFinalize<D>),
    /// Evidence of a validator sending both nullify and finalize for the same view (Byzantine behavior)
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

/// Seed represents a threshold signature over the current view.
#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct Seed {
    /// The view for which this seed is generated
    pub view: View,
    /// The partial signature on the seed
    pub signature: Signature,
}

impl Seed {
    /// Creates a new seed with the given view and signature.
    pub fn new(view: View, signature: Signature) -> Self {
        Seed { view, signature }
    }

    /// Verifies the threshold signature on this seed.
    pub fn verify(&self, namespace: &[u8], public_key: &Public) -> bool {
        let seed_namespace = seed_namespace(namespace);
        let message = view_message(self.view);
        verify_message(public_key, Some(&seed_namespace), &message, &self.signature).is_ok()
    }
}

impl Viewable for Seed {
    fn view(&self) -> View {
        self.view
    }
}

impl Write for Seed {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.view).write(writer);
        self.signature.write(writer);
    }
}

impl Read for Seed {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = UInt::read(reader)?.into();
        let signature = Signature::read(reader)?;
        Ok(Seed { view, signature })
    }
}

impl EncodeSize for Seed {
    fn encode_size(&self) -> usize {
        UInt(self.view).encode_size() + self.signature.encode_size()
    }
}

/// ConflictingNotarize represents evidence of a Byzantine validator sending conflicting notarizes.
/// This is used to prove that a validator has equivocated (voted for different proposals in the same view).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConflictingNotarize<D: Digest> {
    /// The view in which the conflict occurred
    pub view: View,
    /// The parent view of the first conflicting proposal
    pub parent_1: View,
    /// The payload of the first conflicting proposal
    pub payload_1: D,
    /// The signature on the first conflicting proposal
    pub signature_1: PartialSignature,
    /// The parent view of the second conflicting proposal
    pub parent_2: View,
    /// The payload of the second conflicting proposal
    pub payload_2: D,
    /// The signature on the second conflicting proposal
    pub signature_2: PartialSignature,
}

impl<D: Digest> ConflictingNotarize<D> {
    /// Creates a new conflicting notarize evidence from two conflicting notarizes.
    pub fn new(notarize_1: Notarize<D>, notarize_2: Notarize<D>) -> Self {
        assert_eq!(notarize_1.view(), notarize_2.view());
        assert_eq!(notarize_1.signer(), notarize_2.signer());
        ConflictingNotarize {
            view: notarize_1.view(),
            parent_1: notarize_1.proposal.parent,
            payload_1: notarize_1.proposal.payload,
            signature_1: notarize_1.proposal_signature,
            parent_2: notarize_2.proposal.parent,
            payload_2: notarize_2.proposal.payload,
            signature_2: notarize_2.proposal_signature,
        }
    }

    /// Reconstructs the original proposals from this evidence.
    pub fn proposals(&self) -> (Proposal<D>, Proposal<D>) {
        (
            Proposal::new(self.view, self.parent_1, self.payload_1),
            Proposal::new(self.view, self.parent_2, self.payload_2),
        )
    }

    /// Verifies that both conflicting signatures are valid, proving Byzantine behavior.
    pub fn verify(&self, namespace: &[u8], identity: &Poly<Public>) -> bool {
        let (proposal_1, proposal_2) = self.proposals();
        let notarize_namespace = notarize_namespace(namespace);
        let notarize_message_1 = proposal_1.encode();
        let notarize_message_1 = (
            Some(notarize_namespace.as_ref()),
            notarize_message_1.as_ref(),
        );
        let notarize_message_2 = proposal_2.encode();
        let notarize_message_2 = (
            Some(notarize_namespace.as_ref()),
            notarize_message_2.as_ref(),
        );
        partial_verify_multiple_messages(
            identity,
            self.signer(),
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
        self.view
    }
}

impl<D: Digest> Write for ConflictingNotarize<D> {
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

impl<D: Digest> Read for ConflictingNotarize<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = UInt::read(reader)?.into();
        let parent_1 = UInt::read(reader)?.into();
        let payload_1 = D::read(reader)?;
        let signature_1 = PartialSignature::read(reader)?;
        let parent_2 = UInt::read(reader)?.into();
        let payload_2 = D::read(reader)?;
        let signature_2 = PartialSignature::read(reader)?;
        if signature_1.index != signature_2.index {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::ConflictingNotarize",
                "mismatched signatures",
            ));
        }
        Ok(ConflictingNotarize {
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

impl<D: Digest> EncodeSize for ConflictingNotarize<D> {
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

/// ConflictingFinalize represents evidence of a Byzantine validator sending conflicting finalizes.
/// Similar to ConflictingNotarize, but for finalizes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConflictingFinalize<D: Digest> {
    /// The view in which the conflict occurred
    pub view: View,
    /// The parent view of the first conflicting proposal
    pub parent_1: View,
    /// The payload of the first conflicting proposal
    pub payload_1: D,
    /// The signature on the first conflicting proposal
    pub signature_1: PartialSignature,
    /// The parent view of the second conflicting proposal
    pub parent_2: View,
    /// The payload of the second conflicting proposal
    pub payload_2: D,
    /// The signature on the second conflicting proposal
    pub signature_2: PartialSignature,
}

impl<D: Digest> ConflictingFinalize<D> {
    /// Creates a new conflicting finalize evidence from two conflicting finalizes.
    pub fn new(finalize_1: Finalize<D>, finalize_2: Finalize<D>) -> Self {
        assert_eq!(finalize_1.view(), finalize_2.view());
        assert_eq!(finalize_1.signer(), finalize_2.signer());
        ConflictingFinalize {
            view: finalize_1.view(),
            parent_1: finalize_1.proposal.parent,
            payload_1: finalize_1.proposal.payload,
            signature_1: finalize_1.proposal_signature,
            parent_2: finalize_2.proposal.parent,
            payload_2: finalize_2.proposal.payload,
            signature_2: finalize_2.proposal_signature,
        }
    }

    /// Reconstructs the original proposals from this evidence.
    pub fn proposals(&self) -> (Proposal<D>, Proposal<D>) {
        (
            Proposal::new(self.view, self.parent_1, self.payload_1),
            Proposal::new(self.view, self.parent_2, self.payload_2),
        )
    }

    /// Verifies that both conflicting signatures are valid, proving Byzantine behavior.
    pub fn verify(&self, namespace: &[u8], identity: &Poly<Public>) -> bool {
        let (proposal_1, proposal_2) = self.proposals();
        let finalize_namespace = finalize_namespace(namespace);
        let finalize_message_1 = proposal_1.encode();
        let finalize_message_1 = (
            Some(finalize_namespace.as_ref()),
            finalize_message_1.as_ref(),
        );
        let finalize_message_2 = proposal_2.encode();
        let finalize_message_2 = (
            Some(finalize_namespace.as_ref()),
            finalize_message_2.as_ref(),
        );
        partial_verify_multiple_messages(
            identity,
            self.signer(),
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
        self.view
    }
}

impl<D: Digest> Write for ConflictingFinalize<D> {
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

impl<D: Digest> Read for ConflictingFinalize<D> {
    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let view = UInt::read(reader)?.into();
        let parent_1 = UInt::read(reader)?.into();
        let payload_1 = D::read(reader)?;
        let signature_1 = PartialSignature::read(reader)?;
        let parent_2 = UInt::read(reader)?.into();
        let payload_2 = D::read(reader)?;
        let signature_2 = PartialSignature::read(reader)?;
        if signature_1.index != signature_2.index {
            return Err(Error::Invalid(
                "consensus::threshold_simplex::ConflictingFinalize",
                "mismatched signatures",
            ));
        }
        Ok(ConflictingFinalize {
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

impl<D: Digest> EncodeSize for ConflictingFinalize<D> {
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

/// NullifyFinalize represents evidence of a Byzantine validator sending both a nullify and finalize
/// for the same view, which is contradictory behavior (a validator should either try to skip a view OR
/// finalize a proposal, not both).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NullifyFinalize<D: Digest> {
    /// The proposal that the validator tried to finalize
    pub proposal: Proposal<D>,
    /// The signature on the nullify
    pub view_signature: PartialSignature,
    /// The signature on the finalize
    pub finalize_signature: PartialSignature,
}

impl<D: Digest> NullifyFinalize<D> {
    /// Creates a new nullify-finalize evidence from a nullify and a finalize.
    pub fn new(nullify: Nullify, finalize: Finalize<D>) -> Self {
        assert_eq!(nullify.view(), finalize.view());
        assert_eq!(nullify.signer(), finalize.signer());
        NullifyFinalize {
            proposal: finalize.proposal,
            view_signature: nullify.view_signature,
            finalize_signature: finalize.proposal_signature,
        }
    }

    /// Verifies that both the nullify and finalize signatures are valid, proving Byzantine behavior.
    pub fn verify(&self, namespace: &[u8], identity: &Poly<Public>) -> bool {
        let nullify_namespace = nullify_namespace(namespace);
        let nullify_message = view_message(self.proposal.view);
        let nullify_message = (Some(nullify_namespace.as_ref()), nullify_message.as_ref());
        let finalize_namespace = finalize_namespace(namespace);
        let finalize_message = self.proposal.encode();
        let finalize_message = (Some(finalize_namespace.as_ref()), finalize_message.as_ref());
        partial_verify_multiple_messages(
            identity,
            self.signer(),
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
            return Err(Error::Invalid(
                "consensus::threshold_simplex::NullifyFinalize",
                "mismatched signatures",
            ));
        }
        Ok(NullifyFinalize {
            proposal,
            view_signature,
            finalize_signature,
        })
    }
}

impl<D: Digest> EncodeSize for NullifyFinalize<D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size()
            + self.view_signature.encode_size()
            + self.finalize_signature.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::{
            dkg::ops,
            primitives::{group::Share, ops::threshold_signature_recover, poly},
        },
        sha256::Digest as Sha256,
    };
    use commonware_utils::quorum;
    use rand::{rngs::StdRng, SeedableRng};

    const NAMESPACE: &[u8] = b"test";

    // Helper function to create a sample digest
    fn sample_digest(v: u8) -> Sha256 {
        Sha256::from([v; 32]) // Simple fixed digest for testing
    }

    // Helper function to generate BLS shares and polynomial
    fn generate_test_data(n: usize, t: u32, seed: u64) -> (poly::Public, Vec<Share>) {
        let mut rng = StdRng::seed_from_u64(seed);
        ops::generate_shares(&mut rng, None, n as u32, t)
    }

    #[test]
    fn test_proposal_encode_decode() {
        let proposal = Proposal::new(10, 5, sample_digest(1));
        let encoded = proposal.encode();
        let decoded = Proposal::<Sha256>::decode(encoded).unwrap();
        assert_eq!(proposal, decoded);
    }

    #[test]
    fn test_notarize_encode_decode() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        let proposal = Proposal::new(10, 5, sample_digest(1));
        let notarize = Notarize::sign(NAMESPACE, &shares[0], proposal);

        let encoded = notarize.encode();
        let decoded = Notarize::<Sha256>::decode(encoded).unwrap();

        assert_eq!(notarize, decoded);
        assert!(decoded.verify(NAMESPACE, &commitment));
    }

    #[test]
    fn test_notarization_encode_decode() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        let proposal = Proposal::new(10, 5, sample_digest(1));

        // Create notarizes
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        // Recover threshold signature
        let proposal_partials = notarizes.iter().map(|n| &n.proposal_signature);
        let proposal_signature = threshold_signature_recover(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover(t, seed_partials).unwrap();

        // Create notarization
        let notarization = Notarization::new(proposal, proposal_signature, seed_signature);
        let encoded = notarization.encode();
        let decoded = Notarization::<Sha256>::decode(encoded).unwrap();
        assert_eq!(notarization, decoded);

        // Verify the notarization
        let public_key = poly::public(&commitment);
        assert!(decoded.verify(NAMESPACE, public_key));

        // Create seed
        let seed = notarization.seed();
        let encoded = seed.encode();
        let decoded = Seed::decode(encoded).unwrap();
        assert_eq!(seed, decoded);

        // Verify the seed
        assert!(decoded.verify(NAMESPACE, public_key));
    }

    #[test]
    fn test_nullify_encode_decode() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        let nullify = Nullify::sign(NAMESPACE, &shares[0], 10);

        let encoded = nullify.encode();
        let decoded = Nullify::decode(encoded).unwrap();

        assert_eq!(nullify, decoded);
        assert!(decoded.verify(NAMESPACE, &commitment));
    }

    #[test]
    fn test_nullification_encode_decode() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        // Create nullifies
        let nullifies: Vec<_> = shares
            .iter()
            .map(|s| Nullify::sign(NAMESPACE, s, 10))
            .collect();

        // Recover threshold signature
        let view_partials = nullifies.iter().map(|n| &n.view_signature);
        let view_signature = threshold_signature_recover(t, view_partials).unwrap();
        let seed_partials = nullifies.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover(t, seed_partials).unwrap();

        // Create nullification
        let nullification = Nullification::new(10, view_signature, seed_signature);
        let encoded = nullification.encode();
        let decoded = Nullification::decode(encoded).unwrap();
        assert_eq!(nullification, decoded);

        // Verify the nullification
        let public_key = poly::public(&commitment);
        assert!(decoded.verify(NAMESPACE, public_key));

        // Create seed
        let seed = nullification.seed();
        let encoded = seed.encode();
        let decoded = Seed::decode(encoded).unwrap();
        assert_eq!(seed, decoded);

        // Verify the seed
        assert!(decoded.verify(NAMESPACE, public_key));
    }

    #[test]
    fn test_finalize_encode_decode() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        let proposal = Proposal::new(10, 5, sample_digest(1));
        let finalize = Finalize::sign(NAMESPACE, &shares[0], proposal);

        let encoded = finalize.encode();
        let decoded = Finalize::<Sha256>::decode(encoded).unwrap();

        assert_eq!(finalize, decoded);
        assert!(decoded.verify(NAMESPACE, &commitment));
    }

    #[test]
    fn test_finalization_encode_decode() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        let proposal = Proposal::new(10, 5, sample_digest(1));

        // Create finalizes
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::sign(NAMESPACE, s, proposal.clone()))
            .collect();
        let finalizes: Vec<_> = shares
            .iter()
            .map(|s| Finalize::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        // Recover threshold signatures
        let proposal_partials = finalizes.iter().map(|f| &f.proposal_signature);
        let proposal_signature = threshold_signature_recover(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover(t, seed_partials).unwrap();

        // Create finalization
        let finalization = Finalization::new(proposal, proposal_signature, seed_signature);
        let encoded = finalization.encode();
        let decoded = Finalization::<Sha256>::decode(encoded).unwrap();
        assert_eq!(finalization, decoded);

        // Verify the finalization
        let public_key = poly::public(&commitment);
        assert!(decoded.verify(NAMESPACE, public_key));

        // Create seed
        let seed = finalization.seed();
        let encoded = seed.encode();
        let decoded = Seed::decode(encoded).unwrap();
        assert_eq!(seed, decoded);

        // Verify the seed
        assert!(decoded.verify(NAMESPACE, public_key));
    }

    #[test]
    fn test_backfiller_encode_decode() {
        // Test Request
        let request = Request::new(1, vec![10, 11], vec![12, 13]);
        let backfiller = Backfiller::Request::<Sha256>(request.clone());
        let encoded = backfiller.encode();
        let decoded = Backfiller::<Sha256>::decode_cfg(encoded, &usize::MAX).unwrap();
        assert!(matches!(decoded, Backfiller::Request(r) if r == request));

        // Test Response
        let n = 5;
        let t = quorum(n as u32);
        let (_, shares) = generate_test_data(n, t, 0);

        // Create a notarization
        let proposal = Proposal::new(10, 5, sample_digest(1));
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        let proposal_partials = notarizes.iter().map(|n| &n.proposal_signature);
        let proposal_signature = threshold_signature_recover(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover(t, seed_partials).unwrap();

        let notarization = Notarization::new(proposal, proposal_signature, seed_signature);

        // Create a nullification
        let nullifies: Vec<_> = shares
            .iter()
            .map(|s| Nullify::sign(NAMESPACE, s, 11))
            .collect();

        let view_partials = nullifies.iter().map(|n| &n.view_signature);
        let view_signature = threshold_signature_recover(t, view_partials).unwrap();
        let seed_partials = nullifies.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover(t, seed_partials).unwrap();

        let nullification = Nullification::new(11, view_signature, seed_signature);

        // Create a response
        let response = Response::new(1, vec![notarization], vec![nullification]);
        let backfiller = Backfiller::Response::<Sha256>(response.clone());
        let encoded = backfiller.encode();
        let decoded = Backfiller::<Sha256>::decode_cfg(encoded, &usize::MAX).unwrap();
        assert!(matches!(decoded, Backfiller::Response(r) if r.id == response.id));
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
        let n = 5;
        let t = quorum(n as u32);
        let (_, shares) = generate_test_data(n, t, 0);

        // Create a notarization
        let proposal = Proposal::new(10, 5, sample_digest(1));
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        let proposal_partials = notarizes.iter().map(|n| &n.proposal_signature);
        let proposal_signature = threshold_signature_recover(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover(t, seed_partials).unwrap();

        let notarization = Notarization::new(proposal, proposal_signature, seed_signature);

        // Create a nullification
        let nullifies: Vec<_> = shares
            .iter()
            .map(|s| Nullify::sign(NAMESPACE, s, 11))
            .collect();

        let view_partials = nullifies.iter().map(|n| &n.view_signature);
        let view_signature = threshold_signature_recover(t, view_partials).unwrap();
        let seed_partials = nullifies.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover(t, seed_partials).unwrap();

        let nullification = Nullification::new(11, view_signature, seed_signature);

        // Create a response
        let response = Response::new(1, vec![notarization], vec![nullification]);
        let encoded = response.encode();
        let decoded = Response::<Sha256>::decode_cfg(encoded, &usize::MAX).unwrap();
        assert_eq!(response.id, decoded.id);
        assert_eq!(response.notarizations.len(), decoded.notarizations.len());
        assert_eq!(response.nullifications.len(), decoded.nullifications.len());
    }

    #[test]
    fn test_conflicting_notarize_encode_decode() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        let proposal1 = Proposal::new(10, 5, sample_digest(1));
        let proposal2 = Proposal::new(10, 5, sample_digest(2));
        let notarize1 = Notarize::sign(NAMESPACE, &shares[0], proposal1);
        let notarize2 = Notarize::sign(NAMESPACE, &shares[0], proposal2);
        let conflicting_notarize = ConflictingNotarize::new(notarize1, notarize2);

        let encoded = conflicting_notarize.encode();
        let decoded = ConflictingNotarize::<Sha256>::decode(encoded).unwrap();

        assert_eq!(conflicting_notarize, decoded);
        assert!(decoded.verify(NAMESPACE, &commitment));
    }

    #[test]
    fn test_conflicting_finalize_encode_decode() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        let proposal1 = Proposal::new(10, 5, sample_digest(1));
        let proposal2 = Proposal::new(10, 5, sample_digest(2));
        let finalize1 = Finalize::sign(NAMESPACE, &shares[0], proposal1);
        let finalize2 = Finalize::sign(NAMESPACE, &shares[0], proposal2);
        let conflicting_finalize = ConflictingFinalize::new(finalize1, finalize2);

        let encoded = conflicting_finalize.encode();
        let decoded = ConflictingFinalize::<Sha256>::decode(encoded).unwrap();

        assert_eq!(conflicting_finalize, decoded);
        assert!(decoded.verify(NAMESPACE, &commitment));
    }

    #[test]
    fn test_nullify_finalize_encode_decode() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        let proposal = Proposal::new(10, 5, sample_digest(1));
        let nullify = Nullify::sign(NAMESPACE, &shares[0], 10);
        let finalize = Finalize::sign(NAMESPACE, &shares[0], proposal);
        let nullify_finalize = NullifyFinalize::new(nullify, finalize);

        let encoded = nullify_finalize.encode();
        let decoded = NullifyFinalize::<Sha256>::decode(encoded).unwrap();

        assert_eq!(nullify_finalize, decoded);
        assert!(decoded.verify(NAMESPACE, &commitment));
    }

    #[test]
    fn test_notarize_verify_wrong_namespace() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        let proposal = Proposal::new(10, 5, sample_digest(1));
        let notarize = Notarize::sign(NAMESPACE, &shares[0], proposal);

        // Verify with correct namespace and identity - should pass
        assert!(notarize.verify(NAMESPACE, &commitment));

        // Verify with wrong namespace - should fail
        assert!(!notarize.verify(b"wrong_namespace", &commitment));
    }

    #[test]
    fn test_notarize_verify_wrong_identity() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment1, shares1) = generate_test_data(n, t, 0);

        // Generate a different set of BLS keys/shares
        let (commitment2, _) = generate_test_data(n, t, 1);

        let proposal = Proposal::new(10, 5, sample_digest(1));
        let notarize = Notarize::sign(NAMESPACE, &shares1[0], proposal);

        // Verify with correct identity - should pass
        assert!(notarize.verify(NAMESPACE, &commitment1));

        // Verify with wrong identity - should fail
        assert!(!notarize.verify(NAMESPACE, &commitment2));
    }

    #[test]
    fn test_notarization_verify_wrong_keys() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        let proposal = Proposal::new(10, 5, sample_digest(1));

        // Create notarizes
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        // Recover threshold signature
        let proposal_partials = notarizes.iter().map(|n| &n.proposal_signature);
        let proposal_signature = threshold_signature_recover(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover(t, seed_partials).unwrap();

        // Create notarization
        let notarization = Notarization::new(proposal, proposal_signature, seed_signature);

        // Verify with correct public key - should pass
        let public_key = poly::public(&commitment);
        assert!(notarization.verify(NAMESPACE, public_key));

        // Generate a different set of BLS keys/shares
        let (wrong_commitment, _) = generate_test_data(n, t, 1);
        let wrong_public_key = poly::public(&wrong_commitment);

        // Verify with wrong public key - should fail
        assert!(!notarization.verify(NAMESPACE, wrong_public_key));
    }

    #[test]
    fn test_notarization_verify_wrong_namespace() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        let proposal = Proposal::new(10, 5, sample_digest(1));

        // Create notarizes
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        // Recover threshold signature
        let proposal_partials = notarizes.iter().map(|n| &n.proposal_signature);
        let proposal_signature = threshold_signature_recover(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover(t, seed_partials).unwrap();

        // Create notarization
        let notarization = Notarization::new(proposal, proposal_signature, seed_signature);

        // Verify with correct namespace - should pass
        let public_key = poly::public(&commitment);
        assert!(notarization.verify(NAMESPACE, public_key));

        // Verify with wrong namespace - should fail
        assert!(!notarization.verify(b"wrong_namespace", public_key));
    }

    #[test]
    fn test_threshold_recover_insufficient_signatures() {
        let n = 5;
        let t = quorum(n as u32); // For n=5, t should be 4 (2f+1 where f=1)
        let (_, shares) = generate_test_data(n, t, 0);

        let proposal = Proposal::new(10, 5, sample_digest(1));

        // Create notarizes, but only collect t-1 of them
        let notarizes: Vec<_> = shares
            .iter()
            .take((t as usize) - 1) // One less than the threshold
            .map(|s| Notarize::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        // Try to recover threshold signature with insufficient partials - should fail
        let proposal_partials = notarizes.iter().map(|n| &n.proposal_signature);
        let result = threshold_signature_recover(t, proposal_partials);

        // Should not be able to recover the threshold signature
        assert!(result.is_err());
    }

    #[test]
    fn test_conflicting_notarize_detection() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        // Create two different proposals for the same view
        let proposal1 = Proposal::new(10, 5, sample_digest(1));
        let proposal2 = Proposal::new(10, 5, sample_digest(2)); // Same view, different payload

        // Create notarizes for both proposals from the same validator
        let notarize1 = Notarize::sign(NAMESPACE, &shares[0], proposal1.clone());
        let notarize2 = Notarize::sign(NAMESPACE, &shares[0], proposal2);

        // Create conflict evidence
        let conflict = ConflictingNotarize::new(notarize1, notarize2.clone());

        // Verify the evidence is valid
        assert!(conflict.verify(NAMESPACE, &commitment));

        // Now create invalid evidence using different validator keys
        let notarize3 = Notarize::sign(NAMESPACE, &shares[1], proposal1.clone());

        // This should compile but verification should fail because the signatures
        // are from different validators
        let invalid_conflict = ConflictingNotarize {
            view: conflict.view,
            parent_1: conflict.parent_1,
            payload_1: conflict.payload_1,
            signature_1: conflict.signature_1,
            parent_2: notarize3.proposal.parent,
            payload_2: notarize3.proposal.payload,
            signature_2: notarize3.proposal_signature,
        };

        // Verification should still fail even with correct identity
        assert!(!invalid_conflict.verify(NAMESPACE, &commitment));
    }

    #[test]
    fn test_nullify_finalize_detection() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        let view = 10;

        // Create a nullify for view 10
        let nullify = Nullify::sign(NAMESPACE, &shares[0], view);

        // Create a finalize for the same view
        let proposal = Proposal::new(view, 5, sample_digest(1));
        let finalize = Finalize::sign(NAMESPACE, &shares[0], proposal);

        // Create nullify+finalize evidence
        let conflict = NullifyFinalize::new(nullify, finalize.clone());

        // Verify the evidence is valid
        assert!(conflict.verify(NAMESPACE, &commitment));

        // Now try with wrong namespace
        assert!(!conflict.verify(b"wrong_namespace", &commitment));

        // Now create invalid evidence with different validators
        let nullify2 = Nullify::sign(NAMESPACE, &shares[1], view);

        // Compile but verification should fail because signatures are from different validators
        let invalid_conflict = NullifyFinalize {
            proposal: finalize.proposal,
            view_signature: conflict.view_signature,
            finalize_signature: nullify2.view_signature,
        };

        // Verification should fail
        assert!(!invalid_conflict.verify(NAMESPACE, &commitment));
    }

    #[test]
    fn test_finalization_wrong_signature() {
        let n = 5;
        let t = quorum(n as u32);
        let (commitment, shares) = generate_test_data(n, t, 0);

        // Create a completely different key set
        let (wrong_commitment, _) = generate_test_data(n, t, 1);

        let proposal = Proposal::new(10, 5, sample_digest(1));

        // Create finalizes and notarizes for threshold signatures
        let finalizes: Vec<_> = shares
            .iter()
            .map(|s| Finalize::sign(NAMESPACE, s, proposal.clone()))
            .collect();
        let notarizes: Vec<_> = shares
            .iter()
            .map(|s| Notarize::sign(NAMESPACE, s, proposal.clone()))
            .collect();

        // Recover threshold signatures
        let proposal_partials = finalizes.iter().map(|f| &f.proposal_signature);
        let proposal_signature = threshold_signature_recover(t, proposal_partials).unwrap();
        let seed_partials = notarizes.iter().map(|n| &n.seed_signature);
        let seed_signature = threshold_signature_recover(t, seed_partials).unwrap();

        // Create finalization
        let finalization = Finalization::new(proposal, proposal_signature, seed_signature);

        // Verify with correct public key - should pass
        let public_key = poly::public(&commitment);
        assert!(finalization.verify(NAMESPACE, public_key));

        // Verify with wrong public key - should fail
        let wrong_public_key = poly::public(&wrong_commitment);
        assert!(!finalization.verify(NAMESPACE, wrong_public_key));
    }
}
