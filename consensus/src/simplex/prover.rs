use super::{wire, View};
use crate::Proof;
use bytes::{Buf, BufMut};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        poly::{self, Eval},
    },
    Digest, Hasher, Signature,
};
use std::marker::PhantomData;

/// Encode and decode proofs of activity.
///
/// We don't use protobuf for proof encoding because we expect external parties
/// to decode proofs in constrained environments where protobuf may not be implemented.
#[derive(Clone)]
pub struct Prover<H: Hasher> {
    _hasher: PhantomData<H>,
}

/// If we expose partial signatures of proofs, can be used to construct a partial signature
/// over pre-aggregated data (where the public key of each index can be derived from the group
/// polynomial). This can be very useful for distributing rewards without including all partial signatures
/// in a block.
impl<H: Hasher> Prover<H> {
    /// Create a new prover with the given signing `namespace`.
    pub fn new() -> Self {
        Self {
            _hasher: PhantomData,
        }
    }

    /// Serialize a proposal proof.
    pub(crate) fn serialize_proposal(
        proposal: &wire::Proposal,
        partial_signature: &Signature,
    ) -> Proof {
        // Setup proof
        let len = 8 + 8 + proposal.payload.len() + partial_signature.len();

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(proposal.view);
        proof.put_u64(proposal.parent);
        proof.extend_from_slice(&proposal.payload);
        proof.extend_from_slice(partial_signature);
        proof.into()
    }

    /// Deserialize a proposal proof.
    fn deserialize_proposal(
        mut proof: Proof,
    ) -> Option<(View, View, Digest, poly::Eval<group::Signature>)> {
        // Ensure proof is big enough
        let digest_len = H::len();
        if proof.len() != 8 + 8 + digest_len + group::PARTIAL_SIGNATURE_LENGTH {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(digest_len);
        let signature = proof.copy_to_bytes(group::PARTIAL_SIGNATURE_LENGTH);
        let signature = poly::Eval::deserialize(&signature)?;
        Some((view, parent, payload, signature))
    }

    /// Serialize an aggregation proof.
    pub(crate) fn serialize_threshold(
        proposal: &wire::Proposal,
        signature: &Signature,
        seed: &Signature,
    ) -> Proof {
        // Setup proof
        let len =
            8 + 8 + proposal.payload.len() + group::SIGNATURE_LENGTH + group::SIGNATURE_LENGTH;

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(proposal.view);
        proof.put_u64(proposal.parent);
        proof.extend_from_slice(&proposal.payload);
        proof.extend_from_slice(signature);
        proof.extend_from_slice(seed);
        proof.into()
    }

    /// Deserialize an aggregation proof.
    fn deserialize_threshold(
        mut proof: Proof,
    ) -> Option<(View, View, Digest, group::Signature, group::Signature)> {
        // Ensure proof prefix is big enough
        let digest_len = H::len();
        let len = 8 + 8 + digest_len + group::SIGNATURE_LENGTH + group::SIGNATURE_LENGTH;
        if proof.len() < len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(digest_len);
        let signature = proof.copy_to_bytes(group::SIGNATURE_LENGTH);
        let signature = group::Signature::deserialize(&signature)?;
        let seed = proof.copy_to_bytes(group::SIGNATURE_LENGTH);
        let seed = group::Signature::deserialize(&seed)?;
        Some((view, parent, payload, signature, seed))
    }

    /// Deserialize a notarize proof.
    pub fn deserialize_notarize(
        proof: Proof,
    ) -> Option<(View, View, Digest, Eval<group::Signature>)> {
        Self::deserialize_proposal(proof)
    }

    /// Deserialize a notarization proof.
    pub fn deserialize_notarization(
        proof: Proof,
    ) -> Option<(View, View, Digest, group::Signature, group::Signature)> {
        Self::deserialize_threshold(proof)
    }

    /// Deserialize a finalize proof.
    pub fn deserialize_finalize(
        proof: Proof,
    ) -> Option<(View, View, Digest, Eval<group::Signature>)> {
        Self::deserialize_proposal(proof)
    }

    /// Deserialize a finalization proof.
    pub fn deserialize_finalization(
        proof: Proof,
    ) -> Option<(View, View, Digest, group::Signature, group::Signature)> {
        Self::deserialize_threshold(proof)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn serialize_conflicting_proposal(
        view: View,
        parent_1: View,
        payload_1: &Digest,
        signature_1: &Signature,
        parent_2: View,
        payload_2: &Digest,
        signature_2: &Signature,
    ) -> Proof {
        // Setup proof
        let digest_len = H::len();
        let len = 8
            + 8
            + digest_len
            + 4
            + group::SIGNATURE_LENGTH
            + 8
            + digest_len
            + 4
            + group::SIGNATURE_LENGTH;

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(view);
        proof.put_u64(parent_1);
        proof.extend_from_slice(payload_1);
        proof.extend_from_slice(signature_1);
        proof.put_u64(parent_2);
        proof.extend_from_slice(payload_2);
        proof.extend_from_slice(signature_2);
        proof.into()
    }

    fn deserialize_conflicting_proposal(
        mut proof: Proof,
    ) -> Option<(
        View,
        (View, Digest, Eval<group::Signature>),
        (View, Digest, Eval<group::Signature>),
    )> {
        // Ensure proof is big enough
        let digest_len = H::len();
        let len = 8
            + 8
            + digest_len
            + 4
            + group::SIGNATURE_LENGTH
            + 8
            + digest_len
            + group::SIGNATURE_LENGTH;
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let parent_1 = proof.get_u64();
        let payload_1 = proof.copy_to_bytes(digest_len);
        let signature_1 = proof.copy_to_bytes(group::PARTIAL_SIGNATURE_LENGTH);
        let signature_1 = Eval::deserialize(&signature_1)?;
        let parent_2 = proof.get_u64();
        let payload_2 = proof.copy_to_bytes(digest_len);
        let signature_2 = proof.copy_to_bytes(group::PARTIAL_SIGNATURE_LENGTH);
        let signature_2 = Eval::deserialize(&signature_2)?;
        Some((
            view,
            (parent_1, payload_1, signature_1),
            (parent_2, payload_2, signature_2),
        ))
    }

    /// Serialize a conflicting notarize proof.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn serialize_conflicting_notarize(
        view: View,
        parent_1: View,
        payload_1: &Digest,
        signature_1: &Signature,
        parent_2: View,
        payload_2: &Digest,
        signature_2: &Signature,
    ) -> Proof {
        Self::serialize_conflicting_proposal(
            view,
            parent_1,
            payload_1,
            signature_1,
            parent_2,
            payload_2,
            signature_2,
        )
    }

    /// Deserialize a conflicting notarization proof.
    pub fn deserialize_conflicting_notarize(
        proof: Proof,
    ) -> Option<(
        View,
        (View, Digest, Eval<group::Signature>),
        (View, Digest, Eval<group::Signature>),
    )> {
        Self::deserialize_conflicting_proposal(proof)
    }

    /// Serialize a conflicting finalize proof.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn serialize_conflicting_finalize(
        view: View,
        parent_1: View,
        payload_1: &Digest,
        signature_1: &Signature,
        parent_2: View,
        payload_2: &Digest,
        signature_2: &Signature,
    ) -> Proof {
        Self::serialize_conflicting_proposal(
            view,
            parent_1,
            payload_1,
            signature_1,
            parent_2,
            payload_2,
            signature_2,
        )
    }

    /// Deserialize a conflicting finalization proof.
    pub fn deserialize_conflicting_finalize(
        proof: Proof,
    ) -> Option<(
        View,
        (View, Digest, Eval<group::Signature>),
        (View, Digest, Eval<group::Signature>),
    )> {
        Self::deserialize_conflicting_proposal(proof)
    }

    /// Serialize a conflicting nullify and finalize proof.
    pub(crate) fn serialize_nullify_finalize(
        view: View,
        parent: View,
        payload: &Digest,
        signature_finalize: &Signature,
        signature_null: &Signature,
    ) -> Proof {
        // Setup proof
        let digest_len = H::len();
        let len =
            8 + 8 + digest_len + group::PARTIAL_SIGNATURE_LENGTH + group::PARTIAL_SIGNATURE_LENGTH;

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(view);
        proof.put_u64(parent);
        proof.extend_from_slice(payload);
        proof.extend_from_slice(signature_finalize);
        proof.extend_from_slice(signature_null);
        proof.into()
    }

    /// Deserialize a conflicting nullify and finalize proof.
    pub fn deserialize_nullify_finalize(
        mut proof: Proof,
    ) -> Option<(
        View,
        (View, Digest, Eval<group::Signature>),
        (View, Eval<group::Signature>),
    )> {
        // Ensure proof is big enough
        let digest_len = H::len();
        let len =
            8 + 8 + digest_len + group::PARTIAL_SIGNATURE_LENGTH + group::PARTIAL_SIGNATURE_LENGTH;
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(digest_len);
        let signature_finalize = proof.copy_to_bytes(group::PARTIAL_SIGNATURE_LENGTH);
        let signature_finalize = Eval::deserialize(&signature_finalize)?;
        let signature_null = proof.copy_to_bytes(group::PARTIAL_SIGNATURE_LENGTH);
        let signature_null = Eval::deserialize(&signature_null)?;
        Some((
            view,
            (parent, payload, signature_finalize),
            (parent, signature_null),
        ))
    }
}
