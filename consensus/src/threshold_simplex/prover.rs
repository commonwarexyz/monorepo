use super::{
    encoder::{
        finalize_namespace, notarize_namespace, nullify_message, nullify_namespace,
        proposal_message, seed_message, seed_namespace,
    },
    wire, View,
};
use crate::Proof;
use bytes::{Buf, BufMut};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        ops,
        poly::{self, Eval},
    },
    Digest, Hasher, Signature,
};
use std::marker::PhantomData;

type Callback = Box<dyn Fn(&poly::Poly<group::Public>) -> Option<u32>>;

pub struct Verifier {
    callback: Callback,
}

impl Verifier {
    fn new<F>(callback: F) -> Self
    where
        F: Fn(&poly::Poly<group::Public>) -> Option<u32> + 'static,
    {
        Self {
            callback: Box::new(callback),
        }
    }

    pub fn verify(self, identity: &poly::Poly<group::Public>) -> Option<u32> {
        (self.callback)(identity)
    }
}

/// Encode and decode proofs of activity.
///
/// We don't use protobuf for proof encoding because we expect external parties
/// to decode proofs in constrained environments where protobuf may not be implemented.
#[derive(Clone)]
pub struct Prover<H: Hasher> {
    _hasher: PhantomData<H>,

    public: group::Public,

    seed_namespace: Vec<u8>,
    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,
}

/// If we expose partial signatures of proofs, can be used to construct a partial signature
/// over pre-aggregated data (where the public key of each index can be derived from the group
/// polynomial). This can be very useful for distributing rewards without including all partial signatures
/// in a block.
impl<H: Hasher> Prover<H> {
    /// Create a new prover with the given signing `namespace`.
    pub fn new(public: group::Public, namespace: &[u8]) -> Self {
        Self {
            _hasher: PhantomData,

            public,

            seed_namespace: seed_namespace(namespace),
            notarize_namespace: notarize_namespace(namespace),
            nullify_namespace: nullify_namespace(namespace),
            finalize_namespace: finalize_namespace(namespace),
        }
    }

    /// Serialize a proposal proof.
    pub fn serialize_proposal(proposal: &wire::Proposal, partial_signature: &Signature) -> Proof {
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
        namespace: &[u8],
    ) -> Option<(View, View, Digest, Verifier)> {
        // Ensure proof is big enough
        let digest_len = H::len();
        if proof.len() != 8 + 8 + digest_len + poly::PARTIAL_SIGNATURE_LENGTH {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(digest_len);
        let signature = proof.copy_to_bytes(poly::PARTIAL_SIGNATURE_LENGTH);
        let signature = poly::Eval::deserialize(&signature)?;

        // Create callback
        let proposal_message = proposal_message(view, parent, &payload);
        let namespace = namespace.to_vec();
        let callback = move |identity: &poly::Poly<group::Public>| -> Option<u32> {
            if ops::partial_verify_message(
                identity,
                Some(&namespace),
                &proposal_message,
                &signature,
            )
            .is_err()
            {
                return None;
            }
            Some(signature.index)
        };
        Some((view, parent, payload, Verifier::new(callback)))
    }

    /// Serialize an aggregation proof.
    pub fn serialize_threshold(
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
        &self,
        mut proof: Proof,
        namespace: &[u8],
    ) -> Option<(View, View, Digest, group::Signature, group::Signature)> {
        // Ensure proof prefix is big enough
        let digest_len = H::len();
        let len = 8 + 8 + digest_len + group::SIGNATURE_LENGTH + group::SIGNATURE_LENGTH;
        if proof.len() < len {
            return None;
        }

        // Verify signature
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(digest_len);
        let message = proposal_message(view, parent, &payload);
        let signature = proof.copy_to_bytes(group::SIGNATURE_LENGTH);
        let signature = group::Signature::deserialize(&signature)?;
        if ops::verify_message(&self.public, Some(namespace), &message, &signature).is_err() {
            return None;
        }

        // Verify seed
        let message = seed_message(view);
        let seed = proof.copy_to_bytes(group::SIGNATURE_LENGTH);
        let seed = group::Signature::deserialize(&seed)?;
        if ops::verify_message(&self.public, Some(&self.seed_namespace), &message, &seed).is_err() {
            return None;
        }
        Some((view, parent, payload, signature, seed))
    }

    /// Deserialize a notarize proof.
    pub fn deserialize_notarize(&self, proof: Proof) -> Option<(View, View, Digest, Verifier)> {
        Self::deserialize_proposal(proof, &self.notarize_namespace)
    }

    /// Deserialize a notarization proof.
    pub fn deserialize_notarization(
        &self,
        proof: Proof,
    ) -> Option<(View, View, Digest, group::Signature, group::Signature)> {
        self.deserialize_threshold(proof, &self.notarize_namespace)
    }

    /// Deserialize a finalize proof.
    pub fn deserialize_finalize(&self, proof: Proof) -> Option<(View, View, Digest, Verifier)> {
        Self::deserialize_proposal(proof, &self.finalize_namespace)
    }

    /// Deserialize a finalization proof.
    pub fn deserialize_finalization(
        &self,
        proof: Proof,
    ) -> Option<(View, View, Digest, group::Signature, group::Signature)> {
        self.deserialize_threshold(proof, &self.finalize_namespace)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn serialize_conflicting_proposal(
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
            + poly::PARTIAL_SIGNATURE_LENGTH
            + 8
            + digest_len
            + poly::PARTIAL_SIGNATURE_LENGTH;

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
        namespace: &[u8],
    ) -> Option<(View, Verifier)> {
        // Ensure proof is big enough
        let digest_len = H::len();
        let len = 8
            + 8
            + digest_len
            + poly::PARTIAL_SIGNATURE_LENGTH
            + 8
            + digest_len
            + poly::PARTIAL_SIGNATURE_LENGTH;
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let parent_1 = proof.get_u64();
        let payload_1 = proof.copy_to_bytes(digest_len);
        let signature_1 = proof.copy_to_bytes(poly::PARTIAL_SIGNATURE_LENGTH);
        let signature_1 = Eval::deserialize(&signature_1)?;
        let parent_2 = proof.get_u64();
        let payload_2 = proof.copy_to_bytes(digest_len);
        let signature_2 = proof.copy_to_bytes(poly::PARTIAL_SIGNATURE_LENGTH);
        let signature_2 = Eval::deserialize(&signature_2)?;
        if signature_1.index != signature_2.index {
            return None;
        }

        // Create callback
        let namespace = namespace.to_vec();
        let callback = move |identity: &poly::Poly<group::Public>| -> Option<u32> {
            if ops::partial_verify_message(
                identity,
                Some(&namespace),
                &proposal_message(view, parent_1, &payload_1),
                &signature_1,
            )
            .is_err()
            {
                return None;
            }
            if ops::partial_verify_message(
                identity,
                Some(&namespace),
                &proposal_message(view, parent_2, &payload_2),
                &signature_2,
            )
            .is_err()
            {
                return None;
            }
            Some(signature_1.index)
        };
        Some((view, Verifier::new(callback)))
    }

    /// Serialize a conflicting notarize proof.
    #[allow(clippy::too_many_arguments)]
    pub fn serialize_conflicting_notarize(
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
    pub fn deserialize_conflicting_notarize(&self, proof: Proof) -> Option<(View, Verifier)> {
        Self::deserialize_conflicting_proposal(proof, &self.notarize_namespace)
    }

    /// Serialize a conflicting finalize proof.
    #[allow(clippy::too_many_arguments)]
    pub fn serialize_conflicting_finalize(
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
    pub fn deserialize_conflicting_finalize(&self, proof: Proof) -> Option<(View, Verifier)> {
        Self::deserialize_conflicting_proposal(proof, &self.finalize_namespace)
    }

    /// Serialize a conflicting nullify and finalize proof.
    pub fn serialize_nullify_finalize(
        view: View,
        parent: View,
        payload: &Digest,
        signature_finalize: &Signature,
        signature_null: &Signature,
    ) -> Proof {
        // Setup proof
        let digest_len = H::len();
        let len =
            8 + 8 + digest_len + poly::PARTIAL_SIGNATURE_LENGTH + poly::PARTIAL_SIGNATURE_LENGTH;

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
    pub fn deserialize_nullify_finalize(&self, mut proof: Proof) -> Option<(View, Verifier)> {
        // Ensure proof is big enough
        let digest_len = H::len();
        let len =
            8 + 8 + digest_len + poly::PARTIAL_SIGNATURE_LENGTH + poly::PARTIAL_SIGNATURE_LENGTH;
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(digest_len);
        let signature_finalize = proof.copy_to_bytes(poly::PARTIAL_SIGNATURE_LENGTH);
        let signature_finalize = Eval::deserialize(&signature_finalize)?;
        let signature_null = proof.copy_to_bytes(poly::PARTIAL_SIGNATURE_LENGTH);
        let signature_null = Eval::deserialize(&signature_null)?;
        if signature_finalize.index != signature_null.index {
            return None;
        }

        // Create callback
        let finalize_namespace = self.finalize_namespace.clone();
        let nullify_namespace = self.nullify_namespace.clone();
        let callback = move |identity: &poly::Poly<group::Public>| -> Option<u32> {
            if ops::partial_verify_message(
                identity,
                Some(&finalize_namespace),
                &proposal_message(view, parent, &payload),
                &signature_finalize,
            )
            .is_err()
            {
                return None;
            }
            if ops::partial_verify_message(
                identity,
                Some(&nullify_namespace),
                &nullify_message(view),
                &signature_null,
            )
            .is_err()
            {
                return None;
            }
            Some(signature_finalize.index)
        };
        Some((view, Verifier::new(callback)))
    }
}
