use super::{
    encoder::{
        finalize_namespace, notarize_namespace, nullify_message, nullify_namespace,
        proposal_message,
    },
    wire, View,
};
use crate::{Digest, Proof};
use bytes::{Buf, BufMut};
use commonware_cryptography::{PublicKey, Scheme, Signature};
use std::{collections::HashSet, marker::PhantomData};

/// Encode and decode proofs of activity.
///
/// We don't use protobuf for proof encoding because we expect external parties
/// to decode proofs in constrained environments where protobuf may not be implemented.
#[derive(Clone)]
pub struct Prover<C: Scheme> {
    _crypto: PhantomData<C>,

    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,

    digest: usize,
}

impl<C: Scheme> Prover<C> {
    /// Create a new prover with the given signing `namespace`.
    pub fn new(namespace: &[u8], digest: usize) -> Self {
        Self {
            _crypto: PhantomData,

            notarize_namespace: notarize_namespace(namespace),
            nullify_namespace: nullify_namespace(namespace),
            finalize_namespace: finalize_namespace(namespace),

            digest,
        }
    }

    /// Serialize a proposal proof.
    pub fn serialize_proposal(
        proposal: &wire::Proposal,
        public_key: &PublicKey,
        signature: &Signature,
    ) -> Proof {
        // Setup proof
        let len = size_of::<u64>()
            + size_of::<u64>()
            + proposal.payload.len()
            + public_key.len()
            + signature.len();

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(proposal.view);
        proof.put_u64(proposal.parent);
        proof.extend_from_slice(&proposal.payload);
        proof.extend_from_slice(public_key);
        proof.extend_from_slice(signature);
        proof.into()
    }

    /// Deserialize a proposal proof.
    fn deserialize_proposal(
        &self,
        mut proof: Proof,
        check_sig: bool,
        namespace: &[u8],
    ) -> Option<(View, View, Digest, PublicKey)> {
        // Ensure proof is big enough
        let (public_key_len, signature_len) = C::len();
        if proof.len()
            != size_of::<u64>() + size_of::<u64>() + self.digest + public_key_len + signature_len
        {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(self.digest);
        let public_key = proof.copy_to_bytes(public_key_len);
        let signature = proof.copy_to_bytes(signature_len);

        // Verify signature
        let proposal_message = proposal_message(view, parent, &payload);
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            if !C::verify(Some(namespace), &proposal_message, &public_key, &signature) {
                return None;
            }
        }

        Some((view, parent, payload, public_key))
    }

    /// Serialize an aggregation proof.
    pub fn serialize_aggregation(
        proposal: &wire::Proposal,
        signatures: Vec<(&PublicKey, &Signature)>,
    ) -> Proof {
        // Setup proof
        let (public_key_len, signature_len) = C::len();
        let len = size_of::<u64>()
            + size_of::<u64>()
            + proposal.payload.len()
            + size_of::<u32>()
            + signatures.len() * (public_key_len + signature_len);

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(proposal.view);
        proof.put_u64(proposal.parent);
        proof.extend_from_slice(&proposal.payload);
        proof.put_u32(signatures.len() as u32);
        for (public_key, signature) in signatures {
            proof.extend_from_slice(public_key);
            proof.extend_from_slice(signature);
        }
        proof.into()
    }

    /// Deserialize an aggregation proof.
    fn deserialize_aggregation(
        &self,
        mut proof: Proof,
        max: u32,
        check_sigs: bool,
        namespace: &[u8],
    ) -> Option<(View, View, Digest, Vec<PublicKey>)> {
        // Ensure proof prefix is big enough
        let len = size_of::<u64>() + size_of::<u64>() + self.digest + size_of::<u32>();
        if proof.len() < len {
            return None;
        }

        // Decode proof prefix
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(self.digest);
        let count = proof.get_u32();
        if count > max {
            return None;
        }
        let count = count as usize;
        let message = proposal_message(view, parent, &payload);

        // Check for integer overflow in size calculation
        let (public_key_len, signature_len) = C::len();
        let item_size = public_key_len.checked_add(signature_len)?;
        let total_size = count.checked_mul(item_size)?;
        if proof.remaining() != total_size {
            return None;
        }

        // Decode signatures
        let mut seen = HashSet::with_capacity(count);
        for _ in 0..count {
            // Check if already saw public key
            let public_key = proof.copy_to_bytes(public_key_len);
            if seen.contains(&public_key) {
                return None;
            }
            seen.insert(public_key.clone());

            // Verify signature
            let signature = proof.copy_to_bytes(signature_len);
            if check_sigs {
                if !C::validate(&public_key) {
                    return None;
                }
                if !C::verify(Some(namespace), &message, &public_key, &signature) {
                    return None;
                }
            }
        }
        Some((view, parent, payload, seen.into_iter().collect()))
    }

    /// Deserialize a notarize proof.
    pub fn deserialize_notarize(
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(View, View, Digest, PublicKey)> {
        self.deserialize_proposal(proof, check_sig, &self.notarize_namespace)
    }

    /// Deserialize a notarization proof.
    pub fn deserialize_notarization(
        &self,
        proof: Proof,
        max: u32,
        check_sigs: bool,
    ) -> Option<(View, View, Digest, Vec<PublicKey>)> {
        self.deserialize_aggregation(proof, max, check_sigs, &self.notarize_namespace)
    }

    /// Deserialize a finalize proof.
    pub fn deserialize_finalize(
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(View, View, Digest, PublicKey)> {
        self.deserialize_proposal(proof, check_sig, &self.finalize_namespace)
    }

    /// Deserialize a finalization proof.
    pub fn deserialize_finalization(
        &self,
        proof: Proof,
        max: u32,
        check_sigs: bool,
    ) -> Option<(View, View, Digest, Vec<PublicKey>)> {
        self.deserialize_aggregation(proof, max, check_sigs, &self.finalize_namespace)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn serialize_conflicting_proposal(
        view: View,
        public_key: &PublicKey,
        parent_1: View,
        payload_1: &Digest,
        signature_1: &Signature,
        parent_2: View,
        payload_2: &Digest,
        signature_2: &Signature,
    ) -> Proof {
        // Setup proof
        let (public_key_len, signature_len) = C::len();
        let len = size_of::<u64>()
            + public_key_len
            + size_of::<u64>()
            + payload_1.len()
            + signature_len
            + size_of::<u64>()
            + payload_2.len()
            + signature_len;

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(view);
        proof.extend_from_slice(public_key);
        proof.put_u64(parent_1);
        proof.extend_from_slice(payload_1);
        proof.extend_from_slice(signature_1);
        proof.put_u64(parent_2);
        proof.extend_from_slice(payload_2);
        proof.extend_from_slice(signature_2);
        proof.into()
    }

    fn deserialize_conflicting_proposal(
        &self,
        mut proof: Proof,
        check_sig: bool,
        namespace: &[u8],
    ) -> Option<(PublicKey, View)> {
        // Ensure proof is big enough
        let (public_key_len, signature_len) = C::len();
        let len = size_of::<u64>()
            + public_key_len
            + size_of::<u64>()
            + self.digest
            + signature_len
            + size_of::<u64>()
            + self.digest
            + signature_len;
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let public_key = proof.copy_to_bytes(public_key_len);
        let parent_1 = proof.get_u64();
        let payload_1 = proof.copy_to_bytes(self.digest);
        let signature_1 = proof.copy_to_bytes(signature_len);
        let parent_2 = proof.get_u64();
        let payload_2 = proof.copy_to_bytes(self.digest);
        let signature_2 = proof.copy_to_bytes(signature_len);

        // Verify signatures
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            let proposal_message_1 = proposal_message(view, parent_1, &payload_1);
            let proposal_message_2 = proposal_message(view, parent_2, &payload_2);
            if !C::verify(
                Some(namespace),
                &proposal_message_1,
                &public_key,
                &signature_1,
            ) || !C::verify(
                Some(namespace),
                &proposal_message_2,
                &public_key,
                &signature_2,
            ) {
                return None;
            }
        }
        Some((public_key, view))
    }

    /// Serialize a conflicting notarize proof.
    #[allow(clippy::too_many_arguments)]
    pub fn serialize_conflicting_notarize(
        view: View,
        public_key: &PublicKey,
        parent_1: View,
        payload_1: &Digest,
        signature_1: &Signature,
        parent_2: View,
        payload_2: &Digest,
        signature_2: &Signature,
    ) -> Proof {
        Self::serialize_conflicting_proposal(
            view,
            public_key,
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
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View)> {
        self.deserialize_conflicting_proposal(proof, check_sig, &self.notarize_namespace)
    }

    /// Serialize a conflicting finalize proof.
    #[allow(clippy::too_many_arguments)]
    pub fn serialize_conflicting_finalize(
        view: View,
        public_key: &PublicKey,
        parent_1: View,
        payload_1: &Digest,
        signature_1: &Signature,
        parent_2: View,
        payload_2: &Digest,
        signature_2: &Signature,
    ) -> Proof {
        Self::serialize_conflicting_proposal(
            view,
            public_key,
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
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View)> {
        self.deserialize_conflicting_proposal(proof, check_sig, &self.finalize_namespace)
    }

    /// Serialize a conflicting nullify and finalize proof.
    pub fn serialize_nullify_finalize(
        view: View,
        public_key: &PublicKey,
        parent: View,
        payload: &Digest,
        signature_finalize: &Signature,
        signature_null: &Signature,
    ) -> Proof {
        // Setup proof
        let (public_key_len, signature_len) = C::len();
        let len = size_of::<u64>()
            + public_key_len
            + size_of::<u64>()
            + payload.len()
            + signature_len
            + signature_len;

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(view);
        proof.extend_from_slice(public_key);
        proof.put_u64(parent);
        proof.extend_from_slice(payload);
        proof.extend_from_slice(signature_finalize);
        proof.extend_from_slice(signature_null);
        proof.into()
    }

    /// Deserialize a conflicting nullify and finalize proof.
    pub fn deserialize_nullify_finalize(
        &self,
        mut proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View)> {
        // Ensure proof is big enough
        let (public_key_len, signature_len) = C::len();
        let len = size_of::<u64>()
            + public_key_len
            + size_of::<u64>()
            + self.digest
            + signature_len
            + signature_len;
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let public_key = proof.copy_to_bytes(public_key_len);
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(self.digest);
        let signature_finalize = proof.copy_to_bytes(signature_len);
        let signature_null = proof.copy_to_bytes(signature_len);

        // Verify signatures
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            let finalize_message = proposal_message(view, parent, &payload);
            let null_message = nullify_message(view);
            if !C::verify(
                Some(&self.finalize_namespace),
                &finalize_message,
                &public_key,
                &signature_finalize,
            ) || !C::verify(
                Some(&self.nullify_namespace),
                &null_message,
                &public_key,
                &signature_null,
            ) {
                return None;
            }
        }
        Some((public_key, view))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Ed25519, Hasher, Sha256};

    #[test]
    fn test_deserialize_aggregation_empty() {
        // Create a proof with no signers
        let prover = Prover::<Ed25519>::new(b"test", Sha256::DIGEST_LENGTH);
        let mut proof = Vec::new();
        proof.put_u64(1); // view
        proof.put_u64(0); // parent
        proof.extend_from_slice(&[0; Sha256::DIGEST_LENGTH]); // payload
        proof.put_u32(0); // count of 0 signatures is valid

        // Verify that the proof is accepted
        let result =
            prover.deserialize_aggregation(proof.into(), 10, false, &prover.notarize_namespace);
        assert!(result.is_some());
    }

    #[test]
    fn test_deserialize_aggregation_short_header() {
        // Create a proof with incorrect signers
        let mut proof = Vec::new();
        proof.put_u64(1); // view
        proof.put_u64(0); // parent
        proof.extend_from_slice(&[0; Sha256::DIGEST_LENGTH]); // payload

        // Verify that the proof is rejected
        let prover = Prover::<Ed25519>::new(b"test", Sha256::DIGEST_LENGTH);
        let result = prover.deserialize_aggregation(
            proof.into(),
            u32::MAX, // Allow any count to test overflow protection
            false,
            &prover.notarize_namespace,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_deserialize_aggregation_malicious_count() {
        // Create a proof with incorrect signers
        let mut proof = Vec::new();
        proof.put_u64(1); // view
        proof.put_u64(0); // parent
        proof.extend_from_slice(&[0; Sha256::DIGEST_LENGTH]); // payload
        proof.put_u32(100);

        // Verify that the proof is rejected
        let prover = Prover::<Ed25519>::new(b"test", Sha256::DIGEST_LENGTH);
        let result = prover.deserialize_aggregation(
            proof.into(),
            u32::MAX, // Allow any count to test overflow protection
            false,
            &prover.notarize_namespace,
        );
        assert!(result.is_none());
    }
}
