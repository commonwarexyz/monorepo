use super::{
    encoder::{
        finalize_namespace, notarize_namespace, nullify_message, nullify_namespace,
        proposal_message,
    },
    wire, View,
};
use crate::Proof;
use bytes::{Buf, BufMut};
use commonware_cryptography::{Octets, Scheme};
use std::{collections::HashSet, marker::PhantomData};

/// Encode and decode proofs of activity.
///
/// We don't use protobuf for proof encoding because we expect external parties
/// to decode proofs in constrained environments where protobuf may not be implemented.
#[derive(Clone)]
pub struct Prover<C: Scheme, D: Octets> {
    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,

    _crypto: PhantomData<C>,
    _digest: PhantomData<D>,
}

impl<C: Scheme, D: Octets> Prover<C, D> {
    /// Create a new prover with the given signing `namespace`.
    pub fn new(namespace: &[u8]) -> Self {
        Self {
            notarize_namespace: notarize_namespace(namespace),
            nullify_namespace: nullify_namespace(namespace),
            finalize_namespace: finalize_namespace(namespace),

            _crypto: PhantomData,
            _digest: PhantomData,
        }
    }

    /// Serialize a proposal proof.
    pub fn serialize_proposal(
        proposal: &wire::Proposal,
        public_key: &C::PublicKey,
        signature: &C::Signature,
    ) -> Proof {
        // Setup proof
        let len = size_of::<u64>()
            + size_of::<u64>()
            + size_of::<D>()
            + size_of::<C::PublicKey>()
            + size_of::<C::Signature>();

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
    ) -> Option<(View, View, D, C::PublicKey)> {
        // Ensure proof is big enough
        if proof.len()
            != size_of::<u64>()
                + size_of::<u64>()
                + size_of::<D>()
                + size_of::<C::PublicKey>()
                + size_of::<C::Signature>()
        {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = D::read_from(&mut proof).ok()?;
        let public_key = C::PublicKey::read_from(&mut proof).ok()?;
        let signature = C::Signature::read_from(&mut proof).ok()?;

        // Verify signature
        let proposal_message = proposal_message(view, parent, &payload);
        if check_sig && !C::verify(Some(namespace), &proposal_message, &public_key, &signature) {
            return None;
        }

        Some((view, parent, payload, public_key))
    }

    /// Serialize an aggregation proof.
    pub fn serialize_aggregation(
        proposal: &wire::Proposal,
        signatures: Vec<(&C::PublicKey, &C::Signature)>,
    ) -> Proof {
        // Setup proof
        let len = size_of::<u64>()
            + size_of::<u64>()
            + size_of::<D>()
            + size_of::<u32>()
            + signatures.len() * (size_of::<C::PublicKey>() + size_of::<C::Signature>());

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
    ) -> Option<(View, View, D, Vec<C::PublicKey>)> {
        // Ensure proof prefix is big enough
        let len = size_of::<u64>() + size_of::<u64>() + size_of::<D>() + size_of::<u32>();
        if proof.len() < len {
            return None;
        }

        // Decode proof prefix
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = D::read_from(&mut proof).ok()?;
        let count = proof.get_u32();
        if count > max {
            return None;
        }
        let count = count as usize;
        let message = proposal_message(view, parent, &payload);

        // Check for integer overflow in size calculation
        let item_size = size_of::<C::PublicKey>().checked_add(size_of::<C::Signature>())?;
        let total_size = count.checked_mul(item_size)?;
        if proof.remaining() != total_size {
            return None;
        }

        // Decode signatures
        let mut seen = HashSet::with_capacity(count);
        for _ in 0..count {
            // Check if already saw public key
            let public_key = C::PublicKey::read_from(&mut proof).ok()?;
            if seen.contains(&public_key) {
                return None;
            }
            seen.insert(public_key.clone());

            // Verify signature
            if check_sigs {
                let signature = C::Signature::read_from(&mut proof).ok()?;
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
    ) -> Option<(View, View, D, C::PublicKey)> {
        self.deserialize_proposal(proof, check_sig, &self.notarize_namespace)
    }

    /// Deserialize a notarization proof.
    pub fn deserialize_notarization(
        &self,
        proof: Proof,
        max: u32,
        check_sigs: bool,
    ) -> Option<(View, View, D, Vec<C::PublicKey>)> {
        self.deserialize_aggregation(proof, max, check_sigs, &self.notarize_namespace)
    }

    /// Deserialize a finalize proof.
    pub fn deserialize_finalize(
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(View, View, D, C::PublicKey)> {
        self.deserialize_proposal(proof, check_sig, &self.finalize_namespace)
    }

    /// Deserialize a finalization proof.
    pub fn deserialize_finalization(
        &self,
        proof: Proof,
        max: u32,
        check_sigs: bool,
    ) -> Option<(View, View, D, Vec<C::PublicKey>)> {
        self.deserialize_aggregation(proof, max, check_sigs, &self.finalize_namespace)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn serialize_conflicting_proposal(
        view: View,
        public_key: &C::PublicKey,
        parent_1: View,
        payload_1: &D,
        signature_1: &C::Signature,
        parent_2: View,
        payload_2: &D,
        signature_2: &C::Signature,
    ) -> Proof {
        // Setup proof
        let len = size_of::<u64>()
            + size_of::<C::PublicKey>()
            + size_of::<u64>()
            + size_of::<D>()
            + size_of::<C::Signature>()
            + size_of::<u64>()
            + size_of::<D>()
            + size_of::<C::Signature>();

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
    ) -> Option<(C::PublicKey, View)> {
        // Ensure proof is big enough
        let len = size_of::<u64>()
            + size_of::<C::PublicKey>()
            + size_of::<u64>()
            + size_of::<D>()
            + size_of::<C::Signature>()
            + size_of::<u64>()
            + size_of::<D>()
            + size_of::<C::Signature>();
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let public_key = C::PublicKey::read_from(&mut proof).ok()?;
        let parent_1 = proof.get_u64();
        let payload_1 = D::read_from(&mut proof).ok()?;
        let signature_1 = C::Signature::read_from(&mut proof).ok()?;
        let parent_2 = proof.get_u64();
        let payload_2 = D::read_from(&mut proof).ok()?;
        let signature_2 = C::Signature::read_from(&mut proof).ok()?;

        // Verify signatures
        if check_sig {
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
        public_key: &C::PublicKey,
        parent_1: View,
        payload_1: &D,
        signature_1: &C::Signature,
        parent_2: View,
        payload_2: &D,
        signature_2: &C::Signature,
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
    ) -> Option<(C::PublicKey, View)> {
        self.deserialize_conflicting_proposal(proof, check_sig, &self.notarize_namespace)
    }

    /// Serialize a conflicting finalize proof.
    #[allow(clippy::too_many_arguments)]
    pub fn serialize_conflicting_finalize(
        view: View,
        public_key: &C::PublicKey,
        parent_1: View,
        payload_1: &D,
        signature_1: &C::Signature,
        parent_2: View,
        payload_2: &D,
        signature_2: &C::Signature,
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
    ) -> Option<(C::PublicKey, View)> {
        self.deserialize_conflicting_proposal(proof, check_sig, &self.finalize_namespace)
    }

    /// Serialize a conflicting nullify and finalize proof.
    pub fn serialize_nullify_finalize(
        view: View,
        public_key: &C::PublicKey,
        parent: View,
        payload: &D,
        signature_finalize: &C::Signature,
        signature_null: &C::Signature,
    ) -> Proof {
        // Setup proof
        let len = size_of::<u64>()
            + size_of::<C::PublicKey>()
            + size_of::<u64>()
            + size_of::<D>()
            + size_of::<C::Signature>()
            + size_of::<C::Signature>();

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
    ) -> Option<(C::PublicKey, View)> {
        // Ensure proof is big enough
        let len = size_of::<u64>()
            + size_of::<C::PublicKey>()
            + size_of::<u64>()
            + size_of::<D>()
            + size_of::<C::Signature>()
            + size_of::<C::Signature>();
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let public_key = C::PublicKey::read_from(&mut proof).ok()?;
        let parent = proof.get_u64();
        let payload = D::read_from(&mut proof).ok()?;
        let signature_finalize = C::Signature::read_from(&mut proof).ok()?;
        let signature_null = C::Signature::read_from(&mut proof).ok()?;

        // Verify signatures
        if check_sig {
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
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Ed25519};

    fn test_digest(value: u8) -> Sha256Digest {
        Sha256Digest::from([value; size_of::<Sha256Digest>()])
    }

    #[test]
    fn test_deserialize_aggregation_empty() {
        // Create a proof with no signers
        let prover = Prover::<Ed25519, Sha256Digest>::new(b"test");
        let mut proof = Vec::new();
        proof.put_u64(1); // view
        proof.put_u64(0); // parent
        proof.extend_from_slice(&test_digest(0)); // payload
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
        proof.extend_from_slice(&test_digest(0)); // payload

        // Verify that the proof is rejected
        let prover = Prover::<Ed25519, Sha256Digest>::new(b"test");
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
        proof.extend_from_slice(&test_digest(0)); // payload
        proof.put_u32(100);

        // Verify that the proof is rejected
        let prover = Prover::<Ed25519, Sha256Digest>::new(b"test");
        let result = prover.deserialize_aggregation(
            proof.into(),
            u32::MAX, // Allow any count to test overflow protection
            false,
            &prover.notarize_namespace,
        );
        assert!(result.is_none());
    }
}
