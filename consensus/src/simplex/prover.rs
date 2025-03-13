use super::{
    encoder::{
        finalize_namespace, notarize_namespace, nullify_message, nullify_namespace,
        proposal_message,
    },
    wire, View,
};
use crate::Proof;
use bytes::{Buf, BufMut};
use commonware_cryptography::Scheme;
use commonware_utils::Array;
use std::{collections::HashSet, marker::PhantomData};

/// Encode and decode proofs of activity.
///
/// We don't use protobuf for proof encoding because we expect external parties
/// to decode proofs in constrained environments where protobuf may not be implemented.
#[derive(Clone)]
pub struct Prover<C: Scheme, D: Array> {
    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,

    _crypto: PhantomData<C>,
    _digest: PhantomData<D>,
}

impl<C: Scheme, D: Array> Prover<C, D> {
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
        let len = u64::LEN_CODEC
            + u64::LEN_CODEC
            + D::LEN_CODEC
            + C::PublicKey::LEN_CODEC
            + C::Signature::LEN_CODEC;

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
            != u64::LEN_CODEC
                + u64::LEN_CODEC
                + D::LEN_CODEC
                + C::PublicKey::LEN_CODEC
                + C::Signature::LEN_CODEC
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
        signatures: Vec<(&C::PublicKey, C::Signature)>,
    ) -> Proof {
        // Setup proof
        let len = u64::LEN_CODEC
            + u64::LEN_CODEC
            + D::LEN_CODEC
            + u32::LEN_CODEC
            + signatures.len() * (C::PublicKey::LEN_CODEC + C::Signature::LEN_CODEC);

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(proposal.view);
        proof.put_u64(proposal.parent);
        proof.extend_from_slice(&proposal.payload);
        proof.put_u32(signatures.len() as u32);
        for (public_key, signature) in signatures {
            proof.extend_from_slice(public_key);
            proof.extend_from_slice(&signature);
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
        let len = u64::LEN_CODEC + u64::LEN_CODEC + D::LEN_CODEC + u32::LEN_CODEC;
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
        let item_size = C::PublicKey::LEN_CODEC.checked_add(C::Signature::LEN_CODEC)?;
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

            // Read signature
            let signature = C::Signature::read_from(&mut proof).ok()?;

            // Verify signature
            if check_sigs && !C::verify(Some(namespace), &message, &public_key, &signature) {
                return None;
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
        let len = u64::LEN_CODEC
            + C::PublicKey::LEN_CODEC
            + u64::LEN_CODEC
            + D::LEN_CODEC
            + C::Signature::LEN_CODEC
            + u64::LEN_CODEC
            + D::LEN_CODEC
            + C::Signature::LEN_CODEC;

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
        let len = u64::LEN_CODEC
            + C::PublicKey::LEN_CODEC
            + u64::LEN_CODEC
            + D::LEN_CODEC
            + C::Signature::LEN_CODEC
            + u64::LEN_CODEC
            + D::LEN_CODEC
            + C::Signature::LEN_CODEC;
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
        let len = u64::LEN_CODEC
            + C::PublicKey::LEN_CODEC
            + u64::LEN_CODEC
            + D::LEN_CODEC
            + C::Signature::LEN_CODEC
            + C::Signature::LEN_CODEC;

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
        let len = u64::LEN_CODEC
            + C::PublicKey::LEN_CODEC
            + u64::LEN_CODEC
            + D::LEN_CODEC
            + C::Signature::LEN_CODEC
            + C::Signature::LEN_CODEC;
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
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Ed25519, Hasher, Sha256};
    use rand::SeedableRng;

    fn test_digest(value: u8) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(&[value]);
        hasher.finalize()
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

    #[test]
    fn test_deserialize_aggregation() {
        // Verify correctness with and without checking signatures
        for checked in [true, false] {
            // Create a proposal to sign
            let (view, parent, payload) = (1, 0, test_digest(0));
            let proposal = wire::Proposal {
                view,
                parent,
                payload: payload.to_vec(),
            };
            let message = proposal_message(view, parent, &payload);

            // Sign the message with 3 different signers
            const NAMESPACE: &[u8] = b"test";
            let mut rng = rand::rngs::StdRng::seed_from_u64(0);
            let mut signers: Vec<_> = (0..3).map(|_| Ed25519::new(&mut rng)).collect();
            let pub_keys = signers
                .iter()
                .map(|signer| signer.public_key())
                .collect::<Vec<_>>();
            let sigs = signers
                .iter_mut()
                .map(|signer| signer.sign(Some(NAMESPACE), &message))
                .collect::<Vec<_>>();
            let keys_and_sigs = pub_keys.iter().zip(sigs).collect();

            // Should be able to deserialize the serialized proof
            let proof =
                Prover::<Ed25519, Sha256Digest>::serialize_aggregation(&proposal, keys_and_sigs);
            let prover = Prover::<Ed25519, Sha256Digest>::new(NAMESPACE);
            let result = prover.deserialize_aggregation(proof, u32::MAX, checked, NAMESPACE);

            // Deserialized proof should match the content of the original proof
            let (view, parent, payload, signers) = result.expect("unable to deserialize proof");
            assert_eq!(view, proposal.view);
            assert_eq!(parent, proposal.parent);
            assert_eq!(payload.as_ref(), &proposal.payload);
            assert_eq!(signers.len(), 3);
            for public_key in pub_keys.iter() {
                assert!(signers.contains(public_key));
            }
        }
    }
}
