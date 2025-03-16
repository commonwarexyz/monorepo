use super::{
    encoder::{
        finalize_namespace, notarize_namespace, nullify_message, nullify_namespace,
        proposal_message, seed_message, seed_namespace,
    },
    wire, View,
};
use crate::Proof;
use bytes::{Buf, BufMut};
use commonware_cryptography::bls12381::primitives::{
    group::{self, Element},
    ops,
    poly::{self, Eval},
};
use commonware_cryptography::Digest;
use commonware_utils::SizedSerialize;
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
pub struct Prover<D: Digest> {
    public: group::Public,

    seed_namespace: Vec<u8>,
    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,

    _digest: PhantomData<D>,
}

/// If we expose partial signatures of proofs, can be used to construct a partial signature
/// over pre-aggregated data (where the public key of each index can be derived from the group
/// polynomial). This can be very useful for distributing rewards without including all partial signatures
/// in a block.
impl<D: Digest> Prover<D> {
    /// Create a new prover with the given signing `namespace`.
    pub fn new(public: group::Public, namespace: &[u8]) -> Self {
        Self {
            public,

            seed_namespace: seed_namespace(namespace),
            notarize_namespace: notarize_namespace(namespace),
            nullify_namespace: nullify_namespace(namespace),
            finalize_namespace: finalize_namespace(namespace),

            _digest: PhantomData,
        }
    }

    /// Serialize a proposal proof.
    pub fn serialize_proposal(proposal: &wire::Proposal, partial_signature: &[u8]) -> Proof {
        // Setup proof
        let len = u64::SERIALIZED_LEN
            + u64::SERIALIZED_LEN
            + D::SERIALIZED_LEN
            + poly::PARTIAL_SIGNATURE_LENGTH;

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
        &self,
        mut proof: Proof,
        namespace: &[u8],
    ) -> Option<(View, View, D, Verifier)> {
        // Ensure proof is big enough
        let expected_len = u64::SERIALIZED_LEN
            + u64::SERIALIZED_LEN
            + D::SERIALIZED_LEN
            + poly::PARTIAL_SIGNATURE_LENGTH;
        if proof.len() != expected_len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = D::read_from(&mut proof).ok()?;
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
    pub fn serialize_threshold(proposal: &wire::Proposal, signature: &[u8], seed: &[u8]) -> Proof {
        // Setup proof
        let len = u64::SERIALIZED_LEN
            + u64::SERIALIZED_LEN
            + D::SERIALIZED_LEN
            + group::SIGNATURE_LENGTH
            + group::SIGNATURE_LENGTH;

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
    ) -> Option<(View, View, D, group::Signature, group::Signature)> {
        // Ensure proof prefix is big enough
        let expected_len = u64::SERIALIZED_LEN
            + u64::SERIALIZED_LEN
            + D::SERIALIZED_LEN
            + group::SIGNATURE_LENGTH
            + group::SIGNATURE_LENGTH;
        if proof.len() != expected_len {
            return None;
        }

        // Verify signature
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = D::read_from(&mut proof).ok()?;
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
    pub fn deserialize_notarize(&self, proof: Proof) -> Option<(View, View, D, Verifier)> {
        Self::deserialize_proposal(self, proof, &self.notarize_namespace)
    }

    /// Deserialize a notarization proof.
    pub fn deserialize_notarization(
        &self,
        proof: Proof,
    ) -> Option<(View, View, D, group::Signature, group::Signature)> {
        self.deserialize_threshold(proof, &self.notarize_namespace)
    }

    /// Deserialize a finalize proof.
    pub fn deserialize_finalize(&self, proof: Proof) -> Option<(View, View, D, Verifier)> {
        self.deserialize_proposal(proof, &self.finalize_namespace)
    }

    /// Deserialize a finalization proof.
    pub fn deserialize_finalization(
        &self,
        proof: Proof,
    ) -> Option<(View, View, D, group::Signature, group::Signature)> {
        self.deserialize_threshold(proof, &self.finalize_namespace)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn serialize_conflicting_proposal(
        view: View,
        parent_1: View,
        payload_1: &D,
        signature_1: &[u8],
        parent_2: View,
        payload_2: &D,
        signature_2: &[u8],
    ) -> Proof {
        // Setup proof
        let len = u64::SERIALIZED_LEN
            + u64::SERIALIZED_LEN
            + D::SERIALIZED_LEN
            + poly::PARTIAL_SIGNATURE_LENGTH
            + u64::SERIALIZED_LEN
            + D::SERIALIZED_LEN
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
        &self,
        mut proof: Proof,
        namespace: &[u8],
    ) -> Option<(View, Verifier)> {
        // Ensure proof is big enough
        let expected_len = u64::SERIALIZED_LEN
            + u64::SERIALIZED_LEN
            + D::SERIALIZED_LEN
            + poly::PARTIAL_SIGNATURE_LENGTH
            + u64::SERIALIZED_LEN
            + D::SERIALIZED_LEN
            + poly::PARTIAL_SIGNATURE_LENGTH;
        if proof.len() != expected_len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let parent_1 = proof.get_u64();
        let payload_1 = D::read_from(&mut proof).ok()?;
        let signature_1 = proof.copy_to_bytes(poly::PARTIAL_SIGNATURE_LENGTH);
        let signature_1 = Eval::deserialize(&signature_1)?;
        let parent_2 = proof.get_u64();
        let payload_2 = D::read_from(&mut proof).ok()?;
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
        payload_1: &D,
        signature_1: &[u8],
        parent_2: View,
        payload_2: &D,
        signature_2: &[u8],
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
        self.deserialize_conflicting_proposal(proof, &self.notarize_namespace)
    }

    /// Serialize a conflicting finalize proof.
    #[allow(clippy::too_many_arguments)]
    pub fn serialize_conflicting_finalize(
        view: View,
        parent_1: View,
        payload_1: &D,
        signature_1: &[u8],
        parent_2: View,
        payload_2: &D,
        signature_2: &[u8],
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
        self.deserialize_conflicting_proposal(proof, &self.finalize_namespace)
    }

    /// Serialize a conflicting nullify and finalize proof.
    pub fn serialize_nullify_finalize(
        view: View,
        parent: View,
        payload: &D,
        signature_finalize: &[u8],
        signature_null: &[u8],
    ) -> Proof {
        // Setup proof
        let len = u64::SERIALIZED_LEN
            + u64::SERIALIZED_LEN
            + D::SERIALIZED_LEN
            + poly::PARTIAL_SIGNATURE_LENGTH
            + poly::PARTIAL_SIGNATURE_LENGTH;

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
        let expected_len = u64::SERIALIZED_LEN
            + u64::SERIALIZED_LEN
            + D::SERIALIZED_LEN
            + poly::PARTIAL_SIGNATURE_LENGTH
            + poly::PARTIAL_SIGNATURE_LENGTH;
        if proof.len() != expected_len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = D::read_from(&mut proof).ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        bls12381::{
            dkg::ops::generate_shares,
            primitives::group::{self, Share},
        },
        sha256::Digest as Sha256Digest,
        Hasher, Sha256,
    };
    use ops::{keypair, partial_sign_message, sign_message};
    use rand::{rngs::StdRng, SeedableRng};

    fn generate_threshold() -> (group::Public, poly::Public, Vec<Share>) {
        let mut sampler = StdRng::seed_from_u64(0);
        let (public, shares) = generate_shares(&mut sampler, None, 4, 3);
        (*poly::public(&public), public, shares)
    }

    fn generate_keypair() -> (group::Private, group::Public) {
        let mut sampler = StdRng::seed_from_u64(0);
        keypair(&mut sampler)
    }

    fn test_digest(value: u8) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(&[value]);
        hasher.finalize()
    }

    #[test]
    fn test_deserialize_proposal() {
        // Create valid signature
        let (public, poly, shares) = generate_threshold();
        let prover = Prover::<Sha256Digest>::new(public, b"test");
        let payload = test_digest(0);
        let signature = partial_sign_message(
            &shares[0],
            Some(&prover.seed_namespace),
            &proposal_message(1, 0, &payload),
        )
        .serialize();

        // Create a proof with a length that would cause overflow
        let mut proof = Vec::new();
        proof.put_u64(1); // view
        proof.put_u64(0); // parent
        proof.extend_from_slice(&payload); // payload
        proof.extend_from_slice(&signature); // signature

        // Verify correct proof
        let (_, _, _, verifier) = prover
            .deserialize_proposal(proof.into(), &prover.notarize_namespace)
            .unwrap();
        assert!(verifier.verify(&poly).is_none());
    }

    #[test]
    fn test_deserialize_proposal_invalid() {
        // Create valid signature
        let (public, poly, shares) = generate_threshold();
        let prover = Prover::<Sha256Digest>::new(public, b"test");
        let payload = test_digest(0);
        let signature = partial_sign_message(
            &shares[0],
            Some(&prover.seed_namespace),
            &proposal_message(1, 1, &payload),
        )
        .serialize();

        // Create a proof with a length that would cause overflow
        let mut proof = Vec::new();
        proof.put_u64(1); // view
        proof.put_u64(0); // parent
        proof.extend_from_slice(&payload); // payload
        proof.extend_from_slice(&signature); // invalid signature

        // Verify bad signature
        let (_, _, _, verifier) = prover
            .deserialize_proposal(proof.into(), &prover.notarize_namespace)
            .unwrap();
        assert!(verifier.verify(&poly).is_none());
    }

    #[test]
    fn test_deserialize_proposal_underflow() {
        // Create valid signature
        let (public, _, shares) = generate_threshold();
        let prover = Prover::<Sha256Digest>::new(public, b"test");
        let payload = test_digest(0);
        let signature = partial_sign_message(
            &shares[0],
            Some(&prover.seed_namespace),
            &proposal_message(1, 0, &payload),
        )
        .serialize();

        // Shorten signature
        let signature = signature[0..group::SIGNATURE_LENGTH - 1].to_vec();

        // Create a proof with a length that would cause overflow
        let mut proof = Vec::new();
        proof.put_u64(1); // view
        proof.put_u64(0); // parent
        proof.extend_from_slice(&payload); // payload
        proof.extend_from_slice(&signature); // undersized signature

        // Verify bad proof
        let result = prover.deserialize_proposal(proof.into(), &prover.notarize_namespace);
        assert!(result.is_none());
    }

    #[test]
    fn test_deserialize_proposal_overflow() {
        // Create valid signature
        let (public, _, shares) = generate_threshold();
        let prover = Prover::<Sha256Digest>::new(public, b"test");
        let payload = test_digest(0);
        let signature = partial_sign_message(
            &shares[0],
            Some(&prover.seed_namespace),
            &proposal_message(1, 0, &payload),
        )
        .serialize();

        // Extend signature
        let signature = [signature, vec![0; 1]].concat();

        // Create a proof with a length that would cause overflow
        let mut proof = Vec::new();
        proof.put_u64(1); // view
        proof.put_u64(0); // parent
        proof.extend_from_slice(&payload); // payload
        proof.extend_from_slice(&signature); // oversized signature

        // Verify bad proof
        let result = prover.deserialize_proposal(proof.into(), &prover.notarize_namespace);
        assert!(result.is_none());
    }

    #[test]
    fn test_deserialize_threshold() {
        // Create valid signature
        let (private, public) = generate_keypair();
        let prover = Prover::<Sha256Digest>::new(public, b"test");

        // Generate a valid signature
        let payload = test_digest(0);
        let proposal_signature = sign_message(
            &private,
            Some(&prover.notarize_namespace),
            &proposal_message(1, 0, &payload),
        )
        .serialize();
        let seed_signature =
            sign_message(&private, Some(&prover.seed_namespace), &seed_message(1)).serialize();

        // Create a proof with a length that would cause overflow
        let mut proof = Vec::new();
        proof.put_u64(1); // view
        proof.put_u64(0); // parent
        proof.extend_from_slice(&payload); // payload
        proof.extend_from_slice(&proposal_signature); // proposal signature
        proof.extend_from_slice(&seed_signature); // seed signature

        // Verify correct proof
        let result = prover.deserialize_threshold(proof.into(), &prover.notarize_namespace);
        assert!(result.is_some());
    }

    #[test]
    fn test_deserialize_threshold_invalid() {
        // Create valid signature
        let (private, public) = generate_keypair();
        let prover = Prover::<Sha256Digest>::new(public, b"test");

        // Generate a valid signature
        let payload = test_digest(0);
        let proposal_signature = sign_message(
            &private,
            Some(&prover.notarize_namespace),
            &proposal_message(1, 0, &payload),
        )
        .serialize();
        let seed_signature =
            sign_message(&private, Some(&prover.seed_namespace), &seed_message(2)).serialize();

        // Create a proof with a length that would cause overflow
        let mut proof = Vec::new();
        proof.put_u64(1); // view
        proof.put_u64(0); // parent
        proof.extend_from_slice(&payload); // payload
        proof.extend_from_slice(&proposal_signature); // proposal signature
        proof.extend_from_slice(&seed_signature); // invalid signature

        // Verify correct proof
        let result = prover.deserialize_threshold(proof.into(), &prover.notarize_namespace);
        assert!(result.is_none());
    }

    #[test]
    fn test_deserialize_threshold_underflow() {
        // Create valid signature
        let (private, public) = generate_keypair();
        let prover = Prover::<Sha256Digest>::new(public, b"test");

        // Generate a valid signature
        let payload = test_digest(0);
        let proposal_signature = sign_message(
            &private,
            Some(&prover.notarize_namespace),
            &proposal_message(1, 0, &payload),
        )
        .serialize();
        let seed_signature =
            sign_message(&private, Some(&prover.seed_namespace), &seed_message(1)).serialize();

        // Shorten seed signature
        let seed_signature = seed_signature[0..group::SIGNATURE_LENGTH - 1].to_vec();

        // Create a proof with a length that would cause overflow
        let mut proof = Vec::new();
        proof.put_u64(1); // view
        proof.put_u64(0); // parent
        proof.extend_from_slice(&payload); // payload
        proof.extend_from_slice(&proposal_signature); // proposal signature
        proof.extend_from_slice(&seed_signature); // undersized signature

        // Verify correct proof
        let result = prover.deserialize_threshold(proof.into(), &prover.notarize_namespace);
        assert!(result.is_none());
    }

    #[test]
    fn test_deserialize_threshold_overflow() {
        // Create valid signature
        let (private, public) = generate_keypair();
        let prover = Prover::<Sha256Digest>::new(public, b"test");

        // Generate a valid signature
        let payload = test_digest(0);
        let proposal_signature = sign_message(
            &private,
            Some(&prover.notarize_namespace),
            &proposal_message(1, 0, &payload),
        )
        .serialize();
        let seed_signature =
            sign_message(&private, Some(&prover.seed_namespace), &seed_message(1)).serialize();

        // Extend seed signature
        let seed_signature = [seed_signature, vec![0; 1]].concat();

        // Create a proof with a length that would cause overflow
        let mut proof = Vec::new();
        proof.put_u64(1); // view
        proof.put_u64(0); // parent
        proof.extend_from_slice(&payload); // payload
        proof.extend_from_slice(&proposal_signature); // proposal signature
        proof.extend_from_slice(&seed_signature); // oversized signature

        // Verify correct proof
        let result = prover.deserialize_threshold(proof.into(), &prover.notarize_namespace);
        assert!(result.is_none());
    }
}
