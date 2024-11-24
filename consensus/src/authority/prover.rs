//! Prover module for the authority node.
//!
//! We don't use protobuf for proof encoding because we expect external parties
//! to decode proofs in constrained environments where protobuf may not be implemented.

use super::{
    encoder::{
        finalize_namespace, notarize_namespace, nullify_message, nullify_namespace,
        proposal_message,
    },
    wire, View,
};
use crate::Proof;
use bytes::{Buf, BufMut, Bytes};
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
use core::panic;
use std::{collections::HashSet, marker::PhantomData};

#[derive(Clone)]
pub struct Prover<C: Scheme, H: Hasher> {
    _crypto: PhantomData<C>,
    hasher: H,

    notarize_namespace: Vec<u8>,
    nullify_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,
}

impl<C: Scheme, H: Hasher> Prover<C, H> {
    pub fn new(hasher: H, namespace: Bytes) -> Self {
        Self {
            _crypto: PhantomData,
            hasher,

            notarize_namespace: notarize_namespace(&namespace),
            nullify_namespace: nullify_namespace(&namespace),
            finalize_namespace: finalize_namespace(&namespace),
        }
    }

    fn serialize_proposal(
        view: View,
        parent: View,
        payload: &Digest,
        signature: &wire::Signature,
    ) -> Proof {
        // Setup proof
        let len = 8 + 8 + payload.len() + signature.public_key.len() + signature.signature.len();

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(view);
        proof.put_u64(parent);
        proof.extend_from_slice(payload);
        proof.extend_from_slice(&signature.public_key);
        proof.extend_from_slice(&signature.signature);
        proof.into()
    }

    fn deserialize_proposal(
        mut proof: Proof,
        check_sig: bool,
        namespace: &[u8],
    ) -> Option<(View, View, Digest, PublicKey)> {
        // Ensure proof is big enough
        let digest_len = H::len();
        let (public_key_len, signature_len) = C::len();
        if proof.len() != 8 + 8 + digest_len + public_key_len + signature_len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(digest_len);
        let public_key = proof.copy_to_bytes(public_key_len);
        let signature = proof.copy_to_bytes(signature_len);

        // Verify signature
        let proposal_message = proposal_message(view, parent, &payload);
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            if !C::verify(namespace, &proposal_message, &public_key, &signature) {
                return None;
            }
        }

        Some((view, parent, payload, public_key))
    }

    fn serialize_aggregation(
        view: View,
        parent: View,
        payload: &Digest,
        signatures: &[wire::Signature],
    ) -> Proof {
        // Setup proof
        let (public_key_len, signature_len) = C::len();
        let len = 8 + 8 + payload.len() + 4 + signatures.len() * (public_key_len + signature_len);

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(view);
        proof.put_u64(parent);
        proof.extend_from_slice(&payload);
        proof.put_u32(signatures.len() as u32);
        for signature in signatures {
            proof.extend_from_slice(&signature.public_key);
            proof.extend_from_slice(&signature.signature);
        }
        proof.into()
    }

    fn deserialize_aggregation(
        mut proof: Proof,
        max: u32,
        check_sigs: bool,
        namespace: &[u8],
    ) -> Option<(View, View, Digest, Vec<PublicKey>)> {
        // Ensure proof prefix is big enough
        let digest_len = H::len();
        let len = 8 + 8 + digest_len + 4;
        if proof.len() < len {
            return None;
        }

        // Decode proof prefix
        let view = proof.get_u64();
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(digest_len);
        let count = proof.get_u32();
        if count > max {
            return None;
        }
        let count = count as usize;
        let message = proposal_message(view, parent, &payload);

        // Decode signatures
        let (public_key_len, signature_len) = C::len();
        if proof.remaining() != count * (public_key_len + signature_len) {
            return None;
        }
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
                if !C::verify(namespace, &message, &public_key, &signature) {
                    return None;
                }
            }
        }
        Some((view, parent, payload, seen.into_iter().collect()))
    }

    pub(crate) fn serialize_notarize(notarize: &wire::Notarize) -> Proof {
        // Extract proposal
        let proposal = notarize.proposal.as_ref().expect("missing proposal");

        // Setup proof
        Self::serialize_proposal(
            proposal.view,
            proposal.parent,
            &proposal.payload,
            notarize.signature.as_ref().expect("missing signature"),
        )
    }

    pub fn deserialize_notarize(
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(View, View, Digest, PublicKey)> {
        Self::deserialize_proposal(proof, check_sig, &self.notarize_namespace)
    }

    pub(crate) fn serialize_notarization(notarization: &wire::Notarization) -> Proof {
        // Extract proposal
        let proposal = notarization.proposal.as_ref().expect("missing proposal");

        // Setup proof
        Self::serialize_aggregation(
            proposal.view,
            proposal.parent,
            &proposal.payload,
            &notarization.signatures,
        )
    }

    pub fn deserialize_notarization(
        &self,
        proof: Proof,
        max: u32,
        check_sigs: bool,
    ) -> Option<(View, View, Digest, Vec<PublicKey>)> {
        Self::deserialize_aggregation(proof, max, check_sigs, &self.notarize_namespace)
    }

    pub(crate) fn serialize_finalize(finalize: &wire::Finalize) -> Proof {
        // Extract proposal
        let proposal = finalize.proposal.as_ref().expect("missing proposal");

        // Setup proof
        Self::serialize_proposal(
            proposal.view,
            proposal.parent,
            &proposal.payload,
            finalize.signature.as_ref().expect("missing signature"),
        )
    }

    pub fn deserialize_finalize(
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(View, View, Digest, PublicKey)> {
        Self::deserialize_proposal(proof, check_sig, &self.finalize_namespace)
    }

    pub(crate) fn serialize_finalization(finalization: &wire::Finalization) -> Proof {
        // Extract proposal
        let proposal = finalization.proposal.as_ref().expect("missing proposal");

        // Setup proof
        Self::serialize_aggregation(
            proposal.view,
            proposal.parent,
            &proposal.payload,
            &finalization.signatures,
        )
    }

    pub fn deserialize_finalization(
        &self,
        proof: Proof,
        max: u32,
        check_sigs: bool,
    ) -> Option<(View, View, Digest, Vec<PublicKey>)> {
        Self::deserialize_aggregation(proof, max, check_sigs, &self.finalize_namespace)
    }

    pub(crate) fn serialize_conflicting_proposal(
        view_1: View,
        parent_1: View,
        payload_1: &Digest,
        signature_1: &wire::Signature,
        view_2: View,
        parent_2: View,
        payload_2: &Digest,
        signature_2: &wire::Signature,
    ) -> Proof {
        // Setup proof
        let digest_len = H::len();
        let (public_key_len, signature_len) = C::len();
        let len =
            8 + public_key_len + 8 + digest_len + signature_len + 8 + digest_len + signature_len;

        // Ensure proof can be generated correctly
        if view_1 != view_2 {
            panic!("views do not match");
        }
        let view = view_1;
        if signature_1.public_key != signature_2.public_key {
            panic!("public keys do not match");
        }
        let public_key = signature_1.public_key.as_ref();

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(view);
        proof.put(public_key);
        proof.put_u64(parent_1);
        proof.extend_from_slice(&payload_1);
        proof.extend_from_slice(&signature_1.signature);
        proof.put_u64(parent_2);
        proof.extend_from_slice(&payload_2);
        proof.extend_from_slice(&signature_2.signature);
        proof.into()
    }

    pub fn deserialize_conflicting_proposal(
        mut proof: Proof,
        check_sig: bool,
        namespace: &[u8],
    ) -> Option<(PublicKey, View)> {
        // Ensure proof is big enough
        let digest_len = H::len();
        let (public_key_len, signature_len) = C::len();
        let len =
            8 + public_key_len + 8 + digest_len + signature_len + 8 + digest_len + signature_len;
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let public_key = proof.copy_to_bytes(public_key_len);
        let parent_1 = proof.get_u64();
        let payload_1 = proof.copy_to_bytes(digest_len);
        let signature_1 = proof.copy_to_bytes(signature_len);
        let parent_2 = proof.get_u64();
        let payload_2 = proof.copy_to_bytes(digest_len);
        let signature_2 = proof.copy_to_bytes(signature_len);

        // Verify signatures
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            let proposal_message_1 = proposal_message(view, parent_1, &payload_1);
            let proposal_message_2 = proposal_message(view, parent_2, &payload_2);
            if !C::verify(namespace, &proposal_message_1, &public_key, &signature_1)
                || !C::verify(namespace, &proposal_message_2, &public_key, &signature_2)
            {
                return None;
            }
        }
        Some((public_key, view))
    }

    pub(crate) fn serialize_conflicting_notarize(
        view_1: View,
        parent_1: View,
        payload_1: &Digest,
        signature_1: &wire::Signature,
        view_2: View,
        parent_2: View,
        payload_2: &Digest,
        signature_2: &wire::Signature,
    ) -> Proof {
        Self::serialize_conflicting_proposal(
            view_1,
            parent_1,
            payload_1,
            signature_1,
            view_2,
            parent_2,
            payload_2,
            signature_2,
        )
    }

    pub fn deserialize_conflicting_notarize(
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View)> {
        Self::deserialize_conflicting_proposal(proof, check_sig, &self.notarize_namespace)
    }

    pub(crate) fn serialize_conflicting_finalize(
        view_1: View,
        parent_1: View,
        payload_1: &Digest,
        signature_1: &wire::Signature,
        view_2: View,
        parent_2: View,
        payload_2: &Digest,
        signature_2: &wire::Signature,
    ) -> Proof {
        Self::serialize_conflicting_proposal(
            view_1,
            parent_1,
            payload_1,
            signature_1,
            view_2,
            parent_2,
            payload_2,
            signature_2,
        )
    }

    pub fn deserialize_conflicting_finalize(
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View)> {
        Self::deserialize_conflicting_proposal(proof, check_sig, &self.finalize_namespace)
    }

    pub(crate) fn serialize_nullify_finalize(
        view: View,
        parent: View,
        payload: &Digest,
        signature_finalize: &wire::Signature,
        signature_null: &wire::Signature,
    ) -> Proof {
        // Setup proof
        let digest_len = H::len();
        let (public_key_len, signature_len) = C::len();
        let len = 8 + public_key_len + 8 + digest_len + signature_len + signature_len;

        // Ensure proof can be generated correctly
        if signature_finalize.public_key != signature_null.public_key {
            panic!("public keys do not match");
        }
        let public_key = signature_finalize.public_key.as_ref();

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(view);
        proof.put(public_key);
        proof.put_u64(parent);
        proof.extend_from_slice(payload);
        proof.extend_from_slice(&signature_finalize.signature);
        proof.extend_from_slice(&signature_null.signature);
        proof.into()
    }

    pub fn deserialize_nullify_finalize(
        &self,
        mut proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View)> {
        // Ensure proof is big enough
        let digest_len = H::len();
        let (public_key_len, signature_len) = C::len();
        let len = 8 + public_key_len + 8 + digest_len + signature_len + signature_len;
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let public_key = proof.copy_to_bytes(public_key_len);
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(digest_len);
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
                &self.finalize_namespace,
                &finalize_message,
                &public_key,
                &signature_finalize,
            ) || !C::verify(
                &self.nullify_namespace,
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
