//! Prover module for the authority node.
//!
//! We don't use protobuf for proof encoding because we expect external parties
//! to decode proofs in constrained environments where protobuf may not be implemented.

use super::{
    encoder::{
        finalize_namespace, header_namespace, null_message, proposal_message, vote_namespace,
    },
    wire, Height, View,
};
use crate::Proof;
use bytes::{Buf, BufMut, Bytes};
use commonware_cryptography::{Digest, Hasher, PublicKey, Scheme};
use core::panic;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Prover<C: Scheme, H: Hasher> {
    _crypto: PhantomData<C>,
    hasher: H,

    header_namespace: Vec<u8>,
    vote_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,
}

impl<C: Scheme, H: Hasher> Prover<C, H> {
    pub fn new(hasher: H, namespace: Bytes) -> Self {
        Self {
            _crypto: PhantomData,
            hasher,

            header_namespace: header_namespace(&namespace),
            vote_namespace: vote_namespace(&namespace),
            finalize_namespace: finalize_namespace(&namespace),
        }
    }

    fn serialize_proposal(
        view: View,
        height: Height,
        parent: View,
        payload: Digest,
        signature: wire::Signature,
    ) -> Proof {
        // Setup proof
        let digest_len = H::len();
        let (public_key_len, signature_len) = C::len();
        let len = 8 + 8 + 8 + digest_len + public_key_len + signature_len;
        let mut proof = Vec::with_capacity(len);

        // Encode proof
        proof.put_u64(view);
        proof.put_u64(height);
        proof.put_u64(parent);
        proof.put(payload);
        proof.put(signature.public_key);
        proof.put(signature.signature);
        proof.into()
    }

    fn deserialize_proposal(
        mut proof: Proof,
        check_sig: bool,
        namespace: &[u8],
    ) -> Option<(View, Height, View, Digest, PublicKey)> {
        // Ensure proof is big enough
        let digest_len = H::len();
        let (public_key_len, signature_len) = C::len();
        if proof.len() != 8 + 8 + 8 + digest_len + public_key_len + signature_len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let height = proof.get_u64();
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(digest_len);
        let public_key = proof.copy_to_bytes(public_key_len);
        let signature = proof.copy_to_bytes(signature_len);

        // Verify signature
        let proposal_message = proposal_message(view, height, parent, &payload);
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            if !C::verify(namespace, &proposal_message, &public_key, &signature) {
                return None;
            }
        }

        Some((view, height, parent, payload, public_key))
    }

    pub(crate) fn serialize_header(
        view: View,
        height: Height,
        parent: View,
        payload: Digest,
        signature: wire::Signature,
    ) -> Proof {
        Self::serialize_proposal(view, height, parent, payload, signature)
    }

    pub fn deserialize_header(
        &mut self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(View, Height, View, Digest, PublicKey)> {
        Self::deserialize_proposal(proof, check_sig, &self.header_namespace)
    }

    pub(crate) fn serialize_vote(vote: wire::Vote) -> Proof {
        // Extract container
        let container = vote.container.unwrap().payload.unwrap();
        let proposal = match container {
            wire::container::Payload::Proposal(proposal) => proposal,
            _ => panic!("invalid container"),
        };

        // Setup proof
        Self::serialize_proposal(
            proposal.view,
            proposal.height,
            proposal.parent,
            proposal.payload,
            vote.signature.unwrap(),
        )
    }

    pub fn deserialize_vote(
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(View, Height, View, Digest, PublicKey)> {
        Self::deserialize_proposal(proof, check_sig, &self.vote_namespace)
    }

    pub(crate) fn serialize_finalize(finalize: wire::Finalize) -> Proof {
        // Extract container
        let container = finalize.container.unwrap().payload.unwrap();
        let proposal = match container {
            wire::container::Payload::Proposal(proposal) => proposal,
            _ => panic!("invalid container"),
        };

        // Setup proof
        Self::serialize_proposal(
            proposal.view,
            proposal.height,
            proposal.parent,
            proposal.payload,
            finalize.signature.unwrap(),
        )
    }

    pub fn deserialize_finalize(
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(View, Height, View, Digest, PublicKey)> {
        Self::deserialize_proposal(proof, check_sig, &self.finalize_namespace)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn serialize_conflicting_proposal(
        view: View,
        height_1: Height,
        parent_1: View,
        payload_1: Digest,
        signature_1: wire::Signature,
        height_2: Height,
        parent_2: View,
        payload_2: Digest,
        signature_2: wire::Signature,
    ) -> Proof {
        // Setup proof
        let digest_len = H::len();
        let (public_key_len, signature_len) = C::len();
        let len = 8
            + public_key_len
            + 8
            + 8
            + digest_len
            + signature_len
            + 8
            + 8
            + digest_len
            + signature_len;

        // Ensure proof can be generated correctly
        if signature_1.public_key != signature_2.public_key {
            panic!("public keys do not match");
        }
        let public_key = signature_1.public_key;

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(view);
        proof.put(public_key);
        proof.put_u64(height_1);
        proof.put_u64(parent_1);
        proof.put(payload_1);
        proof.put(signature_1.signature);
        proof.put_u64(height_2);
        proof.put_u64(parent_2);
        proof.put(payload_2);
        proof.put(signature_2.signature);
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
        let len = 8
            + public_key_len
            + 8
            + 8
            + digest_len
            + signature_len
            + 8
            + 8
            + digest_len
            + signature_len;
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let public_key = proof.copy_to_bytes(public_key_len);
        let height_1 = proof.get_u64();
        let parent_1 = proof.get_u64();
        let payload_1 = proof.copy_to_bytes(digest_len);
        let signature_1 = proof.copy_to_bytes(signature_len);
        let height_2 = proof.get_u64();
        let parent_2 = proof.get_u64();
        let payload_2 = proof.copy_to_bytes(digest_len);
        let signature_2 = proof.copy_to_bytes(signature_len);

        // Verify signatures
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            let proposal_message_1 = proposal_message(view, height_1, parent_1, &payload_1);
            let proposal_message_2 = proposal_message(view, height_2, parent_2, &payload_2);
            if !C::verify(namespace, &proposal_message_1, &public_key, &signature_1)
                || !C::verify(namespace, &proposal_message_2, &public_key, &signature_2)
            {
                return None;
            }
        }
        Some((public_key, view))
    }

    pub(crate) fn serialize_conflicting_vote(
        view: View,
        height_1: Height,
        parent_1: View,
        payload_1: Digest,
        signature_1: wire::Signature,
        height_2: Height,
        parent_2: View,
        payload_2: Digest,
        signature_2: wire::Signature,
    ) -> Proof {
        Self::serialize_conflicting_proposal(
            view,
            height_1,
            parent_1,
            payload_1,
            signature_1,
            height_2,
            parent_2,
            payload_2,
            signature_2,
        )
    }

    pub fn deserialize_conflicting_vote(
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View)> {
        Self::deserialize_conflicting_proposal(proof, check_sig, &self.vote_namespace)
    }

    pub(crate) fn serialize_conflicting_finalize(
        view: View,
        height_1: Height,
        parent_1: View,
        payload_1: Digest,
        signature_1: wire::Signature,
        height_2: Height,
        parent_2: View,
        payload_2: Digest,
        signature_2: wire::Signature,
    ) -> Proof {
        Self::serialize_conflicting_proposal(
            view,
            height_1,
            parent_1,
            payload_1,
            signature_1,
            height_2,
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

    pub(crate) fn serialize_null_finalize(
        view: View,
        height: Height,
        parent: View,
        payload: Digest,
        signature_finalize: wire::Signature,
        signature_null: wire::Signature,
    ) -> Proof {
        // Setup proof
        let (public_key_len, signature_len) = C::len();
        let len = 8 + public_key_len + 8 + 8 + H::len() + signature_len + signature_len;

        // Ensure proof can be generated correctly
        if signature_finalize.public_key != signature_null.public_key {
            panic!("public keys do not match");
        }
        let public_key = signature_finalize.public_key;

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(view);
        proof.put(public_key);
        proof.put_u64(height);
        proof.put_u64(parent);
        proof.put(payload);
        proof.put(signature_finalize.signature);
        proof.put(signature_null.signature);
        proof.into()
    }

    pub fn deserialize_null_finalize(
        &self,
        mut proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View)> {
        // Ensure proof is big enough
        let (public_key_len, signature_len) = C::len();
        let len = 8 + public_key_len + 8 + 8 + H::len() + signature_len + signature_len;
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let public_key = proof.copy_to_bytes(public_key_len);
        let height = proof.get_u64();
        let parent = proof.get_u64();
        let payload = proof.copy_to_bytes(H::len());
        let signature_finalize = proof.copy_to_bytes(signature_len);
        let signature_null = proof.copy_to_bytes(signature_len);

        // Verify signatures
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            let finalize_message = proposal_message(view, height, parent, &payload);
            let null_message = null_message(view);
            if !C::verify(
                &self.finalize_namespace,
                &finalize_message,
                &public_key,
                &signature_finalize,
            ) || !C::verify(
                &self.vote_namespace,
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
