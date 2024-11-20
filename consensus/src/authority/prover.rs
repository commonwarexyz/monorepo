//! Prover module for the authority node.
//!
//! We don't use protobuf for proof encoding because we expect external parties
//! to decode proofs in constrained environments where protobuf may not be implemented.

use super::{
    encoder::{
        finalize_namespace, header_namespace, null_message, proposal_message, vote_namespace,
    },
    wire, View,
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
        index: &wire::Index,
        parent: &wire::Parent,
        payload: &Digest,
        signature: &wire::Signature,
    ) -> Proof {
        // Setup proof
        let len = 8
            + 8
            + 8
            + parent.digest.len()
            + payload.len()
            + signature.public_key.len()
            + signature.signature.len();

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(index.view);
        proof.put_u64(index.height);
        proof.put_u64(parent.view);
        proof.extend_from_slice(&parent.digest);
        proof.extend_from_slice(payload);
        proof.extend_from_slice(&signature.public_key);
        proof.extend_from_slice(&signature.signature);
        proof.into()
    }

    fn deserialize_proposal(
        mut proof: Proof,
        check_sig: bool,
        namespace: &[u8],
    ) -> Option<(wire::Index, wire::Parent, Digest, PublicKey)> {
        // Ensure proof is big enough
        let digest_len = H::len();
        let (public_key_len, signature_len) = C::len();
        if proof.len() != 8 + 8 + 8 + digest_len + digest_len + public_key_len + signature_len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let height = proof.get_u64();
        let index = wire::Index { view, height };
        let parent_view = proof.get_u64();
        let parent_digest = proof.copy_to_bytes(digest_len);
        let parent = wire::Parent {
            view: parent_view,
            digest: parent_digest,
        };
        let payload = proof.copy_to_bytes(digest_len);
        let public_key = proof.copy_to_bytes(public_key_len);
        let signature = proof.copy_to_bytes(signature_len);

        // Verify signature
        let proposal_message = proposal_message(&index, &parent, &payload);
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            if !C::verify(namespace, &proposal_message, &public_key, &signature) {
                return None;
            }
        }

        Some((index, parent, payload, public_key))
    }

    pub(crate) fn serialize_header(
        index: &wire::Index,
        parent: &wire::Parent,
        payload: &Digest,
        signature: &wire::Signature,
    ) -> Proof {
        Self::serialize_proposal(index, parent, payload, signature)
    }

    pub fn deserialize_header(
        &mut self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(wire::Index, wire::Parent, Digest, PublicKey)> {
        Self::deserialize_proposal(proof, check_sig, &self.header_namespace)
    }

    pub(crate) fn serialize_vote(vote: &wire::Vote) -> Proof {
        // Extract proposal
        let container = vote
            .container
            .as_ref()
            .expect("missing container")
            .payload
            .as_ref()
            .expect("missing payload");
        let wire::container::Payload::Proposal(proposal) = container else {
            panic!("container is not proposal")
        };

        // Setup proof
        Self::serialize_proposal(
            proposal.index.as_ref().expect("missing index"),
            proposal.parent.as_ref().expect("missing parent"),
            &proposal.payload,
            vote.signature.as_ref().expect("missing signature"),
        )
    }

    pub fn deserialize_vote(
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(wire::Index, wire::Parent, Digest, PublicKey)> {
        Self::deserialize_proposal(proof, check_sig, &self.vote_namespace)
    }

    pub(crate) fn serialize_finalize(finalize: wire::Finalize) -> Proof {
        // Extract proposal
        let proposal = finalize.proposal.as_ref().expect("missing proposal");

        // Setup proof
        Self::serialize_proposal(
            proposal.index.as_ref().expect("missing index"),
            proposal.parent.as_ref().expect("missing parent"),
            &proposal.payload,
            finalize.signature.as_ref().expect("missing signature"),
        )
    }

    pub fn deserialize_finalize(
        &self,
        proof: Proof,
        check_sig: bool,
    ) -> Option<(wire::Index, wire::Parent, Digest, PublicKey)> {
        Self::deserialize_proposal(proof, check_sig, &self.finalize_namespace)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn serialize_conflicting_proposal(
        index_1: &wire::Index,
        parent_1: &wire::Parent,
        payload_1: &Digest,
        signature_1: &wire::Signature,
        index_2: &wire::Index,
        parent_2: &wire::Parent,
        payload_2: &Digest,
        signature_2: &wire::Signature,
    ) -> Proof {
        // Setup proof
        let digest_len = H::len();
        let (public_key_len, signature_len) = C::len();
        let len = 8
            + public_key_len
            + 8
            + 8
            + digest_len
            + digest_len
            + signature_len
            + 8
            + 8
            + digest_len
            + digest_len
            + signature_len;

        // Ensure proof can be generated correctly
        if index_1.view != index_2.view {
            panic!("views do not match");
        }
        let view = index_1.view;
        if signature_1.public_key != signature_2.public_key {
            panic!("public keys do not match");
        }
        let public_key = signature_1.public_key.as_ref();

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(view);
        proof.put(public_key);
        proof.put_u64(index_1.height);
        proof.put_u64(parent_1.view);
        proof.extend_from_slice(&parent_1.digest);
        proof.extend_from_slice(&payload_1);
        proof.extend_from_slice(&signature_1.signature);
        proof.put_u64(index_2.height);
        proof.put_u64(parent_2.view);
        proof.extend_from_slice(&parent_2.digest);
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
        let len = 8
            + public_key_len
            + 8
            + 8
            + digest_len
            + digest_len
            + signature_len
            + 8
            + 8
            + digest_len
            + digest_len
            + signature_len;
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let public_key = proof.copy_to_bytes(public_key_len);
        let height_1 = proof.get_u64();
        let index_1 = wire::Index {
            view,
            height: height_1,
        };
        let parent_view_1 = proof.get_u64();
        let parent_digest_1 = proof.copy_to_bytes(digest_len);
        let parent_1 = wire::Parent {
            view: parent_view_1,
            digest: parent_digest_1,
        };
        let payload_1 = proof.copy_to_bytes(digest_len);
        let signature_1 = proof.copy_to_bytes(signature_len);
        let height_2 = proof.get_u64();
        let index_2 = wire::Index {
            view,
            height: height_2,
        };
        let parent_view_2 = proof.get_u64();
        let parent_digest_2 = proof.copy_to_bytes(digest_len);
        let parent_2 = wire::Parent {
            view: parent_view_2,
            digest: parent_digest_2,
        };
        let payload_2 = proof.copy_to_bytes(digest_len);
        let signature_2 = proof.copy_to_bytes(signature_len);

        // Verify signatures
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            let proposal_message_1 = proposal_message(&index_1, &parent_1, &payload_1);
            let proposal_message_2 = proposal_message(&index_2, &parent_2, &payload_2);
            if !C::verify(namespace, &proposal_message_1, &public_key, &signature_1)
                || !C::verify(namespace, &proposal_message_2, &public_key, &signature_2)
            {
                return None;
            }
        }
        Some((public_key, view))
    }

    pub(crate) fn serialize_conflicting_vote(
        index_1: &wire::Index,
        parent_1: &wire::Parent,
        payload_1: &Digest,
        signature_1: &wire::Signature,
        index_2: &wire::Index,
        parent_2: &wire::Parent,
        payload_2: &Digest,
        signature_2: &wire::Signature,
    ) -> Proof {
        Self::serialize_conflicting_proposal(
            index_1,
            parent_1,
            payload_1,
            signature_1,
            index_2,
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
        index_1: &wire::Index,
        parent_1: &wire::Parent,
        payload_1: &Digest,
        signature_1: &wire::Signature,
        index_2: &wire::Index,
        parent_2: &wire::Parent,
        payload_2: &Digest,
        signature_2: &wire::Signature,
    ) -> Proof {
        Self::serialize_conflicting_proposal(
            index_1,
            parent_1,
            payload_1,
            signature_1,
            index_2,
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
        index: &wire::Index,
        parent: &wire::Parent,
        payload: &Digest,
        signature_finalize: &wire::Signature,
        signature_null: &wire::Signature,
    ) -> Proof {
        // Setup proof
        let digest_len = H::len();
        let (public_key_len, signature_len) = C::len();
        let len =
            8 + public_key_len + 8 + 8 + digest_len + digest_len + signature_len + signature_len;

        // Ensure proof can be generated correctly
        if signature_finalize.public_key != signature_null.public_key {
            panic!("public keys do not match");
        }
        let public_key = signature_finalize.public_key.as_ref();

        // Encode proof
        let mut proof = Vec::with_capacity(len);
        proof.put_u64(index.view);
        proof.put(public_key);
        proof.put_u64(index.height);
        proof.put_u64(parent.view);
        proof.extend_from_slice(&parent.digest);
        proof.extend_from_slice(payload);
        proof.extend_from_slice(&signature_finalize.signature);
        proof.extend_from_slice(&signature_null.signature);
        proof.into()
    }

    pub fn deserialize_null_finalize(
        &self,
        mut proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View)> {
        // Ensure proof is big enough
        let digest_len = H::len();
        let (public_key_len, signature_len) = C::len();
        let len =
            8 + public_key_len + 8 + 8 + digest_len + digest_len + signature_len + signature_len;
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let view = proof.get_u64();
        let null = wire::Null { view };
        let public_key = proof.copy_to_bytes(public_key_len);
        let height = proof.get_u64();
        let index = wire::Index { view, height };
        let parent_view = proof.get_u64();
        let parent_digest = proof.copy_to_bytes(digest_len);
        let parent = wire::Parent {
            view: parent_view,
            digest: parent_digest,
        };
        let payload = proof.copy_to_bytes(digest_len);
        let signature_finalize = proof.copy_to_bytes(signature_len);
        let signature_null = proof.copy_to_bytes(signature_len);

        // Verify signatures
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            let finalize_message = proposal_message(&index, &parent, &payload);
            let null_message = null_message(&null);
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
