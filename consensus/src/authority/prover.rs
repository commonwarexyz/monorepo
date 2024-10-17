use super::{
    encoder::{
        finalize_digest, finalize_namespace, proposal_digest, proposal_namespace, vote_digest,
        vote_namespace,
    },
    wire, CONFLICTING_FINALIZE, CONFLICTING_PROPOSAL, CONFLICTING_VOTE, FINALIZE,
    NULL_AND_FINALIZE, PROPOSAL, VOTE,
};
use crate::{Activity, Hash, Hasher, Height, Proof, View};
use bytes::{Buf, BufMut, Bytes};
use commonware_cryptography::{PublicKey, Scheme};
use core::panic;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Prover<C: Scheme, H: Hasher> {
    _crypto: PhantomData<C>,
    hasher: H,

    proposal_namespace: Vec<u8>,
    vote_namespace: Vec<u8>,
    finalize_namespace: Vec<u8>,
}

impl<C: Scheme, H: Hasher> Prover<C, H> {
    pub fn new(hasher: H, namespace: Bytes) -> Self {
        Self {
            _crypto: PhantomData,
            hasher,
            proposal_namespace: proposal_namespace(&namespace),
            vote_namespace: vote_namespace(&namespace),
            finalize_namespace: finalize_namespace(&namespace),
        }
    }

    pub fn activity(mut proof: Proof) -> Activity {
        proof.get_u8()
    }

    pub(crate) fn serialize_proposal(
        view: View,
        height: Height,
        parent: Hash,
        payload: Hash,
        signature: wire::Signature,
    ) -> Proof {
        // Setup proof
        let hash_size = H::size();
        let (public_key_size, signature_size) = C::size();
        let size = 1 + 8 + 8 + hash_size + hash_size + public_key_size + signature_size;
        let mut proof = Vec::with_capacity(size);

        // Encode proof
        proof.put_u8(PROPOSAL);
        proof.put_u64(view);
        proof.put_u64(height);
        proof.put(parent);
        proof.put(payload);
        proof.put(signature.public_key);
        proof.put(signature.signature);
        proof.into()
    }

    pub fn deserialize_proposal(
        &mut self,
        mut proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View, Height, Hash)> {
        // Ensure proof is big enough
        let hash_size = H::size();
        let (public_key_size, signature_size) = C::size();
        if proof.len() != 1 + 8 + 8 + hash_size + hash_size + public_key_size + signature_size {
            return None;
        }

        // Decode proof
        let activity_type: Activity = proof.get_u8();
        if activity_type != PROPOSAL {
            return None;
        }
        let view = proof.get_u64();
        let height = proof.get_u64();
        let parent = proof.copy_to_bytes(hash_size);
        let payload = proof.copy_to_bytes(hash_size);
        let public_key = proof.copy_to_bytes(public_key_size);
        let signature = proof.copy_to_bytes(signature_size);

        // Verify signature
        let proposal_digest = proposal_digest(view, height, &parent, &payload);
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            if !C::verify(
                &self.proposal_namespace,
                &proposal_digest,
                &public_key,
                &signature,
            ) {
                return None;
            }
        }

        // Compute hash
        Some((public_key, view, height, self.hasher.hash(&proposal_digest)))
    }

    pub(crate) fn serialize_vote(vote: wire::Vote) -> Proof {
        // Setup proof
        let (public_key_size, signature_size) = C::size();
        let size = 1 + 8 + 8 + H::size() + public_key_size + signature_size;
        let mut proof = Vec::with_capacity(size);

        // Encode proofs
        proof.put_u8(VOTE);
        proof.put_u64(vote.view);
        proof.put_u64(vote.height.expect("height not populated"));
        proof.put(vote.hash.expect("hash not populated"));
        let signature = vote.signature.expect("signature not populated");
        proof.put(signature.public_key);
        proof.put(signature.signature);
        proof.into()
    }

    pub fn deserialize_vote(
        &self,
        mut proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View, Height, Hash)> {
        // Ensure proof is big enough
        let hash_size = H::size();
        let (public_key_size, signature_size) = C::size();
        if proof.len() != 1 + 8 + 8 + hash_size + public_key_size + signature_size {
            return None;
        }

        // Decode proof
        let activity_type: Activity = proof.get_u8();
        if activity_type != VOTE {
            return None;
        }
        let view = proof.get_u64();
        let height = proof.get_u64();
        let hash = proof.copy_to_bytes(hash_size);
        let public_key = proof.copy_to_bytes(public_key_size);
        let signature = proof.copy_to_bytes(signature_size);

        // Verify signature
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            let vote_digest = vote_digest(view, Some(height), Some(&hash));
            if !C::verify(&self.vote_namespace, &vote_digest, &public_key, &signature) {
                return None;
            }
        }
        Some((public_key, view, height, hash))
    }

    pub(crate) fn serialize_finalize(finalize: wire::Finalize) -> Proof {
        // Setup proof
        let (public_key_size, signature_size) = C::size();
        let size = 1 + 8 + 8 + H::size() + public_key_size + signature_size;
        let mut proof = Vec::with_capacity(size);

        // Encode proof
        proof.put_u8(FINALIZE);
        proof.put_u64(finalize.view);
        proof.put_u64(finalize.height);
        proof.put(finalize.hash);
        let signature = finalize.signature.expect("signature not populated");
        proof.put(signature.public_key);
        proof.put(signature.signature);
        proof.into()
    }

    pub fn deserialize_finalize(
        &self,
        mut proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View, Height, Hash)> {
        // Ensure proof is big enough
        let hash_size = H::size();
        let (public_key_size, signature_size) = C::size();
        if proof.len() != 1 + 8 + 8 + hash_size + public_key_size + signature_size {
            return None;
        }

        // Decode proof
        let activity_type: Activity = proof.get_u8();
        if activity_type != FINALIZE {
            return None;
        }
        let view = proof.get_u64();
        let height = proof.get_u64();
        let hash = proof.copy_to_bytes(hash_size);
        let public_key = proof.copy_to_bytes(public_key_size);
        let signature = proof.copy_to_bytes(signature_size);

        // Verify signature
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            let finalize_digest = finalize_digest(view, height, &hash);
            if !C::verify(
                &self.finalize_namespace,
                &finalize_digest,
                &public_key,
                &signature,
            ) {
                return None;
            }
        }
        Some((public_key, view, height, hash))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn serialize_conflicting_proposal(
        view: View,
        height_1: Height,
        parent_1: Hash,
        payload_1: Hash,
        signature_1: wire::Signature,
        height_2: Height,
        parent_2: Hash,
        payload_2: Hash,
        signature_2: wire::Signature,
    ) -> Proof {
        // Setup proof
        let hash_size = H::size();
        let (public_key_size, signature_size) = C::size();
        let size = 1
            + 8
            + public_key_size
            + 8
            + hash_size
            + hash_size
            + signature_size
            + 8
            + hash_size
            + hash_size
            + signature_size;

        // Ensure proof can be generated correctly
        if signature_1.public_key != signature_2.public_key {
            panic!("public keys do not match");
        }
        let public_key = signature_1.public_key;

        // Encode proof
        let mut proof = Vec::with_capacity(size);
        proof.put_u8(CONFLICTING_PROPOSAL);
        proof.put_u64(view);
        proof.put(public_key);
        proof.put_u64(height_1);
        proof.put(parent_1);
        proof.put(payload_1);
        proof.put(signature_1.signature);
        proof.put_u64(height_2);
        proof.put(parent_2);
        proof.put(payload_2);
        proof.put(signature_2.signature);
        proof.into()
    }

    pub fn deserialize_conflicting_proposal(
        &self,
        mut proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View)> {
        // Ensure proof is big enough
        let hash_size = H::size();
        let (public_key_size, signature_size) = C::size();
        let size = 1
            + 8
            + public_key_size
            + 8
            + hash_size
            + hash_size
            + signature_size
            + 8
            + hash_size
            + hash_size
            + signature_size;
        if proof.len() != size {
            return None;
        }

        // Decode proof
        let activity_type: Activity = proof.get_u8();
        if activity_type != CONFLICTING_PROPOSAL {
            return None;
        }
        let view = proof.get_u64();
        let public_key = proof.copy_to_bytes(public_key_size);
        let height_1 = proof.get_u64();
        let parent_1 = proof.copy_to_bytes(hash_size);
        let payload_1 = proof.copy_to_bytes(hash_size);
        let signature_1 = proof.copy_to_bytes(signature_size);
        let height_2 = proof.get_u64();
        let parent_2 = proof.copy_to_bytes(hash_size);
        let payload_2 = proof.copy_to_bytes(hash_size);
        let signature_2 = proof.copy_to_bytes(signature_size);

        // Verify signatures
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            let proposal_digest_1 = proposal_digest(view, height_1, &parent_1, &payload_1);
            let proposal_digest_2 = proposal_digest(view, height_2, &parent_2, &payload_2);
            if !C::verify(
                &self.proposal_namespace,
                &proposal_digest_1,
                &public_key,
                &signature_1,
            ) || !C::verify(
                &self.proposal_namespace,
                &proposal_digest_2,
                &public_key,
                &signature_2,
            ) {
                return None;
            }
        }
        Some((public_key, view))
    }

    pub(crate) fn serialize_conflicting_vote(
        view: View,
        height_1: Height,
        hash_1: Hash,
        signature_1: wire::Signature,
        height_2: Height,
        hash_2: Hash,
        signature_2: wire::Signature,
    ) -> Proof {
        // Setup proof
        let hash_size = H::size();
        let (public_key_size, signature_size) = C::size();
        let size = 1
            + 8
            + public_key_size
            + 8
            + hash_size
            + signature_size
            + 8
            + hash_size
            + signature_size;

        // Ensure proof can be generated correctly
        if signature_1.public_key != signature_2.public_key {
            panic!("public keys do not match");
        }
        let public_key = signature_1.public_key;

        // Encode proof
        let mut proof = Vec::with_capacity(size);
        proof.put_u8(CONFLICTING_VOTE);
        proof.put_u64(view);
        proof.put(public_key);
        proof.put_u64(height_1);
        proof.put(hash_1);
        proof.put(signature_1.signature);
        proof.put_u64(height_2);
        proof.put(hash_2);
        proof.put(signature_2.signature);
        proof.into()
    }

    pub fn deserialize_conflicting_vote(
        &self,
        mut proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View)> {
        // Ensure proof is big enough
        let hash_size = H::size();
        let (public_key_size, signature_size) = C::size();
        let size = 1
            + 8
            + public_key_size
            + 8
            + hash_size
            + signature_size
            + 8
            + hash_size
            + signature_size;
        if proof.len() != size {
            return None;
        }

        // Decode proof
        let activity_type: Activity = proof.get_u8();
        if activity_type != CONFLICTING_VOTE {
            return None;
        }
        let view = proof.get_u64();
        let public_key = proof.copy_to_bytes(public_key_size);
        let height_1 = proof.get_u64();
        let hash_1 = proof.copy_to_bytes(hash_size);
        let signature_1 = proof.copy_to_bytes(signature_size);
        let height_2 = proof.get_u64();
        let hash_2 = proof.copy_to_bytes(hash_size);
        let signature_2 = proof.copy_to_bytes(signature_size);

        // Verify signatures
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            let vote_digest_1 = vote_digest(view, Some(height_1), Some(&hash_1));
            let vote_digest_2 = vote_digest(view, Some(height_2), Some(&hash_2));
            if !C::verify(
                &self.vote_namespace,
                &vote_digest_1,
                &public_key,
                &signature_1,
            ) || !C::verify(
                &self.vote_namespace,
                &vote_digest_2,
                &public_key,
                &signature_2,
            ) {
                return None;
            }
        }
        Some((public_key, view))
    }

    pub(crate) fn serialize_conflicting_finalize(
        view: View,
        height_1: Height,
        hash_1: Hash,
        signature_1: wire::Signature,
        height_2: Height,
        hash_2: Hash,
        signature_2: wire::Signature,
    ) -> Proof {
        // Setup proof
        let hash_size = H::size();
        let (public_key_size, signature_size) = C::size();
        let size = 1
            + 8
            + public_key_size
            + 8
            + hash_size
            + signature_size
            + 8
            + hash_size
            + signature_size;

        // Ensure proof can be generated correctly
        if signature_1.public_key != signature_2.public_key {
            panic!("public keys do not match");
        }
        let public_key = signature_1.public_key;

        // Encode proof
        let mut proof = Vec::with_capacity(size);
        proof.put_u8(CONFLICTING_FINALIZE);
        proof.put_u64(view);
        proof.put(public_key);
        proof.put_u64(height_1);
        proof.put(hash_1);
        proof.put(signature_1.signature);
        proof.put_u64(height_2);
        proof.put(hash_2);
        proof.put(signature_2.signature);
        proof.into()
    }

    pub fn deserialize_conflicting_finalize(
        &self,
        mut proof: Proof,
        check_sig: bool,
    ) -> Option<(PublicKey, View)> {
        let hash_size = H::size();
        let (public_key_size, signature_size) = C::size();
        let size = 1
            + 8
            + public_key_size
            + 8
            + hash_size
            + signature_size
            + 8
            + hash_size
            + signature_size;
        if proof.len() != size {
            return None;
        }

        // Decode proof
        let activity_type: Activity = proof.get_u8();
        if activity_type != CONFLICTING_FINALIZE {
            return None;
        }
        let view = proof.get_u64();
        let public_key = proof.copy_to_bytes(public_key_size);
        let height_1 = proof.get_u64();
        let hash_1 = proof.copy_to_bytes(hash_size);
        let signature_1 = proof.copy_to_bytes(signature_size);
        let height_2 = proof.get_u64();
        let hash_2 = proof.copy_to_bytes(hash_size);
        let signature_2 = proof.copy_to_bytes(signature_size);

        // Verify signatures
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            let finalize_digest_1 = finalize_digest(view, height_1, &hash_1);
            let finalize_digest_2 = finalize_digest(view, height_2, &hash_2);
            if !C::verify(
                &self.finalize_namespace,
                &finalize_digest_1,
                &public_key,
                &signature_1,
            ) || !C::verify(
                &self.finalize_namespace,
                &finalize_digest_2,
                &public_key,
                &signature_2,
            ) {
                return None;
            }
        }
        Some((public_key, view))
    }

    pub(crate) fn serialize_null_finalize(
        view: View,
        height: Height,
        hash: Hash,
        signature_finalize: wire::Signature,
        signature_null: wire::Signature,
    ) -> Proof {
        // Setup proof
        let (public_key_size, signature_size) = C::size();
        let size = 1 + 8 + public_key_size + 8 + H::size() + signature_size + signature_size;

        // Ensure proof can be generated correctly
        if signature_finalize.public_key != signature_null.public_key {
            panic!("public keys do not match");
        }
        let public_key = signature_finalize.public_key;

        // Encode proof
        let mut proof = Vec::with_capacity(size);
        proof.put_u8(NULL_AND_FINALIZE);
        proof.put_u64(view);
        proof.put(public_key);
        proof.put_u64(height);
        proof.put(hash);
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
        let (public_key_size, signature_size) = C::size();
        let size = 1 + 8 + public_key_size + 8 + H::size() + signature_size + signature_size;
        if proof.len() != size {
            return None;
        }

        // Decode proof
        let activity_type: Activity = proof.get_u8();
        if activity_type != NULL_AND_FINALIZE {
            return None;
        }
        let view = proof.get_u64();
        let public_key = proof.copy_to_bytes(public_key_size);
        let height = proof.get_u64();
        let hash = proof.copy_to_bytes(H::size());
        let signature_finalize = proof.copy_to_bytes(signature_size);
        let signature_null = proof.copy_to_bytes(signature_size);

        // Verify signatures
        if check_sig {
            if !C::validate(&public_key) {
                return None;
            }
            let finalize_digest = finalize_digest(view, height, &hash);
            let null_digest = vote_digest(view, None, None);
            if !C::verify(
                &self.finalize_namespace,
                &finalize_digest,
                &public_key,
                &signature_finalize,
            ) || !C::verify(
                &self.vote_namespace,
                &null_digest,
                &public_key,
                &signature_null,
            ) {
                return None;
            }
        }
        Some((public_key, view))
    }
}
