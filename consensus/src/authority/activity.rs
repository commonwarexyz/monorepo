use super::{encoding::vote_digest, wire, VOTE};
use crate::{Activity, Hash, Hasher, Height, Proof, View};
use bytes::{Buf, BufMut};
use commonware_cryptography::{PublicKey, Scheme};
use std::marker::PhantomData;

pub struct Encoder<C: Scheme, H: Hasher> {
    crypto: PhantomData<C>,
    hasher: PhantomData<H>,
    vote_namespace: Vec<u8>,
}

impl<C: Scheme, H: Hasher> Encoder<C, H> {
    pub fn encode_vote(vote: wire::Vote) -> Proof {
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

    pub fn verify_vote(&self, mut proof: Proof) -> Option<(PublicKey, View, Height, Hash)> {
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
        if !C::validate(&public_key) {
            return None;
        }
        let vote_digest = vote_digest(view, Some(height), Some(&hash));
        if !C::verify(&self.vote_namespace, &vote_digest, &public_key, &signature) {
            return None;
        }
        Some((public_key, view, height, hash))
    }
}
