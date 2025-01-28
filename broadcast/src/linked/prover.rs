use super::{encoder, wire};
use crate::Proof;
use bytes::Buf;
use commonware_cryptography::{Hasher, PublicKey, Scheme, Signature};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Prover<C: Scheme, H: Hasher> {
    _crypto: PhantomData<C>,
    _hasher: PhantomData<H>,

    ack_namespace: Vec<u8>,
}

impl<C: Scheme, H: Hasher> Prover<C, H> {
    /// Create a new prover with the given signing `namespace`.
    pub fn new(namespace: &[u8]) -> Self {
        Self {
            _crypto: PhantomData,
            _hasher: PhantomData,
            ack_namespace: encoder::ack_namespace(namespace),
        }
    }

    pub fn serialize_acknowlegement(
        &self,
        chunk: &wire::Chunk,
        identity: &PublicKey,
        threshold: &Signature,
    ) -> Proof {
        let serialized_chunk = encoder::serialize_chunk(chunk, true);

        // Initial capacity
        let len = serialized_chunk.len() + identity.len() + threshold.len();
        let mut proof = Vec::with_capacity(len);

        // Encode proof
        proof.extend_from_slice(&serialized_chunk);
        proof.extend_from_slice(identity);
        proof.extend_from_slice(threshold);
        proof.into()
    }

    pub fn deserialize_acknowledgement(
        &self,
        mut proof: Proof,
    ) -> Option<(wire::Chunk, PublicKey, Signature)> {
        let digest_len = H::len();
        let (public_key_len, signature_len) = C::len();

        let short_len = 8 + 8 + digest_len + public_key_len + signature_len;
        let long_len = short_len + digest_len + digest_len;

        // Ensure proof is the right size
        if proof.len() != short_len && proof.len() != long_len {
            return None;
        }
        let has_parent = proof.len() == long_len;

        // Decode proof
        let sequencer = proof.copy_to_bytes(public_key_len);
        let height = proof.get_u64();
        let payload_digest = proof.copy_to_bytes(digest_len);
        let mut parent = None;
        if has_parent {
            let chunk_digest = proof.copy_to_bytes(digest_len);
            let threshold = proof.copy_to_bytes(digest_len);
            parent = Some(wire::chunk::Parent {
                chunk_digest,
                threshold,
            });
        }
        let signature = proof.copy_to_bytes(signature_len);
        let identity = proof.copy_to_bytes(public_key_len);
        let threshold = proof.copy_to_bytes(signature_len);

        // Create chunk
        let chunk = wire::Chunk {
            sequencer,
            height,
            payload_digest,
            parent,
            signature,
        };

        Some((chunk, identity, threshold))
    }
}
