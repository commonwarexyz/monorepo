use super::{encoder, wire, Context, Epoch};
use crate::Proof;
use bytes::{Buf, BufMut};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        ops,
    },
    Digest, Hasher, Scheme,
};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Prover<C: Scheme, H: Hasher> {
    _crypto: PhantomData<C>,
    _hasher: PhantomData<H>,

    public: group::Public,
    namespace: Vec<u8>,
}

impl<C: Scheme, H: Hasher> Prover<C, H> {
    /// Create a new prover with the given signing `namespace`.
    pub fn new(public: group::Public, namespace: &[u8]) -> Self {
        Self {
            _crypto: PhantomData,
            _hasher: PhantomData,
            public,
            namespace: encoder::ack_namespace(namespace),
        }
    }

    /// Returns 1) the length of a proof and 2) a tuple with the lengths of:
    /// - the digest
    /// - the public key
    /// - the signature
    fn get_len() -> (usize, (usize, usize, usize)) {
        let len_digest = H::len();
        let (len_public_key, len_signature) = C::len();

        let mut len = 0;
        len += len_public_key; // context.sequencer
        len += 8; // context.height
        len += len_digest; // payload_digest
        len += 8; // epoch
        len += len_signature; // threshold

        (len, (len_digest, len_public_key, len_signature))
    }

    pub fn serialize_threshold(
        context: &Context,
        payload_digest: &Digest,
        epoch: Epoch,
        threshold: &group::Signature,
    ) -> Proof {
        let (len, _) = Prover::<C, H>::get_len();
        let mut proof = Vec::with_capacity(len);

        // Encode proof
        proof.extend_from_slice(&context.sequencer);
        proof.put_u64(context.height);
        proof.extend_from_slice(payload_digest);
        proof.put_u64(epoch);
        proof.extend_from_slice(&threshold.serialize());
        proof.into()
    }

    pub fn deserialize_threshold(
        &self,
        mut proof: Proof,
    ) -> Option<(Context, Digest, group::Signature)> {
        let (len, (digest_len, public_key_len, signature_len)) = Prover::<C, H>::get_len();

        // Ensure proof is the right size
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let sequencer = proof.copy_to_bytes(public_key_len);
        let height = proof.get_u64();
        let payload_digest = proof.copy_to_bytes(digest_len);
        let epoch = proof.get_u64();
        let threshold = proof.copy_to_bytes(signature_len);
        let threshold = group::Signature::deserialize(&threshold)?;

        // Verify signature
        let chunk = wire::Chunk {
            sequencer: sequencer.clone(),
            height,
            payload_digest: payload_digest.clone(),
        };
        let msg = encoder::serialize(&chunk, Some(epoch));
        if ops::verify_message(&self.public, Some(&self.namespace), &msg, &threshold).is_err() {
            return None;
        }

        Some((Context { sequencer, height }, payload_digest, threshold))
    }
}
