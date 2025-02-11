use super::{namespace, serializer, wire, Context, Epoch};
use crate::Proof;
use bytes::{Buf, BufMut};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        ops,
    },
    Array, Scheme,
};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Prover<C: Scheme, D: Array, P: Array> {
    _crypto: PhantomData<C>,
    _digest: PhantomData<D>,

    public: group::Public,
    namespace: Vec<u8>,
}

impl<C: Scheme, D: Array, P: Array> Prover<C, D, P> {
    /// Create a new prover with the given signing `namespace`.
    pub fn new(public: group::Public, namespace: &[u8]) -> Self {
        Self {
            _crypto: PhantomData,
            _digest: PhantomData,
            public,
            namespace: namespace::ack(namespace),
        }
    }

    /// Returns 1) the length of a proof and 2) a tuple with the lengths of:
    /// - the digest
    /// - the public key
    /// - the signature
    fn get_len() -> (usize, (usize, usize)) {
        let len_digest = size_of::<D>();

        let mut len = 0;
        len += len_public_key; // context.sequencer
        len += size_of::<u64>(); // context.height
        len += len_digest; // payload
        len += size_of::<u64>(); // epoch
        len += len_signature; // threshold

        (len, (len_public_key, len_signature))
    }

    pub fn serialize_threshold(
        context: &Context<P>,
        payload: &D,
        epoch: Epoch,
        threshold: &group::Signature,
    ) -> Proof {
        let (len, _) = Prover::<C, D>::get_len();
        let mut proof = Vec::with_capacity(len);

        // Encode proof
        proof.extend_from_slice(&context.sequencer);
        proof.put_u64(context.height);
        proof.extend_from_slice(payload);
        proof.put_u64(epoch);
        proof.extend_from_slice(&threshold.serialize());
        proof.into()
    }

    pub fn deserialize_threshold(
        &self,
        mut proof: Proof,
    ) -> Option<(Context<P>, D, group::Signature)> {
        let (len, (public_key_len, signature_len)) = Prover::<C, D>::get_len();

        // Ensure proof is the right size
        if proof.len() != len {
            return None;
        }

        // Decode proof
        let sequencer = proof.copy_to_bytes(public_key_len);
        let height = proof.get_u64();
        let Ok(payload) = D::read_from(&mut proof) else {
            return None;
        };
        let epoch = proof.get_u64();
        let threshold = proof.copy_to_bytes(signature_len);
        let threshold = group::Signature::deserialize(&threshold)?;

        // Verify signature
        let chunk = wire::Chunk {
            sequencer: sequencer.clone(),
            height,
            payload: payload.to_vec(),
        };
        let msg = serializer::ack(&chunk, epoch);
        if ops::verify_message(&self.public, Some(&self.namespace), &msg, &threshold).is_err() {
            return None;
        }

        Some((Context { sequencer, height }, payload, threshold))
    }
}
