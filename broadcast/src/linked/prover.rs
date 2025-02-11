use super::{namespace, safe, serializer, Context, Epoch};
use crate::Proof;
use bytes::{Buf, BufMut};
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        ops,
    },
    Array, Scheme,
};
use commonware_utils::SizedSerialize;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct Prover<C: Scheme, D: Array> {
    _crypto: PhantomData<C>,
    _digest: PhantomData<D>,

    public: group::Public,
    namespace: Vec<u8>,
}

impl<C: Scheme, D: Array> Prover<C, D> {
    /// Create a new prover with the given signing `namespace`.
    pub fn new(public: group::Public, namespace: &[u8]) -> Self {
        Self {
            _crypto: PhantomData,
            _digest: PhantomData,
            public,
            namespace: namespace::ack(namespace),
        }
    }

    /// Returns the length of a proof
    fn proof_len() -> usize {
        let mut len = 0;
        len += C::PublicKey::SERIALIZED_LEN; // context.sequencer
        len += u64::SERIALIZED_LEN; // context.height
        len += D::SERIALIZED_LEN; // payload
        len += u64::SERIALIZED_LEN; // epoch
        len += C::Signature::SERIALIZED_LEN; // threshold
        len
    }

    pub fn serialize_threshold(
        context: &Context<C::PublicKey>,
        payload: &D,
        epoch: Epoch,
        threshold: &group::Signature,
    ) -> Proof {
        let mut proof = Vec::with_capacity(Self::proof_len());

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
    ) -> Option<(Context<C::PublicKey>, D, group::Signature)> {
        // Ensure proof is the right size

        if proof.len() != Self::proof_len() {
            return None;
        }

        // Decode proof
        let sequencer = C::PublicKey::read_from(&mut proof).ok()?;
        let height = proof.get_u64();
        let Ok(payload) = D::read_from(&mut proof) else {
            return None;
        };
        let epoch = proof.get_u64();
        let threshold = proof.copy_to_bytes(C::Signature::SERIALIZED_LEN);
        let threshold = group::Signature::deserialize(&threshold)?;

        // Verify signature
        let chunk = safe::Chunk::<D, C::PublicKey> {
            sequencer: sequencer.clone(),
            height,
            payload: payload.clone(),
        };
        let msg = serializer::ack(&chunk, epoch);
        if ops::verify_message(&self.public, Some(&self.namespace), &msg, &threshold).is_err() {
            return None;
        }

        Some((Context { sequencer, height }, payload, threshold))
    }
}
