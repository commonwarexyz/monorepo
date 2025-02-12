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

/// Encode and decode proofs of broadcast.
///
/// We don't use protobuf for proof encoding because we expect external parties
/// to decode proofs in constrained environments where protobuf may not be implemented.
#[derive(Clone)]
pub struct Prover<C: Scheme, D: Array> {
    _crypto: PhantomData<C>,
    _digest: PhantomData<D>,

    public: group::Public,
    namespace: Vec<u8>,
}

impl<C: Scheme, D: Array> SizedSerialize for Prover<C, D> {
    /// The length of a serialized proof.
    const SERIALIZED_LEN: usize = C::PublicKey::SERIALIZED_LEN
        + u64::SERIALIZED_LEN
        + D::SERIALIZED_LEN
        + u64::SERIALIZED_LEN
        + C::Signature::SERIALIZED_LEN;
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

    /// Generate a proof for the given `context`, `payload`, `epoch`, and `threshold`.
    pub fn serialize_threshold(
        context: &Context<C::PublicKey>,
        payload: &D,
        epoch: Epoch,
        threshold: &group::Signature,
    ) -> Proof {
        let mut proof = Vec::with_capacity(Self::SERIALIZED_LEN);

        // Encode proof
        proof.extend_from_slice(&context.sequencer);
        proof.put_u64(context.height);
        proof.extend_from_slice(payload);
        proof.put_u64(epoch);
        proof.extend_from_slice(&threshold.serialize());
        proof.into()
    }

    /// Deserialize a proof into a `context`, `payload`, `epoch`, and `threshold`.
    /// Returns `None` if the proof is invalid.
    pub fn deserialize_threshold(
        &self,
        mut proof: Proof,
    ) -> Option<(Context<C::PublicKey>, D, Epoch, group::Signature)> {
        // Ensure proof is the right size

        if proof.len() != Self::SERIALIZED_LEN {
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

        Some((Context { sequencer, height }, payload, epoch, threshold))
    }
}
