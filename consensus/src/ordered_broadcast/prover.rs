//! Generate and verify proofs of broadcast.
//!
//! The proofs contain threshold signatures of validators that have seen and validated a chunk.

use super::{namespace, parsed, serializer, Context, Epoch};
use crate::Proof;
use bytes::{Buf, BufMut};
use commonware_codec::SizedInfo;
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        ops,
    },
    Digest, Scheme,
};
use commonware_utils::Array;
use std::marker::PhantomData;

/// Encode and decode proofs of broadcast.
///
/// We don't use protobuf for proof encoding because we expect external parties
/// to decode proofs in constrained environments where protobuf may not be implemented.
#[derive(Clone)]
pub struct Prover<C: Scheme, D: Digest> {
    _crypto: PhantomData<C>,
    _digest: PhantomData<D>,
    namespace: Vec<u8>,
    public: group::Public,
}

impl<C: Scheme, D: Digest> Prover<C, D> {
    /// The length of a serialized proof.
    const PROOF_LEN: usize = C::PublicKey::LEN_ENCODED
        + u64::LEN_ENCODED
        + D::LEN_ENCODED
        + u64::LEN_ENCODED
        + group::SIGNATURE_LENGTH;

    /// Create a new prover with the given signing `namespace`.
    pub fn new(namespace: &[u8], public: group::Public) -> Self {
        Self {
            _crypto: PhantomData,
            _digest: PhantomData,
            namespace: namespace::ack(namespace),
            public,
        }
    }

    /// Generate a proof for the given `context`, `payload`, `epoch`, and `threshold`.
    pub fn serialize_threshold(
        context: &Context<C::PublicKey>,
        payload: &D,
        epoch: Epoch,
        threshold: &group::Signature,
    ) -> Proof {
        let mut proof = Vec::with_capacity(Self::PROOF_LEN);

        // Encode proof
        proof.extend_from_slice(&context.sequencer);
        proof.put_u64(context.height);
        proof.extend_from_slice(payload);
        proof.put_u64(epoch);
        proof.extend_from_slice(&threshold.serialize());
        let result: Proof = proof.into();

        // Ensure proof is the right size
        assert!(result.len() == Self::PROOF_LEN);
        result
    }

    /// Deserialize a proof into a `context`, `payload`, `epoch`, and `threshold`.
    /// Returns `None` if the proof is invalid.
    pub fn deserialize_threshold(
        &self,
        mut proof: Proof,
    ) -> Option<(Context<C::PublicKey>, D, Epoch, group::Signature)> {
        // Ensure proof is the right size
        if proof.len() != Self::PROOF_LEN {
            return None;
        }

        // Decode proof
        let sequencer = C::PublicKey::read_from(&mut proof).ok()?;
        let height = proof.get_u64();
        let Ok(payload) = D::read_from(&mut proof) else {
            return None;
        };
        let epoch = proof.get_u64();
        let threshold = proof.copy_to_bytes(group::SIGNATURE_LENGTH);
        let threshold = group::Signature::deserialize(&threshold)?;

        // Verify signature
        let chunk = parsed::Chunk {
            sequencer: sequencer.clone(),
            height,
            payload,
        };
        let msg = serializer::ack(&chunk, epoch);
        if ops::verify_message(&self.public, Some(&self.namespace), &msg, &threshold).is_err() {
            return None;
        }

        Some((Context { sequencer, height }, payload, epoch, threshold))
    }
}
