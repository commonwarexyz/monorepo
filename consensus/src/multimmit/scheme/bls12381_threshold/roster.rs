//! Ordinary-key rosters checked by proof of knowledge.

use super::Error;
use crate::multimmit::scheme::Namespace;
use commonware_cryptography::{
    PublicKey,
    bls12381::primitives::{ops::sas, variant::Variant},
};
use commonware_math::algebra::Additive;
use commonware_parallel::Strategy;
use commonware_utils::{
    TryFromIterator,
    ordered::{BiMap, Set},
    union,
};
use core::fmt;
use rand_core::CryptoRng;
use std::collections::HashSet;

/// An ordinary-key roster whose proofs of knowledge have been verified.
///
/// Multimmit aggregates ordinary signatures into V-QCs and L-QCs. Accepting a key whose holder
/// might not know its secrets would make those certificates vulnerable to rogue-key attacks, so
/// [`super::Scheme`] can only be constructed from this validated type.
#[derive(Clone)]
pub struct Roster<P: PublicKey, V: Variant> {
    pub(super) participants: BiMap<P, sas::PublicKey<V>>,
    namespace: Vec<u8>,
}

impl<P: PublicKey, V: Variant> fmt::Debug for Roster<P, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Roster")
            .field("participants", &self.participants.len())
            .finish()
    }
}

impl<P: PublicKey, V: Variant> Roster<P, V> {
    /// Verifies participant proofs of knowledge and constructs an ordered roster.
    ///
    /// Each tuple binds an identity key to an ordinary public key and its proof, which must have
    /// been generated for that identity by [`Self::proof_of_knowledge`]. Identity and ordinary keys
    /// must both be unique. Verification may be parallelized by `strategy`.
    pub fn verify(
        namespace: &[u8],
        expected: usize,
        mut participants: Vec<(P, sas::PublicKey<V>, sas::ProofOfKnowledge)>,
        strategy: &impl Strategy,
    ) -> Result<Self, Error> {
        if expected == 0 || participants.len() != expected {
            return Err(Error::Participants);
        }

        participants.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        if participants.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(Error::DuplicateParticipant);
        }
        let mut public_keys = HashSet::with_capacity(expected);
        if participants
            .iter()
            .any(|(_, public, _)| !public_keys.insert(*public))
        {
            return Err(Error::DuplicateParticipant);
        }

        let derived = Namespace::new(namespace);
        strategy.try_map_collect_vec(&participants, |(identity, public, proof)| {
            if public.x() == &V::Public::zero() || public.y() == &V::Public::zero() {
                return Err(Error::ProofOfKnowledge);
            }
            proof
                .verify(&proof_namespace(&derived, identity), public)
                .map_err(|_| Error::ProofOfKnowledge)
        })?;

        let participants = BiMap::try_from_iter(
            participants
                .into_iter()
                .map(|(identity, public, _)| (identity, public)),
        )
        .map_err(|_| Error::DuplicateParticipant)?;
        Ok(Self {
            participants,
            namespace: namespace.to_vec(),
        })
    }

    /// Generates the proof of knowledge that [`Self::verify`] requires of `identity`'s ordinary
    /// key.
    pub fn proof_of_knowledge(
        rng: &mut impl CryptoRng,
        namespace: &[u8],
        identity: &P,
        private: &sas::PrivateKey,
    ) -> sas::ProofOfKnowledge {
        let derived = Namespace::new(namespace);
        sas::ProofOfKnowledge::prove(
            rng,
            &proof_namespace(&derived, identity),
            private,
            &sas::PublicKey::<V>::from_private(private),
        )
    }

    /// Returns identity keys in participant-index order.
    pub const fn participants(&self) -> &Set<P> {
        self.participants.keys()
    }

    /// Returns ordinary public keys in participant-index order.
    pub const fn public_keys(&self) -> &BiMap<P, sas::PublicKey<V>> {
        &self.participants
    }

    /// Returns whether the proofs were verified under the base `namespace`.
    pub(super) fn matches_namespace(&self, namespace: &[u8]) -> bool {
        self.namespace == namespace
    }
}

/// Returns the namespace of `identity`'s proof, which binds the proof to the identity that
/// registers the key.
fn proof_namespace<P: PublicKey>(namespace: &Namespace, identity: &P) -> Vec<u8> {
    union(&namespace.proof_of_knowledge, identity.as_ref())
}
