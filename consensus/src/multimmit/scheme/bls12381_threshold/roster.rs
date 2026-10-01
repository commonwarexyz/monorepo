//! Ordinary-key rosters checked by proof of possession.

use super::Error;
use crate::multimmit::scheme::Namespace;
use commonware_cryptography::{
    PublicKey,
    bls12381::primitives::{group::Private, ops, variant::Variant},
};
use commonware_math::algebra::Additive;
use commonware_parallel::Strategy;
use commonware_utils::{
    TryFromIterator,
    ordered::{BiMap, Set},
};
use core::fmt;
use std::collections::HashSet;

/// An ordinary BLS key roster whose proofs of possession have been verified.
///
/// Multimmit aggregates ordinary signatures into V-QCs and L-QCs. Accepting an unproven public
/// key would make those certificates vulnerable to rogue-key attacks, so [`super::Scheme`] can
/// only be constructed from this validated type.
#[derive(Clone)]
pub struct Roster<P: PublicKey, V: Variant> {
    pub(super) participants: BiMap<P, V::Public>,
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
    /// Verifies participant proofs of possession and constructs an ordered roster.
    ///
    /// Each tuple binds an identity key to an ordinary BLS public key and its proof. Identity and
    /// BLS keys must both be unique. Verification may be parallelized by `strategy`.
    pub fn verify(
        namespace: &[u8],
        expected: usize,
        mut participants: Vec<(P, V::Public, V::Signature)>,
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

        let proof_namespace = Namespace::new(namespace).proof_of_possession;
        strategy.try_map_collect_vec(&participants, |(_, public, proof)| {
            if public == &V::Public::zero() || proof == &V::Signature::zero() {
                return Err(Error::ProofOfPossession);
            }
            ops::verify_proof_of_possession::<V>(public, &proof_namespace, proof)
                .map_err(|_| Error::ProofOfPossession)
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

    /// Generates the proof of possession required by [`Self::verify`].
    pub fn proof_of_possession(namespace: &[u8], private: &Private) -> V::Signature {
        let namespace = Namespace::new(namespace);
        ops::sign_proof_of_possession::<V>(private, &namespace.proof_of_possession)
    }

    /// Returns identity keys in participant-index order.
    pub const fn participants(&self) -> &Set<P> {
        self.participants.keys()
    }

    /// Returns ordinary BLS public keys in participant-index order.
    pub const fn public_keys(&self) -> &BiMap<P, V::Public> {
        &self.participants
    }

    /// Returns whether the proofs were verified under the base `namespace`.
    pub(super) fn matches_namespace(&self, namespace: &[u8]) -> bool {
        self.namespace == namespace
    }
}
