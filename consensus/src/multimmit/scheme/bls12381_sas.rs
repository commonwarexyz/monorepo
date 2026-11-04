//! Pointcheval-Sanders synchronized aggregate ordinary keys with threshold data-availability and
//! nullification keys.
//!
//! **ALPHA, research grade.** Ordinary keys sign synchronized aggregate signatures
//! ([`sas`]), which aggregate across
//! signers that share a [`Synchronized`](commonware_cryptography::certificate::Synchronized)
//! period. Every signature in one V-QC or L-QC shares its view period, so a certificate verifies
//! with one pairing product however many distinct vote bodies it covers. The DA and
//! nullification roles are the threshold roles of [`bls12381`](super::bls12381).
//!
//! # Security
//!
//! - A key must sign at most one message per period, or anyone can forge its signature on any
//!   message in that period. Multimmit assigns periods to durable signing slots (see
//!   [`scheme`](super)), and the scheme itself does not track them.
//! - Aggregation is only sound for keys whose holders know their secrets. [`Roster`] verifies a
//!   [`sas::ProofOfKnowledge`] for every ordinary key, bound to the holder's identity, before any
//!   scheme can be constructed.
//! - Every scheme precomputes a [`sas::KeyTable`] of the roster's ordinary keys, which costs 24 KiB
//!   per participant for
//!   [`MinPk`](commonware_cryptography::bls12381::primitives::variant::MinPk) and 48 KiB for
//!   [`MinSig`](commonware_cryptography::bls12381::primitives::variant::MinSig), and is shared by
//!   every clone.

use super::{
    Available, Error, Generic, Marker,
    bls12381::{
        Quorum, deal_sharings, ensure_da_quorum, nullify, validate_identities, validate_shares,
        validate_sharings,
    },
};
use crate::multimmit::{checkpoint, config::Parameters};
use commonware_cryptography::{
    PublicKey,
    bls12381::primitives::{group::Share, ops::sas, sharing::Sharing, variant::Variant},
};
use commonware_math::algebra::Additive;
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::{
    Participant, TryFromIterator,
    ordered::{BiMap, Set},
};
use core::{fmt, hash::Hash};
use rand_core::CryptoRng;
use std::{collections::HashSet, sync::Arc};

/// Synchronized aggregate ordinary keys over [`OrdinarySubject`](super::OrdinarySubject)s.
pub mod ordinary {
    use crate::multimmit::scheme::{Namespace, OrdinarySubject};
    use commonware_cryptography::impl_certificate_bls12381_sas;
    use commonware_utils::N5f1;

    impl_certificate_bls12381_sas!(OrdinarySubject, Namespace, N5f1);
}

/// The synchronized aggregate suite over identities `P` and BLS variant `V`, with DA
/// certificates at the quorum `Q`.
pub struct Scheme<P, V, Q = Available>(Marker<(P, V, Q)>);

impl<P, V, Q> Clone for Scheme<P, V, Q> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P, V, Q> Copy for Scheme<P, V, Q> {}

impl<P, V, Q> Default for Scheme<P, V, Q> {
    fn default() -> Self {
        Self(Marker::default())
    }
}

impl<P, V, Q> PartialEq for Scheme<P, V, Q> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<P, V, Q> Eq for Scheme<P, V, Q> {}

impl<P, V, Q> Hash for Scheme<P, V, Q> {
    fn hash<H: core::hash::Hasher>(&self, _: &mut H) {}
}

impl<P, V, Q> fmt::Debug for Scheme<P, V, Q> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bls12381_sas::Scheme")
    }
}

impl<P: PublicKey, V: Variant, Q: Quorum> super::Scheme for Scheme<P, V, Q> {
    type PublicKey = P;
    type DaFaults = Q;
    type Ordinary = ordinary::Scheme<P, V>;
    type Da = Q::Da<P, V>;
    type Nullify = nullify::Scheme<P, V>;

    fn da_certificate_config(_: usize) {}

    fn nullification_config(_: usize) {}
}

/// The local participant's secret key material.
///
/// Both shares must belong to the participant whose ordinary key is `ordinary`.
#[derive(Clone)]
pub struct SignerKeys {
    /// Ordinary synchronized aggregate signing key registered in the [`Roster`].
    pub ordinary: sas::PrivateKey,
    /// Share of the data-availability sharing.
    pub da: Share,
    /// Share of the `2f+1` nullification sharing.
    pub nullification: Share,
}

impl<P: PublicKey, V: Variant, Q: Quorum> Scheme<P, V, Q> {
    /// Creates a signer from the local participant's ordinary key and threshold shares.
    ///
    /// See the module-level security requirements. Fails when any key, share, sharing, or
    /// participant index is inconsistent with the epoch configuration.
    pub fn signer(
        parameters: &Arc<Parameters>,
        roster: Roster<P, V>,
        keys: SignerKeys,
        da: Sharing<V>,
        nullification: Sharing<V>,
    ) -> Result<Generic<Self>, Error> {
        roster.ensure_namespace(parameters)?;
        ensure_da_quorum::<Q>(parameters)?;
        validate_sharings(parameters, &da, &nullification)?;
        let ordinary = sas::PublicKey::<V>::from_private(&keys.ordinary);
        let participant = roster
            .participants
            .values()
            .iter()
            .position(|public| public == &ordinary)
            .map(Participant::from_usize)
            .ok_or(Error::UnknownKey)?;
        validate_shares(
            participant,
            &keys.da,
            &keys.nullification,
            &da,
            &nullification,
        )?;
        let namespace = parameters.namespace();
        let identities = roster.participants.keys().clone();
        let ordinary = ordinary::Scheme::signer(namespace, roster.participants, keys.ordinary)
            .ok_or(Error::UnknownKey)?;
        let da = Q::signer(namespace, identities.clone(), da, keys.da).ok_or(Error::Share)?;
        let nullify =
            nullify::Scheme::signer(namespace, identities, nullification, keys.nullification)
                .ok_or(Error::Share)?;
        Generic::new(parameters, ordinary, da, nullify)
    }

    /// Creates a verifier with the ordinary key roster and both public threshold sharings.
    ///
    /// See the module-level security requirements. Fails when the public material is
    /// inconsistent with the epoch configuration.
    pub fn verifier(
        parameters: &Arc<Parameters>,
        roster: Roster<P, V>,
        da: Sharing<V>,
        nullification: Sharing<V>,
    ) -> Result<Generic<Self>, Error> {
        roster.ensure_namespace(parameters)?;
        ensure_da_quorum::<Q>(parameters)?;
        validate_sharings(parameters, &da, &nullification)?;
        let namespace = parameters.namespace();
        let identities = roster.participants.keys().clone();
        let ordinary = ordinary::Scheme::verifier(namespace, roster.participants);
        let da = Q::verifier(namespace, identities.clone(), da);
        let nullify = nullify::Scheme::verifier(namespace, identities, nullification);
        Generic::new(parameters, ordinary, da, nullify)
    }

    /// Creates a verifier for complete certificates without retaining public threshold sharings.
    ///
    /// This role verifies ordinary signatures, V-QCs, L-QCs, recovered DA certificates, and
    /// recovered nullifications. It cannot verify or recover threshold shares.
    pub fn certificate_verifier(
        parameters: &Arc<Parameters>,
        roster: Roster<P, V>,
        da_identity: V::Public,
        nullification_identity: V::Public,
    ) -> Result<Generic<Self>, Error> {
        roster.ensure_namespace(parameters)?;
        validate_identities::<V>(&da_identity, &nullification_identity)?;
        let namespace = parameters.namespace();
        let ordinary = ordinary::Scheme::verifier(namespace, roster.participants);
        let da = Q::certificate_verifier(namespace, da_identity);
        let nullify = nullify::Scheme::certificate_verifier(namespace, nullification_identity);
        Generic::new(parameters, ordinary, da, nullify).map(Generic::certificates_only)
    }

    /// Deals a complete committee from one trusted dealer, for tests and local deployments.
    ///
    /// Every ordinary key, its proof of knowledge, and both sharings derive from `rng`, so
    /// whoever runs the dealer learns every secret.
    pub fn deal(
        rng: &mut impl CryptoRng,
        parameters: &Arc<Parameters>,
        identities: &Set<P>,
    ) -> Result<Dealt<P, V, Q>, Error> {
        let codec = parameters.codec_config();
        let mut ordinary = Vec::with_capacity(identities.len());
        let roster_input = identities
            .iter()
            .map(|identity| {
                let (private, public) = sas::keypair::<_, V>(&mut *rng);
                let proof = Roster::<P, V>::proof_of_knowledge(
                    &mut *rng,
                    parameters.namespace(),
                    identity,
                    &private,
                );
                ordinary.push(private);
                (identity.clone(), public, proof)
            })
            .collect();
        let roster = Roster::verify(
            parameters.namespace(),
            codec.participants(),
            roster_input,
            &Sequential,
        )?;
        let (da, nullification) = deal_sharings::<V>(rng, parameters)?;
        let signers = ordinary
            .into_iter()
            .zip(da.shares)
            .zip(nullification.shares)
            .map(|((ordinary, da_share), nullification_share)| {
                Self::signer(
                    parameters,
                    roster.clone(),
                    SignerKeys {
                        ordinary,
                        da: da_share,
                        nullification: nullification_share,
                    },
                    da.sharing.clone(),
                    nullification.sharing.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let verifier = Self::verifier(
            parameters,
            roster.clone(),
            da.sharing.clone(),
            nullification.sharing.clone(),
        )?;
        Ok(Dealt {
            roster,
            da: da.sharing,
            nullification: nullification.sharing,
            signers,
            verifier,
        })
    }
}

/// Checkpoint certificates from the committee's nullification key.
impl<P: PublicKey, V: Variant, Q: Quorum> Generic<Scheme<P, V, Q>> {
    /// Returns the scheme that certifies [`aggregation`](crate::aggregation) checkpoints with
    /// this committee's `2f+1` nullification key, under the aggregation namespace `namespace`.
    ///
    /// A signer signs checkpoints with its nullification share, a verifier also verifies
    /// individual shares, and a certificate verifier verifies recovered certificates. See
    /// [`checkpoint`].
    pub fn checkpoint(&self, namespace: &[u8]) -> checkpoint::Scheme<P, V> {
        self.nullify().checkpoint(namespace)
    }
}

/// A committee dealt by [`Scheme::deal`].
pub struct Dealt<P: PublicKey, V: Variant, Q: Quorum = Available> {
    /// The verified ordinary-key roster.
    pub roster: Roster<P, V>,
    /// The data-availability sharing.
    pub da: Sharing<V>,
    /// The `2f+1` nullification sharing.
    pub nullification: Sharing<V>,
    /// One signer per participant, in roster order.
    pub signers: Vec<Generic<Scheme<P, V, Q>>>,
    /// A verifier holding both public sharings.
    pub verifier: Generic<Scheme<P, V, Q>>,
}

/// An ordinary synchronized aggregate key roster whose proofs of knowledge have been verified.
///
/// Multimmit aggregates ordinary signatures into V-QCs and L-QCs. Accepting a key whose holder
/// cannot prove knowledge of its secret would let that holder choose its key as a function of
/// others' keys and forge aggregates. Every proof is bound to the holder's identity, so no
/// participant can register another's key as its own.
#[derive(Clone)]
pub struct Roster<P: PublicKey, V: Variant> {
    participants: BiMap<P, sas::PublicKey<V>>,
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
    /// Verifies one proof of knowledge per participant and returns the ordered roster.
    ///
    /// `participants` pairs each identity with its ordinary public key and proof. Fails unless
    /// there are exactly `expected` entries with distinct identities and distinct keys with
    /// nonzero components whose proofs verify under `namespace`.
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

        let derived = super::Namespace::new(namespace);
        strategy.try_map_collect_vec(&participants, |(identity, public, proof)| {
            if public.x() == &V::Public::zero() || public.y() == &V::Public::zero() {
                return Err(Error::ProofOfKnowledge);
            }
            proof
                .verify(&derived.registration(identity.as_ref()), public)
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

    /// Proves knowledge of `private` for registration under `identity` and `namespace`.
    pub fn proof_of_knowledge(
        rng: &mut impl CryptoRng,
        namespace: &[u8],
        identity: &P,
        private: &sas::PrivateKey,
    ) -> sas::ProofOfKnowledge {
        let derived = super::Namespace::new(namespace);
        sas::ProofOfKnowledge::prove(
            rng,
            &derived.registration(identity.as_ref()),
            private,
            &sas::PublicKey::<V>::from_private(private),
        )
    }

    /// Returns the ordered identity-key committee.
    pub const fn participants(&self) -> &Set<P> {
        self.participants.keys()
    }

    /// Returns the ordinary public keys in identity-key order.
    pub const fn public_keys(&self) -> &BiMap<P, sas::PublicKey<V>> {
        &self.participants
    }

    fn ensure_namespace(&self, parameters: &Parameters) -> Result<(), Error> {
        if self.namespace != parameters.namespace() {
            return Err(Error::Namespace);
        }
        if self.participants.len() != parameters.codec_config().participants() {
            return Err(Error::Participants);
        }
        Ok(())
    }
}
