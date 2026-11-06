//! Pointcheval-Sanders synchronized aggregate ordinary keys with threshold or aggregate
//! data-availability keys and threshold nullification keys.
//!
//! **ALPHA, research grade.** Ordinary keys sign synchronized aggregate signatures
//! ([`sas`]), which aggregate across
//! signers that share a [`Synchronized`](commonware_cryptography::certificate::Synchronized)
//! period. Every signature in one V-QC or L-QC shares its view period, so a certificate verifies
//! with one pairing product however many distinct vote bodies it covers. The nullification role is
//! the threshold role of [`bls12381`](super::bls12381). The DA role is either the same threshold
//! role ([`Threshold`]) or ordinary keys signing DA votes in their chain-position period, aggregated
//! with a signer bitmap ([`Aggregate`], [`da_aggregate`]), whose certificates can serve as payment
//! chains' receipts.
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
//!   every clone. The [`Aggregate`] DA role holds a second table.

pub use super::bls12381::{Aggregate, Threshold};
use super::{
    Available, DaSubject, Error, Generic, Marker, RoleDigest,
    bls12381::{
        da, deal_nullification_sharing, deal_sharings, nullify, validate_identities,
        validate_nullification_sharing, validate_share, validate_shares, validate_sharings,
    },
};
use crate::multimmit::config::Parameters;
use commonware_codec::Read;
use commonware_cryptography::{
    PublicKey,
    bls12381::{
        certificate::{sas as sas_certificate, threshold},
        primitives::{group::Share, ops::sas, sharing::Sharing, variant::Variant},
    },
    certificate::{self, Verifier},
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

/// Synchronized aggregate ordinary keys signing data-availability votes, aggregated at `n-2f` or
/// more with a signer bitmap, the [`Aggregate`] DA role.
pub mod da_aggregate {
    use crate::multimmit::scheme::{Available, DaSubject, Namespace};
    use commonware_cryptography::impl_certificate_bls12381_sas;

    impl_certificate_bls12381_sas!(DaSubject, Namespace, Available);
}

/// A synchronized aggregate suite's data-availability role: [`Threshold`] or [`Aggregate`].
pub trait DaRole: Copy + fmt::Debug + Default + Eq + Hash + Send + Sync + 'static {
    /// The DA role scheme over identities `P` and BLS variant `V`.
    type Da<P: PublicKey, V: Variant>: for<'a> certificate::Scheme<
            PublicKey = P,
            Faults = Available,
            Subject<'a, RoleDigest> = DaSubject,
        >;

    /// Returns the decoding configuration of a certificate in a committee of `participants`.
    #[doc(hidden)]
    fn certificate_config<P: PublicKey, V: Variant>(
        participants: usize,
    ) -> <<Self::Da<P, V> as Verifier>::Certificate as Read>::Cfg;

    /// Returns how many signers a certificate aggregates, or `None` when it does not reveal them.
    #[doc(hidden)]
    fn signers<P: PublicKey, V: Variant>(
        certificate: &<Self::Da<P, V> as Verifier>::Certificate,
    ) -> Option<usize>;
}

impl DaRole for Threshold {
    type Da<P: PublicKey, V: Variant> = da::Scheme<P, V>;

    fn certificate_config<P: PublicKey, V: Variant>(_: usize) {}

    fn signers<P: PublicKey, V: Variant>(_: &threshold::Certificate<V>) -> Option<usize> {
        None
    }
}

impl DaRole for Aggregate {
    type Da<P: PublicKey, V: Variant> = da_aggregate::Scheme<P, V>;

    fn certificate_config<P: PublicKey, V: Variant>(participants: usize) -> usize {
        participants
    }

    fn signers<P: PublicKey, V: Variant>(
        certificate: &sas_certificate::Certificate<V>,
    ) -> Option<usize> {
        Some(certificate.signers.count())
    }
}

/// The synchronized aggregate suite over identities `P` and BLS variant `V`, with the DA role `R`.
pub struct Scheme<P, V, R = Threshold>(Marker<(P, V, R)>);

impl<P, V, R> Clone for Scheme<P, V, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P, V, R> Copy for Scheme<P, V, R> {}

impl<P, V, R> Default for Scheme<P, V, R> {
    fn default() -> Self {
        Self(Marker::default())
    }
}

impl<P, V, R> PartialEq for Scheme<P, V, R> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<P, V, R> Eq for Scheme<P, V, R> {}

impl<P, V, R> Hash for Scheme<P, V, R> {
    fn hash<H: core::hash::Hasher>(&self, _: &mut H) {}
}

impl<P, V, R> fmt::Debug for Scheme<P, V, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bls12381_sas::Scheme")
    }
}

impl<P: PublicKey, V: Variant, R: DaRole> super::Scheme for Scheme<P, V, R> {
    type PublicKey = P;
    type Ordinary = ordinary::Scheme<P, V>;
    type Da = R::Da<P, V>;
    type Nullify = nullify::Scheme<P, V>;

    fn da_certificate_config(participants: usize) -> <super::DaCertificateOf<Self> as Read>::Cfg {
        R::certificate_config::<P, V>(participants)
    }

    fn nullification_config(_: usize) {}

    fn da_signers(_: &Self::Da, certificate: &super::DaCertificateOf<Self>) -> Option<usize> {
        R::signers::<P, V>(certificate)
    }
}

/// The local participant's secret key material under the [`Threshold`] DA role.
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

/// Returns the local participant of a roster, by its ordinary public key.
fn roster_participant<P: PublicKey, V: Variant>(
    roster: &Roster<P, V>,
    ordinary: &sas::PrivateKey,
) -> Result<Participant, Error> {
    let ordinary = sas::PublicKey::<V>::from_private(ordinary);
    roster
        .participants
        .values()
        .iter()
        .position(|public| public == &ordinary)
        .map(Participant::from_usize)
        .ok_or(Error::UnknownKey)
}

impl<P: PublicKey, V: Variant> Scheme<P, V, Threshold> {
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
        validate_sharings(parameters, &da, &nullification)?;
        let participant = roster_participant(&roster, &keys.ordinary)?;
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
        let da = da::Scheme::signer(namespace, identities.clone(), da, keys.da).ok_or(Error::Share)?;
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
        validate_sharings(parameters, &da, &nullification)?;
        let namespace = parameters.namespace();
        let identities = roster.participants.keys().clone();
        let ordinary = ordinary::Scheme::verifier(namespace, roster.participants);
        let da = da::Scheme::verifier(namespace, identities.clone(), da);
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
        let da = da::Scheme::certificate_verifier(namespace, da_identity);
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
    ) -> Result<Dealt<P, V>, Error> {
        let (roster, ordinary) = deal_roster::<P, V>(rng, parameters, identities)?;
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

impl<P: PublicKey, V: Variant> Scheme<P, V, Aggregate> {
    /// Creates a signer from the local participant's ordinary key and nullification share.
    ///
    /// The ordinary key also signs DA votes, under their own namespace and chain-position period.
    /// See the module-level security requirements. Fails when the key, share, sharing, or
    /// participant index is inconsistent with the epoch configuration.
    pub fn signer(
        parameters: &Arc<Parameters>,
        roster: Roster<P, V>,
        ordinary: sas::PrivateKey,
        nullification_share: Share,
        nullification: Sharing<V>,
    ) -> Result<Generic<Self>, Error> {
        roster.ensure_namespace(parameters)?;
        validate_nullification_sharing(parameters, &nullification)?;
        let participant = roster_participant(&roster, &ordinary)?;
        validate_share(participant, &nullification_share, &nullification)?;
        let namespace = parameters.namespace();
        let identities = roster.participants.keys().clone();
        let da = da_aggregate::Scheme::signer(namespace, roster.participants.clone(), ordinary.clone())
            .ok_or(Error::UnknownKey)?;
        let ordinary = ordinary::Scheme::signer(namespace, roster.participants, ordinary)
            .ok_or(Error::UnknownKey)?;
        let nullify =
            nullify::Scheme::signer(namespace, identities, nullification, nullification_share)
                .ok_or(Error::Share)?;
        Generic::new(parameters, ordinary, da, nullify)
    }

    /// Creates a verifier with the ordinary key roster and the public nullification sharing.
    pub fn verifier(
        parameters: &Arc<Parameters>,
        roster: Roster<P, V>,
        nullification: Sharing<V>,
    ) -> Result<Generic<Self>, Error> {
        roster.ensure_namespace(parameters)?;
        validate_nullification_sharing(parameters, &nullification)?;
        let namespace = parameters.namespace();
        let identities = roster.participants.keys().clone();
        let da = da_aggregate::Scheme::verifier(namespace, roster.participants.clone());
        let ordinary = ordinary::Scheme::verifier(namespace, roster.participants);
        let nullify = nullify::Scheme::verifier(namespace, identities, nullification);
        Generic::new(parameters, ordinary, da, nullify)
    }

    /// Creates a verifier for complete certificates without retaining the public nullification
    /// sharing.
    ///
    /// This role verifies ordinary signatures, V-QCs, L-QCs, DA certificates, receipts, and
    /// recovered nullifications. It cannot verify DA votes or recover nullifications.
    pub fn certificate_verifier(
        parameters: &Arc<Parameters>,
        roster: Roster<P, V>,
        nullification_identity: V::Public,
    ) -> Result<Generic<Self>, Error> {
        roster.ensure_namespace(parameters)?;
        if nullification_identity == V::Public::zero() {
            return Err(Error::Sharing);
        }
        let namespace = parameters.namespace();
        let da = da_aggregate::Scheme::verifier(namespace, roster.participants.clone());
        let ordinary = ordinary::Scheme::verifier(namespace, roster.participants);
        let nullify = nullify::Scheme::certificate_verifier(namespace, nullification_identity);
        Generic::new(parameters, ordinary, da, nullify).map(Generic::certificates_only)
    }

    /// Deals a complete committee from one trusted dealer, for tests and local deployments.
    ///
    /// Every ordinary key, its proof of knowledge, and the nullification sharing derive from
    /// `rng`, so whoever runs the dealer learns every secret.
    pub fn deal(
        rng: &mut impl CryptoRng,
        parameters: &Arc<Parameters>,
        identities: &Set<P>,
    ) -> Result<AggregateDealt<P, V>, Error> {
        let (roster, ordinary) = deal_roster::<P, V>(rng, parameters, identities)?;
        let nullification = deal_nullification_sharing::<V>(rng, parameters)?;
        let signers = ordinary
            .into_iter()
            .zip(nullification.shares)
            .map(|(ordinary, share)| {
                Self::signer(
                    parameters,
                    roster.clone(),
                    ordinary,
                    share,
                    nullification.sharing.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let verifier = Self::verifier(parameters, roster.clone(), nullification.sharing.clone())?;
        Ok(AggregateDealt {
            roster,
            nullification: nullification.sharing,
            signers,
            verifier,
        })
    }
}

/// Deals one ordinary key per identity with its proof of knowledge, and verifies the roster.
fn deal_roster<P: PublicKey, V: Variant>(
    rng: &mut impl CryptoRng,
    parameters: &Parameters,
    identities: &Set<P>,
) -> Result<(Roster<P, V>, Vec<sas::PrivateKey>), Error> {
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
        parameters.codec_config().participants(),
        roster_input,
        &Sequential,
    )?;
    Ok((roster, ordinary))
}

/// A committee dealt by [`Scheme::deal`] under the [`Threshold`] DA role.
pub struct Dealt<P: PublicKey, V: Variant> {
    /// The verified ordinary-key roster.
    pub roster: Roster<P, V>,
    /// The data-availability sharing.
    pub da: Sharing<V>,
    /// The `2f+1` nullification sharing.
    pub nullification: Sharing<V>,
    /// One signer per participant, in roster order.
    pub signers: Vec<Generic<Scheme<P, V, Threshold>>>,
    /// A verifier holding both public sharings.
    pub verifier: Generic<Scheme<P, V, Threshold>>,
}

/// A committee dealt by [`Scheme::deal`] under the [`Aggregate`] DA role.
pub struct AggregateDealt<P: PublicKey, V: Variant> {
    /// The verified ordinary-key roster.
    pub roster: Roster<P, V>,
    /// The `2f+1` nullification sharing.
    pub nullification: Sharing<V>,
    /// One signer per participant, in roster order.
    pub signers: Vec<Generic<Scheme<P, V, Aggregate>>>,
    /// A verifier holding the public nullification sharing.
    pub verifier: Generic<Scheme<P, V, Aggregate>>,
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
