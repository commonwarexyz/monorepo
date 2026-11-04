//! BLS12-381 multisig ordinary keys with threshold data-availability and nullification keys.
//!
//! This is Multimmit's default suite:
//!
//! - ordinary keys sign BLS multi-signatures ([`ordinary`]), so a V-QC or L-QC aggregates its
//!   transcript into one signature that verifies with one pairing per distinct message;
//! - a threshold sharing at the epoch's [`DaQuorum`](crate::multimmit::types::DaQuorum) (`n-2f`,
//!   or `n-f` for binding certificates) produces constant-size data-availability certificates
//!   ([`da`] or [`da_binding`]); and
//! - a `2f+1` threshold sharing produces constant-size nullifications ([`nullify`]).
//!
//! # Registration
//!
//! Aggregating BLS signatures over different messages is only sound when no participant chose
//! its key as a function of others' keys. [`Roster`] verifies a proof of possession for every
//! ordinary key, bound to the participant's identity, before any scheme can be constructed. The
//! DA and nullification sharings must be generated independently: constructors check their public
//! structure, thresholds, and distinct group identities, but cannot prove how key material was
//! generated.
//!
//! # Roles
//!
//! A signer holds its ordinary key and both threshold shares, a verifier holds both public
//! sharings, and a certificate verifier holds only both group identities. A certificate verifier
//! checks ordinary signatures and recovered certificates but cannot check or recover shares.

use super::{Available, Binding, DaFaults, DaSubject, Error, Generic, Marker, RoleDigest};
use crate::multimmit::{checkpoint, config::Parameters};
use bytes::BytesMut;
use commonware_codec::{Read as _, Write as _};
use commonware_cryptography::{
    PublicKey,
    bls12381::{
        certificate::threshold,
        primitives::{
            group::{Private, Scalar, Share},
            ops,
            sharing::{Mode, ModeVersion, Sharing},
            variant::Variant,
        },
    },
    certificate,
};
use commonware_math::{algebra::Additive, poly::Poly};
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::{
    N5f1, Participant, TryFromIterator,
    ordered::{BiMap, Set},
};
use core::{fmt, hash::Hash, num::NonZeroU32};
use rand_core::CryptoRng;
use std::{collections::HashSet, sync::Arc};

/// BLS multisig ordinary keys over [`OrdinarySubject`](super::OrdinarySubject)s.
pub mod ordinary {
    use crate::multimmit::scheme::{Namespace, OrdinarySubject};
    use commonware_cryptography::impl_certificate_bls12381_multisig;
    use commonware_utils::N5f1;

    impl_certificate_bls12381_multisig!(OrdinarySubject, Namespace, N5f1);
}

/// Threshold data-availability keys at the `n-2f` quorum of
/// [`DaQuorum::Available`](crate::multimmit::types::DaQuorum::Available).
pub mod da {
    use crate::multimmit::scheme::{Available, DaSubject, Namespace};
    use commonware_cryptography::impl_certificate_bls12381_threshold;

    impl_certificate_bls12381_threshold!(DaSubject, Namespace, Available);
}

/// Threshold data-availability keys at the `n-f` quorum of
/// [`DaQuorum::Binding`](crate::multimmit::types::DaQuorum::Binding).
pub mod da_binding {
    use crate::multimmit::scheme::{Binding, DaSubject, Namespace};
    use commonware_cryptography::impl_certificate_bls12381_threshold;

    impl_certificate_bls12381_threshold!(DaSubject, Namespace, Binding);
}

/// `2f+1` threshold nullification keys.
///
/// [`Scheme`](nullify::Scheme) is the threshold scheme that
/// [`impl_certificate_bls12381_threshold!`](commonware_cryptography::impl_certificate_bls12381_threshold)
/// generates, written out so the same sharing can also certify
/// [`checkpoint`]s.
pub mod nullify {
    use crate::multimmit::{
        checkpoint,
        scheme::{Namespace, NullifySubject},
    };
    use commonware_cryptography::{
        Digest, PublicKey,
        bls12381::{
            certificate::threshold::{self, Generic},
            primitives::{group::Share, sharing::Sharing, variant::Variant},
        },
        certificate::{self, AssemblyError, Attestation, Membership, Verification},
    };
    use commonware_parallel::Strategy;
    use commonware_utils::{faults::N5f1Nullification, iter::NonEmpty, ordered::Set};
    use rand_core::CryptoRng;

    /// BLS12-381 threshold nullification scheme at the `2f+1` quorum.
    #[derive(Clone, Debug)]
    pub struct Scheme<P: PublicKey, V: Variant>(Generic<P, V, Namespace>);

    impl<P: PublicKey, V: Variant> Scheme<P, V> {
        /// Creates a signer from the nullification sharing and the local share.
        ///
        /// Returns `None` if the share does not belong to the sharing.
        ///
        /// # Panics
        ///
        /// Panics if the sharing does not have one share per participant at the `2f+1`
        /// threshold, or if the share index is not a participant.
        pub fn signer(
            namespace: &[u8],
            participants: Set<P>,
            sharing: Sharing<V>,
            share: Share,
        ) -> Option<Self> {
            Generic::signer::<N5f1Nullification>(namespace, participants, sharing, share).map(Self)
        }

        /// Creates a verifier that can check and recover nullify shares.
        ///
        /// # Panics
        ///
        /// Panics if the sharing does not have one share per participant at the `2f+1`
        /// threshold.
        pub fn verifier(namespace: &[u8], participants: Set<P>, sharing: Sharing<V>) -> Self {
            Self(Generic::verifier::<N5f1Nullification>(
                namespace,
                participants,
                sharing,
            ))
        }

        /// Creates a verifier that only checks recovered nullifications.
        pub fn certificate_verifier(namespace: &[u8], identity: V::Public) -> Self {
            Self(Generic::certificate_verifier(namespace, identity))
        }

        /// Returns the group identity of the nullification sharing.
        pub fn identity(&self) -> &V::Public {
            self.0.identity()
        }

        /// Returns the local share if this instance can sign.
        pub const fn share(&self) -> Option<&Share> {
            self.0.share()
        }

        /// Returns the scheme that certifies checkpoints with the same key material, under the
        /// aggregation namespace `namespace`.
        ///
        /// A signer signs checkpoints with its share, a verifier also verifies individual
        /// checkpoint shares, and a certificate verifier verifies recovered certificates.
        pub fn checkpoint(&self, namespace: &[u8]) -> checkpoint::Scheme<P, V> {
            match &self.0 {
                Generic::Signer {
                    participants,
                    polynomial,
                    share,
                    ..
                } => checkpoint::Scheme::signer(
                    namespace,
                    participants.clone(),
                    polynomial.clone(),
                    share.clone(),
                )
                .expect("a signer's share belongs to its sharing"),
                Generic::Verifier {
                    participants,
                    polynomial,
                    ..
                } => checkpoint::Scheme::verifier(
                    namespace,
                    participants.clone(),
                    polynomial.clone(),
                ),
                Generic::CertificateVerifier { identity, .. } => {
                    checkpoint::Scheme::certificate_verifier(namespace, *identity)
                }
            }
        }
    }

    impl<P: PublicKey, V: Variant> certificate::Verifier for Scheme<P, V> {
        type Subject<'a, D: Digest> = NullifySubject;
        type Faults = N5f1Nullification;
        type PublicKey = P;
        type Certificate = threshold::Certificate<V>;

        fn verify_certificate<R, D>(
            &self,
            rng: &mut R,
            subject: NullifySubject,
            certificate: &Self::Certificate,
            _strategy: &impl Strategy,
        ) -> bool
        where
            R: CryptoRng,
            D: Digest,
        {
            self.0.verify_certificate(rng, subject, certificate)
        }

        fn verify_certificates<'a, R, D, I>(
            &self,
            rng: &mut R,
            certificates: NonEmpty<I>,
            strategy: &impl Strategy,
        ) -> bool
        where
            R: CryptoRng,
            D: Digest,
            I: Iterator<Item = (NullifySubject, &'a Self::Certificate)>,
        {
            self.0.verify_certificates(rng, certificates, strategy)
        }

        fn is_batchable() -> bool {
            Generic::<P, V, Namespace>::is_batchable()
        }

        fn max_certificate_size(_participants: u32) -> usize {
            <Self::Certificate as commonware_codec::FixedSize>::SIZE
        }

        fn certificate_codec_config(&self) {}

        fn certificate_codec_config_unbounded() {}
    }

    impl<P: PublicKey, V: Variant> certificate::Scheme for Scheme<P, V> {
        type Signature = V::Signature;

        fn me(&self) -> Option<Membership> {
            self.0.signer_index().map(Membership::Signer)
        }

        fn participants(&self) -> &Set<P> {
            self.0.participants()
        }

        fn sign<D: Digest>(&self, subject: NullifySubject) -> Option<Attestation<Self>> {
            self.0.sign(subject)
        }

        fn verify_attestation<R, D>(
            &self,
            _rng: &mut R,
            subject: NullifySubject,
            attestation: &Attestation<Self>,
            _strategy: &impl Strategy,
        ) -> bool
        where
            R: CryptoRng,
            D: Digest,
        {
            self.0.verify_attestation(subject, attestation)
        }

        fn verify_attestations<R, D, I>(
            &self,
            rng: &mut R,
            subject: NullifySubject,
            attestations: I,
            strategy: &impl Strategy,
        ) -> Verification<Self>
        where
            R: CryptoRng,
            D: Digest,
            I: IntoIterator<Item = Attestation<Self>>,
            I::IntoIter: Send,
        {
            self.0
                .verify_attestations(rng, subject, attestations, strategy)
        }

        fn optimistic_assemble<'a, R, D, I, J>(
            &self,
            rng: &mut R,
            subject: NullifySubject,
            pending: I,
            verified: J,
            strategy: &impl Strategy,
        ) -> Result<Self::Certificate, Verification<Self>>
        where
            R: CryptoRng,
            D: Digest,
            I: IntoIterator<Item = Attestation<Self>>,
            I::IntoIter: ExactSizeIterator + Send,
            J: IntoIterator<Item = &'a Attestation<Self>>,
            J::IntoIter: Send,
        {
            certificate::optimistic_assemble::<Self, _, D, _, _>(
                self, rng, subject, pending, verified, strategy,
            )
        }

        fn assemble<I>(
            &self,
            attestations: NonEmpty<I>,
            strategy: &impl Strategy,
        ) -> Result<Self::Certificate, AssemblyError>
        where
            I: Iterator<Item = Attestation<Self>> + Send,
        {
            self.0.assemble::<Self, _>(attestations, strategy)
        }

        fn is_attributable() -> bool {
            Generic::<P, V, Namespace>::is_attributable()
        }
    }
}

/// A data-availability fault model with a BLS12-381 threshold DA role.
///
/// Implemented by [`Available`] ([`da`]) and [`Binding`] ([`da_binding`]).
pub trait Quorum: DaFaults {
    /// The threshold DA role at this quorum.
    type Da<P: PublicKey, V: Variant>: for<'a> certificate::Scheme<
            PublicKey = P,
            Faults = Self,
            Certificate = threshold::Certificate<V>,
            Signature = V::Signature,
            Subject<'a, RoleDigest> = DaSubject,
        >;

    /// Builds a DA signer. The sharing must be validated first.
    #[doc(hidden)]
    fn signer<P: PublicKey, V: Variant>(
        namespace: &[u8],
        participants: Set<P>,
        sharing: Sharing<V>,
        share: Share,
    ) -> Option<Self::Da<P, V>>;

    /// Builds a DA verifier. The sharing must be validated first.
    #[doc(hidden)]
    fn verifier<P: PublicKey, V: Variant>(
        namespace: &[u8],
        participants: Set<P>,
        sharing: Sharing<V>,
    ) -> Self::Da<P, V>;

    /// Builds a DA certificate verifier.
    #[doc(hidden)]
    fn certificate_verifier<P: PublicKey, V: Variant>(
        namespace: &[u8],
        identity: V::Public,
    ) -> Self::Da<P, V>;
}

macro_rules! impl_quorum {
    ($faults:ty, $module:ident) => {
        impl Quorum for $faults {
            type Da<P: PublicKey, V: Variant> = $module::Scheme<P, V>;

            fn signer<P: PublicKey, V: Variant>(
                namespace: &[u8],
                participants: Set<P>,
                sharing: Sharing<V>,
                share: Share,
            ) -> Option<Self::Da<P, V>> {
                $module::Scheme::signer(namespace, participants, sharing, share)
            }

            fn verifier<P: PublicKey, V: Variant>(
                namespace: &[u8],
                participants: Set<P>,
                sharing: Sharing<V>,
            ) -> Self::Da<P, V> {
                $module::Scheme::verifier(namespace, participants, sharing)
            }

            fn certificate_verifier<P: PublicKey, V: Variant>(
                namespace: &[u8],
                identity: V::Public,
            ) -> Self::Da<P, V> {
                $module::Scheme::certificate_verifier(namespace, identity)
            }
        }
    };
}

impl_quorum!(Available, da);
impl_quorum!(Binding, da_binding);

/// The BLS12-381 multisig suite over identities `P` and BLS variant `V`, with DA certificates at
/// the quorum `Q`.
///
/// `V` may be either [`MinPk`](commonware_cryptography::bls12381::primitives::variant::MinPk)
/// or [`MinSig`](commonware_cryptography::bls12381::primitives::variant::MinSig).
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
        formatter.write_str("bls12381::Scheme")
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
    /// Ordinary BLS signing key registered in the [`Roster`].
    pub ordinary: Private,
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
        let ordinary = ops::compute_public::<V>(&keys.ordinary);
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
    /// Every ordinary key, its proof of possession, and both sharings derive from `rng`, so
    /// whoever runs the dealer learns every secret. The roster lists `identities` in order.
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
                let (private, public) = ops::keypair::<_, V>(&mut *rng);
                let proof =
                    Roster::<P, V>::proof_of_possession(parameters.namespace(), identity, &private);
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

/// A sharing and every participant's share, dealt by one trusted dealer.
pub struct DealtSharing<V: Variant> {
    /// The public sharing.
    pub sharing: Sharing<V>,
    /// One share per participant, in participant order.
    pub shares: Vec<Share>,
}

/// An ordinary BLS key roster whose proofs of possession have been verified.
///
/// Multimmit aggregates ordinary signatures over different messages into V-QCs and L-QCs.
/// Accepting a key whose holder cannot prove possession of its secret would let that holder
/// choose its key as a function of others' keys and forge aggregates (a rogue-key attack). Every
/// proof signs under a namespace bound to the holder's identity, so no participant can register
/// another's key as its own.
#[derive(Clone)]
pub struct Roster<P: PublicKey, V: Variant> {
    participants: BiMap<P, V::Public>,
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
    /// Verifies one proof of possession per participant and returns the ordered roster.
    ///
    /// `participants` pairs each identity with its ordinary public key and proof. Fails unless
    /// there are exactly `expected` entries with distinct identities and distinct, nonzero keys
    /// whose proofs verify under `namespace`.
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

        let derived = super::Namespace::new(namespace);
        strategy.try_map_collect_vec(&participants, |(identity, public, proof)| {
            if public == &V::Public::zero() {
                return Err(Error::ProofOfKnowledge);
            }
            ops::verify_proof_of_possession::<V>(
                public,
                &derived.registration(identity.as_ref()),
                proof,
            )
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

    /// Proves possession of `private` for registration under `identity` and `namespace`.
    pub fn proof_of_possession(namespace: &[u8], identity: &P, private: &Private) -> V::Signature {
        let derived = super::Namespace::new(namespace);
        ops::sign_proof_of_possession::<V>(private, &derived.registration(identity.as_ref()))
    }

    /// Returns the ordered identity-key committee.
    pub const fn participants(&self) -> &Set<P> {
        self.participants.keys()
    }

    /// Returns the ordinary public keys in identity-key order.
    pub const fn public_keys(&self) -> &BiMap<P, V::Public> {
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

/// Checks that the suite's DA fault model matches the epoch's, before any threshold role is
/// built over a sharing dealt for the epoch's quorum.
pub(super) fn ensure_da_quorum<Q: DaFaults>(parameters: &Parameters) -> Result<(), Error> {
    if Q::QUORUM != parameters.codec_config().da_quorum_kind() {
        return Err(Error::DaQuorum);
    }
    Ok(())
}

/// Checks both group identities: nonzero and distinct.
pub(super) fn validate_identities<V: Variant>(
    da: &V::Public,
    nullification: &V::Public,
) -> Result<(), Error> {
    if da == &V::Public::zero() || nullification == &V::Public::zero() {
        return Err(Error::Sharing);
    }
    if da == nullification {
        return Err(Error::SharedIdentity);
    }
    Ok(())
}

/// Checks both public sharings against the epoch configuration and precomputes their partial
/// public keys.
pub(super) fn validate_sharings<V: Variant>(
    parameters: &Parameters,
    da: &Sharing<V>,
    nullification: &Sharing<V>,
) -> Result<(), Error> {
    validate_identities::<V>(da.public(), nullification.public())?;
    let codec = parameters.codec_config();
    let total = codec.participants();
    let da_quorum = u32::try_from(codec.da_quorum()).map_err(|_| Error::Participants)?;
    if !valid_sharing(da, total, da_quorum)
        || !valid_sharing(nullification, total, N5f1::nullification_quorum(total))
    {
        return Err(Error::Sharing);
    }
    da.precompute_partial_publics();
    nullification.precompute_partial_publics();
    Ok(())
}

/// Checks that both shares belong to `participant` and to their sharings.
pub(super) fn validate_shares<V: Variant>(
    participant: Participant,
    da_share: &Share,
    nullification_share: &Share,
    da: &Sharing<V>,
    nullification: &Sharing<V>,
) -> Result<(), Error> {
    if da_share.index != participant
        || nullification_share.index != participant
        || da.partial_public(participant).map_err(|_| Error::Share)? != da_share.public::<V>()
        || nullification
            .partial_public(participant)
            .map_err(|_| Error::Share)?
            != nullification_share.public::<V>()
    {
        return Err(Error::Share);
    }
    Ok(())
}

fn valid_sharing<V: Variant>(sharing: &Sharing<V>, total: usize, required: u32) -> bool {
    if sharing.total().get() as usize != total
        || sharing.required() != required
        || sharing.public() == &V::Public::zero()
    {
        return false;
    }

    let mut publics = HashSet::with_capacity(total);
    (0..total).all(|index| {
        let Ok(public) = sharing.partial_public(Participant::from_usize(index)) else {
            return false;
        };
        public != V::Public::zero() && publics.insert(public)
    })
}

/// Deals the DA and nullification sharings of an epoch.
pub(super) fn deal_sharings<V: Variant>(
    rng: &mut impl CryptoRng,
    parameters: &Parameters,
) -> Result<(DealtSharing<V>, DealtSharing<V>), Error> {
    let codec = parameters.codec_config();
    let participants = u32::try_from(codec.participants()).map_err(|_| Error::Participants)?;
    let da = deal_sharing::<V>(
        rng,
        participants,
        u32::try_from(codec.da_quorum()).map_err(|_| Error::Participants)?,
    );
    let nullification = deal_sharing::<V>(
        rng,
        participants,
        u32::try_from(codec.nullification_quorum()).map_err(|_| Error::Participants)?,
    );
    Ok((da, nullification))
}

/// Deals one sharing of `total` shares with threshold `required`.
pub fn deal_sharing<V: Variant>(
    rng: &mut impl CryptoRng,
    total: u32,
    required: u32,
) -> DealtSharing<V> {
    let private = Poly::<Scalar>::new(rng, required - 1);
    let shares = (0..total)
        .map(|index| {
            let point = Scalar::from_u64(u64::from(index) + 1);
            Share::new(Participant::new(index), Private::new(private.eval(&point)))
        })
        .collect();
    let public = Poly::<V::Public>::commit(private);
    // A sharing has no public constructor from its polynomial; its canonical encoding is the
    // supported way to build one.
    let mut encoded = BytesMut::new();
    Mode::NonZeroCounter.write(&mut encoded);
    total.write(&mut encoded);
    public.write(&mut encoded);
    let mut encoded = encoded.freeze();
    let total = NonZeroU32::new(total).expect("a sharing has at least one participant");
    let sharing = Sharing::read_cfg(&mut encoded, &(total, ModeVersion::v0()))
        .expect("a freshly committed sharing decodes");
    DealtSharing { sharing, shares }
}
