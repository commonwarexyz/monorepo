//! BLS12-381 multisig ordinary keys with threshold or aggregate data-availability keys and
//! threshold nullification keys.
//!
//! This is Multimmit's default suite:
//!
//! - ordinary keys sign BLS multi-signatures ([`ordinary`]), so a V-QC or L-QC aggregates its
//!   transcript into one signature that verifies with one pairing per distinct message;
//! - data-availability certificates at `n-2f` come from one of two DA roles:
//!   - [`Threshold`] (the default): an `n-2f` threshold sharing produces constant-size
//!     certificates ([`da`]); or
//!   - [`Aggregate`]: ordinary keys sign DA votes too, and a certificate aggregates them with a
//!     signer bitmap ([`da_aggregate`]), so it can count `n-f` signers and serve as a payment
//!     chain's receipt (the specification's one-signature-scheme variant); and
//! - a `2f+1` threshold sharing produces constant-size nullifications ([`nullify`]).
//!
//! # Registration
//!
//! Aggregating BLS signatures over different messages is only sound when no participant chose
//! its key as a function of others' keys. [`Roster`] verifies a proof of possession for every
//! ordinary key, bound to the participant's identity, before any scheme can be constructed. The
//! threshold sharings must be generated independently: constructors check their public
//! structure, thresholds, and distinct group identities, but cannot prove how key material was
//! generated.
//!
//! # Roles
//!
//! A signer holds its ordinary key and its threshold shares, a verifier holds the public
//! sharings, and a certificate verifier holds only the group identities. A certificate verifier
//! checks ordinary signatures and complete certificates but cannot check or recover shares.

use super::{Available, DaSubject, Error, Generic, Marker, RoleDigest};
use crate::multimmit::config::Parameters;
use bytes::BytesMut;
use commonware_codec::{Read, Write as _};
use commonware_cryptography::{
    PublicKey,
    bls12381::{
        certificate::{multisig, threshold},
        primitives::{
            group::{Private, Scalar, Share},
            ops,
            sharing::{Mode, ModeVersion, Sharing},
            variant::Variant,
        },
    },
    certificate::{self, Verifier},
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

/// Threshold data-availability keys at `n-2f`, the [`Threshold`] DA role.
pub mod da {
    use crate::multimmit::scheme::{Available, DaSubject, Namespace};
    use commonware_cryptography::impl_certificate_bls12381_threshold;

    impl_certificate_bls12381_threshold!(DaSubject, Namespace, Available);
}

/// Ordinary keys signing data-availability votes, aggregated at `n-2f` or more with a signer
/// bitmap, the [`Aggregate`] DA role.
pub mod da_aggregate {
    use crate::multimmit::scheme::{Available, DaSubject, Namespace};
    use commonware_cryptography::impl_certificate_bls12381_multisig;

    impl_certificate_bls12381_multisig!(DaSubject, Namespace, Available);
}

/// `2f+1` threshold nullification keys.
pub mod nullify {
    use crate::multimmit::scheme::{Namespace, NullifyFaults, NullifySubject};
    use commonware_cryptography::impl_certificate_bls12381_threshold;

    impl_certificate_bls12381_threshold!(NullifySubject, Namespace, NullifyFaults);
}

/// Data-availability certificates from an `n-2f` threshold sharing (the default).
///
/// Certificates are constant-size and verify against one group key, but do not reveal their
/// signers, so an epoch with payment chains cannot use them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Threshold;

/// Data-availability certificates that aggregate ordinary-key signatures with a signer bitmap.
///
/// Certificates grow by a bitmap of `ceil(n/8)` bytes and are not unique as bit strings, but count
/// their signers, so a payment chain's producer can form `n-f` receipts. No DA key sharing is
/// dealt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Aggregate;

/// A BLS12-381 data-availability role: [`Threshold`] or [`Aggregate`].
pub trait DaRole: Copy + fmt::Debug + Default + Eq + Hash + Send + Sync + 'static {
    /// The DA role scheme over identities `P` and BLS variant `V`.
    type Da<P: PublicKey, V: Variant>: for<'a> certificate::Scheme<
            PublicKey = P,
            Faults = Available,
            Signature = V::Signature,
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

    fn signers<P: PublicKey, V: Variant>(certificate: &multisig::Certificate<V>) -> Option<usize> {
        Some(certificate.signers.count())
    }
}

/// The BLS12-381 multisig suite over identities `P` and BLS variant `V`, with the DA role `R`.
///
/// `V` may be either [`MinPk`](commonware_cryptography::bls12381::primitives::variant::MinPk)
/// or [`MinSig`](commonware_cryptography::bls12381::primitives::variant::MinSig).
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
        formatter.write_str("bls12381::Scheme")
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
    /// Ordinary BLS signing key registered in the [`Roster`].
    pub ordinary: Private,
    /// Share of the data-availability sharing.
    pub da: Share,
    /// Share of the `2f+1` nullification sharing.
    pub nullification: Share,
}

/// Returns the local participant of a roster, by its ordinary public key.
fn roster_participant<P: PublicKey, V: Variant>(
    roster: &Roster<P, V>,
    ordinary: &Private,
) -> Result<Participant, Error> {
    let ordinary = ops::compute_public::<V>(ordinary);
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
    /// Every ordinary key, its proof of possession, and both sharings derive from `rng`, so
    /// whoever runs the dealer learns every secret. The roster lists `identities` in order.
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
    /// The ordinary key also signs DA votes, under their own namespace. See the module-level
    /// security requirements. Fails when the key, share, sharing, or participant index is
    /// inconsistent with the epoch configuration.
    pub fn signer(
        parameters: &Arc<Parameters>,
        roster: Roster<P, V>,
        ordinary: Private,
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
    /// Every ordinary key, its proof of possession, and the nullification sharing derive from
    /// `rng`, so whoever runs the dealer learns every secret. The roster lists `identities` in
    /// order.
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

/// Deals one ordinary key per identity with its proof of possession, and verifies the roster.
fn deal_roster<P: PublicKey, V: Variant>(
    rng: &mut impl CryptoRng,
    parameters: &Parameters,
    identities: &Set<P>,
) -> Result<(Roster<P, V>, Vec<Private>), Error> {
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

/// Checks the public nullification sharing against the epoch configuration and precomputes its
/// partial public keys.
pub(super) fn validate_nullification_sharing<V: Variant>(
    parameters: &Parameters,
    nullification: &Sharing<V>,
) -> Result<(), Error> {
    let total = parameters.codec_config().participants();
    if !valid_sharing(nullification, total, N5f1::nullification_quorum(total)) {
        return Err(Error::Sharing);
    }
    nullification.precompute_partial_publics();
    Ok(())
}

/// Checks that a share belongs to `participant` and to its sharing.
pub(super) fn validate_share<V: Variant>(
    participant: Participant,
    share: &Share,
    sharing: &Sharing<V>,
) -> Result<(), Error> {
    if share.index != participant
        || sharing.partial_public(participant).map_err(|_| Error::Share)? != share.public::<V>()
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

/// Deals the nullification sharing of an epoch.
pub(super) fn deal_nullification_sharing<V: Variant>(
    rng: &mut impl CryptoRng,
    parameters: &Parameters,
) -> Result<DealtSharing<V>, Error> {
    let codec = parameters.codec_config();
    Ok(deal_sharing::<V>(
        rng,
        u32::try_from(codec.participants()).map_err(|_| Error::Participants)?,
        u32::try_from(codec.nullification_quorum()).map_err(|_| Error::Participants)?,
    ))
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
