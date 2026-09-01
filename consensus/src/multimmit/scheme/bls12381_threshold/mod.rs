//! BLS12-381 signatures and threshold certificates without a VRF.
//!
//! Multimmit uses three independent key roles:
//!
//! - ordinary BLS keys authenticate transaction blocks, leader blocks, votes, and novotes;
//! - an `n-2f` threshold sharing produces constant-size data-availability certificates; and
//! - a `2f+1` threshold sharing produces constant-size nullifications.
//!
//! V-QCs and L-QCs aggregate the ordinary signatures represented by their compact
//! signer-to-message transcripts. They are not recovered threshold signatures.
//!
//! # Roles
//!
//! A [`Scheme`] is a signer (ordinary key plus both threshold shares), a verifier (both public
//! sharings), or a certificate verifier (both group identities only). A certificate verifier
//! checks ordinary signatures and recovered certificates but cannot check or recover shares.
//!
//! # Verification
//!
//! Every artifact decomposes into pairing claims after its structural checks. Individual
//! verifiers check those claims directly, and batch verification checks the claims of many
//! artifacts as one randomly scaled pairing product.

/// Declares a method public under the `mocks` feature, so benches and tests outside the crate
/// can drive it directly, and crate-private otherwise.
macro_rules! mocks_pub {
    ($(#[$meta:meta])* fn $($item:tt)*) => {
        #[cfg(any(test, feature = "mocks"))]
        $(#[$meta])*
        pub fn $($item)*

        #[cfg(not(any(test, feature = "mocks")))]
        $(#[$meta])*
        pub(crate) fn $($item)*
    };
}

mod assemble;
mod batch;
mod claims;
pub(crate) mod dealer;
mod roster;
#[cfg(not(target_arch = "wasm32"))]
mod sign;
#[cfg(test)]
mod tests;

use super::Namespace;
use crate::{
    Epochable,
    multimmit::{
        config::Parameters,
        types::{ChainId, CodecConfig, Error as TypesError, LeaderBlock, VoteBody},
    },
    types::Epoch,
};
#[cfg(any(test, feature = "mocks"))]
pub use assemble::SignatureVerification;
#[cfg(not(any(test, feature = "mocks", target_arch = "wasm32")))]
pub(crate) use assemble::SignatureVerification;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use batch::CertificateVotes;
use commonware_cryptography::{
    Digest, PublicKey,
    bls12381::primitives::{
        group::{Private, Share},
        ops,
        sharing::Sharing,
        variant::Variant,
    },
};
use commonware_math::algebra::Additive;
use commonware_utils::{
    N5f1, Participant,
    ordered::{BiMap, Set},
};
use core::fmt;
pub use dealer::{Dealt, deal};
pub use roster::Roster;
use std::{collections::HashSet, sync::Arc};

/// An error while constructing or verifying a Multimmit cryptographic artifact.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The scheme has no local signing material.
    #[error("scheme is verifier-only")]
    VerifierOnly,
    /// The scheme has only certificate-verification material.
    #[error("threshold sharing is unavailable")]
    SharingUnavailable,
    /// The local key does not own the producer or leader role.
    #[error("unexpected signer")]
    Signer,
    /// A signature, aggregate, share, or recovered certificate is invalid.
    #[error("invalid signature")]
    Signature,
    /// The supplied messages do not form the required certificate quorum.
    #[error("invalid quorum")]
    Quorum,
    /// A compact transcript does not reconstruct the supplied messages.
    #[error("invalid vote transcript")]
    Transcript,
    /// The object belongs to another epoch.
    #[error("epoch mismatch")]
    Context,
    /// The producer chain is outside the configured chain range.
    #[error("chain out of range")]
    Chain,
    /// A protocol object failed structural validation.
    #[error(transparent)]
    Types(#[from] TypesError),
    /// The roster was verified under another namespace.
    #[error("roster namespace mismatch")]
    Namespace,
    /// The roster does not have exactly one entry per committee participant.
    #[error("roster size does not match the committee")]
    Participants,
    /// Two roster entries share an identity or an ordinary key.
    #[error("duplicate roster entry")]
    DuplicateParticipant,
    /// An ordinary public key or its proof of possession is invalid.
    #[error("invalid proof of possession")]
    ProofOfPossession,
    /// A threshold sharing has the wrong size or threshold, or a zero or repeated key.
    #[error("invalid threshold sharing")]
    Sharing,
    /// The DA and nullification sharings share a group identity.
    #[error("threshold roles share a group identity")]
    SharedIdentity,
    /// The ordinary key is not in the roster.
    #[error("ordinary key is not in the roster")]
    UnknownKey,
    /// A threshold share does not belong to the local participant or to its sharing.
    #[error("threshold share mismatch")]
    Share,
}

/// The outcome of an optimistic data-availability recovery that did not produce a certificate.
///
/// A quorum of shares interpolates to the group signature exactly when every share is the
/// correct evaluation of the group polynomial, so a failed recovery is proof that at least one
/// share is invalid without saying which. [`Self::InvalidShares`] carries the attribution pass's
/// answer, and every named signer supplied a share that fails on its own partial public key.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) enum DaRecoveryError {
    /// The recovery could not be attempted against these shares at all.
    #[error(transparent)]
    Scheme(#[from] Error),
    /// The recovered signature is invalid, and exactly these signers supplied invalid shares.
    #[error("invalid data-availability shares")]
    InvalidShares(Vec<Participant>),
}

/// The local participant's secret key material.
///
/// Both shares must belong to the participant whose ordinary key is `ordinary`.
#[derive(Clone)]
pub struct SignerKeys {
    /// Ordinary BLS key registered in the [`Roster`].
    pub ordinary: Private,
    /// Share of the `n-2f` data-availability sharing.
    pub da: Share,
    /// Share of the `2f+1` nullification sharing.
    pub nullification: Share,
}

/// The key material a scheme holds, which fixes what it can sign and verify.
#[derive(Clone)]
enum Material<V: Variant> {
    /// Signs with ordinary and threshold keys, and verifies everything.
    Signer {
        keys: SignerKeys,
        da: Sharing<V>,
        nullification: Sharing<V>,
    },
    /// Verifies everything, including individual threshold shares.
    Verifier {
        da: Sharing<V>,
        nullification: Sharing<V>,
    },
    /// Verifies ordinary signatures and recovered certificates, but not threshold shares.
    CertificateVerifier {
        da_identity: V::Public,
        nullification_identity: V::Public,
    },
}

impl<V: Variant> Material<V> {
    const fn keys(&self) -> Option<&SignerKeys> {
        match self {
            Self::Signer { keys, .. } => Some(keys),
            Self::Verifier { .. } | Self::CertificateVerifier { .. } => None,
        }
    }

    const fn da_sharing(&self) -> Option<&Sharing<V>> {
        match self {
            Self::Signer { da, .. } | Self::Verifier { da, .. } => Some(da),
            Self::CertificateVerifier { .. } => None,
        }
    }

    const fn nullification_sharing(&self) -> Option<&Sharing<V>> {
        match self {
            Self::Signer { nullification, .. } | Self::Verifier { nullification, .. } => {
                Some(nullification)
            }
            Self::CertificateVerifier { .. } => None,
        }
    }

    fn da_identity(&self) -> &V::Public {
        match self {
            Self::Signer { da, .. } | Self::Verifier { da, .. } => da.public(),
            Self::CertificateVerifier { da_identity, .. } => da_identity,
        }
    }

    fn nullification_identity(&self) -> &V::Public {
        match self {
            Self::Signer { nullification, .. } | Self::Verifier { nullification, .. } => {
                nullification.public()
            }
            Self::CertificateVerifier {
                nullification_identity,
                ..
            } => nullification_identity,
        }
    }
}

/// Multimmit's concrete BLS12-381 scheme.
///
/// `V` may be either [`commonware_cryptography::bls12381::primitives::variant::MinPk`] or
/// [`commonware_cryptography::bls12381::primitives::variant::MinSig`].
///
/// The ordinary signing roster is proof-of-possession checked by [`Roster`]. The DA and
/// nullification sharings must be generated independently. The constructor checks their public
/// structure, thresholds, and distinct group identities, but cannot prove how key material was
/// generated.
#[derive(Clone)]
pub struct Scheme<P: PublicKey, V: Variant> {
    parameters: Arc<Parameters>,
    namespace: Namespace,
    participants: BiMap<P, V::Public>,
    material: Material<V>,
}

impl<P: PublicKey, V: Variant> fmt::Debug for Scheme<P, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Scheme")
            .field("epoch", &self.parameters.epoch())
            .field("participants", &self.participants.len())
            .field("me", &self.me())
            .finish()
    }
}

impl<P: PublicKey, V: Variant> Scheme<P, V> {
    /// Creates a signer from the local participant's ordinary key and threshold shares.
    ///
    /// See the type-level security requirements. Fails when any key, share, sharing, or
    /// participant index is inconsistent with the epoch configuration.
    pub fn signer(
        parameters: &Arc<Parameters>,
        roster: Roster<P, V>,
        keys: SignerKeys,
        da: Sharing<V>,
        nullification: Sharing<V>,
    ) -> Result<Self, Error> {
        if !roster.matches_namespace(parameters.namespace()) {
            return Err(Error::Namespace);
        }
        validate_public_material(parameters, roster.public_keys(), &da, &nullification)?;

        let ordinary = ops::compute_public::<V>(&keys.ordinary);
        let participant = roster
            .public_keys()
            .values()
            .iter()
            .position(|public| public == &ordinary)
            .map(Participant::from_usize)
            .ok_or(Error::UnknownKey)?;
        if keys.da.index != participant
            || keys.nullification.index != participant
            || da.partial_public(participant).map_err(|_| Error::Share)? != keys.da.public::<V>()
            || nullification
                .partial_public(participant)
                .map_err(|_| Error::Share)?
                != keys.nullification.public::<V>()
        {
            return Err(Error::Share);
        }

        Ok(Self::new(
            parameters,
            roster,
            Material::Signer {
                keys,
                da,
                nullification,
            },
        ))
    }

    /// Creates a verifier with the ordinary key roster and both public threshold sharings.
    ///
    /// See the type-level security requirements. Fails when the public material is inconsistent
    /// with the epoch configuration.
    pub fn verifier(
        parameters: &Arc<Parameters>,
        roster: Roster<P, V>,
        da: Sharing<V>,
        nullification: Sharing<V>,
    ) -> Result<Self, Error> {
        if !roster.matches_namespace(parameters.namespace()) {
            return Err(Error::Namespace);
        }
        validate_public_material(parameters, roster.public_keys(), &da, &nullification)?;
        Ok(Self::new(
            parameters,
            roster,
            Material::Verifier { da, nullification },
        ))
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
    ) -> Result<Self, Error> {
        if !roster.matches_namespace(parameters.namespace()) {
            return Err(Error::Namespace);
        }
        validate_certificate_material::<P, V>(
            parameters,
            roster.public_keys(),
            &da_identity,
            &nullification_identity,
        )?;
        Ok(Self::new(
            parameters,
            roster,
            Material::CertificateVerifier {
                da_identity,
                nullification_identity,
            },
        ))
    }

    fn new(parameters: &Arc<Parameters>, roster: Roster<P, V>, material: Material<V>) -> Self {
        if let (Some(da), Some(nullification)) =
            (material.da_sharing(), material.nullification_sharing())
        {
            da.precompute_partial_publics();
            nullification.precompute_partial_publics();
        }
        Self {
            parameters: Arc::clone(parameters),
            namespace: Namespace::new(parameters.namespace()),
            participants: roster.participants,
            material,
        }
    }

    /// Returns this scheme bound to `parameters`, which must differ from its own only in their
    /// leader schedule.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn with_parameters(mut self, parameters: Arc<Parameters>) -> Self {
        debug_assert!(
            self.parameters.epoch() == parameters.epoch()
                && self.parameters.namespace() == parameters.namespace()
                && self.parameters.codec_config() == parameters.codec_config()
                && self.parameters.producers() == parameters.producers(),
            "only the leader schedule may change"
        );
        self.parameters = parameters;
        self
    }

    /// Returns the epoch parameters this scheme signs and verifies under.
    pub const fn parameters(&self) -> &Arc<Parameters> {
        &self.parameters
    }

    /// Returns the ordered identity-key committee.
    pub const fn participants(&self) -> &Set<P> {
        self.participants.keys()
    }

    /// Returns the ordinary BLS public-key roster in identity-key order.
    pub const fn public_keys(&self) -> &BiMap<P, V::Public> {
        &self.participants
    }

    /// Returns this instance's participant index when it can sign.
    pub fn me(&self) -> Option<Participant> {
        self.material.keys().map(|keys| keys.da.index)
    }

    /// Returns the immutable decoding and quorum limits for this epoch.
    pub fn codec_config(&self) -> CodecConfig {
        self.parameters.codec_config()
    }

    /// Returns the public `n-2f` DA sharing when this is a full verifier.
    pub const fn da_sharing(&self) -> Option<&Sharing<V>> {
        self.material.da_sharing()
    }

    /// Returns the public `2f+1` nullification sharing when this is a full verifier.
    pub const fn nullification_sharing(&self) -> Option<&Sharing<V>> {
        self.material.nullification_sharing()
    }

    /// Returns the DA threshold group identity.
    pub fn da_identity(&self) -> &V::Public {
        self.material.da_identity()
    }

    /// Returns the nullification threshold group identity.
    pub fn nullification_identity(&self) -> &V::Public {
        self.material.nullification_identity()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn signer_keys(&self) -> Result<&SignerKeys, Error> {
        self.material.keys().ok_or(Error::VerifierOnly)
    }

    fn public(&self, participant: Participant) -> Option<&V::Public> {
        self.participants.value(usize::from(participant))
    }

    fn ensure_epoch(&self, epoch: Epoch) -> Result<(), Error> {
        if epoch != self.parameters.epoch() {
            return Err(Error::Context);
        }
        Ok(())
    }

    fn ensure_leader<D: Digest>(&self, leader: &LeaderBlock<V, D>) -> Result<(), Error> {
        self.ensure_epoch(leader.epoch())?;
        Ok(leader.validate(self.codec_config())?)
    }

    fn ensure_vote_body<D: Digest>(&self, body: &VoteBody<D>) -> Result<(), Error> {
        self.ensure_epoch(body.epoch())?;
        Ok(body.validate(self.codec_config())?)
    }

    /// Returns whether `chain` is one of the configured producer chains.
    fn chain_in_range(&self, chain: ChainId) -> bool {
        (chain.get() as usize) < self.codec_config().chains()
    }

    fn ensure_chain(&self, chain: ChainId) -> Result<(), Error> {
        if !self.chain_in_range(chain) {
            return Err(Error::Chain);
        }
        Ok(())
    }

    fn producer(&self, chain: ChainId) -> Result<Participant, Error> {
        self.parameters.producer(chain).ok_or(Error::Chain)
    }
}

impl<P: PublicKey, V: Variant> Epochable for Scheme<P, V> {
    fn epoch(&self) -> Epoch {
        self.parameters.epoch()
    }
}

/// Checks the public sharings of a signer or verifier against the epoch configuration.
fn validate_public_material<P: PublicKey, V: Variant>(
    parameters: &Parameters,
    participants: &BiMap<P, V::Public>,
    da: &Sharing<V>,
    nullification: &Sharing<V>,
) -> Result<(), Error> {
    validate_certificate_material::<P, V>(
        parameters,
        participants,
        da.public(),
        nullification.public(),
    )?;
    if participants
        .values()
        .iter()
        .any(|public| public == &V::Public::zero())
    {
        return Err(Error::ProofOfPossession);
    }
    let total = parameters.codec_config().participants();
    if !valid_sharing(da, total, N5f1::da_quorum(total))
        || !valid_sharing(nullification, total, N5f1::nullification_quorum(total))
    {
        return Err(Error::Sharing);
    }
    Ok(())
}

/// Checks the roster size and both group identities against the epoch configuration.
fn validate_certificate_material<P: PublicKey, V: Variant>(
    parameters: &Parameters,
    participants: &BiMap<P, V::Public>,
    da: &V::Public,
    nullification: &V::Public,
) -> Result<(), Error> {
    if participants.len() != parameters.codec_config().participants() || participants.is_empty() {
        return Err(Error::Participants);
    }
    if da == &V::Public::zero() || nullification == &V::Public::zero() {
        return Err(Error::Sharing);
    }
    if da == nullification {
        return Err(Error::SharedIdentity);
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
