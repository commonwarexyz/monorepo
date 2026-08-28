//! Cryptographic primitives for generating and verifying certificates.
//!
//! This module provides the [`Verifier`] and [`Scheme`] traits and implementations for
//! producing signatures, validating them (individually or in batches), assembling certificates, and
//! verifying recovered certificates.
//!
//! # Pluggable Cryptography
//!
//! Certificates are generic over the signing scheme, allowing users to choose
//! the scheme best suited for their requirements:
//!
//! - [`ed25519`]: Attributable signatures with individual verification. HSM-friendly, no trusted
//!   setup required, and widely supported. Certificates contain individual signatures from each
//!   signer.
//!
//! - [`secp256r1`]: Attributable signatures with individual verification. HSM-friendly, no trusted
//!   setup required, and widely supported by hardware security modules. Unlike ed25519, does not
//!   benefit from batch verification. Certificates contain individual signatures from each signer.
#![cfg_attr(
    feature = "bls12381",
    doc = "
- [`bls12381_multisig`]: Attributable signatures with aggregated verification. Signatures
  can be aggregated into a single multi-signature for compact certificates while preserving
  attribution (signer indices are stored alongside the aggregated signature). Callers must verify
  a proof of possession for every BLS signing key before constructing the scheme.

- [`bls12381_threshold`]: Non-attributable threshold signatures. Produces succinct
  certificates that are constant-size regardless of committee size. Requires a trusted
  setup (distributed key generation) and cannot attribute signatures to individual signers.
"
)]
//! # Attributable Schemes and Fault Evidence
//!
//! Signing schemes differ in whether per-participant activities can be used as evidence of
//! either liveness or of committing a fault:
//!
//! - **Attributable Schemes**: Individual signatures can be presented to some third party as
//!   evidence of either liveness or of committing a fault. Certificates contain signer indices
//!   alongside individual signatures, enabling secure per-participant activity tracking and
//!   conflict detection.
//!
//! - **Non-Attributable Schemes**: Individual signatures cannot be presented to some third party
//!   as evidence because they can be forged after collecting a quorum of partial signatures.
//!   Authenticated peer connections allow this evidence to be used locally, but not by an external
//!   observer.
//!
//! The [`Scheme::is_attributable()`] associated function signals whether evidence can be safely
//! exposed to third parties.
//!
//! # Identity Keys vs Signing Keys
//!
//! A participant may supply both an identity key and a signing key. The identity key
//! is used for assigning a unique order to the participant set and authenticating connections
//! whereas the signing key is used for producing and verifying signatures/certificates.
//!
#![cfg_attr(
    feature = "bls12381",
    doc = "Some cryptographic schemes are only performant when used in batch verification (like
[`bls12381_multisig`]) and/or are refreshed frequently (like [`bls12381_threshold`])."
)]
//! Refer to [ed25519] for an example of a scheme that uses the same key for both purposes.

#[cfg(feature = "bls12381")]
pub use crate::bls12381::certificate::{
    multisig as bls12381_multisig, threshold as bls12381_threshold,
};
pub use crate::ed25519::certificate as ed25519;
#[commonware_macros::stability(ALPHA)]
pub use crate::secp256r1::certificate as secp256r1;
use crate::{Digest, PublicKey};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, sync::Arc, vec, vec::Vec};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{
    Codec, CodecFixed, EncodeSize, Error as CodecError, Read, ReadExt, Write, types::lazy::Lazy,
};
use commonware_parallel::Strategy;
use commonware_utils::{Faults, Participant, bitmap::BitMap, iter::NonEmpty, ordered::Set};
use core::{fmt::Debug, hash::Hash};
use rand_core::CryptoRng;
#[cfg(feature = "std")]
use std::{collections::BTreeSet, sync::Arc, vec::Vec};
use thiserror::Error;

/// A participant's attestation for a certificate.
#[derive(Clone, Debug)]
pub struct Attestation<S: Scheme> {
    /// Index of the signer inside the participant set.
    pub signer: Participant,
    /// Scheme-specific signature or share produced for a given subject.
    pub signature: Lazy<S::Signature>,
}

impl<S: Scheme> PartialEq for Attestation<S> {
    fn eq(&self, other: &Self) -> bool {
        self.signer == other.signer && self.signature == other.signature
    }
}

impl<S: Scheme> Eq for Attestation<S> {}

impl<S: Scheme> Hash for Attestation<S> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.signer.hash(state);
        self.signature.hash(state);
    }
}

impl<S: Scheme> Write for Attestation<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signer.write(writer);
        self.signature.write(writer);
    }
}

impl<S: Scheme> EncodeSize for Attestation<S> {
    fn encode_size(&self) -> usize {
        self.signer.encode_size() + self.signature.encode_size()
    }
}

impl<S: Scheme> Read for Attestation<S> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let signer = Participant::read(reader)?;
        let signature = ReadExt::read(reader)?;

        Ok(Self { signer, signature })
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme> arbitrary::Arbitrary<'_> for Attestation<S>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let signer = Participant::arbitrary(u)?;
        let signature = S::Signature::arbitrary(u)?;
        Ok(Self {
            signer,
            signature: signature.into(),
        })
    }
}

/// Result of batch-verifying attestations.
pub struct Verification<S: Scheme> {
    /// Contains the attestations accepted by the scheme.
    pub verified: Vec<Attestation<S>>,
    /// Identifies the participant indices rejected during batch verification.
    pub invalid: Vec<Participant>,
}

impl<S: Scheme> Verification<S> {
    /// Creates a new `Verification` result.
    pub const fn new(verified: Vec<Attestation<S>>, invalid: Vec<Participant>) -> Self {
        Self { verified, invalid }
    }
}

/// Errors returned while assembling attestations into a certificate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AssemblyError {
    /// Structurally valid attestations do not meet the scheme's quorum.
    #[error("insufficient attestations: expected={0}, found={1}")]
    InsufficientAttestations(u32, u32),
    /// An attestation references an index outside the participant set.
    #[error("unknown signer: {0}")]
    UnknownSigner(Participant),
    /// More than one attestation references the same signer.
    #[error("duplicate signer: {0}")]
    DuplicateSigner(Participant),
    /// An attestation contains a malformed encoded signature.
    #[error("malformed signature from signer: {0}")]
    MalformedSignature(Participant),
    /// The scheme could not recover a certificate from structurally valid attestations.
    #[error("certificate recovery failed")]
    RecoveryFailed,
}

/// Trait for namespace types that can derive themselves from a base namespace.
///
/// This trait is implemented by namespace types to define how they are computed
/// from a base namespace string.
pub trait Namespace: Clone + Send + Sync {
    /// Derive a namespace from the given base.
    fn derive(namespace: &[u8]) -> Self;
}

impl Namespace for Vec<u8> {
    fn derive(namespace: &[u8]) -> Self {
        namespace.to_vec()
    }
}

/// Identifies the subject of a signature or certificate.
pub trait Subject: Clone + Debug + Send + Sync {
    /// Pre-computed namespace(s) for this subject type.
    type Namespace: Namespace;

    /// Get the namespace bytes for this subject instance.
    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8];

    /// Get the message bytes for this subject instance.
    fn message(&self) -> Bytes;
}

/// Cryptographic surface for recovered certificate verification.
///
/// A `Verifier` verifies recovered certificates, but does not expose participant
/// metadata or signing operations.
pub trait Verifier: Clone + Debug + Send + Sync + 'static {
    /// Subject type for certificate verification.
    type Subject<'a, D: Digest>: Subject;

    /// Fault model used to compute certificate quorums.
    type Faults: Faults;

    /// Public key type for participant identity used to order and index the participant set.
    type PublicKey: PublicKey;

    /// Certificate assembled from a set of attestations.
    type Certificate: Clone + Debug + PartialEq + Eq + Hash + Send + Sync + Codec;

    /// Verifies a certificate that was recovered or received from the network.
    fn verify_certificate<R, D>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        certificate: &Self::Certificate,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest;

    /// Verifies a non-empty stream of certificates, returning `false` at the first verification
    /// failure.
    fn verify_certificates<'a, R, D, I>(
        &self,
        rng: &mut R,
        certificates: NonEmpty<I>,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
        I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
    {
        for (subject, certificate) in certificates {
            if !self.verify_certificate(rng, subject, certificate, strategy) {
                return false;
            }
        }

        true
    }

    /// Batch-verifies certificates and returns a per-item result.
    ///
    /// For batchable schemes, attempts batch verification first and bisects
    /// on failure to efficiently identify invalid certificates. For
    /// non-batchable schemes, verifies each certificate individually.
    /// Empty input returns an empty result.
    fn verify_certificates_bisect<'a, R, D>(
        &self,
        rng: &mut R,
        certificates: &[(Self::Subject<'a, D>, &'a Self::Certificate)],
        strategy: &impl Strategy,
    ) -> Vec<bool>
    where
        R: CryptoRng,
        D: Digest,
        Self::Subject<'a, D>: Copy,
        Self::Certificate: 'a,
    {
        let len = certificates.len();
        let mut verified = vec![false; len];
        if len == 0 {
            return verified;
        }

        // Non-batchable schemes (e.g. secp256r1) gain nothing from bisection
        // since verify_certificates already checks one-by-one.
        if !Self::is_batchable() {
            for (i, (subject, certificate)) in certificates.iter().enumerate() {
                verified[i] = self.verify_certificate(rng, *subject, certificate, strategy);
            }
            return verified;
        }

        // Iterative bisection: try the full range first. If batch verification
        // passes, mark the entire range valid. If it fails, split in half and
        // retry each half. Singletons that fail remain false.
        //
        //       [0..8) fail
        //      /            \
        //   [0..4) pass   [4..8) fail
        //                /          \
        //            [4..6) pass  [6..8) fail
        //                        /        \
        //                    [6..7) pass  [7..8) fail
        let mut stack = vec![(0, len)];
        while let Some((start, end)) = stack.pop() {
            let (first, rest) = certificates[start..end]
                .split_first()
                .expect("bisection ranges are non-empty");
            let certificates = NonEmpty::new(*first, rest.iter().copied());
            if self.verify_certificates(rng, certificates, strategy) {
                verified[start..end].fill(true);
            } else if end - start > 1 {
                let mid = start + (end - start) / 2;
                stack.push((mid, end));
                stack.push((start, mid));
            }
        }

        verified
    }

    /// Returns whether this scheme benefits from batch verification.
    ///
    /// Schemes that benefit from batch verification should return `true`, allowing callers to
    /// optimize by deferring verification until multiple signatures are available.
    ///
    /// Schemes that don't benefit from batch verification (like [`secp256r1`]) should
    /// return `false`, indicating that eager per-signature verification is preferred.
    fn is_batchable() -> bool;

    /// Encoding configuration for bounded-size certificate decoding used in network payloads.
    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg;

    /// Encoding configuration that allows unbounded certificate decoding.
    ///
    /// Only use this when decoding data from trusted local storage, it must not be exposed to
    /// adversarial inputs or network payloads.
    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg;
}

/// Cryptographic surface for multi-party certificate schemes.
///
/// A `Scheme` extends [`Verifier`] with the signing surface: it produces attestations, validates
/// them (individually or in batches), and assembles certificates. Implementations may override the
/// provided defaults to take advantage of scheme-specific batching strategies.
pub trait Scheme: Verifier {
    /// Signature emitted by individual participants.
    type Signature: Clone + Debug + PartialEq + Eq + Hash + Send + Sync + CodecFixed<Cfg = ()>;

    /// Returns the index of "self" in the participant set, if available.
    /// Returns `None` if the scheme is a verifier-only instance.
    fn me(&self) -> Option<Participant>;

    /// Returns the ordered set of participant public identity keys managed by the scheme.
    fn participants(&self) -> &Set<Self::PublicKey>;

    /// Signs a subject.
    /// Returns `None` if the scheme cannot sign (e.g. it's a verifier-only instance).
    fn sign<D: Digest>(&self, subject: Self::Subject<'_, D>) -> Option<Attestation<Self>>;

    /// Verifies a single attestation against the participant material managed by the scheme.
    fn verify_attestation<R, D>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        attestation: &Attestation<Self>,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest;

    /// Batch-verifies attestations and separates valid attestations from signer indices that failed
    /// verification. Empty input produces an empty result in both sets.
    ///
    /// Callers must not include duplicate attestations from the same signer: duplicates may
    /// produce incorrect results.
    fn verify_attestations<R, D, I>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        attestations: I,
        strategy: &impl Strategy,
    ) -> Verification<Self>
    where
        R: CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
    {
        let mut invalid = BTreeSet::new();

        let verified = attestations.into_iter().filter_map(|attestation| {
            if self.verify_attestation(&mut *rng, subject.clone(), &attestation, strategy) {
                Some(attestation)
            } else {
                invalid.insert(attestation.signer);
                None
            }
        });

        Verification::new(verified.collect(), invalid.into_iter().collect())
    }

    /// Assembles a non-empty stream of attestations into a certificate.
    ///
    /// Insufficient input returns [`AssemblyError::InsufficientAttestations`].
    /// A signer-unique quorum already verified for one subject must assemble successfully.
    fn assemble<I>(
        &self,
        attestations: NonEmpty<I>,
        strategy: &impl Strategy,
    ) -> Result<Self::Certificate, AssemblyError>
    where
        I: Iterator<Item = Attestation<Self>> + Send;

    /// Returns whether per-participant fault evidence can be safely exposed.
    ///
    /// Schemes where individual signatures can be safely reported as fault evidence should
    /// return `true`.
    fn is_attributable() -> bool;
}

/// A scheme handle returned by a [`Provider`] for one scope.
///
/// Always usable as a [`Verifier`] for certificate verification. The full signing scheme is
/// recoverable with [`Scoped::into_scheme`] only when the scope was built with [`Scoped::scheme`].
/// A scope built with [`Scoped::verifier`] yields `None`.
#[derive(Clone, Debug)]
pub struct Scoped<S: Scheme> {
    scheme: Arc<S>,
    can_sign: bool,
}

impl<S: Scheme> Scoped<S> {
    /// Builds a verify-only scope.
    pub const fn verifier(scheme: Arc<S>) -> Self {
        Self {
            scheme,
            can_sign: false,
        }
    }

    /// Builds a full signing scope.
    pub const fn scheme(scheme: Arc<S>) -> Self {
        Self {
            scheme,
            can_sign: true,
        }
    }

    /// Returns the full signing scheme, or `None` for a verify-only scope.
    pub fn into_scheme(self) -> Option<Arc<S>> {
        self.can_sign.then_some(self.scheme)
    }
}

impl<S: Scheme> Verifier for Scoped<S> {
    type Subject<'a, D: Digest> = S::Subject<'a, D>;
    type Faults = S::Faults;
    type PublicKey = S::PublicKey;
    type Certificate = S::Certificate;

    fn verify_certificate<R, D>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        certificate: &Self::Certificate,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
    {
        self.scheme
            .verify_certificate(rng, subject, certificate, strategy)
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
        I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
    {
        self.scheme.verify_certificates(rng, certificates, strategy)
    }

    fn is_batchable() -> bool {
        S::is_batchable()
    }

    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {
        self.scheme.certificate_codec_config()
    }

    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {
        S::certificate_codec_config_unbounded()
    }
}

/// Supplies the signing scheme for a given scope.
///
/// This trait uses an associated `Scope` type, allowing implementations to work
/// with any scope representation (e.g., epoch numbers, block heights, etc.).
pub trait Provider: Clone + Send + Sync + 'static {
    /// The scope type used to look up schemes.
    type Scope: Clone + Send + Sync + 'static;
    /// The signing scheme to provide.
    type Scheme: Scheme;

    /// Return a [`Scoped`] for `scope` capable of verifying certificates produced under it.
    ///
    /// A scheme that can verify certificates from any scope without scope-specific state should
    /// return a verify-only [`Scoped`] (via [`Scoped::verifier`]) for every scope. A fixed group
    /// public key that survives committee rotation is one such case. A scheme that needs
    /// scope-specific verification state should return `None` once that state is unavailable.
    fn scoped(&self, scope: Self::Scope) -> Option<Scoped<Self::Scheme>>;

    /// Return the full signing scheme that corresponds to `scope`, if available.
    ///
    /// The default returns a scheme only when [`Provider::scoped`] yields a signing scope, so a
    /// verify-only scope produces `None`. Override this when the signing scheme is available even
    /// for scopes that [`Provider::scoped`] serves with a verify-only result.
    fn scheme(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        self.scoped(scope).and_then(Scoped::into_scheme)
    }
}

/// Bitmap wrapper that tracks which participants signed a certificate.
///
/// Internally, it stores bits in 1-byte chunks for compact encoding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signers {
    bitmap: BitMap<1>,
}

impl Signers {
    /// Builds [`Signers`] from an iterator of signer indices.
    ///
    /// Indices need not be sorted: some signing schemes aggregate commutatively, so ordering
    /// is left to the caller.
    pub fn new(
        participants: u32,
        signers: impl IntoIterator<Item = Participant>,
    ) -> Result<Self, AssemblyError> {
        let mut bitmap = BitMap::zeroes(u64::from(participants));
        for signer in signers.into_iter() {
            let index = u64::from(signer.get());
            if index >= bitmap.len() {
                return Err(AssemblyError::UnknownSigner(signer));
            }
            if bitmap.get(index) {
                return Err(AssemblyError::DuplicateSigner(signer));
            }
            bitmap.set(index, true);
        }

        Ok(Self { bitmap })
    }

    /// Requires at least `required` signers in an already validated set.
    pub(crate) fn require(self, required: u32) -> Result<Self, AssemblyError> {
        let found = u32::try_from(self.count()).expect("signer count exceeds u32::MAX");
        if found < required {
            return Err(AssemblyError::InsufficientAttestations(required, found));
        }

        Ok(self)
    }

    /// Returns the length of the bitmap (the size of the participant set).
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.bitmap.len() as usize
    }

    /// Returns how many participants are marked as signers.
    pub fn count(&self) -> usize {
        self.bitmap.count_ones() as usize
    }

    /// Iterates over signer indices in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = Participant> + '_ {
        self.bitmap
            .ones_iter()
            .map(|index| Participant::from_usize(index as usize))
    }
}

/// Builds [`Signers`] using the participant set as the valid signer-index range.
///
/// # Panics
///
/// Panics if the participant count exceeds `u32::MAX`.
impl<'a, P, I> TryFrom<(&'a Set<P>, I)> for Signers
where
    I: IntoIterator<Item = Participant>,
{
    type Error = AssemblyError;

    fn try_from((participants, signers): (&'a Set<P>, I)) -> Result<Self, Self::Error> {
        let total = u32::try_from(participants.len()).expect("participant count exceeds u32::MAX");
        Self::new(total, signers)
    }
}

impl Write for Signers {
    fn write(&self, writer: &mut impl BufMut) {
        self.bitmap.write(writer);
    }
}

impl EncodeSize for Signers {
    fn encode_size(&self) -> usize {
        self.bitmap.encode_size()
    }
}

impl Read for Signers {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_participants: &usize) -> Result<Self, CodecError> {
        let bitmap = BitMap::read_cfg(reader, &(*max_participants as u64))?;
        // The participant count is treated as an upper bound for decoding flexibility, e.g. one
        // might use `Scheme::certificate_codec_config_unbounded` for decoding certificates from
        // local storage.
        //
        // Exact length validation **must** be enforced at verification time by the signing schemes
        // against the actual participant set size.
        Ok(Self { bitmap })
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Signers {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let participants = u.arbitrary_len::<u8>()? % 10;
        let signer_count = u.arbitrary_len::<u8>()?.min(participants);
        let signers = (0..u32::try_from(signer_count).expect("signer count exceeds u32::MAX"))
            .map(Participant::new)
            .collect::<Vec<_>>();
        Ok(Self::new(participants.try_into().unwrap(), signers)
            .expect("indices are unique and in range"))
    }
}

/// A scheme provider that always returns the same scheme regardless of scope.
#[derive(Clone, Debug)]
pub struct ConstantProvider<S: Scheme, Sc = ()> {
    scheme: Arc<S>,
    _scope: core::marker::PhantomData<Sc>,
}

impl<S: Scheme, Sc> ConstantProvider<S, Sc> {
    /// Creates a new provider that always returns the given scheme.
    pub fn new(scheme: S) -> Self {
        Self {
            scheme: Arc::new(scheme),
            _scope: core::marker::PhantomData,
        }
    }
}

impl<S: Scheme, Sc: Clone + Send + Sync + 'static> crate::certificate::Provider
    for ConstantProvider<S, Sc>
{
    type Scope = Sc;
    type Scheme = S;

    fn scoped(&self, _: Sc) -> Option<Scoped<S>> {
        Some(Scoped::scheme(self.scheme.clone()))
    }
}

#[cfg(feature = "mocks")]
pub mod mocks;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Signer as _, ed25519::PrivateKey, sha256::Digest as Sha256Digest};
    use commonware_codec::{Decode, Encode};
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::{TryCollect, non_empty, ordered::Set, test_rng};
    use ed25519_fixture::{Scheme as Ed25519Scheme, TestSubject};

    #[test]
    fn test_new_signers() {
        let signers = Signers::new(6, [0, 3, 5].map(Participant::new)).unwrap();
        let collected: Vec<_> = signers.iter().collect();
        assert_eq!(
            collected,
            vec![0, 3, 5]
                .into_iter()
                .map(Participant::new)
                .collect::<Vec<_>>()
        );
        assert_eq!(signers.count(), 3);
    }

    #[test]
    fn test_new_out_of_bounds() {
        assert_eq!(
            Signers::new(4, [0, 4].map(Participant::new)),
            Err(AssemblyError::UnknownSigner(Participant::new(4)))
        );
    }

    #[test]
    fn test_new_duplicate() {
        assert_eq!(
            Signers::new(4, [0, 0, 1].map(Participant::new)),
            Err(AssemblyError::DuplicateSigner(Participant::new(0)))
        );
    }

    #[test]
    fn test_new_not_increasing() {
        assert!(Signers::new(4, [2, 1].map(Participant::new)).is_ok());
    }

    #[test]
    fn test_try_from_set_and_require() {
        let participants = Set::from_iter_dedup(0..4);
        let signers = Signers::try_from((&participants, [0, 2, 3].map(Participant::new)))
            .unwrap()
            .require(3)
            .unwrap();
        assert_eq!(signers.count(), 3);
        assert_eq!(
            Signers::try_from((&participants, [0, 2].map(Participant::new)))
                .unwrap()
                .require(3),
            Err(AssemblyError::InsufficientAttestations(3, 2))
        );
    }

    #[test]
    fn test_try_from_set_checks_signer_bounds() {
        let participants = Set::<u8>::default();
        let signer = Participant::new(0);
        assert_eq!(
            Signers::try_from((&participants, [signer])),
            Err(AssemblyError::UnknownSigner(signer))
        );
    }

    #[test]
    fn test_codec_round_trip() {
        let signers = Signers::new(9, [1, 6].map(Participant::new)).unwrap();
        let encoded = signers.encode();
        let decoded = Signers::decode_cfg(encoded, &9).unwrap();
        assert_eq!(decoded, signers);
    }

    #[test]
    fn test_decode_respects_participant_limit() {
        let signers = Signers::new(8, [0, 3, 7].map(Participant::new)).unwrap();
        let encoded = signers.encode();
        // More participants than expected should fail.
        assert!(Signers::decode_cfg(encoded.clone(), &2).is_err());
        // Exact participant bound succeeds.
        assert!(Signers::decode_cfg(encoded.clone(), &8).is_ok());
        // Less participants than expected succeeds (upper bound).
        assert!(Signers::decode_cfg(encoded, &10).is_ok());
    }

    mod ed25519_fixture {
        use crate::{certificate::Subject, impl_certificate_ed25519};
        use commonware_utils::N3f1;

        /// Test subject for certificate verification tests.
        #[derive(Copy, Clone, Debug)]
        pub struct TestSubject {
            pub message: &'static [u8],
        }

        impl Subject for TestSubject {
            type Namespace = Vec<u8>;

            fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
                derived
            }

            fn message(&self) -> bytes::Bytes {
                bytes::Bytes::from_static(self.message)
            }
        }

        // Use the macro to generate the test scheme
        impl_certificate_ed25519!(TestSubject, Vec<u8>, N3f1);
    }

    const NAMESPACE: &[u8] = b"test-bisect";
    const MESSAGE: &[u8] = b"good message";
    const BAD_MESSAGE: &[u8] = b"bad message";

    fn make_certificate(
        schemes: &[Ed25519Scheme],
        message: &'static [u8],
    ) -> <Ed25519Scheme as Verifier>::Certificate {
        let attestations: Vec<_> = schemes
            .iter()
            .filter_map(|s| s.sign::<Sha256Digest>(TestSubject { message }))
            .collect();
        schemes[0]
            .assemble(non_empty![@attestations], &Sequential)
            .expect("assembly failed")
    }

    fn setup_ed25519(n: u32) -> (Vec<Ed25519Scheme>, Ed25519Scheme) {
        let mut rng = test_rng();
        let private_keys: Vec<_> = (0..n).map(|_| PrivateKey::random(&mut rng)).collect();
        let participants: Set<crate::ed25519::PublicKey> = private_keys
            .iter()
            .map(|sk| sk.public_key())
            .try_collect()
            .unwrap();
        let signers: Vec<_> = private_keys
            .into_iter()
            .map(|sk| Ed25519Scheme::signer(NAMESPACE, participants.clone(), sk).unwrap())
            .collect();
        let verifier = Ed25519Scheme::verifier(NAMESPACE, participants);
        (signers, verifier)
    }

    #[test]
    fn test_bisect_empty() {
        let mut rng = test_rng();
        let (_, verifier) = setup_ed25519(4);
        let result =
            verifier.verify_certificates_bisect::<_, Sha256Digest>(&mut rng, &[], &Sequential);
        assert!(result.is_empty());
    }

    #[test]
    fn test_bisect_all_valid() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_ed25519(4);
        let cert = make_certificate(&schemes, MESSAGE);
        let good = TestSubject { message: MESSAGE };
        let pairs: Vec<_> = (0..5).map(|_| (good, &cert)).collect();
        let result =
            verifier.verify_certificates_bisect::<_, Sha256Digest>(&mut rng, &pairs, &Sequential);
        assert_eq!(result, vec![true; 5]);
    }

    #[test]
    fn test_bisect_mixed() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_ed25519(4);
        let cert = make_certificate(&schemes, MESSAGE);
        let good = TestSubject { message: MESSAGE };
        let bad = TestSubject {
            message: BAD_MESSAGE,
        };
        let pairs = vec![
            (good, &cert),
            (bad, &cert),
            (good, &cert),
            (bad, &cert),
            (good, &cert),
            (good, &cert),
            (bad, &cert),
            (bad, &cert),
        ];
        let expected = vec![true, false, true, false, true, true, false, false];
        let result =
            verifier.verify_certificates_bisect::<_, Sha256Digest>(&mut rng, &pairs, &Sequential);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_bisect_all_invalid() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_ed25519(4);
        let cert = make_certificate(&schemes, MESSAGE);
        let bad = TestSubject {
            message: BAD_MESSAGE,
        };
        let pairs: Vec<_> = (0..4).map(|_| (bad, &cert)).collect();
        let result =
            verifier.verify_certificates_bisect::<_, Sha256Digest>(&mut rng, &pairs, &Sequential);
        assert_eq!(result, vec![false; 4]);
    }

    #[test]
    fn test_bisect_single_valid() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_ed25519(4);
        let cert = make_certificate(&schemes, MESSAGE);
        let pairs = vec![(TestSubject { message: MESSAGE }, &cert)];
        let result =
            verifier.verify_certificates_bisect::<_, Sha256Digest>(&mut rng, &pairs, &Sequential);
        assert_eq!(result, vec![true]);
    }

    #[test]
    fn test_bisect_single_invalid() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_ed25519(4);
        let cert = make_certificate(&schemes, MESSAGE);
        let pairs = vec![(
            TestSubject {
                message: BAD_MESSAGE,
            },
            &cert,
        )];
        let result =
            verifier.verify_certificates_bisect::<_, Sha256Digest>(&mut rng, &pairs, &Sequential);
        assert_eq!(result, vec![false]);
    }

    #[test]
    fn test_scoped_verifies_and_into_scheme() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_ed25519(4);
        let cert = make_certificate(&schemes, MESSAGE);
        let subject = TestSubject { message: MESSAGE };

        let as_verifier = Scoped::verifier(Arc::new(verifier));
        let as_scheme = Scoped::scheme(Arc::new(schemes[0].clone()));

        // Both scopes verify a valid certificate through the `Verifier` impl.
        assert!(as_verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject,
            &cert,
            &Sequential,
        ));
        assert!(as_scheme.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject,
            &cert,
            &Sequential,
        ));
        let pairs = [(subject, &cert)];
        assert!(as_verifier.verify_certificates::<_, Sha256Digest, _>(
            &mut rng,
            non_empty![@pairs.iter().copied()],
            &Sequential,
        ));
        assert_eq!(
            <Scoped<Ed25519Scheme> as Verifier>::is_batchable(),
            <Ed25519Scheme as Verifier>::is_batchable(),
        );
        assert_eq!(
            as_verifier.certificate_codec_config(),
            schemes[0].certificate_codec_config(),
        );
        let _ = <Scoped<Ed25519Scheme> as Verifier>::certificate_codec_config_unbounded();

        // A verify-only scope never yields its scheme; a full scope always does.
        assert!(as_verifier.into_scheme().is_none());
        assert!(as_scheme.into_scheme().is_some());

        let provider = ConstantProvider::<_, ()>::new(schemes[0].clone());
        assert!(provider.scoped(()).is_some());
        assert!(provider.scheme(()).is_some());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::{ed25519_fixture::Scheme, *};
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Signers>,
            CodecConformance<Attestation<Scheme>>,
        }
    }
}
