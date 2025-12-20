//! Cryptographic primitives for generating and verifying certificates.
//!
//! This module provides the [`Scheme`] trait and implementations for producing
//! signatures, validating them (individually or in batches), assembling
//! certificates, and verifying recovered certificates.
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
//! - [`bls12381_multisig`]: Attributable signatures with aggregated verification. Signatures
//!   can be aggregated into a single multi-signature for compact certificates while preserving
//!   attribution (signer indices are stored alongside the aggregated signature).
//!
//! - [`bls12381_threshold`]: Non-attributable threshold signatures. Produces succinct
//!   certificates that are constant-size regardless of committee size. Requires a trusted
//!   setup (distributed key generation) and cannot attribute signatures to individual signers.
//!
//! # Attributable Schemes and Fault Evidence
//!
//! Signing schemes differ in whether per-participant activities can be used as evidence of
//! either liveness or of committing a fault:
//!
//! - **Attributable Schemes** ([`ed25519`], [`bls12381_multisig`]): Individual signatures can be
//!   presented to some third party as evidence of either liveness or of committing a fault.
//!   Certificates contain signer indices alongside individual signatures, enabling secure
//!   per-participant activity tracking and conflict detection.
//!
//! - **Non-Attributable Schemes** ([`bls12381_threshold`]): Individual signatures cannot be
//!   presented to some third party as evidence of either liveness or of committing a fault
//!   because they can be forged by other players (often after some quorum of partial signatures
//!   are collected). With [`bls12381_threshold`], possession of any `t` valid partial signatures
//!   can be used to forge a partial signature for any other player. Because peer connections are
//!   authenticated, evidence can be used locally (as it must be sent by said participant) but
//!   cannot be used by an external observer.
//!
//! The [`Scheme::is_attributable()`] method signals whether evidence can be safely exposed to
//! third parties.
//!
//! # Identity Keys vs Signing Keys
//!
//! A participant may supply both an identity key and a signing key. The identity key
//! is used for assigning a unique order to the participant set and authenticating connections
//! whereas the signing key is used for producing and verifying signatures/certificates.
//!
//! This flexibility is supported because some cryptographic schemes are only performant when
//! used in batch verification (like [bls12381_multisig]) and/or are refreshed frequently
//! (like [bls12381_threshold]). Refer to [ed25519] for an example of a scheme that uses the
//! same key for both purposes.

pub use crate::{
    bls12381::certificate::{multisig as bls12381_multisig, threshold as bls12381_threshold},
    ed25519::certificate as ed25519,
    impl_certificate_bls12381_multisig, impl_certificate_bls12381_threshold,
    impl_certificate_ed25519,
};
use crate::{Digest, PublicKey};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{varint::UInt, Codec, CodecFixed, EncodeSize, Error, Read, ReadExt, Write};
use commonware_utils::{bitmap::BitMap, ordered::Set};
use core::{fmt::Debug, hash::Hash};
use rand::{CryptoRng, Rng};
#[cfg(feature = "std")]
use std::{collections::BTreeSet, sync::Arc, vec::Vec};

/// A participant's attestation for a certificate.
#[derive(Clone, Debug)]
pub struct Attestation<S: Scheme> {
    /// Index of the signer inside the participant set.
    pub signer: u32,
    /// Scheme-specific signature or share produced for a given subject.
    pub signature: S::Signature,
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
        UInt(self.signer).write(writer);
        self.signature.write(writer);
    }
}

impl<S: Scheme> EncodeSize for Attestation<S> {
    fn encode_size(&self) -> usize {
        UInt(self.signer).encode_size() + self.signature.encode_size()
    }
}

impl<S: Scheme> Read for Attestation<S> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let signer = UInt::read(reader)?.into();
        let signature = S::Signature::read(reader)?;

        Ok(Self { signer, signature })
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme> arbitrary::Arbitrary<'_> for Attestation<S>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let signer = u32::arbitrary(u)?;
        let signature = S::Signature::arbitrary(u)?;
        Ok(Self { signer, signature })
    }
}

/// Result of batch-verifying attestations.
pub struct Verification<S: Scheme> {
    /// Contains the attestations accepted by the scheme.
    pub verified: Vec<Attestation<S>>,
    /// Identifies the participant indices rejected during batch verification.
    pub invalid: Vec<u32>,
}

impl<S: Scheme> Verification<S> {
    /// Creates a new `Verification` result.
    pub const fn new(verified: Vec<Attestation<S>>, invalid: Vec<u32>) -> Self {
        Self { verified, invalid }
    }
}

/// Identifies the subject of a signature or certificate.
pub trait Subject: Clone + Debug + Send + Sync {
    /// Returns the namespace and message for the subject, given some base namespace.
    fn namespace_and_message(&self, namespace: &[u8]) -> (Bytes, Bytes);
}

/// Cryptographic surface for multi-party certificate schemes.
///
/// A `Scheme` produces attestations, validates them (individually or in batches), assembles
/// certificates, and verifies recovered certificates. Implementations may override the
/// provided defaults to take advantage of scheme-specific batching strategies.
pub trait Scheme: Clone + Debug + Send + Sync + 'static {
    /// Subject type for signing and verification.
    type Subject<'a, D: Digest>: Subject;

    /// Public key type for participant identity used to order and index the participant set.
    type PublicKey: PublicKey;
    /// Signature emitted by individual participants.
    type Signature: Clone + Debug + PartialEq + Eq + Hash + Send + Sync + CodecFixed<Cfg = ()>;
    /// Certificate assembled from a set of attestations.
    type Certificate: Clone + Debug + PartialEq + Eq + Hash + Send + Sync + Codec;

    /// Returns the index of "self" in the participant set, if available.
    /// Returns `None` if the scheme is a verifier-only instance.
    fn me(&self) -> Option<u32>;

    /// Returns the ordered set of participant public identity keys managed by the scheme.
    fn participants(&self) -> &Set<Self::PublicKey>;

    /// Signs a subject using the supplied namespace for domain separation.
    /// Returns `None` if the scheme cannot sign (e.g. it's a verifier-only instance).
    fn sign<D: Digest>(
        &self,
        namespace: &[u8],
        subject: Self::Subject<'_, D>,
    ) -> Option<Attestation<Self>>;

    /// Verifies a single attestation against the participant material managed by the scheme.
    fn verify_attestation<D: Digest>(
        &self,
        namespace: &[u8],
        subject: Self::Subject<'_, D>,
        attestation: &Attestation<Self>,
    ) -> bool;

    /// Batch-verifies attestations and separates valid attestations from signer indices that failed
    /// verification.
    ///
    /// Callers must not include duplicate attestations from the same signer.
    fn verify_attestations<R, D, I>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        subject: Self::Subject<'_, D>,
        attestations: I,
    ) -> Verification<Self>
    where
        R: Rng + CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<Self>>,
    {
        let mut invalid = BTreeSet::new();

        let verified = attestations.into_iter().filter_map(|attestation| {
            if self.verify_attestation(namespace, subject.clone(), &attestation) {
                Some(attestation)
            } else {
                invalid.insert(attestation.signer);
                None
            }
        });

        Verification::new(verified.collect(), invalid.into_iter().collect())
    }

    /// Assembles attestations into a certificate, returning `None` if the threshold is not met.
    ///
    /// Callers must not include duplicate attestations from the same signer.
    fn assemble<I>(&self, attestations: I) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Attestation<Self>>;

    /// Verifies a certificate that was recovered or received from the network.
    fn verify_certificate<R: Rng + CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        subject: Self::Subject<'_, D>,
        certificate: &Self::Certificate,
    ) -> bool;

    /// Verifies a stream of certificates, returning `false` at the first failure.
    fn verify_certificates<'a, R, D, I>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        certificates: I,
    ) -> bool
    where
        R: Rng + CryptoRng,
        D: Digest,
        I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
    {
        for (subject, certificate) in certificates {
            if !self.verify_certificate(rng, namespace, subject, certificate) {
                return false;
            }
        }

        true
    }

    /// Returns whether per-participant fault evidence can be safely exposed.
    ///
    /// Schemes where individual signatures can be safely reported as fault evidence should
    /// return `true`.
    fn is_attributable(&self) -> bool;

    /// Encoding configuration for bounded-size certificate decoding used in network payloads.
    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg;

    /// Encoding configuration that allows unbounded certificate decoding.
    ///
    /// Only use this when decoding data from trusted local storage, it must not be exposed to
    /// adversarial inputs or network payloads.
    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg;
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

    /// Return the signing scheme that corresponds to `scope`.
    fn scoped(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>>;

    /// Return a certificate verifier that can validate certificates from all scopes.
    ///
    /// This method allows implementations to provide a verifier that can validate
    /// certificates from all scopes (without scope-specific state). For example,
    /// `bls12381_threshold::Scheme` maintains a static public key across epochs that
    /// can be used to verify certificates from any epoch, even after the committee
    /// has rotated and the underlying secret shares have been refreshed.
    ///
    /// The default implementation returns `None`. Callers should fall back to
    /// [`Provider::scoped`] for scope-specific verification.
    fn all(&self) -> Option<Arc<Self::Scheme>> {
        None
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
    /// # Panics
    ///
    /// Panics if the sequence contains indices larger than the size of the participant set
    /// or duplicates.
    pub fn from(participants: usize, signers: impl IntoIterator<Item = u32>) -> Self {
        let mut bitmap = BitMap::zeroes(participants as u64);
        for signer in signers.into_iter() {
            assert!(
                !bitmap.get(signer as u64),
                "duplicate signer index: {signer}",
            );
            // We opt to not assert order here because some signing schemes allow
            // for commutative aggregation of signatures (and sorting is unnecessary
            // overhead).

            bitmap.set(signer as u64, true);
        }

        Self { bitmap }
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
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.bitmap
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| bit.then_some(index as u32))
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

    fn read_cfg(reader: &mut impl Buf, max_participants: &usize) -> Result<Self, Error> {
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
        let signers = (0..signer_count as u32).collect::<Vec<_>>();
        Ok(Self::from(participants, signers))
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

    fn scoped(&self, _: Sc) -> Option<Arc<S>> {
        Some(self.scheme.clone())
    }

    fn all(&self) -> Option<Arc<Self::Scheme>> {
        Some(self.scheme.clone())
    }
}

#[cfg(feature = "mocks")]
pub mod mocks {
    //! Mocks for certificate signing schemes.

    /// A fixture containing identities, identity private keys, per-participant
    /// signing schemes, and a single verifier scheme.
    #[derive(Clone, Debug)]
    pub struct Fixture<S> {
        /// A sorted vector of participant public identity keys.
        pub participants: Vec<crate::ed25519::PublicKey>,
        /// A sorted vector of participant private identity keys (matching order with `participants`).
        pub private_keys: Vec<crate::ed25519::PrivateKey>,
        /// A vector of per-participant scheme instances (matching order with `participants`).
        pub schemes: Vec<S>,
        /// A single scheme verifier.
        pub verifier: S,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};

    #[test]
    fn test_from_signers() {
        let signers = Signers::from(6, [0, 3, 5]);
        let collected: Vec<_> = signers.iter().collect();
        assert_eq!(collected, vec![0, 3, 5]);
        assert_eq!(signers.count(), 3);
    }

    #[test]
    #[should_panic(expected = "bit 4 out of bounds (len: 4)")]
    fn test_from_out_of_bounds() {
        Signers::from(4, [0, 4]);
    }

    #[test]
    #[should_panic(expected = "duplicate signer index: 0")]
    fn test_from_duplicate() {
        Signers::from(4, [0, 0, 1]);
    }

    #[test]
    fn test_from_not_increasing() {
        Signers::from(4, [2, 1]);
    }

    #[test]
    fn test_codec_round_trip() {
        let signers = Signers::from(9, [1, 6]);
        let encoded = signers.encode();
        let decoded = Signers::decode_cfg(encoded, &9).unwrap();
        assert_eq!(decoded, signers);
    }

    #[test]
    fn test_decode_respects_participant_limit() {
        let signers = Signers::from(8, [0, 3, 7]);
        let encoded = signers.encode();
        // More participants than expected should fail.
        assert!(Signers::decode_cfg(encoded.clone(), &2).is_err());
        // Exact participant bound succeeds.
        assert!(Signers::decode_cfg(encoded.clone(), &8).is_ok());
        // Less participants than expected succeeds (upper bound).
        assert!(Signers::decode_cfg(encoded, &10).is_ok());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        /// Test context type for generic scheme tests.
        #[derive(Clone, Debug)]
        pub struct TestSubject<'a> {
            pub message: &'a [u8],
        }

        impl<'a> Subject for TestSubject<'a> {
            fn namespace_and_message(&self, namespace: &[u8]) -> (Bytes, Bytes) {
                (namespace.to_vec().into(), self.message.to_vec().into())
            }
        }

        // Use the macro to generate the test scheme (signer/verifier are unused in conformance tests)
        impl_certificate_ed25519!(TestSubject<'a>);

        commonware_conformance::conformance_tests! {
            CodecConformance<Signers>,
            CodecConformance<Attestation<Scheme>>,
        }
    }
}
