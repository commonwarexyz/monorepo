//! BLS12-381 synchronized aggregate signature signing scheme implementation.
//!
//! This module provides both the generic implementation and a macro to generate protocol-specific
//! wrappers, mirroring [`multisig`](super::multisig). Participants sign with Pointcheval-Sanders
//! synchronized aggregate signatures ([`sas`]): every signer in a period signs against a common
//! base, so attestations by distinct signers over different subjects in one period aggregate into
//! a signature that verifies with one pairing per period. Subjects implement [`Synchronized`] to
//! name their period.
//!
//! Certificates over one subject hold a signer bitmap and the aggregate signature, like
//! [`multisig`](super::multisig) certificates. [`Aggregator`] verification multiplies participant
//! keys through a [`sas::KeyTable`] precomputed at construction and shared by clones.
//!
//! # Proof of Knowledge
//!
//! Before constructing a scheme, callers must verify a [`sas::ProofOfKnowledge`] for every public
//! key in the participant map. Without it, aggregate verification is vulnerable to rogue-key
//! attacks. Verify each proof during participant registration with
//! [`ProofOfKnowledge::verify`](sas::ProofOfKnowledge::verify), then construct schemes only from
//! the validated participant set.
//!
//! # One Subject per Period
//!
//! A signer must sign at most one subject per period: two signatures by one key over different
//! subjects in a period let anyone forge that key's signature on any subject in that period. The
//! scheme signs every subject it is given, so protocols must assign periods as described in
//! [`Synchronized`].

#[cfg(feature = "mocks")]
pub mod mocks;

use super::claims::{self, Owned, Prepared};
use crate::{
    Digest, PublicKey,
    bls12381::primitives::{
        ops::{aggregate, sas},
        variant::Variant,
    },
    certificate::{
        Aggregator, AssemblyError, Attestation, Item, Namespace, Scheme, Signers, Subject as _,
        Synchronized, Verification,
    },
};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet, sync::Arc, vec, vec::Vec};
use bytes::{BufMut, Bytes};
use commonware_codec::{
    Buf, EncodeSize, Error, FixedSize, Read, ReadExt, Write, types::lazy::Lazy,
};
use commonware_math::algebra::Additive;
use commonware_parallel::Strategy;
use commonware_utils::{
    Participant, Widen,
    iter::NonEmpty,
    ordered::{BiMap, Quorum, Set},
};
use rand_core::CryptoRng;
#[cfg(feature = "std")]
use std::{collections::BTreeSet, sync::Arc};

/// Generic BLS12-381 synchronized aggregate signature implementation.
///
/// This struct contains the core cryptographic operations without protocol-specific context
/// types. It can be reused across different protocols by wrapping it with protocol-specific trait
/// implementations via the macro.
#[derive(Clone, Debug)]
pub struct Generic<P: PublicKey, V: Variant, N: Namespace> {
    /// Participants' identity keys and synchronized aggregate signing keys.
    ///
    /// Every signing key must have a verified proof of knowledge.
    pub participants: BiMap<P, sas::PublicKey<V>>,
    /// Precomputed multiples of the participants' signing keys, shared by clones.
    table: Arc<sas::KeyTable<V>>,
    /// Key used for generating signatures.
    pub signer: Option<(Participant, sas::PrivateKey)>,
    /// Pre-computed namespace(s) for this subject type.
    pub namespace: N,
}

impl<P: PublicKey, V: Variant, N: Namespace> Generic<P, V, N> {
    /// Creates a new scheme instance with the provided key material.
    ///
    /// Participants have both an identity key and a signing key. The identity key is used for
    /// participant set ordering and indexing, while the signing key is used for signing and
    /// verification.
    ///
    /// Returns `None` if the provided private key does not match any signing key in the
    /// participant set.
    ///
    /// # Security
    ///
    /// This function does not verify proofs of knowledge. The caller must verify one for every
    /// public key in `participants` before constructing the scheme. See the [module-level
    /// documentation](crate::bls12381::certificate::sas) for details.
    pub fn signer(
        namespace: &[u8],
        participants: BiMap<P, sas::PublicKey<V>>,
        private_key: sas::PrivateKey,
    ) -> Option<Self> {
        let public_key = sas::PublicKey::<V>::from_private(&private_key);
        let index = participants
            .values()
            .iter()
            .position(|public| public == &public_key)?;
        Some(Self::new(
            namespace,
            participants,
            Some((Participant::from_usize(index), private_key)),
        ))
    }

    /// Builds a verifier that can authenticate signatures, aggregates, and certificates.
    ///
    /// # Security
    ///
    /// This function does not verify proofs of knowledge. The caller must verify one for every
    /// public key in `participants` before constructing the scheme. See the [module-level
    /// documentation](crate::bls12381::certificate::sas) for details.
    pub fn verifier(namespace: &[u8], participants: BiMap<P, sas::PublicKey<V>>) -> Self {
        Self::new(namespace, participants, None)
    }

    fn new(
        namespace: &[u8],
        participants: BiMap<P, sas::PublicKey<V>>,
        signer: Option<(Participant, sas::PrivateKey)>,
    ) -> Self {
        Self {
            table: Arc::new(sas::KeyTable::new(participants.values())),
            participants,
            signer,
            namespace: N::derive(namespace),
        }
    }

    /// Returns the ordered set of identity keys.
    pub const fn participants(&self) -> &Set<P> {
        self.participants.keys()
    }

    /// Returns the index this instance signs at, or `None` if it cannot sign.
    pub fn signer_index(&self) -> Option<Participant> {
        self.signer.as_ref().map(|(index, _)| *index)
    }

    /// Signs a subject in its period and returns the attestation.
    ///
    /// # Warning
    ///
    /// Signing two different subjects in one period lets anyone forge this signer's signature on
    /// any subject in that period. See the [module-level
    /// documentation](crate::bls12381::certificate::sas).
    pub fn sign<S>(&self, subject: impl Synchronized<Namespace = N>) -> Option<Attestation<S>>
    where
        S: Scheme<Signature = V::Signature>,
    {
        let (index, private_key) = self.signer.as_ref()?;
        let signature = sas::sign_message::<V>(
            private_key,
            &subject.period(&self.namespace),
            subject.namespace(&self.namespace),
            &subject.message(),
        );

        Some(Attestation {
            signer: *index,
            signature: signature.into(),
        })
    }

    /// Verifies a single attestation from a signer.
    pub fn verify_attestation<S>(
        &self,
        subject: impl Synchronized<Namespace = N>,
        attestation: &Attestation<S>,
    ) -> bool
    where
        S: Scheme<Signature = V::Signature>,
    {
        let Some(public_key) = self.participants.value(attestation.signer.into()) else {
            return false;
        };
        let Some(signature) = attestation.signature.get() else {
            return false;
        };

        sas::verify_message::<V>(
            public_key,
            &subject.period(&self.namespace),
            subject.namespace(&self.namespace),
            &subject.message(),
            signature,
        )
        .is_ok()
    }

    /// Batch-verifies attestations over one subject and returns verified attestations and invalid
    /// signers.
    pub fn verify_attestations<S, R, I>(
        &self,
        rng: &mut R,
        subject: impl Synchronized<Namespace = N>,
        attestations: I,
        strategy: &impl Strategy,
    ) -> Verification<S>
    where
        S: Scheme<Signature = V::Signature>,
        R: CryptoRng,
        I: IntoIterator<Item = Attestation<S>>,
        I::IntoIter: Send,
    {
        let (candidates, failures) =
            strategy.map_partition_collect_vec(attestations.into_iter(), |attestation| {
                let signer = attestation.signer;
                let value = self
                    .participants
                    .value(signer.into())
                    .and_then(|public_key| {
                        attestation
                            .signature
                            .get()
                            .copied()
                            .map(|signature| (attestation, (*public_key, signature)))
                    });
                (signer, value)
            });
        let mut invalid: BTreeSet<_> = failures.into_iter().collect();

        // If there are no candidates to verify, return before doing any work.
        if candidates.is_empty() {
            return Verification::new(Vec::new(), invalid.into_iter().collect());
        }

        // Every claim signs the same message in the same period, so the batch hashes both once.
        let period = subject.period(&self.namespace);
        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();
        let claims: Vec<_> = candidates
            .iter()
            .map(|(_, (public, signature))| sas::Claim {
                period: &period,
                signature: *signature,
                terms: vec![sas::Term {
                    public: *public,
                    namespace,
                    message: &message,
                }],
            })
            .collect();
        for index in sas::verify_claims_with_table(rng, &claims, &self.table, strategy) {
            invalid.insert(candidates[index].0.signer);
        }

        let verified = candidates
            .into_iter()
            .map(|(attestation, _)| attestation)
            .filter(|attestation| !invalid.contains(&attestation.signer))
            .collect();
        Verification::new(verified, invalid.into_iter().collect())
    }

    /// Assembles a certificate from a non-empty collection of attestations.
    pub fn assemble<S, I>(&self, attestations: NonEmpty<I>) -> Result<Certificate<V>, AssemblyError>
    where
        S: Scheme<Signature = V::Signature>,
        I: Iterator<Item = Attestation<S>>,
    {
        let mut signers =
            Signers::try_from((self.participants.keys(), core::iter::empty::<Participant>()))?;
        let mut signature = aggregate::Signature::zero();
        for Attestation {
            signer,
            signature: attestation,
        } in attestations
        {
            self.participants
                .value(signer.into())
                .ok_or(AssemblyError::UnknownSigner(signer))?;
            let attestation = attestation
                .get()
                .ok_or(AssemblyError::MalformedSignature(signer))?;
            signers.insert(signer)?;
            signature.add(attestation);
        }
        let signers = signers.require(self.participants.quorum::<S::Faults>())?;

        Ok(Certificate {
            signers,
            signature: Lazy::from(signature),
        })
    }

    /// Returns the claim that `certificate` signs `subject`, after its structural checks.
    ///
    /// Every signer signs the same message, so their keys sum into one key.
    fn certificate_claim<S: Scheme>(
        &self,
        subject: &impl Synchronized<Namespace = N>,
        certificate: &Certificate<V>,
    ) -> Option<CertificateClaim<'_, V>> {
        if certificate.signers.len() != self.participants.len()
            || certificate.signers.count() < Widen::widen(self.participants.quorum::<S::Faults>())
        {
            return None;
        }
        let signature = *certificate.signature.get()?.inner();
        let mut x = V::Public::zero();
        let mut y = V::Public::zero();
        for signer in certificate.signers.iter() {
            let public_key = self.participants.value(signer.into())?;
            x += public_key.x();
            y += public_key.y();
        }
        Some(CertificateClaim {
            period: subject.period(&self.namespace),
            signature,
            public: sas::PublicKey::new(x, y),
            namespace: subject.namespace(&self.namespace),
            message: subject.message(),
        })
    }

    /// Verifies a certificate.
    pub fn verify_certificate<S, R>(
        &self,
        _rng: &mut R,
        subject: impl Synchronized<Namespace = N>,
        certificate: &Certificate<V>,
    ) -> bool
    where
        S: Scheme,
        R: CryptoRng,
    {
        self.certificate_claim::<S>(&subject, certificate)
            .is_some_and(|claim| {
                sas::verify_message::<V>(
                    &claim.public,
                    &claim.period,
                    claim.namespace,
                    &claim.message,
                    &claim.signature,
                )
                .is_ok()
            })
    }

    /// Verifies multiple certificates with one randomly weighted batch.
    pub fn verify_certificates<'a, S, R, T, I>(
        &self,
        rng: &mut R,
        certificates: NonEmpty<I>,
        strategy: &impl Strategy,
    ) -> bool
    where
        S: Scheme,
        T: Synchronized<Namespace = N>,
        R: CryptoRng,
        I: Iterator<Item = (T, &'a Certificate<V>)>,
    {
        let certificates = certificates.into_iter();
        let mut prepared = Vec::with_capacity(certificates.size_hint().0);
        for (subject, certificate) in certificates {
            let Some(claim) = self.certificate_claim::<S>(&subject, certificate) else {
                return false;
            };
            prepared.push(claim);
        }
        let claims: Vec<_> = prepared
            .iter()
            .map(|claim| sas::Claim {
                period: &claim.period,
                signature: claim.signature,
                terms: vec![sas::Term {
                    public: claim.public,
                    namespace: claim.namespace,
                    message: &claim.message,
                }],
            })
            .collect();
        sas::verify_claims(rng, &claims, strategy).is_empty()
    }

    /// Sums attestations over any subjects into an aggregate.
    pub fn aggregate<'a, S, I>(
        &self,
        attestations: NonEmpty<I>,
    ) -> Result<Lazy<aggregate::Signature<V>>, AssemblyError>
    where
        S: Scheme<Signature = V::Signature>,
        I: Iterator<Item = &'a Attestation<S>>,
    {
        let mut signers =
            Signers::try_from((self.participants.keys(), core::iter::empty::<Participant>()))?;
        let mut signature = aggregate::Signature::zero();
        for attestation in attestations {
            signers.insert(attestation.signer)?;
            signature.add(
                attestation
                    .signature
                    .get()
                    .ok_or(AssemblyError::MalformedSignature(attestation.signer))?,
            );
        }
        Ok(Lazy::from(signature))
    }

    /// Verifies attestations and aggregates over any subjects with one randomly weighted batch,
    /// returning one verdict per item.
    ///
    /// Known terms are subtracted from their aggregate before the batch, so they cost nothing in
    /// it. The remaining terms of an aggregate must share one period. The batch costs one pairing
    /// per distinct period plus one, and multiplies participant keys through the precomputed
    /// table.
    pub fn verify_aggregates<'a, S, R, D>(
        &self,
        rng: &mut R,
        items: &[Item<'_, 'a, S, D>],
        strategy: &impl Strategy,
    ) -> Vec<bool>
    where
        S: Aggregator<Signature = V::Signature, Aggregate = Lazy<aggregate::Signature<V>>>,
        S::Subject<'a, D>: Synchronized<Namespace = N>,
        R: CryptoRng,
        D: Digest,
    {
        // Decoding signatures and building messages dominate preparation, so items prepare in
        // parallel.
        let prepared = strategy.map_collect_vec(items, |item| {
            claims::prepare::<_, _, V, _, _>(
                self.participants.len(),
                item,
                |aggregate| aggregate.get().map(|signature| *signature.inner()),
                |signer, subject| {
                    Some(Owned {
                        period: subject.period(&self.namespace),
                        public: *self.participants.value(signer.into())?,
                        namespace: subject.namespace(&self.namespace),
                        message: subject.message(),
                    })
                },
            )
        });

        let mut verdicts = vec![false; items.len()];
        let mut positions = Vec::with_capacity(items.len());
        let mut entries = Vec::<sas::Claim<'_, V>>::with_capacity(items.len());
        for (position, prepared) in prepared.iter().enumerate() {
            match prepared {
                Prepared::Settled(valid) => verdicts[position] = *valid,
                Prepared::Claim { signature, terms } => {
                    let terms = terms.as_slice();
                    let period = &terms[0].period;
                    if terms.iter().any(|term| term.period != *period) {
                        continue;
                    }
                    verdicts[position] = true;
                    positions.push(position);
                    entries.push(sas::Claim {
                        period,
                        signature: *signature,
                        terms: terms
                            .iter()
                            .map(|term| sas::Term {
                                public: term.public,
                                namespace: term.namespace,
                                message: &term.message,
                            })
                            .collect(),
                    });
                }
            }
        }
        if !entries.is_empty() {
            for index in sas::verify_claims_with_table(rng, &entries, &self.table, strategy) {
                verdicts[positions[index]] = false;
            }
        }
        verdicts
    }

    pub const fn is_attributable() -> bool {
        true
    }

    pub const fn is_batchable() -> bool {
        true
    }

    /// Returns the maximum encoded certificate size for at most `participants` participants.
    pub fn max_certificate_size(participants: u32) -> usize {
        Signers::max_encode_size(participants) + V::Signature::SIZE
    }

    pub const fn certificate_codec_config(&self) -> <Certificate<V> as Read>::Cfg {
        self.participants.len()
    }

    pub const fn certificate_codec_config_unbounded() -> <Certificate<V> as Read>::Cfg {
        u32::MAX as usize
    }

    /// Returns the encoded size of an aggregate, which does not depend on its terms.
    pub const fn max_aggregate_size(_terms: u32) -> usize {
        aggregate::Signature::<V>::SIZE
    }
}

/// A certificate's claim over one summed key.
struct CertificateClaim<'n, V: Variant> {
    period: Bytes,
    signature: V::Signature,
    public: sas::PublicKey<V>,
    namespace: &'n [u8],
    message: Bytes,
}

/// Certificate formed by an aggregated synchronized aggregate signature plus the signers that
/// contributed to it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<V: Variant> {
    /// Bitmap of participant indices that contributed signatures.
    pub signers: Signers,
    /// Sum of the signatures of every signer.
    pub signature: Lazy<aggregate::Signature<V>>,
}

impl<V: Variant> Write for Certificate<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signers.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Variant> EncodeSize for Certificate<V> {
    fn encode_size(&self) -> usize {
        self.signers.encode_size() + self.signature.encode_size()
    }
}

impl<V: Variant> Read for Certificate<V> {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, participants: &usize) -> Result<Self, Error> {
        let signers = Signers::read_cfg(reader, participants)?;
        if signers.count() == 0 {
            return Err(Error::Invalid(
                "cryptography::bls12381::certificate::sas::Certificate",
                "Certificate contains no signers",
            ));
        }

        let signature = Lazy::<aggregate::Signature<V>>::read(reader)?;

        Ok(Self { signers, signature })
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for Certificate<V>
where
    V::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let signers = Signers::arbitrary(u)?;
        let signature = aggregate::Signature::arbitrary(u)?;
        Ok(Self {
            signers,
            signature: Lazy::from(signature),
        })
    }
}

/// Generates a BLS12-381 synchronized aggregate signing scheme wrapper for a specific protocol.
///
/// This macro creates a complete wrapper struct with constructors, `Scheme` and `Aggregator`
/// trait implementations, and a `fixture` function for testing.
///
/// # Parameters
///
/// - `$subject`: The subject type used as `Scheme::Subject<'a, D>`. It must implement
///   [`Synchronized`]. Use `'a` and `D` in the subject type to bind to the GAT lifetime and
///   digest type parameters.
///
/// - `$namespace`: The namespace type that implements [`Namespace`]. The scheme calls
///   `$namespace::derive(base)` at construction time and passes the result to
///   `Subject::namespace()` and `Synchronized::period()` during signing and verification.
///
/// - `$faults`: The [`Faults`](commonware_utils::Faults) implementation used to compute certificate
///   quorums.
///
/// # Security
///
/// The generated constructors do not verify proofs of knowledge. Before constructing a scheme,
/// callers must verify a [`sas::ProofOfKnowledge`] for every public key in the participant map.
/// Otherwise, aggregate verification is vulnerable to rogue-key attacks.
///
/// # Example
/// ```ignore
/// // For non-generic subject types with a single namespace:
/// impl_certificate_bls12381_sas!(MySubject, Vec<u8>, commonware_utils::N3f1);
///
/// // For protocols with generic subject types:
/// impl_certificate_bls12381_sas!(Subject<'a, D>, Namespace, commonware_utils::N3f1);
/// ```
#[macro_export]
macro_rules! impl_certificate_bls12381_sas {
    ($subject:ty, $namespace:ty, $faults:ty) => {
        /// Generates a test fixture with Ed25519 identities and BLS12-381 synchronized aggregate
        /// signing schemes.
        ///
        /// Returns a [`commonware_cryptography::certificate::mocks::Fixture`] whose keys and
        /// scheme instances share a consistent ordering.
        #[cfg(feature = "mocks")]
        #[allow(dead_code)]
        pub fn fixture<V, R>(
            rng: &mut R,
            namespace: &[u8],
            n: u32,
        ) -> $crate::certificate::mocks::Fixture<Scheme<$crate::ed25519::PublicKey, V>>
        where
            V: $crate::bls12381::primitives::variant::Variant,
            R: rand_core::CryptoRng,
        {
            $crate::bls12381::certificate::sas::mocks::fixture::<_, V, _>(
                rng,
                namespace,
                n,
                Scheme::signer,
                Scheme::verifier,
            )
        }

        /// BLS12-381 synchronized aggregate signing scheme wrapper.
        ///
        /// Every participant public key must have a verified proof of knowledge before this
        /// scheme is constructed.
        #[derive(Clone, Debug)]
        pub struct Scheme<
            P: $crate::PublicKey,
            V: $crate::bls12381::primitives::variant::Variant,
        > {
            /// Verification state, plus the signing material of a signer.
            generic: $crate::bls12381::certificate::sas::Generic<P, V, $namespace>,
            /// Index of the local identity key for an instance built with [`Self::member`].
            member: Option<commonware_utils::Participant>,
        }

        impl<
            P: $crate::PublicKey,
            V: $crate::bls12381::primitives::variant::Variant,
        > Scheme<P, V> {
            /// Creates a new scheme instance with the provided key material.
            ///
            /// # Security
            ///
            /// This function does not verify proofs of knowledge. The caller must verify one for
            /// every public key in `participants` before constructing the scheme.
            pub fn signer(
                namespace: &[u8],
                participants: commonware_utils::ordered::BiMap<
                    P,
                    $crate::bls12381::primitives::ops::sas::PublicKey<V>,
                >,
                private_key: $crate::bls12381::primitives::ops::sas::PrivateKey,
            ) -> Option<Self> {
                Some(Self {
                    generic: $crate::bls12381::certificate::sas::Generic::signer(
                        namespace,
                        participants,
                        private_key,
                    )?,
                    member: None,
                })
            }

            /// Builds a verifier that can authenticate signatures, aggregates, and certificates.
            ///
            /// A participant without signing material should use [`Self::member`] instead, so the
            /// scheme reports its membership.
            ///
            /// # Security
            ///
            /// This function does not verify proofs of knowledge. The caller must verify one for
            /// every public key in `participants` before constructing the scheme.
            pub fn verifier(
                namespace: &[u8],
                participants: commonware_utils::ordered::BiMap<
                    P,
                    $crate::bls12381::primitives::ops::sas::PublicKey<V>,
                >,
            ) -> Self {
                Self {
                    generic: $crate::bls12381::certificate::sas::Generic::verifier(
                        namespace,
                        participants,
                    ),
                    member: None,
                }
            }

            /// Builds a committee member that verifies like [`Self::verifier`] but also knows
            /// its own place in the participant set.
            ///
            /// The instance cannot sign, and [`Scheme::me`] returns [`Membership::Member`] at
            /// the position of the identity key `public_key` in the participant set. Returns
            /// `None` if `public_key` is not a participant identity key.
            ///
            /// # Security
            ///
            /// This function does not verify proofs of knowledge. The caller must verify one for
            /// every public key in `participants` before constructing the scheme.
            ///
            /// [`Scheme::me`]: commonware_cryptography::certificate::Scheme::me
            /// [`Membership::Member`]: commonware_cryptography::certificate::Membership::Member
            pub fn member(
                namespace: &[u8],
                participants: commonware_utils::ordered::BiMap<
                    P,
                    $crate::bls12381::primitives::ops::sas::PublicKey<V>,
                >,
                public_key: &P,
            ) -> Option<Self> {
                let member =
                    commonware_utils::ordered::Quorum::index(participants.keys(), public_key)?;
                Some(Self {
                    generic: $crate::bls12381::certificate::sas::Generic::verifier(
                        namespace,
                        participants,
                    ),
                    member: Some(member),
                })
            }
        }

        impl<
            P: $crate::PublicKey,
            V: $crate::bls12381::primitives::variant::Variant,
        > $crate::certificate::Verifier for Scheme<P, V> {
            type Subject<'a, D: $crate::Digest> = $subject;
            type Faults = $faults;
            type PublicKey = P;
            type Certificate = $crate::bls12381::certificate::sas::Certificate<V>;

            fn verify_certificate<R, D>(
                &self,
                rng: &mut R,
                subject: Self::Subject<'_, D>,
                certificate: &Self::Certificate,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> bool
            where
                R: rand_core::CryptoRng,
                D: $crate::Digest,
            {
                self.generic
                    .verify_certificate::<Self, _>(rng, subject, certificate)
            }

            fn verify_certificates<'a, R, D, I>(
                &self,
                rng: &mut R,
                certificates: commonware_utils::iter::NonEmpty<I>,
                strategy: &impl commonware_parallel::Strategy,
            ) -> bool
            where
                R: rand_core::CryptoRng,
                D: $crate::Digest,
                I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
            {
                self.generic
                    .verify_certificates::<Self, _, _, _>(rng, certificates, strategy)
            }

            fn is_batchable() -> bool {
                $crate::bls12381::certificate::sas::Generic::<P, V, $namespace>::is_batchable()
            }

            fn max_certificate_size(participants: u32) -> usize {
                $crate::bls12381::certificate::sas::Generic::<P, V, $namespace>::max_certificate_size(participants)
            }

            fn certificate_codec_config(
                &self,
            ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                self.generic.certificate_codec_config()
            }

            fn certificate_codec_config_unbounded() -> <Self::Certificate as commonware_codec::Read>::Cfg {
                $crate::bls12381::certificate::sas::Generic::<P, V, $namespace>::certificate_codec_config_unbounded()
            }
        }

        impl<
            P: $crate::PublicKey,
            V: $crate::bls12381::primitives::variant::Variant,
        > $crate::certificate::Scheme for Scheme<P, V> {
            type Signature = V::Signature;

            fn me(&self) -> Option<$crate::certificate::Membership> {
                self.generic
                    .signer_index()
                    .map($crate::certificate::Membership::Signer)
                    .or(self.member.map($crate::certificate::Membership::Member))
            }

            fn participants(&self) -> &commonware_utils::ordered::Set<Self::PublicKey> {
                self.generic.participants()
            }

            fn sign<D: $crate::Digest>(
                &self,
                subject: Self::Subject<'_, D>,
            ) -> Option<$crate::certificate::Attestation<Self>> {
                self.generic.sign(subject)
            }

            fn verify_attestation<R, D>(
                &self,
                _rng: &mut R,
                subject: Self::Subject<'_, D>,
                attestation: &$crate::certificate::Attestation<Self>,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> bool
            where
                R: rand_core::CryptoRng,
                D: $crate::Digest,
            {
                self.generic
                    .verify_attestation(subject, attestation)
            }

            fn verify_attestations<R, D, I>(
                &self,
                rng: &mut R,
                subject: Self::Subject<'_, D>,
                attestations: I,
                strategy: &impl commonware_parallel::Strategy,
            ) -> $crate::certificate::Verification<Self>
            where
                R: rand_core::CryptoRng,
                D: $crate::Digest,
                I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
                I::IntoIter: Send
            {
                self.generic
                    .verify_attestations(rng, subject, attestations, strategy)
            }

            fn optimistic_assemble<'a, R, D, I, J>(
                &self,
                rng: &mut R,
                subject: Self::Subject<'_, D>,
                pending: I,
                verified: J,
                strategy: &impl commonware_parallel::Strategy,
            ) -> Result<Self::Certificate, $crate::certificate::Verification<Self>>
            where
                R: rand_core::CryptoRng,
                D: $crate::Digest,
                I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
                I::IntoIter: ExactSizeIterator + Send,
                J: IntoIterator<Item = &'a $crate::certificate::Attestation<Self>>,
                J::IntoIter: Send,
            {
                $crate::certificate::optimistic_assemble::<Self, _, D, _, _>(
                    self, rng, subject, pending, verified, strategy,
                )
            }

            fn assemble<I>(
                &self,
                attestations: commonware_utils::iter::NonEmpty<I>,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> Result<Self::Certificate, $crate::certificate::AssemblyError>
            where
                I: Iterator<Item = $crate::certificate::Attestation<Self>> + Send,
            {
                self.generic.assemble::<Self, _>(attestations)
            }

            fn is_attributable() -> bool {
                $crate::bls12381::certificate::sas::Generic::<P, V, $namespace>::is_attributable()
            }
        }

        impl<
            P: $crate::PublicKey,
            V: $crate::bls12381::primitives::variant::Variant,
        > $crate::certificate::Aggregator for Scheme<P, V> {
            type Aggregate = commonware_codec::types::lazy::Lazy<
                $crate::bls12381::primitives::ops::aggregate::Signature<V>,
            >;

            fn aggregate<'a, I>(
                &self,
                attestations: commonware_utils::iter::NonEmpty<I>,
            ) -> Result<Self::Aggregate, $crate::certificate::AssemblyError>
            where
                I: Iterator<Item = &'a $crate::certificate::Attestation<Self>>,
            {
                self.generic.aggregate::<Self, _>(attestations)
            }

            fn verify_aggregates<R, D>(
                &self,
                rng: &mut R,
                items: &[$crate::certificate::Item<'_, '_, Self, D>],
                strategy: &impl commonware_parallel::Strategy,
            ) -> Vec<bool>
            where
                R: rand_core::CryptoRng,
                D: $crate::Digest,
            {
                self.generic.verify_aggregates(rng, items, strategy)
            }

            fn max_aggregate_size(terms: u32) -> usize {
                $crate::bls12381::certificate::sas::Generic::<P, V, $namespace>::max_aggregate_size(terms)
            }

            fn aggregate_codec_config(
                _terms: u32,
            ) -> <Self::Aggregate as commonware_codec::Read>::Cfg {
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Signer as _,
        bls12381::primitives::{
            group::Scalar,
            variant::{MinPk, MinSig},
        },
        certificate::{
            Membership, Scheme as _, Subject, Term, Verifier as _, aggregator_tests::Suite,
        },
        ed25519::{self, PrivateKey as Ed25519PrivateKey},
        sha256::Digest as Sha256Digest,
    };
    use commonware_codec::{Decode, Encode};
    use commonware_math::algebra::{CryptoGroup, Random};
    use commonware_parallel::Sequential;
    use commonware_utils::{Faults, N3f1, TryCollect, non_empty, test_rng, union_unique};

    const NAMESPACE: &[u8] = b"test-bls12381-sas";
    const PERIOD: u64 = 7;

    /// Test subject signed in a numbered period.
    #[derive(Clone, Debug)]
    pub struct TestSubject {
        pub period: u64,
        pub message: Bytes,
    }

    impl Subject for TestSubject {
        type Namespace = Vec<u8>;

        fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
            derived
        }

        fn message(&self) -> Bytes {
            self.message.clone()
        }
    }

    impl Synchronized for TestSubject {
        fn period(&self, derived: &Self::Namespace) -> Bytes {
            Bytes::from(union_unique(derived, &self.period.to_be_bytes()))
        }
    }

    impl_certificate_bls12381_sas!(TestSubject, Vec<u8>, N3f1);

    fn subject(index: usize) -> TestSubject {
        TestSubject {
            period: PERIOD,
            message: Bytes::from(format!("subject {index}")),
        }
    }

    fn setup_signers<V: Variant>(
        rng: &mut impl CryptoRng,
        n: u32,
    ) -> (
        Vec<Scheme<ed25519::PublicKey, V>>,
        Scheme<ed25519::PublicKey, V>,
    ) {
        let keys: Vec<_> = (0..n).map(|_| sas::keypair::<_, V>(&mut *rng)).collect();
        let participants: BiMap<ed25519::PublicKey, sas::PublicKey<V>> = keys
            .iter()
            .map(|(_, public)| (Ed25519PrivateKey::random(&mut *rng).public_key(), *public))
            .try_collect()
            .unwrap();
        let signers = keys
            .into_iter()
            .map(|(private, _)| Scheme::signer(NAMESPACE, participants.clone(), private).unwrap())
            .collect();
        let verifier = Scheme::verifier(NAMESPACE, participants);
        (signers, verifier)
    }

    fn quorum_attestations<V: Variant>(
        schemes: &[Scheme<ed25519::PublicKey, V>],
        subject: &TestSubject,
    ) -> Vec<Attestation<Scheme<ed25519::PublicKey, V>>> {
        let quorum = N3f1::quorum(schemes.len()) as usize;
        schemes
            .iter()
            .take(quorum)
            .map(|scheme| scheme.sign::<Sha256Digest>(subject.clone()).unwrap())
            .collect()
    }

    #[test]
    fn test_is_attributable_and_batchable() {
        assert!(Scheme::<ed25519::PublicKey, MinPk>::is_attributable());
        assert!(Scheme::<ed25519::PublicKey, MinSig>::is_batchable());
    }

    /// Signatures verify only in their own period, and verifiers cannot sign.
    fn sign_verify<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let attestation = schemes[0].sign::<Sha256Digest>(subject(0)).unwrap();
        assert!(verifier.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            subject(0),
            &attestation,
            &Sequential
        ));

        let mut later = subject(0);
        later.period += 1;
        assert!(!verifier.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            later,
            &attestation,
            &Sequential
        ));
        assert!(!verifier.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            subject(1),
            &attestation,
            &Sequential
        ));
        assert!(verifier.sign::<Sha256Digest>(subject(0)).is_none());
    }

    #[test]
    fn test_sign_verify() {
        sign_verify::<MinPk>();
        sign_verify::<MinSig>();
    }

    /// Batch verification over one subject reports exactly the invalid and unknown signers.
    fn verify_attestations<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 5);
        let mut attestations: Vec<_> = schemes
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(subject(0)).unwrap())
            .collect();
        let forged = attestations[1].signer;
        attestations[1].signature = schemes[1]
            .sign::<Sha256Digest>(subject(1))
            .unwrap()
            .signature;
        let unknown = Participant::new(5);
        attestations[4].signer = unknown;

        let verification = verifier.verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            subject(0),
            attestations,
            &Sequential,
        );
        let mut expected = vec![forged, unknown];
        expected.sort();
        assert_eq!(verification.invalid, expected);
        assert_eq!(verification.verified.len(), 3);

        let empty = verifier.verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            subject(0),
            Vec::new(),
            &Sequential,
        );
        assert!(empty.verified.is_empty() && empty.invalid.is_empty());
    }

    #[test]
    fn test_verify_attestations() {
        verify_attestations::<MinPk>();
        verify_attestations::<MinSig>();
    }

    /// Certificates assemble from a quorum and verify only for their subject and signers.
    fn certificate<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let attestations = quorum_attestations(&schemes, &subject(0));
        let certificate = schemes[0]
            .assemble(non_empty![@attestations.clone()], &Sequential)
            .unwrap();
        assert!(verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject(0),
            &certificate,
            &Sequential
        ));
        let mut later = subject(0);
        later.period += 1;
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            later,
            &certificate,
            &Sequential
        ));

        // Corrupted signatures, signers below quorum, and mismatched bitmaps fail.
        let mut corrupted = certificate.clone();
        corrupted.signature = Lazy::from(aggregate::Signature::zero());
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject(0),
            &corrupted,
            &Sequential
        ));
        let mut signers: Vec<_> = certificate.signers.iter().collect();
        signers.pop();
        let mut truncated = certificate.clone();
        truncated.signers = Signers::new(4, signers.clone()).unwrap();
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject(0),
            &truncated,
            &Sequential
        ));
        let mut widened = certificate.clone();
        widened.signers = Signers::new(5, certificate.signers.iter()).unwrap();
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject(0),
            &widened,
            &Sequential
        ));

        // Assembly rejects sub-quorum, unknown, duplicate, and malformed inputs.
        let quorum = N3f1::quorum(4);
        assert_eq!(
            schemes[0].assemble(non_empty![@attestations[1..].iter().cloned()], &Sequential),
            Err(AssemblyError::InsufficientAttestations(quorum, quorum - 1))
        );
        let mut unknown = attestations.clone();
        unknown[0].signer = Participant::new(9);
        assert_eq!(
            schemes[0].assemble(non_empty![@unknown], &Sequential),
            Err(AssemblyError::UnknownSigner(Participant::new(9)))
        );
        let mut duplicate = attestations.clone();
        duplicate.push(attestations[0].clone());
        assert_eq!(
            schemes[0].assemble(non_empty![@duplicate], &Sequential),
            Err(AssemblyError::DuplicateSigner(attestations[0].signer))
        );
        let mut malformed = attestations.clone();
        malformed[1].signature = Lazy::deferred(&mut Bytes::from_static(&[0u8]), ());
        assert_eq!(
            schemes[0].assemble(non_empty![@malformed], &Sequential),
            Err(AssemblyError::MalformedSignature(attestations[1].signer))
        );
    }

    #[test]
    fn test_certificate() {
        certificate::<MinPk>();
        certificate::<MinSig>();
    }

    /// Certificates over subjects in different periods verify together, and one corrupted
    /// certificate fails the batch.
    fn verify_certificates<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let subjects: Vec<_> = (0..3)
            .map(|i| TestSubject {
                period: i,
                message: Bytes::from(format!("message {i}")),
            })
            .collect();
        let mut certificates: Vec<_> = subjects
            .iter()
            .map(|subject| {
                schemes[0]
                    .assemble(
                        non_empty![@quorum_attestations(&schemes, subject)],
                        &Sequential,
                    )
                    .unwrap()
            })
            .collect();
        let pairs = subjects.iter().cloned().zip(certificates.iter());
        assert!(verifier.verify_certificates::<_, Sha256Digest, _>(
            &mut rng,
            non_empty![@pairs],
            &Sequential
        ));

        certificates[1].signature = certificates[0].signature.clone();
        let pairs = subjects.iter().cloned().zip(certificates.iter());
        assert!(!verifier.verify_certificates::<_, Sha256Digest, _>(
            &mut rng,
            non_empty![@pairs],
            &Sequential
        ));
    }

    #[test]
    fn test_verify_certificates() {
        verify_certificates::<MinPk>();
        verify_certificates::<MinSig>();
    }

    /// Certificates round trip at their maximum size and reject empty or oversized bitmaps.
    fn certificate_codec<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);
        let certificate = schemes[0]
            .assemble(
                non_empty![@schemes
                    .iter()
                    .map(|scheme| scheme.sign::<Sha256Digest>(subject(0)).unwrap())],
                &Sequential,
            )
            .unwrap();
        let encoded = certificate.encode();
        assert_eq!(
            encoded.len(),
            Scheme::<ed25519::PublicKey, V>::max_certificate_size(4)
        );
        assert_eq!(
            Certificate::<V>::decode_cfg(encoded.clone(), &4).unwrap(),
            certificate
        );
        assert!(Certificate::<V>::decode_cfg(encoded, &3).is_err());

        let empty = Certificate::<V> {
            signers: Signers::new(4, core::iter::empty()).unwrap(),
            signature: certificate.signature,
        };
        assert!(Certificate::<V>::decode_cfg(empty.encode(), &4).is_err());
    }

    #[test]
    fn test_certificate_codec() {
        certificate_codec::<MinPk>();
        certificate_codec::<MinSig>();
    }

    /// Members report their membership without signing, and clones share one key table.
    #[test]
    fn test_member_and_shared_table() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<MinSig>(&mut rng, 4);
        let participants = verifier.generic.participants.clone();
        let index = Participant::new(2);
        let key = participants.keys().key(index).unwrap().clone();
        let member = Scheme::<_, MinSig>::member(NAMESPACE, participants.clone(), &key).unwrap();
        assert_eq!(member.me(), Some(Membership::Member(index)));
        assert!(member.sign::<Sha256Digest>(subject(0)).is_none());
        let outsider = Ed25519PrivateKey::random(&mut rng).public_key();
        assert!(Scheme::<_, MinSig>::member(NAMESPACE, participants, &outsider).is_none());
        assert_eq!(verifier.me(), None);
        assert!(matches!(schemes[0].me(), Some(Membership::Signer(_))));

        let clone = schemes[0].clone();
        assert!(Arc::ptr_eq(&clone.generic.table, &schemes[0].generic.table));
        assert_eq!(schemes[0].generic.table.len(), 4);
    }

    fn aggregator_suite<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(&mut test_rng(), 5);
        Suite {
            schemes: &schemes,
            verifier: &verifier,
            subject,
            unique: true,
        }
        .run();
    }

    #[test]
    fn test_aggregator_suite() {
        aggregator_suite::<MinPk>();
        aggregator_suite::<MinSig>();
    }

    /// The terms left after discharge must share one period, malformed aggregates fail, and errors
    /// that cancel across two aggregates are caught by the batch's random weights.
    fn aggregate_structure<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let mut subjects: Vec<_> = (0..4).map(subject).collect();
        subjects[3].period += 1;
        let attestations: Vec<_> = schemes
            .iter()
            .zip(&subjects)
            .map(|(scheme, subject)| scheme.sign::<Sha256Digest>(subject.clone()).unwrap())
            .collect();
        let mut terms: Vec<Term<'_, _, Sha256Digest>> = attestations
            .iter()
            .zip(&subjects)
            .map(|(attestation, subject)| Term {
                signer: attestation.signer,
                subject: subject.clone(),
                known: None,
            })
            .collect();
        let aggregate = verifier.aggregate(non_empty![@&attestations]).unwrap();
        assert!(!verifier.verify_aggregate(&mut rng, &terms, &aggregate, &Sequential));
        terms[3].known = Some(&attestations[3]);
        assert!(verifier.verify_aggregate(&mut rng, &terms, &aggregate, &Sequential));
        terms[3].known = None;

        let terms = &terms[..3];
        let aggregate = verifier.aggregate(non_empty![@&attestations[..3]]).unwrap();
        assert!(verifier.verify_aggregate(&mut rng, terms, &aggregate, &Sequential));
        let malformed = Lazy::deferred(
            &mut Bytes::from(vec![0xFF; aggregate::Signature::<V>::SIZE]),
            (),
        );
        assert!(!verifier.verify_aggregate(&mut rng, terms, &malformed, &Sequential));

        let delta = V::Signature::generator() * &Scalar::random(&mut rng);
        let inner = *aggregate.get().unwrap().inner();
        let high = Lazy::<aggregate::Signature<V>>::deferred(&mut (inner + &delta).encode(), ());
        let low = Lazy::<aggregate::Signature<V>>::deferred(&mut (inner - &delta).encode(), ());
        let items = [
            Item::Aggregate {
                terms,
                aggregate: &high,
            },
            Item::Aggregate {
                terms,
                aggregate: &low,
            },
            Item::Aggregate {
                terms,
                aggregate: &aggregate,
            },
        ];
        assert_eq!(
            verifier.verify_aggregates(&mut rng, &items, &Sequential),
            vec![false, false, true]
        );
    }

    #[test]
    fn test_aggregate_structure() {
        aggregate_structure::<MinPk>();
        aggregate_structure::<MinSig>();
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Certificate<MinSig>>,
        }
    }
}
