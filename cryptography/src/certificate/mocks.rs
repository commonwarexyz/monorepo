//! Mocks for certificate signing schemes.

use super::{Attestation, Scheme, Signers, Subject, Verification};
use crate::{
    ed25519::{PrivateKey, PublicKey as Ed25519PublicKey},
    Digest, PublicKey,
};
use bytes::Bytes;
use commonware_utils::{
    ordered::{Quorum, Set},
    sequence::U64,
    sync::Mutex,
    Faults, Participant,
};
use core::fmt;
use rand_core::CryptoRngCore;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::Arc,
    vec::Vec,
};

/// A fixture containing identities, identity private keys, per-participant
/// signing schemes, and a single verifier scheme.
#[derive(Clone, Debug)]
pub struct Fixture<S> {
    /// A sorted vector of participant public identity keys.
    pub participants: Vec<Ed25519PublicKey>,
    /// A sorted vector of participant private identity keys (matching order with `participants`).
    pub private_keys: Vec<PrivateKey>,
    /// A vector of per-participant scheme instances (matching order with `participants`).
    pub schemes: Vec<S>,
    /// A single scheme verifier.
    pub verifier: S,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct SignedSubject {
    namespace: Vec<u8>,
    message: Bytes,
}

impl SignedSubject {
    fn new<S: Subject>(subject: S, derived: &S::Namespace) -> Self {
        Self {
            namespace: Subject::namespace(&subject, derived).to_vec(),
            message: Subject::message(&subject),
        }
    }
}

#[derive(Debug, Default)]
struct SignerSignatures {
    by: HashMap<u64, SignedSubject>,
    by_subject: HashMap<SignedSubject, u64>,
}

#[derive(Debug, Default)]
struct Signatures {
    /// The counter is global so each signature ID is unique across all signers. A per-signer
    /// counter would let two signers share the same ID for different subjects, making
    /// a forged attestation (with a swapped signer field) pass verification.
    next: u64,
    by_signer: HashMap<Participant, SignerSignatures>,
}

impl Signatures {
    const fn next(&mut self) -> u64 {
        let current = self.next;
        self.next = self.next.checked_add(1).expect("signature overflow");
        current
    }
}

#[derive(Debug, Default)]
struct Certificates {
    next: u64,
    by: HashMap<u64, SignedSubject>,
    by_artifact: HashMap<(SignedSubject, Signers), u64>,
}

impl Certificates {
    const fn next(&mut self) -> u64 {
        let current = self.next;
        self.next = self.next.checked_add(1).expect("certificate overflow");
        current
    }
}

#[derive(Debug, Default)]
struct Inner {
    signatures: Signatures,
    certificates: Certificates,
}

/// Shared state for mock schemes created by the same test fixture.
#[derive(Clone, Default)]
pub struct Shared(Arc<Mutex<Inner>>);

/// Generic mock certificate implementation.
///
/// Signatures and certificates are cheap synthetic IDs. Verification succeeds only
/// if the corresponding subject was previously recorded in shared state.
pub struct Generic<
    P,
    N,
    const ATTRIBUTABLE: bool = true,
    const BATCHABLE: bool = true,
    const ALLOW_INVALID: bool = true,
> where
    P: PublicKey,
    N: super::Namespace,
{
    me: Option<Participant>,
    participants: Set<P>,
    namespace: N,
    shared: Shared,
}

impl<P, N, const ATTRIBUTABLE: bool, const BATCHABLE: bool, const ALLOW_INVALID: bool> fmt::Debug
    for Generic<P, N, ATTRIBUTABLE, BATCHABLE, ALLOW_INVALID>
where
    P: PublicKey,
    N: super::Namespace,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Generic")
            .field("me", &self.me)
            .field("participants", &self.participants)
            .finish_non_exhaustive()
    }
}

impl<P, N, const ATTRIBUTABLE: bool, const BATCHABLE: bool, const ALLOW_INVALID: bool> Clone
    for Generic<P, N, ATTRIBUTABLE, BATCHABLE, ALLOW_INVALID>
where
    P: PublicKey,
    N: super::Namespace,
{
    fn clone(&self) -> Self {
        Self {
            me: self.me,
            participants: self.participants.clone(),
            namespace: self.namespace.clone(),
            shared: self.shared.clone(),
        }
    }
}

impl<P, N, const ATTRIBUTABLE: bool, const BATCHABLE: bool, const ALLOW_INVALID: bool>
    Generic<P, N, ATTRIBUTABLE, BATCHABLE, ALLOW_INVALID>
where
    P: PublicKey,
    N: super::Namespace,
{
    fn invalid<T: Default>(reason: &str) -> T {
        if ALLOW_INVALID {
            T::default()
        } else {
            panic!("invalid mock certificate request: {reason}");
        }
    }

    /// Creates a signer bound to the provided participant index.
    pub fn signer(
        namespace: &[u8],
        participants: Set<P>,
        me: Participant,
        shared: Shared,
    ) -> Option<Self> {
        participants.key(me)?;
        Some(Self {
            me: Some(me),
            participants,
            namespace: N::derive(namespace),
            shared,
        })
    }

    /// Creates a verifier sharing the provided state.
    pub fn verifier(namespace: &[u8], participants: Set<P>, shared: Shared) -> Self {
        Self {
            me: None,
            participants,
            namespace: N::derive(namespace),
            shared,
        }
    }

    /// Returns the index of "self" in the participant set, if available.
    pub const fn me(&self) -> Option<Participant> {
        self.me
    }

    /// Returns the ordered participant set.
    pub const fn participants(&self) -> &Set<P> {
        &self.participants
    }

    /// Signs a subject and returns a cheap synthetic signature ID.
    ///
    /// Re-signing the same subject from the same signer reuses the existing
    /// synthetic signature so the mock behaves like deterministic schemes.
    pub fn sign<'a, S, D>(&self, subject: S::Subject<'a, D>) -> Option<Attestation<S>>
    where
        S: Scheme<Signature = U64>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        let signer = self.me?;
        let signed_subject = SignedSubject::new(subject, &self.namespace);

        let mut inner = self.shared.0.lock();
        inner.signatures.by_signer.entry(signer).or_default();
        let existing = inner.signatures.by_signer[&signer]
            .by_subject
            .get(&signed_subject)
            .copied();
        let signature = existing.unwrap_or_else(|| {
            let sig = inner.signatures.next();
            let entries = inner.signatures.by_signer.get_mut(&signer).unwrap();
            entries.by.insert(sig, signed_subject.clone());
            entries.by_subject.insert(signed_subject, sig);
            sig
        });

        Some(Attestation {
            signer,
            signature: U64::new(signature).into(),
        })
    }

    /// Verifies a single mock attestation.
    pub fn verify_attestation<'a, S, D>(
        &self,
        subject: S::Subject<'a, D>,
        attestation: &Attestation<S>,
    ) -> bool
    where
        S: Scheme<Signature = U64>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        if self.participants.key(attestation.signer).is_none() {
            return Self::invalid("attestation signer missing from participant set");
        }

        let Some(signature) = attestation.signature.get() else {
            return Self::invalid("attestation signature missing");
        };
        let expected_subject = SignedSubject::new(subject, &self.namespace);
        let signature = u64::from(signature);
        let inner = self.shared.0.lock();
        inner
            .signatures
            .by_signer
            .get(&attestation.signer)
            .and_then(|entries| entries.by.get(&signature))
            .is_some_and(|stored| stored == &expected_subject)
            || Self::invalid("attestation not found or subject mismatched")
    }

    /// Verifies attestations one-by-one and returns verified attestations and invalid signers.
    pub fn verify_attestations<'a, S, R, D, I>(
        &self,
        _rng: &mut R,
        subject: S::Subject<'a, D>,
        attestations: I,
    ) -> Verification<S>
    where
        S: Scheme<Signature = U64>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRngCore,
        D: Digest,
        I: IntoIterator<Item = Attestation<S>>,
    {
        let mut invalid = BTreeSet::new();
        let mut verified = Vec::new();

        for attestation in attestations {
            if self.verify_attestation::<S, D>(subject.clone(), &attestation) {
                verified.push(attestation);
            } else {
                invalid.insert(attestation.signer);
            }
        }

        Verification::new(verified, invalid.into_iter().collect())
    }

    /// Assembles attestations into a mock certificate.
    pub fn assemble<S, I, M>(&self, attestations: I) -> Option<U64>
    where
        S: Scheme<Signature = U64>,
        I: IntoIterator<Item = Attestation<S>>,
        M: Faults,
    {
        let mut unique_signers = HashSet::new();
        let mut signers = Vec::new();
        let mut signed_subject = None;
        let mut inner = self.shared.0.lock();

        for attestation in attestations {
            self.participants
                .key(attestation.signer)
                .or_else(|| Self::invalid("attestation signer missing from participant set"))?;

            let signature = attestation
                .signature
                .get()
                .or_else(|| Self::invalid("attestation signature missing"))?;
            let signature = u64::from(signature);
            let entry = inner
                .signatures
                .by_signer
                .get(&attestation.signer)
                .or_else(|| Self::invalid("attestation signer not found"))?
                .by
                .get(&signature)
                .or_else(|| Self::invalid("attestation signature not found"))?
                .clone();

            if let Some(existing) = &signed_subject {
                if existing != &entry {
                    return Self::invalid("attestations signed different subjects");
                }
            } else {
                signed_subject = Some(entry);
            }

            if !unique_signers.insert(attestation.signer) {
                return Self::invalid("duplicate signer");
            }
            signers.push(attestation.signer);
        }

        if signers.len() < self.participants.quorum::<M>() as usize {
            return None;
        }

        let subject = signed_subject?;
        let signers = Signers::from(self.participants.len(), signers);
        let stored_subject = subject.clone();
        let artifact = (subject, signers);
        let certificate = inner
            .certificates
            .by_artifact
            .get(&artifact)
            .copied()
            .unwrap_or_else(|| {
                let certificate = inner.certificates.next();
                inner.certificates.by.insert(certificate, stored_subject);
                inner.certificates.by_artifact.insert(artifact, certificate);
                certificate
            });

        Some(U64::new(certificate))
    }

    /// Verifies a mock certificate.
    pub fn verify_certificate<'a, S, R, D, M>(
        &self,
        _rng: &mut R,
        subject: S::Subject<'a, D>,
        certificate: &U64,
    ) -> bool
    where
        S: Scheme<Certificate = U64>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRngCore,
        D: Digest,
        M: Faults,
    {
        let expected_subject = SignedSubject::new(subject, &self.namespace);
        let certificate = u64::from(certificate);
        let inner = self.shared.0.lock();
        inner
            .certificates
            .by
            .get(&certificate)
            .is_some_and(|subject| subject == &expected_subject)
            || Self::invalid("certificate not found or subject mismatched")
    }

    /// Verifies a batch of certificates one-by-one.
    pub fn verify_certificates<'a, S, R, D, I, M>(&self, rng: &mut R, mut certificates: I) -> bool
    where
        S: Scheme<Certificate = U64>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: rand::Rng + rand::CryptoRng,
        D: Digest,
        I: Iterator<Item = (S::Subject<'a, D>, &'a U64)>,
        M: Faults,
    {
        certificates.all(|(subject, certificate)| {
            self.verify_certificate::<S, _, D, M>(rng, subject, certificate)
        })
    }

    /// Returns whether this scheme is attributable.
    pub const fn is_attributable() -> bool {
        ATTRIBUTABLE
    }

    /// Returns whether this scheme supports batch verification.
    pub const fn is_batchable() -> bool {
        BATCHABLE
    }

    /// Returns the codec bound for certificates produced by this participant set.
    pub const fn certificate_codec_config(&self) {}

    /// Returns the unbounded codec configuration.
    pub const fn certificate_codec_config_unbounded() {}
}

/// Implements a mock mock certificate scheme for a concrete subject and namespace.
///
/// This follows the same binding pattern as the other certificate macros: the protocol
/// supplies the subject type and namespace type, and the macro emits a local `Scheme`
/// wrapper plus a `fixture(...)` helper for tests.
///
/// # Example
/// ```ignore
/// use commonware_cryptography::impl_certificate_mock;
///
/// impl_certificate_mock!(Subject<'a, D>, Namespace);
/// ```
#[macro_export]
macro_rules! impl_certificate_mock {
    ($subject:ty, $namespace:ty) => {
        /// Generates a test fixture with Ed25519 identities and a mock mock scheme.
        #[cfg(feature = "mocks")]
        #[allow(dead_code)]
        pub fn fixture<R>(
            rng: &mut R,
            namespace: &[u8],
            n: u32,
        ) -> $crate::certificate::mocks::Fixture<Scheme<$crate::ed25519::PublicKey>>
        where
            R: rand::RngCore + rand::CryptoRng,
        {
            fixture_with::<true, true, true, R>(rng, namespace, n)
        }

        /// Generates a test fixture with explicit mock certificate behavior flags.
        #[cfg(feature = "mocks")]
        #[allow(dead_code)]
        pub fn fixture_with<
            const ATTRIBUTABLE: bool,
            const BATCHABLE: bool,
            const ALLOW_INVALID: bool,
            R,
        >(
            rng: &mut R,
            namespace: &[u8],
            n: u32,
        ) -> $crate::certificate::mocks::Fixture<
            Scheme<$crate::ed25519::PublicKey, ATTRIBUTABLE, BATCHABLE, ALLOW_INVALID>,
        >
        where
            R: rand::RngCore + rand::CryptoRng,
        {
            assert!(n > 0);

            let associated = $crate::ed25519::certificate::mocks::participants(rng, n);
            let participants = associated.keys().clone();
            let participants_vec: ::std::vec::Vec<_> = participants.clone().into();
            let private_keys: ::std::vec::Vec<_> = participants_vec
                .iter()
                .map(|public_key| {
                    associated
                        .get_value(public_key)
                        .expect("participant key must have an associated private key")
                        .clone()
                })
                .collect();

            let shared = $crate::certificate::mocks::Shared::default();
            let schemes = participants_vec
                .iter()
                .enumerate()
                .map(|(idx, _)| {
                    Scheme::signer(
                        namespace,
                        participants.clone(),
                        commonware_utils::Participant::new(idx as u32),
                        shared.clone(),
                    )
                    .expect("scheme signer must be a participant")
                })
                .collect();
            let verifier = Scheme::verifier(namespace, participants, shared);

            $crate::certificate::mocks::Fixture {
                participants: participants_vec,
                private_keys,
                schemes,
                verifier,
            }
        }

        /// Ledger-backed mock signing scheme wrapper.
        #[derive(Clone, Debug)]
        pub struct Scheme<
            P: $crate::PublicKey,
            const ATTRIBUTABLE: bool = true,
            const BATCHABLE: bool = true,
            const ALLOW_INVALID: bool = true,
        > {
            generic: $crate::certificate::mocks::Generic<
                P,
                $namespace,
                ATTRIBUTABLE,
                BATCHABLE,
                ALLOW_INVALID,
            >,
        }

        impl<
                P: $crate::PublicKey,
                const ATTRIBUTABLE: bool,
                const BATCHABLE: bool,
                const ALLOW_INVALID: bool,
            > Scheme<P, ATTRIBUTABLE, BATCHABLE, ALLOW_INVALID>
        {
            pub fn signer(
                namespace: &[u8],
                participants: commonware_utils::ordered::Set<P>,
                me: commonware_utils::Participant,
                shared: $crate::certificate::mocks::Shared,
            ) -> Option<Self> {
                Some(Self {
                    generic: $crate::certificate::mocks::Generic::signer(
                        namespace,
                        participants,
                        me,
                        shared,
                    )?,
                })
            }

            pub fn verifier(
                namespace: &[u8],
                participants: commonware_utils::ordered::Set<P>,
                shared: $crate::certificate::mocks::Shared,
            ) -> Self {
                Self {
                    generic: $crate::certificate::mocks::Generic::verifier(
                        namespace,
                        participants,
                        shared,
                    ),
                }
            }
        }

        impl<
                P: $crate::PublicKey,
                const ATTRIBUTABLE: bool,
                const BATCHABLE: bool,
                const ALLOW_INVALID: bool,
            > $crate::certificate::Scheme for Scheme<P, ATTRIBUTABLE, BATCHABLE, ALLOW_INVALID>
        {
            type Subject<'a, D: $crate::Digest> = $subject;
            type PublicKey = P;
            type Signature = commonware_utils::sequence::U64;
            type Certificate = commonware_utils::sequence::U64;

            fn me(&self) -> Option<commonware_utils::Participant> {
                self.generic.me()
            }

            fn participants(&self) -> &commonware_utils::ordered::Set<Self::PublicKey> {
                self.generic.participants()
            }

            fn sign<D: $crate::Digest>(
                &self,
                subject: Self::Subject<'_, D>,
            ) -> Option<$crate::certificate::Attestation<Self>> {
                self.generic.sign::<Self, D>(subject)
            }

            fn verify_attestation<R, D>(
                &self,
                _rng: &mut R,
                subject: Self::Subject<'_, D>,
                attestation: &$crate::certificate::Attestation<Self>,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> bool
            where
                R: rand_core::CryptoRngCore,
                D: $crate::Digest,
            {
                self.generic
                    .verify_attestation::<Self, D>(subject, attestation)
            }

            fn verify_attestations<R, D, I>(
                &self,
                rng: &mut R,
                subject: Self::Subject<'_, D>,
                attestations: I,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> $crate::certificate::Verification<Self>
            where
                R: rand_core::CryptoRngCore,
                D: $crate::Digest,
                I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
            {
                self.generic
                    .verify_attestations::<Self, _, D, _>(rng, subject, attestations)
            }

            fn assemble<I, M>(
                &self,
                attestations: I,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> Option<Self::Certificate>
            where
                I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
                M: commonware_utils::Faults,
            {
                self.generic.assemble::<Self, _, M>(attestations)
            }

            fn verify_certificate<R, D, M>(
                &self,
                rng: &mut R,
                subject: Self::Subject<'_, D>,
                certificate: &Self::Certificate,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> bool
            where
                R: rand_core::CryptoRngCore,
                D: $crate::Digest,
                M: commonware_utils::Faults,
            {
                self.generic
                    .verify_certificate::<Self, _, D, M>(rng, subject, certificate)
            }

            fn verify_certificates<'a, R, D, I, M>(
                &self,
                rng: &mut R,
                certificates: I,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> bool
            where
                R: rand::Rng + rand::CryptoRng,
                D: $crate::Digest,
                I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
                M: commonware_utils::Faults,
            {
                self.generic
                    .verify_certificates::<Self, _, D, _, M>(rng, certificates)
            }

            fn is_attributable() -> bool {
                $crate::certificate::mocks::Generic::<
                    P,
                    $namespace,
                    ATTRIBUTABLE,
                    BATCHABLE,
                    ALLOW_INVALID,
                >::is_attributable()
            }

            fn is_batchable() -> bool {
                $crate::certificate::mocks::Generic::<
                    P,
                    $namespace,
                    ATTRIBUTABLE,
                    BATCHABLE,
                    ALLOW_INVALID,
                >::is_batchable()
            }

            fn certificate_codec_config(
                &self,
            ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                self.generic.certificate_codec_config()
            }

            fn certificate_codec_config_unbounded(
            ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                $crate::certificate::mocks::Generic::<
                    P,
                    $namespace,
                    ATTRIBUTABLE,
                    BATCHABLE,
                    ALLOW_INVALID,
                >::certificate_codec_config_unbounded()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::{Certificates, Shared, Signatures};
    use crate::{
        certificate::{Attestation, Lazy, Scheme as _},
        ed25519::PublicKey as Ed25519PublicKey,
        sha256::Digest as Sha256Digest,
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, Encode};
    use commonware_parallel::Sequential;
    use commonware_utils::{sequence::U64, test_rng, N3f1, Participant};

    #[derive(Clone, Copy, Debug)]
    pub struct TestSubject<'a> {
        message: &'a [u8],
    }

    impl crate::certificate::Subject for TestSubject<'_> {
        type Namespace = Vec<u8>;

        fn namespace<'a>(&self, namespace: &'a Self::Namespace) -> &'a [u8] {
            namespace
        }

        fn message(&self) -> Bytes {
            self.message.to_vec().into()
        }
    }

    impl_certificate_mock!(TestSubject<'a>, Vec<u8>);

    #[test]
    fn attestation_round_trip_verifies() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject { message: b"vote-1" };
        let attestation = fixture.schemes[0]
            .sign::<Sha256Digest>(subject)
            .expect("signer must produce an attestation");

        assert!(fixture.verifier.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            subject,
            &attestation,
            &Sequential,
        ));
        assert!(!fixture.verifier.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            TestSubject { message: b"vote-2" },
            &attestation,
            &Sequential,
        ));
    }

    #[test]
    fn repeated_signing_reuses_same_mock_signature() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject { message: b"vote-1" };

        let first = fixture.schemes[0]
            .sign::<Sha256Digest>(subject)
            .expect("signer must produce an attestation");
        let second = fixture.schemes[0]
            .sign::<Sha256Digest>(subject)
            .expect("signer must produce an attestation");
        let other = fixture.schemes[0]
            .sign::<Sha256Digest>(TestSubject { message: b"vote-2" })
            .expect("signer must produce an attestation");

        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    #[should_panic(expected = "signature overflow")]
    fn signature_overflow_panics() {
        let mut signatures = Signatures {
            next: u64::MAX,
            ..Default::default()
        };

        let _ = signatures.next();
    }

    #[test]
    #[should_panic(expected = "certificate overflow")]
    fn certificate_overflow_panics() {
        let mut certificates = Certificates {
            next: u64::MAX,
            ..Default::default()
        };

        let _ = certificates.next();
    }

    #[test]
    fn configurable_properties_follow_type_flags() {
        assert!(Scheme::<Ed25519PublicKey>::is_attributable());
        assert!(Scheme::<Ed25519PublicKey>::is_batchable());

        assert!(!Scheme::<Ed25519PublicKey, false, false>::is_attributable());
        assert!(!Scheme::<Ed25519PublicKey, false, false>::is_batchable());
    }

    #[test]
    fn signer_and_verifier_expose_expected_metadata() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject {
            message: b"metadata",
        };
        let cloned = fixture.schemes[0].clone();

        assert_eq!(fixture.verifier.me(), None);
        assert_eq!(cloned.me(), Some(Participant::new(0)));
        assert_eq!(fixture.verifier.participants().len(), 4);
        assert_eq!(fixture.verifier.certificate_codec_config(), ());
        assert_eq!(
            Scheme::<Ed25519PublicKey>::certificate_codec_config_unbounded(),
            ()
        );
        assert!(Scheme::<Ed25519PublicKey>::signer(
            b"mock-scheme",
            fixture.verifier.participants().clone(),
            Participant::new(99),
            Shared::default(),
        )
        .is_none());
        assert!(fixture.verifier.sign::<Sha256Digest>(subject).is_none());
        assert!(cloned.sign::<Sha256Digest>(subject).is_some());
        assert!(format!("{cloned:?}").contains("participants"));
    }

    #[test]
    fn verify_attestation_rejects_malformed_and_foreign_attestations() {
        let mut rng = test_rng();
        let scheme_fixture = fixture(&mut rng, b"mock-scheme", 4);
        let foreign_fixture = fixture(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject { message: b"vote-1" };
        let attestation = scheme_fixture.schemes[0]
            .sign::<Sha256Digest>(subject)
            .expect("signer must produce an attestation");
        let mut invalid_signer = attestation;
        invalid_signer.signer = Participant::new(99);
        let mut truncated = &[0u8, 1, 2][..];
        let missing_signature = Attestation::<Scheme<Ed25519PublicKey>> {
            signer: Participant::new(2),
            signature: Lazy::deferred(&mut truncated, ()),
        };
        let foreign = foreign_fixture.schemes[3]
            .sign::<Sha256Digest>(subject)
            .expect("foreign signer must produce an attestation");

        assert!(!scheme_fixture
            .verifier
            .verify_attestation::<_, Sha256Digest>(
                &mut rng,
                subject,
                &invalid_signer,
                &Sequential,
            ));
        assert!(!scheme_fixture
            .verifier
            .verify_attestation::<_, Sha256Digest>(
                &mut rng,
                subject,
                &missing_signature,
                &Sequential,
            ));
        assert!(!scheme_fixture
            .verifier
            .verify_attestation::<_, Sha256Digest>(&mut rng, subject, &foreign, &Sequential,));
    }

    #[test]
    fn signer_swapped_attestation_is_rejected() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject { message: b"vote-1" };
        let attestation_a = fixture.schemes[0]
            .sign::<Sha256Digest>(subject)
            .expect("signer must produce an attestation");
        let attestation_b = fixture.schemes[1]
            .sign::<Sha256Digest>(subject)
            .expect("signer must produce an attestation");
        let mut forged = attestation_a.clone();
        forged.signer = Participant::new(1);

        assert_ne!(
            attestation_a.signature.get(),
            attestation_b.signature.get(),
            "different signers signing the same subject must receive distinct synthetic IDs"
        );

        assert!(
            !fixture.verifier.verify_attestation::<_, Sha256Digest>(
                &mut rng,
                subject,
                &forged,
                &Sequential,
            ),
            "swapping signer on an attestation must fail verification"
        );
    }

    #[test]
    fn verify_attestations_partitions_valid_and_invalid_inputs() {
        let mut rng = test_rng();
        let scheme_fixture = fixture(&mut rng, b"mock-scheme", 4);
        let foreign_fixture = fixture(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject { message: b"vote-1" };
        let valid_a = scheme_fixture.schemes[0]
            .sign::<Sha256Digest>(subject)
            .expect("signer must produce an attestation");
        let valid_b = scheme_fixture.schemes[1]
            .sign::<Sha256Digest>(subject)
            .expect("signer must produce an attestation");
        let mut truncated = &[9u8, 9, 9][..];
        let missing_signature = Attestation::<Scheme<Ed25519PublicKey>> {
            signer: Participant::new(2),
            signature: Lazy::deferred(&mut truncated, ()),
        };
        let foreign = foreign_fixture.schemes[3]
            .sign::<Sha256Digest>(subject)
            .expect("foreign signer must produce an attestation");

        let verification = scheme_fixture
            .verifier
            .verify_attestations::<_, Sha256Digest, _>(
                &mut rng,
                subject,
                [valid_a.clone(), missing_signature, foreign, valid_b.clone()],
                &Sequential,
            );

        assert_eq!(verification.verified, vec![valid_a, valid_b]);
        assert_eq!(
            verification.invalid,
            vec![Participant::new(2), Participant::new(3)]
        );
    }

    #[test]
    fn certificate_round_trip_verifies() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject {
            message: b"certificate-subject",
        };
        let attestations: Vec<_> = fixture.schemes[..3]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(subject).unwrap())
            .collect();
        let certificate = fixture
            .verifier
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();
        let encoded = certificate.encode();
        let decoded =
            U64::decode_cfg(encoded, &fixture.verifier.certificate_codec_config()).unwrap();

        assert!(
            fixture
                .verifier
                .verify_certificate::<_, Sha256Digest, N3f1>(
                    &mut rng,
                    subject,
                    &decoded,
                    &Sequential,
                )
        );
        assert!(!fixture
            .verifier
            .verify_certificate::<_, Sha256Digest, N3f1>(
                &mut rng,
                TestSubject {
                    message: b"other-subject",
                },
                &decoded,
                &Sequential,
            ));
    }

    #[test]
    fn repeated_assembly_reuses_the_same_certificate() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject {
            message: b"certificate-subject",
        };
        let attestations: Vec<_> = fixture.schemes[..3]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(subject).unwrap())
            .collect();

        let first = fixture
            .verifier
            .assemble::<_, N3f1>(attestations.clone(), &Sequential)
            .unwrap();
        let second = fixture
            .verifier
            .assemble::<_, N3f1>(
                attestations.iter().cloned().rev().collect::<Vec<_>>(),
                &Sequential,
            )
            .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn certificate_decode_round_trip_uses_unit_config() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject { message: b"bound" };
        let attestations: Vec<_> = fixture.schemes[..3]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(subject).unwrap())
            .collect();
        let certificate = fixture
            .verifier
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();
        let encoded = certificate.encode();

        assert_eq!(
            U64::decode_cfg(encoded, &fixture.verifier.certificate_codec_config()).unwrap(),
            certificate
        );
    }

    #[test]
    fn certificate_assembly_requires_matching_subjects_and_quorum() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject { message: b"vote-1" };

        assert!(fixture
            .verifier
            .assemble::<_, N3f1>(
                [
                    fixture.schemes[0].sign::<Sha256Digest>(subject).unwrap(),
                    fixture.schemes[1].sign::<Sha256Digest>(subject).unwrap(),
                ],
                &Sequential,
            )
            .is_none());

        assert!(fixture
            .verifier
            .assemble::<_, N3f1>(
                [
                    fixture.schemes[0].sign::<Sha256Digest>(subject).unwrap(),
                    fixture.schemes[1].sign::<Sha256Digest>(subject).unwrap(),
                    fixture.schemes[2]
                        .sign::<Sha256Digest>(TestSubject { message: b"vote-2" })
                        .unwrap(),
                ],
                &Sequential,
            )
            .is_none());
    }

    #[test]
    fn certificate_assembly_rejects_duplicate_signers() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject {
            message: b"duplicate-signer",
        };
        let attestation = fixture.schemes[0]
            .sign::<Sha256Digest>(subject)
            .expect("signer must produce an attestation");

        let certificate = fixture.verifier.assemble::<_, N3f1>(
            [
                attestation.clone(),
                attestation,
                fixture.schemes[1].sign::<Sha256Digest>(subject).unwrap(),
            ],
            &Sequential,
        );

        assert!(
            certificate.is_none(),
            "duplicate signers should be rejected by mock assembly"
        );
    }

    #[test]
    fn certificate_verification_rejects_mismatched_subject_and_batch_failures() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, b"mock-scheme", 4);
        let subject_a = TestSubject { message: b"vote-a" };
        let subject_b = TestSubject { message: b"vote-b" };
        let attestations_a: Vec<_> = fixture.schemes[..3]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(subject_a).unwrap())
            .collect();
        let attestations_b: Vec<_> = fixture.schemes[..3]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(subject_b).unwrap())
            .collect();
        let certificate_a = fixture
            .verifier
            .assemble::<_, N3f1>(attestations_a, &Sequential)
            .unwrap();
        let certificate_b = fixture
            .verifier
            .assemble::<_, N3f1>(attestations_b, &Sequential)
            .unwrap();
        let missing = U64::new(u64::MAX);

        assert!(!fixture
            .verifier
            .verify_certificate::<_, Sha256Digest, N3f1>(
                &mut rng,
                subject_a,
                &certificate_b,
                &Sequential,
            ));
        assert!(!fixture
            .verifier
            .verify_certificate::<_, Sha256Digest, N3f1>(
                &mut rng,
                subject_b,
                &missing,
                &Sequential,
            ));
        assert!(fixture
            .verifier
            .verify_certificates::<_, Sha256Digest, _, N3f1>(
                &mut rng,
                [(subject_a, &certificate_a), (subject_b, &certificate_b)].into_iter(),
                &Sequential,
            ));
        assert!(!fixture
            .verifier
            .verify_certificates::<_, Sha256Digest, _, N3f1>(
                &mut rng,
                [(subject_a, &certificate_a), (subject_b, &missing)].into_iter(),
                &Sequential,
            ));
    }

    #[test]
    #[should_panic(expected = "invalid mock certificate request")]
    fn strict_invalid_requests_panic() {
        let mut rng = test_rng();
        let fixture = fixture_with::<true, false, false, _>(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject { message: b"vote-1" };
        let attestation = fixture.schemes[0]
            .sign::<Sha256Digest>(subject)
            .expect("signer must produce an attestation");

        let _ = fixture.verifier.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            TestSubject { message: b"vote-2" },
            &attestation,
            &Sequential,
        );
    }

    #[test]
    #[should_panic(expected = "invalid mock certificate request")]
    fn strict_invalid_assembly_requests_panic() {
        let mut rng = test_rng();
        let fixture = fixture_with::<true, true, false, _>(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject { message: b"vote-1" };

        let _ = fixture.verifier.assemble::<_, N3f1>(
            [
                fixture.schemes[0].sign::<Sha256Digest>(subject).unwrap(),
                fixture.schemes[1]
                    .sign::<Sha256Digest>(TestSubject { message: b"vote-2" })
                    .unwrap(),
                fixture.schemes[2].sign::<Sha256Digest>(subject).unwrap(),
            ],
            &Sequential,
        );
    }
}
