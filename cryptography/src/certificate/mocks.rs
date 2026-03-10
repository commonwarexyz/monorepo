//! Mocks for certificate signing schemes.

use super::{Attestation, Scheme, Signers, Subject, Verification};
use crate::{
    ed25519::{PrivateKey, PublicKey as Ed25519PublicKey},
    Digest, PublicKey,
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error as CodecError, Read, Write};
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredCertificate {
    subject: SignedSubject,
    signers: Signers,
}

#[derive(Debug, Default)]
struct Ledger {
    next_signature: u64,
    signatures: HashMap<Participant, HashMap<u64, SignedSubject>>,
    next_certificate: u64,
    certificates: HashMap<u64, StoredCertificate>,
}

/// Shared state for ledger-backed mock schemes created by the same test fixture.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct SharedLedger(Arc<Mutex<Ledger>>);

/// Cheap certificate type backed by a shared in-memory ledger.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate {
    id: U64,
    signers: Signers,
}

impl Write for Certificate {
    fn write(&self, writer: &mut impl BufMut) {
        self.id.write(writer);
        self.signers.write(writer);
    }
}

impl EncodeSize for Certificate {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.signers.encode_size()
    }
}

impl Read for Certificate {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_participants: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            id: U64::read_cfg(reader, &())?,
            signers: Signers::read_cfg(reader, max_participants)?,
        })
    }
}

/// Generic ledger-backed certificate implementation.
///
/// Signatures and certificates are cheap synthetic IDs. Verification succeeds only
/// if the corresponding subject was previously recorded in the shared ledger.
#[doc(hidden)]
pub struct Generic<
    P: PublicKey,
    N: super::Namespace,
    const ATTRIBUTABLE: bool = true,
    const BATCHABLE: bool = false,
    const ALLOW_INVALID: bool = true,
> {
    me: Option<Participant>,
    participants: Set<P>,
    namespace: N,
    ledger: SharedLedger,
}

impl<
        P: PublicKey,
        N: super::Namespace,
        const ATTRIBUTABLE: bool,
        const BATCHABLE: bool,
        const ALLOW_INVALID: bool,
    > fmt::Debug for Generic<P, N, ATTRIBUTABLE, BATCHABLE, ALLOW_INVALID>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Generic")
            .field("me", &self.me)
            .field("participants", &self.participants)
            .finish_non_exhaustive()
    }
}

impl<
        P: PublicKey,
        N: super::Namespace,
        const ATTRIBUTABLE: bool,
        const BATCHABLE: bool,
        const ALLOW_INVALID: bool,
    > Clone for Generic<P, N, ATTRIBUTABLE, BATCHABLE, ALLOW_INVALID>
{
    fn clone(&self) -> Self {
        Self {
            me: self.me,
            participants: self.participants.clone(),
            namespace: self.namespace.clone(),
            ledger: self.ledger.clone(),
        }
    }
}

impl<
        P: PublicKey,
        N: super::Namespace,
        const ATTRIBUTABLE: bool,
        const BATCHABLE: bool,
        const ALLOW_INVALID: bool,
    > Generic<P, N, ATTRIBUTABLE, BATCHABLE, ALLOW_INVALID>
{
    fn invalid_none<T>(reason: &str) -> Option<T> {
        if ALLOW_INVALID {
            None
        } else {
            panic!("invalid mock certificate request: {reason}");
        }
    }

    fn invalid_bool(reason: &str) -> bool {
        if ALLOW_INVALID {
            false
        } else {
            panic!("invalid mock certificate request: {reason}");
        }
    }

    /// Creates a signer bound to the provided participant index.
    pub fn signer(
        namespace: &[u8],
        participants: Set<P>,
        me: Participant,
        ledger: SharedLedger,
    ) -> Option<Self> {
        participants.key(me)?;
        Some(Self {
            me: Some(me),
            participants,
            namespace: N::derive(namespace),
            ledger,
        })
    }

    /// Creates a verifier sharing the provided ledger state.
    pub fn verifier(namespace: &[u8], participants: Set<P>, ledger: SharedLedger) -> Self {
        Self {
            me: None,
            participants,
            namespace: N::derive(namespace),
            ledger,
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
    pub fn sign<'a, S, D>(&self, subject: S::Subject<'a, D>) -> Option<Attestation<S>>
    where
        S: Scheme<Signature = U64>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        let signer = self.me?;
        let signed_subject = SignedSubject::new(subject, &self.namespace);

        let mut ledger = self.ledger.0.lock();
        let signature_id = ledger.next_signature;
        ledger.next_signature = ledger.next_signature.wrapping_add(1);
        ledger
            .signatures
            .entry(signer)
            .or_default()
            .insert(signature_id, signed_subject);

        Some(Attestation {
            signer,
            signature: U64::new(signature_id).into(),
        })
    }

    /// Verifies a single ledger-backed attestation.
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
            return Self::invalid_bool("attestation signer missing from participant set");
        }

        let Some(signature) = attestation.signature.get() else {
            return Self::invalid_bool("attestation signature missing");
        };
        let expected_subject = SignedSubject::new(subject, &self.namespace);
        let signature_id = u64::from(signature);
        let ledger = self.ledger.0.lock();
        ledger
            .signatures
            .get(&attestation.signer)
            .and_then(|entries| entries.get(&signature_id))
            .is_some_and(|stored| stored == &expected_subject)
            || Self::invalid_bool("attestation not recorded in ledger or subject mismatched")
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

    /// Assembles attestations into a ledger-backed certificate.
    pub fn assemble<S, I, M>(&self, attestations: I) -> Option<Certificate>
    where
        S: Scheme<Signature = U64>,
        I: IntoIterator<Item = Attestation<S>>,
        M: Faults,
    {
        let mut unique_signers = HashSet::new();
        let mut signers = Vec::new();
        let mut signed_subject = None;
        let mut ledger = self.ledger.0.lock();

        for attestation in attestations {
            self.participants
                .key(attestation.signer)
                .or_else(|| Self::invalid_none("attestation signer missing from participant set"))?;

            let signature = attestation
                .signature
                .get()
                .or_else(|| Self::invalid_none("attestation signature missing"))?;
            let signature_id = u64::from(signature);
            let entry = ledger
                .signatures
                .get(&attestation.signer)
                .or_else(|| Self::invalid_none("attestation signer missing from ledger"))?
                .get(&signature_id)
                .or_else(|| Self::invalid_none("attestation signature missing from ledger"))?
                .clone();

            if let Some(existing) = &signed_subject {
                if existing != &entry {
                    return Self::invalid_none("attestations signed different subjects");
                }
            } else {
                signed_subject = Some(entry);
            }

            if unique_signers.insert(attestation.signer) {
                signers.push(attestation.signer);
            }
        }

        if signers.len() < self.participants.quorum::<M>() as usize {
            return None;
        }

        let subject = signed_subject?;
        let signers = Signers::from(self.participants.len(), signers);
        let certificate_id = ledger.next_certificate;
        ledger.next_certificate = ledger.next_certificate.wrapping_add(1);
        ledger.certificates.insert(
            certificate_id,
            StoredCertificate {
                subject,
                signers: signers.clone(),
            },
        );

        Some(Certificate {
            id: U64::new(certificate_id),
            signers,
        })
    }

    /// Verifies a ledger-backed certificate.
    pub fn verify_certificate<'a, S, R, D, M>(
        &self,
        _rng: &mut R,
        subject: S::Subject<'a, D>,
        certificate: &Certificate,
    ) -> bool
    where
        S: Scheme<Certificate = Certificate>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: CryptoRngCore,
        D: Digest,
        M: Faults,
    {
        if certificate.signers.len() != self.participants.len() {
            return Self::invalid_bool("certificate signer set length mismatched participant set");
        }
        if certificate.signers.count() < self.participants.quorum::<M>() as usize {
            return Self::invalid_bool("certificate below quorum");
        }

        let expected_subject = SignedSubject::new(subject, &self.namespace);
        let certificate_id = u64::from(&certificate.id);
        let ledger = self.ledger.0.lock();
        ledger
            .certificates
            .get(&certificate_id)
            .is_some_and(|stored| {
                stored.subject == expected_subject && stored.signers == certificate.signers
            })
            || Self::invalid_bool("certificate missing from ledger or subject/signers mismatched")
    }

    /// Verifies a batch of certificates one-by-one.
    pub fn verify_certificates<'a, S, R, D, I, M>(
        &self,
        rng: &mut R,
        mut certificates: I,
    ) -> bool
    where
        S: Scheme<Certificate = Certificate>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        R: rand::Rng + rand::CryptoRng,
        D: Digest,
        I: Iterator<Item = (S::Subject<'a, D>, &'a Certificate)>,
        M: Faults,
    {
        certificates
            .all(|(subject, certificate)| self.verify_certificate::<S, _, D, M>(rng, subject, certificate))
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
    pub const fn certificate_codec_config(&self) -> usize {
        self.participants.len()
    }

    /// Returns the unbounded codec configuration.
    pub const fn certificate_codec_config_unbounded() -> usize {
        usize::MAX
    }
}

/// Implements a ledger-backed mock certificate scheme for a concrete subject and namespace.
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
        /// Generates a test fixture with Ed25519 identities and a ledger-backed mock scheme.
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
            fixture_with::<true, false, true, R>(rng, namespace, n)
        }

        /// Generates a test fixture with explicit mock certificate behavior flags.
        #[cfg(feature = "mocks")]
        #[allow(dead_code)]
        pub fn fixture_with<const ATTRIBUTABLE: bool, const BATCHABLE: bool, const ALLOW_INVALID: bool, R>(
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

            let ledger = $crate::certificate::mocks::SharedLedger::default();
            let schemes = participants_vec
                .iter()
                .enumerate()
                .map(|(idx, _)| {
                    Scheme::signer(
                        namespace,
                        participants.clone(),
                        commonware_utils::Participant::new(idx as u32),
                        ledger.clone(),
                    )
                    .expect("scheme signer must be a participant")
                })
                .collect();
            let verifier = Scheme::verifier(namespace, participants, ledger);

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
            const BATCHABLE: bool = false,
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
                ledger: $crate::certificate::mocks::SharedLedger,
            ) -> Option<Self> {
                Some(Self {
                    generic: $crate::certificate::mocks::Generic::signer(
                        namespace,
                        participants,
                        me,
                        ledger,
                    )?,
                })
            }

            pub fn verifier(
                namespace: &[u8],
                participants: commonware_utils::ordered::Set<P>,
                ledger: $crate::certificate::mocks::SharedLedger,
            ) -> Self {
                Self {
                    generic: $crate::certificate::mocks::Generic::verifier(
                        namespace,
                        participants,
                        ledger,
                    ),
                }
            }
        }

        impl<
                P: $crate::PublicKey,
                const ATTRIBUTABLE: bool,
                const BATCHABLE: bool,
                const ALLOW_INVALID: bool,
            > $crate::certificate::Scheme
            for Scheme<P, ATTRIBUTABLE, BATCHABLE, ALLOW_INVALID>
        {
            type Subject<'a, D: $crate::Digest> = $subject;
            type PublicKey = P;
            type Signature = commonware_utils::sequence::U64;
            type Certificate = $crate::certificate::mocks::Certificate;

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
                self.generic.verify_attestation::<Self, D>(subject, attestation)
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
    use super::Certificate;
    use crate::{
        certificate::Scheme as _, ed25519::PublicKey as Ed25519PublicKey,
        sha256::Digest as Sha256Digest,
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, Encode};
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, N3f1};

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
    fn configurable_properties_follow_type_flags() {
        assert!(Scheme::<Ed25519PublicKey>::is_attributable());
        assert!(!Scheme::<Ed25519PublicKey>::is_batchable());

        assert!(!Scheme::<Ed25519PublicKey, false, true>::is_attributable());
        assert!(Scheme::<Ed25519PublicKey, false, true>::is_batchable());
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
        let certificate = fixture.verifier.assemble::<_, N3f1>(attestations, &Sequential).unwrap();
        let encoded = certificate.encode();
        let decoded =
            Certificate::decode_cfg(encoded, &fixture.verifier.participants().len()).unwrap();

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
        assert!(
            !fixture
                .verifier
                .verify_certificate::<_, Sha256Digest, N3f1>(
                    &mut rng,
                    TestSubject {
                        message: b"other-subject",
                    },
                    &decoded,
                    &Sequential,
                )
        );
    }

    #[test]
    fn certificate_decode_round_trip_uses_participant_bound() {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject { message: b"bound" };
        let attestations: Vec<_> = fixture.schemes[..3]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(subject).unwrap())
            .collect();
        let certificate = fixture.verifier.assemble::<_, N3f1>(attestations, &Sequential).unwrap();
        let encoded = certificate.encode();

        assert!(Certificate::decode_cfg(encoded.clone(), &4).is_ok());
        assert!(Certificate::decode_cfg(encoded, &2).is_err());
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
}
