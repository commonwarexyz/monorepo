//! FN-DSA certificate signing scheme.
//!
//! This module instantiates the [individually verified certificate scheme](individual) with
//! FN-DSA signing keys and provides a macro to generate protocol-specific wrappers. Like
//! Secp256r1 and ML-DSA, FN-DSA signatures are attributable and verified one at a time.
//!
//! See [crate::fn_dsa] for the experimental status of FN-DSA: certificate encodings may change
//! with the underlying signature encoding.

use crate::{certificate::individual, fn_dsa};

/// FN-DSA signing scheme parameterized by identity type, FN-DSA variant, and namespace type.
///
/// It can be reused across different protocols (simplex, aggregation, etc.) by wrapping it with
/// protocol-specific trait implementations via [crate::impl_certificate_fn_dsa].
pub type Generic<P, V, N> = individual::Generic<P, fn_dsa::PrivateKey<V>, N>;

/// Certificate containing the FN-DSA signatures of a quorum.
pub type Certificate<V> = individual::Certificate<fn_dsa::Signature<V>>;

/// Generates an FN-DSA signing scheme wrapper for a specific protocol.
///
/// This macro creates a complete wrapper struct, generic over the FN-DSA
/// [Variant](crate::fn_dsa::Variant), with constructors, `Scheme` trait implementation, and a
/// `fixture` function for testing.
///
/// # Parameters
///
/// - `$subject`: The subject type used as `Scheme::Subject<'a, D>`. Use `'a` and `D`
///   in the subject type to bind to the GAT lifetime and digest type parameters.
///
/// - `$namespace`: The namespace type that implements
///   [`Namespace`](crate::certificate::Namespace).
///   This type pre-computes and stores any protocol-specific namespace bytes derived from
///   a base namespace. The scheme calls `$namespace::derive(base)` at construction time
///   to create the namespace, then passes it to `Subject::namespace()` during signing
///   and verification. For simple protocols with only a base namespace, `Vec<u8>` can be used directly.
///   For protocols with multiple message types, a custom struct can pre-compute all variants.
///
/// - `$faults`: The [`Faults`](commonware_utils::Faults) implementation used to compute certificate
///   quorums.
///
/// # Example
/// ```ignore
/// // For non-generic subject types with a single namespace:
/// impl_certificate_fn_dsa!(MySubject, Vec<u8>, commonware_utils::N3f1);
///
/// // For protocols with generic subject types:
/// impl_certificate_fn_dsa!(
///     Subject<'a, D>,
///     Namespace,
///     commonware_utils::N3f1,
/// );
/// ```
#[macro_export]
macro_rules! impl_certificate_fn_dsa {
    ($subject:ty, $namespace:ty, $faults:ty) => {
        /// Generates a test fixture with Ed25519 identities and FN-DSA signing schemes.
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
            V: $crate::fn_dsa::Variant,
            R: rand_core::CryptoRng,
        {
            $crate::certificate::individual::mocks::fixture(
                rng,
                namespace,
                n,
                Scheme::signer,
                Scheme::verifier,
            )
        }

        /// FN-DSA signing scheme wrapper.
        #[derive(Clone, Debug)]
        pub struct Scheme<P: $crate::PublicKey, V: $crate::fn_dsa::Variant> {
            generic: $crate::fn_dsa::certificate::Generic<P, V, $namespace>,
        }

        impl<P: $crate::PublicKey, V: $crate::fn_dsa::Variant> Scheme<P, V> {
            /// Creates a new scheme instance with the provided key material.
            pub fn signer(
                namespace: &[u8],
                participants: commonware_utils::ordered::BiMap<P, $crate::fn_dsa::PublicKey<V>>,
                private_key: $crate::fn_dsa::PrivateKey<V>,
            ) -> Option<Self> {
                Some(Self {
                    generic: $crate::fn_dsa::certificate::Generic::signer(
                        namespace,
                        participants,
                        private_key,
                    )?,
                })
            }

            /// Builds a verifier that can authenticate signatures and certificates.
            pub fn verifier(
                namespace: &[u8],
                participants: commonware_utils::ordered::BiMap<P, $crate::fn_dsa::PublicKey<V>>,
            ) -> Self {
                Self {
                    generic: $crate::fn_dsa::certificate::Generic::verifier(
                        namespace,
                        participants,
                    ),
                }
            }
        }

        impl<P: $crate::PublicKey, V: $crate::fn_dsa::Variant> $crate::certificate::Verifier
            for Scheme<P, V>
        {
            type Subject<'a, D: $crate::Digest> = $subject;
            type Faults = $faults;
            type PublicKey = P;
            type Certificate = $crate::fn_dsa::certificate::Certificate<V>;

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
                self.generic.verify_certificate::<Self, _, D>(
                    rng,
                    subject,
                    certificate,
                )
            }

            fn verify_certificates<'a, R, D, I>(
                &self,
                rng: &mut R,
                certificates: commonware_utils::iter::NonEmpty<I>,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> bool
            where
                R: rand_core::CryptoRng,
                D: $crate::Digest,
                I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
            {
                for (subject, certificate) in certificates {
                    if !self.generic.verify_certificate::<Self, _, D>(rng, subject, certificate) {
                        return false;
                    }
                }
                true
            }

            fn is_batchable() -> bool {
                $crate::fn_dsa::certificate::Generic::<P, V, $namespace>::is_batchable()
            }

            fn certificate_codec_config(
                &self,
            ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                self.generic.certificate_codec_config()
            }

            fn certificate_codec_config_unbounded() -> <Self::Certificate as commonware_codec::Read>::Cfg {
                $crate::fn_dsa::certificate::Generic::<P, V, $namespace>::certificate_codec_config_unbounded()
            }
        }

        impl<P: $crate::PublicKey, V: $crate::fn_dsa::Variant> $crate::certificate::Scheme
            for Scheme<P, V>
        {
            type Signature = $crate::fn_dsa::Signature<V>;

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
                self.generic.sign::<_, D>(subject)
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
                    .verify_attestation::<_, D>(subject, attestation)
            }

            fn verify_attestations<R, D, I>(
                &self,
                rng: &mut R,
                subject: Self::Subject<'_, D>,
                attestations: I,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> $crate::certificate::Verification<Self>
            where
                R: rand_core::CryptoRng,
                D: $crate::Digest,
                I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
            {
                self.generic.verify_attestations::<_, _, D, _>(
                    rng,
                    subject,
                    attestations,
                )
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
                $crate::certificate::verify_then_assemble::<Self, _, D, _, _>(
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
                $crate::fn_dsa::certificate::Generic::<P, V, $namespace>::is_attributable()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Signer as _,
        certificate::{AssemblyError, Scheme as _, Signers, Subject, Verifier as _},
        fn_dsa::{PrivateKey, PublicKey, Variant},
        sha256::Digest as Sha256Digest,
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, Encode, FixedSize, types::lazy::Lazy};
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::{
        Faults, N3f1, Participant, TryCollect, non_empty, ordered::BiMap, test_rng,
    };
    use rand_core::CryptoRng;

    const NAMESPACE: &[u8] = b"test-fn-dsa";
    const MESSAGE: &[u8] = b"test message";

    /// Test context type for generic scheme tests.
    #[derive(Clone, Debug)]
    pub struct TestSubject {
        pub message: Bytes,
    }

    impl Subject for TestSubject {
        type Namespace = Vec<u8>;

        fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
            derived.as_ref()
        }

        fn message(&self) -> Bytes {
            self.message.clone()
        }
    }

    impl_certificate_fn_dsa!(TestSubject, Vec<u8>, N3f1);

    fn subject(message: &'static [u8]) -> TestSubject {
        TestSubject {
            message: Bytes::from_static(message),
        }
    }

    /// Scheme that uses FN-DSA keys as both identity and signing keys.
    type TestScheme<V> = Scheme<PublicKey<V>, V>;

    /// Returns signers sorted by participant index and a verifier.
    fn setup_signers<V: Variant>(
        rng: &mut impl CryptoRng,
        n: u32,
    ) -> (Vec<TestScheme<V>>, TestScheme<V>) {
        let private_keys: Vec<_> = (0..n)
            .map(|_| PrivateKey::<V>::random(&mut *rng))
            .collect();

        // Use FN-DSA keys as both identity and signing keys.
        let participants: BiMap<PublicKey<V>, PublicKey<V>> = private_keys
            .iter()
            .map(|sk| {
                let pk = sk.public_key();
                (pk.clone(), pk)
            })
            .try_collect()
            .unwrap();

        let mut signers: Vec<_> = private_keys
            .into_iter()
            .map(|sk| Scheme::signer(NAMESPACE, participants.clone(), sk).unwrap())
            .collect();
        signers.sort_by_key(|scheme| scheme.me());
        let verifier = Scheme::verifier(NAMESPACE, participants);

        (signers, verifier)
    }

    fn attest<P: crate::PublicKey, V: Variant>(
        schemes: &[Scheme<P, V>],
        message: &'static [u8],
    ) -> Vec<crate::certificate::Attestation<Scheme<P, V>>> {
        schemes
            .iter()
            .map(|s| s.sign::<Sha256Digest>(subject(message)).unwrap())
            .collect()
    }

    fn assemble<P: crate::PublicKey, V: Variant>(
        schemes: &[Scheme<P, V>],
        message: &'static [u8],
    ) -> Certificate<V> {
        let attestations = attest(schemes, message);
        schemes[0]
            .assemble(non_empty![@attestations], &Sequential)
            .unwrap()
    }

    fn properties<V: Variant>() {
        assert!(Scheme::<PublicKey<V>, V>::is_attributable());
        assert!(!Scheme::<PublicKey<V>, V>::is_batchable());
    }

    fn sign_and_verify_attestation<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);

        for (index, scheme) in schemes.iter().enumerate() {
            assert_eq!(scheme.me(), Some(Participant::from_usize(index)));
            let attestation = scheme.sign::<Sha256Digest>(subject(MESSAGE)).unwrap();
            assert_eq!(attestation.signer, Participant::from_usize(index));
            assert!(verifier.verify_attestation::<_, Sha256Digest>(
                &mut rng,
                subject(MESSAGE),
                &attestation,
                &Sequential,
            ));

            // The attestation does not verify for another subject.
            assert!(!verifier.verify_attestation::<_, Sha256Digest>(
                &mut rng,
                subject(b"other message"),
                &attestation,
                &Sequential,
            ));

            // The attestation does not verify when attributed to another participant.
            let mut misattributed = attestation;
            misattributed.signer = Participant::from_usize((index + 1) % schemes.len());
            assert!(!verifier.verify_attestation::<_, Sha256Digest>(
                &mut rng,
                subject(MESSAGE),
                &misattributed,
                &Sequential,
            ));
        }

        // A verifier cannot sign.
        assert!(verifier.me().is_none());
        assert!(verifier.sign::<Sha256Digest>(subject(MESSAGE)).is_none());
    }

    fn signer_requires_participant_key<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);
        let participants = schemes[0].generic.participants.clone();
        assert!(
            Scheme::signer(NAMESPACE, participants, PrivateKey::<V>::random(&mut rng)).is_none()
        );
    }

    fn verify_attestations_reports_invalid_signers<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 5);
        let mut attestations = attest(&schemes, MESSAGE);

        // Participant 1 signs a different subject.
        attestations[1] = schemes[1]
            .sign::<Sha256Digest>(subject(b"other message"))
            .unwrap();

        // Participant 2 provides a signature that does not decode.
        let mut truncated = Bytes::from_static(&[0u8]);
        attestations[2].signature = Lazy::deferred(&mut truncated, ());

        // An attestation from an unknown participant.
        let mut unknown = attestations[4].clone();
        unknown.signer = Participant::new(999);
        attestations.push(unknown);

        let verification = verifier.verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            subject(MESSAGE),
            attestations,
            &Sequential,
        );
        let verified: Vec<_> = verification.verified.iter().map(|a| a.signer).collect();
        assert_eq!(
            verified,
            vec![
                Participant::new(0),
                Participant::new(3),
                Participant::new(4)
            ]
        );
        assert_eq!(
            verification.invalid,
            vec![
                Participant::new(1),
                Participant::new(2),
                Participant::new(999)
            ]
        );
    }

    fn assemble_and_verify_certificate<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len()) as usize;

        // Attestations are assembled in signer order regardless of arrival order.
        let mut attestations = attest(&schemes[..quorum], MESSAGE);
        attestations.reverse();
        let certificate = schemes[0]
            .assemble(non_empty![@attestations], &Sequential)
            .unwrap();
        let signers: Vec<_> = certificate.signers.iter().collect();
        assert_eq!(
            signers,
            (0..quorum).map(Participant::from_usize).collect::<Vec<_>>()
        );

        assert!(verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject(MESSAGE),
            &certificate,
            &Sequential,
        ));
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject(b"other message"),
            &certificate,
            &Sequential,
        ));

        // Swapping signatures between signers invalidates the certificate.
        let mut swapped = certificate.clone();
        swapped.signatures.swap(0, 1);
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject(MESSAGE),
            &swapped,
            &Sequential,
        ));

        // Certificates over different subjects verify together, and one bad certificate fails all.
        let other = assemble(&schemes, b"other message");
        assert!(verifier.verify_certificates::<_, Sha256Digest, _>(
            &mut rng,
            non_empty![
                (subject(MESSAGE), &certificate),
                (subject(b"other message"), &other)
            ],
            &Sequential,
        ));
        assert!(!verifier.verify_certificates::<_, Sha256Digest, _>(
            &mut rng,
            non_empty![
                (subject(MESSAGE), &certificate),
                (subject(b"other message"), &swapped)
            ],
            &Sequential,
        ));
    }

    fn assemble_rejects_invalid_attestations<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<V>(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len());

        // Below quorum.
        let attestations = attest(&schemes[..quorum as usize - 1], MESSAGE);
        assert_eq!(
            schemes[0].assemble(non_empty![@attestations], &Sequential),
            Err(AssemblyError::InsufficientAttestations(quorum, quorum - 1))
        );

        // Unknown signer.
        let mut attestations = attest(&schemes[..quorum as usize], MESSAGE);
        attestations[0].signer = Participant::new(999);
        assert_eq!(
            schemes[0].assemble(non_empty![@attestations], &Sequential),
            Err(AssemblyError::UnknownSigner(Participant::new(999)))
        );

        // Duplicate signer.
        let mut attestations = attest(&schemes[..quorum as usize], MESSAGE);
        let duplicate = attestations[0].clone();
        attestations.push(duplicate);
        assert_eq!(
            schemes[0].assemble(non_empty![@attestations], &Sequential),
            Err(AssemblyError::DuplicateSigner(Participant::new(0)))
        );

        // Malformed signature.
        let mut attestations = attest(&schemes[..quorum as usize], MESSAGE);
        let mut truncated = Bytes::from_static(&[0u8]);
        attestations[1].signature = Lazy::deferred(&mut truncated, ());
        assert_eq!(
            schemes[0].assemble(non_empty![@attestations], &Sequential),
            Err(AssemblyError::MalformedSignature(Participant::new(1)))
        );
    }

    fn verify_certificate_rejects_invalid_shape<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let participants = schemes.len();
        let certificate = assemble(&schemes[..3], MESSAGE);

        // Below quorum.
        let mut sub_quorum = certificate.clone();
        sub_quorum.signers = Signers::new(
            participants as u32,
            [Participant::new(0), Participant::new(1)],
        )
        .unwrap();
        sub_quorum.signatures.pop();
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject(MESSAGE),
            &sub_quorum,
            &Sequential,
        ));

        // Signer and signature counts differ.
        let mut mismatched = certificate.clone();
        mismatched.signatures.pop();
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject(MESSAGE),
            &mismatched,
            &Sequential,
        ));

        // Signer bitmap sized for a different participant set.
        let mut resized = certificate.clone();
        resized.signers =
            Signers::new(participants as u32 + 1, certificate.signers.iter()).unwrap();
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject(MESSAGE),
            &resized,
            &Sequential,
        ));
    }

    fn certificate_codec<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let participants = schemes.len();
        let participant_count = participants as u32;
        let certificate = assemble(&schemes[..3], MESSAGE);

        // Roundtrip with the bound derived from the participant set.
        let encoded = certificate.encode();
        let decoded =
            Certificate::<V>::decode_cfg(encoded.clone(), &verifier.certificate_codec_config())
                .unwrap();
        assert_eq!(decoded, certificate);
        assert!(verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject(MESSAGE),
            &decoded,
            &Sequential,
        ));

        // A certificate encoded for more participants exceeds the bound.
        assert!(Certificate::<V>::decode_cfg(encoded, &(participants - 1)).is_err());

        // No signers.
        let empty = Certificate::<V> {
            signers: Signers::new(participant_count, core::iter::empty::<Participant>()).unwrap(),
            signatures: Vec::new(),
        };
        assert!(Certificate::<V>::decode_cfg(empty.encode(), &participants).is_err());

        // Signer and signature counts differ.
        let mismatched = Certificate::<V> {
            signers: Signers::new(
                participant_count,
                [Participant::new(0), Participant::new(1)],
            )
            .unwrap(),
            signatures: vec![certificate.signatures[0].clone()],
        };
        assert!(Certificate::<V>::decode_cfg(mismatched.encode(), &participants).is_err());
    }

    fn certificate_with_malformed_signature<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(&mut rng, 4);
        let certificate = assemble(&schemes[..3], MESSAGE);

        // Corrupt the header byte of the last signature so that it no longer decodes.
        let mut encoded = certificate.encode().to_vec();
        let header = encoded.len() - fn_dsa::Signature::<V>::SIZE;
        encoded[header] ^= 0xFF;

        // Signatures are decoded lazily, so the certificate itself decodes.
        let decoded = Certificate::<V>::decode_cfg(Bytes::from(encoded), &schemes.len()).unwrap();
        assert!(decoded.signatures[2].get().is_none());
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject(MESSAGE),
            &decoded,
            &Sequential,
        ));
    }

    #[cfg(feature = "mocks")]
    fn fixture_verifies<V: Variant>() {
        let mut rng = test_rng();
        let fixture = fixture::<V, _>(&mut rng, NAMESPACE, 4);
        let certificate = assemble(&fixture.schemes[..3], MESSAGE);
        assert!(fixture.verifier.verify_certificate::<_, Sha256Digest>(
            &mut rng,
            subject(MESSAGE),
            &certificate,
            &Sequential,
        ));
    }

    crate::fn_dsa::variant_tests!(
        properties,
        sign_and_verify_attestation,
        signer_requires_participant_key,
        verify_attestations_reports_invalid_signers,
        assemble_and_verify_certificate,
        assemble_rejects_invalid_attestations,
        verify_certificate_rejects_invalid_shape,
        certificate_codec,
        certificate_with_malformed_signature,
        #[cfg(feature = "mocks")]
        fixture_verifies,
    );

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::fn_dsa::{FnDsa512, FnDsa1024};
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Certificate<FnDsa512>> => 1024,
            CodecConformance<Certificate<FnDsa1024>> => 1024,
        }
    }
}
