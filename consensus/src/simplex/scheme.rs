//! Signing scheme implementations for `simplex`.
//!
//! # Attributable Schemes and Liveness/Fault Evidence
//!
//! Signing schemes differ in whether per-validator activities can be used as evidence of either
//! liveness or of committing a fault:
//!
//! - **Attributable Schemes** ([`ed25519`], [`bls12381_multisig`]): Individual signatures can be presented
//!   to some third party as evidence of either liveness or of committing a fault. Certificates contain signer
//!   indices alongside individual signatures, enabling secure per-validator activity tracking and
//!   conflict detection.
//!
//! - **Non-Attributable schemes** ([`bls12381_threshold`]): Individual signatures cannot be presented
//!   to some third party as evidence of either liveness or of committing a fault because they can be forged
//!   by other players (often after some quorum of partial signatures are collected). With [`bls12381_threshold`],
//!   possession of any `t` valid partial signatures can be used to forge a partial signature for any other player.
//!   Because peer connections are authenticated, evidence can be used locally (as it must be sent by said participant)
//!   but can't be used by an external observer.
//!
//! The [`Scheme::is_attributable()`] method signals whether evidence can be safely
//! exposed. For applications only interested in collecting evidence for liveness/faults, use [`reporter::AttributableReporter`]
//! which automatically handles filtering and verification based on scheme (hiding votes/proofs that are not attributable). If
//! full observability is desired, process all messages passed through the [`crate::Reporter`] interface.

pub mod bls12381_multisig {
    //! BLS12-381 multi-signature implementation of the [`Scheme`] trait for `simplex`.
    //!
    //! [`Scheme`] is **attributable**: individual signatures can be
    //! used by an external observer as evidence of either liveness or of committing a fault.
    //! Certificates contain signer indices alongside an aggregated signature,
    //! enabling secure per-validator activity tracking and conflict detection.

    use crate::{
        simplex::{scheme::SeededScheme, types::Subject},
        types::Round,
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::Variant, impl_bls12381_multisig_certificate, PublicKey,
    };

    impl_bls12381_multisig_certificate!(Subject<'a, D>);

    impl<P: PublicKey, V: Variant + Send + Sync> SeededScheme for Scheme<P, V> {
        type Seed = ();

        fn seed(&self, _: Round, _: &Self::Certificate) -> Option<Self::Seed> {
            None
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::{
            simplex::{
                scheme::{bls12381_multisig, SeededScheme},
                types::Subject,
            },
            types::{Epoch, Round, View},
        };
        use commonware_cryptography::{
            bls12381::primitives::variant::{MinPk, MinSig, Variant},
            certificate::{mocks::Fixture, Scheme as _},
            sha256::Digest as Sha256Digest,
        };
        use commonware_utils::quorum_from_slice;
        use rand::{rngs::StdRng, SeedableRng};

        fn test_seed_returns_none<V: Variant + Send + Sync>() {
            let mut rng = StdRng::seed_from_u64(42);
            let Fixture { schemes, .. } = bls12381_multisig::fixture::<V, _>(&mut rng, 4);

            let quorum = quorum_from_slice(&schemes) as usize;

            // Create a certificate for testing
            let signatures: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|s| {
                    s.sign_vote::<Sha256Digest>(
                        b"test",
                        Subject::Nullify {
                            round: Round::new(Epoch::new(1), View::new(1)),
                        },
                    )
                    .unwrap()
                })
                .collect();

            let certificate = schemes[0].assemble_certificate(signatures).unwrap();

            let round = Round::new(Epoch::new(1), View::new(1));
            assert!(schemes[0].seed(round, &certificate).is_none());
        }

        #[test]
        fn test_seed_returns_none_variants() {
            test_seed_returns_none::<MinPk>();
            test_seed_returns_none::<MinSig>();
        }
    }
}

pub mod bls12381_threshold {
    //! BLS12-381 threshold implementation of the [`Scheme`] trait for `simplex`.
    //!
    //! [`Scheme`] is **non-attributable**: exposing partial signatures
    //! as evidence of either liveness or of committing a fault is not safe. With threshold signatures,
    //! any `t` valid partial signatures can be used to forge a partial signature for any other player,
    //! enabling equivocation attacks. Because peer connections are authenticated, evidence can be used locally
    //! (as it must be sent by said participant) but can't be used by an external observer.

    use crate::{
        simplex::{
            scheme::{
                finalize_namespace, notarize_namespace, nullify_namespace, seed_namespace,
                seed_namespace_and_message, vote_namespace_and_message, SeededScheme,
            },
            types::{Finalization, Notarization, Subject},
        },
        types::{Epoch, Round, View},
        Epochable, Viewable,
    };
    use bytes::{Buf, BufMut};
    use commonware_codec::{Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write};
    use commonware_cryptography::{
        bls12381::{
            primitives::{
                group::Share,
                ops::{
                    aggregate_signatures, aggregate_verify_multiple_messages, partial_sign_message,
                    partial_verify_multiple_public_keys, threshold_signature_recover_pair,
                    verify_message,
                },
                sharing::Sharing,
                variant::{PartialSignature, Variant},
            },
            tle,
        },
        certificate::{
            Scheme as SchemeTrait, Signature as CertificateSignature, SignatureVerification,
        },
        Digest, PublicKey,
    };
    use commonware_utils::ordered::Set;
    use rand::{CryptoRng, Rng};
    use std::{
        collections::{BTreeSet, HashMap},
        fmt::Debug,
    };

    /// BLS12-381 threshold implementation of the [`Scheme`] trait.
    ///
    /// It is possible for a node to play one of the following roles: a signer (with its share),
    /// a verifier (with evaluated public polynomial), or an external verifier that
    /// only checks recovered certificates.
    #[derive(Clone, Debug)]
    pub enum Scheme<P: PublicKey, V: Variant> {
        Signer {
            /// Participants in the committee.
            participants: Set<P>,
            /// The public polynomial, used for the group identity, and partial signatures.
            polynomial: Sharing<V>,
            /// Local share used to generate partial signatures.
            share: Share,
        },
        Verifier {
            /// Participants in the committee.
            participants: Set<P>,
            /// The public polynomial, used for the group identity, and partial signatures.
            polynomial: Sharing<V>,
        },
        CertificateVerifier {
            /// Public identity of the committee (constant across reshares).
            identity: V::Public,
        },
    }

    impl<P: PublicKey, V: Variant> Scheme<P, V> {
        /// Constructs a signer instance with a private share and evaluated public polynomial.
        ///
        /// The participant identity keys are used for committee ordering and indexing.
        /// The polynomial can be evaluated to obtain public verification keys for partial
        /// signatures produced by committee members.
        ///
        /// Returns `None` if the share's public key does not match any participant.
        ///
        /// * `participants` - ordered set of participant identity keys
        /// * `polynomial` - public polynomial for threshold verification
        /// * `share` - local threshold share for signing
        pub fn signer(participants: Set<P>, polynomial: Sharing<V>, share: Share) -> Option<Self> {
            assert_eq!(
                polynomial.total().get() as usize,
                participants.len(),
                "polynomial total must equal participant len"
            );
            polynomial.precompute_partial_publics();
            let partial_public = polynomial
                .partial_public(share.index)
                .expect("share index must match participant indices");
            if partial_public == share.public::<V>() {
                Some(Self::Signer {
                    participants,
                    polynomial,
                    share,
                })
            } else {
                None
            }
        }

        /// Produces a verifier that can authenticate votes but does not hold signing state.
        ///
        /// The participant identity keys are used for committee ordering and indexing.
        /// The polynomial can be evaluated to obtain public verification keys for partial
        /// signatures produced by committee members.
        ///
        /// * `participants` - ordered set of participant identity keys
        /// * `polynomial` - public polynomial for threshold verification
        pub fn verifier(participants: Set<P>, polynomial: Sharing<V>) -> Self {
            assert_eq!(
                polynomial.total().get() as usize,
                participants.len(),
                "polynomial total must equal participant len"
            );
            polynomial.precompute_partial_publics();

            Self::Verifier {
                participants,
                polynomial,
            }
        }

        /// Creates a verifier that only checks recovered certificates.
        ///
        /// This lightweight verifier can authenticate recovered threshold certificates but cannot
        /// verify individual votes or partial signatures.
        ///
        /// * `identity` - public identity of the committee (constant across reshares)
        pub const fn certificate_verifier(identity: V::Public) -> Self {
            Self::CertificateVerifier { identity }
        }

        /// Returns the ordered set of participant public identity keys in the committee.
        pub fn participants(&self) -> &Set<P> {
            match self {
                Self::Signer { participants, .. } => participants,
                Self::Verifier { participants, .. } => participants,
                _ => panic!("can only be called for signer and verifier"),
            }
        }

        /// Returns the public identity of the committee (constant across reshares).
        pub fn identity(&self) -> &V::Public {
            match self {
                Self::Signer { polynomial, .. } => polynomial.public(),
                Self::Verifier { polynomial, .. } => polynomial.public(),
                Self::CertificateVerifier { identity, .. } => identity,
            }
        }

        /// Returns the local share if this instance can generate partial signatures.
        pub const fn share(&self) -> Option<&Share> {
            match self {
                Self::Signer { share, .. } => Some(share),
                _ => None,
            }
        }

        /// Returns the evaluated public polynomial for validating partial signatures produced by committee members.
        pub fn polynomial(&self) -> &Sharing<V> {
            match self {
                Self::Signer { polynomial, .. } => polynomial,
                Self::Verifier { polynomial, .. } => polynomial,
                _ => panic!("can only be called for signer and verifier"),
            }
        }

        /// Encrypts a message for a target round using Timelock Encryption ([TLE](tle)).
        ///
        /// The encrypted message can only be decrypted using the seed signature
        /// from a certificate of the target round (i.e. notarization, finalization,
        /// or nullification).
        pub fn encrypt<R: Rng + CryptoRng>(
            &self,
            rng: &mut R,
            namespace: &[u8],
            target: Round,
            message: impl Into<tle::Block>,
        ) -> tle::Ciphertext<V> {
            encrypt(rng, *self.identity(), namespace, target, message)
        }
    }

    /// Encrypts a message for a future round using Timelock Encryption ([TLE](tle)).
    ///
    /// The encrypted message can only be decrypted using the seed signature
    /// from a certificate of the target round (i.e. notarization, finalization,
    /// or nullification).
    pub fn encrypt<R: Rng + CryptoRng, V: Variant>(
        rng: &mut R,
        identity: V::Public,
        namespace: &[u8],
        target: Round,
        message: impl Into<tle::Block>,
    ) -> tle::Ciphertext<V> {
        let block = message.into();
        let seed_ns = seed_namespace(namespace);
        let target_message = target.encode();
        tle::encrypt(rng, identity, (Some(&seed_ns), &target_message), &block)
    }

    /// Generates a test fixture with Ed25519 identities and BLS12-381 threshold schemes.
    ///
    /// Returns a [`commonware_cryptography::certificate::mocks::Fixture`] whose keys and
    /// scheme instances share a consistent ordering.
    #[cfg(feature = "mocks")]
    pub fn fixture<V, R>(
        rng: &mut R,
        n: u32,
    ) -> commonware_cryptography::certificate::mocks::Fixture<
        Scheme<commonware_cryptography::ed25519::PublicKey, V>,
    >
    where
        V: Variant,
        R: rand::RngCore + rand::CryptoRng,
    {
        commonware_cryptography::bls12381::certificate::threshold::mocks::fixture::<_, V, _>(
            rng,
            n,
            Scheme::signer,
            Scheme::verifier,
        )
    }

    /// Combined vote/seed signature pair emitted by the BLS12-381 threshold scheme.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct Signature<V: Variant> {
        /// Signature over the consensus vote message (partial or recovered aggregate).
        pub vote_signature: V::Signature,
        /// Signature over the per-view seed (partial or recovered aggregate).
        pub seed_signature: V::Signature,
    }

    impl<V: Variant> Write for Signature<V> {
        fn write(&self, writer: &mut impl BufMut) {
            self.vote_signature.write(writer);
            self.seed_signature.write(writer);
        }
    }

    impl<V: Variant> Read for Signature<V> {
        type Cfg = ();

        fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
            let vote_signature = V::Signature::read(reader)?;
            let seed_signature = V::Signature::read(reader)?;

            Ok(Self {
                vote_signature,
                seed_signature,
            })
        }
    }

    impl<V: Variant> FixedSize for Signature<V> {
        const SIZE: usize = V::Signature::SIZE * 2;
    }

    #[cfg(feature = "arbitrary")]
    impl<V: Variant> arbitrary::Arbitrary<'_> for Signature<V>
    where
        V::Signature: for<'a> arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
            Ok(Self {
                vote_signature: u.arbitrary()?,
                seed_signature: u.arbitrary()?,
            })
        }
    }

    /// Seed represents a threshold signature over the current view.
    #[derive(Clone, Debug, PartialEq, Hash, Eq)]
    pub struct Seed<V: Variant> {
        /// The round for which this seed is generated
        pub round: Round,
        /// The threshold signature on the seed.
        pub signature: V::Signature,
    }

    impl<V: Variant> Seed<V> {
        /// Creates a new seed with the given view and signature.
        pub const fn new(round: Round, signature: V::Signature) -> Self {
            Self { round, signature }
        }

        /// Verifies the threshold signature on this [Seed].
        pub fn verify<P: PublicKey>(&self, scheme: &Scheme<P, V>, namespace: &[u8]) -> bool {
            let seed_namespace = seed_namespace(namespace);
            let seed_message = self.round.encode();

            verify_message::<V>(
                scheme.identity(),
                Some(&seed_namespace),
                &seed_message,
                &self.signature,
            )
            .is_ok()
        }

        /// Returns the round associated with this seed.
        pub const fn round(&self) -> Round {
            self.round
        }

        /// Decrypts a [TLE](tle) ciphertext using this seed.
        ///
        /// Returns `None` if the ciphertext is invalid or encrypted for a different
        /// round than this seed.
        pub fn decrypt(&self, ciphertext: &tle::Ciphertext<V>) -> Option<tle::Block> {
            decrypt(self, ciphertext)
        }
    }

    /// Decrypts a [TLE](tle) ciphertext using the seed from a certificate (i.e.
    /// notarization, finalization, or nullification).
    ///
    /// Returns `None` if the ciphertext is invalid or encrypted for a different
    /// round than the given seed.
    pub fn decrypt<V: Variant>(
        seed: &Seed<V>,
        ciphertext: &tle::Ciphertext<V>,
    ) -> Option<tle::Block> {
        tle::decrypt(&seed.signature, ciphertext)
    }

    impl<V: Variant> Epochable for Seed<V> {
        fn epoch(&self) -> Epoch {
            self.round.epoch()
        }
    }

    impl<V: Variant> Viewable for Seed<V> {
        fn view(&self) -> View {
            self.round.view()
        }
    }

    impl<V: Variant> Write for Seed<V> {
        fn write(&self, writer: &mut impl BufMut) {
            self.round.write(writer);
            self.signature.write(writer);
        }
    }

    impl<V: Variant> Read for Seed<V> {
        type Cfg = ();

        fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
            let round = Round::read(reader)?;
            let signature = V::Signature::read(reader)?;

            Ok(Self { round, signature })
        }
    }

    impl<V: Variant> EncodeSize for Seed<V> {
        fn encode_size(&self) -> usize {
            self.round.encode_size() + self.signature.encode_size()
        }
    }

    #[cfg(feature = "arbitrary")]
    impl<V: Variant> arbitrary::Arbitrary<'_> for Seed<V>
    where
        V::Signature: for<'a> arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
            Ok(Self {
                round: u.arbitrary()?,
                signature: u.arbitrary()?,
            })
        }
    }

    /// Seedable is a trait that provides access to the seed associated with a message.
    pub trait Seedable<V: Variant> {
        /// Returns the seed associated with this object.
        fn seed(&self) -> Seed<V>;
    }

    impl<P: PublicKey, V: Variant, D: Digest> Seedable<V> for Notarization<Scheme<P, V>, D> {
        fn seed(&self) -> Seed<V> {
            Seed::new(self.proposal.round, self.certificate.seed_signature)
        }
    }

    impl<P: PublicKey, V: Variant, D: Digest> Seedable<V> for Finalization<Scheme<P, V>, D> {
        fn seed(&self) -> Seed<V> {
            Seed::new(self.proposal.round, self.certificate.seed_signature)
        }
    }

    impl<P: PublicKey, V: Variant + Send + Sync> SchemeTrait for Scheme<P, V> {
        type Context<'a, D: Digest> = Subject<'a, D>;
        type PublicKey = P;
        type Signature = Signature<V>;
        type Certificate = Signature<V>;

        fn me(&self) -> Option<u32> {
            match self {
                Self::Signer { share, .. } => Some(share.index),
                _ => None,
            }
        }

        fn participants(&self) -> &Set<Self::PublicKey> {
            self.participants()
        }

        fn sign_vote<D: Digest>(
            &self,
            namespace: &[u8],
            subject: Subject<'_, D>,
        ) -> Option<CertificateSignature<Self>> {
            let share = self.share()?;

            let (vote_namespace, vote_message) = vote_namespace_and_message(namespace, &subject);
            let vote_signature = partial_sign_message::<V>(
                share,
                Some(vote_namespace.as_ref()),
                vote_message.as_ref(),
            )
            .value;

            let (seed_namespace, seed_message) = seed_namespace_and_message(namespace, &subject);
            let seed_signature = partial_sign_message::<V>(
                share,
                Some(seed_namespace.as_ref()),
                seed_message.as_ref(),
            )
            .value;

            let signature = Signature {
                vote_signature,
                seed_signature,
            };

            Some(CertificateSignature {
                signer: share.index,
                signature,
            })
        }

        fn assemble_certificate<I>(&self, signatures: I) -> Option<Self::Certificate>
        where
            I: IntoIterator<Item = CertificateSignature<Self>>,
        {
            let (vote_partials, seed_partials): (Vec<_>, Vec<_>) = signatures
                .into_iter()
                .map(|sig| {
                    (
                        PartialSignature::<V> {
                            index: sig.signer,
                            value: sig.signature.vote_signature,
                        },
                        PartialSignature::<V> {
                            index: sig.signer,
                            value: sig.signature.seed_signature,
                        },
                    )
                })
                .unzip();

            let quorum = self.polynomial();
            if vote_partials.len() < quorum.required() as usize {
                return None;
            }

            let (vote_signature, seed_signature) = threshold_signature_recover_pair::<V, _>(
                quorum,
                vote_partials.iter(),
                seed_partials.iter(),
            )
            .ok()?;

            Some(Signature {
                vote_signature,
                seed_signature,
            })
        }

        fn verify_vote<D: Digest>(
            &self,
            namespace: &[u8],
            subject: Subject<'_, D>,
            signature: &CertificateSignature<Self>,
        ) -> bool {
            let Ok(evaluated) = self.polynomial().partial_public(signature.signer) else {
                return false;
            };

            let (vote_namespace, vote_message) = vote_namespace_and_message(namespace, &subject);
            let (seed_namespace, seed_message) = seed_namespace_and_message(namespace, &subject);

            let sig = aggregate_signatures::<V, _>(&[
                signature.signature.vote_signature,
                signature.signature.seed_signature,
            ]);

            aggregate_verify_multiple_messages::<V, _>(
                &evaluated,
                &[
                    (Some(vote_namespace.as_ref()), vote_message.as_ref()),
                    (Some(seed_namespace.as_ref()), seed_message.as_ref()),
                ],
                &sig,
                1,
            )
            .is_ok()
        }

        fn verify_votes<R, D, I>(
            &self,
            _rng: &mut R,
            namespace: &[u8],
            subject: Subject<'_, D>,
            signatures: I,
        ) -> SignatureVerification<Self>
        where
            R: Rng + CryptoRng,
            D: Digest,
            I: IntoIterator<Item = CertificateSignature<Self>>,
        {
            let mut invalid = BTreeSet::new();
            let (vote_partials, seed_partials): (Vec<_>, Vec<_>) = signatures
                .into_iter()
                .map(|sig| {
                    (
                        PartialSignature::<V> {
                            index: sig.signer,
                            value: sig.signature.vote_signature,
                        },
                        PartialSignature::<V> {
                            index: sig.signer,
                            value: sig.signature.seed_signature,
                        },
                    )
                })
                .unzip();

            let polynomial = self.polynomial();
            let (vote_namespace, vote_message) = vote_namespace_and_message(namespace, &subject);
            if let Err(errs) = partial_verify_multiple_public_keys::<V, _>(
                polynomial,
                Some(vote_namespace.as_ref()),
                vote_message.as_ref(),
                vote_partials.iter(),
            ) {
                for partial in errs {
                    invalid.insert(partial.index);
                }
            }

            let (seed_namespace, seed_message) = seed_namespace_and_message(namespace, &subject);
            if let Err(errs) = partial_verify_multiple_public_keys::<V, _>(
                polynomial,
                Some(seed_namespace.as_ref()),
                seed_message.as_ref(),
                seed_partials
                    .iter()
                    .filter(|partial| !invalid.contains(&partial.index)),
            ) {
                for partial in errs {
                    invalid.insert(partial.index);
                }
            }

            let verified = vote_partials
                .into_iter()
                .zip(seed_partials)
                .map(|(vote, seed)| CertificateSignature {
                    signer: vote.index,
                    signature: Signature {
                        vote_signature: vote.value,
                        seed_signature: seed.value,
                    },
                })
                .filter(|sig| !invalid.contains(&sig.signer))
                .collect();

            let invalid_signers = invalid.into_iter().collect();

            SignatureVerification::new(verified, invalid_signers)
        }

        fn verify_certificate<R: Rng + CryptoRng, D: Digest>(
            &self,
            _rng: &mut R,
            namespace: &[u8],
            subject: Subject<'_, D>,
            certificate: &Self::Certificate,
        ) -> bool {
            let identity = self.identity();

            let (vote_namespace, vote_message) = vote_namespace_and_message(namespace, &subject);
            let (seed_namespace, seed_message) = seed_namespace_and_message(namespace, &subject);

            let signature = aggregate_signatures::<V, _>(&[
                certificate.vote_signature,
                certificate.seed_signature,
            ]);

            aggregate_verify_multiple_messages::<V, _>(
                identity,
                &[
                    (Some(vote_namespace.as_ref()), vote_message.as_ref()),
                    (Some(seed_namespace.as_ref()), seed_message.as_ref()),
                ],
                &signature,
                1,
            )
            .is_ok()
        }

        fn verify_certificates<'a, R, D, I>(
            &self,
            _rng: &mut R,
            namespace: &[u8],
            certificates: I,
        ) -> bool
        where
            R: Rng + CryptoRng,
            D: Digest,
            I: Iterator<Item = (Subject<'a, D>, &'a Self::Certificate)>,
        {
            let identity = self.identity();

            let mut seeds = HashMap::new();
            let mut messages = Vec::new();
            let mut signatures = Vec::new();

            let notarize_namespace = notarize_namespace(namespace);
            let nullify_namespace = nullify_namespace(namespace);
            let finalize_namespace = finalize_namespace(namespace);
            let seed_namespace = seed_namespace(namespace);

            for (context, certificate) in certificates {
                match context {
                    Subject::Notarize { proposal } => {
                        // Prepare notarize message
                        let notarize_message = proposal.encode();
                        let notarize_message =
                            (Some(notarize_namespace.as_slice()), notarize_message);
                        messages.push(notarize_message);
                    }
                    Subject::Nullify { round } => {
                        // Prepare nullify message
                        let nullify_encoded = round.encode();
                        let nullify_message =
                            (Some(nullify_namespace.as_slice()), nullify_encoded.clone());
                        messages.push(nullify_message);
                    }
                    Subject::Finalize { proposal } => {
                        // Prepare finalize message
                        let finalize_message = proposal.encode();
                        let finalize_message =
                            (Some(finalize_namespace.as_slice()), finalize_message);
                        messages.push(finalize_message);
                    }
                }
                signatures.push(&certificate.vote_signature);

                // Seed signatures are per-view, so multiple certificates for the same view
                // (e.g., notarization and finalization) share the same seed. We only include
                // each unique seed once in the aggregate, but verify all certificates for a
                // view have matching seeds.
                if let Some(previous) = seeds.get(&context.view()) {
                    if *previous != &certificate.seed_signature {
                        return false;
                    }
                } else {
                    let seed_message = match context {
                        Subject::Notarize { proposal } | Subject::Finalize { proposal } => {
                            proposal.round.encode()
                        }
                        Subject::Nullify { round } => round.encode(),
                    };

                    messages.push((Some(seed_namespace.as_slice()), seed_message));
                    signatures.push(&certificate.seed_signature);
                    seeds.insert(context.view(), &certificate.seed_signature);
                }
            }

            // Aggregate signatures
            let signature = aggregate_signatures::<V, _>(signatures);
            aggregate_verify_multiple_messages::<V, _>(
                identity,
                &messages
                    .iter()
                    .map(|(namespace, message)| (namespace.as_deref(), message.as_ref()))
                    .collect::<Vec<_>>(),
                &signature,
                1,
            )
            .is_ok()
        }

        fn is_attributable(&self) -> bool {
            false
        }

        fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {}

        fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {}
    }

    impl<P: PublicKey, V: Variant + Send + Sync> SeededScheme for Scheme<P, V> {
        type Seed = Seed<V>;

        fn seed(&self, round: Round, certificate: &Self::Certificate) -> Option<Self::Seed> {
            Some(Seed::new(round, certificate.seed_signature))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            simplex::{
                scheme::{bls12381_threshold, notarize_namespace, seed_namespace},
                types::{Finalization, Finalize, Notarization, Notarize, Proposal, Subject},
            },
            types::{Round, View},
        };
        use commonware_codec::{Decode, Encode};
        use commonware_cryptography::{
            bls12381::{
                dkg::{self, deal_anonymous},
                primitives::{
                    ops::partial_sign_message,
                    variant::{MinPk, MinSig, Variant},
                },
            },
            certificate::mocks::Fixture,
            ed25519,
            ed25519::certificate::mocks::participants as ed25519_participants,
            sha256::Digest as Sha256Digest,
            Hasher, Sha256,
        };
        use commonware_utils::{quorum_from_slice, NZU32};
        use rand::{rngs::StdRng, thread_rng, SeedableRng};

        const NAMESPACE: &[u8] = b"bls-threshold-signing-scheme";

        type Scheme<V> = super::Scheme<ed25519::PublicKey, V>;
        type Signature<V> = super::Signature<V>;

        fn setup_signers<V: Variant>(n: u32, seed: u64) -> (Vec<Scheme<V>>, Scheme<V>) {
            let mut rng = StdRng::seed_from_u64(seed);
            let Fixture {
                schemes, verifier, ..
            } = bls12381_threshold::fixture::<V, _>(&mut rng, n);

            (schemes, verifier)
        }

        fn sample_proposal(epoch: Epoch, view: View, tag: u8) -> Proposal<Sha256Digest> {
            Proposal::new(
                Round::new(epoch, view),
                view.previous().unwrap(),
                Sha256::hash(&[tag]),
            )
        }

        fn signer_shares_must_match_participant_indices<V: Variant>() {
            let mut rng = StdRng::seed_from_u64(7);
            let participants = ed25519_participants(&mut rng, 4);
            let (polynomial, mut shares) =
                dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(4));
            shares[0].index = 999;
            Scheme::<V>::signer(participants.keys().clone(), polynomial, shares[0].clone());
        }

        #[test]
        #[should_panic(expected = "share index must match participant indices")]
        fn test_signer_shares_must_match_participant_indices_min_pk() {
            signer_shares_must_match_participant_indices::<MinPk>();
        }

        #[test]
        #[should_panic(expected = "share index must match participant indices")]
        fn test_signer_shares_must_match_participant_indices_min_sig() {
            signer_shares_must_match_participant_indices::<MinSig>();
        }
        fn scheme_polynomial_threshold_must_equal_quorum<V: Variant>() {
            let mut rng = StdRng::seed_from_u64(7);
            let participants = ed25519_participants(&mut rng, 5);
            let (polynomial, shares) = deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(4));
            Scheme::<V>::signer(participants.keys().clone(), polynomial, shares[0].clone());
        }

        #[test]
        #[should_panic(expected = "polynomial total must equal participant len")]
        fn test_scheme_polynomial_threshold_must_equal_quorum_min_pk() {
            scheme_polynomial_threshold_must_equal_quorum::<MinPk>();
        }

        #[test]
        #[should_panic(expected = "polynomial total must equal participant len")]
        fn test_scheme_polynomial_threshold_must_equal_quorum_min_sig() {
            scheme_polynomial_threshold_must_equal_quorum::<MinSig>();
        }

        fn verifier_polynomial_threshold_must_equal_quorum<V: Variant>() {
            let mut rng = StdRng::seed_from_u64(7);
            let participants = ed25519_participants(&mut rng, 5);
            let (polynomial, _) = deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(4));
            Scheme::<V>::verifier(participants.keys().clone(), polynomial);
        }

        #[test]
        #[should_panic(expected = "polynomial total must equal participant len")]
        fn test_verifier_polynomial_threshold_must_equal_quorum_min_pk() {
            verifier_polynomial_threshold_must_equal_quorum::<MinPk>();
        }

        #[test]
        #[should_panic(expected = "polynomial total must equal participant len")]
        fn test_verifier_polynomial_threshold_must_equal_quorum_min_sig() {
            verifier_polynomial_threshold_must_equal_quorum::<MinSig>();
        }

        fn sign_vote_roundtrip_for_each_context<V: Variant>() {
            let (schemes, _) = setup_signers::<V>(4, 7);
            let scheme = &schemes[0];

            let proposal = sample_proposal(Epoch::new(0), View::new(2), 1);
            let notarize_vote = scheme
                .sign_vote(
                    NAMESPACE,
                    Subject::Notarize {
                        proposal: &proposal,
                    },
                )
                .unwrap();
            assert!(scheme.verify_vote(
                NAMESPACE,
                Subject::Notarize {
                    proposal: &proposal,
                },
                &notarize_vote
            ));

            let nullify_vote = scheme
                .sign_vote::<Sha256Digest>(
                    NAMESPACE,
                    Subject::Nullify {
                        round: proposal.round,
                    },
                )
                .unwrap();
            assert!(scheme.verify_vote::<Sha256Digest>(
                NAMESPACE,
                Subject::Nullify {
                    round: proposal.round,
                },
                &nullify_vote
            ));

            let finalize_vote = scheme
                .sign_vote(
                    NAMESPACE,
                    Subject::Finalize {
                        proposal: &proposal,
                    },
                )
                .unwrap();
            assert!(scheme.verify_vote(
                NAMESPACE,
                Subject::Finalize {
                    proposal: &proposal,
                },
                &finalize_vote
            ));
        }

        #[test]
        fn test_sign_vote_roundtrip_for_each_context() {
            sign_vote_roundtrip_for_each_context::<MinPk>();
            sign_vote_roundtrip_for_each_context::<MinSig>();
        }

        fn verifier_cannot_sign<V: Variant>() {
            let (_, verifier) = setup_signers::<V>(4, 11);

            let proposal = sample_proposal(Epoch::new(0), View::new(3), 2);
            assert!(
                verifier
                    .sign_vote(
                        NAMESPACE,
                        Subject::Notarize {
                            proposal: &proposal,
                        },
                    )
                    .is_none(),
                "verifier should not produce signatures"
            );
        }

        #[test]
        fn test_verifier_cannot_sign() {
            verifier_cannot_sign::<MinPk>();
            verifier_cannot_sign::<MinSig>();
        }

        fn verifier_accepts_votes<V: Variant>() {
            let (schemes, verifier) = setup_signers::<V>(4, 11);
            let proposal = sample_proposal(Epoch::new(0), View::new(3), 2);
            let vote = schemes[1]
                .sign_vote(
                    NAMESPACE,
                    Subject::Notarize {
                        proposal: &proposal,
                    },
                )
                .unwrap();
            assert!(verifier.verify_vote(
                NAMESPACE,
                Subject::Notarize {
                    proposal: &proposal,
                },
                &vote
            ));
        }

        #[test]
        fn test_verifier_accepts_votes() {
            verifier_accepts_votes::<MinPk>();
            verifier_accepts_votes::<MinSig>();
        }

        fn verify_votes_filters_bad_signers<V: Variant>() {
            let (schemes, _) = setup_signers::<V>(5, 13);
            let quorum = quorum_from_slice(&schemes) as usize;
            let proposal = sample_proposal(Epoch::new(0), View::new(5), 3);

            let mut votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|scheme| {
                    scheme
                        .sign_vote(
                            NAMESPACE,
                            Subject::Notarize {
                                proposal: &proposal,
                            },
                        )
                        .unwrap()
                })
                .collect();

            let verification = schemes[0].verify_votes(
                &mut thread_rng(),
                NAMESPACE,
                Subject::Notarize {
                    proposal: &proposal,
                },
                votes.clone(),
            );
            assert!(verification.invalid_signers.is_empty());
            assert_eq!(verification.verified.len(), quorum);

            votes[0].signer = 999;
            let verification = schemes[0].verify_votes(
                &mut thread_rng(),
                NAMESPACE,
                Subject::Notarize {
                    proposal: &proposal,
                },
                votes,
            );
            assert_eq!(verification.invalid_signers, vec![999]);
            assert_eq!(verification.verified.len(), quorum - 1);
        }

        #[test]
        fn test_verify_votes_filters_bad_signers() {
            verify_votes_filters_bad_signers::<MinPk>();
            verify_votes_filters_bad_signers::<MinSig>();
        }

        fn assemble_certificate_requires_quorum<V: Variant>() {
            let (schemes, _) = setup_signers::<V>(4, 17);
            let quorum = quorum_from_slice(&schemes) as usize;
            let proposal = sample_proposal(Epoch::new(0), View::new(7), 4);

            let votes: Vec<_> = schemes
                .iter()
                .take(quorum - 1)
                .map(|scheme| {
                    scheme
                        .sign_vote(
                            NAMESPACE,
                            Subject::Notarize {
                                proposal: &proposal,
                            },
                        )
                        .unwrap()
                })
                .collect();

            assert!(schemes[0].assemble_certificate(votes).is_none());
        }

        #[test]
        fn test_assemble_certificate_requires_quorum() {
            assemble_certificate_requires_quorum::<MinPk>();
            assemble_certificate_requires_quorum::<MinSig>();
        }

        fn verify_certificate<V: Variant>() {
            let (schemes, verifier) = setup_signers::<V>(4, 19);
            let quorum = quorum_from_slice(&schemes) as usize;
            let proposal = sample_proposal(Epoch::new(0), View::new(9), 5);

            let votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|scheme| {
                    scheme
                        .sign_vote(
                            NAMESPACE,
                            Subject::Finalize {
                                proposal: &proposal,
                            },
                        )
                        .unwrap()
                })
                .collect();

            let certificate = schemes[0]
                .assemble_certificate(votes)
                .expect("assemble certificate");

            assert!(verifier.verify_certificate(
                &mut thread_rng(),
                NAMESPACE,
                Subject::Finalize {
                    proposal: &proposal,
                },
                &certificate,
            ));
        }

        #[test]
        fn test_verify_certificate() {
            verify_certificate::<MinPk>();
            verify_certificate::<MinSig>();
        }

        fn verify_certificate_detects_corruption<V: Variant>() {
            let (schemes, verifier) = setup_signers::<V>(4, 23);
            let quorum = quorum_from_slice(&schemes) as usize;
            let proposal = sample_proposal(Epoch::new(0), View::new(11), 6);

            let votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|scheme| {
                    scheme
                        .sign_vote(
                            NAMESPACE,
                            Subject::Notarize {
                                proposal: &proposal,
                            },
                        )
                        .unwrap()
                })
                .collect();

            let certificate = schemes[0]
                .assemble_certificate(votes)
                .expect("assemble certificate");

            assert!(verifier.verify_certificate(
                &mut thread_rng(),
                NAMESPACE,
                Subject::Notarize {
                    proposal: &proposal,
                },
                &certificate,
            ));

            let mut corrupted = certificate;
            corrupted.vote_signature = corrupted.seed_signature;
            assert!(!verifier.verify_certificate(
                &mut thread_rng(),
                NAMESPACE,
                Subject::Notarize {
                    proposal: &proposal,
                },
                &corrupted,
            ));
        }

        #[test]
        fn test_verify_certificate_detects_corruption() {
            verify_certificate_detects_corruption::<MinPk>();
            verify_certificate_detects_corruption::<MinSig>();
        }

        fn certificate_codec_roundtrip<V: Variant>() {
            let (schemes, _) = setup_signers::<V>(5, 29);
            let quorum = quorum_from_slice(&schemes) as usize;
            let proposal = sample_proposal(Epoch::new(0), View::new(13), 7);

            let votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|scheme| {
                    scheme
                        .sign_vote(
                            NAMESPACE,
                            Subject::Notarize {
                                proposal: &proposal,
                            },
                        )
                        .unwrap()
                })
                .collect();

            let certificate = schemes[0]
                .assemble_certificate(votes)
                .expect("assemble certificate");

            let encoded = certificate.encode();
            let decoded =
                Signature::<V>::decode_cfg(encoded.freeze(), &()).expect("decode certificate");
            assert_eq!(decoded, certificate);
        }

        #[test]
        fn test_certificate_codec_roundtrip() {
            certificate_codec_roundtrip::<MinPk>();
            certificate_codec_roundtrip::<MinSig>();
        }

        fn seed_codec_roundtrip<V: Variant>() {
            let (schemes, _) = setup_signers::<V>(4, 5);
            let quorum = quorum_from_slice(&schemes) as usize;
            let proposal = sample_proposal(Epoch::new(0), View::new(1), 0);

            let votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|scheme| {
                    scheme
                        .sign_vote(
                            NAMESPACE,
                            Subject::Finalize {
                                proposal: &proposal,
                            },
                        )
                        .unwrap()
                })
                .collect();

            let certificate = schemes[0]
                .assemble_certificate(votes)
                .expect("assemble certificate");

            let seed = schemes[0]
                .seed(proposal.round, &certificate)
                .expect("extract seed");

            let encoded = seed.encode();
            let decoded = Seed::<V>::decode_cfg(encoded, &()).expect("decode seed");
            assert_eq!(decoded, seed);
        }

        #[test]
        fn test_seed_codec_roundtrip() {
            seed_codec_roundtrip::<MinPk>();
            seed_codec_roundtrip::<MinSig>();
        }

        fn seed_verify<V: Variant>() {
            let (schemes, _) = setup_signers::<V>(4, 5);
            let quorum = quorum_from_slice(&schemes) as usize;
            let proposal = sample_proposal(Epoch::new(0), View::new(1), 0);

            let votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|scheme| {
                    scheme
                        .sign_vote(
                            NAMESPACE,
                            Subject::Finalize {
                                proposal: &proposal,
                            },
                        )
                        .unwrap()
                })
                .collect();

            let certificate = schemes[0]
                .assemble_certificate(votes)
                .expect("assemble certificate");

            let seed = schemes[0]
                .seed(proposal.round, &certificate)
                .expect("extract seed");

            assert!(seed.verify(&schemes[0], NAMESPACE));

            let invalid_seed = schemes[0]
                .seed(
                    Round::new(proposal.epoch(), proposal.view().next()),
                    &certificate,
                )
                .expect("extract seed");

            assert!(!invalid_seed.verify(&schemes[0], NAMESPACE));
        }

        #[test]
        fn test_seed_verify() {
            seed_verify::<MinPk>();
            seed_verify::<MinSig>();
        }

        fn seedable<V: Variant>() {
            let (schemes, _) = setup_signers::<V>(4, 5);
            let quorum = quorum_from_slice(&schemes) as usize;
            let proposal = sample_proposal(Epoch::new(0), View::new(1), 0);

            let notarizes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|scheme| Notarize::sign(scheme, NAMESPACE, proposal.clone()).unwrap())
                .collect();

            let notarization = Notarization::from_notarizes(&schemes[0], &notarizes).unwrap();

            let finalizes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|scheme| Finalize::sign(scheme, NAMESPACE, proposal.clone()).unwrap())
                .collect();

            let finalization = Finalization::from_finalizes(&schemes[0], &finalizes).unwrap();

            assert_eq!(notarization.seed(), finalization.seed());
            assert!(notarization.seed().verify(&schemes[0], NAMESPACE));
        }

        #[test]
        fn test_seedable() {
            seedable::<MinPk>();
            seedable::<MinSig>();
        }

        fn scheme_clone_and_verifier<V: Variant>() {
            let (schemes, verifier) = setup_signers::<V>(4, 31);
            let signer = schemes[0].clone();
            let proposal = sample_proposal(Epoch::new(0), View::new(21), 9);

            assert!(
                signer
                    .sign_vote(
                        NAMESPACE,
                        Subject::Notarize {
                            proposal: &proposal,
                        },
                    )
                    .is_some(),
                "signer should produce votes"
            );

            assert!(
                verifier
                    .sign_vote(
                        NAMESPACE,
                        Subject::Notarize {
                            proposal: &proposal,
                        },
                    )
                    .is_none(),
                "verifier should not produce votes"
            );
        }

        #[test]
        fn test_scheme_clone_and_verifier() {
            scheme_clone_and_verifier::<MinPk>();
            scheme_clone_and_verifier::<MinSig>();
        }

        fn certificate_verifier_accepts_certificates<V: Variant>() {
            let (schemes, _) = setup_signers::<V>(4, 37);
            let quorum = quorum_from_slice(&schemes) as usize;
            let proposal = sample_proposal(Epoch::new(0), View::new(15), 8);

            let votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|scheme| {
                    scheme
                        .sign_vote(
                            NAMESPACE,
                            Subject::Finalize {
                                proposal: &proposal,
                            },
                        )
                        .unwrap()
                })
                .collect();

            let certificate = schemes[0]
                .assemble_certificate(votes)
                .expect("assemble certificate");

            let certificate_verifier = Scheme::<V>::certificate_verifier(*schemes[0].identity());
            assert!(
                certificate_verifier
                    .sign_vote(
                        NAMESPACE,
                        Subject::Finalize {
                            proposal: &proposal,
                        },
                    )
                    .is_none(),
                "certificate verifier should not produce votes"
            );
            assert!(certificate_verifier.verify_certificate(
                &mut thread_rng(),
                NAMESPACE,
                Subject::Finalize {
                    proposal: &proposal,
                },
                &certificate,
            ));
        }

        #[test]
        fn test_certificate_verifier_accepts_certificates() {
            certificate_verifier_accepts_certificates::<MinPk>();
            certificate_verifier_accepts_certificates::<MinSig>();
        }

        fn certificate_verifier_panics_on_vote<V: Variant>() {
            let (schemes, _) = setup_signers::<V>(4, 37);
            let certificate_verifier = Scheme::<V>::certificate_verifier(*schemes[0].identity());
            let proposal = sample_proposal(Epoch::new(0), View::new(15), 8);
            let vote = schemes[1]
                .sign_vote(
                    NAMESPACE,
                    Subject::Finalize {
                        proposal: &proposal,
                    },
                )
                .unwrap();

            certificate_verifier.verify_vote(
                NAMESPACE,
                Subject::Finalize {
                    proposal: &proposal,
                },
                &vote,
            );
        }

        #[test]
        #[should_panic(expected = "can only be called for signer and verifier")]
        fn test_certificate_verifier_panics_on_vote_min_pk() {
            certificate_verifier_panics_on_vote::<MinPk>();
        }

        #[test]
        #[should_panic(expected = "can only be called for signer and verifier")]
        fn test_certificate_verifier_panics_on_vote_min_sig() {
            certificate_verifier_panics_on_vote::<MinSig>();
        }

        fn verify_certificate_returns_seed_randomness<V: Variant>() {
            let (schemes, _) = setup_signers::<V>(4, 43);
            let quorum = quorum_from_slice(&schemes) as usize;
            let proposal = sample_proposal(Epoch::new(0), View::new(19), 10);

            let votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|scheme| {
                    scheme
                        .sign_vote(
                            NAMESPACE,
                            Subject::Notarize {
                                proposal: &proposal,
                            },
                        )
                        .unwrap()
                })
                .collect();

            let certificate = schemes[0]
                .assemble_certificate(votes)
                .expect("assemble certificate");

            let seed = schemes[0].seed(proposal.round, &certificate).unwrap();
            assert_eq!(seed.signature, certificate.seed_signature);
        }

        #[test]
        fn test_verify_certificate_returns_seed_randomness() {
            verify_certificate_returns_seed_randomness::<MinPk>();
            verify_certificate_returns_seed_randomness::<MinSig>();
        }

        fn certificate_decode_rejects_length_mismatch<V: Variant>() {
            let (schemes, _) = setup_signers::<V>(4, 47);
            let quorum = quorum_from_slice(&schemes) as usize;
            let proposal = sample_proposal(Epoch::new(0), View::new(21), 11);

            let votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|scheme| {
                    scheme
                        .sign_vote::<Sha256Digest>(
                            NAMESPACE,
                            Subject::Nullify {
                                round: proposal.round,
                            },
                        )
                        .unwrap()
                })
                .collect();

            let certificate = schemes[0]
                .assemble_certificate(votes)
                .expect("assemble certificate");

            let mut encoded = certificate.encode().freeze();
            let truncated = encoded.split_to(encoded.len() - 1);
            assert!(Signature::<V>::decode_cfg(truncated, &()).is_err());
        }

        #[test]
        fn test_certificate_decode_rejects_length_mismatch() {
            certificate_decode_rejects_length_mismatch::<MinPk>();
            certificate_decode_rejects_length_mismatch::<MinSig>();
        }

        fn sign_vote_partial_matches_share<V: Variant>() {
            let (schemes, _) = setup_signers::<V>(4, 53);
            let scheme = &schemes[0];
            let share = scheme.share().expect("has share");

            let proposal = sample_proposal(Epoch::new(0), View::new(23), 12);
            let vote = scheme
                .sign_vote(
                    NAMESPACE,
                    Subject::Notarize {
                        proposal: &proposal,
                    },
                )
                .unwrap();

            let notarize_namespace = notarize_namespace(NAMESPACE);
            let notarize_message = proposal.encode();
            let expected_message = partial_sign_message::<V>(
                share,
                Some(notarize_namespace.as_ref()),
                notarize_message.as_ref(),
            )
            .value;

            let seed_namespace = seed_namespace(NAMESPACE);
            let seed_message = proposal.round.encode();
            let expected_seed = partial_sign_message::<V>(
                share,
                Some(seed_namespace.as_ref()),
                seed_message.as_ref(),
            )
            .value;

            assert_eq!(vote.signer, share.index);
            assert_eq!(vote.signature.vote_signature, expected_message);
            assert_eq!(vote.signature.seed_signature, expected_seed);
        }

        #[test]
        fn test_sign_vote_partial_matches_share() {
            sign_vote_partial_matches_share::<MinPk>();
            sign_vote_partial_matches_share::<MinSig>();
        }

        fn verify_certificate_detects_seed_corruption<V: Variant>() {
            let (schemes, verifier) = setup_signers::<V>(4, 59);
            let quorum = quorum_from_slice(&schemes) as usize;
            let proposal = sample_proposal(Epoch::new(0), View::new(25), 13);

            let votes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|scheme| {
                    scheme
                        .sign_vote::<Sha256Digest>(
                            NAMESPACE,
                            Subject::Nullify {
                                round: proposal.round,
                            },
                        )
                        .unwrap()
                })
                .collect();

            let certificate = schemes[0]
                .assemble_certificate(votes)
                .expect("assemble certificate");

            assert!(verifier.verify_certificate::<_, Sha256Digest>(
                &mut thread_rng(),
                NAMESPACE,
                Subject::Nullify {
                    round: proposal.round,
                },
                &certificate,
            ));

            let mut corrupted = certificate;
            corrupted.seed_signature = corrupted.vote_signature;
            assert!(!verifier.verify_certificate::<_, Sha256Digest>(
                &mut thread_rng(),
                NAMESPACE,
                Subject::Nullify {
                    round: proposal.round,
                },
                &corrupted,
            ));
        }

        #[test]
        fn test_verify_certificate_detects_seed_corruption() {
            verify_certificate_detects_seed_corruption::<MinPk>();
            verify_certificate_detects_seed_corruption::<MinSig>();
        }

        fn encrypt_decrypt<V: Variant>() {
            let (schemes, verifier) = setup_signers::<V>(4, 61);
            let quorum = quorum_from_slice(&schemes) as usize;

            // Prepare a message to encrypt
            let message = b"Secret message for future view10";

            // Target round for encryption
            let target = Round::new(Epoch::new(333), View::new(10));

            // Encrypt using the scheme
            let ciphertext = schemes[0].encrypt(&mut thread_rng(), NAMESPACE, target, *message);

            // Can also encrypt with the verifier scheme
            let ciphertext_verifier =
                verifier.encrypt(&mut thread_rng(), NAMESPACE, target, *message);

            // Generate notarization for the target round to get the seed
            let proposal = sample_proposal(target.epoch(), target.view(), 14);
            let notarizes: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|scheme| Notarize::sign(scheme, NAMESPACE, proposal.clone()).unwrap())
                .collect();

            let notarization = Notarization::from_notarizes(&schemes[0], &notarizes).unwrap();

            // Decrypt using the seed
            let seed = notarization.seed();
            let decrypted = seed.decrypt(&ciphertext).unwrap();
            assert_eq!(message, decrypted.as_ref());

            let decrypted_verifier = seed.decrypt(&ciphertext_verifier).unwrap();
            assert_eq!(message, decrypted_verifier.as_ref());
        }

        #[test]
        fn test_encrypt_decrypt() {
            encrypt_decrypt::<MinPk>();
            encrypt_decrypt::<MinSig>();
        }

        #[cfg(feature = "arbitrary")]
        mod conformance {
            use super::*;
            use commonware_codec::conformance::CodecConformance;

            commonware_conformance::conformance_tests! {
                CodecConformance<Signature<MinSig>>,
                CodecConformance<Seed<MinSig>>,
            }
        }
    }
}

pub mod ed25519 {
    //! Ed25519 implementation of the [`Scheme`] trait for `simplex`.
    //!
    //! [`Scheme`] is **attributable**: individual signatures can be safely
    //! presented to some third party as evidence of either liveness or of committing a fault. Certificates
    //! contain signer indices alongside individual signatures, enabling secure
    //! per-validator activity tracking and fault detection.

    use crate::{
        simplex::{scheme::SeededScheme, types::Subject},
        types::Round,
    };
    use commonware_cryptography::impl_ed25519_certificate;

    impl_ed25519_certificate!(Subject<'a, D>);

    impl SeededScheme for Scheme {
        type Seed = ();

        fn seed(&self, _: Round, _: &Self::Certificate) -> Option<Self::Seed> {
            None
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::{
            simplex::{
                scheme::{ed25519, SeededScheme},
                types::Subject,
            },
            types::{Epoch, Round, View},
        };
        use commonware_cryptography::{
            certificate::{mocks::Fixture, Scheme as _},
            sha256::Digest as Sha256Digest,
        };
        use commonware_utils::quorum_from_slice;
        use rand::{rngs::StdRng, SeedableRng};

        #[test]
        fn test_seed_returns_none() {
            let mut rng = StdRng::seed_from_u64(42);
            let Fixture { schemes, .. } = ed25519::fixture(&mut rng, 4);

            let quorum = quorum_from_slice(&schemes) as usize;

            let signatures: Vec<_> = schemes
                .iter()
                .take(quorum)
                .map(|s| {
                    s.sign_vote::<Sha256Digest>(
                        b"test",
                        Subject::Nullify {
                            round: Round::new(Epoch::new(1), View::new(1)),
                        },
                    )
                    .unwrap()
                })
                .collect();

            let certificate = schemes[0].assemble_certificate(signatures).unwrap();

            let round = Round::new(Epoch::new(1), View::new(1));
            assert!(schemes[0].seed(round, &certificate).is_none());
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        pub mod reporter {
            //! Wrapper for scheme-dependent activity filtering and verification.
            //!
            //! # Overview
            //!
            //! The [`AttributableReporter`] provides a composable wrapper around consensus reporters
            //! that automatically filters and verifies activities based on scheme attributability.
            //! This ensures that:
            //!
            //! 1. **Peer activities are cryptographically verified** before being reported
            //! 2. **Non-attributable schemes** suppress per-validator activities from peers to prevent
            //!    signature forgery attacks
            //! 3. **Certificates** are always reported as they contain valid quorum proofs
            //!
            //! # Security Rationale
            //!
            //! With [`super::bls12381_threshold`], any `t` valid partial signatures
            //! can be used to forge a partial signature for any participant. If per-validator activities
            //! were exposed for such schemes, adversaries could fabricate evidence of either liveness or of committing a fault.
            //! This wrapper prevents that attack by suppressing peer activities for non-attributable schemes.

            use crate::{
                simplex::{scheme::SimplexScheme, types::Activity},
                Reporter,
            };
            use commonware_cryptography::{certificate::Scheme, Digest};
            use rand::{CryptoRng, Rng};

            /// Reporter wrapper that filters and verifies activities based on scheme attributability.
            ///
            /// This wrapper provides scheme-aware activity filtering with automatic verification of peer
            /// activities. It prevents signature forgery attacks on non-attributable schemes while ensuring
            /// all activities are cryptographically valid before reporting.
            #[derive(Clone)]
            pub struct AttributableReporter<
                E: Clone + Rng + CryptoRng + Send + 'static,
                S: Scheme,
                D: Digest,
                R: Reporter<Activity = Activity<S, D>>,
            > {
                /// RNG for certificate verification
                rng: E,
                /// Signing scheme for verification
                scheme: S,
                /// Namespace for domain separation in verification
                namespace: Vec<u8>,
                /// Inner reporter that receives filtered activities
                reporter: R,
                /// Whether to always verify peer activities
                verify: bool,
            }

            impl<
                    E: Clone + Rng + CryptoRng + Send + 'static,
                    S: Scheme,
                    D: Digest,
                    R: Reporter<Activity = Activity<S, D>>,
                > AttributableReporter<E, S, D, R>
            {
                /// Creates a new `AttributableReporter` that wraps an inner reporter.
                pub const fn new(rng: E, scheme: S, namespace: Vec<u8>, reporter: R, verify: bool) -> Self {
                    Self {
                        rng,
                        scheme,
                        namespace,
                        reporter,
                        verify,
                    }
                }
            }

            impl<
                    E: Clone + Rng + CryptoRng + Send + 'static,
                    S: SimplexScheme<D>,
                    D: Digest,
                    R: Reporter<Activity = Activity<S, D>>,
                > Reporter for AttributableReporter<E, S, D, R>
            {
                type Activity = Activity<S, D>;

                async fn report(&mut self, activity: Self::Activity) {
                    // Verify peer activities if verification is enabled
                    if self.verify
                        && !activity.verified()
                        && !activity.verify(&mut self.rng, &self.scheme, &self.namespace)
                    {
                        // Drop unverified peer activity
                        return;
                    }

                    // Filter based on scheme attributability
                    if !self.scheme.is_attributable() {
                        match activity {
                            Activity::Notarize(_)
                            | Activity::Nullify(_)
                            | Activity::Finalize(_)
                            | Activity::ConflictingNotarize(_)
                            | Activity::ConflictingFinalize(_)
                            | Activity::NullifyFinalize(_) => {
                                // Drop per-validator peer activity for non-attributable scheme
                                return;
                            }
                            Activity::Notarization(_)
                            | Activity::Nullification(_)
                            | Activity::Finalization(_) => {
                                // Always report certificates
                            }
                        }
                    }

                    self.reporter.report(activity).await;
                }
            }

            #[cfg(test)]
            mod tests {
                use super::*;
                use crate::{
                    simplex::{
                        scheme::{bls12381_threshold, ed25519, Scheme},
                        types::{Notarization, Notarize, Proposal, Subject},
                    },
                    types::{Epoch, Round, View},
                };
                use commonware_cryptography::{
                    bls12381::primitives::variant::MinPk, certificate::mocks::Fixture,
                    sha256::Digest as Sha256Digest, Hasher, Sha256,
                };
                use futures::executor::block_on;
                use rand::{rngs::StdRng, SeedableRng};
                use std::sync::{Arc, Mutex};

                const NAMESPACE: &[u8] = b"test-reporter";

                #[derive(Clone)]
                struct MockReporter<S: Scheme, D: Digest> {
                    activities: Arc<Mutex<Vec<Activity<S, D>>>>,
                }

                impl<S: Scheme, D: Digest> MockReporter<S, D> {
                    fn new() -> Self {
                        Self {
                            activities: Arc::new(Mutex::new(Vec::new())),
                        }
                    }

                    fn reported(&self) -> Vec<Activity<S, D>> {
                        self.activities.lock().unwrap().clone()
                    }

                    fn count(&self) -> usize {
                        self.activities.lock().unwrap().len()
                    }
                }

                impl<S: Scheme, D: Digest> Reporter for MockReporter<S, D> {
                    type Activity = Activity<S, D>;

                    async fn report(&mut self, activity: Self::Activity) {
                        self.activities.lock().unwrap().push(activity);
                    }
                }

                fn create_proposal(epoch: u64, view: u64) -> Proposal<Sha256Digest> {
                    let data = format!("proposal-{epoch}-{view}");
                    let hash = Sha256::hash(data.as_bytes());
                    let epoch = Epoch::new(epoch);
                    let view = View::new(view);
                    Proposal::new(Round::new(epoch, view), view, hash)
                }

                #[test]
                fn test_invalid_peer_activity_dropped() {
                    // Invalid peer activities should be dropped when verification is enabled
                    let mut rng = StdRng::seed_from_u64(42);
                    let Fixture {
                        schemes, verifier, ..
                    } = ed25519::fixture(&mut rng, 4);

                    assert!(verifier.is_attributable(), "Ed25519 must be attributable");

                    let mock = MockReporter::new();
                    let mut reporter =
                        AttributableReporter::new(rng, verifier, NAMESPACE.to_vec(), mock.clone(), true);

                    // Create an invalid activity (wrong namespace)
                    let proposal = create_proposal(0, 1);
                    let signature = schemes[1]
                        .sign_vote::<Sha256Digest>(
                            &[], // Invalid namespace
                            Subject::Notarize {
                                proposal: &proposal,
                            },
                        )
                        .expect("signing failed");
                    let notarize = Notarize {
                        proposal,
                        signature,
                    };

                    // Report it
                    block_on(reporter.report(Activity::Notarize(notarize)));

                    // Should be dropped
                    assert_eq!(mock.count(), 0);
                }

                #[test]
                fn test_skip_verification() {
                    // When verification is disabled, invalid activities pass through
                    let mut rng = StdRng::seed_from_u64(42);
                    let Fixture {
                        schemes, verifier, ..
                    } = ed25519::fixture(&mut rng, 4);

                    assert!(verifier.is_attributable(), "Ed25519 must be attributable");

                    let mock = MockReporter::new();
                    let mut reporter = AttributableReporter::new(
                        rng,
                        verifier,
                        NAMESPACE.to_vec(),
                        mock.clone(),
                        false, // Disable verification
                    );

                    // Create an invalid activity (wrong namespace)
                    let proposal = create_proposal(0, 1);
                    let signature = schemes[1]
                        .sign_vote::<Sha256Digest>(
                            &[], // Invalid namespace
                            Subject::Notarize {
                                proposal: &proposal,
                            },
                        )
                        .expect("signing failed");
                    let notarize = Notarize {
                        proposal,
                        signature,
                    };

                    // Report it
                    block_on(reporter.report(Activity::Notarize(notarize)));

                    // Should be reported even though it's invalid
                    assert_eq!(mock.count(), 1);
                    let reported = mock.reported();
                    assert!(matches!(reported[0], Activity::Notarize(_)));
                }

                #[test]
                fn test_certificates_always_reported() {
                    // Certificates should always be reported, even for non-attributable schemes
                    let mut rng = StdRng::seed_from_u64(42);
                    let Fixture {
                        schemes, verifier, ..
                    } = bls12381_threshold::fixture::<MinPk, _>(&mut rng, 4);

                    assert!(
                        !verifier.is_attributable(),
                        "BLS threshold must be non-attributable"
                    );

                    let mock = MockReporter::new();
                    let mut reporter =
                        AttributableReporter::new(rng, verifier, NAMESPACE.to_vec(), mock.clone(), true);

                    // Create a certificate from multiple validators
                    let proposal = create_proposal(0, 1);
                    let votes: Vec<_> = schemes
                        .iter()
                        .map(|scheme| {
                            scheme
                                .sign_vote::<Sha256Digest>(
                                    NAMESPACE,
                                    Subject::Notarize {
                                        proposal: &proposal,
                                    },
                                )
                                .expect("signing failed")
                        })
                        .collect();

                    let certificate = schemes[0]
                        .assemble_certificate(votes)
                        .expect("failed to assemble certificate");

                    let notarization = Notarization {
                        proposal,
                        certificate,
                    };

                    // Report it
                    block_on(reporter.report(Activity::Notarization(notarization)));

                    // Should be reported even though scheme is non-attributable (certificates are quorum proofs)
                    assert_eq!(mock.count(), 1);
                    let reported = mock.reported();
                    assert!(matches!(reported[0], Activity::Notarization(_)));
                }

                #[test]
                fn test_non_attributable_filters_peer_activities() {
                    // Non-attributable schemes (like BLS threshold) must filter peer per-validator activities
                    let mut rng = StdRng::seed_from_u64(42);
                    let Fixture {
                        schemes, verifier, ..
                    } = bls12381_threshold::fixture::<MinPk, _>(&mut rng, 4);

                    assert!(
                        !verifier.is_attributable(),
                        "BLS threshold must be non-attributable"
                    );

                    let mock = MockReporter::new();
                    let mut reporter =
                        AttributableReporter::new(rng, verifier, NAMESPACE.to_vec(), mock.clone(), true);

                    // Create peer activity (from validator 1)
                    let proposal = create_proposal(0, 1);
                    let signature = schemes[1]
                        .sign_vote::<Sha256Digest>(
                            NAMESPACE,
                            Subject::Notarize {
                                proposal: &proposal,
                            },
                        )
                        .expect("signing failed");

                    let notarize = Notarize {
                        proposal,
                        signature,
                    };

                    // Report peer per-validator activity
                    block_on(reporter.report(Activity::Notarize(notarize)));

                    // Must be filtered
                    assert_eq!(mock.count(), 0);
                }

                #[test]
                fn test_attributable_scheme_reports_peer_activities() {
                    // Ed25519 (attributable) should report peer per-validator activities
                    let mut rng = StdRng::seed_from_u64(42);
                    let Fixture {
                        schemes, verifier, ..
                    } = ed25519::fixture(&mut rng, 4);

                    assert!(verifier.is_attributable(), "Ed25519 must be attributable");

                    let mock = MockReporter::new();
                    let mut reporter =
                        AttributableReporter::new(rng, verifier, NAMESPACE.to_vec(), mock.clone(), true);

                    // Create a peer activity (from validator 1)
                    let proposal = create_proposal(0, 1);
                    let signature = schemes[1]
                        .sign_vote::<Sha256Digest>(
                            NAMESPACE,
                            Subject::Notarize {
                                proposal: &proposal,
                            },
                        )
                        .expect("signing failed");

                    let notarize = Notarize {
                        proposal,
                        signature,
                    };

                    // Report the peer per-validator activity
                    block_on(reporter.report(Activity::Notarize(notarize)));

                    // Should be reported since scheme is attributable
                    assert_eq!(mock.count(), 1);
                    let reported = mock.reported();
                    assert!(matches!(reported[0], Activity::Notarize(_)));
                }
            }
        }
    }
}

use crate::{simplex::types::Subject, types::Round};
use commonware_codec::Encode;
use commonware_cryptography::{
    certificate::{Context, Scheme},
    Digest,
};
use commonware_utils::union;

impl<'a, D: Digest> Context for Subject<'a, D> {
    fn namespace_and_message(&self, namespace: &[u8]) -> (Vec<u8>, Vec<u8>) {
        vote_namespace_and_message(namespace, self)
    }
}

/// Extension trait for schemes that can derive randomness from certificates.
///
/// Some signing schemes (like [`bls12381_threshold`]) produce certificates that contain
/// embedded randomness which can be extracted and used for leader election or other
/// protocol-level randomness requirements. This trait provides a uniform interface for
/// extracting that randomness when available.
///
/// Schemes that do not support embedded randomness (like [`ed25519`] and [`bls12381_multisig`])
/// implement this trait but return `None` from [`SeededScheme::seed`].
pub trait SeededScheme: Scheme {
    /// Randomness seed derived from a certificate, if the scheme supports it.
    type Seed: Clone + Encode + Send;

    /// Extracts randomness seed, if provided by the scheme, derived from the certificate
    /// for the given round.
    fn seed(&self, round: Round, certificate: &Self::Certificate) -> Option<Self::Seed>;
}

pub trait SimplexScheme<D: Digest>: for<'a> SeededScheme<Context<'a, D> = Subject<'a, D>> {}

impl<D: Digest, S> SimplexScheme<D> for S where
    S: for<'a> SeededScheme<Context<'a, D> = Subject<'a, D>>
{
}

// Constants for domain separation in signature verification
// These are used to prevent cross-protocol attacks and message-type confusion
const SEED_SUFFIX: &[u8] = b"_SEED";
const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

/// Creates a namespace for seed messages by appending the SEED_SUFFIX
/// The seed is used for leader election and randomness generation
#[inline]
pub(crate) fn seed_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, SEED_SUFFIX)
}

/// Creates a namespace for notarize messages by appending the NOTARIZE_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn notarize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

/// Creates a namespace for nullify messages by appending the NULLIFY_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn nullify_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

/// Creates a namespace for finalize messages by appending the FINALIZE_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn finalize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
}

/// Produces the vote namespace and message bytes for a given vote context.
///
/// Returns the final namespace (with the context-specific suffix) and the
/// serialized message to sign or verify.
#[inline]
pub(crate) fn vote_namespace_and_message<D: Digest>(
    namespace: &[u8],
    subject: &Subject<'_, D>,
) -> (Vec<u8>, Vec<u8>) {
    match subject {
        Subject::Notarize { proposal } => {
            (notarize_namespace(namespace), proposal.encode().to_vec())
        }
        Subject::Nullify { round } => (nullify_namespace(namespace), round.encode().to_vec()),
        Subject::Finalize { proposal } => {
            (finalize_namespace(namespace), proposal.encode().to_vec())
        }
    }
}

/// Produces the seed namespace and message bytes for a given vote context.
///
/// Returns the final namespace (with the seed suffix) and the serialized
/// message to sign or verify.
#[inline]
pub(crate) fn seed_namespace_and_message<D: Digest>(
    namespace: &[u8],
    subject: &Subject<'_, D>,
) -> (Vec<u8>, Vec<u8>) {
    (
        seed_namespace(namespace),
        match subject {
            Subject::Notarize { proposal } | Subject::Finalize { proposal } => {
                proposal.round.encode().to_vec()
            }
            Subject::Nullify { round } => round.encode().to_vec(),
        },
    )
}
