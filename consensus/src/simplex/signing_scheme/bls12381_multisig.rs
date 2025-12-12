//! BLS12-381 multi-signature implementation of the [`Scheme`] trait for `simplex`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be
//! used by an external observer as evidence of either liveness or of committing a fault.
//! Certificates contain signer indices alongside an aggregated signature,
//! enabling secure per-validator activity tracking and conflict detection.

use crate::{
    simplex::{
        signing_scheme::{self, utils::Signers, vote_namespace_and_message},
        types::{Signature, SignatureVerification, Subject},
    },
    types::Round,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Private,
        ops::{
            aggregate_signatures, aggregate_verify_multiple_public_keys, compute_public,
            sign_message, verify_message,
        },
        variant::Variant,
    },
    Digest, PublicKey,
};
use commonware_utils::ordered::{BiMap, Quorum, Set};
use rand::{CryptoRng, Rng};
use std::{collections::BTreeSet, fmt::Debug};

/// BLS12-381 multi-signature implementation of the [`Scheme`] trait.
#[derive(Clone, Debug)]
pub struct Scheme<P: PublicKey, V: Variant> {
    /// Participants in the committee.
    participants: BiMap<P, V::Public>,
    /// Key used for generating signatures.
    signer: Option<(u32, Private)>,
}

impl<P: PublicKey, V: Variant> Scheme<P, V> {
    /// Creates a new scheme instance with the provided key material.
    ///
    /// Participants have both an identity key and a consensus key. The identity key
    /// is used for committee ordering and indexing, while the consensus key is used for
    /// signing and verification.
    ///
    /// Returns `None` if the provided private key does not match any consensus key
    /// in the committee.
    pub fn signer(participants: BiMap<P, V::Public>, private_key: Private) -> Option<Self> {
        let public_key = compute_public::<V>(&private_key);
        let signer = participants
            .values()
            .iter()
            .position(|p| p == &public_key)
            .map(|index| (index as u32, private_key))?;

        Some(Self {
            participants,
            signer: Some(signer),
        })
    }

    /// Builds a verifier that can authenticate votes and certificates.
    ///
    /// Participants have both an identity key and a consensus key. The identity key
    /// is used for committee ordering and indexing, while the consensus key is used for
    /// verification.
    pub const fn verifier(participants: BiMap<P, V::Public>) -> Self {
        Self {
            participants,
            signer: None,
        }
    }
}

/// Certificate formed by an aggregated BLS12-381 signature plus the signers that
/// contributed to it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<V: Variant> {
    /// Bitmap of validator indices that contributed signatures.
    pub signers: Signers,
    /// Aggregated BLS signature covering all votes in this certificate.
    pub signature: V::Signature,
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
                "consensus::simplex::signing_scheme::bls12381_multisig::Certificate",
                "Certificate contains no signers",
            ));
        }

        let signature = V::Signature::read(reader)?;

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
        let signature = V::Signature::arbitrary(u)?;
        Ok(Self { signers, signature })
    }
}

impl<P: PublicKey, V: Variant + Send + Sync> signing_scheme::Scheme for Scheme<P, V> {
    type PublicKey = P;
    type Signature = V::Signature;
    type Certificate = Certificate<V>;
    type Seed = ();

    fn me(&self) -> Option<u32> {
        self.signer.as_ref().map(|(index, _)| *index)
    }

    fn participants(&self) -> &Set<Self::PublicKey> {
        &self.participants
    }

    fn sign_vote<D: Digest>(
        &self,
        namespace: &[u8],
        subject: Subject<'_, D>,
    ) -> Option<Signature<Self>> {
        let (index, private_key) = self.signer.as_ref()?;

        let (namespace, message) = vote_namespace_and_message(namespace, subject);
        let signature = sign_message::<V>(private_key, Some(namespace.as_ref()), message.as_ref());

        Some(Signature {
            signer: *index,
            signature,
        })
    }

    fn verify_vote<D: Digest>(
        &self,
        namespace: &[u8],
        subject: Subject<'_, D>,
        signature: &Signature<Self>,
    ) -> bool {
        let Some(public_key) = self.participants.value(signature.signer as usize) else {
            return false;
        };

        let (namespace, message) = vote_namespace_and_message(namespace, subject);
        verify_message::<V>(
            public_key,
            Some(namespace.as_ref()),
            message.as_ref(),
            &signature.signature,
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
        I: IntoIterator<Item = Signature<Self>>,
    {
        let mut invalid = BTreeSet::new();
        let mut candidates = Vec::new();
        let mut publics = Vec::new();
        let mut sigs = Vec::new();
        for sig in signatures.into_iter() {
            let Some(public_key) = self.participants.value(sig.signer as usize) else {
                invalid.insert(sig.signer);
                continue;
            };

            publics.push(*public_key);
            sigs.push(sig.signature);
            candidates.push(sig);
        }

        // If there are no candidates to verify, return before doing any work.
        if candidates.is_empty() {
            return SignatureVerification::new(candidates, invalid.into_iter().collect());
        }

        // Verify the aggregate signature.
        let (namespace, message) = vote_namespace_and_message(namespace, subject);
        if aggregate_verify_multiple_public_keys::<V, _>(
            publics.iter(),
            Some(namespace.as_ref()),
            message.as_ref(),
            &aggregate_signatures::<V, _>(sigs.iter()),
        )
        .is_err()
        {
            for (sig, public_key) in candidates.iter().zip(publics.iter()) {
                if verify_message::<V>(
                    public_key,
                    Some(namespace.as_ref()),
                    message.as_ref(),
                    &sig.signature,
                )
                .is_err()
                {
                    invalid.insert(sig.signer);
                }
            }
        }

        // Collect the invalid signers.
        let verified = candidates
            .into_iter()
            .filter(|sig| !invalid.contains(&sig.signer))
            .collect();
        let invalid_signers: Vec<_> = invalid.into_iter().collect();

        SignatureVerification::new(verified, invalid_signers)
    }

    fn assemble_certificate<I>(&self, signatures: I) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Signature<Self>>,
    {
        // Collect the signers and signatures.
        let mut entries = Vec::new();
        for Signature { signer, signature } in signatures {
            if signer as usize >= self.participants.len() {
                return None;
            }

            entries.push((signer, signature));
        }
        if entries.len() < self.participants.quorum() as usize {
            return None;
        }

        // Produce signers and aggregate signature.
        let (signers, sigs): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::from(self.participants.len(), signers);
        let signature = aggregate_signatures::<V, _>(sigs.iter());

        Some(Certificate { signers, signature })
    }

    fn verify_certificate<R: Rng + CryptoRng, D: Digest>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        subject: Subject<'_, D>,
        certificate: &Self::Certificate,
    ) -> bool {
        // If the certificate signers length does not match the participant set, return false.
        if certificate.signers.len() != self.participants.len() {
            return false;
        }

        // If the certificate does not meet the quorum, return false.
        if certificate.signers.count() < self.participants.quorum() as usize {
            return false;
        }

        // Collect the public keys.
        let mut publics = Vec::with_capacity(certificate.signers.count());
        for signer in certificate.signers.iter() {
            let Some(public_key) = self.participants.value(signer as usize) else {
                return false;
            };

            publics.push(*public_key);
        }

        // Verify the aggregate signature.
        let (namespace, message) = vote_namespace_and_message(namespace, subject);
        aggregate_verify_multiple_public_keys::<V, _>(
            publics.iter(),
            Some(namespace.as_ref()),
            message.as_ref(),
            &certificate.signature,
        )
        .is_ok()
    }

    fn seed(&self, _: Round, _: &Self::Certificate) -> Option<Self::Seed> {
        None
    }

    fn is_attributable(&self) -> bool {
        true
    }

    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {
        self.participants.len()
    }

    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {
        u32::MAX as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            mocks::fixtures::{bls12381_multisig, Fixture},
            signing_scheme::Scheme as _,
            types::{Proposal, Subject},
        },
        types::{Epoch, Round, View},
    };
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{
        bls12381::primitives::{
            group::Element,
            variant::{MinPk, MinSig, Variant},
        },
        ed25519,
        sha256::Digest as Sha256Digest,
        Hasher, Sha256,
    };
    use commonware_utils::quorum_from_slice;
    use rand::{
        rngs::{OsRng, StdRng},
        thread_rng, SeedableRng,
    };

    const NAMESPACE: &[u8] = b"bls-multisig-signing-scheme";

    #[allow(clippy::type_complexity)]
    fn setup_signers<V: Variant>(
        n: u32,
        seed: u64,
    ) -> (
        Vec<Scheme<ed25519::PublicKey, V>>,
        BiMap<ed25519::PublicKey, V::Public>,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let Fixture { schemes, .. } = bls12381_multisig::<V, _>(&mut rng, n);
        let participants = schemes.first().unwrap().participants.clone();

        (schemes, participants)
    }

    fn sample_proposal(round: u64, view: u64, tag: u8) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(Epoch::new(round), View::new(view)),
            View::new(view).previous().unwrap(),
            Sha256::hash(&[tag]),
        )
    }

    fn sign_vote_roundtrip_for_each_context<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 42);
        let scheme = &schemes[0];

        let proposal = sample_proposal(0, 2, 1);
        let vote = scheme
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
            &vote
        ));

        let vote = scheme
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
            &vote
        ));

        let vote = scheme
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
            &vote
        ));
    }

    #[test]
    fn test_sign_vote_roundtrip_for_each_context() {
        sign_vote_roundtrip_for_each_context::<MinPk>();
        sign_vote_roundtrip_for_each_context::<MinSig>();
    }

    fn verifier_cannot_sign<V: Variant>() {
        let (_, participants) = setup_signers::<V>(4, 42);
        let verifier = Scheme::<ed25519::PublicKey, V>::verifier(participants);

        let proposal = sample_proposal(0, 3, 2);
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
    fn test_verifier_cannot_sign_min() {
        verifier_cannot_sign::<MinPk>();
        verifier_cannot_sign::<MinSig>();
    }

    fn verify_votes_filters_bad_signers<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(5, 42);
        let quorum = quorum_from_slice(&schemes) as usize;
        let proposal = sample_proposal(0, 5, 3);

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

        // Invalid signer index should be detected.
        votes[0].signer = 999;
        let verification = schemes[0].verify_votes(
            &mut thread_rng(),
            NAMESPACE,
            Subject::Notarize {
                proposal: &proposal,
            },
            votes.clone(),
        );
        assert_eq!(verification.invalid_signers, vec![999]);
        assert_eq!(verification.verified.len(), quorum - 1);

        // Invalid signature should be detected.
        votes[0].signer = 0;
        votes[0].signature = votes[1].signature;
        let verification = schemes[0].verify_votes(
            &mut thread_rng(),
            NAMESPACE,
            Subject::Notarize {
                proposal: &proposal,
            },
            votes,
        );
        assert_eq!(verification.invalid_signers, vec![0]);
        assert_eq!(verification.verified.len(), quorum - 1);
    }

    #[test]
    fn test_verify_votes_filters_bad_signers() {
        verify_votes_filters_bad_signers::<MinPk>();
        verify_votes_filters_bad_signers::<MinSig>();
    }

    fn assemble_certificate_sorts_signers<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 42);
        let proposal = sample_proposal(0, 7, 4);

        let votes = [
            schemes[2]
                .sign_vote(
                    NAMESPACE,
                    Subject::Finalize {
                        proposal: &proposal,
                    },
                )
                .unwrap(),
            schemes[0]
                .sign_vote(
                    NAMESPACE,
                    Subject::Finalize {
                        proposal: &proposal,
                    },
                )
                .unwrap(),
            schemes[1]
                .sign_vote(
                    NAMESPACE,
                    Subject::Finalize {
                        proposal: &proposal,
                    },
                )
                .unwrap(),
        ];

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");
        assert_eq!(certificate.signers.count(), 3);
        assert_eq!(
            certificate.signers.iter().collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn test_assemble_certificate_sorts_signers() {
        assemble_certificate_sorts_signers::<MinPk>();
        assemble_certificate_sorts_signers::<MinSig>();
    }

    fn assemble_certificate_requires_quorum<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 42);
        let proposal = sample_proposal(0, 9, 5);

        let votes: Vec<_> = schemes
            .iter()
            .take(2)
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

    fn assemble_certificate_rejects_out_of_range_signer<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 42);
        let proposal = sample_proposal(0, 13, 7);

        let mut votes: Vec<_> = schemes
            .iter()
            .take(3)
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
        votes[0].signer = 42;

        assert!(schemes[0].assemble_certificate(votes).is_none());
    }

    #[test]
    fn test_assemble_certificate_rejects_out_of_range_signer() {
        assemble_certificate_rejects_out_of_range_signer::<MinPk>();
        assemble_certificate_rejects_out_of_range_signer::<MinSig>();
    }

    fn verify_certificate_detects_corruption<V: Variant>() {
        let (schemes, participants) = setup_signers::<V>(4, 42);
        let proposal = sample_proposal(0, 15, 8);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
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

        let verifier = Scheme::verifier(participants);
        assert!(verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            Subject::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));

        let mut corrupted = certificate;
        corrupted.signature = V::Signature::zero();
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            Subject::Finalize {
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
        let (schemes, _) = setup_signers::<V>(4, 42);
        let proposal = sample_proposal(0, 21, 11);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
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
        let decoded = Certificate::<V>::decode_cfg(encoded, &schemes.len()).expect("decode");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_certificate_codec_roundtrip() {
        certificate_codec_roundtrip::<MinPk>();
        certificate_codec_roundtrip::<MinSig>();
    }

    fn scheme_clone_and_into_verifier<V: Variant>() {
        let (schemes, participants) = setup_signers::<V>(4, 42);
        let proposal = sample_proposal(0, 23, 12);

        let clone = schemes[0].clone();
        assert!(
            clone
                .sign_vote(
                    NAMESPACE,
                    Subject::Notarize {
                        proposal: &proposal,
                    },
                )
                .is_some(),
            "cloned signer should retain signing capability"
        );

        let verifier = Scheme::<ed25519::PublicKey, V>::verifier(participants);
        assert!(
            verifier
                .sign_vote(
                    NAMESPACE,
                    Subject::Notarize {
                        proposal: &proposal,
                    },
                )
                .is_none(),
            "verifier must not sign votes"
        );
    }

    #[test]
    fn test_scheme_clone_and_into_verifier() {
        scheme_clone_and_into_verifier::<MinPk>();
        scheme_clone_and_into_verifier::<MinSig>();
    }

    fn verify_certificate<V: Variant>() {
        let (schemes, participants) = setup_signers::<V>(4, 42);
        let quorum = quorum_from_slice(&schemes) as usize;
        let proposal = sample_proposal(0, 23, 12);

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

        let verifier = Scheme::verifier(participants);
        assert!(verifier.verify_certificate(
            &mut OsRng,
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

    fn verify_certificates_batch<V: Variant>() {
        let (schemes, participants) = setup_signers::<V>(4, 42);
        let proposal_a = sample_proposal(0, 23, 12);
        let proposal_b = sample_proposal(1, 24, 13);

        let votes_a: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        Subject::Notarize {
                            proposal: &proposal_a,
                        },
                    )
                    .unwrap()
            })
            .collect();
        let votes_b: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        Subject::Finalize {
                            proposal: &proposal_b,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let certificate_a = schemes[0]
            .assemble_certificate(votes_a)
            .expect("assemble certificate");
        let certificate_b = schemes[0]
            .assemble_certificate(votes_b)
            .expect("assemble certificate");

        let verifier = Scheme::verifier(participants);
        let mut iter = [
            (
                Subject::Notarize {
                    proposal: &proposal_a,
                },
                &certificate_a,
            ),
            (
                Subject::Finalize {
                    proposal: &proposal_b,
                },
                &certificate_b,
            ),
        ]
        .into_iter();

        assert!(verifier.verify_certificates(&mut thread_rng(), NAMESPACE, &mut iter));
    }

    #[test]
    fn test_verify_certificates_batch() {
        verify_certificates_batch::<MinPk>();
        verify_certificates_batch::<MinSig>();
    }

    fn verify_certificates_batch_detects_failure<V: Variant>() {
        let (schemes, participants) = setup_signers::<V>(4, 42);
        let proposal_a = sample_proposal(0, 25, 14);
        let proposal_b = sample_proposal(1, 26, 15);

        let votes_a: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        Subject::Notarize {
                            proposal: &proposal_a,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let votes_b: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        Subject::Finalize {
                            proposal: &proposal_b,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let certificate_a = schemes[0]
            .assemble_certificate(votes_a)
            .expect("assemble certificate");
        let mut bad_certificate = schemes[0]
            .assemble_certificate(votes_b)
            .expect("assemble certificate");
        bad_certificate.signature = certificate_a.signature;

        let verifier = Scheme::verifier(participants);
        let mut iter = [
            (
                Subject::Notarize {
                    proposal: &proposal_a,
                },
                &certificate_a,
            ),
            (
                Subject::Finalize {
                    proposal: &proposal_b,
                },
                &bad_certificate,
            ),
        ]
        .into_iter();

        assert!(!verifier.verify_certificates(&mut thread_rng(), NAMESPACE, &mut iter));
    }

    #[test]
    fn test_verify_certificates_batch_detects_failure() {
        verify_certificates_batch_detects_failure::<MinPk>();
        verify_certificates_batch_detects_failure::<MinSig>();
    }

    fn verify_certificate_rejects_sub_quorum<V: Variant>() {
        let (schemes, participants) = setup_signers::<V>(4, 42);
        let proposal = sample_proposal(0, 17, 9);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
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

        let mut truncated = certificate;
        let mut signers: Vec<u32> = truncated.signers.iter().collect();
        signers.pop();
        truncated.signers = Signers::from(participants.len(), signers);

        let verifier = Scheme::verifier(participants);
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            Subject::Finalize {
                proposal: &proposal,
            },
            &truncated,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_sub_quorum() {
        verify_certificate_rejects_sub_quorum::<MinPk>();
        verify_certificate_rejects_sub_quorum::<MinSig>();
    }

    fn verify_certificate_rejects_unknown_signer<V: Variant>() {
        let (schemes, participants) = setup_signers::<V>(4, 42);
        let proposal = sample_proposal(0, 19, 10);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
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

        let mut certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        let mut signers: Vec<u32> = certificate.signers.iter().collect();
        signers.push(participants.len() as u32);
        certificate.signers = Signers::from(participants.len() + 1, signers);

        let verifier = Scheme::verifier(participants);
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            Subject::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_unknown_signer() {
        verify_certificate_rejects_unknown_signer::<MinPk>();
        verify_certificate_rejects_unknown_signer::<MinSig>();
    }

    fn verify_certificate_rejects_invalid_certificate_signers_size<V: Variant>() {
        let (schemes, participants) = setup_signers::<V>(4, 42);
        let proposal = sample_proposal(0, 20, 11);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
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

        let mut certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        // The certificate is valid
        let verifier = Scheme::verifier(participants.clone());
        assert!(verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            Subject::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));

        // Make the signers bitmap size smaller
        let signers: Vec<u32> = certificate.signers.iter().collect();
        certificate.signers = Signers::from(participants.len() - 1, signers);

        // The certificate verification should fail
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            Subject::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_invalid_certificate_signers_size() {
        verify_certificate_rejects_invalid_certificate_signers_size::<MinPk>();
        verify_certificate_rejects_invalid_certificate_signers_size::<MinSig>();
    }

    fn certificate_decode_checks_sorted_unique_signers<V: Variant>() {
        let (schemes, participants) = setup_signers::<V>(4, 42);
        let proposal = sample_proposal(0, 19, 10);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
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

        // Well-formed certificate decodes successfully.
        let encoded = certificate.encode();
        let mut cursor = &encoded[..];
        let decoded = Certificate::<V>::read_cfg(&mut cursor, &participants.len())
            .expect("decode certificate");
        assert_eq!(decoded, certificate);

        // Certificate with no signers is rejected.
        let empty = Certificate::<V> {
            signers: Signers::from(participants.len(), std::iter::empty::<u32>()),
            signature: certificate.signature,
        };
        assert!(Certificate::<V>::decode_cfg(empty.encode(), &participants.len()).is_err());

        // Certificate containing more signers than the participant set is rejected.
        let mut signers = certificate.signers.iter().collect::<Vec<_>>();
        signers.push(participants.len() as u32);
        let extended = Certificate::<V> {
            signers: Signers::from(participants.len() + 1, signers),
            signature: certificate.signature,
        };
        assert!(Certificate::<V>::decode_cfg(extended.encode(), &participants.len()).is_err());
    }

    #[test]
    fn test_certificate_decode_checks_sorted_unique_signers() {
        certificate_decode_checks_sorted_unique_signers::<MinPk>();
        certificate_decode_checks_sorted_unique_signers::<MinSig>();
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
