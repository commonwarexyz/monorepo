//! BLS12-381 multisignature implementation of the signing scheme abstraction.
//!
//! Validators author plain BLS signatures which are then aggregated into a single
//! certificate signature. The certificate retains signer indices so verifiers can
//! reconstruct which public keys contributed to the aggregate.

use crate::{
    simplex::{
        signing_scheme::{self, vote_namespace_and_message},
        types::{Vote, VoteContext, VoteVerification},
    },
    types::Round,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Private,
        ops::{
            aggregate_signatures, aggregate_verify_multiple_public_keys, compute_public,
            sign_message, verify_message,
        },
        variant::Variant,
    },
    Digest,
};
use commonware_utils::quorum_from_slice;
use rand::{CryptoRng, Rng};
use std::{collections::BTreeSet, fmt::Debug};

/// BLS multisignature implementation of the [`Scheme`] trait.
///
/// The scheme keeps the participant ordering plus (optionally) the local private
/// key so it can produce votes as well as batch-verify signatures from peers.
#[derive(Clone, Debug)]
pub struct Scheme<V: Variant> {
    /// Participant set used for signer indexing and batch verification.
    participants: Vec<V::Public>,
    /// Optional local signing key paired with its participant index.
    signer: Option<(u32, Private)>,
    /// Quorum (2f+1) computed from the participant set.
    quorum: u32,
}

impl<V: Variant> Scheme<V> {
    /// Creates a new scheme instance with the provided key material.
    ///
    /// * `participants` - ordered validator set used for verification.
    /// * `private_key` - optional secret key enabling signing capabilities.
    pub fn new(participants: Vec<V::Public>, private_key: Private) -> Self {
        let signer = participants
            .iter()
            .position(|p| *p == compute_public::<V>(&private_key))
            .map(|index| (index as u32, private_key));

        let quorum = quorum_from_slice(&participants);

        Self {
            participants,
            signer,
            quorum,
        }
    }

    /// Builds a pure verifier that can authenticate votes and certificates.
    pub fn verifier(participants: Vec<V::Public>) -> Self {
        let quorum = quorum_from_slice(&participants);

        Self {
            participants,
            signer: None,
            quorum,
        }
    }

    fn participant(&self, index: u32) -> Option<&V::Public> {
        self.participants.get(index as usize)
    }
}

/// Multisignature certificate: aggregate signature plus contributing signer indices.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<V: Variant> {
    /// Indices of the validators that contributed signatures (ascending order).
    pub signers: Vec<u32>,
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
        let signers = Vec::<u32>::read_range(reader, ..=*participants)?;

        if signers.is_empty() {
            return Err(Error::Invalid(
                "consensus::simplex::signing_scheme::bls12381_multisig::Certificate",
                "Certificate contains no signers",
            ));
        }

        if signers.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::Invalid(
                "consensus::simplex::signing_scheme::bls12381_multisig::Certificate",
                "Signers are not strictly increasing",
            ));
        }

        if signers
            .iter()
            .any(|signer| (*signer as usize) >= *participants)
        {
            return Err(Error::Invalid(
                "consensus::simplex::signing_scheme::bls12381_multisig::Certificate",
                "Signer index exceeds participant set",
            ));
        }

        let signature = V::Signature::read(reader)?;

        Ok(Self { signers, signature })
    }
}

impl<V: Variant + Send + Sync> signing_scheme::Scheme for Scheme<V> {
    type Signature = V::Signature;
    type Certificate = Certificate<V>;
    type Seed = ();

    fn sign_vote<D: Digest>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
    ) -> Option<Vote<Self>> {
        let (index, private_key) = self.signer.as_ref()?;

        let (namespace, message) = vote_namespace_and_message(namespace, context);
        let signature = sign_message::<V>(private_key, Some(namespace.as_ref()), message.as_ref());

        Some(Vote {
            signer: *index,
            signature,
        })
    }

    fn verify_vote<D: Digest>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        vote: &Vote<Self>,
    ) -> bool {
        let Some(public_key) = self.participant(vote.signer) else {
            return false;
        };

        let (namespace, message) = vote_namespace_and_message(namespace, context);
        verify_message::<V>(
            public_key,
            Some(namespace.as_ref()),
            message.as_ref(),
            &vote.signature,
        )
        .is_ok()
    }

    fn verify_votes<R, D, I>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        votes: I,
    ) -> VoteVerification<Self>
    where
        R: Rng + CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Vote<Self>>,
    {
        let mut invalid = BTreeSet::new();
        let mut candidates = Vec::new();
        let mut publics = Vec::new();
        let mut signatures = Vec::new();
        for vote in votes.into_iter() {
            let Some(public_key) = self.participant(vote.signer) else {
                invalid.insert(vote.signer);
                continue;
            };

            publics.push(*public_key);
            signatures.push(vote.signature);
            candidates.push(vote);
        }

        // If there are no candidates to verify, return before doing any work.
        if candidates.is_empty() {
            return VoteVerification::new(candidates, invalid.into_iter().collect());
        }

        // Verify the aggregate signature.
        let (namespace, message) = vote_namespace_and_message(namespace, context);
        if aggregate_verify_multiple_public_keys::<V, _>(
            publics.iter(),
            Some(namespace.as_ref()),
            message.as_ref(),
            &aggregate_signatures::<V, _>(signatures.iter()),
        )
        .is_err()
        {
            for (vote, public_key) in candidates.iter().zip(publics.iter()) {
                if verify_message::<V>(
                    public_key,
                    Some(namespace.as_ref()),
                    message.as_ref(),
                    &vote.signature,
                )
                .is_err()
                {
                    invalid.insert(vote.signer);
                }
            }
        }

        // Collect the invalid signers.
        let verified = candidates
            .into_iter()
            .filter(|vote| !invalid.contains(&vote.signer))
            .collect();
        let invalid_signers: Vec<_> = invalid.into_iter().collect();

        VoteVerification::new(verified, invalid_signers)
    }

    fn assemble_certificate<I>(&self, votes: I) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Vote<Self>>,
    {
        // Collect the signers and signatures.
        let mut entries = Vec::new();
        for Vote { signer, signature } in votes {
            if signer as usize >= self.participants.len() {
                return None;
            }

            entries.push((signer, signature));
        }
        if entries.len() < self.quorum as usize {
            return None;
        }

        // Sort the signers and aggregate the signatures.
        entries.sort_by_key(|(signer, _)| *signer);
        let (signers, signatures): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
        let signature = aggregate_signatures::<V, _>(signatures.iter());

        Some(Certificate { signers, signature })
    }

    fn verify_certificate<R: Rng + CryptoRng, D: Digest>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        certificate: &Self::Certificate,
    ) -> bool {
        // Ensure signers are valid.
        if certificate.signers.len() < self.quorum as usize {
            return false;
        }
        if certificate
            .signers
            .iter()
            .any(|signer| (*signer as usize) >= self.participants.len())
        {
            return false;
        }

        // Collect the public keys.
        let mut publics = Vec::with_capacity(certificate.signers.len());
        for signer in &certificate.signers {
            let Some(public_key) = self.participant(*signer) else {
                return false;
            };

            publics.push(*public_key);
        }

        // Verify the aggregate signature.
        let (namespace, message) = vote_namespace_and_message(namespace, context);
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
            signing_scheme::Scheme as _,
            types::{Proposal, VoteContext},
        },
        types::Round,
    };
    use commonware_codec::{Decode, Encode, Write};
    use commonware_cryptography::{
        bls12381::primitives::{
            group::{self, Element},
            ops::compute_public,
            variant::{MinPk, MinSig, Variant},
        },
        sha256::Digest as Sha256Digest,
        Hasher, Sha256,
    };
    use commonware_utils::quorum;
    use rand::{
        rngs::{OsRng, StdRng},
        thread_rng, SeedableRng,
    };

    const NAMESPACE: &[u8] = b"bls-multisig-signing-scheme";

    fn generate_private_keys(n: usize) -> Vec<group::Private> {
        let mut rng = StdRng::seed_from_u64(42);
        (0..n)
            .map(|_| group::Private::from_rand(&mut rng))
            .collect()
    }

    fn participants<V: Variant>(keys: &[group::Private]) -> Vec<V::Public> {
        keys.iter().map(|key| compute_public::<V>(key)).collect()
    }

    fn signing_schemes<V: Variant>(n: usize) -> (Vec<Scheme<V>>, Vec<V::Public>) {
        let keys = generate_private_keys(n);
        let participants = participants::<V>(&keys);
        let schemes = keys
            .into_iter()
            .map(|key| Scheme::new(participants.clone(), key))
            .collect();
        (schemes, participants)
    }

    fn sample_proposal(round: u64, view: u64, tag: u8) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(round, view),
            view.saturating_sub(1),
            Sha256::hash(&[tag]),
        )
    }

    fn sign_vote_roundtrip_for_each_context<V: Variant>() {
        let (schemes, _) = signing_schemes::<V>(4);
        let scheme = &schemes[0];

        let proposal = sample_proposal(0, 2, 1);
        let vote = scheme
            .sign_vote(
                NAMESPACE,
                VoteContext::Notarize {
                    proposal: &proposal,
                },
            )
            .unwrap();
        assert!(scheme.verify_vote(
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
            &vote
        ));

        let vote = scheme
            .sign_vote::<Sha256Digest>(
                NAMESPACE,
                VoteContext::Nullify {
                    round: proposal.round,
                },
            )
            .unwrap();
        assert!(scheme.verify_vote::<Sha256Digest>(
            NAMESPACE,
            VoteContext::Nullify {
                round: proposal.round,
            },
            &vote
        ));

        let vote = scheme
            .sign_vote(
                NAMESPACE,
                VoteContext::Finalize {
                    proposal: &proposal,
                },
            )
            .unwrap();
        assert!(scheme.verify_vote(
            NAMESPACE,
            VoteContext::Finalize {
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
        let (_, participants) = signing_schemes::<V>(3);
        let verifier = Scheme::<V>::verifier(participants);

        let proposal = sample_proposal(0, 3, 2);
        assert!(
            verifier
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Notarize {
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
        let (schemes, _) = signing_schemes::<V>(5);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 5, 3);

        let mut votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Notarize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let verification = schemes[0].verify_votes(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Notarize {
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
            VoteContext::Notarize {
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

    fn assemble_certificate_sorts_signers<V: Variant>() {
        let (schemes, _) = signing_schemes::<V>(4);
        let proposal = sample_proposal(0, 7, 4);

        let votes = [
            schemes[2]
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Finalize {
                        proposal: &proposal,
                    },
                )
                .unwrap(),
            schemes[0]
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Finalize {
                        proposal: &proposal,
                    },
                )
                .unwrap(),
            schemes[1]
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Finalize {
                        proposal: &proposal,
                    },
                )
                .unwrap(),
        ];

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");
        assert_eq!(certificate.signers.len(), 3);
        let mut sorted = certificate.signers.clone();
        sorted.sort();
        assert_eq!(certificate.signers, sorted);
    }

    #[test]
    fn test_assemble_certificate_sorts_signers() {
        assemble_certificate_sorts_signers::<MinPk>();
        assemble_certificate_sorts_signers::<MinSig>();
    }

    fn assemble_certificate_requires_quorum<V: Variant>() {
        let (schemes, _) = signing_schemes::<V>(4);
        let proposal = sample_proposal(0, 9, 5);

        let votes: Vec<_> = schemes
            .iter()
            .take(2)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Notarize {
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

    fn assemble_certificate_rejects_duplicate_signers<V: Variant>() {
        let (schemes, _) = signing_schemes::<V>(3);
        let proposal = sample_proposal(0, 11, 6);

        let vote = schemes[0]
            .sign_vote(
                NAMESPACE,
                VoteContext::Notarize {
                    proposal: &proposal,
                },
            )
            .unwrap();

        let votes = vec![vote.clone(), vote];
        assert!(schemes[0].assemble_certificate(votes).is_none());
    }

    #[test]
    fn test_assemble_certificate_rejects_duplicate_signers() {
        assemble_certificate_rejects_duplicate_signers::<MinPk>();
        assemble_certificate_rejects_duplicate_signers::<MinSig>();
    }

    fn assemble_certificate_rejects_out_of_range_signer<V: Variant>() {
        let (schemes, _) = signing_schemes::<V>(4);
        let proposal = sample_proposal(0, 13, 7);

        let mut votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Notarize {
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
        let (schemes, participants) = signing_schemes::<V>(4);
        let proposal = sample_proposal(0, 15, 8);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Finalize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        let verifier = Scheme::<V>::verifier(participants.clone());
        assert!(verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));

        let mut corrupted = certificate.clone();
        corrupted.signature = V::Signature::zero();
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
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
        let (schemes, _) = signing_schemes::<V>(4);
        let proposal = sample_proposal(0, 21, 11);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Notarize {
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
        let (schemes, participants) = signing_schemes::<V>(3);
        let proposal = sample_proposal(0, 23, 12);

        let clone = schemes[0].clone();
        assert!(
            clone
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Notarize {
                        proposal: &proposal,
                    },
                )
                .is_some(),
            "cloned signer should retain signing capability"
        );

        let verifier = Scheme::<V>::verifier(participants);
        assert!(
            verifier
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Notarize {
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
        let (schemes, participants) = signing_schemes::<V>(3);
        let proposal = sample_proposal(0, 23, 12);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum(schemes.len() as u32) as usize)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Finalize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        let verifier = Scheme::<V>::verifier(participants);
        assert!(verifier.verify_certificate(
            &mut OsRng,
            NAMESPACE,
            VoteContext::Finalize {
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
        let (schemes, participants) = signing_schemes::<V>(4);
        let proposal_a = sample_proposal(0, 23, 12);
        let proposal_b = sample_proposal(1, 24, 13);

        let votes_a: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Notarize {
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
                        VoteContext::Finalize {
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

        let verifier = Scheme::<V>::verifier(participants);
        let mut iter = [
            (
                VoteContext::Notarize {
                    proposal: &proposal_a,
                },
                &certificate_a,
            ),
            (
                VoteContext::Finalize {
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
        let (schemes, participants) = signing_schemes::<V>(4);
        let proposal_a = sample_proposal(0, 25, 14);
        let proposal_b = sample_proposal(1, 26, 15);

        let votes_a: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Notarize {
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
                        VoteContext::Finalize {
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

        let verifier = Scheme::<V>::verifier(participants);
        let mut iter = [
            (
                VoteContext::Notarize {
                    proposal: &proposal_a,
                },
                &certificate_a,
            ),
            (
                VoteContext::Finalize {
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
        let (schemes, participants) = signing_schemes::<V>(4);
        let proposal = sample_proposal(0, 17, 9);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Finalize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        let mut truncated = certificate.clone();
        truncated.signers.pop();

        let verifier = Scheme::<V>::verifier(participants);
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
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
        let (schemes, participants) = signing_schemes::<V>(4);
        let proposal = sample_proposal(0, 19, 10);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Finalize {
                            proposal: &proposal,
                        },
                    )
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        let mut invalid = certificate.clone();
        invalid.signers[0] = participants.len() as u32;

        let verifier = Scheme::<V>::verifier(participants);
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &invalid,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_unknown_signer() {
        verify_certificate_rejects_unknown_signer::<MinPk>();
        verify_certificate_rejects_unknown_signer::<MinSig>();
    }

    fn certificate_decode_checks_sorted_unique_signers<V: Variant>() {
        let (schemes, participants) = signing_schemes::<V>(4);
        let proposal = sample_proposal(0, 19, 10);

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        NAMESPACE,
                        VoteContext::Notarize {
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
        let mut cursor = &encoded[..];
        let decoded = Certificate::<V>::read_cfg(&mut cursor, &participants.len())
            .expect("decode certificate");
        assert_eq!(decoded, certificate);

        let duplicate = Certificate::<V> {
            signers: vec![0, 0],
            signature: certificate.signature,
        };
        let mut dup_bytes = Vec::new();
        duplicate.write(&mut dup_bytes);
        let mut dup_slice = dup_bytes.as_slice();
        assert!(Certificate::<V>::read_cfg(&mut dup_slice, &participants.len()).is_err());

        let unsorted = Certificate::<V> {
            signers: vec![1, 0],
            signature: certificate.signature,
        };
        let mut unsorted_bytes = Vec::new();
        unsorted.write(&mut unsorted_bytes);
        let mut unsorted_slice = unsorted_bytes.as_slice();
        assert!(Certificate::<V>::read_cfg(&mut unsorted_slice, &participants.len()).is_err());
    }

    #[test]
    fn test_certificate_decode_checks_sorted_unique_signers() {
        certificate_decode_checks_sorted_unique_signers::<MinPk>();
        certificate_decode_checks_sorted_unique_signers::<MinSig>();
    }
}
