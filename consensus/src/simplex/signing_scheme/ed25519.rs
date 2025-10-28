//! Ed25519 implementation of the [`Scheme`] trait for `simplex`.
//!
//! [`Scheme`] is **attributable**: individual signatures can be safely
//! presented to some third party as evidence of either liveness or of committing a fault. Certificates
//! contain signer indices alongside individual signatures, enabling secure
//! per-validator activity tracking and fault detection.

use crate::{
    simplex::{
        signing_scheme::{self, utils::Signers, vote_namespace_and_message},
        types::{OrderedExt, Vote, VoteContext, VoteVerification},
    },
    types::Round,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadRangeExt, Write};
use commonware_cryptography::{
    ed25519::{self, Batch},
    BatchVerifier, Digest, Signer as _, Verifier as _,
};
use commonware_utils::set::Ordered;
use rand::{CryptoRng, Rng};
use std::collections::BTreeSet;

/// Ed25519 implementation of the [`Scheme`] trait.
#[derive(Clone, Debug)]
pub struct Scheme {
    /// Participants in the committee.
    participants: Ordered<ed25519::PublicKey>,
    /// Key used for generating signatures.
    signer: Option<(u32, ed25519::PrivateKey)>,
}

impl Scheme {
    /// Creates a new scheme instance with the provided key material.
    ///
    /// Participants use the same key for both identity and consensus.
    ///
    /// If the provided private key does not match any consensus key in the committee,
    /// the instance will act as a verifier (unable to generate signatures).
    pub fn new(
        participants: Ordered<ed25519::PublicKey>,
        private_key: ed25519::PrivateKey,
    ) -> Self {
        let signer = participants
            .position(&private_key.public_key())
            .map(|index| (index as u32, private_key));

        Self {
            participants,
            signer,
        }
    }

    /// Builds a verifier that can authenticate votes without generating signatures.
    ///
    /// Participants use the same key for both identity and consensus.
    pub fn verifier(participants: Ordered<ed25519::PublicKey>) -> Self {
        Self {
            participants,
            signer: None,
        }
    }

    /// Stage a certificate for batch verification.
    fn batch_verify_certificate<'a, D: Digest>(
        &self,
        batch: &mut Batch,
        namespace: &[u8],
        context: VoteContext<'a, D>,
        certificate: &'a Certificate,
    ) -> bool {
        // If the certificate signers length does not match the participant set, return false.
        if certificate.signers.len() != self.participants.len() {
            return false;
        }

        // If the certificate signers and signatures counts differ, return false.
        if certificate.signers.count() != certificate.signatures.len() {
            return false;
        }

        // If the certificate does not meet the quorum, return false.
        if certificate.signers.count() < self.participants.quorum() as usize {
            return false;
        }

        // Add the certificate to the batch.
        let (namespace, message) = vote_namespace_and_message(namespace, context);
        for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
            let Some(public_key) = self.participants.get(signer as usize) else {
                return false;
            };

            batch.add(
                Some(namespace.as_ref()),
                message.as_ref(),
                public_key,
                signature,
            );
        }

        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate {
    /// Bitmap of validator indices that contributed signatures.
    pub signers: Signers,
    /// Ed25519 signatures emitted by the respective validators ordered by signer index.
    pub signatures: Vec<ed25519::Signature>,
}

impl Write for Certificate {
    fn write(&self, writer: &mut impl BufMut) {
        self.signers.write(writer);
        self.signatures.write(writer);
    }
}

impl EncodeSize for Certificate {
    fn encode_size(&self) -> usize {
        self.signers.encode_size() + self.signatures.encode_size()
    }
}

impl Read for Certificate {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, participants: &usize) -> Result<Self, Error> {
        let signers = Signers::read_cfg(reader, participants)?;
        if signers.count() == 0 {
            return Err(Error::Invalid(
                "consensus::simplex::signing_scheme::ed25519::Certificate",
                "Certificate contains no signers",
            ));
        }

        let signatures = Vec::<ed25519::Signature>::read_range(reader, ..=*participants)?;
        if signers.count() != signatures.len() {
            return Err(Error::Invalid(
                "consensus::simplex::signing_scheme::ed25519::Certificate",
                "Signers and signatures counts differ",
            ));
        }

        Ok(Self {
            signers,
            signatures,
        })
    }
}

impl signing_scheme::Scheme for Scheme {
    type PublicKey = ed25519::PublicKey;
    type Signature = ed25519::Signature;
    type Certificate = Certificate;
    type Seed = ();

    fn me(&self) -> Option<u32> {
        self.signer.as_ref().map(|(index, _)| *index)
    }

    fn participants(&self) -> &Ordered<Self::PublicKey> {
        &self.participants
    }

    fn sign_vote<D: Digest>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
    ) -> Option<Vote<Self>> {
        let (index, private_key) = self.signer.as_ref()?;

        let (namespace, message) = vote_namespace_and_message(namespace, context);
        let signature = private_key.sign(Some(namespace.as_ref()), message.as_ref());

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
        let Some(public_key) = self.participants.get(vote.signer as usize) else {
            return false;
        };

        let (namespace, message) = vote_namespace_and_message(namespace, context);
        public_key.verify(Some(namespace.as_ref()), message.as_ref(), &vote.signature)
    }

    fn verify_votes<R, D, I>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        votes: I,
    ) -> VoteVerification<Self>
    where
        R: Rng + CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Vote<Self>>,
    {
        let (namespace, message) = vote_namespace_and_message(namespace, context);

        let mut invalid = BTreeSet::new();
        let mut candidates = Vec::new();
        let mut batch = Batch::new();

        for vote in votes.into_iter() {
            let Some(public_key) = self.participants.get(vote.signer as usize) else {
                invalid.insert(vote.signer);
                continue;
            };

            batch.add(
                Some(namespace.as_ref()),
                message.as_ref(),
                public_key,
                &vote.signature,
            );

            candidates.push((vote, public_key));
        }

        if !candidates.is_empty() && !batch.verify(rng) {
            // Batch failed: fall back to per-signer verification to isolate faulty votes.
            for (vote, public_key) in &candidates {
                if !public_key.verify(Some(namespace.as_ref()), message.as_ref(), &vote.signature) {
                    invalid.insert(vote.signer);
                }
            }
        }

        let verified = candidates
            .into_iter()
            .filter_map(|(vote, _)| {
                if invalid.contains(&vote.signer) {
                    None
                } else {
                    Some(vote)
                }
            })
            .collect();

        VoteVerification::new(verified, invalid.into_iter().collect())
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
        if entries.len() < self.participants.quorum() as usize {
            return None;
        }

        // Sort the signatures by signer index.
        entries.sort_by_key(|(signer, _)| *signer);
        let (signer, signatures): (Vec<u32>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::from(self.participants.len(), signer);

        Some(Certificate {
            signers,
            signatures,
        })
    }

    fn verify_certificate<R: Rng + CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        certificate: &Self::Certificate,
    ) -> bool {
        let mut batch = Batch::new();
        if !self.batch_verify_certificate(&mut batch, namespace, context, certificate) {
            return false;
        }

        batch.verify(rng)
    }

    fn verify_certificates<'a, R, D, I>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        certificates: I,
    ) -> bool
    where
        R: Rng + CryptoRng,
        D: Digest,
        I: Iterator<Item = (VoteContext<'a, D>, &'a Self::Certificate)>,
    {
        let mut batch = Batch::new();
        for (context, certificate) in certificates {
            if !self.batch_verify_certificate(&mut batch, namespace, context, certificate) {
                return false;
            }
        }

        batch.verify(rng)
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
            mocks::fixtures::{ed25519, Fixture},
            signing_scheme::Scheme as _,
            types::{Proposal, VoteContext},
        },
        types::Round,
    };
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Hasher, Sha256};
    use commonware_utils::quorum;
    use rand::{
        rngs::{OsRng, StdRng},
        thread_rng, SeedableRng,
    };

    const NAMESPACE: &[u8] = b"ed25519-signing-scheme";

    fn setup_signers(n: u32, seed: u64) -> (Vec<Scheme>, Ordered<ed25519::PublicKey>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519(&mut rng, n);

        (schemes, participants.into())
    }

    fn sample_proposal(round: u64, view: u64, tag: u8) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(round, view),
            view.saturating_sub(1),
            Sha256::hash(&[tag]),
        )
    }

    #[test]
    fn test_sign_vote_roundtrip_for_each_context() {
        let (schemes, _) = setup_signers(4, 42);
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
    fn test_verify_votes_filters_bad_signers() {
        let (schemes, _) = setup_signers(5, 42);
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

        let scheme = &schemes[0];
        let verification = scheme.verify_votes(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
            votes.clone(),
        );
        assert!(verification.invalid_signers.is_empty());
        assert_eq!(verification.verified.len(), quorum);

        // Invalid signer index should be detected.
        votes[0].signer = 999;
        let verification = scheme.verify_votes(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
            votes.clone(),
        );
        assert_eq!(verification.invalid_signers, vec![999]);
        assert_eq!(verification.verified.len(), quorum - 1);

        // Invalid signature should be detected.
        votes[0].signer = 0;
        votes[0].signature = votes[1].signature.clone();
        let verification = scheme.verify_votes(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
            votes,
        );
        assert_eq!(verification.invalid_signers, vec![0]);
        assert_eq!(verification.verified.len(), quorum - 1);
    }

    #[test]
    fn test_assemble_certificate_sorts_signers() {
        let (schemes, _) = setup_signers(4, 42);
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
        assert_eq!(
            certificate.signers.iter().collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn test_assemble_certificate_requires_quorum() {
        let (schemes, _) = setup_signers(4, 42);
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
    fn test_assemble_certificate_rejects_out_of_range_signer() {
        let (schemes, _) = setup_signers(4, 42);
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
    #[should_panic(expected = "duplicate signer index: 2")]
    fn test_assemble_certificate_rejects_duplicate_signers() {
        let (schemes, _) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 25, 13);

        let mut votes: Vec<_> = schemes
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

        votes.push(votes.last().unwrap().clone());

        schemes[0].assemble_certificate(votes);
    }

    #[test]
    fn test_verify_certificate_detects_corruption() {
        let (schemes, participants) = setup_signers(4, 42);
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

        let verifier = Scheme::verifier(participants);
        assert!(verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));

        let mut corrupted = certificate.clone();
        corrupted.signatures[0] = corrupted.signatures[1].clone();
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
    fn test_certificate_codec_roundtrip() {
        let (schemes, _) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 17, 9);

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
        let decoded = Certificate::decode_cfg(encoded, &schemes.len()).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_scheme_clone_and_verifier() {
        let (schemes, participants) = setup_signers(4, 42);
        let signer = schemes[0].clone();
        let proposal = sample_proposal(0, 21, 11);

        assert!(
            signer
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Notarize {
                        proposal: &proposal,
                    },
                )
                .is_some(),
            "signer should produce votes"
        );

        let verifier = Scheme::verifier(participants);
        assert!(
            verifier
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Notarize {
                        proposal: &proposal,
                    },
                )
                .is_none(),
            "verifier should not produce votes"
        );
    }

    #[test]
    fn test_certificate_decode_validation() {
        let (schemes, participants) = setup_signers(4, 42);
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

        // Well-formed certificate decodes successfully.
        let encoded = certificate.encode();
        let mut cursor = &encoded[..];
        let decoded =
            Certificate::read_cfg(&mut cursor, &participants.len()).expect("decode certificate");
        assert_eq!(decoded, certificate);

        // Certificate with no signers is rejected.
        let empty = Certificate {
            signers: Signers::from(participants.len(), std::iter::empty::<u32>()),
            signatures: Vec::new(),
        };
        assert!(Certificate::decode_cfg(empty.encode(), &participants.len()).is_err());

        // Certificate with mismatched signature count is rejected.
        let mismatched = Certificate {
            signers: Signers::from(participants.len(), [0u32, 1]),
            signatures: vec![certificate.signatures[0].clone()],
        };
        assert!(Certificate::decode_cfg(mismatched.encode(), &participants.len()).is_err());

        // Certificate containing more signers than the participant set is rejected.
        let mut signers = certificate.signers.iter().collect::<Vec<_>>();
        signers.push(participants.len() as u32);
        let mut signatures = certificate.signatures.clone();
        signatures.push(certificate.signatures[0].clone());
        let extended = Certificate {
            signers: Signers::from(participants.len() + 1, signers),
            signatures,
        };
        assert!(Certificate::decode_cfg(extended.encode(), &participants.len()).is_err());
    }

    #[test]
    fn test_verify_certificate() {
        let (schemes, participants) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 21, 11);

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

        let verifier = Scheme::verifier(participants);
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
    fn test_verify_certificate_rejects_sub_quorum() {
        let (schemes, participants) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 23, 12);

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
        let mut signers: Vec<u32> = truncated.signers.iter().collect();
        signers.pop();
        truncated.signers = Signers::from(participants.len(), signers);
        truncated.signatures.pop();

        let verifier = Scheme::verifier(participants);
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
    fn test_verify_certificate_rejects_unknown_signer() {
        let (schemes, participants) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 25, 13);

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

        let mut certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        let mut signers: Vec<u32> = certificate.signers.iter().collect();
        signers.push(participants.len() as u32);
        certificate.signers = Signers::from(participants.len() + 1, signers);
        certificate
            .signatures
            .push(certificate.signatures[0].clone());

        let verifier = Scheme::verifier(participants);
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_invalid_certificate_signers_size() {
        let (schemes, participants) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 26, 14);

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

        let mut certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        // The certificate is valid
        let verifier = Scheme::verifier(participants.clone());
        assert!(verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
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
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));
    }

    #[test]
    fn test_verify_certificate_rejects_mismatched_signature_count() {
        let (schemes, participants) = setup_signers(4, 42);
        let proposal = sample_proposal(0, 27, 14);

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

        let mut certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");
        certificate.signatures.pop();

        let verifier = Scheme::verifier(participants);
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
            &certificate,
        ));
    }

    #[test]
    fn test_verify_certificates_batch_detects_failure() {
        let (schemes, participants) = setup_signers(4, 42);
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
        let mut bad_certificate = schemes[0]
            .assemble_certificate(votes_b)
            .expect("assemble certificate");
        bad_certificate.signatures[0] = bad_certificate.signatures[1].clone();

        let verifier = Scheme::verifier(participants);
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
}
