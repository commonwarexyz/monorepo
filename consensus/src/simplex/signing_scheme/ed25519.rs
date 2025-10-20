//! Ed25519 quorum signature implementation of the signing scheme abstraction.
//!
//! This module batches ordinary Ed25519 signatures from a quorum of participants
//! and packages them as certificates that satisfy the generic consensus interface.

use crate::{
    simplex::{
        signing_scheme::{self, vote_namespace_and_message},
        types::{Participants, Vote, VoteContext, VoteVerification},
    },
    types::Round,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadRangeExt, Write};
use commonware_cryptography::{
    ed25519::{Batch, PrivateKey, PublicKey, Signature as Ed25519Signature},
    BatchVerifier, Digest, Signer as _, Verifier as _,
};
use rand::{CryptoRng, Rng};
use std::collections::BTreeSet;

/// Ed25519 implementation of the [`Scheme`] trait.
///
/// The scheme keeps the participant ordering plus (optionally) the local private
/// key so it can produce votes as well as batch-verify signatures from peers.
#[derive(Clone, Debug)]
pub struct Scheme {
    /// Participant set (sorted) used for signer indexing and batch verification.
    participants: Participants<PublicKey>,
    /// Optional local signing key paired with its participant index.
    signer: Option<(u32, PrivateKey)>,
}

impl Scheme {
    /// Creates a new scheme instance with the provided key material.
    ///
    /// * `participants` - ordered validator set used for verification.
    /// * `private_key` - optional secret key enabling signing capabilities.
    pub fn new(participants: impl Into<Participants<PublicKey>>, private_key: PrivateKey) -> Self {
        let participants = participants.into();

        let signer = participants
            .index(&private_key.public_key())
            .map(|index| (index, private_key));

        Self {
            participants,
            signer,
        }
    }

    /// Builds a pure verifier that can authenticate votes without signing.
    pub fn verifier(participants: impl Into<Participants<PublicKey>>) -> Self {
        Self {
            participants: participants.into(),
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
        // If the certificate does not meet the quorum, return false.
        if certificate.signers.len() < self.participants.quorum() as usize {
            return false;
        }
        if certificate.signers.len() != certificate.signatures.len() {
            return false;
        }
        if certificate
            .signers
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return false;
        }

        // Add the certificate to the batch.
        let (namespace, message) = vote_namespace_and_message(namespace, context);
        for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
            let Some(public_key) = self.participants.get(*signer) else {
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

/// Multi-signature certificate formed by collecting Ed25519 signatures plus
/// their signer indices sorted in ascending order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate {
    /// Indices of the validators that contributed signatures (ascending order).
    pub signers: Vec<u32>,
    /// Ed25519 signatures emitted by the respective validators.
    pub signatures: Vec<Ed25519Signature>,
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
        let signers = Vec::<u32>::read_range(reader, ..=*participants)?;

        if signers.is_empty() {
            return Err(Error::Invalid(
                "consensus::simplex::signing_scheme::ed25519::Certificate",
                "Certificate contains no signers",
            ));
        }

        let signatures = Vec::<Ed25519Signature>::read_range(reader, ..=*participants)?;

        if signers.len() != signatures.len() {
            return Err(Error::Invalid(
                "consensus::simplex::signing_scheme::ed25519::Certificate",
                "Signers and signatures counts differ",
            ));
        }

        if signers.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::Invalid(
                "consensus::simplex::signing_scheme::ed25519::Certificate",
                "Signatures are not sorted by public key index",
            ));
        }

        let certificate = Self {
            signers,
            signatures,
        };

        if certificate
            .signers
            .iter()
            .any(|signer| (*signer as usize) >= *participants)
        {
            return Err(Error::Invalid(
                "consensus::simplex::signing_scheme::ed25519::Certificate",
                "Signer index exceeds participant set",
            ));
        }

        Ok(certificate)
    }
}

impl signing_scheme::Scheme for Scheme {
    type Signature = Ed25519Signature;
    type Certificate = Certificate;
    type Seed = ();

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
        let Some(public_key) = self.participants.get(vote.signer) else {
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
            let Some(public_key) = self.participants.get(vote.signer) else {
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
        let (signers, signatures): (Vec<_>, Vec<_>) = entries.into_iter().unzip();

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
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Hasher, PrivateKeyExt, Sha256};
    use commonware_utils::quorum;
    use rand::{rngs::OsRng, thread_rng};

    const NAMESPACE: &[u8] = b"ed25519-signing-scheme";

    fn generate_private_keys(n: usize) -> Vec<PrivateKey> {
        let mut keys: Vec<_> = (0..n).map(|i| PrivateKey::from_seed(i as u64)).collect();
        keys.sort_by_key(|key| key.public_key());
        keys
    }

    fn participants(keys: &[PrivateKey]) -> Vec<PublicKey> {
        keys.iter().map(|key| key.public_key()).collect()
    }

    fn schemes(n: usize) -> (Vec<Scheme>, Vec<PublicKey>) {
        let keys = generate_private_keys(n);
        let participants = participants(&keys);
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

    #[test]
    fn test_sign_vote_roundtrip_for_each_context() {
        let (schemes, _) = schemes(4);
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
        let (schemes, _) = schemes(5);
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

        votes[0].signer = 999;
        let verification = scheme.verify_votes(
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
    fn test_assemble_certificate_sorts_signers() {
        let (schemes, _) = schemes(4);
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
        assert_eq!(certificate.signers, vec![0, 1, 2]);
    }

    #[test]
    fn test_assemble_certificate_requires_quorum() {
        let (schemes, _) = schemes(4);
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
        let (schemes, _) = schemes(4);
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
    fn test_verify_certificate_detects_corruption() {
        let (schemes, participants) = schemes(4);
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

        let verifier = Scheme::verifier(participants.clone());
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
        let (schemes, _) = schemes(4);
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
        let (schemes, participants) = schemes(4);
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

        let verifier = Scheme::verifier(participants.clone());
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
    fn test_certificate_decode_checks_sorted_unique_signers() {
        let (schemes, participants) = schemes(4);
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

        // Duplicate signer indices fail to decode.
        let duplicate = Certificate {
            signers: vec![0, 0],
            signatures: vec![
                certificate.signatures[0].clone(),
                certificate.signatures[0].clone(),
            ],
        };
        let mut dup_bytes = Vec::new();
        duplicate.write(&mut dup_bytes);
        let mut dup_slice = dup_bytes.as_slice();
        assert!(Certificate::read_cfg(&mut dup_slice, &participants.len()).is_err());

        // Unsorted signer indices fail to decode.
        let unsorted = Certificate {
            signers: vec![1, 0],
            signatures: vec![
                certificate.signatures[1].clone(),
                certificate.signatures[0].clone(),
            ],
        };
        let mut unsorted_bytes = Vec::new();
        unsorted.write(&mut unsorted_bytes);
        let mut unsorted_slice = unsorted_bytes.as_slice();
        assert!(Certificate::read_cfg(&mut unsorted_slice, &participants.len()).is_err());
    }

    #[test]
    fn test_verify_certificate() {
        let (schemes, participants) = schemes(4);
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
        let (schemes, participants) = schemes(4);
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
        truncated.signers.pop();
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
        let (schemes, participants) = schemes(4);
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

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        let mut invalid = certificate.clone();
        invalid.signers[0] = participants.len() as u32;

        let verifier = Scheme::verifier(participants);
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
    fn test_verify_certificate_rejects_duplicate_signers() {
        let (schemes, participants) = schemes(4);
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
        certificate.signers[1] = certificate.signers[0];

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
        let (schemes, participants) = schemes(4);
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
