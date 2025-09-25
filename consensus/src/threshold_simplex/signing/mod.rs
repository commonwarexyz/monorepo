//! Signing abstractions for simplex.

use crate::{
    threshold_simplex::types::{
        finalize_namespace, notarize_namespace, nullify_namespace, seed_namespace, Proposal,
    },
    types::Round,
};
use commonware_codec::Encode;
use commonware_cryptography::{
    bls12381::primitives::{
        group::Share,
        ops::{
            aggregate_signatures, aggregate_verify_multiple_messages, partial_sign_message,
            partial_verify_multiple_public_keys_precomputed, threshold_signature_recover_pair,
        },
        poly::PartialSignature,
        variant::Variant,
        Error as ThresholdError,
    },
    Digest,
};
use std::collections::BTreeSet;
use thiserror::Error;

/// Errors emitted by signing scheme implementations.
#[derive(Debug, Error)]
pub enum Error {
    /// Placeholder until real logic is implemented in later phases.
    #[error("not implemented")]
    NotImplemented,
    /// Signer index does not match the scheme's share.
    #[error("signer mismatch (expected {expected}, got {actual})")]
    SignerMismatch { expected: u32, actual: u32 },
    /// Not enough votes to assemble a certificate.
    #[error("insufficient votes: required {required}, got {actual}")]
    InsufficientVotes { required: usize, actual: usize },
    /// Threshold recovery failure.
    #[error("threshold error: {0}")]
    Threshold(#[from] ThresholdError),
}

/// Identifies the context in which a vote or certificate is produced.
pub enum VoteContext<'a, D: Digest> {
    Notarize {
        namespace: &'a [u8],
        proposal: &'a Proposal<D>,
    },
    Nullify {
        namespace: &'a [u8],
        round: Round,
    },
    Finalize {
        namespace: &'a [u8],
        proposal: &'a Proposal<D>,
    },
}

/// Signed vote emitted by a participant.
#[derive(Debug)]
pub struct Vote<S: SigningScheme> {
    pub signer: S::SignerId,
    pub signature: S::Signature,
}

impl<S: SigningScheme> Clone for Vote<S> {
    fn clone(&self) -> Self {
        Self {
            signer: self.signer.clone(),
            signature: self.signature.clone(),
        }
    }
}

/// Threshold randomness recovered from consensus certificates.
#[derive(Clone, Debug, PartialEq)]
pub struct Seed<V: Variant> {
    pub round: Round,
    pub signature: V::Signature,
}

impl<V: Variant> Seed<V> {
    fn new(round: Round, signature: V::Signature) -> Self {
        Seed { round, signature }
    }
}

/// Result of verifying a batch of votes.
pub struct VoteVerification<S: SigningScheme> {
    pub verified: Vec<Vote<S>>,
    pub invalid_signers: Vec<S::SignerId>,
}

impl<S: SigningScheme> VoteVerification<S> {
    pub fn new(verified: Vec<Vote<S>>, invalid_signers: Vec<S::SignerId>) -> Self {
        Self {
            verified,
            invalid_signers,
        }
    }
}

/// Trait that signing schemes must implement.
pub trait SigningScheme: Send + Sync {
    type SignerId: Clone + Ord;
    type Signature: Clone;
    type Certificate: Clone;
    type Randomness;

    fn sign_vote<D: Digest>(
        &self,
        context: VoteContext<'_, D>,
        signer: Self::SignerId,
    ) -> Result<Vote<Self>, Error>
    where
        Self: Sized;

    fn verify_votes<D: Digest, I>(
        &self,
        context: VoteContext<'_, D>,
        votes: I,
    ) -> VoteVerification<Self>
    where
        I: IntoIterator<Item = Vote<Self>>,
        Self: Sized;

    fn assemble_certificate<D: Digest>(
        &self,
        context: VoteContext<'_, D>,
        votes: &[Vote<Self>],
    ) -> Result<Self::Certificate, Error>
    where
        Self: Sized;

    fn verify_certificate<D: Digest>(
        &self,
        context: VoteContext<'_, D>,
        certificate: &Self::Certificate,
    ) -> Result<Option<Self::Randomness>, Error>
    where
        Self: Sized;
}

/// Placeholder for the upcoming BLS threshold implementation.
#[derive(Debug)]
pub struct BlsThresholdScheme<V: Variant> {
    polynomial: Vec<V::Public>,
    identity: V::Public,
    share: Share,
    threshold: usize,
}

impl<V: Variant> BlsThresholdScheme<V> {
    pub fn new(
        polynomial: Vec<V::Public>,
        identity: V::Public,
        share: Share,
        threshold: usize,
    ) -> Self {
        Self {
            polynomial,
            identity,
            share,
            threshold,
        }
    }
}

impl<V: Variant + Send + Sync> SigningScheme for BlsThresholdScheme<V> {
    type SignerId = u32;
    type Signature = (V::Signature, V::Signature);
    type Certificate = (V::Signature, V::Signature);
    type Randomness = Seed<V>;

    fn sign_vote<D: Digest>(
        &self,
        context: VoteContext<'_, D>,
        signer: Self::SignerId,
    ) -> Result<Vote<Self>, Error> {
        if signer != self.share.index {
            return Err(Error::SignerMismatch {
                expected: self.share.index,
                actual: signer,
            });
        }

        let signature = match context {
            VoteContext::Notarize {
                namespace,
                proposal,
            } => {
                let notarize_ns = notarize_namespace(namespace);
                let proposal_bytes = proposal.encode();
                let proposal_sig = partial_sign_message::<V>(
                    &self.share,
                    Some(notarize_ns.as_ref()),
                    proposal_bytes.as_ref(),
                )
                .value;

                let seed_ns = seed_namespace(namespace);
                let seed_bytes = proposal.round.encode();
                let seed_sig = partial_sign_message::<V>(
                    &self.share,
                    Some(seed_ns.as_ref()),
                    seed_bytes.as_ref(),
                )
                .value;

                (proposal_sig, seed_sig)
            }
            VoteContext::Nullify { namespace, round } => {
                let nullify_ns = nullify_namespace(namespace);
                let message_bytes = round.encode();
                let view_sig = partial_sign_message::<V>(
                    &self.share,
                    Some(nullify_ns.as_ref()),
                    message_bytes.as_ref(),
                )
                .value;

                let seed_ns = seed_namespace(namespace);
                let seed_sig = partial_sign_message::<V>(
                    &self.share,
                    Some(seed_ns.as_ref()),
                    message_bytes.as_ref(),
                )
                .value;

                (view_sig, seed_sig)
            }
            VoteContext::Finalize {
                namespace,
                proposal,
            } => {
                let finalize_ns = finalize_namespace(namespace);
                let proposal_bytes = proposal.encode();
                let proposal_sig = partial_sign_message::<V>(
                    &self.share,
                    Some(finalize_ns.as_ref()),
                    proposal_bytes.as_ref(),
                )
                .value;

                let seed_ns = seed_namespace(namespace);
                let seed_bytes = proposal.round.encode();
                let seed_sig = partial_sign_message::<V>(
                    &self.share,
                    Some(seed_ns.as_ref()),
                    seed_bytes.as_ref(),
                )
                .value;

                (proposal_sig, seed_sig)
            }
        };

        Ok(Vote { signer, signature })
    }

    fn assemble_certificate<D: Digest>(
        &self,
        _context: VoteContext<'_, D>,
        votes: &[Vote<Self>],
    ) -> Result<Self::Certificate, Error> {
        if votes.len() < self.threshold {
            return Err(Error::InsufficientVotes {
                required: self.threshold,
                actual: votes.len(),
            });
        }

        let proposal_partials: Vec<_> = votes
            .iter()
            .map(|vote| PartialSignature::<V> {
                index: vote.signer,
                value: vote.signature.0.clone(),
            })
            .collect();

        let seed_partials: Vec<_> = votes
            .iter()
            .map(|vote| PartialSignature::<V> {
                index: vote.signer,
                value: vote.signature.1.clone(),
            })
            .collect();

        let (proposal_sig, seed_sig) = threshold_signature_recover_pair::<V, _>(
            self.threshold as u32,
            proposal_partials.iter(),
            seed_partials.iter(),
        )?;

        Ok((proposal_sig, seed_sig))
    }

    fn verify_votes<D: Digest, I>(
        &self,
        context: VoteContext<'_, D>,
        votes: I,
    ) -> VoteVerification<Self>
    where
        I: IntoIterator<Item = Vote<Self>>,
        Self: Sized,
    {
        let votes: Vec<Vote<Self>> = votes.into_iter().collect();
        if votes.is_empty() {
            return VoteVerification::new(Vec::new(), Vec::new());
        }

        let mut invalid: BTreeSet<Self::SignerId> = BTreeSet::new();

        match context {
            VoteContext::Notarize {
                namespace,
                proposal,
            } => {
                let notarize_ns = notarize_namespace(namespace);
                let proposal_bytes = proposal.encode();
                let proposal_partials: Vec<_> = votes
                    .iter()
                    .map(|vote| PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.0.clone(),
                    })
                    .collect();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    &self.polynomial,
                    Some(notarize_ns.as_ref()),
                    proposal_bytes.as_ref(),
                    proposal_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }

                let seed_ns = seed_namespace(namespace);
                let seed_bytes = proposal.round.encode();
                let seed_partials: Vec<_> = votes
                    .iter()
                    .filter(|vote| !invalid.contains(&vote.signer))
                    .map(|vote| PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.1.clone(),
                    })
                    .collect();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    &self.polynomial,
                    Some(seed_ns.as_ref()),
                    seed_bytes.as_ref(),
                    seed_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }
            }
            VoteContext::Nullify { namespace, round } => {
                let nullify_ns = nullify_namespace(namespace);
                let message_bytes = round.encode();
                let view_partials: Vec<_> = votes
                    .iter()
                    .map(|vote| PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.0.clone(),
                    })
                    .collect();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    &self.polynomial,
                    Some(nullify_ns.as_ref()),
                    message_bytes.as_ref(),
                    view_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }

                let seed_ns = seed_namespace(namespace);
                let seed_partials: Vec<_> = votes
                    .iter()
                    .filter(|vote| !invalid.contains(&vote.signer))
                    .map(|vote| PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.1.clone(),
                    })
                    .collect();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    &self.polynomial,
                    Some(seed_ns.as_ref()),
                    message_bytes.as_ref(),
                    seed_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }
            }
            VoteContext::Finalize {
                namespace,
                proposal,
            } => {
                let finalize_ns = finalize_namespace(namespace);
                let proposal_bytes = proposal.encode();
                let proposal_partials: Vec<_> = votes
                    .iter()
                    .map(|vote| PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.0.clone(),
                    })
                    .collect();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    &self.polynomial,
                    Some(finalize_ns.as_ref()),
                    proposal_bytes.as_ref(),
                    proposal_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }

                let seed_ns = seed_namespace(namespace);
                let seed_bytes = proposal.round.encode();
                let seed_partials: Vec<_> = votes
                    .iter()
                    .filter(|vote| !invalid.contains(&vote.signer))
                    .map(|vote| PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.1.clone(),
                    })
                    .collect();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    &self.polynomial,
                    Some(seed_ns.as_ref()),
                    seed_bytes.as_ref(),
                    seed_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }
            }
        }

        let verified = votes
            .into_iter()
            .filter(|vote| !invalid.contains(&vote.signer))
            .collect();

        let invalid_signers = invalid.into_iter().collect();

        VoteVerification::new(verified, invalid_signers)
    }

    fn verify_certificate<D: Digest>(
        &self,
        context: VoteContext<'_, D>,
        certificate: &Self::Certificate,
    ) -> Result<Option<Self::Randomness>, Error>
    where
        Self: Sized,
    {
        let aggregate_pair = |messages: &[_], certificate: &Self::Certificate| {
            let signature =
                aggregate_signatures::<V, _>(&[certificate.0.clone(), certificate.1.clone()]);
            aggregate_verify_multiple_messages::<V, _>(&self.identity, messages, &signature, 1)
        };

        let round = match context {
            VoteContext::Notarize {
                namespace,
                proposal,
            } => {
                let notarize_ns = notarize_namespace(namespace);
                let proposal_bytes = proposal.encode();
                let notarize_message = (Some(notarize_ns.as_ref()), proposal_bytes.as_ref());

                let seed_ns = seed_namespace(namespace);
                let seed_bytes = proposal.round.encode();
                let seed_message = (Some(seed_ns.as_ref()), seed_bytes.as_ref());

                aggregate_pair(&[notarize_message, seed_message], certificate)?;
                proposal.round
            }
            VoteContext::Nullify { namespace, round } => {
                let nullify_ns = nullify_namespace(namespace);
                let round_bytes = round.encode();
                let nullify_message = (Some(nullify_ns.as_ref()), round_bytes.as_ref());

                let seed_ns = seed_namespace(namespace);
                let seed_message = (Some(seed_ns.as_ref()), round_bytes.as_ref());

                aggregate_pair(&[nullify_message, seed_message], certificate)?;
                round
            }
            VoteContext::Finalize {
                namespace,
                proposal,
            } => {
                let finalize_ns = finalize_namespace(namespace);
                let proposal_bytes = proposal.encode();
                let finalize_message = (Some(finalize_ns.as_ref()), proposal_bytes.as_ref());

                let seed_ns = seed_namespace(namespace);
                let seed_bytes = proposal.round.encode();
                let seed_message = (Some(seed_ns.as_ref()), seed_bytes.as_ref());

                aggregate_pair(&[finalize_message, seed_message], certificate)?;
                proposal.round
            }
        };

        Ok(Some(Seed::new(round, certificate.1.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_simplex::types::{Finalize, Notarize, Nullify};
    use commonware_cryptography::{
        bls12381::{
            dkg::ops::{evaluate_all, generate_shares},
            primitives::{group::Element, variant::MinSig},
        },
        sha256::Digest as Sha256Digest,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn vote_context_compiles() {
        let round = Round::new(0, 0);
        let payload = Sha256Digest::from([0u8; 32]);
        let proposal = Proposal::new(round, round.view(), payload);
        let namespace = b"ns";
        let ctx = VoteContext::Notarize {
            namespace,
            proposal: &proposal,
        };
        match ctx {
            VoteContext::Notarize { .. } => {}
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn bls_scheme_stores_configuration() {
        let mut rng = StdRng::seed_from_u64(7);
        let threshold = 3usize;
        let (public_poly, shares) =
            generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
        let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
        let identity = *public_poly.constant();
        let scheme: BlsThresholdScheme<MinSig> =
            BlsThresholdScheme::new(polynomial.clone(), identity, shares[0].clone(), threshold);
        assert_eq!(scheme.polynomial.len(), polynomial.len());
        assert!(scheme.identity == identity);
        assert_eq!(shares.len(), 4); // ensure we used the DKG outputs
        assert_eq!(scheme.share.index, shares[0].index);
    }

    #[test]
    fn sign_vote_matches_notarize() {
        let mut rng = StdRng::seed_from_u64(11);
        let threshold = 3usize;
        let (public_poly, mut shares) =
            generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
        let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
        let identity = *public_poly.constant();
        let share = shares.remove(0);
        let scheme: BlsThresholdScheme<MinSig> =
            BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

        let round = Round::new(0, 5);
        let payload = Sha256Digest::from([1u8; 32]);
        let proposal = Proposal::new(round, 4, payload);
        let namespace = b"notarize";

        let vote = scheme
            .sign_vote(
                VoteContext::Notarize {
                    namespace,
                    proposal: &proposal,
                },
                share.index,
            )
            .expect("sign vote");

        let legacy = Notarize::<MinSig, _>::sign(namespace, &share, proposal.clone());
        assert!(vote.signature.0 == legacy.proposal_signature.value);
        assert!(vote.signature.1 == legacy.seed_signature.value);
    }

    #[test]
    fn sign_vote_matches_nullify() {
        let mut rng = StdRng::seed_from_u64(13);
        let threshold = 3usize;
        let (public_poly, mut shares) =
            generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
        let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
        let identity = *public_poly.constant();
        let share = shares.remove(0);
        let scheme: BlsThresholdScheme<MinSig> =
            BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

        let round = Round::new(0, 7);
        let namespace = b"nullify";

        let vote = scheme
            .sign_vote::<Sha256Digest>(VoteContext::Nullify { namespace, round }, share.index)
            .expect("sign vote");

        let legacy = Nullify::<MinSig>::sign(namespace, &share, round);
        assert!(vote.signature.0 == legacy.view_signature.value);
        assert!(vote.signature.1 == legacy.seed_signature.value);
    }

    #[test]
    fn sign_vote_matches_finalize() {
        let mut rng = StdRng::seed_from_u64(17);
        let threshold = 3usize;
        let (public_poly, mut shares) =
            generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
        let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
        let identity = *public_poly.constant();
        let share = shares.remove(0);
        let scheme: BlsThresholdScheme<MinSig> =
            BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

        let round = Round::new(0, 9);
        let payload = Sha256Digest::from([2u8; 32]);
        let proposal = Proposal::new(round, 8, payload);
        let namespace = b"finalize";

        let vote = scheme
            .sign_vote(
                VoteContext::Finalize {
                    namespace,
                    proposal: &proposal,
                },
                share.index,
            )
            .expect("sign vote");

        let legacy = Finalize::<MinSig, _>::sign(namespace, &share, proposal.clone());
        assert!(vote.signature.0 == legacy.proposal_signature.value);
        let seed_ns = seed_namespace(namespace);
        let seed_bytes = proposal.round.encode();
        let expected_seed =
            partial_sign_message::<MinSig>(&share, Some(seed_ns.as_ref()), seed_bytes.as_ref());
        assert!(vote.signature.1 == expected_seed.value);
    }

    #[test]
    fn sign_vote_rejects_wrong_signer() {
        let mut rng = StdRng::seed_from_u64(19);
        let threshold = 3usize;
        let (public_poly, mut shares) =
            generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
        let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
        let identity = *public_poly.constant();
        let share = shares.remove(0);
        let scheme: BlsThresholdScheme<MinSig> =
            BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

        let round = Round::new(0, 1);
        let payload = Sha256Digest::from([3u8; 32]);
        let proposal = Proposal::new(round, 0, payload);

        let err = scheme
            .sign_vote(
                VoteContext::Notarize {
                    namespace: b"ns",
                    proposal: &proposal,
                },
                share.index + 1,
            )
            .expect_err("expected mismatch");

        match err {
            Error::SignerMismatch { expected, actual } => {
                assert_eq!(expected, share.index);
                assert_eq!(actual, share.index + 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn verify_votes_notarize_filters_invalid() {
        let mut rng = StdRng::seed_from_u64(23);
        let threshold = 3usize;
        let (public_poly, shares) =
            generate_shares::<_, MinSig>(&mut rng, None, 5, threshold as u32);
        let polynomial = evaluate_all::<MinSig>(&public_poly, 5);
        let identity = *public_poly.constant();

        let schemes: Vec<_> = shares
            .iter()
            .map(|share| {
                BlsThresholdScheme::<MinSig>::new(
                    polynomial.clone(),
                    identity,
                    share.clone(),
                    threshold,
                )
            })
            .collect();

        let round = Round::new(0, 12);
        let payload = Sha256Digest::from([4u8; 32]);
        let proposal = Proposal::new(round, 11, payload);
        let namespace = b"verify-notarize";

        let votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        VoteContext::Notarize {
                            namespace,
                            proposal: &proposal,
                        },
                        scheme.share.index,
                    )
                    .expect("sign vote")
            })
            .collect();

        let verifier = &schemes[0];

        let verification = verifier.verify_votes(
            VoteContext::Notarize {
                namespace,
                proposal: &proposal,
            },
            votes.clone(),
        );
        assert!(verification.invalid_signers.is_empty());
        assert_eq!(verification.verified.len(), votes.len());

        let mut corrupted = votes.clone();
        corrupted[0].signer = 42;
        let verification = verifier.verify_votes(
            VoteContext::Notarize {
                namespace,
                proposal: &proposal,
            },
            corrupted,
        );
        assert_eq!(verification.invalid_signers, vec![42]);
        assert_eq!(verification.verified.len(), votes.len() - 1);
    }

    #[test]
    fn assemble_certificate_notarize() {
        let mut rng = StdRng::seed_from_u64(29);
        let threshold = 3usize;
        let (public_poly, shares) =
            generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
        let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
        let identity = *public_poly.constant();
        let schemes: Vec<_> = shares
            .iter()
            .map(|share| {
                BlsThresholdScheme::<MinSig>::new(
                    polynomial.clone(),
                    identity,
                    share.clone(),
                    threshold,
                )
            })
            .collect();

        let round = Round::new(0, 15);
        let payload = Sha256Digest::from([5u8; 32]);
        let proposal = Proposal::new(round, 14, payload);
        let namespace = b"assemble-notarize";

        let votes: Vec<_> = schemes
            .iter()
            .take(threshold)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        VoteContext::Notarize {
                            namespace,
                            proposal: &proposal,
                        },
                        scheme.share.index,
                    )
                    .expect("sign vote")
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(
                VoteContext::Notarize {
                    namespace,
                    proposal: &proposal,
                },
                &votes,
            )
            .expect("assemble");

        let expected_proposal: Vec<_> = votes
            .iter()
            .map(|vote| PartialSignature::<MinSig> {
                index: vote.signer,
                value: vote.signature.0.clone(),
            })
            .collect();
        let expected_seed: Vec<_> = votes
            .iter()
            .map(|vote| PartialSignature::<MinSig> {
                index: vote.signer,
                value: vote.signature.1.clone(),
            })
            .collect();
        let expected = threshold_signature_recover_pair::<MinSig, _>(
            threshold as u32,
            expected_proposal.iter(),
            expected_seed.iter(),
        )
        .expect("recover");

        assert_eq!(certificate.0, expected.0);
        assert_eq!(certificate.1, expected.1);
    }

    #[test]
    fn assemble_certificate_requires_quorum() {
        let mut rng = StdRng::seed_from_u64(31);
        let threshold = 3usize;
        let (public_poly, shares) =
            generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
        let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
        let identity = *public_poly.constant();
        let schemes: Vec<_> = shares
            .iter()
            .map(|share| {
                BlsThresholdScheme::<MinSig>::new(
                    polynomial.clone(),
                    identity,
                    share.clone(),
                    threshold,
                )
            })
            .collect();

        let round = Round::new(0, 18);
        let payload = Sha256Digest::from([6u8; 32]);
        let proposal = Proposal::new(round, 17, payload);
        let namespace = b"assemble-insufficient";

        let votes: Vec<_> = schemes
            .iter()
            .take(threshold - 1)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        VoteContext::Notarize {
                            namespace,
                            proposal: &proposal,
                        },
                        scheme.share.index,
                    )
                    .expect("sign vote")
            })
            .collect();

        let err = schemes[0]
            .assemble_certificate(
                VoteContext::Notarize {
                    namespace,
                    proposal: &proposal,
                },
                &votes,
            )
            .expect_err("expected insufficient votes");

        match err {
            Error::InsufficientVotes { required, actual } => {
                assert_eq!(required, threshold);
                assert_eq!(actual, votes.len());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn build_scheme_set(
        seed: u64,
        n: usize,
        threshold: usize,
    ) -> (Vec<BlsThresholdScheme<MinSig>>, Vec<Share>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let (public_poly, shares) =
            generate_shares::<_, MinSig>(&mut rng, None, n as u32, threshold as u32);
        let polynomial = evaluate_all::<MinSig>(&public_poly, n as u32);
        let identity = *public_poly.constant();
        let schemes = shares
            .iter()
            .map(|share| {
                BlsThresholdScheme::new(polynomial.clone(), identity, share.clone(), threshold)
            })
            .collect();
        (schemes, shares)
    }

    #[test]
    fn verify_certificate_notarize_success_and_failure() {
        let threshold = 3;
        let (schemes, _) = build_scheme_set(33, 4, threshold);
        let round = Round::new(0, 20);
        let payload = Sha256Digest::from([7u8; 32]);
        let proposal = Proposal::new(round, 19, payload);
        let namespace = b"verify-cert-notarize";

        let votes: Vec<_> = schemes
            .iter()
            .take(threshold)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        VoteContext::Notarize {
                            namespace,
                            proposal: &proposal,
                        },
                        scheme.share.index,
                    )
                    .expect("sign vote")
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(
                VoteContext::Notarize {
                    namespace,
                    proposal: &proposal,
                },
                &votes,
            )
            .expect("assemble");

        let randomness = schemes[1]
            .verify_certificate(
                VoteContext::Notarize {
                    namespace,
                    proposal: &proposal,
                },
                &certificate,
            )
            .expect("verify");
        let expected_seed = Seed::new(proposal.round, certificate.1.clone());
        assert_eq!(randomness, Some(expected_seed));

        let mut bad_certificate = certificate.clone();
        let mut corrupted = bad_certificate.0.clone();
        corrupted.add(&<MinSig as Variant>::Signature::one());
        bad_certificate.0 = corrupted;
        let err = schemes[1]
            .verify_certificate(
                VoteContext::Notarize {
                    namespace,
                    proposal: &proposal,
                },
                &bad_certificate,
            )
            .expect_err("expected invalid certificate");
        assert!(matches!(err, Error::Threshold(_)));
    }

    #[test]
    fn verify_certificate_nullify_success_and_failure() {
        let threshold = 3;
        let (schemes, _) = build_scheme_set(35, 4, threshold);
        let round = Round::new(0, 22);
        let namespace = b"verify-cert-nullify";

        let votes: Vec<_> = schemes
            .iter()
            .take(threshold)
            .map(|scheme| {
                scheme
                    .sign_vote::<Sha256Digest>(
                        VoteContext::Nullify { namespace, round },
                        scheme.share.index,
                    )
                    .expect("sign vote")
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate::<Sha256Digest>(VoteContext::Nullify { namespace, round }, &votes)
            .expect("assemble");

        let randomness = schemes[1]
            .verify_certificate::<Sha256Digest>(
                VoteContext::Nullify { namespace, round },
                &certificate,
            )
            .expect("verify");
        let expected_seed = Seed::new(round, certificate.1.clone());
        assert_eq!(randomness, Some(expected_seed));

        let mut bad_certificate = certificate.clone();
        let mut corrupted = bad_certificate.1.clone();
        corrupted.add(&<MinSig as Variant>::Signature::one());
        bad_certificate.1 = corrupted;
        let err = schemes[1]
            .verify_certificate::<Sha256Digest>(
                VoteContext::Nullify { namespace, round },
                &bad_certificate,
            )
            .expect_err("expected invalid certificate");
        assert!(matches!(err, Error::Threshold(_)));
    }

    #[test]
    fn verify_certificate_finalize_success_and_failure() {
        let threshold = 3;
        let (schemes, _) = build_scheme_set(37, 4, threshold);
        let round = Round::new(0, 25);
        let payload = Sha256Digest::from([8u8; 32]);
        let proposal = Proposal::new(round, 24, payload);
        let namespace = b"verify-cert-finalize";

        let votes: Vec<_> = schemes
            .iter()
            .take(threshold)
            .map(|scheme| {
                scheme
                    .sign_vote(
                        VoteContext::Finalize {
                            namespace,
                            proposal: &proposal,
                        },
                        scheme.share.index,
                    )
                    .expect("sign vote")
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(
                VoteContext::Finalize {
                    namespace,
                    proposal: &proposal,
                },
                &votes,
            )
            .expect("assemble");

        let randomness = schemes[1]
            .verify_certificate(
                VoteContext::Finalize {
                    namespace,
                    proposal: &proposal,
                },
                &certificate,
            )
            .expect("verify");
        let expected_seed = Seed::new(proposal.round, certificate.1.clone());
        assert_eq!(randomness, Some(expected_seed));

        let mut bad_certificate = certificate.clone();
        let mut corrupted = bad_certificate.0.clone();
        corrupted.add(&<MinSig as Variant>::Signature::one());
        bad_certificate.0 = corrupted;
        let err = schemes[1]
            .verify_certificate(
                VoteContext::Finalize {
                    namespace,
                    proposal: &proposal,
                },
                &bad_certificate,
            )
            .expect_err("expected invalid certificate");
        assert!(matches!(err, Error::Threshold(_)));
    }
}
