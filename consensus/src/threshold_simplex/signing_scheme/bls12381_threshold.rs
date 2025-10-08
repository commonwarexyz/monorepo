//! Signing abstractions for simplex.

use crate::{
    threshold_simplex::{
        signing_scheme::{
            finalize_namespace, notarize_namespace, nullify_namespace, seed_namespace,
        },
        types::{SigningScheme, Vote, VoteContext, VoteVerification},
    },
    Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{
    bls12381::{
        dkg::ops,
        primitives::{
            group::Share,
            ops::{
                aggregate_signatures, aggregate_verify_multiple_messages, partial_sign_message,
                partial_verify_multiple_public_keys_precomputed, threshold_signature_recover_pair,
            },
            poly::{self, PartialSignature, Public},
            variant::Variant,
        },
    },
    Digest,
};
use commonware_utils::quorum;
use rand::{CryptoRng, Rng};
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Debug,
};

#[derive(Clone, Debug)]
pub enum Scheme<V: Variant> {
    Signer {
        identity: V::Public,
        polynomial: Vec<V::Public>,
        share: Share,
        threshold: u32,
    },
    Verifier {
        identity: V::Public,
        polynomial: Vec<V::Public>,
        threshold: u32,
    },
    CertificateVerifier {
        identity: V::Public,
    },
}

impl<V: Variant> Scheme<V> {
    pub fn new<P>(participants: &[P], polynomial: &Public<V>, share: Share) -> Self {
        let identity = *poly::public::<V>(polynomial);
        let polynomial = ops::evaluate_all::<V>(polynomial, participants.len() as u32);
        let threshold = quorum(polynomial.len() as u32);

        Self::Signer {
            polynomial,
            identity,
            share,
            threshold,
        }
    }

    pub fn verifier<P>(participants: &[P], polynomial: &Public<V>) -> Self {
        let identity = *poly::public::<V>(polynomial);
        let polynomial = ops::evaluate_all::<V>(polynomial, participants.len() as u32);
        let threshold = quorum(polynomial.len() as u32);

        Self::Verifier {
            identity,
            polynomial,
            threshold,
        }
    }

    pub fn certificate_verifier(identity: V::Public) -> Self {
        Self::CertificateVerifier { identity }
    }

    pub fn into_verifier(self) -> Self {
        match self {
            Scheme::Signer {
                identity,
                polynomial,
                threshold,
                ..
            } => Scheme::Verifier {
                identity,
                polynomial,
                threshold,
            },
            Scheme::Verifier { .. } => self,
            _ => panic!("cannot convert certificate verifier into verifier"),
        }
    }

    pub fn identity(&self) -> &V::Public {
        match self {
            Scheme::Signer { identity, .. } => identity,
            Scheme::Verifier { identity, .. } => identity,
            Scheme::CertificateVerifier { identity } => identity,
        }
    }

    pub fn share(&self) -> Option<&Share> {
        match self {
            Scheme::Signer { share, .. } => Some(share),
            _ => None,
        }
    }

    pub fn polynomial(&self) -> &[V::Public] {
        match self {
            Scheme::Signer { polynomial, .. } => polynomial,
            Scheme::Verifier { polynomial, .. } => polynomial,
            _ => panic!("can only be called for signer and verifier"),
        }
    }

    pub fn threshold(&self) -> u32 {
        match self {
            Scheme::Signer { threshold, .. } => *threshold,
            Scheme::Verifier { threshold, .. } => *threshold,
            _ => panic!("can only be called for signer and verifier"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature<V: Variant> {
    pub message_signature: V::Signature,
    pub seed_signature: V::Signature,
}

impl<V: Variant> Write for Signature<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.message_signature.write(writer);
        self.seed_signature.write(writer);
    }
}

impl<V: Variant> Read for Signature<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let message_signature = V::Signature::read(reader)?;
        let seed_signature = V::Signature::read(reader)?;

        Ok(Self {
            message_signature,
            seed_signature,
        })
    }
}

impl<V: Variant> EncodeSize for Signature<V> {
    fn encode_size(&self) -> usize {
        self.message_signature.encode_size() + self.seed_signature.encode_size()
    }
}

impl<V: Variant + Send + Sync> SigningScheme for Scheme<V> {
    type Signature = Signature<V>;
    type Certificate = Signature<V>;
    type Randomness = V::Signature;

    type CertificateCfg = ();

    fn can_sign(&self) -> bool {
        self.share().is_some()
    }

    fn sign_vote<D: Digest>(&self, namespace: &[u8], context: VoteContext<'_, D>) -> Vote<Self> {
        let share = self
            .share()
            .expect("can only be called after checking can_sign");

        let signature = match context {
            VoteContext::Notarize { proposal } => {
                let notarize_namespace = notarize_namespace(namespace);
                let notarize_message = proposal.encode();
                let proposal_signature = partial_sign_message::<V>(
                    share,
                    Some(notarize_namespace.as_ref()),
                    notarize_message.as_ref(),
                )
                .value;

                let seed_namespace = seed_namespace(namespace);
                let seed_message = proposal.round.encode();
                let seed_signature = partial_sign_message::<V>(
                    share,
                    Some(seed_namespace.as_ref()),
                    seed_message.as_ref(),
                )
                .value;

                Signature {
                    message_signature: proposal_signature,
                    seed_signature,
                }
            }
            VoteContext::Nullify { round } => {
                let nullify_namespace = nullify_namespace(namespace);
                let nullify_message = round.encode();
                let round_signature = partial_sign_message::<V>(
                    share,
                    Some(nullify_namespace.as_ref()),
                    nullify_message.as_ref(),
                )
                .value;

                let seed_namespace = seed_namespace(namespace);
                let seed_signature = partial_sign_message::<V>(
                    share,
                    Some(seed_namespace.as_ref()),
                    nullify_message.as_ref(),
                )
                .value;

                Signature {
                    message_signature: round_signature,
                    seed_signature,
                }
            }
            VoteContext::Finalize { proposal } => {
                let finalize_namespace = finalize_namespace(namespace);
                let finalize_message = proposal.encode();
                let proposal_signature = partial_sign_message::<V>(
                    share,
                    Some(finalize_namespace.as_ref()),
                    finalize_message.as_ref(),
                )
                .value;

                let seed_namespace = seed_namespace(namespace);
                let seed_message = proposal.round.encode();
                let seed_signature = partial_sign_message::<V>(
                    share,
                    Some(seed_namespace.as_ref()),
                    seed_message.as_ref(),
                )
                .value;

                Signature {
                    message_signature: proposal_signature,
                    seed_signature,
                }
            }
        };

        Vote {
            signer: share.index,
            signature,
        }
    }

    fn assemble_certificate<I>(&self, votes: I) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Vote<Self>>,
    {
        let threshold = self.threshold();

        let (message_partials, seed_partials): (Vec<_>, Vec<_>) = votes
            .into_iter()
            .map(|vote| {
                (
                    PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.message_signature,
                    },
                    PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.seed_signature,
                    },
                )
            })
            .unzip();

        if message_partials.len() < threshold as usize {
            return None;
        }

        let (message_signature, seed_signature) = threshold_signature_recover_pair::<V, _>(
            threshold,
            message_partials.iter(),
            seed_partials.iter(),
        )
        .ok()?;

        Some(Signature {
            message_signature,
            seed_signature,
        })
    }

    fn verify_vote<D: Digest>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        vote: &Vote<Self>,
    ) -> bool {
        let polynomial = self.polynomial();

        match context {
            VoteContext::Notarize { proposal } => {
                let Some(evaluated) = polynomial.get(vote.signer as usize) else {
                    return false;
                };

                let notarize_namespace = notarize_namespace(namespace);
                let notarize_message = proposal.encode();
                let notarize_message =
                    (Some(notarize_namespace.as_ref()), notarize_message.as_ref());

                let seed_namespace = seed_namespace(namespace);
                let seed_message = proposal.round.encode();
                let seed_message = (Some(seed_namespace.as_ref()), seed_message.as_ref());

                let signature = aggregate_signatures::<V, _>(&[
                    vote.signature.message_signature,
                    vote.signature.seed_signature,
                ]);

                aggregate_verify_multiple_messages::<V, _>(
                    evaluated,
                    &[notarize_message, seed_message],
                    &signature,
                    1,
                )
                .is_ok()
            }
            VoteContext::Nullify { round } => {
                let Some(evaluated) = polynomial.get(vote.signer as usize) else {
                    return false;
                };

                let nullify_namespace = nullify_namespace(namespace);
                let nullify_encoded = round.encode();
                let nullify_message = (Some(nullify_namespace.as_ref()), nullify_encoded.as_ref());

                let seed_namespace = seed_namespace(namespace);
                let seed_message = (Some(seed_namespace.as_ref()), nullify_encoded.as_ref());

                let signature = aggregate_signatures::<V, _>(&[
                    vote.signature.message_signature,
                    vote.signature.seed_signature,
                ]);

                aggregate_verify_multiple_messages::<V, _>(
                    evaluated,
                    &[nullify_message, seed_message],
                    &signature,
                    1,
                )
                .is_ok()
            }
            VoteContext::Finalize { proposal } => {
                let Some(evaluated) = polynomial.get(vote.signer as usize) else {
                    return false;
                };

                let finalize_namespace = finalize_namespace(namespace);
                let finalize_message = proposal.encode();
                let finalize_message =
                    (Some(finalize_namespace.as_ref()), finalize_message.as_ref());

                let seed_namespace = seed_namespace(namespace);
                let seed_message = proposal.round.encode();
                let seed_message = (Some(seed_namespace.as_ref()), seed_message.as_ref());

                let signature = aggregate_signatures::<V, _>(&[
                    vote.signature.message_signature,
                    vote.signature.seed_signature,
                ]);

                aggregate_verify_multiple_messages::<V, _>(
                    evaluated,
                    &[finalize_message, seed_message],
                    &signature,
                    1,
                )
                .is_ok()
            }
        }
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
        let polynomial = self.polynomial();

        let mut invalid = BTreeSet::new();
        let (message_partials, seed_partials): (Vec<_>, Vec<_>) = votes
            .into_iter()
            .map(|vote| {
                (
                    PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.message_signature,
                    },
                    PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.seed_signature,
                    },
                )
            })
            .unzip();

        match context {
            VoteContext::Notarize { proposal } => {
                let notarize_namespace = notarize_namespace(namespace);
                let notarize_message = proposal.encode();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    polynomial,
                    Some(notarize_namespace.as_ref()),
                    notarize_message.as_ref(),
                    message_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }

                let seed_namespace = seed_namespace(namespace);
                let seed_message = proposal.round.encode();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
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
            }
            VoteContext::Nullify { round } => {
                let nullify_namespace = nullify_namespace(namespace);
                let nullify_message = round.encode();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    polynomial,
                    Some(nullify_namespace.as_ref()),
                    nullify_message.as_ref(),
                    message_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }

                let seed_namespace = seed_namespace(namespace);

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    polynomial,
                    Some(seed_namespace.as_ref()),
                    nullify_message.as_ref(),
                    seed_partials
                        .iter()
                        .filter(|partial| !invalid.contains(&partial.index)),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }
            }
            VoteContext::Finalize { proposal } => {
                let finalize_namespace = finalize_namespace(namespace);
                let finalize_message = proposal.encode();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
                    polynomial,
                    Some(finalize_namespace.as_ref()),
                    finalize_message.as_ref(),
                    message_partials.iter(),
                ) {
                    for partial in errs {
                        invalid.insert(partial.index);
                    }
                }

                let seed_namespace = seed_namespace(namespace);
                let seed_message = proposal.round.encode();

                if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
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
            }
        }

        let verified = message_partials
            .into_iter()
            .zip(seed_partials)
            .map(|(message, seed)| Vote {
                signer: message.index,
                signature: Signature {
                    message_signature: message.value,
                    seed_signature: seed.value,
                },
            })
            .filter(|vote| !invalid.contains(&vote.signer))
            .collect();

        let invalid_signers = invalid.into_iter().collect();

        VoteVerification::new(verified, invalid_signers)
    }

    fn verify_certificate<R: Rng + CryptoRng, D: Digest>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        certificate: &Self::Certificate,
    ) -> bool {
        let identity = self.identity();

        match context {
            VoteContext::Notarize { proposal } => {
                let notarize_namespace = notarize_namespace(namespace);
                let notarize_message = proposal.encode();
                let notarize_message =
                    (Some(notarize_namespace.as_ref()), notarize_message.as_ref());

                let seed_namespace = seed_namespace(namespace);
                let seed_message = proposal.round.encode();
                let seed_message = (Some(seed_namespace.as_ref()), seed_message.as_ref());

                let signature = aggregate_signatures::<V, _>(&[
                    certificate.message_signature,
                    certificate.seed_signature,
                ]);

                aggregate_verify_multiple_messages::<V, _>(
                    identity,
                    &[notarize_message, seed_message],
                    &signature,
                    1,
                )
                .is_ok()
            }
            VoteContext::Nullify { round } => {
                let nullify_namespace = nullify_namespace(namespace);
                let nullify_encoded = round.encode();
                let nullify_message = (Some(nullify_namespace.as_ref()), nullify_encoded.as_ref());

                let seed_namespace = seed_namespace(namespace);
                let seed_message = (Some(seed_namespace.as_ref()), nullify_encoded.as_ref());

                let signature = aggregate_signatures::<V, _>(&[
                    certificate.message_signature,
                    certificate.seed_signature,
                ]);

                aggregate_verify_multiple_messages::<V, _>(
                    identity,
                    &[nullify_message, seed_message],
                    &signature,
                    1,
                )
                .is_ok()
            }
            VoteContext::Finalize { proposal } => {
                let finalize_namespace = finalize_namespace(namespace);
                let finalize_message = proposal.encode();
                let finalize_message =
                    (Some(finalize_namespace.as_ref()), finalize_message.as_ref());

                let seed_namespace = seed_namespace(namespace);
                let seed_message = proposal.round.encode();
                let seed_message = (Some(seed_namespace.as_ref()), seed_message.as_ref());

                let signature = aggregate_signatures::<V, _>(&[
                    certificate.message_signature,
                    certificate.seed_signature,
                ]);

                aggregate_verify_multiple_messages::<V, _>(
                    identity,
                    &[finalize_message, seed_message],
                    &signature,
                    1,
                )
                .is_ok()
            }
        }
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
        I: Iterator<Item = (VoteContext<'a, D>, &'a Self::Certificate)>,
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
                VoteContext::Notarize { proposal } => {
                    // Prepare notarize message
                    let notarize_message = proposal.encode();
                    let notarize_message = (Some(notarize_namespace.as_slice()), notarize_message);
                    messages.push(notarize_message);
                    signatures.push(&certificate.message_signature);

                    // Add seed message (if not already present)
                    if let Some(previous) = seeds.get(&proposal.view()) {
                        if *previous != &certificate.seed_signature {
                            return false;
                        }
                    } else {
                        let seed_message = proposal.round.encode();
                        let seed_message = (Some(seed_namespace.as_slice()), seed_message);
                        messages.push(seed_message);
                        signatures.push(&certificate.seed_signature);
                        seeds.insert(proposal.view(), &certificate.seed_signature);
                    }
                }
                VoteContext::Nullify { round } => {
                    // Prepare nullify message
                    let nullify_encoded = round.encode();
                    let nullify_message =
                        (Some(nullify_namespace.as_slice()), nullify_encoded.clone());
                    messages.push(nullify_message);
                    signatures.push(&certificate.message_signature);

                    // Add seed message (if not already present)
                    if let Some(previous) = seeds.get(&round.view()) {
                        if *previous != &certificate.seed_signature {
                            return false;
                        }
                    } else {
                        let seed_message = (Some(seed_namespace.as_slice()), nullify_encoded);
                        messages.push(seed_message);
                        signatures.push(&certificate.seed_signature);
                        seeds.insert(round.view(), &certificate.seed_signature);
                    }
                }
                VoteContext::Finalize { proposal } => {
                    // Prepare finalize message
                    let finalize_message = proposal.encode();
                    let finalize_message = (Some(finalize_namespace.as_slice()), finalize_message);
                    messages.push(finalize_message);
                    signatures.push(&certificate.message_signature);

                    // Add seed message (if not already present)
                    if let Some(previous) = seeds.get(&proposal.view()) {
                        if *previous != &certificate.seed_signature {
                            return false;
                        }
                    } else {
                        let seed_message = proposal.round.encode();
                        let seed_message = (Some(seed_namespace.as_slice()), seed_message);
                        messages.push(seed_message);
                        signatures.push(&certificate.seed_signature);
                        seeds.insert(proposal.view(), &certificate.seed_signature);
                    }
                }
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

    fn randomness(&self, certificate: &Self::Certificate) -> Option<Self::Randomness> {
        Some(certificate.seed_signature)
    }

    fn certificate_codec_config(&self) -> Self::CertificateCfg {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{threshold_simplex::types::Proposal, types::Round};
    use commonware_cryptography::{
        bls12381::{
            dkg::ops::{evaluate_all, generate_shares},
            primitives::variant::MinSig,
        },
        sha256::Digest as Sha256Digest,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn vote_context_compiles() {
        let round = Round::new(0, 0);
        let payload = Sha256Digest::from([0u8; 32]);
        let proposal = Proposal::new(round, round.view(), payload);
        let ctx = VoteContext::Notarize {
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
        let threshold = 3;
        let (polynomial, shares) =
            generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
        let scheme: Scheme<MinSig> = Scheme::new(&vec![0; 4], &polynomial, shares[0].clone());

        let identity = *polynomial.constant();
        let polynomial = evaluate_all::<MinSig>(&polynomial, 4);

        assert_eq!(scheme.polynomial().len(), polynomial.len());
        assert!(*scheme.identity() == identity);
        assert_eq!(shares.len(), 4); // ensure we used the DKG outputs
        assert_eq!(scheme.share().unwrap().index, shares[0].index);
    }

    // #[test]
    // fn sign_vote_matches_notarize() {
    //     let mut rng = StdRng::seed_from_u64(11);
    //     let threshold = 3usize;
    //     let (public_poly, mut shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let share = shares.remove(0);
    //     let scheme: BlsThresholdScheme<MinSig> =
    //         BlsThresholdScheme::new(share.index, polynomial, identity, share.clone(), threshold);

    //     let round = Round::new(0, 5);
    //     let payload = Sha256Digest::from([1u8; 32]);
    //     let proposal = Proposal::new(round, 4, payload);
    //     let namespace = b"notarize";

    //     let vote = scheme
    //         .sign_vote(VoteContext::Notarize {
    //             namespace,
    //             proposal: &proposal,
    //         })
    //         .expect("sign vote");

    //     // let legacy = types::Notarize::<MinSig, _>::sign(namespace, &share, proposal.clone());
    //     // assert!(vote.signature.0 == legacy.proposal_signature.value);
    //     // assert!(vote.signature.1 == legacy.seed_signature.value);
    // }

    // #[test]
    // fn sign_vote_matches_nullify() {
    //     let mut rng = StdRng::seed_from_u64(13);
    //     let threshold = 3usize;
    //     let (public_poly, mut shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let share = shares.remove(0);
    //     let scheme: BlsThresholdScheme<MinSig> =
    //         BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

    //     let round = Round::new(0, 7);
    //     let namespace = b"nullify";

    //     let vote = scheme
    //         .sign_vote::<Sha256Digest>(VoteContext::Nullify { namespace, round }, share.index)
    //         .expect("sign vote");

    //     let legacy = types::Nullify::<MinSig>::sign(namespace, &share, round);
    //     assert!(vote.signature.0 == legacy.view_signature.value);
    //     assert!(vote.signature.1 == legacy.seed_signature.value);
    // }

    // #[test]
    // fn sign_vote_matches_finalize() {
    //     let mut rng = StdRng::seed_from_u64(17);
    //     let threshold = 3usize;
    //     let (public_poly, mut shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let share = shares.remove(0);
    //     let scheme: BlsThresholdScheme<MinSig> =
    //         BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

    //     let round = Round::new(0, 9);
    //     let payload = Sha256Digest::from([2u8; 32]);
    //     let proposal = Proposal::new(round, 8, payload);
    //     let namespace = b"finalize";

    //     let vote = scheme
    //         .sign_vote(
    //             VoteContext::Finalize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             share.index,
    //         )
    //         .expect("sign vote");

    //     let legacy = types::Finalize::<MinSig, _>::sign(namespace, &share, proposal.clone());
    //     assert!(vote.signature.0 == legacy.proposal_signature.value);
    //     let seed_ns = seed_namespace(namespace);
    //     let seed_bytes = proposal.round.encode();
    //     let expected_seed =
    //         partial_sign_message::<MinSig>(&share, Some(seed_ns.as_ref()), seed_bytes.as_ref());
    //     assert!(vote.signature.1 == expected_seed.value);
    // }

    // #[test]
    // fn sign_vote_rejects_wrong_signer() {
    //     let mut rng = StdRng::seed_from_u64(19);
    //     let threshold = 3usize;
    //     let (public_poly, mut shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let share = shares.remove(0);
    //     let scheme: BlsThresholdScheme<MinSig> =
    //         BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

    //     let round = Round::new(0, 1);
    //     let payload = Sha256Digest::from([3u8; 32]);
    //     let proposal = Proposal::new(round, 0, payload);

    //     let err = scheme
    //         .sign_vote(
    //             VoteContext::Notarize {
    //                 namespace: b"ns",
    //                 proposal: &proposal,
    //             },
    //             share.index + 1,
    //         )
    //         .expect_err("expected mismatch");

    //     match err {
    //         Error::SignerMismatch { expected, actual } => {
    //             assert_eq!(expected, share.index);
    //             assert_eq!(actual, share.index + 1);
    //         }
    //         other => panic!("unexpected error: {other:?}"),
    //     }
    // }

    // #[test]
    // fn vote_codec_roundtrip() {
    //     let mut rng = StdRng::seed_from_u64(41);
    //     let threshold = 3usize;
    //     let (public_poly, mut shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let share = shares.remove(0);
    //     let scheme: BlsThresholdScheme<MinSig> =
    //         BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

    //     let round = Round::new(0, 7);
    //     let payload = Sha256Digest::from([2u8; 32]);
    //     let proposal = Proposal::new(round, 6, payload);

    //     let vote = scheme
    //         .sign_vote(
    //             VoteContext::Notarize {
    //                 namespace: b"codec-vote",
    //                 proposal: &proposal,
    //             },
    //             share.index,
    //         )
    //         .expect("vote");

    //     let encoded = vote.encode();
    //     let decoded = <Vote<BlsThresholdScheme<MinSig>>>::decode(encoded).expect("decode");
    //     assert_eq!(decoded, vote);
    // }

    // #[test]
    // fn notarize_vote_codec_roundtrip() {
    //     let mut rng = StdRng::seed_from_u64(43);
    //     let threshold = 3usize;
    //     let (public_poly, mut shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let share = shares.remove(0);
    //     let scheme: BlsThresholdScheme<MinSig> =
    //         BlsThresholdScheme::new(polynomial, identity, share.clone(), threshold);

    //     let round = Round::new(0, 9);
    //     let payload = Sha256Digest::from([9u8; 32]);
    //     let proposal = Proposal::new(round, 8, payload);

    //     let vote = scheme
    //         .sign_vote(
    //             VoteContext::Notarize {
    //                 namespace: b"codec-notarize-vote",
    //                 proposal: &proposal,
    //             },
    //             share.index,
    //         )
    //         .expect("vote");

    //     let message: Notarize<BlsThresholdScheme<MinSig>, Sha256Digest> = Notarize {
    //         proposal: proposal.clone(),
    //         vote,
    //     };

    //     let encoded = message.encode();
    //     let decoded =
    //         <Notarize<BlsThresholdScheme<MinSig>, Sha256Digest>>::decode(encoded).expect("decode");
    //     assert_eq!(decoded.proposal, message.proposal);
    //     assert_eq!(decoded.vote, message.vote);
    // }

    // #[test]
    // fn notarization_certificate_codec_roundtrip() {
    //     let threshold = 3usize;
    //     let (schemes, _) = build_scheme_set(45, 4, threshold);
    //     let round = Round::new(0, 30);
    //     let payload = Sha256Digest::from([4u8; 32]);
    //     let proposal = Proposal::new(round, 29, payload);
    //     let namespace = b"codec-notarization";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(threshold)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote(
    //                     VoteContext::Notarize {
    //                         namespace,
    //                         proposal: &proposal,
    //                     },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let certificate = schemes[0]
    //         .assemble_certificate(
    //             VoteContext::Notarize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &votes,
    //         )
    //         .expect("assemble");

    //     let message: Notarization<BlsThresholdScheme<MinSig>, Sha256Digest> = Notarization {
    //         proposal: proposal.clone(),
    //         certificate,
    //     };

    //     let encoded = message.encode();
    //     let decoded = <Notarization<BlsThresholdScheme<MinSig>, Sha256Digest>>::decode(encoded)
    //         .expect("decode");
    //     assert_eq!(decoded.proposal, message.proposal);
    //     assert_eq!(decoded.certificate, message.certificate);
    // }

    // #[test]
    // fn verify_votes_notarize_filters_invalid() {
    //     let mut rng = StdRng::seed_from_u64(23);
    //     let threshold = 3usize;
    //     let (public_poly, shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 5, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 5);
    //     let identity = *public_poly.constant();

    //     let schemes: Vec<_> = shares
    //         .iter()
    //         .map(|share| {
    //             BlsThresholdScheme::<MinSig>::new(
    //                 polynomial.clone(),
    //                 identity,
    //                 share.clone(),
    //                 threshold,
    //             )
    //         })
    //         .collect();

    //     let round = Round::new(0, 12);
    //     let payload = Sha256Digest::from([4u8; 32]);
    //     let proposal = Proposal::new(round, 11, payload);
    //     let namespace = b"verify-notarize";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(3)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote(
    //                     VoteContext::Notarize {
    //                         namespace,
    //                         proposal: &proposal,
    //                     },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let verifier = &schemes[0];

    //     let verification = verifier.verify_votes(
    //         VoteContext::Notarize {
    //             namespace,
    //             proposal: &proposal,
    //         },
    //         votes.clone(),
    //     );
    //     assert!(verification.invalid_signers.is_empty());
    //     assert_eq!(verification.verified.len(), votes.len());

    //     let mut corrupted = votes.clone();
    //     corrupted[0].signer = 42;
    //     let verification = verifier.verify_votes(
    //         VoteContext::Notarize {
    //             namespace,
    //             proposal: &proposal,
    //         },
    //         corrupted,
    //     );
    //     assert_eq!(verification.invalid_signers, vec![42]);
    //     assert_eq!(verification.verified.len(), votes.len() - 1);
    // }

    // #[test]
    // fn assemble_certificate_notarize() {
    //     let mut rng = StdRng::seed_from_u64(29);
    //     let threshold = 3usize;
    //     let (public_poly, shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let schemes: Vec<_> = shares
    //         .iter()
    //         .map(|share| {
    //             BlsThresholdScheme::<MinSig>::new(
    //                 polynomial.clone(),
    //                 identity,
    //                 share.clone(),
    //                 threshold,
    //             )
    //         })
    //         .collect();

    //     let round = Round::new(0, 15);
    //     let payload = Sha256Digest::from([5u8; 32]);
    //     let proposal = Proposal::new(round, 14, payload);
    //     let namespace = b"assemble-notarize";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(threshold)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote(
    //                     VoteContext::Notarize {
    //                         namespace,
    //                         proposal: &proposal,
    //                     },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let certificate = schemes[0]
    //         .assemble_certificate(
    //             VoteContext::Notarize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &votes,
    //         )
    //         .expect("assemble");

    //     let expected_proposal: Vec<_> = votes
    //         .iter()
    //         .map(|vote| PartialSignature::<MinSig> {
    //             index: vote.signer,
    //             value: vote.signature.0.clone(),
    //         })
    //         .collect();
    //     let expected_seed: Vec<_> = votes
    //         .iter()
    //         .map(|vote| PartialSignature::<MinSig> {
    //             index: vote.signer,
    //             value: vote.signature.1.clone(),
    //         })
    //         .collect();
    //     let expected = threshold_signature_recover_pair::<MinSig, _>(
    //         threshold as u32,
    //         expected_proposal.iter(),
    //         expected_seed.iter(),
    //     )
    //     .expect("recover");

    //     assert_eq!(certificate.0, expected.0);
    //     assert_eq!(certificate.1, expected.1);
    // }

    // #[test]
    // fn assemble_certificate_requires_quorum() {
    //     let mut rng = StdRng::seed_from_u64(31);
    //     let threshold = 3usize;
    //     let (public_poly, shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, 4, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, 4);
    //     let identity = *public_poly.constant();
    //     let schemes: Vec<_> = shares
    //         .iter()
    //         .map(|share| {
    //             BlsThresholdScheme::<MinSig>::new(
    //                 polynomial.clone(),
    //                 identity,
    //                 share.clone(),
    //                 threshold,
    //             )
    //         })
    //         .collect();

    //     let round = Round::new(0, 18);
    //     let payload = Sha256Digest::from([6u8; 32]);
    //     let proposal = Proposal::new(round, 17, payload);
    //     let namespace = b"assemble-insufficient";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(threshold - 1)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote(
    //                     VoteContext::Notarize {
    //                         namespace,
    //                         proposal: &proposal,
    //                     },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let err = schemes[0]
    //         .assemble_certificate(
    //             VoteContext::Notarize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &votes,
    //         )
    //         .expect_err("expected insufficient votes");

    //     match err {
    //         Error::InsufficientVotes { required, actual } => {
    //             assert_eq!(required, threshold);
    //             assert_eq!(actual, votes.len());
    //         }
    //         other => panic!("unexpected error: {other:?}"),
    //     }
    // }

    // fn build_scheme_set(
    //     seed: u64,
    //     n: usize,
    //     threshold: usize,
    // ) -> (Vec<BlsThresholdScheme<MinSig>>, Vec<Share>) {
    //     let mut rng = StdRng::seed_from_u64(seed);
    //     let (public_poly, shares) =
    //         generate_shares::<_, MinSig>(&mut rng, None, n as u32, threshold as u32);
    //     let polynomial = evaluate_all::<MinSig>(&public_poly, n as u32);
    //     let identity = *public_poly.constant();
    //     let schemes = shares
    //         .iter()
    //         .map(|share| {
    //             BlsThresholdScheme::new(polynomial.clone(), identity, share.clone(), threshold)
    //         })
    //         .collect();
    //     (schemes, shares)
    // }

    // #[test]
    // fn verify_certificate_notarize_success_and_failure() {
    //     let threshold = 3;
    //     let (schemes, _) = build_scheme_set(33, 4, threshold);
    //     let round = Round::new(0, 20);
    //     let payload = Sha256Digest::from([7u8; 32]);
    //     let proposal = Proposal::new(round, 19, payload);
    //     let namespace = b"verify-cert-notarize";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(threshold)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote(
    //                     VoteContext::Notarize {
    //                         namespace,
    //                         proposal: &proposal,
    //                     },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let certificate = schemes[0]
    //         .assemble_certificate(
    //             VoteContext::Notarize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &votes,
    //         )
    //         .expect("assemble");

    //     let randomness = schemes[1]
    //         .verify_certificate(
    //             VoteContext::Notarize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &certificate,
    //         )
    //         .expect("verify");
    //     let expected_seed = (proposal.round, certificate.1.clone());
    //     assert_eq!(randomness, Some(expected_seed));

    //     let mut bad_certificate = certificate.clone();
    //     let mut corrupted = bad_certificate.0.clone();
    //     corrupted.add(&<MinSig as Variant>::Signature::one());
    //     bad_certificate.0 = corrupted;
    //     let err = schemes[1]
    //         .verify_certificate(
    //             VoteContext::Notarize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &bad_certificate,
    //         )
    //         .expect_err("expected invalid certificate");
    //     assert!(matches!(err, Error::Threshold(_)));
    // }

    // #[test]
    // fn verify_certificate_nullify_success_and_failure() {
    //     let threshold = 3;
    //     let (schemes, _) = build_scheme_set(35, 4, threshold);
    //     let round = Round::new(0, 22);
    //     let namespace = b"verify-cert-nullify";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(threshold)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote::<Sha256Digest>(
    //                     VoteContext::Nullify { namespace, round },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let certificate = schemes[0]
    //         .assemble_certificate::<Sha256Digest>(VoteContext::Nullify { namespace, round }, &votes)
    //         .expect("assemble");

    //     let randomness = schemes[1]
    //         .verify_certificate::<Sha256Digest>(
    //             VoteContext::Nullify { namespace, round },
    //             &certificate,
    //         )
    //         .expect("verify");
    //     let expected_seed = (round, certificate.1.clone());
    //     assert_eq!(randomness, Some(expected_seed));

    //     let mut bad_certificate = certificate.clone();
    //     let mut corrupted = bad_certificate.1.clone();
    //     corrupted.add(&<MinSig as Variant>::Signature::one());
    //     bad_certificate.1 = corrupted;
    //     let err = schemes[1]
    //         .verify_certificate::<Sha256Digest>(
    //             VoteContext::Nullify { namespace, round },
    //             &bad_certificate,
    //         )
    //         .expect_err("expected invalid certificate");
    //     assert!(matches!(err, Error::Threshold(_)));
    // }

    // #[test]
    // fn verify_certificate_finalize_success_and_failure() {
    //     let threshold = 3;
    //     let (schemes, _) = build_scheme_set(37, 4, threshold);
    //     let round = Round::new(0, 25);
    //     let payload = Sha256Digest::from([8u8; 32]);
    //     let proposal = Proposal::new(round, 24, payload);
    //     let namespace = b"verify-cert-finalize";

    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .take(threshold)
    //         .map(|scheme| {
    //             scheme
    //                 .sign_vote(
    //                     VoteContext::Finalize {
    //                         namespace,
    //                         proposal: &proposal,
    //                     },
    //                     scheme.share.index,
    //                 )
    //                 .expect("sign vote")
    //         })
    //         .collect();

    //     let certificate = schemes[0]
    //         .assemble_certificate(
    //             VoteContext::Finalize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &votes,
    //         )
    //         .expect("assemble");

    //     let randomness = schemes[1]
    //         .verify_certificate(
    //             VoteContext::Finalize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &certificate,
    //         )
    //         .expect("verify");
    //     let expected_seed = (proposal.round, certificate.1.clone());
    //     assert_eq!(randomness, Some(expected_seed));

    //     let mut bad_certificate = certificate.clone();
    //     let mut corrupted = bad_certificate.0.clone();
    //     corrupted.add(&<MinSig as Variant>::Signature::one());
    //     bad_certificate.0 = corrupted;
    //     let err = schemes[1]
    //         .verify_certificate(
    //             VoteContext::Finalize {
    //                 namespace,
    //                 proposal: &proposal,
    //             },
    //             &bad_certificate,
    //         )
    //         .expect_err("expected invalid certificate");
    //     assert!(matches!(err, Error::Threshold(_)));
    // }
}
