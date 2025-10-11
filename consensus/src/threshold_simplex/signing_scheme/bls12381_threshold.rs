//! BLS12-381 threshold implementation of the signing scheme abstraction.
//!
//! Validators contribute partial signatures over both the consensus message and the
//! per-view seed that feeds leader selection and downstream randomness. Once a quorum
//! is collected, the partials are aggregated into a certificate under the shared BLS
//! public identity.

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
                partial_verify_multiple_public_keys_precomputed, threshold_signature_recover,
                threshold_signature_recover_pair,
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

/// Signing scheme state for the BLS threshold flow.
///
/// The enum mirrors the roles a node may play: a signer (with its share),
/// a verifier (with evaluated public polynomial), or an external verifier that
/// only checks recovered certificates.
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

/// Combined message/seed signature pair emitted by the BLS scheme.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Signature<V: Variant> {
    /// Signature over the consensus message (partial or recovered aggregate).
    pub message_signature: V::Signature,
    /// Signature over the per-view seed (partial or recovered aggregate).
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

    fn into_verifier(self) -> Self {
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

    fn assemble_certificate<I>(
        &self,
        votes: I,
        certificate: Option<Self::Certificate>,
    ) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Vote<Self>>,
    {
        let threshold = self.threshold();

        // We can re-use the notarization certificate's seed signature
        if let Some(notarization_certificate) = certificate {
            let message_partials: Vec<_> = votes
                .into_iter()
                .map(|vote| PartialSignature::<V> {
                    index: vote.signer,
                    value: vote.signature.message_signature,
                })
                .collect();

            if message_partials.len() < threshold as usize {
                return None;
            }

            let message_signature =
                threshold_signature_recover::<V, _>(threshold, message_partials.iter()).ok()?;

            return Some(Signature {
                message_signature,
                seed_signature: notarization_certificate.seed_signature,
            });
        }

        // Otherwise we need to recover both signatures
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

    fn certificate_codec_config_unbounded() -> Self::CertificateCfg {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        threshold_simplex::{
            signing_scheme::{notarize_namespace, seed_namespace},
            types::{Proposal, VoteContext},
        },
        types::Round,
    };
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{
        bls12381::{
            dkg::ops,
            primitives::{
                ops::partial_sign_message,
                poly::Public,
                variant::{MinPk, MinSig, Variant},
            },
        },
        sha256::Digest as Sha256Digest,
        Hasher, Sha256,
    };
    use commonware_utils::quorum;
    use rand::{rngs::StdRng, thread_rng, SeedableRng};

    const NAMESPACE: &[u8] = b"bls-threshold-signing-scheme";

    type Scheme<V> = super::Scheme<V>;
    type Signature<V> = super::Signature<V>;

    fn setup_signers<V: Variant>(n: u32, seed: u64) -> (Vec<Scheme<V>>, Vec<()>, Public<V>) {
        assert!(n >= 2);
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = quorum(n);
        let (polynomial, shares) = ops::generate_shares::<_, V>(&mut rng, None, n, threshold);

        let participants = vec![(); n as usize];
        let schemes = shares
            .into_iter()
            .map(|share| Scheme::new(&participants, &polynomial, share))
            .collect();

        (schemes, participants, polynomial)
    }

    fn sample_proposal(round: u64, view: u64, tag: u8) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(round, view),
            view.saturating_sub(1),
            Sha256::hash(&[tag]),
        )
    }

    fn sign_vote_roundtrip_for_each_context<V: Variant>() {
        let (schemes, _, _) = setup_signers::<V>(4, 7);
        let scheme = &schemes[0];
        assert!(scheme.can_sign());

        let proposal = sample_proposal(0, 2, 1);
        let notarize_vote = scheme.sign_vote(
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
        );
        assert!(scheme.verify_vote(
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
            &notarize_vote
        ));

        let nullify_vote = scheme.sign_vote::<Sha256Digest>(
            NAMESPACE,
            VoteContext::Nullify {
                round: proposal.round,
            },
        );
        assert!(scheme.verify_vote::<Sha256Digest>(
            NAMESPACE,
            VoteContext::Nullify {
                round: proposal.round,
            },
            &nullify_vote
        ));

        let finalize_vote = scheme.sign_vote(
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
        );
        assert!(scheme.verify_vote(
            NAMESPACE,
            VoteContext::Finalize {
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
        let (_, participants, polynomial) = setup_signers::<V>(4, 11);
        let verifier = Scheme::<V>::verifier(&participants, &polynomial);
        assert!(!verifier.can_sign());

        let proposal = sample_proposal(0, 3, 2);
        verifier.sign_vote(
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
        );
    }

    #[test]
    #[should_panic(expected = "can only be called after checking can_sign")]
    fn test_verifier_cannot_sign_min_pk() {
        verifier_cannot_sign::<MinPk>();
    }

    #[test]
    #[should_panic(expected = "can only be called after checking can_sign")]
    fn test_verifier_cannot_sign_min_sig() {
        verifier_cannot_sign::<MinSig>();
    }

    fn verifier_accepts_votes<V: Variant>() {
        let (schemes, participants, polynomial) = setup_signers::<V>(4, 11);
        let verifier = Scheme::<V>::verifier(&participants, &polynomial);
        assert!(!verifier.can_sign());

        let proposal = sample_proposal(0, 3, 2);
        let vote = schemes[1].sign_vote(
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
        );
        let verifier = Scheme::<V>::verifier(&participants, &polynomial);
        assert!(verifier.verify_vote(
            NAMESPACE,
            VoteContext::Notarize {
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
        let (schemes, _, _) = setup_signers::<V>(5, 13);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 5, 3);

        let mut votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme.sign_vote(
                    NAMESPACE,
                    VoteContext::Notarize {
                        proposal: &proposal,
                    },
                )
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

    fn assemble_certificate_requires_quorum<V: Variant>() {
        let (schemes, _, _) = setup_signers::<V>(4, 17);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 7, 4);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum - 1)
            .map(|scheme| {
                scheme.sign_vote(
                    NAMESPACE,
                    VoteContext::Notarize {
                        proposal: &proposal,
                    },
                )
            })
            .collect();

        assert!(schemes[0].assemble_certificate(votes, None).is_none());
    }

    #[test]
    fn test_assemble_certificate_requires_quorum() {
        assemble_certificate_requires_quorum::<MinPk>();
        assemble_certificate_requires_quorum::<MinSig>();
    }

    fn verify_certificate<V: Variant>() {
        let (schemes, participants, polynomial) = setup_signers::<V>(4, 19);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 9, 5);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme.sign_vote(
                    NAMESPACE,
                    VoteContext::Finalize {
                        proposal: &proposal,
                    },
                )
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes, None)
            .expect("assemble certificate");

        let verifier = Scheme::<V>::verifier(&participants, &polynomial);
        assert!(verifier.verify_certificate(
            &mut thread_rng(),
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

    fn verify_certificate_detects_corruption<V: Variant>() {
        let (schemes, participants, polynomial) = setup_signers::<V>(4, 23);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 11, 6);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme.sign_vote(
                    NAMESPACE,
                    VoteContext::Notarize {
                        proposal: &proposal,
                    },
                )
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes, None)
            .expect("assemble certificate");

        let verifier = Scheme::<V>::verifier(&participants, &polynomial);
        assert!(verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
            &certificate,
        ));

        let mut corrupted = certificate.clone();
        corrupted.message_signature = corrupted.seed_signature;
        assert!(
            !Scheme::<V>::verifier(&participants, &polynomial).verify_certificate(
                &mut thread_rng(),
                NAMESPACE,
                VoteContext::Notarize {
                    proposal: &proposal,
                },
                &corrupted,
            )
        );
    }

    #[test]
    fn test_verify_certificate_detects_corruption() {
        verify_certificate_detects_corruption::<MinPk>();
        verify_certificate_detects_corruption::<MinSig>();
    }

    fn certificate_codec_roundtrip<V: Variant>() {
        let (schemes, _, _) = setup_signers::<V>(5, 29);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 13, 7);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme.sign_vote(
                    NAMESPACE,
                    VoteContext::Notarize {
                        proposal: &proposal,
                    },
                )
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes, None)
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

    fn scheme_clone_and_into_verifier<V: Variant>() {
        let (schemes, participants, polynomial) = setup_signers::<V>(3, 31);
        let signer = schemes[0].clone();
        assert!(signer.can_sign());

        let verifier = signer.clone().into_verifier();
        assert!(!verifier.can_sign());

        let pure_verifier = Scheme::<V>::verifier(&participants, &polynomial);
        assert!(!pure_verifier.can_sign());
    }

    #[test]
    fn test_scheme_clone_and_into_verifier() {
        scheme_clone_and_into_verifier::<MinPk>();
        scheme_clone_and_into_verifier::<MinSig>();
    }

    fn certificate_verifier_accepts_certificates<V: Variant>() {
        let (schemes, _, polynomial) = setup_signers::<V>(4, 37);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 15, 8);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme.sign_vote(
                    NAMESPACE,
                    VoteContext::Finalize {
                        proposal: &proposal,
                    },
                )
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes, None)
            .expect("assemble certificate");

        let certificate_verifier = Scheme::<V>::certificate_verifier(*polynomial.constant());
        assert!(!certificate_verifier.can_sign());
        assert!(certificate_verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Finalize {
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
        let (schemes, _, polynomial) = setup_signers::<V>(4, 37);
        let certificate_verifier = Scheme::<V>::certificate_verifier(*polynomial.constant());
        let proposal = sample_proposal(0, 15, 8);
        let vote = schemes[1].sign_vote(
            NAMESPACE,
            VoteContext::Finalize {
                proposal: &proposal,
            },
        );

        certificate_verifier.verify_vote(
            NAMESPACE,
            VoteContext::Finalize {
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

    fn assemble_certificate_reuses_notarization_seed<V: Variant>() {
        let (schemes, _, _) = setup_signers::<V>(5, 41);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 17, 9);

        let notarize_votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme.sign_vote(
                    NAMESPACE,
                    VoteContext::Notarize {
                        proposal: &proposal,
                    },
                )
            })
            .collect();

        let notarization_certificate = schemes[0]
            .assemble_certificate(notarize_votes, None)
            .expect("assemble notarization");

        let finalize_votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme.sign_vote(
                    NAMESPACE,
                    VoteContext::Finalize {
                        proposal: &proposal,
                    },
                )
            })
            .collect();

        let finalization_certificate = schemes[0]
            .assemble_certificate(finalize_votes, Some(notarization_certificate.clone()))
            .expect("assemble finalization");

        assert_eq!(
            finalization_certificate.seed_signature,
            notarization_certificate.seed_signature
        );
    }

    #[test]
    fn test_assemble_certificate_reuses_notarization_seed() {
        assemble_certificate_reuses_notarization_seed::<MinPk>();
        assemble_certificate_reuses_notarization_seed::<MinSig>();
    }

    fn verify_certificate_returns_seed_randomness<V: Variant>() {
        let (schemes, _, _) = setup_signers::<V>(4, 43);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 19, 10);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme.sign_vote(
                    NAMESPACE,
                    VoteContext::Notarize {
                        proposal: &proposal,
                    },
                )
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes, None)
            .expect("assemble certificate");

        let randomness = schemes[0].randomness(&certificate);
        assert_eq!(randomness, Some(certificate.seed_signature));
    }

    #[test]
    fn test_verify_certificate_returns_seed_randomness() {
        verify_certificate_returns_seed_randomness::<MinPk>();
        verify_certificate_returns_seed_randomness::<MinSig>();
    }

    fn certificate_decode_rejects_length_mismatch<V: Variant>() {
        let (schemes, _, _) = setup_signers::<V>(4, 47);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 21, 11);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme.sign_vote::<Sha256Digest>(
                    NAMESPACE,
                    VoteContext::Nullify {
                        round: proposal.round,
                    },
                )
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes, None)
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
        let (schemes, _, _) = setup_signers::<V>(4, 53);
        let scheme = &schemes[0];
        let share = scheme.share().expect("has share");

        let proposal = sample_proposal(0, 23, 12);
        let vote = scheme.sign_vote(
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
        );

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
        let expected_seed =
            partial_sign_message::<V>(share, Some(seed_namespace.as_ref()), seed_message.as_ref())
                .value;

        assert_eq!(vote.signer, share.index);
        assert_eq!(vote.signature.message_signature, expected_message);
        assert_eq!(vote.signature.seed_signature, expected_seed);
    }

    #[test]
    fn test_sign_vote_partial_matches_share() {
        sign_vote_partial_matches_share::<MinPk>();
        sign_vote_partial_matches_share::<MinSig>();
    }

    fn verify_certificate_detects_seed_corruption<V: Variant>() {
        let (schemes, participants, polynomial) = setup_signers::<V>(4, 59);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 25, 13);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme.sign_vote::<Sha256Digest>(
                    NAMESPACE,
                    VoteContext::Nullify {
                        round: proposal.round,
                    },
                )
            })
            .collect();

        let certificate = schemes[0]
            .assemble_certificate(votes, None)
            .expect("assemble certificate");

        let verifier = Scheme::<V>::verifier(&participants, &polynomial);
        assert!(verifier.verify_certificate::<_, Sha256Digest>(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Nullify {
                round: proposal.round,
            },
            &certificate,
        ));

        let mut corrupted = certificate.clone();
        corrupted.seed_signature = corrupted.message_signature;
        assert!(!Scheme::<V>::verifier(&participants, &polynomial)
            .verify_certificate::<_, Sha256Digest>(
                &mut thread_rng(),
                NAMESPACE,
                VoteContext::Nullify {
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
}
