//! BLS12-381 threshold implementation of the [`Scheme`] trait for `simplex`.
//!
//! [`Scheme`] is **non-attributable**: exposing partial signatures
//! as evidence of either liveness or of committing a fault is not safe. With threshold signatures,
//! any `t` valid partial signatures can be used to forge a partial signature for any other player,
//! enabling equivocation attacks. Because peer connections are authenticated, evidence can be used locally
//! (as it must be sent by said participant) but can't be used by an external observer.

use crate::{
    simplex::{
        signing_scheme::{
            self, finalize_namespace, notarize_namespace, nullify_namespace, seed_namespace,
            seed_namespace_and_message, vote_namespace_and_message,
        },
        types::{Finalization, Notarization, OrderedExt, Vote, VoteContext, VoteVerification},
    },
    types::{Epoch, Round, View},
    Epochable, Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{
    bls12381::{
        dkg::ops,
        primitives::{
            group::Share,
            ops::{
                aggregate_signatures, aggregate_verify_multiple_messages, partial_sign_message,
                partial_verify_multiple_public_keys_precomputed, threshold_signature_recover_pair,
                verify_message,
            },
            poly::{self, PartialSignature, Public},
            variant::Variant,
        },
        tle,
    },
    Digest, PublicKey,
};
use commonware_utils::set::{Ordered, OrderedAssociated};
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
        participants: OrderedAssociated<P, V::Public>,
        /// Public identity of the committee (constant across reshares).
        identity: V::Public,
        /// Local share used to generate partial signatures.
        share: Share,
    },
    Verifier {
        /// Participants in the committee.
        participants: OrderedAssociated<P, V::Public>,
        /// Public identity of the committee (constant across reshares).
        identity: V::Public,
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
    /// If the provided share does not match the polynomial evaluation at its index,
    /// the instance will act as a verifier (unable to sign votes).
    ///
    /// * `participants` - ordered set of participant identity keys
    /// * `polynomial` - public polynomial for threshold verification
    /// * `share` - local threshold share for signing
    pub fn new(participants: Ordered<P>, polynomial: &Public<V>, share: Share) -> Self {
        let identity = *poly::public::<V>(polynomial);
        let polynomial = ops::evaluate_all::<V>(polynomial, participants.len() as u32);
        let participants = participants
            .into_iter()
            .zip(polynomial)
            .collect::<OrderedAssociated<_, _>>();

        let public_key = share.public::<V>();
        if let Some(index) = participants.values().iter().position(|p| p == &public_key) {
            assert_eq!(
                index as u32, share.index,
                "share index must match participant index"
            );
            Self::Signer {
                participants,
                identity,
                share,
            }
        } else {
            Self::Verifier {
                participants,
                identity,
            }
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
    pub fn verifier(participants: Ordered<P>, polynomial: &Public<V>) -> Self {
        let identity = *poly::public::<V>(polynomial);
        let polynomial = ops::evaluate_all::<V>(polynomial, participants.len() as u32);
        let participants = participants
            .into_iter()
            .zip(polynomial)
            .collect::<OrderedAssociated<_, _>>();

        Self::Verifier {
            participants,
            identity,
        }
    }

    /// Creates a verifier that only checks recovered certificates.
    ///
    /// This lightweight verifier can authenticate recovered threshold certificates but cannot
    /// verify individual votes or partial signatures.
    ///
    /// * `identity` - public identity of the committee (constant across reshares)
    pub fn certificate_verifier(identity: V::Public) -> Self {
        Self::CertificateVerifier { identity }
    }

    /// Returns the ordered set of participant public identity keys in the committee.
    pub fn participants(&self) -> &Ordered<P> {
        match self {
            Scheme::Signer { participants, .. } => participants,
            Scheme::Verifier { participants, .. } => participants,
            _ => panic!("can only be called for signer and verifier"),
        }
    }

    /// Returns the public identity of the committee (constant across reshares).
    pub fn identity(&self) -> &V::Public {
        match self {
            Scheme::Signer { identity, .. } => identity,
            Scheme::Verifier { identity, .. } => identity,
            Scheme::CertificateVerifier { identity, .. } => identity,
        }
    }

    /// Returns the local share if this instance can generate partial signatures.
    pub fn share(&self) -> Option<&Share> {
        match self {
            Scheme::Signer { share, .. } => Some(share),
            _ => None,
        }
    }

    /// Returns the evaluated public polynomial for validating partial signatures produced by committee members.
    pub fn polynomial(&self) -> &[V::Public] {
        match self {
            Scheme::Signer { participants, .. } => participants.values(),
            Scheme::Verifier { participants, .. } => participants.values(),
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
    pub fn new(round: Round, signature: V::Signature) -> Self {
        Seed { round, signature }
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
    pub fn round(&self) -> Round {
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
pub fn decrypt<V: Variant>(seed: &Seed<V>, ciphertext: &tle::Ciphertext<V>) -> Option<tle::Block> {
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

impl<P: PublicKey, V: Variant + Send + Sync> signing_scheme::Scheme for Scheme<P, V> {
    type PublicKey = P;
    type Signature = Signature<V>;
    type Certificate = Signature<V>;
    type Seed = Seed<V>;

    fn me(&self) -> Option<u32> {
        match self {
            Scheme::Signer { share, .. } => Some(share.index),
            _ => None,
        }
    }

    fn participants(&self) -> &Ordered<Self::PublicKey> {
        self.participants()
    }

    fn sign_vote<D: Digest>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
    ) -> Option<Vote<Self>> {
        let share = self.share()?;

        let (vote_namespace, vote_message) = vote_namespace_and_message(namespace, context);
        let vote_signature =
            partial_sign_message::<V>(share, Some(vote_namespace.as_ref()), vote_message.as_ref())
                .value;

        let (seed_namespace, seed_message) = seed_namespace_and_message(namespace, context);
        let seed_signature =
            partial_sign_message::<V>(share, Some(seed_namespace.as_ref()), seed_message.as_ref())
                .value;

        let signature = Signature {
            vote_signature,
            seed_signature,
        };

        Some(Vote {
            signer: share.index,
            signature,
        })
    }

    fn assemble_certificate<I>(&self, votes: I) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Vote<Self>>,
    {
        let (vote_partials, seed_partials): (Vec<_>, Vec<_>) = votes
            .into_iter()
            .map(|vote| {
                (
                    PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.vote_signature,
                    },
                    PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.seed_signature,
                    },
                )
            })
            .unzip();

        let quorum = self.participants().quorum();
        if vote_partials.len() < quorum as usize {
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
        context: VoteContext<'_, D>,
        vote: &Vote<Self>,
    ) -> bool {
        let Some(evaluated) = self.polynomial().get(vote.signer as usize) else {
            return false;
        };

        let (vote_namespace, vote_message) = vote_namespace_and_message(namespace, context);
        let (seed_namespace, seed_message) = seed_namespace_and_message(namespace, context);

        let signature = aggregate_signatures::<V, _>(&[
            vote.signature.vote_signature,
            vote.signature.seed_signature,
        ]);

        aggregate_verify_multiple_messages::<V, _>(
            evaluated,
            &[
                (Some(vote_namespace.as_ref()), vote_message.as_ref()),
                (Some(seed_namespace.as_ref()), seed_message.as_ref()),
            ],
            &signature,
            1,
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
        let (vote_partials, seed_partials): (Vec<_>, Vec<_>) = votes
            .into_iter()
            .map(|vote| {
                (
                    PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.vote_signature,
                    },
                    PartialSignature::<V> {
                        index: vote.signer,
                        value: vote.signature.seed_signature,
                    },
                )
            })
            .unzip();

        let polynomial = self.polynomial();
        let (vote_namespace, vote_message) = vote_namespace_and_message(namespace, context);
        if let Err(errs) = partial_verify_multiple_public_keys_precomputed::<V, _>(
            polynomial,
            Some(vote_namespace.as_ref()),
            vote_message.as_ref(),
            vote_partials.iter(),
        ) {
            for partial in errs {
                invalid.insert(partial.index);
            }
        }

        let (seed_namespace, seed_message) = seed_namespace_and_message(namespace, context);
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

        let verified = vote_partials
            .into_iter()
            .zip(seed_partials)
            .map(|(vote, seed)| Vote {
                signer: vote.index,
                signature: Signature {
                    vote_signature: vote.value,
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

        let (vote_namespace, vote_message) = vote_namespace_and_message(namespace, context);
        let (seed_namespace, seed_message) = seed_namespace_and_message(namespace, context);

        let signature =
            aggregate_signatures::<V, _>(&[certificate.vote_signature, certificate.seed_signature]);

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
                }
                VoteContext::Nullify { round } => {
                    // Prepare nullify message
                    let nullify_encoded = round.encode();
                    let nullify_message =
                        (Some(nullify_namespace.as_slice()), nullify_encoded.clone());
                    messages.push(nullify_message);
                }
                VoteContext::Finalize { proposal } => {
                    // Prepare finalize message
                    let finalize_message = proposal.encode();
                    let finalize_message = (Some(finalize_namespace.as_slice()), finalize_message);
                    messages.push(finalize_message);
                }
            }
            signatures.push(&certificate.vote_signature);

            // Add seed message (if not already present)
            if let Some(previous) = seeds.get(&context.view()) {
                if *previous != &certificate.seed_signature {
                    return false;
                }
            } else {
                let seed_message = match context {
                    VoteContext::Notarize { proposal } | VoteContext::Finalize { proposal } => {
                        proposal.round.encode()
                    }
                    VoteContext::Nullify { round } => round.encode(),
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

    fn seed(&self, round: Round, certificate: &Self::Certificate) -> Option<Self::Seed> {
        Some(Seed::new(round, certificate.seed_signature))
    }

    fn is_attributable(&self) -> bool {
        false
    }

    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {}

    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            mocks::fixtures::{bls12381_threshold, ed25519_participants, Fixture},
            signing_scheme::{notarize_namespace, seed_namespace, Scheme as _},
            types::{Finalization, Finalize, Notarization, Notarize, Proposal, VoteContext},
        },
        types::Round,
    };
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{
        bls12381::primitives::{
            ops::partial_sign_message,
            variant::{MinPk, MinSig, Variant},
        },
        ed25519,
        sha256::Digest as Sha256Digest,
        Hasher, Sha256,
    };
    use commonware_utils::quorum;
    use rand::{rngs::StdRng, thread_rng, SeedableRng};

    const NAMESPACE: &[u8] = b"bls-threshold-signing-scheme";

    type Scheme<V> = super::Scheme<ed25519::PublicKey, V>;
    type Signature<V> = super::Signature<V>;

    fn setup_signers<V: Variant>(n: u32, seed: u64) -> (Vec<Scheme<V>>, Scheme<V>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let Fixture {
            schemes, verifier, ..
        } = bls12381_threshold::<V, _>(&mut rng, n);

        (schemes, verifier)
    }

    fn sample_proposal(round: u64, view: u64, tag: u8) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(round, view),
            view.saturating_sub(1),
            Sha256::hash(&[tag]),
        )
    }

    fn signer_shares_must_match_participant_indices<V: Variant>() {
        let mut rng = StdRng::seed_from_u64(7);
        let participants = ed25519_participants(&mut rng, 4);
        let (polynomial, mut shares) = ops::generate_shares::<_, V>(&mut rng, None, 4, 3);
        shares[0].index = 999;
        Scheme::<V>::new(participants.keys().clone(), &polynomial, shares[0].clone());
    }

    #[test]
    #[should_panic(expected = "share index must match participant index")]
    fn test_signer_shares_must_match_participant_indices() {
        signer_shares_must_match_participant_indices::<MinPk>();
        signer_shares_must_match_participant_indices::<MinSig>();
    }

    fn sign_vote_roundtrip_for_each_context<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 7);
        let scheme = &schemes[0];

        let proposal = sample_proposal(0, 2, 1);
        let notarize_vote = scheme
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
            &notarize_vote
        ));

        let nullify_vote = scheme
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
            &nullify_vote
        ));

        let finalize_vote = scheme
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
    fn test_verifier_cannot_sign() {
        verifier_cannot_sign::<MinPk>();
        verifier_cannot_sign::<MinSig>();
    }

    fn verifier_accepts_votes<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(4, 11);
        let proposal = sample_proposal(0, 3, 2);
        let vote = schemes[1]
            .sign_vote(
                NAMESPACE,
                VoteContext::Notarize {
                    proposal: &proposal,
                },
            )
            .unwrap();
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
        let (schemes, _) = setup_signers::<V>(5, 13);
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

    fn assemble_certificate_requires_quorum<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 17);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 7, 4);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum - 1)
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

    fn verify_certificate<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(4, 19);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 9, 5);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
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
        let (schemes, verifier) = setup_signers::<V>(4, 23);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 11, 6);

        let votes: Vec<_> = schemes
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

        let certificate = schemes[0]
            .assemble_certificate(votes)
            .expect("assemble certificate");

        assert!(verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Notarize {
                proposal: &proposal,
            },
            &certificate,
        ));

        let mut corrupted = certificate.clone();
        corrupted.vote_signature = corrupted.seed_signature;
        assert!(!verifier.verify_certificate(
            &mut thread_rng(),
            NAMESPACE,
            VoteContext::Notarize {
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
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 13, 7);

        let votes: Vec<_> = schemes
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
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 1, 0);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
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
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 1, 0);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
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

        let seed = schemes[0]
            .seed(proposal.round, &certificate)
            .expect("extract seed");

        assert!(seed.verify(&schemes[0], NAMESPACE));

        let invalid_seed = schemes[0]
            .seed(
                Round::new(proposal.epoch(), proposal.view() + 1),
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
        let proposal = sample_proposal(0, 1, 0);

        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum(schemes.len() as u32) as usize)
            .map(|scheme| Notarize::sign(scheme, NAMESPACE, proposal.clone()).unwrap())
            .collect();

        let notarization = Notarization::from_notarizes(&schemes[0], &notarizes).unwrap();

        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum(schemes.len() as u32) as usize)
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
        let proposal = sample_proposal(0, 21, 9);

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
    fn test_scheme_clone_and_verifier() {
        scheme_clone_and_verifier::<MinPk>();
        scheme_clone_and_verifier::<MinSig>();
    }

    fn certificate_verifier_accepts_certificates<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 37);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 15, 8);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
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

        let certificate_verifier = Scheme::<V>::certificate_verifier(*schemes[0].identity());
        assert!(
            certificate_verifier
                .sign_vote(
                    NAMESPACE,
                    VoteContext::Finalize {
                        proposal: &proposal,
                    },
                )
                .is_none(),
            "certificate verifier should not produce votes"
        );
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
        let (schemes, _) = setup_signers::<V>(4, 37);
        let certificate_verifier = Scheme::<V>::certificate_verifier(*schemes[0].identity());
        let proposal = sample_proposal(0, 15, 8);
        let vote = schemes[1]
            .sign_vote(
                NAMESPACE,
                VoteContext::Finalize {
                    proposal: &proposal,
                },
            )
            .unwrap();

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

    fn verify_certificate_returns_seed_randomness<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(4, 43);
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 19, 10);

        let votes: Vec<_> = schemes
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
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 21, 11);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign_vote::<Sha256Digest>(
                        NAMESPACE,
                        VoteContext::Nullify {
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

        let proposal = sample_proposal(0, 23, 12);
        let vote = scheme
            .sign_vote(
                NAMESPACE,
                VoteContext::Notarize {
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
        let expected_seed =
            partial_sign_message::<V>(share, Some(seed_namespace.as_ref()), seed_message.as_ref())
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
        let quorum = quorum(schemes.len() as u32) as usize;
        let proposal = sample_proposal(0, 25, 13);

        let votes: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| {
                scheme
                    .sign_vote::<Sha256Digest>(
                        NAMESPACE,
                        VoteContext::Nullify {
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
            VoteContext::Nullify {
                round: proposal.round,
            },
            &certificate,
        ));

        let mut corrupted = certificate.clone();
        corrupted.seed_signature = corrupted.vote_signature;
        assert!(!verifier.verify_certificate::<_, Sha256Digest>(
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

    fn encrypt_decrypt<V: Variant>() {
        let (schemes, verifier) = setup_signers::<V>(4, 61);

        // Prepare a message to encrypt
        let message = b"Secret message for future view10";

        // Target round for encryption
        let target = Round::new(333, 10);

        // Encrypt using the scheme
        let ciphertext = schemes[0].encrypt(&mut thread_rng(), NAMESPACE, target, *message);

        // Can also encrypt with the verifier scheme
        let ciphertext_verifier = verifier.encrypt(&mut thread_rng(), NAMESPACE, target, *message);

        // Generate notarization for the target round to get the seed
        let proposal = sample_proposal(target.epoch(), target.view(), 14);
        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum(schemes.len() as u32) as usize)
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
}
