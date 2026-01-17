//! BLS12-381 threshold implementation of the [`Scheme`] trait for `minimmit`.
//!
//! [`Scheme`] is **non-attributable**: exposing partial signatures
//! as evidence of either liveness or of committing a fault is not safe. With threshold signatures,
//! any `t` valid partial signatures can be used to forge a partial signature for any other player,
//! enabling equivocation attacks. Because peer connections are authenticated, evidence can be used locally
//! (as it must be sent by said participant) but can't be used by an external observer.

use crate::{
    minimmit::{
        scheme::{seed_namespace, Namespace},
        types::{Finalization, MNotarization, Subject},
    },
    types::{Epoch, Participant, Round, View},
    Epochable, Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{
    bls12381::{
        primitives::{
            group::Share,
            ops::{self, aggregate, batch, threshold},
            sharing::Sharing,
            variant::{PartialSignature, Variant},
        },
        tle,
    },
    certificate::{self, Attestation, Signers, Subject as CertificateSubject, Verification},
    Digest, PublicKey,
};
use commonware_parallel::Strategy;
use commonware_utils::{ordered::Set, Faults, N5f1};
use rand::{rngs::StdRng, SeedableRng};
use rand_core::CryptoRngCore;
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Debug,
};

/// The role-specific data for a BLS12-381 threshold scheme participant.
#[derive(Clone, Debug)]
enum Role<P: PublicKey, V: Variant> {
    Signer {
        /// Participants in the committee.
        participants: Set<P>,
        /// The public polynomial, used for the group identity, and partial signatures.
        polynomial: Sharing<V>,
        /// Local share used to generate partial signatures.
        share: Share,
        /// Pre-computed namespaces for domain separation.
        namespace: Namespace,
    },
    Verifier {
        /// Participants in the committee.
        participants: Set<P>,
        /// The public polynomial, used for the group identity, and partial signatures.
        polynomial: Sharing<V>,
        /// Pre-computed namespaces for domain separation.
        namespace: Namespace,
    },
    CertificateVerifier {
        /// Public identity of the committee (constant across reshares).
        identity: V::Public,
        /// Pre-computed namespaces for domain separation.
        namespace: Namespace,
    },
}

/// BLS12-381 threshold implementation of the [`certificate::Scheme`] trait.
///
/// It is possible for a node to play one of the following roles: a signer (with its share),
/// a verifier (with evaluated public polynomial), or an external verifier that
/// only checks recovered certificates.
#[derive(Clone, Debug)]
pub struct Scheme<P: PublicKey, V: Variant> {
    role: Role<P, V>,
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
    /// * `namespace` - base namespace for domain separation
    /// * `participants` - ordered set of participant identity keys
    /// * `polynomial` - public polynomial for threshold verification
    /// * `share` - local threshold share for signing
    pub fn signer(
        namespace: &[u8],
        participants: Set<P>,
        polynomial: Sharing<V>,
        share: Share,
    ) -> Option<Self> {
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
            Some(Self {
                role: Role::Signer {
                    participants,
                    polynomial,
                    share,
                    namespace: Namespace::new(namespace),
                },
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
    /// * `namespace` - base namespace for domain separation
    /// * `participants` - ordered set of participant identity keys
    /// * `polynomial` - public polynomial for threshold verification
    pub fn verifier(namespace: &[u8], participants: Set<P>, polynomial: Sharing<V>) -> Self {
        assert_eq!(
            polynomial.total().get() as usize,
            participants.len(),
            "polynomial total must equal participant len"
        );
        polynomial.precompute_partial_publics();

        Self {
            role: Role::Verifier {
                participants,
                polynomial,
                namespace: Namespace::new(namespace),
            },
        }
    }

    /// Creates a verifier that only checks recovered certificates.
    ///
    /// This lightweight verifier can authenticate recovered threshold certificates but cannot
    /// verify individual votes or partial signatures.
    ///
    /// * `namespace` - base namespace for domain separation
    /// * `identity` - public identity of the committee (constant across reshares)
    pub fn certificate_verifier(namespace: &[u8], identity: V::Public) -> Self {
        Self {
            role: Role::CertificateVerifier {
                identity,
                namespace: Namespace::new(namespace),
            },
        }
    }

    /// Returns the ordered set of participant public identity keys in the committee.
    pub fn participants(&self) -> &Set<P> {
        match &self.role {
            Role::Signer { participants, .. } => participants,
            Role::Verifier { participants, .. } => participants,
            Role::CertificateVerifier { .. } => {
                panic!("can only be called for signer and verifier")
            }
        }
    }

    /// Returns the public identity of the committee (constant across reshares).
    pub fn identity(&self) -> &V::Public {
        match &self.role {
            Role::Signer { polynomial, .. } => polynomial.public(),
            Role::Verifier { polynomial, .. } => polynomial.public(),
            Role::CertificateVerifier { identity, .. } => identity,
        }
    }

    /// Returns the local share if this instance can generate partial signatures.
    pub const fn share(&self) -> Option<&Share> {
        match &self.role {
            Role::Signer { share, .. } => Some(share),
            _ => None,
        }
    }

    /// Returns the evaluated public polynomial for validating partial signatures produced by committee members.
    pub fn polynomial(&self) -> &Sharing<V> {
        match &self.role {
            Role::Signer { polynomial, .. } => polynomial,
            Role::Verifier { polynomial, .. } => polynomial,
            Role::CertificateVerifier { .. } => {
                panic!("can only be called for signer and verifier")
            }
        }
    }

    /// Returns the pre-computed namespaces.
    const fn namespace(&self) -> &Namespace {
        match &self.role {
            Role::Signer { namespace, .. } => namespace,
            Role::Verifier { namespace, .. } => namespace,
            Role::CertificateVerifier { namespace, .. } => namespace,
        }
    }

    /// Encrypts a message for a target round using Timelock Encryption ([TLE](tle)).
    ///
    /// The encrypted message can only be decrypted using the seed signature
    /// from a certificate of the target round (i.e. M-notarization, finalization,
    /// or nullification).
    pub fn encrypt<R: CryptoRngCore>(
        &self,
        rng: &mut R,
        target: Round,
        message: impl Into<tle::Block>,
    ) -> tle::Ciphertext<V> {
        let block = message.into();
        let target_message = target.encode();
        tle::encrypt(
            rng,
            *self.identity(),
            (&self.namespace().seed, &target_message),
            &block,
        )
    }
}

/// Encrypts a message for a future round using Timelock Encryption ([TLE](tle)).
///
/// The encrypted message can only be decrypted using the seed signature
/// from a certificate of the target round (i.e. M-notarization, finalization,
/// or nullification).
pub fn encrypt<R: CryptoRngCore, V: Variant>(
    rng: &mut R,
    identity: V::Public,
    namespace: &[u8],
    target: Round,
    message: impl Into<tle::Block>,
) -> tle::Ciphertext<V> {
    let block = message.into();
    let seed_ns = seed_namespace(namespace);
    let target_message = target.encode();
    tle::encrypt(rng, identity, (&seed_ns, &target_message), &block)
}

/// Generates a test fixture with Ed25519 identities and BLS12-381 threshold schemes.
///
/// Returns a [`commonware_cryptography::certificate::mocks::Fixture`] whose keys and
/// scheme instances share a consistent ordering.
///
/// Unlike the simplex fixture, this uses M5f1 for the polynomial threshold so that
/// M-notarization (2f+1 votes) can recover signatures. Finalization (n-f votes) will
/// have more than enough.
#[cfg(feature = "mocks")]
pub fn fixture<V, R>(
    rng: &mut R,
    namespace: &[u8],
    n: u32,
) -> commonware_cryptography::certificate::mocks::Fixture<
    Scheme<commonware_cryptography::ed25519::PublicKey, V>,
>
where
    V: Variant,
    R: rand::RngCore + rand::CryptoRng,
{
    use commonware_cryptography::{bls12381::dkg::deal, certificate::mocks::Fixture, ed25519};
    use commonware_utils::M5f1;

    assert!(n > 0);

    let associated = ed25519::certificate::mocks::participants(rng, n);
    let participants = associated.keys().clone();
    let participants_vec: Vec<_> = participants.clone().into();
    let private_keys: Vec<_> = participants_vec
        .iter()
        .map(|pk| {
            associated
                .get_value(pk)
                .expect("participant key must have an associated private key")
                .clone()
        })
        .collect();

    // Use M5f1 for the polynomial threshold so M-notarization (2f+1) can recover
    let (output, shares) = deal::<V, _, M5f1>(rng, Default::default(), participants.clone())
        .expect("deal should succeed");
    let polynomial = output.public().clone();

    let schemes = shares
        .into_iter()
        .map(|(_, share)| {
            Scheme::signer(namespace, participants.clone(), polynomial.clone(), share)
                .expect("scheme signer must be a participant")
        })
        .collect();
    let verifier = Scheme::verifier(namespace, participants, polynomial);

    Fixture {
        participants: participants_vec,
        private_keys,
        schemes,
        verifier,
    }
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

/// Certificate type for the BLS12-381 threshold scheme in minimmit.
///
/// This enum supports two forms:
/// - `Threshold`: Recovered threshold signature (for M-notarization, Nullification)
/// - `Aggregated`: Aggregated signatures with signers bitmap (for Finalization)
///
/// The distinction exists because:
/// - M-notarization/Nullification (2f+1 quorum) uses recovered threshold signatures
///   that can be verified against the group public key
/// - Finalization (n-f quorum) uses aggregated signatures with explicit signers
///   to prove exactly which validators signed (unforgeable even though 2f+1 partials
///   could forge additional threshold signatures)
///
/// Both forms include a seed signature for TLE support.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Certificate<V: Variant> {
    /// Recovered threshold signature.
    ///
    /// Used for M-notarization and Nullification (2f+1 quorum).
    /// Can be verified against the group public key.
    Threshold {
        /// The recovered threshold signature over the vote message.
        vote_signature: V::Signature,
        /// The recovered threshold signature over the seed (for TLE/randomness).
        seed_signature: V::Signature,
    },
    /// Aggregated signatures with explicit signers.
    ///
    /// Used for Finalization (n-f quorum). The vote signature is an aggregation
    /// of partial signatures that can be verified against the aggregated public
    /// keys of the signers. The seed signature is still recovered via threshold
    /// cryptography (since we have >= 2f+1 partials).
    Aggregated {
        /// Bitmap of which participants contributed signatures.
        signers: Signers,
        /// Aggregated BLS signature from the partial vote signatures.
        vote_signature: V::Signature,
        /// The recovered threshold signature over the seed (for TLE/randomness).
        seed_signature: V::Signature,
    },
}

impl<V: Variant> Certificate<V> {
    /// Returns the vote signature regardless of certificate type.
    pub const fn vote_signature(&self) -> &V::Signature {
        match self {
            Self::Threshold { vote_signature, .. } => vote_signature,
            Self::Aggregated { vote_signature, .. } => vote_signature,
        }
    }

    /// Returns the seed signature (available for both certificate types).
    pub const fn seed_signature(&self) -> &V::Signature {
        match self {
            Self::Threshold { seed_signature, .. } => seed_signature,
            Self::Aggregated { seed_signature, .. } => seed_signature,
        }
    }

    /// Returns true if this is a Threshold certificate.
    pub const fn is_threshold(&self) -> bool {
        matches!(self, Self::Threshold { .. })
    }

    /// Returns true if this is an Aggregated certificate.
    pub const fn is_aggregated(&self) -> bool {
        matches!(self, Self::Aggregated { .. })
    }
}

impl<V: Variant> Write for Certificate<V> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Threshold {
                vote_signature,
                seed_signature,
            } => {
                writer.put_u8(0); // Tag for Threshold
                vote_signature.write(writer);
                seed_signature.write(writer);
            }
            Self::Aggregated {
                signers,
                vote_signature,
                seed_signature,
            } => {
                writer.put_u8(1); // Tag for Aggregated
                signers.write(writer);
                vote_signature.write(writer);
                seed_signature.write(writer);
            }
        }
    }
}

impl<V: Variant> EncodeSize for Certificate<V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            // 1 byte tag
            Self::Threshold {
                vote_signature,
                seed_signature,
            } => vote_signature.encode_size() + seed_signature.encode_size(),
            Self::Aggregated {
                signers,
                vote_signature,
                seed_signature,
            } => {
                signers.encode_size() + vote_signature.encode_size() + seed_signature.encode_size()
            }
        }
    }
}

impl<V: Variant> Read for Certificate<V> {
    /// Config is the maximum number of participants (upper bound for Signers bitmap decoding).
    /// The actual participant count is validated at verification time.
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_participants: &usize) -> Result<Self, Error> {
        if reader.remaining() < 1 {
            return Err(Error::EndOfBuffer);
        }
        let tag = reader.get_u8();
        match tag {
            0 => {
                // Threshold
                let vote_signature = V::Signature::read(reader)?;
                let seed_signature = V::Signature::read(reader)?;
                Ok(Self::Threshold {
                    vote_signature,
                    seed_signature,
                })
            }
            1 => {
                // Aggregated
                let signers = Signers::read_cfg(reader, max_participants)?;
                let vote_signature = V::Signature::read(reader)?;
                let seed_signature = V::Signature::read(reader)?;
                Ok(Self::Aggregated {
                    signers,
                    vote_signature,
                    seed_signature,
                })
            }
            _ => Err(Error::Invalid("Certificate", "unknown tag")),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for Certificate<V>
where
    V::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        // Randomly choose between Threshold and Aggregated
        if u.arbitrary::<bool>()? {
            Ok(Self::Threshold {
                vote_signature: u.arbitrary()?,
                seed_signature: u.arbitrary()?,
            })
        } else {
            Ok(Self::Aggregated {
                signers: u.arbitrary()?,
                vote_signature: u.arbitrary()?,
                seed_signature: u.arbitrary()?,
            })
        }
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
    pub fn verify<P: PublicKey>(&self, scheme: &Scheme<P, V>) -> bool {
        let seed_message = self.round.encode();

        ops::verify_message::<V>(
            scheme.identity(),
            &scheme.namespace().seed,
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
/// M-notarization, finalization, or nullification).
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

impl<P: PublicKey, V: Variant, D: Digest> Seedable<V> for MNotarization<Scheme<P, V>, D> {
    fn seed(&self) -> Seed<V> {
        Seed::new(self.proposal.round, *self.certificate.seed_signature())
    }
}

impl<P: PublicKey, V: Variant, D: Digest> Seedable<V> for Finalization<Scheme<P, V>, D> {
    fn seed(&self) -> Seed<V> {
        Seed::new(self.proposal.round, *self.certificate.seed_signature())
    }
}

/// Extracts the seed message bytes from a Subject.
///
/// The seed message is the round encoded as bytes, used for per-view randomness.
fn seed_message_from_subject<D: Digest>(subject: &Subject<'_, D>) -> bytes::Bytes {
    match subject {
        Subject::Notarize { proposal } => proposal.round.encode(),
        Subject::Nullify { round } => round.encode(),
    }
}

impl<P: PublicKey, V: Variant> certificate::Scheme for Scheme<P, V> {
    type Subject<'a, D: Digest> = Subject<'a, D>;
    type PublicKey = P;
    type Signature = Signature<V>;
    type Certificate = Certificate<V>;

    fn me(&self) -> Option<Participant> {
        match &self.role {
            Role::Signer { share, .. } => Some(share.index),
            _ => None,
        }
    }

    fn participants(&self) -> &Set<Self::PublicKey> {
        self.participants()
    }

    fn sign<D: Digest>(&self, subject: Subject<'_, D>) -> Option<Attestation<Self>> {
        let share = self.share()?;

        let namespace = self.namespace();
        let vote_namespace = subject.namespace(namespace);
        let vote_message = subject.message();
        let vote_signature =
            threshold::sign_message::<V>(share, vote_namespace, &vote_message).value;

        let seed_message = seed_message_from_subject(&subject);
        let seed_signature =
            threshold::sign_message::<V>(share, &namespace.seed, &seed_message).value;

        let signature = Signature {
            vote_signature,
            seed_signature,
        };

        Some(Attestation {
            signer: share.index,
            signature,
        })
    }

    fn verify_attestation<R, D>(
        &self,
        rng: &mut R,
        subject: Subject<'_, D>,
        attestation: &Attestation<Self>,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRngCore,
        D: Digest,
    {
        let Ok(evaluated) = self.polynomial().partial_public(attestation.signer) else {
            return false;
        };

        let namespace = self.namespace();
        let vote_namespace = subject.namespace(namespace);
        let vote_message = subject.message();
        let seed_message = seed_message_from_subject(&subject);

        let entries = &[
            (
                vote_namespace,
                vote_message.as_ref(),
                attestation.signature.vote_signature,
            ),
            (
                &namespace.seed,
                seed_message.as_ref(),
                attestation.signature.seed_signature,
            ),
        ];
        batch::verify_same_signer::<_, V, _>(rng, &evaluated, entries, strategy).is_ok()
    }

    fn verify_attestations<R, D, I>(
        &self,
        rng: &mut R,
        subject: Subject<'_, D>,
        attestations: I,
        strategy: &impl Strategy,
    ) -> Verification<Self>
    where
        R: CryptoRngCore,
        D: Digest,
        I: IntoIterator<Item = Attestation<Self>>,
    {
        let namespace = self.namespace();
        let (vote_partials, seed_partials): (Vec<_>, Vec<_>) = attestations
            .into_iter()
            .map(|attestation| {
                (
                    PartialSignature::<V> {
                        index: attestation.signer,
                        value: attestation.signature.vote_signature,
                    },
                    PartialSignature::<V> {
                        index: attestation.signer,
                        value: attestation.signature.seed_signature,
                    },
                )
            })
            .unzip();

        let polynomial = self.polynomial();
        let vote_namespace = subject.namespace(namespace);
        let vote_message = subject.message();
        let seed_message = seed_message_from_subject(&subject);

        // Generate independent RNG seeds for concurrent verification
        let mut vote_rng_seed = [0u8; 32];
        let mut seed_rng_seed = [0u8; 32];
        rng.fill_bytes(&mut vote_rng_seed);
        rng.fill_bytes(&mut seed_rng_seed);

        // Verify vote and seed signatures concurrently.
        let (vote_invalid, seed_invalid) = strategy.join(
            || {
                let mut vote_rng = StdRng::from_seed(vote_rng_seed);
                match threshold::batch_verify_same_message::<_, V, _>(
                    &mut vote_rng,
                    polynomial,
                    vote_namespace,
                    &vote_message,
                    vote_partials.iter(),
                    strategy,
                ) {
                    Ok(()) => BTreeSet::new(),
                    Err(errs) => errs.into_iter().map(|p| p.index).collect(),
                }
            },
            || {
                let mut seed_rng = StdRng::from_seed(seed_rng_seed);
                match threshold::batch_verify_same_message::<_, V, _>(
                    &mut seed_rng,
                    polynomial,
                    &namespace.seed,
                    &seed_message,
                    seed_partials.iter(),
                    strategy,
                ) {
                    Ok(()) => BTreeSet::new(),
                    Err(errs) => errs.into_iter().map(|p| p.index).collect(),
                }
            },
        );
        // Merge invalid sets
        let invalid: BTreeSet<_> = vote_invalid.union(&seed_invalid).copied().collect();

        let verified = vote_partials
            .into_iter()
            .zip(seed_partials)
            .map(|(vote, seed)| Attestation {
                signer: vote.index,
                signature: Signature {
                    vote_signature: vote.value,
                    seed_signature: seed.value,
                },
            })
            .filter(|attestation| !invalid.contains(&attestation.signer))
            .collect();

        Verification::new(verified, invalid.into_iter().collect())
    }

    fn assemble<I, M>(&self, attestations: I, strategy: &impl Strategy) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Attestation<Self>>,
        M: Faults,
    {
        let attestations: Vec<_> = attestations.into_iter().collect();
        let (vote_partials, seed_partials): (Vec<_>, Vec<_>) = attestations
            .iter()
            .map(|attestation| {
                (
                    PartialSignature::<V> {
                        index: attestation.signer,
                        value: attestation.signature.vote_signature,
                    },
                    PartialSignature::<V> {
                        index: attestation.signer,
                        value: attestation.signature.seed_signature,
                    },
                )
            })
            .unzip();

        let quorum = self.polynomial();
        let n = self.participants().len() as u32;
        let m_required = M::quorum(n) as usize;

        if vote_partials.len() < m_required {
            return None;
        }

        // Determine which certificate type to produce based on whether we can
        // recover a threshold signature. The polynomial threshold is 2f+1 (M5f1),
        // so we can only recover if we have at least that many signatures.
        // For L-quorum (n-f) where we can't trust threshold recovery (signatures
        // could be forged from 2f+1 partials), we use aggregation instead.
        let l_quorum = N5f1::quorum(n) as usize;

        if vote_partials.len() >= l_quorum {
            // L-quorum: Use aggregated signature with explicit signers.
            // This proves exactly which validators signed (unforgeable).
            let signers = Signers::from(n as usize, attestations.iter().map(|a| a.signer));

            // Aggregate the vote partial signatures using BLS point addition
            let aggregated_vote =
                aggregate::combine_signatures::<V, _>(vote_partials.iter().map(|p| &p.value));

            // Recover the seed signature via threshold recovery (we have >= 2f+1 partials)
            let seed_signature =
                threshold::recover::<V, _, M>(quorum, seed_partials.iter(), strategy).ok()?;

            Some(Certificate::Aggregated {
                signers,
                vote_signature: *aggregated_vote.inner(),
                seed_signature,
            })
        } else {
            // M-quorum: Recover threshold signature.
            // Safe because threshold = 2f+1 = M-quorum.
            let (vote_signature, seed_signature) = threshold::recover_pair::<V, _, M>(
                quorum,
                vote_partials.iter(),
                seed_partials.iter(),
                strategy,
            )
            .ok()?;

            Some(Certificate::Threshold {
                vote_signature,
                seed_signature,
            })
        }
    }

    fn verify_certificate<R, D, M>(
        &self,
        rng: &mut R,
        subject: Subject<'_, D>,
        certificate: &Self::Certificate,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRngCore,
        D: Digest,
        M: Faults,
    {
        let namespace = self.namespace();
        let vote_namespace = subject.namespace(namespace);
        let vote_message = subject.message();

        match certificate {
            Certificate::Threshold {
                vote_signature,
                seed_signature,
            } => {
                // Verify recovered threshold signatures against group identity
                let identity = self.identity();
                let seed_message = seed_message_from_subject(&subject);

                let entries = &[
                    (vote_namespace, vote_message.as_ref(), *vote_signature),
                    (&namespace.seed, seed_message.as_ref(), *seed_signature),
                ];
                batch::verify_same_signer::<_, V, _>(rng, identity, entries, strategy).is_ok()
            }
            Certificate::Aggregated {
                signers,
                vote_signature,
                seed_signature,
            } => {
                // Verify aggregated vote signature against aggregated public keys.
                let polynomial = self.polynomial();

                // Collect partial public keys for all signers
                let partial_publics: Vec<_> = signers
                    .iter()
                    .filter_map(|signer| polynomial.partial_public(signer).ok())
                    .collect();

                // Ensure we have the expected number of public keys
                if partial_publics.len() != signers.count() {
                    return false;
                }

                // Aggregate the public keys
                let aggregated_public =
                    aggregate::combine_public_keys::<V, _>(partial_publics.iter());

                // Wrap signature in aggregate::Signature for verification
                let aggregated_sig = aggregate::Signature::<V>::from_raw(*vote_signature);

                // Verify the aggregated vote signature
                if aggregate::verify_same_message::<V>(
                    &aggregated_public,
                    vote_namespace,
                    &vote_message,
                    &aggregated_sig,
                )
                .is_err()
                {
                    return false;
                }

                // Verify the recovered seed signature against group identity
                let identity = self.identity();
                let seed_message = seed_message_from_subject(&subject);
                ops::verify_message::<V>(identity, &namespace.seed, &seed_message, seed_signature)
                    .is_ok()
            }
        }
    }

    fn verify_certificates<'a, R, D, I, M>(
        &self,
        rng: &mut R,
        certificates: I,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRngCore,
        D: Digest,
        I: Iterator<Item = (Subject<'a, D>, &'a Self::Certificate)>,
        M: Faults,
    {
        let identity = self.identity();
        let namespace = self.namespace();

        // Separate Threshold and Aggregated certificates for different verification paths
        let mut seeds = HashMap::new();
        let mut threshold_entries: Vec<_> = Vec::new();
        let mut aggregated_certs: Vec<_> = Vec::new();

        for (context, certificate) in certificates {
            let vote_namespace = context.namespace(namespace);
            let vote_message = context.message();

            // All certificates (both Threshold and Aggregated) have seed signatures
            // that can be batch-verified against the group identity. Seed signatures
            // are per-view, so multiple certificates for the same view share the same seed.
            let seed_signature = certificate.seed_signature();
            if let Some(previous) = seeds.get(&context.view()) {
                if previous != seed_signature {
                    return false;
                }
            } else {
                let seed_message = seed_message_from_subject(&context);
                threshold_entries.push((namespace.seed.clone(), seed_message, *seed_signature));
                seeds.insert(context.view(), *seed_signature);
            }

            match certificate {
                Certificate::Threshold { vote_signature, .. } => {
                    // Vote signature can be batch-verified against group identity
                    threshold_entries.push((
                        vote_namespace.to_vec(),
                        vote_message.clone(),
                        *vote_signature,
                    ));
                }
                Certificate::Aggregated {
                    signers,
                    vote_signature,
                    ..
                } => {
                    // Vote signature needs per-certificate verification against aggregated public keys
                    aggregated_certs.push((vote_namespace, vote_message, signers, vote_signature));
                }
            }
        }

        // Batch verify all Threshold vote signatures and all seed signatures against the group identity
        if !threshold_entries.is_empty() {
            let entries_refs: Vec<_> = threshold_entries
                .iter()
                .map(|(ns, msg, sig)| (ns.as_slice(), msg.as_ref(), *sig))
                .collect();
            if batch::verify_same_signer::<_, V, _>(rng, identity, &entries_refs, strategy).is_err()
            {
                return false;
            }
        }

        // Verify each Aggregated certificate's vote signature individually
        // (Each has a different aggregated public key based on signers)
        for (vote_namespace, vote_message, signers, vote_signature) in aggregated_certs {
            let polynomial = self.polynomial();

            // Collect partial public keys for all signers
            let partial_publics: Vec<_> = signers
                .iter()
                .filter_map(|signer| polynomial.partial_public(signer).ok())
                .collect();

            // Ensure we have the expected number of public keys
            if partial_publics.len() != signers.count() {
                return false;
            }

            // Aggregate the public keys
            let aggregated_public = aggregate::combine_public_keys::<V, _>(partial_publics.iter());

            // Wrap signature in aggregate::Signature for verification
            let aggregated_sig = aggregate::Signature::<V>::from_raw(*vote_signature);

            // Verify the aggregated vote signature
            if aggregate::verify_same_message::<V>(
                &aggregated_public,
                vote_namespace,
                &vote_message,
                &aggregated_sig,
            )
            .is_err()
            {
                return false;
            }
        }

        true
    }

    fn is_attributable() -> bool {
        false
    }

    fn is_batchable() -> bool {
        true
    }

    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {
        self.participants().len()
    }

    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {
        // For unbounded decoding, use a reasonable max (e.g., 1024 participants)
        // This is only used for decoding certificates when we don't have scheme context
        1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        minimmit::{
            scheme::{bls12381_threshold, notarize_namespace, seed_namespace},
            types::{Finalization, MNotarization, Notarize, Proposal, Subject},
        },
        types::{Round, View},
    };
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{
        bls12381::{
            dkg::{self, deal_anonymous},
            primitives::{
                ops::threshold,
                variant::{MinPk, MinSig, Variant},
            },
        },
        certificate::{mocks::Fixture, Scheme as _},
        ed25519,
        ed25519::certificate::mocks::participants as ed25519_participants,
        sha256::Digest as Sha256Digest,
        Hasher, Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, Faults, M5f1, N5f1, NZU32};
    use rand::{rngs::StdRng, SeedableRng};

    const NAMESPACE: &[u8] = b"minimmit-bls-threshold";

    type Scheme<V> = super::Scheme<ed25519::PublicKey, V>;

    fn setup_signers<V: Variant>(n: u32, seed: u64) -> (Vec<Scheme<V>>, Scheme<V>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let Fixture {
            schemes, verifier, ..
        } = bls12381_threshold::fixture::<V, _>(&mut rng, NAMESPACE, n);

        (schemes, verifier)
    }

    fn sample_proposal(epoch: Epoch, view: View, tag: u8) -> Proposal<Sha256Digest> {
        let parent_view = view.previous().unwrap();
        // Use deterministic parent_payload based on parent view
        let parent_payload = Sha256::hash(&[parent_view.get() as u8]);
        Proposal::new(
            Round::new(epoch, view),
            parent_view,
            parent_payload,
            Sha256::hash(&[tag]),
        )
    }

    fn signer_shares_must_match_participant_indices<V: Variant>() {
        let mut rng = test_rng();
        let participants = ed25519_participants(&mut rng, 6);
        let (polynomial, mut shares) =
            dkg::deal_anonymous::<V, N5f1>(&mut rng, Default::default(), NZU32!(6));
        shares[0].index = Participant::new(999);
        Scheme::<V>::signer(
            NAMESPACE,
            participants.keys().clone(),
            polynomial,
            shares[0].clone(),
        );
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
        let mut rng = test_rng();
        let participants = ed25519_participants(&mut rng, 7);
        let (polynomial, shares) =
            deal_anonymous::<V, N5f1>(&mut rng, Default::default(), NZU32!(6));
        Scheme::<V>::signer(
            NAMESPACE,
            participants.keys().clone(),
            polynomial,
            shares[0].clone(),
        );
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

    #[test]
    fn test_is_not_attributable() {
        assert!(!Scheme::<MinPk>::is_attributable());
        assert!(!Scheme::<MinSig>::is_attributable());
    }

    #[test]
    fn test_is_batchable() {
        assert!(Scheme::<MinPk>::is_batchable());
        assert!(Scheme::<MinSig>::is_batchable());
    }

    fn sign_vote_roundtrip_for_each_context<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(6, 7);
        let scheme = &schemes[0];
        let mut rng = test_rng();

        let proposal = sample_proposal(Epoch::new(0), View::new(2), 1);

        // Test notarize
        let notarize_vote = scheme
            .sign(Subject::Notarize {
                proposal: &proposal,
            })
            .unwrap();
        assert!(scheme.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            Subject::Notarize {
                proposal: &proposal,
            },
            &notarize_vote,
            &Sequential,
        ));

        // Test nullify
        let nullify_vote = scheme
            .sign::<Sha256Digest>(Subject::Nullify {
                round: proposal.round,
            })
            .unwrap();
        assert!(scheme.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            Subject::Nullify {
                round: proposal.round,
            },
            &nullify_vote,
            &Sequential,
        ));
    }

    #[test]
    fn test_sign_vote_roundtrip_for_each_context() {
        sign_vote_roundtrip_for_each_context::<MinPk>();
        sign_vote_roundtrip_for_each_context::<MinSig>();
    }

    fn verifier_cannot_sign<V: Variant>() {
        let (_, verifier) = setup_signers::<V>(6, 11);

        let proposal = sample_proposal(Epoch::new(0), View::new(3), 2);
        assert!(
            verifier
                .sign(Subject::Notarize {
                    proposal: &proposal,
                })
                .is_none(),
            "verifier should not produce signatures"
        );
    }

    #[test]
    fn test_verifier_cannot_sign() {
        verifier_cannot_sign::<MinPk>();
        verifier_cannot_sign::<MinSig>();
    }

    fn m_notarization_requires_m_quorum<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(6, 17);
        let m_quorum = M5f1::quorum_from_slice(&schemes) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(7), 4);

        // Not enough votes for M-quorum
        let votes: Vec<_> = schemes
            .iter()
            .take(m_quorum - 1)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        assert!(schemes[0].assemble::<_, M5f1>(votes, &Sequential).is_none());

        // Exactly M-quorum votes
        let votes: Vec<_> = schemes
            .iter()
            .take(m_quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        assert!(schemes[0].assemble::<_, M5f1>(votes, &Sequential).is_some());
    }

    #[test]
    fn test_m_notarization_requires_m_quorum() {
        m_notarization_requires_m_quorum::<MinPk>();
        m_notarization_requires_m_quorum::<MinSig>();
    }

    fn finalization_requires_l_quorum<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(6, 19);
        let m_quorum = M5f1::quorum_from_slice(&schemes) as usize;
        let l_quorum = N5f1::quorum_from_slice(&schemes) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(9), 5);

        // M-quorum is not enough for finalization
        let votes: Vec<_> = schemes
            .iter()
            .take(m_quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        assert!(schemes[0].assemble::<_, N5f1>(votes, &Sequential).is_none());

        // L-quorum votes are enough
        let votes: Vec<_> = schemes
            .iter()
            .take(l_quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        assert!(schemes[0].assemble::<_, N5f1>(votes, &Sequential).is_some());
    }

    #[test]
    fn test_finalization_requires_l_quorum() {
        finalization_requires_l_quorum::<MinPk>();
        finalization_requires_l_quorum::<MinSig>();
    }

    fn seedable<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(6, 5);
        let m_quorum = M5f1::quorum_from_slice(&schemes) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(1), 0);

        // Build M-notarization from M-quorum notarizes
        let notarizes: Vec<_> = schemes
            .iter()
            .take(m_quorum)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        let m_notarization =
            MNotarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap();

        // M-notarization should have a valid seed (it uses Threshold certificate)
        assert_eq!(m_notarization.seed().round, proposal.round);
        assert!(m_notarization.seed().verify(&schemes[0]));

        // Build Finalization from L-quorum notarizes
        let l_quorum = N5f1::quorum_from_slice(&schemes) as usize;
        let notarizes: Vec<_> = schemes
            .iter()
            .take(l_quorum)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        let finalization =
            Finalization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap();

        // Finalization should also have a valid seed (Aggregated certificate includes recovered seed)
        assert_eq!(finalization.seed().round, proposal.round);
        assert!(finalization.seed().verify(&schemes[0]));

        // Both should have the same seed signature (same round, same polynomial)
        assert_eq!(
            m_notarization.seed().signature,
            finalization.seed().signature
        );
    }

    #[test]
    fn test_seedable() {
        seedable::<MinPk>();
        seedable::<MinSig>();
    }

    fn certificate_codec_roundtrip_threshold<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(6, 29);
        let m_quorum = M5f1::quorum_from_slice(&schemes) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(13), 7);

        let votes: Vec<_> = schemes
            .iter()
            .take(m_quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, M5f1>(votes, &Sequential)
            .expect("assemble certificate");

        // M-quorum should produce Threshold certificate
        assert!(certificate.is_threshold());

        let encoded = certificate.encode();
        let n = schemes[0].participants().len();
        let decoded = Certificate::<V>::decode_cfg(encoded, &n).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    fn certificate_codec_roundtrip_aggregated<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(6, 31);
        let l_quorum = N5f1::quorum_from_slice(&schemes) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(15), 8);

        let votes: Vec<_> = schemes
            .iter()
            .take(l_quorum)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N5f1>(votes, &Sequential)
            .expect("assemble certificate");

        // L-quorum should produce Aggregated certificate
        assert!(certificate.is_aggregated());

        let encoded = certificate.encode();
        let n = schemes[0].participants().len();
        let decoded = Certificate::<V>::decode_cfg(encoded, &n).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_certificate_codec_roundtrip() {
        certificate_codec_roundtrip_threshold::<MinPk>();
        certificate_codec_roundtrip_threshold::<MinSig>();
        certificate_codec_roundtrip_aggregated::<MinPk>();
        certificate_codec_roundtrip_aggregated::<MinSig>();
    }

    fn sign_vote_partial_matches_share<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(6, 53);
        let scheme = &schemes[0];
        let share = scheme.share().expect("has share");

        let proposal = sample_proposal(Epoch::new(0), View::new(23), 12);
        let vote = scheme
            .sign(Subject::Notarize {
                proposal: &proposal,
            })
            .unwrap();

        let notarize_namespace = notarize_namespace(NAMESPACE);
        let notarize_message = proposal.encode();
        let expected_message = threshold::sign_message::<V>(
            share,
            notarize_namespace.as_ref(),
            notarize_message.as_ref(),
        )
        .value;

        let seed_namespace = seed_namespace(NAMESPACE);
        let seed_message = proposal.round.encode();
        let expected_seed =
            threshold::sign_message::<V>(share, seed_namespace.as_ref(), seed_message.as_ref())
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
}
