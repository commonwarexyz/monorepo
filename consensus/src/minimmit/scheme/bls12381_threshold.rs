//! BLS12-381 threshold implementation of the [`Scheme`] trait for `minimmit`.
//!
//! This scheme uses different certificate types for M-notarization vs L-notarization:
//!
//! - **M-notarization (2f+1)**: Uses aggregated signatures with explicit signers bitmap.
//!   Each partial signature is individually verifiable and combined via BLS point addition.
//!   This is unforgeable - you cannot create valid signatures without the actual private keys.
//!
//! - **L-notarization/Finalization (n-f)**: Uses threshold signature recovery.
//!   The polynomial threshold is set to n-f, so threshold recovery only succeeds at L-quorum.
//!   This prevents the security issue where 2f+1 partials could forge additional signatures.
//!
//! [`Scheme`] is **non-attributable**: exposing partial signatures as evidence of either liveness
//! or of committing a fault is not safe. With threshold signatures, any `t` valid partial signatures
//! can be used to forge a partial signature for any other player, enabling equivocation attacks.
//! Because peer connections are authenticated, evidence can be used locally (as it must be sent by
//! said participant) but can't be used by an external observer.

use crate::{
    minimmit::{scheme::Namespace, types::Subject},
    types::Participant,
};
use bytes::{Buf, BufMut};
use commonware_codec::{types::lazy::Lazy, EncodeSize, Error, Read, ReadExt as _, Write};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Share,
        ops::{self, aggregate, batch, threshold},
        sharing::Sharing,
        variant::{PartialSignature, Variant},
    },
    certificate::{self, Attestation, Signers, Subject as CertificateSubject, Verification},
    Digest, PublicKey,
};
use commonware_parallel::Strategy;
use commonware_utils::{ordered::Set, Faults, N5f1};
use rand_core::CryptoRngCore;
use std::{collections::BTreeSet, fmt::Debug};

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
        /// Pre-computed namespace for domain separation.
        namespace: Namespace,
    },
    Verifier {
        /// Participants in the committee.
        participants: Set<P>,
        /// The public polynomial, used for the group identity, and partial signatures.
        polynomial: Sharing<V>,
        /// Pre-computed namespace for domain separation.
        namespace: Namespace,
    },
    CertificateVerifier {
        /// Public identity of the committee (constant across reshares).
        identity: V::Public,
        /// Pre-computed namespace for domain separation.
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

    /// Returns the pre-computed namespace.
    const fn namespace(&self) -> &Namespace {
        match &self.role {
            Role::Signer { namespace, .. } => namespace,
            Role::Verifier { namespace, .. } => namespace,
            Role::CertificateVerifier { namespace, .. } => namespace,
        }
    }
}

/// Generates a test fixture with Ed25519 identities and BLS12-381 threshold schemes.
///
/// Returns a [`commonware_cryptography::certificate::mocks::Fixture`] whose keys and
/// scheme instances share a consistent ordering.
///
/// Uses N5f1 (n-f) for the polynomial threshold so that only L-quorum can recover
/// threshold signatures. M-notarization uses aggregated signatures instead.
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

    // Use N5f1 (n-f) for the polynomial threshold so only L-quorum can recover
    // threshold signatures. M-notarization uses aggregated signatures instead.
    let (output, shares) = deal::<V, _, N5f1>(rng, Default::default(), participants.clone())
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

/// Partial signature emitted by the BLS12-381 threshold scheme.
///
/// This is a partial signature over the vote message that can be:
/// - Verified individually against the signer's partial public key
/// - Aggregated with other partial signatures via BLS point addition (for M-notarization)
/// - Combined via threshold recovery when we have n-f partials (for L-notarization)
pub type Signature<V> = <V as Variant>::Signature;

/// Certificate type for the BLS12-381 threshold scheme in minimmit.
///
/// This enum supports two forms with SWAPPED semantics for security:
///
/// - `Aggregated`: Used for M-notarization/Nullification (2f+1 quorum).
///   Contains aggregated signatures with explicit signers bitmap. Each partial
///   signature is individually verifiable and combined via BLS point addition.
///   This is unforgeable - you cannot create valid signatures without private keys.
///
/// - `Threshold`: Used for Finalization (n-f quorum).
///   Contains a recovered threshold signature. The polynomial threshold is set to
///   n-f, so threshold recovery ONLY succeeds at L-quorum. This prevents the
///   security issue where 2f+1 partials could forge additional signatures.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Certificate<V: Variant> {
    /// Aggregated signatures with explicit signers.
    ///
    /// Used for M-notarization and Nullification (2f+1 quorum).
    /// The vote signature is an aggregation of partial signatures that can be
    /// verified against the aggregated public keys of the signers.
    Aggregated {
        /// Bitmap of which participants contributed signatures.
        signers: Signers,
        /// Aggregated BLS signature from the partial vote signatures.
        vote_signature: Lazy<V::Signature>,
    },
    /// Recovered threshold signature.
    ///
    /// Used for Finalization (n-f quorum).
    /// Can only be recovered with n-f partials (polynomial threshold = n-f).
    /// Verified against the group public key.
    Threshold {
        /// The recovered threshold signature over the vote message.
        vote_signature: Lazy<V::Signature>,
    },
}

impl<V: Variant> Certificate<V> {
    /// Returns the vote signature regardless of certificate type.
    ///
    /// Returns `None` if the signature fails to decode.
    pub fn vote_signature(&self) -> Option<&V::Signature> {
        match self {
            Self::Aggregated { vote_signature, .. } => vote_signature.get(),
            Self::Threshold { vote_signature, .. } => vote_signature.get(),
        }
    }

    /// Returns true if this is an Aggregated certificate (M-notarization/Nullification).
    pub const fn is_aggregated(&self) -> bool {
        matches!(self, Self::Aggregated { .. })
    }

    /// Returns true if this is a Threshold certificate (Finalization).
    pub const fn is_threshold(&self) -> bool {
        matches!(self, Self::Threshold { .. })
    }
}

impl<V: Variant> Write for Certificate<V> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Aggregated {
                signers,
                vote_signature,
            } => {
                writer.put_u8(0); // Tag for Aggregated
                signers.write(writer);
                vote_signature.write(writer);
            }
            Self::Threshold { vote_signature } => {
                writer.put_u8(1); // Tag for Threshold
                vote_signature.write(writer);
            }
        }
    }
}

impl<V: Variant> EncodeSize for Certificate<V> {
    fn encode_size(&self) -> usize {
        1 + match self {
            // 1 byte tag
            Self::Aggregated {
                signers,
                vote_signature,
            } => signers.encode_size() + vote_signature.encode_size(),
            Self::Threshold { vote_signature } => vote_signature.encode_size(),
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
                // Aggregated
                let signers = Signers::read_cfg(reader, max_participants)?;
                let vote_signature = Lazy::<V::Signature>::read(reader)?;
                Ok(Self::Aggregated {
                    signers,
                    vote_signature,
                })
            }
            1 => {
                // Threshold
                let vote_signature = Lazy::<V::Signature>::read(reader)?;
                Ok(Self::Threshold { vote_signature })
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
        // Randomly choose between Aggregated and Threshold
        if u.arbitrary::<bool>()? {
            Ok(Self::Aggregated {
                signers: u.arbitrary()?,
                vote_signature: Lazy::from(u.arbitrary::<V::Signature>()?),
            })
        } else {
            Ok(Self::Threshold {
                vote_signature: Lazy::from(u.arbitrary::<V::Signature>()?),
            })
        }
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
        let signature = threshold::sign_message::<V>(share, vote_namespace, &vote_message).value;

        Some(Attestation {
            signer: share.index,
            signature: Lazy::from(signature),
        })
    }

    fn verify_attestation<R, D>(
        &self,
        _rng: &mut R,
        subject: Subject<'_, D>,
        attestation: &Attestation<Self>,
        _strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRngCore,
        D: Digest,
    {
        let Ok(evaluated) = self.polynomial().partial_public(attestation.signer) else {
            return false;
        };
        let Some(signature) = attestation.signature.get() else {
            return false;
        };

        let namespace = self.namespace();
        let vote_namespace = subject.namespace(namespace);
        let vote_message = subject.message();

        ops::verify_message::<V>(&evaluated, vote_namespace, &vote_message, signature).is_ok()
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
        I::IntoIter: Send,
    {
        let namespace = self.namespace();

        // Extract signatures from lazy attestations in parallel, tracking failures
        let (vote_partials, failures) =
            strategy.map_partition_collect_vec(attestations.into_iter(), |attestation| {
                let index = attestation.signer;
                let partial = attestation
                    .signature
                    .get()
                    .map(|&value| PartialSignature::<V> { index, value });
                (index, partial)
            });
        let mut invalid: BTreeSet<_> = failures.into_iter().collect();

        let polynomial = self.polynomial();
        let vote_namespace = subject.namespace(namespace);
        let vote_message = subject.message();

        if let Err(errs) = threshold::batch_verify_same_message::<_, V, _>(
            rng,
            polynomial,
            vote_namespace,
            &vote_message,
            vote_partials.iter(),
            strategy,
        ) {
            for partial in errs {
                invalid.insert(partial.index);
            }
        }

        let verified = vote_partials
            .into_iter()
            .filter(|partial| !invalid.contains(&partial.index))
            .map(|partial| Attestation {
                signer: partial.index,
                signature: Lazy::from(partial.value),
            })
            .collect();

        Verification::new(verified, invalid.into_iter().collect())
    }

    fn assemble<I, M>(&self, attestations: I, strategy: &impl Strategy) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
        M: Faults,
    {
        // Extract signatures from lazy attestations in parallel.
        // Malformed attestations are dropped so a single bad vote cannot block
        // certificate assembly when enough valid votes remain.
        let (vote_partials, _) =
            strategy.map_partition_collect_vec(attestations.into_iter(), |attestation| {
                let index = attestation.signer;
                let partial = attestation
                    .signature
                    .get()
                    .map(|&value| PartialSignature::<V> { index, value });
                (index, partial)
            });

        let polynomial = self.polynomial();
        let n = self.participants().len() as u32;
        let m_required = M::quorum(n) as usize;

        if vote_partials.len() < m_required {
            return None;
        }

        // The polynomial threshold is n-f (N5f1), so we can only recover a threshold
        // signature when we have at least L-quorum (n-f) partials.
        // For M-quorum (2f+1), we use aggregation instead (unforgeable).
        let l_quorum = N5f1::quorum(n) as usize;

        if vote_partials.len() >= l_quorum {
            // L-quorum: Recover threshold signature.
            // Safe because polynomial threshold = n-f = L-quorum.
            let vote_signature =
                threshold::recover::<V, _, N5f1>(polynomial, vote_partials.iter(), strategy)
                    .ok()?;

            Some(Certificate::Threshold {
                vote_signature: Lazy::from(vote_signature),
            })
        } else {
            // M-quorum: Use aggregated signature with explicit signers.
            // This proves exactly which validators signed (unforgeable).
            let signers = Signers::from(n as usize, vote_partials.iter().map(|p| p.index));

            // Aggregate the vote partial signatures using BLS point addition
            let aggregated_vote =
                aggregate::combine_signatures::<V, _>(vote_partials.iter().map(|p| &p.value));

            Some(Certificate::Aggregated {
                signers,
                vote_signature: Lazy::from(*aggregated_vote.inner()),
            })
        }
    }

    fn verify_certificate<R, D, M>(
        &self,
        rng: &mut R,
        subject: Subject<'_, D>,
        certificate: &Self::Certificate,
        _strategy: &impl Strategy,
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
            Certificate::Threshold { vote_signature } => {
                // Get the lazy signature
                let Some(sig) = vote_signature.get() else {
                    return false;
                };
                // Verify recovered threshold signature against group identity
                let identity = self.identity();
                batch::verify_same_signer::<_, V, _>(
                    rng,
                    identity,
                    &[(vote_namespace, vote_message.as_ref(), *sig)],
                    &commonware_parallel::Sequential,
                )
                .is_ok()
            }
            Certificate::Aggregated {
                signers,
                vote_signature,
            } => {
                let participants = self.participants().len();
                if signers.len() != participants {
                    return false;
                }
                let quorum = M::quorum(participants as u32) as usize;
                if signers.count() < quorum {
                    return false;
                }

                // Get the lazy signature
                let Some(sig) = vote_signature.get() else {
                    return false;
                };
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
                let aggregated_sig = aggregate::Signature::<V>::from_raw(*sig);

                // Verify the aggregated vote signature
                aggregate::verify_same_message::<V>(
                    &aggregated_public,
                    vote_namespace,
                    &vote_message,
                    &aggregated_sig,
                )
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
        let participants = self.participants().len();
        let quorum = M::quorum(participants as u32) as usize;

        // Separate Threshold and Aggregated certificates for different verification paths
        let mut threshold_entries: Vec<_> = Vec::new();
        let mut aggregated_certs: Vec<_> = Vec::new();

        for (context, certificate) in certificates {
            let vote_namespace = context.namespace(namespace);
            let vote_message = context.message();

            match certificate {
                Certificate::Threshold { vote_signature } => {
                    // Get the lazy signature
                    let Some(sig) = vote_signature.get() else {
                        return false;
                    };
                    // Vote signature can be batch-verified against group identity
                    threshold_entries.push((vote_namespace.to_vec(), vote_message.clone(), *sig));
                }
                Certificate::Aggregated {
                    signers,
                    vote_signature,
                } => {
                    if signers.len() != participants || signers.count() < quorum {
                        return false;
                    }
                    // Get the lazy signature
                    let Some(sig) = vote_signature.get() else {
                        return false;
                    };
                    // Vote signature needs per-certificate verification against aggregated public keys
                    aggregated_certs.push((vote_namespace, vote_message, signers, *sig));
                }
            }
        }

        // Batch verify all Threshold vote signatures against the group identity
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
            let aggregated_sig = aggregate::Signature::<V>::from_raw(vote_signature);

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
            scheme::{bls12381_threshold, notarize_namespace},
            types::{Notarize, Proposal, Subject},
        },
        types::{Epoch, Round, View},
    };
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{
        bls12381::{
            dkg::{self, deal_anonymous},
            primitives::variant::{MinPk, MinSig, Variant},
        },
        certificate::{mocks::Fixture, Scheme as _},
        ed25519,
        ed25519::certificate::mocks::participants as ed25519_participants,
        sha256::Digest as Sha256Digest,
        Hasher, Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, M5f1, N5f1, NZU32};
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

    fn aggregated_certificate_requires_quorum<V: Variant>() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<V>(6, 13);
        let proposal = sample_proposal(Epoch::new(0), View::new(1), 1);

        let votes: Vec<_> = schemes
            .iter()
            .take(2)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
            .collect();

        let vote_partials: Vec<_> = votes
            .iter()
            .map(|vote| {
                let signature = vote.attestation.signature.get().expect("signature");
                PartialSignature::<V> {
                    index: vote.attestation.signer,
                    value: *signature,
                }
            })
            .collect();
        let signers = Signers::from(schemes.len(), vote_partials.iter().map(|p| p.index));
        let aggregated_vote =
            aggregate::combine_signatures::<V, _>(vote_partials.iter().map(|p| &p.value));
        let certificate = Certificate::Aggregated {
            signers,
            vote_signature: Lazy::from(*aggregated_vote.inner()),
        };

        let subject = Subject::Notarize {
            proposal: &proposal,
        };
        assert!(
            !verifier.verify_certificate::<_, Sha256Digest, M5f1>(
                &mut rng,
                subject,
                &certificate,
                &Sequential
            ),
            "certificate should fail without M-quorum"
        );
    }

    #[test]
    fn test_aggregated_certificate_requires_quorum() {
        aggregated_certificate_requires_quorum::<MinPk>();
        aggregated_certificate_requires_quorum::<MinSig>();
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
        let m_quorum = M5f1::quorum(schemes.len()) as usize;
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

    fn malformed_attestation_does_not_block_m_quorum_assembly<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(6, 59);
        let m_quorum = M5f1::quorum(schemes.len()) as usize;
        let proposal = sample_proposal(Epoch::new(0), View::new(8), 42);

        // Start with quorum + 1 valid attestations.
        let mut attestations: Vec<_> = schemes
            .iter()
            .take(m_quorum + 1)
            .map(|scheme| {
                scheme
                    .sign(Subject::Notarize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();

        // Corrupt one attestation so Lazy::get() fails during assemble().
        let mut malformed = &b""[..];
        attestations[0].signature = Lazy::deferred(&mut malformed, ());

        // Desired behavior: ignore malformed attestations if enough valid votes remain.
        assert!(
            schemes[0]
                .assemble::<_, M5f1>(attestations, &Sequential)
                .is_some(),
            "single malformed attestation should not prevent M-quorum assembly"
        );
    }

    #[test]
    fn test_m_notarization_requires_m_quorum() {
        m_notarization_requires_m_quorum::<MinPk>();
        m_notarization_requires_m_quorum::<MinSig>();
    }

    #[test]
    fn test_malformed_attestation_does_not_block_m_quorum_assembly() {
        malformed_attestation_does_not_block_m_quorum_assembly::<MinPk>();
        malformed_attestation_does_not_block_m_quorum_assembly::<MinSig>();
    }

    fn finalization_requires_l_quorum<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(6, 19);
        let m_quorum = M5f1::quorum(schemes.len()) as usize;
        let l_quorum = N5f1::quorum(schemes.len()) as usize;
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

    fn certificate_codec_roundtrip_aggregated_m_quorum<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(6, 29);
        let m_quorum = M5f1::quorum(schemes.len()) as usize;
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

        // M-quorum produces Aggregated certificate (unforgeable individual signatures)
        assert!(certificate.is_aggregated());

        let encoded = certificate.encode();
        let n = schemes[0].participants().len();
        let decoded = Certificate::<V>::decode_cfg(encoded, &n).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    fn certificate_codec_roundtrip_threshold_l_quorum<V: Variant>() {
        let (schemes, _) = setup_signers::<V>(6, 31);
        let l_quorum = N5f1::quorum(schemes.len()) as usize;
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

        // L-quorum produces Threshold certificate (recovery requires n-f partials)
        assert!(certificate.is_threshold());

        let encoded = certificate.encode();
        let n = schemes[0].participants().len();
        let decoded = Certificate::<V>::decode_cfg(encoded, &n).expect("decode certificate");
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn test_certificate_codec_roundtrip() {
        certificate_codec_roundtrip_aggregated_m_quorum::<MinPk>();
        certificate_codec_roundtrip_aggregated_m_quorum::<MinSig>();
        certificate_codec_roundtrip_threshold_l_quorum::<MinPk>();
        certificate_codec_roundtrip_threshold_l_quorum::<MinSig>();
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
        let expected_signature = threshold::sign_message::<V>(
            share,
            notarize_namespace.as_ref(),
            notarize_message.as_ref(),
        )
        .value;

        assert_eq!(vote.signer, share.index);
        assert_eq!(vote.signature.get().unwrap(), &expected_signature);
    }

    #[test]
    fn test_sign_vote_partial_matches_share() {
        sign_vote_partial_matches_share::<MinPk>();
        sign_vote_partial_matches_share::<MinSig>();
    }
}
