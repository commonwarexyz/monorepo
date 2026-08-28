//! Exact-cardinality BLS12-381 commitment certificates over clearing headers.

use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, RangeCfg, Read, Write};
use commonware_cryptography::{Hasher, bls12381::primitives::group::G2};
use commonware_utils::{
    N3f1, Participant,
    ordered::{Error as OrderedError, Quorum as _, Set},
};
use thiserror::Error;

/// Signature namespace for an admitted clearing header.
pub const HEADER_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_HEADER";
/// Hash namespace for the exact canonical validator committee.
pub const COMMITTEE_HASH_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_COMMITTEE";

/// Largest committee representable by the clearing admission protocol.
pub const MAX_COMMITTEE_SIZE: usize = u16::MAX as usize;

fn commit_participants<H>(participants: &Set<G2>) -> H::Digest
where
    H: Hasher,
{
    let encoded = participants.encode();
    H::hash(&[COMMITTEE_HASH_NAMESPACE, encoded.as_ref()])
}

/// A canonically ordered `3f+1` validator committee.
///
/// Each BLS public key is the validator's sole protocol identity. Keys are decoded and group
/// checked once when the committee is constructed or decoded, then retained for the epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Committee(Set<G2>);

impl Committee {
    /// Validates and canonically orders a registered epoch committee.
    ///
    /// # Security
    ///
    /// The caller must authenticate each validator registration and verify its MinSig proof of
    /// possession before calling this constructor.
    pub fn new(members: Vec<G2>) -> Result<Self, Error> {
        if !valid_committee_size(members.len()) {
            return Err(Error::InvalidCommitteeSize);
        }
        let members = Set::try_from(members).map_err(|error| match error {
            OrderedError::DuplicateKey | OrderedError::DuplicateValue => Error::DuplicateValidator,
        })?;
        Ok(Self(members))
    }

    /// Validator keys in canonical certificate-index order.
    pub fn members(&self) -> &[G2] {
        self.0.as_ref()
    }

    /// Number of Byzantine validators tolerated by the committee.
    pub fn faults(&self) -> usize {
        self.0.max_faults::<N3f1>() as usize
    }

    /// Exact number of attestations in an admission certificate.
    pub fn quorum(&self) -> usize {
        self.0.quorum::<N3f1>() as usize
    }

    /// Finds a validator's canonical certificate index.
    pub fn index_of(&self, validator: &G2) -> Option<Participant> {
        self.0.index(validator)
    }

    /// Commits to the exact canonical BLS participant set.
    pub fn commitment<H: Hasher>(&self) -> H::Digest {
        commit_participants::<H>(&self.0)
    }
}

impl Write for Committee {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl EncodeSize for Committee {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl Read for Committee {
    /// Maximum accepted committee length.
    type Cfg = usize;

    /// Decodes a canonical registered committee.
    ///
    /// This checks the key encodings and committee shape. The embedding application must only
    /// accept committees whose validator registrations and MinSig proofs of possession were
    /// authenticated before the epoch began.
    fn read_cfg(buf: &mut impl Buf, maximum: &Self::Cfg) -> Result<Self, CodecError> {
        let maximum = (*maximum).min(MAX_COMMITTEE_SIZE);
        let members = Set::<G2>::read_cfg(buf, &(RangeCfg::new(1..=maximum), ()))?;
        if !valid_committee_size(members.len()) {
            return Err(CodecError::Invalid(
                "clearing::Committee",
                "committee length must be a representable 3f+1",
            ));
        }
        Ok(Self(members))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Committee {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        const MAX_ARBITRARY_FAULTS: u8 = 7;

        let faults = usize::from(u.arbitrary::<u8>()? % (MAX_ARBITRARY_FAULTS + 1));
        let len = faults * 3 + 1;
        let mut members = Vec::with_capacity(len);
        for _ in 0..len {
            members.push(u.arbitrary()?);
        }
        Self::new(members).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

const fn valid_committee_size(len: usize) -> bool {
    len > 0 && len <= MAX_COMMITTEE_SIZE && (len - 1).is_multiple_of(3)
}

/// Validator committee or certificate failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Error {
    /// Committee length is not representable as `3f+1`.
    #[error("committee length must be a representable 3f+1")]
    InvalidCommitteeSize,
    /// A validator BLS key appears more than once.
    #[error("committee contains a duplicate validator")]
    DuplicateValidator,
    /// The supplied committee does not match the epoch's authenticated commitment.
    #[error("validator committee does not match the authenticated assignment")]
    CommitteeMismatch,
    /// A signing key or attestation references a validator outside the committee.
    #[error("validator is not a member of the committee")]
    UnknownValidator,
    /// More than one attestation came from the same validator.
    #[error("certificate contains duplicate validator attestations")]
    DuplicateAttestation,
    /// A certificate does not contain exactly `2f+1` attestations.
    #[error("certificate does not contain the exact quorum")]
    WrongQuorumSize,
    /// A dealing or slice request does not match the deterministic assignment.
    #[error("dealing or slice request does not match the assignment")]
    IncompleteAssignment,
    /// An assigned proof slice failed semantic authentication.
    #[error("assigned proof slice is invalid")]
    InvalidSlice,
    /// An attestation could not be assembled into a certificate.
    #[error("certificate contains an invalid attestation")]
    InvalidAttestation,
    /// The scheme was constructed without a validator signing key.
    #[error("certificate scheme cannot sign")]
    SigningUnavailable,
}

/// BLS12-381 MinSig exact-quorum admission certificates.
pub mod bls12381 {
    use super::{Committee, Error, HEADER_NAMESPACE};
    use crate::bajillion::transition::Header;
    use alloc::{collections::BTreeSet, vec::Vec};
    use bytes::{Buf, BufMut};
    use commonware_codec::{
        Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write, types::lazy::Lazy,
    };
    use commonware_cryptography::{
        Digest,
        bls12381::{
            certificate::multisig,
            primitives::{
                group::{G1, Private},
                ops::{self, aggregate},
                variant::MinSig,
            },
        },
        certificate::Signers,
    };
    use commonware_utils::Participant;

    /// One aggregate MinSig signature plus an explicit signer bitmap.
    pub type Certificate = multisig::Certificate<MinSig>;

    /// One validator's MinSig signature over a clearing header.
    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    pub struct Vote {
        /// Index of the signer inside the epoch committee.
        pub signer: Participant,
        /// Validator signature, decoded lazily at the verification boundary.
        pub signature: Lazy<G1>,
    }

    impl Write for Vote {
        fn write(&self, writer: &mut impl BufMut) {
            self.signer.write(writer);
            self.signature.write(writer);
        }
    }

    impl EncodeSize for Vote {
        fn encode_size(&self) -> usize {
            self.signer.encode_size() + self.signature.encode_size()
        }
    }

    impl Read for Vote {
        type Cfg = ();

        fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            Ok(Self {
                signer: Participant::read(reader)?,
                signature: Lazy::read(reader)?,
            })
        }
    }

    #[cfg(feature = "arbitrary")]
    impl arbitrary::Arbitrary<'_> for Vote {
        fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
            Ok(Self {
                signer: u.arbitrary()?,
                signature: Lazy::from(u.arbitrary::<G1>()?),
            })
        }
    }

    /// Concrete MinSig scheme owning one epoch's canonical participant order.
    #[derive(Clone, Debug)]
    pub struct Scheme {
        committee: Committee,
        signer: Option<(Participant, Private)>,
    }

    impl Scheme {
        /// Builds a signing scheme from a registered committee and matching private key.
        pub fn signer(committee: Committee, signing_key: Private) -> Result<Self, Error> {
            let public_key = ops::compute_public::<MinSig>(&signing_key);
            let signer = committee
                .index_of(&public_key)
                .ok_or(Error::UnknownValidator)?;
            Ok(Self {
                committee,
                signer: Some((signer, signing_key)),
            })
        }

        /// Builds a verify-only scheme from a registered epoch committee.
        pub const fn verifier(committee: Committee) -> Self {
            Self {
                committee,
                signer: None,
            }
        }

        /// Returns the epoch committee that defines participant indices.
        pub const fn committee(&self) -> &Committee {
            &self.committee
        }

        /// Returns this scheme's validator index when it can sign.
        pub fn me(&self) -> Option<Participant> {
            self.signer.as_ref().map(|(index, _)| *index)
        }

        /// Signs one context-bound clearing header.
        pub fn sign<D: Digest>(&self, header: &Header<D>) -> Result<Vote, Error> {
            let (signer, private_key) = self.signer.as_ref().ok_or(Error::SigningUnavailable)?;
            Ok(Vote {
                signer: *signer,
                signature: ops::sign_message::<MinSig>(
                    private_key,
                    HEADER_NAMESPACE,
                    &header.encode(),
                )
                .into(),
            })
        }

        /// Verifies one validator vote against the cached epoch key.
        pub fn verify_vote<D: Digest>(&self, header: &Header<D>, vote: &Vote) -> bool {
            let Some(public_key) = self.committee.members().get(usize::from(vote.signer)) else {
                return false;
            };
            let Some(signature) = vote.signature.get() else {
                return false;
            };
            ops::verify_message::<MinSig>(public_key, HEADER_NAMESPACE, &header.encode(), signature)
                .is_ok()
        }

        /// Assembles exactly `2f+1` distinct in-committee votes.
        ///
        /// This checks encoding, committee membership, and uniqueness, but deliberately not the
        /// signatures themselves. The caller must verify every vote with [`Self::verify_vote`]
        /// before assembly. One unverified non-signature yields a certificate that fails
        /// settlement verification with no way to attribute the faulty signer.
        pub fn assemble_exact<I>(&self, input: I) -> Result<Certificate, Error>
        where
            I: IntoIterator<Item = Vote>,
        {
            // Consume at most one item beyond quorum so oversized or unbounded iterators are
            // rejected without unbounded work.
            let quorum = self.committee.quorum();
            let mut input = input.into_iter();
            let mut entries = Vec::with_capacity(quorum);
            let mut signers = BTreeSet::new();
            for _ in 0..quorum {
                let vote = input.next().ok_or(Error::WrongQuorumSize)?;
                if usize::from(vote.signer) >= self.committee.members().len() {
                    return Err(Error::UnknownValidator);
                }
                if !signers.insert(vote.signer) {
                    return Err(Error::DuplicateAttestation);
                }
                let signature = vote
                    .signature
                    .get()
                    .copied()
                    .ok_or(Error::InvalidAttestation)?;
                entries.push((vote.signer, signature));
            }
            if input.next().is_some() {
                return Err(Error::WrongQuorumSize);
            }

            Ok(Certificate {
                signers: Signers::from(
                    self.committee.members().len(),
                    entries.iter().map(|(signer, _)| *signer),
                ),
                signature: aggregate::combine_signatures::<MinSig, _>(
                    entries.iter().map(|(_, signature)| signature),
                )
                .into(),
            })
        }

        /// Verifies an exact-quorum certificate over one context-bound header.
        pub fn verify_exact<D: Digest>(
            &self,
            header: &Header<D>,
            certificate: &Certificate,
        ) -> bool {
            if certificate.signers.len() != self.committee.members().len()
                || certificate.signers.count() != self.committee.quorum()
            {
                return false;
            }

            // Participant indices select group-checked public keys retained by the epoch scheme.
            let public_key = aggregate::combine_public_keys::<MinSig, _>(
                certificate
                    .signers
                    .iter()
                    .filter_map(|signer| self.committee.members().get(usize::from(signer))),
            );
            let Some(signature) = certificate.signature.get() else {
                return false;
            };
            aggregate::verify_same_message::<MinSig>(
                &public_key,
                HEADER_NAMESPACE,
                &header.encode(),
                signature,
            )
            .is_ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Committee, Error, bls12381};
    use crate::bajillion::transition::Header;
    use bytes::Bytes;
    use commonware_codec::{Decode, DecodeExt, Encode, EncodeSize, types::lazy::Lazy};
    use commonware_cryptography::{
        Hasher, Sha256,
        bls12381::primitives::{
            group::{Private, Scalar},
            ops::{aggregate, compute_public},
            variant::MinSig,
        },
        certificate::Signers,
        sha256::Digest as Sha256Digest,
    };
    use commonware_utils::Participant;

    fn fixture(count: u64) -> (Committee, Vec<Private>) {
        let keys = (0..count)
            .map(|index| Private::new(Scalar::from(index + 1)))
            .collect::<Vec<_>>();
        let members = keys.iter().map(compute_public::<MinSig>).collect();
        (Committee::new(members).unwrap(), keys)
    }

    fn test_header(label: &[u8]) -> Header<Sha256Digest> {
        Header::decode(Sha256::hash(&[label]).as_ref()).unwrap()
    }

    fn schemes(committee: &Committee, keys: Vec<Private>) -> Vec<bls12381::Scheme> {
        keys.into_iter()
            .map(|key| bls12381::Scheme::signer(committee.clone(), key).unwrap())
            .collect()
    }

    #[test]
    fn committee_is_exact_canonical_and_commits_keys() {
        let (committee, keys) = fixture(4);
        assert_eq!(committee.faults(), 1);
        assert_eq!(committee.quorum(), 3);
        assert!(committee.members().windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            committee.index_of(committee.members().first().unwrap()),
            Some(Participant::new(0))
        );

        assert_eq!(Committee::new(Vec::new()), Err(Error::InvalidCommitteeSize));
        assert_eq!(
            Committee::new(vec![
                compute_public::<MinSig>(&keys[0]),
                compute_public::<MinSig>(&keys[1]),
                compute_public::<MinSig>(&keys[2]),
                compute_public::<MinSig>(&keys[0]),
            ]),
            Err(Error::DuplicateValidator)
        );

        let encoded = committee.encode();
        assert_eq!(
            Committee::decode_cfg(encoded.clone(), &4).unwrap(),
            committee
        );
        assert!(Committee::decode_cfg(encoded, &3).is_err());

        let mut members = committee.members().to_vec();
        members[0] = compute_public::<MinSig>(&Private::new(Scalar::from(99)));
        let changed = Committee::new(members).unwrap();
        assert_ne!(
            committee.commitment::<Sha256>(),
            changed.commitment::<Sha256>()
        );
    }

    #[test]
    fn min_sig_exact_quorum_roundtrip_and_header_binding() {
        let (committee, keys) = fixture(4);
        let schemes = schemes(&committee, keys);
        let verifier = bls12381::Scheme::verifier(committee);
        let header = test_header(b"header");
        let votes = schemes
            .iter()
            .take(3)
            .map(|scheme| scheme.sign(&header).unwrap())
            .collect::<Vec<_>>();
        for vote in &votes {
            assert!(verifier.verify_vote(&header, vote));
        }
        let certificate = schemes[0].assemble_exact(votes).unwrap();
        assert_eq!(certificate.signers.len(), 4);
        assert_eq!(certificate.signers.count(), 3);
        assert!(verifier.verify_exact(&header, &certificate));
        assert!(!verifier.verify_exact(&test_header(b"other"), &certificate));
    }

    #[test]
    fn assembly_rejects_non_exact_duplicate_unknown_and_malformed_votes() {
        let (committee, keys) = fixture(4);
        let schemes = schemes(&committee, keys);
        let header = test_header(b"header");
        let votes = schemes
            .iter()
            .map(|scheme| scheme.sign(&header).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            schemes[0].assemble_exact(votes[..2].to_vec()),
            Err(Error::WrongQuorumSize)
        );
        assert_eq!(
            schemes[0].assemble_exact(votes.clone()),
            Err(Error::WrongQuorumSize)
        );
        assert_eq!(
            schemes[0].assemble_exact(vec![votes[0].clone(), votes[0].clone(), votes[1].clone(),]),
            Err(Error::DuplicateAttestation)
        );

        let mut unknown = votes[..3].to_vec();
        unknown[2].signer = Participant::new(99);
        assert_eq!(
            schemes[0].assemble_exact(unknown),
            Err(Error::UnknownValidator)
        );

        let mut truncated = Bytes::from_static(b"truncated");
        let mut malformed = votes[..3].to_vec();
        malformed[0].signature = Lazy::deferred(&mut truncated, ());
        assert_eq!(
            schemes[0].assemble_exact(malformed),
            Err(Error::InvalidAttestation)
        );
    }

    #[test]
    fn verification_rejects_non_exact_bitmaps() {
        let (committee, keys) = fixture(4);
        let schemes = schemes(&committee, keys);
        let verifier = bls12381::Scheme::verifier(committee);
        let header = test_header(b"header");
        let votes = schemes
            .iter()
            .map(|scheme| scheme.sign(&header).unwrap())
            .collect::<Vec<_>>();
        let exact = schemes[0].assemble_exact(votes[..3].to_vec()).unwrap();
        let signatures = votes
            .iter()
            .map(|vote| *vote.signature.get().unwrap())
            .collect::<Vec<_>>();
        let super_quorum = bls12381::Certificate {
            signers: Signers::from(4, votes.iter().map(|vote| vote.signer)),
            signature: aggregate::combine_signatures::<MinSig, _>(signatures.iter()).into(),
        };
        assert!(!verifier.verify_exact(&header, &super_quorum));

        let mut wrong_bitmap = exact.clone();
        wrong_bitmap.signers = Signers::from(5, votes[..3].iter().map(|vote| vote.signer));
        assert!(!verifier.verify_exact(&header, &wrong_bitmap));

        let sub_quorum = bls12381::Certificate {
            signers: Signers::from(4, votes[..2].iter().map(|vote| vote.signer)),
            signature: exact.signature,
        };
        assert!(!verifier.verify_exact(&header, &sub_quorum));
    }

    #[test]
    fn certificate_is_signature_plus_validator_bitmap() {
        let (committee, keys) = fixture(100);
        let schemes = schemes(&committee, keys);
        let header = test_header(b"hundred-validator-header");
        let votes = schemes
            .iter()
            .take(67)
            .map(|scheme| scheme.sign(&header).unwrap())
            .collect::<Vec<_>>();
        let certificate = schemes[0].assemble_exact(votes).unwrap();

        assert_eq!(certificate.signers.len(), 100);
        assert_eq!(certificate.signers.count(), 67);
        let signature_bytes = certificate.signature.encode_size();
        let bitmap_length_prefix_bytes = 100_u64.encode_size();
        let validator_bitmap_bytes = 100_usize.div_ceil(8);
        let expected = signature_bytes + bitmap_length_prefix_bytes + validator_bitmap_bytes;
        assert_eq!(signature_bytes, 48);
        assert_eq!(certificate.encode_size(), expected);
        assert_eq!(certificate.encode().len(), expected);
        assert_eq!(
            bls12381::Certificate::decode_cfg(certificate.encode(), &100).unwrap(),
            certificate
        );
    }

    #[test]
    fn signing_key_must_be_registered() {
        let (committee, _) = fixture(4);
        assert_eq!(
            bls12381::Scheme::signer(committee, Private::new(Scalar::from(99))).map(|_| ()),
            Err(Error::UnknownValidator)
        );
    }

    #[test]
    fn vote_codec_preserves_lazy_signature_validation() {
        let (committee, keys) = fixture(1);
        let scheme = bls12381::Scheme::signer(committee, keys.into_iter().next().unwrap()).unwrap();
        let header = test_header(b"header");
        let vote = scheme.sign(&header).unwrap();
        assert_eq!(bls12381::Vote::decode(vote.encode()).unwrap(), vote);

        let mut unknown = vote;
        unknown.signer = Participant::new(1);
        assert!(!scheme.verify_vote(&header, &unknown));
    }
}
