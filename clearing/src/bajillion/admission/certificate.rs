//! Exact-cardinality validator certificates over clearing headers.

use crate::bajillion::transition::Header;
use alloc::vec::Vec;
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, RangeCfg, Read, Write};
use commonware_cryptography::{
    Digest, Hasher, PublicKey, certificate::Subject as CertificateSubject,
};
use commonware_utils::{Participant, ordered::Set};
use thiserror::Error;

/// Signature namespace for an admitted clearing header.
pub const HEADER_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_HEADER";
/// Hash namespace for the exact canonical validator committee.
pub const COMMITTEE_HASH_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_COMMITTEE";

/// Largest committee representable by the clearing admission protocol.
pub const MAX_COMMITTEE_SIZE: usize = u16::MAX as usize;

fn commit_participants<H, P>(participants: &Set<P>) -> H::Digest
where
    H: Hasher,
    P: PublicKey + Ord,
{
    let encoded = participants.encode();
    H::hash(&[COMMITTEE_HASH_NAMESPACE, encoded.as_ref()])
}

/// A canonically ordered `3f+1` validator committee.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Committee<P>(Set<P>);

impl<P: PublicKey + Ord> Committee<P> {
    /// Validates and canonically orders a validator committee.
    pub fn new(members: Vec<P>) -> Result<Self, Error> {
        if !valid_committee_size(members.len()) {
            return Err(Error::InvalidCommitteeSize);
        }
        let members = Set::try_from(members).map_err(|_| Error::DuplicateValidator)?;
        Ok(Self(members))
    }

    /// Validators in canonical certificate-index order.
    pub fn members(&self) -> &[P] {
        self.0.as_ref()
    }

    /// Canonically ordered validator set used by certificate schemes.
    pub const fn participants(&self) -> &Set<P> {
        &self.0
    }

    /// Consumes the committee and returns its canonical validator set.
    pub fn into_participants(self) -> Set<P> {
        self.0
    }

    /// Number of Byzantine validators tolerated by the committee.
    pub const fn faults(&self) -> usize {
        (self.0.len() - 1) / 3
    }

    /// Exact number of attestations in an admission certificate.
    pub const fn quorum(&self) -> usize {
        self.faults() * 2 + 1
    }

    /// Finds a validator's canonical certificate index.
    pub fn index_of(&self, validator: &P) -> Option<Participant> {
        self.0.position(validator).map(Participant::from_usize)
    }

    /// Commits to the exact canonical committee used for certificate indices.
    pub fn commitment<H: Hasher>(&self) -> H::Digest {
        commit_participants::<H, P>(&self.0)
    }
}

impl<P: PublicKey + Ord> Write for Committee<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl<P: PublicKey + Ord> EncodeSize for Committee<P> {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl<P: PublicKey + Ord> Read for Committee<P> {
    /// Maximum accepted committee length.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, maximum: &Self::Cfg) -> Result<Self, CodecError> {
        let maximum = (*maximum).min(MAX_COMMITTEE_SIZE);
        let members = Set::<P>::read_cfg(buf, &(RangeCfg::new(1..=maximum), ()))?;
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
impl<'a, P> arbitrary::Arbitrary<'a> for Committee<P>
where
    P: PublicKey + Ord + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
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

/// Owned canonical subject signed by clearing validators.
#[derive(Clone, Debug)]
pub struct HeaderSubject<P: PublicKey, D: Digest> {
    header: Header<P, D>,
}

impl<P: PublicKey, D: Digest> HeaderSubject<P, D> {
    /// Wraps a canonical clearing header as a certificate subject.
    pub const fn new(header: Header<P, D>) -> Self {
        Self { header }
    }

    /// Clones a canonical clearing header into a certificate subject.
    pub fn from_header(header: &Header<P, D>) -> Self {
        Self::new(header.clone())
    }

    /// Returns the canonical clearing header.
    pub const fn header(&self) -> &Header<P, D> {
        &self.header
    }

    /// Consumes the subject and returns its canonical clearing header.
    pub fn into_header(self) -> Header<P, D> {
        self.header
    }
}

impl<P: PublicKey, D: Digest> CertificateSubject for HeaderSubject<P, D> {
    type Namespace = Vec<u8>;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        derived
    }

    fn message(&self) -> Bytes {
        self.header.encode()
    }
}

/// Validator committee or certificate failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Error {
    /// Committee length is not representable as `3f+1`.
    #[error("committee length must be a representable 3f+1")]
    InvalidCommitteeSize,
    /// A committee key appears more than once.
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
    /// A validator did not supply exactly its deterministic slice assignment.
    #[error("validator slice assignment is incomplete or noncanonical")]
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

/// Ed25519 exact-quorum admission certificates using the Curve25519 backend.
pub mod curve25519 {
    use super::{Committee, Error, HEADER_NAMESPACE, HeaderSubject, commit_participants};
    use crate::bajillion::transition::Header;
    use alloc::{collections::BTreeSet, vec::Vec};
    use bytes::{Buf, BufMut};
    use commonware_codec::{
        EncodeSize, Error as CodecError, Read, ReadRangeExt, Write, types::lazy::Lazy,
    };
    use commonware_cryptography::{
        BatchVerifier as BatchVerifierTrait, Digest, Hasher, PublicKey as PublicKeyTrait,
        Signer as SignerTrait,
        certificate::{
            Attestation, Scheme as CertificateScheme, Signers, Subject as CertificateSubject,
            Verification, Verifier as CertificateVerifier,
        },
        curve25519::{
            BatchVerifier as ValidatorBatchVerifier, Signature as ValidatorSignature, SigningKey,
            VerifyingKey as ValidatorVerifyingKey,
        },
    };
    use commonware_parallel::Strategy;
    use commonware_utils::{
        N3f1, Participant,
        ordered::{Quorum, Set},
    };
    use core::{fmt, marker::PhantomData};
    use rand_core::CryptoRng;

    /// An exact-quorum clearing header certificate.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct Certificate {
        /// Bitmap of committee indices that signed the header.
        pub signers: Signers,
        /// Canonical signatures ordered by increasing signer index.
        pub signatures: Vec<Lazy<ValidatorSignature>>,
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
        /// Maximum accepted committee and signature count.
        type Cfg = usize;

        fn read_cfg(reader: &mut impl Buf, participants: &Self::Cfg) -> Result<Self, CodecError> {
            let signers = Signers::read_cfg(reader, participants)?;
            if signers.count() == 0 {
                return Err(CodecError::Invalid(
                    "clearing::admission::curve25519::Certificate",
                    "certificate contains no signers",
                ));
            }

            let signatures = Vec::<Lazy<ValidatorSignature>>::read_range(reader, ..=*participants)?;
            if signers.count() != signatures.len() {
                return Err(CodecError::Invalid(
                    "clearing::admission::curve25519::Certificate",
                    "signer and signature counts differ",
                ));
            }

            Ok(Self {
                signers,
                signatures,
            })
        }
    }

    #[cfg(feature = "arbitrary")]
    impl arbitrary::Arbitrary<'_> for Certificate {
        fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
            const MAX_ARBITRARY_PARTICIPANTS: u8 = 10;

            let participants = usize::from(u.int_in_range::<u8>(1..=MAX_ARBITRARY_PARTICIPANTS)?);
            let mut signer_indices = Vec::with_capacity(participants);
            for index in 0..participants {
                if u.arbitrary::<bool>()? {
                    signer_indices.push(Participant::from_usize(index));
                }
            }
            if signer_indices.is_empty() {
                signer_indices.push(Participant::new(0));
            }
            let signers = Signers::from(participants, signer_indices);
            let signatures = (0..signers.count())
                .map(|_| u.arbitrary::<ValidatorSignature>().map(Lazy::from))
                .collect::<arbitrary::Result<Vec<_>>>()?;
            Ok(Self {
                signers,
                signatures,
            })
        }
    }

    /// Ed25519 scheme for exact-quorum clearing header certificates.
    #[derive(Clone)]
    pub struct Scheme<P: PublicKeyTrait + Ord> {
        participants: Set<ValidatorVerifyingKey>,
        signer: Option<(Participant, SigningKey)>,
        namespace: Vec<u8>,
        _header_public_key: PhantomData<fn() -> P>,
    }

    impl<P: PublicKeyTrait + Ord> fmt::Debug for Scheme<P> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("Scheme")
                .field("participants", &self.participants)
                .field(
                    "signer",
                    &self.signer.as_ref().map(|(participant, _)| participant),
                )
                .finish_non_exhaustive()
        }
    }

    impl<P: PublicKeyTrait + Ord + 'static> Scheme<P> {
        /// Builds a scheme that signs and verifies for an exact clearing committee.
        pub fn signer(
            committee: Committee<ValidatorVerifyingKey>,
            signing_key: SigningKey,
        ) -> Result<Self, Error> {
            let participants = committee.into_participants();
            let signer = participants
                .index(&signing_key.public_key())
                .ok_or(Error::UnknownValidator)?;
            Ok(Self::new(participants, Some((signer, signing_key))))
        }

        /// Builds a verify-only scheme for an exact clearing committee.
        pub fn verifier(committee: Committee<ValidatorVerifyingKey>) -> Self {
            Self::new(committee.into_participants(), None)
        }

        /// Returns validators in canonical certificate-index order.
        pub const fn participants(&self) -> &Set<ValidatorVerifyingKey> {
            &self.participants
        }

        /// Commits to the exact canonical committee used for certificate indices.
        pub fn committee_commitment<H: Hasher>(&self) -> H::Digest {
            commit_participants::<H, ValidatorVerifyingKey>(&self.participants)
        }

        /// Returns this scheme's validator index when it can sign.
        pub fn me(&self) -> Option<Participant> {
            self.signer.as_ref().map(|(participant, _)| *participant)
        }

        /// Number of Byzantine validators tolerated by this scheme.
        pub const fn faults(&self) -> usize {
            (self.participants.len() - 1) / 3
        }

        /// Exact number of attestations accepted by this scheme.
        pub const fn quorum(&self) -> usize {
            self.faults() * 2 + 1
        }

        /// Assembles exactly `2f+1` distinct in-committee attestations.
        pub fn assemble_exact<I>(
            &self,
            input: I,
            _strategy: &impl Strategy,
        ) -> Result<Certificate, Error>
        where
            I: IntoIterator<Item = Attestation<Self>>,
            I::IntoIter: Send,
        {
            let quorum = self.quorum();
            let entries = self.collect_attestations(input)?;
            if entries.len() != quorum {
                return Err(Error::WrongQuorumSize);
            }
            Ok(self.certificate(entries))
        }

        fn collect_attestations<I>(
            &self,
            input: I,
        ) -> Result<Vec<(Participant, ValidatorSignature)>, Error>
        where
            I: IntoIterator<Item = Attestation<Self>>,
            I::IntoIter: Send,
        {
            let mut entries = Vec::with_capacity(self.quorum());
            let mut signers = BTreeSet::new();
            for attestation in input {
                if usize::from(attestation.signer) >= self.participants.len() {
                    return Err(Error::UnknownValidator);
                }
                if !signers.insert(attestation.signer) {
                    return Err(Error::DuplicateAttestation);
                }
                let Some(signature) = attestation.signature.get().cloned() else {
                    return Err(Error::InvalidAttestation);
                };
                entries.push((attestation.signer, signature));
            }
            entries.sort_unstable_by_key(|(signer, _)| *signer);
            Ok(entries)
        }

        fn certificate(&self, entries: Vec<(Participant, ValidatorSignature)>) -> Certificate {
            let (signers, signatures): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
            Certificate {
                signers: Signers::from(self.participants.len(), signers),
                signatures: signatures.into_iter().map(Lazy::from).collect(),
            }
        }

        /// Verifies one exact-quorum certificate over a canonical header.
        pub fn verify_exact<R, D>(
            &self,
            rng: &mut R,
            header: &Header<P, D>,
            certificate: &Certificate,
            strategy: &impl Strategy,
        ) -> bool
        where
            R: CryptoRng,
            D: Digest,
        {
            <Self as CertificateVerifier>::verify_certificate(
                self,
                rng,
                HeaderSubject::from_header(header),
                certificate,
                strategy,
            )
        }

        fn new(
            participants: Set<ValidatorVerifyingKey>,
            signer: Option<(Participant, SigningKey)>,
        ) -> Self {
            Self {
                participants,
                signer,
                namespace: HEADER_NAMESPACE.to_vec(),
                _header_public_key: PhantomData,
            }
        }

        fn has_exact_quorum(&self, certificate: &Certificate) -> bool {
            certificate.signers.len() == self.participants.len()
                && certificate.signers.count() == self.quorum()
                && certificate.signatures.len() == self.quorum()
        }

        fn stage_certificate<D: Digest>(
            &self,
            batch: &mut ValidatorBatchVerifier,
            subject: HeaderSubject<P, D>,
            certificate: &Certificate,
        ) -> bool {
            if !self.has_exact_quorum(certificate) {
                return false;
            }

            let namespace = subject.namespace(&self.namespace);
            let message = subject.message();
            for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
                let Some(public_key) = self.participants.key(signer) else {
                    return false;
                };
                let Some(signature) = signature.get() else {
                    return false;
                };
                if !<ValidatorBatchVerifier as BatchVerifierTrait>::add_owned(
                    batch,
                    namespace,
                    message.clone(),
                    public_key,
                    signature,
                ) {
                    return false;
                }
            }
            true
        }
    }

    impl<P: PublicKeyTrait + Ord + 'static> CertificateVerifier for Scheme<P> {
        type Subject<'a, D: Digest> = HeaderSubject<P, D>;
        type Faults = N3f1;
        type PublicKey = ValidatorVerifyingKey;
        type Certificate = Certificate;

        fn verify_certificate<R, D>(
            &self,
            rng: &mut R,
            subject: Self::Subject<'_, D>,
            certificate: &Self::Certificate,
            strategy: &impl Strategy,
        ) -> bool
        where
            R: CryptoRng,
            D: Digest,
        {
            let mut batch =
                <ValidatorBatchVerifier as BatchVerifierTrait>::new(certificate.signatures.len());
            self.stage_certificate(&mut batch, subject, certificate)
                && <ValidatorBatchVerifier as BatchVerifierTrait>::verify(batch, rng, strategy)
        }

        fn verify_certificates<'a, R, D, I>(
            &self,
            rng: &mut R,
            certificates: I,
            strategy: &impl Strategy,
        ) -> bool
        where
            R: CryptoRng,
            D: Digest,
            I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
        {
            let mut batch =
                <ValidatorBatchVerifier as BatchVerifierTrait>::new(self.participants.len());
            let mut count = 0usize;
            for (subject, certificate) in certificates {
                if !self.stage_certificate(&mut batch, subject, certificate) {
                    return false;
                }
                count = count.saturating_add(1);
            }
            count == 0
                || <ValidatorBatchVerifier as BatchVerifierTrait>::verify(batch, rng, strategy)
        }

        fn is_batchable() -> bool {
            true
        }

        fn certificate_codec_config(&self) -> usize {
            self.participants.len()
        }

        fn certificate_codec_config_unbounded() -> usize {
            u32::MAX as usize
        }
    }

    impl<P: PublicKeyTrait + Ord + 'static> CertificateScheme for Scheme<P> {
        type Signature = ValidatorSignature;

        fn me(&self) -> Option<Participant> {
            self.me()
        }

        fn participants(&self) -> &Set<Self::PublicKey> {
            &self.participants
        }

        /// This authority-level method may sign without authenticating or retaining an assignment.
        /// Honest validators should authenticate and retain their exact assignment with
        /// [`seal`](crate::bajillion::admission::seal) and make it durable before publishing the
        /// vote.
        fn sign<D: Digest>(&self, subject: Self::Subject<'_, D>) -> Option<Attestation<Self>> {
            let (signer, signing_key) = self.signer.as_ref()?;
            let signature =
                signing_key.sign(subject.namespace(&self.namespace), &subject.message());
            Some(Attestation {
                signer: *signer,
                signature: signature.into(),
            })
        }

        fn verify_attestation<R, D>(
            &self,
            _rng: &mut R,
            subject: Self::Subject<'_, D>,
            attestation: &Attestation<Self>,
            _strategy: &impl Strategy,
        ) -> bool
        where
            R: CryptoRng,
            D: Digest,
        {
            let Some(public_key) = self.participants.key(attestation.signer) else {
                return false;
            };
            let Some(signature) = attestation.signature.get() else {
                return false;
            };
            public_key.verify(
                subject.namespace(&self.namespace),
                &subject.message(),
                signature,
            )
        }

        fn verify_attestations<R, D, I>(
            &self,
            rng: &mut R,
            subject: Self::Subject<'_, D>,
            attestations: I,
            strategy: &impl Strategy,
        ) -> Verification<Self>
        where
            R: CryptoRng,
            D: Digest,
            I: IntoIterator<Item = Attestation<Self>>,
            I::IntoIter: Send,
        {
            let namespace = subject.namespace(&self.namespace);
            let message = subject.message();
            let mut batch =
                <ValidatorBatchVerifier as BatchVerifierTrait>::new(self.participants.len());
            let mut seen = BTreeSet::new();
            let mut invalid = BTreeSet::new();
            let mut candidates = Vec::new();
            for attestation in attestations {
                if !seen.insert(attestation.signer) {
                    invalid.insert(attestation.signer);
                    continue;
                }
                let Some(public_key) = self.participants.key(attestation.signer) else {
                    invalid.insert(attestation.signer);
                    continue;
                };
                let Some(signature) = attestation.signature.get() else {
                    invalid.insert(attestation.signer);
                    continue;
                };
                if !<ValidatorBatchVerifier as BatchVerifierTrait>::add_owned(
                    &mut batch,
                    namespace,
                    message.clone(),
                    public_key,
                    signature,
                ) {
                    invalid.insert(attestation.signer);
                    continue;
                }
                candidates.push(attestation);
            }

            if !candidates.is_empty()
                && !<ValidatorBatchVerifier as BatchVerifierTrait>::verify(batch, rng, strategy)
            {
                for attestation in &candidates {
                    let Some(public_key) = self.participants.key(attestation.signer) else {
                        invalid.insert(attestation.signer);
                        continue;
                    };
                    let Some(signature) = attestation.signature.get() else {
                        invalid.insert(attestation.signer);
                        continue;
                    };
                    if !public_key.verify(namespace, &message, signature) {
                        invalid.insert(attestation.signer);
                    }
                }
            }

            let verified = candidates
                .into_iter()
                .filter(|attestation| !invalid.contains(&attestation.signer))
                .collect();
            Verification::new(verified, invalid.into_iter().collect())
        }

        fn assemble<I>(
            &self,
            attestations: I,
            _strategy: &impl Strategy,
        ) -> Option<Self::Certificate>
        where
            I: IntoIterator<Item = Attestation<Self>>,
            I::IntoIter: Send,
        {
            let mut entries = self.collect_attestations(attestations).ok()?;
            if entries.len() < self.quorum() {
                return None;
            }
            entries.truncate(self.quorum());
            Some(self.certificate(entries))
        }

        fn is_attributable() -> bool {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Committee, Error, HEADER_NAMESPACE, HeaderSubject,
        curve25519::{Certificate, Scheme},
    };
    use crate::bajillion::{
        boundary::{DepositBatch, WithdrawalBatch},
        state::{AccountState, StateLeaf},
        transition::{
            Assignment, CloseContext, CloseLimits, Header, StateCache, build_close, validate_close,
        },
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, DecodeExt, Encode, types::lazy::Lazy};
    use commonware_cryptography::{
        Hasher, Sha256, Signer as _,
        certificate::{Attestation, Scheme as _, Signers, Subject as _, Verifier as _},
        curve25519::{Signature, SigningKey, VerifyingKey},
        sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{Participant, test_rng};

    struct InflatedSizeHint<I>(I);

    impl<I: Iterator> Iterator for InflatedSizeHint<I> {
        type Item = I::Item;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (usize::MAX, Some(usize::MAX))
        }
    }

    fn validator_keys() -> Vec<SigningKey> {
        (0..4).map(SigningKey::from_seed).collect()
    }

    fn committee(keys: &[SigningKey]) -> Committee<VerifyingKey> {
        Committee::new(keys.iter().map(|key| key.public_key()).collect()).unwrap()
    }

    fn validated_header() -> Header<VerifyingKey, Sha256Digest> {
        let operator = SigningKey::from_seed(100);
        let account = SigningKey::from_seed(101).public_key();
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account,
            state: AccountState {
                balance: 3,
                active: true,
                ..AccountState::default()
            },
        }])
        .unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let assignment = Assignment::new(Sha256::hash(&[b"test-committee"]), 0).unwrap();
        let context = CloseContext::new::<Sha256>(
            Sha256::hash(&[b"deployment"]),
            7,
            operator.public_key(),
            &cache,
            &deposits,
            &withdrawals,
            49,
            50,
            CloseLimits::protocol_maximum(),
            assignment,
        )
        .unwrap();
        let close = build_close::<Sha256, _, _>(
            &cache,
            &context,
            &deposits,
            &withdrawals,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        validate_close::<Sha256, _, _>(&context, &deposits, &withdrawals, &close).unwrap();
        close.header
    }

    #[test]
    fn committee_is_exact_canonical_and_bounded() {
        let keys = validator_keys();
        let mut members = keys.iter().map(|key| key.public_key()).collect::<Vec<_>>();
        members.reverse();
        let committee = Committee::new(members).unwrap();
        assert_eq!(committee.faults(), 1);
        assert_eq!(committee.quorum(), 3);
        assert!(committee.members().windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            committee.index_of(committee.members().first().unwrap()),
            Some(Participant::new(0))
        );

        assert_eq!(
            Committee::<VerifyingKey>::new(Vec::new()),
            Err(Error::InvalidCommitteeSize)
        );
        assert_eq!(
            Committee::new(keys[..3].iter().map(|key| key.public_key()).collect()),
            Err(Error::InvalidCommitteeSize)
        );
        let mut duplicate = keys.iter().map(|key| key.public_key()).collect::<Vec<_>>();
        duplicate[3] = duplicate[0].clone();
        assert_eq!(Committee::new(duplicate), Err(Error::DuplicateValidator));

        let encoded = committee.encode();
        assert_eq!(
            Committee::<VerifyingKey>::decode_cfg(encoded.clone(), &4).unwrap(),
            committee
        );
        assert!(Committee::<VerifyingKey>::decode_cfg(encoded, &3).is_err());

        let reordered =
            Committee::new(keys.iter().rev().map(|key| key.public_key()).collect()).unwrap();
        assert_eq!(
            committee.commitment::<Sha256>(),
            reordered.commitment::<Sha256>()
        );
    }

    #[test]
    fn scheme_commitment_matches_canonical_committee_encoding() {
        let keys = validator_keys();
        let committee = committee(&keys);
        let expected = committee.commitment::<Sha256>();
        let signer = Scheme::<VerifyingKey>::signer(committee.clone(), keys[0].clone()).unwrap();
        let verifier = Scheme::<VerifyingKey>::verifier(committee);

        assert_eq!(signer.committee_commitment::<Sha256>(), expected);
        assert_eq!(verifier.committee_commitment::<Sha256>(), expected);
    }

    #[test]
    fn signatures_bind_the_complete_header_and_namespace() {
        let keys = validator_keys();
        let committee = committee(&keys);
        let schemes = keys
            .into_iter()
            .map(|key| Scheme::<VerifyingKey>::signer(committee.clone(), key).unwrap())
            .collect::<Vec<_>>();
        let verifier = Scheme::<VerifyingKey>::verifier(committee);
        let header = validated_header();
        let subject = HeaderSubject::from_header(&header);
        assert_eq!(
            subject.namespace(&HEADER_NAMESPACE.to_vec()),
            HEADER_NAMESPACE
        );
        assert_eq!(subject.message(), header.encode());

        let votes = schemes
            .iter()
            .take(3)
            .map(|scheme| scheme.sign(HeaderSubject::from_header(&header)).unwrap())
            .collect::<Vec<_>>();
        let certificate = schemes[0].assemble_exact(votes, &Sequential).unwrap();
        let mut rng = test_rng();
        assert!(verifier.verify_exact(&mut rng, &header, &certificate, &Sequential));

        let mut other = header.clone();
        other.challenge_deadline = other.challenge_deadline.saturating_add(1);
        assert!(!verifier.verify_exact(&mut rng, &other, &certificate, &Sequential));
    }

    #[test]
    fn assembly_rejects_non_exact_and_duplicate_inputs_without_panicking() {
        let keys = validator_keys();
        let committee = committee(&keys);
        let schemes = keys
            .into_iter()
            .map(|key| Scheme::<VerifyingKey>::signer(committee.clone(), key).unwrap())
            .collect::<Vec<_>>();
        let header = validated_header();
        let votes = schemes
            .iter()
            .map(|scheme| scheme.sign(HeaderSubject::from_header(&header)).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            schemes[0].assemble_exact(votes[..2].to_vec(), &Sequential),
            Err(Error::WrongQuorumSize)
        );
        assert_eq!(
            schemes[0].assemble_exact(votes.clone(), &Sequential),
            Err(Error::WrongQuorumSize)
        );
        let duplicate = vec![votes[0].clone(), votes[0].clone(), votes[1].clone()];
        assert_eq!(
            schemes[0].assemble_exact(duplicate.clone(), &Sequential),
            Err(Error::DuplicateAttestation)
        );
        assert!(schemes[0].assemble(duplicate, &Sequential).is_none());

        let mut unknown = votes[..3].to_vec();
        unknown[2].signer = Participant::new(99);
        assert_eq!(
            schemes[0].assemble_exact(unknown, &Sequential),
            Err(Error::UnknownValidator)
        );

        let mut truncated = Bytes::from_static(b"truncated");
        let mut lazy_invalid = votes[..3].to_vec();
        lazy_invalid[0].signature = Lazy::deferred(&mut truncated, ());
        assert_eq!(
            schemes[0].assemble_exact(lazy_invalid, &Sequential),
            Err(Error::InvalidAttestation)
        );

        let mut reversed = votes[..3].to_vec();
        reversed.reverse();
        let canonical = schemes[0]
            .assemble_exact(votes[..3].to_vec(), &Sequential)
            .unwrap();
        assert_eq!(
            schemes[0].assemble_exact(reversed, &Sequential).unwrap(),
            canonical
        );
        assert_eq!(
            schemes[0]
                .assemble_exact(InflatedSizeHint(votes[..3].iter().cloned()), &Sequential,)
                .unwrap(),
            canonical
        );
    }

    #[test]
    fn trait_assembly_normalizes_super_quorum_to_an_exact_certificate() {
        let keys = validator_keys();
        let committee = committee(&keys);
        let schemes = keys
            .into_iter()
            .map(|key| Scheme::<VerifyingKey>::signer(committee.clone(), key).unwrap())
            .collect::<Vec<_>>();
        let verifier = Scheme::<VerifyingKey>::verifier(committee);
        let header = validated_header();
        let mut votes = schemes
            .iter()
            .map(|scheme| scheme.sign(HeaderSubject::from_header(&header)).unwrap())
            .collect::<Vec<_>>();
        votes.reverse();

        let certificate = schemes[0].assemble(votes, &Sequential).unwrap();
        assert_eq!(certificate.signers.count(), 3);
        assert_eq!(certificate.signatures.len(), 3);
        assert_eq!(
            certificate.signers,
            Signers::from(4, (0..3).map(Participant::from_usize))
        );
        assert!(verifier.verify_exact(&mut test_rng(), &header, &certificate, &Sequential));
    }

    #[test]
    fn verification_rejects_super_quorums_and_malformed_certificates() {
        let keys = validator_keys();
        let committee = committee(&keys);
        let schemes = keys
            .into_iter()
            .map(|key| Scheme::<VerifyingKey>::signer(committee.clone(), key).unwrap())
            .collect::<Vec<_>>();
        let verifier = Scheme::<VerifyingKey>::verifier(committee);
        let header = validated_header();
        let mut votes = schemes
            .iter()
            .map(|scheme| scheme.sign(HeaderSubject::from_header(&header)).unwrap())
            .collect::<Vec<_>>();
        votes.sort_unstable_by_key(|vote| vote.signer);
        let super_quorum = Certificate {
            signers: Signers::from(4, votes.iter().map(|vote| vote.signer)),
            signatures: votes.iter().map(|vote| vote.signature.clone()).collect(),
        };
        let mut rng = test_rng();
        assert!(!verifier.verify_exact(&mut rng, &header, &super_quorum, &Sequential));

        let sub_quorum = Certificate {
            signers: Signers::from(4, votes[..2].iter().map(|vote| vote.signer)),
            signatures: votes[..2]
                .iter()
                .map(|vote| vote.signature.clone())
                .collect(),
        };
        assert!(!verifier.verify_exact(&mut rng, &header, &sub_quorum, &Sequential));

        let exact = Certificate {
            signers: Signers::from(4, votes[..3].iter().map(|vote| vote.signer)),
            signatures: votes[..3]
                .iter()
                .map(|vote| vote.signature.clone())
                .collect(),
        };
        assert!(verifier.verify_exact(&mut rng, &header, &exact, &Sequential));
        assert!(
            verifier.verify_certificates(
                &mut rng,
                [
                    (HeaderSubject::from_header(&header), &exact),
                    (HeaderSubject::from_header(&header), &exact),
                ]
                .into_iter(),
                &Sequential,
            )
        );
        assert!(verifier.verify_certificates(
            &mut rng,
            core::iter::empty::<(HeaderSubject<VerifyingKey, Sha256Digest>, &Certificate,)>(),
            &Sequential,
        ));
        assert!(
            !verifier.verify_certificates(
                &mut rng,
                [
                    (HeaderSubject::from_header(&header), &exact),
                    (HeaderSubject::from_header(&header), &super_quorum),
                ]
                .into_iter(),
                &Sequential,
            )
        );

        let mut corrupt = exact.clone();
        corrupt.signatures[0] = corrupt.signatures[1].clone();
        assert!(!verifier.verify_exact(&mut rng, &header, &corrupt, &Sequential));

        let malformed_signature = Signature::decode([0xff; 64].as_slice()).unwrap();
        let mut malformed = exact.clone();
        malformed.signatures[0] = malformed_signature.into();
        assert!(!verifier.verify_exact(&mut rng, &header, &malformed, &Sequential));

        let mut wrong_bitmap = exact.clone();
        wrong_bitmap.signers = Signers::from(5, votes[..3].iter().map(|vote| vote.signer));
        assert!(!verifier.verify_exact(&mut rng, &header, &wrong_bitmap, &Sequential));

        let empty = Certificate {
            signers: Signers::from(4, core::iter::empty()),
            signatures: Vec::new(),
        };
        assert!(!verifier.verify_exact(&mut rng, &header, &empty, &Sequential));
        assert!(Certificate::decode_cfg(empty.encode(), &4).is_err());

        let mismatched = Certificate {
            signers: Signers::from(4, votes[..2].iter().map(|vote| vote.signer)),
            signatures: vec![votes[0].signature.clone()],
        };
        assert!(Certificate::decode_cfg(mismatched.encode(), &4).is_err());

        let encoded = exact.encode();
        assert_eq!(Certificate::decode_cfg(encoded.clone(), &4).unwrap(), exact);
        assert!(Certificate::decode_cfg(encoded, &3).is_err());
    }

    #[test]
    fn attestations_reject_wrong_namespace_duplicates_unknown_and_lazy_invalid() {
        let keys = validator_keys();
        let committee = committee(&keys);
        let schemes = keys
            .iter()
            .cloned()
            .map(|key| Scheme::<VerifyingKey>::signer(committee.clone(), key).unwrap())
            .collect::<Vec<_>>();
        let header = validated_header();
        let subject = HeaderSubject::from_header(&header);
        let votes = schemes
            .iter()
            .map(|scheme| scheme.sign(subject.clone()).unwrap())
            .collect::<Vec<_>>();
        let mut rng = test_rng();

        let corrupt_signer = votes[1].signer;
        let mut corrupt = votes.clone();
        corrupt[1].signature = corrupt[0].signature.clone();
        let result = schemes[0].verify_attestations(
            &mut rng,
            subject.clone(),
            InflatedSizeHint(corrupt.into_iter()),
            &Sequential,
        );
        assert_eq!(result.invalid, vec![corrupt_signer]);
        assert_eq!(result.verified.len(), 3);

        let duplicate_signer = votes[0].signer;
        let result = schemes[0].verify_attestations(
            &mut rng,
            subject.clone(),
            vec![votes[0].clone(), votes[0].clone(), votes[1].clone()],
            &Sequential,
        );
        assert_eq!(result.invalid, vec![duplicate_signer]);
        assert_eq!(result.verified, vec![votes[1].clone()]);

        let mut unknown = votes[0].clone();
        unknown.signer = Participant::new(99);
        let result =
            schemes[0].verify_attestations(&mut rng, subject.clone(), [unknown], &Sequential);
        assert_eq!(result.invalid, vec![Participant::new(99)]);
        assert!(result.verified.is_empty());

        let mut truncated = Bytes::from_static(b"truncated");
        let lazy_invalid = Attestation::<Scheme<VerifyingKey>> {
            signer: votes[0].signer,
            signature: Lazy::deferred(&mut truncated, ()),
        };
        let result = schemes[0].verify_attestations(&mut rng, subject, [lazy_invalid], &Sequential);
        assert_eq!(result.invalid, vec![votes[0].signer]);
        assert!(result.verified.is_empty());

        let wrong_namespace = b"_COMMONWARE_CLEARING_WRONG_HEADER";
        let wrong_signer = committee.index_of(&keys[0].public_key()).unwrap();
        let wrong = Attestation::<Scheme<VerifyingKey>> {
            signer: wrong_signer,
            signature: keys[0].sign(wrong_namespace, &header.encode()).into(),
        };
        let mut wrong_votes = votes
            .iter()
            .filter(|vote| vote.signer != wrong_signer)
            .take(2)
            .cloned()
            .collect::<Vec<_>>();
        wrong_votes.push(wrong);
        let certificate = schemes[0].assemble_exact(wrong_votes, &Sequential).unwrap();
        assert!(!schemes[0].verify_exact(&mut rng, &header, &certificate, &Sequential,));
    }

    #[test]
    fn malformed_and_wrong_committee_keys_fail_closed() {
        let keys = validator_keys();
        let validator_committee = committee(&keys);
        let schemes = keys
            .iter()
            .cloned()
            .map(|key| Scheme::<VerifyingKey>::signer(validator_committee.clone(), key).unwrap())
            .collect::<Vec<_>>();
        let header = validated_header();
        let votes = schemes
            .iter()
            .take(3)
            .map(|scheme| scheme.sign(HeaderSubject::from_header(&header)).unwrap())
            .collect::<Vec<_>>();
        let certificate = schemes[0].assemble_exact(votes, &Sequential).unwrap();
        let mut rng = test_rng();

        let wrong_keys = (10..14).map(SigningKey::from_seed).collect::<Vec<_>>();
        let wrong_verifier = Scheme::<VerifyingKey>::verifier(committee(&wrong_keys));
        assert!(!wrong_verifier.verify_exact(&mut rng, &header, &certificate, &Sequential,));

        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(VerifyingKey::decode(identity.as_slice()).is_err());
        assert!(VerifyingKey::decode([0xff; 32].as_slice()).is_err());

        let order_two = [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        assert!(VerifyingKey::decode(order_two.as_slice()).is_err());
    }
}
