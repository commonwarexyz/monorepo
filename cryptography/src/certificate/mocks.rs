//! Mocks for certificate signing schemes.

use super::{Attestation, Namespace as _, Scheme, Signers, Subject};
use crate::{
    ed25519::{
        certificate::mocks::participants as identity_participants, PrivateKey, PublicKey,
    },
    Digest,
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error as CodecError, Read, Write};
use commonware_parallel::Strategy;
use commonware_utils::{
    ordered::{Quorum, Set},
    sequence::U64,
    sync::Mutex,
    Participant,
};
use core::{fmt, marker::PhantomData};
use rand::{CryptoRng, RngCore};
use rand_core::CryptoRngCore;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    vec::Vec,
};

/// A fixture containing identities, identity private keys, per-participant
/// signing schemes, and a single verifier scheme.
#[derive(Clone, Debug)]
pub struct Fixture<S> {
    /// A sorted vector of participant public identity keys.
    pub participants: Vec<PublicKey>,
    /// A sorted vector of participant private identity keys (matching order with `participants`).
    pub private_keys: Vec<PrivateKey>,
    /// A vector of per-participant scheme instances (matching order with `participants`).
    pub schemes: Vec<S>,
    /// A single scheme verifier.
    pub verifier: S,
}

/// A family of certificate subjects that share a common namespace type.
pub trait SubjectFamily: Send + Sync + 'static {
    /// Namespace derived from the base namespace for all subjects in this family.
    type Namespace: super::Namespace;

    /// Subject type for signing and verification.
    type Subject<'a, D: Digest>: Subject<Namespace = Self::Namespace>;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct SignedSubject {
    namespace: Vec<u8>,
    message: Bytes,
}

impl SignedSubject {
    fn new<S: Subject>(subject: S, derived: &S::Namespace) -> Self {
        Self {
            namespace: Subject::namespace(&subject, derived).to_vec(),
            message: Subject::message(&subject),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoredCertificate {
    subject: SignedSubject,
    signers: Signers,
}

#[derive(Debug, Default)]
struct Ledger {
    next_signature: u64,
    signatures: HashMap<Participant, HashMap<u64, SignedSubject>>,
    next_certificate: u64,
    certificates: HashMap<u64, StoredCertificate>,
}

/// Cheap certificate type backed by a shared in-memory ledger.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate {
    id: U64,
    signers: Signers,
}

impl Write for Certificate {
    fn write(&self, writer: &mut impl BufMut) {
        self.id.write(writer);
        self.signers.write(writer);
    }
}

impl EncodeSize for Certificate {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.signers.encode_size()
    }
}

impl Read for Certificate {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_participants: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            id: U64::read_cfg(reader, &())?,
            signers: Signers::read_cfg(reader, max_participants)?,
        })
    }
}

/// Test-only signing scheme backed by a shared in-memory ledger.
///
/// Signatures and certificates are cheap synthetic IDs. Verification succeeds only
/// if the corresponding subject was previously recorded in the shared ledger.
pub struct LedgerScheme<F: SubjectFamily> {
    me: Option<Participant>,
    participants: Set<PublicKey>,
    namespace: F::Namespace,
    ledger: Arc<Mutex<Ledger>>,
    _family: PhantomData<fn() -> F>,
}

impl<F: SubjectFamily> fmt::Debug for LedgerScheme<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LedgerScheme")
            .field("me", &self.me)
            .field("participants", &self.participants)
            .finish_non_exhaustive()
    }
}

impl<F: SubjectFamily> Clone for LedgerScheme<F> {
    fn clone(&self) -> Self {
        Self {
            me: self.me,
            participants: self.participants.clone(),
            namespace: self.namespace.clone(),
            ledger: self.ledger.clone(),
            _family: PhantomData,
        }
    }
}

impl<F: SubjectFamily> LedgerScheme<F> {
    fn new(
        namespace: &[u8],
        participants: Set<PublicKey>,
        me: Option<Participant>,
        ledger: Arc<Mutex<Ledger>>,
    ) -> Self {
        Self {
            me,
            participants,
            namespace: F::Namespace::derive(namespace),
            ledger,
            _family: PhantomData,
        }
    }
}

/// Builds a shared mock scheme fixture that keeps real participant identities
/// but replaces expensive cryptographic checks with ledger lookups.
pub fn fixture<F, R>(rng: &mut R, namespace: &[u8], n: u32) -> Fixture<LedgerScheme<F>>
where
    F: SubjectFamily,
    R: RngCore + CryptoRng,
{
    assert!(n > 0);

    let associated = identity_participants(rng, n);
    let participants = associated.keys().clone();
    let participants_vec: Vec<_> = participants.clone().into();
    let private_keys = participants_vec
        .iter()
        .map(|public_key| {
            associated
                .get_value(public_key)
                .expect("participant key must have an associated private key")
                .clone()
        })
        .collect();

    let ledger = Arc::new(Mutex::new(Ledger::default()));
    let schemes = participants_vec
        .iter()
        .map(|public_key| {
            let me = participants
                .index(public_key)
                .expect("fixture participant must be indexed");
            LedgerScheme::new(namespace, participants.clone(), Some(me), ledger.clone())
        })
        .collect();

    Fixture {
        participants: participants_vec,
        private_keys,
        schemes,
        verifier: LedgerScheme::new(namespace, participants, None, ledger),
    }
}

impl<F: SubjectFamily> Scheme for LedgerScheme<F> {
    type Subject<'a, D: Digest> = F::Subject<'a, D>;
    type PublicKey = PublicKey;
    type Signature = U64;
    type Certificate = Certificate;

    fn me(&self) -> Option<Participant> {
        self.me
    }

    fn participants(&self) -> &Set<Self::PublicKey> {
        &self.participants
    }

    fn sign<D: Digest>(&self, subject: Self::Subject<'_, D>) -> Option<Attestation<Self>> {
        let signer = self.me?;
        let signed_subject = SignedSubject::new(subject, &self.namespace);

        let mut ledger = self.ledger.lock();
        let signature_id = ledger.next_signature;
        ledger.next_signature = ledger.next_signature.wrapping_add(1);
        ledger
            .signatures
            .entry(signer)
            .or_default()
            .insert(signature_id, signed_subject);

        Some(Attestation {
            signer,
            signature: U64::new(signature_id).into(),
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
        R: CryptoRngCore,
        D: Digest,
    {
        if self.participants.key(attestation.signer).is_none() {
            return false;
        }

        let Some(signature) = attestation.signature.get() else {
            return false;
        };
        let expected_subject = SignedSubject::new(subject, &self.namespace);
        let signature_id = u64::from(signature);
        let ledger = self.ledger.lock();
        ledger
            .signatures
            .get(&attestation.signer)
            .and_then(|entries| entries.get(&signature_id))
            == Some(&expected_subject)
    }

    fn assemble<I, M>(
        &self,
        attestations: I,
        _strategy: &impl Strategy,
    ) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
        M: commonware_utils::Faults,
    {
        let mut unique_signers = HashSet::new();
        let mut signers = Vec::new();
        let mut signed_subject = None;
        let mut ledger = self.ledger.lock();

        for attestation in attestations {
            self.participants.key(attestation.signer)?;

            let signature = attestation.signature.get()?;
            let signature_id = u64::from(signature);
            let entry = ledger
                .signatures
                .get(&attestation.signer)?
                .get(&signature_id)?
                .clone();

            if let Some(existing) = &signed_subject {
                if existing != &entry {
                    return None;
                }
            } else {
                signed_subject = Some(entry);
            }

            if unique_signers.insert(attestation.signer) {
                signers.push(attestation.signer);
            }
        }

        if signers.len() < self.participants.quorum::<M>() as usize {
            return None;
        }

        let subject = signed_subject?;
        let signers = Signers::from(self.participants.len(), signers);
        let certificate_id = ledger.next_certificate;
        ledger.next_certificate = ledger.next_certificate.wrapping_add(1);
        ledger.certificates.insert(
            certificate_id,
            StoredCertificate {
                subject,
                signers: signers.clone(),
            },
        );

        Some(Certificate {
            id: U64::new(certificate_id),
            signers,
        })
    }

    fn verify_certificate<R, D, M>(
        &self,
        _rng: &mut R,
        subject: Self::Subject<'_, D>,
        certificate: &Self::Certificate,
        _strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRngCore,
        D: Digest,
        M: commonware_utils::Faults,
    {
        if certificate.signers.len() != self.participants.len() {
            return false;
        }
        if certificate.signers.count() < self.participants.quorum::<M>() as usize {
            return false;
        }

        let expected_subject = SignedSubject::new(subject, &self.namespace);
        let certificate_id = u64::from(&certificate.id);
        let ledger = self.ledger.lock();
        ledger
            .certificates
            .get(&certificate_id)
            .is_some_and(|stored| {
                stored.subject == expected_subject && stored.signers == certificate.signers
            })
    }

    fn is_attributable() -> bool {
        true
    }

    fn is_batchable() -> bool {
        false
    }

    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {
        self.participants.len()
    }

    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {
        usize::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::{fixture, Certificate, SubjectFamily};
    use crate::{certificate::Scheme as _, sha256::Digest as Sha256Digest};
    use bytes::Bytes;
    use commonware_codec::{Decode, Encode};
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, N3f1};

    #[derive(Clone, Copy, Debug)]
    struct TestFamily;

    impl SubjectFamily for TestFamily {
        type Namespace = Vec<u8>;
        type Subject<'a, D: crate::Digest> = TestSubject<'a>;
    }

    #[derive(Clone, Copy, Debug)]
    struct TestSubject<'a> {
        message: &'a [u8],
    }

    impl crate::certificate::Subject for TestSubject<'_> {
        type Namespace = Vec<u8>;

        fn namespace<'a>(&self, namespace: &'a Self::Namespace) -> &'a [u8] {
            namespace
        }

        fn message(&self) -> Bytes {
            self.message.to_vec().into()
        }
    }

    #[test]
    fn attestation_round_trip_verifies() {
        let mut rng = test_rng();
        let fixture = fixture::<TestFamily, _>(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject { message: b"vote-1" };
        let attestation = fixture.schemes[0]
            .sign::<Sha256Digest>(subject)
            .expect("signer must produce an attestation");

        assert!(fixture.verifier.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            subject,
            &attestation,
            &Sequential,
        ));
        assert!(!fixture.verifier.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            TestSubject { message: b"vote-2" },
            &attestation,
            &Sequential,
        ));
    }

    #[test]
    fn certificate_round_trip_verifies() {
        let mut rng = test_rng();
        let fixture = fixture::<TestFamily, _>(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject {
            message: b"certificate-subject",
        };
        let attestations: Vec<_> = fixture.schemes[..3]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(subject).unwrap())
            .collect();
        let certificate = fixture.verifier.assemble::<_, N3f1>(attestations, &Sequential).unwrap();
        let encoded = certificate.encode();
        let decoded =
            Certificate::decode_cfg(encoded, &fixture.verifier.participants.len()).unwrap();

        assert!(
            fixture
                .verifier
                .verify_certificate::<_, Sha256Digest, N3f1>(
                    &mut rng,
                    subject,
                    &decoded,
                    &Sequential,
                )
        );
        assert!(
            !fixture
                .verifier
                .verify_certificate::<_, Sha256Digest, N3f1>(
                    &mut rng,
                    TestSubject {
                        message: b"other-subject",
                    },
                    &decoded,
                    &Sequential,
                )
        );
    }

    #[test]
    fn certificate_decode_round_trip_uses_participant_bound() {
        let mut rng = test_rng();
        let fixture = fixture::<TestFamily, _>(&mut rng, b"mock-scheme", 4);
        let subject = TestSubject { message: b"bound" };
        let attestations: Vec<_> = fixture.schemes[..3]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(subject).unwrap())
            .collect();
        let certificate = fixture.verifier.assemble::<_, N3f1>(attestations, &Sequential).unwrap();
        let encoded = certificate.encode();

        assert!(Certificate::decode_cfg(encoded.clone(), &4).is_ok());
        assert!(Certificate::decode_cfg(encoded, &2).is_err());
    }
}
