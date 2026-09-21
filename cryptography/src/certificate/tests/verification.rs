use super::{ed25519_fixture::TestSubject, setup_ed25519};
use crate::{
    Digest, Signer as _,
    bls12381::{
        dkg::feldman_desmedt as dkg,
        primitives::{
            sharing::Mode,
            variant::{MinPk, MinSig, Variant},
        },
    },
    certificate::{
        AssemblyError, Attestation, Scheme as CertificateScheme, Verification, Verifier,
    },
    ed25519::{PrivateKey as Ed25519PrivateKey, PublicKey},
    sha256::Digest as Sha256Digest,
};
use bytes::Bytes;
use commonware_codec::{Read, types::lazy::Lazy};
use commonware_math::algebra::Random;
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::{
    Faults, N3f1, NZU32, Participant, TryCollect, iter::NonEmpty, non_empty, ordered::Set,
    sync::Mutex, test_rng,
};
use rand_core::CryptoRng;
use std::sync::Arc;

#[allow(dead_code)]
mod threshold {
    use super::TestSubject;
    use crate::impl_certificate_bls12381_threshold;
    use commonware_utils::N3f1;

    impl_certificate_bls12381_threshold!(TestSubject, Vec<u8>, N3f1);
}

const NAMESPACE: &[u8] = b"certificate-recovery";
const SUBJECT: TestSubject = TestSubject {
    message: b"subject",
};
const OTHER_SUBJECT: TestSubject = TestSubject {
    message: b"other-subject",
};

fn threshold_signers<V: Variant>(
    rng: &mut impl CryptoRng,
    n: u32,
) -> Vec<threshold::Scheme<PublicKey, V>> {
    let identity_keys: Vec<_> = (0..n)
        .map(|_| Ed25519PrivateKey::random(&mut *rng))
        .collect();
    let participants: Set<PublicKey> = identity_keys
        .iter()
        .map(|key| key.public_key())
        .try_collect()
        .unwrap();
    let (polynomial, shares) =
        dkg::deal_anonymous::<V, N3f1>(&mut *rng, Mode::NonZeroCounter, NZU32!(n));
    shares
        .into_iter()
        .map(|share| {
            threshold::Scheme::signer(NAMESPACE, participants.clone(), polynomial.clone(), share)
                .unwrap()
        })
        .collect()
}

fn never<S: CertificateScheme>() -> impl Iterator<Item = Attestation<S>> {
    std::iter::from_fn(|| -> Option<Attestation<S>> {
        panic!("additional attestations must not be consumed")
    })
}

fn threshold_success<V: Variant>() {
    let mut rng = test_rng();
    let schemes = threshold_signers::<V>(&mut rng, 5);
    let quorum = N3f1::quorum(schemes.len() as u32) as usize;
    let attestations: Vec<_> = schemes
        .iter()
        .take(quorum)
        .map(|scheme| scheme.sign::<Sha256Digest>(SUBJECT).unwrap())
        .collect();
    let pending = attestations[..2].to_vec();
    let additional = attestations[2..].to_vec();
    let expected = schemes[0]
        .assemble(
            non_empty![@pending.clone().into_iter().chain(additional.clone())],
            &Sequential,
        )
        .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let verifier = Recording {
        inner: schemes[0].clone(),
        calls: Arc::clone(&calls),
    };

    let Ok(recovered) = verifier.verify_certificate_or_attestations::<_, Sha256Digest, _, _>(
        &mut rng,
        SUBJECT,
        pending
            .into_iter()
            .map(Recording::outer)
            .collect::<Vec<_>>(),
        additional
            .into_iter()
            .map(Recording::outer)
            .collect::<Vec<_>>(),
        &Sequential,
    ) else {
        panic!("a valid threshold quorum must recover")
    };

    assert_eq!(recovered, expected);
    assert!(calls.lock().is_empty());
    assert!(schemes[0].verify_certificate::<_, Sha256Digest>(
        &mut rng,
        SUBJECT,
        &recovered,
        &Sequential,
    ));
    assert!(!schemes[0].verify_certificate::<_, Sha256Digest>(
        &mut rng,
        OTHER_SUBJECT,
        &recovered,
        &Sequential,
    ));

    // Threshold recovery uses the lowest quorum of signer indices.
    let unused_bad = Recording::outer(schemes[quorum].sign::<Sha256Digest>(OTHER_SUBJECT).unwrap());
    let Ok(recovered) = verifier.verify_certificate_or_attestations::<_, Sha256Digest, _, _>(
        &mut rng,
        SUBJECT,
        attestations
            .into_iter()
            .map(Recording::outer)
            .collect::<Vec<_>>(),
        vec![unused_bad],
        &Sequential,
    ) else {
        panic!("an unused bad candidate must not invalidate a recovered certificate")
    };
    assert_eq!(recovered, expected);
    assert!(calls.lock().is_empty());
}

#[test]
fn test_threshold_recovers_exact_certificate_with_additional_attestations() {
    threshold_success::<MinPk>();
    threshold_success::<MinSig>();
}

#[test]
fn test_empty_and_attributable_inputs_skip_assembly() {
    let mut rng = test_rng();
    let schemes = threshold_signers::<MinPk>(&mut rng, 5);
    let result = schemes[0].verify_certificate_or_attestations::<_, Sha256Digest, _, _>(
        &mut rng,
        SUBJECT,
        Vec::new(),
        never(),
        &Sequential,
    );
    let Err(Verification { verified, invalid }) = result else {
        panic!("empty pending input cannot assemble a certificate")
    };
    assert!(verified.is_empty());
    assert!(invalid.is_empty());

    let (schemes, _) = setup_ed25519(4);
    let valid = schemes[0].sign::<Sha256Digest>(SUBJECT).unwrap();
    let invalid_attestation = schemes[1].sign::<Sha256Digest>(OTHER_SUBJECT).unwrap();
    let invalid_signer = invalid_attestation.signer;
    let result = schemes[0].verify_certificate_or_attestations::<_, Sha256Digest, _, _>(
        &mut rng,
        SUBJECT,
        vec![valid.clone(), invalid_attestation],
        never(),
        &Sequential,
    );
    let Err(Verification { verified, invalid }) = result else {
        panic!("attributable schemes must verify pending attestations ordinarily")
    };
    assert_eq!(verified, vec![valid]);
    assert_eq!(invalid, vec![invalid_signer]);
}

#[derive(Clone, Debug)]
struct Recording<S> {
    inner: S,
    calls: Arc<Mutex<Vec<Vec<Participant>>>>,
}

impl<S: CertificateScheme> Recording<S> {
    fn inner(attestation: Attestation<Self>) -> Attestation<S> {
        Attestation {
            signer: attestation.signer,
            signature: attestation.signature,
        }
    }

    fn outer(attestation: Attestation<S>) -> Attestation<Self> {
        Attestation {
            signer: attestation.signer,
            signature: attestation.signature,
        }
    }
}

impl<S: CertificateScheme> Verifier for Recording<S> {
    type Subject<'a, D: Digest> = S::Subject<'a, D>;
    type Faults = S::Faults;
    type PublicKey = S::PublicKey;
    type Certificate = S::Certificate;

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
        self.inner
            .verify_certificate(rng, subject, certificate, strategy)
    }

    fn is_batchable() -> bool {
        S::is_batchable()
    }

    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {
        self.inner.certificate_codec_config()
    }

    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {
        S::certificate_codec_config_unbounded()
    }
}

impl<S: CertificateScheme> CertificateScheme for Recording<S> {
    type Signature = S::Signature;

    fn me(&self) -> Option<Participant> {
        self.inner.me()
    }

    fn participants(&self) -> &Set<Self::PublicKey> {
        self.inner.participants()
    }

    fn sign<D: Digest>(&self, subject: Self::Subject<'_, D>) -> Option<Attestation<Self>> {
        self.inner.sign(subject).map(Self::outer)
    }

    fn verify_attestation<R, D>(
        &self,
        rng: &mut R,
        subject: Self::Subject<'_, D>,
        attestation: &Attestation<Self>,
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
    {
        self.inner.verify_attestation(
            rng,
            subject,
            &Attestation {
                signer: attestation.signer,
                signature: attestation.signature.clone(),
            },
            strategy,
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
        let attestations: Vec<_> = attestations.into_iter().collect();
        self.calls
            .lock()
            .push(attestations.iter().map(|a| a.signer).collect());
        let result = self.inner.verify_attestations(
            rng,
            subject,
            attestations.into_iter().map(Self::inner),
            strategy,
        );
        Verification::new(
            result.verified.into_iter().map(Self::outer).collect(),
            result.invalid,
        )
    }

    fn assemble<I>(
        &self,
        attestations: NonEmpty<I>,
        strategy: &impl Strategy,
    ) -> Result<Self::Certificate, AssemblyError>
    where
        I: Iterator<Item = Attestation<Self>> + Send,
    {
        self.inner.assemble(
            non_empty![@attestations.into_iter().map(Self::inner)],
            strategy,
        )
    }

    fn is_attributable() -> bool {
        S::is_attributable()
    }
}

fn expected_halves(len: usize) -> Vec<Vec<Participant>> {
    let middle = len.div_ceil(2);
    let first = (0..middle).map(Participant::from_usize).collect();
    if middle == len {
        vec![first]
    } else {
        vec![first, (middle..len).map(Participant::from_usize).collect()]
    }
}

#[test]
fn test_rejected_certificate_verifies_pending_halves_directly() {
    for n in [1, 5, 7] {
        let mut rng = test_rng();
        let schemes = threshold_signers::<MinPk>(&mut rng, n);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let verifier = Recording {
            inner: schemes[0].clone(),
            calls: Arc::clone(&calls),
        };
        let quorum = N3f1::quorum(n) as usize;
        let pending: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|scheme| Recording::outer(scheme.sign::<Sha256Digest>(OTHER_SUBJECT).unwrap()))
            .collect();

        let result = verifier.verify_certificate_or_attestations::<_, Sha256Digest, _, _>(
            &mut rng,
            SUBJECT,
            pending,
            std::iter::empty(),
            &Sequential,
        );
        let Err(Verification { verified, invalid }) = result else {
            panic!("a certificate for another subject must be rejected")
        };
        assert!(verified.is_empty());
        assert_eq!(
            invalid,
            (0..quorum).map(Participant::from_usize).collect::<Vec<_>>()
        );
        assert_eq!(*calls.lock(), expected_halves(quorum));
    }
}

#[test]
fn test_malformed_assembly_falls_back_to_pending_halves() {
    let mut rng = test_rng();
    let schemes = threshold_signers::<MinPk>(&mut rng, 5);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let verifier = Recording {
        inner: schemes[0].clone(),
        calls: Arc::clone(&calls),
    };
    let quorum = N3f1::quorum(schemes.len() as u32) as usize;
    let mut pending: Vec<_> = schemes
        .iter()
        .take(quorum)
        .map(|scheme| Recording::outer(scheme.sign::<Sha256Digest>(SUBJECT).unwrap()))
        .collect();
    let mut malformed = Bytes::from_static(&[0]);
    pending[0].signature = Lazy::deferred(&mut malformed, ());

    let result = verifier.verify_certificate_or_attestations::<_, Sha256Digest, _, _>(
        &mut rng,
        SUBJECT,
        pending,
        std::iter::empty(),
        &Sequential,
    );
    let Err(Verification { verified, invalid }) = result else {
        panic!("malformed assembly must fall back to ordinary verification")
    };
    assert_eq!(verified.len(), quorum - 1);
    assert_eq!(invalid, vec![Participant::new(0)]);
    assert_eq!(*calls.lock(), expected_halves(quorum));
}

#[test]
fn test_fallback_classifies_pending_only() {
    let mut rng = test_rng();
    let schemes = threshold_signers::<MinPk>(&mut rng, 5);
    let quorum = N3f1::quorum(schemes.len()) as usize;
    let pending: Vec<_> = schemes[..2]
        .iter()
        .map(|scheme| scheme.sign::<Sha256Digest>(SUBJECT).unwrap())
        .collect();

    let result = schemes[0].verify_certificate_or_attestations::<_, Sha256Digest, _, _>(
        &mut rng,
        SUBJECT,
        pending.clone(),
        std::iter::empty(),
        &Sequential,
    );
    let Err(Verification { verified, invalid }) = result else {
        panic!("insufficient candidates must fall back")
    };
    assert_eq!(verified, pending);
    assert!(invalid.is_empty());

    let bad_additional: Vec<_> = schemes[2..4]
        .iter()
        .map(|scheme| scheme.sign::<Sha256Digest>(OTHER_SUBJECT).unwrap())
        .collect();
    assert_eq!(pending.len() + bad_additional.len(), quorum);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let verifier = Recording {
        inner: schemes[0].clone(),
        calls: Arc::clone(&calls),
    };
    let recorded_pending: Vec<_> = pending.iter().cloned().map(Recording::outer).collect();
    let result = verifier.verify_certificate_or_attestations::<_, Sha256Digest, _, _>(
        &mut rng,
        SUBJECT,
        recorded_pending.clone(),
        bad_additional
            .into_iter()
            .map(Recording::outer)
            .collect::<Vec<_>>(),
        &Sequential,
    );
    let Err(Verification { verified, invalid }) = result else {
        panic!("bad additional candidates must not authenticate a certificate")
    };
    assert_eq!(verified, recorded_pending);
    assert!(invalid.is_empty());
    assert_eq!(
        *calls.lock(),
        vec![vec![pending[0].signer], vec![pending[1].signer]]
    );

    let result = schemes[0].verify_certificate_or_attestations::<_, Sha256Digest, _, _>(
        &mut rng,
        SUBJECT,
        pending.clone(),
        vec![pending[0].clone(), pending[1].clone()],
        &Sequential,
    );
    let Err(Verification { verified, invalid }) = result else {
        panic!("overlapping additional candidates must fall back")
    };
    assert_eq!(verified, pending);
    assert!(invalid.is_empty());

    let mut unknown = pending[0].clone();
    unknown.signer = Participant::new(999);
    let result = schemes[0].verify_certificate_or_attestations::<_, Sha256Digest, _, _>(
        &mut rng,
        SUBJECT,
        vec![unknown, pending[1].clone()],
        vec![pending[0].clone(), pending[1].clone()],
        &Sequential,
    );
    let Err(Verification { verified, invalid }) = result else {
        panic!("an unknown pending signer must be classified by fallback")
    };
    assert_eq!(verified, vec![pending[1].clone()]);
    assert_eq!(invalid, vec![Participant::new(999)]);
}
