//! Shared fixtures and timing helpers for optimistic assembly benchmarks.

use bytes::Bytes;
use commonware_cryptography::{
    Digest,
    certificate::{Attestation, Scheme, Subject, Verification},
};
use commonware_parallel::Sequential;
use commonware_utils::{Participant, TestRng, non_empty};
use criterion::{BatchSize, Criterion};
use rand_core::CryptoRng;
use std::hint::black_box;

const MESSAGE: &[u8] = b"hello";
const RNG_SEED: u64 = 1;

#[derive(Clone, Debug)]
pub struct BenchSubject;

impl Subject for BenchSubject {
    type Namespace = Vec<u8>;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        derived
    }

    fn message(&self) -> Bytes {
        Bytes::from_static(MESSAGE)
    }
}

/// Input cases for optimistic assembly and its fallback.
#[derive(Clone, Copy)]
pub enum Case {
    /// A quorum of valid attestations.
    Valid,
    /// A quorum with one invalid attestation, leaving too few to certify.
    Bad,
    /// A quorum plus one attestation, leaving a valid quorum after rejection.
    Spare,
    /// A quorum with one invalid attestation in each fallback half.
    Split,
}

impl Case {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Bad => "bad",
            Self::Spare => "spare",
            Self::Split => "split",
        }
    }

    const fn expects_certificate(self) -> bool {
        matches!(self, Self::Valid | Self::Spare)
    }
}

fn fixture<S: Scheme>(
    attestations: &[Attestation<S>],
    quorum: usize,
    case: Case,
) -> (Vec<Attestation<S>>, Vec<Participant>) {
    assert_eq!(attestations.len(), quorum + 1);
    match case {
        Case::Valid => (attestations[..quorum].to_vec(), Vec::new()),
        Case::Split => {
            let mut pending = attestations[..quorum].to_vec();
            let chunk = pending.len().div_ceil(2);

            // The excluded spare's valid signature is well-formed but invalid for both
            // claimed signers.
            let replacement = attestations[quorum].signature.clone();
            pending[0].signature = replacement.clone();
            pending[chunk].signature = replacement;
            let mut invalid = vec![pending[0].signer, pending[chunk].signer];
            invalid.sort_unstable();
            (pending, invalid)
        }
        Case::Bad | Case::Spare => {
            // Corrupt the minimum signer so threshold recovery's quorum always includes it.
            let mut pending = attestations.to_vec();
            let invalid_position = pending
                .iter()
                .enumerate()
                .min_by_key(|(_, attestation)| attestation.signer)
                .map(|(position, _)| position)
                .unwrap();
            let invalid = pending[invalid_position].signer;
            let replacement = pending
                .iter()
                .find(|attestation| attestation.signer != invalid)
                .unwrap()
                .signature
                .clone();
            pending[invalid_position].signature = replacement;

            if matches!(case, Case::Bad) {
                let removed = pending
                    .iter()
                    .rposition(|attestation| attestation.signer != invalid)
                    .unwrap();
                pending.remove(removed);
            }

            (pending, vec![invalid])
        }
    }
}

/// Attempt optimistic assembly, then assemble any verified quorum retained on failure.
fn assemble_with_fallback<S, R, D>(
    scheme: &S,
    rng: &mut R,
    subject: S::Subject<'static, D>,
    pending: Vec<Attestation<S>>,
    quorum: usize,
) -> (Verification<S>, Option<S::Certificate>)
where
    S: Scheme,
    R: CryptoRng,
    D: Digest,
{
    let mut result = match scheme.optimistic_assemble::<_, D, _, _>(
        rng,
        subject,
        pending,
        std::iter::empty(),
        &Sequential,
    ) {
        Ok(certificate) => return (Verification::new(Vec::new(), Vec::new()), Some(certificate)),
        Err(result) => result,
    };
    let certificate = if result.verified.len() >= quorum {
        Some(
            scheme
                .assemble(non_empty![@result.verified.drain(..)], &Sequential)
                .expect("verified quorum must assemble"),
        )
    } else {
        None
    };
    (result, certificate)
}

fn assert_verification<S: Scheme>(
    verification: &Verification<S>,
    expected_verified: &[Attestation<S>],
    expected_invalid: &[Participant],
) {
    assert_eq!(verification.verified.as_slice(), expected_verified);
    assert_invalid(&verification.invalid, expected_invalid);
}

fn assert_invalid(invalid: &[Participant], expected: &[Participant]) {
    let mut invalid = invalid.to_vec();
    let mut expected = expected.to_vec();
    invalid.sort_unstable();
    expected.sort_unstable();
    assert!(invalid.windows(2).all(|pair| pair[0] != pair[1]));
    assert!(expected.windows(2).all(|pair| pair[0] != pair[1]));
    assert_eq!(invalid, expected);
}

/// Benchmark optimistic assembly, including any fallback and subsequent certificate construction.
pub fn bench_case<S, D>(
    c: &mut Criterion,
    name: &str,
    scheme: &S,
    subject: S::Subject<'static, D>,
    attestations: &[Attestation<S>],
    quorum: usize,
    case: Case,
) where
    S: Scheme,
    D: Digest,
{
    let (pending, expected_invalid) = fixture(attestations, quorum, case);
    let (expected_pending, expected_failures) = match case {
        Case::Valid => (quorum, 0),
        Case::Bad => (quorum, 1),
        Case::Spare => (quorum + 1, 1),
        Case::Split => (quorum, 2),
    };
    assert_eq!(pending.len(), expected_pending);
    assert_eq!(expected_invalid.len(), expected_failures);
    let expected_verified: Vec<_> = pending
        .iter()
        .filter(|attestation| !expected_invalid.contains(&attestation.signer))
        .cloned()
        .collect();
    assert_eq!(
        expected_verified.len(),
        expected_pending - expected_failures
    );

    // Establish structural assembly and the candidate's expected authentication result.
    let candidate = scheme
        .assemble(non_empty![@pending.clone().into_iter()], &Sequential)
        .expect("signer-unique quorum must assemble structurally");
    assert_eq!(
        scheme.verify_certificate::<_, D>(
            &mut TestRng::new(RNG_SEED),
            subject.clone(),
            &candidate,
            &Sequential,
        ),
        expected_invalid.is_empty()
    );

    // Establish the optimistic decision and its exact fallback evidence.
    let mut direct_rng = TestRng::new(RNG_SEED);
    let direct = scheme.optimistic_assemble::<_, D, _, _>(
        &mut direct_rng,
        subject.clone(),
        pending.clone(),
        std::iter::empty(),
        &Sequential,
    );
    if expected_invalid.is_empty() {
        let certificate = direct.ok().expect("valid quorum must certify");
        assert!(scheme.verify_certificate::<_, D>(
            &mut direct_rng,
            subject.clone(),
            &certificate,
            &Sequential,
        ));
    } else {
        let verification = direct.expect_err("invalid candidate must enter fallback");
        assert_verification(&verification, &expected_verified, &expected_invalid);
    }

    // Establish that both recursive halves independently require invalid isolation.
    if matches!(case, Case::Split) {
        let chunk = pending.len().div_ceil(2);
        for half in [pending[..chunk].to_vec(), pending[chunk..].to_vec()] {
            let half_invalid = expected_invalid
                .iter()
                .copied()
                .find(|invalid| {
                    half.iter()
                        .any(|attestation| attestation.signer == *invalid)
                })
                .unwrap();
            let half_verified: Vec<_> = half
                .iter()
                .filter(|attestation| attestation.signer != half_invalid)
                .cloned()
                .collect();
            let half_verification = scheme.verify_attestations::<_, D, _>(
                &mut TestRng::new(RNG_SEED),
                subject.clone(),
                half,
                &Sequential,
            );
            assert_verification(&half_verification, &half_verified, &[half_invalid]);
        }
    }

    // Verify the final certificate or retained fallback evidence before timing.
    let (verification, certificate) = assemble_with_fallback(
        scheme,
        &mut TestRng::new(RNG_SEED),
        subject.clone(),
        pending.clone(),
        quorum,
    );
    assert_eq!(certificate.is_some(), case.expects_certificate());
    if let Some(certificate) = &certificate {
        assert_invalid(&verification.invalid, &expected_invalid);
        assert!(verification.verified.is_empty());
        assert!(scheme.verify_certificate::<_, D>(
            &mut TestRng::new(RNG_SEED),
            subject.clone(),
            certificate,
            &Sequential,
        ));
    } else {
        assert_verification(&verification, &expected_verified, &expected_invalid);
    }

    let mut rng = TestRng::new(RNG_SEED);
    c.bench_function(name, |b| {
        b.iter_batched(
            || pending.clone(),
            |pending| {
                black_box(assemble_with_fallback(
                    scheme,
                    &mut rng,
                    subject.clone(),
                    pending,
                    quorum,
                ));
            },
            BatchSize::SmallInput,
        );
    });
}
