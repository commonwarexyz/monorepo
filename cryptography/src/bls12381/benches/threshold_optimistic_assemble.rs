use bytes::Bytes;
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::{
            sharing::Mode,
            variant::{MinPk, MinSig, Variant},
        },
    },
    certificate::{Attestation, Scheme as _, Subject, Verifier as _},
    ed25519::{self, PrivateKey},
    impl_certificate_bls12381_threshold,
    sha256::Digest as Sha256Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::{Faults, N3f1, TestRng, TryCollect, non_empty, ordered::Set};
use criterion::{BatchSize, Criterion, criterion_group};
use rand::seq::SliceRandom;
use std::hint::black_box;

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_THRESHOLD_OPTIMISTIC_ASSEMBLE";
const MESSAGE: &[u8] = b"hello";

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

impl_certificate_bls12381_threshold!(BenchSubject, Vec<u8>, N3f1);

type Threshold<V> = Scheme<ed25519::PublicKey, V>;

fn setup<V: Variant>(mode: Mode, n: u32) -> (Threshold<V>, Vec<Attestation<Threshold<V>>>) {
    let participants: Set<_> = (0..n)
        .map(|i| PrivateKey::from_seed(u64::from(i)).public_key())
        .try_collect()
        .unwrap();
    let mut rng = TestRng::new(u64::from(n));
    let (output, shares) =
        deal::<V, _, N3f1>(&mut rng, mode, participants.clone()).expect("deal should succeed");
    let sharing = output.public().clone();

    // Sample a quorum across the committee's interpolation points.
    let mut selected: Vec<_> = shares.into_iter().map(|(_, share)| share).collect();
    selected.shuffle(&mut rng);

    // Scheme construction warms the shared partial-public-key cache before timing.
    let attestations = selected
        .into_iter()
        .take(N3f1::quorum(n) as usize)
        .map(|share| {
            Scheme::signer(NAMESPACE, participants.clone(), sharing.clone(), share)
                .expect("share must match a participant")
                .sign::<Sha256Digest>(BenchSubject)
                .unwrap()
        })
        .collect();

    (
        Scheme::verifier(NAMESPACE, participants, sharing),
        attestations,
    )
}

fn bench_variant<V: Variant>(c: &mut Criterion, variant: &str) {
    for mode in [Mode::NonZeroCounter, Mode::RootsOfUnity] {
        for (n, quorum) in [(100, 67), (298, 199)] {
            assert_eq!(N3f1::quorum(n), quorum);
            let (scheme, attestations) = setup::<V>(mode, n);
            let mode = match mode {
                Mode::NonZeroCounter => "counter",
                Mode::RootsOfUnity => "roots",
            };

            let mut check_rng = TestRng::new(0);
            let certificate = scheme
                .optimistic_assemble::<_, Sha256Digest, _, _>(
                    &mut check_rng,
                    BenchSubject,
                    attestations.clone(),
                    std::iter::empty(),
                    &Sequential,
                )
                .ok()
                .expect("valid quorum must certify");
            assert!(scheme.verify_certificate::<_, Sha256Digest>(
                &mut check_rng,
                BenchSubject,
                &certificate,
                &Sequential,
            ));

            let mut optimistic_rng = TestRng::new(1);
            c.bench_function(
                &format!(
                    "{}/path=optimistic variant={} mode={} n={} quorum={}",
                    module_path!(),
                    variant,
                    mode,
                    n,
                    quorum,
                ),
                |b| {
                    b.iter_batched(
                        || attestations.clone(),
                        |pending| {
                            let certificate = scheme
                                .optimistic_assemble::<_, Sha256Digest, _, _>(
                                    &mut optimistic_rng,
                                    BenchSubject,
                                    pending,
                                    std::iter::empty(),
                                    &Sequential,
                                )
                                .ok()
                                .expect("valid quorum must certify");
                            black_box(certificate);
                        },
                        BatchSize::SmallInput,
                    );
                },
            );

            let mut baseline_rng = TestRng::new(1);
            c.bench_function(
                &format!(
                    "{}/path=baseline variant={} mode={} n={} quorum={}",
                    module_path!(),
                    variant,
                    mode,
                    n,
                    quorum,
                ),
                |b| {
                    b.iter_batched(
                        || attestations.clone(),
                        |pending| {
                            let verification = scheme.verify_attestations::<_, Sha256Digest, _>(
                                &mut baseline_rng,
                                BenchSubject,
                                pending,
                                &Sequential,
                            );
                            let certificate = scheme
                                .assemble(non_empty![@verification.verified], &Sequential)
                                .expect("verified quorum must assemble");
                            black_box(certificate);
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

fn bench_threshold_optimistic_assemble(c: &mut Criterion) {
    bench_variant::<MinPk>(c, "MinPk");
    bench_variant::<MinSig>(c, "MinSig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_threshold_optimistic_assemble,
}
