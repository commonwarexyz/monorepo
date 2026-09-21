use super::optimistic_assemble::{BenchSubject, Case, bench_case};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::{
            sharing::Mode,
            variant::{MinPk, MinSig, Variant},
        },
    },
    certificate::{Attestation, Scheme as _},
    ed25519::{self, PrivateKey},
    impl_certificate_bls12381_threshold,
    sha256::Digest as Sha256Digest,
};
use commonware_utils::{Faults, N3f1, TestRng, TryCollect, ordered::Set};
use criterion::{Criterion, criterion_group};
use rand::seq::SliceRandom;

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_THRESHOLD_OPTIMISTIC_ASSEMBLE";

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

    // Sample a quorum plus a spare across the committee's interpolation points.
    let mut selected: Vec<_> = shares.into_iter().map(|(_, share)| share).collect();
    selected.shuffle(&mut rng);

    // Scheme construction warms the shared partial-public-key cache before timing.
    let attestations = selected
        .into_iter()
        .take(N3f1::quorum(n) as usize + 1)
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
            let mode_name = match mode {
                Mode::NonZeroCounter => "counter",
                Mode::RootsOfUnity => "roots",
            };
            for case in [Case::Valid, Case::Bad, Case::Spare, Case::Split] {
                bench_case::<_, Sha256Digest>(
                    c,
                    &format!(
                        "{}/variant={} mode={} n={} case={}",
                        module_path!(),
                        variant,
                        mode_name,
                        n,
                        case.name(),
                    ),
                    &scheme,
                    BenchSubject,
                    &attestations,
                    quorum as usize,
                    case,
                );
            }
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
