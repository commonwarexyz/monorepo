use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt::deal,
        primitives::{
            self,
            sharing::{Mode, Sharing},
            variant::{MinPk, MinSig, PartialSignature, Variant},
        },
    },
    ed25519::PrivateKey,
};
use commonware_parallel::Sequential;
use commonware_utils::{Faults, N3f1, TryCollect, non_empty, test_rng};
use criterion::{Criterion, criterion_group};
use rand::seq::SliceRandom;
use std::hint::black_box;

const NAMESPACE: &[u8] = b"benchmark";
const MESSAGE: &[u8] = b"hello";

fn setup<V: Variant>(mode: Mode, n: u32) -> (Sharing<V>, Vec<PartialSignature<V>>) {
    let mut rng = test_rng();
    let players = (0..n)
        .map(|i| PrivateKey::from_seed(i as u64).public_key())
        .try_collect()
        .unwrap();
    let (output, shares) =
        deal::<V, _, N3f1>(&mut rng, mode, players).expect("deal should succeed");
    let sharing = output.public().clone();
    sharing.precompute_partial_publics();
    let mut selected = shares.values().iter().collect::<Vec<_>>();
    selected.shuffle(&mut rng);
    let partials = selected
        .into_iter()
        .take(N3f1::quorum(n) as usize)
        .map(|share| primitives::ops::threshold::sign_message::<V>(share, NAMESPACE, MESSAGE))
        .collect::<Vec<_>>();

    let signature = primitives::ops::threshold::recover(&sharing, &partials, &Sequential)
        .expect("recovery should succeed");
    primitives::ops::verify_message::<V>(sharing.public(), NAMESPACE, MESSAGE, &signature)
        .expect("recovered signature should verify");

    (sharing, partials)
}

fn bench_variant<V: Variant>(c: &mut Criterion, variant: &str) {
    for mode in [Mode::NonZeroCounter, Mode::RootsOfUnity] {
        for n in [100, 298] {
            let quorum = N3f1::quorum(n);
            let (sharing, partials) = setup::<V>(mode, n);

            c.bench_function(
                &format!(
                    "{}/path=optimistic variant={} mode={} n={} quorum={}",
                    module_path!(),
                    variant,
                    match mode {
                        Mode::NonZeroCounter => "counter",
                        Mode::RootsOfUnity => "roots",
                    },
                    n,
                    quorum,
                ),
                |b| {
                    b.iter(|| {
                        let signature = primitives::ops::threshold::recover(
                            &sharing,
                            black_box(&partials),
                            &Sequential,
                        )
                        .expect("recovery should succeed");
                        primitives::ops::verify_message::<V>(
                            sharing.public(),
                            NAMESPACE,
                            MESSAGE,
                            black_box(&signature),
                        )
                        .expect("recovered signature should verify");
                    });
                },
            );

            let mut rng = test_rng();
            c.bench_function(
                &format!(
                    "{}/path=baseline variant={} mode={} n={} quorum={}",
                    module_path!(),
                    variant,
                    match mode {
                        Mode::NonZeroCounter => "counter",
                        Mode::RootsOfUnity => "roots",
                    },
                    n,
                    quorum,
                ),
                |b| {
                    b.iter(|| {
                        primitives::ops::threshold::batch_verify_same_message::<_, V, _>(
                            &mut rng,
                            &sharing,
                            NAMESPACE,
                            MESSAGE,
                            non_empty![@black_box(&partials).iter()],
                            &Sequential,
                        )
                        .expect("batch verification should succeed");
                        black_box(
                            primitives::ops::threshold::recover(
                                &sharing,
                                black_box(&partials),
                                &Sequential,
                            )
                            .expect("recovery should succeed"),
                        );
                    });
                },
            );
        }
    }
}

fn bench_threshold_verify_recover(c: &mut Criterion) {
    bench_variant::<MinSig>(c, "MinSig");
    bench_variant::<MinPk>(c, "MinPk");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_threshold_verify_recover,
}
