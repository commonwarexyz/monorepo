use crate::common::{N_LEAVES, SAMPLE_SIZE, StandardHasher, multi_samples};
use commonware_cryptography::Sha256;
use commonware_storage::merkle::{Bagging::ForwardFold, Family, verification};
use criterion::{Criterion, criterion_group};
use futures::executor::block_on;
use std::hint::black_box;

/// Times multi-proof verification, with the proof generated before timing starts.
fn bench_verify_multi_family<F: Family>(c: &mut Criterion, family: &str) {
    for n in N_LEAVES {
        let (mem, root, samples) = multi_samples::<F>(n);
        let locations: Vec<_> = samples.iter().map(|(loc, _)| *loc).collect();
        let proof = block_on(verification::multi_proof(&mem, 0, &locations)).unwrap();
        let elements: Vec<_> = samples
            .into_iter()
            .map(|(loc, element)| (element, loc))
            .collect();
        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        c.bench_function(
            &format!(
                "{}/n={n} items={SAMPLE_SIZE} family={family}",
                module_path!(),
            ),
            |b| {
                b.iter(|| {
                    assert!(black_box(&proof).verify_multi_inclusion(
                        &hasher,
                        black_box(&elements),
                        &root
                    ))
                })
            },
        );
    }
}

fn bench_verify_multi(c: &mut Criterion) {
    bench_verify_multi_family::<commonware_storage::mmr::Family>(c, "mmr");
    bench_verify_multi_family::<commonware_storage::mmb::Family>(c, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_verify_multi
}
