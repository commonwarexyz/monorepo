use crate::common::{SAMPLE_SIZE, StandardHasher, n_leaves, range_samples};
use commonware_cryptography::Sha256;
use commonware_storage::merkle::{Bagging::ForwardFold, Family};
use criterion::{BatchSize, Criterion, criterion_group};
use futures::executor::block_on;

/// Times range proof verification, with the proofs generated in setup.
fn bench_verify_many_elements_family<F: Family>(c: &mut Criterion, family: &str) {
    for &n in n_leaves() {
        for range in [2, 5, 10, 25, 50, 100, 250, 500, 1_000, 5_000] {
            c.bench_function(
                &format!(
                    "{}/n={n} range={range} samples={SAMPLE_SIZE} family={family}",
                    module_path!(),
                ),
                |b| {
                    b.iter_batched(
                        || {
                            let (mem, root, samples) = range_samples::<F>(n, range);
                            let hasher = StandardHasher::<Sha256>::new(ForwardFold);
                            let proofs = block_on(async {
                                let mut proofs = Vec::with_capacity(samples.len());
                                for (range, elements) in samples {
                                    let proof = mem.range_proof(&hasher, range.clone(), 0).unwrap();
                                    proofs.push((range, elements, proof));
                                }
                                proofs
                            });
                            (root, proofs)
                        },
                        |(root, proofs)| {
                            let hasher = StandardHasher::<Sha256>::new(ForwardFold);
                            for (range, elements, proof) in proofs {
                                assert!(proof.verify_range_inclusion(
                                    &hasher,
                                    range.start,
                                    &elements,
                                    &root
                                ));
                            }
                        },
                        BatchSize::LargeInput,
                    )
                },
            );
        }
    }
}

fn bench_verify_many_elements(c: &mut Criterion) {
    bench_verify_many_elements_family::<commonware_storage::mmr::Family>(c, "mmr");
    bench_verify_many_elements_family::<commonware_storage::mmb::Family>(c, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_verify_many_elements
}
