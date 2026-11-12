use crate::common::{N_LEAVES, SAMPLE_SIZE, StandardHasher, range_samples};
use commonware_cryptography::Sha256;
use commonware_storage::merkle::{Bagging::ForwardFold, Family};
use criterion::{BatchSize, Criterion, criterion_group};
use futures::executor::block_on;
use std::hint::black_box;

/// Times range proof generation without verification.
fn bench_range_proof_family<F: Family>(c: &mut Criterion, family: &str) {
    for n in N_LEAVES {
        for range in [2, 5, 10, 25, 50, 100, 250, 500, 1_000, 5_000] {
            c.bench_function(
                &format!(
                    "{}/n={n} range={range} samples={SAMPLE_SIZE} family={family}",
                    module_path!(),
                ),
                |b| {
                    // Borrow the fixture so the tree is freed after timing stops
                    b.iter_batched_ref(
                        || range_samples::<F>(n, range),
                        |(mem, _, samples)| {
                            let hasher = StandardHasher::<Sha256>::new(ForwardFold);
                            block_on(async {
                                for (range, _) in samples.iter() {
                                    black_box(mem.range_proof(&hasher, range.clone(), 0).unwrap());
                                }
                            })
                        },
                        BatchSize::LargeInput,
                    )
                },
            );
        }
    }
}

fn bench_range_proof(c: &mut Criterion) {
    bench_range_proof_family::<commonware_storage::mmr::Family>(c, "mmr");
    bench_range_proof_family::<commonware_storage::mmb::Family>(c, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_range_proof
}
