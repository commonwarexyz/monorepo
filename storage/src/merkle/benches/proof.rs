use crate::common::{N_LEAVES, SAMPLE_SIZE, StandardHasher, single_samples};
use commonware_cryptography::Sha256;
use commonware_storage::merkle::{Bagging::ForwardFold, Family};
use criterion::{BatchSize, Criterion, criterion_group};
use futures::executor::block_on;
use std::hint::black_box;

/// Times single-leaf proof generation without verification.
fn bench_proof_family<F: Family>(c: &mut Criterion, family: &str) {
    for n in N_LEAVES {
        c.bench_function(
            &format!(
                "{}/n={n} samples={SAMPLE_SIZE} family={family}",
                module_path!(),
            ),
            |b| {
                b.iter_batched(
                    || single_samples::<F>(n),
                    |(mem, _, samples)| {
                        block_on(async {
                            let hasher = StandardHasher::<Sha256>::new(ForwardFold);
                            for (loc, _) in samples {
                                black_box(mem.proof(&hasher, loc, 0).unwrap());
                            }
                        });
                    },
                    BatchSize::LargeInput,
                )
            },
        );
    }
}

fn bench_proof(c: &mut Criterion) {
    bench_proof_family::<commonware_storage::mmr::Family>(c, "mmr");
    bench_proof_family::<commonware_storage::mmb::Family>(c, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_proof
}
