use crate::common::{N_LEAVES, SAMPLE_SIZE, multi_samples};
use commonware_storage::merkle::{Family, verification};
use criterion::{Criterion, criterion_group};
use futures::executor::block_on;
use std::hint::black_box;

/// Times multi-proof generation without verification.
fn bench_multi_proof_family<F: Family>(c: &mut Criterion, family: &str) {
    for n in N_LEAVES {
        let (mem, _, samples) = multi_samples::<F>(n);
        let locations: Vec<_> = samples.into_iter().map(|(loc, _)| loc).collect();
        c.bench_function(
            &format!(
                "{}/n={n} items={SAMPLE_SIZE} family={family}",
                module_path!(),
            ),
            |b| {
                b.iter(|| {
                    black_box(
                        block_on(verification::multi_proof(&mem, 0, black_box(&locations)))
                            .unwrap(),
                    )
                })
            },
        );
    }
}

fn bench_multi_proof(c: &mut Criterion) {
    bench_multi_proof_family::<commonware_storage::mmr::Family>(c, "mmr");
    bench_multi_proof_family::<commonware_storage::mmb::Family>(c, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_multi_proof
}
