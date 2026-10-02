use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
use criterion::{BatchSize, Criterion, criterion_group};
use std::hint::black_box;

fn bench_digest_cmp(c: &mut Criterion) {
    for n in [10u64, 100, 1_000, 10_000, 50_000, 100_000] {
        let digests: Vec<Digest> = (0..n)
            .map(|i| Sha256::hash(&[&i.to_be_bytes()[..]]))
            .collect();
        c.bench_function(&format!("{}/op=sort n={n}", module_path!()), |b| {
            b.iter_batched(
                || digests.clone(),
                |mut v| {
                    v.sort_unstable();
                    v
                },
                BatchSize::LargeInput,
            );
        });
        let mut sorted = digests.clone();
        sorted.sort_unstable();
        c.bench_function(&format!("{}/op=search n={n}", module_path!()), |b| {
            b.iter(|| {
                for d in &digests {
                    black_box(sorted.binary_search(black_box(d)).is_ok());
                }
            });
        });
    }
}

criterion_group!(benches, bench_digest_cmp);
