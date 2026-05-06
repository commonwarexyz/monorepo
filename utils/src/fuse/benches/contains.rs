use commonware_utils::fuse::BinaryFuseFilter;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::hint::black_box;

fn bench_contains<F: commonware_utils::fuse::Fingerprint>(c: &mut Criterion, n: usize) {
    let mut rng = StdRng::seed_from_u64(n as u64);
    let keys: Vec<u64> = (0..n).map(|_| rng.gen()).collect();
    let filter = BinaryFuseFilter::<F>::new(n as u64, 32, &keys).expect("construction failed");
    let probe: u64 = rng.gen();
    let fp_bits = F::SIZE * 8;
    c.bench_function(
        &format!("{}/fp_bits={fp_bits} n={n}", module_path!()),
        |b| {
            b.iter(|| black_box(&filter).contains(black_box(probe)));
        },
    );
}

fn benchmark_contains(c: &mut Criterion) {
    for n in [1_000, 100_000, 1_000_000] {
        bench_contains::<u8>(c, n);
        bench_contains::<u16>(c, n);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_contains,
}
