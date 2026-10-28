use super::utils::{blst_final_exp, blst_miller_loop, pairs, to_blst};
use commonware_cryptography_bls12381::old::pairing::multi_pairing;
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

fn bench_multi_pairing(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for n in [1, 2, 8, 32] {
        let pairs = pairs(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("impl=bls12381 n={n}"), |b| {
            b.iter(|| black_box(multi_pairing(&pairs)));
        });
        let (p, q) = to_blst(&pairs);
        group.bench_function(format!("impl=blst n={n}"), |b| {
            b.iter(|| black_box(blst_final_exp(&blst_miller_loop(&p, &q))));
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_multi_pairing
}
