use super::utils::{balanced_pairs, blst_final_exp, blst_miller_loop, to_blst};
use commonware_cryptography_bls12381::pairing::pairing_check;
use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

fn bench_pairing_check(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    for n in [2, 9, 33] {
        let pairs = balanced_pairs(n);
        assert!(pairing_check(&pairs));
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("impl=bls12381 n={n}"), |b| {
            b.iter(|| black_box(pairing_check(&pairs)));
        });
        let (p, q) = to_blst(&pairs);
        group.bench_function(format!("impl=blst n={n}"), |b| {
            b.iter(|| {
                let product = blst_final_exp(&blst_miller_loop(&p, &q));
                // SAFETY: the pointer references a valid field element.
                black_box(unsafe { blst::blst_fp12_is_one(&product) })
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_pairing_check
}
